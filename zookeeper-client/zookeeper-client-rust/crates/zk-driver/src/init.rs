// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Drop-in handle creation (`zkrs_handle_new`).
//!
//! [`Init`] runs the work that C `zookeeper_init` does before it starts
//! threads, in the C order:
//!
//! 1. Parse the host string with the legacy rules
//!    (`zk_proto::legacy::connect::parse_init`). A chroot error fails
//!    here, before any resolution.
//! 2. The initial resolution through the `resolve` leaf
//!    (zookeeper.c:1450), with the per-host loop of
//!    `crate::resolve::ResolveRun`: a LOG flush before each leaf call
//!    and before the reseed. When entry k has a port error, the loop
//!    resolves entries 0..k-1, then fails: the "no port in %s" or
//!    "invalid port in %s" line comes after their lines, no reseed runs,
//!    and the errno is EINVAL (zookeeper.c:870-889).
//! 3. The SASL point when SASL parameters were given
//!    ([`InitStep::SaslPoint`]): C creates the SASL session now
//!    (zookeeper.c:1472-1479).
//! 4. [`InitStep::Ready`]. The flavor then makes its handle: mt creates
//!    the waker (mt_adaptor.c:244) in `threaded::Shared::new`.
//!
//! Each [`InitStep::More`] and [`InitStep::SaslPoint`] is a `ZKRS_MORE`.
//! C drains and calls `step` again.

use zk_jute::JString;
use zk_proto::legacy::connect::{HostParseError, HostParseErrorKind, parse_init};
use zk_proto::legacy::hashtable::c_str;
use zk_proto::{Action, Compat, Config, Connection, DriverMode, HostSpec, LogArg, LogSite, rc};

use crate::host::{DriverTokens, connection_hooks, discard_leftovers, log_record};
use crate::outbox::{Flavor, Item, Outbox, ResumeAt};
use crate::resolve::{ResolveEnd, ResolveRun};
use crate::state::{Core, Env};
use crate::sync::{Mutex, Unlocked};

/// The arguments of `zkrs_handle_new`.
pub struct InitArgs {
    /// The configuration. `hosts`, `host_text` and `chroot` are filled
    /// from `host_string`.
    pub cfg: Config,
    /// The raw host string of `zookeeper_init`.
    pub host_string: Vec<u8>,
    /// The profile. The drop-in uses `Compat::LEGACY_C`.
    pub compat: Compat,
    /// The driver mode: `DriverMode::MT` or `DriverMode::ST`.
    pub mode: DriverMode,
    /// The flavor of the pump.
    pub flavor: Flavor,
}

/// A failed init. C frees the handle and returns NULL with this errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitError {
    /// The errno, or `None` when C keeps the errno of the caller
    /// (`HostParseErrorKind::NoHosts`).
    pub errno: Option<i32>,
}

/// The result of one [`Init::step`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitStep {
    /// LOG items wait before a blocking call. C drains and calls `step`.
    More,
    /// `*rc = ZKRS_INIT_SASL_POINT`: C creates the SASL session, drains
    /// and calls `step`.
    SaslPoint,
    /// The connection is ready. Take it with [`Shared::from_init`](crate::threaded::Shared::from_init) or [`Polled::from_init`](crate::polled::Polled::from_init).
    Ready,
    /// The init failed. C drains, then frees the handle.
    Failed(InitError),
}

/// The stage of an init.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitPhase {
    /// The initial resolution runs.
    Resolve,
    /// The port error of the parse waits after the prefix resolution.
    PortError,
    /// The SASL point is next.
    Sasl,
    /// Ready.
    Ready,
    /// Failed.
    Failed,
}

/// One drop-in init in progress.
pub struct Init<T: DriverTokens> {
    /// The connection. It is behind the `core` lock, so the resolution
    /// loop is the one of `iocore`.
    pub(crate) core: Mutex<Core<T>>,
    /// The services.
    pub(crate) env: Env<T>,
    /// The flavor.
    pub(crate) flavor: Flavor,
    /// The resolution loop.
    pub(crate) run: Option<ResolveRun>,
    /// The port error of entry k, reported after entries 0..k-1.
    pub(crate) port_error: Option<HostParseError>,
    /// True when SASL parameters were given.
    pub(crate) sasl: bool,
    /// The stage.
    pub(crate) phase: InitPhase,
    /// The error of a failed init. `step` gives it again after `Failed`.
    error: Option<InitError>,
}

impl<T: DriverTokens> Init<T> {
    /// Parses the host string and makes the connection.
    ///
    /// A port error keeps its prefix entries as the host list, so the
    /// resolution loop resolves them first. Other parse errors fail here.
    /// The core hooks come from `crate::host::connection_hooks`.
    ///
    /// Log records of the parse go to `ob`.
    ///
    /// # Errors
    ///
    /// Returns the errno of a parse error that is not a port error.
    pub fn new(args: InitArgs, env: Env<T>, ob: &mut Outbox<T>) -> Result<Self, InitError> {
        let InitArgs {
            mut cfg,
            host_string,
            compat,
            mode,
            flavor,
        } = args;
        let port_error = match parse_init(&host_string) {
            Ok(cs) => {
                cfg.hosts = cs.hosts.into_iter().map(HostSpec::Legacy).collect();
                cfg.host_text = JString::Bytes(cs.host_text);
                cfg.chroot = cs.chroot.map(JString::Bytes);
                None
            }
            Err(mut e) if e.entry.is_some() => {
                // The chroot check passed before the host parse failed. So
                // the split of the raw string is valid.
                let (host_text, chroot) = split_chroot(&host_string);
                let prefix = std::mem::take(&mut e.prefix);
                cfg.hosts = prefix.into_iter().map(HostSpec::Legacy).collect();
                cfg.host_text = JString::Bytes(host_text);
                cfg.chroot = chroot.map(JString::Bytes);
                Some(e)
            }
            Err(e) => return Err(InitError { errno: e.errno }),
        };
        let sasl = cfg.sasl;
        let (rng, log, dw) = connection_hooks(&env.host);
        let now = env.clock.now();
        let conn = Box::new(Connection::new(cfg, compat, mode, rng, log, dw, now));
        let mut core = Core::new(conn);
        // A barrier here only stores the stopped stage. The first step
        // resumes it before it does other work.
        core.pump(flavor, ob, &*env.host);
        Ok(Self {
            core: Mutex::new(core),
            env,
            flavor,
            run: None,
            port_error,
            sasl,
            phase: InitPhase::Resolve,
            error: None,
        })
    }

    /// Runs the init until it must stop.
    ///
    /// The first call takes `Resolve{initial: true}` from `poll_action`
    /// and runs the resolution loop. The port error, when there is one,
    /// gives its log record and `Failed` with EINVAL after the prefix.
    pub fn step(&mut self, proof: &mut Unlocked, ob: &mut Outbox<T>) -> InitStep {
        let step = self.net_step(proof, ob);
        if matches!(step, InitStep::More | InitStep::SaslPoint) {
            ob.set_resume(ResumeAt::Init);
        }
        step
    }

    /// Runs the phases in order until one must stop.
    fn net_step(&mut self, proof: &mut Unlocked, ob: &mut Outbox<T>) -> InitStep {
        loop {
            match self.phase {
                InitPhase::Resolve => {
                    if let Some(step) = self.resolve_step(proof, ob) {
                        return step;
                    }
                }
                InitPhase::PortError => {
                    let errno = self.port_error.take().map_or(Some(EINVAL), |e| {
                        self.push_port_line(&e, ob);
                        e.errno
                    });
                    return self.fail(InitError { errno });
                }
                InitPhase::Sasl => {
                    self.phase = InitPhase::Ready;
                    return InitStep::SaslPoint;
                }
                InitPhase::Ready => return InitStep::Ready,
                InitPhase::Failed => {
                    return InitStep::Failed(self.error.unwrap_or(InitError {
                        errno: Some(EINVAL),
                    }));
                }
            }
        }
    }

    /// Runs the initial resolution. It returns `None` when the phase
    /// changed and the loop goes on.
    fn resolve_step(&mut self, proof: &mut Unlocked, ob: &mut Outbox<T>) -> Option<InitStep> {
        let now = self.env.clock.now();
        {
            let mut core = self.core.lock(proof);
            core.resume_stopped(now);
            if core.pump(self.flavor, ob, &*self.env.host) {
                return Some(InitStep::More);
            }
        }
        if self.run.is_none() {
            let action = self
                .core
                .lock(proof)
                .conn
                .as_deref_mut()
                .and_then(|c| c.poll_action(now));
            match action {
                Some(Action::Resolve {
                    generation, hosts, ..
                }) => self.run = Some(ResolveRun::new(generation, hosts)),
                // A new connection always asks for the resolution first.
                // Without it no address can resolve.
                _ => {
                    return Some(self.fail(InitError {
                        errno: Some(EINVAL),
                    }));
                }
            }
        }
        let Some(run) = self.run.as_mut() else {
            return Some(self.fail(InitError {
                errno: Some(EINVAL),
            }));
        };
        let cx = self.env.resolve_ctx(&self.core, self.flavor);
        if self.port_error.is_some() {
            // C stops at the bad entry: no reseed and no server set update.
            if let ResolveEnd::More = run.run_hosts(&cx, proof, ob) {
                return Some(InitStep::More);
            }
            self.phase = InitPhase::PortError;
            return None;
        }
        match run.run(&cx, proof, ob) {
            ResolveEnd::More => Some(InitStep::More),
            ResolveEnd::Done { rc } if rc == rc::ZOK => {
                self.phase = if self.sasl {
                    InitPhase::Sasl
                } else {
                    InitPhase::Ready
                };
                None
            }
            ResolveEnd::Done { .. } => {
                let errno = self
                    .core
                    .lock(proof)
                    .conn
                    .as_deref_mut()
                    .and_then(Connection::take_errno_hint);
                Some(self.fail(InitError { errno }))
            }
        }
    }

    /// Queues the C log line of a port error.
    fn push_port_line(&self, e: &HostParseError, ob: &mut Outbox<T>) {
        let site = match e.kind {
            HostParseErrorKind::NoPort => LogSite::ResolveNoPort,
            _ => LogSite::ResolveBadPort,
        };
        let args = vec![LogArg::Str(JString::Bytes(e.subject.clone()))];
        if let Some(record) = log_record(&*self.env.host, site, args) {
            ob.push(Item::Log(record));
        }
    }

    /// Ends the init with an error. Later calls give the same error.
    fn fail(&mut self, error: InitError) -> InitStep {
        self.phase = InitPhase::Failed;
        self.error = Some(error);
        InitStep::Failed(error)
    }

    /// Gives the core and the services to the flavor after `Ready`.
    #[must_use]
    pub(crate) fn into_parts(self) -> (Core<T>, Env<T>) {
        (self.core.into_inner(), self.env)
    }

    /// Abandons a failed init. Every token goes to `discard_token`.
    pub fn abandon(self) {
        let (mut core, env) = self.into_parts();
        let host = &*env.host;
        // The requeued items and the st local FIFO are items that C did
        // not take. The outbox gives their tokens to discard_token.
        let mut ob = Outbox::new();
        core.restore_requeued(&mut ob);
        ob.extend_items(core.local.drain(..));
        ob.finish(host);
        if let Some(conn) = core.conn.take() {
            discard_leftovers(host, conn);
        }
    }
}

/// The C `errno` value `EINVAL`.
const EINVAL: i32 = zk_proto::legacy::connect::EINVAL;

/// Splits a host string into the host text and the chroot, as
/// `parse_init` does. The string ends at the first NUL. A chroot of
/// only "/" is no chroot.
fn split_chroot(raw: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    let s = c_str(raw);
    match s.iter().position(|&b| b == b'/') {
        Some(i) => {
            let host = s.get(..i).unwrap_or_default().to_vec();
            let root = s.get(i..).unwrap_or_default();
            let root = (root.len() > 1).then(|| root.to_vec());
            (host, root)
        }
        None => (s.to_vec(), None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use std::net::SocketAddr;
    use std::sync::Arc;

    use zk_proto::SecretBytes;
    use zk_testkit::tokens::{AuthId, TestTokens};

    use super::*;
    use crate::host::HostLeaves;
    use crate::testutil::TestHost;

    fn args(hosts: &[u8], sasl: bool) -> InitArgs {
        let mut cfg = Config::legacy(10_000);
        cfg.sasl = sasl;
        InitArgs {
            cfg,
            host_string: hosts.to_vec(),
            compat: Compat::LEGACY_C,
            mode: DriverMode::ST,
            flavor: Flavor::St,
        }
    }

    fn host_with(names: &[&[u8]]) -> Arc<TestHost> {
        let host = Arc::new(TestHost::new());
        for (i, name) in names.iter().enumerate() {
            let a: SocketAddr = format!("10.0.0.{}:2181", i + 1).parse().unwrap();
            host.set_addrs(name, vec![a]);
        }
        host
    }

    fn new_init(
        host: &Arc<TestHost>,
        hosts: &[u8],
        sasl: bool,
        ob: &mut Outbox<TestTokens>,
    ) -> Result<Init<TestTokens>, InitError> {
        let dyn_host: Arc<dyn HostLeaves<TestTokens>> = host.clone();
        Init::new(args(hosts, sasl), Env::new(dyn_host), ob)
    }

    /// Takes every item and gives the log sites, in order.
    fn drain(ob: &mut Outbox<TestTokens>) -> Vec<LogSite> {
        let mut sites = Vec::new();
        while let Some(item) = ob.pop() {
            if let Item::Log(r) = item {
                sites.push(r.site);
            }
        }
        sites
    }

    #[test]
    fn port_error_splits_the_raw_string_as_the_parse_does() {
        let split = |s: &[u8]| split_chroot(s);
        assert_eq!(
            split(b"a:1,b/app\0junk"),
            (b"a:1,b".to_vec(), Some(b"/app".to_vec()))
        );
        assert_eq!(split(b"a:1,b/"), (b"a:1,b".to_vec(), None));
        assert_eq!(split(b"a:1,b"), (b"a:1,b".to_vec(), None));
        assert_eq!(split(b"a:1\0/app"), (b"a:1".to_vec(), None));
        // Only the prefix before the bad entry resolves.
        let host = host_with(&[b"a"]);
        let mut ob = Outbox::new();
        let mut init = new_init(&host, b"a:1,b/app", false, &mut ob).unwrap();
        let step = init.step(&mut Unlocked::new_at_entry(), &mut ob);
        assert!(matches!(step, InitStep::Failed(_)));
        assert_eq!(host.resolves(), 1);
        assert_eq!(drain(&mut ob), [LogSite::ResolveNoPort]);
    }

    #[test]
    fn abandon_discards_every_token() {
        let host = host_with(&[b"a"]);
        let mut ob = Outbox::new();
        let init = new_init(&host, b"a:1", false, &mut ob).unwrap();
        {
            let mut core = init.core.lock_owner();
            let conn = core.conn.as_deref_mut().unwrap();
            let cred = SecretBytes::from(b"pw".to_vec());
            let now = zk_proto::Millis(0);
            let added = conn.add_auth(JString::from("digest"), cred, Some(AuthId::new(1)), now);
            assert!(added.is_ok());
            core.local.push_back(Item::AuthResult {
                token: AuthId::new(2),
                rc: 0,
            });
            let mut left = Outbox::new();
            left.push(Item::AuthResult {
                token: AuthId::new(3),
                rc: 0,
            });
            core.requeued = Some(left.requeue());
        }
        init.abandon();
        assert_eq!(host.discarded(), ["auth", "auth", "auth"]);
    }
}
