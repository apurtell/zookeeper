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

//! The core-lock state that every driver shares.
//!
//! `Core` is the value behind the `core` mutex. It holds the proto
//! `Connection` and the driver state that must change under the same
//! lock: the stopped stage of a barrier, the requeued items, the st local
//! FIFO, the peer address cache and the SASL answer of C.
//!
//! Field writers:
//!
//! | Field | Writer |
//! |---|---|
//! | `conn` | `Core::new`; the final close takes it (`threaded`, `polled`, `native`) |
//! | `stopped` | `iocore` (the pump and the resume) |
//! | `requeued` | the flavor modules (`requeue`); `iocore` restores it |
//! | `local` | `outbox::pump` through `FifoBound::Local` (st) |
//! | `peer` | `iocore` (set at TCP connect, cleared when the transport goes) |
//! | `sasl` | the flavor modules (`sasl_result`); `iocore` takes it |
//! | `set_servers_runs`, `next_run_id` | `resolve::SetServersRun`; `requeue` adopts a run |
//! | `orphan_close` | `threaded` and `polled` (`requeue`, `close`) |

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use zk_jute::JString;
use zk_proto::{
    AddAuthError, Connection, HostSpec, Millis, Request, SaslError, SaslStep, SecretBytes, Stage,
    Stopped, SubmitError, Submitted, Tokens,
};

/// The result of one submit to proto.
pub(crate) type SubmitResult<T> = Result<Submitted<T>, SubmitError<T>>;

use crate::clock::{Clock, MonotonicClock};
use crate::dispatch::ReadGate;
use crate::host::HostLeaves;
use crate::iocore::{DeferPolicy, DriverConfig, StepCtx};
use crate::net::poll::{Poll, RustixPoll};
use crate::net::tls::TlsConnector;
use crate::net::waker::{WakeRx, Waker};
use crate::outbox::{FifoBound, Flavor, Item, Outbox, Pumped, Requeued, ResumeAt, pump};
use crate::resolve::{ResolveCtx, SetServersRun};
use crate::sync::atomic::AtomicBool;
use crate::sync::{Mutex, Unlocked};

/// The services of one handle, fixed at creation.
///
/// zk-ffi fills it from the host vtable and the `zookeeper_init_ssl`
/// arguments. zk-client fills it from the builder.
pub struct Env<T: Tokens> {
    /// The host leaves.
    pub host: Arc<dyn HostLeaves<T>>,
    /// The TLS connector, or `None` for plaintext.
    pub tls: Option<Arc<dyn TlsConnector>>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// The poll call. zk-ffi may inject its `WSAPoll` wrapper.
    pub poll: Arc<dyn Poll>,
    /// The driver parameters.
    pub cfg: DriverConfig,
}

impl<T: Tokens> Env<T> {
    /// Makes the services with no TLS, the monotonic clock, `RustixPoll`
    /// and the default parameters.
    #[must_use]
    pub fn new(host: Arc<dyn HostLeaves<T>>) -> Self {
        Self {
            host,
            tls: None,
            clock: Arc::new(MonotonicClock::new()),
            poll: Arc::new(RustixPoll),
            cfg: DriverConfig::default(),
        }
    }

    /// Makes the services of one step call.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn step_ctx<'a>(
        &'a self,
        core: &'a Mutex<Core<T>>,
        flavor: Flavor,
        defer: DeferPolicy,
        wake: Option<(&'a Waker, &'a WakeRx)>,
        abort: Option<&'a AtomicBool>,
        gate: Option<&'a ReadGate>,
    ) -> StepCtx<'a, T> {
        StepCtx {
            core,
            host: &*self.host,
            tls: self.tls.as_deref(),
            clock: &*self.clock,
            poll: &*self.poll,
            wake,
            abort,
            cfg: &self.cfg,
            flavor,
            defer,
            gate,
        }
    }

    /// Makes the services of a resolution loop.
    pub(crate) fn resolve_ctx<'a>(
        &'a self,
        core: &'a Mutex<Core<T>>,
        flavor: Flavor,
    ) -> ResolveCtx<'a, T> {
        ResolveCtx {
            core,
            host: &*self.host,
            clock: &*self.clock,
            flavor,
        }
    }
}

/// Reads the connection under the `core` lock. It returns `None` after
/// the final close took the connection. Accessors such as `zoo_state`
/// use it.
pub(crate) fn read_conn<T: Tokens, R>(
    core: &Mutex<Core<T>>,
    proof: &mut Unlocked,
    f: impl FnOnce(&Connection<T>) -> R,
) -> Option<R> {
    core.lock(proof).conn.as_deref().map(f)
}

/// Reads the connection as [`read_conn`] does, at an API entry. The
/// caller holds no driver lock, so the helper makes the proof itself.
pub(crate) fn read_at_entry<T: Tokens, R>(
    core: &Mutex<Core<T>>,
    f: impl FnOnce(&Connection<T>) -> R,
) -> Option<R> {
    read_conn(core, &mut Unlocked::new_at_entry(), f)
}

/// Runs `f` on the connection under the `core` lock, at an API entry.
/// It returns `None` after the final close took the connection.
pub(crate) fn with_conn_at_entry<T: Tokens, R>(
    core: &Mutex<Core<T>>,
    now: Millis,
    f: impl FnOnce(&mut Connection<T>, Millis) -> R,
) -> Option<R> {
    let mut proof = Unlocked::new_at_entry();
    core.lock(&mut proof).conn.as_deref_mut().map(|c| f(c, now))
}

/// The answer of C to a SASL START or STEP item (`zkrs_sasl_result`).
///
/// zk-ffi copies the glue output into this value at once. The effects
/// come in the next resume, when `iocore` gives it to proto.
#[derive(Debug)]
pub enum SaslAnswer {
    /// The answer to START.
    Started {
        /// The generation of the START item.
        generation: u32,
        /// The mechanism name and the first step, or the error.
        result: Result<(String, SaslStep), SaslError>,
    },
    /// The answer to STEP.
    Stepped {
        /// The generation of the STEP item.
        generation: u32,
        /// The next step, or the error.
        result: Result<SaslStep, SaslError>,
    },
}

/// The value behind the `core` lock.
pub(crate) struct Core<T: Tokens> {
    /// The connection. `None` after the final close took it.
    pub(crate) conn: Option<Box<Connection<T>>>,
    /// The stopped stage of the last barrier. The next resume gives it
    /// to `Connection::resume`.
    pub(crate) stopped: Option<Stopped>,
    /// The items that a throwing callback left. The next
    /// driving call delivers them first.
    pub(crate) requeued: Option<Requeued<T>>,
    /// The st local FIFO. The other flavors leave it empty.
    pub(crate) local: VecDeque<Item<T>>,
    /// The peer address of the current transport, for `zkrs_peer_addr`.
    pub(crate) peer: Option<SocketAddr>,
    /// The SASL answer that the next resume gives to proto.
    pub(crate) sasl: Option<SaslAnswer>,
    /// A `set_servers` list that the IO side must resolve, with its
    /// resolver generation. Proto leaves this resolution to the driver.
    /// The native and tokio handles set it, and the next interest step
    /// takes it.
    pub(crate) set_servers: Option<(u64, Vec<HostSpec>)>,
    /// The drop-in `zoo_set_servers` calls that wait for a resume.
    pub(crate) set_servers_runs: Vec<SetServersRun>,
    /// The id of the next `zoo_set_servers` run.
    pub(crate) next_run_id: u64,
    /// A close stage that lost its resume, because a callback threw. The
    /// next close call of the application continues it.
    pub(crate) orphan_close: Option<ResumeAt>,
}

impl<T: Tokens> Core<T> {
    /// Wraps a new connection. The connection is on the heap, so the
    /// handles stay small and no stack frame holds a copy.
    pub(crate) fn new(conn: Box<Connection<T>>) -> Self {
        Self {
            conn: Some(conn),
            stopped: None,
            requeued: None,
            local: VecDeque::new(),
            peer: None,
            sasl: None,
            set_servers: None,
            set_servers_runs: Vec::new(),
            next_run_id: 0,
            orphan_close: None,
        }
    }
}

impl<T: Tokens> Core<T> {
    /// Pumps the proto outputs into `ob`, with the FIFO rule of the
    /// flavor.
    ///
    /// It returns true at a barrier. The step then returns `ZKRS_MORE`.
    /// The stopped stage, if any, goes to `stopped` for the next resume.
    /// With no connection it does nothing and returns false.
    pub(crate) fn pump(
        &mut self,
        flavor: Flavor,
        ob: &mut Outbox<T>,
        host: &dyn HostLeaves<T>,
    ) -> bool {
        let Some(conn) = self.conn.as_deref_mut() else {
            return false;
        };
        let bound = match flavor {
            Flavor::Mt => FifoBound::Publish,
            Flavor::St => FifoBound::Local(&mut self.local),
            Flavor::Native => FifoBound::Inline,
        };
        match pump(conn, ob, bound, host) {
            Pumped::Drained => false,
            Pumped::Barrier(stopped) => {
                if stopped.is_some() {
                    self.stopped = stopped;
                }
                true
            }
        }
    }

    /// Gives the stopped stage of the last barrier to proto. It
    /// does nothing when no stage is stopped.
    pub(crate) fn resume_stopped(&mut self, now: Millis) {
        if let (Some(conn), Some(stopped)) = (self.conn.as_deref_mut(), self.stopped.take()) {
            conn.resume(stopped, now);
        }
    }

    /// Submits a request to proto through `send`, one of the
    /// `Connection` submit entries. With no connection the submit fails
    /// at the validation stage with `code`.
    pub(crate) fn submit_or(
        &mut self,
        req: Request<T>,
        now: Millis,
        code: i32,
        send: impl FnOnce(&mut Connection<T>, Request<T>, Millis) -> SubmitResult<T>,
    ) -> SubmitResult<T> {
        match self.conn.as_deref_mut() {
            Some(conn) => send(conn, req, now),
            None => Err(SubmitError {
                stage: Stage::Validate,
                code,
                token: req.token,
            }),
        }
    }

    /// Records an auth entry in proto. With no connection the call fails
    /// with `code` and gives the completion token back.
    pub(crate) fn add_auth_or(
        &mut self,
        scheme: JString,
        cred: SecretBytes,
        done: Option<T::Auth>,
        now: Millis,
        code: i32,
    ) -> Result<(), AddAuthError<T>> {
        match self.conn.as_deref_mut() {
            Some(conn) => conn.add_auth(scheme, cred, done, now),
            None => Err(AddAuthError { code, done }),
        }
    }

    /// Gives a new host list of a native handle to proto. It returns the
    /// new resolver generation, or 0 with no connection.
    ///
    /// Proto does not resolve a `set_servers` list. The helper keeps the
    /// list in `Core::set_servers`, and the IO side resolves it as a job.
    pub(crate) fn set_servers_native(&mut self, hosts: Vec<HostSpec>, now: Millis) -> u64 {
        let generation = self
            .conn
            .as_deref_mut()
            .map_or(0, |conn| conn.set_servers(hosts.clone(), now));
        if generation != 0 {
            self.set_servers = Some((generation, hosts));
        }
        generation
    }

    /// Moves the requeued items to the front of `ob`. It
    /// returns true when items moved. The step then returns `ZKRS_MORE`
    /// before it does other work.
    pub(crate) fn restore_requeued(&mut self, ob: &mut Outbox<T>) -> bool {
        match self.requeued.take() {
            Some(r) if !r.is_empty() => {
                ob.restore(r);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TestHost, test_connection};
    use zk_proto::DriverMode;
    use zk_testkit::tokens::TestTokens;

    #[test]
    fn pump_of_a_new_core_has_no_barrier() {
        let host = TestHost::new();
        let mut core: Core<TestTokens> = Core::new(Box::new(test_connection(DriverMode::ST)));
        let mut ob = Outbox::new();
        assert!(!core.pump(Flavor::St, &mut ob, &host));
        assert!(!core.restore_requeued(&mut ob));
        core.resume_stopped(Millis(0));
        assert!(ob.is_empty());
    }
}
