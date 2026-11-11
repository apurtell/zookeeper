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

//! The connection state machine and its shared state.
//!
//! [`Connection`] is made of sub-state structs. Each struct belongs to one
//! module, and only that module changes its fields. The other modules call
//! the methods of the owning module. `IMPLEMENTATION_GUIDE.md` lists the
//! owners and the calls between them.

use crate::auth::AuthState;
use crate::close::CloseState;
use crate::compat::Compat;
use crate::config::{ClientId, Config, DriverMode};
use crate::hooks::{DefaultWatcher, LogFilter, Rng, Tokens};
use crate::hosts::Hosts;
use crate::interest::InterestState;
use crate::log::{LogArg, LogSite, Logger};
use crate::output::{Output, Outputs, Stopped, Work};
use crate::recv::Recv;
use crate::requests::Requests;
use crate::sasl::SaslState;
use crate::session::SessionState;
use crate::state::{Phase, State};
use crate::teardown::TeardownState;
use crate::time::Millis;
use crate::timers::Timers;
use crate::watches::Watches;
use core::fmt;
use zeroize::Zeroize;

/// The state that several modules read. The guide names the writer of
/// each field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Core {
    /// The visible state. Writers call `set_state`.
    pub(crate) state: State,
    /// The internal phase. The session, sasl and teardown modules write
    /// it.
    pub(crate) phase: Phase,
    /// The session identity. The session module writes it.
    pub(crate) client_id: ClientId,
    /// The session timeout T: the requested value, then the negotiated
    /// value.
    pub(crate) recv_timeout: i32,
    /// The largest zxid seen in a reply header. The recv module writes it.
    pub(crate) last_zxid: i64,
    /// True when a read-write server accepted the session id.
    pub(crate) seen_rw_before: bool,
    /// The errno that the shim sets after the call.
    pub(crate) errno_hint: Option<i32>,
    /// True while a transport exists.
    pub(crate) has_transport: bool,
    /// The transport epoch. Each new transport and each transport loss
    /// advance it.
    pub(crate) epoch: u64,
}

/// One ZooKeeper connection: the deterministic protocol core.
///
/// The driver owns the I/O, the clock and the threads. It calls the
/// methods of this type under its lock and acts on the actions and
/// outputs that come back.
pub struct Connection<T: Tokens> {
    pub(crate) cfg: Config,
    pub(crate) compat: Compat,
    pub(crate) mode: DriverMode,
    pub(crate) rng: Box<dyn Rng>,
    pub(crate) default_watcher: Box<dyn DefaultWatcher<T::Watcher>>,
    pub(crate) log: Logger,
    pub(crate) out: Outputs<T>,
    pub(crate) core: Core,
    pub(crate) requests: Requests<T>,
    pub(crate) recv: Recv,
    pub(crate) watches: Watches<T::Watcher>,
    pub(crate) auth: AuthState<T>,
    pub(crate) sasl: SaslState,
    pub(crate) hosts: Hosts,
    pub(crate) timers: Timers,
    pub(crate) interest: InterestState,
    pub(crate) session: SessionState,
    pub(crate) teardown: TeardownState<T>,
    pub(crate) close: CloseState,
}

/// Every token and output that a connection still holds when it is
/// dropped.
pub struct Leftovers<T: Tokens> {
    /// The completions that never left the core, oldest first.
    pub completions: Vec<T::Completion>,
    /// The auth tokens that never left the core, in list order.
    pub auth: Vec<T::Auth>,
    /// The outputs that the driver did not pop.
    pub outputs: Vec<Output<T>>,
}

impl<T: Tokens> fmt::Debug for Leftovers<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leftovers")
            .field("completions", &self.completions.len())
            .field("auth", &self.auth.len())
            .field("outputs", &self.outputs)
            .finish()
    }
}

impl<T: Tokens> fmt::Debug for Connection<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("state", &self.core.state)
            .field("phase", &self.core.phase)
            .field("client_id", &self.core.client_id)
            .field("pending", &self.requests.fifo.len())
            .field("outputs", &self.out)
            .finish_non_exhaustive()
    }
}

/// The connection wipes the session password copies that it holds when
/// it ends. `ClientId` is `Copy`, so other copies can exist. The owners
/// of those copies wipe them.
impl<T: Tokens> Drop for Connection<T> {
    fn drop(&mut self) {
        self.core.client_id.passwd.zeroize();
        self.cfg.client_id.passwd.zeroize();
    }
}

impl<T: Tokens> Connection<T> {
    /// Makes a connection in state 999 with no transport.
    ///
    /// The first `poll_action` yields `Action::Resolve{initial: true}`.
    #[must_use]
    pub fn new(
        cfg: Config,
        compat: Compat,
        mode: DriverMode,
        rng: Box<dyn Rng>,
        log: Box<dyn LogFilter>,
        default_watcher: Box<dyn DefaultWatcher<T::Watcher>>,
        now: Millis,
    ) -> Self {
        let core = Core {
            state: State::NotConnected,
            phase: Phase::Idle,
            client_id: cfg.client_id,
            recv_timeout: cfg.timeout_ms,
            last_zxid: 0,
            seen_rw_before: cfg.client_id.session_id != 0,
            errno_hint: None,
            has_transport: false,
            epoch: 0,
        };
        Self {
            requests: Requests::new(cfg.xid_seed),
            recv: Recv::new(compat.max_frame_len),
            watches: Watches::new(compat.watch_table, cfg.c_char_signed),
            auth: AuthState::new(),
            sasl: SaslState::new(),
            hosts: Hosts::new(cfg.hosts.clone(), cfg.resolve_delay_ms),
            timers: Timers::new(now),
            interest: InterestState::new(),
            session: SessionState::default(),
            teardown: TeardownState::new(),
            close: CloseState::default(),
            out: Outputs::new(),
            log: Logger::new(log),
            core,
            cfg,
            compat,
            mode,
            rng,
            default_watcher,
        }
    }

    /// Pops the next output.
    ///
    /// It returns `None` when nothing is queued, or right after a barrier
    /// output. After a barrier the driver calls [`Self::take_stopped`],
    /// delivers the barrier, and then calls [`Self::resume`].
    pub fn poll_output(&mut self) -> Option<Output<T>> {
        self.out.poll()
    }

    /// Returns true when the next [`Self::poll_output`] gives an output
    /// or stops a stage. It is false while the handle of a stopped stage
    /// waits for [`Self::take_stopped`].
    #[must_use]
    pub fn has_output(&self) -> bool {
        self.out.has_output()
    }

    /// Takes the handle of the stage that stopped at the last popped
    /// barrier. Then `poll_output` continues with the outputs of other
    /// calls.
    pub fn take_stopped(&mut self) -> Option<Stopped> {
        self.out.take_stopped()
    }

    /// Continues a stopped stage.
    ///
    /// An unknown handle, or a handle after `destroy`, does nothing.
    pub fn resume(&mut self, work: Stopped, now: Millis) {
        let Some(job) = self.out.take_suspended(work) else {
            return;
        };
        match job {
            Work::Hold => {}
            Work::Teardown(j) => self.continue_teardown(j, now),
            Work::Close(j) => self.continue_close(j, now),
            Work::AuthReply(j) => self.continue_auth_reply(j, now),
            Work::Finalize(j) => self.continue_finalize(j, now),
        }
    }

    /// Returns the visible state.
    #[must_use]
    pub fn state(&self) -> State {
        self.core.state
    }

    /// Returns the session timeout: the negotiated value after a
    /// handshake, else the requested value.
    #[must_use]
    pub fn recv_timeout(&self) -> i32 {
        self.core.recv_timeout
    }

    /// Returns the session identity.
    #[must_use]
    pub fn client_id(&self) -> ClientId {
        self.core.client_id
    }

    /// Returns the largest zxid seen in a reply header.
    #[must_use]
    pub fn last_zxid(&self) -> i64 {
        self.core.last_zxid
    }

    /// Returns true while a transport exists.
    #[must_use]
    pub fn has_transport(&self) -> bool {
        self.core.has_transport
    }

    /// Returns true while a stage is stopped at a barrier or parked.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        self.out.is_suspended()
    }

    /// Takes the errno that the shim sets after the call.
    pub fn take_errno_hint(&mut self) -> Option<i32> {
        self.core.errno_hint.take()
    }

    /// Moves out every token that never left the core, and the outputs
    /// that the driver did not pop.
    ///
    /// The order of completions is: stopped stages, the forced-close
    /// snapshot, then the FIFO.
    #[must_use]
    pub fn into_leftovers(mut self) -> Leftovers<T> {
        let mut completions = Vec::new();
        let mut auth = Vec::new();
        let (outputs, works) = core::mem::replace(&mut self.out, Outputs::new()).into_parts();
        for w in works {
            let (c, a) = w.into_tokens();
            completions.extend(c);
            auth.extend(a);
        }
        if let Some(snap) = self.teardown.forced.take() {
            let (c, a) = snap.into_tokens();
            completions.extend(c);
            auth.extend(a);
        }
        completions.extend(self.requests.fifo.drain(..).map(|p| p.token));
        auth.extend(self.auth.take_tokens());
        Leftovers {
            completions,
            auth,
            outputs,
        }
    }

    /// Sets the visible state.
    pub(crate) fn set_state(&mut self, state: State) {
        self.core.state = state;
    }

    /// Sets the errno hint of the call.
    pub(crate) fn set_errno_hint(&mut self, errno: i32) {
        self.core.errno_hint = Some(errno);
    }

    /// Opens a transport and returns its new epoch.
    pub(crate) fn open_transport(&mut self) -> u64 {
        // A lent frame has no bytes to send again. The teardown drops it
        // before a new transport opens (see `Requests::clear_pins`).
        // Production code never panics, so only the tests check this.
        #[cfg(test)]
        assert!(
            !self.requests.tx.iter().any(|f| f.is_lent()),
            "a lent frame outlives its transport"
        );
        self.core.has_transport = true;
        self.core.epoch = self.core.epoch.wrapping_add(1);
        self.core.epoch
    }

    /// Marks the transport lost and advances the epoch.
    pub(crate) fn lose_transport(&mut self) {
        self.core.has_transport = false;
        self.core.epoch = self.core.epoch.wrapping_add(1);
    }

    /// Pushes a log output for the site when the filter enables it. The
    /// closure runs only in that case.
    pub(crate) fn emit_log<F>(&mut self, site: LogSite, args: F)
    where
        F: FnOnce() -> Vec<LogArg>,
    {
        let record = self.log.record(site, args);
        self.out.push_log(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::{AllLevels, NoDefaultWatcher};

    struct Tk;
    impl Tokens for Tk {
        type Completion = u32;
        type Watcher = u32;
        type Auth = u32;
    }

    struct FixedRng;
    impl Rng for FixedRng {
        fn on_resolution(&mut self) {}
        fn random(&mut self) -> i64 {
            0
        }
        fn drand48(&mut self) -> f64 {
            0.0
        }
    }

    #[test]
    fn new_connection_is_idle() {
        let conn: Connection<Tk> = Connection::new(
            Config::legacy(30_000),
            Compat::LEGACY_C,
            DriverMode::ST,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(NoDefaultWatcher),
            Millis(0),
        );
        assert_eq!(conn.state(), State::NotConnected);
        assert_eq!(conn.recv_timeout(), 30_000);
        assert!(!conn.has_transport());
        assert!(!conn.is_suspended());
        assert_eq!(conn.pending_len(), 0);
        assert!(conn.hosts.initial && conn.hosts.resolve_due);
        let left = conn.into_leftovers();
        assert!(left.completions.is_empty() && left.auth.is_empty() && left.outputs.is_empty());
    }
}
