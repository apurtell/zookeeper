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

//! The staged teardown and the forced close.
//!
//! The module owns [`TeardownState`]. A teardown runs stages T0 to T6 and
//! stops after each barrier. A forced close takes a
//! snapshot at its trigger and runs the remaining stages later.

use std::collections::VecDeque;

use crate::action::{TlsConfigStep, TlsResourceAt, TransportFailure};
use crate::connection::Connection;
use crate::errno;
use crate::hooks::Tokens;
use crate::log::{LogArg, LogSite};
use crate::output::{Output, TerminateReason, Work};
use crate::rc;
use crate::requests::{OutFrame, Pending};
use crate::state::{Cause, Phase, State};
use crate::time::{Millis, until};
use zk_jute::JString;

/// The next stage of a teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TeardownStage {
    /// T2: the session event.
    Session,
    /// T3: take the snapshot. A normal job takes `tx` and the FIFO as they
    /// stand now. A forced job takes the snapshot of its trigger.
    Snapshot,
    /// T3: fail the snapshot entries. The job holds the entries left.
    FailFifo,
    /// T3: the auth lock point.
    Lockpoint,
    /// T3: the auth completions.
    Auth,
    /// T4 to T6.
    Finish,
}

/// A teardown that runs or stopped at a barrier.
pub(crate) struct TeardownJob<T: Tokens> {
    /// The cause.
    pub(crate) cause: Cause,
    /// The next stage.
    pub(crate) stage: TeardownStage,
    /// True when the state was 3 or 5 when the teardown started.
    pub(crate) connected: bool,
    /// The FIFO entries left to fail, once T3 took its snapshot.
    pub(crate) entries: VecDeque<Pending<T>>,
    /// The auth tokens of a forced-close snapshot, in list order.
    pub(crate) auth: Vec<T::Auth>,
    /// The rc for pending work, from `Cause::rc_for`.
    pub(crate) rc: i32,
    /// True for the remaining stages of a forced close.
    pub(crate) forced: bool,
}

impl<T: Tokens> TeardownJob<T> {
    /// Moves every token out of the job.
    pub(crate) fn into_tokens(self) -> (Vec<T::Completion>, Vec<T::Auth>) {
        (
            self.entries.into_iter().map(|p| p.token).collect(),
            self.auth,
        )
    }
}

/// The work that a forced close took at its trigger.
pub(crate) struct ForcedSnapshot<T: Tokens> {
    /// True when the state was 3 or 5 at the trigger.
    pub(crate) connected: bool,
    /// The frames of the closed connection. They are never sent.
    pub(crate) tx: VecDeque<OutFrame>,
    /// The FIFO entries of the closed connection.
    pub(crate) fifo: VecDeque<Pending<T>>,
    /// The auth tokens, in list order. The entries stay in the list.
    pub(crate) auth: Vec<T::Auth>,
}

impl<T: Tokens> ForcedSnapshot<T> {
    /// Moves every token out of the snapshot.
    pub(crate) fn into_tokens(self) -> (Vec<T::Completion>, Vec<T::Auth>) {
        (self.fifo.into_iter().map(|p| p.token).collect(), self.auth)
    }
}

/// The teardown state of one connection.
pub(crate) struct TeardownState<T: Tokens> {
    /// The snapshot of a forced close whose stages did not run yet.
    pub(crate) forced: Option<ForcedSnapshot<T>>,
    /// The cause of the most recent teardown.
    pub(crate) last_cause: Option<Cause>,
    /// The OS errno of the most recent teardown, when it has one.
    pub(crate) last_errno: Option<i32>,
    /// True while the job of a forced close runs and has not reached T3.
    /// The snapshot stays in `forced` until T3, so a close from the T2
    /// callback can take it.
    forced_started: bool,
    /// True from the start of T3 until the teardown ends. A close in
    /// this window waits, so the teardown fails its snapshot first.
    t3_started: bool,
    /// The test seam: when set, the calls to other modules are recorded
    /// here and a simple model replaces them.
    #[cfg(test)]
    pub(crate) stub: Option<Vec<PeerCall>>,
}

impl<T: Tokens> TeardownState<T> {
    /// Makes a state with no teardown.
    pub(crate) fn new() -> Self {
        Self {
            forced: None,
            last_cause: None,
            last_errno: None,
            forced_started: false,
            t3_started: false,
            #[cfg(test)]
            stub: None,
        }
    }
}

/// A call from this module to a function of another module. The test
/// seam records it.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PeerCall {
    /// `session_watchers`.
    SessionWatchers,
    /// `queue_set_watches`.
    QueueSetWatches,
    /// `queue_auth_resend`.
    QueueAuthResend,
    /// `begin_sasl`.
    BeginSasl,
    /// `sasl_on_teardown`.
    SaslOnTeardown,
    /// `sasl_on_destroy`.
    SaslOnDestroy,
    /// `hosts_on_handle_error` or `hosts_on_session_lost`.
    HostsOnHandleError,
    /// `clear_watches` with its reason.
    ClearWatches(TerminateReason),
    /// `fail_pending_run` with its rc.
    FailPendingRun(i32),
    /// `request_frame` with its xid and operation.
    RequestFrame(i32, i32),
}

/// The T0 line of a teardown: a site in `handle_socket_error_msg` form.
pub(crate) struct T0Line {
    /// The site.
    site: LogSite,
    /// The errno that the line prints.
    errno: i32,
    /// The arguments that follow the four common arguments.
    extra: Vec<LogArg>,
}

impl T0Line {
    /// Makes a line with no extra argument.
    pub(crate) fn new(site: LogSite, errno: i32) -> Self {
        Self {
            site,
            errno,
            extra: Vec::new(),
        }
    }

    /// Makes a line with extra arguments.
    pub(crate) fn with(site: LogSite, errno: i32, extra: Vec<LogArg>) -> Self {
        Self { site, errno, extra }
    }
}

/// Returns the bit pattern of a session id for a `%#llx` argument.
pub(crate) fn session_id_arg(id: i64) -> LogArg {
    LogArg::Ptr(u64::from_ne_bytes(id.to_ne_bytes()))
}

impl<T: Tokens> Connection<T> {
    /// Takes a transport failure from the driver.
    ///
    /// Contract:
    /// - `TlsConfig` logs its site, sets the errno hint `EINVAL`, sets
    ///   phase TlsConfigFailed and returns `ZSSLCONNECTIONERROR`. It is not
    ///   a teardown.
    /// - `Poll` returns `ZSYSTEMERROR` with no teardown (close flush).
    /// - Every other variant maps to its `Cause` and starts `teardown`
    ///   with the errno for the T0 line. It returns the teardown rc.
    /// - With no transport it returns `ZOK` and does nothing.
    /// - After `destroy` it returns `ZOK` and does nothing. The destroy
    ///   already failed all work, and no stage may stop after it.
    ///
    /// `SocketCreate` and `TcpRefused` are the exception to the last rule.
    /// The driver reports them before `handle_connect_started`, when no
    /// transport exists, and C runs `handle_socket_error_msg` for them
    /// (zookeeper.c:2681-2711).
    pub fn handle_transport_failed(&mut self, f: TransportFailure, now: Millis) -> i32 {
        if self.close.destroyed {
            return rc::ZOK;
        }
        // `teardown` makes the default T0 line of each failure. Only a TLS
        // resource failure gives a different line.
        match f {
            TransportFailure::SocketCreate { errno } => {
                self.teardown(Cause::SocketCreate, errno, now)
            }
            TransportFailure::TcpRefused { errno } => {
                self.teardown(Cause::ConnectFailed, errno, now)
            }
            _ if !self.core.has_transport => rc::ZOK,
            TransportFailure::Io { errno } => self.teardown(Cause::Io, errno, now),
            TransportFailure::Eof => self.teardown(Cause::Eof, errno::EHOSTDOWN, now),
            TransportFailure::TlsResource { at, errno } => {
                let site = match at {
                    TlsResourceAt::ContextNew => {
                        self.emit_log(LogSite::TlsContextNew, Vec::new);
                        LogSite::SockTlsContextNew
                    }
                    TlsResourceAt::ConnectionNew => LogSite::SockTlsConnectionNew,
                };
                self.teardown_with_line(Cause::Tls, Some(T0Line::new(site, errno)), now)
            }
            TransportFailure::TlsHandshake { errno } => self.teardown(Cause::Tls, errno, now),
            TransportFailure::TlsConfig { step, file } => {
                self.tls_config_failed(step, file);
                self.core.phase = Phase::TlsConfigFailed;
                rc::ZSSLCONNECTIONERROR
            }
            TransportFailure::Poll { .. } => rc::ZSYSTEMERROR,
        }
    }

    /// Logs the site of a failed TLS configuration step and sets the
    /// errno hint `EINVAL`. The connect and the read-only probe use one
    /// rule, so the two failures give the same log and errno.
    pub(crate) fn tls_config_failed(&mut self, step: TlsConfigStep, file: JString) {
        let (site, with_file) = match step {
            TlsConfigStep::CaFile => (LogSite::TlsCaFile, true),
            TlsConfigStep::DefaultVerifyPaths => (LogSite::TlsDefaultVerifyPaths, false),
            TlsConfigStep::ClientCertChain => (LogSite::TlsClientCertChain, true),
            TlsConfigStep::ClientKey => (LogSite::TlsClientKey, true),
            TlsConfigStep::CheckPrivateKey => (LogSite::TlsCheckPrivateKey, false),
        };
        self.emit_log(site, || {
            if with_file {
                vec![LogArg::Str(file)]
            } else {
                Vec::new()
            }
        });
        self.set_errno_hint(errno::EINVAL);
    }

    /// Runs a forced close trigger from the single-threaded submit flush.
    ///
    /// Contract: the same as `forced_close_trigger`.
    pub fn handle_forced_close(&mut self, now: Millis) {
        self.forced_close_trigger(now);
    }

    /// Runs the remaining stages of a forced close, if they are pending.
    ///
    /// Contract: while a stage is
    /// suspended it returns false and runs nothing. Otherwise it takes the
    /// snapshot, starts a `Cause::ForcedClose` job with no T0 line, and
    /// returns true. The snapshot frames are dropped.
    ///
    /// After `begin_close` it does nothing, because the close fails the
    /// snapshot. The job takes the snapshot at T3, not here, so that a
    /// close from the T2 callback finds it.
    pub fn run_pending_teardown(&mut self, now: Millis) -> bool {
        if self.out.is_suspended() || self.close.closing || self.teardown.forced_started {
            return false;
        }
        let Some(connected) = self.teardown.forced.as_ref().map(|s| s.connected) else {
            return false;
        };
        self.teardown.forced_started = true;
        let cause = Cause::ForcedClose;
        let rc = cause.rc_for(self.compat.disconnect_rc);
        self.teardown_start_job(cause, connected, None, rc, true, now);
        true
    }

    /// Returns the cause of the most recent teardown.
    #[must_use]
    pub fn last_teardown_cause(&self) -> Option<Cause> {
        self.teardown.last_cause
    }

    /// Returns the errno of the most recent teardown, or `None` when it
    /// had no errno. The driver gives the value of the OS. Only the
    /// `ConnectFailed`, `Io` and `SocketCreate` causes always carry the
    /// value of the OS.
    #[must_use]
    pub fn last_teardown_errno(&self) -> Option<i32> {
        self.teardown.last_errno
    }

    /// Starts a teardown and returns its rc.
    ///
    /// Contract:
    /// - T0: the trigger ERROR line in `handle_socket_error_msg` form, with
    ///   `errno`. The causes that the table exempts log nothing.
    /// - T1: `queue_close_transport`, `sasl_on_teardown`, `recv.reset`,
    ///   `requests.clear_pins`, phase Idle, no transport, a new epoch.
    /// - Then the job runs through `continue_teardown`.
    /// - It records `last_cause`. The rc is
    ///   `cause.rc_for(compat.disconnect_rc)`, and `RwServerFound` uses
    ///   `ZCONNECTIONLOSS`.
    ///
    /// The T0 arguments that `errno` does not carry come from the core
    /// state. A caller that knows them uses `teardown_with_line`.
    pub(crate) fn teardown(&mut self, cause: Cause, errno: i32, now: Millis) -> i32 {
        let line = self.teardown_default_line(cause, errno, now);
        self.teardown_with_line(cause, line, now)
    }

    /// Runs teardown stages from `job.stage` until the end or a barrier.
    ///
    /// Contract:
    /// - T2: `Session{state}` for `state < 0`, else `Session{Connecting}`
    ///   when connected. Natively, a failed attempt that is not a forced
    ///   close also gives `Session{Connecting}`. A barrier parks the job.
    /// - T3: take `tx` and the FIFO as they stand now (a forced job uses
    ///   its own entries). Drop the frames. `fail_pending_run` the entries,
    ///   parking the job after each Direct run. Then `AuthLockpoint` when
    ///   lock points are on, then `Auth{tokens, rc, barrier}`.
    /// - T4: the "Previous connection" DEBUG line, `state = 0` when
    ///   `state >= 0` (a forced job keeps 999), then `DrainPoint`.
    /// - T5: `hosts_on_handle_error` for the causes that run it, or
    ///   `hosts_on_session_lost` when the job ends a session.
    /// - T6: nothing more.
    pub(crate) fn continue_teardown(&mut self, mut job: TeardownJob<T>, now: Millis) {
        loop {
            match job.stage {
                TeardownStage::Session => {
                    job.stage = TeardownStage::Snapshot;
                    if self.teardown_session_event(job.connected, job.forced) {
                        self.out.park(Work::Teardown(job));
                        return;
                    }
                }
                TeardownStage::Snapshot => {
                    job.stage = TeardownStage::FailFifo;
                    self.teardown.t3_started = true;
                    if job.forced {
                        self.teardown.forced_started = false;
                        if let Some(snap) = self.teardown.forced.take() {
                            let ForcedSnapshot { fifo, auth, .. } = snap;
                            job.entries = fifo;
                            job.auth = auth;
                        }
                    } else {
                        let (_tx, fifo) = self.requests.take_all();
                        job.entries = fifo;
                    }
                }
                TeardownStage::FailFifo => {
                    if !job.entries.is_empty() {
                        let mut entries = core::mem::take(&mut job.entries);
                        let stopped = self.teardown_peer_fail_pending_run(&mut entries, job.rc);
                        job.entries = entries;
                        if stopped {
                            self.out.park(Work::Teardown(job));
                            return;
                        }
                    }
                    job.stage = TeardownStage::Lockpoint;
                }
                TeardownStage::Lockpoint => {
                    job.stage = TeardownStage::Auth;
                    if self.compat.emits_lockpoints() {
                        self.out.push(Output::AuthLockpoint);
                        self.out.park(Work::Teardown(job));
                        return;
                    }
                }
                TeardownStage::Auth => {
                    job.stage = TeardownStage::Finish;
                    let mut tokens = core::mem::take(&mut job.auth);
                    if !job.forced {
                        tokens.extend(self.auth.take_tokens());
                    }
                    if !tokens.is_empty() {
                        let barrier = self.compat.emits_lockpoints();
                        self.out.push(Output::Auth {
                            tokens,
                            rc: job.rc,
                            barrier,
                        });
                        if barrier {
                            self.out.park(Work::Teardown(job));
                            return;
                        }
                    }
                }
                TeardownStage::Finish => {
                    self.teardown_finish(&job, now);
                    self.teardown.t3_started = false;
                    // A close that came during T3 runs now, after the
                    // snapshot of this teardown completed.
                    self.close_run_deferred(now);
                    return;
                }
            }
        }
    }

    /// Runs a forced close trigger.
    ///
    /// Contract: with no transport it does nothing. Otherwise it records
    /// `connected`, sets state 999 and phase Idle, runs T1, and moves `tx`,
    /// the FIFO and the auth tokens into `teardown.forced`. It pushes no
    /// output other than logs.
    pub(crate) fn forced_close_trigger(&mut self, _now: Millis) {
        if !self.core.has_transport {
            return;
        }
        let connected = self.core.state.is_connected();
        self.set_state(State::NotConnected);
        self.teardown_t1();
        let (tx, fifo) = self.requests.take_all();
        let auth = self.auth.take_tokens();
        // The design allows one snapshot only. A second snapshot can only
        // come from a driver that breaks the call order. The merge keeps
        // every token in that case.
        match self.teardown.forced.as_mut() {
            Some(snap) => {
                snap.tx.extend(tx);
                snap.fifo.extend(fifo);
                snap.auth.extend(auth);
            }
            None => {
                self.teardown.forced = Some(ForcedSnapshot {
                    connected,
                    tx,
                    fifo,
                    auth,
                });
            }
        }
    }

    /// Starts a teardown with a known T0 line and returns its rc.
    ///
    /// It runs T0 and T1 and then the job, as `teardown` does. `None`
    /// gives no T0 line. After `destroy` it only returns the rc.
    pub(crate) fn teardown_with_line(
        &mut self,
        cause: Cause,
        line: Option<T0Line>,
        now: Millis,
    ) -> i32 {
        let rc = cause.rc_for(self.compat.disconnect_rc);
        // A destroyed connection has no work to fail. A new job would stop
        // at a barrier that no driver can resume.
        if self.close.destroyed {
            return rc;
        }
        let errno = line.as_ref().map(|l| l.errno).filter(|&e| e != 0);
        if let Some(line) = line {
            self.teardown_t0(line, rc);
        }
        let connected = self.core.state.is_connected();
        self.teardown_t1();
        self.teardown_start_job(cause, connected, errno, rc, false, now);
        rc
    }

    /// Records the cause and the errno of a new teardown, and runs its
    /// job from stage T2.
    fn teardown_start_job(
        &mut self,
        cause: Cause,
        connected: bool,
        errno: Option<i32>,
        rc: i32,
        forced: bool,
        now: Millis,
    ) {
        self.teardown.last_cause = Some(cause);
        self.teardown.last_errno = errno;
        let job = TeardownJob {
            cause,
            stage: TeardownStage::Session,
            connected,
            entries: VecDeque::new(),
            auth: Vec::new(),
            rc,
            forced,
        };
        self.continue_teardown(job, now);
    }

    /// Starts an `XidMismatch` teardown with the two xids of the legacy
    /// line, in the order that C prints them: the reply xid first, then
    /// the xid of the FIFO head (zookeeper.c:3621-3624).
    pub(crate) fn teardown_xid_mismatch(
        &mut self,
        reply_xid: i32,
        head_xid: i32,
        errno: i32,
        now: Millis,
    ) -> i32 {
        let line = T0Line::with(
            LogSite::SockUnexpectedXid,
            errno,
            vec![
                LogArg::I64(i64::from(reply_xid)),
                LogArg::I64(i64::from(head_xid)),
            ],
        );
        self.teardown_with_line(Cause::XidMismatch, Some(line), now)
    }

    /// Returns true while a stopped teardown is in its T3 or later
    /// stages. `destroy` takes such a job, so the flag is false after it.
    pub(crate) fn teardown_t3_in_flight(&self) -> bool {
        self.teardown.t3_started && !self.close.destroyed
    }

    /// Takes the snapshot of a forced close for a close operation.
    pub(crate) fn teardown_take_forced(&mut self) -> Option<ForcedSnapshot<T>> {
        self.teardown.forced.take()
    }

    /// Runs stage T1: the transport closes and the connection state
    /// resets. The epoch always advances, so a stopped job of the old
    /// transport stops when it continues.
    pub(crate) fn teardown_t1(&mut self) {
        if self.core.has_transport {
            self.queue_close_transport();
        }
        self.teardown_peer_sasl_on_teardown();
        self.recv.reset();
        self.requests.clear_pins();
        self.core.phase = Phase::Idle;
        self.lose_transport();
        self.session = crate::session::SessionState::default();
    }

    /// Pushes the T0 line in `handle_socket_error_msg` form.
    fn teardown_t0(&mut self, line: T0Line, rc: i32) {
        let server = self.current_server();
        let T0Line { site, errno, extra } = line;
        self.emit_log(site, move || {
            let mut args = vec![
                LogArg::Endpoint(server),
                LogArg::I64(i64::from(rc)),
                LogArg::I64(i64::from(errno)),
                LogArg::ErrnoStr(errno),
            ];
            args.extend(extra);
            args
        });
    }

    /// Returns the T0 line of a cause when the caller gives only the
    /// errno. `AuthFailed`, `RwServerFound`, `SaslTeardown` and
    /// `ForcedClose` give `None`, because they have no line of this form.
    fn teardown_default_line(&self, cause: Cause, errno: i32, now: Millis) -> Option<T0Line> {
        let server = self.current_server();
        match cause {
            Cause::ConnectFailed => {
                let site = if !self.core.has_transport {
                    LogSite::SockConnectFailed
                } else if self.cfg.tls {
                    LogSite::SockRefusedTls
                } else {
                    LogSite::SockRefused
                };
                Some(T0Line::new(site, errno))
            }
            Cause::Io => Some(self.teardown_io_line(errno)),
            Cause::Eof | Cause::ProtocolError => Some(T0Line::new(LogSite::SockRecvFailed, errno)),
            Cause::SocketCreate => Some(T0Line::new(LogSite::SockSocketFailed, errno)),
            Cause::Tls => Some(T0Line::new(LogSite::SockTlsConnect, errno)),
            Cause::RecvTimeout => {
                // C prints -recv_to, with recv_to = T*2/3 - idle_recv.
                let exceeded = self.timers_recv_overdue_ms(now);
                Some(T0Line::with(
                    LogSite::SockTimedOut,
                    errno,
                    vec![LogArg::Endpoint(server), LogArg::I64(exceeded)],
                ))
            }
            Cause::TlsHandshakeTimeout => {
                let exceeded = match self.core.phase {
                    Phase::TlsHandshaking { deadline } => until(now, deadline).saturating_neg(),
                    _ => 0,
                };
                Some(T0Line::with(
                    LogSite::SockTimedOut,
                    errno,
                    vec![LogArg::Endpoint(server), LogArg::I64(exceeded)],
                ))
            }
            Cause::XidMismatch => {
                let head = self.requests.fifo.front().map_or(0, |p| p.xid);
                Some(T0Line::with(
                    LogSite::SockUnexpectedXid,
                    errno,
                    vec![LogArg::I64(0), LogArg::I64(i64::from(head))],
                ))
            }
            Cause::SessionExpired => Some(T0Line::with(
                LogSite::SockSessionExpired,
                errno,
                vec![session_id_arg(self.core.client_id.session_id)],
            )),
            Cause::AuthFailed | Cause::RwServerFound | Cause::SaslTeardown | Cause::ForcedClose => {
                None
            }
        }
    }

    /// Returns the T0 line of an I/O failure.
    ///
    /// `TransportFailure::Io` does not say whether a read or a write
    /// failed. The site comes from the core state: an unsent `Connect`
    /// frame gives the handshake send site, bytes that wait for their
    /// acknowledgement give the flush site, and otherwise the receive site.
    fn teardown_io_line(&self, errno: i32) -> T0Line {
        if self.session.handshake_pending && !self.session.connect_sent {
            T0Line::with(
                LogSite::SockHandshakeSend,
                errno,
                vec![LogArg::ErrnoStr(errno)],
            )
        } else if self.requests.unacked > 0 {
            T0Line::new(LogSite::SockFlushFailed, errno)
        } else {
            T0Line::new(LogSite::SockRecvFailed, errno)
        }
    }

    /// Runs stage T2 and returns true when its output is a barrier.
    fn teardown_session_event(&mut self, connected: bool, forced: bool) -> bool {
        let state = self.core.state;
        if state.is_unrecoverable() {
            let name = state.c_name();
            self.emit_log(LogSite::CleanupSessionState, || {
                vec![crate::log::str_arg(name.as_bytes())]
            });
            self.emit_session(state, Vec::new())
        } else if connected {
            self.emit_log(LogSite::CleanupSessionConnecting, Vec::new);
            self.emit_session(State::Connecting, Vec::new())
        } else if !forced && !self.compat.session_fanout_to_path_watchers {
            // Natively, session events go only to the state watcher. A
            // failed attempt then also gives `Connecting`, so the client
            // can record the cause while it retries. C gives
            // no event here. A forced close is not a retry, so it gives
            // no event.
            self.emit_session(State::Connecting, Vec::new())
        } else {
            false
        }
    }

    /// Runs stages T4 to T6.
    fn teardown_finish(&mut self, job: &TeardownJob<T>, now: Millis) {
        let server = self.current_server();
        let delay = self.hosts.delay;
        self.emit_log(LogSite::CleanupPrevious, || {
            vec![LogArg::Endpoint(server), LogArg::I64(i64::from(delay))]
        });
        if !job.forced && self.core.state.code() >= 0 {
            self.set_state(State::Closed);
        }
        self.out.push(Output::DrainPoint);
        if job.cause.runs_handle_error() {
            self.teardown_peer_hosts_on_handle_error(job.connected, now);
        }
        // T6: the cause selects the reason that ends the watches.
        // `clear_watches` applies the profile rules: expiry and
        // auth failure clear under `clear_watches_on_expiry`, and a plain
        // disconnect clears only when `restore_watches` is false.
        let reason = match job.cause {
            Cause::SessionExpired => TerminateReason::SessionExpired,
            Cause::AuthFailed | Cause::SaslTeardown => TerminateReason::AuthFailed,
            _ => TerminateReason::ConnectionLost,
        };
        self.teardown_peer_clear_watches(reason);
    }

    // The calls to other modules go through these wrappers. In a unit
    // test with the seam set, a wrapper records the call and runs a simple
    // model. Thus a teardown test stays independent of those modules.

    /// Calls `session_watchers`.
    pub(crate) fn teardown_peer_session_watchers(&mut self) -> Vec<T::Watcher> {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::SessionWatchers);
                return self.default_watcher.snapshot().into_iter().collect();
            }
        }
        self.session_watchers()
    }

    /// Calls `queue_set_watches`.
    pub(crate) fn teardown_peer_queue_set_watches(&mut self) {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::QueueSetWatches);
                return;
            }
        }
        self.queue_set_watches();
    }

    /// Calls `queue_auth_resend`.
    pub(crate) fn teardown_peer_queue_auth_resend(&mut self) {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::QueueAuthResend);
                return;
            }
        }
        self.queue_auth_resend();
    }

    /// Calls `begin_sasl`.
    pub(crate) fn teardown_peer_begin_sasl(&mut self, now: Millis) {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::BeginSasl);
                self.core.phase = Phase::Sasl(crate::state::SaslNegotiation::default());
                return;
            }
        }
        self.begin_sasl(now);
    }

    /// Calls `sasl_on_teardown`.
    pub(crate) fn teardown_peer_sasl_on_teardown(&mut self) {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::SaslOnTeardown);
                return;
            }
        }
        self.sasl_on_teardown();
    }

    /// Calls `sasl_on_destroy`.
    pub(crate) fn teardown_peer_sasl_on_destroy(&mut self) {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::SaslOnDestroy);
                return;
            }
        }
        self.sasl_on_destroy();
    }

    /// Calls `hosts_on_session_lost` when the teardown ends an established
    /// session, else `hosts_on_handle_error`.
    pub(crate) fn teardown_peer_hosts_on_handle_error(&mut self, connected: bool, now: Millis) {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::HostsOnHandleError);
                return;
            }
        }
        if connected {
            self.hosts_on_session_lost(now);
        } else {
            self.hosts_on_handle_error(now);
        }
    }

    /// Calls `clear_watches`.
    pub(crate) fn teardown_peer_clear_watches(&mut self, reason: TerminateReason) {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::ClearWatches(reason));
                return;
            }
        }
        self.clear_watches(reason);
    }

    /// Calls `fail_pending_run`. The model fails the entries up to the
    /// last Direct entry, as the contract of `fail_pending_run` says.
    pub(crate) fn teardown_peer_fail_pending_run(
        &mut self,
        entries: &mut VecDeque<Pending<T>>,
        rc: i32,
    ) -> bool {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::FailPendingRun(rc));
                let last_direct = entries
                    .iter()
                    .rposition(|p| p.route == crate::request::Route::Direct);
                let count = last_direct.map_or(entries.len(), |i| i.saturating_add(1));
                for _ in 0..count {
                    if let Some(p) = entries.pop_front() {
                        self.out.push(Output::Completion {
                            token: p.token,
                            route: p.route,
                            result: crate::output::OpResult::teardown(rc),
                            delivery_logs: Vec::new(),
                        });
                    }
                }
                return last_direct.is_some();
            }
        }
        self.fail_pending_run(entries, rc)
    }

    /// Calls `request_frame`. The model writes the length prefix, the xid,
    /// the operation and the body.
    pub(crate) fn teardown_peer_request_frame(
        &mut self,
        xid: i32,
        op_type: i32,
        body: &[u8],
    ) -> Vec<u8> {
        #[cfg(test)]
        {
            if let Some(calls) = self.teardown.stub.as_mut() {
                calls.push(PeerCall::RequestFrame(xid, op_type));
                let len = i32::try_from(body.len().saturating_add(8)).unwrap_or(i32::MAX);
                let mut out = Vec::new();
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&xid.to_be_bytes());
                out.extend_from_slice(&op_type.to_be_bytes());
                out.extend_from_slice(body);
                return out;
            }
        }
        Self::request_frame(xid, op_type, body)
    }
}

/// Shared helpers for the unit tests of the session, close, teardown
/// and auth modules.
#[cfg(test)]
pub(crate) mod test_support {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use zk_jute::JString;

    use super::PeerCall;
    use crate::action::ConnectStart;
    use crate::auth::AuthEntry;
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::connection::Connection;
    use crate::hooks::{AllLevels, DefaultWatcher, Rng, Tokens};
    use crate::log::LogSite;
    use crate::output::{Output, TerminateReason};
    use crate::request::Route;
    use crate::requests::{Pending, Shape};
    use crate::secret::SecretBytes;
    use crate::time::Millis;

    /// The tokens of the tests.
    pub(crate) struct Tk;
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

    /// The default watcher of the tests.
    pub(crate) const DEFAULT_WATCHER: u32 = 7;

    struct Dw;
    impl DefaultWatcher<u32> for Dw {
        fn snapshot(&self) -> Option<u32> {
            Some(DEFAULT_WATCHER)
        }
    }

    /// Makes a connection with the test seam set.
    pub(crate) fn conn_with(cfg: Config, compat: Compat, mode: DriverMode) -> Connection<Tk> {
        let mut c = Connection::new(
            cfg,
            compat,
            mode,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(Dw),
            Millis(0),
        );
        c.teardown.stub = Some(Vec::new());
        c
    }

    /// Makes a connection with the default test config.
    pub(crate) fn conn(compat: Compat, mode: DriverMode) -> Connection<Tk> {
        conn_with(Config::legacy(30_000), compat, mode)
    }

    /// Makes a FIFO entry.
    pub(crate) fn pend(xid: i32, route: Route, token: u32) -> Pending<Tk> {
        Pending {
            xid,
            shape: Shape::Void,
            route,
            token,
            watch: None,
            unwatch: None,
            written: true,
        }
    }

    /// Adds an auth entry that holds a token.
    pub(crate) fn add_auth(c: &mut Connection<Tk>, token: u32) {
        c.auth.list.push(AuthEntry {
            scheme: JString::Bytes(b"digest".to_vec()),
            cred: SecretBytes::new(b"u:p".to_vec()),
            done: Some(token),
        });
    }

    /// Builds a 37-byte `ConnectResponse` body.
    pub(crate) fn response(timeout: i32, session_id: i64, read_only: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&timeout.to_be_bytes());
        b.extend_from_slice(&session_id.to_be_bytes());
        b.extend_from_slice(&16i32.to_be_bytes());
        b.extend_from_slice(&[0xAB; 16]);
        b.push(u8::from(read_only));
        b
    }

    /// Runs the connect inputs of an `InProgress` connect with no TLS.
    pub(crate) fn connect(c: &mut Connection<Tk>, now: Millis) {
        c.handle_connect_started(ConnectStart::InProgress, now);
        c.handle_tcp_connected(now);
        c.handle_transport_ready(now);
        c.on_connect_sent();
    }

    /// Connects, takes a response for session 0x55, and drains.
    pub(crate) fn establish(c: &mut Connection<Tk>, now: Millis) {
        connect(c, now);
        let body = response(30_000, 0x55, false);
        let _ = c.on_connect_response(&body, now);
        let _ = drain(c, now);
        let _ = calls(c);
    }

    /// One output, in a form that tests can compare.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum Ev {
        /// A log line.
        Log(LogSite),
        /// A session event: state, barrier, watchers.
        Session(i32, bool, Vec<u32>),
        /// A completion: token, rc, direct.
        Done(u32, i32, bool),
        /// An auth completion: tokens, rc, barrier.
        Auth(Vec<u32>, i32, bool),
        /// `AuthLockpoint`.
        Lockpoint,
        /// `ClientId` with the session id.
        ClientId(i64),
        /// `WatchTerminated`.
        Terminated(TerminateReason),
        /// `Watch`.
        Watch,
        /// `DrainPoint`.
        Drain,
        /// The driver took a stop handle.
        Stop,
    }

    /// Maps an output.
    pub(crate) fn ev(o: Output<Tk>) -> Ev {
        match o {
            Output::Log(r) => Ev::Log(r.site),
            Output::Session {
                state,
                barrier,
                watchers,
                ..
            } => Ev::Session(state.code(), barrier, watchers),
            Output::Completion {
                token,
                route,
                result,
                ..
            } => Ev::Done(token, result.rc, route == Route::Direct),
            Output::Auth {
                tokens,
                rc,
                barrier,
            } => Ev::Auth(tokens, rc, barrier),
            Output::AuthLockpoint => Ev::Lockpoint,
            Output::ClientId(id) => Ev::ClientId(id.session_id),
            Output::WatchTerminated { reason, .. } => Ev::Terminated(reason),
            Output::Watch { .. } => Ev::Watch,
            Output::DrainPoint => Ev::Drain,
        }
    }

    /// Pops every output and resumes at each stop.
    pub(crate) fn drain(c: &mut Connection<Tk>, now: Millis) -> Vec<Ev> {
        let mut evs = Vec::new();
        loop {
            if let Some(o) = c.poll_output() {
                evs.push(ev(o));
                continue;
            }
            match c.take_stopped() {
                Some(s) => {
                    evs.push(Ev::Stop);
                    c.resume(s, now);
                }
                None => break,
            }
        }
        evs
    }

    /// Pops outputs up to the first stop, and returns the stop handle.
    pub(crate) fn until_stop(c: &mut Connection<Tk>) -> (Vec<Ev>, Option<crate::Stopped>) {
        let mut evs = Vec::new();
        while let Some(o) = c.poll_output() {
            evs.push(ev(o));
        }
        (evs, c.take_stopped())
    }

    /// Removes the log lines.
    pub(crate) fn no_logs(evs: &[Ev]) -> Vec<Ev> {
        evs.iter()
            .filter(|e| !matches!(e, Ev::Log(_)))
            .cloned()
            .collect()
    }

    /// Returns the log sites.
    pub(crate) fn logs(evs: &[Ev]) -> Vec<LogSite> {
        evs.iter()
            .filter_map(|e| match e {
                Ev::Log(s) => Some(*s),
                _ => None,
            })
            .collect()
    }

    /// Takes the recorded calls to other modules.
    pub(crate) fn calls(c: &mut Connection<Tk>) -> Vec<PeerCall> {
        c.teardown
            .stub
            .as_mut()
            .map(core::mem::take)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::test_support::*;
    use super::*;
    use crate::action::{ConnectStart, TlsConfigStep, TlsResourceAt};
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::request::Route;
    use zk_jute::JString;

    const CL: i32 = rc::ZCONNECTIONLOSS;

    /// A connected legacy connection with two Queued entries, one Direct
    /// entry between them, and one auth token.
    fn loaded(mode: DriverMode) -> Connection<Tk> {
        let mut c = conn(Compat::LEGACY_C, mode);
        establish(&mut c, Millis(10));
        c.requests.push_pending(pend(1, Route::Queued, 11));
        c.requests.push_pending(pend(2, Route::Direct, 12));
        c.requests.push_pending(pend(3, Route::Queued, 13));
        add_auth(&mut c, 21);
        c
    }

    #[test]
    fn the_teardown_keeps_the_os_errno() {
        let mut c = conn(Compat::NATIVE, DriverMode::NATIVE);
        establish(&mut c, Millis(10));
        let _ = c.handle_transport_failed(TransportFailure::Io { errno: 54 }, Millis(20));
        assert_eq!(c.last_teardown_cause(), Some(Cause::Io));
        assert_eq!(c.last_teardown_errno(), Some(54));
        // An errno of 0 means that the OS gave no value.
        let mut c = conn(Compat::NATIVE, DriverMode::NATIVE);
        establish(&mut c, Millis(10));
        let _ = c.handle_transport_failed(TransportFailure::Io { errno: 0 }, Millis(20));
        assert_eq!(c.last_teardown_errno(), None);
    }

    #[test]
    fn teardown_stops_at_each_barrier_then_resumes() {
        let mut c = loaded(DriverMode::ST);
        let rc = c.handle_transport_failed(TransportFailure::Eof, Millis(20));
        assert_eq!(rc, CL);
        assert_eq!(c.state(), State::Connected, "T2 sees the old state");
        assert!(!c.has_transport());
        assert!(c.is_suspended());
        assert_eq!(c.last_teardown_cause(), Some(Cause::Eof));

        // T0 and T2.
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(
            evs,
            vec![
                Ev::Log(LogSite::SockRecvFailed),
                Ev::Log(LogSite::CleanupSessionConnecting),
                Ev::Session(1, true, vec![DEFAULT_WATCHER]),
            ]
        );
        // A request from the T2 callback is in the T3 snapshot.
        c.requests.push_pending(pend(4, Route::Queued, 14));
        c.resume(stop.unwrap(), Millis(20));

        // T3: the Direct run.
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs, vec![Ev::Done(11, CL, false), Ev::Done(12, CL, true)]);
        c.resume(stop.unwrap(), Millis(20));

        // T3: the rest of the run, then the lock point.
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(
            evs,
            vec![
                Ev::Done(13, CL, false),
                Ev::Done(14, CL, false),
                Ev::Lockpoint
            ]
        );
        c.resume(stop.unwrap(), Millis(20));

        // T3: auth.
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs, vec![Ev::Auth(vec![21], CL, true)]);
        assert_eq!(c.state(), State::Connected);
        c.resume(stop.unwrap(), Millis(20));

        // T4 to T6.
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs, vec![Ev::Log(LogSite::CleanupPrevious), Ev::Drain]);
        assert!(stop.is_none());
        assert!(!c.is_suspended());
        assert_eq!(c.state(), State::Closed);
        assert_eq!(c.core.phase, Phase::Idle);
        assert_eq!(
            calls(&mut c),
            vec![
                PeerCall::SaslOnTeardown,
                PeerCall::SessionWatchers,
                PeerCall::FailPendingRun(CL),
                PeerCall::FailPendingRun(CL),
                PeerCall::HostsOnHandleError,
                PeerCall::ClearWatches(TerminateReason::ConnectionLost),
            ]
        );
        let left = c.into_leftovers();
        assert!(left.completions.is_empty() && left.auth.is_empty());
    }

    #[test]
    fn teardown_without_barriers_runs_in_one_call() {
        let mut c = conn(Compat::NATIVE, DriverMode::NATIVE);
        establish(&mut c, Millis(10));
        c.requests.push_pending(pend(1, Route::Queued, 11));
        add_auth(&mut c, 21);
        let rc = c.handle_transport_failed(TransportFailure::Io { errno: 104 }, Millis(20));
        assert_eq!(rc, CL);
        assert!(!c.is_suspended());
        assert_eq!(
            no_logs(&drain(&mut c, Millis(20))),
            vec![
                Ev::Session(1, false, vec![DEFAULT_WATCHER]),
                Ev::Done(11, CL, false),
                Ev::Auth(vec![21], CL, false),
                Ev::Drain,
            ]
        );
        assert_eq!(c.state(), State::Closed);
    }

    #[test]
    fn stopped_teardown_job_is_dropped_with_destroy() {
        let mut c = loaded(DriverMode::ST);
        let _ = c.teardown(Cause::RecvTimeout, errno::ETIMEDOUT, Millis(40_000));
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs.first(), Some(&Ev::Log(LogSite::SockTimedOut)));
        c.destroy(Millis(40_000));
        c.resume(stop.unwrap(), Millis(40_000));
        let evs = no_logs(&drain(&mut c, Millis(40_000)));
        let cl = rc::ZCLOSING;
        assert_eq!(
            evs,
            vec![
                Ev::Done(11, cl, false),
                Ev::Done(12, cl, true),
                Ev::Done(13, cl, false),
                Ev::Lockpoint,
                Ev::Auth(vec![21], cl, false),
                Ev::Drain,
            ]
        );
        assert!(c.into_leftovers().completions.is_empty());
    }

    #[test]
    fn rc_per_cause_and_profile() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::MT);
        establish(&mut c, Millis(1));
        let rc = c.handle_transport_failed(TransportFailure::TlsHandshake { errno: 0 }, Millis(2));
        assert_eq!(rc, rc::ZSSLCONNECTIONERROR);
        assert_eq!(c.last_teardown_cause(), Some(Cause::Tls));

        let mut n = conn(Compat::NATIVE, DriverMode::NATIVE);
        establish(&mut n, Millis(1));
        let rc = n.handle_transport_failed(TransportFailure::TlsHandshake { errno: 0 }, Millis(2));
        assert_eq!(rc, CL);

        let mut n = conn(Compat::NATIVE, DriverMode::NATIVE);
        establish(&mut n, Millis(1));
        n.set_state(State::AuthFailed);
        let rc = n.teardown(Cause::AuthFailed, 0, Millis(2));
        assert_eq!(rc, rc::ZAUTHFAILED);
        let evs = drain(&mut n, Millis(2));
        assert_eq!(evs.first(), Some(&Ev::Log(LogSite::CleanupSessionState)));
        assert_eq!(n.state(), State::AuthFailed);
        assert!(calls(&mut n).contains(&PeerCall::ClearWatches(TerminateReason::AuthFailed)));
    }

    #[test]
    fn transport_failure_sites() {
        // With no transport only SocketCreate and TcpRefused run.
        let mut c = conn(Compat::LEGACY_C, DriverMode::MT);
        assert_eq!(
            c.handle_transport_failed(TransportFailure::Eof, Millis(1)),
            rc::ZOK
        );
        assert!(drain(&mut c, Millis(1)).is_empty());
        let rc = c.handle_transport_failed(TransportFailure::SocketCreate { errno: 24 }, Millis(1));
        assert_eq!(rc, rc::ZSYSTEMERROR);
        let evs = drain(&mut c, Millis(1));
        assert_eq!(c.state(), State::Closed);
        assert_eq!(
            evs,
            vec![
                Ev::Log(LogSite::SockSocketFailed),
                Ev::Lockpoint,
                Ev::Stop,
                Ev::Log(LogSite::CleanupPrevious),
                Ev::Drain
            ]
        );
        let rc = c.handle_transport_failed(TransportFailure::TcpRefused { errno: 61 }, Millis(1));
        assert_eq!(rc, CL);
        assert_eq!(
            logs(&drain(&mut c, Millis(1))).first(),
            Some(&LogSite::SockConnectFailed)
        );

        // Refused after an EINPROGRESS connect.
        c.handle_connect_started(ConnectStart::InProgress, Millis(2));
        let _ = c.handle_transport_failed(TransportFailure::TcpRefused { errno: 61 }, Millis(2));
        assert_eq!(
            logs(&drain(&mut c, Millis(2))).first(),
            Some(&LogSite::SockRefused)
        );

        // A send failure before the Connect frame is out.
        c.handle_connect_started(ConnectStart::InProgress, Millis(3));
        c.handle_tcp_connected(Millis(3));
        c.handle_transport_ready(Millis(3));
        let _ = drain(&mut c, Millis(3));
        let _ = c.handle_transport_failed(TransportFailure::Io { errno: 32 }, Millis(3));
        assert_eq!(
            logs(&drain(&mut c, Millis(3))).first(),
            Some(&LogSite::SockHandshakeSend)
        );

        // TLS resource sites.
        c.handle_connect_started(ConnectStart::InProgress, Millis(4));
        let _ = c.handle_transport_failed(
            TransportFailure::TlsResource {
                at: TlsResourceAt::ContextNew,
                errno: 0,
            },
            Millis(4),
        );
        let l = logs(&drain(&mut c, Millis(4)));
        assert_eq!(
            &l[..2],
            &[LogSite::TlsContextNew, LogSite::SockTlsContextNew]
        );
        c.handle_connect_started(ConnectStart::InProgress, Millis(5));
        let _ = c.handle_transport_failed(
            TransportFailure::TlsResource {
                at: TlsResourceAt::ConnectionNew,
                errno: 0,
            },
            Millis(5),
        );
        assert_eq!(
            logs(&drain(&mut c, Millis(5))).first(),
            Some(&LogSite::SockTlsConnectionNew)
        );
    }

    #[test]
    fn tls_config_failure_is_not_a_teardown() {
        let mut cfg = Config::legacy(30_000);
        cfg.tls = true;
        let mut c = conn_with(cfg, Compat::LEGACY_C, DriverMode::MT);
        c.handle_connect_started(ConnectStart::InProgress, Millis(1));
        assert_eq!(c.state(), State::SslConnecting);
        let rc = c.handle_transport_failed(
            TransportFailure::TlsConfig {
                step: TlsConfigStep::CaFile,
                file: JString::Bytes(b"/ca.pem".to_vec()),
            },
            Millis(1),
        );
        assert_eq!(rc, rc::ZSSLCONNECTIONERROR);
        assert_eq!(c.take_errno_hint(), Some(errno::EINVAL));
        assert_eq!(c.core.phase, Phase::TlsConfigFailed);
        assert_eq!(c.state(), State::SslConnecting);
        assert!(c.has_transport());
        assert_eq!(drain(&mut c, Millis(1)), vec![Ev::Log(LogSite::TlsCaFile)]);
        assert_eq!(c.last_teardown_cause(), None);
        let rc = c.handle_transport_failed(TransportFailure::Poll { errno: 4 }, Millis(1));
        assert_eq!(rc, rc::ZSYSTEMERROR);
        assert!(c.has_transport());
    }

    #[test]
    fn expiry_logs_state_and_rc() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::MT);
        establish(&mut c, Millis(1));
        let _ = c.teardown(Cause::Eof, 0, Millis(2));
        let _ = drain(&mut c, Millis(2));
        connect(&mut c, Millis(3));
        let body = response(30_000, 0x66, false);
        assert_eq!(
            c.on_connect_response(&body, Millis(3)),
            crate::recv::Flow::Done(rc::ZSESSIONEXPIRED)
        );
        assert_eq!(c.state(), State::ExpiredSession);
        assert_eq!(c.take_errno_hint(), Some(errno::ESTALE));
        let evs = drain(&mut c, Millis(3));
        assert_eq!(
            evs,
            vec![
                Ev::Log(LogSite::InitiatedConnectionLate),
                Ev::Log(LogSite::SockSessionExpired),
                Ev::Log(LogSite::CleanupSessionState),
                Ev::Session(-112, false, vec![DEFAULT_WATCHER]),
                Ev::Lockpoint,
                Ev::Stop,
                Ev::Log(LogSite::CleanupPrevious),
                Ev::Drain,
            ]
        );
    }

    #[test]
    fn forced_close_trigger_then_pending_stages() {
        let mut c = loaded(DriverMode::ST);
        c.requests.push_tail(OutFrame::plain(
            crate::requests::FrameKind::Request { xid: 3 },
            vec![1, 2, 3],
        ));
        c.forced_close_trigger(Millis(5));
        assert_eq!(c.state(), State::NotConnected);
        assert_eq!(c.core.phase, Phase::Idle);
        assert!(!c.has_transport());
        assert!(c.requests.fifo.is_empty() && c.requests.tx.is_empty());
        assert!(c.auth.list.iter().all(|e| e.done.is_none()));
        assert_eq!(c.auth.list.len(), 1, "the entry stays for the resend");
        assert!(drain(&mut c, Millis(5)).is_empty());
        assert!(
            c.interest
                .queued
                .iter()
                .any(|a| matches!(a, crate::action::Action::CloseTransport))
        );

        // A second trigger does nothing.
        c.handle_forced_close(Millis(5));
        // Work after the trigger stays for the next connection.
        c.requests.push_pending(pend(9, Route::Queued, 19));

        assert!(c.run_pending_teardown(Millis(6)));
        assert_eq!(c.last_teardown_cause(), Some(Cause::ForcedClose));
        assert!(!c.run_pending_teardown(Millis(6)), "suspended");
        let evs = drain(&mut c, Millis(6));
        assert_eq!(
            no_logs(&evs),
            vec![
                Ev::Session(1, true, vec![DEFAULT_WATCHER]),
                Ev::Stop,
                Ev::Done(11, CL, false),
                Ev::Done(12, CL, true),
                Ev::Stop,
                Ev::Done(13, CL, false),
                Ev::Lockpoint,
                Ev::Stop,
                Ev::Auth(vec![21], CL, true),
                Ev::Stop,
                Ev::Drain,
            ]
        );
        assert_eq!(
            logs(&evs),
            vec![LogSite::CleanupSessionConnecting, LogSite::CleanupPrevious]
        );
        assert_eq!(c.state(), State::NotConnected);
        assert_eq!(c.requests.fifo.len(), 1);
        assert!(!calls(&mut c).contains(&PeerCall::HostsOnHandleError));
        assert!(!c.run_pending_teardown(Millis(7)));
    }

    #[test]
    fn forced_stages_wait_for_a_suspended_stage() {
        let mut c = loaded(DriverMode::ST);
        // A finalize-like stop: park a hold behind a lock point.
        c.out.push(Output::AuthLockpoint);
        c.out.park(Work::Hold);
        c.forced_close_trigger(Millis(5));
        assert!(!c.run_pending_teardown(Millis(5)));
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs, vec![Ev::Lockpoint]);
        assert!(!c.run_pending_teardown(Millis(5)));
        c.resume(stop.unwrap(), Millis(5));
        assert!(c.run_pending_teardown(Millis(6)));
        let evs = no_logs(&drain(&mut c, Millis(6)));
        assert_eq!(
            evs.first(),
            Some(&Ev::Session(1, true, vec![DEFAULT_WATCHER]))
        );
    }

    #[test]
    fn close_from_the_t2_callback_takes_the_snapshot() {
        let mut c = loaded(DriverMode::ST);
        c.forced_close_trigger(Millis(5));
        assert!(c.run_pending_teardown(Millis(6)));
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(
            no_logs(&evs),
            vec![Ev::Session(1, true, vec![DEFAULT_WATCHER])]
        );
        // The close runs in the callback and fails the snapshot first.
        c.requests.push_pending(pend(9, Route::Queued, 19));
        c.begin_close(Millis(6));
        let (evs, stop2) = until_stop(&mut c);
        let cl = rc::ZCLOSING;
        assert_eq!(evs, vec![Ev::Done(11, cl, false), Ev::Done(12, cl, true)]);
        c.resume(stop2.unwrap(), Millis(6));
        let evs = no_logs(&drain(&mut c, Millis(6)));
        assert_eq!(
            evs,
            vec![
                Ev::Done(13, cl, false),
                Ev::Done(19, cl, false),
                Ev::Lockpoint,
                Ev::Stop,
                Ev::Auth(vec![21], cl, false),
                Ev::Drain,
            ]
        );
        // The teardown resumes and finds an empty snapshot.
        c.resume(stop.unwrap(), Millis(6));
        let evs = no_logs(&drain(&mut c, Millis(6)));
        assert_eq!(evs, vec![Ev::Lockpoint, Ev::Stop, Ev::Drain]);
        assert!(c.into_leftovers().completions.is_empty());
    }

    /// Opens a transport, sends the `Connect` frame and takes the
    /// response, as a driver does.
    fn open_and_send_connect(c: &mut Connection<Tk>, now: Millis) {
        c.handle_connect_started(ConnectStart::InProgress, now);
        c.handle_tcp_connected(now);
        c.handle_transport_ready(now);
        let mut out = Vec::new();
        let n = c.poll_transmit(&mut out, usize::MAX);
        assert_eq!(c.requests.tx.len(), 1, "the Connect frame goes alone");
        assert_eq!(c.requests.tx[0].kind, crate::requests::FrameKind::Connect);
        assert_eq!(n, out.len());
        c.handle_transmitted(n, now);
        let _ = c.on_connect_response(&response(30_000, 0x55, false), now);
        let _ = drain(c, now);
    }

    /// Queues a setData of `len` bytes and returns its xid.
    fn queue_set(c: &mut Connection<Tk>, len: usize) -> i32 {
        let req = crate::request::Request {
            op: crate::request::Op::SetData {
                path: crate::request::PathIn::Legacy(Some(b"/a".to_vec())),
                data: zk_jute::JBuffer::Bytes(vec![0x5a; len]),
                version: -1,
            },
            token: 5,
            route: Route::Queued,
            defect: crate::request::InputDefect::default(),
        };
        match c.submit(req, Millis(0)) {
            Ok(crate::request::Submitted::Queued { xid }) => xid,
            _ => panic!("submit failed"),
        }
    }

    /// Rule: a lent frame never reaches a new transport. T1
    /// clears its pin. While the job waits at the T2 barrier, the core
    /// gives no connect action. The T3 snapshot then drops the frame.
    /// The next transport sends the `Connect` frame first, then each new
    /// request whole and in order.
    #[test]
    fn a_lent_frame_goes_away_before_the_next_transport() {
        let now = Millis(10);
        let mut c = conn(Compat::LEGACY_C, DriverMode::ST);
        open_and_send_connect(&mut c, now);
        let big = 1024 * 1024;
        let _ = queue_set(&mut c, big);
        let _ = queue_set(&mut c, 10);
        let mut out = Vec::new();
        let n = c.poll_transmit(&mut out, usize::MAX);
        assert!(c.requests.tx[0].is_lent());
        assert_eq!(n, out.len());
        c.handle_transmitted(1000, now);

        let _ = c.handle_transport_failed(TransportFailure::Eof, now);
        assert!(c.is_suspended(), "the job waits at the T2 barrier");
        assert!(c.poll_action(now).is_none(), "no connect while it waits");
        let head = &c.requests.tx[0];
        assert!(head.is_lent() && !head.pinned && c.requests.unacked == 0);
        let _ = drain(&mut c, now);
        assert!(!c.is_suspended());
        assert!(c.requests.tx.is_empty(), "T3 drops the lent frame");

        // The open of the new transport asserts that no lent frame is
        // left. The new requests go out whole and in order.
        open_and_send_connect(&mut c, now);
        let small = queue_set(&mut c, 10);
        let large = queue_set(&mut c, big);
        let mut wire = Vec::new();
        for _ in 0..2 {
            let mut out = Vec::new();
            let n = c.poll_transmit(&mut out, usize::MAX);
            c.handle_transmitted(n, now);
            wire.extend_from_slice(&out);
        }
        assert!(c.requests.tx.is_empty());
        use zk_jute::Record as _;
        let mut r = zk_jute::Reader::new(&wire);
        for (xid, len) in [(small, 10), (large, big)] {
            let _len = r.read_i32().unwrap();
            let hdr = zk_jute::proto::RequestHeader::decode(&mut r).unwrap();
            let rec = zk_jute::proto::SetDataRequest::decode(&mut r).unwrap();
            assert_eq!(hdr.xid, xid);
            assert_eq!(rec.data.as_bytes(), Some(&vec![0x5a; len][..]));
        }
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn forced_close_with_no_transport_does_nothing() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::ST);
        c.forced_close_trigger(Millis(1));
        assert!(c.teardown.forced.is_none());
        assert!(!c.run_pending_teardown(Millis(1)));
        assert_eq!(c.state(), State::NotConnected);
    }

    #[test]
    fn epoch_advances_and_finalize_stops_after_teardown() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::ST);
        connect(&mut c, Millis(1));
        let body = response(30_000, 0x55, false);
        assert_eq!(
            c.on_connect_response(&body, Millis(1)),
            crate::recv::Flow::Stop
        );
        let (_, stop) = until_stop(&mut c);
        // A teardown during the finalize lock point.
        let epoch = c.core.epoch;
        let _ = c.teardown(Cause::Eof, 0, Millis(2));
        assert_ne!(c.core.epoch, epoch);
        let _ = drain(&mut c, Millis(2));
        let _ = calls(&mut c);
        c.resume(stop.unwrap(), Millis(2));
        assert!(drain(&mut c, Millis(2)).is_empty());
        assert!(!calls(&mut c).contains(&PeerCall::QueueAuthResend));
    }
}
