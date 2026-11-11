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

//! The transport life cycle, the handshake and finalize.
//!
//! The module owns [`SessionState`]. It moves the phase from Idle through
//! TCP connect, TLS and the handshake to Established, and it emits the
//! session events.

use zeroize::Zeroize;
use zk_jute::handshake::{ConnectRequest, decode_connect_response};

use crate::action::ConnectStart;
use crate::compat::{ExpiryRule, HandshakeTimeout};
use crate::config::{ClientId, SessionDelivery};
use crate::connection::Connection;
use crate::errno;
use crate::hooks::Tokens;
use crate::log::{LogArg, LogRecord, LogSite, str_arg};
use crate::output::{Output, Work};
use crate::recv::Flow;
use crate::requests::{FrameKind, OutFrame};
use crate::state::{Cause, Phase, State, event_name};
use crate::teardown::{T0Line, session_id_arg};
use crate::time::{Millis, two_thirds};

/// The event type of a session event in the legacy watcher line.
const SESSION_EVENT: i32 = -1;

/// The handshake state of the current transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct SessionState {
    /// True from `handle_transport_ready` until the ConnectResponse.
    pub(crate) handshake_pending: bool,
    /// True when the `Connect` frame is completely sent.
    pub(crate) connect_sent: bool,
    /// True when the `ConnectResponse` said read-only.
    pub(crate) read_only: bool,
    /// True when the TCP connect of this transport completed at once. The
    /// timer reset and the log line of the immediate path then apply.
    immediate: bool,
}

/// The step at which finalize stopped.
///
/// Finalize has six steps: the state, the INFO line, SetWatches, the auth
/// lock point and resend, the session event, and the held frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FinalizeStep {
    /// After the `AuthLockpoint` of step 4. The auth resend and the
    /// session event remain.
    AfterLockpoint,
    /// After the `Session{barrier: true}` output (step 5). Step 6 remains.
    AfterSession,
}

/// The remaining steps of finalize.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FinalizeJob {
    /// The step to continue at.
    pub(crate) step: FinalizeStep,
    /// The transport epoch of the finalize. A teardown or forced close
    /// during the barrier changes it, and then nothing more runs.
    pub(crate) epoch: u64,
}

impl<T: Tokens> Connection<T> {
    /// Takes the start of a TCP connect.
    ///
    /// Contract: it opens the transport
    /// (`core.has_transport`, a new transport epoch). `InProgress` sets
    /// phase TcpConnecting, state 1 (7 with TLS), records
    /// `connect_started_at` and resets the timers. `Immediate` keeps the
    /// visible state: the driver calls `handle_tcp_connected` and
    /// `handle_transport_ready` under the same lock hold.
    ///
    /// The call is valid only after a `Connect` action that has no answer
    /// yet. The core refuses the new transport after `begin_close` or
    /// `destroy`, and when a transport already exists. It then queues
    /// `CloseTransport`, so the driver closes the socket that it opened.
    pub fn handle_connect_started(&mut self, kind: ConnectStart, now: Millis) {
        if self.close.closing || self.core.has_transport {
            self.queue_close_transport();
            return;
        }
        let _epoch = self.open_transport();
        let immediate = matches!(kind, ConnectStart::Immediate);
        self.session = SessionState {
            immediate,
            ..SessionState::default()
        };
        self.core.phase = Phase::TcpConnecting;
        if !immediate {
            let state = if self.cfg.tls {
                State::SslConnecting
            } else {
                State::Connecting
            };
            self.set_state(state);
            self.timers.connect_started_at = Some(now);
            self.timers.reset_for_connect(now);
        }
    }

    /// Takes a completed TCP connect.
    ///
    /// Contract: with TLS the phase becomes TlsHandshaking with
    /// `deadline = now + T*2/3`, and on the immediate path the timers
    /// reset. With no TLS it does nothing more: `handle_transport_ready`
    /// follows.
    pub fn handle_tcp_connected(&mut self, now: Millis) {
        if !self.core.has_transport || self.core.phase != Phase::TcpConnecting {
            return;
        }
        if self.cfg.tls {
            let deadline = now.offset_ms(two_thirds(self.core.recv_timeout));
            self.core.phase = Phase::TlsHandshaking { deadline };
            if self.session.immediate {
                self.timers.reset_for_connect(now);
            }
        }
    }

    /// Takes a ready transport and starts the handshake.
    ///
    /// Contract: it pushes the `ConnectRequest` as a priority
    /// secret `Connect` frame, sets phase
    /// Associating, `handshake_pending`, and state 2. On the immediate
    /// path with no TLS it also resets the timers.
    ///
    /// It also logs the "Initiated connection" line of C, which follows
    /// `prime_connection` on both connect paths (zookeeper.c:2729, 3116).
    pub fn handle_transport_ready(&mut self, now: Millis) {
        let ready = matches!(
            self.core.phase,
            Phase::TcpConnecting | Phase::TlsHandshaking { .. }
        );
        if !self.core.has_transport || !ready {
            return;
        }
        let time_out = match self.compat.handshake_timeout {
            HandshakeTimeout::Negotiated => self.core.recv_timeout,
            HandshakeTimeout::Requested => self.cfg.timeout_ms,
        };
        let session_id = if self.core.seen_rw_before {
            self.core.client_id.session_id
        } else {
            0
        };
        let mut req = ConnectRequest {
            protocol_version: 0,
            last_zxid_seen: self.core.last_zxid,
            time_out,
            session_id,
            passwd: self.core.client_id.passwd,
            read_only: self.cfg.allow_read_only,
        };
        let mut frame = req.encode_frame();
        let bytes = frame.to_vec();
        frame.zeroize();
        req.passwd.zeroize();
        self.requests
            .push_priority(OutFrame::secret(FrameKind::Connect, bytes));
        self.core.phase = Phase::Associating;
        self.session.handshake_pending = true;
        self.session.connect_sent = false;
        self.set_state(State::Associating);
        if self.session.immediate && !self.cfg.tls {
            self.timers.reset_for_connect(now);
        }
        let site = if self.session.immediate {
            LogSite::InitiatedConnection
        } else {
            LogSite::InitiatedConnectionLate
        };
        let server = self.current_server();
        self.emit_log(site, || vec![LogArg::Endpoint(server)]);
    }

    /// Records the complete send of the `Connect` frame.
    pub(crate) fn on_connect_sent(&mut self) {
        self.session.connect_sent = true;
    }

    /// Processes the `ConnectResponse`.
    ///
    /// Contract:
    /// - A body that `decode_connect_response` rejects tears down with
    ///   `Cause::ProtocolError`.
    /// - Expiry per `Compat::expiry`: state -112, errno hint `ESTALE`, a
    ///   `Cause::SessionExpired` teardown and `Flow::Done(ZSESSIONEXPIRED)`.
    /// - Otherwise it adopts the timeout and the client id, pushes
    ///   `Output::ClientId`, and then runs `begin_sasl` (with
    ///   `cfg.sasl`) or `start_finalize`.
    ///
    /// With SASL it returns `Flow::Stop`, because the phase waits for the
    /// mechanism.
    pub(crate) fn on_connect_response(&mut self, body: &[u8], now: Millis) -> Flow {
        let Ok(mut resp) = decode_connect_response(body) else {
            return Flow::Done(self.teardown(Cause::ProtocolError, 0, now));
        };
        let old_id = if self.core.seen_rw_before {
            self.core.client_id.session_id
        } else {
            0
        };
        self.core.seen_rw_before = self.core.seen_rw_before || !resp.read_only;
        let id_changed = old_id != 0 && old_id != resp.session_id;
        let no_timeout = self.compat.expiry == ExpiryRule::Java && resp.time_out <= 0;
        if id_changed || no_timeout {
            resp.passwd.zeroize();
            self.set_state(State::ExpiredSession);
            self.set_errno_hint(errno::ESTALE);
            let line = T0Line::with(
                LogSite::SockSessionExpired,
                errno::ESTALE,
                vec![session_id_arg(old_id)],
            );
            return Flow::Done(self.teardown_with_line(Cause::SessionExpired, Some(line), now));
        }
        self.core.recv_timeout = resp.time_out;
        self.core.client_id = ClientId {
            session_id: resp.session_id,
            passwd: resp.passwd,
        };
        resp.passwd.zeroize();
        self.session.read_only = resp.read_only;
        self.session.handshake_pending = false;
        self.out.push(Output::ClientId(self.core.client_id));
        if self.cfg.sasl {
            self.teardown_peer_begin_sasl(now);
            Flow::Stop
        } else {
            self.start_finalize(now)
        }
    }

    /// Runs finalize steps 1 to 4.
    ///
    /// Contract: state 5 or 3, `hosts.servers.reconfig = false`, phase
    /// Established, the INFO "session establishment complete" line, then
    /// `queue_set_watches`.
    /// With `Compat::emits_lockpoints` it pushes `AuthLockpoint`, parks
    /// `FinalizeJob{AfterLockpoint}` and returns `Flow::Stop`. Otherwise
    /// it continues at once, as `continue_finalize` does.
    ///
    /// Without lock points it returns `Flow::Stop` when the session event
    /// is a barrier, else `Flow::Continue`.
    pub(crate) fn start_finalize(&mut self, _now: Millis) -> Flow {
        let read_only = self.session.read_only;
        let state = if read_only {
            State::ReadOnly
        } else {
            State::Connected
        };
        self.set_state(state);
        self.hosts.servers.reconfig = false;
        self.hosts_on_established();
        self.core.phase = Phase::Established;
        let server = self.current_server();
        let sid = session_id_arg(self.core.client_id.session_id);
        let timeout = i64::from(self.core.recv_timeout);
        self.emit_log(LogSite::SessionEstablished, || {
            let mode: &[u8] = if read_only { b"(READ-ONLY mode)" } else { b"" };
            vec![
                LogArg::Endpoint(server),
                sid,
                LogArg::I64(timeout),
                str_arg(mode),
            ]
        });
        self.teardown_peer_queue_set_watches();
        let epoch = self.core.epoch;
        if self.compat.emits_lockpoints() {
            self.out.push(Output::AuthLockpoint);
            self.out.park(Work::Finalize(FinalizeJob {
                step: FinalizeStep::AfterLockpoint,
                epoch,
            }));
            return Flow::Stop;
        }
        if self.session_finalize_tail(epoch) {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    /// Continues finalize after a barrier.
    ///
    /// Contract: when `job.epoch` is not live, stop.
    /// `AfterLockpoint` runs `queue_auth_resend`, then `emit_session` with
    /// the connected state, and parks `AfterSession` when that output is a
    /// barrier. Step 6 makes the held frames sendable: nothing to do in
    /// the core, because the phase gate now opens.
    pub(crate) fn continue_finalize(&mut self, job: FinalizeJob, _now: Millis) {
        if job.epoch != self.core.epoch || !self.core.has_transport {
            return;
        }
        match job.step {
            FinalizeStep::AfterLockpoint => {
                let _stopped = self.session_finalize_tail(job.epoch);
            }
            FinalizeStep::AfterSession => {}
        }
    }

    /// Pushes a session event with its watchers and delivery logs.
    ///
    /// Contract: the watchers come from
    /// `session_watchers`. The delivery logs start with the DEBUG "Calling
    /// a watcher for node []" line. `barrier` is true when
    /// `DriverMode::session_delivery` is `Inline`. It returns that value,
    /// so the caller parks its job and stops.
    pub(crate) fn emit_session(&mut self, state: State, extra_logs: Vec<LogRecord>) -> bool {
        let watchers = self.teardown_peer_session_watchers();
        let mut delivery_logs = Vec::new();
        if let Some(r) = self.log.record(LogSite::CallingWatcher, || {
            vec![
                str_arg(b""),
                LogArg::I64(i64::from(SESSION_EVENT)),
                str_arg(event_name(SESSION_EVENT).as_bytes()),
            ]
        }) {
            delivery_logs.push(r);
        }
        delivery_logs.extend(extra_logs);
        let barrier = self.mode.session_delivery == SessionDelivery::Inline;
        self.out.push(Output::Session {
            state,
            watchers,
            barrier,
            delivery_logs,
        });
        barrier
    }

    /// Runs finalize steps 4 to 5: the auth resend, the DEBUG line and the
    /// connected session event. It parks the `AfterSession` step when the
    /// event is a barrier, and then returns true.
    fn session_finalize_tail(&mut self, epoch: u64) -> bool {
        self.teardown_peer_queue_auth_resend();
        self.emit_log(LogSite::FinalizeSessionEvent, Vec::new);
        let state = self.core.state;
        if self.emit_session(state, Vec::new()) {
            self.out.park(Work::Finalize(FinalizeJob {
                step: FinalizeStep::AfterSession,
                epoch,
            }));
            true
        } else {
            false
        }
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

    use super::*;
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::output::TerminateReason;
    use crate::rc;
    use crate::teardown::PeerCall;
    use crate::teardown::test_support::*;

    /// Returns the `Connect` frame bytes at the head of `tx`.
    fn connect_frame(c: &Connection<Tk>) -> Vec<u8> {
        let f = c
            .requests
            .tx
            .iter()
            .find(|f| f.kind == FrameKind::Connect)
            .expect("a Connect frame");
        f.bytes.as_slice().to_vec()
    }

    /// Returns the `timeOut` and `sessionId` fields of a `Connect` frame.
    fn frame_fields(frame: &[u8]) -> (i32, i64) {
        let t = i32::from_be_bytes(frame[16..20].try_into().unwrap());
        let s = i64::from_be_bytes(frame[20..28].try_into().unwrap());
        (t, s)
    }

    fn resumed_cfg(sid: i64) -> Config {
        let mut cfg = Config::legacy(30_000);
        cfg.client_id = ClientId {
            session_id: sid,
            passwd: [0x11; 16],
        };
        cfg
    }

    #[test]
    fn connect_start_sets_state_and_phase() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::ST);
        let epoch = c.core.epoch;
        c.handle_connect_started(ConnectStart::InProgress, Millis(50));
        assert!(c.has_transport());
        assert_ne!(c.core.epoch, epoch);
        assert_eq!(c.state(), State::Connecting);
        assert_eq!(c.core.phase, Phase::TcpConnecting);
        assert_eq!(c.timers.connect_started_at, Some(Millis(50)));
        assert_eq!(c.timers.last_recv, Millis(50));

        let mut cfg = Config::legacy(30_000);
        cfg.tls = true;
        let mut t = conn_with(cfg, Compat::LEGACY_C, DriverMode::ST);
        t.handle_connect_started(ConnectStart::InProgress, Millis(1));
        assert_eq!(t.state(), State::SslConnecting);
        t.handle_tcp_connected(Millis(10));
        assert_eq!(
            t.core.phase,
            Phase::TlsHandshaking {
                deadline: Millis(20_010)
            }
        );
        t.handle_transport_ready(Millis(30));
        assert_eq!(t.state(), State::Associating);
        assert_eq!(t.core.phase, Phase::Associating);
    }

    #[test]
    fn immediate_connect_keeps_state_and_resets_timers_late() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::ST);
        c.handle_connect_started(ConnectStart::Immediate, Millis(5));
        assert_eq!(c.state(), State::NotConnected);
        assert_eq!(c.timers.last_recv, Millis(0));
        c.handle_tcp_connected(Millis(5));
        assert_eq!(c.core.phase, Phase::TcpConnecting);
        c.handle_transport_ready(Millis(6));
        assert_eq!(c.state(), State::Associating);
        assert_eq!(c.timers.last_recv, Millis(6));
        assert!(c.session.handshake_pending);
        assert!(!c.session.connect_sent);
        assert_eq!(
            drain(&mut c, Millis(6)),
            vec![Ev::Log(LogSite::InitiatedConnection)]
        );
        // The frame is ready only once.
        c.handle_transport_ready(Millis(7));
        assert_eq!(c.requests.tx.len(), 1);
    }

    #[test]
    fn fresh_session_handshake_and_finalize_with_lockpoints() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::ST);
        connect(&mut c, Millis(1));
        let frame = connect_frame(&c);
        assert_eq!(frame.len(), 49);
        assert_eq!(frame_fields(&frame), (30_000, 0));
        assert!(c.requests.tx.front().unwrap().kind == FrameKind::Connect);
        let _ = drain(&mut c, Millis(1));

        let flow = c.on_connect_response(&response(10_000, 0x55, false), Millis(2));
        assert_eq!(flow, Flow::Stop);
        assert_eq!(c.state(), State::Connected);
        assert_eq!(c.core.phase, Phase::Established);
        assert_eq!(c.recv_timeout(), 10_000);
        assert_eq!(c.client_id().session_id, 0x55);
        assert_eq!(c.client_id().passwd, [0xAB; 16]);
        assert!(c.core.seen_rw_before);
        assert!(!c.session.handshake_pending);

        // Stop 1: the lock point.
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(
            evs,
            vec![
                Ev::ClientId(0x55),
                Ev::Log(LogSite::SessionEstablished),
                Ev::Lockpoint
            ]
        );
        assert_eq!(calls(&mut c), vec![PeerCall::QueueSetWatches]);
        c.resume(stop.unwrap(), Millis(2));

        // Stop 2: the session event.
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(
            evs,
            vec![
                Ev::Log(LogSite::FinalizeSessionEvent),
                Ev::Session(3, true, vec![DEFAULT_WATCHER])
            ]
        );
        assert_eq!(
            calls(&mut c),
            vec![PeerCall::QueueAuthResend, PeerCall::SessionWatchers]
        );
        c.resume(stop.unwrap(), Millis(2));
        assert!(drain(&mut c, Millis(2)).is_empty());
        assert!(!c.is_suspended());
    }

    #[test]
    fn session_event_carries_the_delivery_log() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::MT);
        assert!(!c.emit_session(State::Connecting, Vec::new()));
        match c.poll_output() {
            Some(Output::Session {
                state,
                barrier,
                delivery_logs,
                ..
            }) => {
                assert_eq!(state, State::Connecting);
                assert!(!barrier);
                assert_eq!(delivery_logs.len(), 1);
                assert_eq!(delivery_logs[0].site, LogSite::CallingWatcher);
                assert_eq!(delivery_logs[0].args[1], LogArg::I64(-1));
            }
            _ => panic!("no session output"),
        }
    }

    #[test]
    fn finalize_without_lockpoints() {
        // Dispatch delivery: no barrier at all.
        let mut c = conn(Compat::NATIVE, DriverMode::NATIVE);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(10_000, 0x55, false), Millis(2));
        assert_eq!(flow, Flow::Continue);
        assert!(!c.is_suspended());
        assert_eq!(
            no_logs(&drain(&mut c, Millis(2))),
            vec![
                Ev::ClientId(0x55),
                Ev::Session(3, false, vec![DEFAULT_WATCHER])
            ]
        );

        // Inline delivery: one stop at the session event.
        let mut c = conn(Compat::NATIVE, DriverMode::ST);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(10_000, 0x55, false), Millis(2));
        assert_eq!(flow, Flow::Stop);
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(
            no_logs(&evs),
            vec![
                Ev::ClientId(0x55),
                Ev::Session(3, true, vec![DEFAULT_WATCHER])
            ]
        );
        c.resume(stop.unwrap(), Millis(2));
        assert!(drain(&mut c, Millis(2)).is_empty());
    }

    #[test]
    fn finalize_with_lockpoints_and_dispatch_stops_once() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::MT);
        connect(&mut c, Millis(1));
        let _ = c.on_connect_response(&response(10_000, 0x55, true), Millis(2));
        assert_eq!(c.state(), State::ReadOnly);
        assert!(!c.core.seen_rw_before);
        let evs = drain(&mut c, Millis(2));
        assert_eq!(
            no_logs(&evs),
            vec![
                Ev::ClientId(0x55),
                Ev::Lockpoint,
                Ev::Stop,
                Ev::Session(5, false, vec![DEFAULT_WATCHER])
            ]
        );
    }

    #[test]
    fn resumed_session_handshake() {
        let mut c = conn_with(resumed_cfg(0x77), Compat::LEGACY_C, DriverMode::MT);
        connect(&mut c, Millis(1));
        assert_eq!(frame_fields(&connect_frame(&c)), (30_000, 0x77));
        let flow = c.on_connect_response(&response(20_000, 0x77, false), Millis(2));
        assert_eq!(flow, Flow::Stop);
        assert_eq!(c.state(), State::Connected);
        assert_eq!(c.client_id().session_id, 0x77);

        // Negotiated: the next handshake asks for the negotiated timeout.
        let _ = drain(&mut c, Millis(2));
        let _ = c.teardown(Cause::Eof, 0, Millis(3));
        let _ = drain(&mut c, Millis(3));
        connect(&mut c, Millis(4));
        assert_eq!(frame_fields(&connect_frame(&c)), (20_000, 0x77));

        // Requested: every handshake asks for the configured timeout.
        let mut n = conn_with(resumed_cfg(0x77), Compat::NATIVE, DriverMode::NATIVE);
        connect(&mut n, Millis(1));
        let _ = n.on_connect_response(&response(20_000, 0x77, false), Millis(2));
        let _ = drain(&mut n, Millis(2));
        let _ = n.teardown(Cause::Eof, 0, Millis(3));
        let _ = drain(&mut n, Millis(3));
        connect(&mut n, Millis(4));
        assert_eq!(frame_fields(&connect_frame(&n)), (30_000, 0x77));
    }

    #[test]
    fn expiry_under_legacy_rule() {
        // A changed id expires the session.
        let mut c = conn_with(resumed_cfg(0x77), Compat::LEGACY_C, DriverMode::MT);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(20_000, 0x88, false), Millis(2));
        assert_eq!(flow, Flow::Done(rc::ZSESSIONEXPIRED));
        assert_eq!(c.state(), State::ExpiredSession);
        assert_eq!(c.take_errno_hint(), Some(crate::errno::ESTALE));
        assert_eq!(c.last_teardown_cause(), Some(Cause::SessionExpired));
        assert!(!c.has_transport());
        assert_eq!(c.client_id().session_id, 0x77);
        let evs = drain(&mut c, Millis(2));
        assert!(evs.contains(&Ev::Session(-112, false, vec![DEFAULT_WATCHER])));
        assert!(!evs.contains(&Ev::ClientId(0x88)));

        // A timeout of 0 is not an expiry under the legacy rule.
        let mut c = conn_with(resumed_cfg(0x77), Compat::LEGACY_C, DriverMode::MT);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(0, 0x77, false), Millis(2));
        assert_eq!(flow, Flow::Stop);
        assert_eq!(c.state(), State::Connected);
        assert_eq!(c.recv_timeout(), 0);

        // A new id on a session never seen read-write is no expiry.
        let mut c = conn(Compat::LEGACY_C, DriverMode::MT);
        connect(&mut c, Millis(1));
        let _ = c.on_connect_response(&response(1_000, 0x10, true), Millis(2));
        let _ = drain(&mut c, Millis(2));
        let _ = c.teardown(Cause::Eof, 0, Millis(3));
        let _ = drain(&mut c, Millis(3));
        connect(&mut c, Millis(4));
        assert_eq!(frame_fields(&connect_frame(&c)).1, 0);
        let flow = c.on_connect_response(&response(1_000, 0x20, false), Millis(5));
        assert_eq!(flow, Flow::Stop);
        assert_eq!(c.client_id().session_id, 0x20);
    }

    #[test]
    fn expiry_under_java_rule() {
        let mut c = conn_with(resumed_cfg(0x77), Compat::NATIVE, DriverMode::NATIVE);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(0, 0x77, false), Millis(2));
        assert_eq!(flow, Flow::Done(rc::ZSESSIONEXPIRED));
        assert_eq!(c.state(), State::ExpiredSession);
        let evs = drain(&mut c, Millis(2));
        assert_eq!(
            evs.first(),
            Some(&Ev::Log(LogSite::InitiatedConnectionLate))
        );
        assert_eq!(evs.get(1), Some(&Ev::Log(LogSite::SockSessionExpired)));
        assert!(calls(&mut c).contains(&PeerCall::ClearWatches(TerminateReason::SessionExpired)));

        // A fresh session with a negative timeout also expires.
        let mut c = conn(Compat::NATIVE, DriverMode::NATIVE);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(-1, 0x55, false), Millis(2));
        assert_eq!(flow, Flow::Done(rc::ZSESSIONEXPIRED));

        // A changed id expires under the Java rule too.
        let mut c = conn_with(resumed_cfg(0x77), Compat::NATIVE, DriverMode::NATIVE);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(5_000, 0x99, false), Millis(2));
        assert_eq!(flow, Flow::Done(rc::ZSESSIONEXPIRED));
    }

    #[test]
    fn bad_response_is_a_protocol_error() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::MT);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&[0; 10], Millis(2));
        assert_eq!(flow, Flow::Done(rc::ZCONNECTIONLOSS));
        assert_eq!(c.last_teardown_cause(), Some(Cause::ProtocolError));
        assert!(!c.has_transport());
    }

    #[test]
    fn sasl_starts_after_the_response() {
        let mut cfg = Config::legacy(30_000);
        cfg.sasl = true;
        let mut c = conn_with(cfg, Compat::LEGACY_C, DriverMode::ST);
        connect(&mut c, Millis(1));
        let flow = c.on_connect_response(&response(10_000, 0x55, false), Millis(2));
        assert_eq!(flow, Flow::Stop);
        assert_eq!(c.state(), State::Associating);
        assert!(matches!(c.core.phase, Phase::Sasl(_)));
        assert_eq!(calls(&mut c), vec![PeerCall::BeginSasl]);
        assert_eq!(no_logs(&drain(&mut c, Millis(2))), vec![Ev::ClientId(0x55)]);

        // SASL completion runs finalize.
        assert_eq!(c.start_finalize(Millis(3)), Flow::Stop);
        assert_eq!(c.state(), State::Connected);
    }

    #[test]
    fn finalize_job_of_an_old_epoch_does_nothing() {
        let mut c = conn(Compat::LEGACY_C, DriverMode::ST);
        connect(&mut c, Millis(1));
        let _ = c.on_connect_response(&response(10_000, 0x55, false), Millis(2));
        let (_, stop) = until_stop(&mut c);
        c.forced_close_trigger(Millis(3));
        let _ = calls(&mut c);
        c.resume(stop.unwrap(), Millis(3));
        assert!(drain(&mut c, Millis(3)).is_empty());
        assert!(calls(&mut c).is_empty());
    }
}
