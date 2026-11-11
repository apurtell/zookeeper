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

//! The timers.
//!
//! The module owns [`Timers`]. The core has no clock: each timer compares
//! the `now` of the driver with recorded times.

use zk_jute::{opcode, xid};

use crate::action::Action;
use crate::compat::CloseMode;
use crate::connection::Connection;
use crate::errno::ETIMEDOUT;
use crate::hooks::Tokens;
use crate::log::{LogArg, LogSite};
use crate::requests::{FrameKind, OutFrame};
use crate::state::{Cause, Phase, State};
use crate::time::{Millis, clamp_timeout, elapsed, third, two_thirds, until};

/// The first interval of the read-only probe.
pub(crate) const RW_PROBE_MIN_MS: u32 = 200;
/// The largest interval of the read-only probe.
pub(crate) const RW_PROBE_MAX_MS: u32 = 60_000;
/// The largest lateness of an iteration that gives no WARN.
pub(crate) const DEADLINE_WARN_MAX_MS: i64 = 200;

/// The recorded times of one connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timers {
    /// The time of the last complete received frame.
    pub(crate) last_recv: Millis,
    /// The time of the last completely sent frame.
    pub(crate) last_send: Millis,
    /// The time of the last ping.
    pub(crate) last_ping: Millis,
    /// The time of the last read-only probe.
    pub(crate) last_ping_rw: Millis,
    /// The read-only probe interval, from 200 ms up to 60 s.
    pub(crate) rw_timeout_ms: u32,
    /// The `now` of `handle_connect_started(InProgress)`.
    pub(crate) connect_started_at: Option<Millis>,
    /// The deadline that the last `finish_interest` reported.
    pub(crate) next_deadline: Option<Millis>,
}

impl Timers {
    /// Makes timers that start at `now`.
    pub(crate) fn new(now: Millis) -> Self {
        Self {
            last_recv: now,
            last_send: now,
            last_ping: now,
            last_ping_rw: now,
            rw_timeout_ms: RW_PROBE_MIN_MS,
            connect_started_at: None,
            next_deadline: None,
        }
    }

    /// Records a complete received frame.
    pub(crate) fn on_recv(&mut self, now: Millis) {
        self.last_recv = now;
    }

    /// Records a completely sent frame.
    pub(crate) fn on_send(&mut self, now: Millis) {
        self.last_send = now;
    }

    /// Resets the times at the end of a connect block. C skips the reset
    /// when the block returns early.
    pub(crate) fn reset_for_connect(&mut self, now: Millis) {
        self.last_recv = now;
        self.last_send = now;
        self.last_ping = now;
        self.last_ping_rw = now;
        self.rw_timeout_ms = RW_PROBE_MIN_MS;
    }
}

impl<T: Tokens> Connection<T> {
    /// Runs the timers of step 4 of an interest iteration.
    ///
    /// Contract:
    /// - Receive: `T*2/3 - idle_recv <= 0` starts a `Cause::RecvTimeout`
    ///   teardown and sets the errno hint `ETIMEDOUT`. It is skipped in
    ///   every TCP-connect phase when `connect_timeout_ms` is set. It also
    ///   applies in the TCP-connect phase of state 7, where C has no bound
    ///   (spec "Timers and keepalive pings").
    /// - TCP connect (native): `elapsed >= connect_timeout_ms` starts a
    ///   `Cause::RecvTimeout` teardown.
    /// - TLS handshake: `now >= deadline` starts a
    ///   `Cause::TlsHandshakeTimeout` teardown.
    /// - Ping: when connected and `T/3 - idle_send <= 0`, and the FIFO is
    ///   empty or `ping_when_outstanding` is true, append a Ping frame. No
    ///   new ping goes in while the send queue holds a ping.
    /// - RO probe: in ReadOnly with `idle_ping_rw >= rw_timeout`, double
    ///   the interval up to 60 s and return `ProbeRw`.
    /// - A teardown queues `CloseTransport` through the teardown itself.
    pub(crate) fn run_timers(&mut self, now: Millis) -> Option<Action> {
        if !self.core.has_transport {
            return None;
        }
        let t = self.core.recv_timeout;
        let tcp_connecting = self.core.phase == Phase::TcpConnecting;

        // A teardown ends the timer step, as the C return does.
        if let (true, Some(bound)) = (tcp_connecting, self.cfg.connect_timeout_ms) {
            let started = self.timers.connect_started_at.unwrap_or(now);
            if elapsed(now, started) >= i64::from(bound) {
                self.timers_expire(Cause::RecvTimeout, now);
                return None;
            }
        } else if self.timers_recv_left_ms(now) <= 0 {
            self.timers_expire(Cause::RecvTimeout, now);
            return None;
        }
        if let Phase::TlsHandshaking { deadline } = self.core.phase {
            if now >= deadline {
                self.timers_expire(Cause::TlsHandshakeTimeout, now);
                return None;
            }
        }

        // The send queue holds at most one ping. While the socket takes no
        // bytes, received frames keep the receive rule quiet. C then adds a
        // ping at each step, and the queue grows without a limit.
        if self.core.state.is_connected()
            && third(t).saturating_sub(elapsed(now, self.timers.last_send)) <= 0
            && (self.requests.fifo.is_empty() || self.compat.ping_when_outstanding)
            && !self.requests.tx.iter().any(|f| f.kind == FrameKind::Ping)
        {
            self.queue_ping(now);
            self.interest.ping_queued = true;
        }

        if self.core.state == State::ReadOnly
            && elapsed(now, self.timers.last_ping_rw) >= i64::from(self.timers.rw_timeout_ms)
        {
            self.timers.last_ping_rw = now;
            self.timers.rw_timeout_ms = self
                .timers
                .rw_timeout_ms
                .saturating_mul(2)
                .clamp(RW_PROBE_MIN_MS, RW_PROBE_MAX_MS);
            let endpoint = self.probe_endpoint()?;
            let tls = self.cfg.tls.then_some(self.compat.tls_verify);
            return Some(Action::ProbeRw { endpoint, tls });
        }
        None
    }

    /// Sets the errno hint `ETIMEDOUT` and starts the teardown of an
    /// expired timer. The teardown rc becomes the rc of the iteration.
    fn timers_expire(&mut self, cause: Cause, now: Millis) {
        self.set_errno_hint(ETIMEDOUT);
        self.interest.rc = self.teardown(cause, ETIMEDOUT, now);
    }

    /// Returns `recv_to = T*2/3 - idle_recv`. A value of 0 or less means
    /// that the receive deadline is past.
    pub(crate) fn timers_recv_left_ms(&self, now: Millis) -> i64 {
        two_thirds(self.core.recv_timeout).saturating_sub(elapsed(now, self.timers.last_recv))
    }

    /// Returns the milliseconds by which the receive deadline is past, for
    /// the "exceeded timeout by %dms" text of the T0 line.
    pub(crate) fn timers_recv_overdue_ms(&self, now: Millis) -> i64 {
        self.timers_recv_left_ms(now).saturating_neg()
    }

    /// Returns the `timeout_ms` of `finish_interest` with a transport.
    ///
    /// Contract: `max(0, min(recv_to, send_to, rw_left, tls_left,
    /// connect_left))`. When `connect_timeout_ms` is set, the TCP-connect
    /// phase leaves out `recv_to`. State 7 has no special rule, because the
    /// receive timeout applies there too. Under a `Drain` close it is also
    /// capped at `close_deadline - now`.
    pub(crate) fn transport_timeout_ms(&self, now: Millis) -> u32 {
        let t = self.core.recv_timeout;
        let recv_to = self.timers_recv_left_ms(now);
        let mut send_to = third(t);
        if self.core.state.is_connected() {
            let left = third(t).saturating_sub(elapsed(now, self.timers.last_send));
            if left > 0 {
                send_to = left;
            }
        }
        let tcp_connecting = self.core.phase == Phase::TcpConnecting;
        let mut timeout = match (tcp_connecting, self.cfg.connect_timeout_ms) {
            (true, Some(bound)) => {
                // The connect bound replaces the receive rule.
                let started = self.timers.connect_started_at.unwrap_or(now);
                let connect_left = i64::from(bound).saturating_sub(elapsed(now, started));
                send_to.min(connect_left)
            }
            _ => recv_to.min(send_to),
        };
        if self.core.state == State::ReadOnly {
            let rw_left = i64::from(self.timers.rw_timeout_ms)
                .saturating_sub(elapsed(now, self.timers.last_ping_rw));
            timeout = timeout.min(rw_left);
        }
        if let Phase::TlsHandshaking { deadline } = self.core.phase {
            timeout = timeout.min(until(now, deadline));
        }
        if self.compat.close_mode == CloseMode::Drain && self.close.closing {
            if let Some(deadline) = self.close.deadline {
                timeout = timeout.min(until(now, deadline));
            }
        }
        clamp_timeout(timeout)
    }

    /// Emits the deadline WARN at the start of an iteration.
    ///
    /// Contract: when `next_deadline` is set and
    /// `now - next_deadline > min(T/10, 200)`, log "Exceeded deadline by
    /// %dms".
    pub(crate) fn check_deadline_warn(&mut self, now: Millis) {
        let Some(deadline) = self.timers.next_deadline else {
            return;
        };
        let late = until(deadline, now);
        let max_exceed = i64::from(self.core.recv_timeout)
            .checked_div(10)
            .unwrap_or(0)
            .min(DEADLINE_WARN_MAX_MS);
        if late > max_exceed {
            self.emit_log(LogSite::DeadlineExceeded, || vec![LogArg::I64(late)]);
        }
    }

    /// Queues a ping frame (xid -2, op 11) at the tail and records
    /// `last_ping`.
    pub(crate) fn queue_ping(&mut self, now: Millis) {
        self.requests.push_tail(OutFrame::plain(
            FrameKind::Ping,
            Self::request_frame(xid::PING, opcode::PING, &[]),
        ));
        self.timers.last_ping = now;
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::compat::Compat;
    use crate::config::DriverMode;
    use crate::interest::test_support::{Tk, conn, conn_with, init_two, sa};
    use crate::request::Route;
    use crate::requests::{Pending, Shape};

    /// Makes a connected legacy connection with fresh timers at 0.
    fn connected() -> Connection<Tk> {
        let mut c = conn();
        init_two(&mut c);
        c.core.has_transport = true;
        c.core.state = State::Connected;
        c.core.phase = Phase::Established;
        c
    }

    /// Returns a FIFO entry with no watch.
    fn pending() -> Pending<Tk> {
        Pending {
            xid: 1,
            shape: Shape::Data,
            route: Route::Queued,
            token: 7,
            watch: None,
            unwatch: None,
            written: true,
        }
    }

    #[test]
    fn receive_deadline_boundary() {
        let mut c = connected();
        // T = 30 s: the deadline is 2/3 T = 20 s after the last frame.
        c.timers.last_send = Millis(19_999);
        assert!(c.run_timers(Millis(19_999)).is_none());
        assert_eq!(c.timers_recv_left_ms(Millis(19_999)), 1);
        assert_eq!(c.core.errno_hint, None);
        // At 20 s the rule fires: recv_to is 0.
        assert_eq!(c.timers_recv_left_ms(Millis(20_000)), 0);
        assert_eq!(c.timers_recv_overdue_ms(Millis(20_250)), 250);
    }

    /// Rule: state 7 gets no receive deadline exemption. A connect bound
    /// takes the place of the receive deadline in the TCP-connect phase.
    #[test]
    fn receive_deadline_exemptions() {
        // State 7 in the TCP-connect phase is not exempt (spec). The tv is
        // min(recv_to, T/3), and the teardown runs at 2/3 T.
        let mut c = conn();
        init_two(&mut c);
        c.core.has_transport = true;
        c.core.state = State::SslConnecting;
        c.core.phase = Phase::TcpConnecting;
        assert_eq!(c.transport_timeout_ms(Millis(1_000)), 10_000);
        assert_eq!(c.transport_timeout_ms(Millis(15_000)), 5_000);
        assert_eq!(c.transport_timeout_ms(Millis(19_999)), 1);
        assert!(c.run_timers(Millis(19_999)).is_none());
        assert!(c.core.has_transport);
        assert!(c.run_timers(Millis(20_000)).is_none());
        assert!(!c.core.has_transport);
        assert_eq!(c.core.errno_hint, Some(ETIMEDOUT));
        assert_eq!(c.interest.rc, zk_jute::rc::ZOPERATIONTIMEOUT);

        // With a connect bound, state 1 is exempt until the bound.
        let (mut n, _) = conn_with(Compat::LEGACY_C, DriverMode::ST, |cfg| {
            cfg.connect_timeout_ms = Some(40_000);
        });
        n.core.has_transport = true;
        n.core.state = State::Connecting;
        n.core.phase = Phase::TcpConnecting;
        n.timers.connect_started_at = Some(Millis(0));
        assert!(n.run_timers(Millis(39_999)).is_none());
        assert_eq!(n.core.errno_hint, None);
        // The connect bound replaces recv_to in the timeout.
        assert_eq!(n.transport_timeout_ms(Millis(35_000)), 5_000);
        assert_eq!(n.transport_timeout_ms(Millis(1_000)), 10_000);
    }

    #[test]
    fn tls_handshake_deadline_boundary() {
        let mut c = conn();
        c.core.has_transport = true;
        c.core.state = State::SslConnecting;
        c.core.phase = Phase::TlsHandshaking {
            deadline: Millis(5_000),
        };
        assert!(c.run_timers(Millis(4_999)).is_none());
        assert_eq!(c.transport_timeout_ms(Millis(4_000)), 1_000);
        assert_eq!(c.transport_timeout_ms(Millis(5_000)), 0);
    }

    #[test]
    fn ping_boundary_and_frame() {
        let mut c = connected();
        assert!(c.run_timers(Millis(9_999)).is_none());
        assert!(c.requests.tx.is_empty());
        assert_eq!(c.transport_timeout_ms(Millis(9_999)), 1);
        assert!(c.run_timers(Millis(10_000)).is_none());
        assert_eq!(c.requests.tx.len(), 1);
        let f = &c.requests.tx[0];
        assert_eq!(f.kind, FrameKind::Ping);
        assert_eq!(
            f.bytes.as_slice(),
            &[0, 0, 0, 8, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 11]
        );
        assert_eq!(c.timers.last_ping, Millis(10_000));
        // send_to resets to T/3 once the send deadline is past.
        assert_eq!(c.transport_timeout_ms(Millis(10_000)), 10_000);
        assert_eq!(c.transport_timeout_ms(Millis(15_000)), 5_000);
    }

    #[test]
    fn interest_records_the_queued_ping() {
        let mut c = connected();
        assert!(c.begin_interest(Millis(9_999)).is_ok());
        assert!(c.run_timers(Millis(9_999)).is_none());
        assert!(!c.interest_queued_ping());
        assert!(c.run_timers(Millis(10_000)).is_none());
        assert!(c.interest_queued_ping());
        // The next call starts with no ping.
        assert!(c.begin_interest(Millis(10_001)).is_ok());
        assert!(!c.interest_queued_ping());
    }

    #[test]
    fn ping_queue_holds_one_unsent_ping() {
        for compat in [Compat::LEGACY_C, Compat::NATIVE] {
            let (mut c, _) = conn_with(compat, DriverMode::ST, |_| {});
            init_two(&mut c);
            c.core.has_transport = true;
            c.core.state = State::Connected;
            c.core.phase = Phase::Established;
            // The socket takes no bytes, but frames keep arriving.
            for now in (10_000..10_100).step_by(10) {
                c.timers.last_recv = Millis(now);
                assert!(c.run_timers(Millis(now)).is_none());
            }
            let pings = c
                .requests
                .tx
                .iter()
                .filter(|f| f.kind == FrameKind::Ping)
                .count();
            assert_eq!(pings, 1, "{compat:?}");
            assert_eq!(c.timers.last_ping, Millis(10_000));
            // After the ping leaves the queue, the next deadline adds one.
            c.requests.tx.clear();
            c.timers.last_send = Millis(10_100);
            c.timers.last_recv = Millis(20_100);
            assert!(c.run_timers(Millis(20_100)).is_none());
            assert_eq!(c.requests.tx.len(), 1);
        }
    }

    #[test]
    fn ping_waits_for_an_empty_fifo_in_legacy() {
        let mut c = connected();
        c.requests.fifo.push_back(pending());
        assert!(c.run_timers(Millis(10_000)).is_none());
        assert!(c.requests.tx.is_empty());

        let compat = Compat {
            ping_when_outstanding: true,
            ..Compat::LEGACY_C
        };
        let (mut n, _) = conn_with(compat, DriverMode::ST, |_| {});
        n.core.has_transport = true;
        n.core.state = State::Connected;
        n.core.phase = Phase::Established;
        n.requests.fifo.push_back(pending());
        assert!(n.run_timers(Millis(10_000)).is_none());
        assert_eq!(n.requests.tx.len(), 1);
    }

    #[test]
    fn read_only_probe_boundary_and_backoff() {
        let mut c = connected();
        c.core.state = State::ReadOnly;
        let mut now = 0u64;
        let mut expected = RW_PROBE_MIN_MS;
        for _ in 0..12 {
            // Keep the ping and the receive rule quiet.
            c.timers.last_send = Millis(now);
            c.timers.last_recv = Millis(now);
            let edge = now + u64::from(expected);
            c.timers.last_send = Millis(edge - 1);
            c.timers.last_recv = Millis(edge - 1);
            assert!(c.run_timers(Millis(edge - 1)).is_none());
            assert_eq!(c.transport_timeout_ms(Millis(edge - 1)), 1);
            c.timers.last_send = Millis(edge);
            c.timers.last_recv = Millis(edge);
            let Some(Action::ProbeRw { endpoint, tls }) = c.run_timers(Millis(edge)) else {
                panic!("expected ProbeRw");
            };
            assert_eq!(endpoint.addr, sa("10.0.0.1:2181"));
            assert_eq!(tls, None);
            assert_eq!(c.timers.last_ping_rw, Millis(edge));
            expected = (expected * 2).min(RW_PROBE_MAX_MS);
            assert_eq!(c.timers.rw_timeout_ms, expected);
            now = edge;
        }
        assert_eq!(c.timers.rw_timeout_ms, RW_PROBE_MAX_MS);
    }

    #[test]
    fn drain_close_caps_the_timeout() {
        let compat = Compat {
            close_mode: CloseMode::Drain,
            ..Compat::LEGACY_C
        };
        let (mut c, _) = conn_with(compat, DriverMode::ST, |_| {});
        c.core.has_transport = true;
        c.core.state = State::Connected;
        c.core.phase = Phase::Established;
        c.close.closing = true;
        c.close.deadline = Some(Millis(1_500));
        assert_eq!(c.transport_timeout_ms(Millis(1_000)), 500);
        assert_eq!(c.transport_timeout_ms(Millis(2_000)), 0);
    }

    #[test]
    fn no_timer_runs_without_transport() {
        let mut c = conn();
        c.core.state = State::Connected;
        assert!(c.run_timers(Millis(100_000)).is_none());
        assert!(c.requests.tx.is_empty());
    }
}
