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

//! The interest iteration and the action queue.
//!
//! The module owns [`InterestState`]. One iteration is `begin_interest`,
//! `poll_action` until `None`, then `finish_interest`. It follows the
//! order of C `zookeeper_interest`.

use std::collections::VecDeque;

use zk_jute::rc;

use crate::action::{Action, Interest, InterestOutcome};
use crate::compat::Backoff;
use crate::config::InterestBits;
use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::hosts::ConnectDecision;
use crate::state::Phase;
use crate::time::{Millis, clamp_timeout, until};

/// The next step of the running iteration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum IterStep {
    /// No iteration runs. `poll_action` yields only queued actions.
    #[default]
    Idle,
    /// Step 1: resolution.
    Resolve,
    /// Step 2: the connect decision.
    Connect,
    /// Step 3: SASL calls.
    Sasl,
    /// Step 4: the timers.
    Timers,
    /// Step 5: the queued actions, `CloseTransport` included.
    Drain,
    /// The iteration yielded everything.
    Done,
}

/// The state of the interest iteration.
pub(crate) struct InterestState {
    /// The next step.
    pub(crate) step: IterStep,
    /// The rc that `finish_interest` returns.
    pub(crate) rc: i32,
    /// False when `finish_interest` must return `outputs: None`.
    pub(crate) write_outputs: bool,
    /// The actions that inputs outside the iteration steps produced, in
    /// order. `CloseTransport` is always before any later `Connect`.
    pub(crate) queued: VecDeque<Action>,
    /// True when the transport closed during the current call.
    pub(crate) closed_this_call: bool,
    /// True when the connect decision chose a backoff wait.
    pub(crate) backoff_wait: bool,
    /// True when the timer step queued a ping in the current call.
    pub(crate) ping_queued: bool,
}

impl InterestState {
    /// Makes an idle state.
    pub(crate) fn new() -> Self {
        Self {
            step: IterStep::Idle,
            rc: zk_jute::rc::ZOK,
            write_outputs: true,
            queued: VecDeque::new(),
            closed_this_call: false,
            backoff_wait: false,
            ping_queued: false,
        }
    }
}

impl<T: Tokens> Connection<T> {
    /// Starts one interest iteration.
    ///
    /// Contract:
    /// - An unrecoverable state, or a suspended stage, returns
    ///   `Err(ZINVALIDSTATE)` and starts nothing.
    /// - Otherwise it runs `check_deadline_warn`, resets the iteration
    ///   fields, sets `step = Resolve` and returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns `ZINVALIDSTATE` as stated.
    pub fn begin_interest(&mut self, now: Millis) -> Result<(), i32> {
        if self.core.state.is_unrecoverable() || self.out.is_suspended() {
            return Err(rc::ZINVALIDSTATE);
        }
        self.check_deadline_warn(now);
        self.interest.rc = rc::ZOK;
        self.interest.write_outputs = true;
        self.interest.closed_this_call = false;
        self.interest.backoff_wait = false;
        self.interest.ping_queued = false;
        self.hosts.block_connect = false;
        self.interest.step = IterStep::Resolve;
        Ok(())
    }

    /// Returns the next driver action, or `None`.
    ///
    /// Contract:
    /// - While a stage is suspended it returns `None`.
    /// - Queued actions go first, in order (`CloseTransport` from a
    ///   teardown or forced close, `Sasl` calls after `handle_read`).
    /// - Inside an iteration it runs the steps in order: `resolve_action`,
    ///   `connect_decision` (no transport and no close only), `poll_sasl_action`,
    ///   `run_timers`, then the queued actions again.
    /// - A whole-list resolution failure under `LegacyRcPreserved` with no
    ///   transport ends the list and clears `write_outputs`.
    /// - After `destroy` it yields `CloseTransport`, then the final
    ///   `Sasl(Dispose)`.
    pub fn poll_action(&mut self, now: Millis) -> Option<Action> {
        if self.out.is_suspended() {
            return None;
        }
        if let Some(action) = self.interest.queued.pop_front() {
            return Some(action);
        }
        if self.close.destroyed {
            // After destroy only the final mechanism calls remain.
            return self.interest_sasl_action();
        }
        loop {
            match self.interest.step {
                IterStep::Idle | IterStep::Done => {
                    // The first resolution of a handle runs outside an
                    // iteration, as zookeeper_init resolves at once.
                    if self.hosts.initial && !self.close.closing {
                        if let Some(action) = self.resolve_action(now) {
                            return Some(action);
                        }
                    }
                    return self.interest_sasl_action();
                }
                IterStep::Resolve => {
                    self.interest.step = IterStep::Connect;
                    if let Some(action) = self.resolve_action(now) {
                        return Some(action);
                    }
                }
                IterStep::Connect => {
                    self.interest.step = IterStep::Sasl;
                    // A closing connection makes no new transport, as the
                    // C IO loop stops at `close_requested`.
                    if self.core.has_transport || self.close.closing {
                        continue;
                    }
                    // C returns from update_addrs before the delay check,
                    // so the block goes before the connect decision.
                    if self.hosts.block_connect {
                        self.interest_end_unwritten();
                        return None;
                    }
                    match self.connect_decision(now) {
                        ConnectDecision::Connect(action) => {
                            // An earlier close of this call is past. The
                            // new transport is the socket of the outputs.
                            self.interest.closed_this_call = false;
                            return Some(action);
                        }
                        ConnectDecision::Wait => self.interest.backoff_wait = true,
                        ConnectDecision::Blocked => {
                            self.interest_end_unwritten();
                            return None;
                        }
                        ConnectDecision::Failed => {
                            // C returns at once after the socket failure.
                            self.interest.step = IterStep::Drain;
                        }
                    }
                }
                IterStep::Sasl => {
                    if let Some(action) = self.interest_sasl_action() {
                        return Some(action);
                    }
                    self.interest.step = IterStep::Timers;
                }
                IterStep::Timers => {
                    self.interest.step = IterStep::Drain;
                    if let Some(action) = self.run_timers(now) {
                        return Some(action);
                    }
                }
                IterStep::Drain => {
                    // The queue was empty at the top of this call.
                    self.interest.step = IterStep::Done;
                    return None;
                }
            }
            if let Some(action) = self.interest.queued.pop_front() {
                return Some(action);
            }
        }
    }

    /// Ends the iteration and returns the rc and the interest.
    ///
    /// Contract:
    /// - `outputs` is `None` where C returns before it writes its outputs.
    /// - No transport: `read = write = false`, and `timeout_ms` is T/60
    ///   after a `OneShotSkip` wait, `not_before - now` in a `Deadline`
    ///   pause, else 0.
    /// - With a transport: `read` is true unless the decoder is stalled;
    ///   `write` follows `DriverMode::interest` (`write_interest`);
    ///   `timeout_ms` from `transport_timeout_ms`.
    /// - `has_socket` is false when the transport closed in this call.
    /// - It records `timers.next_deadline` and sets `step = Idle`.
    pub fn finish_interest(&mut self, now: Millis) -> InterestOutcome {
        let rc = self.interest.rc;
        let outputs = if !self.interest.write_outputs {
            None
        } else if self.core.has_transport {
            let timeout_ms = self.transport_timeout_ms(now);
            // C records the deadline only in its socket block.
            self.timers.next_deadline = Some(now.saturating_add_ms(u64::from(timeout_ms)));
            Some(Interest {
                has_socket: !self.interest.closed_this_call,
                // A stalled decoder takes no bytes. Read interest stops
                // until the receive timeout ends the transport. This replaces
                // the busy loop of C for a negative frame length.
                read: !self.recv.stalled,
                write: self.write_interest(),
                timeout_ms,
            })
        } else {
            let timeout_ms = match self.compat.reconnect_backoff {
                Backoff::OneShotSkip if self.interest.backoff_wait => clamp_timeout(
                    i64::from(self.core.recv_timeout)
                        .checked_div(60)
                        .unwrap_or(0),
                ),
                Backoff::Deadline => self
                    .hosts
                    .not_before
                    .map_or(0, |nb| clamp_timeout(until(now, nb))),
                Backoff::OneShotSkip => 0,
            };
            Some(Interest {
                has_socket: false,
                read: false,
                write: false,
                timeout_ms,
            })
        };
        self.interest.step = IterStep::Idle;
        InterestOutcome { rc, outputs }
    }

    /// Returns true when the timer step of the current or last interest
    /// call queued a ping. The st driver then flushes the send queue in
    /// that call, as C `send_ping` does.
    #[must_use]
    pub fn interest_queued_ping(&self) -> bool {
        self.interest.ping_queued
    }

    /// Returns the write interest of an iteration with a transport.
    ///
    /// Contract: `LegacyExact` is `(has_unsent && (connected ||
    /// sasl)) || phase == TcpConnecting || connect_frame_unwritten`, and
    /// false in TlsHandshaking and TlsConfigFailed. `Precise` is true only
    /// when `poll_transmit` would copy a byte.
    pub(crate) fn write_interest(&self) -> bool {
        if !self.core.has_transport {
            return false;
        }
        match self.mode.interest {
            InterestBits::LegacyExact => match self.core.phase {
                Phase::TlsHandshaking { .. } | Phase::TlsConfigFailed => false,
                phase => {
                    let ready = self.core.state.is_connected() || matches!(phase, Phase::Sasl(_));
                    (self.requests.has_unsent() && ready)
                        || phase == Phase::TcpConnecting
                        || self.requests.connect_frame_unwritten()
                }
            },
            InterestBits::Precise => self.interest_would_transmit(),
        }
    }

    /// Returns true when `poll_transmit` would copy a byte now. It walks
    /// `tx` as `poll_transmit` does: the gate stops the walk, and the
    /// bytes already copied and not acknowledged are skipped.
    fn interest_would_transmit(&self) -> bool {
        if !self.requests.has_unsent() {
            return false;
        }
        let mut copied = self.requests.unacked;
        for frame in &self.requests.tx {
            if !self.may_send(frame.kind) {
                return false;
            }
            let left = frame.len().saturating_sub(frame.written);
            if left > copied {
                return true;
            }
            copied = copied.saturating_sub(left);
        }
        false
    }

    /// Ends the action list of an iteration where C returns before it
    /// writes its outputs.
    fn interest_end_unwritten(&mut self) {
        self.interest.write_outputs = false;
        self.interest.step = IterStep::Done;
    }

    /// Returns the next SASL call. The SASL module holds the order and
    /// the outstanding wait. With no call queued nothing is due.
    fn interest_sasl_action(&mut self) -> Option<Action> {
        if self.sasl.calls.is_empty() {
            return None;
        }
        self.poll_sasl_action()
    }

    /// Queues `CloseTransport` and records the close for `has_socket`.
    /// It does nothing when one is already queued.
    pub(crate) fn queue_close_transport(&mut self) {
        let queued = self
            .interest
            .queued
            .iter()
            .any(|a| matches!(a, Action::CloseTransport));
        if !queued {
            self.interest.queued.push_back(Action::CloseTransport);
        }
        self.interest.closed_this_call = true;
    }
}

/// Fixtures that the unit tests of the interest, timer and host
/// modules share.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
pub(crate) mod test_support {
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use crate::compat::Compat;
    use crate::config::{Config, DriverMode, Endpoint, HostSpec, HostToken};
    use crate::connection::Connection;
    use crate::hooks::{AllLevels, NoDefaultWatcher, Rng, Tokens};
    use crate::legacy::connect::HostSpec as LegacyHostSpec;
    use crate::log::{LogRecord, LogSite};
    use crate::output::Output;
    use crate::time::Millis;

    /// Token types of the tests.
    pub(crate) struct Tk;
    impl Tokens for Tk {
        type Completion = u32;
        type Watcher = u32;
        type Auth = u32;
    }

    /// The scripted values and the call counts of [`TestRng`].
    #[derive(Default)]
    pub(crate) struct Draws {
        /// The next `random` values. An empty queue gives 0.
        pub(crate) random: VecDeque<i64>,
        /// The next `drand48` values. An empty queue gives 0.0.
        pub(crate) drand: VecDeque<f64>,
        /// The count of `random` calls.
        pub(crate) random_calls: usize,
        /// The count of `drand48` calls.
        pub(crate) drand_calls: usize,
        /// The count of `on_resolution` calls.
        pub(crate) resolutions: usize,
    }

    /// A scripted random source with shared call counts.
    pub(crate) struct TestRng(pub(crate) Arc<Mutex<Draws>>);
    impl Rng for TestRng {
        fn on_resolution(&mut self) {
            self.0.lock().unwrap().resolutions += 1;
        }
        fn random(&mut self) -> i64 {
            let mut d = self.0.lock().unwrap();
            d.random_calls += 1;
            d.random.pop_front().unwrap_or(0)
        }
        fn drand48(&mut self) -> f64 {
            let mut d = self.0.lock().unwrap();
            d.drand_calls += 1;
            d.drand.pop_front().unwrap_or(0.0)
        }
    }

    /// Returns a socket address.
    pub(crate) fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Returns a legacy host entry.
    pub(crate) fn host(name: &str, port: u16) -> HostSpec {
        HostSpec::Legacy(LegacyHostSpec {
            host: name.as_bytes().to_vec(),
            service: port.to_string().into_bytes(),
            port: i32::from(port),
        })
    }

    /// Returns an endpoint with the host token of entry `index`.
    pub(crate) fn ep(addr: &str, index: usize, name: &str) -> Endpoint {
        Endpoint {
            addr: sa(addr),
            host: HostToken {
                index,
                name: name.as_bytes().to_vec(),
            },
        }
    }

    /// Makes a connection with the hosts `a:2181` and `b:2181`.
    pub(crate) fn conn_with(
        compat: Compat,
        mode: DriverMode,
        edit: impl FnOnce(&mut Config),
    ) -> (Connection<Tk>, Arc<Mutex<Draws>>) {
        let mut cfg = Config::legacy(30_000);
        cfg.hosts = vec![host("a", 2181), host("b", 2181)];
        cfg.host_text = zk_jute::JString::Bytes(b"a:2181,b:2181".to_vec());
        edit(&mut cfg);
        let draws = Arc::new(Mutex::new(Draws::default()));
        let conn = Connection::new(
            cfg,
            compat,
            mode,
            Box::new(TestRng(Arc::clone(&draws))),
            Box::new(AllLevels),
            Box::new(NoDefaultWatcher),
            Millis(0),
        );
        (conn, draws)
    }

    /// Makes a legacy connection.
    pub(crate) fn conn() -> Connection<Tk> {
        conn_with(Compat::LEGACY_C, DriverMode::ST, |_| {}).0
    }

    /// Takes every pending log record.
    pub(crate) fn logs(conn: &mut Connection<Tk>) -> Vec<LogRecord> {
        let mut out = Vec::new();
        while let Some(o) = conn.poll_output() {
            if let Output::Log(r) = o {
                out.push(r);
            }
        }
        out
    }

    /// Takes the sites of every pending log record.
    pub(crate) fn sites(conn: &mut Connection<Tk>) -> Vec<LogSite> {
        logs(conn).into_iter().map(|r| r.site).collect()
    }

    /// Answers a `Resolve` action: host 0 gives `a`, host 1 gives `b`.
    /// `None` fails the host.
    pub(crate) fn answer(
        conn: &mut Connection<Tk>,
        generation: u64,
        per_host: &[Option<&str>],
        now: Millis,
    ) -> i32 {
        for (i, a) in per_host.iter().enumerate() {
            let result = match a {
                Some(addr) => Ok(vec![sa(addr)]),
                None => Err(crate::action::ResolveError {
                    gai_rc: -2,
                    errno: 2,
                }),
            };
            conn.handle_host_resolved(
                generation,
                crate::action::HostResolution {
                    host: i,
                    result,
                    skipped_families: Vec::new(),
                },
                now,
            );
        }
        conn.handle_resolved(generation, false, now)
    }

    /// Commits the list `a=10.0.0.1:2181`, `b=10.0.0.2:2181` through the
    /// first `Resolve` action.
    pub(crate) fn init_two(conn: &mut Connection<Tk>) {
        let Some(crate::action::Action::Resolve {
            generation,
            initial: true,
            ..
        }) = conn.poll_action(Millis(0))
        else {
            panic!("no initial Resolve");
        };
        let rc = answer(
            conn,
            generation,
            &[Some("10.0.0.1:2181"), Some("10.0.0.2:2181")],
            Millis(0),
        );
        assert_eq!(rc, zk_jute::rc::ZOK);
        let _ = logs(conn);
    }

    /// Runs one iteration with no transport. Each `Resolve` gets the two
    /// good addresses. It returns the other actions and the outcome.
    pub(crate) fn iterate(
        conn: &mut Connection<Tk>,
        now: Millis,
    ) -> (Vec<crate::action::Action>, crate::action::InterestOutcome) {
        conn.begin_interest(now).unwrap();
        let mut actions = Vec::new();
        while let Some(a) = conn.poll_action(now) {
            if let crate::action::Action::Resolve { generation, .. } = a {
                answer(
                    conn,
                    generation,
                    &[Some("10.0.0.1:2181"), Some("10.0.0.2:2181")],
                    now,
                );
            } else {
                actions.push(a);
            }
        }
        (actions, conn.finish_interest(now))
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
    use super::test_support::{conn, conn_with, iterate, sa, sites};
    use super::*;
    use crate::compat::Compat;
    use crate::config::DriverMode;
    use crate::log::LogSite;
    use crate::requests::{FrameKind, OutFrame};
    use crate::state::State;

    /// Returns the address of a `Connect` action.
    fn connect_addr(a: &Action) -> std::net::SocketAddr {
        match a {
            Action::Connect { endpoint, .. } => endpoint.addr,
            other => panic!("not a Connect: {other:?}"),
        }
    }

    #[test]
    fn full_iteration_without_transport_resolves_then_connects() {
        let mut c = conn();
        c.begin_interest(Millis(0)).unwrap();
        let Some(Action::Resolve {
            generation,
            hosts,
            initial,
        }) = c.poll_action(Millis(0))
        else {
            panic!("expected Resolve");
        };
        assert!(initial);
        assert_eq!(hosts.len(), 2);
        let rc = super::test_support::answer(
            &mut c,
            generation,
            &[Some("10.0.0.1:2181"), Some("10.0.0.2:2181")],
            Millis(0),
        );
        assert_eq!(rc, rc::ZOK);
        let Some(Action::Connect { endpoint, tls }) = c.poll_action(Millis(0)) else {
            panic!("expected Connect");
        };
        assert_eq!(endpoint.addr, sa("10.0.0.1:2181"));
        assert_eq!(endpoint.host.name, b"a".to_vec());
        assert_eq!(tls, None);
        assert_eq!(c.current_server(), Some(sa("10.0.0.1:2181")));
        assert!(c.poll_action(Millis(0)).is_none());
        let out = c.finish_interest(Millis(0));
        assert_eq!(out.rc, rc::ZOK);
        assert_eq!(
            out.outputs,
            Some(Interest {
                has_socket: false,
                read: false,
                write: false,
                timeout_ms: 0,
            })
        );
        assert_eq!(c.interest.step, IterStep::Idle);

        // The legacy cadence resolves again in the next iteration.
        c.begin_interest(Millis(1)).unwrap();
        let Some(Action::Resolve { initial, .. }) = c.poll_action(Millis(1)) else {
            panic!("expected Resolve");
        };
        assert!(!initial);
    }

    #[test]
    fn begin_interest_rejects_unrecoverable_state() {
        let mut c = conn();
        c.core.state = State::ExpiredSession;
        assert_eq!(c.begin_interest(Millis(0)), Err(rc::ZINVALIDSTATE));
        assert_eq!(c.interest.step, IterStep::Idle);
    }

    /// Rule: with no transport, a whole-list resolution failure blocks the
    /// connect and writes no outputs.
    #[test]
    fn whole_list_failure_legacy_rc_preserved_blocks_and_hides_outputs() {
        let mut c = conn();
        super::test_support::init_two(&mut c);
        c.hosts.delay = true;
        c.begin_interest(Millis(5)).unwrap();
        let Some(Action::Resolve { generation, .. }) = c.poll_action(Millis(5)) else {
            panic!("expected Resolve");
        };
        let rc = super::test_support::answer(&mut c, generation, &[None, None], Millis(5));
        assert_eq!(rc, rc::ZSYSTEMERROR);
        assert_eq!(c.take_errno_hint(), Some(2));
        assert!(c.poll_action(Millis(5)).is_none());
        let out = c.finish_interest(Millis(5));
        assert_eq!(out.rc, rc::ZSYSTEMERROR);
        assert_eq!(out.outputs, None);
        // C returns before the delay check, so the delay stays.
        assert!(c.hosts.delay);
        let s = sites(&mut c);
        assert_eq!(s.len(), 2);
        assert!(!s.contains(&LogSite::DelayingConnection));
        // The last good list stays.
        assert_eq!(c.hosts.servers.addrs.len(), 2);
    }

    /// Rule: with a transport, a whole-list resolution failure keeps the
    /// resolver rc and writes the outputs.
    #[test]
    fn whole_list_failure_with_transport_keeps_rc_and_writes_outputs() {
        let mut c = conn();
        super::test_support::init_two(&mut c);
        c.core.has_transport = true;
        c.core.state = State::Connected;
        c.core.phase = Phase::Established;
        c.begin_interest(Millis(1000)).unwrap();
        let Some(Action::Resolve { generation, .. }) = c.poll_action(Millis(1000)) else {
            panic!("expected Resolve");
        };
        let rc = super::test_support::answer(&mut c, generation, &[None, None], Millis(1000));
        assert_eq!(rc, rc::ZSYSTEMERROR);
        assert!(!c.hosts.block_connect);
        assert!(c.poll_action(Millis(1000)).is_none());
        let out = c.finish_interest(Millis(1000));
        assert_eq!(out.rc, rc::ZSYSTEMERROR);
        assert_eq!(
            out.outputs,
            Some(Interest {
                has_socket: true,
                read: true,
                write: false,
                timeout_ms: 9_000,
            })
        );
        assert_eq!(c.timers.next_deadline, Some(Millis(10_000)));
    }

    /// Rule: after a full pass, `OneShotSkip` waits for one iteration only.
    #[test]
    fn one_shot_skip_waits_one_iteration_after_a_full_pass() {
        let mut c = conn();
        super::test_support::init_two(&mut c);
        // The first pass goes through `new`. Then `addrs` gives A, B.
        let mut seen = Vec::new();
        let mut now = 0;
        let mut waits = Vec::new();
        while seen.len() < 6 {
            now += 10;
            let (actions, out) = iterate(&mut c, Millis(now));
            match actions.first() {
                Some(a) => {
                    seen.push(connect_addr(a));
                    assert_eq!(out.outputs.unwrap().timeout_ms, 0);
                    // The driver reports a failure: teardown stage T5.
                    c.hosts_on_handle_error(Millis(now));
                }
                None => {
                    waits.push(seen.len());
                    assert_eq!(out.outputs.unwrap().timeout_ms, 500);
                    assert!(sites(&mut c).contains(&LogSite::DelayingConnection));
                }
            }
        }
        let a = sa("10.0.0.1:2181");
        let b = sa("10.0.0.2:2181");
        // SingleAdvance: each failure moves the cursor once.
        assert_eq!(seen, vec![a, b, a, b, a, b]);
        // The first pass through `new` gives no delay. Each later full
        // pass over `addrs` gives one.
        assert_eq!(waits, vec![4]);
    }

    /// Rule: after a failure, the current server is the peeked address.
    #[test]
    fn single_advance_reports_the_peeked_server_after_a_failure() {
        let mut c = conn();
        super::test_support::init_two(&mut c);
        c.hosts.servers.reconfig = false;
        c.cycle_next_server();
        assert_eq!(c.current_server(), Some(sa("10.0.0.1:2181")));
        c.hosts_on_handle_error(Millis(0));
        assert_eq!(c.current_server(), Some(sa("10.0.0.2:2181")));
        assert!(!c.hosts.delay);
        c.cycle_next_server();
        assert_eq!(c.current_server(), Some(sa("10.0.0.2:2181")));
        c.hosts_on_handle_error(Millis(0));
        assert_eq!(c.current_server(), Some(sa("10.0.0.1:2181")));
        assert!(c.hosts.delay);
    }

    #[test]
    fn deadline_backoff_pauses_until_not_before() {
        let compat = Compat {
            reconnect_backoff: crate::compat::Backoff::Deadline,
            ..Compat::LEGACY_C
        };
        let (mut c, draws) = conn_with(compat, DriverMode::ST, |cfg| {
            cfg.reconnect_delay_ms = 1000;
            cfg.reconnect_jitter_pct = 10;
        });
        super::test_support::init_two(&mut c);
        c.hosts.servers.reconfig = false;
        c.hosts.servers.addrs.reset();
        let _ = c.hosts.servers.addrs.next_item();
        let _ = c.hosts.servers.addrs.next_item();
        // j = 100, so the draw 150 gives the offset +50.
        draws.lock().unwrap().random.push_back(150);
        c.hosts_on_handle_error(Millis(5000));
        assert_eq!(draws.lock().unwrap().random_calls, 1);
        assert!(!c.hosts.delay);
        assert_eq!(c.hosts.not_before, Some(Millis(6050)));

        let (actions, out) = iterate(&mut c, Millis(5000));
        assert!(actions.is_empty());
        assert_eq!(out.outputs.unwrap().timeout_ms, 1050);
        assert!(!sites(&mut c).contains(&LogSite::DelayingConnection));

        let (actions, out) = iterate(&mut c, Millis(6049));
        assert!(actions.is_empty());
        assert_eq!(out.outputs.unwrap().timeout_ms, 1);

        let (actions, _) = iterate(&mut c, Millis(6050));
        assert_eq!(connect_addr(&actions[0]), sa("10.0.0.1:2181"));
        assert_eq!(c.hosts.not_before, None);
    }

    #[test]
    fn deadline_backoff_with_zero_delay_draws_nothing() {
        let compat = Compat {
            reconnect_backoff: crate::compat::Backoff::Deadline,
            ..Compat::LEGACY_C
        };
        let (mut c, draws) = conn_with(compat, DriverMode::ST, |_| {});
        super::test_support::init_two(&mut c);
        c.hosts.servers.addrs.reset();
        let _ = c.hosts.servers.addrs.next_item();
        let _ = c.hosts.servers.addrs.next_item();
        c.hosts_on_handle_error(Millis(5000));
        assert_eq!(draws.lock().unwrap().random_calls, 0);
        assert_eq!(c.hosts.not_before, None);
        let (actions, _) = iterate(&mut c, Millis(5000));
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn finish_interest_timeouts_per_case() {
        // No transport and no backoff: 0.
        let mut c = conn();
        super::test_support::init_two(&mut c);
        c.interest.step = IterStep::Done;
        let out = c.finish_interest(Millis(0));
        assert_eq!(out.outputs.unwrap().timeout_ms, 0);
        assert_eq!(c.timers.next_deadline, None);

        // OneShotSkip wait: T/60.
        c.interest.backoff_wait = true;
        assert_eq!(
            c.finish_interest(Millis(0)).outputs.unwrap().timeout_ms,
            500
        );
        c.interest.backoff_wait = false;

        // Deadline pause: not_before - now.
        let compat = Compat {
            reconnect_backoff: crate::compat::Backoff::Deadline,
            ..Compat::LEGACY_C
        };
        let (mut d, _) = conn_with(compat, DriverMode::ST, |_| {});
        d.hosts.not_before = Some(Millis(700));
        d.interest.backoff_wait = true;
        assert_eq!(
            d.finish_interest(Millis(200)).outputs.unwrap().timeout_ms,
            500
        );
        assert_eq!(
            d.finish_interest(Millis(900)).outputs.unwrap().timeout_ms,
            0
        );

        // Transport: the transport timeout, and the deadline is recorded.
        c.core.has_transport = true;
        c.core.state = State::Connecting;
        c.core.phase = Phase::TcpConnecting;
        let out = c.finish_interest(Millis(100));
        assert_eq!(
            out.outputs,
            Some(Interest {
                has_socket: true,
                read: true,
                write: true,
                timeout_ms: 10_000,
            })
        );
        assert_eq!(c.timers.next_deadline, Some(Millis(10_100)));

        // Outputs not written.
        c.interest.write_outputs = false;
        assert_eq!(c.finish_interest(Millis(100)).outputs, None);
    }

    #[test]
    fn stalled_decoder_clears_read_interest() {
        let mut c = conn();
        super::test_support::init_two(&mut c);
        c.core.has_transport = true;
        c.core.state = State::Connected;
        c.core.phase = Phase::Established;
        c.interest.step = IterStep::Done;
        assert!(c.finish_interest(Millis(0)).outputs.unwrap().read);
        // A negative length stalls the decoder under LEGACY_C.
        let r = c.handle_read(&[0xFF, 0xFF, 0xFF, 0xFF, 1, 2], Millis(0));
        assert_eq!(r.consumed, 4);
        assert!(c.recv.stalled);
        let out = c.finish_interest(Millis(0)).outputs.unwrap();
        assert!(!out.read);
        assert!(out.has_socket);
        // The receive timer still runs, so the timeout stays finite.
        assert!(out.timeout_ms > 0);
    }

    #[test]
    fn closed_transport_reports_no_socket() {
        let mut c = conn();
        c.hosts.initial = false;
        c.hosts.resolve_due = false;
        c.begin_interest(Millis(0)).unwrap();
        c.queue_close_transport();
        assert!(matches!(
            c.poll_action(Millis(0)),
            Some(Action::CloseTransport)
        ));
        // The empty list ends the call through the empty-list path, which
        // a teardown needs. Stop before it.
        c.interest.step = IterStep::Drain;
        assert!(c.poll_action(Millis(0)).is_none());
        let out = c.finish_interest(Millis(0));
        assert!(!out.outputs.unwrap().has_socket);
        // The flag stays for a transport that is still recorded.
        c.core.has_transport = true;
        c.interest.closed_this_call = true;
        assert!(!c.finish_interest(Millis(0)).outputs.unwrap().has_socket);
    }

    #[test]
    fn write_interest_legacy_exact() {
        let mut c = conn();
        c.core.has_transport = true;
        c.core.state = State::Connecting;
        c.core.phase = Phase::TcpConnecting;
        assert!(c.write_interest());

        c.core.state = State::SslConnecting;
        c.core.phase = Phase::TlsHandshaking {
            deadline: Millis(10),
        };
        c.requests
            .push_tail(OutFrame::plain(FrameKind::Ping, vec![0; 12]));
        assert!(!c.write_interest());
        c.core.phase = Phase::TlsConfigFailed;
        assert!(!c.write_interest());

        // Associating with an unsent Connect frame.
        c.requests.tx.clear();
        c.core.state = State::Associating;
        c.core.phase = Phase::Associating;
        assert!(!c.write_interest());
        c.requests
            .push_tail(OutFrame::plain(FrameKind::Connect, vec![0; 4]));
        assert!(c.write_interest());

        // Connected with unsent bytes.
        c.requests.tx.clear();
        c.core.state = State::Connected;
        c.core.phase = Phase::Established;
        assert!(!c.write_interest());
        c.requests
            .push_tail(OutFrame::plain(FrameKind::Ping, vec![0; 12]));
        assert!(c.write_interest());

        // Not connected and not in SASL: unsent bytes give no write.
        c.core.state = State::NotConnected;
        c.core.phase = Phase::Idle;
        assert!(!c.write_interest());
    }

    #[test]
    fn write_interest_precise() {
        let (mut c, _) = conn_with(Compat::LEGACY_C, DriverMode::MT, |_| {});
        // TcpConnecting has no bytes to copy, where LegacyExact asks for a
        // write.
        c.core.has_transport = true;
        c.core.state = State::Connecting;
        c.core.phase = Phase::TcpConnecting;
        assert!(!c.write_interest());
        // Acknowledged bytes are not sendable.
        let mut f = OutFrame::plain(FrameKind::Ping, vec![0; 12]);
        f.written = 12;
        c.requests.tx.push_back(f);
        c.core.state = State::Connected;
        c.core.phase = Phase::Established;
        assert!(!c.write_interest());
        // No transport: no write.
        c.requests.tx.clear();
        c.requests
            .push_tail(OutFrame::plain(FrameKind::Ping, vec![0; 12]));
        c.core.has_transport = false;
        assert!(!c.write_interest());
    }

    #[test]
    fn queued_actions_go_first_and_idle_yields_only_them() {
        let mut c = conn();
        c.hosts.initial = false;
        c.interest.queued.push_back(Action::CloseTransport);
        assert!(matches!(
            c.poll_action(Millis(0)),
            Some(Action::CloseTransport)
        ));
        assert!(c.poll_action(Millis(0)).is_none());
    }

    #[test]
    fn deadline_warn_threshold() {
        let mut c = conn();
        c.timers.next_deadline = Some(Millis(1000));
        c.begin_interest(Millis(1200)).unwrap();
        assert!(sites(&mut c).is_empty());
        c.begin_interest(Millis(1201)).unwrap();
        let logs = super::test_support::logs(&mut c);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].site, LogSite::DeadlineExceeded);
        assert_eq!(logs[0].args, vec![crate::log::LogArg::I64(201)]);
        // T/10 is the bound when it is below 200.
        c.core.recv_timeout = 1000;
        c.begin_interest(Millis(1101)).unwrap();
        assert_eq!(sites(&mut c), vec![LogSite::DeadlineExceeded]);
        c.begin_interest(Millis(1100)).unwrap();
        assert!(sites(&mut c).is_empty());
    }
}
