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

//! Close, abandon and destroy.
//!
//! The module owns [`CloseState`]. `Compat::close_mode` selects the C
//! close, which fails pending work at once, or the native drain, which
//! waits for the CLOSE_OP reply.

use std::collections::VecDeque;

use crate::action::CloseProgress;
use crate::compat::CloseMode;
use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::output::{Output, TerminateReason, Work};
use crate::rc;
use crate::recv::Flow;
use crate::requests::{FrameKind, OutFrame, Pending};
use crate::state::Phase;
use crate::teardown::ForcedSnapshot;
use crate::time::Millis;

/// The flush bound of the close in the driver.
pub const CLOSE_FLUSH_MS: u32 = 3000;
/// The read wait after the close flush in the driver.
pub const CLOSE_WAIT_MS: u32 = 1500;

/// The operation that made a close job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CloseKind {
    /// `begin_close`.
    Begin,
    /// `destroy`.
    Destroy,
    /// `abandon`.
    Abandon,
}

/// The next stage of a close job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CloseStage {
    /// Fail the entries with `ZCLOSING`. The job holds the entries left.
    FailFifo,
    /// The auth lock point.
    Lockpoint,
    /// The auth completions.
    Auth,
    /// `DrainPoint` and the rest of the operation.
    Finish,
}

/// A close stage that runs or stopped at a barrier.
pub(crate) struct CloseJob<T: Tokens> {
    /// The operation.
    pub(crate) kind: CloseKind,
    /// The next stage.
    pub(crate) stage: CloseStage,
    /// The entries left to fail: the forced-close snapshot first, then the
    /// FIFO.
    pub(crate) entries: VecDeque<Pending<T>>,
    /// The auth tokens to complete, the snapshot tokens first.
    pub(crate) auth: Vec<T::Auth>,
}

impl<T: Tokens> CloseJob<T> {
    /// Moves every token out of the job.
    pub(crate) fn into_tokens(self) -> (Vec<T::Completion>, Vec<T::Auth>) {
        (
            self.entries.into_iter().map(|p| p.token).collect(),
            self.auth,
        )
    }
}

/// The close state of one connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct CloseState {
    /// True after `begin_close` or `destroy`.
    pub(crate) closing: bool,
    /// The xid of the queued CLOSE_OP.
    pub(crate) close_xid: Option<i32>,
    /// True when `queue_close_op` ran in an established session. The
    /// phase gate then lets every frame go out.
    pub(crate) flush_established: bool,
    /// The deadline of a `Drain` close.
    pub(crate) deadline: Option<Millis>,
    /// True when a `Drain` close completed.
    pub(crate) complete: bool,
    /// The result of a completed `Drain` close. The first
    /// completion sets it, and it does not change after that.
    pub(crate) outcome: Option<i32>,
    /// True after `destroy`.
    pub(crate) destroyed: bool,
    /// True when `queue_close_op` queued nothing.
    op_refused: bool,
    /// The transport epoch when `queue_close_op` queued the CLOSE_OP. A
    /// later epoch means that a teardown ended that transport.
    pub(crate) op_epoch: u64,
    /// A close that waits for a stopped teardown. The teardown started
    /// its T3, so it fails its own snapshot first. The close then runs
    /// when the teardown ends.
    pub(crate) deferred: Option<CloseKind>,
}

impl<T: Tokens> Connection<T> {
    /// Starts a close.
    ///
    /// Contract:
    /// - `LegacyFailPending`: set `closing`; fail the forced snapshot
    ///   entries, then every FIFO entry, with `ZCLOSING` (Direct runs are
    ///   barriers); `AuthLockpoint`; `Auth{ZCLOSING, barrier: false}`;
    ///   `DrainPoint`. No session event. `tx` stays.
    /// - `Drain`: set `closing` and the deadline `now + close_timeout_ms`
    ///   once. The FIFO stays.
    ///
    /// A second `LegacyFailPending` call does nothing, because the first
    /// call failed all pending work.
    ///
    /// A teardown can be stopped in its T3 when the call comes, for
    /// example at a Direct completion. That teardown fails its snapshot
    /// with its own rc first, and the close fails the later work when the
    /// teardown ends. Completions thus keep submission order.
    pub fn begin_close(&mut self, now: Millis) {
        match self.compat.close_mode {
            CloseMode::Drain => {
                self.close.closing = true;
                if self.close.deadline.is_none() {
                    let ms = u64::from(self.cfg.close_timeout_ms);
                    self.close.deadline = Some(now.saturating_add_ms(ms));
                }
            }
            CloseMode::LegacyFailPending => {
                if self.close.closing {
                    return;
                }
                self.close.closing = true;
                if self.teardown_t3_in_flight() {
                    self.close.deferred = Some(CloseKind::Begin);
                    return;
                }
                self.close_begin_now(now);
            }
        }
    }

    /// Runs the `LegacyFailPending` close job.
    fn close_begin_now(&mut self, now: Millis) {
        let (mut entries, auth) = self.close_take_snapshot();
        entries.extend(self.requests.take_fifo());
        self.close_run(CloseKind::Begin, entries, auth, now);
    }

    /// Queues the CLOSE_OP frame when connected.
    ///
    /// Contract: when the state is connected, append a `Close` frame
    /// (normal xid, op -11, no completion), record `close_xid` and
    /// `flush_established`, and return true. Otherwise queue nothing and
    /// return false.
    pub fn queue_close_op(&mut self) -> bool {
        if !self.core.state.is_connected() || !self.core.has_transport {
            self.close.op_refused = true;
            return false;
        }
        let xid = self.requests.next_xid();
        let bytes = self.teardown_peer_request_frame(xid, zk_jute::opcode::CLOSE, &[]);
        self.requests
            .push_tail(OutFrame::plain(FrameKind::Close, bytes));
        self.close.close_xid = Some(xid);
        self.close.flush_established = self.core.phase == Phase::Established;
        self.close.op_epoch = self.core.epoch;
        self.close.op_refused = false;
        true
    }

    /// Reports the progress of a `Drain` close (a native hook).
    ///
    /// Contract: `Complete` on the CLOSE_OP reply, when `now >=
    /// deadline`, when `queue_close_op` returned false, or when a teardown
    /// ended the transport. Otherwise `Pending`.
    ///
    /// Before `begin_close` it reports `Pending`. Under
    /// `LegacyFailPending` the close has no drain, so it reports
    /// `Complete`. Once complete, it stays complete.
    pub fn close_step(&mut self, now: Millis) -> CloseProgress {
        if !self.close.closing {
            return CloseProgress::Pending;
        }
        if self.compat.close_mode == CloseMode::LegacyFailPending {
            return CloseProgress::Complete;
        }
        let transport_ended = !self.core.has_transport
            || (self.close.close_xid.is_some() && self.core.epoch != self.close.op_epoch);
        let past_deadline = self.close.deadline.is_some_and(|d| now >= d);
        if self.close.complete || self.close.op_refused || transport_ended || past_deadline {
            self.close.complete = true;
            if self.close.outcome.is_none() {
                self.close.outcome = Some(if self.close.op_refused {
                    rc::ZOK
                } else if transport_ended {
                    rc::ZCONNECTIONLOSS
                } else {
                    rc::ZOPERATIONTIMEOUT
                });
            }
            CloseProgress::Complete
        } else {
            CloseProgress::Pending
        }
    }

    /// Closes with no CLOSE_OP (a native hook).
    ///
    /// Contract: queue `CloseTransport` when a transport exists,
    /// fail pending work with `ZCLOSING`, and push
    /// `WatchTerminated{Closed}` through `clear_watches`.
    ///
    /// The transport close is teardown stage T1 with no session event.
    /// The frames in `tx` are dropped, because no transport sends them.
    ///
    /// A teardown that is stopped in its T3 ends first, as for
    /// `begin_close`.
    pub fn abandon(&mut self, now: Millis) {
        if self.close.destroyed {
            return;
        }
        self.close.closing = true;
        if self.teardown_t3_in_flight() {
            // Abandon does all that a deferred `begin_close` does, and more.
            self.close.deferred = Some(CloseKind::Abandon);
            return;
        }
        self.close_abandon_now(now);
    }

    /// Runs the abandon job.
    fn close_abandon_now(&mut self, now: Millis) {
        if self.core.has_transport {
            self.teardown_t1();
        }
        let (mut entries, auth) = self.close_take_snapshot();
        let (_tx, fifo) = self.requests.take_all();
        entries.extend(fifo);
        self.close_run(CloseKind::Abandon, entries, auth, now);
    }

    /// Fails everything that is left and ends the connection.
    ///
    /// Contract: set `closing` and `destroyed`. Fail the snapshot and the
    /// FIFO with `ZCLOSING`, then `AuthLockpoint`, `Auth{ZCLOSING}` and
    /// `DrainPoint`. Every suspended job is taken from the outputs and its
    /// tokens fail with `ZCLOSING` first, and `Outputs::mark_destroyed`
    /// runs. `tx` is dropped. Under the native profile `clear_watches`
    /// runs with `Closed`. Then `poll_action` yields `CloseTransport` when
    /// a transport exists, and `sasl_on_destroy` queues the final
    /// `Dispose`.
    ///
    /// No stage resumes after `destroy`, so the job runs to the end in
    /// one call and parks nothing. A second call does nothing.
    pub fn destroy(&mut self, now: Millis) {
        if self.close.destroyed {
            return;
        }
        self.close.closing = true;
        self.close.destroyed = true;
        // Destroy takes the stopped teardown, so a deferred close has
        // nothing left to do.
        self.close.deferred = None;
        let mut entries = VecDeque::new();
        let mut auth = Vec::new();
        for work in self.out.take_all_work() {
            match work {
                Work::Teardown(job) => {
                    entries.extend(job.entries);
                    auth.extend(job.auth);
                }
                Work::Close(job) => {
                    entries.extend(job.entries);
                    auth.extend(job.auth);
                }
                Work::Hold | Work::AuthReply(_) | Work::Finalize(_) => {}
            }
        }
        let (snap_entries, snap_auth) = self.close_take_snapshot();
        entries.extend(snap_entries);
        auth.extend(snap_auth);
        let (_tx, fifo) = self.requests.take_all();
        entries.extend(fifo);
        self.out.mark_destroyed();
        self.close_run(CloseKind::Destroy, entries, auth, now);
    }

    /// Runs a close job of `kind` from its first stage. The job fails
    /// `entries`, then the auth tokens `auth`.
    fn close_run(
        &mut self,
        kind: CloseKind,
        entries: VecDeque<Pending<T>>,
        auth: Vec<T::Auth>,
        now: Millis,
    ) {
        let job = CloseJob {
            kind,
            stage: CloseStage::FailFifo,
            entries,
            auth,
        };
        self.continue_close(job, now);
    }

    /// Returns true while the close flush of an established session may
    /// send every frame kind. The flush belongs to the transport that
    /// queued the CLOSE_OP, so a later transport keeps the normal gate.
    pub(crate) fn close_flush_open(&self) -> bool {
        self.close.flush_established && self.core.epoch == self.close.op_epoch
    }

    /// Returns true after `begin_close` or `destroy`.
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.close.closing
    }

    /// Returns the result of a completed `Drain` close.
    ///
    /// It is `None` until `close_step` reports `Complete` or the CLOSE_OP
    /// reply arrives. The first result stays:
    ///
    /// - `ZOK`: the CLOSE_OP reply arrived, or the close queued no
    ///   CLOSE_OP.
    /// - `ZCONNECTIONLOSS`: a teardown ended the transport first.
    /// - `ZOPERATIONTIMEOUT`: the close deadline came first.
    ///
    /// Under `LegacyFailPending` it is always `None`. The drop-in driver
    /// computes its own close rc.
    #[must_use]
    pub fn close_outcome(&self) -> Option<i32> {
        if self.compat.close_mode == CloseMode::LegacyFailPending {
            return None;
        }
        self.close.outcome
    }

    /// Continues a close job after a barrier, until the end or the next
    /// barrier.
    ///
    /// A `Destroy` job parks nothing, because `destroy` ends every stop.
    /// It still pushes the barrier outputs in order. Its lock point
    /// follows `Compat::emits_lockpoints`, as the other jobs do.
    pub(crate) fn continue_close(&mut self, mut job: CloseJob<T>, _now: Millis) {
        let parks = job.kind != CloseKind::Destroy;
        loop {
            match job.stage {
                CloseStage::FailFifo => {
                    if job.entries.is_empty() {
                        job.stage = CloseStage::Lockpoint;
                        continue;
                    }
                    let mut entries = core::mem::take(&mut job.entries);
                    let stopped = self.teardown_peer_fail_pending_run(&mut entries, rc::ZCLOSING);
                    job.entries = entries;
                    if stopped && parks {
                        self.out.park(Work::Close(job));
                        return;
                    }
                }
                CloseStage::Lockpoint => {
                    job.stage = CloseStage::Auth;
                    if self.compat.emits_lockpoints() {
                        self.out.push(Output::AuthLockpoint);
                        if parks {
                            self.out.park(Work::Close(job));
                            return;
                        }
                    }
                }
                CloseStage::Auth => {
                    job.stage = CloseStage::Finish;
                    let mut tokens = core::mem::take(&mut job.auth);
                    tokens.extend(self.auth.take_tokens());
                    if !tokens.is_empty() {
                        self.out.push(Output::Auth {
                            tokens,
                            rc: rc::ZCLOSING,
                            barrier: false,
                        });
                    }
                }
                CloseStage::Finish => {
                    self.close_finish(job.kind);
                    return;
                }
            }
        }
    }

    /// Runs a close that waited for a teardown. The teardown calls it
    /// after its last stage.
    pub(crate) fn close_run_deferred(&mut self, now: Millis) {
        match self.close.deferred.take() {
            Some(CloseKind::Begin) => self.close_begin_now(now),
            Some(CloseKind::Abandon) => self.close_abandon_now(now),
            Some(CloseKind::Destroy) | None => {}
        }
    }

    /// Takes the CLOSE_OP reply under `Drain`.
    ///
    /// Contract: it marks the close complete and returns
    /// `Flow::Done(ZOK)`.
    pub(crate) fn on_close_reply(&mut self, _now: Millis) -> Flow {
        self.close.complete = true;
        if self.close.outcome.is_none() {
            self.close.outcome = Some(rc::ZOK);
        }
        Flow::Done(rc::ZOK)
    }

    /// Takes the entries and auth tokens of a forced-close snapshot whose
    /// T3 did not start. The frames of the snapshot are dropped.
    fn close_take_snapshot(&mut self) -> (VecDeque<Pending<T>>, Vec<T::Auth>) {
        match self.teardown_take_forced() {
            Some(ForcedSnapshot { fifo, auth, .. }) => (fifo, auth),
            None => (VecDeque::new(), Vec::new()),
        }
    }

    /// Runs the last stage of a close job: `DrainPoint`, then the rest of
    /// the operation.
    fn close_finish(&mut self, kind: CloseKind) {
        self.out.push(Output::DrainPoint);
        match kind {
            CloseKind::Begin => {}
            CloseKind::Abandon => {
                self.teardown_peer_clear_watches(TerminateReason::Closed);
            }
            CloseKind::Destroy => {
                self.teardown_peer_clear_watches(TerminateReason::Closed);
                if self.core.has_transport {
                    self.queue_close_transport();
                    self.core.phase = Phase::Idle;
                    self.lose_transport();
                }
                self.teardown_peer_sasl_on_destroy();
            }
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
    use crate::action::{Action, TransportFailure};
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::request::Route;
    use crate::state::{Cause, State};
    use crate::teardown::PeerCall;
    use crate::teardown::test_support::*;

    const CL: i32 = rc::ZCLOSING;

    fn loaded(compat: Compat, mode: DriverMode) -> Connection<Tk> {
        let mut cfg = Config::legacy(30_000);
        cfg.close_timeout_ms = 1_000;
        let mut c = conn_with(cfg, compat, mode);
        establish(&mut c, Millis(10));
        c.requests.push_pending(pend(1, Route::Queued, 11));
        c.requests.push_pending(pend(2, Route::Direct, 12));
        c.requests.push_pending(pend(3, Route::Queued, 13));
        add_auth(&mut c, 21);
        c
    }

    fn queued_close_transport(c: &Connection<Tk>) -> bool {
        c.interest
            .queued
            .iter()
            .any(|a| matches!(a, Action::CloseTransport))
    }

    #[test]
    fn begin_close_legacy_fails_pending_work() {
        let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
        let tx_len = c.requests.tx.len();
        c.begin_close(Millis(20));
        assert!(c.is_closing());
        assert!(c.requests.fifo.is_empty());
        assert_eq!(c.requests.tx.len(), tx_len, "tx stays");
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs, vec![Ev::Done(11, CL, false), Ev::Done(12, CL, true)]);
        c.resume(stop.unwrap(), Millis(20));
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs, vec![Ev::Done(13, CL, false), Ev::Lockpoint]);
        c.resume(stop.unwrap(), Millis(20));
        let evs = drain(&mut c, Millis(20));
        assert_eq!(evs, vec![Ev::Auth(vec![21], CL, false), Ev::Drain]);
        assert_eq!(c.state(), State::Connected, "no session event");
        assert!(c.has_transport());

        // A second call does nothing, and the close needs no drain.
        c.begin_close(Millis(21));
        assert!(drain(&mut c, Millis(21)).is_empty());
        assert_eq!(c.close_step(Millis(21)), CloseProgress::Complete);
        assert_eq!(c.close_outcome(), None, "the drop-in driver has the rc");

        // CLOSE_OP still goes out after a legacy close.
        assert!(c.queue_close_op());
        assert_eq!(c.requests.tx.back().unwrap().kind, FrameKind::Close);
    }

    #[test]
    fn begin_close_drain_keeps_pending_work() {
        let mut c = loaded(Compat::NATIVE, DriverMode::NATIVE);
        assert_eq!(c.close_step(Millis(20)), CloseProgress::Pending);
        c.begin_close(Millis(20));
        assert!(c.is_closing());
        assert_eq!(c.close.deadline, Some(Millis(1_020)));
        assert_eq!(c.requests.fifo.len(), 3);
        assert!(drain(&mut c, Millis(20)).is_empty());
        // The second call keeps the first deadline.
        c.begin_close(Millis(500));
        assert_eq!(c.close.deadline, Some(Millis(1_020)));
        assert_eq!(c.close_step(Millis(500)), CloseProgress::Pending);
    }

    #[test]
    fn close_step_runs_to_completion_on_the_reply() {
        let mut c = loaded(Compat::NATIVE, DriverMode::NATIVE);
        c.begin_close(Millis(20));
        let _ = calls(&mut c);
        assert!(c.queue_close_op());
        let xid = c.close.close_xid.unwrap();
        assert_eq!(
            calls(&mut c),
            vec![PeerCall::RequestFrame(xid, zk_jute::opcode::CLOSE)]
        );
        assert!(c.close.flush_established);
        let frame = c.requests.tx.back().unwrap();
        assert_eq!(frame.kind, FrameKind::Close);
        assert_eq!(frame.bytes.len(), 12);
        assert_eq!(c.requests.fifo.len(), 3, "no completion for CLOSE_OP");
        assert_eq!(c.close_step(Millis(30)), CloseProgress::Pending);
        assert_eq!(c.close_outcome(), None);
        assert_eq!(c.on_close_reply(Millis(40)), Flow::Done(rc::ZOK));
        assert_eq!(c.close_step(Millis(40)), CloseProgress::Complete);
        assert_eq!(c.close_step(Millis(41)), CloseProgress::Complete);
        assert_eq!(c.close_outcome(), Some(rc::ZOK));

        // The driver then destroys the connection.
        c.destroy(Millis(41));
        let evs = no_logs(&drain(&mut c, Millis(41)));
        assert_eq!(
            evs,
            vec![
                Ev::Done(11, CL, false),
                Ev::Done(12, CL, true),
                Ev::Done(13, CL, false),
                Ev::Auth(vec![21], CL, false),
                Ev::Drain,
            ]
        );
        assert!(queued_close_transport(&c));
        assert!(!c.has_transport());
    }

    #[test]
    fn close_step_completes_at_the_deadline() {
        let mut c = loaded(Compat::NATIVE, DriverMode::NATIVE);
        c.begin_close(Millis(20));
        assert!(c.queue_close_op());
        assert_eq!(c.close_step(Millis(1_019)), CloseProgress::Pending);
        assert_eq!(c.close_step(Millis(1_020)), CloseProgress::Complete);
        assert_eq!(c.close_outcome(), Some(rc::ZOPERATIONTIMEOUT));
        // A later reply does not change the result.
        let _ = c.on_close_reply(Millis(1_030));
        assert_eq!(c.close_outcome(), Some(rc::ZOPERATIONTIMEOUT));
    }

    #[test]
    fn close_step_completes_when_close_op_is_refused() {
        let mut c = conn(Compat::NATIVE, DriverMode::NATIVE);
        c.begin_close(Millis(1));
        assert!(!c.queue_close_op());
        assert!(c.requests.tx.is_empty());
        assert_eq!(c.close_step(Millis(1)), CloseProgress::Complete);
        assert_eq!(c.close_outcome(), Some(rc::ZOK));
    }

    #[test]
    fn close_step_completes_after_a_teardown() {
        let mut c = loaded(Compat::NATIVE, DriverMode::NATIVE);
        c.begin_close(Millis(20));
        assert!(c.queue_close_op());
        let _ = c.handle_transport_failed(TransportFailure::Eof, Millis(30));
        assert_eq!(c.last_teardown_cause(), Some(Cause::Eof));
        assert_eq!(c.close_step(Millis(30)), CloseProgress::Complete);
        assert_eq!(c.close_outcome(), Some(rc::ZCONNECTIONLOSS));
        // A teardown during the drain fails the FIFO with its own rc.
        let evs = no_logs(&drain(&mut c, Millis(30)));
        assert!(evs.contains(&Ev::Done(11, rc::ZCONNECTIONLOSS, false)));
        assert!(c.is_closing());
    }

    #[test]
    fn destroy_with_a_suspended_close_job() {
        let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
        c.begin_close(Millis(20));
        let (evs, stop) = until_stop(&mut c);
        assert_eq!(evs, vec![Ev::Done(11, CL, false), Ev::Done(12, CL, true)]);
        c.requests.push_pending(pend(4, Route::Queued, 14));
        let _ = calls(&mut c);
        c.destroy(Millis(21));
        assert!(c.is_closing());
        assert!(c.out.is_destroyed());
        assert!(c.requests.tx.is_empty());
        // The job entries fail first, then the FIFO.
        let evs = drain(&mut c, Millis(21));
        assert_eq!(
            no_logs(&evs),
            vec![
                Ev::Done(13, CL, false),
                Ev::Done(14, CL, false),
                Ev::Lockpoint,
                Ev::Auth(vec![21], CL, false),
                Ev::Drain,
            ]
        );
        assert!(!c.is_suspended());
        assert_eq!(
            calls(&mut c),
            vec![
                PeerCall::FailPendingRun(CL),
                PeerCall::ClearWatches(TerminateReason::Closed),
                PeerCall::SaslOnDestroy,
            ]
        );
        assert!(queued_close_transport(&c));
        assert!(!c.has_transport());
        // The old stop resumes nothing.
        c.resume(stop.unwrap(), Millis(22));
        assert!(drain(&mut c, Millis(22)).is_empty());
        // A second destroy, and an abandon, do nothing.
        c.destroy(Millis(22));
        c.abandon(Millis(22));
        assert!(drain(&mut c, Millis(22)).is_empty());
        let left = c.into_leftovers();
        assert!(left.completions.is_empty() && left.auth.is_empty());
    }

    #[test]
    fn destroy_with_a_suspended_teardown_and_snapshot() {
        let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
        c.forced_close_trigger(Millis(5));
        assert!(c.run_pending_teardown(Millis(6)));
        let (_, stop) = until_stop(&mut c);
        assert!(stop.is_some());
        c.requests.push_pending(pend(4, Route::Queued, 14));
        c.destroy(Millis(7));
        let evs = no_logs(&drain(&mut c, Millis(7)));
        assert_eq!(
            evs,
            vec![
                Ev::Done(11, CL, false),
                Ev::Done(12, CL, true),
                Ev::Done(13, CL, false),
                Ev::Done(14, CL, false),
                Ev::Lockpoint,
                Ev::Auth(vec![21], CL, false),
                Ev::Drain,
            ]
        );
        assert!(!c.has_transport());
        assert!(c.teardown.forced.is_none());
        assert!(c.into_leftovers().completions.is_empty());
    }

    #[test]
    fn abandon_closes_the_transport_and_fails_work() {
        let mut c = loaded(Compat::NATIVE, DriverMode::NATIVE);
        let _ = calls(&mut c);
        c.abandon(Millis(20));
        assert!(c.is_closing());
        assert!(!c.has_transport());
        assert!(queued_close_transport(&c));
        assert!(c.requests.tx.is_empty());
        let evs = no_logs(&drain(&mut c, Millis(20)));
        assert_eq!(
            evs,
            vec![
                Ev::Done(11, CL, false),
                Ev::Done(12, CL, true),
                Ev::Stop,
                Ev::Done(13, CL, false),
                Ev::Auth(vec![21], CL, false),
                Ev::Drain,
            ]
        );
        let calls = calls(&mut c);
        assert_eq!(
            calls.last(),
            Some(&PeerCall::ClearWatches(TerminateReason::Closed))
        );
        assert!(!calls.contains(&PeerCall::HostsOnHandleError));
        assert_eq!(c.close_step(Millis(21)), CloseProgress::Complete);
    }

    #[test]
    fn begin_close_stops_the_pending_forced_stages() {
        let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
        c.forced_close_trigger(Millis(5));
        c.begin_close(Millis(6));
        assert!(!c.run_pending_teardown(Millis(6)));
        let evs = no_logs(&drain(&mut c, Millis(6)));
        assert_eq!(
            evs,
            vec![
                Ev::Done(11, CL, false),
                Ev::Done(12, CL, true),
                Ev::Stop,
                Ev::Done(13, CL, false),
                Ev::Lockpoint,
                Ev::Stop,
                Ev::Auth(vec![21], CL, false),
                Ev::Drain,
            ]
        );
        assert!(c.teardown.forced.is_none());
        assert!(!c.run_pending_teardown(Millis(7)));
    }

    #[test]
    fn drain_close_flush_ends_with_its_transport() {
        let mut c = loaded(Compat::NATIVE, DriverMode::NATIVE);
        c.begin_close(Millis(20));
        assert!(c.queue_close_op());
        assert!(c.close_flush_open());
        let _ = c.handle_transport_failed(TransportFailure::Eof, Millis(21));
        let _ = drain(&mut c, Millis(21));
        assert!(!c.close_flush_open(), "the flush belongs to the old epoch");
        // A closing connection asks for no new transport.
        while let Some(a) = c.poll_action(Millis(5_000)) {
            assert!(!matches!(a, Action::Connect { .. }), "{a:?}");
        }
        // A connect that the driver starts anyway is refused.
        c.interest.queued.clear();
        c.handle_connect_started(crate::action::ConnectStart::InProgress, Millis(5_000));
        assert!(!c.has_transport());
        assert!(queued_close_transport(&c));
    }

    #[test]
    fn connect_started_with_a_live_transport_is_refused() {
        let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
        let epoch = c.core.epoch;
        let state = c.state();
        c.interest.queued.clear();
        c.handle_connect_started(crate::action::ConnectStart::InProgress, Millis(20));
        assert!(queued_close_transport(&c));
        assert_eq!(c.core.epoch, epoch);
        assert_eq!(c.state(), state);
        assert!(c.has_transport());
    }

    #[test]
    fn connect_started_after_destroy_is_refused() {
        let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
        c.destroy(Millis(20));
        let _ = drain(&mut c, Millis(20));
        c.interest.queued.clear();
        c.handle_connect_started(crate::action::ConnectStart::InProgress, Millis(21));
        assert!(!c.has_transport());
        assert!(queued_close_transport(&c));
    }

    #[test]
    fn transport_failures_after_destroy_do_nothing() {
        let failures = [
            TransportFailure::SocketCreate { errno: 24 },
            TransportFailure::TcpRefused { errno: 111 },
            TransportFailure::Io { errno: 104 },
            TransportFailure::Eof,
            TransportFailure::TlsHandshake { errno: 0 },
        ];
        for f in failures {
            let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
            c.destroy(Millis(20));
            let _ = drain(&mut c, Millis(20));
            let _ = calls(&mut c);
            let cause = c.last_teardown_cause();
            let _ = c.handle_transport_failed(f.clone(), Millis(21));
            let evs = no_logs(&drain(&mut c, Millis(21)));
            assert!(evs.is_empty(), "{f:?}: {evs:?}");
            assert!(!c.is_suspended(), "{f:?}");
            assert!(calls(&mut c).is_empty(), "{f:?}");
            assert_eq!(c.last_teardown_cause(), cause, "{f:?}");
            assert!(!c.run_pending_teardown(Millis(22)), "{f:?}");
        }
    }

    fn add_auth_now(c: &mut Connection<Tk>, token: u32) -> Result<(), crate::AddAuthError<Tk>> {
        c.add_auth(
            zk_jute::JString::from("digest"),
            crate::SecretBytes::from_slice(b"pw"),
            Some(token),
            Millis(30),
        )
    }

    #[test]
    fn add_auth_after_destroy_gives_the_token_back() {
        for (compat, mode) in [
            (Compat::LEGACY_C, DriverMode::ST),
            (Compat::NATIVE, DriverMode::NATIVE),
        ] {
            let mut c = loaded(compat, mode);
            c.destroy(Millis(20));
            let _ = drain(&mut c, Millis(20));
            let e = add_auth_now(&mut c, 31).unwrap_err();
            assert_eq!(e.code, rc::ZINVALIDSTATE);
            assert_eq!(e.done, Some(31));
            assert!(c.auth.take_tokens().is_empty());
            assert!(c.into_leftovers().auth.is_empty());
        }
    }

    #[test]
    fn add_auth_while_a_drain_close_runs_is_refused() {
        let mut c = loaded(Compat::NATIVE, DriverMode::NATIVE);
        c.begin_close(Millis(20));
        let e = add_auth_now(&mut c, 31).unwrap_err();
        assert_eq!(e.code, CL);
        assert_eq!(e.done, Some(31));
        // The legacy close keeps the C behavior and takes the entry.
        let mut c = loaded(Compat::LEGACY_C, DriverMode::ST);
        c.begin_close(Millis(20));
        let _ = drain(&mut c, Millis(20));
        assert!(add_auth_now(&mut c, 31).is_ok());
    }
}
