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

//! Close scenarios: the two close modes, destroy and abandon with pending
//! work, and the stops of a teardown at each barrier. The source is the
//! spec row "Close Semantics".

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::cell::Cell;
use std::rc::Rc;

use common::{Profile, connects};
use zk_jute::{opcode, rc};
use zk_proto::{CloseProgress, InputDefect, Output, Route, Stage, State, TerminateReason};
use zk_testkit::server::{Rule, RuleAction};
use zk_testkit::{ActionRecord, Event, Harness, Ticket, WatcherId};

/// Makes the server drop each request on `path` and each SET_AUTH, so
/// the work stays pending.
fn hold(h: &mut Harness, path: &str) {
    h.server_mut()
        .add_rule(Rule::on_request().path(path).then(RuleAction::Ignore));
    h.server_mut().add_rule(
        Rule::on_request()
            .op(opcode::SET_AUTH)
            .then(RuleAction::Ignore),
    );
}

fn events_since(h: &Harness, mark: usize) -> Vec<&Event> {
    h.recorder().since(mark).iter().map(|r| &r.event).collect()
}

fn pos(ev: &[&Event], mut pred: impl FnMut(&Event) -> bool) -> Option<usize> {
    ev.iter().position(|e| pred(e))
}

fn closes_since(h: &Harness, mark: usize) -> usize {
    events_since(h, mark)
        .iter()
        .filter(|e| matches!(e, Event::Action(ActionRecord::CloseTransport)))
        .count()
}

// Source: C zookeeper_close, spec row "Close Semantics". The C close fails
// the pending requests and the auth entries with ZCLOSING at once. It emits
// AuthLockpoint and DrainPoint, no session event, and it sends CLOSE_OP.
#[test]
fn legacy_close_fails_pending_work_with_closing() {
    for p in Profile::LEGACY {
        let mut h = p.harness(60);
        h.connect().unwrap();
        hold(&mut h, "/slow");
        let ops = h.ops();
        let t = h.submit(ops.get_data("/slow", None)).unwrap();
        let a = h.add_auth("digest", b"u:pw").unwrap();
        h.run_for(100).unwrap();
        let mark = h.recorder().mark();
        h.close().unwrap();
        h.expect_completion(t, rc::ZCLOSING).unwrap();
        h.expect_exactly_once().unwrap();
        assert_eq!(h.recorder().auth_results(), vec![(vec![a], rc::ZCLOSING)]);
        let ev = events_since(&h, mark);
        assert!(
            !ev.iter()
                .any(|e| matches!(e, Event::Output(Output::Session { .. }))),
            "{p:?}"
        );
        let comp = pos(&ev, |e| {
            matches!(e, Event::Output(Output::Completion { .. }))
        })
        .unwrap();
        let lock = pos(&ev, |e| matches!(e, Event::Output(Output::AuthLockpoint))).unwrap();
        let auth = pos(&ev, |e| matches!(e, Event::Output(Output::Auth { .. }))).unwrap();
        let drain = pos(&ev, |e| matches!(e, Event::Output(Output::DrainPoint))).unwrap();
        assert!(comp < lock && lock < auth && auth < drain, "{p:?}");
        assert_eq!(h.server().request_count(opcode::CLOSE), 1, "{p:?}");
        assert_eq!(closes_since(&h, mark), 1, "{p:?}");
        let now = h.now();
        assert_eq!(h.conn_mut().close_step(now), CloseProgress::Complete);
    }
}

// Source: spec row "Close Semantics". The native close keeps the pending
// requests. Their replies arrive before the CLOSE_OP reply, and that reply
// ends the drain before the deadline.
#[test]
fn drain_close_waits_for_the_pending_replies() {
    let mut h = Profile::Native.harness(61);
    h.connect().unwrap();
    h.server_mut().add_rule(
        Rule::on_request()
            .path("/late")
            .then(RuleAction::Delay(500)),
    );
    let ops = h.ops();
    let t = h.submit(ops.create("/late", b"x", 0)).unwrap();
    let start = h.now();
    h.close().unwrap();
    let spent = h.now().0 - start.0;
    h.expect_completion(t, rc::ZOK).unwrap();
    h.expect_exactly_once().unwrap();
    assert!((500..2_000).contains(&spent), "{spent}");
    assert_eq!(h.server().request_count(opcode::CLOSE), 1);
    assert!(h.server().tree().get(b"/late").is_some());
}

// Source: zk-proto close_step. A drain with no CLOSE_OP reply ends at
// begin_close plus close_timeout_ms. Destroy then fails the rest with
// ZCLOSING.
#[test]
fn drain_close_ends_at_the_deadline() {
    let mut h = Profile::Native.harness(62);
    h.connect().unwrap();
    hold(&mut h, "/slow");
    h.server_mut().add_rule(
        Rule::on_request()
            .op(opcode::CLOSE)
            .then(RuleAction::Ignore),
    );
    let ops = h.ops();
    let t = h.submit(ops.get_data("/slow", None)).unwrap();
    let start = h.now();
    let now = h.now();
    h.conn_mut().begin_close(now);
    assert!(h.conn_mut().queue_close_op());
    h.pump(now);
    h.run_until(
        |h| {
            let n = h.now();
            h.conn_mut().close_step(n) == CloseProgress::Complete
        },
        10_000,
    )
    .unwrap();
    assert_eq!(h.now().0 - start.0, 2_000);
    assert!(h.recorder().completion(t).is_none());
    let now = h.now();
    h.conn_mut().destroy(now);
    h.pump(now);
    h.expect_completion(t, rc::ZCLOSING).unwrap();
    h.expect_exactly_once().unwrap();
}

// Source: zk-proto queue_close_op. With no connection the core queues no
// CLOSE_OP, and close_step completes at once.
#[test]
fn drain_close_without_a_connection_completes_at_once() {
    let mut h = Profile::Native.harness(63);
    let ops = h.ops();
    let t = h.submit(ops.exists("/", None)).unwrap();
    let now = h.now();
    h.conn_mut().begin_close(now);
    assert!(!h.conn_mut().queue_close_op());
    assert_eq!(h.conn_mut().close_step(now), CloseProgress::Complete);
    h.conn_mut().destroy(now);
    h.pump(now);
    h.expect_completion(t, rc::ZCLOSING).unwrap();
    h.expect_exactly_once().unwrap();
    assert_eq!(h.server().request_count(opcode::CLOSE), 0);
}

// Source: spec row "Close Semantics", C add_completion. After begin_close the
// native core refuses a submit at Validate with ZCLOSING. C refuses the
// completion with ZINVALIDSTATE, and the API returns ZMARSHALLINGERROR.
#[test]
fn submit_after_begin_close_is_refused() {
    for p in Profile::ALL {
        let mut h = p.harness(64);
        h.connect().unwrap();
        let now = h.now();
        h.conn_mut().begin_close(now);
        h.pump(now);
        let ops = h.ops();
        let e = h.submit(ops.exists("/", None)).unwrap_err();
        if p.is_native() {
            assert_eq!((e.stage, e.code), (Stage::Validate, rc::ZCLOSING));
        } else {
            assert_eq!(e.code, rc::ZMARSHALLINGERROR, "{p:?}");
        }
        h.close().unwrap();
        h.expect_exactly_once().unwrap();
    }
}

/// Sets up written and unwritten requests, a pending auth and a watch.
/// It returns the tickets in submit order.
fn pending_work(h: &mut Harness) -> Vec<Ticket> {
    h.connect().unwrap();
    hold(h, "/slow");
    let ops = h.ops();
    h.call(ops.create("/w", b"", 0)).unwrap();
    h.call(ops.exists("/w", Some(WatcherId::new(7, 1))))
        .unwrap();
    let mut ts = Vec::new();
    for _ in 0..3 {
        ts.push(h.submit(ops.get_data("/slow", None)).unwrap());
    }
    h.run_for(100).unwrap();
    // A zero budget keeps the next requests in tx.
    h.set_write_budget(Some(0));
    for _ in 0..2 {
        ts.push(h.submit(ops.exists("/slow", None)).unwrap());
    }
    h.run_for(10).unwrap();
    ts
}

// Source: zk-proto destroy. Destroy fails every pending request once with
// ZCLOSING, in FIFO order, and completes the auth entry. It sends no
// CLOSE_OP and closes the transport. The native profile ends the watches
// with Closed.
#[test]
fn destroy_fails_every_pending_completion_once() {
    for p in Profile::ALL {
        let mut h = p.harness(65);
        let ts = pending_work(&mut h);
        let a = h.add_auth("digest", b"u:pw").unwrap();
        h.run_for(10).unwrap();
        let mark = h.recorder().mark();
        let now = h.now();
        h.conn_mut().destroy(now);
        h.pump(now);
        for t in &ts {
            h.expect_completion(*t, rc::ZCLOSING).unwrap();
        }
        assert_eq!(h.recorder().completion_order()[2..], ts[..], "{p:?}");
        h.expect_exactly_once().unwrap();
        assert_eq!(h.recorder().auth_results(), vec![(vec![a], rc::ZCLOSING)]);
        assert_eq!(closes_since(&h, mark), 1, "{p:?}");
        assert_eq!(h.server().request_count(opcode::CLOSE), 0, "{p:?}");
        let ended = h
            .recorder()
            .outputs_since(mark)
            .any(|o| matches!(o, Output::WatchTerminated { watchers, reason: TerminateReason::Closed } if watchers.contains(&WatcherId::new(7, 1))));
        assert_eq!(ended, p.is_native(), "{p:?}");
        // A second destroy does nothing.
        let n = h.recorder().len();
        let now = h.now();
        h.conn_mut().destroy(now);
        h.pump(now);
        assert_eq!(h.recorder().len(), n, "{p:?}");
    }
}

// Source: zk-proto abandon, a native hook. Abandon closes the transport
// with no CLOSE_OP and no session event. It fails the pending work with
// ZCLOSING and ends the watches with Closed. A later destroy adds no
// completion.
#[test]
fn abandon_closes_without_close_op() {
    let mut h = Profile::Native.harness(66);
    let ts = pending_work(&mut h);
    let mark = h.recorder().mark();
    let now = h.now();
    h.conn_mut().abandon(now);
    h.pump(now);
    for t in &ts {
        h.expect_completion(*t, rc::ZCLOSING).unwrap();
    }
    assert_eq!(closes_since(&h, mark), 1);
    assert!(
        !h.recorder()
            .outputs_since(mark)
            .any(|o| matches!(o, Output::Session { .. }))
    );
    assert!(h.recorder().outputs_since(mark).any(|o| matches!(
        o,
        Output::WatchTerminated {
            reason: TerminateReason::Closed,
            ..
        }
    )));
    let now = h.now();
    h.conn_mut().destroy(now);
    h.pump(now);
    h.expect_exactly_once().unwrap();
    assert_eq!(h.server().request_count(opcode::CLOSE), 0);
}

/// Returns true when the two records after `i` are a stop and a resume
/// of one handle.
fn stops_at(ev: &[&Event], i: usize) -> bool {
    match (ev.get(i + 1), ev.get(i + 2)) {
        (Some(Event::Stopped(a)), Some(Event::Resumed(b))) => a == b,
        _ => false,
    }
}

// Source: the zk-proto teardown stages T2-T4. Under ST a teardown stops at
// the Session{Connecting} barrier, the AuthLockpoint and the Auth barrier.
// Under MT the Session event is no barrier, but each Direct completion is.
// The harness resumes each stop once, and the stages keep the order T2, T3
// fail, lock point, auth, T4 DrainPoint.
#[test]
fn teardown_stops_and_resumes_at_each_barrier() {
    for p in Profile::LEGACY {
        let mut h = p.harness(67);
        h.connect().unwrap();
        hold(&mut h, "/slow");
        let ops = h.ops();
        let route = if p == Profile::St {
            Route::Queued
        } else {
            Route::Direct
        };
        let t = h
            .submit_with(ops.get_data("/slow", None), route, InputDefect::default())
            .unwrap();
        let a = h.add_auth("digest", b"u:pw").unwrap();
        h.run_for(100).unwrap();
        let mark = h.recorder().mark();
        h.reset_current();
        h.run_until(|h| h.recorder().completion(t).is_some(), 1_000)
            .unwrap();
        h.run_for(10).unwrap();
        h.expect_completion(t, rc::ZCONNECTIONLOSS).unwrap();
        assert_eq!(
            h.recorder().auth_results(),
            vec![(vec![a], rc::ZCONNECTIONLOSS)]
        );
        let ev = events_since(&h, mark);
        let sess = pos(&ev, |e| {
            matches!(
                e,
                Event::Output(Output::Session {
                    state: State::Connecting,
                    ..
                })
            )
        })
        .unwrap();
        let comp = pos(&ev, |e| {
            matches!(e, Event::Output(Output::Completion { .. }))
        })
        .unwrap();
        let lock = pos(&ev, |e| matches!(e, Event::Output(Output::AuthLockpoint))).unwrap();
        let auth = pos(&ev, |e| matches!(e, Event::Output(Output::Auth { .. }))).unwrap();
        let drain = pos(&ev, |e| matches!(e, Event::Output(Output::DrainPoint))).unwrap();
        assert!(
            sess < comp && comp < lock && lock < auth && auth < drain,
            "{p:?}"
        );
        assert_eq!(stops_at(&ev, sess), p == Profile::St, "{p:?}");
        assert_eq!(stops_at(&ev, comp), p == Profile::Mt, "{p:?}");
        assert!(stops_at(&ev, lock), "{p:?}");
        assert!(stops_at(&ev, auth), "{p:?}");
        assert!(matches!(
            ev[auth],
            Event::Output(Output::Auth { barrier: true, .. })
        ));
        h.expect_exactly_once().unwrap();
    }
}

/// The barrier at which a hook ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    Session,
    Direct,
    Lockpoint,
    Auth,
}

impl At {
    fn matches(self, o: &Output<zk_testkit::TestTokens>) -> bool {
        match self {
            Self::Session => matches!(
                o,
                Output::Session {
                    state: State::Connecting,
                    barrier: true,
                    ..
                }
            ),
            Self::Direct => matches!(
                o,
                Output::Completion {
                    route: Route::Direct,
                    ..
                }
            ),
            Self::Lockpoint => matches!(o, Output::AuthLockpoint),
            Self::Auth => matches!(o, Output::Auth { barrier: true, .. }),
        }
    }
}

/// Runs a teardown with two pending requests and one auth entry. A hook
/// calls `end` at the first output that `at` matches. It returns the
/// harness, the tickets and the auth ticket.
fn end_at_barrier(
    p: Profile,
    at: At,
    seed: u64,
    end: fn(&mut zk_proto::Connection<zk_testkit::TestTokens>, zk_proto::Millis),
) -> (Harness, Vec<Ticket>, zk_testkit::AuthTicket) {
    let mut h = p.harness(seed);
    h.connect().unwrap();
    hold(&mut h, "/slow");
    let ops = h.ops();
    // A failure run ends at the last Direct entry (C cleanup_bufs), so
    // only the first request is Direct.
    let mut ts = Vec::new();
    for i in 0..2 {
        let route = if at == At::Direct && i == 0 {
            Route::Direct
        } else {
            Route::Queued
        };
        ts.push(
            h.submit_with(ops.get_data("/slow", None), route, InputDefect::default())
                .unwrap(),
        );
    }
    let a = h.add_auth("digest", b"u:pw").unwrap();
    h.run_for(100).unwrap();
    let fired = Rc::new(Cell::new(false));
    let seen = Rc::clone(&fired);
    h.set_hook(Box::new(move |ctx, o| {
        if !seen.get() && at.matches(o) {
            seen.set(true);
            end(ctx.conn, ctx.now);
        }
    }));
    h.reset_current();
    h.run_for(200).unwrap();
    assert!(fired.get(), "{p:?} {at:?}");
    (h, ts, a)
}

fn destroy(c: &mut zk_proto::Connection<zk_testkit::TestTokens>, now: zk_proto::Millis) {
    c.destroy(now);
}

fn begin_close(c: &mut zk_proto::Connection<zk_testkit::TestTokens>, now: zk_proto::Millis) {
    c.begin_close(now);
}

// Source: zk-proto destroy. A destroy takes every suspended job. A destroy
// from a barrier callback ends the stopped teardown. Each request and auth
// entry completes once. The work that the teardown did not reach yet fails
// with ZCLOSING, and the core makes no new connect.
#[test]
fn destroy_from_each_teardown_barrier_completes_everything_once() {
    let cases = [
        (
            Profile::St,
            At::Session,
            [rc::ZCLOSING, rc::ZCLOSING],
            rc::ZCLOSING,
        ),
        (
            Profile::Mt,
            At::Direct,
            [rc::ZCONNECTIONLOSS, rc::ZCLOSING],
            rc::ZCLOSING,
        ),
        (
            Profile::St,
            At::Lockpoint,
            [rc::ZCONNECTIONLOSS, rc::ZCONNECTIONLOSS],
            rc::ZCLOSING,
        ),
        (
            Profile::St,
            At::Auth,
            [rc::ZCONNECTIONLOSS, rc::ZCONNECTIONLOSS],
            rc::ZCONNECTIONLOSS,
        ),
    ];
    for (i, (p, at, want, want_auth)) in cases.into_iter().enumerate() {
        let (h, ts, a) = end_at_barrier(p, at, 70 + i as u64, destroy);
        for (t, w) in ts.iter().zip(want) {
            h.expect_completion(*t, w)
                .unwrap_or_else(|e| panic!("{p:?} {at:?}: {e}"));
        }
        h.expect_exactly_once().unwrap();
        assert_eq!(
            h.recorder().auth_results(),
            vec![(vec![a], want_auth)],
            "{p:?} {at:?}"
        );
        assert_eq!(connects(&h), 1, "{p:?} {at:?}");
    }
}

// Source: zk-proto begin_close under LegacyFailPending. A close from the
// Session barrier fails the FIFO with ZCLOSING before the teardown takes
// its snapshot. The resumed teardown finds no work, so each completion
// still comes once.
#[test]
fn legacy_close_from_the_session_barrier_completes_everything_once() {
    let (mut h, ts, a) = end_at_barrier(Profile::St, At::Session, 80, begin_close);
    for t in &ts {
        h.expect_completion(*t, rc::ZCLOSING).unwrap();
    }
    assert_eq!(h.recorder().auth_results(), vec![(vec![a], rc::ZCLOSING)]);
    h.close().unwrap();
    h.expect_exactly_once().unwrap();
}

/// Runs a teardown that stops at its first Direct completion in T3. The
/// hook submits one more request and then calls `end`. It returns the
/// harness, the tickets in submission order and the auth ticket.
fn end_at_direct_with_late_work(
    p: Profile,
    seed: u64,
    end: fn(&mut zk_proto::Connection<zk_testkit::TestTokens>, zk_proto::Millis),
) -> (Harness, Vec<Ticket>, zk_testkit::AuthTicket) {
    let mut h = p.harness(seed);
    h.connect().unwrap();
    hold(&mut h, "/slow");
    let ops = h.ops();
    let mut ts = Vec::new();
    for route in [Route::Direct, Route::Queued, Route::Queued] {
        ts.push(
            h.submit_with(ops.get_data("/slow", None), route, InputDefect::default())
                .unwrap(),
        );
    }
    let a = h.add_auth("digest", b"u:pw").unwrap();
    h.run_for(100).unwrap();
    let late: Rc<Cell<Option<Ticket>>> = Rc::new(Cell::new(None));
    let slot = Rc::clone(&late);
    let ops2 = h.ops();
    h.set_hook(Box::new(move |ctx, o| {
        if slot.get().is_none() && At::Direct.matches(o) {
            let t = ctx.submit(ops2.get_data("/slow", None)).unwrap();
            slot.set(Some(t));
            end(ctx.conn, ctx.now);
        }
    }));
    h.reset_current();
    h.run_for(200).unwrap();
    ts.push(late.get().expect("the hook did not run"));
    (h, ts, a)
}

fn abandon(c: &mut zk_proto::Connection<zk_testkit::TestTokens>, now: zk_proto::Millis) {
    c.abandon(now);
}

// Once T3 has started, it finishes its snapshot with ZCONNECTIONLOSS, and
// the close fails only the later work, in submission order. A close from a
// Direct barrier in T3 waits for the teardown. The snapshot entries and the
// auth entry fail with ZCONNECTIONLOSS first, and only then the later
// request fails with ZCLOSING.
#[test]
fn close_from_a_direct_barrier_in_t3_keeps_submission_order() {
    let cases = [
        (Profile::Mt, begin_close as fn(&mut _, _)),
        (Profile::Native, abandon as fn(&mut _, _)),
    ];
    for (i, (p, end)) in cases.into_iter().enumerate() {
        let (mut h, ts, a) = end_at_direct_with_late_work(p, 90 + i as u64, end);
        let want = [
            rc::ZCONNECTIONLOSS,
            rc::ZCONNECTIONLOSS,
            rc::ZCONNECTIONLOSS,
            rc::ZCLOSING,
        ];
        for (t, w) in ts.iter().zip(want) {
            h.expect_completion(*t, w)
                .unwrap_or_else(|e| panic!("{p:?}: {e}"));
        }
        assert_eq!(h.recorder().completion_order(), ts, "{p:?}");
        assert_eq!(
            h.recorder().auth_results(),
            vec![(vec![a], rc::ZCONNECTIONLOSS)],
            "{p:?}"
        );
        h.close().unwrap();
        h.expect_exactly_once().unwrap();
    }
}
