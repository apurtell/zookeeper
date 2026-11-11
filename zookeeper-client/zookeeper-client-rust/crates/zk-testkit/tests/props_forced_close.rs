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

//! Property 5: forced-close capture.
//!
//! A forced close fires at a random barrier or at a quiet point. The
//! trigger captures the snapshot, and the next `run_pending_teardown`
//! fails it. The visible state is 999 until the forced teardown ends.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod props_common;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use props_common::{Profile, check_once, config, profile};
use proptest::prelude::*;
use zk_jute::{opcode, rc};
use zk_proto::{Cause, Origin, Output, Route, State};
use zk_testkit::server::{Rule, RuleAction};
use zk_testkit::{ConnectStyle, Event, Harness, HarnessError, Ops, Ticket, WatcherId};

/// Where the forced close fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    /// From the hook of the k-th barrier output (1-based).
    Barrier(usize),
    /// From the test, with no output in flight, while connected.
    Quiet,
    /// From the test, while a connect is in progress.
    Connecting,
    /// From the test while connected, then a close before the next step.
    QuietThenClose,
}

fn point() -> impl Strategy<Value = Point> {
    prop_oneof![
        3 => (1usize..8).prop_map(Point::Barrier),
        2 => Just(Point::Quiet),
        1 => Just(Point::Connecting),
        1 => Just(Point::QuietThenClose),
    ]
}

#[derive(Clone, Debug)]
struct Case {
    p: Profile,
    seed: u64,
    point: Point,
    /// The requests that the server holds, so they wait in the FIFO.
    held: usize,
    /// The requests that get a reply. Under MT they use the Direct route,
    /// so each completion is a barrier.
    answered: usize,
    auths: usize,
    hold_auth: bool,
    survivors: usize,
}

fn case() -> impl Strategy<Value = Case> {
    (
        profile(),
        any::<u64>(),
        point(),
        0usize..5,
        0usize..5,
        0usize..3,
        any::<bool>(),
        0usize..3,
    )
        .prop_map(
            |(p, seed, point, held, answered, auths, hold_auth, survivors)| Case {
                p,
                seed,
                point,
                held,
                answered,
                auths,
                hold_auth,
                survivors,
            },
        )
}

/// What the hook saw at the pop of one output.
#[derive(Clone, Copy, Debug)]
struct Seen {
    state: State,
}

/// The facts of the trigger.
#[derive(Clone, Debug)]
struct Trig {
    /// The index of the first output after the trigger.
    out_index: usize,
    /// The record length at the trigger.
    rec_mark: usize,
    /// The ticket of the output in flight, if it is a completion.
    current: Option<Ticket>,
    had_transport: bool,
    connected: bool,
    before: State,
    after: State,
    after_pending: usize,
    after_transport: bool,
}

#[derive(Default)]
struct Ctl {
    k: Option<usize>,
    barriers: usize,
    seen: Vec<Seen>,
    trig: Option<Trig>,
    drain: Option<usize>,
    survivors: usize,
    survivor_tickets: Vec<Ticket>,
    errors: Vec<String>,
}

fn fail(e: impl std::fmt::Debug) -> TestCaseError {
    TestCaseError::fail(format!("{e:?}"))
}

/// Runs the trigger and records its facts. The survivors are submitted
/// after it, so they are not in the snapshot.
fn trigger(
    ctl: &mut Ctl,
    conn: &mut zk_proto::Connection<zk_testkit::TestTokens>,
    now: zk_proto::Millis,
    out_index: usize,
    rec_mark: usize,
    current: Option<Ticket>,
) -> Trig {
    let had_transport = conn.has_transport();
    let before = conn.state();
    conn.handle_forced_close(now);
    let t = Trig {
        out_index,
        rec_mark,
        current,
        had_transport,
        connected: before.is_connected(),
        before,
        after: conn.state(),
        after_pending: conn.pending_len(),
        after_transport: conn.has_transport(),
    };
    let _ = ctl;
    t
}

fn hold(h: &mut Harness, hold_auth: bool) {
    for op in [opcode::GET_DATA, opcode::EXISTS, opcode::GET_CHILDREN] {
        h.server_mut()
            .add_rule(Rule::on_request().op(op).then(RuleAction::Ignore));
    }
    if hold_auth {
        h.server_mut().add_rule(
            Rule::on_request()
                .op(opcode::SET_AUTH)
                .then(RuleAction::Ignore),
        );
    }
}

fn queue(h: &mut Harness, c: &Case) -> Result<(), TestCaseError> {
    let ops = h.ops();
    // The answered requests go first. A reply behind a held request
    // would be an xid mismatch.
    for _ in 0..c.answered {
        let route = if c.p == Profile::Mt {
            Route::Direct
        } else {
            Route::Queued
        };
        h.submit_with(ops.sync("/"), route, zk_proto::InputDefect::default())
            .map_err(fail)?;
    }
    for i in 0..c.held {
        let op = match i % 3 {
            0 => ops.get_data("/a", None),
            1 => ops.exists("/a", Some(WatcherId::new(3, 3))),
            _ => ops.get_children("/", None),
        };
        h.submit(op).map_err(fail)?;
    }
    for i in 0..c.auths {
        h.add_auth("digest", format!("u{i}:p").as_bytes())
            .map_err(fail)?;
    }
    Ok(())
}

fn ok_or_timeout(r: Result<(), HarnessError>) -> Result<(), TestCaseError> {
    match r {
        Err(HarnessError::Runaway { steps }) => Err(fail(format!("runaway {steps}"))),
        _ => Ok(()),
    }
}

fn run(c: &Case) -> Result<(), TestCaseError> {
    let mut h = c.p.builder(c.seed).build();
    let ops: Ops = h.ops();
    let ctl = Rc::new(RefCell::new(Ctl {
        k: match c.point {
            Point::Barrier(k) => Some(k),
            _ => None,
        },
        survivors: c.survivors,
        ..Ctl::default()
    }));
    let hc = Rc::clone(&ctl);
    h.set_hook(Box::new(move |ctx, o| {
        let mut ctl = hc.borrow_mut();
        let idx = ctl.seen.len();
        ctl.seen.push(Seen {
            state: ctx.conn.state(),
        });
        let fired = ctl.trig.as_ref().is_some_and(|t| t.had_transport);
        let in_window = fired && ctl.drain.is_none();
        if in_window && matches!(o, Output::DrainPoint) {
            ctl.drain = Some(idx);
        }
        if !o.is_barrier() {
            return;
        }
        ctl.barriers += 1;
        if ctl.trig.is_none() && ctl.k == Some(ctl.barriers) {
            let current = match o {
                Output::Completion { token, .. } => Some(token.ticket()),
                _ => None,
            };
            let mark = ctx.recorder.mark();
            let t = trigger(&mut ctl, ctx.conn, ctx.now, idx + 1, mark, current);
            if t.had_transport {
                for i in 0..ctl.survivors {
                    let p = format!("/s{i}");
                    match ctx.submit(ops.create(&p, b"s", 0)) {
                        Ok(t) => ctl.survivor_tickets.push(t),
                        Err(e) => ctl.errors.push(format!("survivor refused: {e:?}")),
                    }
                }
            }
            ctl.trig = Some(t);
        } else if in_window {
            // A trigger with no transport does nothing, so a second trigger
            // inside the forced teardown changes nothing.
            ctx.conn.handle_forced_close(ctx.now);
            if ctx.conn.state() != State::NotConnected {
                ctl.errors
                    .push(format!("retrigger changed state to {:?}", ctx.conn.state()));
            }
        }
    }));
    hold(&mut h, c.hold_auth);
    h.connect().map_err(fail)?;
    if c.point == Point::Connecting {
        h.net_mut()
            .set_connect_style(ConnectStyle::InProgress { delay_ms: 200 });
        h.reset_current();
        ok_or_timeout(h.run_until(
            |h| h.conn().has_transport() && h.state() == State::Connecting,
            30_000,
        ))?;
        prop_assert!(h.conn().has_transport());
        prop_assert_eq!(h.state(), State::Connecting);
    }
    queue(&mut h, c)?;
    match c.point {
        Point::Barrier(_) => {}
        Point::Quiet | Point::QuietThenClose => h.run_for(100).map_err(fail)?,
        Point::Connecting => {}
    }
    if !matches!(c.point, Point::Barrier(_)) {
        // The trigger runs between steps, so the core is not suspended.
        let now = h.now();
        let out_index = ctl.borrow().seen.len();
        let mark = h.recorder().mark();
        prop_assert!(!h.conn().is_suspended());
        let t = {
            let mut g = ctl.borrow_mut();
            trigger(&mut g, h.conn_mut(), now, out_index, mark, None)
        };
        // At the trigger, the trigger pushes logs only.
        while let Some(o) = h.conn_mut().poll_output() {
            prop_assert!(matches!(o, Output::Log(_)), "trigger output {:?}", o);
            let state = h.conn().state();
            ctl.borrow_mut().seen.push(Seen { state });
            h.recorder_mut().push(now, Event::Output(o));
        }
        ctl.borrow_mut().trig = Some(t);
        if c.point != Point::QuietThenClose {
            for i in 0..c.survivors {
                let t = h
                    .submit(ops.create(&format!("/s{i}"), b"s", 0))
                    .map_err(fail)?;
                ctl.borrow_mut().survivor_tickets.push(t);
            }
        } else {
            h.close().map_err(fail)?;
        }
    }
    if c.point != Point::QuietThenClose {
        let hc = Rc::clone(&ctl);
        ok_or_timeout(h.run_until(
            move |h| {
                let g = hc.borrow();
                let fired = g.trig.as_ref().is_some_and(|t| t.had_transport);
                fired
                    && g.drain.is_some()
                    && g.survivor_tickets
                        .iter()
                        .all(|t| h.recorder().completion_count(*t) > 0)
            },
            60_000,
        ))?;
    }

    let g = ctl.borrow();
    prop_assert!(g.errors.is_empty(), "{:?}", g.errors);
    if let Some(t) = g.trig.clone() {
        check_trigger(&h, c, &g, &t)?;
    }
    drop(g);
    let f = h.finish();
    check_once(&f)
}

fn check_trigger(h: &Harness, c: &Case, g: &Ctl, t: &Trig) -> Result<(), TestCaseError> {
    if !t.had_transport {
        // With no transport the trigger does nothing.
        prop_assert_eq!(t.after, t.before);
        return Ok(());
    }
    // At the trigger: state 999, T1 ran, the FIFO moved into the snapshot.
    prop_assert_eq!(t.after, State::NotConnected);
    prop_assert!(!t.after_transport);
    prop_assert_eq!(t.after_pending, 0);

    // The snapshot: each queued request that had not completed.
    let rec = h.recorder().all();
    let mut done: BTreeSet<Ticket> = BTreeSet::new();
    let mut snapshot: Vec<Ticket> = Vec::new();
    for r in &rec[..t.rec_mark] {
        match &r.event {
            Event::Submitted { ticket, .. } => snapshot.push(*ticket),
            Event::Output(Output::Completion { token, .. }) => {
                done.insert(token.ticket());
            }
            _ => {}
        }
    }
    snapshot.retain(|x| !done.contains(x) && Some(*x) != t.current);

    if c.point == Point::QuietThenClose {
        // A close before T3 starts fails the snapshot with ZCLOSING.
        for x in &snapshot {
            let r = h.recorder().completion(*x).unwrap();
            prop_assert_eq!(r.rc, rc::ZCLOSING, "ticket {}", x.0);
        }
        return Ok(());
    }

    let drain = g.drain;
    prop_assert!(drain.is_some(), "no forced drain point");
    let drain = drain.unwrap();
    // The visible state stays 999 from the trigger to the forced T4.
    for (i, s) in g.seen.iter().enumerate().take(drain + 1).skip(t.out_index) {
        prop_assert_eq!(s.state, State::NotConnected, "output {} state", i);
    }
    let window: Vec<&Output<zk_testkit::TestTokens>> = h
        .recorder()
        .outputs()
        .skip(t.out_index)
        .take(drain + 1 - t.out_index)
        .collect();
    // T2: Session{Connecting} only when the state was connected.
    let sessions: Vec<State> = window
        .iter()
        .filter_map(|o| match o {
            Output::Session { state, .. } => Some(*state),
            _ => None,
        })
        .collect();
    if t.connected {
        prop_assert_eq!(&sessions, &vec![State::Connecting]);
    } else {
        prop_assert!(sessions.is_empty(), "{:?}", sessions);
    }
    // No T0 line: ForcedClose is exempt, because C logs nothing at either
    // trigger site.
    for o in &window {
        if let Output::Log(l) = o {
            prop_assert!(
                !format!("{:?}", l.site).starts_with("Sock"),
                "T0 {:?}",
                l.site
            );
        }
    }
    // T3: the snapshot fails with ZCONNECTIONLOSS in order.
    let failed: Vec<Ticket> = window
        .iter()
        .filter_map(|o| match o {
            Output::Completion { token, result, .. } => {
                assert_eq!(
                    result.rc,
                    rc::ZCONNECTIONLOSS,
                    "ticket {}",
                    token.ticket().0
                );
                assert_eq!(result.origin, Origin::Teardown);
                Some(token.ticket())
            }
            _ => None,
        })
        .collect();
    prop_assert_eq!(&failed, &snapshot);
    for o in &window {
        if let Output::Auth { rc: r, .. } = o {
            prop_assert_eq!(*r, rc::ZCONNECTIONLOSS);
        }
    }
    // A request submitted after the trigger survives.
    for x in &g.survivor_tickets {
        let r = h.recorder().completion(*x);
        prop_assert!(r.is_some(), "survivor {} lost", x.0);
        prop_assert_eq!(r.unwrap().origin, Origin::Reply, "survivor {}", x.0);
    }
    prop_assert_eq!(h.conn().last_teardown_cause(), Some(Cause::ForcedClose));
    Ok(())
}

proptest! {
    #![proptest_config(config(0x5eed_0005))]

    // Source: C handle_error from the reconfig path of
    // zoo_cycle_next_server and update_addrs. The trigger captures the
    // snapshot. The next run_pending_teardown fails it. The state is 999
    // between the two calls.
    /// Ledger: ST-13, DV-FIX-8
    #[test]
    fn forced_close_captures_then_finishes(c in case()) {
        run(&c)?;
    }
}

/// Runs a reconfig that drops the current server (C update_addrs). The
/// forced close fires inside `handle_resolved`.
fn run_reconfig(p: Profile, seed: u64, held: usize) -> Result<(), TestCaseError> {
    let mut h = p.builder(seed).servers(2).build();
    let first = h.host_spec(0);
    let (_, r0) = h.set_servers(vec![first]);
    prop_assert_eq!(r0, rc::ZOK);
    let seen: Rc<RefCell<Vec<State>>> = Rc::new(RefCell::new(Vec::new()));
    let s2 = Rc::clone(&seen);
    h.set_hook(Box::new(move |ctx, _o| {
        s2.borrow_mut().push(ctx.conn.state())
    }));
    hold(&mut h, false);
    h.connect().map_err(fail)?;
    prop_assert_eq!(h.conn().current_server(), Some(zk_testkit::server_addr(0)));
    let ops = h.ops();
    let mut tickets = Vec::new();
    for i in 0..held {
        let op = if i % 2 == 0 {
            ops.get_data("/a", None)
        } else {
            ops.exists("/a", None)
        };
        tickets.push(h.submit(op).map_err(fail)?);
    }
    h.run_for(50).map_err(fail)?;
    let out_mark = seen.borrow().len();
    let second = h.host_spec(1);
    let (_, r1) = h.set_servers(vec![second]);
    prop_assert_eq!(r1, rc::ZOK);
    // The trigger ran inside handle_resolved: state 999, no transport.
    prop_assert_eq!(h.state(), State::NotConnected);
    prop_assert!(!h.conn().has_transport());
    ok_or_timeout(h.run_until(
        |h| {
            h.recorder()
                .outputs()
                .skip(out_mark)
                .any(|o| matches!(o, Output::DrainPoint))
        },
        30_000,
    ))?;
    let outs: Vec<String> = h
        .recorder()
        .outputs()
        .skip(out_mark)
        .map(|o| props_common::kind(o).to_owned())
        .collect();
    let drain = outs.iter().position(|k| k == "DrainPoint").unwrap();
    for (i, s) in seen
        .borrow()
        .iter()
        .enumerate()
        .skip(out_mark)
        .take(drain + 1)
    {
        prop_assert_eq!(*s, State::NotConnected, "output {} state", i);
    }
    for t in &tickets {
        let r = h.recorder().completion(*t).unwrap();
        prop_assert_eq!(r.rc, rc::ZCONNECTIONLOSS);
        prop_assert_eq!(r.origin, Origin::Teardown);
    }
    prop_assert_eq!(h.conn().last_teardown_cause(), Some(Cause::ForcedClose));
    // The client connects to the new server and resumes the session.
    h.connect().map_err(fail)?;
    prop_assert_eq!(h.conn().current_server(), Some(zk_testkit::server_addr(1)));
    let f = h.finish();
    check_once(&f)
}

proptest! {
    #![proptest_config(props_common::config_cases(64, 0x5eed_0015))]

    // Source: C update_addrs with reconfig. A new host list without the
    // current server forces a close of the transport.
    #[test]
    fn reconfig_forces_a_close(p in profile(), seed in any::<u64>(), held in 0usize..5) {
        run_reconfig(p, seed, held)?;
    }
}
