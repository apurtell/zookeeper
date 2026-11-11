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

//! The loom models of the threaded drop-in driver.
//!
//! A build with `--cfg loom` replaces the lock facade with the loom
//! types. loom threads then play the C IO and dispatch loops, and they
//! call the real step functions of [`Shared`]. loom runs every
//! interleaving of the facade operations, up to the preemption bound.
//!
//! The models need private state: the socket-pair rig, the test host
//! and the handle constructor. So they are unit tests and not files in
//! `tests/`. Run them with `cargo xtask loom`.
//!
//! - The completion queue: each completion token reaches the dispatch
//!   thread exactly once, no wakeup is lost, and the thread exits only
//!   after the close mark and the IO exit.
//! - The close mark: a close from a foreign thread, a close from a
//!   callback on the IO thread, and both at the same time, give each
//!   request exactly one result. The IO thread holds decoded replies
//!   when the close starts.
//! - The order: the dispatch thread delivers the real replies in
//!   request order, also when another thread pumps during the close.
//! - The close tail: a result that only `destroy` gives reaches the
//!   dispatch thread once. In a foreign close it comes before the close
//!   mark. In a close from a completion callback, the dispatch thread
//!   delivers it at its exit.
//! - The dispatch end: a callback ends the dispatch thread while a
//!   foreign close waits for the queued callbacks. The cleanup handler
//!   wakes that close, and no result reaches a callback after the end.
//!
//! loom runs every thread on one OS thread. A blocking system call
//! thus stops the whole model. The rig sends the replies before the
//! threads start, and the poll of the IO step never blocks. After its
//! first step, the IO thread waits for the close request with
//! `yield_now`, in place of the poll on the waker.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use loom::thread::{self, JoinHandle};
use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use zk_jute::rc::{ZCLOSING, ZCONNECTIONLOSS, ZOK};
use zk_proto::{Compat, DriverMode, LogSite, OpResult, PathIn, Request, State};
use zk_testkit::server::codec::{encode_reply, split_frames};
use zk_testkit::tokens::{CompletionId, TestTokens};

use super::{
    Rig, accept_frame, exists_xids, queued_exists, read_ev, stop_the_teardown,
    submit_a_sync_and_a_queued_request, write_ev,
};
use crate::clock::Clock;
use crate::host::HostLeaves;
use crate::net::poll::Poll;
use crate::outbox::{Flavor, Item, Outbox, Step, ThreadOp, ThreadRole};
use crate::state::{Core, Env};
use crate::sync::{Condvar, Mutex, Unlocked};
use crate::testutil::{RealPoll, TestHost, exists_request, test_connection};
use crate::threaded::{Role, Shared};

type S = Shared<TestTokens>;

/// The default preemption bound. `LOOM_MAX_PREEMPTIONS` overrides it.
const DEFAULT_PREEMPTIONS: usize = 3;

/// Runs `f` under loom with a bounded number of preemptions.
pub(crate) fn model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    if b.preemption_bound.is_none() {
        b.preemption_bound = Some(DEFAULT_PREEMPTIONS);
    }
    b.check(f);
}

/// Makes a handle around a connection with no socket. A close fails
/// each pending request with ZCLOSING.
fn handle() -> (Arc<S>, Arc<TestHost>) {
    let host = Arc::new(TestHost::new());
    let leaves: Arc<dyn HostLeaves<TestTokens>> = host.clone();
    let core = Core::new(Box::new(test_connection(DriverMode::MT)));
    let mut ob = Outbox::new();
    let shared = Shared::new(core, Env::new(leaves), &mut ob).unwrap();
    assert!(ob.is_empty());
    (shared, host)
}

fn exists(id: u64) -> Request<TestTokens> {
    exists_request(PathIn::Legacy(Some(b"/".to_vec())), id)
}

/// A result that the IO thread decoded.
fn decoded(id: u64) -> Item<TestTokens> {
    Item::Result {
        token: CompletionId::new(id),
        result: OpResult::teardown(ZCONNECTIONLOSS),
        delivery_logs: Vec::new(),
    }
}

/// The result codes of each token id.
type ByToken = BTreeMap<u64, Vec<i32>>;

/// The completions that one thread delivered.
#[derive(Debug, Default)]
struct Delivered {
    /// The result codes of each token id, in delivery order.
    by_token: ByToken,
    /// The token id and the result code of each delivery, in order.
    order: Vec<(u64, i32)>,
    /// The token id and the result code of each auth completion, in
    /// order.
    auths: Vec<(u64, i32)>,
}

impl Delivered {
    fn new() -> Self {
        Self::default()
    }

    fn is_empty(&self) -> bool {
        self.order.is_empty() && self.auths.is_empty()
    }

    /// Checks that the results with `rc` come in token order. The tests
    /// submit the requests in token order, so this is the request order.
    fn assert_in_order(&self, rc: i32) {
        let ids: Vec<u64> = self
            .order
            .iter()
            .filter(|(_, r)| *r == rc)
            .map(|(id, _)| *id)
            .collect();
        assert!(
            ids.is_sorted(),
            "results {rc} out of order: {:?}",
            self.order
        );
    }
}

fn note(seen: &mut Delivered, item: &Item<TestTokens>) {
    match item {
        Item::Result { token, result, .. } => {
            seen.by_token.entry(token.id()).or_default().push(result.rc);
            seen.order.push((token.id(), result.rc));
        }
        Item::AuthResult { token, rc } => seen.auths.push((token.id(), *rc)),
        _ => {}
    }
}

/// Drives one call to its end, as C does. `on` sees each item when C
/// takes it.
fn drive(
    s: &S,
    first: Step,
    ob: &mut Outbox<TestTokens>,
    rc: &mut i32,
    mut on: impl FnMut(&Item<TestTokens>),
) -> Step {
    let mut step = first;
    loop {
        while let Some(item) = ob.pop() {
            on(&item);
        }
        if step != Step::More {
            return step;
        }
        step = s.resume(ob, rc);
    }
}

/// A count of deliveries that a thread can wait on. The wait blocks, so
/// loom reports a deadlock when no delivery comes.
#[derive(Default)]
struct Count {
    n: Mutex<usize>,
    cv: Condvar,
}

impl Count {
    fn add(&self) {
        *self.n.lock_owner() += 1;
        self.cv.notify_all();
    }

    fn wait_for(&self, n: usize) {
        let mut got = self.n.lock_owner();
        while *got < n {
            got = self.cv.wait(got);
        }
    }
}

/// The dispatch loop of C. After `Exit` the thread gives back its ref.
/// It returns the delivered completions.
fn spawn_dispatch(s: &Arc<S>) -> JoinHandle<Delivered> {
    spawn_counted_dispatch(s, Arc::default())
}

/// The dispatch loop of C. It counts each delivered item, so another
/// thread can wait for a delivery.
fn spawn_counted_dispatch(s: &Arc<S>, count: Arc<Count>) -> JoinHandle<Delivered> {
    let s = Arc::clone(s);
    thread::spawn(move || {
        let mut seen = Delivered::new();
        loop {
            let mut ob = s.outbox();
            if s.wait_dispatch(&mut ob) == Step::Exit {
                break;
            }
            while let Some(item) = ob.pop() {
                note(&mut seen, &item);
                count.add();
            }
        }
        // Only a close gives the mark, so the queue state must show it.
        {
            let fifo = s.queue.fifo.lock_owner();
            assert!(fifo.close_published && fifo.io_exited && fifo.items.is_empty());
        }
        let mut ob = s.outbox();
        let mut rc = -1;
        let first = s.thread_exit(Role::Dispatch, &mut ob, &mut rc);
        assert_eq!(drive(&s, first, &mut ob, &mut rc, |_| {}), Step::Done(ZOK));
        seen
    })
}

/// The IO thread of C with no socket. It publishes the decoded results
/// of `ids` in one IO step. With `early`, it then leaves its loop at
/// once, as after a session expiry. Else it waits for the close
/// request, as the poll of C waits for the waker.
fn spawn_io(s: &Arc<S>, ids: &'static [u64], early: bool) -> JoinHandle<()> {
    spawn_paced_io(s, ids, early, None)
}

/// The IO thread of C with no socket. With no `pace`, it acts as
/// [`spawn_io`] does. With `pace`, it publishes each result in its own
/// IO step. It then waits for the delivery before the next result.
fn spawn_paced_io(
    s: &Arc<S>,
    ids: &'static [u64],
    early: bool,
    pace: Option<Arc<Count>>,
) -> JoinHandle<()> {
    let s = Arc::clone(s);
    thread::spawn(move || {
        match &pace {
            None => {
                let mut ob = s.outbox();
                for id in ids {
                    ob.push_publish(decoded(*id));
                }
                assert!(ob.pop().is_none());
            }
            Some(count) => {
                for (done, id) in (1..).zip(ids) {
                    let mut ob = s.outbox();
                    ob.push_publish(decoded(*id));
                    assert!(ob.pop().is_none());
                    count.wait_for(done);
                }
            }
        }
        if !early {
            while !s.life.close_requested() {
                thread::yield_now();
            }
            let mut ob = s.outbox();
            let mut rc = -1;
            assert_eq!(s.io_step(&mut ob, &mut rc), Step::Exit);
        }
        let mut ob = s.outbox();
        let mut rc = -1;
        let first = s.thread_exit(Role::Io, &mut ob, &mut rc);
        assert_eq!(drive(&s, first, &mut ob, &mut rc, |_| {}), Step::Done(ZOK));
    })
}

/// Closes from a foreign thread, as `zookeeper_close` does. The join
/// items join the loom threads. It returns what the dispatch thread
/// delivered. The closer delivers nothing on its own thread.
fn close_foreign(s: &S, io: JoinHandle<()>, dispatch: JoinHandle<Delivered>) -> Delivered {
    let (seen, got) = close_foreign_seen(s, io, dispatch);
    assert!(seen.is_empty(), "{seen:?}");
    got
}

/// Closes from a foreign thread, as [`close_foreign`] does. It returns
/// what the closer and the dispatch thread delivered.
fn close_foreign_seen(
    s: &S,
    io: JoinHandle<()>,
    dispatch: JoinHandle<Delivered>,
) -> (Delivered, Delivered) {
    let mut io = Some(io);
    let mut dispatch = Some(dispatch);
    let mut got = None;
    let mut seen = Delivered::new();
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.close(Role::Foreign, &mut ob, &mut rc);
    let end = drive(s, first, &mut ob, &mut rc, |item| match item {
        Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Io,
        } => io.take().unwrap().join().unwrap(),
        Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Dispatch,
        } => got = Some(dispatch.take().unwrap().join().unwrap()),
        other => note(&mut seen, other),
    });
    assert_eq!((end, rc), (Step::Release, ZOK));
    // A foreign close delivers no request completion on its own thread.
    // Auth completions can run there, as in legacy `free_completions`.
    assert!(seen.order.is_empty(), "{seen:?}");
    (seen, got.expect("the close joined the dispatch thread"))
}

fn expect(pairs: &[(u64, i32)]) -> ByToken {
    pairs.iter().map(|(id, rc)| (*id, vec![*rc])).collect()
}

/// The completion queue. The IO thread publishes decoded results while
/// a foreign thread closes the handle. The IO thread can leave its loop
/// at any point after the close request, also before the close publishes
/// its ZCLOSING results. The dispatch thread delivers each token once
/// and exits only after the mark.
#[test]
fn loom_completion_queue_delivers_each_token_once() {
    model(|| {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        assert!(s.submit(exists(1)).is_ok());
        assert!(s.submit(exists(2)).is_ok());
        let dispatch = spawn_dispatch(&s);
        let io = spawn_io(&s, &[10, 11], false);
        let got = close_foreign(&s, io, dispatch);
        got.assert_in_order(ZCONNECTIONLOSS);
        assert_eq!(
            got.by_token,
            expect(&[
                (1, ZCLOSING),
                (2, ZCLOSING),
                (10, ZCONNECTIONLOSS),
                (11, ZCONNECTIONLOSS)
            ])
        );
        assert!(host.discarded().is_empty());
    });
}

/// No wakeup is lost. The IO thread publishes one result, and then it
/// waits for its delivery before it publishes the next. Only the publish
/// wakes the dispatch thread, because no close comes before the
/// deliveries.
#[test]
fn loom_completion_queue_wakes_the_dispatch_thread_for_each_publish() {
    model(|| {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let count = Arc::new(Count::default());
        let dispatch = spawn_counted_dispatch(&s, Arc::clone(&count));
        let io = spawn_paced_io(&s, &[10, 11], false, Some(Arc::clone(&count)));
        count.wait_for(2);
        let got = close_foreign(&s, io, dispatch);
        got.assert_in_order(ZCONNECTIONLOSS);
        assert_eq!(
            got.by_token,
            expect(&[(10, ZCONNECTIONLOSS), (11, ZCONNECTIONLOSS)])
        );
        assert!(host.discarded().is_empty());
    });
}

/// An IO thread that leaves its loop before any close does not end the
/// dispatch thread. The thread waits for the mark of the later close.
#[test]
fn loom_completion_queue_outlives_an_early_io_exit() {
    model(|| {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        assert!(s.submit(exists(1)).is_ok());
        let dispatch = spawn_dispatch(&s);
        let io = spawn_io(&s, &[10], true);
        let got = close_foreign(&s, io, dispatch);
        assert_eq!(
            got.by_token,
            expect(&[(1, ZCLOSING), (10, ZCONNECTIONLOSS)])
        );
        assert!(host.discarded().is_empty());
    });
}

/// The dispatch loop of C, with a callback that ends the thread. The
/// thread delivers the first item of its first batch. Then the cleanup
/// handler runs, and the thread keeps its ref.
fn spawn_ending_dispatch(s: &Arc<S>) -> JoinHandle<Delivered> {
    let s = Arc::clone(s);
    thread::spawn(move || {
        let mut seen = Delivered::new();
        let mut ob = s.outbox();
        // Only a foreign close gives the mark, after the wait. The IO
        // thread publishes before that, so the first wait gives a batch.
        assert_eq!(s.wait_dispatch(&mut ob), Step::Done(ZOK));
        note(&mut seen, &ob.pop().unwrap());
        s.dispatch_ended(&mut ob);
        seen
    })
}

/// A callback ends the dispatch thread while the IO thread publishes and
/// a foreign thread closes. The end can come before the close or during
/// its wait for the queued callbacks. The cleanup handler always ends
/// that wait, so the close returns. The close then gives back the ref of
/// the ended thread and runs the final close. Each token reaches a
/// callback at most once, and `discard_token` gets the others.
#[test]
fn loom_a_dispatch_end_wakes_a_foreign_close() {
    model(|| {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        assert!(s.submit(exists(1)).is_ok());
        let dispatch = spawn_ending_dispatch(&s);
        let io = spawn_io(&s, &[10, 11], false);
        let (_, got) = close_foreign_seen(&s, io, dispatch);
        assert_eq!(got.order.len(), 1);
        assert!(got.by_token.values().all(|rcs| rcs.len() == 1));
        assert_eq!(host.discarded(), ["completion", "completion"]);
        assert_eq!(s.life.refs(), 0);
    });
}

/// A foreign thread submits while another foreign thread closes. The
/// request either fails at submit and keeps its token, or reaches the
/// dispatch thread exactly once.
#[test]
fn loom_a_submit_that_races_the_close_completes_once() {
    model(|| {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let dispatch = spawn_dispatch(&s);
        let io = spawn_io(&s, &[], false);
        let submitter = {
            let s = Arc::clone(&s);
            thread::spawn(move || s.submit(exists(7)).is_ok())
        };
        let got = close_foreign(&s, io, dispatch);
        let accepted = submitter.join().unwrap();
        if accepted {
            assert_eq!(got.by_token, expect(&[(7, ZCLOSING)]));
        } else {
            assert!(got.is_empty(), "{got:?}");
        }
        assert!(host.discarded().is_empty());
    });
}

// ---------------------------------------------------------------------
// The close mark over a socket pair.
// ---------------------------------------------------------------------

/// The result code of each reply that the peer sends.
const ZNONODE: i32 = -101;

/// Reads from the peer end until it holds `n` whole frames. It waits up
/// to 1 s for each read, and it never waits for an idle socket.
fn recv_frames(r: &Rig, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while split_frames(&out).map_or(0, |f| f.len()) < n {
        let mut fds = [PollFd::new(&r.peer, PollFlags::IN)];
        assert_eq!(RealPoll.poll(&mut fds, 1000).unwrap(), 1, "no frame came");
        loop {
            match r.peer.recv(&mut buf) {
                Ok(0) => panic!("the driver closed the socket"),
                Ok(k) => out.extend_from_slice(&buf[..k]),
                Err(Errno::WOULDBLOCK) => break,
                Err(Errno::INTR) => {}
                Err(e) => panic!("peer recv: {e}"),
            }
        }
    }
    out
}

/// Makes an mt rig in `Connected` with one queued exists request for
/// each id in `ids`. The peer replies ZNONODE to each request in one
/// write, so the next read of the driver takes every reply.
fn rig_with_replies(ids: &[u64]) -> Rig {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    // The final close sends CLOSE_OP and does not wait for the peer.
    r.env.cfg.close_wait_ms = 0;
    let _ = r.process(write_ev());
    let _connect = recv_frames(&r, 1);
    r.peer_send(&accept_frame());
    let _ = r.process(read_ev());
    assert_eq!(r.state(), State::Connected);
    {
        let now = r.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let mut core = r.core.lock(&mut proof);
        let conn = core.conn.as_deref_mut().unwrap();
        for id in ids {
            assert!(conn.submit(queued_exists(*id), now).is_ok());
        }
    }
    let _ = r.interest();
    let _ = r.process(write_ev());
    let xids = exists_xids(&recv_frames(&r, ids.len()));
    assert_eq!(xids.len(), ids.len(), "{xids:?}");
    let mut replies = Vec::new();
    for (zxid, xid) in (5..).zip(&xids) {
        replies.extend_from_slice(&encode_reply(*xid, zxid, ZNONODE, &[]));
    }
    r.peer_send(&replies);
    r.wait_readable();
    r
}

/// A poll that never blocks. A real wait stops every loom thread, so
/// the closer cannot run and write the waker byte. When no descriptor
/// is ready, this poll lets the other threads run and then reports a
/// timeout. A real poll can also end at its timeout with no event.
struct ModelPoll;

impl Poll for ModelPoll {
    fn poll(&self, fds: &mut [PollFd<'_>], timeout_ms: i32) -> rustix::io::Result<usize> {
        let ready = RealPoll.poll(fds, 0)?;
        if ready == 0 && timeout_ms != 0 {
            thread::yield_now();
        }
        Ok(ready)
    }
}

/// The threaded handle over the rig. The peer end stays open until the
/// model iteration ends.
struct RigHandle {
    s: Arc<S>,
    host: Arc<TestHost>,
    _peer: crate::net::sock::TcpSock,
}

fn into_handle(r: Rig) -> RigHandle {
    let Rig {
        host,
        mut env,
        core,
        io,
        peer,
        ..
    } = r;
    env.poll = Arc::new(ModelPoll);
    let mut ob = Outbox::new();
    let s = Shared::new(core.into_inner(), env, &mut ob).unwrap();
    assert!(ob.is_empty());
    s.io.lock_owner().io = io;
    s.thread_enter(Role::Io);
    s.thread_enter(Role::Dispatch);
    RigHandle {
        s,
        host,
        _peer: peer,
    }
}

/// The dispatch thread as a value that any closer can join. The close
/// that wins gives the join item, and that thread takes the handle.
#[derive(Clone)]
struct DispatchSlot {
    handle: Arc<Mutex<Option<JoinHandle<Delivered>>>>,
    got: Arc<Mutex<Option<Delivered>>>,
}

impl DispatchSlot {
    fn spawn(s: &Arc<S>) -> Self {
        Self {
            handle: Arc::new(Mutex::new(Some(spawn_dispatch(s)))),
            got: Arc::new(Mutex::new(None)),
        }
    }

    fn join(&self) {
        let h = self.handle.lock_owner().take().expect("one join only");
        let got = h.join().unwrap();
        *self.got.lock_owner() = Some(got);
    }

    fn delivered(&self) -> Delivered {
        self.got
            .lock_owner()
            .take()
            .expect("a close joined the dispatch thread")
    }
}

fn is_queueing_log(item: &Item<TestTokens>) -> bool {
    matches!(item, Item::Log(rec) if rec.site == LogSite::QueueingAsync)
}

/// The IO thread of C over the rig. It runs one IO step and drains it.
/// With `close_in_log`, the log callback of the first queued reply
/// closes the handle with the IO role. Then the thread waits for the
/// close request, takes `Exit` and leaves. It returns the results that
/// it delivered on its own thread.
fn io_thread(s: &S, close_in_log: bool, dispatch: &DispatchSlot) -> Delivered {
    let mut seen = Delivered::new();
    let mut closed = false;
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.io_step(&mut ob, &mut rc);
    let end = drive(s, first, &mut ob, &mut rc, |item| {
        note(&mut seen, item);
        if close_in_log && !closed && is_queueing_log(item) {
            closed = true;
            let mut ob = s.outbox();
            let mut rc = -1;
            let first = s.close(Role::Io, &mut ob, &mut rc);
            let end = drive(s, first, &mut ob, &mut rc, |item| match item {
                Item::Thread {
                    op: ThreadOp::Join,
                    role: ThreadRole::Dispatch,
                } => dispatch.join(),
                Item::Thread {
                    op: ThreadOp::Join,
                    role: ThreadRole::Io,
                } => panic!("the IO thread joins itself"),
                other => note(&mut seen, other),
            });
            assert_eq!(end, Step::Done(ZOK));
        }
    });
    if end != Step::Exit {
        while !s.life.close_requested() {
            thread::yield_now();
        }
        let mut ob = s.outbox();
        let mut rc = -1;
        assert_eq!(s.io_step(&mut ob, &mut rc), Step::Exit);
    }
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.thread_exit(Role::Io, &mut ob, &mut rc);
    let end = drive(s, first, &mut ob, &mut rc, |item| note(&mut seen, item));
    assert!(matches!(end, Step::Done(ZOK) | Step::Release), "{end:?}");
    seen
}

/// Closes from a foreign thread. It joins the IO thread at its join
/// item. A close that loses the race to another close gives no item.
fn foreign_close(
    s: &S,
    io: &mut Option<JoinHandle<Delivered>>,
    dispatch: &DispatchSlot,
) -> (Delivered, Delivered) {
    let mut seen = Delivered::new();
    let mut on_io = Delivered::new();
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.close(Role::Foreign, &mut ob, &mut rc);
    let end = drive(s, first, &mut ob, &mut rc, |item| match item {
        Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Io,
        } => on_io = io.take().unwrap().join().unwrap(),
        Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Dispatch,
        } => dispatch.join(),
        other => note(&mut seen, other),
    });
    assert!(matches!(end, Step::Done(ZOK) | Step::Release), "{end:?}");
    (seen, on_io)
}

/// Merges the deliveries of all threads by token.
fn merge(parts: &[&Delivered]) -> ByToken {
    let mut all = ByToken::new();
    for part in parts {
        for (id, rcs) in &part.by_token {
            all.entry(*id).or_default().extend_from_slice(rcs);
        }
    }
    all
}

/// Checks that each request got exactly one result, with the reply code
/// or ZCLOSING, and that the final close ran and discarded no token.
/// The dispatch thread must deliver the replies in request order, because
/// ZooKeeper completes the requests of one session in order.
fn check_once(h: &RigHandle, ids: &[u64], all: &ByToken, dispatched: &Delivered) {
    dispatched.assert_in_order(ZNONODE);
    assert_eq!(all.keys().copied().collect::<Vec<_>>(), ids, "{all:?}");
    for (id, rcs) in all {
        assert!(
            matches!(rcs.as_slice(), [ZNONODE] | [ZCLOSING]),
            "request {id}: {rcs:?}"
        );
    }
    assert!(h.host.discarded().is_empty(), "{:?}", h.host.discarded());
    let mut proof = Unlocked::new_at_entry();
    assert!(h.s.core.lock(&mut proof).conn.is_none(), "no final close");
}

/// The close from a log callback on the IO thread. The IO step decoded
/// two replies in one read. The callback of the first log line closes
/// the handle while the dispatch thread runs. Each reply reaches the
/// dispatch thread once, with its real result code.
#[test]
fn loom_a_close_from_an_io_log_callback_delivers_every_decoded_reply() {
    model(|| {
        let h = into_handle(rig_with_replies(&[2, 3]));
        let dispatch = DispatchSlot::spawn(&h.s);
        let on_io = io_thread(&h.s, true, &dispatch);
        let got = dispatch.delivered();
        assert!(on_io.is_empty(), "{on_io:?}");
        assert_eq!(got.by_token, expect(&[(2, ZNONODE), (3, ZNONODE)]));
        check_once(&h, &[2, 3], &got.by_token, &got);
    });
}

/// A foreign close races an IO step that holds decoded replies. Each
/// request gets one result: its reply when the IO step takes it first,
/// else ZCLOSING.
#[test]
fn loom_a_foreign_close_racing_an_io_step_gives_one_result_each() {
    model(|| {
        let h = into_handle(rig_with_replies(&[2, 3]));
        let dispatch = DispatchSlot::spawn(&h.s);
        let mut io = Some({
            let s = Arc::clone(&h.s);
            let d = dispatch.clone();
            thread::spawn(move || io_thread(&s, false, &d))
        });
        let (on_closer, on_io) = foreign_close(&h.s, &mut io, &dispatch);
        assert!(io.is_none(), "the close joined the IO thread");
        let got = dispatch.delivered();
        assert!(on_closer.is_empty() && on_io.is_empty());
        check_once(&h, &[2, 3], &got.by_token, &got);
    });
}

/// A foreign close and a close from a log callback on the IO thread race.
/// Either close can win. Each request still gets exactly one result, and
/// the final close runs once.
#[test]
fn loom_a_foreign_close_racing_an_io_callback_close_gives_one_result_each() {
    model(|| {
        let h = into_handle(rig_with_replies(&[2, 3]));
        let dispatch = DispatchSlot::spawn(&h.s);
        let mut io = Some({
            let s = Arc::clone(&h.s);
            let d = dispatch.clone();
            thread::spawn(move || io_thread(&s, true, &d))
        });
        let (on_closer, mut on_io) = foreign_close(&h.s, &mut io, &dispatch);
        // The IO thread detaches itself when its close wins. The model
        // joins it here, because loom needs every thread to end.
        if let Some(io) = io.take() {
            on_io = io.join().unwrap();
        }
        let got = dispatch.delivered();
        let all = merge(&[&got, &on_closer, &on_io]);
        check_once(&h, &[2, 3], &all, &got);
    });
}

/// Makes an mt rig in `Connected` with the sync request 1, the queued
/// request 2 and the auth 3. The peer then ends the stream with no reply.
fn rig_at_the_end_of_the_stream() -> Rig {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    let _ = r.process(write_ev());
    let _connect = recv_frames(&r, 1);
    r.peer_send(&accept_frame());
    let _ = r.process(read_ev());
    assert_eq!(r.state(), State::Connected);
    submit_a_sync_and_a_queued_request(&mut r);
    let _requests = recv_frames(&r, 3);
    rustix::net::shutdown(&r.peer, rustix::net::Shutdown::Write).unwrap();
    r.wait_readable();
    r
}

/// The close tail. The teardown of the IO thread stops for good, so only
/// `destroy` fails the queued request and the auth. A foreign close runs
/// `destroy` while the dispatch thread runs. The dispatch thread delivers
/// the request result once, before it exits at the mark. The closer runs
/// the auth completion once, and no token goes to `discard_token`.
#[test]
fn loom_a_foreign_close_gives_a_destroy_result_to_the_dispatch_thread() {
    model(|| {
        let h = into_handle(rig_at_the_end_of_the_stream());
        stop_the_teardown(&h.s);
        let dispatch = spawn_dispatch(&h.s);
        let io = spawn_io(&h.s, &[], false);
        let (closer, got) = close_foreign_seen(&h.s, io, dispatch);
        assert_eq!(got.by_token, expect(&[(2, ZCLOSING)]));
        assert!(got.auths.is_empty(), "{got:?}");
        assert_eq!(closer.auths, [(3, ZCLOSING)]);
        assert!(h.host.discarded().is_empty(), "{:?}", h.host.discarded());
        let mut proof = Unlocked::new_at_entry();
        assert!(h.s.core.lock(&mut proof).conn.is_none(), "no final close");
    });
}

/// The dispatch thread of C whose first completion callback closes the
/// handle. The close joins the IO thread at its join item. At the exit
/// of the dispatch loop, the thread runs the close tail. It returns what
/// the thread delivered and the end of its exit.
fn spawn_closing_dispatch(s: &Arc<S>, io: JoinHandle<()>) -> JoinHandle<(Delivered, Step)> {
    let s = Arc::clone(s);
    thread::spawn(move || {
        let mut io = Some(io);
        let mut seen = Delivered::new();
        loop {
            let mut ob = s.outbox();
            if s.wait_dispatch(&mut ob) == Step::Exit {
                break;
            }
            while let Some(item) = ob.pop() {
                note(&mut seen, &item);
                if io.is_none() {
                    continue;
                }
                let mut ob = s.outbox();
                let mut rc = -1;
                let first = s.close(Role::Dispatch, &mut ob, &mut rc);
                let end = drive(&s, first, &mut ob, &mut rc, |item| match item {
                    Item::Thread {
                        op: ThreadOp::Join,
                        role: ThreadRole::Io,
                    } => io.take().unwrap().join().unwrap(),
                    Item::Thread {
                        op: ThreadOp::Join,
                        role: ThreadRole::Dispatch,
                    } => panic!("the dispatch thread joins itself"),
                    other => note(&mut seen, other),
                });
                assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
            }
        }
        assert!(io.is_none(), "the close joined the IO thread");
        let mut ob = s.outbox();
        let mut rc = -1;
        let first = s.thread_exit(Role::Dispatch, &mut ob, &mut rc);
        let end = drive(&s, first, &mut ob, &mut rc, |item| note(&mut seen, item));
        assert_eq!(rc, ZOK);
        (seen, end)
    })
}

/// The close tail at the exit of the dispatch thread. The teardown of the
/// IO thread stops for good, so only `destroy` fails the queued request
/// and the auth. A completion callback closes the handle, and the
/// dispatch thread runs `destroy` at its exit. An application thread
/// holds a ref, so the release can run on either thread. The dispatch
/// thread delivers each result once, and the release comes once.
#[test]
fn loom_a_close_from_a_completion_callback_delivers_destroy_results_once() {
    model(|| {
        let h = into_handle(rig_at_the_end_of_the_stream());
        stop_the_teardown(&h.s);
        h.s.thread_enter(Role::Foreign);
        let io = spawn_io(&h.s, &[], false);
        let dispatch = spawn_closing_dispatch(&h.s, io);
        let holder = {
            let s = Arc::clone(&h.s);
            thread::spawn(move || {
                let mut ob = s.outbox();
                let mut rc = -1;
                let first = s.thread_exit(Role::Foreign, &mut ob, &mut rc);
                let mut seen = Delivered::new();
                let end = drive(&s, first, &mut ob, &mut rc, |item| note(&mut seen, item));
                assert_eq!(rc, ZOK);
                (seen, end)
            })
        };
        let (got, dispatch_end) = dispatch.join().unwrap();
        let (on_holder, holder_end) = holder.join().unwrap();
        assert!(on_holder.is_empty(), "{on_holder:?}");
        assert_eq!(got.by_token, expect(&[(2, ZCLOSING)]));
        assert_eq!(got.auths, [(3, ZCLOSING)]);
        let releases = [dispatch_end, holder_end]
            .iter()
            .filter(|end| **end == Step::Release)
            .count();
        assert_eq!(releases, 1, "{dispatch_end:?} {holder_end:?}");
        assert!(h.host.discarded().is_empty(), "{:?}", h.host.discarded());
        let mut proof = Unlocked::new_at_entry();
        assert!(h.s.core.lock(&mut proof).conn.is_none(), "no final close");
    });
}
