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

//! The guaranteed delete of the participant nodes.
//!
//! This module has the purpose of Curator's guaranteed delete and of its
//! `FindAndDeleteProtectedNodeInBackground`. A drop cannot wait, so a
//! drop gives its node to this module, and the module deletes the node
//! with no further call of the application.
//!
//! The design has two levels:
//!
//! 1. A drop of a known node sends the `delete` at once. A small waker
//!    watches the reply and takes it on the thread that completes it. A
//!    success, `NoNode` or another final error ends the job there. Thus
//!    a delete with no fault starts no thread, and the reply does not
//!    hold the read gate of the client.
//! 2. An error that can change moves the job to one background thread,
//!    `zk-recipes-delete`. The thread starts when the first job comes
//!    and stops when no job is left. One thread serves the process.
//!
//! A create that a drop abandons before its reply also uses the thread,
//! with no fault. Its reply comes on the IO side, and the waker sends no
//! request there. Thus the thread sends the `delete`.
//!
//! After a connection loss or `NotReadOnly`, a job retries only at a new
//! `Connected` epoch of the same session. A read-only connection does
//! not count, because a read-only server applies no write. After
//! `TooManyPendingRequests`, the client sent nothing. The job then waits
//! for room in the request queue and sends again. A job ends with a
//! success, `NoNode` or another final error. It also ends when the
//! client reaches a terminal state, also after a detach. A job holds a
//! [`WeakClient`], so it does not keep the session open. It holds a
//! `Client` only while it submits a request, never across an `await`.
//!
//! A protected create with an unknown outcome has no known node name.
//! Its job lists the parent after a `sync` and deletes only the children
//! that carry the exact recorded `_c_<uuid>-` id.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread, ThreadId};

use apache_zookeeper::{
    Client, Error, ResponseFuture, Stat, StateWatcher, Version, WeakClient, ZPath, ZPathBuf,
};

use super::protected::ProtectedId;
use super::session::{is_retryable, synced_list, writable_after};

/// The name of the background thread.
const THREAD_NAME: &str = "zk-recipes-delete";

/// One job as an owned future.
type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Deletes the node at `path` with no further call of the caller.
///
/// The `delete` goes out now. When its reply gives an error that can
/// change, the background thread sends it again (see [`retry`]).
pub(crate) fn delete(client: &Client, path: ZPathBuf) {
    let session = Session::new(client);
    let sent = session.state.current().epoch;
    let reply = client.delete(&path, None::<Version>);
    watch(async move {
        if let Some(next) = reply.await.err().and_then(|e| retry(&e, sent)) {
            submit(delete_task(session, path, next));
        }
    });
}

/// Takes over a participant create that the caller gave up before its
/// reply.
///
/// A success gives the node name, and the background thread deletes the
/// node. A connection loss leaves the outcome unknown, so the background
/// thread looks for the node by its id. Each other error means that the
/// server made no node. `sent` is the epoch when the create went out.
pub(crate) fn abandon_create(
    client: &Client,
    parent: ZPathBuf,
    id: ProtectedId,
    sent: u64,
    reply: ResponseFuture<(ZPathBuf, Stat)>,
) {
    let session = Session::new(client);
    watch(async move {
        match reply.await {
            Ok((path, _)) => submit(delete_task(session, path, Next::Now)),
            Err(e) if e.is_connection_loss() => {
                submit(lookup_task(session, parent, id, sent));
            }
            Err(_) => {}
        }
    });
}

/// Finds and deletes the node of a protected create with an unknown
/// outcome. `sent` is the epoch when the create went out.
pub(crate) fn find_and_delete(client: &Client, parent: ZPathBuf, id: ProtectedId, sent: u64) {
    submit(lookup_task(Session::new(client), parent, id, sent));
}

/// The session of one job. It does not keep the session open.
struct Session {
    client: WeakClient,
    state: StateWatcher,
}

impl Session {
    fn new(client: &Client) -> Self {
        Self {
            client: client.downgrade(),
            state: client.state_watcher(),
        }
    }

    /// Submits requests with a `Client` that lives only for this call.
    /// It gives `None` after the last `Client` dropped. The session then
    /// closes, and its ephemeral nodes go away with it.
    fn send<T>(&self, f: impl FnOnce(&Client) -> T) -> Option<T> {
        self.client.upgrade().map(|client| f(&client))
    }
}

/// What a job waits for before it sends again.
#[derive(Clone, Copy)]
enum Next {
    /// Nothing. The job sends at once.
    Now,
    /// A `Connected` state with an epoch above this epoch. A request of
    /// this epoch has an unknown result, or a read-only server refused
    /// it.
    Epoch(u64),
    /// Room in the request queue, then a `Connected` state in this epoch
    /// or later. The client refused a request of this epoch and sent
    /// nothing.
    Room(u64),
}

/// The wait after `e`, for a request that went out in `epoch`. It gives
/// `None` for a final error, which ends the job.
///
/// A full queue (`max_pending_requests`) is not final. Curator has no
/// such limit, but the node of a refused `delete` blocks the other
/// participants in the same way as a lost one.
fn retry(e: &Error, epoch: u64) -> Option<Next> {
    if is_retryable(e) {
        Some(Next::Epoch(epoch))
    } else if matches!(e, Error::TooManyPendingRequests) {
        Some(Next::Room(epoch))
    } else {
        None
    }
}

/// Waits as `next` tells, and gives the epoch of the next send. It gives
/// `None` when the client reaches a terminal state.
///
/// The wait for room uses [`Client::ready`]. Its future holds no strong
/// reference to the client, so the wait does not keep the session open.
async fn wait(session: &mut Session, next: Next) -> Option<u64> {
    match next {
        Next::Now => Some(session.state.current().epoch),
        Next::Epoch(after) => writable_after(&mut session.state, after).await,
        Next::Room(epoch) => {
            session.send(Client::ready)?.await.ok()?;
            writable_after(&mut session.state, epoch.saturating_sub(1)).await
        }
    }
}

/// Deletes `path` after the wait of `next`, and sends again until the
/// `delete` gives a final result.
async fn delete_task(mut session: Session, path: ZPathBuf, mut next: Next) {
    loop {
        let Some(sent) = wait(&mut session, next).await else {
            return;
        };
        let Some(reply) = session.send(|c| c.delete(&path, None::<Version>)) else {
            return;
        };
        let Some(later) = reply.await.err().and_then(|e| retry(&e, sent)) else {
            return;
        };
        next = later;
    }
}

/// Lists `parent` after a `sync` and deletes each child with the exact
/// `id`. It does a new pass after each error that can change, until one
/// pass ends with no such error.
///
/// The `sync` makes the server catch up with the leader, so the list
/// shows a create that the ensemble applied. The first pass waits for an
/// epoch after `sent`, because the create went out in that epoch or
/// earlier. Each pass runs on a `Connected` state, because a read-only
/// server can show an old list.
async fn lookup_task(mut session: Session, parent: ZPathBuf, id: ProtectedId, sent: u64) {
    let mut next = Next::Epoch(sent);
    loop {
        let Some(epoch) = wait(&mut session, next).await else {
            return;
        };
        let Some(later) = lookup_pass(&session, parent.as_path(), &id, epoch).await else {
            return;
        };
        next = later;
    }
}

/// Does one pass of [`lookup_task`] in `epoch`. It gives the wait before
/// the next pass, or `None` when the job ends.
async fn lookup_pass(
    session: &Session,
    parent: ZPath<'_>,
    id: &ProtectedId,
    epoch: u64,
) -> Option<Next> {
    let (sync, mut list) = session.send(|c| (c.sync(parent), c.get_children(parent)))?;
    let children = match synced_list(sync, &mut list).await {
        Ok(children) => children,
        // A missing parent has no child. A final error ends the job.
        Err(e) => return retry(&e, epoch),
    };
    let paths: Vec<ZPathBuf> = children
        .iter()
        .filter(|child| id.owns(child))
        .filter_map(|child| parent.join(child).ok())
        .collect();
    if paths.is_empty() {
        return None;
    }
    delete_owned(session, &paths, epoch).await
}

/// Deletes the `paths` of one pass in `epoch`. It gives the wait before
/// the next pass, or `None` when each `delete` has a final result.
async fn delete_owned(session: &Session, paths: &[ZPathBuf], epoch: u64) -> Option<Next> {
    let deletes = session.send(|c| {
        paths
            .iter()
            .map(|p| c.delete(p, None::<Version>))
            .collect::<Vec<_>>()
    })?;
    // A lost `delete` waits for a new epoch. That wait also covers a
    // refused `delete`, because the next pass lists the parent again.
    let (mut lost, mut refused) = (false, false);
    for reply in deletes {
        match reply.await.err().and_then(|e| retry(&e, epoch)) {
            Some(Next::Epoch(_)) => lost = true,
            Some(_) => refused = true,
            None => {}
        }
    }
    if lost {
        Some(Next::Epoch(epoch))
    } else if refused {
        Some(Next::Room(epoch))
    } else {
        None
    }
}

/// Runs `fut` with no thread of its own. The caller polls it once, and
/// each wake polls it again on the thread that wakes it.
///
/// The future awaits only one `ResponseFuture`. The client calls its
/// waker after it releases each lock, and a poll of a ready reply does
/// not block. Thus the poll is safe on the IO side of the client. The
/// future then ends, or it moves its job to the background thread.
fn watch(fut: impl Future<Output = ()> + Send + 'static) {
    let inline = Arc::new(Inline(Mutex::new(Some(Box::pin(fut)))));
    inline.poll();
}

/// The waker and the future of [`watch`]. The lock lets one poll run at
/// a time. A wake that comes during a poll waits, then polls again, so
/// it is not lost.
struct Inline(Mutex<Option<Task>>);

impl Inline {
    fn poll(self: &Arc<Self>) {
        let waker = Waker::from(Arc::clone(self));
        let mut cx = Context::from_waker(&waker);
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let ready = slot
            .as_mut()
            .is_some_and(|task| task.as_mut().poll(&mut cx).is_ready());
        if ready {
            let done = slot.take();
            drop(slot);
            drop(done);
        }
    }
}

impl Wake for Inline {
    fn wake(self: Arc<Self>) {
        self.poll();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.poll();
    }
}

/// The background thread and its new jobs.
struct Worker {
    /// The jobs that the thread did not take yet.
    queue: Vec<Task>,
    /// The thread, while it runs.
    thread: Option<Thread>,
    /// The number of thread starts, for the tests.
    #[cfg(test)]
    starts: usize,
}

/// The one worker of the process.
static WORKER: Mutex<Worker> = Mutex::new(Worker {
    queue: Vec::new(),
    thread: None,
    #[cfg(test)]
    starts: 0,
});

/// The worker state. No code holds the lock across a poll, so a
/// poisoned lock still holds a valid state.
fn worker() -> MutexGuard<'static, Worker> {
    WORKER.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Gives a job to the background thread, and starts the thread when it
/// does not run.
fn submit(job: impl Future<Output = ()> + Send + 'static) {
    let mut w = worker();
    w.queue.push(Box::pin(job));
    if let Some(t) = &w.thread {
        t.unpark();
        return;
    }
    // The new thread waits for the lock, so it sees `thread` set.
    match thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(run)
    {
        Ok(handle) => {
            w.thread = Some(handle.thread().clone());
            #[cfg(test)]
            {
                w.starts = w.starts.saturating_add(1);
            }
        }
        Err(_) => {
            // With no thread, the jobs cannot run. Their nodes go away
            // when the session ends. The drop runs after the unlock.
            let lost = std::mem::take(&mut w.queue);
            drop(w);
            drop(lost);
        }
    }
}

/// The loop of the background thread.
///
/// It polls each job when a wake comes, and parks between the wakes,
/// so a waiting job uses no CPU. When no job is left, the thread clears
/// its entry under the lock and exits. The next job starts a new
/// thread. The thread is detached, so it does not block the exit of
/// the process or the close of a client.
fn run() {
    let me = thread::current();
    let _exit = Exit(me.id());
    let waker = Waker::from(Arc::new(Unpark(me)));
    let mut cx = Context::from_waker(&waker);
    let mut jobs: Vec<Task> = Vec::new();
    loop {
        {
            let mut w = worker();
            jobs.append(&mut w.queue);
            if jobs.is_empty() {
                w.thread = None;
                return;
            }
        }
        // A job that panics ends alone. The other jobs go on.
        jobs.retain_mut(|job| {
            matches!(
                catch_unwind(AssertUnwindSafe(|| job.as_mut().poll(&mut cx))),
                Ok(Poll::Pending)
            )
        });
        if !jobs.is_empty() {
            thread::park();
        }
    }
}

/// Clears the entry of the worker when its thread ends by an unwind.
/// The check of the id keeps the entry of a newer thread.
struct Exit(ThreadId);

impl Drop for Exit {
    fn drop(&mut self) {
        let mut w = worker();
        if w.thread.as_ref().is_some_and(|t| t.id() == self.0) {
            w.thread = None;
        }
    }
}

/// The waker of the background thread.
struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// True while the background thread runs.
#[cfg(test)]
fn running() -> bool {
    worker().thread.is_some()
}

/// The number of thread starts so far.
#[cfg(test)]
fn starts() -> usize {
    worker().starts
}

#[cfg(test)]
mod tests {
    //! These tests read the private state of the worker. The tests that
    //! use only the public API are in `tests/lock_sim.rs` and
    //! `tests/latch_sim.rs`.

    use std::time::Duration;

    use apache_zookeeper::{Client, Runtime, SessionState, ThreadOptions};
    use zk_fakeserver::{Action, FakeServer, Rule};

    use super::{running, starts};
    use crate::{DistributedLock, LeaderLatch};

    const WAIT: Duration = Duration::from_secs(10);
    const OP_DELETE: i32 = 2;
    const OP_CREATE2: i32 = 15;
    const ERR_NOT_READ_ONLY: i32 = -119;

    /// The tests share the one worker, so they run one at a time.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn within<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(WAIT, f).await.expect("timed out")
    }

    async fn connect(server: &FakeServer) -> Client {
        within(
            Client::builder(server.connect_string())
                .session_timeout(Duration::from_secs(4))
                .reconnect_delay(Duration::from_millis(50))
                .runtime(Runtime::Thread(ThreadOptions::default()))
                .connect(),
        )
        .await
        .unwrap()
    }

    async fn until(mut pred: impl FnMut() -> bool) {
        within(async {
            while !pred() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
    }

    fn children(server: &FakeServer, path: &str) -> usize {
        server.cluster().children(path).map_or(0, |c| c.len())
    }

    /// Makes the `delete` of a held lock node fail with `NotReadOnly`
    /// each time. The job then waits for a new epoch in the worker.
    async fn stuck_delete(server: &FakeServer, client: &Client, path: &str) {
        let guard = within(DistributedLock::new(client, path).unwrap().acquire())
            .await
            .unwrap();
        server.add_rule(
            Rule::on_request()
                .op(OP_DELETE)
                .path(guard.node().as_str())
                .then(Action::Reply {
                    err: ERR_NOT_READ_ONLY,
                }),
        );
        drop(guard);
        until(running).await;
        assert_eq!(server.script().rules()[0].fired(), 1);
    }

    /// The calls that confirm their deletes, and the drops with no fault,
    /// start no thread.
    #[tokio::test]
    async fn no_worker_without_a_lost_delete() {
        let _serial = SERIAL.lock().await;
        until(|| !running()).await;
        let before = starts();
        let server = FakeServer::start().unwrap();
        let a = connect(&server).await;
        let b = connect(&server).await;
        let lock = DistributedLock::new(&a, "/quiet/lock").unwrap();
        let guard = within(lock.acquire()).await.unwrap();
        let other = DistributedLock::new(&b, "/quiet/lock").unwrap();
        assert!(within(other.try_acquire()).await.unwrap().is_none());
        within(guard.release()).await.unwrap();
        let guard = within(lock.acquire()).await.unwrap();
        drop(guard);
        until(|| children(&server, "/quiet/lock") == 0).await;

        let latch = LeaderLatch::new(&a, "/quiet/latch", "a").unwrap();
        let mut started = within(latch.start()).await.unwrap();
        assert!(within(started.changed()).await.unwrap());
        within(started.close()).await.unwrap();
        let started = within(latch.start()).await.unwrap();
        drop(started);
        until(|| children(&server, "/quiet/latch") == 0).await;

        assert_eq!(starts(), before);
        assert!(!running());
        within(a.close()).await.unwrap();
        within(b.close()).await.unwrap();
    }

    /// A create that a drop abandons before its reply starts the thread
    /// once with no fault. The thread sends the `delete`, because the
    /// reply comes on the IO side. Then the thread exits.
    #[tokio::test]
    async fn dropped_create_in_flight_starts_the_worker_once() {
        const PATH: &str = "/inflight/lock";
        let _serial = SERIAL.lock().await;
        until(|| !running()).await;
        let before = starts();
        let server = FakeServer::start().unwrap();
        let client = connect(&server).await;
        let lock = DistributedLock::new(&client, PATH).unwrap();
        // Make the parents first, so the next create is the only one.
        drop(within(lock.acquire()).await.unwrap());
        until(|| children(&server, PATH) == 0).await;
        assert_eq!(starts(), before);
        server.add_rule(
            Rule::on_request()
                .op(OP_CREATE2)
                .path_prefix("/inflight/lock/_c_")
                .once()
                .then(Action::Delay(Duration::from_millis(300))),
        );
        {
            let mut acquire = std::pin::pin!(lock.acquire());
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(std::future::Future::poll(acquire.as_mut(), &mut cx).is_pending());
        }
        until(|| children(&server, PATH) == 1).await;
        until(|| children(&server, PATH) == 0).await;
        until(|| !running()).await;
        assert_eq!(starts(), before.saturating_add(1));
        within(client.close()).await.unwrap();
    }

    /// A session expiry ends the job with no further `delete`, and the
    /// worker exits.
    #[tokio::test]
    async fn expiry_stops_the_retries_and_the_worker_exits() {
        let _serial = SERIAL.lock().await;
        until(|| !running()).await;
        let server = FakeServer::start().unwrap();
        let client = connect(&server).await;
        let mut state = client.state_watcher();
        stuck_delete(&server, &client, "/expire/lock").await;

        assert!(server.cluster().expire_session(client.session().0.0));
        within(async {
            while state.current().state != SessionState::Expired {
                state.changed().await;
            }
        })
        .await;
        until(|| !running()).await;
        assert_eq!(server.script().rules()[0].fired(), 1);
        assert_eq!(children(&server, "/expire/lock"), 0);
    }

    /// The job holds no `Client`. The drop of the last `Client` closes
    /// the session, and the worker exits.
    #[tokio::test]
    async fn last_client_drop_closes_the_session_and_the_worker_exits() {
        let _serial = SERIAL.lock().await;
        until(|| !running()).await;
        let server = FakeServer::start().unwrap();
        let client = connect(&server).await;
        let mut state = client.state_watcher();
        stuck_delete(&server, &client, "/last/lock").await;

        drop(client);
        within(async {
            while state.current().state != SessionState::Closed {
                state.changed().await;
            }
        })
        .await;
        until(|| server.cluster().sessions().is_empty()).await;
        until(|| !running()).await;
        assert_eq!(server.script().rules()[0].fired(), 1);
        assert_eq!(children(&server, "/last/lock"), 0);
    }
}
