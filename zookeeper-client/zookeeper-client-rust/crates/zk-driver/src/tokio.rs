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

//! The tokio task driver (feature `tokio`, Unix only).
//!
//! One task per client runs `run`. It does what the native threaded
//! driver does, with these changes:
//!
//! - Readiness comes from `tokio::io::unix::AsyncFd` over the socket fd.
//!   The task registers the fd again for each wait. `IoCore` gives no
//!   transport identity, and the OS can give a closed fd number to a new
//!   socket. A kept registration can thus miss the events of a new socket.
//! - Wakes come from a `tokio::sync::Notify`, not the pipe waker. The
//!   probe poll set has no waker, so the probe checks the close flag
//!   after each poll (at most 1 s).
//! - Every blocking call is a job (`DeferPolicy::ALL`): resolution, the
//!   reseed, `TlsConnector::new_conn`, the RW probe and the native SASL
//!   mechanism go to `spawn_blocking`. A step that returns
//!   `Progress::Wait` gives its jobs through `IoCore::take_jobs`, and the
//!   task awaits each result before it continues, so the step order is
//!   the inline order. A resolution with an open socket is the exception:
//!   it runs in the background, and the socket I/O goes on.
//! - Timers use `tokio::time::sleep` on the interest timeout. A
//!   hand-written `poll_fn` waits on the notify, the readiness and the
//!   timer, so the module needs no `select!` macro.
//!
//! Lock rule: only synchronous helpers take the `io` and `core` locks
//! and make the [`Unlocked`] proof. The async functions only await. No
//! guard and no proof lives across an `.await`, so the task future is
//! `Send`.
//!
//! The runtime must enable IO and time (`enable_io`, `enable_time`).

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::Poll as TaskPoll;
use std::time::Duration;

use ::tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use ::tokio::io::{Interest, Ready};
use zk_jute::JString;
use zk_proto::rc::{ZCLOSING, ZCONNECTIONLOSS, ZOK, ZSYSTEMERROR};
use zk_proto::{
    Action, AddAuthError, Cause, ClientId, CloseProgress, Connection, Endpoint, HostResolution,
    HostSpec, Millis, MultiOpRef, ProbeOutcome, Request, ResolveError, SaslCall, SaslCallKind,
    SaslError, SaslSession, SecretBytes, SubmitError, Submitted, TlsResourceAt,
};

use crate::dispatch::{ReadGate, RouteSink};
use crate::host::{DriverTokens, discard_leftovers};
use crate::iocore::{
    DeferPolicy, InterestOut, IoCore, Job, JobCtx, JobDone, Progress, StepCtx, run_job,
};
use crate::native::{SaslHosts, no_mechanism};
use crate::net::poll::PollEvents;
use crate::net::probe::{ProbeCtx, ProbeEnd};
use crate::net::tls::TlsSetupError;
use crate::outbox::{Flavor, Item, Outbox, SaslItem};
use crate::state::{
    Core, Env, SaslAnswer, SubmitResult, read_at_entry, read_conn, with_conn_at_entry,
};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::{Guard, Mutex, Unlocked};

/// The `getaddrinfo` rc of a resolve job that ended with no result
/// (`EAI_FAIL`).
#[cfg(any(target_os = "linux", target_os = "android"))]
const JOB_EAI_FAIL: i32 = -4;
/// The `getaddrinfo` rc of a resolve job that ended with no result
/// (`EAI_FAIL`).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const JOB_EAI_FAIL: i32 = 4;

/// The errno of a resolve job that ended with no result (`EIO`).
const JOB_EIO: i32 = 5;

/// The longest wait when the fd registration fails. The process step
/// then checks the socket at this rate.
const REGISTER_RETRY: Duration = Duration::from_millis(10);

/// The limit of the barrier rounds of one drain. A real drain needs
/// few rounds.
const MAX_DRAIN_ROUNDS: u32 = 4096;

/// The limit of the `poll_action` calls after `destroy`. Only the
/// `CloseTransport` and the final `Dispose` remain then.
const MAX_FINAL_ACTIONS: u32 = 64;

/// The task-side state behind the `io` lock.
pub(crate) struct TaskIo {
    /// The transport and the step continuation.
    pub(crate) io: IoCore,
    /// The native SASL mechanism. A job takes it out and gives it back.
    pub(crate) sasl: Option<Box<dyn SaslSession>>,
}

/// The shared state of one tokio client.
pub(crate) struct TaskShared<T: DriverTokens> {
    pub(crate) core: Mutex<Core<T>>,
    pub(crate) io: Mutex<TaskIo>,
    pub(crate) notify: ::tokio::sync::Notify,
    pub(crate) gate: ReadGate,
    pub(crate) sink: Arc<dyn RouteSink<T>>,
    pub(crate) env: Env<T>,
    /// Set by `close`. The probe job reads it.
    pub(crate) close_requested: Arc<AtomicBool>,
    /// Set by `detach`.
    pub(crate) detached: AtomicBool,
    /// The close rc, sent once when the task ends.
    pub(crate) exit: ::tokio::sync::watch::Sender<Option<i32>>,
    /// The host of each resolved address, for the SASL mechanism. It is
    /// a leaf lock.
    pub(crate) hosts: Mutex<SaslHosts>,
    /// True when the client has a SASL mechanism. Only such a client
    /// records the host of each resolved address.
    pub(crate) sasl_hosts: bool,
    /// True when `queue_close_op` queued the CLOSE_OP. It selects the
    /// close rc and the close_notify. Its writer holds the core lock.
    graceful: AtomicBool,
}

/// The client handle of a tokio driver.
///
/// The session lasts until `close`, `detach` or the drop of the last
/// clone. That drop starts the same close in the background. The task
/// keeps only the shared state, so it does not keep the session open.
pub struct TaskHandle<T: DriverTokens> {
    pub(crate) shared: Arc<TaskShared<T>>,
    /// The clones share it. Its drop starts the close.
    owner: Arc<CloseOnDrop<T>>,
}

impl<T: DriverTokens> Clone for TaskHandle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            owner: Arc::clone(&self.owner),
        }
    }
}

/// Reports taken items to the read gate of a tokio driver.
///
/// A receiver can outlive the last handle while the task drains the
/// queue for the close. The reporter holds no close owner, so it does
/// not keep the session open. It keeps the gate correct until the task
/// ends.
pub struct TaskGate<T: DriverTokens> {
    shared: Arc<TaskShared<T>>,
}

impl<T: DriverTokens> Clone for TaskGate<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T: DriverTokens> TaskGate<T> {
    /// A receiver took or dropped a counted item. When the read gate
    /// reopens, it notifies the task.
    pub fn taken(&self) {
        if self.shared.gate.taken() {
            self.shared.notify.notify_one();
        }
    }
}

/// Starts the close when the last clone of a handle drops.
struct CloseOnDrop<T: DriverTokens> {
    shared: Arc<TaskShared<T>>,
}

impl<T: DriverTokens> Drop for CloseOnDrop<T> {
    fn drop(&mut self) {
        // A close or a detach before the drop makes this do nothing.
        self.shared.tokio_close();
    }
}

impl<T: DriverTokens> TaskHandle<T> {
    /// Makes the first handle of `shared`.
    pub(crate) fn from_shared(shared: Arc<TaskShared<T>>) -> Self {
        let owner = Arc::new(CloseOnDrop {
            shared: Arc::clone(&shared),
        });
        Self { shared, owner }
    }
}

/// Sends the exit value when the task future goes away with no exit.
///
/// The future can go away before its first poll or during a pass, for
/// example at runtime shutdown. The guard then drops the transport,
/// releases the tokens and sends `ZCONNECTIONLOSS`. Thus `closed` does
/// not wait forever.
struct ExitGuard<T: DriverTokens> {
    shared: Arc<TaskShared<T>>,
}

impl<T: DriverTokens> Drop for ExitGuard<T> {
    fn drop(&mut self) {
        self.shared.tokio_abort_exit();
    }
}

/// Starts the driver task on `rt`.
///
/// `conn` is a `DriverMode::NATIVE` connection with `Compat::NATIVE`.
/// The driver sets `env.cfg.cloexec`, because every native handle uses
/// CLOEXEC. The handle owns no thread: the task ends after the close,
/// the detach or the drop of the runtime. The runtime must enable IO
/// and time.
pub fn spawn<T: DriverTokens>(
    conn: Box<Connection<T>>,
    env: Env<T>,
    sink: Arc<dyn RouteSink<T>>,
    sasl: Option<Box<dyn SaslSession>>,
    rt: &::tokio::runtime::Handle,
) -> TaskHandle<T> {
    let mut env = env;
    env.cfg.cloexec = true;
    let shared = Arc::new(TaskShared::tokio_new(conn, env, sink, sasl));
    // The guard is part of the future from the start. Thus a runtime
    // that drops the task before its first poll still sends the exit.
    let guard = ExitGuard {
        shared: Arc::clone(&shared),
    };
    let task = run(Arc::clone(&shared));
    drop(rt.spawn(async move {
        let guard = guard;
        task.await;
        drop(guard);
    }));
    TaskHandle::from_shared(shared)
}

/// The body of the task.
///
/// Each pass: the detach and close checks, the interest step, the jobs
/// (`Progress::Wait`) through `spawn_blocking`, the routing of the
/// outbox, then one wait on the `AsyncFd` readiness, the `notify` and
/// the timeout, then the process step. The close and detach rules are
/// those of `crate::native`.
///
/// A background resolve job runs on the blocking pool across passes.
/// The wait also watches that job, and its result applies before the
/// process step.
pub(crate) async fn run<T: DriverTokens>(shared: Arc<TaskShared<T>>) {
    let mut ob: Outbox<T> = Outbox::new();
    let mut bg: Option<BgTask> = None;
    let rc = loop {
        if shared.detached.load(Ordering::Acquire) {
            break tokio_detach_exit(&shared, &mut ob).await;
        }
        if shared.close_requested.load(Ordering::Acquire) {
            if let Some(rc) = shared.tokio_close_rc() {
                break tokio_final_close(&shared, &mut ob, rc).await;
            }
        }
        let mut out = InterestOut::UNWRITTEN;
        let p = shared.tokio_interest(&mut ob, &mut out);
        tokio_settle(&shared, p, &mut ob, &mut out, &mut bg).await;
        let plan = shared.tokio_wait_plan(&out);
        let (events, finished) = tokio_wait_with(&shared, plan, &mut bg).await;
        // The process step has no interest outputs. The resume of a
        // process continuation writes into this scratch value.
        let mut scratch = InterestOut::UNWRITTEN;
        if let Some(done) = finished {
            let p = shared.tokio_complete_resolve(done, &mut ob, &mut scratch);
            tokio_settle(&shared, p, &mut ob, &mut scratch, &mut bg).await;
        }
        let p = shared.tokio_process(events, &mut ob);
        tokio_settle(&shared, p, &mut ob, &mut scratch, &mut bg).await;
    };
    shared.tokio_finish(rc);
}

/// Continues one step until it is done.
///
/// `More` routes the outbox and resumes the step. `Wait` routes the
/// outbox, runs the deferred jobs one at a time and gives each result
/// to `complete_job`. The step thus keeps the inline order of its calls.
///
/// A step that waits for the background resolve job awaits that job
/// here. At the end a new background job starts in `bg`.
async fn tokio_settle<T: DriverTokens>(
    shared: &Arc<TaskShared<T>>,
    first: Progress,
    ob: &mut Outbox<T>,
    out: &mut InterestOut,
    bg: &mut Option<BgTask>,
) {
    let mut p = first;
    let mut jobs: VecDeque<Job> = VecDeque::new();
    loop {
        tokio_route(shared, ob).await;
        match p {
            Progress::More => p = shared.tokio_resume(ob, out),
            Progress::Done(_) | Progress::Wait => {
                jobs.extend(shared.tokio_take_jobs());
                // A job that a done step left still gets its result, so
                // no deferred call is lost.
                if let Some(job) = jobs.pop_front() {
                    let done = tokio_job(shared, job).await;
                    p = shared.tokio_complete(done, ob, out);
                    continue;
                }
                tokio_start_bg(shared, bg);
                if p != Progress::Wait {
                    return;
                }
                let Some(task) = bg.take() else {
                    return;
                };
                let done = task.join().await;
                p = shared.tokio_complete_resolve(done, ob, out);
            }
        }
    }
}

/// A background resolve job on the blocking pool.
struct BgTask {
    /// The task of the job.
    handle: ::tokio::task::JoinHandle<JobDone>,
    /// The facts for the fallback result.
    kind: JobKind,
}

impl BgTask {
    /// Starts `job` on the blocking pool.
    fn launch<T: DriverTokens>(shared: &Arc<TaskShared<T>>, job: Job) -> Self {
        let kind = JobKind::of(&job);
        let s = Arc::clone(shared);
        let handle = ::tokio::task::spawn_blocking(move || s.tokio_run_job(job));
        Self { handle, kind }
    }

    /// Gives the result of a finished task. A panic gives the fallback
    /// result of `JobKind::failed`.
    fn result(self, r: Result<JobDone, ::tokio::task::JoinError>) -> JobDone {
        r.unwrap_or_else(|_| self.kind.failed())
    }

    /// Waits for the job and gives its result.
    async fn join(mut self) -> JobDone {
        let r = (&mut self.handle).await;
        self.result(r)
    }
}

/// Starts the background resolve job of the last step, when there is
/// one.
fn tokio_start_bg<T: DriverTokens>(shared: &Arc<TaskShared<T>>, bg: &mut Option<BgTask>) {
    if let Some(job) = shared.tokio_take_bg_job() {
        *bg = Some(BgTask::launch(shared, job));
    }
}

/// The facts of a job that its fallback result needs.
enum JobKind {
    Resolve { generation: u64, hosts: usize },
    NewConn,
    Probe { endpoint: Endpoint },
}

impl JobKind {
    fn of(job: &Job) -> Self {
        match job {
            Job::Resolve {
                generation, hosts, ..
            } => Self::Resolve {
                generation: *generation,
                hosts: hosts.len(),
            },
            Job::NewConn { .. } => Self::NewConn,
            Job::Probe { endpoint, .. } => Self::Probe {
                endpoint: endpoint.clone(),
            },
        }
    }

    /// The result of a job that ended with no value (a panic). Each
    /// value is a failure of the same call.
    fn failed(self) -> JobDone {
        match self {
            Self::Resolve { generation, hosts } => JobDone::Resolved {
                generation,
                results: (0..hosts)
                    .map(|host| HostResolution {
                        host,
                        result: Err(ResolveError {
                            gai_rc: JOB_EAI_FAIL,
                            errno: JOB_EIO,
                        }),
                        skipped_families: Vec::new(),
                    })
                    .collect(),
            },
            Self::NewConn => JobDone::NewConn(Err(TlsSetupError::Resource {
                at: TlsResourceAt::ConnectionNew,
            })),
            Self::Probe { endpoint } => JobDone::Probe {
                endpoint,
                end: ProbeEnd::Done(ProbeOutcome::Failed(None)),
            },
        }
    }
}

/// Runs one deferred job on the blocking pool. The runtime worker does
/// not block (`DeferPolicy::ALL`).
async fn tokio_job<T: DriverTokens>(shared: &Arc<TaskShared<T>>, job: Job) -> JobDone {
    BgTask::launch(shared, job).join().await
}

/// Routes the outbox in order.
///
/// The synchronous part routes until a `Sasl` item. The mechanism call
/// then runs on the blocking pool, and the routing continues after it.
async fn tokio_route<T: DriverTokens>(shared: &Arc<TaskShared<T>>, ob: &mut Outbox<T>) {
    while let Some(item) = shared.tokio_route_sync(ob) {
        tokio_sasl(shared, item).await;
    }
}

/// Runs one SASL call of the native mechanism.
///
/// START and STEP put the answer in `Core::sasl` for the next resume.
/// The mechanism leaves the `io` lock for the call. A panic of the
/// mechanism is a mechanism error, and the mechanism is then gone.
/// `Dispose` keeps the mechanism, because the next START starts it
/// again. The final close drops it.
async fn tokio_sasl<T: DriverTokens>(shared: &Arc<TaskShared<T>>, item: SaslItem) {
    let SaslCall { generation, kind } = item.call;
    let answer = match kind {
        SaslCallKind::Dispose => return,
        SaslCallKind::Start => SaslAnswer::Started {
            generation,
            result: tokio_sasl_call(shared, item.addrs, |s| s.start()).await,
        },
        SaslCallKind::Step(token) => SaslAnswer::Stepped {
            generation,
            result: tokio_sasl_call(shared, None, move |s| {
                s.step(token.as_ref().map(SecretBytes::expose))
            })
            .await,
        },
    };
    shared.tokio_store_sasl(answer);
}

/// Runs `call` on the mechanism on the blocking pool, and then puts the
/// mechanism back. With `addrs`, the mechanism first gets the
/// connection facts. With no mechanism, or after a panic, the result is
/// the `no_mechanism` error.
async fn tokio_sasl_call<T: DriverTokens, R: Send + 'static>(
    shared: &Arc<TaskShared<T>>,
    addrs: Option<(SocketAddr, SocketAddr)>,
    call: impl FnOnce(&mut dyn SaslSession) -> Result<R, SaslError> + Send + 'static,
) -> Result<R, SaslError> {
    let Some(mut session) = shared.tokio_take_sasl() else {
        return Err(no_mechanism());
    };
    if let Some((local, peer)) = addrs {
        let host = shared.hosts.lock_owner().host_of(peer);
        session.connection(&host, local, peer);
    }
    let run = move || {
        let r = call(&mut *session);
        (session, r)
    };
    match ::tokio::task::spawn_blocking(run).await {
        Ok((session, r)) => {
            shared.tokio_put_sasl(session);
            r
        }
        Err(_) => Err(no_mechanism()),
    }
}

/// What one wait watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WaitPlan {
    /// The socket and its READ and WRITE interest.
    fd: Option<(RawFd, PollEvents)>,
    /// The wait limit. `None` waits on the notify only.
    timeout: Option<Duration>,
}

/// Waits on the notify, the socket readiness and the timer. It returns
/// the socket events.
///
/// Each wait makes a new `AsyncFd` registration, and the registration
/// goes away before the process step. The kernel reports the current
/// readiness at registration, so no event is lost.
#[cfg(test)]
async fn tokio_wait<T: DriverTokens>(shared: &TaskShared<T>, plan: WaitPlan) -> PollEvents {
    tokio_wait_with(shared, plan, &mut None).await.0
}

/// Waits as `tokio_wait` does, and also for the background resolve job
/// in `bg`. It returns the socket events and the result of that job
/// when it ended.
async fn tokio_wait_with<T: DriverTokens>(
    shared: &TaskShared<T>,
    plan: WaitPlan,
    bg: &mut Option<BgTask>,
) -> (PollEvents, Option<JobDone>) {
    if plan.timeout == Some(Duration::ZERO) {
        ::tokio::task::yield_now().await;
        let done = match bg.take_if(|t| t.handle.is_finished()) {
            Some(task) => Some(task.join().await),
            None => None,
        };
        return (PollEvents::NONE, done);
    }
    let mut timeout = plan.timeout;
    let afd = match plan.fd {
        None => None,
        Some((fd, want)) => match tokio_register(fd, want) {
            Ok(afd) => Some((afd, want)),
            Err(_) => {
                timeout = Some(timeout.map_or(REGISTER_RETRY, |t| t.min(REGISTER_RETRY)));
                None
            }
        },
    };
    let mut notified = pin!(shared.notify.notified());
    let mut sleep = pin!(timeout.map(::tokio::time::sleep));
    let mut finished = None;
    let events = poll_fn(|cx| {
        let woken = notified.as_mut().poll(cx).is_ready();
        if let Some(task) = bg.as_mut() {
            if let TaskPoll::Ready(r) = Pin::new(&mut task.handle).poll(cx) {
                finished = Some(r);
            }
        }
        let mut events = PollEvents::NONE;
        if let Some((afd, want)) = &afd {
            if want.read {
                events = tokio_merge(events, tokio_ready_events(afd.poll_read_ready(cx)));
            }
            if want.write {
                events = tokio_merge(events, tokio_ready_events(afd.poll_write_ready(cx)));
            }
        }
        let timed_out = sleep
            .as_mut()
            .as_pin_mut()
            .is_some_and(|s| s.poll(cx).is_ready());
        if woken || timed_out || !events.is_empty() || finished.is_some() {
            TaskPoll::Ready(events)
        } else {
            TaskPoll::Pending
        }
    })
    .await;
    let done = finished.and_then(|r| bg.take().map(|task| task.result(r)));
    (events, done)
}

/// The events of one readiness poll. `Pending` gives no events.
fn tokio_ready_events(poll: TaskPoll<std::io::Result<AsyncFdReadyGuard<'_, RawFd>>>) -> PollEvents {
    match poll {
        TaskPoll::Ready(Ok(guard)) => tokio_events(guard.ready()),
        TaskPoll::Ready(Err(_)) => tokio_error_events(),
        TaskPoll::Pending => PollEvents::NONE,
    }
}

/// Registers the socket fd with the reactor for one wait.
///
/// `IoCore` gives the socket only as a `RawFd`, so the safe and
/// deprecated `AsyncFd::with_interest` is the only registration that
/// needs no `unsafe`. Its I/O safety rule holds: only the task closes
/// the socket, and the registration goes away before the next step.
/// The `ExitGuard` closes the socket only after the task future, and
/// thus the registration, is gone.
#[allow(deprecated)]
fn tokio_register(fd: RawFd, want: PollEvents) -> std::io::Result<AsyncFd<RawFd>> {
    AsyncFd::with_interest(fd, tokio_interest_of(want))
}

/// The tokio interest of the legacy bits.
fn tokio_interest_of(want: PollEvents) -> Interest {
    match (want.read, want.write) {
        (true, true) => Interest::READABLE.add(Interest::WRITABLE),
        (false, true) => Interest::WRITABLE,
        _ => Interest::READABLE,
    }
}

/// Maps tokio readiness to the legacy events.
///
/// An error gives READ and WRITE, so the next recv or send reports it.
/// A closed read side gives READ, and a closed write side gives WRITE.
/// Tokio sets both sides at a hang-up, so a hang-up gives READ and WRITE.
fn tokio_events(ready: Ready) -> PollEvents {
    let error = ready.is_error();
    PollEvents {
        read: error || ready.is_readable() || ready.is_read_closed(),
        write: error || ready.is_writable() || ready.is_write_closed(),
    }
}

/// The events of a readiness error. The steps then see the error.
fn tokio_error_events() -> PollEvents {
    PollEvents {
        read: true,
        write: true,
    }
}

/// The union of two event sets.
fn tokio_merge(a: PollEvents, b: PollEvents) -> PollEvents {
    PollEvents {
        read: a.read || b.read,
        write: a.write || b.write,
    }
}

/// Routes the proto outputs until no barrier is left.
async fn tokio_drain<T: DriverTokens>(shared: &Arc<TaskShared<T>>, ob: &mut Outbox<T>) {
    for _ in 0..MAX_DRAIN_ROUNDS {
        let barrier = shared.tokio_pump(ob);
        tokio_route(shared, ob).await;
        if !barrier {
            return;
        }
        shared.tokio_resume_stopped();
    }
}

/// The exit after `detach` (`abandon`).
///
/// The handle called `abandon`. The task routes its outputs, drops the
/// transport with no close_notify and exits with `ZOK`.
async fn tokio_detach_exit<T: DriverTokens>(
    shared: &Arc<TaskShared<T>>,
    ob: &mut Outbox<T>,
) -> i32 {
    tokio_drain(shared, ob).await;
    shared.tokio_release(ob);
    ZOK
}

/// The final close after `CloseProgress::Complete`.
///
/// 1. A graceful close on TLS sends close_notify through `close_flush`
///    on the blocking pool. Its rc does not change the close rc.
/// 2. `destroy`, then the routing of its outputs.
/// 3. The last actions: `CloseTransport` and the final `Dispose`.
/// 4. The leftover tokens go to `discard_token`.
async fn tokio_final_close<T: DriverTokens>(
    shared: &Arc<TaskShared<T>>,
    ob: &mut Outbox<T>,
    rc: i32,
) -> i32 {
    if shared.tokio_wants_close_notify() {
        let s = Arc::clone(shared);
        if let Ok(items) = ::tokio::task::spawn_blocking(move || s.tokio_close_flush()).await {
            ob.extend_items(items);
        }
    }
    shared.tokio_destroy();
    tokio_drain(shared, ob).await;
    for _ in 0..MAX_FINAL_ACTIONS {
        if !shared.tokio_final_action() {
            break;
        }
        tokio_drain(shared, ob).await;
    }
    shared.tokio_release(ob);
    rc
}

impl<T: DriverTokens> TaskHandle<T> {
    /// Submits one request and notifies the task.
    ///
    /// After the task ends, the request fails at the validation stage
    /// with `ZCLOSING`, as a closing connection refuses it.
    ///
    /// # Errors
    ///
    /// Returns the proto submit error with its token.
    pub fn submit(&self, req: Request<T>) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_with_data(req, None)
    }

    /// Submits one request whose data is borrowed, as
    /// `Connection::submit_with_data` tells. The other rules are those
    /// of [`Self::submit`].
    ///
    /// # Errors
    ///
    /// Returns the proto submit error with its token.
    pub fn submit_with_data(
        &self,
        req: Request<T>,
        data: Option<&[u8]>,
    ) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_by(req, |c, r, now| c.submit_with_data(r, data, now))
    }

    /// Submits one write multi whose sub-ops are borrowed, as
    /// `Connection::submit_multi_ref` tells. The other rules are those
    /// of [`Self::submit`].
    ///
    /// # Errors
    ///
    /// Returns the proto submit error with its token.
    pub fn submit_multi_ref(
        &self,
        req: Request<T>,
        ops: &[MultiOpRef<'_>],
    ) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_by(req, |c, r, now| c.submit_multi_ref(r, ops, now))
    }

    /// Submits one request through `send` under the core lock, and
    /// notifies the task when proto accepts it.
    fn submit_by(
        &self,
        req: Request<T>,
        send: impl FnOnce(&mut Connection<T>, Request<T>, Millis) -> SubmitResult<T>,
    ) -> SubmitResult<T> {
        let now = self.shared.env.clock.now();
        let r = self
            .shared
            .core
            .lock(&mut Unlocked::new_at_entry())
            .submit_or(req, now, ZCLOSING, send);
        if r.is_ok() {
            self.shared.notify.notify_one();
        }
        r
    }

    /// Records an auth entry and notifies the task.
    ///
    /// After the task ends, it fails with `ZCLOSING`.
    ///
    /// # Errors
    ///
    /// Returns the proto error with the completion token.
    pub fn add_auth(
        &self,
        scheme: JString,
        cred: SecretBytes,
        done: Option<T::Auth>,
    ) -> Result<(), AddAuthError<T>> {
        let now = self.shared.env.clock.now();
        let r = self
            .shared
            .core
            .lock(&mut Unlocked::new_at_entry())
            .add_auth_or(scheme, cred, done, now, ZCLOSING);
        if r.is_ok() {
            self.shared.notify.notify_one();
        }
        r
    }

    /// Gives a new host list to proto and notifies the task. It returns
    /// the new resolver generation, or 0 after the task ends.
    pub fn set_servers(&self, hosts: Vec<HostSpec>) -> u64 {
        let now = self.shared.env.clock.now();
        let generation = self
            .shared
            .core
            .lock(&mut Unlocked::new_at_entry())
            .set_servers_native(hosts, now);
        self.shared.notify.notify_one();
        generation
    }

    /// Starts a graceful close: `begin_close` and `queue_close_op` under
    /// the core lock, the close flag, a notify. A second call does
    /// nothing.
    ///
    /// The close flag comes first. If the task sees it before
    /// `begin_close`, `close_step` gives `Pending`, and the task checks
    /// again in the next pass.
    pub fn close(&self) {
        self.shared.tokio_close();
    }

    /// Waits until the task ends and returns the close rc.
    ///
    /// The close rc is `ZOK`, `ZOPERATIONTIMEOUT` or `ZCONNECTIONLOSS`.
    /// A task that goes away with no exit, for example at runtime
    /// shutdown, gives `ZCONNECTIONLOSS`. Each call gives the same value.
    pub async fn closed(&self) -> i32 {
        let mut rx = self.shared.exit.subscribe();
        loop {
            let seen = *rx.borrow_and_update();
            if let Some(rc) = seen {
                return rc;
            }
            if rx.changed().await.is_err() {
                let last = *rx.borrow();
                return last.unwrap_or(ZSYSTEMERROR);
            }
        }
    }

    /// Ends the client with no close request (`abandon`).
    ///
    /// `abandon` runs under the core lock before the detach flag is set.
    /// Thus the task routes its outputs. The close flag is set too, and
    /// it aborts a running probe job.
    pub fn detach(&self) {
        let s = &self.shared;
        let now = s.env.clock.now();
        {
            // The check and the flags are under the core lock. Thus only
            // one of two concurrent calls abandons the connection.
            let mut proof = Unlocked::new_at_entry();
            let mut core = s.core.lock(&mut proof);
            if s.detached.load(Ordering::Acquire) {
                return;
            }
            if let Some(conn) = core.conn.as_deref_mut() {
                conn.abandon(now);
            }
            s.detached.store(true, Ordering::Release);
            s.close_requested.store(true, Ordering::Release);
        }
        s.notify.notify_one();
    }

    /// A receiver took or dropped a counted item. When the read gate
    /// reopens, it notifies the task.
    pub fn taken(&self) {
        if self.shared.gate.taken() {
            self.shared.notify.notify_one();
        }
    }

    /// Returns a reporter for the read gate. The reporter does not keep
    /// the session open.
    #[must_use]
    pub fn gate_reporter(&self) -> TaskGate<T> {
        TaskGate {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Returns the read gate, for tests and metrics.
    #[must_use]
    pub fn gate(&self) -> &ReadGate {
        &self.shared.gate
    }

    /// The state code of the connection. 0 after the task ends.
    #[must_use]
    pub fn state(&self) -> i32 {
        read_at_entry(&self.shared.core, |c| c.state().code()).unwrap_or(0)
    }

    /// The session identity.
    #[must_use]
    pub fn client_id(&self) -> ClientId {
        read_at_entry(&self.shared.core, Connection::client_id).unwrap_or_default()
    }

    /// The cause of the last teardown, for `DisconnectCause`.
    #[must_use]
    pub fn last_teardown_cause(&self) -> Option<Cause> {
        read_at_entry(&self.shared.core, Connection::last_teardown_cause).flatten()
    }

    /// Runs `f` on the connection under the core lock. It returns `None`
    /// after the driver exits.
    ///
    /// zk-client reads values that the handle has no accessor for, for
    /// example `last_zxid` and `pending_len`. `f` must not block, and it
    /// must not call into the handle.
    pub fn read_conn<R>(&self, f: impl FnOnce(&Connection<T>) -> R) -> Option<R> {
        read_at_entry(&self.shared.core, f)
    }

    /// Runs `f` on the connection under the core lock, then wakes the
    /// driver. It returns `None` after the driver exits.
    ///
    /// zk-client uses it for `detach_watcher` and the `RemoveWatches`
    /// request that can follow it in the same lock scope. The wake lets
    /// the driver route the outputs that `f` makes. `f` must not block,
    /// and it must not call into the handle.
    pub fn with_conn<R>(
        &self,
        f: impl FnOnce(&mut Connection<T>, zk_proto::Millis) -> R,
    ) -> Option<R> {
        let r = with_conn_at_entry(&self.shared.core, self.shared.env.clock.now(), f);
        self.shared.notify.notify_one();
        r
    }
}

impl<T: DriverTokens> TaskShared<T> {
    /// The defer policy of the tokio driver.
    pub(crate) const DEFER: DeferPolicy = DeferPolicy::ALL;

    /// The pump flavor.
    pub(crate) const FLAVOR: Flavor = Flavor::Native;
}

/// The synchronous helpers of the task. Each helper takes its locks and
/// releases them before it returns.
impl<T: DriverTokens> TaskShared<T> {
    /// Starts the graceful close: `begin_close`, `queue_close_op` and a
    /// notify. Only the first close request does this. `TaskHandle::close`
    /// and the drop of the last handle use it.
    fn tokio_close(&self) {
        if self.close_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        let now = self.env.clock.now();
        {
            let mut proof = Unlocked::new_at_entry();
            let mut core = self.core.lock(&mut proof);
            if let Some(conn) = core.conn.as_deref_mut() {
                conn.begin_close(now);
                let queued = conn.queue_close_op();
                self.graceful.store(queued, Ordering::Release);
            }
        }
        self.notify.notify_one();
    }

    /// Makes the shared state of a new client. `spawn` and the tests use
    /// it.
    fn tokio_new(
        conn: Box<Connection<T>>,
        env: Env<T>,
        sink: Arc<dyn RouteSink<T>>,
        sasl: Option<Box<dyn SaslSession>>,
    ) -> Self {
        let gate = ReadGate::new(env.cfg.dispatch_queue_capacity);
        let (exit, _) = ::tokio::sync::watch::channel(None);
        let sasl_hosts = sasl.is_some();
        Self {
            core: Mutex::new(Core::new(conn)),
            io: Mutex::new(TaskIo {
                io: IoCore::new(),
                sasl,
            }),
            notify: ::tokio::sync::Notify::new(),
            gate,
            sink,
            env,
            close_requested: Arc::new(AtomicBool::new(false)),
            detached: AtomicBool::new(false),
            exit,
            hosts: Mutex::new(SaslHosts::default()),
            sasl_hosts,
            graceful: AtomicBool::new(false),
        }
    }

    /// The services of one step call: no waker, the close flag as the
    /// abort flag, and the read gate.
    fn tokio_step_ctx(&self) -> StepCtx<'_, T> {
        self.env.step_ctx(
            &self.core,
            Self::FLAVOR,
            Self::DEFER,
            None,
            Some(&self.close_requested),
            Some(&self.gate),
        )
    }

    /// Prepares one `IoCore` step. It makes the `Unlocked` proof and the
    /// step services, and then takes the `io` lock.
    fn tokio_step_io(&self) -> (Unlocked, StepCtx<'_, T>, Guard<'_, TaskIo>) {
        let proof = Unlocked::new_at_entry();
        let cx = self.tokio_step_ctx();
        (proof, cx, self.io.lock_owner())
    }

    fn tokio_interest(&self, ob: &mut Outbox<T>, out: &mut InterestOut) -> Progress {
        let (mut proof, cx, mut io) = self.tokio_step_io();
        io.io.interest_step(&cx, &mut proof, ob, out)
    }

    fn tokio_process(&self, events: PollEvents, ob: &mut Outbox<T>) -> Progress {
        let (mut proof, cx, mut io) = self.tokio_step_io();
        io.io.process_step(&cx, &mut proof, events, ob)
    }

    fn tokio_resume(&self, ob: &mut Outbox<T>, out: &mut InterestOut) -> Progress {
        let (mut proof, cx, mut io) = self.tokio_step_io();
        io.io.resume(&cx, &mut proof, ob, out)
    }

    fn tokio_complete(&self, done: JobDone, ob: &mut Outbox<T>, out: &mut InterestOut) -> Progress {
        let (mut proof, cx, mut io) = self.tokio_step_io();
        io.io.complete_job(&cx, &mut proof, done, ob, out)
    }

    fn tokio_complete_resolve(
        &self,
        done: JobDone,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        let (mut proof, cx, mut io) = self.tokio_step_io();
        io.io.complete_resolve(&cx, &mut proof, done, ob, out)
    }

    fn tokio_take_jobs(&self) -> Vec<Job> {
        self.io.lock_owner().io.take_jobs()
    }

    fn tokio_take_bg_job(&self) -> Option<Job> {
        self.io.lock_owner().io.take_bg_job()
    }

    /// Runs one job with no driver lock, on the blocking pool. The probe
    /// has no waker. It reads the close flag after each poll.
    fn tokio_run_job(&self, job: Job) -> JobDone {
        let proof = Unlocked::new_at_entry();
        let cx = JobCtx {
            host: &*self.env.host,
            probe: ProbeCtx {
                poll: &*self.env.poll,
                clock: &*self.env.clock,
                wake: None,
                abort: Some(&self.close_requested),
                tls: self.env.tls.as_deref(),
                cloexec: self.env.cfg.cloexec,
                phase_ms: self.env.cfg.probe_phase_ms,
            },
        };
        let names = self.sasl_hosts.then_some(&job).and_then(SaslHosts::names);
        let done = run_job(&cx, &proof, job);
        if let Some(names) = names {
            self.hosts.lock_owner().record(&names, &done);
        }
        done
    }

    /// Routes the items of `ob` in order until a `Sasl` item, and
    /// returns that item.
    ///
    /// Each item that counts adds one to the read gate. `Thread` and
    /// `AuthLockpoint` do not occur in the native flavor.
    fn tokio_route_sync(&self, ob: &mut Outbox<T>) -> Option<SaslItem> {
        while let Some(item) = ob.pop() {
            match item {
                Item::Sasl(sasl) => return Some(sasl),
                Item::Thread { .. } | Item::AuthLockpoint => {}
                other => {
                    if self.sink.route(other) {
                        self.gate.routed();
                    }
                }
            }
        }
        None
    }

    fn tokio_take_sasl(&self) -> Option<Box<dyn SaslSession>> {
        self.io.lock_owner().sasl.take()
    }

    fn tokio_put_sasl(&self, session: Box<dyn SaslSession>) {
        self.io.lock_owner().sasl = Some(session);
    }

    fn tokio_store_sasl(&self, answer: SaslAnswer) {
        let mut proof = Unlocked::new_at_entry();
        self.core.lock(&mut proof).sasl = Some(answer);
    }

    /// Computes the wait of one pass.
    ///
    /// With interest outputs, the task waits on the socket bits and the
    /// timeout. With no outputs, an unrecoverable or ended connection
    /// waits on the notify only. Otherwise the wait is `recv_timeout/60`,
    /// at least 1 ms.
    fn tokio_wait_plan(&self, out: &InterestOut) -> WaitPlan {
        if out.written {
            let want = PollEvents::from_bits(out.bits);
            let fd = (out.fd >= 0 && !want.is_empty()).then_some((out.fd, want));
            let ms = u64::try_from(out.timeout_ms).unwrap_or(0);
            return WaitPlan {
                fd,
                timeout: Some(Duration::from_millis(ms)),
            };
        }
        let mut proof = Unlocked::new_at_entry();
        let facts = read_conn(&self.core, &mut proof, |c| {
            (c.state().is_unrecoverable(), c.recv_timeout())
        });
        let timeout = match facts {
            None | Some((true, _)) => None,
            Some((false, recv)) => {
                let ms = u64::try_from(recv)
                    .unwrap_or(0)
                    .checked_div(60)
                    .unwrap_or(0);
                Some(Duration::from_millis(ms.max(1)))
            }
        };
        WaitPlan { fd: None, timeout }
    }

    /// Returns the close rc when the close is complete, or `None` while
    /// it is pending.
    ///
    /// `close_step` decides when the close ends. Proto
    /// `close_outcome` then gives the rc, so the native and tokio
    /// drivers report the same close result.
    fn tokio_close_rc(&self) -> Option<i32> {
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let mut core = self.core.lock(&mut proof);
        let Some(conn) = core.conn.as_deref_mut() else {
            return Some(ZOK);
        };
        match conn.close_step(now) {
            CloseProgress::Complete => Some(conn.close_outcome().unwrap_or(ZOK)),
            CloseProgress::Pending => None,
        }
    }

    /// Returns true when the final close sends close_notify: a graceful
    /// close with TLS and an open socket.
    fn tokio_wants_close_notify(&self) -> bool {
        self.graceful.load(Ordering::Acquire)
            && self.env.tls.is_some()
            && self.io.lock_owner().io.has_socket()
    }

    /// The flush, the wait and the close_notify of a graceful TLS close.
    /// It blocks, so it runs on the blocking pool. It returns the log
    /// lines of the close wait. The flush rc does not change the close
    /// rc.
    fn tokio_close_flush(&self) -> Vec<Item<T>> {
        let (mut proof, cx, mut io) = self.tokio_step_io();
        let mut ob = Outbox::new();
        let _flush_rc = io.io.close_flush(&cx, &mut proof, &mut ob);
        drop(io);
        std::iter::from_fn(|| ob.pop()).collect()
    }

    fn tokio_destroy(&self) {
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        if let Some(conn) = self.core.lock(&mut proof).conn.as_deref_mut() {
            conn.destroy(now);
        }
    }

    /// Pumps the proto outputs into `ob`. It returns true at a barrier.
    fn tokio_pump(&self, ob: &mut Outbox<T>) -> bool {
        let mut proof = Unlocked::new_at_entry();
        self.core
            .lock(&mut proof)
            .pump(Self::FLAVOR, ob, &*self.env.host)
    }

    fn tokio_resume_stopped(&self) {
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        self.core.lock(&mut proof).resume_stopped(now);
    }

    /// Runs one action after `destroy`. `CloseTransport` drops the
    /// transport, and the final `Dispose` drops the mechanism. It returns
    /// false when proto has no action left.
    fn tokio_final_action(&self) -> bool {
        let now = self.env.clock.now();
        let mut io = self.io.lock_owner();
        let action = {
            let mut proof = Unlocked::new_at_entry();
            let mut core = self.core.lock(&mut proof);
            match core.conn.as_deref_mut() {
                Some(conn) => conn.poll_action(now),
                None => None,
            }
        };
        match action {
            None => false,
            Some(Action::CloseTransport) => {
                io.io.drop_transport();
                true
            }
            Some(Action::Sasl(SaslCall {
                kind: SaslCallKind::Dispose,
                ..
            })) => {
                io.sasl = None;
                true
            }
            Some(_) => true,
        }
    }

    /// Ends the driver state: no transport, no mechanism, no connection.
    /// The leftover tokens go to `discard_token`.
    fn tokio_release(&self, ob: &mut Outbox<T>) {
        {
            let mut io = self.io.lock_owner();
            io.io.drop_transport();
            io.sasl = None;
        }
        self.tokio_discard_conn();
        ob.finish(&*self.env.host);
    }

    /// Sends the exit value once.
    fn tokio_finish(&self, rc: i32) {
        self.exit.send_if_modified(|v| {
            if v.is_some() {
                return false;
            }
            *v = Some(rc);
            true
        });
    }

    /// The exit of a task future that goes away (`ExitGuard`).
    ///
    /// A blocking job that still runs can hold the `io` lock. The helper
    /// then leaves the transport to that job. The transport closes when
    /// the last `Arc` goes.
    fn tokio_abort_exit(&self) {
        if self.exit.borrow().is_some() {
            return;
        }
        if let Some(mut io) = self.io.try_lock() {
            io.io.drop_transport();
            io.sasl = None;
        }
        self.tokio_discard_conn();
        self.tokio_finish(ZCONNECTIONLOSS);
    }

    /// Takes the connection and gives its leftover tokens to
    /// `discard_token`. The discard runs without the core lock.
    fn tokio_discard_conn(&self) {
        let conn = self.core.lock(&mut Unlocked::new_at_entry()).conn.take();
        if let Some(conn) = conn {
            discard_leftovers(&*self.env.host, conn);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::host::HostLeaves;

    use std::io::Write;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    use zk_proto::rc::ZOPERATIONTIMEOUT;
    use zk_proto::{OpResult, Origin, PathIn, SaslStep, State};

    use zk_testkit::tokens::{CompletionId, TestTokens};

    use crate::testutil::{TestHost, exists_request, native_connection};

    /// A sink that keeps the items. Results count.
    #[derive(Default)]
    struct Keep(std::sync::Mutex<Vec<Item<TestTokens>>>);

    impl RouteSink<TestTokens> for Keep {
        fn route(&self, item: Item<TestTokens>) -> bool {
            let counts = matches!(item, Item::Result { .. } | Item::AuthResult { .. });
            self.0.lock().unwrap().push(item);
            counts
        }
    }

    /// A mechanism with a fixed name and no tokens.
    struct Fixed;

    impl SaslSession for Fixed {
        fn start(&mut self) -> Result<(String, SaslStep), SaslError> {
            Ok((
                "FIXED".to_owned(),
                SaslStep {
                    token: None,
                    done: true,
                },
            ))
        }

        fn step(&mut self, _challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
            Ok(SaslStep {
                token: None,
                done: true,
            })
        }
    }

    type Parts = (TaskHandle<TestTokens>, Arc<Keep>);

    fn handle_with(sasl: Option<Box<dyn SaslSession>>) -> Parts {
        let leaves: Arc<dyn HostLeaves<TestTokens>> = Arc::new(TestHost::new());
        let mut env = Env::new(leaves);
        env.cfg.dispatch_queue_capacity = 2;
        let sink = Arc::new(Keep::default());
        let shared = TaskShared::tokio_new(native_connection(), env, sink.clone(), sasl);
        (TaskHandle::from_shared(Arc::new(shared)), sink)
    }

    fn handle() -> TaskHandle<TestTokens> {
        handle_with(None).0
    }

    fn rt() -> ::tokio::runtime::Runtime {
        ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn exists(id: u64) -> Request<TestTokens> {
        exists_request(PathIn::Native("/".into()), id)
    }

    /// Returns true when the notify holds a permit, and takes it.
    fn notified(rt: &::tokio::runtime::Runtime, h: &TaskHandle<TestTokens>) -> bool {
        rt.block_on(async {
            ::tokio::time::timeout(Duration::from_millis(20), h.shared.notify.notified())
                .await
                .is_ok()
        })
    }

    fn connected_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    #[test]
    fn submit_queues_and_notifies() {
        let rt = rt();
        let h = handle();
        assert!(!notified(&rt, &h));
        assert!(h.submit(exists(1)).is_ok());
        assert!(notified(&rt, &h));
        assert!(!notified(&rt, &h));
        assert_eq!(h.state(), State::NotConnected.code());
    }

    #[test]
    fn close_sets_the_flags_once() {
        let rt = rt();
        let h = handle();
        h.close();
        assert!(h.shared.close_requested.load(Ordering::Acquire));
        assert!(!h.shared.detached.load(Ordering::Acquire));
        // Not connected: no CLOSE_OP, so the close is not graceful.
        assert!(!h.shared.graceful.load(Ordering::Acquire));
        assert!(notified(&rt, &h));
        h.close();
        assert!(!notified(&rt, &h));
        // The closing connection refuses new requests.
        let err = h.submit(exists(2)).err().unwrap();
        assert_eq!(err.code, ZCLOSING);
        assert!(!notified(&rt, &h));
        // A close with no CLOSE_OP is complete at once with ZOK.
        assert_eq!(h.shared.tokio_close_rc(), Some(ZOK));
    }

    #[test]
    fn the_drop_of_the_last_clone_starts_the_close() {
        let rt = rt();
        let h = handle();
        let shared = Arc::clone(&h.shared);
        let other = h.clone();
        drop(h);
        // A clone still lives, so the session stays open.
        assert!(!shared.close_requested.load(Ordering::Acquire));
        drop(other);
        assert!(shared.close_requested.load(Ordering::Acquire));
        let woke = rt.block_on(async {
            ::tokio::time::timeout(Duration::from_millis(20), shared.notify.notified())
                .await
                .is_ok()
        });
        assert!(woke);
        assert_eq!(shared.tokio_close_rc(), Some(ZOK));
    }

    #[test]
    fn detach_abandons_and_sets_the_flags() {
        let rt = rt();
        let h = handle();
        assert!(h.submit(exists(3)).is_ok());
        assert!(notified(&rt, &h));
        h.detach();
        assert!(h.shared.detached.load(Ordering::Acquire));
        assert!(h.shared.close_requested.load(Ordering::Acquire));
        assert!(notified(&rt, &h));
        let mut proof = Unlocked::new_at_entry();
        assert_eq!(
            read_conn(&h.shared.core, &mut proof, Connection::is_closing),
            Some(true)
        );
    }

    #[test]
    fn handles_after_the_end_fail_with_closing() {
        let rt = rt();
        let h = handle();
        let mut ob = Outbox::new();
        h.shared.tokio_release(&mut ob);
        let err = h.submit(exists(4)).err().unwrap();
        assert_eq!(err.code, ZCLOSING);
        assert_eq!(err.token, CompletionId::new(4));
        let err = h
            .add_auth(
                JString::Bytes(b"digest".to_vec()),
                SecretBytes::from_slice(b"u:p"),
                None,
            )
            .err()
            .unwrap();
        assert_eq!(err.code, ZCLOSING);
        assert!(!notified(&rt, &h));
        assert_eq!(h.set_servers(Vec::new()), 0);
        assert_eq!(h.state(), 0);
        assert_eq!(h.shared.tokio_close_rc(), Some(ZOK));
    }

    #[test]
    fn closed_gives_the_exit_value_to_every_waiter() {
        let rt = rt();
        let h = handle();
        let h2 = h.clone();
        let waiter = rt.spawn(async move { h2.closed().await });
        h.shared.tokio_finish(ZOPERATIONTIMEOUT);
        h.shared.tokio_finish(ZOK);
        assert_eq!(rt.block_on(waiter).unwrap(), ZOPERATIONTIMEOUT);
        assert_eq!(rt.block_on(h.closed()), ZOPERATIONTIMEOUT);
    }

    #[test]
    fn taken_reopens_the_gate_and_notifies() {
        let rt = rt();
        let h = handle();
        h.gate().routed();
        h.gate().routed();
        assert!(!h.gate().is_open());
        h.taken();
        assert!(h.gate().is_open());
        assert!(notified(&rt, &h));
        h.taken();
        assert!(!notified(&rt, &h));
    }

    #[test]
    fn exit_guard_releases_and_sends_connection_loss() {
        let rt = rt();
        let h = handle();
        drop(ExitGuard {
            shared: Arc::clone(&h.shared),
        });
        assert_eq!(h.state(), 0);
        assert_eq!(rt.block_on(h.closed()), ZCONNECTIONLOSS);
    }

    #[test]
    fn a_dropped_runtime_ends_an_unpolled_task() {
        let leaves: Arc<dyn HostLeaves<TestTokens>> = Arc::new(TestHost::new());
        let rt = rt();
        let h = spawn(
            native_connection(),
            Env::new(leaves),
            Arc::new(Keep::default()),
            None,
            rt.handle(),
        );
        assert!(h.shared.env.cfg.cloexec);
        // A current_thread runtime polls the task only inside block_on.
        drop(rt);
        assert_eq!(*h.shared.exit.borrow(), Some(ZCONNECTIONLOSS));
        assert_eq!(h.state(), 0);
    }

    #[test]
    fn route_counts_items_and_answers_sasl() {
        let rt = rt();
        let (h, sink) = handle_with(Some(Box::new(Fixed)));
        let mut ob = Outbox::new();
        ob.push(Item::Result {
            token: CompletionId::new(5),
            result: OpResult {
                rc: ZCONNECTIONLOSS,
                zxid: 0,
                origin: Origin::Teardown,
                reply: None,
            },
            delivery_logs: Vec::new(),
        });
        ob.push(Item::Sasl(SaslItem {
            call: SaslCall {
                generation: 7,
                kind: SaslCallKind::Start,
            },
            addrs: None,
        }));
        ob.push(Item::AuthLockpoint);
        rt.block_on(tokio_route(&h.shared, &mut ob));
        assert!(ob.is_empty());
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        assert_eq!(h.gate().count(), 1);
        let answer = {
            let mut proof = Unlocked::new_at_entry();
            h.shared.core.lock(&mut proof).sasl.take()
        };
        match answer {
            Some(SaslAnswer::Started {
                generation: 7,
                result: Ok((name, _)),
            }) => assert_eq!(name, "FIXED"),
            other => panic!("unexpected answer {other:?}"),
        }
        // The mechanism is back after the call.
        assert!(h.shared.io.lock_owner().sasl.is_some());
    }

    /// A mechanism that records each connection call.
    struct Conn(Arc<std::sync::Mutex<Vec<Seen>>>);

    /// The host, the local address and the peer address of one call.
    type Seen = (Vec<u8>, SocketAddr, SocketAddr);

    impl SaslSession for Conn {
        fn start(&mut self) -> Result<(String, SaslStep), SaslError> {
            Fixed.start()
        }

        fn step(&mut self, challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
            Fixed.step(challenge)
        }

        fn connection(&mut self, host: &[u8], local: SocketAddr, peer: SocketAddr) {
            self.0.lock().unwrap().push((host.to_vec(), local, peer));
        }
    }

    #[test]
    fn sasl_start_gives_the_resolved_host_to_the_mechanism() {
        let rt = rt();
        let host = Arc::new(TestHost::new());
        let peer = SocketAddr::from(([10, 0, 0, 1], 2181));
        let local = SocketAddr::from(([127, 0, 0, 1], 40000));
        host.set_addrs(b"zk1.example", vec![peer]);
        let leaves: Arc<dyn HostLeaves<TestTokens>> = host;
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mech: Box<dyn SaslSession> = Box::new(Conn(Arc::clone(&seen)));
        let shared = Arc::new(TaskShared::tokio_new(
            native_connection(),
            Env::new(leaves),
            Arc::new(Keep::default()),
            Some(mech),
        ));
        let hosts = zk_proto::legacy::connect::parse_servers(b"zk1.example:2181")
            .unwrap()
            .into_iter()
            .map(zk_proto::HostSpec::Legacy)
            .collect();
        let done = shared.tokio_run_job(Job::Resolve {
            generation: 1,
            hosts,
            shuffle: false,
        });
        assert!(matches!(done, JobDone::Resolved { generation: 1, .. }));
        let mut ob = Outbox::new();
        ob.push(Item::Sasl(SaslItem {
            call: SaslCall {
                generation: 1,
                kind: SaslCallKind::Start,
            },
            addrs: Some((local, peer)),
        }));
        rt.block_on(tokio_route(&shared, &mut ob));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(b"zk1.example".to_vec(), local, peer)]
        );
    }

    #[test]
    fn a_resolve_job_records_hosts_only_with_a_mechanism() {
        let peer = SocketAddr::from(([10, 0, 0, 1], 2181));
        let with: Box<dyn SaslSession> = Box::new(Conn(Arc::default()));
        for (sasl, want) in [(None, &b"10.0.0.1"[..]), (Some(with), b"zk1.example")] {
            let host = Arc::new(TestHost::new());
            host.set_addrs(b"zk1.example", vec![peer]);
            let leaves: Arc<dyn HostLeaves<TestTokens>> = host;
            let shared = TaskShared::tokio_new(
                native_connection(),
                Env::new(leaves),
                Arc::new(Keep::default()),
                sasl,
            );
            let hosts = zk_proto::legacy::connect::parse_servers(b"zk1.example:2181")
                .unwrap()
                .into_iter()
                .map(zk_proto::HostSpec::Legacy)
                .collect();
            let done = shared.tokio_run_job(Job::Resolve {
                generation: 1,
                hosts,
                shuffle: false,
            });
            assert!(matches!(done, JobDone::Resolved { generation: 1, .. }));
            assert_eq!(shared.hosts.lock_owner().host_of(peer), want);
        }
    }

    #[test]
    fn sasl_with_no_mechanism_is_a_mechanism_error() {
        let rt = rt();
        let h = handle();
        let mut ob = Outbox::new();
        ob.push(Item::Sasl(SaslItem {
            call: SaslCall {
                generation: 2,
                kind: SaslCallKind::Step(None),
            },
            addrs: None,
        }));
        rt.block_on(tokio_route(&h.shared, &mut ob));
        let mut proof = Unlocked::new_at_entry();
        let answer = h.shared.core.lock(&mut proof).sasl.take();
        assert!(matches!(
            answer,
            Some(SaslAnswer::Stepped {
                generation: 2,
                result: Err(SaslError {
                    rc: ZSYSTEMERROR,
                    ..
                })
            })
        ));
    }

    #[test]
    fn wait_plan_follows_the_interest_outputs() {
        let h = handle();
        let out = InterestOut {
            rc: ZOK,
            written: true,
            fd: 9,
            bits: crate::net::poll::ZOOKEEPER_READ,
            timeout_ms: 250,
        };
        let plan = h.shared.tokio_wait_plan(&out);
        let read = PollEvents {
            read: true,
            write: false,
        };
        assert_eq!(plan.fd, Some((9, read)));
        assert_eq!(plan.timeout, Some(Duration::from_millis(250)));
        let none = InterestOut { bits: 0, ..out };
        assert_eq!(h.shared.tokio_wait_plan(&none).fd, None);
        // No outputs: recv_timeout/60, at least 1 ms.
        let plan = h.shared.tokio_wait_plan(&InterestOut::UNWRITTEN);
        assert!(plan.fd.is_none());
        assert!(plan.timeout.is_some_and(|t| t >= Duration::from_millis(1)));
        // No connection: the notify only.
        let mut ob = Outbox::new();
        h.shared.tokio_release(&mut ob);
        let plan = h.shared.tokio_wait_plan(&InterestOut::UNWRITTEN);
        assert_eq!(plan.timeout, None);
    }

    #[test]
    fn wait_reports_socket_readiness() {
        let rt = rt();
        let h = handle();
        let (a, mut b) = connected_pair();
        a.set_nonblocking(true).unwrap();
        let read = PollEvents {
            read: true,
            write: false,
        };
        let plan = WaitPlan {
            fd: Some((a.as_raw_fd(), read)),
            timeout: Some(Duration::from_millis(20)),
        };
        // Nothing to read: the timer ends the wait.
        assert_eq!(rt.block_on(tokio_wait(&h.shared, plan)), PollEvents::NONE);
        b.write_all(b"x").unwrap();
        let plan = WaitPlan {
            timeout: Some(Duration::from_secs(5)),
            ..plan
        };
        assert!(rt.block_on(tokio_wait(&h.shared, plan)).read);
        // A connected socket is writable.
        let write = PollEvents {
            read: false,
            write: true,
        };
        let plan = WaitPlan {
            fd: Some((a.as_raw_fd(), write)),
            timeout: Some(Duration::from_secs(5)),
        };
        assert!(rt.block_on(tokio_wait(&h.shared, plan)).write);
    }

    #[test]
    fn wait_ends_on_notify_and_on_a_zero_timeout() {
        let rt = rt();
        let h = handle();
        h.shared.notify.notify_one();
        let plan = WaitPlan {
            fd: None,
            timeout: None,
        };
        assert_eq!(rt.block_on(tokio_wait(&h.shared, plan)), PollEvents::NONE);
        let plan = WaitPlan {
            fd: None,
            timeout: Some(Duration::ZERO),
        };
        assert_eq!(rt.block_on(tokio_wait(&h.shared, plan)), PollEvents::NONE);
    }

    #[test]
    fn job_failures_match_the_job() {
        let done = JobKind::Resolve {
            generation: 3,
            hosts: 2,
        }
        .failed();
        match done {
            JobDone::Resolved {
                generation: 3,
                results,
            } => {
                assert_eq!(results.len(), 2);
                assert!(results.iter().all(|r| r.result.is_err()));
                assert_eq!(results[1].host, 1);
            }
            _ => panic!("not a resolve result"),
        }
        assert!(matches!(
            JobKind::NewConn.failed(),
            JobDone::NewConn(Err(TlsSetupError::Resource {
                at: TlsResourceAt::ConnectionNew
            }))
        ));
    }

    #[test]
    fn readiness_maps_to_legacy_events() {
        let read = PollEvents {
            read: true,
            write: false,
        };
        let write = PollEvents {
            read: false,
            write: true,
        };
        assert_eq!(tokio_events(Ready::READABLE), read);
        assert_eq!(tokio_events(Ready::READ_CLOSED), read);
        assert_eq!(tokio_events(Ready::WRITE_CLOSED), write);
        assert_eq!(tokio_events(Ready::ERROR), tokio_error_events());
        assert_eq!(tokio_merge(read, write), tokio_error_events());
        assert_eq!(tokio_interest_of(PollEvents::NONE), Interest::READABLE);
    }

    #[test]
    fn task_future_is_send() {
        fn is_send<F: Send>(_: &F) {}
        let h = handle();
        let fut = run(Arc::clone(&h.shared));
        is_send(&fut);
        drop(fut);
    }
}
