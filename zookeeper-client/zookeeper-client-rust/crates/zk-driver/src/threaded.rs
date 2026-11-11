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

//! The threaded drop-in driver of `libzookeeper_mt`.
//!
//! C owns the two library threads. Each thread calls one entry of
//! [`Shared`] in a loop and drains the outbox between calls:
//!
//! - the IO thread: [`Shared::io_step`] until `Step::Exit`, then
//!   [`Shared::thread_exit`];
//! - the dispatch thread: [`Shared::wait_dispatch`] until `Step::Exit`,
//!   then [`Shared::thread_exit`]. After a close from a completion
//!   callback, that exit runs the close tail;
//! - any thread: [`Shared::close`] with the role of the caller;
//! - after `Step::More`: [`Shared::resume`]. The outbox names the step
//!   that it continues ([`ResumeAt`]).
//!
//! Lock order: `auth_lock` (C), then `io`, then `core`, then the `fifo`
//! leaf lock. No lock is held when a step returns to C.
//!
//! The native threaded driver is in `crate::native`. It uses `IoCore`
//! directly, not this type. A merge of the two drivers is an open
//! question.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use rustix::event::{PollFd, PollFlags};
use zk_jute::JString;
use zk_jute::rc::{ZINVALIDSTATE, ZMARSHALLINGERROR, ZOK};
use zk_proto::legacy::connect::{HostParseError, HostParseErrorKind, parse_servers};
use zk_proto::{
    Action, AddAuthError, ClientId, Connection, HostSpec, LogArg, LogRecord, LogSite, Millis,
    MultiOpRef, Request, SecretBytes, Stage, Stopped, SubmitError, Submitted,
};

use crate::host::{DriverTokens, HostLeaves, discard_leftovers, log_record};
use crate::iocore::{DeferPolicy, InterestOut, IoCore, Progress};
use crate::lifecycle::Lifecycle;
use crate::net::poll::{PollEvents, clamp_timeout_ms, map_revents, request_flags};
use crate::net::sock::errno_value;
use crate::net::waker::{WakeRx, Waker};
use crate::outbox::{
    FifoBound, Flavor, Item, Outbox, Publish, Pumped, Requeued, ResumeAt, SaslItem, Step, ThreadOp,
    ThreadRole, discard_item, pump,
};
use crate::resolve::{SetServersEnd, SetServersRun, adopt_set_servers};
use crate::state::{
    Core, Env, SaslAnswer, SubmitResult, read_at_entry, read_conn, with_conn_at_entry,
};
use crate::sync::{Condvar, Mutex, Unlocked};

/// The role of the calling thread. C keeps it in thread-local storage
/// and passes it in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The thread in `zookeeper_init` during start.
    Init,
    /// The IO thread.
    Io,
    /// The dispatch (completion) thread.
    Dispatch,
    /// Any application thread.
    Foreign,
}

/// The dispatch FIFO. It is unbounded, as in C.
pub(crate) struct Fifo<T: DriverTokens> {
    /// The published items, oldest first.
    pub(crate) items: VecDeque<Item<T>>,
    /// True after the IO thread left its loop or detached in a close.
    pub(crate) io_exited: bool,
    /// True after the drain of a close reached the close mark. Every
    /// result of that close is then in `items` or already taken.
    pub(crate) close_published: bool,
    /// True while the dispatch thread delivers a batch that it took.
    pub(crate) busy: bool,
    /// True while a foreign close waits for the dispatch thread to
    /// become idle. Only then does the dispatch thread signal `idle`.
    pub(crate) settling: bool,
    /// True when a completion callback continues a requeued foreign
    /// close. That close then does not wait for the dispatch thread.
    pub(crate) closer_is_dispatch: bool,
    /// True after a callback ended the dispatch thread, for example with
    /// `pthread_exit`. No later callback runs. The thread did not give
    /// back its ref, so the close that joins it gives it back.
    pub(crate) dispatch_ended: bool,
}

/// The FIFO and its condition variable. Outboxes publish into it.
pub(crate) struct DispatchQueue<T: DriverTokens> {
    /// The FIFO. A leaf lock: no other lock is taken under it.
    pub(crate) fifo: Mutex<Fifo<T>>,
    /// Signals a new item, `io_exited`, `close_published` or a close.
    pub(crate) cv: Condvar,
    /// Signals a foreign close that the dispatch thread finished a batch.
    pub(crate) idle: Condvar,
}

impl<T: DriverTokens> Publish<T> for DispatchQueue<T> {
    fn publish(&self, item: Item<T>) {
        self.fifo.lock_owner().items.push_back(item);
        self.cv.notify_one();
    }

    fn close_published(&self) {
        self.fifo.lock_owner().close_published = true;
        self.cv.notify_all();
    }
}

impl<T: DriverTokens> DispatchQueue<T> {
    /// Wakes every waiter after a flag changed outside the FIFO lock.
    /// The lock makes sure that no waiter is between its check and its
    /// wait, so no wake is lost.
    fn wake_all(&self) {
        drop(self.fifo.lock_owner());
        self.cv.notify_all();
    }

    /// Waits until the FIFO is empty and the dispatch thread delivers no
    /// batch. A foreign close calls it after the IO join, so no new
    /// result can come. The dispatch thread then has run every callback
    /// of the results so far, as the completion thread of C has before
    /// its join returns.
    ///
    /// When a callback ends the dispatch thread, no callback runs any
    /// more. The wait then returns, and the close discards the results.
    fn wait_idle(&self) {
        let mut fifo = self.fifo.lock_owner();
        if fifo.closer_is_dispatch {
            return;
        }
        fifo.settling = true;
        while !fifo.dispatch_ended && (fifo.busy || !fifo.items.is_empty()) {
            fifo = self.idle.wait(fifo);
        }
        fifo.settling = false;
    }
}

/// The IO-owner state behind the `io` lock.
pub(crate) struct IoSide {
    /// The transport and the step continuation.
    pub(crate) io: IoCore,
    /// The read end of the waker.
    pub(crate) wake_rx: WakeRx,
    /// The progress of the final close, between its barriers.
    pub(crate) final_stage: FinalStage,
    /// The part of the IO iteration that the next resume continues.
    phase: IoPhase,
    /// The interest outputs of the current IO iteration.
    out: InterestOut,
    /// True when the state became unrecoverable. The next IO step exits.
    exit_next: bool,
    /// The rc of the close flush. The final `Release` gives it.
    final_rc: i32,
    /// The stopped stage of the `destroy` pump, for the next resume.
    final_stopped: Option<Stopped>,
}

/// The parts of one IO iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoPhase {
    /// No iteration runs.
    Idle,
    /// `interest_step` runs or stopped at a barrier.
    Interest,
    /// The interest is complete. The poll comes next.
    Poll,
    /// `process_step` stopped at a barrier.
    Process,
}

/// The stages of the close tail and the final close.
///
/// The close tail moves the stage from `NotStarted` to `Release`. It runs
/// on the closing thread, or at the exit of the dispatch thread. Only the
/// release belongs to the last reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalStage {
    /// The final close has not started.
    NotStarted,
    /// The "Closing" line is out. The flush and wait come next.
    Flush,
    /// The flush is complete or skipped. The "Freeing" line and
    /// `destroy` come next.
    Free,
    /// `destroy` ran. Its pump continues after each barrier.
    Destroy,
    /// `destroy` ran and its items are out. The transport drop, the SASL
    /// `Dispose` and `Release` come next.
    Release,
    /// `Release` was given. Nothing is left to do.
    Released,
}

/// The progress of a close before the final close.
///
/// The close keeps its own stopped stage, because the IO step can hold
/// a different stage in `Core::stopped` at the same time.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CloseStage {
    /// No close runs.
    Idle,
    /// `begin_close` ran. Its pump continues after each barrier.
    Pump {
        /// The role of the closing thread.
        role: Role,
        /// The stopped stage of the last barrier.
        stopped: Option<Stopped>,
    },
    /// The `begin_close` items are out. The join and detach items come
    /// next, one per barrier.
    Threads {
        /// The role of the closing thread.
        role: Role,
        /// The thread of the next item.
        next: ThreadRole,
    },
    /// The IO thread is gone. A foreign close waits until the dispatch
    /// thread has delivered every queued result. The close tail comes
    /// next, so its log lines and its CLOSE_OP follow those callbacks.
    Settle {
        /// The role of the closing thread.
        role: Role,
    },
    /// The IO thread is gone. The close tail runs on this thread. In a
    /// foreign close the dispatch thread delivers its results. At the
    /// exit of the dispatch thread, that thread delivers them itself.
    Tail {
        /// The role of the closing thread.
        role: Role,
    },
    /// The thread items are out. The epilog comes next.
    Epilog {
        /// True when the dispatch thread runs the close tail at its exit.
        tail_at_exit: bool,
    },
    /// A close from a completion callback is complete. The dispatch
    /// thread runs the close tail when it leaves its loop.
    AtDispatchExit,
}

/// The largest number of actions that the final close takes after
/// `destroy`. Proto gives at most a `CloseTransport` and a `Dispose`.
const MAX_FINAL_ACTIONS: usize = 16;

/// One `libzookeeper_mt` handle.
pub struct Shared<T: DriverTokens> {
    pub(crate) core: Mutex<Core<T>>,
    pub(crate) io: Mutex<IoSide>,
    pub(crate) queue: Arc<DispatchQueue<T>>,
    pub(crate) waker: Waker,
    pub(crate) life: Lifecycle,
    pub(crate) close_stage: Mutex<CloseStage>,
    pub(crate) env: Env<T>,
}

impl<T: DriverTokens> Shared<T> {
    /// Makes the handle after `Init` gave `Ready`.
    ///
    /// The waker pipe never gets CLOEXEC, as mt_adaptor.c:244 makes it with
    /// a plain `pipe`. The `sock_cloexec` flag applies to sockets only.
    ///
    /// # Errors
    ///
    /// When the pipe fails it pushes the `LogSite::PipeFailed` record
    /// into `ob` and returns the errno. C drains, abandons the
    /// connection and returns NULL.
    pub(crate) fn new(core: Core<T>, env: Env<T>, ob: &mut Outbox<T>) -> Result<Arc<Self>, i32> {
        let (waker, wake_rx) = match Waker::new(false) {
            Ok(pair) => pair,
            Err(e) => {
                let errno = errno_value(e);
                let args = vec![LogArg::I64(i64::from(errno))];
                push_log(&*env.host, ob, LogSite::PipeFailed, args);
                return Err(errno);
            }
        };
        let side = IoSide {
            io: IoCore::new(),
            wake_rx,
            final_stage: FinalStage::NotStarted,
            phase: IoPhase::Idle,
            out: InterestOut::UNWRITTEN,
            exit_next: false,
            final_rc: ZOK,
            final_stopped: None,
        };
        let queue = DispatchQueue {
            fifo: Mutex::new(Fifo {
                items: VecDeque::new(),
                io_exited: false,
                close_published: false,
                busy: false,
                settling: false,
                closer_is_dispatch: false,
                dispatch_ended: false,
            }),
            cv: Condvar::new(),
            idle: Condvar::new(),
        };
        Ok(Arc::new(Self {
            core: Mutex::new(core),
            io: Mutex::new(side),
            queue: Arc::new(queue),
            waker,
            life: Lifecycle::new(),
            close_stage: Mutex::new(CloseStage::Idle),
            env,
        }))
    }

    /// Makes the handle from a ready init. See `Shared::new`.
    ///
    /// # Errors
    ///
    /// Returns the errno of the pipe failure.
    pub fn from_init(init: crate::init::Init<T>, ob: &mut Outbox<T>) -> Result<Arc<Self>, i32> {
        let (core, env) = init.into_parts();
        Self::new(core, env, ob)
    }

    /// Makes an outbox that publishes into the dispatch FIFO. zk-ffi
    /// makes one per driving call.
    #[must_use]
    pub fn outbox(&self) -> Outbox<T> {
        let queue: Arc<dyn Publish<T>> = self.queue.clone();
        Outbox::with_publish(queue)
    }

    /// `zkrs_thread_enter`: takes a ref for a library thread or the init
    /// thread.
    pub fn thread_enter(&self, _role: Role) {
        self.life.prolog();
    }

    /// `zkrs_thread_exit`.
    ///
    /// IO: set `io_exited` unless a close from this thread did, notify
    /// the dispatch thread. Dispatch: after a close from a completion
    /// callback, run the close tail and deliver its results on this
    /// thread. Then the epilog, which can run the final close in this
    /// call (`More`, then `Release`).
    pub fn thread_exit(&self, role: Role, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        if role == Role::Io {
            self.queue.fifo.lock_owner().io_exited = true;
            self.queue.cv.notify_all();
        }
        if role == Role::Dispatch {
            let mut stage = self.close_stage.lock_owner();
            if *stage == CloseStage::AtDispatchExit {
                *stage = CloseStage::Tail {
                    role: Role::Dispatch,
                };
                drop(stage);
                return self.run_close(ob, rc);
            }
        }
        self.leave(ob, rc)
    }

    /// `zkrs_dispatch_ended`: a callback ended the dispatch thread, for
    /// example with `pthread_exit`. The cleanup handler of that thread
    /// calls it.
    ///
    /// The items in `ob` that C did not take go to `discard_token`, so
    /// they get no callback. Then the function marks the thread as
    /// ended and wakes a foreign close that waits for the queued
    /// callbacks. The C client never frees the results that are left,
    /// because it leaks the handle. The drop-in discards them at the
    /// release, with no callback. The thread gives back no ref here,
    /// because the last ref runs the final close. The close that joins
    /// the thread gives back its ref after the join.
    pub fn dispatch_ended(&self, ob: &mut Outbox<T>) {
        ob.finish(&*self.env.host);
        let mut fifo = self.queue.fifo.lock_owner();
        fifo.dispatch_ended = true;
        fifo.busy = false;
        drop(fifo);
        self.queue.idle.notify_all();
    }

    /// One IO iteration, `zkrs_io_step`.
    ///
    /// 1. `Exit` after a close request.
    /// 2. `interest_step` under `io`.
    /// 3. `More` when the outbox has items, so each line reaches the log
    ///    before the wait.
    /// 4. The poll set from the interest. With no outputs, wait on the
    ///    waker for `recv_timeout/60` ms (at least 1). Timeout 0
    ///    while `buffered_ready`. Round the timeout up to whole ms.
    /// 5. `Poll::poll([waker, socket?])`. EINTR is no event. Map the
    ///    revents with `net::poll::map_revents`.
    /// 6. Waker IN: `WakeRx::reset`. Then `process_step`.
    /// 7. When the state is unrecoverable, the next call gives `Exit`.
    pub fn io_step(&self, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let mut guard = self.io.lock_owner();
        if self.life.close_requested() || guard.exit_next {
            return Step::Exit;
        }
        guard.phase = IoPhase::Interest;
        guard.out = InterestOut::UNWRITTEN;
        self.run_io(&mut guard, false, ob, rc)
    }

    /// `zkrs_resume`: continues the step that `ob` names.
    pub fn resume(&self, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        match ob.take_resume() {
            Some(ResumeAt::IoStep) => {
                let mut guard = self.io.lock_owner();
                self.run_io(&mut guard, true, ob, rc)
            }
            Some(ResumeAt::Close) => self.run_close(ob, rc),
            Some(ResumeAt::FinalClose) => self.run_final(ob, rc),
            Some(ResumeAt::SetServers(id)) => {
                let cx = self.env.resolve_ctx(&self.core, Self::FLAVOR);
                let mut proof = Unlocked::new_at_entry();
                let end = SetServersRun::resume(&cx, &mut proof, ob, id);
                self.set_servers_end(end, ob, rc)
            }
            // The other tags belong to other flavors. Nothing waits.
            _ => {
                *rc = ZOK;
                Step::Done(ZOK)
            }
        }
    }

    /// `zkrs_wait_dispatch`.
    ///
    /// Wait until the FIFO has items, or until `close_published` and
    /// `io_exited` are both set. An empty FIFO then gives `Exit`. Else
    /// move the whole batch into `ob`, in order, and give `Done(ZOK)`.
    ///
    /// The thread does not exit on the close request alone. The IO thread
    /// can leave its loop before the close publishes its ZCLOSING
    /// results. The close mark makes sure that the thread delivers them.
    /// C can discard them here, so this is a deliberate difference.
    ///
    /// Each call also tells a waiting foreign close that C delivered the
    /// last batch.
    pub fn wait_dispatch(&self, ob: &mut Outbox<T>) -> Step {
        let mut fifo = self.queue.fifo.lock_owner();
        // C delivered the last batch before this call.
        fifo.busy = false;
        if fifo.settling {
            self.queue.idle.notify_all();
        }
        while fifo.items.is_empty() && !(fifo.close_published && fifo.io_exited) {
            fifo = self.queue.cv.wait(fifo);
        }
        if fifo.items.is_empty() {
            return Step::Exit;
        }
        let batch = std::mem::take(&mut fifo.items);
        fifo.busy = true;
        drop(fifo);
        ob.extend_items(batch);
        Step::Done(ZOK)
    }

    /// `zkrs_close` by role.
    ///
    /// - A forked child: `forked_close` only, `Done(ZOK)`.
    /// - `prolog`, then `request_close`. A second close: epilog,
    ///   `Done(ZOK)`.
    /// - refs > 1: `begin_close` and the pump, then the steps of the
    ///   role, each thread item a barrier, then the epilog.
    ///   - Foreign: join IO, the wait for the queued callbacks, the
    ///     close tail, the close mark, join dispatch.
    ///   - Dispatch: the close mark, join IO, detach dispatch. The
    ///     dispatch thread runs the close tail when it exits.
    ///   - IO: the close mark, detach IO, join dispatch. The final close
    ///     runs the close tail.
    /// - Else: the final close in this call.
    ///
    /// The close tail: `queue_close_op`, the "Closing" line, `More`,
    /// `IoCore::close_flush`, the "Freeing" line, `destroy` and its pump.
    /// The tail runs only when no IO step runs. In a foreign close the
    /// dispatch thread is still alive, so it delivers every result of
    /// the tail. The dispatch thread delivers the results of its own tail
    /// itself.
    ///
    /// The final close: the close tail if no close ran it, then drop the
    /// transport, the SASL `Dispose`, and `Release` with the close rc.
    /// The tokens that are left go to `discard_token`. A tail with no
    /// completion thread leaves its results there (IO role, no threads).
    ///
    /// With no socket, the tail skips `close_flush` and the rc is `ZOK`
    /// (zookeeper.c `zookeeper_close`).
    pub fn close(&self, role: Role, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        if self.life.is_forked_child() {
            self.forked_close();
            *rc = ZOK;
            return Step::Done(ZOK);
        }
        // The count comes from the close prolog, before the request is
        // public. An API call that leaves later cannot make a nested close
        // look final (zookeeper.c `zookeeper_close`).
        let refs = self.life.prolog();
        if !self.life.request_close() {
            if let Some(step) = self.adopt_close(role, ob, rc) {
                return step;
            }
            return self.leave(ob, rc);
        }
        if refs <= 1 {
            return self.final_close(ob, rc);
        }
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        if let Some(conn) = self.core.lock(&mut proof).conn.as_deref_mut() {
            conn.begin_close(now);
        }
        *self.close_stage.lock_owner() = CloseStage::Pump {
            role,
            stopped: None,
        };
        self.run_close(ob, rc)
    }

    /// Submits one request and wakes the IO thread.
    ///
    /// After a close request the core gives ZMARSHALLINGERROR, as C does.
    /// mt runs no flush on the app thread.
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

    /// Submits one request through `send` under the core lock, and wakes
    /// the IO thread when proto accepts it.
    fn submit_by(
        &self,
        req: Request<T>,
        send: impl FnOnce(&mut Connection<T>, Request<T>, Millis) -> SubmitResult<T>,
    ) -> SubmitResult<T> {
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let result = {
            let mut core = self.core.lock(&mut proof);
            match core.conn.as_deref_mut() {
                // Proto accepts work until `begin_close` runs. C refuses
                // work from the close request on, so the driver does too.
                Some(conn) if !self.life.close_requested() || conn.is_closing() => {
                    send(conn, req, now)
                }
                _ => Err(SubmitError {
                    stage: Stage::Enqueue,
                    code: ZMARSHALLINGERROR,
                    token: req.token,
                }),
            }
        };
        if result.is_ok() {
            self.waker.wake();
        }
        result
    }

    /// `zoo_add_auth`: records the entry and wakes the IO thread.
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
        let now = self.env.clock.now();
        let result = self.core.lock(&mut Unlocked::new_at_entry()).add_auth_or(
            scheme,
            cred,
            done,
            now,
            ZINVALIDSTATE,
        );
        if result.is_ok() {
            self.waker.wake();
        }
        result
    }

    /// `zoo_set_servers`: parses the list, gives it to proto, resolves it
    /// and wakes the IO thread. A rebalance is a forced close. The
    /// IO thread runs its teardown.
    ///
    /// The per-host loop runs on the calling thread. It
    /// gives `More` before each blocking leaf when LOG items wait, and at
    /// each barrier. The resume entry continues it. `Done` has the C rc.
    pub fn set_servers(&self, hosts: &[u8], ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let host = &*self.env.host;
        let specs = match parse_servers(hosts) {
            Ok(specs) => specs.into_iter().map(HostSpec::Legacy).collect::<Vec<_>>(),
            Err(e) => {
                // An unparsable list is not committed.
                if let Some(rec) = parse_error_record(host, &e) {
                    ob.push(Item::Log(rec));
                }
                *rc = e.rc;
                return Step::Done(e.rc);
            }
        };
        let cx = self.env.resolve_ctx(&self.core, Self::FLAVOR);
        let mut proof = Unlocked::new_at_entry();
        let end = SetServersRun::start(&cx, &mut proof, ob, specs);
        self.set_servers_end(end, ob, rc)
    }

    /// Ends one segment of `zoo_set_servers`. A complete call wakes the
    /// IO thread, which resolves nothing more and connects to the list.
    fn set_servers_end(&self, end: SetServersEnd, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        match end {
            SetServersEnd::More(id) => {
                ob.set_resume(ResumeAt::SetServers(id));
                Step::More
            }
            SetServersEnd::Done { rc: code, .. } => {
                if code != ZINVALIDSTATE {
                    self.waker.wake();
                }
                *rc = code;
                Step::Done(code)
            }
        }
    }

    /// `zkrs_sasl_result`: stores the answer of C. The next resume gives
    /// it to proto.
    pub fn sasl_result(&self, answer: SaslAnswer) {
        let mut proof = Unlocked::new_at_entry();
        self.core.lock(&mut proof).sasl = Some(answer);
    }

    /// `zkrs_outbox_requeue`: stores the untaken items. The next driving
    /// call delivers them first.
    ///
    /// The requeued outbox can name a stopped stage that no thread
    /// resumes now. A close stage waits for the next close call of the
    /// application. A `zoo_set_servers` run goes to the IO thread.
    pub fn requeue(&self, rest: Requeued<T>) {
        let mut proof = Unlocked::new_at_entry();
        let mut core = self.core.lock(&mut proof);
        let mut wake = false;
        match rest.resume_at() {
            Some(at @ (ResumeAt::Close | ResumeAt::FinalClose)) => core.orphan_close = Some(at),
            Some(ResumeAt::SetServers(id)) => {
                adopt_set_servers(&mut core, id);
                wake = true;
            }
            _ => {}
        }
        if wake {
            self.waker.wake();
        }
        let merged = match core.requeued.take() {
            None => rest,
            Some(old) => {
                // The older items stay in front of the newer items.
                let mut ob = Outbox::new();
                ob.restore(rest);
                ob.restore(old);
                ob.requeue()
            }
        };
        core.requeued = Some(merged);
    }

    /// `zkrs_peer_addr`: the peer of the current transport.
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        // The IO thread holds `io` while it polls. The cache in the core
        // gives the answer with no wait.
        let mut proof = Unlocked::new_at_entry();
        self.core.lock(&mut proof).peer
    }

    /// The mt-exported `zookeeper_interest`: it
    /// reports "no socket" and never drives the state machine.
    #[must_use]
    pub fn interest_exported(&self) -> InterestOut {
        let mut proof = Unlocked::new_at_entry();
        let facts = read_conn(&self.core, &mut proof, |c| {
            (c.state().code(), c.recv_timeout())
        });
        match facts {
            Some((state, recv_timeout)) if state >= 0 => InterestOut {
                rc: ZOK,
                written: true,
                fd: -1,
                bits: 0,
                timeout_ms: i64::from(recv_timeout.checked_div(3).unwrap_or(0)),
            },
            _ => InterestOut {
                rc: ZINVALIDSTATE,
                ..InterestOut::UNWRITTEN
            },
        }
    }

    /// The mt-exported `zookeeper_process`: ZINVALIDSTATE.
    #[must_use]
    pub fn process_exported(&self) -> i32 {
        ZINVALIDSTATE
    }

    /// `zoo_state`. 0 after the final close.
    #[must_use]
    pub fn state(&self) -> i32 {
        read_at_entry(&self.core, |c| c.state().code()).unwrap_or(0)
    }

    /// `zoo_recv_timeout`.
    #[must_use]
    pub fn recv_timeout(&self) -> i32 {
        read_at_entry(&self.core, Connection::recv_timeout).unwrap_or(0)
    }

    /// `zoo_client_id`.
    #[must_use]
    pub fn client_id(&self) -> ClientId {
        read_at_entry(&self.core, Connection::client_id).unwrap_or_default()
    }

    /// Runs `f` on the connection under the core lock. It returns `None`
    /// after the final close.
    ///
    /// zk-ffi reads values that the handle has no accessor for, for
    /// example `current_server`. `f` must not block, and it must
    /// not call into the handle.
    pub fn read_conn<R>(&self, f: impl FnOnce(&Connection<T>) -> R) -> Option<R> {
        read_at_entry(&self.core, f)
    }

    /// Runs `f` on the connection under the core lock, then wakes the IO
    /// thread. It returns `None` after the final close.
    ///
    /// zk-ffi uses it for `zoo_set_servers_resolution_delay` and
    /// `zoo_cycle_next_server`. The wake lets the IO thread route
    /// the outputs that `f` makes. `f` must not block, and it must not
    /// call into the handle.
    pub fn with_conn<R>(
        &self,
        f: impl FnOnce(&mut Connection<T>, zk_proto::Millis) -> R,
    ) -> Option<R> {
        let r = with_conn_at_entry(&self.core, self.env.clock.now(), f);
        self.waker.wake();
        r
    }

    /// The defer policy of the drop-in: every blocking call inline.
    pub(crate) const DEFER: DeferPolicy = DeferPolicy::NONE;

    /// The pump flavor.
    pub(crate) const FLAVOR: Flavor = Flavor::Mt;

    /// The resume tag of the IO step.
    pub(crate) const IO_RESUME: ResumeAt = ResumeAt::IoStep;
}

/// The IO iteration.
impl<T: DriverTokens> Shared<T> {
    /// Runs the IO iteration from its phase until it completes or stops
    /// at a barrier. `resumed` is true when C drained after a `More` of
    /// this iteration.
    fn run_io(&self, side: &mut IoSide, resumed: bool, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let IoSide {
            io,
            wake_rx,
            phase,
            out,
            exit_next,
            ..
        } = side;
        let cx = self.env.step_ctx(
            &self.core,
            Self::FLAVOR,
            Self::DEFER,
            Some((&self.waker, &*wake_rx)),
            Some(self.life.close_flag()),
            None,
        );
        let mut proof = Unlocked::new_at_entry();
        let mut resumed = resumed;
        loop {
            match *phase {
                IoPhase::Idle => {
                    *rc = ZOK;
                    return Step::Done(ZOK);
                }
                IoPhase::Interest => {
                    let progress = if resumed {
                        io.resume(&cx, &mut proof, ob, out)
                    } else {
                        io.interest_step(&cx, &mut proof, ob, out)
                    };
                    resumed = false;
                    if progress == Progress::More {
                        ob.set_resume(Self::IO_RESUME);
                        return Step::More;
                    }
                    *phase = IoPhase::Poll;
                    // The waiting lines go out before the poll blocks.
                    if !ob.is_empty() {
                        ob.set_resume(Self::IO_RESUME);
                        return Step::More;
                    }
                }
                IoPhase::Poll => {
                    let events = self.poll_once(io, wake_rx, out, &mut proof);
                    *phase = IoPhase::Process;
                    let progress = io.process_step(&cx, &mut proof, events, ob);
                    if progress == Progress::More {
                        ob.set_resume(Self::IO_RESUME);
                        return Step::More;
                    }
                    return self.end_io(phase, exit_next, progress, &mut proof, rc);
                }
                IoPhase::Process => {
                    let mut unused = InterestOut::UNWRITTEN;
                    let progress = io.resume(&cx, &mut proof, ob, &mut unused);
                    if progress == Progress::More {
                        ob.set_resume(Self::IO_RESUME);
                        return Step::More;
                    }
                    return self.end_io(phase, exit_next, progress, &mut proof, rc);
                }
            }
        }
    }

    /// Waits for the waker and the socket. It
    /// returns the socket events. A poll error gives no event.
    fn poll_once(
        &self,
        io: &IoCore,
        wake_rx: &WakeRx,
        out: &InterestOut,
        proof: &mut Unlocked,
    ) -> PollEvents {
        let (recv_timeout, suspended) =
            read_conn(&self.core, proof, |c| (c.recv_timeout(), c.is_suspended()))
                .unwrap_or((0, false));
        let timeout_ms = if io.buffered_ready(suspended, true) {
            0
        } else if out.written {
            out.timeout_ms
        } else {
            // C polls with stale values here. A short wait on the waker
            // replaces them.
            i64::from(recv_timeout.checked_div(60).unwrap_or(0).max(1))
        };
        let sock = if out.written && out.fd >= 0 {
            io.conn.sock()
        } else {
            None
        };
        // The poll set is a stack array, as in the native driver, so a
        // wait makes no allocation.
        let timeout = clamp_timeout_ms(timeout_ms);
        let polled = match sock {
            Some(sock) => {
                let want = request_flags(PollEvents::from_bits(out.bits));
                let mut fds = [PollFd::new(wake_rx, PollFlags::IN), PollFd::new(sock, want)];
                let ok = self.env.poll.poll(&mut fds, timeout).is_ok();
                let [w, s] = &fds;
                ok.then(|| {
                    (
                        w.revents().contains(PollFlags::IN),
                        map_revents(s.revents()),
                    )
                })
            }
            None => {
                let mut fds = [PollFd::new(wake_rx, PollFlags::IN)];
                let ok = self.env.poll.poll(&mut fds, timeout).is_ok();
                let [w] = &fds;
                ok.then(|| (w.revents().contains(PollFlags::IN), PollEvents::NONE))
            }
        };
        // EINTR and the other errors give no event. The next iteration
        // polls again.
        let Some((woken, events)) = polled else {
            return PollEvents::NONE;
        };
        if woken {
            wake_rx.reset(&self.waker);
        }
        events
    }

    /// Ends the IO iteration. An unrecoverable state makes the next IO
    /// step exit, as `do_io` leaves its loop (mt_adaptor.c:465-468).
    fn end_io(
        &self,
        phase: &mut IoPhase,
        exit_next: &mut bool,
        progress: Progress,
        proof: &mut Unlocked,
        rc: &mut i32,
    ) -> Step {
        *phase = IoPhase::Idle;
        let r = match progress {
            Progress::Done(r) => r,
            Progress::More | Progress::Wait => ZOK,
        };
        if read_conn(&self.core, proof, |c| c.state().code() < 0).unwrap_or(true) {
            *exit_next = true;
        }
        *rc = r;
        Step::Done(r)
    }
}

/// The close by role and the final close.
impl<T: DriverTokens> Shared<T> {
    /// Drops the ref of the caller. The call that drops the last ref
    /// after a close request runs the final close.
    fn leave(&self, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        if self.life.epilog() {
            return self.final_close(ob, rc);
        }
        *rc = ZOK;
        Step::Done(ZOK)
    }

    /// Continues a close stage that lost its resume. A callback
    /// threw during the close, so its outbox went to `requeue`.
    ///
    /// The earlier close call still holds its ref, and the stage releases
    /// it. So this call gives back its own ref first. The requeued items
    /// go out before the stage continues. It returns `None` when no
    /// stage waits.
    fn adopt_close(&self, role: Role, ob: &mut Outbox<T>, rc: &mut i32) -> Option<Step> {
        let at = {
            let mut proof = Unlocked::new_at_entry();
            let mut core = self.core.lock(&mut proof);
            let at = core.orphan_close.take()?;
            let _ = core.restore_requeued(ob);
            at
        };
        // The dispatch thread cannot wait for its own batch. When it
        // continues a foreign close, the close skips that wait.
        self.queue.fifo.lock_owner().closer_is_dispatch = role == Role::Dispatch;
        let _ = self.life.epilog();
        Some(match at {
            ResumeAt::FinalClose => self.run_final(ob, rc),
            _ => self.run_close(ob, rc),
        })
    }

    /// The forked-child close. It closes only what it can
    /// reach with no wait, and it sends nothing.
    fn forked_close(&self) {
        if let (Some(_core), Some(mut side)) = (self.core.try_lock(), self.io.try_lock()) {
            side.io.forked_close();
        }
        let _ = self.waker.close_in_child();
    }

    /// Continues a close with refs > 1. It gives one barrier
    /// item for each call, then runs the epilog.
    fn run_close(&self, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let host = &*self.env.host;
        let mut stage = std::mem::replace(&mut *self.close_stage.lock_owner(), CloseStage::Idle);
        loop {
            match stage {
                CloseStage::Idle => {
                    *rc = ZOK;
                    return Step::Done(ZOK);
                }
                CloseStage::Pump { role, stopped } => {
                    let now = self.env.clock.now();
                    let mut proof = Unlocked::new_at_entry();
                    let mut core = self.core.lock(&mut proof);
                    let pumped = match core.conn.as_deref_mut() {
                        Some(conn) => {
                            if let Some(s) = stopped {
                                conn.resume(s, now);
                            }
                            pump(conn, ob, FifoBound::Publish, host)
                        }
                        None => Pumped::Drained,
                    };
                    drop(core);
                    match pumped {
                        Pumped::Barrier(stopped) => {
                            return self.pause_close(CloseStage::Pump { role, stopped }, ob);
                        }
                        Pumped::Drained => {
                            // The mark follows the last publish entry of
                            // this close and comes before the thread
                            // items. A close with no connection has no
                            // results, but it needs the mark too. A
                            // foreign close gives the mark after its
                            // tail, so the dispatch thread stays for the
                            // results of the tail.
                            if role != Role::Foreign {
                                ob.push_close_published();
                            }
                            stage = CloseStage::Threads {
                                role,
                                next: ThreadRole::Io,
                            };
                        }
                    }
                }
                CloseStage::Threads {
                    role,
                    next: ThreadRole::Io,
                } => {
                    let op = if role == Role::Io {
                        self.queue.fifo.lock_owner().io_exited = true;
                        ThreadOp::Detach
                    } else {
                        self.waker.wake();
                        ThreadOp::Join
                    };
                    ob.push(Item::Thread {
                        op,
                        role: ThreadRole::Io,
                    });
                    let next = if role == Role::Foreign {
                        CloseStage::Settle { role }
                    } else {
                        CloseStage::Threads {
                            role,
                            next: ThreadRole::Dispatch,
                        }
                    };
                    return self.pause_close(next, ob);
                }
                CloseStage::Settle { role } => {
                    // Requeued items, such as the IO join, go out first.
                    if !ob.is_empty() {
                        return self.pause_close(CloseStage::Settle { role }, ob);
                    }
                    // The wait holds no lock, so a callback on the
                    // dispatch thread can still call the API.
                    self.queue.wait_idle();
                    stage = CloseStage::Tail { role };
                }
                CloseStage::Tail { role } => {
                    if role == Role::Dispatch {
                        // The dispatch loop is over, so this thread
                        // delivers. The items that are still in the FIFO
                        // are older, so they go out before the tail.
                        let left = std::mem::take(&mut self.queue.fifo.lock_owner().items);
                        ob.extend_items(left);
                        ob.deliver_here();
                    }
                    let paused = {
                        let mut guard = self.io.lock_owner();
                        self.run_tail(&mut guard, ob)
                    };
                    if paused {
                        return self.pause_close(CloseStage::Tail { role }, ob);
                    }
                    if role == Role::Dispatch {
                        stage = CloseStage::Epilog {
                            tail_at_exit: false,
                        };
                    } else {
                        // The mark follows the last publish entry of the
                        // tail. The dispatch thread thus delivers every
                        // result before the join returns.
                        ob.push_close_published();
                        stage = CloseStage::Threads {
                            role,
                            next: ThreadRole::Dispatch,
                        };
                    }
                }
                CloseStage::Threads {
                    role,
                    next: ThreadRole::Dispatch,
                } => {
                    let op = if role == Role::Dispatch {
                        ThreadOp::Detach
                    } else {
                        // The dispatch thread delivers every queued item
                        // before it exits.
                        self.queue.wake_all();
                        ThreadOp::Join
                    };
                    ob.push(Item::Thread {
                        op,
                        role: ThreadRole::Dispatch,
                    });
                    let next = CloseStage::Epilog {
                        tail_at_exit: role == Role::Dispatch,
                    };
                    return self.pause_close(next, ob);
                }
                CloseStage::Epilog { tail_at_exit } => {
                    if tail_at_exit {
                        *self.close_stage.lock_owner() = CloseStage::AtDispatchExit;
                    } else {
                        // When a callback ended the dispatch thread, that
                        // thread kept its ref. The join returned, so this
                        // close gives back that ref first. The close still
                        // holds its own ref, so this epilog is not the
                        // last. leave() then gives back the own ref and
                        // runs the final close.
                        let ended = self.queue.fifo.lock_owner().dispatch_ended;
                        if ended && self.life.epilog() {
                            return self.final_close(ob, rc);
                        }
                    }
                    return self.leave(ob, rc);
                }
                // Only the exit of the dispatch thread continues this
                // stage. Keep it for that exit.
                CloseStage::AtDispatchExit => {
                    *self.close_stage.lock_owner() = CloseStage::AtDispatchExit;
                    *rc = ZOK;
                    return Step::Done(ZOK);
                }
            }
        }
    }

    /// Stores the close stage and gives `More` for the next resume.
    fn pause_close(&self, stage: CloseStage, ob: &mut Outbox<T>) -> Step {
        *self.close_stage.lock_owner() = stage;
        ob.set_resume(ResumeAt::Close);
        Step::More
    }

    /// Starts the final close. The guard makes sure that it
    /// runs exactly once.
    fn final_close(&self, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        if !self.life.begin_final() {
            *rc = ZOK;
            return Step::Done(ZOK);
        }
        self.run_final(ob, rc)
    }

    /// Continues the final close from its stage until it stops at a
    /// barrier or gives `Release`. A close tail that ran earlier leaves
    /// only the release.
    fn run_final(&self, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let mut guard = self.io.lock_owner();
        let side = &mut *guard;
        if self.run_tail(side, ob) {
            return pause_final(ob);
        }
        let mut proof = Unlocked::new_at_entry();
        if side.final_stage == FinalStage::Release {
            side.final_stage = FinalStage::Released;
            self.release(side, ob, &mut proof);
        }
        *rc = side.final_rc;
        Step::Release
    }

    /// Continues the close tail from its stage: the CLOSE_OP and the
    /// "Closing" line, the flush and wait, the "Freeing" line, `destroy`
    /// and its pump. The pump publishes the results into the FIFO.
    ///
    /// It returns true when it stops for C to drain `ob`. The caller
    /// sets the resume tag. It returns false when the tail is complete.
    fn run_tail(&self, side: &mut IoSide, ob: &mut Outbox<T>) -> bool {
        let host = &*self.env.host;
        let mut proof = Unlocked::new_at_entry();
        loop {
            match side.final_stage {
                FinalStage::NotStarted => {
                    let mut core = self.core.lock(&mut proof);
                    // The items that a callback left come first.
                    core.restore_requeued(ob);
                    let closing = core.conn.as_deref_mut().and_then(|conn| {
                        conn.queue_close_op()
                            .then(|| (conn.client_id(), conn.current_server()))
                    });
                    drop(core);
                    side.final_rc = ZOK;
                    side.final_stage = FinalStage::Free;
                    if let Some((id, server)) = closing {
                        let args = vec![session_arg(&id), LogArg::Endpoint(server)];
                        push_log(host, ob, LogSite::Closing, args);
                        if side.io.has_socket() {
                            side.final_stage = FinalStage::Flush;
                        }
                    }
                    // The lines go out before the flush blocks.
                    if !ob.is_empty() {
                        return true;
                    }
                }
                FinalStage::Flush => {
                    // No waker and no abort flag: the close request is
                    // set, and the flush has its own budget.
                    let cx =
                        self.env
                            .step_ctx(&self.core, Self::FLAVOR, Self::DEFER, None, None, None);
                    side.final_rc = side.io.close_flush(&cx, &mut proof, ob);
                    side.final_stage = FinalStage::Free;
                }
                FinalStage::Free => {
                    let now = self.env.clock.now();
                    let mut core = self.core.lock(&mut proof);
                    if let Some(conn) = core.conn.as_deref_mut() {
                        let args = vec![session_arg(&conn.client_id())];
                        push_log(host, ob, LogSite::Freeing, args);
                        conn.destroy(now);
                    }
                    side.final_stopped = None;
                    side.final_stage = FinalStage::Destroy;
                }
                FinalStage::Destroy => {
                    let now = self.env.clock.now();
                    let mut core = self.core.lock(&mut proof);
                    let pumped = match core.conn.as_deref_mut() {
                        Some(conn) => {
                            if let Some(s) = side.final_stopped.take() {
                                conn.resume(s, now);
                            }
                            pump(conn, ob, FifoBound::Publish, host)
                        }
                        None => Pumped::Drained,
                    };
                    drop(core);
                    match pumped {
                        Pumped::Barrier(stopped) => {
                            side.final_stopped = stopped;
                            return true;
                        }
                        Pumped::Drained => {
                            side.final_stage = FinalStage::Release;
                            // C publishes the FIFO-bound items while it
                            // drains, so they are in the FIFO before the
                            // caller continues.
                            if !ob.is_empty() {
                                return true;
                            }
                        }
                    }
                }
                FinalStage::Release | FinalStage::Released => return false,
            }
        }
    }

    /// Ends the final close. It drops the
    /// transport, queues the SASL `Dispose`, and gives every token that
    /// is left to `discard_token`.
    fn release(&self, side: &mut IoSide, ob: &mut Outbox<T>, proof: &mut Unlocked) {
        let host = &*self.env.host;
        let now = self.env.clock.now();
        let mut core = self.core.lock(proof);
        if let Some(conn) = core.conn.as_deref_mut() {
            for _ in 0..MAX_FINAL_ACTIONS {
                match conn.poll_action(now) {
                    Some(Action::CloseTransport) => side.io.drop_transport(),
                    Some(Action::Sasl(call)) => {
                        ob.push(Item::Sasl(SaslItem { call, addrs: None }));
                    }
                    // A destroyed connection has no other work.
                    Some(_) => {}
                    None => break,
                }
            }
        }
        side.io.drop_transport();
        core.peer = None;
        core.sasl = None;
        core.stopped = None;
        let conn = core.conn.take();
        let requeued = core.requeued.take();
        let local = std::mem::take(&mut core.local);
        drop(core);
        if let Some(conn) = conn {
            discard_leftovers(host, conn);
        }
        if let Some(requeued) = requeued {
            let mut rest = Outbox::new();
            rest.restore(requeued);
            rest.finish(host);
        }
        let fifo = std::mem::take(&mut self.queue.fifo.lock_owner().items);
        for item in local.into_iter().chain(fifo) {
            discard_item(host, item);
        }
    }
}

/// Stores the resume tag of the final close and gives `More`.
fn pause_final<T: DriverTokens>(ob: &mut Outbox<T>) -> Step {
    ob.set_resume(ResumeAt::FinalClose);
    Step::More
}

/// Pushes one log line when its level is on.
fn push_log<T: DriverTokens>(
    host: &dyn HostLeaves<T>,
    ob: &mut Outbox<T>,
    site: LogSite,
    args: Vec<LogArg>,
) {
    if let Some(rec) = log_record(host, site, args) {
        ob.push(Item::Log(rec));
    }
}

/// Gives the `%#llx` argument of a session id, as proto does.
fn session_arg(id: &ClientId) -> LogArg {
    LogArg::Ptr(u64::from_ne_bytes(id.session_id.to_ne_bytes()))
}

/// Gives the log line of a port error in a host list, as
/// `resolve_hosts` logs it (zookeeper.c:876, 885).
fn parse_error_record<T: DriverTokens>(
    host: &dyn HostLeaves<T>,
    e: &HostParseError,
) -> Option<LogRecord> {
    let site = match e.kind {
        HostParseErrorKind::NoPort => LogSite::ResolveNoPort,
        HostParseErrorKind::InvalidPort => LogSite::ResolveBadPort,
        _ => return None,
    };
    let args = vec![LogArg::Str(JString::Bytes(e.subject.clone()))];
    log_record(host, site, args)
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
    use std::time::Duration;

    use crate::net::poll::Poll;
    use crate::testutil::{RealPoll, TestHost, exists_request, test_connection};
    use zk_jute::rc::ZBADARGUMENTS;
    use zk_proto::{DriverMode, PathIn, Route, SaslError};
    use zk_testkit::tokens::{AuthId, TestTokens};

    type S = Shared<TestTokens>;

    /// Makes a handle around a new connection with no socket.
    fn handle() -> (Arc<S>, Arc<TestHost>) {
        let host = Arc::new(TestHost::new());
        let leaves: Arc<dyn HostLeaves<TestTokens>> = host.clone();
        let core = Core::new(Box::new(test_connection(DriverMode::MT)));
        let mut ob = Outbox::new();
        let shared = Shared::new(core, Env::new(leaves), &mut ob).unwrap();
        assert!(ob.is_empty());
        (shared, host)
    }

    fn label(item: &Item<TestTokens>) -> String {
        match item {
            Item::Thread { op, role } => format!("{op:?} {role:?}"),
            Item::AuthResult { token, .. } => format!("AuthResult {}", token.id()),
            Item::Result { token, result, .. } => format!("Result {} {}", token.id(), result.rc),
            other => format!("{other:?}"),
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
    ) -> (Step, Vec<String>) {
        let mut seen = Vec::new();
        let mut step = first;
        loop {
            while let Some(item) = ob.pop() {
                on(&item);
                seen.push(label(&item));
            }
            if step != Step::More {
                return (step, seen);
            }
            step = s.resume(ob, rc);
        }
    }

    fn close(s: &S, role: Role, on: impl FnMut(&Item<TestTokens>)) -> (Step, i32, Vec<String>) {
        let mut ob = s.outbox();
        let mut rc = -1;
        let first = s.close(role, &mut ob, &mut rc);
        let (end, seen) = drive(s, first, &mut ob, &mut rc, on);
        (end, rc, seen)
    }

    fn exit(s: &S, role: Role) -> (Step, i32) {
        let mut ob = s.outbox();
        let mut rc = -1;
        let first = s.thread_exit(role, &mut ob, &mut rc);
        let (end, _) = drive(s, first, &mut ob, &mut rc, |_| {});
        (end, rc)
    }

    fn io_step(s: &S) -> Step {
        let mut ob = s.outbox();
        let mut rc = -1;
        s.io_step(&mut ob, &mut rc)
    }

    /// Runs the dispatch loop until it exits.
    fn dispatch_until_exit(s: &S) {
        loop {
            let mut ob = s.outbox();
            if s.wait_dispatch(&mut ob) == Step::Exit {
                return;
            }
            ob.finish(&*s.env.host);
        }
    }

    /// Runs the dispatch loop on its own thread, as C does. After `Exit`
    /// the thread gives back its ref. It returns the delivered items.
    fn spawn_dispatch(s: &Arc<S>) -> std::thread::JoinHandle<Vec<String>> {
        let s = Arc::clone(s);
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            loop {
                let mut ob = s.outbox();
                if s.wait_dispatch(&mut ob) == Step::Exit {
                    break;
                }
                while let Some(item) = ob.pop() {
                    seen.push(label(&item));
                }
            }
            assert_eq!(exit(&s, Role::Dispatch), (Step::Done(ZOK), ZOK));
            seen
        })
    }

    /// Waits long enough for a waiter thread to block in its wait.
    fn settle() {
        std::thread::sleep(Duration::from_millis(50));
    }

    fn published(s: &S) -> bool {
        s.queue.fifo.lock_owner().close_published
    }

    fn sync_exists(id: u64) -> Request<TestTokens> {
        Request {
            route: Route::Direct,
            ..exists(id)
        }
    }

    fn thread_items(seen: &[String]) -> Vec<&str> {
        seen.iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("Join") || l.starts_with("Detach"))
            .collect()
    }

    fn has_conn(s: &S) -> bool {
        let mut proof = Unlocked::new_at_entry();
        s.core.lock(&mut proof).conn.is_some()
    }

    fn readable(s: &S) -> bool {
        let side = s.io.lock_owner();
        let mut fds = [PollFd::new(&side.wake_rx, PollFlags::IN)];
        RealPoll.poll(&mut fds, 0).unwrap() == 1
    }

    fn exists(id: u64) -> Request<TestTokens> {
        exists_request(PathIn::Legacy(Some(b"/".to_vec())), id)
    }

    #[test]
    fn thread_refs_and_the_epilog() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        assert_eq!(s.life.refs(), 2);
        assert_eq!(exit(&s, Role::Dispatch), (Step::Done(ZOK), ZOK));
        assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
        assert_eq!(s.life.refs(), 0);
        assert!(s.queue.fifo.lock_owner().io_exited);
        assert!(has_conn(&s));
        // The last ref after a close request runs the final close.
        s.thread_enter(Role::Init);
        assert!(s.life.request_close());
        assert_eq!(exit(&s, Role::Init), (Step::Release, ZOK));
        assert!(!has_conn(&s));
        assert_eq!(s.state(), 0);
    }

    #[test]
    fn wait_dispatch_keeps_the_order() {
        let (s, _host) = handle();
        for n in 1..=3 {
            s.queue.publish(Item::AuthResult {
                token: AuthId::new(n),
                rc: ZOK,
            });
        }
        let mut ob = s.outbox();
        assert_eq!(s.wait_dispatch(&mut ob), Step::Done(ZOK));
        let got: Vec<String> = std::iter::from_fn(|| ob.pop()).map(|i| label(&i)).collect();
        assert_eq!(got, ["AuthResult 1", "AuthResult 2", "AuthResult 3"]);
        assert!(s.queue.fifo.lock_owner().items.is_empty());
    }

    #[test]
    fn publish_on_take_feeds_the_fifo_in_order() {
        let (s, _host) = handle();
        let mut ob = s.outbox();
        ob.push_publish(Item::AuthResult {
            token: AuthId::new(1),
            rc: ZOK,
        });
        ob.push(Item::AuthLockpoint);
        ob.push_publish(Item::AuthResult {
            token: AuthId::new(2),
            rc: ZOK,
        });
        assert!(matches!(ob.pop(), Some(Item::AuthLockpoint)));
        assert_eq!(s.queue.fifo.lock_owner().items.len(), 1);
        assert!(ob.pop().is_none());
        let mut batch = s.outbox();
        assert_eq!(s.wait_dispatch(&mut batch), Step::Done(ZOK));
        let got: Vec<String> = std::iter::from_fn(|| batch.pop())
            .map(|i| label(&i))
            .collect();
        assert_eq!(got, ["AuthResult 1", "AuthResult 2"]);
    }

    #[test]
    fn the_io_exit_wakes_the_dispatch_thread() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let waiter = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                let mut ob = s.outbox();
                s.wait_dispatch(&mut ob)
            })
        };
        settle();
        assert!(s.life.request_close());
        s.queue.wake_all();
        // A close request alone does not end the wait.
        settle();
        assert!(!waiter.is_finished());
        // The close mark alone does not end the wait.
        s.queue.close_published();
        settle();
        assert!(!waiter.is_finished());
        assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
        assert_eq!(waiter.join().unwrap(), Step::Exit);
        assert_eq!(s.life.refs(), 1);
    }

    /// The IO thread leaves its loop between the close request and the
    /// drain of the ZCLOSING results. The dispatch thread still delivers
    /// each result, and the final close discards nothing.
    #[test]
    fn the_dispatch_thread_waits_for_the_close_mark() {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        assert!(s.submit(exists(1)).is_ok());
        assert!(s.submit(exists(2)).is_ok());
        let mut ob = s.outbox();
        let mut rc = -1;
        let first = s.close(Role::Foreign, &mut ob, &mut rc);
        // The results wait in the outbox of the close. The IO thread sees
        // the request and exits first.
        assert_eq!(io_step(&s), Step::Exit);
        assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
        {
            let fifo = s.queue.fifo.lock_owner();
            assert!(fifo.io_exited && fifo.items.is_empty() && !fifo.close_published);
        }
        assert!(s.life.close_requested());
        let mut waiter = Some(spawn_dispatch(&s));
        settle();
        assert!(!waiter.as_ref().unwrap().is_finished());
        let mut got = Vec::new();
        let (end, seen) = drive(&s, first, &mut ob, &mut rc, |item| match item {
            // A foreign close gives the mark after its tail, so the
            // mark is not out at the IO join.
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } => assert!(!published(&s)),
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } => {
                assert!(published(&s));
                got = waiter.take().unwrap().join().unwrap();
            }
            _ => {}
        });
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        let closing = format!("{}", zk_jute::rc::ZCLOSING);
        assert_eq!(
            got,
            [format!("Result 1 {closing}"), format!("Result 2 {closing}")]
        );
        assert!(host.discarded().is_empty());
        assert!(!has_conn(&s));
    }

    /// An IO thread that exits on an unrecoverable state does not end
    /// the dispatch thread. The thread stays until a close publishes.
    #[test]
    fn an_early_io_exit_keeps_the_dispatch_thread_until_the_close_mark() {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
        let mut waiter = Some(spawn_dispatch(&s));
        settle();
        assert!(!waiter.as_ref().unwrap().is_finished());
        assert!(s.submit(exists(3)).is_ok());
        let mut got = Vec::new();
        let (end, rc, seen) = close(&s, Role::Foreign, |item| {
            if let Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } = item
            {
                got = waiter.take().unwrap().join().unwrap();
            }
        });
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        assert_eq!(got, [format!("Result 3 {}", zk_jute::rc::ZCLOSING)]);
        assert!(host.discarded().is_empty());
    }

    /// The close pump stops at each barrier. The mark goes in only after
    /// the last pass, so it follows every result of the close.
    #[test]
    fn the_close_mark_follows_every_barrier_of_the_close_pump() {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        assert!(s.submit(sync_exists(1)).is_ok());
        assert!(s.submit(exists(2)).is_ok());
        assert!(s.submit(sync_exists(3)).is_ok());
        let mut ob = s.outbox();
        let mut rc = -1;
        let first = s.close(Role::Foreign, &mut ob, &mut rc);
        assert_eq!(first, Step::More);
        let mut before = Vec::new();
        let mut joined = false;
        let mut waiter = None;
        let mut got = Vec::new();
        let (end, seen) = drive(&s, first, &mut ob, &mut rc, |item| match item {
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } => {
                joined = true;
                assert!(!published(&s));
                assert_eq!(io_step(&s), Step::Exit);
                assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
                waiter = Some(spawn_dispatch(&s));
            }
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } => got = waiter.take().unwrap().join().unwrap(),
            other if !joined => before.push((label(other), published(&s))),
            _ => {}
        });
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        let closing = zk_jute::rc::ZCLOSING;
        // The sync results are barriers of the close pump. The mark is
        // not out at any of them.
        let syncs: Vec<_> = before
            .iter()
            .filter(|(l, _)| l.starts_with("Result"))
            .cloned()
            .collect();
        assert_eq!(
            syncs,
            [
                (format!("Result 1 {closing}"), false),
                (format!("Result 3 {closing}"), false)
            ]
        );
        assert!(before.iter().all(|(_, p)| !p), "{before:?}");
        assert!(before.iter().any(|(l, _)| l == "AuthLockpoint"));
        assert_eq!(got, [format!("Result 2 {closing}")]);
        assert!(host.discarded().is_empty());
    }

    /// A close with no connection has no results. It still gives the
    /// mark, so the dispatch thread exits.
    #[test]
    fn a_close_with_no_connection_still_gives_the_mark() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        {
            let mut proof = Unlocked::new_at_entry();
            s.core.lock(&mut proof).conn = None;
        }
        let mut waiter = Some(spawn_dispatch(&s));
        let (end, rc, seen) = close(&s, Role::Foreign, |item| match item {
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } => {
                assert!(!published(&s));
                assert_eq!(io_step(&s), Step::Exit);
                assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
            }
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } => {
                assert!(published(&s));
                assert!(waiter.take().unwrap().join().unwrap().is_empty());
            }
            _ => {}
        });
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
    }

    #[test]
    fn submit_wakes_the_waker() {
        let (s, _host) = handle();
        assert!(!readable(&s));
        assert!(matches!(s.submit(exists(1)), Ok(Submitted::Queued { .. })));
        assert!(readable(&s));
        {
            let side = s.io.lock_owner();
            side.wake_rx.reset(&s.waker);
        }
        assert!(!readable(&s));
        assert!(s.submit(exists(2)).is_ok());
        assert!(readable(&s));
    }

    /// A submit after a close request fails, and mt runs no flush on the
    /// app thread.
    #[test]
    fn submit_after_a_close_request_fails() {
        let (s, _host) = handle();
        assert!(s.life.request_close());
        let err = s.submit(exists(7)).err().unwrap();
        assert_eq!(err.code, ZMARSHALLINGERROR);
        assert_eq!(err.token.id(), 7);
        assert!(!readable(&s));
    }

    #[test]
    fn close_from_a_foreign_thread_joins_both_threads() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let (end, rc, seen) = close(&s, Role::Foreign, |item| match item {
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } => {
                assert_eq!(io_step(&s), Step::Exit);
                assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
            }
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } => {
                dispatch_until_exit(&s);
                assert_eq!(exit(&s, Role::Dispatch), (Step::Done(ZOK), ZOK));
            }
            _ => {}
        });
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        assert!(!has_conn(&s));
    }

    fn auth_result(n: u64) -> Item<TestTokens> {
        Item::AuthResult {
            token: AuthId::new(n),
            rc: ZOK,
        }
    }

    /// Joins the IO thread of a foreign close, as C does.
    fn join_io(s: &S, item: &Item<TestTokens>) {
        if let Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Io,
        } = item
        {
            assert_eq!(io_step(s), Step::Exit);
            assert_eq!(exit(s, Role::Io), (Step::Done(ZOK), ZOK));
        }
    }

    /// A callback ends the dispatch thread while a foreign close waits for
    /// the queued callbacks. The cleanup handler ends the wait. The close
    /// gives back the ref of that thread and runs the final close.
    #[test]
    fn dispatch_end_during_a_foreign_close_ends_the_wait() {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        for n in 1..=3 {
            s.queue.publish(auth_result(n));
        }
        let dispatch = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                let mut ob = s.outbox();
                assert_eq!(s.wait_dispatch(&mut ob), Step::Done(ZOK));
                // C takes the first item, and its callback ends the thread
                // after the close starts to wait.
                assert_eq!(label(&ob.pop().unwrap()), "AuthResult 1");
                while !s.queue.fifo.lock_owner().settling {
                    std::thread::yield_now();
                }
                s.queue.publish(auth_result(4));
                s.dispatch_ended(&mut ob);
            })
        };
        let mut dispatch = Some(dispatch);
        let (end, rc, seen) = close(&s, Role::Foreign, |item| {
            join_io(&s, item);
            if let Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } = item
            {
                dispatch.take().unwrap().join().unwrap();
            }
        });
        assert!(dispatch.is_none());
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        // Items 2 and 3 were in the batch, and item 4 was in the FIFO.
        assert_eq!(host.discarded(), ["auth", "auth", "auth"]);
        assert_eq!(s.life.refs(), 0);
        assert!(!has_conn(&s));
    }

    /// A callback ends the dispatch thread before the close. The close
    /// does not wait, and the final close runs in the close.
    #[test]
    fn dispatch_end_before_a_foreign_close() {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        s.queue.publish(auth_result(1));
        let mut ob = s.outbox();
        assert_eq!(s.wait_dispatch(&mut ob), Step::Done(ZOK));
        s.dispatch_ended(&mut ob);
        assert_eq!(host.discarded(), ["auth"]);
        s.queue.publish(auth_result(2));
        let (end, rc, seen) = close(&s, Role::Foreign, |item| join_io(&s, item));
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        assert_eq!(host.discarded(), ["auth", "auth"]);
        assert_eq!(s.life.refs(), 0);
        assert!(!has_conn(&s));
    }

    /// A callback closes the handle, then ends the dispatch thread. As in
    /// zookeeper.c, no final close runs, and the handle keeps its state.
    /// The test guards against a final close after the own close of the
    /// thread. The close tail stays at the exit of the dispatch thread.
    #[test]
    fn dispatch_end_after_a_dispatch_close_keeps_the_ref() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let (end, rc, _) = close(&s, Role::Dispatch, |item| {
            if let Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } = item
            {
                assert_eq!(io_step(&s), Step::Exit);
                assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
            }
        });
        assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
        let mut ob = s.outbox();
        s.dispatch_ended(&mut ob);
        assert_eq!(s.life.refs(), 1);
        assert!(has_conn(&s));
        assert_eq!(*s.close_stage.lock_owner(), CloseStage::AtDispatchExit);
    }

    /// A callback ends the dispatch thread, and then a callback on the IO
    /// thread closes the handle. The close gives back the ref of the
    /// ended thread. The exit of the IO thread runs the final close.
    #[test]
    fn dispatch_end_before_a_close_from_the_io_thread() {
        let (s, host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        s.queue.publish(auth_result(1));
        let mut ob = s.outbox();
        assert_eq!(s.wait_dispatch(&mut ob), Step::Done(ZOK));
        s.dispatch_ended(&mut ob);
        assert_eq!(host.discarded(), ["auth"]);
        s.queue.publish(auth_result(2));
        let (end, rc, seen) = close(&s, Role::Io, |_| {});
        assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
        assert_eq!(thread_items(&seen), ["Detach Io", "Join Dispatch"]);
        assert!(has_conn(&s));
        assert_eq!(io_step(&s), Step::Exit);
        assert_eq!(exit(&s, Role::Io), (Step::Release, ZOK));
        assert_eq!(host.discarded(), ["auth", "auth"]);
        assert_eq!(s.life.refs(), 0);
        assert!(!has_conn(&s));
    }

    #[test]
    fn close_from_the_io_thread_detaches_it() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let (end, rc, seen) = close(&s, Role::Io, |item| {
            if let Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } = item
            {
                // The detach sets `io_exited`, and the mark is out. So the
                // dispatch thread exits after its drain.
                assert!(published(&s));
                dispatch_until_exit(&s);
                assert_eq!(exit(&s, Role::Dispatch), (Step::Done(ZOK), ZOK));
            }
        });
        assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
        assert_eq!(thread_items(&seen), ["Detach Io", "Join Dispatch"]);
        assert!(s.queue.fifo.lock_owner().io_exited);
        assert!(has_conn(&s));
        // The IO thread leaves its loop and runs the final close.
        assert_eq!(io_step(&s), Step::Exit);
        assert_eq!(exit(&s, Role::Io), (Step::Release, ZOK));
        assert!(!has_conn(&s));
    }

    #[test]
    fn close_from_the_dispatch_thread_detaches_it() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let (end, rc, seen) = close(&s, Role::Dispatch, |item| {
            if let Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } = item
            {
                assert_eq!(io_step(&s), Step::Exit);
                assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
            }
        });
        assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Detach Dispatch"]);
        assert!(has_conn(&s));
        // The dispatch thread gives the mark in its own close, so it does
        // not wait for itself.
        assert!(published(&s));
        // The dispatch thread drains, exits and runs the final close.
        dispatch_until_exit(&s);
        assert_eq!(exit(&s, Role::Dispatch), (Step::Release, ZOK));
        assert!(!has_conn(&s));
    }

    #[test]
    fn close_with_the_last_ref_runs_the_final_close() {
        let (s, host) = handle();
        assert!(s.submit(exists(1)).is_ok());
        let (end, rc, seen) = close(&s, Role::Foreign, |_| {});
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert!(thread_items(&seen).is_empty());
        // The request never left the core. Its token goes to the host.
        assert_eq!(host.discarded(), ["completion"]);
        assert!(s.queue.fifo.lock_owner().items.is_empty());
        let err = s.submit(exists(2)).err().unwrap();
        assert_eq!(err.code, ZMARSHALLINGERROR);
        // A close after the release is a no-op.
        let (end, rc, seen) = close(&s, Role::Foreign, |_| {});
        assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
        assert!(seen.is_empty());
    }

    #[test]
    fn a_second_close_during_a_close_is_a_no_op() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        let (end, rc, seen) = close(&s, Role::Foreign, |item| {
            if let Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } = item
            {
                let mut ob = s.outbox();
                let mut rc = -1;
                assert_eq!(s.close(Role::Foreign, &mut ob, &mut rc), Step::Done(ZOK));
                assert_eq!(rc, ZOK);
                assert!(ob.is_empty());
                assert_eq!(s.life.refs(), 2);
                assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
            }
        });
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
    }

    #[test]
    fn sasl_result_and_requeue_are_stored() {
        let (s, _host) = handle();
        s.sasl_result(SaslAnswer::Stepped {
            generation: 4,
            result: Err(SaslError {
                rc: -1,
                errstring: Vec::new(),
                errdetail: Vec::new(),
            }),
        });
        let mut proof = Unlocked::new_at_entry();
        assert!(matches!(
            s.core.lock(&mut proof).sasl,
            Some(SaslAnswer::Stepped { generation: 4, .. })
        ));

        let mut ob = s.outbox();
        ob.push(Item::AuthLockpoint);
        ob.push_publish(Item::AuthResult {
            token: AuthId::new(1),
            rc: ZOK,
        });
        ob.set_resume(ResumeAt::IoStep);
        s.requeue(ob.requeue());
        let mut ob = s.outbox();
        ob.push(Item::AuthResult {
            token: AuthId::new(2),
            rc: ZOK,
        });
        s.requeue(ob.requeue());

        let mut back = Outbox::new();
        assert!(s.core.lock(&mut proof).restore_requeued(&mut back));
        assert_eq!(back.resume_at(), None);
        let got: Vec<String> = std::iter::from_fn(|| back.pop())
            .map(|i| label(&i))
            .collect();
        assert_eq!(got, ["AuthLockpoint", "AuthResult 1", "AuthResult 2"]);
        assert!(s.core.lock(&mut proof).requeued.is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri reports every descriptor as CLOEXEC")]
    fn the_waker_pipe_has_no_cloexec_with_the_sock_flag() {
        let host = Arc::new(TestHost::new());
        let leaves: Arc<dyn HostLeaves<TestTokens>> = host.clone();
        let core = Core::new(Box::new(test_connection(DriverMode::MT)));
        let mut env = Env::new(leaves);
        env.cfg.cloexec = true;
        let mut ob = Outbox::new();
        let s = Shared::new(core, env, &mut ob).unwrap();
        let io = s.io.lock_owner();
        let flags = rustix::io::fcntl_getfd(&io.wake_rx).unwrap();
        assert!(!flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[test]
    fn set_servers_resolves_and_wakes() {
        let (s, host) = handle();
        host.set_addrs(b"a", vec!["127.0.0.1:1".parse().unwrap()]);
        let mut ob = s.outbox();
        let mut rc = -1;
        assert_eq!(s.set_servers(b"a:1", &mut ob, &mut rc), Step::Done(ZOK));
        assert_eq!(rc, ZOK);
        assert_eq!(host.resolves(), 1);
        assert_eq!(host.reseeds(), 1);
        assert!(readable(&s));
        // A port error commits nothing and resolves nothing.
        let step = s.set_servers(b"a", &mut ob, &mut rc);
        assert_eq!((step, rc), (Step::Done(ZBADARGUMENTS), ZBADARGUMENTS));
        assert_eq!(host.resolves(), 1);
        ob.finish(&*s.env.host);
    }

    #[test]
    fn set_servers_flushes_each_failure_line_before_the_next_resolve() {
        let (s, host) = handle();
        host.set_addrs(b"b", vec!["127.0.0.1:2".parse().unwrap()]);
        let mut ob = s.outbox();
        let mut rc = -1;
        // Host a fails. Its line goes to C before host b resolves.
        let first = s.set_servers(b"a:1,b:2", &mut ob, &mut rc);
        assert_eq!(first, Step::More);
        assert_eq!(host.resolves(), 1);
        assert!(!readable(&s));
        let (end, seen) = drive(&s, first, &mut ob, &mut rc, |_| {});
        assert!(!seen.is_empty());
        assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
        assert_eq!((host.resolves(), host.reseeds()), (2, 1));
        assert!(readable(&s));
    }

    #[test]
    fn a_requeued_set_servers_run_goes_to_the_io_thread() {
        let (s, host) = handle();
        host.set_addrs(b"b", vec!["127.0.0.1:2".parse().unwrap()]);
        let mut ob = s.outbox();
        let mut rc = -1;
        assert_eq!(s.set_servers(b"a:1,b:2", &mut ob, &mut rc), Step::More);
        // A callback throws: C requeues the outbox. No resume follows.
        s.requeue(ob.requeue());
        let mut proof = Unlocked::new_at_entry();
        {
            let core = s.core.lock(&mut proof);
            assert!(core.set_servers_runs.is_empty());
            assert_eq!(core.set_servers.as_ref().map(|(_, h)| h.len()), Some(2));
        }
        assert!(readable(&s));
    }

    #[test]
    fn a_second_close_continues_a_requeued_close_stage() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let mut ob = s.outbox();
        let mut rc = -1;
        assert_eq!(s.close(Role::Foreign, &mut ob, &mut rc), Step::More);
        assert_eq!(ob.resume_at(), Some(ResumeAt::Close));
        // A callback throws: C requeues the outbox. No resume follows.
        s.requeue(ob.requeue());
        let mut proof = Unlocked::new_at_entry();
        assert_eq!(s.core.lock(&mut proof).orphan_close, Some(ResumeAt::Close));
        // The second close continues the stage. It gives the mark after
        // the close tail, before the dispatch join.
        assert!(!published(&s));
        let (end, rc, seen) = close(&s, Role::Foreign, |item| match item {
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } => {
                assert!(!published(&s));
                assert_eq!(io_step(&s), Step::Exit);
                assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
            }
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } => {
                assert!(published(&s));
                dispatch_until_exit(&s);
                assert_eq!(exit(&s, Role::Dispatch), (Step::Done(ZOK), ZOK));
            }
            _ => {}
        });
        assert_eq!((end, rc), (Step::Release, ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        assert!(!has_conn(&s));
        assert!(s.core.lock(&mut proof).orphan_close.is_none());
    }

    /// A completion callback continues a requeued foreign close. The
    /// dispatch thread cannot wait for its own batch, so the close skips
    /// the wait for the dispatch thread and runs the close tail at once.
    #[test]
    fn a_completion_callback_continues_a_requeued_foreign_close() {
        let (s, _host) = handle();
        s.thread_enter(Role::Io);
        s.thread_enter(Role::Dispatch);
        let mut ob = s.outbox();
        let mut rc = -1;
        assert_eq!(s.close(Role::Foreign, &mut ob, &mut rc), Step::More);
        // A callback throws: C requeues the outbox. No resume follows.
        s.requeue(ob.requeue());
        // The dispatch thread takes a batch. Its callback closes.
        s.queue.publish(Item::AuthResult {
            token: AuthId::new(1),
            rc: ZOK,
        });
        let mut batch = s.outbox();
        assert_eq!(s.wait_dispatch(&mut batch), Step::Done(ZOK));
        let closer = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                close(&s, Role::Dispatch, |item| {
                    if let Item::Thread {
                        op: ThreadOp::Join,
                        role: ThreadRole::Io,
                    } = item
                    {
                        assert_eq!(io_step(&s), Step::Exit);
                        assert_eq!(exit(&s, Role::Io), (Step::Done(ZOK), ZOK));
                    }
                })
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !closer.is_finished() {
            assert!(std::time::Instant::now() < deadline, "the close waits");
            settle();
        }
        let (end, rc, seen) = closer.join().unwrap();
        assert_eq!((end, rc), (Step::Done(ZOK), ZOK));
        assert_eq!(thread_items(&seen), ["Join Io", "Join Dispatch"]);
        assert!(published(&s));
        // The callback returns. The thread finishes its batch and exits.
        assert_eq!(
            batch.pop().map(|i| label(&i)),
            Some("AuthResult 1".to_owned())
        );
        dispatch_until_exit(&s);
        assert_eq!(exit(&s, Role::Dispatch), (Step::Release, ZOK));
        assert!(!has_conn(&s));
    }

    #[test]
    fn the_exported_steps_report_no_socket() {
        let (s, _host) = handle();
        let out = s.interest_exported();
        assert_eq!((out.rc, out.written, out.fd, out.bits), (ZOK, true, -1, 0));
        assert_eq!(out.timeout_ms, i64::from(s.recv_timeout() / 3));
        assert_eq!(s.process_exported(), ZINVALIDSTATE);
        let (end, _, _) = close(&s, Role::Foreign, |_| {});
        assert_eq!(end, Step::Release);
        let out = s.interest_exported();
        assert_eq!((out.rc, out.written, out.fd), (ZINVALIDSTATE, false, -1));
    }

    #[test]
    fn peer_addr_reads_the_cache() {
        let (s, _host) = handle();
        assert_eq!(s.peer_addr(), None);
        let addr: SocketAddr = "127.0.0.1:2181".parse().unwrap();
        let mut proof = Unlocked::new_at_entry();
        s.core.lock(&mut proof).peer = Some(addr);
        assert_eq!(s.peer_addr(), Some(addr));
    }
}
