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

//! The native threaded driver (`DispatchMode::IoThread`).
//!
//! One IO thread per client runs `io_loop`. Each pass runs the shared
//! steps of `IoCore`, then routes the outbox items in order through the
//! [`RouteSink`] of zk-client, with no lock held. There is no
//! dispatch thread and no FIFO.
//!
//! - Threads come from a [`Spawn`] implementation. Only
//!   `crate::spawn_std` calls `std::thread::spawn`.
//! - Resolution runs on a short-lived DNS thread per resolver generation
//!   (`DeferPolicy::DNS_THREAD`, spec "Native threaded driver"). With an
//!   open socket the IO thread goes on with pings, reads, flushes and the
//!   close drain while the resolver blocks. The DNS thread gives its
//!   `JobDone` back through `NativeShared::dns` and wakes the IO thread.
//! - SASL runs inline with the native mechanism of zk-client: a `Sasl`
//!   item goes to the [`SaslSession`], and the answer goes to
//!   `Core::sasl` before the resume.
//! - The waker and the sockets have CLOEXEC (`DriverConfig::cloexec` is
//!   true for every native handle).
//! - The read gate ([`ReadGate`]) bounds the undelivered items.
//! - Close (`close_mode = Drain`): see [`NativeHandle::close`].
//!
//! This driver stays apart from `crate::threaded::Shared`. An open
//! question is whether both belong in `threaded.rs`.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use zk_jute::JString;
use zk_proto::rc::{ZCLOSING, ZCONNECTIONLOSS, ZINVALIDSTATE, ZOK, ZSYSTEMERROR};
use zk_proto::{
    Action, AddAuthError, Cause, ClientId, CloseProgress, Connection, HostSpec, Millis, MultiOpRef,
    Request, SaslCall, SaslCallKind, SaslError, SaslSession, SecretBytes, SubmitError, Submitted,
};

use crate::dispatch::{ReadGate, RouteSink};
use crate::host::{DriverTokens, discard_leftovers};
use crate::iocore::{
    DeferPolicy, InterestOut, IoCore, Job, JobCtx, JobDone, Progress, StepCtx, run_job,
};
use crate::net::poll::{PollEvents, clamp_timeout_ms, map_revents, request_flags};
use crate::net::waker::{WakeRx, Waker};
use crate::outbox::{Flavor, Item, Outbox, SaslItem, discard_item};
use crate::state::{
    Core, Env, SaslAnswer, SubmitResult, read_at_entry, read_conn, with_conn_at_entry,
};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::{Condvar, Mutex, Unlocked};

/// The name of the IO thread.
pub const IO_THREAD_NAME: &str = "zk-io";

/// The name of a DNS thread.
pub const DNS_THREAD_NAME: &str = "zk-dns";

/// The most queued actions that the final drain runs after `destroy` or
/// `abandon`. Proto yields at most `CloseTransport` and `Sasl(Dispose)`
/// then, so the bound only stops a faulty loop.
const MAX_FINAL_ACTIONS: usize = 16;

/// A thread body.
pub type ThreadBody = Box<dyn FnOnce() + Send + 'static>;

/// Starts a named thread. zk-client gives `crate::spawn_std` or
/// its own implementation.
pub trait Spawn: Send + Sync {
    /// Starts `body` on a new detached thread with this name.
    ///
    /// # Errors
    ///
    /// Returns the OS error of the thread creation.
    fn spawn(&self, name: &'static str, body: ThreadBody) -> std::io::Result<()>;
}

/// The failure of [`start`].
#[derive(Debug)]
pub enum StartError {
    /// The waker pipe failed.
    Waker(rustix::io::Errno),
    /// The IO thread did not start.
    Spawn(std::io::Error),
}

/// The result slot of the DNS thread.
pub(crate) struct DnsSlot {
    /// True while a DNS thread runs.
    pub(crate) running: bool,
    /// The result of the last DNS thread. The IO thread takes it.
    pub(crate) done: Option<JobDone>,
}

/// The largest number of addresses that [`SaslHosts`] keeps. An address
/// after the limit gets the host text of its IP address.
pub(crate) const SASL_HOSTS_MAX: usize = 256;

/// The connect-string host of each resolved address.
///
/// The SASL mechanism needs the host of the server, for example for the
/// Kerberos principal. The proto START item gives only the socket
/// addresses, so the driver keeps the host of each address from the last
/// resolution. When two hosts give the same address, the first host
/// wins.
#[derive(Debug, Default)]
pub(crate) struct SaslHosts {
    /// The resolver generation of the entries.
    generation: Option<u64>,
    /// Each address and the host text that gave it.
    entries: Vec<(SocketAddr, Vec<u8>)>,
}

impl SaslHosts {
    /// Gives the host text of each entry of a resolve job, by host index.
    /// Another job gives `None`.
    pub(crate) fn names(job: &Job) -> Option<Vec<Vec<u8>>> {
        match job {
            Job::Resolve { hosts, .. } => {
                Some(hosts.iter().map(|h| h.host_bytes().to_vec()).collect())
            }
            _ => None,
        }
    }

    /// Replaces the entries with the result of a resolve job. A result
    /// of an older generation changes nothing.
    pub(crate) fn record(&mut self, names: &[Vec<u8>], done: &JobDone) {
        let JobDone::Resolved {
            generation,
            results,
        } = done
        else {
            return;
        };
        if self.generation.is_some_and(|g| g > *generation) {
            return;
        }
        self.generation = Some(*generation);
        self.entries.clear();
        for r in results {
            let (Some(name), Ok(addrs)) = (names.get(r.host), r.result.as_ref()) else {
                continue;
            };
            for addr in addrs {
                if self.entries.len() >= SASL_HOSTS_MAX {
                    return;
                }
                if !self.entries.iter().any(|(a, _)| a == addr) {
                    self.entries.push((*addr, name.clone()));
                }
            }
        }
    }

    /// Gives the host of `peer`. An unknown address gives the text of its
    /// IP address.
    pub(crate) fn host_of(&self, peer: SocketAddr) -> Vec<u8> {
        self.entries
            .iter()
            .find(|(a, _)| *a == peer)
            .map_or_else(|| peer.ip().to_string().into_bytes(), |(_, h)| h.clone())
    }
}

/// The IO-owner state behind the `io` lock.
pub(crate) struct NativeIo {
    /// The transport and the step continuation.
    pub(crate) io: IoCore,
    /// The read end of the waker.
    pub(crate) wake_rx: WakeRx,
    /// The native SASL mechanism, or `None` with no SASL.
    pub(crate) sasl: Option<Box<dyn SaslSession>>,
}

/// The shared state of one native threaded client.
pub(crate) struct NativeShared<T: DriverTokens> {
    pub(crate) core: Mutex<Core<T>>,
    pub(crate) io: Mutex<NativeIo>,
    pub(crate) waker: Waker,
    pub(crate) gate: ReadGate,
    pub(crate) sink: Arc<dyn RouteSink<T>>,
    pub(crate) env: Env<T>,
    /// Set by `close` and the last-clone drop. It aborts the probe.
    pub(crate) close_requested: AtomicBool,
    /// Set by `detach`.
    pub(crate) detached: AtomicBool,
    pub(crate) dns: Mutex<DnsSlot>,
    /// The host of each resolved address, for the SASL mechanism. It is
    /// a leaf lock.
    pub(crate) hosts: Mutex<SaslHosts>,
    /// True when the client has a SASL mechanism. Only such a client
    /// records the host of each resolved address.
    pub(crate) sasl_hosts: bool,
    /// The close rc, written once when the IO thread exits.
    pub(crate) exit: Mutex<Option<i32>>,
    /// Signals `exit`.
    pub(crate) exit_cv: Condvar,
    /// Starts DNS threads.
    pub(crate) spawner: Arc<dyn Spawn>,
    /// True when `close` queued the CLOSE_OP frame. The close rc needs it.
    close_op_queued: AtomicBool,
    /// The shared state itself. A DNS thread keeps a strong reference
    /// while it runs.
    this: Weak<NativeShared<T>>,
}

/// The end of one IO pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pass {
    /// Run the next pass.
    Again,
    /// The IO thread exits with this close rc.
    Exit(i32),
}

/// How the IO side ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// A graceful close completed.
    Close,
    /// `detach` abandoned the connection.
    Detach,
}

/// The client handle of a native threaded driver. zk-client keeps it in
/// its `Client` and clones the handle per clone of the client.
///
/// The session lasts until `close`, `detach` or the drop of the last
/// clone. That drop starts the same close in the background. The IO
/// thread and the DNS thread keep only the shared state, so they do not
/// keep the session open.
pub struct NativeHandle<T: DriverTokens> {
    pub(crate) shared: Arc<NativeShared<T>>,
    /// The clones share it. Its drop starts the close.
    owner: Arc<CloseOnDrop<T>>,
}

impl<T: DriverTokens> Clone for NativeHandle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            owner: Arc::clone(&self.owner),
        }
    }
}

/// Reports taken items to the read gate of a native driver.
///
/// A receiver can outlive the last handle while the IO thread drains
/// the queue for the close. The reporter holds no close owner, so it
/// does not keep the session open. It keeps the gate correct until the
/// IO thread exits.
pub struct NativeGate<T: DriverTokens> {
    shared: Arc<NativeShared<T>>,
}

impl<T: DriverTokens> Clone for NativeGate<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T: DriverTokens> NativeGate<T> {
    /// A receiver took or dropped a counted item. When the read gate
    /// reopens, it wakes the IO thread.
    pub fn taken(&self) {
        if self.shared.gate.taken() {
            self.shared.waker.wake();
        }
    }
}

/// Starts the close when the last clone of a handle drops.
struct CloseOnDrop<T: DriverTokens> {
    shared: Arc<NativeShared<T>>,
}

impl<T: DriverTokens> Drop for CloseOnDrop<T> {
    fn drop(&mut self) {
        // A close or a detach before the drop makes this do nothing.
        self.shared.close();
    }
}

impl<T: DriverTokens> NativeHandle<T> {
    /// Makes the first handle of `shared`.
    pub(crate) fn from_shared(shared: Arc<NativeShared<T>>) -> Self {
        let owner = Arc::new(CloseOnDrop {
            shared: Arc::clone(&shared),
        });
        Self { shared, owner }
    }
}

/// Starts the native threaded driver for `conn`.
///
/// `env.cfg.cloexec` must be true. `conn` is a `DriverMode::NATIVE`
/// connection with `Compat::NATIVE`. The IO thread starts with the name
/// [`IO_THREAD_NAME`].
///
/// # Errors
///
/// Returns the waker or spawn failure. No thread runs then.
pub fn start<T: DriverTokens>(
    conn: Box<Connection<T>>,
    mut env: Env<T>,
    sink: Arc<dyn RouteSink<T>>,
    sasl: Option<Box<dyn SaslSession>>,
    spawner: Arc<dyn Spawn>,
) -> Result<NativeHandle<T>, StartError> {
    // Every native socket and pipe has CLOEXEC. The driver enforces the
    // rule, so a caller cannot leak descriptors into a child.
    env.cfg.cloexec = true;
    let shared = NativeShared::new(conn, env, sink, sasl, spawner)?;
    let body = Arc::clone(&shared);
    let spawned = shared
        .spawner
        .spawn(IO_THREAD_NAME, Box::new(move || io_loop(body)));
    if let Err(e) = spawned {
        // No IO thread exists, so this thread is the IO owner. It gives
        // the tokens of the connection back to the host.
        let mut proof = Unlocked::new_at_entry();
        let mut io = shared.io.lock_owner();
        shared.release(&mut proof, &mut io);
        return Err(StartError::Spawn(e));
    }
    Ok(NativeHandle::from_shared(shared))
}

/// The body of the IO thread: [`NativeShared::pass`] until `Exit`, then
/// the exit rc into `exit`, `exit_cv.notify_all`.
pub(crate) fn io_loop<T: DriverTokens>(shared: Arc<NativeShared<T>>) {
    let mut proof = Unlocked::new_at_entry();
    let mut ob = Outbox::new();
    let rc = loop {
        let pass = shared.pass(&mut proof, &mut ob);
        // The pass routes every item. An item that is still here has no
        // receiver, so its tokens go back to the host.
        ob.finish(&*shared.env.host);
        if let Pass::Exit(rc) = pass {
            break rc;
        }
    };
    shared.set_exit(rc);
}

/// The body of a DNS thread: `iocore::run_job` for one `Job::Resolve`,
/// the result into `dns`, then a wake.
pub(crate) fn dns_thread<T: DriverTokens>(shared: Arc<NativeShared<T>>, job: crate::iocore::Job) {
    let proof = Unlocked::new_at_entry();
    let names = shared.sasl_hosts.then_some(&job).and_then(SaslHosts::names);
    let done = {
        // The DNS thread has no waker read end. The close flag still
        // stops a probe, but a resolve job runs no probe.
        let cx = shared.env.step_ctx(
            &shared.core,
            NativeShared::<T>::FLAVOR,
            NativeShared::<T>::DEFER,
            None,
            Some(&shared.close_requested),
            None,
        );
        let jcx = JobCtx {
            host: &*shared.env.host,
            probe: cx.probe_ctx(),
        };
        run_job(&jcx, &proof, job)
    };
    if let Some(names) = names {
        shared.hosts.lock_owner().record(&names, &done);
    }
    {
        let mut slot = shared.dns.lock_owner();
        slot.done = Some(done);
        slot.running = false;
    }
    shared.waker.wake();
}

impl<T: DriverTokens> NativeShared<T> {
    /// Makes the shared state with an open read gate and a CLOEXEC waker.
    /// It starts no thread.
    fn new(
        conn: Box<Connection<T>>,
        env: Env<T>,
        sink: Arc<dyn RouteSink<T>>,
        sasl: Option<Box<dyn SaslSession>>,
        spawner: Arc<dyn Spawn>,
    ) -> Result<Arc<Self>, StartError> {
        let (waker, wake_rx) = Waker::new(true).map_err(StartError::Waker)?;
        let gate = ReadGate::new(env.cfg.dispatch_queue_capacity);
        let sasl_hosts = sasl.is_some();
        Ok(Arc::new_cyclic(|this| Self {
            core: Mutex::new(Core::new(conn)),
            io: Mutex::new(NativeIo {
                io: IoCore::new(),
                wake_rx,
                sasl,
            }),
            waker,
            gate,
            sink,
            env,
            close_requested: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            dns: Mutex::new(DnsSlot {
                running: false,
                done: None,
            }),
            hosts: Mutex::new(SaslHosts::default()),
            sasl_hosts,
            exit: Mutex::new(None),
            exit_cv: Condvar::new(),
            spawner,
            close_op_queued: AtomicBool::new(false),
            this: this.clone(),
        }))
    }

    /// Starts the graceful close: `begin_close`, `queue_close_op` and a
    /// wake. Only the first close request does this. `NativeHandle::close`
    /// and the drop of the last handle use it.
    pub(crate) fn close(&self) {
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        {
            let mut core = self.core.lock(&mut proof);
            if self.close_requested.swap(true, Ordering::AcqRel) {
                return;
            }
            if let Some(c) = core.conn.as_deref_mut() {
                c.begin_close(now);
                let queued = c.queue_close_op();
                self.close_op_queued.store(queued, Ordering::Release);
            }
        }
        self.waker.wake();
    }

    /// One IO pass.
    ///
    /// 1. Take a DNS result from `dns` and give it to
    ///    `IoCore::complete_resolve`.
    /// 2. `interest_step` with `Flavor::Native`, `DeferPolicy::DNS_THREAD`
    ///    and the read gate. A deferred `Job::Resolve` starts a DNS
    ///    thread. A background resolve job also starts a DNS thread.
    /// 3. Route the outbox ([`NativeShared::route`]) with no lock held.
    ///    `More` routes, then resumes.
    /// 4. Poll the waker and the socket. With no transport, wait on the
    ///    waker only (a terminal state does not end the IO side).
    /// 5. `process_step`, route, then `close_step` while a close runs.
    /// 6. On `CloseProgress::Complete`: `close_flush` when graceful (it
    ///    sends close_notify), then `destroy`, route, `CloseTransport`,
    ///    `Sasl(Dispose)` and `Exit`. After `detach`: route, then `Exit`.
    ///    The `detach` call already ran `abandon`.
    ///
    /// With an open socket a resolution runs in the background, and the
    /// pass goes on with the socket I/O. With no socket the interest step
    /// waits for the DNS thread. The pass then waits on the waker only,
    /// so a close or a detach still ends the IO side at once.
    pub(crate) fn pass(&self, proof: &mut Unlocked, ob: &mut Outbox<T>) -> Pass {
        let mut guard = self.io.lock_owner();
        let io = &mut *guard;
        if let Some(rc) = self.end_check(proof, ob, io) {
            return Pass::Exit(rc);
        }
        let mut out = InterestOut::UNWRITTEN;
        let (running, done) = {
            let mut slot = self.dns.lock_owner();
            (slot.running, slot.done.take())
        };
        let waiting = io.io.job.is_some();
        let first = match done {
            Some(done) if waiting => {
                let cx = self.step_cx(&io.wake_rx);
                Some(io.io.complete_resolve(&cx, proof, done, ob, &mut out))
            }
            Some(done) => {
                // A background result. The interest step of this pass
                // comes after it.
                self.apply_background(proof, ob, io, done);
                let cx = self.step_cx(&io.wake_rx);
                Some(io.io.interest_step(&cx, proof, ob, &mut out))
            }
            None if running && waiting => None,
            None => {
                let cx = self.step_cx(&io.wake_rx);
                Some(io.io.interest_step(&cx, proof, ob, &mut out))
            }
        };
        let ready = match first {
            Some(p) => self.drive(proof, ob, io, p, &mut out).is_some(),
            None => false,
        };
        self.start_background(proof, ob, io);
        if ready {
            let events = self.poll_io(proof, io, &out);
            if io.io.has_socket() || !events.is_empty() {
                let mut scratch = InterestOut::UNWRITTEN;
                let p = {
                    let cx = self.step_cx(&io.wake_rx);
                    io.io.process_step(&cx, proof, events, ob)
                };
                let _ = self.drive(proof, ob, io, p, &mut scratch);
            }
        } else {
            let ms = self.idle_ms(proof);
            self.wait_waker(io, ms);
        }
        match self.end_check(proof, ob, io) {
            Some(rc) => Pass::Exit(rc),
            None => Pass::Again,
        }
    }

    /// Routes the items of `ob` in order.
    ///
    /// `Sasl` items go to the SASL mechanism. START and STEP store a
    /// `SaslAnswer` in `Core::sasl`. Each other item goes to `sink.route`.
    /// A true result counts in the read gate. `Thread` and
    /// `AuthLockpoint` never occur.
    ///
    /// [`SaslSession`] has no dispose call, and `start` begins a new
    /// mechanism session. So `Dispose` keeps the mechanism. The IO side
    /// drops the mechanism when it exits.
    pub(crate) fn route(&self, proof: &mut Unlocked, ob: &mut Outbox<T>, io: &mut NativeIo) {
        while let Some(item) = ob.pop() {
            match item {
                Item::Sasl(s) => self.sasl_call(proof, io, s),
                // These items carry no token. The native compat profile
                // emits no lock point, and only mt has thread items.
                Item::AuthLockpoint | Item::Thread { .. } => {}
                other => {
                    if self.sink.route(other) {
                        self.gate.routed();
                    }
                }
            }
        }
    }

    /// Makes the services of one step call on the IO thread.
    fn step_cx<'a>(&'a self, wake_rx: &'a WakeRx) -> StepCtx<'a, T> {
        self.env.step_ctx(
            &self.core,
            Self::FLAVOR,
            Self::DEFER,
            Some((&self.waker, wake_rx)),
            Some(&self.close_requested),
            Some(&self.gate),
        )
    }

    /// Runs one step to its end. Each `More` routes, then resumes. Each
    /// `Wait` runs the deferred jobs.
    ///
    /// It returns the rc of `Done`, or `None` while a DNS thread runs.
    fn drive(
        &self,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        io: &mut NativeIo,
        first: Progress,
        out: &mut InterestOut,
    ) -> Option<i32> {
        let mut p = first;
        loop {
            self.route(proof, ob, io);
            p = match p {
                Progress::Done(rc) => return Some(rc),
                Progress::More => {
                    let cx = self.step_cx(&io.wake_rx);
                    io.io.resume(&cx, proof, ob, out)
                }
                Progress::Wait => self.run_jobs(proof, ob, io, out)?,
            };
        }
    }

    /// Runs the jobs of a `Wait`.
    ///
    /// A resolve job goes to a DNS thread, and the step stays suspended
    /// until its result comes. Any other job runs inline, because the
    /// `DNS_THREAD` policy defers only resolution. When no thread starts,
    /// the resolve job also runs inline.
    ///
    /// It returns the progress of the continued step, or `None` while a
    /// DNS thread runs.
    fn run_jobs(
        &self,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        io: &mut NativeIo,
        out: &mut InterestOut,
    ) -> Option<Progress> {
        let mut next = None;
        for job in io.io.take_jobs() {
            let job = match job {
                Job::Resolve { .. } => match self.start_dns(job) {
                    Ok(()) => {
                        next = None;
                        continue;
                    }
                    Err(job) => job,
                },
                other => other,
            };
            let done = self.run_inline(proof, io, job);
            let cx = self.step_cx(&io.wake_rx);
            next = Some(io.io.complete_job(&cx, proof, done, ob, out));
        }
        next
    }

    /// Starts the background resolve job of the last step on a DNS
    /// thread. When no thread starts, the job runs inline and its result
    /// applies at once.
    fn start_background(&self, proof: &mut Unlocked, ob: &mut Outbox<T>, io: &mut NativeIo) {
        while let Some(job) = io.io.take_bg_job() {
            let Err(job) = self.start_dns(job) else {
                return;
            };
            let done = self.run_inline(proof, io, job);
            self.apply_background(proof, ob, io, done);
        }
    }

    /// Applies the result of a background resolve job and drives the
    /// step to its end. The interest outputs of that step are not used.
    fn apply_background(
        &self,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        io: &mut NativeIo,
        done: JobDone,
    ) {
        let mut scratch = InterestOut::UNWRITTEN;
        let p = {
            let cx = self.step_cx(&io.wake_rx);
            io.io.complete_resolve(&cx, proof, done, ob, &mut scratch)
        };
        let _ = self.drive(proof, ob, io, p, &mut scratch);
    }

    /// Starts a DNS thread for a resolve job. It gives the job back when
    /// a DNS thread already runs or the spawn fails.
    fn start_dns(&self, job: Job) -> Result<(), Job> {
        let Some(me) = self.this.upgrade() else {
            return Err(job);
        };
        {
            let mut slot = self.dns.lock_owner();
            if slot.running {
                return Err(job);
            }
            slot.running = true;
        }
        // The cell keeps the job reachable when the spawn fails and drops
        // the body.
        let cell = Arc::new(Mutex::new(Some(job)));
        let body_cell = Arc::clone(&cell);
        let body: ThreadBody = Box::new(move || {
            let job = body_cell.lock_owner().take();
            if let Some(job) = job {
                dns_thread(me, job);
            }
        });
        match self.spawner.spawn(DNS_THREAD_NAME, body) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.dns.lock_owner().running = false;
                let job = cell.lock_owner().take();
                job.map_or(Ok(()), Err)
            }
        }
    }

    /// Runs one job on the IO thread with no core lock held.
    fn run_inline(&self, proof: &mut Unlocked, io: &mut NativeIo, job: Job) -> JobDone {
        let names = self.sasl_hosts.then_some(&job).and_then(SaslHosts::names);
        let cx = self.step_cx(&io.wake_rx);
        let jcx = JobCtx {
            host: &*self.env.host,
            probe: cx.probe_ctx(),
        };
        let done = run_job(&jcx, proof, job);
        if let Some(names) = names {
            self.hosts.lock_owner().record(&names, &done);
        }
        done
    }

    /// Polls the waker and, when the interest step wrote its outputs, the
    /// socket. It returns the socket events.
    ///
    /// With no interest outputs it waits on the waker only, for
    /// `recv_timeout / 60`. While buffered plaintext can make progress
    /// the timeout is 0 and the events include READ.
    fn poll_io(&self, proof: &mut Unlocked, io: &mut NativeIo, out: &InterestOut) -> PollEvents {
        let suspended = read_conn(&self.core, proof, Connection::is_suspended).unwrap_or(false);
        let buffered = io.io.buffered_ready(suspended, self.gate.is_open());
        let timeout = if buffered {
            0
        } else if out.written {
            clamp_timeout_ms(out.timeout_ms)
        } else {
            self.idle_ms(proof)
        };
        let flags =
            (out.written && out.fd >= 0).then(|| request_flags(PollEvents::from_bits(out.bits)));
        let (woke, mut events) = match (io.io.conn.sock(), flags) {
            (Some(sock), Some(flags)) => {
                let mut fds = [
                    PollFd::new(&io.wake_rx, PollFlags::IN),
                    PollFd::new(sock, flags),
                ];
                let ready = self.env.poll.poll(&mut fds, timeout).is_ok_and(|n| n > 0);
                let [w, s] = &fds;
                if ready {
                    (!w.revents().is_empty(), map_revents(s.revents()))
                } else {
                    (false, PollEvents::NONE)
                }
            }
            _ => (self.poll_waker(io, timeout), PollEvents::NONE),
        };
        if woke {
            io.wake_rx.reset(&self.waker);
        }
        if buffered {
            events.read = true;
        }
        events
    }

    /// Waits on the waker only, then rearms it.
    fn wait_waker(&self, io: &mut NativeIo, timeout_ms: i32) {
        if self.poll_waker(io, timeout_ms) {
            io.wake_rx.reset(&self.waker);
        }
    }

    /// Polls the waker alone. It returns true when it fired. EINTR and
    /// other poll errors count as no event.
    fn poll_waker(&self, io: &NativeIo, timeout_ms: i32) -> bool {
        let mut fds = [PollFd::new(&io.wake_rx, PollFlags::IN)];
        let ready = self
            .env
            .poll
            .poll(&mut fds, timeout_ms)
            .is_ok_and(|n| n > 0);
        let [w] = &fds;
        ready && !w.revents().is_empty()
    }

    /// The wait with no interest outputs: `recv_timeout / 60`, at least
    /// 1 ms.
    fn idle_ms(&self, proof: &mut Unlocked) -> i32 {
        read_conn(&self.core, proof, Connection::recv_timeout)
            .unwrap_or(0)
            .checked_div(60)
            .unwrap_or(0)
            .max(1)
    }

    /// Checks for the end of the IO side: a detach, or a close that proto
    /// reports `Complete`. It runs the end and returns the exit rc.
    fn end_check(
        &self,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        io: &mut NativeIo,
    ) -> Option<i32> {
        if self.detached.load(Ordering::Acquire) {
            return Some(self.finish(proof, ob, io, End::Detach));
        }
        if !self.close_requested.load(Ordering::Acquire) {
            return None;
        }
        let now = self.env.clock.now();
        let complete = {
            let mut core = self.core.lock(proof);
            core.conn
                .as_deref_mut()
                .is_none_or(|c| c.close_step(now) == CloseProgress::Complete)
        };
        complete.then(|| self.finish(proof, ob, io, End::Close))
    }

    /// Ends the IO side.
    ///
    /// A close sends the queued frames and close_notify when the
    /// transport is still up, then calls `destroy`. A detach already
    /// called `abandon` in the API call. Both then route the outputs, run
    /// the final actions and give the leftover tokens back to the host.
    fn finish(&self, proof: &mut Unlocked, ob: &mut Outbox<T>, io: &mut NativeIo, end: End) -> i32 {
        self.route(proof, ob, io);
        let rc = match end {
            End::Detach => ZOK,
            End::Close => {
                let rc = self.close_rc(proof, ob, io);
                let now = self.env.clock.now();
                if let Some(c) = self.core.lock(proof).conn.as_deref_mut() {
                    c.destroy(now);
                }
                rc
            }
        };
        self.final_drain(proof, ob, io);
        self.release(proof, io);
        rc
    }

    /// The close rc: `ZOK`, `ZOPERATIONTIMEOUT` or a
    /// connection-loss class code.
    ///
    /// Proto gives the rc through `close_outcome`. A close with no
    /// CLOSE_OP gives `ZOK`, because no session is open. On a live TLS
    /// session, a graceful close then sends close_notify through
    /// `IoCore::close_flush`. The flush result does not change the rc.
    /// The tokio driver uses the same rule.
    fn close_rc(&self, proof: &mut Unlocked, ob: &mut Outbox<T>, io: &mut NativeIo) -> i32 {
        let outcome = read_conn(&self.core, proof, Connection::close_outcome).flatten();
        if !self.close_op_queued.load(Ordering::Acquire) {
            return ZOK;
        }
        let rc = outcome.unwrap_or(ZCONNECTIONLOSS);
        let live = read_conn(&self.core, proof, Connection::has_transport).unwrap_or(false);
        if live && io.io.has_tls_session() {
            let cx = self.step_cx(&io.wake_rx);
            let _flush_rc = io.io.close_flush(&cx, proof, ob);
        }
        rc
    }

    /// Routes the last outputs, then runs the queued actions of proto:
    /// `CloseTransport` drops the transport, and `Sasl(Dispose)` goes to
    /// the mechanism. The transport is closed after the destroy outputs,
    /// as legacy `destroy` does.
    fn final_drain(&self, proof: &mut Unlocked, ob: &mut Outbox<T>, io: &mut NativeIo) {
        self.flush_outputs(proof, ob, io);
        for _ in 0..MAX_FINAL_ACTIONS {
            let now = self.env.clock.now();
            let action = {
                let mut core = self.core.lock(proof);
                core.conn.as_deref_mut().and_then(|c| c.poll_action(now))
            };
            let Some(action) = action else {
                break;
            };
            match action {
                Action::CloseTransport => {
                    io.io.drop_transport();
                    self.core.lock(proof).peer = None;
                }
                Action::Sasl(call) => ob.push(Item::Sasl(SaslItem { call, addrs: None })),
                // A closing connection connects, resolves and probes no
                // more, so these actions are dropped.
                Action::Resolve { .. } | Action::Connect { .. } | Action::ProbeRw { .. } => {}
            }
            self.flush_outputs(proof, ob, io);
        }
        io.io.drop_transport();
        self.core.lock(proof).peer = None;
    }

    /// Pumps and routes the proto outputs until proto has none. A barrier
    /// resumes the stopped stage, so a stopped teardown and a deferred
    /// close run to their end.
    fn flush_outputs(&self, proof: &mut Unlocked, ob: &mut Outbox<T>, io: &mut NativeIo) {
        loop {
            let barrier = {
                let mut core = self.core.lock(proof);
                core.pump(Self::FLAVOR, ob, &*self.env.host)
            };
            self.route(proof, ob, io);
            if !barrier {
                break;
            }
            let now = self.env.clock.now();
            self.core.lock(proof).resume_stopped(now);
        }
    }

    /// Takes the connection and every driver value that holds tokens, and
    /// gives the tokens to `discard_token`. `state` then reads 0.
    fn release(&self, proof: &mut Unlocked, io: &mut NativeIo) {
        let (conn, requeued, local) = {
            let mut core = self.core.lock(proof);
            core.stopped = None;
            core.sasl = None;
            core.peer = None;
            (
                core.conn.take(),
                core.requeued.take(),
                std::mem::take(&mut core.local),
            )
        };
        io.io.drop_transport();
        io.sasl = None;
        let host = &*self.env.host;
        if let Some(conn) = conn {
            discard_leftovers(host, conn);
        }
        if let Some(requeued) = requeued {
            let mut rest = Outbox::new();
            rest.restore(requeued);
            rest.finish(host);
        }
        for item in local {
            discard_item(host, item);
        }
    }

    /// Writes the exit rc once and wakes every `wait_closed` caller.
    fn set_exit(&self, rc: i32) {
        let mut exit = self.exit.lock_owner();
        if exit.is_none() {
            *exit = Some(rc);
        }
        drop(exit);
        self.exit_cv.notify_all();
    }

    /// Runs one SASL call with the native mechanism, with no lock held.
    /// The answer goes to `Core::sasl` for the next resume.
    ///
    /// Before START, the mechanism gets the host and the socket addresses
    /// of the connection.
    fn sasl_call(&self, proof: &mut Unlocked, io: &mut NativeIo, item: SaslItem) {
        let SaslCall { generation, kind } = item.call;
        let mech = io.sasl.as_deref_mut();
        let answer = match kind {
            SaslCallKind::Start => SaslAnswer::Started {
                generation,
                result: match mech {
                    Some(m) => {
                        if let Some((local, peer)) = item.addrs {
                            let host = self.hosts.lock_owner().host_of(peer);
                            m.connection(&host, local, peer);
                        }
                        m.start()
                    }
                    None => Err(no_mechanism()),
                },
            },
            SaslCallKind::Step(token) => SaslAnswer::Stepped {
                generation,
                result: match mech {
                    Some(m) => m.step(token.as_ref().map(SecretBytes::expose)),
                    None => Err(no_mechanism()),
                },
            },
            SaslCallKind::Dispose => return,
        };
        self.core.lock(proof).sasl = Some(answer);
    }
}

/// The mechanism error when proto asks for SASL and the client has no
/// mechanism. Proto then fails the session.
pub(crate) fn no_mechanism() -> SaslError {
    SaslError {
        rc: ZSYSTEMERROR,
        errstring: b"no SASL mechanism".to_vec(),
        errdetail: Vec::new(),
    }
}

impl<T: DriverTokens> NativeHandle<T> {
    /// Submits one request and wakes the IO thread.
    ///
    /// After the IO thread exits, the submit fails with `ZCLOSING`, as a
    /// destroyed `Drain` connection gives.
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
        let now = self.shared.env.clock.now();
        let r = self
            .shared
            .core
            .lock(&mut Unlocked::new_at_entry())
            .submit_or(req, now, ZCLOSING, send);
        if r.is_ok() {
            self.shared.waker.wake();
        }
        r
    }

    /// Records an auth entry and wakes the IO thread.
    ///
    /// After the IO thread exits, it fails with `ZINVALIDSTATE`, as a
    /// destroyed connection gives.
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
            .add_auth_or(scheme, cred, done, now, ZINVALIDSTATE);
        if r.is_ok() {
            self.shared.waker.wake();
        }
        r
    }

    /// Gives a new host list to proto and wakes the IO thread. It returns
    /// the new resolver generation, or 0 after the IO thread exits.
    pub fn set_servers(&self, hosts: Vec<HostSpec>) -> u64 {
        let now = self.shared.env.clock.now();
        let generation = self
            .shared
            .core
            .lock(&mut Unlocked::new_at_entry())
            .set_servers_native(hosts, now);
        self.shared.waker.wake();
        generation
    }

    /// Starts a graceful close: `begin_close` and
    /// `queue_close_op` under the core lock, `close_requested`, a wake.
    /// The IO thread finishes the close. A second call does nothing.
    ///
    /// The flag changes under the core lock, so the IO thread sees the
    /// close in proto when it sees the flag.
    pub fn close(&self) {
        self.shared.close();
    }

    /// Waits until the IO thread exits, at most `timeout`. It returns the
    /// close rc, or `None` at the timeout.
    #[must_use]
    pub fn wait_closed(&self, timeout: std::time::Duration) -> Option<i32> {
        let deadline = Instant::now().checked_add(timeout);
        let mut exit = self.shared.exit.lock_owner();
        loop {
            if let Some(rc) = *exit {
                return Some(rc);
            }
            // A timeout past the end of `Instant` waits in steps of the
            // full timeout.
            let left = deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
            if left == Duration::ZERO {
                return None;
            }
            exit = self.shared.exit_cv.wait_timeout(exit, left).0;
        }
    }

    /// Ends the client with no close request (`abandon`). The IO
    /// thread routes the outputs and exits.
    ///
    /// `abandon` runs here under the core lock, so the pending requests
    /// fail with `ZCLOSING` before the IO thread sees the flag. The call
    /// also sets `close_requested`: it stops a probe and skips a connect,
    /// and a later `close` does nothing. A second call does nothing.
    pub fn detach(&self) {
        let now = self.shared.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        {
            let mut core = self.shared.core.lock(&mut proof);
            if self.shared.detached.load(Ordering::Acquire) {
                return;
            }
            if let Some(c) = core.conn.as_deref_mut() {
                c.abandon(now);
            }
            self.shared.close_requested.store(true, Ordering::Release);
            self.shared.detached.store(true, Ordering::Release);
        }
        self.shared.waker.wake();
    }

    /// A receiver took or dropped a counted item. When the read gate
    /// reopens, it wakes the IO thread.
    pub fn taken(&self) {
        if self.shared.gate.taken() {
            self.shared.waker.wake();
        }
    }

    /// Returns a reporter for the read gate. The reporter does not keep
    /// the session open.
    #[must_use]
    pub fn gate_reporter(&self) -> NativeGate<T> {
        NativeGate {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Wakes the IO thread.
    pub fn wake(&self) {
        self.shared.waker.wake();
    }

    /// Returns the read gate, for tests and metrics.
    #[must_use]
    pub fn gate(&self) -> &ReadGate {
        &self.shared.gate
    }

    /// The state code of the connection. 0 after the IO thread exits.
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
        self.shared.waker.wake();
        r
    }
}

impl<T: DriverTokens> NativeShared<T> {
    /// The defer policy of the native threaded driver.
    pub(crate) const DEFER: DeferPolicy = DeferPolicy::DNS_THREAD;

    /// The pump flavor.
    pub(crate) const FLAVOR: Flavor = Flavor::Native;
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
    use crate::host::HostLeaves;
    use crate::testutil::{TestHost, exists_request, native_connection, test_config};
    use zk_proto::{LogLevel, LogRecord, LogSite, PathIn, SaslStep};

    use zk_testkit::tokens::{AuthId, TestTokens};

    /// Records the kind of each routed item. Results and auth outcomes
    /// count.
    #[derive(Default)]
    struct Collect(std::sync::Mutex<Vec<String>>);

    impl RouteSink<TestTokens> for Collect {
        fn route(&self, item: Item<TestTokens>) -> bool {
            let counts = matches!(item, Item::Result { .. } | Item::AuthResult { .. });
            self.0.lock().unwrap().push(format!("{item:?}"));
            counts
        }
    }

    impl Collect {
        fn kinds(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A spawner that starts no thread. It records the names.
    #[derive(Default)]
    struct NoSpawn(std::sync::Mutex<Vec<&'static str>>);

    impl Spawn for NoSpawn {
        fn spawn(&self, name: &'static str, body: ThreadBody) -> std::io::Result<()> {
            self.0.lock().unwrap().push(name);
            drop(body);
            Err(std::io::Error::other("no threads in unit tests"))
        }
    }

    /// A mechanism that records the challenges it gets.
    #[derive(Default)]
    struct Mech(Arc<std::sync::Mutex<Vec<Option<Vec<u8>>>>>);

    impl SaslSession for Mech {
        fn start(&mut self) -> Result<(String, SaslStep), SaslError> {
            Ok((
                "PLAIN".into(),
                SaslStep {
                    token: Some(SecretBytes::from_slice(b"hi")),
                    done: false,
                },
            ))
        }

        fn step(&mut self, challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
            self.0.lock().unwrap().push(challenge.map(<[u8]>::to_vec));
            Ok(SaslStep {
                token: None,
                done: true,
            })
        }
    }

    struct Fixture {
        h: NativeHandle<TestTokens>,
        host: Arc<TestHost>,
        sink: Arc<Collect>,
        spawner: Arc<NoSpawn>,
    }

    fn native_env(host: &Arc<TestHost>, capacity: usize) -> Env<TestTokens> {
        let leaves: Arc<dyn HostLeaves<TestTokens>> = host.clone();
        let mut env = Env::new(leaves);
        env.cfg.cloexec = true;
        env.cfg.dispatch_queue_capacity = capacity;
        env
    }

    fn fixture(capacity: usize, sasl: Option<Box<dyn SaslSession>>) -> Fixture {
        let host = Arc::new(TestHost::new());
        let sink = Arc::new(Collect::default());
        let spawner = Arc::new(NoSpawn::default());
        let shared = NativeShared::new(
            native_connection(),
            native_env(&host, capacity),
            sink.clone(),
            sasl,
            spawner.clone(),
        )
        .unwrap();
        Fixture {
            h: NativeHandle::from_shared(shared),
            host,
            sink,
            spawner,
        }
    }

    fn exists(id: u64) -> Request<TestTokens> {
        exists_request(PathIn::Native("/".into()), id)
    }

    /// True when the waker pipe is readable. It polls with rustix
    /// directly, so no other driver code runs.
    fn woke(h: &NativeHandle<TestTokens>) -> bool {
        let io = h.shared.io.lock_owner();
        let mut fds = [PollFd::new(&io.wake_rx, PollFlags::IN)];
        let ts = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&ts)).unwrap() == 1
    }

    fn rearm(h: &NativeHandle<TestTokens>) {
        let io = h.shared.io.lock_owner();
        io.wake_rx.reset(&h.shared.waker);
    }

    fn pending(h: &NativeHandle<TestTokens>) -> usize {
        let mut proof = Unlocked::new_at_entry();
        read_conn(&h.shared.core, &mut proof, Connection::pending_len).unwrap()
    }

    /// Runs `f` as the IO owner of the handle.
    fn as_io<R>(
        h: &NativeHandle<TestTokens>,
        f: impl FnOnce(
            &NativeShared<TestTokens>,
            &mut Unlocked,
            &mut Outbox<TestTokens>,
            &mut NativeIo,
        ) -> R,
    ) -> R {
        let mut proof = Unlocked::new_at_entry();
        let mut ob = Outbox::new();
        let mut io = h.shared.io.lock_owner();
        f(&h.shared, &mut proof, &mut ob, &mut io)
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn submit_queues_the_request_and_wakes() {
        let f = fixture(8, None);
        assert!(!woke(&f.h));
        let r = f.h.submit(exists(1));
        assert!(matches!(r, Ok(Submitted::Queued { .. })));
        assert!(woke(&f.h));
        assert_eq!(pending(&f.h), 1);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn wakes_coalesce_and_the_reset_rearms() {
        let f = fixture(8, None);
        f.h.wake();
        f.h.wake();
        assert!(woke(&f.h));
        rearm(&f.h);
        assert!(!woke(&f.h));
        f.h.wake();
        assert!(woke(&f.h));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn set_servers_and_add_auth_wake() {
        let f = fixture(8, None);
        let g = f.h.set_servers(test_config(b"127.0.0.2:2181").hosts);
        assert!(g > 0);
        assert!(woke(&f.h));
        rearm(&f.h);
        let r = f.h.add_auth(
            JString::Bytes(b"digest".to_vec()),
            SecretBytes::from_slice(b"u:p"),
            Some(AuthId::new(1)),
        );
        assert!(r.is_ok());
        assert!(woke(&f.h));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn close_sets_the_flags_once() {
        let f = fixture(8, None);
        f.h.close();
        assert!(f.h.shared.close_requested.load(Ordering::Acquire));
        assert!(!f.h.shared.detached.load(Ordering::Acquire));
        // Not connected: no CLOSE_OP frame, so the close rc is ZOK.
        assert!(!f.h.shared.close_op_queued.load(Ordering::Acquire));
        let mut proof = Unlocked::new_at_entry();
        assert_eq!(
            read_conn(&f.h.shared.core, &mut proof, Connection::is_closing),
            Some(true)
        );
        assert!(woke(&f.h));
        rearm(&f.h);
        f.h.close();
        assert!(!woke(&f.h));
        let e = f.h.submit(exists(2)).err().unwrap();
        assert_eq!(e.code, ZCLOSING);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn the_drop_of_the_last_clone_starts_the_close() {
        let Fixture { h, .. } = fixture(8, None);
        let shared = Arc::clone(&h.shared);
        let other = h.clone();
        drop(h);
        // A clone still lives, so the session stays open.
        assert!(!shared.close_requested.load(Ordering::Acquire));
        drop(other);
        assert!(shared.close_requested.load(Ordering::Acquire));
        let mut proof = Unlocked::new_at_entry();
        assert_eq!(
            read_conn(&shared.core, &mut proof, Connection::is_closing),
            Some(true)
        );
        let io = shared.io.lock_owner();
        let mut fds = [PollFd::new(&io.wake_rx, PollFlags::IN)];
        let ts = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(rustix::event::poll(&mut fds, Some(&ts)).unwrap(), 1);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn the_drop_after_a_detach_does_nothing_more() {
        let Fixture { h, .. } = fixture(8, None);
        let shared = Arc::clone(&h.shared);
        h.detach();
        drop(h);
        assert!(shared.detached.load(Ordering::Acquire));
        // The detach abandoned the connection. The drop queued no close.
        assert!(!shared.close_op_queued.load(Ordering::Acquire));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn a_close_with_no_session_completes_at_once() {
        let f = fixture(8, None);
        assert_eq!(as_io(&f.h, |s, p, ob, io| s.end_check(p, ob, io)), None);
        f.h.close();
        let rc = as_io(&f.h, |s, p, ob, io| s.end_check(p, ob, io));
        assert_eq!(rc, Some(ZOK));
        assert_eq!(f.h.state(), 0);
        let e = f.h.submit(exists(3)).err().unwrap();
        assert_eq!(e.code, ZCLOSING);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn detach_fails_the_pending_requests_and_exits() {
        let f = fixture(8, None);
        f.h.submit(exists(1)).ok().unwrap();
        f.h.detach();
        assert!(f.h.shared.detached.load(Ordering::Acquire));
        assert!(f.h.shared.close_requested.load(Ordering::Acquire));
        assert!(woke(&f.h));
        let rc = as_io(&f.h, |s, p, ob, io| s.end_check(p, ob, io));
        assert_eq!(rc, Some(ZOK));
        assert!(f.sink.kinds().iter().any(|k| k == "Result"));
        assert_eq!(f.h.gate().count(), 1);
        assert_eq!(f.h.state(), 0);
        assert!(f.host.discarded().is_empty());
        // A second detach and a later close do nothing.
        rearm(&f.h);
        f.h.detach();
        f.h.close();
        assert!(!woke(&f.h));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn route_counts_into_the_gate_until_capacity() {
        let f = fixture(2, None);
        as_io(&f.h, |s, p, ob, io| {
            ob.push(Item::Log(LogRecord {
                site: LogSite::TcpNoDelay,
                level: LogLevel::Warn,
                args: Vec::new(),
            }));
            ob.push(Item::AuthResult {
                token: AuthId::new(1),
                rc: ZOK,
            });
            ob.push(Item::AuthLockpoint);
            ob.push(Item::AuthResult {
                token: AuthId::new(2),
                rc: ZOK,
            });
            s.route(p, ob, io);
            assert!(ob.is_empty());
        });
        assert_eq!(f.sink.kinds(), vec!["Log", "AuthResult", "AuthResult"]);
        assert_eq!(f.h.gate().count(), 2);
        assert!(!f.h.gate().is_open());
        assert!(!woke(&f.h));
        f.h.taken();
        assert!(f.h.gate().is_open());
        assert!(woke(&f.h));
        rearm(&f.h);
        f.h.taken();
        assert!(!woke(&f.h));
        assert_eq!(f.h.gate().count(), 0);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn wait_closed_times_out_then_gives_the_exit_rc() {
        let f = fixture(8, None);
        assert_eq!(f.h.wait_closed(Duration::from_millis(10)), None);
        let shared = Arc::clone(&f.h.shared);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            shared.set_exit(ZCONNECTIONLOSS);
        });
        assert_eq!(
            f.h.wait_closed(Duration::from_secs(5)),
            Some(ZCONNECTIONLOSS)
        );
        t.join().unwrap();
        // The first exit value stays.
        f.h.shared.set_exit(ZOK);
        assert_eq!(f.h.wait_closed(Duration::ZERO), Some(ZCONNECTIONLOSS));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn sasl_items_go_to_the_mechanism() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let f = fixture(8, Some(Box::new(Mech(Arc::clone(&seen)))));
        let take = |h: &NativeHandle<TestTokens>| {
            let mut proof = Unlocked::new_at_entry();
            h.shared.core.lock(&mut proof).sasl.take()
        };
        as_io(&f.h, |s, p, ob, io| {
            ob.push(Item::Sasl(SaslItem {
                call: SaslCall {
                    generation: 4,
                    kind: SaslCallKind::Start,
                },
                addrs: None,
            }));
            s.route(p, ob, io);
        });
        match take(&f.h) {
            Some(SaslAnswer::Started {
                generation: 4,
                result: Ok((name, step)),
            }) => {
                assert_eq!(name, "PLAIN");
                assert_eq!(step.token.unwrap().expose(), b"hi");
            }
            other => panic!("unexpected answer {other:?}"),
        }
        as_io(&f.h, |s, p, ob, io| {
            for kind in [
                SaslCallKind::Step(Some(SecretBytes::from_slice(b"c1"))),
                SaslCallKind::Dispose,
            ] {
                ob.push(Item::Sasl(SaslItem {
                    call: SaslCall {
                        generation: 4,
                        kind,
                    },
                    addrs: None,
                }));
            }
            s.route(p, ob, io);
        });
        assert!(matches!(
            take(&f.h),
            Some(SaslAnswer::Stepped {
                generation: 4,
                result: Ok(SaslStep { done: true, .. })
            })
        ));
        assert_eq!(*seen.lock().unwrap(), vec![Some(b"c1".to_vec())]);
        assert!(f.sink.kinds().is_empty());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn sasl_with_no_mechanism_is_a_mechanism_error() {
        let f = fixture(8, None);
        as_io(&f.h, |s, p, ob, io| {
            ob.push(Item::Sasl(SaslItem {
                call: SaslCall {
                    generation: 1,
                    kind: SaslCallKind::Start,
                },
                addrs: None,
            }));
            s.route(p, ob, io);
        });
        let mut proof = Unlocked::new_at_entry();
        let answer = f.h.shared.core.lock(&mut proof).sasl.take();
        assert!(matches!(
            answer,
            Some(SaslAnswer::Started {
                generation: 1,
                result: Err(SaslError {
                    rc: ZSYSTEMERROR,
                    ..
                })
            })
        ));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn release_discards_the_tokens_and_ends_the_api() {
        let f = fixture(8, None);
        f.h.submit(exists(1)).ok().unwrap();
        f.h.submit(exists(2)).ok().unwrap();
        as_io(&f.h, |s, p, _, io| s.release(p, io));
        assert_eq!(f.host.discarded(), vec!["completion", "completion"]);
        assert_eq!(f.h.state(), 0);
        assert_eq!(f.h.client_id(), ClientId::default());
        assert_eq!(f.h.submit(exists(3)).err().unwrap().code, ZCLOSING);
        let e =
            f.h.add_auth(
                JString::Bytes(b"x".to_vec()),
                SecretBytes::new(Vec::new()),
                None,
            )
            .err()
            .unwrap();
        assert_eq!(e.code, ZINVALIDSTATE);
        assert_eq!(f.h.set_servers(Vec::new()), 0);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn a_failed_dns_spawn_gives_the_job_back() {
        let f = fixture(8, None);
        let job = Job::Resolve {
            generation: 1,
            hosts: Vec::new(),
            shuffle: false,
        };
        let back = f.h.shared.start_dns(job);
        assert!(matches!(back, Err(Job::Resolve { generation: 1, .. })));
        assert!(!f.h.shared.dns.lock_owner().running);
        assert_eq!(*f.spawner.0.lock().unwrap(), vec![DNS_THREAD_NAME]);
    }

    /// A mechanism that records each connection call.
    #[derive(Default)]
    struct ConnMech(Arc<std::sync::Mutex<Vec<Seen>>>);

    /// The host, the local address and the peer address of one call.
    type Seen = (Vec<u8>, SocketAddr, SocketAddr);

    impl SaslSession for ConnMech {
        fn start(&mut self) -> Result<(String, SaslStep), SaslError> {
            Ok((
                "X".into(),
                SaslStep {
                    token: None,
                    done: false,
                },
            ))
        }

        fn step(&mut self, _challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
            Err(no_mechanism())
        }

        fn connection(&mut self, host: &[u8], local: SocketAddr, peer: SocketAddr) {
            self.0.lock().unwrap().push((host.to_vec(), local, peer));
        }
    }

    fn resolve_job(generation: u64, servers: &[u8]) -> Job {
        Job::Resolve {
            generation,
            hosts: zk_proto::legacy::connect::parse_servers(servers)
                .unwrap()
                .into_iter()
                .map(HostSpec::Legacy)
                .collect(),
            shuffle: false,
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn a_resolve_job_records_the_host_of_each_address() {
        let f = fixture(8, Some(Box::new(Mech::default())));
        let a = SocketAddr::from(([10, 0, 0, 1], 2181));
        let b = SocketAddr::from(([10, 0, 0, 2], 2181));
        f.host.set_addrs(b"zk1", vec![a, b]);
        f.host.set_addrs(b"zk2", vec![b]);
        as_io(&f.h, |s, p, _ob, io| {
            let done = s.run_inline(p, io, resolve_job(3, b"zk1:2181,zk2:2181,zk3:2181"));
            assert!(matches!(done, JobDone::Resolved { generation: 3, .. }));
        });
        {
            let hosts = f.h.shared.hosts.lock_owner();
            assert_eq!(hosts.host_of(a), b"zk1");
            // Two hosts give `b`. The first host wins.
            assert_eq!(hosts.host_of(b), b"zk1");
            let other = SocketAddr::from(([10, 0, 0, 9], 2181));
            assert_eq!(hosts.host_of(other), b"10.0.0.9");
        }
        // A newer generation replaces the entries. An older one does not.
        f.host.set_addrs(b"zk2", vec![a]);
        as_io(&f.h, |s, p, _ob, io| {
            let _ = s.run_inline(p, io, resolve_job(4, b"zk2:2181"));
            let _ = s.run_inline(p, io, resolve_job(2, b"zk1:2181"));
        });
        let hosts = f.h.shared.hosts.lock_owner();
        assert_eq!(hosts.host_of(a), b"zk2");
        assert_eq!(hosts.host_of(b), b"10.0.0.2");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn a_client_with_no_sasl_records_no_hosts() {
        let f = fixture(8, None);
        let a = SocketAddr::from(([10, 0, 0, 1], 2181));
        f.host.set_addrs(b"zk1", vec![a]);
        as_io(&f.h, |s, p, _ob, io| {
            let done = s.run_inline(p, io, resolve_job(3, b"zk1:2181"));
            assert!(matches!(done, JobDone::Resolved { generation: 3, .. }));
        });
        dns_thread(Arc::clone(&f.h.shared), resolve_job(4, b"zk1:2181"));
        assert!(f.h.shared.dns.lock_owner().done.is_some());
        let hosts = f.h.shared.hosts.lock_owner();
        assert!(hosts.entries.is_empty());
        assert_eq!(hosts.generation, None);
        assert_eq!(hosts.host_of(a), b"10.0.0.1");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn a_dns_thread_records_hosts_with_a_mechanism() {
        let a = SocketAddr::from(([10, 0, 0, 1], 2181));
        let f = fixture(8, Some(Box::new(Mech::default())));
        f.host.set_addrs(b"zk1", vec![a]);
        dns_thread(Arc::clone(&f.h.shared), resolve_job(1, b"zk1:2181"));
        let done = f.h.shared.dns.lock_owner().done.take();
        assert!(matches!(
            done,
            Some(JobDone::Resolved { generation: 1, .. })
        ));
        assert_eq!(f.h.shared.hosts.lock_owner().host_of(a), b"zk1");
    }

    #[test]
    fn the_host_list_is_bounded() {
        let names = vec![b"many".to_vec()];
        let addrs: Vec<SocketAddr> = (0..=SASL_HOSTS_MAX)
            .map(|i| SocketAddr::from(([10, 0, 0, 1], u16::try_from(i + 1).unwrap())))
            .collect();
        let last = *addrs.last().unwrap();
        let done = JobDone::Resolved {
            generation: 1,
            results: vec![zk_proto::HostResolution {
                host: 0,
                result: Ok(addrs),
                skipped_families: Vec::new(),
            }],
        };
        let mut hosts = SaslHosts::default();
        hosts.record(&names, &done);
        assert_eq!(hosts.entries.len(), SASL_HOSTS_MAX);
        assert_eq!(hosts.host_of(last), b"10.0.0.1");
        // Another job kind has no host names.
        let job = Job::Probe {
            endpoint: zk_proto::Endpoint {
                addr: last,
                host: zk_proto::HostToken {
                    index: 0,
                    name: b"many".to_vec(),
                },
            },
            tls: None,
        };
        assert!(SaslHosts::names(&job).is_none());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the waker pipe"
    )]
    fn sasl_start_gives_the_connection_to_the_mechanism() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let f = fixture(8, Some(Box::new(ConnMech(Arc::clone(&seen)))));
        let local = SocketAddr::from(([127, 0, 0, 1], 40000));
        let peer = SocketAddr::from(([10, 0, 0, 1], 2181));
        f.host.set_addrs(b"zk1.example", vec![peer]);
        as_io(&f.h, |s, p, ob, io| {
            let _ = s.run_inline(p, io, resolve_job(1, b"zk1.example:2181"));
            for addrs in [Some((local, peer)), None] {
                ob.push(Item::Sasl(SaslItem {
                    call: SaslCall {
                        generation: 1,
                        kind: SaslCallKind::Start,
                    },
                    addrs,
                }));
                s.route(p, ob, io);
            }
        });
        // A START with no addresses gives no connection call.
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(b"zk1.example".to_vec(), local, peer)]
        );
    }
}
