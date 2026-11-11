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

//! The caller-polled drop-in driver of `libzookeeper_st`.
//!
//! The application owns the event loop. It calls `zookeeper_interest`,
//! polls the descriptor, and calls `zookeeper_process`. Each call is one
//! step of [`Polled`]:
//!
//! - [`Polled::interest`] is `zookeeper_interest`;
//! - [`Polled::process`] is `zookeeper_process`;
//! - after `Step::More`: [`Polled::resume`]. The outbox names the step
//!   that it continues (`ResumeAt`).
//!
//! The st FIFO is local: completions wait in `Core::local` until a
//! `DrainPoint` or a session barrier moves them into the outbox. Each
//! `interest` and `process` call holds a lifecycle ref, so a
//! close from a callback defers the final close to the epilog of the
//! outermost call. A callback can start a nested driving call.
//! Each call has its own frame on a stack, and each frame holds its own
//! ref. Thus only the epilog of the last frame can run the final close.
//!
//! Locks: one mutex is enough for st. The driver still uses the `io`
//! lock, then the `core` lock, as the other flavors do. st has one
//! driving thread, so the two locks never contend. A single lock is a
//! possible future change.

use std::net::SocketAddr;
use std::sync::Arc;

use rustix::event::PollFd;
use zk_jute::JString;
use zk_proto::legacy::connect::{HostParseErrorKind, parse_servers};
use zk_proto::rc::{ZINVALIDSTATE, ZOK, ZSYSTEMERROR};
use zk_proto::{
    Action, AddAuthError, ClientId, Connection, HostSpec, LogArg, LogSite, Millis, MultiOpRef,
    Request, SecretBytes, Stage, State, SubmitError, Submitted,
};

use crate::host::{DriverTokens, discard_leftovers, log_record};
use crate::iocore::{DeferPolicy, InterestOut, IoCore, Progress, StepCtx};
use crate::lifecycle::Lifecycle;
use crate::net::poll::{PollEvents, map_revents, request_flags};
use crate::outbox::{
    FifoBound, Flavor, Item, Outbox, Publish, Requeued, ResumeAt, SaslItem, Step, discard_item,
    pump,
};
use crate::resolve::{SetServersEnd, SetServersRun, adopt_set_servers};
use crate::state::{
    Core, Env, SaslAnswer, SubmitResult, read_at_entry, read_conn, with_conn_at_entry,
};
use crate::sync::{Mutex, Unlocked};

/// The upper limit of the pump passes in one close stage. The nested
/// close counts only the passes that resume a stopped stage. A pump
/// drains every output that is not parked. After `destroy` proto parks
/// nothing, so one or two passes are usual. The limit stops a defect
/// from looping for ever.
const PUMP_PASSES: usize = 64;

/// The upper limit of the `poll_action` calls in the release stage.
/// After `destroy` proto gives only `CloseTransport` and `Sasl(Dispose)`.
const RELEASE_ACTIONS: usize = 16;

/// The progress of an st close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StClose {
    /// No close runs.
    Idle,
    /// A close from a callback is recorded. The epilog of the driving
    /// call runs the final close.
    Deferred,
    /// The "Closing" line is out. The flush and wait come next.
    Flush,
    /// `destroy` ran and its items are out. `Release` comes next.
    Release,
}

/// The stage of the driving call in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StPhase {
    /// No driving call is in progress.
    Idle,
    /// The `iocore` step stopped at a barrier. The resume continues it.
    Step(ResumeAt),
    /// The step is complete and its items are out. The resume runs the
    /// epilog after the callbacks of these items.
    Drain(ResumeAt),
}

/// The own step of a driving call that waits for a stopped stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NewStep {
    /// The interest step of `zookeeper_interest`.
    Interest,
    /// The process step of `zookeeper_process`, with its events.
    Process(u32),
}

/// One driving call in progress.
///
/// A frame holds one lifecycle ref from its prolog to its epilog. The
/// ref stays across the `More` returns, so a close from a callback
/// defers. The outbox of the call names its frame, so a resume and a
/// requeue find the state of the correct call.
#[derive(Clone, Copy, Debug)]
struct Frame {
    /// The identity that the outbox of the call carries.
    id: u64,
    /// The stage of the call.
    phase: StPhase,
    /// The own step of a call that completes a stopped stage of another
    /// call first. The epilog of that stage starts this step.
    next: Option<NewStep>,
    /// The rc of the call.
    rc: i32,
    /// The errno that C sets after the call, or 0.
    errno: i32,
    /// True after a callback threw out of the call. The C
    /// frame of the call is gone, so no resume follows.
    abandoned: bool,
}

/// The IO-owner state of an st handle.
pub(crate) struct StIo {
    /// The transport and the step continuation.
    pub(crate) io: IoCore,
    /// The progress of the close.
    pub(crate) close: StClose,
    /// The rc of the driving call that ended last.
    pub(crate) last_rc: i32,
    /// The errno of the driving call that ended last.
    errno: i32,
    /// The driving calls in progress. The last frame is the innermost
    /// call. Frames below it wait in C for a nested call to return.
    frames: Vec<Frame>,
    /// The identity of the next frame.
    serial: u64,
    /// The kind of the driving call whose `IoCore` stage stopped at a
    /// barrier, while the stage stays stopped.
    stage: Option<ResumeAt>,
    /// True when a close from a callback added items to the local FIFO.
    /// The next resume delivers them before other work.
    refill: bool,
    /// True when the final close flushes the CLOSE_OP frame.
    flush: bool,
    /// The rc of the close flush and wait.
    close_rc: i32,
    /// The driving call that runs the final close in its epilog, or
    /// `None` when `close` runs it.
    owner: Option<ResumeAt>,
    /// True after the release stage.
    released: bool,
}

impl StIo {
    /// Makes the state of a new handle.
    fn new() -> Self {
        Self {
            io: IoCore::new(),
            close: StClose::Idle,
            last_rc: ZOK,
            errno: 0,
            frames: Vec::new(),
            serial: 0,
            stage: None,
            refill: false,
            flush: false,
            close_rc: ZOK,
            owner: None,
            released: false,
        }
    }

    /// Returns the frame of the innermost driving call.
    fn top(&mut self) -> Option<&mut Frame> {
        self.frames.last_mut()
    }
}

/// Collects the FIFO-bound items of a close from a callback.
///
/// The close pumps with the mt rule into an outbox that publishes here.
/// So the FIFO-bound items stay apart from the items that C runs inline,
/// and no drain point moves the local FIFO into the outbox of the close.
struct StCollect<T: DriverTokens> {
    items: Mutex<Vec<Item<T>>>,
}

impl<T: DriverTokens> Publish<T> for StCollect<T> {
    fn publish(&self, item: Item<T>) {
        self.items.lock_owner().push(item);
    }
}

/// One `libzookeeper_st` handle.
pub struct Polled<T: DriverTokens> {
    pub(crate) io: Mutex<StIo>,
    pub(crate) core: Mutex<Core<T>>,
    pub(crate) life: Lifecycle,
    pub(crate) env: Env<T>,
}

impl<T: DriverTokens> Polled<T> {
    /// Makes the handle after `Init` gave `Ready`. st has no waker and no
    /// threads, so it cannot fail.
    pub(crate) fn new(core: Core<T>, env: Env<T>) -> Self {
        Self {
            io: Mutex::new(StIo::new()),
            core: Mutex::new(core),
            life: Lifecycle::new(),
            env,
        }
    }

    /// Makes the handle from a ready init.
    #[must_use]
    pub fn from_init(init: crate::init::Init<T>) -> Self {
        let (core, env) = init.into_parts();
        Self::new(core, env)
    }

    /// Makes an outbox for one driving call. st never publishes.
    #[must_use]
    pub fn outbox(&self) -> Outbox<T> {
        Outbox::new()
    }

    /// `zookeeper_interest`.
    ///
    /// `prolog`, then `IoCore::interest_step` with `Flavor::St` and
    /// `DeferPolicy::NONE`. A barrier sets `ResumeAt::Interest` and gives
    /// `More`; `out` stays unwritten until the call that reaches
    /// `finish_interest`. The last call runs the epilog: a deferred
    /// close runs the final close there (`More`, then `Release`).
    pub fn interest(&self, ob: &mut Outbox<T>, out: &mut InterestOut, rc: &mut i32) -> Step {
        let mut st = self.io.lock_owner();
        self.st_begin(&mut st, NewStep::Interest, ob, Some(out), rc)
    }

    /// `zookeeper_process`.
    ///
    /// `events` holds the `ZOOKEEPER_READ` and `ZOOKEEPER_WRITE` bits of
    /// C. A plaintext read takes `read_hint()` bytes. A barrier
    /// sets `ResumeAt::Process` and gives `More`.
    pub fn process(&self, events: u32, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let mut st = self.io.lock_owner();
        self.st_begin(&mut st, NewStep::Process(events), ob, None, rc)
    }

    /// `zkrs_resume` and `zkrs_interest_resume`: continues the step that
    /// `ob` names. `out` is written only by an interest continuation.
    ///
    /// The frame id in `ob` selects the driving call. The frames above it
    /// belong to nested calls that a thrown callback abandoned, so their
    /// refs go back first.
    pub fn resume(&self, ob: &mut Outbox<T>, out: &mut InterestOut, rc: &mut i32) -> Step {
        // A `zoo_set_servers` run has its own stage. For the other steps
        // the frame state names the stage, and the outbox value is a
        // hint.
        let tag = ob.take_resume();
        if let Some(ResumeAt::SetServers(id)) = tag {
            return self.set_servers_resume(id, ob, rc);
        }
        let mut st = self.io.lock_owner();
        if st.released {
            *rc = Self::st_release_rc(&st);
            return Step::Release;
        }
        match st.close {
            StClose::Flush => return self.st_final_flush(&mut st, ob, Some(out), rc),
            StClose::Release => return self.st_final_release(&mut st, ob, Some(out), rc),
            StClose::Idle | StClose::Deferred => {}
        }
        let found = match ob.frame() {
            Some(id) => st.frames.iter().position(|f| f.id == id),
            None => st.frames.len().checked_sub(1),
        };
        let Some(index) = found else {
            // No driving call owns this outbox. Its call ended already.
            *rc = st.last_rc;
            return Step::Done(st.last_rc);
        };
        self.st_pop_from(&mut st, index.saturating_add(1));
        let fallback = match tag {
            Some(at @ (ResumeAt::Interest | ResumeAt::Process)) => at,
            _ => ResumeAt::Process,
        };
        let phase = st.top().map_or(StPhase::Idle, |f| f.phase);
        if st.refill {
            st.refill = false;
            let mut proof = Unlocked::new_at_entry();
            let mut core = self.core.lock(&mut proof);
            if !core.local.is_empty() {
                ob.extend_items(core.local.drain(..));
                let at = match phase {
                    StPhase::Step(at) | StPhase::Drain(at) => at,
                    StPhase::Idle => fallback,
                };
                ob.set_resume(at);
                return Step::More;
            }
        }
        match phase {
            StPhase::Step(at) if st.io.is_suspended() => {
                let mut proof = Unlocked::new_at_entry();
                let cx = self.st_ctx();
                let p = st.io.resume(&cx, &mut proof, ob, out);
                self.st_after_step(&mut st, at, p, ob, Some(out), rc)
            }
            StPhase::Step(at) | StPhase::Drain(at) => {
                self.st_epilog(&mut st, at, ob, Some(out), rc)
            }
            StPhase::Idle => self.st_epilog(&mut st, fallback, ob, Some(out), rc),
        }
    }

    /// The errno of the driving call that ended last, or 0.
    ///
    /// The shim reads it after the last step of `zookeeper_interest` or
    /// `zookeeper_process` and sets `errno` from it.
    #[must_use]
    pub fn last_errno(&self) -> i32 {
        self.io.lock_owner().errno
    }

    /// Submits one request, then runs one non-blocking flush pass
    /// (`IoCore::flush_once`).
    ///
    /// A failed send is a forced close: `handle_forced_close`, the
    /// transport drop and the pump into `ob`. After a close request the
    /// core gives ZMARSHALLINGERROR, as C does.
    ///
    /// # Errors
    ///
    /// Returns the proto submit error with its token.
    pub fn submit(
        &self,
        req: Request<T>,
        ob: &mut Outbox<T>,
    ) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_with_data(req, None, ob)
    }

    /// Submits one request whose data is borrowed, as
    /// `Connection::submit_with_data` tells. The flush and the close
    /// rules are those of [`Self::submit`].
    ///
    /// # Errors
    ///
    /// Returns the proto submit error with its token.
    pub fn submit_with_data(
        &self,
        req: Request<T>,
        data: Option<&[u8]>,
        ob: &mut Outbox<T>,
    ) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_by(req, ob, |c, r, now| c.submit_with_data(r, data, now))
    }

    /// Submits one write multi whose sub-ops are borrowed, as
    /// `Connection::submit_multi_ref` tells. The flush and the close
    /// rules are those of [`Self::submit`].
    ///
    /// # Errors
    ///
    /// Returns the proto submit error with its token.
    pub fn submit_multi_ref(
        &self,
        req: Request<T>,
        ops: &[MultiOpRef<'_>],
        ob: &mut Outbox<T>,
    ) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_by(req, ob, |c, r, now| c.submit_multi_ref(r, ops, now))
    }

    /// Submits one request through `send` under the core lock, then runs
    /// the flush pass of [`Self::submit`].
    fn submit_by(
        &self,
        req: Request<T>,
        ob: &mut Outbox<T>,
        send: impl FnOnce(&mut Connection<T>, Request<T>, Millis) -> SubmitResult<T>,
    ) -> SubmitResult<T> {
        let mut st = self.io.lock_owner();
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let res = {
            let mut core = self.core.lock(&mut proof);
            let Some(conn) = core.conn.as_deref_mut() else {
                return Err(SubmitError {
                    stage: Stage::Validate,
                    code: ZINVALIDSTATE,
                    token: req.token,
                });
            };
            let res = send(conn, req, now);
            core.pump(Self::FLAVOR, ob, &*self.env.host);
            res
        };
        // C flushes after every submit that reaches the serialization
        // stage, whatever its rc is.
        let flush = match &res {
            Ok(Submitted::Queued { .. }) => true,
            Ok(Submitted::Local(_)) => false,
            Err(e) => e.stage == Stage::Enqueue,
        };
        if flush && st.io.has_socket() {
            let cx = self.st_ctx();
            if !st.io.flush_once(&cx, &mut proof) {
                self.st_forced_close(&mut st, &mut proof, ob, now);
            }
        }
        res
    }

    /// `zoo_add_auth`: records the entry. The next interest call sends
    /// it.
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
        self.core.lock(&mut Unlocked::new_at_entry()).add_auth_or(
            scheme,
            cred,
            done,
            now,
            ZINVALIDSTATE,
        )
    }

    /// `zoo_set_servers`: parses the list, gives it to proto and resolves
    /// it. A rebalance is a forced close.
    ///
    /// The per-host loop gives `More` before each blocking leaf when LOG
    /// items wait, and at each barrier. The resume entry
    /// continues it. `Done` has the C rc.
    pub fn set_servers(&self, hosts: &[u8], ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let host = &*self.env.host;
        let parsed = match parse_servers(hosts) {
            Ok(parsed) => parsed,
            Err(e) => {
                // A parse error changes nothing. Only the port errors
                // have a C log line.
                let site = match e.kind {
                    HostParseErrorKind::NoPort => Some(LogSite::ResolveNoPort),
                    HostParseErrorKind::InvalidPort => Some(LogSite::ResolveBadPort),
                    HostParseErrorKind::Empty
                    | HostParseErrorKind::InvalidChroot
                    | HostParseErrorKind::NoHosts => None,
                };
                if let Some(site) = site {
                    let args = vec![LogArg::Str(JString::Bytes(e.subject))];
                    if let Some(rec) = log_record(host, site, args) {
                        ob.push(Item::Log(rec));
                    }
                }
                *rc = e.rc;
                return Step::Done(e.rc);
            }
        };
        let specs: Vec<HostSpec> = parsed.into_iter().map(HostSpec::Legacy).collect();
        let mut st = self.io.lock_owner();
        let cx = self.env.resolve_ctx(&self.core, Self::FLAVOR);
        let mut proof = Unlocked::new_at_entry();
        let end = SetServersRun::start(&cx, &mut proof, ob, specs);
        self.set_servers_end(&mut st, end, ob, rc)
    }

    /// Continues a stopped `zoo_set_servers` call.
    fn set_servers_resume(&self, id: u64, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let mut st = self.io.lock_owner();
        let cx = self.env.resolve_ctx(&self.core, Self::FLAVOR);
        let mut proof = Unlocked::new_at_entry();
        let end = SetServersRun::resume(&cx, &mut proof, ob, id);
        self.set_servers_end(&mut st, end, ob, rc)
    }

    /// Ends one segment of `zoo_set_servers`.
    ///
    /// A rebalance ends the transport in proto. The caller owns the
    /// socket, so the socket closes now. The next driving call
    /// delivers the outputs of the forced close.
    fn set_servers_end(
        &self,
        st: &mut StIo,
        end: SetServersEnd,
        ob: &mut Outbox<T>,
        rc: &mut i32,
    ) -> Step {
        match end {
            SetServersEnd::More(id) => {
                ob.set_resume(ResumeAt::SetServers(id));
                Step::More
            }
            SetServersEnd::Done { rc: code, lost } => {
                if lost {
                    let mut proof = Unlocked::new_at_entry();
                    self.core.lock(&mut proof).peer = None;
                    st.io.drop_transport();
                }
                *rc = code;
                Step::Done(code)
            }
        }
    }

    /// `zookeeper_close`.
    ///
    /// - A close from a callback (refs > 0): `begin_close`, the pump, and
    ///   `StClose::Deferred`. The epilog of the driving call runs the
    ///   final close.
    /// - Else: the final close in this call, as in mt: the
    ///   "Closing" line, `More`, `IoCore::close_flush`, the "Freeing"
    ///   line, `destroy`, the local FIFO and the leftovers to
    ///   `discard_token`, then `Release` with the close rc.
    ///
    /// With no socket, the final close skips `close_flush` and the rc is
    /// `ZOK` (zookeeper.c `zookeeper_close`).
    ///
    /// st has no fork rule. The legacy st close has no pid check, so a
    /// forked child runs the full close as any other caller does.
    pub fn close(&self, ob: &mut Outbox<T>, rc: &mut i32) -> Step {
        let mut st = self.io.lock_owner();
        // The count comes from the close prolog, before the request is
        // public (zookeeper.c `zookeeper_close`). The refs of abandoned
        // calls go back first, because no epilog of theirs follows.
        let refs = self.life.prolog();
        let refs = refs.saturating_sub(self.st_pop_abandoned(&mut st));
        if !self.life.request_close() {
            let last = self.life.epilog();
            // A deferred close waits for an epilog. When a thrown callback
            // abandoned every driving call, this close runs it.
            if last && st.close == StClose::Deferred && self.life.begin_final() {
                st.owner = None;
                return self.st_final_start(&mut st, ob, None, rc);
            }
            // A callback threw in the final close, so its stage lost the
            // resume. This call continues it.
            let orphan = {
                let mut proof = Unlocked::new_at_entry();
                let mut core = self.core.lock(&mut proof);
                let at = core.orphan_close.take();
                if at.is_some() {
                    let _ = core.restore_requeued(ob);
                }
                at
            };
            if orphan.is_some() {
                match st.close {
                    StClose::Flush => return self.st_final_flush(&mut st, ob, None, rc),
                    StClose::Release => return self.st_final_release(&mut st, ob, None, rc),
                    StClose::Idle | StClose::Deferred => {}
                }
            }
            // A second close does nothing. C can deadlock here.
            *rc = ZOK;
            return Step::Done(ZOK);
        }
        if refs > 1 {
            self.st_close_nested(&mut st, ob);
            st.close = StClose::Deferred;
            let _ = self.life.epilog();
            *rc = ZOK;
            return Step::Done(ZOK);
        }
        if !self.life.begin_final() {
            *rc = ZOK;
            return Step::Done(ZOK);
        }
        st.owner = None;
        self.st_final_start(&mut st, ob, None, rc)
    }

    /// Polls the socket of the handle for the bits of `out`, for at most
    /// `timeout_ms`. It returns the ready bits in the `ZOOKEEPER_READ` and
    /// `ZOOKEEPER_WRITE` form, or 0 with no socket.
    ///
    /// The tests and tools use it in place of the poll of the
    /// application. zk-ffi does not use it. It polls through
    /// `Env::poll` under the `io` lock, which is safe because st has one
    /// driving thread.
    #[must_use]
    pub fn wait_events(&self, out: &InterestOut, timeout_ms: i32) -> u32 {
        let st = self.io.lock_owner();
        let Some(sock) = st.io.conn.sock() else {
            return 0;
        };
        let flags = request_flags(PollEvents::from_bits(out.bits));
        let mut fds = [PollFd::new(sock, flags)];
        match self.env.poll.poll(&mut fds, timeout_ms) {
            Ok(_) => fds.first().map_or(0, |fd| map_revents(fd.revents()).bits()),
            Err(_) => 0,
        }
    }

    /// `zkrs_sasl_result`: stores the answer of C. The next resume gives
    /// it to proto.
    pub fn sasl_result(&self, answer: SaslAnswer) {
        let mut proof = Unlocked::new_at_entry();
        self.core.lock(&mut proof).sasl = Some(answer);
    }

    /// `zkrs_outbox_requeue`: stores the untaken items.
    ///
    /// The requeued outbox can name a stopped stage that no call resumes
    /// now. A final close waits for the next close call of the
    /// application. The next interest step resolves a `zoo_set_servers`
    /// list again.
    pub fn requeue(&self, rest: Requeued<T>) {
        let mut st = self.io.lock_owner();
        // The C frame of this call is gone, so no resume or epilog of it
        // follows. The next entry gives its ref back.
        if let Some(id) = rest.frame() {
            if let Some(f) = st.frames.iter_mut().find(|f| f.id == id) {
                f.abandoned = true;
            }
        }
        drop(st);
        let mut proof = Unlocked::new_at_entry();
        let mut core = self.core.lock(&mut proof);
        match rest.resume_at() {
            Some(ResumeAt::FinalClose) => core.orphan_close = Some(ResumeAt::FinalClose),
            Some(ResumeAt::SetServers(id)) => adopt_set_servers(&mut core, id),
            _ => {}
        }
        if rest.is_empty() {
            return;
        }
        let merged = match core.requeued.take() {
            // Older items stay in front of newer items.
            Some(older) => {
                let mut ob = Outbox::new();
                ob.restore(rest);
                ob.restore(older);
                ob.requeue()
            }
            None => rest,
        };
        core.requeued = Some(merged);
    }

    /// `zkrs_peer_addr`: the peer of the current transport.
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        let mut proof = Unlocked::new_at_entry();
        // zkrs_peer_addr succeeds only in state 3.
        let connected =
            read_conn(&self.core, &mut proof, |c| c.state() == State::Connected).unwrap_or(false);
        if !connected {
            return None;
        }
        match self.io.try_lock() {
            Some(st) => st.io.conn.sock().and_then(|s| s.peer_addr().ok()),
            None => self.core.lock(&mut proof).peer,
        }
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

    /// Runs `f` on the connection under the core lock. It returns `None`
    /// after the final close.
    ///
    /// zk-ffi uses it for `zoo_set_servers_resolution_delay` and
    /// `zoo_cycle_next_server`. st has no IO thread to wake. The
    /// next driving call of the application routes the outputs of `f`.
    /// `f` must not block, and it must not call into the handle.
    pub fn with_conn<R>(&self, f: impl FnOnce(&mut Connection<T>, Millis) -> R) -> Option<R> {
        with_conn_at_entry(&self.core, self.env.clock.now(), f)
    }

    /// The defer policy of the drop-in: every blocking call inline.
    pub(crate) const DEFER: DeferPolicy = DeferPolicy::NONE;

    /// The pump flavor.
    pub(crate) const FLAVOR: Flavor = Flavor::St;

    /// Makes the step services of the drop-in: no waker and no read gate.
    /// The close flag stops a connect after a close from a callback.
    fn st_ctx(&self) -> StepCtx<'_, T> {
        self.env.step_ctx(
            &self.core,
            Self::FLAVOR,
            Self::DEFER,
            None,
            Some(self.life.close_flag()),
            None,
        )
    }

    /// Starts a driving call. It returns a step when the handle cannot
    /// drive, because the final close runs or ran.
    ///
    /// Each call takes its own ref and pushes its own frame, so a nested
    /// call never ends the ref of the call that runs its callback. The
    /// refs of abandoned calls go back here. The prolog comes
    /// first, so these epilogs never run the final close. It also
    /// returns the stage that another call stopped in, if any.
    fn st_enter(
        &self,
        st: &mut StIo,
        ob: &mut Outbox<T>,
        rc: &mut i32,
    ) -> Result<Option<ResumeAt>, Step> {
        let mut proof = Unlocked::new_at_entry();
        let finished = matches!(st.close, StClose::Flush | StClose::Release) || st.released;
        if finished || read_conn(&self.core, &mut proof, |_| ()).is_none() {
            *rc = ZINVALIDSTATE;
            return Err(Step::Done(ZINVALIDSTATE));
        }
        self.life.prolog();
        let _ = self.st_pop_abandoned(st);
        let stopped = if st.io.is_suspended() { st.stage } else { None };
        if st.frames.is_empty() {
            st.refill = false;
        }
        let id = st.serial;
        st.serial = st.serial.wrapping_add(1);
        st.frames.push(Frame {
            id,
            phase: StPhase::Idle,
            next: None,
            rc: ZOK,
            errno: 0,
            abandoned: false,
        });
        ob.set_frame(id);
        Ok(stopped)
    }

    /// Removes the frames from the lowest abandoned frame to the top. It
    /// returns the number of refs that went back.
    ///
    /// A frame above an abandoned frame is abandoned too, because its C
    /// frame is nested in the C frame that unwound.
    fn st_pop_abandoned(&self, st: &mut StIo) -> u32 {
        match st.frames.iter().position(|f| f.abandoned) {
            Some(index) => self.st_pop_from(st, index),
            None => 0,
        }
    }

    /// Removes the frames from `index` to the top, with one epilog for
    /// each frame. It returns the number of frames removed.
    ///
    /// The caller holds a ref of its own, so no epilog here is the last.
    fn st_pop_from(&self, st: &mut StIo, index: usize) -> u32 {
        let mut count = 0_u32;
        while st.frames.len() > index {
            st.frames.pop();
            let _ = self.life.epilog();
            count = count.saturating_add(1);
        }
        count
    }

    /// Starts the step of an interest or process call.
    ///
    /// A callback that unwinds out of a driving call leaves its stage
    /// stopped in `IoCore`. The next driving call completes
    /// that stage first, and its epilog then starts the own step of the
    /// call. A nested driving call does the same with the stage of the
    /// call that runs its callback.
    fn st_begin(
        &self,
        st: &mut StIo,
        next: NewStep,
        ob: &mut Outbox<T>,
        out: Option<&mut InterestOut>,
        rc: &mut i32,
    ) -> Step {
        let stopped = match self.st_enter(st, ob, rc) {
            Ok(stopped) => stopped,
            Err(step) => return step,
        };
        let Some(at) = stopped else {
            return self.st_start(st, next, ob, out, rc);
        };
        if let Some(top) = st.top() {
            top.next = Some(next);
            top.phase = StPhase::Step(at);
        }
        let mut scratch = InterestOut::UNWRITTEN;
        let o = match out {
            Some(o) => o,
            None => &mut scratch,
        };
        let mut proof = Unlocked::new_at_entry();
        let cx = self.st_ctx();
        let p = st.io.resume(&cx, &mut proof, ob, o);
        self.st_after_step(st, at, p, ob, Some(o), rc)
    }

    /// Runs the own step of an interest or process call.
    ///
    /// An errno from an earlier failure is stale here, so the step starts
    /// with no errno.
    fn st_start(
        &self,
        st: &mut StIo,
        next: NewStep,
        ob: &mut Outbox<T>,
        out: Option<&mut InterestOut>,
        rc: &mut i32,
    ) -> Step {
        let mut proof = Unlocked::new_at_entry();
        {
            let mut core = self.core.lock(&mut proof);
            if let Some(conn) = core.conn.as_deref_mut() {
                let _ = conn.take_errno_hint();
            }
        }
        let _ = st.io.take_errno();
        if let Some(top) = st.top() {
            top.errno = 0;
        }
        let cx = self.st_ctx();
        match next {
            NewStep::Interest => {
                let mut scratch = InterestOut::UNWRITTEN;
                let o = match out {
                    Some(o) => o,
                    None => &mut scratch,
                };
                let p = st.io.interest_step(&cx, &mut proof, ob, o);
                self.st_after_step(st, ResumeAt::Interest, p, ob, Some(o), rc)
            }
            NewStep::Process(events) => {
                let p = st
                    .io
                    .process_step(&cx, &mut proof, PollEvents::from_bits(events), ob);
                self.st_after_step(st, ResumeAt::Process, p, ob, None, rc)
            }
        }
    }

    /// Ends one step call of a driving call.
    ///
    /// The ref stays while C runs the callbacks of the items. So a close
    /// from such a callback defers to the epilog of this call.
    /// A completed stage also completes every outer call that waits for
    /// it. Each of these calls gets the rc and runs its epilog at its
    /// resume.
    fn st_after_step(
        &self,
        st: &mut StIo,
        at: ResumeAt,
        progress: Progress,
        ob: &mut Outbox<T>,
        out: Option<&mut InterestOut>,
        rc: &mut i32,
    ) -> Step {
        let done = match progress {
            Progress::More => {
                st.stage = Some(at);
                if let Some(top) = st.top() {
                    top.phase = StPhase::Step(at);
                }
                ob.set_resume(at);
                return Step::More;
            }
            Progress::Done(r) => r,
            // The drop-in defers no job, so no step waits.
            Progress::Wait => ZSYSTEMERROR,
        };
        st.stage = None;
        let errno = if done == ZOK {
            0
        } else {
            self.st_failure_errno(st)
        };
        let waiting = st.frames.len().saturating_sub(1);
        for f in st.frames.iter_mut().take(waiting) {
            if let StPhase::Step(a) = f.phase {
                f.phase = StPhase::Drain(a);
                f.rc = done;
                f.errno = errno;
            }
        }
        if let Some(top) = st.top() {
            top.rc = done;
            if done != ZOK {
                top.errno = errno;
            }
        }
        *rc = done;
        if at == ResumeAt::Process {
            // The end of zookeeper_process is a drain point.
            let mut proof = Unlocked::new_at_entry();
            let mut core = self.core.lock(&mut proof);
            ob.extend_items(core.local.drain(..));
        }
        if !ob.is_empty() {
            if let Some(top) = st.top() {
                top.phase = StPhase::Drain(at);
            }
            ob.set_resume(at);
            return Step::More;
        }
        self.st_epilog(st, at, ob, out, rc)
    }

    /// The errno of a failed step, or 0.
    ///
    /// A protocol cause (session expiry, a timeout, a DNS failure) comes
    /// first. Else the socket errno of the failed transport is the cause.
    fn st_failure_errno(&self, st: &mut StIo) -> i32 {
        let mut proof = Unlocked::new_at_entry();
        let hint = {
            let mut core = self.core.lock(&mut proof);
            core.conn
                .as_deref_mut()
                .and_then(zk_proto::Connection::take_errno_hint)
        };
        let io = st.io.take_errno();
        hint.or(io).unwrap_or(0)
    }

    /// The epilog of a driving call (`api_epilog`). The last ref after a
    /// close request runs the final close in this call.
    fn st_epilog(
        &self,
        st: &mut StIo,
        at: ResumeAt,
        ob: &mut Outbox<T>,
        out: Option<&mut InterestOut>,
        rc: &mut i32,
    ) -> Step {
        let next = st.top().and_then(|top| {
            top.phase = StPhase::Idle;
            top.next.take()
        });
        if let Some(next) = next {
            // The stopped stage of another call is complete. The own step
            // of this call comes next, under the same ref.
            return self.st_start(st, next, ob, out, rc);
        }
        let mut last = false;
        if let Some(frame) = st.frames.pop() {
            st.last_rc = frame.rc;
            st.errno = frame.errno;
            last = self.life.epilog();
        }
        *rc = st.last_rc;
        if last && self.life.begin_final() {
            st.owner = Some(at);
            return self.st_final_start(st, ob, out, rc);
        }
        Step::Done(st.last_rc)
    }

    /// The close from a callback (zookeeper.c `zookeeper_close` with
    /// refs > 1).
    ///
    /// The close job runs to its end here, so the stopped stage of the
    /// driving call stays in its slot. The auth results go to `ob`, as C
    /// calls them inline. The ZCLOSING results go to the tail of the
    /// local FIFO. The driving call delivers them after the current
    /// callback returns.
    fn st_close_nested(&self, st: &mut StIo, ob: &mut Outbox<T>) {
        let host = &*self.env.host;
        let now = self.env.clock.now();
        let collect = Arc::new(StCollect {
            items: Mutex::new(Vec::new()),
        });
        let publish: Arc<dyn Publish<T>> = collect.clone();
        let mut tmp = Outbox::with_publish(publish);
        let mut proof = Unlocked::new_at_entry();
        let mut core = self.core.lock(&mut proof);
        let outer = core.stopped.take();
        if let Some(conn) = core.conn.as_deref_mut() {
            conn.begin_close(now);
        }
        // The mt pump also stops after an item when more outputs wait.
        // The loop empties `tmp` before each pump, so each such pump takes
        // at least one output. Thus only the resumes of a stopped stage
        // count against the limit.
        let mut passes = 0;
        while passes < PUMP_PASSES {
            let barrier = core.pump(Flavor::Mt, &mut tmp, host);
            while let Some(item) = tmp.pop() {
                ob.push(item);
            }
            if core.stopped.is_some() {
                passes = passes.saturating_add(1);
                core.resume_stopped(now);
            } else if !barrier {
                break;
            }
        }
        // A defect can leave a stage stopped. It must not take the slot
        // of the driving call.
        core.stopped = outer;
        let items = std::mem::take(&mut *collect.items.lock_owner());
        if !items.is_empty() {
            core.local.extend(items);
            st.refill = true;
        }
    }

    /// The forced close of a failed send. The caller owns the
    /// socket, so it drops the transport now. The next driving call
    /// delivers the results.
    fn st_forced_close(
        &self,
        st: &mut StIo,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        now: Millis,
    ) {
        let mut core = self.core.lock(proof);
        if let Some(conn) = core.conn.as_deref_mut() {
            conn.handle_forced_close(now);
        }
        core.pump(Self::FLAVOR, ob, &*self.env.host);
        core.peer = None;
        drop(core);
        st.io.drop_transport();
    }

    /// The first stage of the final close: the CLOSE_OP frame and the
    /// "Closing" line (zookeeper.c `zookeeper_close`).
    fn st_final_start(
        &self,
        st: &mut StIo,
        ob: &mut Outbox<T>,
        out: Option<&mut InterestOut>,
        rc: &mut i32,
    ) -> Step {
        let host = &*self.env.host;
        let mut proof = Unlocked::new_at_entry();
        {
            let mut core = self.core.lock(&mut proof);
            // Items that a thrown callback left come first.
            let _ = core.restore_requeued(ob);
            let mut flush = false;
            if let Some(conn) = core.conn.as_deref_mut() {
                flush = conn.queue_close_op() && st.io.has_socket();
                if flush {
                    let id = session_ptr(conn.client_id().session_id);
                    let args = vec![LogArg::Ptr(id), LogArg::Endpoint(conn.current_server())];
                    if let Some(rec) = log_record(host, LogSite::Closing, args) {
                        ob.push(Item::Log(rec));
                    }
                }
            }
            st.flush = flush;
        }
        st.close = StClose::Flush;
        if !ob.is_empty() {
            ob.set_resume(ResumeAt::FinalClose);
            return Step::More;
        }
        self.st_final_flush(st, ob, out, rc)
    }

    /// The second stage of the final close: the flush and wait, the
    /// "Freeing" line and `destroy`.
    ///
    /// The `destroy` outputs follow the C order: the auth
    /// results, then the ZCLOSING results of the local FIFO.
    fn st_final_flush(
        &self,
        st: &mut StIo,
        ob: &mut Outbox<T>,
        out: Option<&mut InterestOut>,
        rc: &mut i32,
    ) -> Step {
        let host = &*self.env.host;
        let mut proof = Unlocked::new_at_entry();
        st.close_rc = if st.flush {
            let cx = self.st_ctx();
            st.io.close_flush(&cx, &mut proof, ob)
        } else {
            ZOK
        };
        let now = self.env.clock.now();
        {
            let mut core = self.core.lock(&mut proof);
            // Older outputs go out before the "Freeing" line.
            let _ = core.pump(Self::FLAVOR, ob, host);
            if let Some(conn) = core.conn.as_deref_mut() {
                let id = session_ptr(conn.client_id().session_id);
                if let Some(rec) = log_record(host, LogSite::Freeing, vec![LogArg::Ptr(id)]) {
                    ob.push(Item::Log(rec));
                }
                conn.destroy(now);
            }
            // `destroy` ends every stopped stage.
            core.stopped = None;
            for _ in 0..PUMP_PASSES {
                if !core.pump(Self::FLAVOR, ob, host) {
                    break;
                }
            }
            ob.extend_items(core.local.drain(..));
        }
        st.close = StClose::Release;
        if !ob.is_empty() {
            ob.set_resume(ResumeAt::FinalClose);
            return Step::More;
        }
        self.st_final_release(st, ob, out, rc)
    }

    /// The last stage of the final close: the transport drop, the SASL
    /// `Dispose` and the release.
    ///
    /// Every token that C did not get goes to `discard_token`, so no
    /// sync waiter can hang.
    fn st_final_release(
        &self,
        st: &mut StIo,
        ob: &mut Outbox<T>,
        out: Option<&mut InterestOut>,
        rc: &mut i32,
    ) -> Step {
        let host = &*self.env.host;
        let now = self.env.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let (conn, local, requeued) = {
            let mut core = self.core.lock(&mut proof);
            let _ = core.pump(Self::FLAVOR, ob, host);
            core.peer = None;
            core.stopped = None;
            core.sasl = None;
            let local: Vec<Item<T>> = core.local.drain(..).collect();
            (core.conn.take(), local, core.requeued.take())
        };
        if let Some(mut conn) = conn {
            for _ in 0..RELEASE_ACTIONS {
                match conn.poll_action(now) {
                    Some(Action::CloseTransport) => st.io.drop_transport(),
                    Some(Action::Sasl(call)) => ob.push(Item::Sasl(SaslItem { call, addrs: None })),
                    Some(
                        Action::Resolve { .. } | Action::Connect { .. } | Action::ProbeRw { .. },
                    ) => {}
                    None => break,
                }
            }
            let _ = pump(&mut conn, ob, FifoBound::Inline, host);
            discard_leftovers(host, conn);
        }
        for item in local {
            discard_item(host, item);
        }
        if let Some(r) = requeued {
            let mut tmp = Outbox::new();
            tmp.restore(r);
            tmp.finish(host);
        }
        st.io.drop_transport();
        st.released = true;
        *rc = Self::st_release_rc(st);
        if st.owner == Some(ResumeAt::Interest) {
            // This call closed the socket, so C sees no descriptor.
            if let Some(o) = out {
                if o.written {
                    o.fd = -1;
                    o.bits = 0;
                    o.timeout_ms = 0;
                }
            }
        }
        Step::Release
    }

    /// The rc of the call that releases. A close call gives the close
    /// rc. A driving call keeps its own rc, as C does.
    fn st_release_rc(st: &StIo) -> i32 {
        match st.owner {
            Some(_) => st.last_rc,
            None => st.close_rc,
        }
    }
}

/// Converts a session id to the `%#llx` argument with no change of bits.
fn session_ptr(id: i64) -> u64 {
    u64::from_ne_bytes(id.to_ne_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::host::HostLeaves;
    use crate::testutil::{TestHost, exists_request, test_connection};
    use zk_proto::rc::{ZBADARGUMENTS, ZCLOSING, ZNOTHING};
    use zk_proto::{DriverMode, LogLevel, PathIn, SaslError};
    use zk_testkit::tokens::{AuthId, TestTokens};

    fn polled(host: &Arc<TestHost>) -> Polled<TestTokens> {
        let core = Core::new(Box::new(test_connection(DriverMode::ST)));
        let leaves: Arc<dyn HostLeaves<TestTokens>> = host.clone();
        Polled::new(core, Env::new(leaves))
    }

    fn exists(id: u64) -> Request<TestTokens> {
        exists_request(PathIn::Legacy(Some(b"/".to_vec())), id)
    }

    fn drain(ob: &mut Outbox<TestTokens>) -> Vec<Item<TestTokens>> {
        std::iter::from_fn(|| ob.pop()).collect()
    }

    /// Runs `step` and every resume to the end. It returns the end step
    /// and the items in order.
    fn run(
        p: &Polled<TestTokens>,
        ob: &mut Outbox<TestTokens>,
        rc: &mut i32,
        mut step: Step,
    ) -> (Step, Vec<Item<TestTokens>>) {
        let mut items = Vec::new();
        let mut out = InterestOut::UNWRITTEN;
        while step == Step::More {
            items.extend(drain(ob));
            step = p.resume(ob, &mut out, rc);
        }
        items.extend(drain(ob));
        (step, items)
    }

    fn log_at(items: &[Item<TestTokens>], site: LogSite) -> Option<usize> {
        items
            .iter()
            .position(|i| matches!(i, Item::Log(r) if r.site == site))
    }

    fn result_of(items: &[Item<TestTokens>], id: u64) -> Option<(usize, i32)> {
        items.iter().enumerate().find_map(|(k, i)| match i {
            Item::Result { token, result, .. } if token.id() == id => Some((k, result.rc)),
            _ => None,
        })
    }

    #[test]
    fn submit_and_close_with_no_socket() {
        let host = Arc::new(TestHost::new());
        host.set_log_level(Some(LogLevel::Info));
        let p = polled(&host);
        let mut ob = p.outbox();
        assert!(matches!(
            p.submit(exists(1), &mut ob),
            Ok(Submitted::Queued { .. })
        ));
        assert!(
            p.add_auth(
                JString::from("digest"),
                SecretBytes::from(b"u:p".to_vec()),
                None
            )
            .is_ok()
        );
        assert_eq!(p.peer_addr(), None);
        assert_eq!(p.wait_events(&InterestOut::UNWRITTEN, 0), 0);

        let mut rc = 1;
        let mut ob = p.outbox();
        let first = p.close(&mut ob, &mut rc);
        let (step, items) = run(&p, &mut ob, &mut rc, first);
        assert_eq!(step, Step::Release);
        assert_eq!(rc, ZOK);
        // No socket: no CLOSE_OP and no "Closing" line.
        assert_eq!(log_at(&items, LogSite::Closing), None);
        let freeing = log_at(&items, LogSite::Freeing).expect("the Freeing line");
        let (at, code) = result_of(&items, 1).expect("the request result");
        assert_eq!(code, ZCLOSING);
        assert!(freeing < at);
        assert!(host.discarded().is_empty());

        // The handle has no connection after the release.
        assert_eq!(p.state(), 0);
        let mut rc = 1;
        assert_eq!(p.process(0, &mut ob, &mut rc), Step::Done(ZINVALIDSTATE));
        let mut out = InterestOut::UNWRITTEN;
        assert_eq!(p.resume(&mut ob, &mut out, &mut rc), Step::Release);
        let Err(err) = p.submit(exists(2), &mut ob) else {
            panic!("no connection");
        };
        assert_eq!(
            (err.stage, err.code, err.token.id()),
            (Stage::Validate, ZINVALIDSTATE, 2)
        );
        assert!(
            p.add_auth(
                JString::from("digest"),
                SecretBytes::from(Vec::new()),
                Some(AuthId::new(3))
            )
            .is_err()
        );
    }

    /// A close from a callback defers the final close to the epilog of
    /// the driving call.
    #[test]
    fn close_from_a_callback_defers_to_the_epilog() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        let mut ob = p.outbox();
        assert!(p.submit(exists(1), &mut ob).is_ok());

        // An interest call ended its step and C runs its callbacks.
        p.life.prolog();
        {
            let mut st = p.io.lock_owner();
            st.frames.push(Frame {
                id: 7,
                phase: StPhase::Drain(ResumeAt::Interest),
                next: None,
                rc: ZNOTHING,
                errno: 0,
                abandoned: false,
            });
        }

        // The callback closes the handle.
        let mut cob = p.outbox();
        let mut crc = 1;
        assert_eq!(p.close(&mut cob, &mut crc), Step::Done(ZOK));
        assert_eq!(crc, ZOK);
        assert!(result_of(&drain(&mut cob), 1).is_none());
        assert_eq!(p.io.lock_owner().close, StClose::Deferred);
        assert_ne!(p.state(), 0);
        assert_eq!(p.life.refs(), 1);
        // A second close does nothing.
        assert_eq!(p.close(&mut cob, &mut crc), Step::Done(ZOK));
        assert_eq!(p.life.refs(), 1);

        // The driving call delivers the ZCLOSING result after the
        // callback, then runs the final close in its epilog.
        let mut ob = p.outbox();
        ob.set_frame(7);
        let mut rc = 1;
        let mut out = InterestOut::UNWRITTEN;
        let first = p.resume(&mut ob, &mut out, &mut rc);
        assert_eq!(first, Step::More);
        let (step, items) = run(&p, &mut ob, &mut rc, first);
        assert_eq!(result_of(&items, 1).map(|r| r.1), Some(ZCLOSING));
        assert_eq!(step, Step::Release);
        // The driving call keeps its own rc.
        assert_eq!(rc, ZNOTHING);
        assert_eq!(p.state(), 0);
        assert_eq!(p.life.refs(), 0);
        assert!(host.discarded().is_empty());
    }

    /// Starts an outer driving call that waits in its drain, as C does
    /// while it runs the callbacks of the call. It returns the frame id.
    fn outer_call_in_drain(p: &Polled<TestTokens>) -> u64 {
        p.life.prolog();
        let mut st = p.io.lock_owner();
        let id = st.serial;
        st.serial = st.serial.wrapping_add(1);
        st.frames.push(Frame {
            id,
            phase: StPhase::Drain(ResumeAt::Process),
            next: None,
            rc: ZNOTHING,
            errno: 0,
            abandoned: false,
        });
        id
    }

    /// Runs a nested `zookeeper_process` call to its end.
    fn nested_process(p: &Polled<TestTokens>) -> Step {
        let mut ob = p.outbox();
        let mut rc = 1;
        let first = p.process(0, &mut ob, &mut rc);
        run(p, &mut ob, &mut rc, first).0
    }

    /// Resumes the outer call to its end.
    fn finish_outer(p: &Polled<TestTokens>, id: u64) -> (Step, i32, Vec<Item<TestTokens>>) {
        let mut ob = p.outbox();
        ob.set_frame(id);
        let mut rc = 1;
        let mut out = InterestOut::UNWRITTEN;
        let first = p.resume(&mut ob, &mut out, &mut rc);
        let (step, items) = run(p, &mut ob, &mut rc, first);
        (step, rc, items)
    }

    #[test]
    fn a_nested_call_then_a_close_releases_in_the_outer_call() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        let mut sob = p.outbox();
        assert!(p.submit(exists(1), &mut sob).is_ok());
        let id = outer_call_in_drain(&p);

        // A callback of the outer call drives the handle, then closes it.
        let nested = nested_process(&p);
        assert!(matches!(nested, Step::Done(_)));
        assert_eq!(p.life.refs(), 1);
        let mut cob = p.outbox();
        let mut crc = 1;
        assert_eq!(p.close(&mut cob, &mut crc), Step::Done(ZOK));
        assert_eq!(p.io.lock_owner().close, StClose::Deferred);
        assert_ne!(p.state(), 0);

        // Only the outer call releases, and it keeps its own rc.
        let (step, rc, items) = finish_outer(&p, id);
        assert_eq!(step, Step::Release);
        assert_eq!(rc, ZNOTHING);
        assert_eq!(result_of(&items, 1).map(|r| r.1), Some(ZCLOSING));
        assert_eq!(p.state(), 0);
        assert_eq!(p.life.refs(), 0);
        assert!(host.discarded().is_empty());
    }

    #[test]
    fn a_close_then_a_nested_call_releases_in_the_outer_call() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        let mut sob = p.outbox();
        assert!(p.submit(exists(1), &mut sob).is_ok());
        let id = outer_call_in_drain(&p);

        // A callback of the outer call closes the handle, then drives it.
        let mut cob = p.outbox();
        let mut crc = 1;
        assert_eq!(p.close(&mut cob, &mut crc), Step::Done(ZOK));
        assert_eq!(p.life.refs(), 1);
        let nested = nested_process(&p);
        assert!(matches!(nested, Step::Done(_)));
        assert_eq!(p.life.refs(), 1);
        assert_ne!(p.state(), 0);

        let (step, rc, _) = finish_outer(&p, id);
        assert_eq!(step, Step::Release);
        assert_eq!(rc, ZNOTHING);
        assert_eq!(p.state(), 0);
        assert_eq!(p.life.refs(), 0);
        assert!(host.discarded().is_empty());
    }

    #[test]
    fn an_abandoned_nested_call_gives_its_ref_back() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        let id = outer_call_in_drain(&p);

        // A nested call stops in its drain, and its callback throws.
        let mut ob = p.outbox();
        ob.push(Item::AuthLockpoint);
        let mut rc = 1;
        p.life.prolog();
        let nested_id = {
            let mut st = p.io.lock_owner();
            let nid = st.serial;
            st.serial = st.serial.wrapping_add(1);
            st.frames.push(Frame {
                id: nid,
                phase: StPhase::Drain(ResumeAt::Process),
                next: None,
                rc: ZOK,
                errno: 0,
                abandoned: false,
            });
            nid
        };
        ob.set_frame(nested_id);
        ob.set_resume(ResumeAt::Process);
        p.requeue(ob.requeue());
        assert_eq!(p.life.refs(), 2);

        // The outer call catches the throw and resumes. The nested ref
        // goes back, and the outer call ends with its own rc.
        let (step, end_rc, _) = finish_outer(&p, id);
        assert_eq!(step, Step::Done(ZNOTHING));
        assert_eq!(end_rc, ZNOTHING);
        assert_eq!(p.life.refs(), 0);
        assert!(p.io.lock_owner().frames.is_empty());
        // A later close runs the final close in that call.
        let mut cob = p.outbox();
        let first = p.close(&mut cob, &mut rc);
        assert_eq!(run(&p, &mut cob, &mut rc, first).0, Step::Release);
    }

    #[test]
    fn a_resume_of_an_ended_call_changes_nothing() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        let mut ob = p.outbox();
        ob.set_frame(42);
        let mut rc = 1;
        let mut out = InterestOut::UNWRITTEN;
        assert_eq!(p.resume(&mut ob, &mut out, &mut rc), Step::Done(ZOK));
        assert_eq!(p.life.refs(), 0);
        assert_eq!(p.last_errno(), 0);
    }

    /// Runs `zoo_set_servers` to its end. It gives the rc and the items.
    fn set_servers(p: &Polled<TestTokens>, hosts: &[u8]) -> (i32, Vec<Item<TestTokens>>) {
        let mut ob = p.outbox();
        let mut rc = -1;
        let first = p.set_servers(hosts, &mut ob, &mut rc);
        let (step, items) = run(p, &mut ob, &mut rc, first);
        assert_eq!(step, Step::Done(rc));
        (rc, items)
    }

    #[test]
    fn set_servers_with_a_bad_string_changes_nothing() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        let (rc, items) = set_servers(&p, b"10.0.0.1");
        assert_eq!(rc, ZBADARGUMENTS);
        assert_eq!(log_at(&items, LogSite::ResolveNoPort), Some(0));
        let (rc, items) = set_servers(&p, b"10.0.0.1:x");
        assert_eq!(rc, ZBADARGUMENTS);
        assert_eq!(log_at(&items, LogSite::ResolveBadPort), Some(0));
        let (rc, items) = set_servers(&p, b",,");
        assert_eq!(rc, ZSYSTEMERROR);
        assert!(items.is_empty());
        assert_eq!(host.resolves(), 0);

        // A good list resolves each host, then reseeds for the shuffle.
        host.set_addrs(b"10.0.0.1", vec![SocketAddr::from(([10, 0, 0, 1], 2182))]);
        assert_eq!(set_servers(&p, b"10.0.0.1:2182").0, ZOK);
        assert_eq!((host.resolves(), host.reseeds()), (1, 1));
        // No address at all is the C resolver error.
        assert_eq!(set_servers(&p, b"10.9.9.9:2181").0, ZSYSTEMERROR);
        assert_eq!((host.resolves(), host.reseeds()), (2, 1));
    }

    #[test]
    fn set_servers_flushes_each_failure_line_before_the_next_resolve() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        host.set_addrs(b"10.0.0.3", vec![SocketAddr::from(([10, 0, 0, 3], 2181))]);
        let mut ob = p.outbox();
        let mut rc = -1;
        // The first host fails. Its line goes to C before the second
        // resolve, and before the reseed.
        assert_eq!(
            p.set_servers(b"10.9.9.1:2181,10.0.0.3:2181", &mut ob, &mut rc),
            Step::More
        );
        assert_eq!(host.resolves(), 1);
        assert_eq!(
            ob.resume_at().map(|a| matches!(a, ResumeAt::SetServers(_))),
            Some(true)
        );
        let first = drain(&mut ob);
        assert!(!first.is_empty());
        assert!(first.iter().all(|i| matches!(i, Item::Log(_))));
        let mut out = InterestOut::UNWRITTEN;
        let step = p.resume(&mut ob, &mut out, &mut rc);
        let (step, _) = run(&p, &mut ob, &mut rc, step);
        assert_eq!(step, Step::Done(ZOK));
        assert_eq!((host.resolves(), host.reseeds()), (2, 1));
        // An unknown run ends with ZINVALIDSTATE.
        ob.set_resume(ResumeAt::SetServers(99));
        assert_eq!(
            p.resume(&mut ob, &mut out, &mut rc),
            Step::Done(ZINVALIDSTATE)
        );
    }

    #[test]
    fn a_second_close_continues_a_requeued_final_close() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        // One requeued item makes the final close stop at its first stage.
        let mut old = p.outbox();
        old.push(Item::AuthLockpoint);
        p.requeue(old.requeue());
        let mut ob = p.outbox();
        let mut rc = -1;
        assert_eq!(p.close(&mut ob, &mut rc), Step::More);
        assert_eq!(ob.resume_at(), Some(ResumeAt::FinalClose));
        // A callback throws: C requeues the outbox. No resume follows.
        p.requeue(ob.requeue());
        let mut ob = p.outbox();
        let first = p.close(&mut ob, &mut rc);
        let (end, items) = run(&p, &mut ob, &mut rc, first);
        assert_eq!(end, Step::Release);
        assert!(matches!(items.first(), Some(Item::AuthLockpoint)));
        assert_eq!(p.state(), 0);
        // A third close does nothing.
        let mut ob = p.outbox();
        assert_eq!(p.close(&mut ob, &mut rc), Step::Done(ZOK));
    }

    #[test]
    fn a_requeued_set_servers_run_goes_to_the_interest_step() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        host.set_addrs(b"10.0.0.3", vec![SocketAddr::from(([10, 0, 0, 3], 2181))]);
        let mut ob = p.outbox();
        let mut rc = -1;
        assert_eq!(
            p.set_servers(b"10.9.9.1:2181,10.0.0.3:2181", &mut ob, &mut rc),
            Step::More
        );
        // A callback throws: C requeues the outbox.
        p.requeue(ob.requeue());
        let mut proof = Unlocked::new_at_entry();
        {
            let core = p.core.lock(&mut proof);
            assert!(core.set_servers_runs.is_empty());
            let (_, hosts) = core.set_servers.as_ref().unwrap();
            assert_eq!(hosts.len(), 2);
        }
    }

    #[test]
    fn requeue_and_sasl_result_are_stored() {
        let host = Arc::new(TestHost::new());
        let p = polled(&host);
        for id in [1, 2] {
            let mut ob = p.outbox();
            ob.push(Item::AuthResult {
                token: AuthId::new(id),
                rc: ZOK,
            });
            p.requeue(ob.requeue());
        }
        p.requeue(Outbox::new().requeue());
        p.sasl_result(SaslAnswer::Stepped {
            generation: 3,
            result: Err(SaslError {
                rc: ZSYSTEMERROR,
                errstring: Vec::new(),
                errdetail: Vec::new(),
            }),
        });
        {
            let mut proof = Unlocked::new_at_entry();
            let core = p.core.lock(&mut proof);
            assert!(matches!(
                core.sasl,
                Some(SaslAnswer::Stepped { generation: 3, .. })
            ));
            assert!(core.requeued.as_ref().is_some_and(|r| !r.is_empty()));
        }

        // The final close delivers the requeued items first, oldest first.
        let mut ob = p.outbox();
        let mut rc = 1;
        let first = p.close(&mut ob, &mut rc);
        let (step, items) = run(&p, &mut ob, &mut rc, first);
        assert_eq!(step, Step::Release);
        let ids: Vec<u64> = items
            .iter()
            .filter_map(|i| match i {
                Item::AuthResult { token, .. } => Some(token.id()),
                _ => None,
            })
            .collect();
        assert_eq!(ids.get(..2), Some(&[1, 2][..]));
        assert!(host.discarded().is_empty());
    }

    #[test]
    fn requeued_items_left_at_the_release_are_discarded() {
        let host = Arc::new(TestHost::new());
        host.set_log_level(Some(LogLevel::Info));
        let p = polled(&host);
        let mut ob = p.outbox();
        let mut rc = 1;
        // The "Freeing" line stops the close before the release stage.
        assert_eq!(p.close(&mut ob, &mut rc), Step::More);
        assert_eq!(p.io.lock_owner().close, StClose::Release);
        // A thrown callback leaves an item that C never takes.
        let mut lost = p.outbox();
        lost.push(Item::AuthResult {
            token: AuthId::new(9),
            rc: ZCLOSING,
        });
        p.requeue(lost.requeue());
        let (step, _) = run(&p, &mut ob, &mut rc, Step::More);
        assert_eq!(step, Step::Release);
        assert_eq!(rc, ZOK);
        assert_eq!(host.discarded(), vec!["auth"]);
    }
}
