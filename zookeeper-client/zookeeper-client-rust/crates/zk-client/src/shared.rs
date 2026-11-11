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

//! `Shared`: the state that every clone of one client shares.
//!
//! `Client` holds `Arc<Shared>`. Futures and watchers hold
//! `Weak<Shared>`, so they never keep the session open. The module owns
//! the submit path, the watch registrations and the watcher detach
//! rule. No user code runs here, and no internal lock is held across a
//! call into the driver.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use zk_jute::JString;
use zk_proto::{
    Connection, InputDefect, Origin, Reply, Request, Route, SecretBytes, SubmitError, Submitted,
};

use crate::decode::{self, Decoder};
use crate::driver::{DriverHandle, Gate};
use crate::error::{Error, map_submit_error};
use crate::future::{ResponseFuture, report_taken};
use crate::observe::OpKind;
use crate::ops::{self, NativeOp};
use crate::path::ZPathBuf;
use crate::route::Router;
use crate::slot::Slot;
use crate::sync::LockExt;
use crate::tokens::{AuthToken, NativeCompletion, NativeTokens, RawResult, ReplyToken, WatchId};
use crate::watch::{
    AddWatchMode, EventQueue, OneshotWatcher, PersistentWatcher, Sink, WatchOutcome, WatcherKind,
};

/// The result of one driver submit.
type Sent = Result<Submitted<NativeTokens>, SubmitError<NativeTokens>>;

/// The next client id. Ids start at 1, because 0 means "not on the IO
/// side" in the IO-side marker.
static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

/// Gives a new client id. The id is unique in the process.
pub(crate) fn next_client_id() -> u64 {
    NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed)
}

/// The builder values that the client needs after `build`.
#[derive(Clone, Debug)]
pub(crate) struct ClientConfig {
    /// The `max_pending_requests` limit, or `None` for no limit.
    pub(crate) max_pending: Option<usize>,
    /// The `persistent_watch_buffer` bound, or `None` for no bound.
    pub(crate) persistent_watch_buffer: Option<usize>,
}

/// The state of one client.
#[derive(Debug)]
pub(crate) struct Shared {
    /// The driver.
    pub(crate) driver: DriverHandle,
    /// The router. The driver holds it too.
    pub(crate) router: Arc<Router>,
    /// The builder values.
    pub(crate) config: Arc<ClientConfig>,
    /// The next watcher id.
    next_watch_id: AtomicU64,
}

impl Shared {
    /// Makes the state and binds the router to it.
    pub(crate) fn new(
        driver: DriverHandle,
        router: Arc<Router>,
        config: Arc<ClientConfig>,
    ) -> Arc<Self> {
        let shared = Arc::new(Self {
            driver,
            router,
            config,
            next_watch_id: AtomicU64::new(1),
        });
        shared.router.bind(&shared);
        shared
    }

    /// Gives a new watcher id. Ids are never reused, so proto never
    /// merges two native watchers.
    pub(crate) fn new_watch_id(&self) -> WatchId {
        WatchId(self.next_watch_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Submits one request and gives the slot of its result.
    ///
    /// The core checks the state, joins the chroot, assigns the xid and
    /// queues the frame under its lock. Thus the call order is the wire
    /// order. A local watch removal completes at once with `Reply::Void`,
    /// and that value does not count against the read gate.
    ///
    /// # Errors
    ///
    /// The terminal error of the client, or the mapped proto refusal.
    pub(crate) fn submit(
        &self,
        op: NativeOp,
        kind: OpKind,
        watch: Option<WatchId>,
    ) -> Result<Arc<Slot<RawResult>>, Error> {
        self.submit_with_data(op, None, kind, watch)
    }

    /// Submits one request whose data is borrowed, as
    /// `Connection::submit_with_data` tells. The core encodes the data
    /// straight into the request frame, so the client makes no copy of
    /// it. The other rules are those of [`Self::submit`].
    ///
    /// # Errors
    ///
    /// The terminal error of the client, or the mapped proto refusal.
    pub(crate) fn submit_with_data(
        &self,
        op: NativeOp,
        data: Option<&[u8]>,
        kind: OpKind,
        watch: Option<WatchId>,
    ) -> Result<Arc<Slot<RawResult>>, Error> {
        self.submit_by(op, kind, watch, |d, req| d.submit_with_data(req, data))
    }

    /// Submits one request through `send`, which gives the request and
    /// its borrowed inputs to the driver. The borrow ends when `send`
    /// returns. The other rules are those of [`Self::submit`].
    fn submit_by(
        &self,
        op: NativeOp,
        kind: OpKind,
        watch: Option<WatchId>,
        send: impl FnOnce(&DriverHandle, Request<NativeTokens>) -> Sent,
    ) -> Result<Arc<Slot<RawResult>>, Error> {
        if let Some(e) = self.terminal_error() {
            return Err(e);
        }
        let slot = Slot::new();
        let token = NativeCompletion::Reply(ReplyToken::new(Arc::clone(&slot), watch, kind));
        let req = Request {
            op,
            token,
            route: Route::Queued,
            defect: InputDefect::default(),
        };
        match send(&self.driver, req) {
            Ok(Submitted::Queued { .. }) => Ok(slot),
            Ok(Submitted::Local(token)) => {
                if let NativeCompletion::Reply(t) = token {
                    let _ = t.complete(local_void(), false);
                }
                Ok(slot)
            }
            Err(e) => {
                let err = self
                    .terminal_error()
                    .unwrap_or_else(|| map_submit_error(e.stage, e.code));
                drop(e.token);
                Err(err)
            }
        }
    }

    /// Submits a request and wraps the slot in a future. A refusal
    /// gives a ready future with the error, and the decoder drops at
    /// once. Thus a watch registration in the decoder removes its sink.
    pub(crate) fn request<T, E: From<Error>>(
        self: &Arc<Self>,
        op: NativeOp,
        kind: OpKind,
        watch: Option<WatchId>,
        decode: Decoder<T, E>,
    ) -> ResponseFuture<T, E> {
        self.request_with_data(op, None, kind, watch, decode)
    }

    /// Submits a request whose data is borrowed, as
    /// [`Self::submit_with_data`] tells, and wraps the slot in a future.
    /// The other rules are those of [`Self::request`].
    pub(crate) fn request_with_data<T, E: From<Error>>(
        self: &Arc<Self>,
        op: NativeOp,
        data: Option<&[u8]>,
        kind: OpKind,
        watch: Option<WatchId>,
        decode: Decoder<T, E>,
    ) -> ResponseFuture<T, E> {
        self.request_by(op, kind, watch, decode, |d, req| {
            d.submit_with_data(req, data)
        })
    }

    /// Submits a request through `send`, as [`Self::submit_by`] tells,
    /// and wraps the slot in a future. A multi gives its borrowed sub-ops
    /// this way. The other rules are those of [`Self::request`].
    pub(crate) fn request_by<T, E: From<Error>>(
        self: &Arc<Self>,
        op: NativeOp,
        kind: OpKind,
        watch: Option<WatchId>,
        decode: Decoder<T, E>,
        send: impl FnOnce(&DriverHandle, Request<NativeTokens>) -> Sent,
    ) -> ResponseFuture<T, E> {
        match self.submit_by(op, kind, watch, send) {
            Ok(slot) => ResponseFuture::waiting(slot, decode, Arc::downgrade(self)),
            Err(e) => {
                drop(decode);
                ResponseFuture::ready(Err(E::from(e)))
            }
        }
    }

    /// Submits a request that nobody waits for: the `RemoveWatches`
    /// request of a watcher drop. A refusal is ignored, because the
    /// watcher is gone already.
    pub(crate) fn submit_discard(&self, op: NativeOp) {
        let _queued = self.submit_untracked(op, NativeCompletion::Discard);
    }

    /// Submits a config read of the follower. It returns false when the
    /// client or the core refuses it.
    pub(crate) fn submit_follow(&self, op: NativeOp) -> bool {
        self.terminal_error().is_none() && self.submit_untracked(op, NativeCompletion::Follow)
    }

    /// Submits a request with a token that has no receiver. It returns
    /// true when the core accepts it.
    fn submit_untracked(&self, op: NativeOp, token: NativeCompletion) -> bool {
        let req = Request {
            op,
            token,
            route: Route::Queued,
            defect: InputDefect::default(),
        };
        self.driver.submit(req).is_ok()
    }

    /// Records one `add_auth` call and gives the future of its result. The
    /// result is `Reply::Void` or an error code.
    ///
    /// A refusal gives a ready future with the terminal error of the
    /// client, or the error of the proto refusal code.
    pub(crate) fn add_auth(
        self: &Arc<Self>,
        scheme: JString,
        cred: SecretBytes,
    ) -> ResponseFuture<()> {
        if let Some(e) = self.terminal_error() {
            return ResponseFuture::ready(Err(e));
        }
        let slot = Slot::new();
        let token = AuthToken::new(Arc::clone(&slot));
        match self.driver.add_auth(scheme, cred, Some(token)) {
            Ok(()) => {
                ResponseFuture::waiting(slot, decode::boxed(decode::void), Arc::downgrade(self))
            }
            Err(e) => {
                drop(e.done);
                ResponseFuture::ready(Err(self
                    .terminal_error()
                    .or_else(|| Error::from_code(e.code))
                    .unwrap_or(Error::SystemError)))
            }
        }
    }

    /// Adds the sink of a new one-shot watcher. The sink exists before the
    /// request is submitted, so an event right after the reply is never
    /// lost.
    pub(crate) fn register_oneshot(
        self: &Arc<Self>,
        path: ZPathBuf,
        kind: WatcherKind,
    ) -> OneshotReg {
        let id = self.new_watch_id();
        let slot = Slot::new();
        self.router
            .sinks
            .lock_unpoisoned()
            .insert(id, Sink::Oneshot(Arc::clone(&slot)));
        OneshotReg {
            id,
            slot,
            shared: Arc::downgrade(self),
            gate: self.driver.gate(),
            path,
            kind,
            armed: false,
        }
    }

    /// Adds the sink of a new persistent watcher.
    pub(crate) fn register_persistent(
        self: &Arc<Self>,
        path: ZPathBuf,
        mode: AddWatchMode,
    ) -> PersistentReg {
        let id = self.new_watch_id();
        let queue = EventQueue::new(self.config.persistent_watch_buffer);
        self.router
            .sinks
            .lock_unpoisoned()
            .insert(id, Sink::Persistent(Arc::clone(&queue)));
        PersistentReg {
            id,
            queue,
            shared: Arc::downgrade(self),
            tokio: self.driver.is_tokio(),
            path,
            mode,
            armed: false,
        }
    }

    /// Removes the sink of a watcher whose handle is gone, then detaches
    /// the watcher from proto. The sink drops after the lock is released. A
    /// second call finds no sink and does no harm.
    pub(crate) fn drop_watch_sink(&self, id: WatchId) {
        let sink = self.router.sinks.lock_unpoisoned().remove(id);
        drop(sink);
        self.detach_watch(id);
    }

    /// Detaches a watcher from proto. Proto can then give a removal
    /// hint: the watcher was the last user of its server watch, and no
    /// request in flight sets it. The client then sends `RemoveWatches`
    /// with no receiver.
    pub(crate) fn detach_watch(&self, id: WatchId) {
        let hint = self
            .driver
            .with_conn(|c, _| c.detach_watcher(&id))
            .flatten();
        if let Some(h) = hint {
            self.submit_discard(ops::remove_hint(h));
        }
    }

    /// Removes a watcher on request: `OneshotWatcher::remove` and
    /// `PersistentWatcher::remove`.
    ///
    /// It gives the slot of the server removal, or `None` when other
    /// local users of the server watch remain, so no request goes out.
    ///
    /// # Errors
    ///
    /// The error of the submit.
    pub(crate) fn remove_watch(&self, id: WatchId) -> Result<Option<Arc<Slot<RawResult>>>, Error> {
        let sink = self.router.sinks.lock_unpoisoned().remove(id);
        drop(sink);
        let hint = self
            .driver
            .with_conn(|c, _| c.detach_watcher(&id))
            .flatten();
        match hint {
            None => Ok(None),
            Some(h) => self
                .submit(ops::remove_hint(h), OpKind::RemoveWatches, None)
                .map(Some),
        }
    }

    /// The request error of a terminal state, or `None`.
    pub(crate) fn terminal_error(&self) -> Option<Error> {
        self.router.state.terminal_error()
    }

    /// The count of queued and in-flight requests. `None` after the
    /// driver exits.
    pub(crate) fn pending_len(&self) -> Option<usize> {
        self.driver.read_conn(Connection::pending_len)
    }

    /// Runs `f` on the connection under the core lock.
    pub(crate) fn read_conn<R>(&self, f: impl FnOnce(&Connection<NativeTokens>) -> R) -> Option<R> {
        self.driver.read_conn(f)
    }
}

/// The result of a local watch removal.
fn local_void() -> RawResult {
    RawResult {
        rc: 0,
        zxid: 0,
        origin: Origin::Reply,
        reply: Some(Reply::Void),
    }
}

/// The registration of a one-shot watcher between the submit and the
/// decode.
///
/// The decoder of the watched request owns it. On success the decoder
/// arms it into an `OneshotWatcher`. A registration that drops unarmed
/// removes its sink and detaches the watcher.
#[derive(Debug)]
pub(crate) struct OneshotReg {
    id: WatchId,
    slot: Arc<Slot<WatchOutcome>>,
    shared: Weak<Shared>,
    /// The read gate. It stays valid after the drop of the last clone.
    gate: Gate,
    path: ZPathBuf,
    kind: WatcherKind,
    armed: bool,
}

impl OneshotReg {
    /// The watcher id, for the `Op` and the reply token.
    pub(crate) fn id(&self) -> WatchId {
        self.id
    }

    /// Makes the watcher handle. The handle now owns the sink.
    pub(crate) fn arm(mut self) -> OneshotWatcher {
        self.armed = true;
        OneshotWatcher::new(
            self.id,
            Arc::clone(&self.slot),
            self.shared.clone(),
            Some(self.gate.clone()),
            self.path.clone(),
            self.kind,
        )
    }
}

impl Drop for OneshotReg {
    fn drop(&mut self) {
        if self.armed {
            return;
        }
        if self.slot.drop_receiver() {
            report_taken(Some(&self.gate));
        }
        if let Some(shared) = self.shared.upgrade() {
            shared.drop_watch_sink(self.id);
        }
    }
}

/// The registration of a persistent watcher between the submit and the
/// decode. It follows the rules of [`OneshotReg`].
#[derive(Debug)]
pub(crate) struct PersistentReg {
    id: WatchId,
    queue: Arc<EventQueue>,
    shared: Weak<Shared>,
    /// True when the tokio driver runs the client.
    tokio: bool,
    path: ZPathBuf,
    mode: AddWatchMode,
    armed: bool,
}

impl PersistentReg {
    /// The watcher id, for the `Op` and the reply token.
    pub(crate) fn id(&self) -> WatchId {
        self.id
    }

    /// Makes the watcher handle. The handle now owns the sink.
    pub(crate) fn arm(mut self) -> PersistentWatcher {
        self.armed = true;
        PersistentWatcher::new(
            self.id,
            Arc::clone(&self.queue),
            self.shared.clone(),
            self.tokio,
            self.path.clone(),
            self.mode,
        )
    }
}

impl Drop for PersistentReg {
    fn drop(&mut self) {
        if self.armed {
            return;
        }
        self.queue.drop_receiver();
        if let Some(shared) = self.shared.upgrade() {
            shared.drop_watch_sink(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ids_are_unique_and_not_zero() {
        let a = next_client_id();
        let b = next_client_id();
        assert_ne!(a, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn a_local_removal_result_is_void() {
        let r = local_void();
        assert_eq!(r.rc, 0);
        assert_eq!(r.reply, Some(Reply::Void));
    }
}
