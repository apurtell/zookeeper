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

//! `Client`: the request methods and the session methods.
//!
//! Each request method follows one pattern:
//! 1. Check the path with `path::checked`. A bad path gives
//!    `ResponseFuture::ready(Err(Error::InvalidPath))`, and nothing goes
//!    out.
//! 2. For a watched read, register the sink with
//!    `Shared::register_oneshot` or `register_persistent`.
//! 3. Build the `Op` with `ops::*` and call `Shared::request` with the
//!    decoder of `decode::*` or `multi::*`.
//!
//! The submit happens before the method returns. Thus the call order is
//! the xid order and the wire order.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use zk_jute::JString;
use zk_proto::{Op, SecretBytes};

use crate::acl::Acl;
use crate::auth::ClientInfo;
use crate::builder::ClientBuilder;
use crate::config::{EnsembleConfig, Reconfig};
use crate::connect_string;
use crate::decode::{self, Decoder};
use crate::error::{Error, MultiError};
use crate::future::{CloseFuture, ReadyFuture, ResponseFuture};
use crate::multi::{self, MultiReader, MultiResults, MultiWriter, ReadResult};
use crate::observe::OpKind;
use crate::ops::{self, NativeOp};
use crate::path::{self, PathArg, ZPath, ZPathBuf};
use crate::shared::Shared;
use crate::tokens::{RawResult, WatchId};
use crate::types::{CreateMode, SessionId, SessionPassword, Stat, VersionArg, Zxid, wire_version};
use crate::watch::{
    AddWatchMode, OneshotWatcher, PersistentWatcher, SessionInfo, StateWatcher, WatcherKind,
};

/// The node of the ensemble config. The chroot never applies to it.
const CONFIG_NODE: &str = "/zookeeper/config";

/// Closes the client when the last `Client` clone drops.
///
/// Futures, watchers and the router can hold `Shared` for a short time.
/// The guard ties the close to the `Client` clones only.
#[derive(Debug)]
struct LifeGuard {
    shared: Weak<Shared>,
}

impl Drop for LifeGuard {
    /// Starts the graceful close in the background. It does not block.
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.driver.close();
        }
    }
}

/// A ZooKeeper client.
///
/// All clones share one session. The session lasts until `close`, until
/// `detach`, or until the last clone drops. `Client` is `Send`, `Sync`,
/// `Clone` and `Unpin`.
#[derive(Clone, Debug)]
pub struct Client {
    /// Declared first, so it drops before `shared`. Only its drop
    /// matters.
    _life: Arc<LifeGuard>,
    shared: Arc<Shared>,
}

/// A handle that does not keep the session open.
///
/// [`Client::downgrade`] makes it. [`WeakClient::upgrade`] gives a
/// `Client` while one `Client` clone lives. After the last clone drops,
/// the close starts, and `upgrade` gives `None`. A component that runs
/// in the background holds this handle, so it does not hold the session
/// open.
#[derive(Clone, Debug)]
pub struct WeakClient {
    life: Weak<LifeGuard>,
    shared: Weak<Shared>,
}

impl WeakClient {
    /// Gives a `Client` of the same session, or `None` after the last
    /// `Client` clone dropped. The new `Client` keeps the session open
    /// until it drops.
    #[must_use]
    pub fn upgrade(&self) -> Option<Client> {
        let life = self.life.upgrade()?;
        let shared = self.shared.upgrade()?;
        Some(Client {
            _life: life,
            shared,
        })
    }
}

/// Counters of one client.
#[derive(Clone, Debug)]
pub struct ClientStats {
    /// Queued and in-flight requests.
    pub pending: usize,
    /// Bytes sent. The drivers do not count bytes, so it is 0
    /// (IMPLEMENTATION_GUIDE.md, "Known differences and open issues").
    pub sent: u64,
    /// Bytes received. It is 0 for the same reason.
    pub received: u64,
    /// Established connections after the first: `epoch - 1`, or 0.
    pub reconnects: u64,
    /// The last zxid that the client saw.
    pub last_zxid: Zxid,
    /// The negotiated session timeout, after the first connection.
    pub negotiated_timeout: Option<Duration>,
    /// The current server, while connected.
    pub server: Option<SocketAddr>,
}

impl Client {
    /// Starts a builder. The connect string uses the Java grammar, for
    /// example `h1:2181,h2,[::1]:2182/chroot`. It is parsed in `connect` or
    /// `build`.
    pub fn builder(connect_string: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(connect_string.into())
    }

    /// Wraps the state of a new client. Only `ClientBuilder::build`
    /// calls it.
    pub(crate) fn from_shared(shared: Arc<Shared>) -> Self {
        Self {
            _life: Arc::new(LifeGuard {
                shared: Arc::downgrade(&shared),
            }),
            shared,
        }
    }

    /// Makes a handle that does not keep the session open.
    #[must_use]
    pub fn downgrade(&self) -> WeakClient {
        WeakClient {
            life: Arc::downgrade(&self._life),
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// The shared state, for the crate.
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Sends one request on a checked path. A bad path gives a ready
    /// `InvalidPath` error, and nothing goes out.
    fn request_at<T: 'static>(
        &self,
        path: &impl PathArg,
        sequential: bool,
        kind: OpKind,
        build: impl FnOnce(&str) -> NativeOp,
        decode: Decoder<T>,
    ) -> ResponseFuture<T> {
        self.request_data_at(path, sequential, kind, None, build, decode)
    }

    /// Sends one request on a checked path, as [`Self::request_at`]
    /// does. `data` is the borrowed data of a create or a set data. The
    /// core encodes it straight into the request frame.
    fn request_data_at<T: 'static>(
        &self,
        path: &impl PathArg,
        sequential: bool,
        kind: OpKind,
        data: Option<&[u8]>,
        build: impl FnOnce(&str) -> NativeOp,
        decode: Decoder<T>,
    ) -> ResponseFuture<T> {
        match path::checked(path, sequential) {
            Ok(p) => self
                .shared
                .request_with_data(build(p), data, kind, None, decode),
            Err(e) => ResponseFuture::ready(Err(Error::InvalidPath(e))),
        }
    }

    /// Sends one read with a one-shot watch. The sink exists before the
    /// submit. The decoder arms the watcher on success and removes the sink
    /// on an error.
    fn watched<B: 'static, T: 'static>(
        &self,
        path: &impl PathArg,
        kind: OpKind,
        watcher: WatcherKind,
        build: impl FnOnce(&str, WatchId) -> NativeOp,
        base: fn(RawResult) -> Result<B, Error>,
        join: fn(B, OneshotWatcher) -> T,
    ) -> ResponseFuture<T> {
        let p = match path::checked(path, false) {
            Ok(p) => p,
            Err(e) => return ResponseFuture::ready(Err(Error::InvalidPath(e))),
        };
        let reg = self
            .shared
            .register_oneshot(ZPath::new_unchecked(p).to_buf(), watcher);
        let id = reg.id();
        self.shared.request(
            build(p, id),
            kind,
            Some(id),
            decode::with_oneshot(base, reg, join),
        )
    }

    // ---- CRUD ----

    /// Creates a node (ops 1, 15, 19 and 21).
    ///
    /// The path is checked with the sequential rule for a sequential
    /// mode. The result path has the chroot stripped. A mode with a TTL
    /// sends op 21, a container sends op 19, and every other mode sends
    /// create2 (op 15).
    pub fn create(
        &self,
        path: impl PathArg,
        data: &[u8],
        mode: CreateMode,
        acl: &[Acl],
    ) -> ResponseFuture<(ZPathBuf, Stat)> {
        let sequential = mode.is_sequential();
        self.request_data_at(
            &path,
            sequential,
            OpKind::Create,
            Some(data),
            |p| ops::create(p, &mode, acl),
            decode::boxed(decode::create),
        )
    }

    /// Deletes a node (op 2). `version` is a `Version`, or `None` for
    /// any version.
    pub fn delete(&self, path: impl PathArg, version: impl VersionArg) -> ResponseFuture<()> {
        let v = wire_version(&version);
        self.request_at(
            &path,
            false,
            OpKind::Delete,
            |p| ops::delete(p, v),
            decode::boxed(decode::void),
        )
    }

    /// Reads the stat of a node (op 3). `NoNode` gives `Ok(None)`.
    pub fn exists(&self, path: impl PathArg) -> ResponseFuture<Option<Stat>> {
        self.request_at(
            &path,
            false,
            OpKind::Exists,
            |p| ops::exists(p, None),
            decode::boxed(decode::exists),
        )
    }

    /// Reads the data of a node (op 4). Null data gives an empty vector.
    pub fn get_data(&self, path: impl PathArg) -> ResponseFuture<(Vec<u8>, Stat)> {
        self.request_at(
            &path,
            false,
            OpKind::GetData,
            |p| ops::get_data(p, None),
            decode::boxed(decode::get_data),
        )
    }

    /// Reads the data of a node (op 4). Null data gives `None`.
    pub fn get_data_opt(&self, path: impl PathArg) -> ResponseFuture<(Option<Vec<u8>>, Stat)> {
        self.request_at(
            &path,
            false,
            OpKind::GetData,
            |p| ops::get_data(p, None),
            decode::boxed(decode::get_data_opt),
        )
    }

    /// Writes the data of a node (op 5).
    pub fn set_data(
        &self,
        path: impl PathArg,
        data: &[u8],
        version: impl VersionArg,
    ) -> ResponseFuture<Stat> {
        let v = wire_version(&version);
        self.request_data_at(
            &path,
            false,
            OpKind::SetData,
            Some(data),
            |p| ops::set_data(p, v),
            decode::boxed(decode::stat),
        )
    }

    /// Lists the child names of a node (specification "Operations").
    /// It sends op 12 and drops the stat.
    pub fn get_children(&self, path: impl PathArg) -> ResponseFuture<Vec<String>> {
        self.request_at(
            &path,
            false,
            OpKind::GetChildren,
            |p| ops::get_children(p, None, true),
            decode::boxed(decode::children),
        )
    }

    /// Lists the child names and the stat of a node (op 12).
    pub fn get_children_with_stat(
        &self,
        path: impl PathArg,
    ) -> ResponseFuture<(Vec<String>, Stat)> {
        self.request_at(
            &path,
            false,
            OpKind::GetChildren,
            |p| ops::get_children(p, None, true),
            decode::boxed(decode::children2),
        )
    }

    /// Counts every descendant of a node (op 104, server 3.6+).
    pub fn get_all_children_number(&self, path: impl PathArg) -> ResponseFuture<u32> {
        self.request_at(
            &path,
            false,
            OpKind::GetAllChildrenNumber,
            ops::get_all_children_number,
            decode::boxed(decode::children_count),
        )
    }

    /// Lists the ephemeral nodes of the session whose path starts with
    /// `prefix`, as a string prefix (op 103, server 3.6+).
    pub fn get_ephemerals(&self, prefix: impl PathArg) -> ResponseFuture<Vec<ZPathBuf>> {
        self.request_at(
            &prefix,
            false,
            OpKind::GetEphemerals,
            ops::get_ephemerals,
            decode::boxed(decode::ephemerals),
        )
    }

    /// Lists every ephemeral node of the session (op 103 with `/`).
    pub fn get_ephemerals_all(&self) -> ResponseFuture<Vec<ZPathBuf>> {
        self.get_ephemerals("/")
    }

    // ---- one-shot watches ----

    /// `exists` with an exist watch. The watch arms on a missing node too.
    pub fn exists_watched(
        &self,
        path: impl PathArg,
    ) -> ResponseFuture<(Option<Stat>, OneshotWatcher)> {
        self.watched(
            &path,
            OpKind::Exists,
            WatcherKind::Data,
            |p, w| ops::exists(p, Some(w)),
            decode::exists,
            |s, w| (s, w),
        )
    }

    /// `get_data` with a data watch.
    pub fn get_data_watched(
        &self,
        path: impl PathArg,
    ) -> ResponseFuture<(Vec<u8>, Stat, OneshotWatcher)> {
        self.watched(
            &path,
            OpKind::GetData,
            WatcherKind::Data,
            |p, w| ops::get_data(p, Some(w)),
            decode::get_data,
            |(d, s), w| (d, s, w),
        )
    }

    /// `get_children_with_stat` with a child watch.
    pub fn get_children_watched(
        &self,
        path: impl PathArg,
    ) -> ResponseFuture<(Vec<String>, Stat, OneshotWatcher)> {
        self.watched(
            &path,
            OpKind::GetChildren,
            WatcherKind::Children,
            |p, w| ops::get_children(p, Some(w), true),
            decode::children2,
            |(c, s), w| (c, s, w),
        )
    }

    // ---- persistent watches ----

    /// Adds a persistent watch (op 106, server 3.6+).
    pub fn add_watch(
        &self,
        path: impl PathArg,
        mode: AddWatchMode,
    ) -> ResponseFuture<PersistentWatcher> {
        let p = match path::checked(&path, false) {
            Ok(p) => p,
            Err(e) => return ResponseFuture::ready(Err(Error::InvalidPath(e))),
        };
        let reg = self
            .shared
            .register_persistent(ZPath::new_unchecked(p).to_buf(), mode);
        let id = reg.id();
        self.shared.request(
            ops::add_watch(p, mode.wire(), id),
            OpKind::AddWatch,
            Some(id),
            decode::with_persistent(reg),
        )
    }

    /// Removes every watcher of `kind` on a path (op 18). With `local_only`
    /// the server is not asked, and the local watchers end with
    /// `WatchError::Removed`.
    pub fn remove_watches(
        &self,
        path: impl PathArg,
        kind: WatcherKind,
        local_only: bool,
    ) -> ResponseFuture<()> {
        let wtype = kind.wire();
        self.request_at(
            &path,
            false,
            OpKind::RemoveWatches,
            |p| ops::remove_watches(p, wtype, local_only),
            decode::boxed(decode::void),
        )
    }

    // ---- ACL ----

    /// Reads the ACL of a node (op 6).
    pub fn get_acl(&self, path: impl PathArg) -> ResponseFuture<(Vec<Acl>, Stat)> {
        self.request_at(
            &path,
            false,
            OpKind::GetAcl,
            ops::get_acl,
            decode::boxed(decode::acl),
        )
    }

    /// Writes the ACL of a node (op 7). `aversion` is the ACL version.
    pub fn set_acl(
        &self,
        path: impl PathArg,
        acl: &[Acl],
        aversion: impl VersionArg,
    ) -> ResponseFuture<Stat> {
        let v = wire_version(&aversion);
        self.request_at(
            &path,
            false,
            OpKind::SetAcl,
            |p| ops::set_acl(p, acl, v),
            decode::boxed(decode::stat),
        )
    }

    // ---- consistency ----

    /// Waits until the server has the leader state of `path` (op 9).
    pub fn sync(&self, path: impl PathArg) -> ResponseFuture<()> {
        self.request_at(
            &path,
            false,
            OpKind::Sync,
            ops::sync,
            decode::boxed(decode::void),
        )
    }

    // ---- transactions ----

    /// Runs a transaction (op 14). An empty transaction still goes to the
    /// server.
    pub fn multi(&self, txn: &MultiWriter<'_>) -> ResponseFuture<MultiResults, MultiError> {
        let writer_id = txn.writer_id();
        // The op holds no sub-op. The core encodes the borrowed sub-ops
        // straight into the request frame, so no path or data is copied.
        let ops = txn.to_ops();
        self.shared.request_by(
            Op::Multi { ops: Vec::new() },
            OpKind::Multi,
            None,
            Box::new(move |r| multi::decode_multi(r, writer_id)),
            |d, req| d.submit_multi_ref(req, &ops),
        )
    }

    /// Runs a batch of reads (op 22, server 3.6+).
    pub fn multi_read(
        &self,
        ops: &MultiReader<'_>,
    ) -> ResponseFuture<Vec<Result<ReadResult, Error>>> {
        self.shared.request(
            Op::MultiRead { ops: ops.to_ops() },
            OpKind::MultiRead,
            None,
            decode::boxed(multi::decode_multi_read),
        )
    }

    // ---- reconfiguration ----

    /// Reads `/zookeeper/config`. The chroot never applies.
    pub fn get_config(&self) -> ResponseFuture<(EnsembleConfig, Stat)> {
        self.shared.request(
            ops::get_config(None),
            OpKind::GetConfig,
            None,
            decode::boxed(decode::config),
        )
    }

    /// `get_config` with a data watch. Its events have the path
    /// `/zookeeper/config` under any chroot.
    pub fn get_config_watched(&self) -> ResponseFuture<(EnsembleConfig, Stat, OneshotWatcher)> {
        let reg = self.shared.register_oneshot(
            ZPath::new_unchecked(CONFIG_NODE).to_buf(),
            WatcherKind::Data,
        );
        let id = reg.id();
        self.shared.request(
            ops::get_config(Some(id)),
            OpKind::GetConfig,
            Some(id),
            decode::with_oneshot(decode::config, reg, |(c, s), w| (c, s, w)),
        )
    }

    /// Changes the ensemble (op 16). `expected` is the config version to
    /// replace, or `None` for any (-1).
    pub fn reconfig(
        &self,
        change: &Reconfig,
        expected: Option<i64>,
    ) -> ResponseFuture<(EnsembleConfig, Stat)> {
        let (joining, leaving, members) = change.wire();
        self.shared.request(
            ops::reconfig(joining, leaving, members, expected.unwrap_or(-1)),
            OpKind::Reconfig,
            None,
            decode::boxed(decode::config),
        )
    }

    /// Replaces the local host list (ZOOKEEPER-1355).
    ///
    /// # Errors
    ///
    /// `Error::InvalidArgument` for a parse error or a chroot. Nothing
    /// changes then. A terminal client gives its terminal error.
    pub fn update_servers(&self, connect_string: &str) -> Result<(), Error> {
        let hosts = connect_string::parse_update(connect_string)?;
        if let Some(e) = self.shared.terminal_error() {
            return Err(e);
        }
        if self.shared.driver.set_servers(hosts) == 0 {
            // The driver exited between the check and the call.
            return Err(self.shared.terminal_error().unwrap_or(Error::Closing));
        }
        Ok(())
    }

    // ---- auth ----

    /// Adds credentials (op 100). Each call has its own result. The entry
    /// is sent again on each reconnect. A refusal ends the session with
    /// `AuthFailed`.
    pub fn add_auth(&self, scheme: &str, data: impl Into<Vec<u8>>) -> ResponseFuture<()> {
        let cred = SecretBytes::new(data.into());
        self.shared.add_auth(JString::from(scheme), cred)
    }

    /// Lists the identities of the session (op 107, server 3.9+).
    pub fn who_am_i(&self) -> ResponseFuture<Vec<ClientInfo>> {
        self.shared.request(
            ops::who_am_i(),
            OpKind::WhoAmI,
            None,
            decode::boxed(decode::who_am_i),
        )
    }

    // ---- session and lifecycle ----

    /// The current session state.
    #[must_use]
    pub fn state(&self) -> SessionInfo {
        self.shared.router.state.snapshot()
    }

    /// A watcher of the session state.
    #[must_use]
    pub fn state_watcher(&self) -> StateWatcher {
        StateWatcher::new(Arc::clone(&self.shared.router.state))
    }

    /// The session id and password. Before the first connection the id is
    /// 0, or the id of `ClientBuilder::session`.
    #[must_use]
    pub fn session(&self) -> (SessionId, SessionPassword) {
        let id = self.shared.driver.client_id();
        (
            SessionId(id.session_id),
            SessionPassword::from_bytes(id.passwd),
        )
    }

    /// The negotiated session timeout, after the first connection.
    #[must_use]
    pub fn negotiated_timeout(&self) -> Option<Duration> {
        if self.state().epoch == 0 {
            return None;
        }
        let ms = self.shared.read_conn(|c| c.recv_timeout())?;
        u64::try_from(ms).ok().map(Duration::from_millis)
    }

    /// The last zxid that the client saw.
    #[must_use]
    pub fn last_zxid(&self) -> Zxid {
        Zxid(self.shared.read_conn(|c| c.last_zxid()).unwrap_or(0))
    }

    /// The current server, while connected.
    #[must_use]
    pub fn connected_server(&self) -> Option<SocketAddr> {
        if !self.state().state.is_connected() {
            return None;
        }
        self.shared.read_conn(|c| c.current_server()).flatten()
    }

    /// The counters of the client.
    #[must_use]
    pub fn stats(&self) -> ClientStats {
        ClientStats {
            pending: self.shared.pending_len().unwrap_or(0),
            sent: 0,
            received: 0,
            reconnects: self.state().epoch.saturating_sub(1),
            last_zxid: self.last_zxid(),
            negotiated_timeout: self.negotiated_timeout(),
            server: self.connected_server(),
        }
    }

    /// Resolves when the pending count is below half of
    /// `max_pending_requests`, and at once with no limit.
    pub fn ready(&self) -> ReadyFuture {
        ReadyFuture::new(Arc::downgrade(&self.shared))
    }

    /// Closes the session. The close starts in this call. New requests fail
    /// with `Closing`, queued requests drain, and then `CloseSession` goes
    /// out. A second call gives the same outcome.
    pub fn close(&self) -> CloseFuture {
        self.shared.driver.close();
        CloseFuture::new(self.shared.driver.close_wait(&self.shared.router))
    }

    /// Ends the connection and keeps the session. Pending requests fail
    /// with `Closing`, and watchers end with `Closed`. Another client
    /// resumes the session with the returned values.
    #[must_use = "the session lives on; use the credentials or close it"]
    pub fn detach(self) -> (SessionId, SessionPassword) {
        let session = self.session();
        self.shared.driver.detach();
        session
    }
}
