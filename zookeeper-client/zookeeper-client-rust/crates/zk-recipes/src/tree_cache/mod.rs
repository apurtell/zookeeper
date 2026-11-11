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

//! The `TreeCache` recipe.
//!
//! The cache keeps an in-memory copy of a subtree. One persistent
//! recursive watch on the root (`AddWatchMode::PersistentRecursive`)
//! keeps it current. The cache needs ZooKeeper 3.6 or later.
//!
//! - `tree`: the cached nodes and their child lists.
//! - `sync`: the full read of the initial sync and of each resync.
//!
//! The cache is a state machine with the steps of `Step`. Each step
//! keeps its requests in the `TreeCache` fields. A future of `next`
//! only polls them. Thus a dropped `next` loses no reply, and the next
//! call goes on from the same step.
//!
//! The cache reads the session state, not the watcher, to find a new
//! epoch. A resync then follows each reconnect, also when the server
//! restores the watch. The server sends no events for the changes of
//! the gap.

mod sync;
mod tree;

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use apache_zookeeper::{
    AddWatchMode, Client, Error, EventKind, PathArg, PathError, PersistentWatcher, ResponseFuture,
    SessionInfo, Stat, StateWatcher, WatchError, WatchedEvent, ZPathBuf,
};

use crate::shared::session::{after_loss, connected_after, terminal_error, watch_terminal_error};
use sync::{NodeRead, Read};
use tree::{Tree, depth};

/// An in-memory copy of a subtree.
///
/// The cache makes progress only while the application awaits
/// [`next`](Self::next). [`get`](Self::get) and
/// [`children`](Self::children) read the copy as the last `next`
/// left it.
#[derive(Debug)]
pub struct TreeCache {
    client: Client,
    root: ZPathBuf,
    cache_data: bool,
    max_depth: Option<usize>,
    /// The watch on the root. It is `None` after `ConnectionLost`, until
    /// the next `add_watch` completes.
    watcher: Option<PersistentWatcher>,
    state: StateWatcher,
    /// The epoch of the last full read. A connected state with a
    /// greater epoch starts a resync.
    epoch: u64,
    /// The epoch at the `add_watch` call of the current watch. The
    /// cache can lose the watch only after this epoch.
    armed: u64,
    tree: Tree,
    /// The events that `next` did not yield yet.
    events: VecDeque<TreeEvent>,
    step: Step,
}

/// The steps of the cache.
#[derive(Debug)]
enum Step {
    /// The cache waits for a watch event or a session change.
    Live,
    /// The cache reads one node after a watch event.
    Apply { path: ZPathBuf, read: NodeRead },
    /// A full read for a resync.
    Sync(Box<Read>),
    /// The watch is gone after `ConnectionLost`. The cache waits for a
    /// connection with an epoch above `after`, then calls `add_watch`.
    /// `add` holds that request and the epoch when it went out.
    Rearm {
        after: u64,
        add: Option<(u64, ResponseFuture<PersistentWatcher>)>,
    },
    /// The cache is ended. The error goes out once, then `next` gives
    /// `None`.
    Ended(Option<Error>),
}

/// What woke the cache in the `Live` step.
enum Wake {
    Watch(Option<Result<WatchedEvent, WatchError>>),
    State(SessionInfo),
    Changed,
}

impl TreeCache {
    /// Starts a builder for a cache of the subtree at `root`.
    /// A bad path gives its error in
    /// [`TreeCacheBuilder::start`].
    pub fn builder(client: &Client, root: impl PathArg) -> TreeCacheBuilder {
        TreeCacheBuilder {
            client: client.clone(),
            root: root.to_zpath().map(|p| p.to_buf()),
            cache_data: true,
            max_depth: None,
        }
    }

    /// A snapshot of one cached node, or `None` when the node is not in
    /// the cache. A path that is not valid gives `None`.
    pub fn get(&self, path: impl PathArg) -> Option<CachedNode> {
        let p = path.to_zpath().ok()?;
        self.tree.get(p)
    }

    /// The names of the cached children of one node, sorted, or `None`
    /// when the node is not in the cache.
    pub fn children(&self, path: impl PathArg) -> Option<Vec<String>> {
        let p = path.to_zpath().ok()?;
        self.tree.children(p)
    }

    /// Drives the cache: it applies watch events and yields the changes
    /// that result.
    ///
    /// After `start`, it first yields one `NodeAdded` for each node of
    /// the initial sync, then `Initialized`. After each new `epoch` that
    /// is not terminal, and after a `WatchError::Lagged`, it reads the
    /// tree again, yields one event for each difference, then
    /// `Resynced`.
    ///
    /// The future is cancellation-safe: a drop loses no event.
    ///
    /// It yields `Some(Err(..))` once and then `None` after a terminal
    /// session state, and after `WatchError::Removed` (as
    /// `Error::NoWatcher`). A `WatchError::ConnectionLost` (a client with
    /// `restore_watches(false)`) does not end the cache: at the next
    /// `epoch` the cache calls `add_watch` again and resyncs.
    ///
    /// Another error of a read, for example `NoAuth`, goes out as
    /// `Some(Err(..))`. The cache then goes on.
    pub async fn next(&mut self) -> Option<Result<TreeEvent, Error>> {
        loop {
            if let Some(ev) = self.events.pop_front() {
                return Some(Ok(ev));
            }
            let out = match &mut self.step {
                Step::Ended(e) => return e.take().map(Err),
                Step::Live => self.live().await,
                Step::Apply { .. } => self.apply().await,
                Step::Sync(_) => self.sync().await,
                Step::Rearm { .. } => self.rearm().await,
            };
            if let Some(e) = out {
                return Some(Err(e));
            }
        }
    }

    /// Waits in the `Live` step. The watcher goes first, so its events
    /// and its `ConnectionLost` come before a new epoch.
    async fn live(&mut self) -> Option<Error> {
        let Some(watcher) = self.watcher.as_mut() else {
            return self.end_on_lost_watcher();
        };
        let client = &self.client;
        let last = self.epoch;
        let mut next = watcher.next();
        let mut changed = self.state.changed();
        let wake = poll_fn(|cx| {
            if let Poll::Ready(o) = Pin::new(&mut next).poll(cx) {
                return Poll::Ready(Wake::Watch(o));
            }
            let info = client.state();
            if info.state.is_terminal() || (info.state.is_connected() && info.epoch > last) {
                return Poll::Ready(Wake::State(info));
            }
            if Pin::new(&mut changed).poll(cx).is_ready() {
                return Poll::Ready(Wake::Changed);
            }
            Poll::Pending
        })
        .await;
        drop(next);
        drop(changed);
        match wake {
            Wake::Watch(Some(Ok(ev))) => {
                self.on_event(ev);
                None
            }
            Wake::Watch(Some(Err(e))) => self.on_watch_error(&e),
            Wake::Watch(None) => self.end_on_lost_watcher(),
            Wake::State(info) => match terminal_error(info.state) {
                Some(e) => self.end(e),
                None => {
                    self.start_sync(info.epoch);
                    None
                }
            },
            Wake::Changed => None,
        }
    }

    /// Handles one watch event. An event below `max_depth` changes
    /// nothing. A create or a data change reads the node, and a delete
    /// removes the cached subtree.
    fn on_event(&mut self, ev: WatchedEvent) {
        let path = ev.path.as_path();
        let Some(d) = depth(self.root.as_path(), path) else {
            return;
        };
        if self.max_depth.is_some_and(|m| d > m) {
            return;
        }
        let cached = self.tree.node(path).map(|n| n.stat);
        match ev.kind {
            EventKind::NodeCreated | EventKind::NodeDataChanged => {
                // A cached copy at or after the event zxid is the
                // result of a later read. It needs no new read.
                if ev.zxid.zip(cached).is_some_and(|(z, s)| s.mzxid >= z) {
                    return;
                }
                let read = NodeRead::submit(&self.client, path, self.cache_data);
                self.step = Step::Apply {
                    path: ev.path,
                    read,
                };
            }
            EventKind::NodeDeleted => {
                // A cached node that was created after the delete is a
                // new node. It stays.
                if ev.zxid.zip(cached).is_some_and(|(z, s)| s.czxid > z) {
                    return;
                }
                self.tree.remove_subtree(path, &mut self.events);
            }
            // A recursive watch gives no other kind.
            _ => {}
        }
    }

    /// Handles one watch error. A lag starts a resync, and a lost
    /// connection arms the watch again at the next epoch. A removed
    /// watch or a terminal state ends the cache.
    fn on_watch_error(&mut self, e: &WatchError) -> Option<Error> {
        if let Some(err) = watch_terminal_error(e) {
            return self.end(err);
        }
        match e {
            WatchError::Lagged { .. } => {
                self.start_sync(self.client.state().epoch);
                None
            }
            WatchError::ConnectionLost => {
                self.watcher = None;
                self.step = Step::Rearm {
                    after: self.armed,
                    add: None,
                };
                None
            }
            WatchError::Removed => self.end(Error::NoWatcher),
            // `InvalidState` comes only from a blocking wait. The
            // watcher stays active.
            _ => None,
        }
    }

    /// Waits for the read of one node, then applies it.
    async fn apply(&mut self) -> Option<Error> {
        let Step::Apply { read, .. } = &mut self.step else {
            return None;
        };
        let out = poll_fn(|cx| read.poll(cx)).await;
        let Step::Apply { path, .. } = std::mem::replace(&mut self.step, Step::Live) else {
            return None;
        };
        match out {
            Ok(node) => {
                self.tree.apply(path.as_path(), node, &mut self.events);
                None
            }
            Err(e) => self.on_error(e),
        }
    }

    /// Starts a full read. `epoch` is the session epoch now.
    fn start_sync(&mut self, epoch: u64) {
        let read = Read::start(
            &self.client,
            &self.root,
            self.cache_data,
            self.max_depth,
            epoch,
        );
        self.step = Step::Sync(Box::new(read));
    }

    /// Waits for the full read, then queues the differences and
    /// `Resynced`.
    async fn sync(&mut self) -> Option<Error> {
        let Step::Sync(read) = &mut self.step else {
            return None;
        };
        let client = &self.client;
        let out = poll_fn(|cx| read.poll(cx, client)).await;
        let epoch = read.epoch();
        self.step = Step::Live;
        self.epoch = epoch;
        match out {
            // A read that spans a reconnect can miss a change of the
            // gap. The `Live` step sees the new epoch and reads again.
            Ok(_) if self.client.state().epoch != epoch => None,
            Ok(new) => {
                self.tree.resync(new, &mut self.events);
                self.events.push_back(TreeEvent::Resynced);
                None
            }
            Err(e) => self.on_error(e),
        }
    }

    /// Arms the watch again after `ConnectionLost`, then resyncs.
    async fn rearm(&mut self) -> Option<Error> {
        let Step::Rearm { after, add } = &mut self.step else {
            return None;
        };
        if add.is_none() {
            let info = match connected_after(&mut self.state, *after).await {
                Ok(info) => info,
                Err(e) => return self.end(e),
            };
            let fut = self
                .client
                .add_watch(&self.root, AddWatchMode::PersistentRecursive);
            *add = Some((info.epoch, fut));
        }
        let Some((since, fut)) = add else {
            return None;
        };
        let since = *since;
        match fut.await {
            Ok(w) => {
                self.watcher = Some(w);
                self.armed = since;
                self.start_sync(self.client.state().epoch);
                None
            }
            Err(e) if e.is_connection_loss() => {
                self.step = Step::Rearm {
                    after: since,
                    add: None,
                };
                None
            }
            Err(e) => self.end(e),
        }
    }

    /// Handles the error of a read. A terminal error ends the cache. A
    /// connection loss needs no action, because a resync follows at
    /// the next epoch. Another error goes to the caller.
    fn on_error(&mut self, e: Error) -> Option<Error> {
        if e.is_session_terminal() {
            return self.end(e);
        }
        if e.is_connection_loss() {
            return None;
        }
        Some(e)
    }

    /// Ends the cache when the watcher gives no more outcomes.
    fn end_on_lost_watcher(&mut self) -> Option<Error> {
        let e = terminal_error(self.client.state().state).unwrap_or(Error::NoWatcher);
        self.end(e)
    }

    /// Ends the cache. The result is the error for `next` to yield now.
    fn end(&mut self, e: Error) -> Option<Error> {
        self.watcher = None;
        self.step = Step::Ended(None);
        Some(e)
    }
}

/// The options of a [`TreeCache`].
#[derive(Debug)]
pub struct TreeCacheBuilder {
    client: Client,
    root: Result<ZPathBuf, PathError>,
    cache_data: bool,
    max_depth: Option<usize>,
}

impl TreeCacheBuilder {
    /// Keeps the node data in the cache. The default is true. With
    /// false, [`CachedNode::data`] is `None`.
    #[must_use]
    pub fn cache_data(mut self, yes: bool) -> Self {
        self.cache_data = yes;
        self
    }

    /// Limits the depth of the cache below the root. The root has depth
    /// 0. The default `None` keeps the whole subtree. Events deeper than
    /// the limit are ignored.
    #[must_use]
    pub fn max_depth(mut self, depth: Option<usize>) -> Self {
        self.max_depth = depth;
        self
    }

    /// Arms the watch, then runs the initial sync.
    ///
    /// `add_watch(root, PersistentRecursive)` goes out before any read,
    /// so no change after the watch is set can be missed. The root need
    /// not exist. The cache stays empty until the root is made.
    ///
    /// A connection loss during the start does not fail it. The start
    /// waits for the next connection, arms the watch again and reads
    /// again.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` for a bad root. The error of `add_watch`,
    /// for example `Unimplemented` from a server before 3.6. A terminal
    /// session error.
    pub async fn start(self) -> Result<TreeCache, Error> {
        let root = self.root?;
        let client = self.client;
        let mut state = client.state_watcher();
        let mut watcher: Option<PersistentWatcher> = None;
        loop {
            let armed = client.state().epoch;
            // The new watch goes out before the old one drops. Thus
            // the server keeps the watch through the change.
            let added = client
                .add_watch(&root, AddWatchMode::PersistentRecursive)
                .await;
            let Some(w) = after_loss(added, &mut state, armed).await? else {
                continue;
            };
            drop(watcher.replace(w));
            let epoch = client.state().epoch;
            let mut read = Read::start(&client, &root, self.cache_data, self.max_depth, epoch);
            let out = poll_fn(|cx| read.poll(cx, &client)).await;
            // The read spans a reconnect. The watch can be gone, so
            // the start arms it again.
            let fresh = after_loss(out, &mut state, epoch).await?;
            let Some(tree) = fresh.filter(|_| client.state().epoch == epoch) else {
                continue;
            };
            let mut events = VecDeque::new();
            tree.added_events(&mut events);
            events.push_back(TreeEvent::Initialized);
            return Ok(TreeCache {
                client,
                root,
                cache_data: self.cache_data,
                max_depth: self.max_depth,
                watcher,
                state,
                epoch,
                armed,
                tree,
                events,
                step: Step::Live,
            });
        }
    }
}

/// A snapshot of one cached node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedNode {
    /// The stat of the node.
    pub stat: Stat,
    /// The data, or `None` with `cache_data(false)`.
    pub data: Option<Arc<[u8]>>,
}

/// One change of a [`TreeCache`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TreeEvent {
    /// A node came into the cache.
    NodeAdded {
        /// The full path, without the chroot.
        path: ZPathBuf,
        /// The new node.
        node: CachedNode,
    },
    /// The data or the stat of a cached node changed.
    NodeUpdated {
        /// The full path, without the chroot.
        path: ZPathBuf,
        /// The node after the change.
        node: CachedNode,
    },
    /// A node left the cache. A removed subtree gives one event for each
    /// node, deepest first.
    NodeRemoved {
        /// The full path, without the chroot.
        path: ZPathBuf,
        /// The last cached value of the node.
        node: CachedNode,
    },
    /// The initial sync is complete.
    Initialized,
    /// A resync after a reconnect or a lag is complete.
    Resynced,
}
