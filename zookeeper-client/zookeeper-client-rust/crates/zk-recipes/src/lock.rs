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

//! `DistributedLock`: a mutual exclusion lock on one path.
//!
//! The lock has the node layout of Apache Curator's `InterProcessMutex`,
//! so Rust and Java processes can contend on one path. Each participant
//! makes `<lock_path>/_c_<uuid>-lock-<seq>`. The participant
//! whose node is first in Curator order holds the lock. Each waiter
//! watches only the node just before its own, so a release wakes only
//! the next waiter.
//!
//! The acquire loop keeps its participant node in a local value. Thus
//! each exit by an error or by a drop of the future submits the delete
//! of the node. Only a held lock moves the node into the guard.
//!
//! Three choices differ from Curator:
//!
//! - When the own node is missing from the child list, another client
//!   deleted it. Curator then fails. This lock makes a new node with a
//!   new `<uuid>` and loops, so `acquire` keeps its promise to wait.
//! - `release` and the delete of `try_acquire` send the delete again
//!   after a connection loss. A delete with an unknown result would
//!   otherwise leave a held lock until the session ends. Curator uses a
//!   guaranteed delete for the same reason.
//! - The recovery lookup after a connection loss sends a `sync` before
//!   the list. After a reconnect to a follower that did not yet apply
//!   the lost create, the `sync` makes the list show it. Curator lists
//!   with no `sync`.
//!
//! A drop cannot wait for a result. Thus each drop gives its node to
//! the guaranteed delete. A drop of a known node gives the path. A drop
//! while a create has an unknown outcome gives the protected id. The
//! guaranteed delete sends the `delete` again at each
//! new connection epoch, or when a full request queue has room, until
//! the node is gone. It needs no further call on the lock.

use apache_zookeeper::{
    Client, Error, EventKind, OneshotWatcher, PathArg, StateWatcher, ZPath, ZPathBuf,
};

use crate::shared::order::{LOCK_MARKER, position, predecessor, sort_children};
use crate::shared::participant::{ParticipantNode, create_participant};
use crate::shared::protected::ProtectedId;
use crate::shared::select::{Either, select};
use crate::shared::session::{after_loss, terminal_error, watch_terminal_error};

/// A distributed, non-reentrant mutual exclusion lock.
///
/// The lock is compatible with Curator's `InterProcessMutex` on the
/// same path. A second `acquire` in a process that holds the lock waits
/// like any other participant. Curator's reentrancy is local to a Java
/// thread and does not show in the node layout.
///
/// While `StateWatcher` reports `Connecting`, a holder cannot know if
/// the session will expire. A holder must then pause the work that the
/// lock protects until the state is `Connected` again. This is the
/// SUSPENDED advice of Curator. `ConnectedReadOnly` needs the same
/// pause. A read-only server can be in a minority partition, and the
/// majority can expire the session there and give the lock to the next
/// waiter.
#[derive(Debug)]
pub struct DistributedLock {
    client: Client,
    path: ZPathBuf,
    data: Vec<u8>,
}

/// The place of the own node in the ordered child list.
enum Place {
    /// The own node is first: it holds the lock.
    First,
    /// The own node waits behind this child.
    After(String),
    /// The own node is not in the list.
    Missing,
}

impl DistributedLock {
    /// Makes a lock on `lock_path`. It sends nothing.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` when `lock_path` is not a valid path.
    pub fn new(client: &Client, lock_path: impl PathArg) -> Result<DistributedLock, Error> {
        let path = lock_path.to_zpath()?.to_buf();
        Ok(Self {
            client: client.clone(),
            path,
            data: Vec::new(),
        })
    }

    /// Sets the data of the participant node. The default is empty.
    /// Neither this crate nor Curator reads it.
    #[must_use]
    pub fn node_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Waits until this participant holds the lock.
    ///
    /// The future makes the participant node, then loops: it
    /// lists the lock path, orders the children, and holds the lock when
    /// its node is first. Otherwise it calls `get_data_watched` on the
    /// node just before its own. On `NoNode` it loops at once. Otherwise
    /// it waits for the watch and loops. A `Connecting` state does not
    /// end the wait. A new connection makes the future list again.
    ///
    /// When another client deletes the own node, the future makes a new
    /// node with a new `<uuid>` and waits again.
    ///
    /// The future is cancellation-safe. When it is dropped while it
    /// waits, it gives its node to the guaranteed delete. The
    /// `delete` goes out at once. After a connection loss, it goes out
    /// again at the next connection epoch. When the future is dropped
    /// before the create reply comes, the guaranteed delete waits for
    /// that reply. A success gives the node name, and the background
    /// thread deletes the node. A connection loss leaves the outcome
    /// unknown, so the guaranteed delete finds the node by its protected
    /// id.
    ///
    /// # Errors
    ///
    /// A terminal session error, or a server error such as `NoAuth`.
    pub async fn acquire(&self) -> Result<LockGuard, Error> {
        let mut state = self.client.state_watcher();
        let mut node = self.create_node().await?;
        // The armed predecessor watch. It stays across a list at a new
        // epoch when the predecessor does not change.
        let mut watch: Option<(String, OneshotWatcher)> = None;
        loop {
            let epoch = state.current().epoch;
            let Some(children) = after_loss(self.list().await, &mut state, epoch).await? else {
                continue;
            };
            let pred = match place(children, node.name()) {
                Place::First => return Ok(LockGuard::new(node, state)),
                Place::Missing => {
                    watch = None;
                    node.forget();
                    node = self.create_node().await?;
                    continue;
                }
                Place::After(pred) => pred,
            };
            let mut watcher = match watch.take() {
                Some((armed, w)) if armed == pred => w,
                _ => {
                    let pred_path = self.path.as_path().join(&pred)?;
                    let read = match self.client.get_data_watched(&pred_path).await {
                        Err(Error::NoNode) => continue,
                        read => read,
                    };
                    let Some((_, _, w)) = after_loss(read, &mut state, epoch).await? else {
                        continue;
                    };
                    w
                }
            };
            if new_epoch(&mut watcher, &mut state, epoch).await? {
                watch = Some((pred, watcher));
            }
        }
    }

    /// Takes the lock only when it is free. It never waits for another
    /// holder.
    ///
    /// The future makes the participant node and checks the order once.
    /// When the node is not first, it deletes the node and returns
    /// `Ok(None)`. The future returns after the server confirms the
    /// delete, so the node does not delay the next participant. When the
    /// delete fails with another error, the future gives that error, and
    /// the guaranteed delete takes the node.
    ///
    /// # Errors
    ///
    /// As for [`acquire`](Self::acquire).
    pub async fn try_acquire(&self) -> Result<Option<LockGuard>, Error> {
        let mut state = self.client.state_watcher();
        let mut node = self.create_node().await?;
        loop {
            let epoch = state.current().epoch;
            let Some(children) = after_loss(self.list().await, &mut state, epoch).await? else {
                continue;
            };
            match place(children, node.name()) {
                Place::First => return Ok(Some(LockGuard::new(node, state))),
                Place::After(_) => {
                    return match node.delete_confirmed().await {
                        // A node that another client deleted is gone too.
                        Ok(()) | Err(Error::NoNode) => Ok(None),
                        Err(e) => Err(e),
                    };
                }
                Place::Missing => {
                    node.forget();
                    node = self.create_node().await?;
                }
            }
        }
    }

    /// Makes a participant node with a new protected id.
    async fn create_node(&self) -> Result<ParticipantNode, Error> {
        create_participant(
            &self.client,
            self.path.as_path(),
            &ProtectedId::new(),
            LOCK_MARKER,
            &self.data,
        )
        .await
    }

    /// Lists the lock path in Curator order. A missing lock path has no
    /// children.
    async fn list(&self) -> Result<Vec<String>, Error> {
        match self.client.get_children(&self.path).await {
            Ok(mut children) => {
                sort_children(&mut children, LOCK_MARKER);
                Ok(children)
            }
            Err(Error::NoNode) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

/// Finds the place of `own` in the sorted `children`.
fn place(children: Vec<String>, own: &str) -> Place {
    match position(&children, own) {
        None => Place::Missing,
        Some(0) => Place::First,
        Some(_) => {
            predecessor(&children, own).map_or(Place::Missing, |p| Place::After(p.to_owned()))
        }
    }
}

/// Waits on the predecessor watch until the order can have changed. The
/// result is true at a new connection epoch above `epoch`. The watch
/// then stays armed, and the caller keeps it for the next list.
///
/// An event, or a watch that the client did not restore, gives false.
///
/// # Errors
///
/// The error of a terminal session state or of a terminal watch error.
async fn new_epoch(
    watcher: &mut OneshotWatcher,
    state: &mut StateWatcher,
    epoch: u64,
) -> Result<bool, Error> {
    loop {
        match select(watcher, &mut state.changed()).await {
            Either::Left(Ok(_)) => return Ok(false),
            Either::Left(Err(e)) => return watch_terminal_error(&e).map_or(Ok(false), Err),
            Either::Right(info) => {
                if let Some(t) = terminal_error(info.state) {
                    return Err(t);
                }
                if info.state.is_connected() && info.epoch > epoch {
                    return Ok(true);
                }
            }
        }
    }
}

/// A held lock.
///
/// The drop gives the participant node to the guaranteed delete and
/// does not wait. The `delete` goes out at once. After a
/// connection loss, it goes out again at the next connection epoch of
/// the same session. [`release`](Self::release) deletes the node and
/// gives the server result.
#[derive(Debug)]
pub struct LockGuard {
    node: ParticipantNode,
    /// The session state of the holder. `lost` reads a clone of it.
    state: StateWatcher,
}

impl LockGuard {
    /// Makes the guard of a node that holds the lock.
    fn new(node: ParticipantNode, state: StateWatcher) -> Self {
        Self { node, state }
    }

    /// The full path of the participant node, without the chroot.
    #[must_use]
    pub fn node(&self) -> ZPath<'_> {
        self.node.path()
    }

    /// Deletes the participant node and gives the server result.
    ///
    /// After a connection loss, or `NotReadOnly`, the future waits for
    /// the next connection and sends the delete again. After a connection
    /// loss a `NoNode` reply to the retry is a success, because the first
    /// delete can have been applied. Each other `NoNode` reply is an
    /// error: another client deleted the node, so the lock was lost
    /// before the release. When the delete fails with another error, the
    /// guaranteed delete also takes the node.
    ///
    /// # Errors
    ///
    /// The error of the `delete`, or a terminal session error.
    pub async fn release(self) -> Result<(), Error> {
        self.node.delete_confirmed().await
    }

    /// Resolves when the lock is certainly lost.
    ///
    /// The result is the terminal error when the session ends, or
    /// `Error::NoNode` when another client deletes the participant node.
    /// The future arms `exists_watched` on the node, and arms it again at
    /// each new `epoch`. A `NodeDeleted` event, or a `None` result of
    /// that call, gives `Error::NoNode`. A `Connecting` state does not
    /// resolve it.
    ///
    /// Any other error of `exists_watched`, except a connection loss,
    /// also resolves the future. The state of the lock is then not
    /// known.
    pub async fn lost(&self) -> Error {
        let client = self.node.client();
        let mut state = self.state.clone();
        let mut watch: Option<OneshotWatcher> = None;
        // The epoch of the last arm. `None` asks for an arm at once.
        let mut armed_at: Option<u64> = None;
        loop {
            let info = state.current();
            if let Some(t) = terminal_error(info.state) {
                return t;
            }
            let due = info.state.is_connected() && armed_at.is_none_or(|at| info.epoch > at);
            if due {
                armed_at = Some(info.epoch);
                match client.exists_watched(self.node.path()).await {
                    Ok((None, _)) => return Error::NoNode,
                    // The old watcher drops after the new one is armed,
                    // so the server watch stays.
                    Ok((Some(_), w)) => watch = Some(w),
                    // The next epoch arms the watch again.
                    Err(e) if e.is_connection_loss() => {}
                    Err(e) => return e,
                }
                continue;
            }
            let mut changed = state.changed();
            match watch.as_mut() {
                Some(w) => match select(w, &mut changed).await {
                    Either::Left(Ok(event)) if event.kind == EventKind::NodeDeleted => {
                        return Error::NoNode;
                    }
                    // A data change, a removed watch or a watch that the
                    // client did not restore: arm again.
                    Either::Left(event) => {
                        if let Some(t) = event.err().as_ref().and_then(watch_terminal_error) {
                            return t;
                        }
                        watch = None;
                        armed_at = None;
                    }
                    Either::Right(_) => {}
                },
                None => {
                    changed.await;
                }
            }
        }
    }
}
