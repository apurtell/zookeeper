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

//! The participant node of the lock and the latch.
//!
//! A participant is one `EphemeralSequential` node with a protected
//! name. [`create_participant`] makes it and runs Curator's
//! protected-mode recovery after a `ConnectionLoss`. [`ParticipantNode`]
//! owns the node and deletes it on drop.
//!
//! Requests go out at call time, and the drop of a
//! `ResponseFuture` does not cancel the request. Thus a `Drop` impl can
//! submit a `delete` with no executor. This is the cancellation design
//! of every recipe.
//!
//! A drop cannot wait for a result. Thus each drop gives its node to
//! the guaranteed delete of [`super::guaranteed`]. A drop of a known
//! node gives the path. A drop while the outcome of a create is not
//! known gives the protected id, because the node name is not known.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{
    Client, CreateMode, Error, ResponseFuture, SessionState, Stat, StateWatcher, Version, ZPath,
    ZPathBuf,
};

use super::guaranteed;
use super::parents::ensure_parents;
use super::protected::ProtectedId;
use super::session::{connected_after, is_retryable, synced_list};

/// The participant node of this process. The drop gives the node to
/// the guaranteed delete and does not wait.
#[derive(Debug)]
pub(crate) struct ParticipantNode {
    client: Client,
    path: ZPathBuf,
    /// False after `forget`, so the drop sends nothing.
    armed: bool,
}

impl ParticipantNode {
    /// Takes ownership of a node that exists.
    pub(crate) fn new(client: &Client, path: ZPathBuf) -> Self {
        Self {
            client: client.clone(),
            path,
            armed: true,
        }
    }

    /// The full path of the node, without the chroot.
    pub(crate) fn path(&self) -> ZPath<'_> {
        self.path.as_path()
    }

    /// The last component of the path: the child name in the parent.
    pub(crate) fn name(&self) -> &str {
        self.path.as_path().name().unwrap_or_default()
    }

    /// The client that owns the session of the node.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// Gives up the node with no `delete`, for a node that is already
    /// gone.
    pub(crate) fn forget(mut self) {
        self.armed = false;
    }

    /// Deletes the node and waits for the server result.
    ///
    /// A delete with an unknown result must not leave the node. A lock
    /// node that stays blocks the next participant until the session
    /// ends. Thus a connection loss, or `NotReadOnly`, waits for the next
    /// connection and sends the delete again. The node stays armed during
    /// the wait, so a drop of the future gives the node to the guaranteed
    /// delete.
    ///
    /// After a connection loss, the earlier delete can have been
    /// applied. Thus a later `NoNode` reply is a success. A read-only
    /// server applies no delete, so `NotReadOnly` alone does not change
    /// the meaning of `NoNode`: another client deleted the node. A loss
    /// on a read-only connection also does not change it, because that
    /// delete reached no server that applies writes.
    ///
    /// Each other error leaves the node in place. The caller gets the
    /// error, and the guaranteed delete also takes the node.
    ///
    /// # Errors
    ///
    /// `NoNode` when no delete that can have been applied came before,
    /// a terminal session error, or another error of the delete.
    pub(crate) async fn delete_confirmed(self) -> Result<(), Error> {
        let mut state = self.client.state_watcher();
        // True after a delete with an unknown outcome.
        let mut maybe_applied = false;
        let result = loop {
            let sent = state.current();
            let sent = (sent.state, sent.epoch);
            match self.client.delete(&self.path, None::<Version>).await {
                Err(Error::NoNode) if maybe_applied => break Ok(()),
                Err(e) if is_retryable(&e) => {
                    maybe_applied |= e.is_connection_loss() && !read_only_epoch(&state, sent);
                    if let Err(t) = connected_after(&mut state, sent.1).await {
                        break Err(t);
                    }
                }
                other => break other,
            }
        };
        match &result {
            // The node is gone, or it goes away with the session.
            Ok(()) | Err(Error::NoNode) => self.forget(),
            Err(e) if e.is_session_terminal() => self.forget(),
            // The drop of `self` gives the node to the guaranteed delete.
            Err(_) => {}
        }
        result
    }
}

/// True when the session was read-only at `sent` (state and epoch) and
/// is still in the same epoch. A request of that time went out on the
/// read-only connection, so the server did not apply it. A request that
/// waited for a later connection sees a later epoch, so the check is
/// false.
fn read_only_epoch(state: &StateWatcher, sent: (SessionState, u64)) -> bool {
    sent.0 == SessionState::ConnectedReadOnly && state.current().epoch == sent.1
}

impl Drop for ParticipantNode {
    fn drop(&mut self) {
        if self.armed {
            guaranteed::delete(&self.client, self.path.clone());
        }
    }
}

/// A participant create in flight.
///
/// A drop before the caller took the reply gives the create to the
/// guaranteed delete. A reply that is ready gives the node name, so the
/// drop deletes the node at once. A ready connection loss leaves the
/// outcome unknown, so the guaranteed delete looks for the id. With no
/// reply yet, the guaranteed delete watches the reply.
struct PendingCreate<'a> {
    client: &'a Client,
    parent: ZPath<'a>,
    id: &'a ProtectedId,
    /// The epoch when the create went out.
    sent: u64,
    reply: Option<ResponseFuture<(ZPathBuf, Stat)>>,
}

impl Future for PendingCreate<'_> {
    type Output = Result<(ZPathBuf, Stat), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(reply) = this.reply.as_mut() else {
            // Polled again after the result. The recipes never do it.
            return Poll::Ready(Err(Error::InvalidState));
        };
        let out = Pin::new(reply).poll(cx);
        if out.is_ready() {
            this.reply = None;
        }
        out
    }
}

impl Drop for PendingCreate<'_> {
    fn drop(&mut self) {
        let Some(mut reply) = self.reply.take() else {
            return;
        };
        let parent = self.parent.to_buf();
        if !reply.is_ready() {
            guaranteed::abandon_create(self.client, parent, self.id.clone(), self.sent, reply);
            return;
        }
        let mut cx = Context::from_waker(Waker::noop());
        match Pin::new(&mut reply).poll(&mut cx) {
            Poll::Ready(Ok((path, _))) => guaranteed::delete(self.client, path),
            Poll::Ready(Err(e)) if e.is_connection_loss() => {
                guaranteed::find_and_delete(self.client, parent, self.id.clone(), self.sent);
            }
            // The server refused the create, so no node exists.
            _ => {}
        }
    }
}

/// The time after a connection loss on the create and before the
/// recovery finds the result. A drop in this time gives the id to the
/// guaranteed delete, because the create can have been applied.
struct Unresolved<'a> {
    client: &'a Client,
    parent: ZPath<'a>,
    id: &'a ProtectedId,
    /// The epoch when the create went out.
    sent: u64,
    armed: bool,
}

impl Drop for Unresolved<'_> {
    fn drop(&mut self) {
        if self.armed {
            guaranteed::find_and_delete(
                self.client,
                self.parent.to_buf(),
                self.id.clone(),
                self.sent,
            );
        }
    }
}

/// Makes the participant node `<parent>/_c_<uuid>-<marker><seq>` with
/// `data`.
///
/// The steps:
/// 1. Create the node as `EphemeralSequential` with the open ACL.
/// 2. On `NoNode`, make the missing parents as containers, then go to
///    step 1.
/// 3. On a connection loss, the create can still be applied.
///    Wait for the next connection, `sync` and list the parent, and
///    adopt the child whose name starts with `_c_<uuid>-`. When no child
///    has the prefix, go to step 1 with the same `id`.
/// 4. On `NotReadOnly`, the server did not apply the create. Wait for
///    the next connection, then go to step 1.
///
/// A drop of the future while the outcome is not known gives `id` to
/// the guaranteed delete.
///
/// # Errors
///
/// A terminal session error, or any other create or list error, for
/// example `NoAuth`.
pub(crate) async fn create_participant(
    client: &Client,
    parent: ZPath<'_>,
    id: &ProtectedId,
    marker: &str,
    data: &[u8],
) -> Result<ParticipantNode, Error> {
    let path = parent.join(&id.node_name(marker))?;
    let mut state = client.state_watcher();
    loop {
        let epoch = state.current().epoch;
        let create = PendingCreate {
            client,
            parent,
            id,
            sent: epoch,
            reply: Some(client.create(
                &path,
                data,
                CreateMode::EphemeralSequential,
                OPEN_ACL_UNSAFE,
            )),
        };
        match create.await {
            Ok((created, _)) => return Ok(ParticipantNode::new(client, created)),
            Err(Error::NoNode) => match ensure_parents(client, parent).await {
                Ok(()) | Err(Error::NoNode) => {}
                Err(e) if e.is_connection_loss() => {}
                Err(e) => return Err(e),
            },
            Err(e) if e.is_connection_loss() => {
                let mut unresolved = Unresolved {
                    client,
                    parent,
                    id,
                    sent: epoch,
                    armed: true,
                };
                connected_after(&mut state, epoch).await?;
                let found = find_protected(client, parent, id, &mut state).await?;
                unresolved.armed = false;
                if let Some(node) = found {
                    return Ok(node);
                }
            }
            // A read-only server refuses the create, so it was not
            // applied. The next connection can reach a server that
            // accepts writes.
            Err(Error::NotReadOnly) => {
                connected_after(&mut state, epoch).await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Lists `parent` and adopts the child with the prefix of `id`. A
/// missing parent means that no child exists.
async fn find_protected(
    client: &Client,
    parent: ZPath<'_>,
    id: &ProtectedId,
    state: &mut StateWatcher,
) -> Result<Option<ParticipantNode>, Error> {
    let children = synced_children(client, parent, state).await?;
    match children.as_deref().and_then(|c| id.find_in(c)) {
        Some(name) => Ok(Some(ParticipantNode::new(client, parent.join(name)?))),
        None => Ok(None),
    }
}

/// Lists `parent` after a `sync`. It gives `None` when `parent` is
/// missing.
///
/// After a reconnect, the client can reach a follower that did not yet
/// apply a create of the old connection. The `sync` makes the server
/// catch up with the leader before the list. Thus the list shows each
/// create that the ensemble applied. Curator lists with no `sync`, so
/// this goes past Curator.
///
/// The two requests go out together. The server keeps the order of one
/// session, so the list waits for the `sync`. A read-only server refuses
/// the `sync`. A connection loss or `NotReadOnly` waits for the next
/// connection and tries again.
async fn synced_children(
    client: &Client,
    parent: ZPath<'_>,
    state: &mut StateWatcher,
) -> Result<Option<Vec<String>>, Error> {
    loop {
        let epoch = state.current().epoch;
        let sync = client.sync(parent);
        let mut list = client.get_children(parent);
        match synced_list(sync, &mut list).await {
            Ok(children) => return Ok(Some(children)),
            Err(Error::NoNode) => return Ok(None),
            Err(e) if is_retryable(&e) => {
                connected_after(state, epoch).await?;
            }
            Err(e) => return Err(e),
        }
    }
}
