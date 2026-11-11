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

//! `LeaderLatch`: leader election on one path.
//!
//! The latch has the node layout of Apache Curator's `LeaderLatch`.
//! Each participant makes `<latch_path>/_c_<uuid>-latch-<seq>` with its
//! participant id as the node data. The participant whose node is first
//! in Curator order is the leader. A participant that is not the leader
//! watches only the node just before its own.
//!
//! # Evaluation
//!
//! [`Latch`] keeps a small state machine. It evaluates the order, and
//! then it leads or it watches its predecessor. A lost connection
//! suspends it, and a new epoch makes it check its own node. A terminal
//! state ends it. Each step that waits keeps its request or its watcher
//! in a field of the latch. Thus a dropped [`Latch::changed`] future
//! loses nothing, and the next call continues from the same step.
//!
//! The leadership holds only while the session stays `Connected` in the
//! epoch of the last evaluation. Each other state revokes it at once.
//! At a new epoch the latch checks its own node with `exists`, and then
//! evaluates the order again.
//!
//! `ConnectedReadOnly` does not give leadership. A read-only server can
//! be in a minority partition, and its view of the order can be old.
//! Meanwhile the majority can expire the session and elect the next
//! participant. Thus the latch waits for a read-write connection. This
//! goes past Curator. Curator's `LeaderLatch` does not check
//! `READ_ONLY`, and it can lead on a read-only server through its
//! predecessor watch.
//!
//! # Choices
//!
//! - When the own node is not in the child list, another client deleted
//!   it. The latch makes a new node with a new `<uuid>`, as Curator's
//!   `reset` does.
//! - A create that fails with `NotReadOnly` waits for the next
//!   connection and tries again. A read-only server applies no write,
//!   so that create did not take effect.
//! - [`Latch::participants`] leaves out a child that goes away during
//!   the read, as Curator does. A missing latch path gives an empty
//!   list.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use apache_zookeeper::{
    Client, Error, OneshotWatcher, PathArg, ResponseFuture, SessionInfo, SessionState, Stat,
    StateWatcher, ZPath, ZPathBuf,
};

use crate::shared::order::{LATCH_MARKER, position, predecessor, sort_children};
use crate::shared::participant::{ParticipantNode, create_participant};
use crate::shared::protected::ProtectedId;
use crate::shared::select::{Either, select};
use crate::shared::session::{terminal_error, watch_terminal_error};

/// A leader election on one path.
///
/// The latch is compatible with Curator's `LeaderLatch` on the same
/// path. Each side reads the participant ids of the other side.
#[derive(Debug)]
pub struct LeaderLatch {
    client: Client,
    path: ZPathBuf,
    id: Vec<u8>,
}

impl LeaderLatch {
    /// Makes a latch on `latch_path` with a participant id. It sends
    /// nothing. The id is the node data, and Curator reads it as the
    /// participant id.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` when `latch_path` is not a valid path.
    pub fn new(
        client: &Client,
        latch_path: impl PathArg,
        participant_id: impl Into<Vec<u8>>,
    ) -> Result<LeaderLatch, Error> {
        let path = latch_path.to_zpath()?.to_buf();
        Ok(Self {
            client: client.clone(),
            path,
            id: participant_id.into(),
        })
    }

    /// Makes the participant node. It does not wait for
    /// leadership.
    ///
    /// The returned [`Latch`] has not evaluated the order yet, so
    /// [`Latch::is_leader`] is false until the first
    /// [`Latch::changed`] or [`Latch::await_leadership`].
    ///
    /// The future is cancellation-safe. When it
    /// is dropped before the create reply comes, the guaranteed delete
    /// waits for that reply. A success gives the node name, and the
    /// background thread deletes the node. A connection loss leaves the
    /// outcome unknown, so the guaranteed delete finds the node by its
    /// protected id and deletes it. The drop of a [`Latch`] while it
    /// makes a new node does the same.
    ///
    /// # Errors
    ///
    /// A terminal session error, or a server error such as `NoAuth`.
    pub async fn start(&self) -> Result<Latch, Error> {
        let state = self.client.state_watcher();
        let node = make_node(&self.client, self.path.as_path(), &self.id).await?;
        let epoch = state.current().epoch;
        Ok(Latch {
            client: self.client.clone(),
            path: self.path.clone(),
            id: self.id.clone(),
            node: Some(node),
            leader: false,
            state,
            epoch,
            step: Step::Evaluate,
            ended: None,
        })
    }
}

/// One started participant of a [`LeaderLatch`].
///
/// The evaluation of leadership runs only while the application awaits
/// [`changed`](Self::changed) or
/// [`await_leadership`](Self::await_leadership).
/// [`is_leader`](Self::is_leader) gives the last value.
///
/// On `Connecting` the latch reports `false` at once, because the
/// leadership is not certain. `ConnectedReadOnly` also reports `false`.
/// At the next `Connected` state of the same session (a new `epoch`),
/// the latch checks that its node exists and evaluates the order
/// again. When the node is gone, it makes a new one with a new
/// `<uuid>`. A terminal state ends the latch with the terminal error.
///
/// The drop gives the participant node to the guaranteed delete and
/// does not wait. The next participant then becomes the
/// leader. After a connection loss, the `delete` goes out again at the
/// next connection epoch of the same session.
#[derive(Debug)]
pub struct Latch {
    client: Client,
    /// The latch path, for the list and for a new node.
    path: ZPathBuf,
    /// The participant id: the data of each node that the latch makes.
    id: Vec<u8>,
    /// The own node. It is `None` while the latch makes a new node, and
    /// after the end.
    node: Option<ParticipantNode>,
    /// The last value that `changed` gave.
    leader: bool,
    state: StateWatcher,
    /// The connection epoch of the last check of the own node.
    epoch: u64,
    /// The step of the evaluation, with its request or watcher.
    step: Step,
    /// The terminal error. Each call after the end gives it again.
    ended: Option<Error>,
}

/// One step of the evaluation of [`Latch`].
#[derive(Debug)]
enum Step {
    /// List the children. No request is in flight.
    Evaluate,
    /// The list of the children is in flight.
    Listing(ResponseFuture<Vec<String>>),
    /// The watched read of the predecessor is in flight.
    Watching(ResponseFuture<(Vec<u8>, Stat, OneshotWatcher)>),
    /// Wait for an event on the predecessor.
    Waiting(OneshotWatcher),
    /// The own node is first. Wait for a change of the session.
    Leading,
    /// The connection is gone. Wait for a connection with a new epoch.
    Suspended,
    /// Check the own node at a new epoch. No request is in flight.
    Check,
    /// The `exists` of the own node is in flight.
    Checking(ResponseFuture<Option<Stat>>),
    /// Make a new node with a new `<uuid>`. No request is in flight.
    Create,
    /// The create of a new node is in flight.
    Creating(PendingNode),
    /// The latch ended or closed.
    Ended,
}

impl Latch {
    /// The last evaluated leadership.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.leader
    }

    /// Resolves at the next change of leadership with the new value.
    ///
    /// A change of the session to `Connecting`, to `ConnectedReadOnly`,
    /// or to a new epoch, ends the leadership at once with `Ok(false)`.
    /// `Ok(true)` comes only while the session is `Connected` in the
    /// epoch of the evaluation. When a terminal state
    /// ends the session of a leader, the call first gives `Ok(false)`.
    ///
    /// The future is cancellation-safe: a drop keeps the latch state.
    ///
    /// # Errors
    ///
    /// The terminal session error. A latch that ended gives the same
    /// error again. A server error of one request, for example `NoAuth`,
    /// comes back once, and the next call does the step again.
    pub async fn changed(&mut self) -> Result<bool, Error> {
        loop {
            if let Some(e) = &self.ended {
                return Err(e.clone());
            }
            match self.advance().await {
                // The session changed in the same poll as the reply that
                // found the own node first. The next step handles the
                // new state, so the leadership is not reported.
                Ok(Some(true)) if !self.holds() => {}
                Ok(Some(value)) if value != self.leader => {
                    self.leader = value;
                    return Ok(value);
                }
                Ok(_) => {}
                Err(e) if e.is_session_terminal() => {
                    self.end(e.clone());
                    if self.leader {
                        // The revocation comes before the error.
                        self.leader = false;
                        return Ok(false);
                    }
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Resolves when this participant is the leader. It
    /// resolves at once when the last evaluation says so and the session
    /// is `Connected` in the epoch of that evaluation.
    ///
    /// # Errors
    ///
    /// As for [`changed`](Self::changed).
    pub async fn await_leadership(&mut self) -> Result<(), Error> {
        loop {
            if let Some(e) = &self.ended {
                return Err(e.clone());
            }
            if self.leader && self.holds() {
                return Ok(());
            }
            if self.changed().await? {
                return Ok(());
            }
        }
    }

    /// Every participant with its id (the node data), in latch order.
    /// The first one is the leader.
    ///
    /// The reads of the node data go out together. A child that goes
    /// away during the read is left out, as Curator's `getParticipants`
    /// does. The first child that remains is the leader.
    ///
    /// # Errors
    ///
    /// The error of the list or of a read other than `NoNode`.
    pub async fn participants(&self) -> Result<Vec<Participant>, Error> {
        let mut children = match self.client.get_children(&self.path).await {
            Ok(children) => children,
            Err(Error::NoNode) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        sort_children(&mut children, LATCH_MARKER);
        let mut reads = Vec::with_capacity(children.len());
        for child in &children {
            let path = self.path.as_path().join(child)?;
            reads.push(self.client.get_data(&path));
        }
        let mut out: Vec<Participant> = Vec::with_capacity(reads.len());
        for read in reads {
            match read.await {
                Ok((id, _)) => {
                    let is_leader = out.is_empty();
                    out.push(Participant { id, is_leader });
                }
                Err(Error::NoNode) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Deletes the participant node and gives the server result.
    ///
    /// When the latch makes a new node at this time, `close` waits for
    /// that create and deletes the new node. When the latch has no node,
    /// it sends nothing and gives `Ok(())`.
    ///
    /// A node that stays after the close blocks the next leader until
    /// the session ends. Thus a connection loss, or `NotReadOnly`, waits
    /// for the next connection and sends the delete again, as
    /// [`LockGuard::release`](crate::LockGuard::release) does. After a
    /// connection loss a `NoNode` reply to the retry is a success. Each
    /// other `NoNode` reply is an error, because another client deleted
    /// the node. When the delete fails with another error, the guaranteed
    /// delete also takes the node.
    ///
    /// # Errors
    ///
    /// The error of the `delete`, or a terminal session error. A latch
    /// that ended gives its terminal error.
    pub async fn close(mut self) -> Result<(), Error> {
        if let Some(e) = self.ended.take() {
            return Err(e);
        }
        let step = std::mem::replace(&mut self.step, Step::Ended);
        let node = match (self.node.take(), step) {
            (Some(node), _) => node,
            (None, Step::Creating(pending)) => pending.await?,
            (None, _) => return Ok(()),
        };
        node.delete_confirmed().await
    }

    /// True when the last evaluation found the own node first, and the
    /// session is `Connected` in the epoch of that evaluation. A
    /// read-only connection does not count.
    fn holds(&self) -> bool {
        let info = self.state.current();
        matches!(self.step, Step::Leading)
            && info.state == SessionState::Connected
            && info.epoch == self.epoch
    }

    /// Ends the latch with a terminal error. The session is gone, so the
    /// node goes away with it, and the latch sends no `delete`.
    fn end(&mut self, e: Error) {
        self.ended = Some(e);
        self.step = Step::Ended;
        if let Some(node) = self.node.take() {
            node.forget();
        }
    }

    /// Gives up the own node, which is gone, and makes a new node next.
    fn node_gone(&mut self) {
        if let Some(node) = self.node.take() {
            node.forget();
        }
        self.step = Step::Create;
    }

    /// Does one step of the evaluation.
    ///
    /// It gives `Some(value)` when the step finds the leadership, and
    /// `None` when the evaluation must go on. Each call that gives
    /// `None` waits for a reply, a watch event or a change of the
    /// session, so the loop of `changed` does not spin.
    async fn advance(&mut self) -> Result<Option<bool>, Error> {
        let info = self.state.current();
        if let Some(e) = terminal_error(info.state) {
            return Err(e);
        }
        if self.revoke(&info) {
            return Ok(Some(false));
        }
        match &mut self.step {
            Step::Evaluate => {
                let list = self.client.get_children(&self.path);
                self.go(Step::Listing(list))
            }
            Step::Listing(reply) => match race(reply, &mut self.state).await {
                Some(out) => self.listed(out),
                None => Ok(None),
            },
            Step::Watching(reply) => match race(reply, &mut self.state).await {
                Some(Ok((_, _, watcher))) => self.go(Step::Waiting(watcher)),
                // The predecessor went away before the read.
                Some(Err(Error::NoNode)) => self.go(Step::Evaluate),
                Some(Err(e)) => self.failed(e, Step::Evaluate),
                None => Ok(None),
            },
            Step::Waiting(watcher) => match race(watcher, &mut self.state).await {
                Some(out) => match out.err().as_ref().and_then(watch_terminal_error) {
                    Some(e) => Err(e),
                    // Each other outcome can change the order.
                    None => self.go(Step::Evaluate),
                },
                None => Ok(None),
            },
            Step::Leading | Step::Suspended => {
                let _ = self.state.changed().await;
                Ok(None)
            }
            Step::Check => match &self.node {
                Some(node) => self.go(Step::Checking(self.client.exists(node.path()))),
                None => self.go(Step::Create),
            },
            Step::Checking(reply) => match race(reply, &mut self.state).await {
                Some(Ok(Some(_))) => self.go(Step::Evaluate),
                Some(Ok(None)) => {
                    self.node_gone();
                    Ok(None)
                }
                Some(Err(e)) => self.failed(e, Step::Check),
                None => Ok(None),
            },
            Step::Create => {
                let pending = self.new_node();
                self.go(Step::Creating(pending))
            }
            Step::Creating(pending) => match race(pending, &mut self.state).await {
                Some(Ok(node)) => {
                    self.node = Some(node);
                    self.epoch = self.state.current().epoch;
                    self.go(Step::Evaluate)
                }
                Some(Err(e)) => self.failed(e, Step::Create),
                None => Ok(None),
            },
            Step::Ended => Err(self.ended.clone().unwrap_or(Error::Closing)),
        }
    }

    /// Applies a change of the session to the step. The result is true
    /// when the change ends the leadership at once.
    ///
    /// A create in flight does its own recovery after a connection loss,
    /// so a change of the session does not stop it. Only a
    /// read-write connection can lead, so a read-only one suspends the
    /// latch as `Connecting` does. After a new epoch, the latch checks
    /// its own node again.
    fn revoke(&mut self, info: &SessionInfo) -> bool {
        if matches!(self.step, Step::Create | Step::Creating(_)) {
            return false;
        }
        if info.state != SessionState::Connected {
            if matches!(self.step, Step::Suspended) {
                return false;
            }
            self.step = Step::Suspended;
            return true;
        }
        if info.epoch <= self.epoch {
            return false;
        }
        self.epoch = info.epoch;
        self.step = Step::Check;
        true
    }

    /// Moves to `step`. The evaluation goes on.
    fn go(&mut self, step: Step) -> Result<Option<bool>, Error> {
        self.step = step;
        Ok(None)
    }

    /// Applies the child list to the leadership.
    fn listed(&mut self, out: Result<Vec<String>, Error>) -> Result<Option<bool>, Error> {
        let mut children = match out {
            Ok(children) => children,
            // The latch path is gone, so the own node is gone too.
            Err(Error::NoNode) => {
                self.node_gone();
                return Ok(Some(false));
            }
            Err(e) => return self.failed(e, Step::Evaluate),
        };
        sort_children(&mut children, LATCH_MARKER);
        let Some(own) = self.node.as_ref().map(ParticipantNode::name) else {
            self.step = Step::Create;
            return Ok(Some(false));
        };
        if position(&children, own) == Some(0) {
            self.step = Step::Leading;
            return Ok(Some(true));
        }
        let Some(before) = predecessor(&children, own) else {
            // Another client deleted the own node.
            self.node_gone();
            return Ok(Some(false));
        };
        match self.path.as_path().join(before) {
            Ok(path) => {
                self.step = Step::Watching(self.client.get_data_watched(&path));
                Ok(Some(false))
            }
            Err(e) => self.failed(e.into(), Step::Evaluate),
        }
    }

    /// Handles the error of a step. After a connection loss the latch
    /// waits for the next epoch. A terminal error goes to the caller,
    /// which ends the latch. Each other error goes to the caller once,
    /// and `next` runs at the next call.
    fn failed(&mut self, e: Error, next: Step) -> Result<Option<bool>, Error> {
        if e.is_connection_loss() {
            return self.go(Step::Suspended);
        }
        self.step = next;
        Err(e)
    }

    /// Starts the create of a new node with a new `<uuid>`.
    fn new_node(&self) -> PendingNode {
        let client = self.client.clone();
        let path = self.path.clone();
        let data = self.id.clone();
        PendingNode(Mutex::new(Box::pin(async move {
            make_node(&client, path.as_path(), &data).await
        })))
    }
}

/// Waits for `step` or for a change of the session. It gives `None` on
/// a change of the session, and `step` keeps its state.
async fn race<F: Future + Unpin>(step: &mut F, state: &mut StateWatcher) -> Option<F::Output> {
    match select(step, &mut state.changed()).await {
        Either::Left(out) => Some(out),
        Either::Right(_) => None,
    }
}

/// Makes a participant node with a new `<uuid>`. The shared create does
/// the recovery after a connection loss and after `NotReadOnly`.
async fn make_node(
    client: &Client,
    path: ZPath<'_>,
    data: &[u8],
) -> Result<ParticipantNode, Error> {
    create_participant(client, path, &ProtectedId::new(), LATCH_MARKER, data).await
}

/// The create of a new node as an owned future, which the latch keeps.
///
/// The mutex makes the future `Sync`, so `&Latch` is `Send`, and the
/// future of [`Latch::participants`] is `Send`. Only `&mut` access
/// reaches the future, so the mutex never locks.
struct PendingNode(Mutex<NodeFuture>);

/// The boxed create of [`PendingNode`].
type NodeFuture = Pin<Box<dyn Future<Output = Result<ParticipantNode, Error>> + Send>>;

impl Future for PendingNode {
    type Output = Result<ParticipantNode, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let fut = self
            .get_mut()
            .0
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        fut.as_mut().poll(cx)
    }
}

impl fmt::Debug for PendingNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingNode").finish_non_exhaustive()
    }
}

/// One participant of a latch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participant {
    /// The participant id: the data of the participant node.
    pub id: Vec<u8>,
    /// True for the first participant in latch order.
    pub is_leader: bool,
}
