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

//! The full read of a `TreeCache`.
//!
//! The read goes breadth-first from the root. For each node it sends a node
//! read and a `get_children` together, and it awaits the replies in call
//! order. The initial sync and each resync use it.
//!
//! The read keeps its requests in its own fields and makes progress
//! only in `poll`. Thus a dropped `next` loses no reply, and the next
//! call goes on from the same point. At most `WINDOW` nodes are in
//! flight. This bound keeps the replies that wait for the cache below
//! the delivery bound of the client (`dispatch_queue_capacity`).
//!
//! A `NoNode` reply means that the node went away during the read. The
//! node and its subtree are then not in the result. The events that
//! the watch gives during the read correct the result later.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use apache_zookeeper::{Client, Error, ResponseFuture, Stat, ZPath, ZPathBuf};

use super::CachedNode;
use super::tree::Tree;

/// The most nodes in flight at one time. Each node has two requests.
const WINDOW: usize = 256;

/// One reply that the read keeps until it uses it.
#[derive(Debug)]
pub(super) struct Reply<T> {
    fut: Option<ResponseFuture<T>>,
    out: Option<Result<T, Error>>,
}

impl<T> Reply<T> {
    fn new(fut: ResponseFuture<T>) -> Self {
        Self {
            fut: Some(fut),
            out: None,
        }
    }

    /// Polls the request. The result is true when the reply is there.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> bool {
        if self.out.is_some() {
            return true;
        }
        let Some(fut) = self.fut.as_mut() else {
            return true;
        };
        match Pin::new(fut).poll(cx) {
            Poll::Ready(r) => {
                self.out = Some(r);
                self.fut = None;
                true
            }
            Poll::Pending => false,
        }
    }

    /// Takes the reply. The read takes each reply once. A second take
    /// gives `Closing`.
    fn take(&mut self) -> Result<T, Error> {
        self.out.take().unwrap_or(Err(Error::Closing))
    }
}

/// The read of one node: `get_data`, or `exists` when the cache keeps
/// no data.
#[derive(Debug)]
pub(super) enum NodeRead {
    /// `get_data`, for `cache_data(true)`.
    Data(Reply<(Vec<u8>, Stat)>),
    /// `exists`, for `cache_data(false)`. It moves no data.
    Stat(Reply<Option<Stat>>),
}

impl NodeRead {
    /// Sends the read of `path`.
    pub(super) fn submit(client: &Client, path: ZPath<'_>, cache_data: bool) -> Self {
        if cache_data {
            Self::Data(Reply::new(client.get_data(path)))
        } else {
            Self::Stat(Reply::new(client.exists(path)))
        }
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> bool {
        match self {
            Self::Data(r) => r.poll_ready(cx),
            Self::Stat(r) => r.poll_ready(cx),
        }
    }

    /// Takes the node, or `None` when it does not exist.
    fn take(&mut self) -> Result<Option<CachedNode>, Error> {
        match self {
            Self::Data(r) => match r.take() {
                Ok((data, stat)) => Ok(Some(CachedNode {
                    stat,
                    data: Some(Arc::from(data)),
                })),
                Err(Error::NoNode) => Ok(None),
                Err(e) => Err(e),
            },
            Self::Stat(r) => r
                .take()
                .map(|s| s.map(|stat| CachedNode { stat, data: None })),
        }
    }

    /// Waits for the node, or `None` when it does not exist.
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<CachedNode>, Error>> {
        if self.poll_ready(cx) {
            Poll::Ready(self.take())
        } else {
            Poll::Pending
        }
    }
}

/// One node in flight.
#[derive(Debug)]
struct InFlight {
    path: ZPathBuf,
    depth: usize,
    node: NodeRead,
    /// `None` at the depth limit: the read does not list children there.
    children: Option<Reply<Vec<String>>>,
}

impl InFlight {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> bool {
        self.node.poll_ready(cx) && self.children.as_mut().is_none_or(|c| c.poll_ready(cx))
    }

    /// The node and its child names, or `None` when the node went away.
    fn take(&mut self) -> Result<Option<(CachedNode, Vec<String>)>, Error> {
        let Some(node) = self.node.take()? else {
            return Ok(None);
        };
        let names = match self.children.as_mut().map(Reply::take) {
            None => Vec::new(),
            Some(Ok(names)) => names,
            Some(Err(Error::NoNode)) => return Ok(None),
            Some(Err(e)) => return Err(e),
        };
        Ok(Some((node, names)))
    }
}

/// A breadth-first read of the subtree. `poll` gives the new tree.
#[derive(Debug)]
pub(super) struct Read {
    /// The session epoch when the read started.
    epoch: u64,
    cache_data: bool,
    max_depth: Option<usize>,
    /// The nodes to read, in breadth-first order, with their depths.
    todo: VecDeque<(ZPathBuf, usize)>,
    /// The nodes in flight, in call order.
    flight: VecDeque<InFlight>,
    tree: Tree,
}

impl Read {
    /// Starts the read of the subtree at `root`, and sends the first
    /// requests. `epoch` is the session epoch now.
    pub(super) fn start(
        client: &Client,
        root: &ZPathBuf,
        cache_data: bool,
        max_depth: Option<usize>,
        epoch: u64,
    ) -> Self {
        let mut read = Self {
            epoch,
            cache_data,
            max_depth,
            todo: VecDeque::from([(root.clone(), 0)]),
            flight: VecDeque::new(),
            tree: Tree::new(root.clone()),
        };
        read.fill(client);
        read
    }

    /// The session epoch when the read started.
    pub(super) fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sends the requests of the next nodes, up to the window.
    fn fill(&mut self, client: &Client) {
        while self.flight.len() < WINDOW {
            let Some((path, depth)) = self.todo.pop_front() else {
                return;
            };
            let node = NodeRead::submit(client, path.as_path(), self.cache_data);
            let children = if self.max_depth.is_some_and(|m| depth >= m) {
                None
            } else {
                Some(Reply::new(client.get_children(&path)))
            };
            self.flight.push_back(InFlight {
                path,
                depth,
                node,
                children,
            });
        }
    }

    /// Drives the read. It gives the tree of the read, or the first
    /// error that is not `NoNode`.
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        client: &Client,
    ) -> Poll<Result<Tree, Error>> {
        loop {
            self.fill(client);
            let Some(front) = self.flight.front_mut() else {
                let empty = Tree::new(self.tree.root().to_buf());
                return Poll::Ready(Ok(std::mem::replace(&mut self.tree, empty)));
            };
            if !front.poll_ready(cx) {
                return Poll::Pending;
            }
            let Some(mut done) = self.flight.pop_front() else {
                continue;
            };
            let (node, mut names) = match done.take() {
                Ok(Some(found)) => found,
                Ok(None) => continue,
                Err(e) => return Poll::Ready(Err(e)),
            };
            // Breadth-first order keeps each parent ahead of its
            // children, so the insert finds the parent.
            if !self.tree.insert(done.path.as_path(), node) {
                continue;
            }
            names.sort();
            let Some(depth) = done.depth.checked_add(1) else {
                continue;
            };
            for name in names {
                // A server name always makes a valid path. Skip any other.
                if let Ok(child) = done.path.as_path().join(&name) {
                    self.todo.push_back((child, depth));
                }
            }
        }
    }
}
