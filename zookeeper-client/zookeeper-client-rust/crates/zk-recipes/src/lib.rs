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

//! Coordination recipes for Apache ZooKeeper.
//!
//! The crate gives three recipes on top of the public API of
//! [`apache_zookeeper`]:
//!
//! - [`DistributedLock`]: a non-reentrant mutual exclusion lock with the
//!   node layout of Apache Curator's `InterProcessMutex`.
//! - [`LeaderLatch`]: leader election with the node layout of Curator's
//!   `LeaderLatch`.
//! - [`TreeCache`]: an in-memory copy of a subtree that a persistent
//!   recursive watch keeps current.
//!
//! # Rules
//!
//! - The recipes use only the public client API. A recipe can do
//!   nothing that an application cannot do itself.
//! - No recipe starts a task. A recipe makes progress only while the
//!   application awaits one of its futures. The futures work on any
//!   executor, and each returned future is `Send`. The one exception is
//!   the guaranteed delete below.
//! - The recipes have no timer. An application bounds a wait with the
//!   timeout of its executor, for example `tokio::time::timeout`.
//! - Each future is cancellation-safe. When the application drops a
//!   future that waits, the future submits a `delete` for each node
//!   that it created and does not give to the caller.
//! - The delete of a participant node is guaranteed, as in Curator. A
//!   drop sends the `delete` at once. When a connection loss stops it,
//!   one background thread of the process, `zk-recipes-delete`, sends
//!   it again at each new `Connected` epoch of the same session. When a
//!   full request queue refuses it, the thread sends it again when the
//!   queue has room. A create that a drop abandons before its reply
//!   also uses the thread. When the outcome of a create is not known,
//!   the thread finds the node by its protected id. The thread starts
//!   only for this work, and it stops when no work is left. It does not
//!   keep a session open. Its work ends when the client reaches a
//!   terminal state, also after a detach. The resumed session then
//!   keeps each node whose delete is not confirmed. Thus release or
//!   close the recipe objects before a detach.
//! - The methods return [`apache_zookeeper::Error`]. A terminal session
//!   state ends each recipe with `SessionExpired`, `AuthFailed` or
//!   `Closing`. The application then makes a new client and new recipe
//!   objects.
//!
//! # Server versions
//!
//! `DistributedLock` and `LeaderLatch` need ZooKeeper 3.5.1 or later,
//! because they create container parents. `TreeCache` needs 3.6 or
//! later, because it uses persistent recursive watches.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::disallowed_macros
    )
)]

mod latch;
mod lock;
mod shared;
mod tree_cache;

pub use latch::{Latch, LeaderLatch, Participant};
pub use lock::{DistributedLock, LockGuard};
pub use tree_cache::{CachedNode, TreeCache, TreeCacheBuilder, TreeEvent};
