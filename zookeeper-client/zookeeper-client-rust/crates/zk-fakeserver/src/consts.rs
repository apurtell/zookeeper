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

//! Constants of the ZooKeeper client API that tests use with the server.

/// Watch event types and keeper states.
pub mod event {
    /// No event type, for a state change.
    pub const NONE: i32 = -1;
    /// A node was created.
    pub const NODE_CREATED: i32 = 1;
    /// A node was deleted.
    pub const NODE_DELETED: i32 = 2;
    /// The data of a node changed.
    pub const NODE_DATA_CHANGED: i32 = 3;
    /// The children of a node changed.
    pub const NODE_CHILDREN_CHANGED: i32 = 4;
    /// A data watch was removed.
    pub const DATA_WATCH_REMOVED: i32 = 5;
    /// A child watch was removed.
    pub const CHILD_WATCH_REMOVED: i32 = 6;
    /// A persistent watch was removed.
    pub const PERSISTENT_WATCH_REMOVED: i32 = 7;
    /// The keeper state of a connected session.
    pub const SYNC_CONNECTED: i32 = 3;
    /// The keeper state of a session on a read-only server.
    pub const CONNECTED_READ_ONLY: i32 = 5;
    /// The keeper state of an expired session.
    pub const EXPIRED: i32 = -112;
}

/// ACL permission bits.
pub mod perms {
    /// Read the data and the children.
    pub const READ: i32 = 1;
    /// Set the data.
    pub const WRITE: i32 = 2;
    /// Create children.
    pub const CREATE: i32 = 4;
    /// Delete children.
    pub const DELETE: i32 = 8;
    /// Set the ACL.
    pub const ADMIN: i32 = 16;
    /// Every permission.
    pub const ALL: i32 = 31;
}

/// Create flags.
pub mod create_mode {
    /// A persistent node.
    pub const PERSISTENT: i32 = 0;
    /// An ephemeral node.
    pub const EPHEMERAL: i32 = 1;
    /// A persistent sequential node.
    pub const PERSISTENT_SEQUENTIAL: i32 = 2;
    /// An ephemeral sequential node.
    pub const EPHEMERAL_SEQUENTIAL: i32 = 3;
    /// A container node.
    pub const CONTAINER: i32 = 4;
    /// A persistent node with a TTL.
    pub const PERSISTENT_WITH_TTL: i32 = 5;
    /// A persistent sequential node with a TTL.
    pub const PERSISTENT_SEQUENTIAL_WITH_TTL: i32 = 6;
}

/// Watcher types of checkWatches and removeWatches.
pub mod watcher_type {
    /// Child watches.
    pub const CHILDREN: i32 = 1;
    /// Data watches.
    pub const DATA: i32 = 2;
    /// Every watch.
    pub const ANY: i32 = 3;
    /// Persistent watches.
    pub const PERSISTENT: i32 = 4;
    /// Persistent recursive watches.
    pub const PERSISTENT_RECURSIVE: i32 = 5;
}

/// Modes of addWatch.
pub mod add_watch_mode {
    /// A persistent watch on one node.
    pub const PERSISTENT: i32 = 0;
    /// A persistent watch on a node and its subtree.
    pub const PERSISTENT_RECURSIVE: i32 = 1;
}
