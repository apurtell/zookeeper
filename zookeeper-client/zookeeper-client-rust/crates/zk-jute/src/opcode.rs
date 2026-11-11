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

//! Operation codes of the request header and the multi header.
//!
//! The values are those of `proto.h` in the C client and of `ZooDefs.OpCode`
//! in the Java client. The names drop the `ZOO_` prefix and the `_OP` suffix
//! of the C names. Some codes exist only for the native client, because the
//! C client never sends them.

/// A watch notification.
pub const NOTIFY: i32 = 0;
/// Create a node.
pub const CREATE: i32 = 1;
/// Delete a node.
pub const DELETE: i32 = 2;
/// Test whether a node exists.
pub const EXISTS: i32 = 3;
/// Read the data of a node.
pub const GET_DATA: i32 = 4;
/// Write the data of a node.
pub const SET_DATA: i32 = 5;
/// Read the ACL of a node.
pub const GET_ACL: i32 = 6;
/// Write the ACL of a node.
pub const SET_ACL: i32 = 7;
/// List the children of a node.
pub const GET_CHILDREN: i32 = 8;
/// Synchronize with the leader.
pub const SYNC: i32 = 9;
/// Keep the session alive.
pub const PING: i32 = 11;
/// List the children of a node and return its `Stat`.
pub const GET_CHILDREN2: i32 = 12;
/// Check the version of a node inside a multi transaction.
pub const CHECK: i32 = 13;
/// Run a multi transaction.
pub const MULTI: i32 = 14;
/// Create a node and return its `Stat`.
pub const CREATE2: i32 = 15;
/// Change the ensemble membership.
pub const RECONFIG: i32 = 16;
/// Check that the server has a watch.
pub const CHECK_WATCHES: i32 = 17;
/// Remove watches.
pub const REMOVE_WATCHES: i32 = 18;
/// Create a container node.
pub const CREATE_CONTAINER: i32 = 19;
/// Delete a container node (server internal).
pub const DELETE_CONTAINER: i32 = 20;
/// Create a node with a time to live.
pub const CREATE_TTL: i32 = 21;
/// Run a multi read (native client only).
pub const MULTI_READ: i32 = 22;
/// Close the session.
pub const CLOSE: i32 = -11;
/// Add authentication data.
pub const SET_AUTH: i32 = 100;
/// Restore watches after a reconnect.
pub const SET_WATCHES: i32 = 101;
/// Send a SASL token.
pub const SASL: i32 = 102;
/// List the ephemeral nodes of the session (native client only).
pub const GET_EPHEMERALS: i32 = 103;
/// Count all descendants of a node (native client only).
pub const GET_ALL_CHILDREN_NUMBER: i32 = 104;
/// Restore watches, persistent watches included (native client only).
pub const SET_WATCHES2: i32 = 105;
/// Add a persistent watch (native client only).
pub const ADD_WATCH: i32 = 106;
/// Ask the server for the identity of the session (native client only).
pub const WHO_AM_I: i32 = 107;
/// The multi header type of a failed operation and of the terminator.
pub const ERROR: i32 = -1;
