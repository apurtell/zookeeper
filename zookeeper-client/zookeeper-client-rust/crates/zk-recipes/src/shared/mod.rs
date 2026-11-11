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

//! Parts that the lock and the latch share, and the session
//! helpers of all three recipes.
//!
//! - `protected`: the protected-mode prefix `_c_<uuid>-` and its
//!   version-4 UUID.
//! - `order`: the participant order of Apache Curator.
//! - `parents`: container parents.
//! - `participant`: the participant create with the recovery after
//!   `ConnectionLoss`, and the node guard that deletes on drop.
//! - `guaranteed`: the guaranteed delete of the nodes that drops give
//!   up, with its background thread.
//! - `session`: the error mapping of terminal states and watch errors,
//!   and the wait for the next connection.
//! - `select`: a two-way select without a runtime.
//!
//! The lock and the latch share these parts, so the two recipes keep one
//! node layout and one recovery.

pub(crate) mod guaranteed;
pub(crate) mod order;
pub(crate) mod parents;
pub(crate) mod participant;
pub(crate) mod protected;
pub(crate) mod select;
pub(crate) mod session;
