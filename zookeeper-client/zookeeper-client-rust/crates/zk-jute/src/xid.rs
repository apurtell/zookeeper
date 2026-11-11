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

//! Reserved transaction identifiers.
//!
//! The server recognizes these xids as special. The values are those of
//! `zk_adaptor.h` in the C client. Normal requests use positive xids.

/// The xid of a watch event that the server sends.
pub const WATCHER_EVENT: i32 = -1;
/// The xid of a ping and its reply.
pub const PING: i32 = -2;
/// The xid of an auth packet and its reply.
pub const AUTH: i32 = -4;
/// The xid of a SetWatches request and its reply.
pub const SET_WATCHES: i32 = -8;
