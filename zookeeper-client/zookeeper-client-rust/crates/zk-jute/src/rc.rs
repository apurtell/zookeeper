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

//! Result codes.
//!
//! The names and values are those of `enum ZOO_ERRORS` in `zookeeper.h`.
//! A server can send a code that is not in this list. The protocol core
//! passes such a code through unchanged.

/// Everything is OK.
pub const ZOK: i32 = 0;
/// The start of the range of system errors. The server never sends it.
pub const ZSYSTEMERROR: i32 = -1;
/// A runtime inconsistency was found.
pub const ZRUNTIMEINCONSISTENCY: i32 = -2;
/// A data inconsistency was found.
pub const ZDATAINCONSISTENCY: i32 = -3;
/// The connection to the server was lost.
pub const ZCONNECTIONLOSS: i32 = -4;
/// Data could not be marshalled or unmarshalled.
pub const ZMARSHALLINGERROR: i32 = -5;
/// The operation is not implemented.
pub const ZUNIMPLEMENTED: i32 = -6;
/// The operation timed out.
pub const ZOPERATIONTIMEOUT: i32 = -7;
/// The arguments are not valid.
pub const ZBADARGUMENTS: i32 = -8;
/// The handle state is not valid.
pub const ZINVALIDSTATE: i32 = -9;
/// No quorum of the new configuration is connected and up to date.
pub const ZNEWCONFIGNOQUORUM: i32 = -13;
/// Another reconfiguration is in progress.
pub const ZRECONFIGINPROGRESS: i32 = -14;
/// The TLS connection failed.
pub const ZSSLCONNECTIONERROR: i32 = -15;
/// The start of the range of API errors. The server never sends it.
pub const ZAPIERROR: i32 = -100;
/// The node does not exist.
pub const ZNONODE: i32 = -101;
/// The client is not authenticated.
pub const ZNOAUTH: i32 = -102;
/// The version does not match.
pub const ZBADVERSION: i32 = -103;
/// Ephemeral nodes cannot have children.
pub const ZNOCHILDRENFOREPHEMERALS: i32 = -108;
/// The node already exists.
pub const ZNODEEXISTS: i32 = -110;
/// The node has children.
pub const ZNOTEMPTY: i32 = -111;
/// The server expired the session.
pub const ZSESSIONEXPIRED: i32 = -112;
/// The callback is not valid.
pub const ZINVALIDCALLBACK: i32 = -113;
/// The ACL is not valid.
pub const ZINVALIDACL: i32 = -114;
/// Client authentication failed.
pub const ZAUTHFAILED: i32 = -115;
/// The handle is closing.
pub const ZCLOSING: i32 = -116;
/// No server responses remain to process. This is not an error.
pub const ZNOTHING: i32 = -117;
/// The session moved to another server, so the server ignored the operation.
pub const ZSESSIONMOVED: i32 = -118;
/// A read-only server received a request that changes state.
pub const ZNOTREADONLY: i32 = -119;
/// An ephemeral node cannot be created on a local session.
pub const ZEPHEMERALONLOCALSESSION: i32 = -120;
/// The watcher could not be found.
pub const ZNOWATCHER: i32 = -121;
/// Reconfiguration is disabled on the server.
pub const ZRECONFIGDISABLED: i32 = -123;
/// The server closed the session because it requires SASL authentication.
pub const ZSESSIONCLOSEDREQUIRESASLAUTH: i32 = -124;
/// The server throttled the operation and did not run it.
pub const ZTHROTTLEDOP: i32 = -127;
