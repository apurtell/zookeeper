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

//! A scripted mock ZooKeeper server for tests.
//!
//! The server binds `127.0.0.1` with a free port and speaks the ZooKeeper
//! wire protocol over plain `std::net` sockets and threads. A model of the
//! Java server gives the replies: the data tree, sessions, ACLs, watches,
//! multi, auth and the error codes. A [`Script`] of [`Rule`]s injects
//! faults on chosen frames, and the server records every client frame as
//! a [`FrameRecord`].
//!
//! # Determinism
//!
//! One seed gives the session ids, the passwords, the rule chances and
//! the random write sizes. One lock orders every frame of every listener.
//! Watch delivery uses sorted order. Stat times come from a logical clock,
//! `epoch_ms + zxid`, so a run gives the same bytes each time. Only wall
//! time effects, such as session expiry and delays, depend on the clock.
//!
//! # Example
//!
//! ```
//! use zk_fakeserver::{Action, FakeServer, RawClient, Rule};
//! use zk_jute::opcode;
//! use zk_jute::proto::GetDataRequest;
//!
//! let server = FakeServer::start().map_err(|e| e.to_string())?;
//! server.add_rule(Rule::on_request().op(opcode::GET_DATA).then(Action::Close));
//! let (mut client, resp) = RawClient::open(server.addr(), 10_000).map_err(|e| e.to_string())?;
//! assert_ne!(resp.session_id, 0);
//! let req = GetDataRequest { path: "/".into(), watch: false };
//! assert!(client.call(opcode::GET_DATA, &req).is_err());
//! assert_eq!(server.transcript().len(), 2);
//! # Ok::<(), String>(())
//! ```
//!
//! # Limits
//!
//! The only SASL mechanism is DIGEST-MD5, which
//! [`FakeServer::set_sasl_digest`] turns on. Without it, a SASL request
//! gets `ZAUTHFAILED`.
//! A close is a TCP shutdown, never a reset, because stable `std` cannot
//! set `SO_LINGER`. The `tls` feature adds `TlsAcceptor`, a rustls server
//! side. Other stream wrappers come from outside the crate as an
//! [`Acceptor`].

#![forbid(unsafe_code)]
// Unit tests may assert and panic.
#![cfg_attr(test, allow(clippy::disallowed_macros))]

mod client;
mod config;
mod consts;
mod digest;
mod link;
mod model;
mod path;
mod rng;
mod script;
mod server;
#[cfg(feature = "tls")]
mod tls;
mod transcript;
mod transport;

pub use client::{DEFAULT_WAIT, RawClient, RawEvent, RawReply};
pub use config::{AuthPolicy, Chunking, ClusterConfig, HandshakeStyle, ServerOptions};
pub use consts::{add_watch_mode, create_mode, event, perms, watcher_type};
pub use digest::digest_id;
pub use model::{NodeInfo, SessionInfo};
pub use script::{Action, Malformed, Rule, Script, Trigger};
pub use server::{Cluster, Ensemble, FakeServer};
#[cfg(feature = "tls")]
pub use tls::{PeerEnd, TlsAcceptor, TlsAcceptorBuilder, TlsSession};
pub use transcript::{ConnectInfo, Detail, FrameKind, FrameRecord, WatchSet};
pub use transport::{Acceptor, PlainAcceptor, Transport};
