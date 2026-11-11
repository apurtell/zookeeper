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

//! Deterministic test kit for the ZooKeeper protocol core.
//!
//! The kit drives a `zk_proto::Connection` with no real I/O. A logical
//! clock, a seeded random source, an in-memory network and a scripted
//! server model replace the outside world. The same seed gives the same
//! run, so a failure is easy to repeat.
//!
//! The main entry is [`Harness`]. It runs the driver loop of the core and
//! records each output in a [`Recorder`]. The recorder checks that each
//! completion token arrives exactly once.
//!
//! The module [`fixtures`] makes the TLS test material at test time, so
//! the repository holds no keys or certificates.
//!
//! ```ignore
//! let mut h = zk_testkit::Harness::st(7);
//! h.connect()?;
//! let ops = h.ops();
//! let r = h.call(ops.create("/a", b"x", 0))?;
//! assert_eq!(r.rc, 0);
//! h.close()?;
//! h.expect_exactly_once()?;
//! ```

#![forbid(unsafe_code)]
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

pub mod chunk;
pub mod clock;
pub mod fixtures;
pub mod harness;
pub mod hooks;
pub mod net;
pub mod recorder;
pub mod rng;
pub mod sasl;
pub mod server;
pub mod tokens;

pub use chunk::{Chunker, Chunking};
pub use clock::ManualClock;
pub use harness::{
    BASE_PORT, DEFAULT_LIMIT_MS, Finished, Harness, HarnessBuilder, HarnessError, HookCtx, Ops,
    OutputHook, ReadMode, RngChoice, SubmitRejected, TRANSMIT_MAX, WriteGate, server_addr,
};
pub use net::{ConnectPlan, ConnectStyle, Network};
pub use recorder::{ActionRecord, Delivery, Event, Recorded, Recorder, SaslKind};
pub use sasl::{SaslScript, ScriptStep, ScriptedSasl};
pub use server::{ServerOptions, ServerSim};
pub use tokens::{AuthId, AuthTicket, CompletionId, TestTokens, Ticket, TokenMint, WatcherId};
