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

//! Network transports, TLS and drivers for the ZooKeeper protocol core.
//!
//! The crate drives a `zk_proto::Connection` over real sockets. It has
//! three driver families:
//!
//! - the threaded drop-in driver of `libzookeeper_mt` ([`threaded`]);
//! - the caller-polled drop-in driver of `libzookeeper_st` ([`polled`]);
//! - the native drivers of the Rust client ([`native`] and, on Unix with
//!   the `tokio` feature, `tokio`).
//!
//! The drop-in drivers never call application code. Each driving call
//! returns an ordered [`outbox::Outbox`], and C runs the callbacks after
//! the Rust frames are gone. The shared I/O steps are in
//! [`iocore`]. Sockets, the waker, the poll call and the read-only probe
//! are in [`net`]. TLS is in `net::tls`.
//!
//! The crate contains no `unsafe` code. Every `unsafe` operation of the
//! drop-in is in zk-ffi.

#![forbid(unsafe_code)]
// Unit tests may assert and panic.
#![cfg_attr(test, allow(clippy::disallowed_macros))]

// The `tls` feature needs exactly one provider feature.
#[cfg(all(
    feature = "tls",
    not(any(
        feature = "tls-ring",
        feature = "tls-aws-lc-rs",
        feature = "tls-aws-lc-rs-fips"
    ))
))]
compile_error!(
    "feature `tls` needs exactly one provider feature: `tls-ring`, `tls-aws-lc-rs` or `tls-aws-lc-rs-fips`"
);

#[cfg(any(
    all(feature = "tls-ring", feature = "tls-aws-lc-rs"),
    all(feature = "tls-ring", feature = "tls-aws-lc-rs-fips"),
    all(feature = "tls-aws-lc-rs", feature = "tls-aws-lc-rs-fips")
))]
compile_error!(
    "feature `tls` takes only one provider feature: select one of `tls-ring`, `tls-aws-lc-rs` or `tls-aws-lc-rs-fips`"
);

pub mod clock;
pub mod dispatch;
pub mod host;
pub mod host_std;
pub mod init;
pub mod iocore;
pub(crate) mod iocore_tls;
pub mod lifecycle;
pub mod native;
pub mod net;
pub mod outbox;
pub mod polled;
pub(crate) mod resolve;
#[cfg(feature = "std-thread")]
pub mod spawn_std;
pub mod state;
pub mod sync;
pub mod threaded;
#[cfg(all(unix, feature = "tokio"))]
pub mod tokio;

#[cfg(test)]
mod iocore_tests;
#[cfg(test)]
pub(crate) mod testutil;

pub use clock::{Clock, MonotonicClock, TestClock};
pub use dispatch::{ReadGate, RouteSink};
pub use host::{Discarded, DriverTokens, HostLeaves};
pub use host_std::StdHostLeaves;
pub use init::{Init, InitArgs, InitError, InitStep};
pub use iocore::{DeferPolicy, DriverConfig, InterestOut, IoCore, Progress, RawSock};
pub use lifecycle::Lifecycle;
pub use native::{NativeGate, NativeHandle, Spawn, StartError};
pub use net::poll::{Poll, PollEvents, RustixPoll};
pub use net::sock::TcpSock;
pub use net::waker::{WakeRx, Waker};
pub use outbox::{Item, Outbox, Requeued, ResumeAt, SaslItem, Step, ThreadOp, ThreadRole};
pub use polled::Polled;
#[cfg(feature = "std-thread")]
pub use spawn_std::StdSpawner;
pub use state::{Env, SaslAnswer};
pub use sync::Unlocked;
pub use threaded::{Role, Shared};
