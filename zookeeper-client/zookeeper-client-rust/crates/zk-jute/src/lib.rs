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

//! Jute records and wire codecs for the ZooKeeper protocol.
//!
//! This crate is the base of the protocol core. It has no third-party
//! dependency and does no I/O. It contains:
//!
//! - the records of the jute modules `org.apache.zookeeper.data` and
//!   `org.apache.zookeeper.proto`, in [`data`] and [`proto`];
//! - the [`Record`] trait, the bounded [`Reader`] and the null-preserving
//!   wire types [`JString`], [`JBuffer`] and [`JVec`];
//! - the length-prefix frame codec ([`FrameDecoder`], [`encode_frame`]);
//! - the fixed-layout handshake codec ([`handshake`]);
//! - the multi-transaction codec ([`multi`]);
//! - the op-code, special-xid and result-code constants ([`opcode`],
//!   [`xid`], [`rc`]).
//!
//! The Java `RustGenerator` in `zookeeper-jute` generates the records from
//! `zookeeper.jute`. The generated file is not in version control. Run
//! `mvn -pl zookeeper-jute generate-sources` from the top level directory to
//! create it.

#![forbid(unsafe_code)]
// Unit tests may assert and panic.
#![cfg_attr(test, allow(clippy::disallowed_macros))]

mod frame;
pub mod handshake;
pub mod multi;
pub mod opcode;
pub mod rc;
mod reply;
mod wire;
pub mod xid;

/// The generated records. The module only gives a scope to the included
/// file; the records are public through [`data`] and [`proto`].
mod generated {
    include!("generated/zookeeper_jute.rs");
}

pub use frame::{
    FrameDecoder, FrameError, FrameStart, Pushed, begin_frame, encode_frame, finish_frame,
};
pub use generated::{data, proto};
pub use reply::REPLY_HEADER_LEN;
pub use wire::{DecodeError, JBuffer, JString, JVec, Reader, Record};
