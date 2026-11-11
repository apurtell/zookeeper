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

//! Cross-checks of the Rust ports against the legacy C client sources.
//!
//! The build script compiles the C hash table, the C address vector, the C
//! watcher tables and verbatim extracts of `zookeeper.c`. This crate gives a
//! safe interface to that C code. The tests in `tests/` drive the C code and
//! the ports in `zk_proto::legacy` with the same inputs and compare the
//! results.
//!
//! The C code has global state, so all calls go through [`with_c`], which
//! holds one global lock. The C code is present only on Unix targets with
//! the C sources in the tree. [`C_AVAILABLE`] tells if it is present. The
//! test `tests/harness.rs` fails on Unix when it is not present, so the C
//! checks cannot turn off silently.

// Unit tests may assert and panic.
#![cfg_attr(test, allow(clippy::disallowed_macros))]

pub mod rng;

#[cfg(zkx_c)]
mod ffi;

#[cfg(zkx_c)]
mod safe;

#[cfg(zkx_c)]
pub use safe::{CApi, CHashTable, Delivery, LogLine, ZtEntry, with_c};

/// The C extract manifest that the build script writes.
pub mod manifest {
    include!(concat!(env!("OUT_DIR"), "/extract_manifest.rs"));
}

/// True when the C code is built into this crate.
pub const C_AVAILABLE: bool = cfg!(zkx_c);
