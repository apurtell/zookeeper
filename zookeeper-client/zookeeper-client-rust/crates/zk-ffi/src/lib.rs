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

//! C ABI bridge for the libzookeeper_mt and libzookeeper_st drop-in libraries.
//!
//! The crate is the Rust half of the drop-in library. The C
//! shim in `zookeeper-client-rust/c/shim` owns every public symbol. It calls
//! the private `zkrs_*` functions of this crate through `shim/zkrs.h`,
//! which cbindgen generates from `src/abi/types.rs` and the exports.
//!
//! One Rust build serves both flavors. `zkrs_init_args.flavor` selects
//! the driver of each handle at run time. The plain build has
//! no cargo feature, so the library has no TLS and no SASL code.
//!
//! All unsafe code is in `abi::raw` (and in the test stand-in). Only
//! those modules allow `unsafe_code`. Each export allows it on the item,
//! for `#[unsafe(no_mangle)]` only. The test
//! `tests/unsafe_scope.rs` fails on an unsafe block, fn, impl or trait
//! in another file.

#![deny(unsafe_code)]
// Unit tests may assert and panic.
#![cfg_attr(test, allow(clippy::disallowed_macros))]

// The drop-in TLS build needs exactly one provider feature.
// zk-driver has the same guard. This one names the zk-ffi features.
#[cfg(all(
    feature = "tls",
    not(any(
        feature = "tls-ring",
        feature = "tls-aws-lc-rs",
        feature = "tls-aws-lc-rs-fips"
    ))
))]
compile_error!(
    "zk-ffi feature `tls` needs exactly one provider feature: \
     `tls-ring`, `tls-aws-lc-rs` or `tls-aws-lc-rs-fips`"
);

mod abi;
