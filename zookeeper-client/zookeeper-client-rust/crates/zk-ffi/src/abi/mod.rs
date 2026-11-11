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

//! The private C ABI of the drop-in library.
//!
//! Layers, from the C boundary inward:
//!
//! - [`types`]: the `repr(C)` types and constants of `zkrs.h`.
//! - [`legacy`]: `repr(C)` mirrors of the public C records.
//! - [`raw`]: every pointer read, pointer write and vtable call. It is the
//!   only module that allows `unsafe_code`, apart from the test stand-in.
//!   An export allows it on the item, for `#[unsafe(no_mangle)]` only.
//! - [`entry`]: `ffi_guard` and `with_handle`, the frame of every export.
//! - The export modules: [`handle`], [`outbox`], [`submit`], [`multi`],
//!   [`accessors`], [`results`] and [`sasl`].
//! - `tls`: the drop-in TLS configuration (`tls` builds only).
//! - The adapters to zk-driver: [`tokens`], [`host`] and [`logging`].
//!
//! cbindgen needs `pub` items, so this module allows `unreachable_pub`.

#![allow(unreachable_pub, reason = "cbindgen exports only pub items")]

pub mod types;

pub(crate) mod legacy;
#[allow(unsafe_code, reason = "the audited raw boundary")]
pub(crate) mod raw;

pub(crate) mod entry;

pub(crate) mod host;
pub(crate) mod logging;
pub(crate) mod tokens;

pub mod accessors;
pub mod handle;
pub mod multi;
pub mod outbox;
pub mod registry;
pub mod results;
pub mod sasl;
pub mod submit;
#[cfg(feature = "tls")]
pub(crate) mod tls;

#[cfg(test)]
pub(crate) mod standin;

#[cfg(all(test, loom))]
mod loom_models;
