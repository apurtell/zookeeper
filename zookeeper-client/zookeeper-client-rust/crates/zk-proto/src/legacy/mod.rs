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

//! Safe ports of legacy C client algorithms whose results the application can observe.
//!
//! The legacy drop-in libraries must give the same orders, permutations and
//! verdicts as the C client. Each module ports one C algorithm and keeps its
//! quirks, unless the specification fixes a defect. In that case the module
//! gives the C rule as a reference and the fixed rule for the drop-in core.
//!
//! - [`hashtable`]: the C hash table, its hash function and its iteration
//!   order.
//! - [`watchers`]: the watcher tables, with C collection and dispatch order.
//! - [`addrvec`]: the address list, its cursor and its shuffle.
//! - [`servers`]: the server list rebalance and the server selection.
//! - [`path`]: the legacy path check and the strict Java path check.
//! - [`chroot`]: the chroot join and strip.
//! - [`connect`]: the legacy and the Java connect string parsers.
//!
//! The Java syntax parts serve the native client. They are here because they
//! share the parsers and the path checks with the legacy parts.
//!
//! # Embedded NUL bytes
//!
//! The C functions read C strings, so they never see a NUL byte inside a
//! string. Through the C ABI the same is true for these ports. A Rust caller
//! can give a byte slice with a NUL, and the ports then apply one of two
//! rules:
//!
//! - A function that computes a value from a C string uses only the bytes
//!   before the first NUL, as C does. The connect string parsers and the hash
//!   table keys use this rule.
//! - A function that accepts or rejects bytes for later use rejects a NUL.
//!   The path check and the chroot join use this rule. Thus a check never
//!   accepts bytes that differ from the bytes that the caller sends.
//!
//! Both rules give the C result for every input that the C ABI can carry.

pub mod addrvec;
pub mod chroot;
pub mod connect;
pub mod hashtable;
pub mod path;
pub mod servers;
pub mod watchers;
