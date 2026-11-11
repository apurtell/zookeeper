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

//! The ABI modules of zk-ffi that the result writers use.
//!
//! The files come from zk-ffi by `#[path]`, so the target tests the same
//! code that the C libraries link. The writers name their siblings as
//! `super::super`, so the module tree has the same shape as in zk-ffi.

#[path = "../../../crates/zk-ffi/src/abi/types.rs"]
pub mod types;

#[path = "../../../crates/zk-ffi/src/abi/legacy.rs"]
pub mod legacy;

#[path = "raw.rs"]
pub mod raw;
