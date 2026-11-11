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

//! `repr(C)` mirrors of the public C records.
//!
//! `abi::raw::writers` writes them. The submit and multi readers read the
//! ACL vector and the `zoo_op_t` array of a request through them. The
//! mirrors follow `generated/zookeeper.jute.h` and `include/zookeeper.h`.
//! The first doc line of each mirror names its C type. A union member of
//! `zoo_op_t` has a dotted name, for example `zoo_op_t.set_op`. The file
//! depends on `std` only, so the `zk-ffi-layout` crate can include it by
//! `#[path]`. That crate compares the size, the alignment and each field
//! of every mirror with the C compiler view of the type.

#![allow(dead_code, reason = "the writers and the layout check use the mirrors")]

use std::ffi::{c_char, c_int};

/// `struct Stat`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CStat {
    pub(crate) czxid: i64,
    pub(crate) mzxid: i64,
    pub(crate) ctime: i64,
    pub(crate) mtime: i64,
    pub(crate) version: i32,
    pub(crate) cversion: i32,
    pub(crate) aversion: i32,
    pub(crate) ephemeral_owner: i64,
    pub(crate) data_length: i32,
    pub(crate) num_children: i32,
    pub(crate) pzxid: i64,
}

/// `struct String_vector`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CStringVector {
    pub(crate) count: i32,
    pub(crate) data: *mut *mut c_char,
}

/// `struct Id`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CId {
    pub(crate) scheme: *mut c_char,
    pub(crate) id: *mut c_char,
}

/// `struct ACL`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CAcl {
    pub(crate) perms: i32,
    pub(crate) id: CId,
}

/// `struct ACL_vector`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CAclVector {
    pub(crate) count: i32,
    pub(crate) data: *mut CAcl,
}

/// `zoo_op_result_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct COpResult {
    pub(crate) err: c_int,
    pub(crate) value: *mut c_char,
    pub(crate) valuelen: c_int,
    pub(crate) stat: *mut CStat,
}

/// `zoo_op_t.create_op`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CCreateOp {
    pub(crate) path: *const c_char,
    pub(crate) data: *const c_char,
    pub(crate) datalen: c_int,
    pub(crate) buf: *mut c_char,
    pub(crate) buflen: c_int,
    pub(crate) acl: *const CAclVector,
    pub(crate) flags: c_int,
    /// `zoo_create2_op_init` does not set it, and the multi never reads it.
    pub(crate) ttl: i64,
}

/// `zoo_op_t.delete_op`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CDeleteOp {
    pub(crate) path: *const c_char,
    pub(crate) version: c_int,
}

/// `zoo_op_t.set_op`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CSetOp {
    pub(crate) path: *const c_char,
    pub(crate) data: *const c_char,
    pub(crate) datalen: c_int,
    pub(crate) version: c_int,
    pub(crate) stat: *mut CStat,
}

/// `zoo_op_t.check_op`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CCheckOp {
    pub(crate) path: *const c_char,
    pub(crate) version: c_int,
}

/// `zoo_op_t`.
///
/// The mirror holds the largest union member, so its size and its
/// alignment are those of the C type. The other members start at the
/// offset of `create_op`. The union of a C op holds only the member of
/// its type, so Rust never makes a reference to a `CZooOp`. A reader
/// copies each field through a raw pointer at its offset. Thus no reader
/// reads bytes that the op init did not write.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CZooOp {
    pub(crate) type_: c_int,
    pub(crate) create_op: CCreateOp,
}
