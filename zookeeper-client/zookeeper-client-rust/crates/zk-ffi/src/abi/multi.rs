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

//! The decomposition of a multi request.
//!
//! C gives the `zoo_op_t[]` array of the caller as it is, with the length
//! of the prefix: every op up to and including the first unsupported
//! type. This module reads each op through raw pointers into the
//! `CZooOp` layout as a borrowed `zk_proto::MultiOpRef`. The path and
//! the value stay in C memory. zk-proto encodes them straight into the
//! owned request frame inside `zkrs_submit`, and no view outlives that
//! call. zk-proto then applies the legacy rules. An op type outside
//! {1, 19, 2, 5, 13} gives UNIMPLEMENTED and overrides earlier errors.
//! Any other sub-op failure gives ZMARSHALLINGERROR at the serialization
//! stage.

use std::ffi::{c_char, c_int};
use std::mem::offset_of;

use zk_jute::opcode;
use zk_proto::{InputDefect, MultiOpRef};

use super::legacy::{CAclVector, CCheckOp, CDeleteOp, CSetOp, CZooOp};
use super::raw;
use super::submit::acl_of_vec;
use super::types::zkrs_request;

/// Reads the prefix of `rq` as borrowed driver sub-ops.
///
/// The function reads `rq.ops[0..ops_len]` through raw pointers. Per op
/// it borrows the path (`raw::cstr_ref`) and the value (`raw::value_ref`).
/// It copies the version, the mode and the ACL entries. It sets a defect
/// flag for a bad ACL vector and for a bad value buffer. `ops_len <
/// count` means C stopped at an unsupported type, which is the last op of
/// the prefix.
///
/// The sub-ops borrow `rq`. The caller holds `rq` for the synchronous
/// submit call only, so the views end before C can free its memory.
pub(crate) fn multi_ops(rq: &zkrs_request) -> Vec<MultiOpRef<'_>> {
    let p = rq.ops.cast::<CZooOp>();
    // A NULL array with a positive length breaks the shim contract.
    // `submit::defects_of` reports it as a request defect, so the
    // request fails at the serialization stage with no sub-op.
    match raw::array_len(p, rq.ops_len) {
        Ok(n) => (0..n).map(|i| multi_op(p.wrapping_add(i))).collect(),
        Err(_) => Vec::new(),
    }
}

/// Reads the legacy op at `op` as a borrowed sub-op.
///
/// The union of an op holds only the member of its type, and a create
/// can have no `ttl`. Thus the reader makes no reference to a `CZooOp`.
/// It copies each field that it uses through a raw pointer.
fn multi_op<'a>(op: *const CZooOp) -> MultiOpRef<'a> {
    let op_type: c_int = field(op, offset_of!(CZooOp, type_));
    // The legacy multi reads the union member of the type only. An
    // unsupported type reads no member.
    match op_type {
        opcode::CREATE | opcode::CREATE_CONTAINER => {
            // The legacy multi sends a plain create that ignores `ttl`
            // (zookeeper.c:4870-4880), so the reader does not read it.
            let path: *const c_char = field(op, offset_of!(CZooOp, create_op.path));
            let p: *const c_char = field(op, offset_of!(CZooOp, create_op.data));
            let len: c_int = field(op, offset_of!(CZooOp, create_op.datalen));
            let v: *const CAclVector = field(op, offset_of!(CZooOp, create_op.acl));
            let (data, bad_value_buffer) = value_ref_of(p, len);
            let (acl, bad_acl) = acl_of_vec(v, false);
            MultiOpRef::Create {
                op_type,
                path: raw::cstr_ref(path),
                data,
                acl,
                mode: field(op, offset_of!(CZooOp, create_op.flags)),
                ttl: -1,
                defect: InputDefect {
                    bad_value_buffer,
                    bad_acl,
                    marshal_oom: false,
                },
            }
        }
        opcode::DELETE => {
            let d: CDeleteOp = field(op, offset_of!(CZooOp, create_op));
            MultiOpRef::Delete {
                path: raw::cstr_ref(d.path),
                version: d.version,
                defect: InputDefect::default(),
            }
        }
        opcode::SET_DATA => {
            let s: CSetOp = field(op, offset_of!(CZooOp, create_op));
            let (data, bad_value_buffer) = value_ref_of(s.data, s.datalen);
            MultiOpRef::SetData {
                path: raw::cstr_ref(s.path),
                data,
                version: s.version,
                defect: InputDefect {
                    bad_value_buffer,
                    ..InputDefect::default()
                },
            }
        }
        opcode::CHECK => {
            let k: CCheckOp = field(op, offset_of!(CZooOp, create_op));
            MultiOpRef::Check {
                path: raw::cstr_ref(k.path),
                version: k.version,
                defect: InputDefect::default(),
            }
        }
        t => MultiOpRef::Other { op_type: t },
    }
}

/// Copies the value of type `T` at byte offset `off` of the op at `op`.
///
/// Every member of the C union starts at the offset of `create_op`. Thus
/// a member read uses that offset with the mirror of the member. The
/// offset step is safe code, and `raw::read_struct` does the only read.
fn field<T: Copy>(op: *const CZooOp, off: usize) -> T {
    raw::read_struct(op.cast::<u8>().wrapping_add(off).cast::<T>())
}

/// Borrows the value buffer of one sub-op. The flag is true for
/// an unusable buffer. Such a buffer gives a null value and an input
/// defect, so zk-proto never encodes it.
fn value_ref_of<'a>(p: *const c_char, len: i32) -> (Option<&'a [u8]>, bool) {
    match raw::value_ref(p, len) {
        Ok(v) => (v, false),
        Err(_) => (None, true),
    }
}

/// Builders of legacy ops for the unit tests.
///
/// `TestOp` has the layout of `zoo_op_t`, and its union is a real union.
/// A builder writes only the member of its type, as the C op inits do.
/// Thus Miri reports a read of any other byte of the union.
#[cfg(test)]
pub(crate) mod test_support {
    use std::ffi::{CStr, c_char, c_int, c_void};

    use crate::abi::legacy::{CAclVector, CCheckOp, CCreateOp, CDeleteOp, CSetOp};

    /// A create member with no `ttl`, as `zoo_create2_op_init` writes it.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(crate) struct Create2 {
        path: *const c_char,
        data: *const c_char,
        datalen: c_int,
        buf: *mut c_char,
        buflen: c_int,
        acl: *const CAclVector,
        flags: c_int,
    }

    /// The union of `zoo_op_t`. `none` writes no byte.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(crate) union Member {
        create: CCreateOp,
        create2: Create2,
        delete: CDeleteOp,
        set: CSetOp,
        check: CCheckOp,
        none: (),
    }

    /// One legacy op in the C layout.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(crate) struct TestOp {
        type_: c_int,
        m: Member,
    }

    impl TestOp {
        /// A create with no `ttl`.
        pub(crate) fn create(
            t: i32,
            path: &CStr,
            data: *const c_char,
            datalen: i32,
            acl: *const CAclVector,
            mode: i32,
        ) -> Self {
            let create2 = Create2 {
                path: path.as_ptr(),
                data,
                datalen,
                buf: std::ptr::null_mut(),
                buflen: 0,
                acl,
                flags: mode,
            };
            Self {
                type_: t,
                m: Member { create2 },
            }
        }

        /// A create with a `ttl`, as `zoo_create_op_init` writes it.
        pub(crate) fn create_ttl(t: i32, path: &CStr, mode: i32, ttl: i64) -> Self {
            let create = CCreateOp {
                path: path.as_ptr(),
                data: std::ptr::null(),
                datalen: -1,
                buf: std::ptr::null_mut(),
                buflen: 0,
                acl: std::ptr::null(),
                flags: mode,
                ttl,
            };
            Self {
                type_: t,
                m: Member { create },
            }
        }

        pub(crate) fn delete(path: &CStr, version: i32) -> Self {
            let delete = CDeleteOp {
                path: path.as_ptr(),
                version,
            };
            Self {
                type_: zk_jute::opcode::DELETE,
                m: Member { delete },
            }
        }

        pub(crate) fn set(path: &CStr, data: *const c_char, datalen: i32, version: i32) -> Self {
            let set = CSetOp {
                path: path.as_ptr(),
                data,
                datalen,
                version,
                stat: std::ptr::null_mut(),
            };
            Self {
                type_: zk_jute::opcode::SET_DATA,
                m: Member { set },
            }
        }

        pub(crate) fn check(path: &CStr, version: i32) -> Self {
            let check = CCheckOp {
                path: path.as_ptr(),
                version,
            };
            Self {
                type_: zk_jute::opcode::CHECK,
                m: Member { check },
            }
        }

        /// An op of type `t` with no member.
        pub(crate) fn unset(t: i32) -> Self {
            Self {
                type_: t,
                m: Member { none: () },
            }
        }
    }

    /// The `zkrs_request.ops` value of an op array.
    pub(crate) fn ops_ptr(ops: &[TestOp]) -> *const c_void {
        ops.as_ptr().cast()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use zk_jute::data::{ACL, Id};
    use zk_jute::{JString, JVec};

    use super::test_support::{TestOp, ops_ptr};
    use super::*;
    use crate::abi::legacy::{CAcl, CAclVector, CId};
    use crate::abi::types::ZKRS_OP_MULTI;

    fn multi(ops: &[TestOp]) -> zkrs_request {
        let n = i32::try_from(ops.len()).unwrap_or(0);
        zkrs_request {
            op: ZKRS_OP_MULTI,
            flags: 0,
            path: std::ptr::null(),
            data: std::ptr::null(),
            datalen: -1,
            acl: std::ptr::null(),
            mode: 0,
            ttl: -1,
            version: -1,
            reconfig_version: -1,
            joining: std::ptr::null(),
            leaving: std::ptr::null(),
            members: std::ptr::null(),
            watch_fn: 0,
            watch_ctx: 0,
            wtype: 0,
            ops: ops_ptr(ops),
            ops_len: n,
            count: n,
        }
    }

    fn legacy(p: &CStr) -> Option<&[u8]> {
        Some(p.to_bytes())
    }

    /// A create sub-op with no data and mode 0.
    fn create_want(path: &CStr, acl: JVec<ACL>, defect: InputDefect) -> MultiOpRef<'_> {
        MultiOpRef::Create {
            op_type: opcode::CREATE,
            path: legacy(path),
            data: None,
            acl,
            mode: 0,
            ttl: -1,
            defect,
        }
    }

    fn empty() -> JVec<ACL> {
        JVec::Items(Vec::new())
    }

    #[test]
    fn the_test_op_has_the_layout_of_the_mirror() {
        assert_eq!(size_of::<TestOp>(), size_of::<CZooOp>());
        assert_eq!(align_of::<TestOp>(), align_of::<CZooOp>());
    }

    #[test]
    fn create_borrows_the_inputs() {
        let mut acl = [CAcl {
            perms: 1,
            id: CId {
                scheme: c"digest".as_ptr().cast_mut(),
                id: c"u:p".as_ptr().cast_mut(),
            },
        }];
        let v = CAclVector {
            count: 1,
            data: acl.as_mut_ptr(),
        };
        let ops = [TestOp::create(
            opcode::CREATE_CONTAINER,
            c"/c",
            c"ab".as_ptr(),
            2,
            &v,
            4,
        )];
        let want = MultiOpRef::Create {
            op_type: opcode::CREATE_CONTAINER,
            path: legacy(c"/c"),
            data: Some(b"ab"),
            acl: JVec::Items(vec![ACL {
                perms: 1,
                id: Id {
                    scheme: JString::from("digest"),
                    id: JString::from("u:p"),
                },
            }]),
            mode: 4,
            ttl: -1,
            defect: InputDefect::default(),
        };
        // The create member has no `ttl`, so Miri also checks that the
        // reader never reads it.
        let rq = multi(&ops);
        assert_eq!(multi_ops(&rq), vec![want]);
    }

    #[test]
    fn create_ignores_the_ttl_and_accepts_a_null_acl() {
        // The legacy multi sends a plain create with no TTL. A NULL ACL
        // vector is an empty ACL with no defect, as in a create.
        let ops = [TestOp::create_ttl(opcode::CREATE, c"/t", 0, 77)];
        let rq = multi(&ops);
        let want = create_want(c"/t", empty(), InputDefect::default());
        assert_eq!(multi_ops(&rq), vec![want]);
    }

    #[test]
    fn create_reports_its_defects() {
        let null = std::ptr::null();
        // NULL data with a positive count is a bad ACL.
        let bad = CAclVector {
            count: 3,
            data: std::ptr::null_mut(),
        };
        // A negative count is the null vector, with no defect.
        let neg = CAclVector {
            count: -1,
            data: std::ptr::null_mut(),
        };
        let ops = [
            TestOp::create(opcode::CREATE, c"/a", null, -1, &bad, 0),
            TestOp::create(opcode::CREATE, c"/b", null, 9, std::ptr::null(), 0),
            TestOp::create(opcode::CREATE, c"/c", null, -1, &neg, 0),
        ];
        let defect = |bad_value_buffer, bad_acl| InputDefect {
            bad_value_buffer,
            bad_acl,
            marshal_oom: false,
        };
        let want = vec![
            create_want(c"/a", empty(), defect(false, true)),
            create_want(c"/b", empty(), defect(true, false)),
            create_want(c"/c", JVec::Null, defect(false, false)),
        ];
        let rq = multi(&ops);
        assert_eq!(multi_ops(&rq), want);
    }

    #[test]
    fn other_types_read_their_own_member() {
        let ops = [
            TestOp::delete(c"/d", 6),
            TestOp::check(c"/k", 7),
            TestOp::set(c"/s", c"".as_ptr(), 0, 8),
            TestOp::set(c"/n", std::ptr::null(), -1, 9),
            TestOp::set(c"/x", std::ptr::null(), -3, 10),
        ];
        let want = vec![
            MultiOpRef::Delete {
                path: legacy(c"/d"),
                version: 6,
                defect: InputDefect::default(),
            },
            MultiOpRef::Check {
                path: legacy(c"/k"),
                version: 7,
                defect: InputDefect::default(),
            },
            MultiOpRef::SetData {
                path: legacy(c"/s"),
                data: Some(b""),
                version: 8,
                defect: InputDefect::default(),
            },
            MultiOpRef::SetData {
                path: legacy(c"/n"),
                data: None,
                version: 9,
                defect: InputDefect::default(),
            },
            MultiOpRef::SetData {
                path: legacy(c"/x"),
                data: None,
                version: 10,
                defect: InputDefect {
                    bad_value_buffer: true,
                    ..InputDefect::default()
                },
            },
        ];
        let rq = multi(&ops);
        assert_eq!(multi_ops(&rq), want);
    }

    #[test]
    fn an_unknown_type_ends_the_prefix_and_reads_no_member() {
        // The op of type 99 has no member, so Miri reports any read of
        // its union.
        let ops = [
            TestOp::check(c"/1", 1),
            TestOp::delete(c"/2", 2),
            TestOp::unset(99),
        ];
        let rq = multi(&ops);
        let got = multi_ops(&rq);
        assert_eq!(got.len(), 3);
        assert_eq!(got.last(), Some(&MultiOpRef::Other { op_type: 99 }));
    }

    #[test]
    fn the_prefix_keeps_the_order() {
        let ops = [TestOp::check(c"/1", 1), TestOp::delete(c"/2", 2)];
        // The sub-ops borrow the request, so the request outlives them.
        let mut rq = multi(&ops);
        let want = vec![
            MultiOpRef::Check {
                path: legacy(c"/1"),
                version: 1,
                defect: InputDefect::default(),
            },
            MultiOpRef::Delete {
                path: legacy(c"/2"),
                version: 2,
                defect: InputDefect::default(),
            },
        ];
        assert_eq!(multi_ops(&rq), want);
        // Only the prefix counts.
        rq.ops_len = 1;
        assert_eq!(multi_ops(&rq).len(), 1);
        rq.ops_len = 0;
        assert!(multi_ops(&rq).is_empty());
        // A negative count reads nothing.
        rq.ops_len = -1;
        assert!(multi_ops(&rq).is_empty());
        // A NULL array with a length is a request defect, not a sub-op.
        rq.ops = std::ptr::null();
        rq.ops_len = 2;
        assert!(multi_ops(&rq).is_empty());
    }
}
