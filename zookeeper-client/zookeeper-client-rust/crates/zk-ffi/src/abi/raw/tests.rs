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

//! Unit tests of `abi::raw`. They run under Miri with Tree
//! Borrows and Stacked Borrows.
//!
//! The writer tests cover each completion kind, every NULL and 0 case of
//! the readers and every truncation rule of the sync copy-out. The tests
//! free every object of a writer as C frees it, so Miri reports a leak
//! or a bad free.

#![allow(unsafe_code, reason = "the tests build C memory by hand")]

use std::ffi::{CStr, c_char, c_void};
use std::ptr;

use super::super::legacy::{CAcl, CAclVector, COpResult, CStat, CStringVector};
use super::super::standin;
use super::super::types::{
    ZKRS_AF_INET, ZKRS_K_ACLLIST, ZKRS_K_DATA, ZKRS_K_MULTI, ZKRS_K_STAT, ZKRS_K_STRING,
    ZKRS_K_STRING_STAT, ZKRS_K_STRINGLIST, ZKRS_K_STRINGLIST_STAT, ZKRS_K_VOID, ZKRS_ORIGIN_REPLY,
    ZKRS_ORIGIN_TEARDOWN, zkrs_acl_view, zkrs_buf, zkrs_multi_copy, zkrs_multi_op, zkrs_outbox,
    zkrs_result_dst, zkrs_result_view, zkrs_sockaddr_view, zkrs_stat, zkrs_str, zkrs_sync_dst,
    zkrs_sync_src,
};
use super::*;

/// Runs the DATA writer on the view `v`, as a C completion does. It
/// gives a copy of the value, or `None` for NULL with the length -1, and
/// the stat. It frees the value as C frees it.
pub(crate) fn write_data(v: *const zkrs_result_view) -> (Option<Vec<u8>>, CStat) {
    let mut st = CStat::default();
    let mut val = ptr::null_mut();
    let mut len = -2;
    let mut d = dst();
    d.stat = (&raw mut st).cast();
    d.value = &raw mut val;
    d.value_len = &raw mut len;
    writers::write_result(v, &d);
    assert_eq!(val.is_null(), len < 0, "a value buffer only for a value");
    let value = usize::try_from(len).ok().map(|n| bytes_at(val, n));
    free(val);
    (value, st)
}

/// The value reader follows the legacy length rules, and its slice
/// points at the C bytes, so no copy is made.
#[test]
fn value_ref_follows_the_legacy_rules() {
    let b = *b"abc";
    let p = b.as_ptr().cast::<c_char>();
    assert_eq!(value_ref(p, -1), Ok(None));
    assert_eq!(value_ref(std::ptr::null(), 0), Ok(Some(&[][..])));
    assert_eq!(value_ref(dangling(), 0), Ok(Some(&[][..])));
    let got = value_ref(p, 3);
    assert_eq!(got, Ok(Some(&b[..])));
    assert_eq!(got.ok().flatten().map(<[u8]>::as_ptr), Some(b.as_ptr()));
    assert_eq!(value_ref(p, -2), Err(RawError::BadValue));
    assert_eq!(value_ref(std::ptr::null(), 1), Err(RawError::BadValue));
}

#[test]
fn readers_copy_strings_and_arrays() {
    let s = c"/a/b";
    assert_eq!(cstr_opt(s.as_ptr()), Some(b"/a/b".to_vec()));
    assert_eq!(cstr_opt(std::ptr::null()), None);
    assert_eq!(
        cstr_secret(s.as_ptr()).map(|z| z.to_vec()),
        Some(b"/a/b".to_vec())
    );
    let a = [1i32, 2, 3];
    assert_eq!(array(a.as_ptr(), 3), Ok(&a[..]));
    assert_eq!(array(std::ptr::null::<i32>(), 0), Ok(&[][..]));
    assert_eq!(array(std::ptr::null::<i32>(), -1), Ok(&[][..]));
    assert_eq!(array(std::ptr::null::<i32>(), 1), Err(RawError::NullData));
    assert_eq!(bytes(std::ptr::null(), 0), Ok(&[][..]));
    assert_eq!(&*c_bytes(b"xy"), b"xy\0");
}

#[test]
fn write_out_and_read_struct_copy_values() {
    let mut v = 0i32;
    write_out(&raw mut v, 9);
    assert_eq!(read_struct(&raw const v), 9);
}

#[test]
fn resolve_collects_pushed_and_skipped_results() {
    let _rec = standin::recorder();
    let a: std::net::SocketAddr = "127.0.0.1:2181".parse().unwrap_or_else(|_| unreachable!());
    standin::set_resolve(vec![zkrs_sockaddr_view::from_addr(Some(a))], vec![17], 0, 0);
    let vt = standin::vtable();
    let u = Unlocked::new_at_entry();
    let mut out = HostAddrs::default();
    let name: &CStr = c"localhost";
    let (err, gai) = vt_resolve(&vt, &u, name, c"2181", &mut out);
    assert_eq!((err, gai), (0, 0));
    assert_eq!(out.addrs, vec![a]);
    assert_eq!(out.skipped_families, vec![17]);
    assert_eq!(
        standin::resolved(),
        vec![(b"localhost".to_vec(), b"2181".to_vec())]
    );
    assert_eq!(zkrs_sockaddr_view::from_addr(Some(a)).family, ZKRS_AF_INET);
}

#[test]
fn pure_wrappers_reach_the_vtable() {
    let _rec = standin::recorder();
    let vt = standin::vtable();
    vt_discard_token(&vt, 77);
    assert_eq!(standin::discarded(), vec![77]);
    assert!(vt_conn_permute_disabled(&vt));
    assert!((vt_rng_drand48(&vt) - 0.5).abs() < f64::EPSILON);
    vt_rng_reseed(&vt, &Unlocked::new_at_entry());
    assert_eq!(standin::reseeds(), 1);
}

#[test]
fn c_alloc_handles_zero_and_minus_one() {
    assert!(writers::c_calloc(-1, 8).is_null());
    let p = writers::c_malloc(4);
    assert!(!p.is_null());
    // SAFETY: `p` comes from libc malloc.
    unsafe { libc::free(p.cast()) };
}

// ---------------------------------------------------------------------
// Writer test helpers.
// ---------------------------------------------------------------------

/// A stat with a different value in every field.
const ST: zkrs_stat = zkrs_stat {
    czxid: 1,
    mzxid: 2,
    ctime: 3,
    mtime: 4,
    version: 5,
    cversion: 6,
    aversion: 7,
    ephemeralOwner: 8,
    dataLength: 9,
    numChildren: 10,
    pzxid: 11,
};

/// The `struct Stat` that `ST` must give.
fn cst(s: &zkrs_stat) -> CStat {
    CStat {
        czxid: s.czxid,
        mzxid: s.mzxid,
        ctime: s.ctime,
        mtime: s.mtime,
        version: s.version,
        cversion: s.cversion,
        aversion: s.aversion,
        ephemeral_owner: s.ephemeralOwner,
        data_length: s.dataLength,
        num_children: s.numChildren,
        pzxid: s.pzxid,
    }
}

/// A stat value that no writer gives, to see untouched records.
fn marker_stat() -> CStat {
    CStat {
        czxid: -7,
        ..CStat::default()
    }
}

/// A non-NULL pointer value that no writer gives, to see untouched
/// pointer members. Nothing reads or frees it.
fn marker_ptr() -> *mut c_char {
    ptr::dangling_mut::<c_char>()
}

fn len32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

fn zstr(s: &CStr) -> zkrs_str {
    zkrs_str {
        ptr: s.as_ptr(),
        len: len32(s.to_bytes().len()),
    }
}

/// A string view of bytes that end in a NUL. `len` excludes it.
fn zbytes(b: &[u8]) -> zkrs_str {
    zkrs_str {
        ptr: b.as_ptr().cast::<c_char>(),
        len: len32(b.len().saturating_sub(1)),
    }
}

fn zbuf(b: &[u8]) -> zkrs_buf {
    zkrs_buf {
        ptr: b.as_ptr().cast::<c_char>(),
        len: len32(b.len()),
    }
}

fn view(kind: u32) -> zkrs_result_view {
    zkrs_result_view {
        kind,
        origin: ZKRS_ORIGIN_REPLY,
        rc: 0,
        failed: 0,
        data: zkrs_buf::null(),
        stat: ptr::null(),
        path: zkrs_str::null(),
        children: ptr::null(),
        nchildren: 0,
        acl: ptr::null(),
        nacl: 0,
        ops: ptr::null(),
        nops: 0,
        delivery_logs: ptr::null(),
        n_delivery_logs: 0,
    }
}

fn dst() -> zkrs_result_dst {
    zkrs_result_dst {
        stat: ptr::null_mut(),
        value: ptr::null_mut(),
        value_len: ptr::null_mut(),
        strings: ptr::null_mut(),
        acl: ptr::null_mut(),
        str: ptr::null_mut(),
        str_len: ptr::null_mut(),
        ops: ptr::null_mut(),
        nops: ptr::null_mut(),
    }
}

fn sync_src(kind: u32) -> zkrs_sync_src {
    zkrs_sync_src {
        kind,
        rc: 0,
        failed: 0,
        origin: 0,
        data: ptr::null(),
        data_len: -1,
        path: ptr::null(),
        path_len: 0,
        stat: ptr::null(),
        ops: ptr::null(),
        nops: 0,
        op_kind: ptr::null(),
    }
}

fn sync_dst() -> zkrs_sync_dst {
    zkrs_sync_dst {
        buffer: ptr::null_mut(),
        buffer_len: ptr::null_mut(),
        path_buffer: ptr::null_mut(),
        path_buffer_len: 0,
        stat: ptr::null_mut(),
        results: ptr::null_mut(),
        count: 0,
    }
}

/// The bytes of a NUL-terminated C string.
fn c_str_at(p: *const c_char) -> Vec<u8> {
    // SAFETY: the writer made `p` with a NUL at the end.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// The `n` bytes at `p`.
fn bytes_at(p: *const c_char, n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    // SAFETY: the writer made `n` readable bytes at `p`.
    unsafe { std::slice::from_raw_parts(p.cast::<u8>(), n) }.to_vec()
}

/// Element `i` of an array that a writer made.
fn elem<T: Copy>(p: *const T, i: usize) -> T {
    // SAFETY: the writer made more than `i` elements at `p`.
    unsafe { p.wrapping_add(i).read() }
}

/// libc `free`, as C and the application call it.
fn free<T>(p: *mut T) {
    // SAFETY: `p` is NULL or comes from the libc allocator of a writer.
    unsafe { libc::free(p.cast::<c_void>()) };
}

/// A NUL-terminated string or NULL, then `free`.
fn take_str(p: *mut c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    let s = c_str_at(p);
    free(p);
    Some(s)
}

/// Reads a vector, then frees it as `deallocate_String_vector` does.
fn take_strings(sv: CStringVector) -> Vec<Option<Vec<u8>>> {
    let n = usize::try_from(sv.count).unwrap_or(0);
    let out = (0..n).map(|i| take_str(elem(sv.data, i))).collect();
    free(sv.data);
    out
}

type AclRow = (i32, Option<Vec<u8>>, Option<Vec<u8>>);

/// Reads a vector, then frees it as `deallocate_ACL_vector` does.
fn take_acl(av: CAclVector) -> Vec<AclRow> {
    let n = usize::try_from(av.count).unwrap_or(0);
    let out = (0..n)
        .map(|i| {
            let a: CAcl = elem(av.data, i);
            (a.perms, take_str(a.id.scheme), take_str(a.id.id))
        })
        .collect();
    free(av.data);
    out
}

/// One per-op copy as a test sees it: err, failed, path, path_len and
/// stat.
type CopyRow = (i32, i32, Option<Vec<u8>>, i32, Option<zkrs_stat>);

/// Reads the per-op copies of a sync record, then frees them.
fn take_copies(ops: *mut zkrs_multi_copy, n: i32) -> Vec<CopyRow> {
    let n = usize::try_from(n).unwrap_or(0);
    let out = (0..n)
        .map(|i| {
            let c: zkrs_multi_copy = elem(ops, i);
            let st = (c.has_stat != 0).then_some(c.stat);
            (c.err, c.failed, take_str(c.path), c.path_len, st)
        })
        .collect();
    free(ops);
    out
}

// ---------------------------------------------------------------------
// write_stat and write_result.
// ---------------------------------------------------------------------

#[test]
fn write_stat_maps_every_field() {
    let mut c = CStat::default();
    writers::write_stat(&raw mut c, &ST);
    assert_eq!(c, cst(&ST));
    // A NULL destination is "no output".
    writers::write_stat(ptr::null_mut(), &ST);
}

#[test]
fn void_and_unknown_kinds_write_nothing() {
    let data = *b"abc";
    for kind in [ZKRS_K_VOID, 99] {
        let mut v = view(kind);
        v.stat = &ST;
        v.data = zbuf(&data);
        v.path = zstr(c"/p");
        let mut st = marker_stat();
        let mut val = marker_ptr();
        let mut len = 42;
        let mut s = marker_ptr();
        let mut d = dst();
        d.stat = (&raw mut st).cast();
        d.value = &raw mut val;
        d.value_len = &raw mut len;
        d.str = &raw mut s;
        writers::write_result(&v, &d);
        assert_eq!(
            (st, val, len, s),
            (marker_stat(), marker_ptr(), 42, marker_ptr())
        );
    }
}

#[test]
fn stat_kind_writes_the_stat() {
    let mut v = view(ZKRS_K_STAT);
    v.stat = &ST;
    let mut st = CStat::default();
    let mut d = dst();
    d.stat = (&raw mut st).cast();
    writers::write_result(&v, &d);
    assert_eq!(st, cst(&ST));
    // A NULL stat destination gets nothing.
    writers::write_result(&v, &dst());
    // A view with no stat gives a zero record, never stale memory.
    let mut st = marker_stat();
    d.stat = (&raw mut st).cast();
    writers::write_result(&view(ZKRS_K_STAT), &d);
    assert_eq!(st, CStat::default());
}

#[test]
fn data_kind_copies_without_a_nul() {
    let data = *b"hello";
    let mut v = view(ZKRS_K_DATA);
    v.data = zbuf(&data);
    v.stat = &ST;
    let mut st = CStat::default();
    let mut val = ptr::null_mut();
    let mut len = 0;
    let mut d = dst();
    d.stat = (&raw mut st).cast();
    d.value = &raw mut val;
    d.value_len = &raw mut len;
    writers::write_result(&v, &d);
    assert!(!val.is_null());
    assert_eq!(len, 5);
    assert_eq!(bytes_at(val, 5), b"hello");
    assert_eq!(st, cst(&ST));
    free(val);
}

/// Rule: a null znode gives `(NULL, -1)`, and an empty znode gives
/// `(malloc(0), 0)`. The buffer has no NUL terminator.
#[test]
fn data_kind_null_and_empty_znodes() {
    // A null znode gives (NULL, -1).
    let mut val = marker_ptr();
    let mut len = 0;
    let mut d = dst();
    d.value = &raw mut val;
    d.value_len = &raw mut len;
    writers::write_result(&view(ZKRS_K_DATA), &d);
    assert_eq!((val, len), (ptr::null_mut(), -1));

    // An empty znode gives malloc(0) and 0, with a NULL or a real view
    // pointer.
    let empty: [u8; 0] = [];
    for p in [ptr::null(), empty.as_ptr().cast::<c_char>()] {
        let mut v = view(ZKRS_K_DATA);
        v.data = zkrs_buf { ptr: p, len: 0 };
        let mut val = marker_ptr();
        let mut len = 9;
        let mut d = dst();
        d.value = &raw mut val;
        d.value_len = &raw mut len;
        writers::write_result(&v, &d);
        assert_eq!(len, 0);
        assert_ne!(val, marker_ptr());
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(!val.is_null());
        free(val);
    }
}

#[test]
fn data_kind_null_destination_members() {
    let data = *b"xyz";
    let mut v = view(ZKRS_K_DATA);
    v.data = zbuf(&data);
    v.stat = &ST;
    // Only the length: no buffer is allocated (Miri sees a leak if one is).
    let mut len = 0;
    let mut d = dst();
    d.value_len = &raw mut len;
    writers::write_result(&v, &d);
    assert_eq!(len, 3);
    // Only the buffer.
    let mut val = ptr::null_mut();
    let mut d = dst();
    d.value = &raw mut val;
    writers::write_result(&v, &d);
    assert_eq!(bytes_at(val, 3), b"xyz");
    free(val);
    // No member at all.
    writers::write_result(&v, &dst());
}

#[test]
fn failed_views_write_nothing() {
    let data = *b"abc";
    let kids = [zstr(c"a")];
    for kind in [
        ZKRS_K_STAT,
        ZKRS_K_DATA,
        ZKRS_K_STRINGLIST,
        ZKRS_K_STRINGLIST_STAT,
        ZKRS_K_ACLLIST,
        ZKRS_K_STRING,
        ZKRS_K_STRING_STAT,
    ] {
        let mut v = view(kind);
        v.failed = 1;
        v.rc = -101;
        v.stat = &ST;
        v.data = zbuf(&data);
        v.path = zstr(c"/p");
        v.children = kids.as_ptr();
        v.nchildren = 1;
        let mut st = marker_stat();
        let mut val = marker_ptr();
        let mut len = 42;
        let mut sv = CStringVector {
            count: 5,
            data: ptr::null_mut(),
        };
        let mut s = marker_ptr();
        let mut slen = 43;
        let mut d = dst();
        d.stat = (&raw mut st).cast();
        d.value = &raw mut val;
        d.value_len = &raw mut len;
        d.strings = (&raw mut sv).cast();
        d.str = &raw mut s;
        d.str_len = &raw mut slen;
        writers::write_result(&v, &d);
        assert_eq!(st, marker_stat());
        assert_eq!((val, len, s, slen), (marker_ptr(), 42, marker_ptr(), 43));
        assert_eq!((sv.count, sv.data), (5, ptr::null_mut()));
    }
}

#[test]
fn stringlist_kinds_use_the_legacy_layout() {
    let long = vec![b'n'; 300];
    let mut long_z = long.clone();
    long_z.push(0);
    let kids = [zstr(c"a"), zkrs_str::null(), zbytes(&long_z), zstr(c"")];
    for kind in [ZKRS_K_STRINGLIST, ZKRS_K_STRINGLIST_STAT] {
        let mut v = view(kind);
        v.children = kids.as_ptr();
        v.nchildren = 4;
        v.stat = &ST;
        let mut sv = CStringVector {
            count: 0,
            data: ptr::null_mut(),
        };
        let mut st = CStat::default();
        let mut d = dst();
        d.strings = (&raw mut sv).cast();
        d.stat = (&raw mut st).cast();
        writers::write_result(&v, &d);
        assert_eq!(sv.count, 4);
        assert_eq!(
            take_strings(sv),
            vec![
                Some(b"a".to_vec()),
                None,
                Some(long.clone()),
                Some(Vec::new())
            ]
        );
        let want = if kind == ZKRS_K_STRINGLIST_STAT {
            cst(&ST)
        } else {
            CStat::default()
        };
        assert_eq!(st, want);
    }
}

/// Rule: a vector comes from `calloc(count, size)`. Count 0 gives a
/// non-NULL pointer, and count -1 gives NULL.
#[test]
fn stringlist_empty_and_null_vectors() {
    // count 0: calloc(0, size) and count 0.
    let mut v = view(ZKRS_K_STRINGLIST);
    v.nchildren = 0;
    let mut sv = CStringVector {
        count: 9,
        data: ptr::null_mut(),
    };
    let mut d = dst();
    d.strings = (&raw mut sv).cast();
    writers::write_result(&v, &d);
    assert_eq!(sv.count, 0);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    assert!(!sv.data.is_null());
    assert!(take_strings(sv).is_empty());

    // count -1: the jute null vector, data NULL with no call.
    v.nchildren = -1;
    let mut sv = CStringVector {
        count: 9,
        data: marker_ptr().cast(),
    };
    d.strings = (&raw mut sv).cast();
    writers::write_result(&v, &d);
    assert_eq!((sv.count, sv.data), (-1, ptr::null_mut()));

    // A NULL strings destination allocates nothing.
    let kids = [zstr(c"a")];
    v.children = kids.as_ptr();
    v.nchildren = 1;
    writers::write_result(&v, &dst());
}

#[test]
fn acllist_kind_copies_every_entry() {
    let acl = [
        zkrs_acl_view {
            perms: 31,
            scheme: zstr(c"world"),
            id: zstr(c"anyone"),
        },
        zkrs_acl_view {
            perms: 1,
            scheme: zstr(c"digest"),
            id: zkrs_str::null(),
        },
    ];
    let mut v = view(ZKRS_K_ACLLIST);
    v.acl = acl.as_ptr();
    v.nacl = 2;
    v.stat = &ST;
    let mut av = CAclVector {
        count: 0,
        data: ptr::null_mut(),
    };
    let mut st = CStat::default();
    let mut d = dst();
    d.acl = (&raw mut av).cast();
    d.stat = (&raw mut st).cast();
    writers::write_result(&v, &d);
    assert_eq!(st, cst(&ST));
    assert_eq!(av.count, 2);
    assert_eq!(
        take_acl(av),
        vec![
            (31, Some(b"world".to_vec()), Some(b"anyone".to_vec())),
            (1, Some(b"digest".to_vec()), None),
        ]
    );

    // count -1 and count 0.
    v.nacl = -1;
    let mut av = CAclVector {
        count: 7,
        data: marker_ptr().cast(),
    };
    d.acl = (&raw mut av).cast();
    writers::write_result(&v, &d);
    assert_eq!((av.count, av.data), (-1, ptr::null_mut()));
    v.nacl = 0;
    writers::write_result(&v, &d);
    assert_eq!(av.count, 0);
    assert!(take_acl(av).is_empty());
    // A NULL ACL destination allocates nothing.
    v.nacl = 2;
    writers::write_result(&v, &dst());
}

#[test]
fn string_kinds_copy_the_path() {
    for kind in [ZKRS_K_STRING, ZKRS_K_STRING_STAT] {
        let mut v = view(kind);
        v.path = zstr(c"/a/b");
        v.stat = &ST;
        let mut s = ptr::null_mut();
        let mut len = 0;
        let mut st = CStat::default();
        let mut d = dst();
        d.str = &raw mut s;
        d.str_len = &raw mut len;
        d.stat = (&raw mut st).cast();
        writers::write_result(&v, &d);
        assert_eq!(len, 4);
        assert_eq!(take_str(s), Some(b"/a/b".to_vec()));
        let want = if kind == ZKRS_K_STRING_STAT {
            cst(&ST)
        } else {
            CStat::default()
        };
        assert_eq!(st, want);
    }
}

#[test]
fn string_kind_null_path_and_null_members() {
    let mut v = view(ZKRS_K_STRING);
    let mut s = marker_ptr();
    let mut len = 5;
    let mut d = dst();
    d.str = &raw mut s;
    d.str_len = &raw mut len;
    writers::write_result(&v, &d);
    assert_eq!((s, len), (ptr::null_mut(), 0));
    // Only the length: no copy is allocated.
    v.path = zstr(c"/x");
    let mut d = dst();
    d.str_len = &raw mut len;
    writers::write_result(&v, &d);
    assert_eq!(len, 2);
    writers::write_result(&v, &dst());
}

#[test]
fn multi_kind_writes_sync_copies() {
    let ops = [
        zkrs_multi_op {
            err: 0,
            failed: 0,
            path: zstr(c"/n0000000001"),
            stat: ptr::null(),
        },
        zkrs_multi_op {
            err: 0,
            failed: 0,
            path: zkrs_str::null(),
            stat: &ST,
        },
        zkrs_multi_op {
            err: -101,
            failed: 1,
            path: zkrs_str::null(),
            stat: ptr::null(),
        },
    ];
    let mut v = view(ZKRS_K_MULTI);
    v.ops = ops.as_ptr();
    v.nops = 3;
    v.rc = -101;
    let mut out = ptr::null_mut();
    let mut n = 0;
    let mut d = dst();
    d.ops = &raw mut out;
    d.nops = &raw mut n;
    writers::write_result(&v, &d);
    assert_eq!(n, 3);
    assert_eq!(
        take_copies(out, n),
        vec![
            (0, 0, Some(b"/n0000000001".to_vec()), 12, None),
            (0, 0, None, 0, Some(ST)),
            (-101, 1, None, 0, None),
        ]
    );
}

#[test]
fn multi_kind_failed_view_has_no_copies() {
    let mut v = view(ZKRS_K_MULTI);
    v.failed = 1;
    v.rc = -118;
    let mut out = ptr::dangling_mut::<zkrs_multi_copy>();
    let mut n = 7;
    let mut d = dst();
    d.ops = &raw mut out;
    d.nops = &raw mut n;
    writers::write_result(&v, &d);
    assert_eq!((out, n), (ptr::null_mut(), 0));
    // One member alone gets nothing, so no copy can leak.
    let ops = [zkrs_multi_op {
        err: 0,
        failed: 0,
        path: zstr(c"/x"),
        stat: ptr::null(),
    }];
    v.ops = ops.as_ptr();
    v.nops = 1;
    v.failed = 0;
    let mut out = ptr::dangling_mut::<zkrs_multi_copy>();
    let mut d = dst();
    d.ops = &raw mut out;
    writers::write_result(&v, &d);
    assert_eq!(out, ptr::dangling_mut());
    let mut n = 7;
    let mut d = dst();
    d.nops = &raw mut n;
    writers::write_result(&v, &d);
    assert_eq!(n, 7);
}

// ---------------------------------------------------------------------
// write_path.
// ---------------------------------------------------------------------

#[test]
fn write_path_is_never_null() {
    // A session event: the jute null string and the empty string.
    for s in [zkrs_str::null(), zstr(c"")] {
        let p = writers::write_path(&s);
        assert_eq!(take_str(p), Some(Vec::new()));
    }
    // A NULL view also gives "".
    assert_eq!(take_str(writers::write_path(ptr::null())), Some(Vec::new()));
    let p = writers::write_path(&zstr(c"/a/b"));
    assert_eq!(take_str(p), Some(b"/a/b".to_vec()));
}

#[test]
fn write_path_copies_a_long_path() {
    let mut long = Vec::with_capacity(5000);
    long.push(b'/');
    long.resize(4999, b'z');
    let mut z = long.clone();
    z.push(0);
    let p = writers::write_path(&zbytes(&z));
    assert_eq!(take_str(p), Some(long));
}

#[test]
fn write_path_through_the_export() {
    let p = super::super::results::zkrs_write_path(&zstr(c"/w"));
    assert_eq!(take_str(p), Some(b"/w".to_vec()));
}

// ---------------------------------------------------------------------
// write_multi.
// ---------------------------------------------------------------------

const K_STR: u8 = 6;
const K_STAT: u8 = 1;
const K_VOID: u8 = 0;

#[test]
fn op_kind_values_match_the_kinds() {
    assert_eq!(u32::from(K_STR), ZKRS_K_STRING);
    assert_eq!(u32::from(K_STAT), ZKRS_K_STAT);
    assert_eq!(u32::from(K_VOID), ZKRS_K_VOID);
}

fn op(err: i32, failed: i32, path: zkrs_str, stat: *const zkrs_stat) -> zkrs_multi_op {
    zkrs_multi_op {
        err,
        failed,
        path,
        stat,
    }
}

fn multi_view(ops: &[zkrs_multi_op]) -> zkrs_result_view {
    let mut v = view(ZKRS_K_MULTI);
    v.ops = ops.as_ptr();
    v.nops = len32(ops.len());
    v
}

#[test]
fn write_multi_success() {
    let ops = [
        op(0, 0, zstr(c"/n0000000007"), ptr::null()),
        op(0, 0, zkrs_str::null(), &ST),
        op(0, 0, zkrs_str::null(), ptr::null()),
        op(0, 0, zkrs_str::null(), ptr::null()),
    ];
    let kinds = [K_STR, K_STAT, K_VOID, K_VOID];
    let mut buf = [0xEEu8; 16];
    let mut st = CStat::default();
    let mut res = [
        COpResult {
            err: 99,
            value: buf.as_mut_ptr().cast(),
            valuelen: 16,
            stat: ptr::null_mut(),
        },
        COpResult {
            err: 99,
            value: ptr::null_mut(),
            valuelen: 0,
            stat: &raw mut st,
        },
        COpResult {
            err: 99,
            value: ptr::null_mut(),
            valuelen: 0,
            stat: ptr::null_mut(),
        },
        COpResult {
            err: 99,
            value: ptr::null_mut(),
            valuelen: 0,
            stat: ptr::null_mut(),
        },
    ];
    writers::write_multi(&multi_view(&ops), res.as_mut_ptr(), kinds.as_ptr(), 4);
    let [a, b, c, d] = res;
    assert_eq!((a.err, a.valuelen), (0, 16));
    assert_eq!(a.value, buf.as_mut_ptr().cast());
    assert_eq!(&buf, b"/n0000000007\0\xEE\xEE\xEE");
    assert_eq!(b.err, 0);
    assert_eq!(b.stat, &raw mut st);
    assert_eq!(st, cst(&ST));
    assert_eq!((c.err, d.err), (0, 0));
}

/// Runs the STRING writer for one create with a buffer of `cap` and
/// returns the buffer and the `value` member after the call.
fn multi_string(path: zkrs_str, cap: i32, failed: i32) -> ([u8; 8], bool, i32) {
    let ops = [op(0, failed, path, ptr::null())];
    let mut buf = [0xEEu8; 8];
    let mut res = [COpResult {
        err: 99,
        value: buf.as_mut_ptr().cast(),
        valuelen: cap,
        stat: ptr::null_mut(),
    }];
    writers::write_multi(&multi_view(&ops), res.as_mut_ptr(), [K_STR].as_ptr(), 1);
    let [r] = res;
    (buf, r.value.is_null(), r.valuelen)
}

#[test]
fn write_multi_string_truncation() {
    let e = 0xEEu8;
    let p = zstr(c"/abcd");
    // The whole path and its NUL fit.
    assert_eq!(multi_string(p, 8, 0), (*b"/abcd\0\xEE\xEE", false, 8));
    assert_eq!(multi_string(p, 6, 0), (*b"/abcd\0\xEE\xEE", false, 6));
    // min(strlen + 1, valuelen) - 1 bytes, then a NUL.
    assert_eq!(multi_string(p, 5, 0), (*b"/abc\0\xEE\xEE\xEE", false, 5));
    assert_eq!(multi_string(p, 1, 0), ([0, e, e, e, e, e, e, e], false, 1));
    // valuelen <= 0: no write, and value stays.
    assert_eq!(multi_string(p, 0, 0), ([e; 8], false, 0));
    assert_eq!(multi_string(p, -3, 0), ([e; 8], false, -3));
    // strlen stops at the first NUL of the path.
    let z = *b"ab\0cd\0";
    assert_eq!(
        multi_string(zbytes(&z), 8, 0),
        (*b"ab\0\xEE\xEE\xEE\xEE\xEE", false, 8)
    );
    // An empty path gives "".
    assert_eq!(
        multi_string(zstr(c""), 8, 0),
        ([0, e, e, e, e, e, e, e], false, 8)
    );
    // A NULL path or an error result clears value. valuelen stays.
    assert_eq!(multi_string(zkrs_str::null(), 8, 0), ([e; 8], true, 8));
    assert_eq!(multi_string(p, 8, 1), ([e; 8], true, 8));
}

#[test]
fn write_multi_null_value_stays_null() {
    let ops = [op(0, 0, zstr(c"/x"), ptr::null())];
    let mut res = [COpResult {
        err: 99,
        value: ptr::null_mut(),
        valuelen: 8,
        stat: ptr::null_mut(),
    }];
    writers::write_multi(&multi_view(&ops), res.as_mut_ptr(), [K_STR].as_ptr(), 1);
    let [r] = res;
    assert_eq!((r.err, r.value, r.valuelen), (0, ptr::null_mut(), 8));
}

#[test]
fn write_multi_per_op_failure() {
    // A failed create, a failed set, and a set with an error but no
    // failure flag: every stat and value is cleared.
    let ops = [
        op(-110, 1, zkrs_str::null(), ptr::null()),
        op(-101, 1, zkrs_str::null(), ptr::null()),
        op(-2, 0, zkrs_str::null(), &ST),
        op(0, 0, zkrs_str::null(), ptr::null()),
    ];
    let kinds = [K_STR, K_STAT, K_STAT, K_STAT];
    let mut buf = [0xEEu8; 4];
    let mut st = [marker_stat(); 3];
    let [s0, s1, s2] = &mut st;
    let mut res = [
        COpResult {
            err: 99,
            value: buf.as_mut_ptr().cast(),
            valuelen: 4,
            stat: ptr::null_mut(),
        },
        COpResult {
            err: 99,
            value: ptr::null_mut(),
            valuelen: 0,
            stat: s0,
        },
        COpResult {
            err: 99,
            value: ptr::null_mut(),
            valuelen: 0,
            stat: s1,
        },
        COpResult {
            err: 99,
            value: ptr::null_mut(),
            valuelen: 0,
            stat: s2,
        },
    ];
    let mut v = multi_view(&ops);
    v.rc = -110;
    writers::write_multi(&v, res.as_mut_ptr(), kinds.as_ptr(), 4);
    let [a, b, c, d] = res;
    assert_eq!((a.err, a.value, a.valuelen), (-110, ptr::null_mut(), 4));
    assert_eq!((b.err, b.stat), (-101, ptr::null_mut()));
    assert_eq!((c.err, c.stat), (-2, ptr::null_mut()));
    // A set with no stat in the view also clears the member.
    assert_eq!((d.err, d.stat), (0, ptr::null_mut()));
    assert_eq!(buf, [0xEE; 4]);
    assert_eq!(st, [marker_stat(); 3]);
}

#[test]
fn write_multi_header_only_error() {
    // Reply None: cleanup_failed_multi gives {err = rc} to every op.
    let mut v = view(ZKRS_K_MULTI);
    v.failed = 1;
    v.rc = -118;
    for origin in [ZKRS_ORIGIN_REPLY, ZKRS_ORIGIN_TEARDOWN] {
        v.origin = origin;
        let kinds = [K_STR, K_STAT, K_VOID];
        let mut buf = [0xEEu8; 4];
        let mut st = marker_stat();
        let mut res = [
            COpResult {
                err: 99,
                value: buf.as_mut_ptr().cast(),
                valuelen: 4,
                stat: ptr::null_mut(),
            },
            COpResult {
                err: 99,
                value: ptr::null_mut(),
                valuelen: 3,
                stat: &raw mut st,
            },
            COpResult {
                err: 99,
                value: marker_ptr(),
                valuelen: 2,
                stat: ptr::null_mut(),
            },
        ];
        writers::write_multi(&v, res.as_mut_ptr(), kinds.as_ptr(), 3);
        let [a, b, c] = res;
        assert_eq!((a.err, a.value, a.valuelen), (-118, ptr::null_mut(), 4));
        assert_eq!((b.err, b.stat, b.valuelen), (-118, ptr::null_mut(), 3));
        assert_eq!((c.err, c.value, c.valuelen), (-118, marker_ptr(), 2));
        assert_eq!((buf, st), ([0xEE; 4], marker_stat()));
    }
}

#[test]
fn write_multi_unsupported_type_is_void() {
    // zks_req_new_multi gives VOID to every op that is not a create or a
    // set, also to the unsupported op that ends the prefix. Any other
    // kind value also writes only err.
    let ops = [op(-6, 1, zstr(c"/x"), &ST), op(-6, 1, zstr(c"/y"), &ST)];
    let kinds = [K_VOID, 99];
    let mut st = marker_stat();
    let mut res = [
        COpResult {
            err: 99,
            value: marker_ptr(),
            valuelen: 1,
            stat: &raw mut st,
        },
        COpResult {
            err: 99,
            value: marker_ptr(),
            valuelen: 1,
            stat: &raw mut st,
        },
    ];
    writers::write_multi(&multi_view(&ops), res.as_mut_ptr(), kinds.as_ptr(), 2);
    let [a, b] = res;
    assert_eq!((a.err, a.value, a.valuelen), (-6, marker_ptr(), 1));
    assert_eq!((b.err, b.value, b.valuelen), (-6, marker_ptr(), 1));
    assert_eq!(st, marker_stat());
}

#[test]
fn write_multi_bounds_and_null_cases() {
    let ops = [
        op(1, 0, zkrs_str::null(), ptr::null()),
        op(2, 0, zkrs_str::null(), ptr::null()),
        op(3, 0, zkrs_str::null(), ptr::null()),
    ];
    let kinds = [K_VOID; 3];
    let fresh = || COpResult {
        err: 99,
        value: ptr::null_mut(),
        valuelen: 0,
        stat: ptr::null_mut(),
    };
    // count < nops: the writer stops at count.
    let mut res = [fresh(), fresh(), fresh()];
    writers::write_multi(&multi_view(&ops), res.as_mut_ptr(), kinds.as_ptr(), 2);
    let [a, b, c] = res;
    assert_eq!((a.err, b.err, c.err), (1, 2, 99));
    // nops < count: the other results stay.
    let mut res = [fresh(), fresh(), fresh()];
    let short = multi_view(ops.get(..1).unwrap_or(&ops));
    writers::write_multi(&short, res.as_mut_ptr(), kinds.as_ptr(), 3);
    let [a, b, c] = res;
    assert_eq!((a.err, b.err, c.err), (1, 99, 99));
    // count 0 or a negative count, and NULL results, write nothing. The
    // kinds can be NULL then.
    let mut res = [fresh()];
    writers::write_multi(&multi_view(&ops), res.as_mut_ptr(), ptr::null(), 0);
    writers::write_multi(&multi_view(&ops), res.as_mut_ptr(), ptr::null(), -1);
    writers::write_multi(&multi_view(&ops), ptr::null_mut(), kinds.as_ptr(), 3);
    let [a] = res;
    assert_eq!(a.err, 99);
    // An empty multi that is not failed writes nothing.
    let mut res = [fresh()];
    writers::write_multi(&view(ZKRS_K_MULTI), res.as_mut_ptr(), kinds.as_ptr(), 1);
    let [a] = res;
    assert_eq!(a.err, 99);
}

#[test]
fn write_multi_through_the_export() {
    let ops = [op(4, 0, zkrs_str::null(), ptr::null())];
    let mut res = [COpResult {
        err: 99,
        value: ptr::null_mut(),
        valuelen: 0,
        stat: ptr::null_mut(),
    }];
    super::super::results::zkrs_write_multi(
        &multi_view(&ops),
        res.as_mut_ptr().cast(),
        [K_VOID].as_ptr(),
        1,
    );
    let [a] = res;
    assert_eq!(a.err, 4);
}

// ---------------------------------------------------------------------
// sync_copy_out.
// ---------------------------------------------------------------------

/// Runs the DATA copy-out with `data` (None is a null znode) into an
/// 8-byte buffer of capacity `cap`. It returns `*buffer_len` and the
/// buffer.
fn sync_get(data: Option<&[u8]>, cap: i32, with_buffer: bool) -> (i32, [u8; 8]) {
    let mut s = sync_src(ZKRS_K_DATA);
    if let Some(b) = data {
        s.data = b.as_ptr().cast();
        s.data_len = len32(b.len());
    }
    let mut buf = [0xEEu8; 8];
    let mut len = cap;
    let mut d = sync_dst();
    if with_buffer {
        d.buffer = buf.as_mut_ptr().cast();
    }
    d.buffer_len = &raw mut len;
    writers::sync_copy_out(&s, &d);
    (len, buf)
}

/// Rule: the sync get copies `min(datalen, capacity)` bytes with no NUL.
/// Null data and capacity -1 give -1 and leave the buffer as it is.
#[test]
fn sync_data_truncation_matrix() {
    let e = 0xEEu8;
    let h = b"hello".as_slice();
    // data_len <= cap: the whole buffer, no NUL.
    assert_eq!(sync_get(Some(h), 8, true), (5, *b"hello\xEE\xEE\xEE"));
    assert_eq!(sync_get(Some(h), 5, true), (5, *b"hello\xEE\xEE\xEE"));
    // data_len > cap: cap bytes.
    assert_eq!(sync_get(Some(h), 3, true), (3, *b"hel\xEE\xEE\xEE\xEE\xEE"));
    assert_eq!(
        sync_get(Some(h), 1, true),
        (1, *b"h\xEE\xEE\xEE\xEE\xEE\xEE\xEE")
    );
    // cap == 0: length 0, no write.
    assert_eq!(sync_get(Some(h), 0, true), (0, [e; 8]));
    // An empty znode: length 0, no write.
    assert_eq!(sync_get(Some(&[]), 8, true), (0, [e; 8]));
    // A null znode: -1, the buffer stays.
    assert_eq!(sync_get(None, 8, true), (-1, [e; 8]));
    assert_eq!(sync_get(None, 0, true), (-1, [e; 8]));
    // cap == -1: -1 with data and with a null znode.
    assert_eq!(sync_get(Some(h), -1, true), (-1, [e; 8]));
    assert_eq!(sync_get(None, -1, true), (-1, [e; 8]));
    // cap < -1: the capacity, no copy. Legacy C crashes in memcpy here.
    assert_eq!(sync_get(Some(h), -5, true), (-5, [e; 8]));
    assert_eq!(sync_get(None, -5, true), (-5, [e; 8]));
    assert_eq!(sync_get(Some(h), i32::MIN, true), (i32::MIN, [e; 8]));
    // A NULL buffer: the formula, no copy (legacy crash row).
    assert_eq!(sync_get(Some(h), 8, false), (5, [e; 8]));
    assert_eq!(sync_get(Some(h), 3, false), (3, [e; 8]));
}

#[test]
fn sync_data_writes_only_for_a_decoded_zok() {
    let h = *b"hello";
    let mut s = sync_src(ZKRS_K_DATA);
    s.data = h.as_ptr().cast();
    s.data_len = 5;
    let rec = cst(&ST);
    s.stat = (&raw const rec).cast();
    for (rc, failed) in [(-101, 1), (-4, 1), (0, 1), (-101, 0)] {
        s.rc = rc;
        s.failed = failed;
        let mut buf = [0xEEu8; 8];
        let mut len = 8;
        let mut st = marker_stat();
        let mut d = sync_dst();
        d.buffer = buf.as_mut_ptr().cast();
        d.buffer_len = &raw mut len;
        d.stat = (&raw mut st).cast();
        writers::sync_copy_out(&s, &d);
        assert_eq!((len, buf, st), (8, [0xEE; 8], marker_stat()));
    }
    // rc == ZOK: the buffer and the stat.
    s.rc = 0;
    s.failed = 0;
    let mut buf = [0u8; 8];
    let mut len = 8;
    let mut st = CStat::default();
    let mut d = sync_dst();
    d.buffer = buf.as_mut_ptr().cast();
    d.buffer_len = &raw mut len;
    d.stat = (&raw mut st).cast();
    writers::sync_copy_out(&s, &d);
    assert_eq!((len, st), (5, rec));
    // A NULL stat is tolerated, and a NULL buffer_len skips the data.
    d.stat = ptr::null_mut();
    writers::sync_copy_out(&s, &d);
    let mut st = CStat::default();
    let mut d = sync_dst();
    d.stat = (&raw mut st).cast();
    writers::sync_copy_out(&s, &d);
    assert_eq!(st, rec);
}

/// Runs the STRING copy-out of `path` into an 8-byte buffer with the
/// capacity `cap`.
fn sync_create(path: Option<&[u8]>, cap: i32, with_buffer: bool) -> [u8; 8] {
    let mut s = sync_src(ZKRS_K_STRING);
    if let Some(p) = path {
        s.path = p.as_ptr().cast();
        s.path_len = len32(p.len().saturating_sub(1));
    }
    let mut buf = [0xEEu8; 8];
    let mut d = sync_dst();
    if with_buffer {
        d.path_buffer = buf.as_mut_ptr().cast();
    }
    d.path_buffer_len = cap;
    writers::sync_copy_out(&s, &d);
    buf
}

/// Rule: the sync create copies `min(strlen + 1, len) - 1` bytes and a
/// NUL. A length of 0 or less copies nothing.
#[test]
fn sync_string_truncation_matrix() {
    let e = 0xEEu8;
    let p = Some(b"/a/b\0".as_slice());
    assert_eq!(sync_create(p, 8, true), *b"/a/b\0\xEE\xEE\xEE");
    assert_eq!(sync_create(p, 5, true), *b"/a/b\0\xEE\xEE\xEE");
    // min(strlen + 1, len) - 1 bytes, then a NUL.
    assert_eq!(sync_create(p, 4, true), *b"/a/\0\xEE\xEE\xEE\xEE");
    assert_eq!(sync_create(p, 1, true), [0, e, e, e, e, e, e, e]);
    // len <= 0: nothing.
    assert_eq!(sync_create(p, 0, true), [e; 8]);
    assert_eq!(sync_create(p, -1, true), [e; 8]);
    assert_eq!(sync_create(p, -9, true), [e; 8]);
    assert_eq!(sync_create(p, i32::MIN, true), [e; 8]);
    // A NULL buffer: nothing (legacy crash row).
    assert_eq!(sync_create(p, 8, false), [e; 8]);
    // strlen stops at the first NUL.
    assert_eq!(
        sync_create(Some(b"ab\0cd\0"), 8, true),
        *b"ab\0\xEE\xEE\xEE\xEE\xEE"
    );
    // An empty path, and a NULL path, give "".
    assert_eq!(sync_create(Some(b"\0"), 8, true), [0, e, e, e, e, e, e, e]);
    assert_eq!(sync_create(None, 8, true), [0, e, e, e, e, e, e, e]);
}

#[test]
fn sync_string_stat_and_error_rcs() {
    let p = *b"/z\0";
    let rec = cst(&ST);
    for kind in [ZKRS_K_STRING, ZKRS_K_STRING_STAT] {
        let mut s = sync_src(kind);
        s.path = p.as_ptr().cast();
        s.path_len = 2;
        s.stat = (&raw const rec).cast();
        let mut buf = [0xEEu8; 4];
        let mut st = CStat::default();
        let mut d = sync_dst();
        d.path_buffer = buf.as_mut_ptr().cast();
        d.path_buffer_len = 4;
        d.stat = (&raw mut st).cast();
        writers::sync_copy_out(&s, &d);
        assert_eq!((buf, st), (*b"/z\0\xEE", rec));
        // An error rc leaves every output as it is.
        s.rc = -110;
        s.failed = 1;
        let mut buf = [0xEEu8; 4];
        let mut st = marker_stat();
        d.path_buffer = buf.as_mut_ptr().cast();
        d.stat = (&raw mut st).cast();
        writers::sync_copy_out(&s, &d);
        assert_eq!((buf, st), ([0xEE; 4], marker_stat()));
    }
}

/// Rule: a sync call copies the stat only for rc 0 and a non-NULL stat.
/// Legacy get_children2 crashes on a NULL stat.
#[test]
fn sync_stat_kinds_copy_the_stat() {
    let rec = cst(&ST);
    for kind in [
        ZKRS_K_STAT,
        ZKRS_K_STRINGLIST,
        ZKRS_K_STRINGLIST_STAT,
        ZKRS_K_ACLLIST,
    ] {
        let mut s = sync_src(kind);
        s.stat = (&raw const rec).cast();
        let mut st = CStat::default();
        let mut d = sync_dst();
        d.stat = (&raw mut st).cast();
        writers::sync_copy_out(&s, &d);
        assert_eq!(st, rec);
        // A NULL stat is tolerated.
        writers::sync_copy_out(&s, &sync_dst());
    }
    // VOID and an unknown kind write nothing.
    for kind in [ZKRS_K_VOID, 77] {
        let mut s = sync_src(kind);
        s.stat = (&raw const rec).cast();
        let mut st = marker_stat();
        let mut d = sync_dst();
        d.stat = (&raw mut st).cast();
        writers::sync_copy_out(&s, &d);
        assert_eq!(st, marker_stat());
    }
}

fn copy(
    err: i32,
    failed: i32,
    path: *mut c_char,
    path_len: i32,
    stat: Option<zkrs_stat>,
) -> zkrs_multi_copy {
    zkrs_multi_copy {
        err,
        failed,
        path,
        path_len,
        has_stat: u32::from(stat.is_some()),
        stat: stat.unwrap_or_default(),
    }
}

#[test]
fn sync_multi_runs_the_per_op_writers() {
    let mut p = *b"/q0000000001\0";
    let ops = [
        copy(0, 0, p.as_mut_ptr().cast(), 12, None),
        copy(0, 0, ptr::null_mut(), 0, Some(ST)),
        copy(-101, 1, ptr::null_mut(), 0, None),
    ];
    let kinds = [K_STR, K_STAT, K_STAT];
    // The per-op writers run for rc == ZOK and for an error rc.
    for rc in [0, -101] {
        let mut s = sync_src(ZKRS_K_MULTI);
        s.rc = rc;
        s.ops = ops.as_ptr();
        s.nops = 3;
        s.op_kind = kinds.as_ptr();
        let mut buf = [0xEEu8; 8];
        let mut st0 = CStat::default();
        let mut st1 = marker_stat();
        let mut res = [
            COpResult {
                err: 99,
                value: buf.as_mut_ptr().cast(),
                valuelen: 8,
                stat: ptr::null_mut(),
            },
            COpResult {
                err: 99,
                value: ptr::null_mut(),
                valuelen: 0,
                stat: &raw mut st0,
            },
            COpResult {
                err: 99,
                value: ptr::null_mut(),
                valuelen: 0,
                stat: &raw mut st1,
            },
        ];
        let mut d = sync_dst();
        d.results = res.as_mut_ptr().cast();
        d.count = 3;
        writers::sync_copy_out(&s, &d);
        let [a, b, c] = res;
        assert_eq!(&buf, b"/q00000\0");
        assert_eq!((a.err, a.valuelen), (0, 8));
        assert_eq!((b.err, b.stat), (0, &raw mut st0));
        assert_eq!(st0, cst(&ST));
        assert_eq!((c.err, c.stat), (-101, ptr::null_mut()));
        assert_eq!(st1, marker_stat());
    }
}

/// Rule: a header-only error and a teardown write the rc into every
/// result slot. Legacy C aborts on the error and leaves the slots on a
/// teardown.
#[test]
fn sync_multi_header_error_teardown_and_empty() {
    let kinds = [K_STR, K_STAT, K_VOID];
    let run = |failed: i32, origin: u32| {
        let mut s = sync_src(ZKRS_K_MULTI);
        s.rc = -118;
        s.failed = failed;
        s.origin = i32::try_from(origin).unwrap_or(0);
        s.op_kind = kinds.as_ptr();
        let mut st = marker_stat();
        let mut res = [
            COpResult {
                err: 99,
                value: marker_ptr(),
                valuelen: 4,
                stat: ptr::null_mut(),
            },
            COpResult {
                err: 99,
                value: ptr::null_mut(),
                valuelen: 0,
                stat: &raw mut st,
            },
            COpResult {
                err: 99,
                value: ptr::null_mut(),
                valuelen: 0,
                stat: ptr::null_mut(),
            },
        ];
        let mut d = sync_dst();
        d.results = res.as_mut_ptr().cast();
        d.count = 3;
        writers::sync_copy_out(&s, &d);
        let [a, b, c] = res;
        (a.err, a.value.is_null(), b.err, b.stat.is_null(), c.err, st)
    };
    // A header-only error: {err = rc, failed = 1} for every op.
    assert_eq!(
        run(1, ZKRS_ORIGIN_REPLY),
        (-118, true, -118, true, -118, marker_stat())
    );
    // A teardown fails every slot as the async multi does. Legacy sync
    // multi leaves the slots as they are.
    assert_eq!(
        run(1, ZKRS_ORIGIN_TEARDOWN),
        (-118, true, -118, true, -118, marker_stat())
    );
    // An empty decoded multi writes nothing.
    assert_eq!(
        run(0, ZKRS_ORIGIN_REPLY),
        (99, false, 99, false, 99, marker_stat())
    );
}

#[test]
fn sync_multi_null_results_and_count_zero() {
    let mut s = sync_src(ZKRS_K_MULTI);
    s.failed = 1;
    s.rc = -4;
    // count 0 and NULL results: nothing, and the kinds can be NULL.
    writers::sync_copy_out(&s, &sync_dst());
    let mut res = [COpResult {
        err: 99,
        value: ptr::null_mut(),
        valuelen: 0,
        stat: ptr::null_mut(),
    }];
    let mut d = sync_dst();
    d.results = res.as_mut_ptr().cast();
    d.count = 0;
    writers::sync_copy_out(&s, &d);
    let [a] = res;
    assert_eq!(a.err, 99);
}

#[test]
fn sync_copy_out_through_the_export() {
    let h = *b"abc";
    let mut s = sync_src(ZKRS_K_DATA);
    s.data = h.as_ptr().cast();
    s.data_len = 3;
    let mut buf = [0u8; 2];
    let mut len = 2;
    let mut d = sync_dst();
    d.buffer = buf.as_mut_ptr().cast();
    d.buffer_len = &raw mut len;
    super::super::results::zkrs_sync_copy_out(&s, &d);
    assert_eq!((len, buf), (2, *b"ab"));
}

#[test]
fn write_result_through_the_export() {
    let mut v = view(ZKRS_K_STAT);
    v.stat = &ST;
    let mut st = CStat::default();
    let mut d = dst();
    d.stat = (&raw mut st).cast();
    super::super::results::zkrs_write_result(&v, &d);
    assert_eq!(st, cst(&ST));
}

// ---------------------------------------------------------------------
// Reader edge cases and the handle and outbox conversions (spec
// "The C Compatibility Layer", the inbound length conventions).
// ---------------------------------------------------------------------

/// A dangling, aligned, non-NULL pointer. The readers must not
/// dereference it, so Miri reports any read through it.
fn dangling<T>() -> *const T {
    ptr::NonNull::<T>::dangling().as_ptr().cast_const()
}

/// Rule (spec "The audited foreign memory module"): -1 is a null
/// payload and the pointer is ignored. 0 is an empty payload and the
/// pointer is ignored. A length below -1 is an error for any pointer.
#[test]
fn value_ref_ignores_the_pointer_for_minus_one_and_zero() {
    assert_eq!(value_ref(dangling(), -1), Ok(None));
    assert_eq!(value_ref(std::ptr::null(), -1), Ok(None));
    assert_eq!(value_ref(dangling(), 0), Ok(Some(&[][..])));
    for len in [-2, -3, -1000, i32::MIN] {
        assert_eq!(value_ref(dangling(), len), Err(RawError::BadValue));
        assert_eq!(value_ref(std::ptr::null(), len), Err(RawError::BadValue));
    }
    assert_eq!(
        value_ref(std::ptr::null(), i32::MAX),
        Err(RawError::BadValue)
    );
}

/// Rule: a positive length gives exactly `len` bytes, also when
/// the C buffer is longer, and the view holds no NUL that C did not give.
#[test]
fn value_ref_reads_exactly_len_bytes() {
    let b = *b"abcdef";
    let p = b.as_ptr().cast::<c_char>();
    assert_eq!(value_ref(p, 1), Ok(Some(&b"a"[..])));
    assert_eq!(value_ref(p, 6), Ok(Some(&b[..])));
    let z = [0u8, 1, 0];
    assert_eq!(value_ref(z.as_ptr().cast(), 3), Ok(Some(&z[..])));
}

/// Rule: `bytes` gives `&[]` for a zero length with any pointer,
/// NullData for NULL with a length, and TooLong past isize::MAX before a
/// slice exists.
#[test]
fn bytes_checks_null_and_length_first() {
    assert_eq!(bytes(dangling(), 0), Ok(&[][..]));
    assert_eq!(bytes(std::ptr::null(), 1), Err(RawError::NullData));
    assert_eq!(bytes(std::ptr::null(), usize::MAX), Err(RawError::NullData));
    let too_long = usize::try_from(isize::MAX).map_or(usize::MAX, |m| m.saturating_add(1));
    assert_eq!(bytes(dangling(), too_long), Err(RawError::TooLong));
    let b = *b"xyz";
    assert_eq!(bytes(b.as_ptr(), 2), Ok(&b"xy"[..]));
}

/// A record that is too large for `count` copies to fit in isize. No
/// value of the type is made; only its size is used.
#[cfg(target_pointer_width = "64")]
type HugeRecord = [u8; 1 << 33];

/// Rule: a counted array gives `&[]` for `count <= 0` with any
/// pointer, NullData for NULL with `count > 0`, and TooLong when the
/// byte size does not fit in isize.
#[test]
fn array_checks_count_null_and_size() {
    for count in [0, -1, -2, i32::MIN] {
        assert_eq!(array(dangling::<u64>(), count), Ok(&[][..]));
        assert_eq!(array(std::ptr::null::<u64>(), count), Ok(&[][..]));
    }
    assert_eq!(
        array(std::ptr::null::<u64>(), i32::MAX),
        Err(RawError::NullData)
    );
    #[cfg(target_pointer_width = "64")]
    {
        let r = array(dangling::<HugeRecord>(), i32::MAX);
        assert_eq!(r.map(<[HugeRecord]>::len), Err(RawError::TooLong));
    }
    let a = [7u64, 8];
    assert_eq!(array(a.as_ptr(), 1), Ok(&a[..1]));
}

/// Rule: a C string is copied without its NUL, an empty string
/// gives an empty copy, and bytes that are not UTF-8 stay as they are.
#[test]
fn cstr_readers_copy_without_the_nul() {
    assert_eq!(cstr_opt(c"".as_ptr()), Some(Vec::new()));
    let raw = [0xffu8, b'/', 0x80, 0];
    assert_eq!(cstr_opt(raw.as_ptr().cast()), Some(vec![0xff, b'/', 0x80]));
    // The borrowed reader gives the same bytes as a view of C memory.
    let got = cstr_ref(raw.as_ptr().cast());
    assert_eq!(got, Some(&raw[..3]));
    assert_eq!(got.map(<[u8]>::as_ptr), Some(raw.as_ptr()));
    assert_eq!(cstr_ref(c"".as_ptr()), Some(&[][..]));
    assert_eq!(cstr_ref(std::ptr::null()), None);
    assert!(cstr_secret(std::ptr::null()).is_none());
    assert_eq!(
        cstr_secret(c"".as_ptr()).map(|z| z.len()),
        Some(0),
        "an empty secret is Some(empty), not None"
    );
    assert_eq!(&*c_bytes(b""), b"\0");
    assert_eq!(&*c_bytes(b"a\0b"), b"a\0b\0");
}

/// Rule: `write_out` and `read_struct` copy a whole `repr(C)`
/// struct through a raw pointer.
#[test]
fn write_out_and_read_struct_copy_structs() {
    let mut s = zkrs_stat::default();
    write_out(&raw mut s, ST);
    assert_eq!(cst(&read_struct(&raw const s)), cst(&ST));
    let mut ob = zkrs_outbox {
        r#impl: ptr::null_mut(),
    };
    let marker = ptr::NonNull::<u64>::dangling().as_ptr().cast::<c_void>();
    write_out(&raw mut ob, zkrs_outbox { r#impl: marker });
    assert_eq!(read_struct(&raw const ob).r#impl, marker);
}

/// Rule: `handle_arc` adds one strong reference for the
/// call, and `handle_release` gives back one reference that C holds.
#[test]
fn handle_conversions_balance_the_strong_count() {
    let _rec = standin::recorder();
    let h = super::super::handle::test_support::new_handle();
    let a = handle_arc(h);
    assert_eq!(Arc::strong_count(&a), 2);
    let b = handle_arc(h);
    assert_eq!(Arc::strong_count(&a), 3);
    drop(b);
    let again = handle_into_raw(Arc::clone(&a));
    assert_eq!(again, h);
    assert_eq!(Arc::strong_count(&a), 3);
    handle_release(again);
    assert_eq!(Arc::strong_count(&a), 2);
    drop(a);
    handle_release(h);
}

/// Rule: `outbox_into_impl` stores the box in `impl`,
/// `outbox_from_impl` borrows it, and `outbox_take` clears `impl` so that
/// the box has one owner. A NULL `impl` gives `None` in both readers.
#[test]
fn outbox_conversions_keep_one_owner() {
    let _rec = standin::recorder();
    let h = super::super::handle::test_support::new_handle();
    let mut ob = zkrs_outbox {
        r#impl: ptr::null_mut(),
    };
    assert!(outbox_from_impl(&raw mut ob).is_none());
    assert!(outbox_take(&raw mut ob).is_none());
    let inner = handle_arc(h);
    outbox_into_impl(&raw mut ob, Box::new(FfiOutbox::new(&inner)));
    assert!(!ob.r#impl.is_null());
    assert!(outbox_from_impl(&raw mut ob).is_some());
    let taken = outbox_take(&raw mut ob);
    assert!(taken.is_some());
    assert!(ob.r#impl.is_null());
    assert!(outbox_take(&raw mut ob).is_none());
    drop(taken);
    drop(inner);
    super::super::handle::zkrs_handle_release(h);
}
