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

//! The result writers and the libc allocators.
//!
//! The writers build the legacy objects from a view in outbox storage,
//! or from a sync record image, into the destinations that C passes.
//! They write the public records through the mirrors in
//! [`super::super::legacy`]. Every allocation uses [`c_malloc`] or
//! [`c_calloc`], so the application `free()` and the jute `deallocate_*`
//! functions free the objects. A failed allocation aborts, because
//! legacy C does not check every allocation.
//!
//! The file depends only on `abi/types.rs`, `abi/legacy.rs`, `libc` and
//! `std`. A standalone harness, such as a fuzz target, can thus include
//! it by `#[path]`.

use std::ffi::{c_char, c_int};
use std::io::Write as _;
use std::mem::offset_of;
use std::ptr;

use super::super::legacy::{CAcl, CAclVector, CId, COpResult, CStat, CStringVector};
use super::super::types::{
    ZKRS_K_ACLLIST, ZKRS_K_DATA, ZKRS_K_MULTI, ZKRS_K_STAT, ZKRS_K_STRING, ZKRS_K_STRING_STAT,
    ZKRS_K_STRINGLIST, ZKRS_K_STRINGLIST_STAT, ZKRS_ORIGIN_TEARDOWN, zkrs_multi_copy,
    zkrs_result_dst, zkrs_result_view, zkrs_stat, zkrs_str, zkrs_sync_dst, zkrs_sync_src,
};

/// libc `malloc(n)`, also for `n == 0`.
///
/// NULL for a non-zero size aborts. For a zero size the libc
/// result stays as it is, as legacy keeps it.
pub(crate) fn c_malloc(n: usize) -> *mut u8 {
    // SAFETY: malloc has no precondition. The caller owns the result.
    let p = unsafe { libc::malloc(n) }.cast::<u8>();
    if p.is_null() && n != 0 {
        std::process::abort();
    }
    p
}

/// libc `calloc(count, size)`, also for `count == 0`.
///
/// `count == -1` gives NULL with no call, which is the result of the
/// legacy `calloc(-1, size)`. Any other negative count also gives NULL.
/// NULL for a non-zero size aborts.
pub(crate) fn c_calloc(count: i32, size: usize) -> *mut u8 {
    let Ok(n) = usize::try_from(count) else {
        return std::ptr::null_mut();
    };
    // SAFETY: calloc has no precondition and checks n * size itself.
    let p = unsafe { libc::calloc(n, size) }.cast::<u8>();
    if p.is_null() && n != 0 && size != 0 {
        std::process::abort();
    }
    p
}

/// Writes `s` into the `struct Stat` at `dst`, field by field.
///
/// `zkrs_stat` and `struct Stat` need not have the same layout.
/// The write goes through the [`CStat`] mirror.
pub(crate) fn write_stat(dst: *mut CStat, s: &zkrs_stat) {
    // The mirror gets each field by name, so a layout difference between
    // the two records changes nothing. A NULL destination gets no write.
    let c = CStat {
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
    };
    put(dst, c);
}

/// `zkrs_write_result`.
///
/// The function builds the objects of the view kind into the non-NULL
/// destinations:
///
/// - the `Stat`;
/// - the DATA buffer: `malloc(len)`, NULL for a null znode;
/// - the STRING copy: `malloc(len + 1)`;
/// - the vectors: `calloc(count, size)` and one `malloc(len + 1)` per
///   string. A count of -1 gives `data == NULL`;
/// - for MULTI into a sync record, one `zkrs_multi_copy` per op.
///
/// A MULTI view with `failed = 1` and `nops = 0` writes `*ops = NULL` and
/// `*nops = 0`.
pub(crate) fn write_result(v: *const zkrs_result_view, d: *const zkrs_result_dst) {
    let v = read_in(v, "zk-ffi: NULL zkrs_result_view");
    let d = read_in(d, "zk-ffi: NULL zkrs_result_dst");
    // A sync multi keeps the per-op copies for every result, so the
    // waiting thread can run the multi writers later.
    if v.kind == ZKRS_K_MULTI {
        put_multi_copies(&v, &d);
        return;
    }
    // A failed view has no body. The caller outputs stay as they are,
    // as in legacy C.
    if v.failed != 0 {
        return;
    }
    match v.kind {
        ZKRS_K_STAT => put_stat(&v, &d),
        ZKRS_K_DATA => {
            put_data(&v, &d);
            put_stat(&v, &d);
        }
        ZKRS_K_STRINGLIST => put_strings(&v, &d),
        ZKRS_K_STRINGLIST_STAT => {
            put_strings(&v, &d);
            put_stat(&v, &d);
        }
        ZKRS_K_ACLLIST => {
            put_acl(&v, &d);
            put_stat(&v, &d);
        }
        ZKRS_K_STRING => put_str(&v, &d),
        ZKRS_K_STRING_STAT => {
            put_str(&v, &d);
            put_stat(&v, &d);
        }
        // VOID has no object. An unknown kind also gets no write.
        _ => {}
    }
}

/// `zkrs_write_path`: `malloc(len + 1)` of the watcher
/// path, `""` for a session event. The result is never NULL.
pub(crate) fn write_path(s: *const zkrs_str) -> *mut c_char {
    // A NULL view and a jute null string both give "", because a watcher
    // always gets a valid string.
    if s.is_null() {
        return dup_str(&[]);
    }
    let s = read_in(s, "zk-ffi: NULL zkrs_str");
    dup_str(str_bytes(s.ptr, s.len).unwrap_or(&[]))
}

/// `zkrs_write_multi`.
///
/// The function runs the legacy `op_result_string_completion` and
/// `op_result_stat_completion` rules over the caller `results[count]`,
/// with the per-op kinds (`ZKRS_K_STRING`, `ZKRS_K_STAT`, else void).
/// A view with `failed = 1` and `nops = 0` gives `{err = rc}` to every
/// result and clears `value` or `stat` by kind.
pub(crate) fn write_multi(
    v: *const zkrs_result_view,
    results: *mut COpResult,
    kinds: *const u8,
    count: i32,
) {
    let v = read_in(v, "zk-ffi: NULL zkrs_result_view");
    let Some(n) = multi_len(results, kinds, count) else {
        return;
    };
    // Reply None (a header error or a teardown): the cleanup_failed_multi
    // rule fakes a failed sub-result for every op (zookeeper.c:3298-3306).
    if v.failed != 0 && v.nops <= 0 {
        fail_all(results, kinds, n, v.rc);
        return;
    }
    // The core gives at most `count` sub-results. The bound keeps a longer
    // view from a write past the caller array.
    for (i, o) in records(v.ops, v.nops).iter().take(n).enumerate() {
        let out = OpOut {
            err: o.err,
            failed: o.failed != 0,
            path: str_bytes(o.path.ptr, o.path.len),
            stat: opt_stat(o.stat),
        };
        write_op(results.wrapping_add(i), kind_at(kinds, i), &out);
    }
}

/// `zkrs_sync_copy_out`.
///
/// The function runs the legacy rc == 0 copy-out from the sync record
/// into the caller buffers on the waiting thread. It applies the
/// `buffer_len` truncation, the `path_buffer` NUL rule and the MULTI
/// rules of legacy C.
pub(crate) fn sync_copy_out(s: *const zkrs_sync_src, d: *const zkrs_sync_dst) {
    let s = read_in(s, "zk-ffi: NULL zkrs_sync_src");
    let d = read_in(d, "zk-ffi: NULL zkrs_sync_dst");
    // The multi per-op writers run for every rc, as legacy
    // deserialize_multi does (zookeeper.c:5529-5531).
    if s.kind == ZKRS_K_MULTI {
        sync_multi(&s, &d);
        return;
    }
    // Every other kind writes the caller buffers only for a decoded
    // reply with rc == ZOK (zookeeper.c:5420-5520).
    if s.rc != 0 || s.failed != 0 {
        return;
    }
    match s.kind {
        ZKRS_K_DATA => {
            sync_data(&s, &d);
            sync_stat(&s, &d);
        }
        ZKRS_K_STRING | ZKRS_K_STRING_STAT => {
            sync_path(&s, &d);
            sync_stat(&s, &d);
        }
        // The vectors go to the caller in C. Only the stat is copied here.
        ZKRS_K_STAT | ZKRS_K_STRINGLIST | ZKRS_K_STRINGLIST_STAT | ZKRS_K_ACLLIST => {
            sync_stat(&s, &d);
        }
        // VOID gives the rc only. An unknown kind also gets no write.
        _ => {}
    }
}

/// The values of one multi sub-result that the per-op writers use.
struct OpOut<'a> {
    /// The sub-op error.
    err: i32,
    /// The sub-result is an error result.
    failed: bool,
    /// The stripped path of a create. `None` is a NULL path.
    path: Option<&'a [u8]>,
    /// The stat of a set.
    stat: Option<zkrs_stat>,
}

/// Runs one legacy multi completion over `results[i]`.
///
/// STRING is `op_result_string_completion`, STAT is
/// `op_result_stat_completion` and every other kind is
/// `op_result_void_completion` (zookeeper.c:4792-4831). `valuelen`
/// never changes.
fn write_op(res: *mut COpResult, kind: u32, o: &OpOut<'_>) {
    put(field::<c_int>(res, offset_of!(COpResult, err)), o.err);
    match kind {
        ZKRS_K_STRING => {
            let value_at = field::<*mut c_char>(res, offset_of!(COpResult, value));
            // Legacy reads `value` at completion time. The application
            // can change it while the multi is pending.
            let value = get(value_at);
            match o.path {
                Some(p) if !value.is_null() && !o.failed => {
                    let cap = get(field::<c_int>(res, offset_of!(COpResult, valuelen)));
                    copy_c_string(value, cap, p);
                }
                _ => put(value_at, ptr::null_mut()),
            }
        }
        ZKRS_K_STAT => {
            let stat_at = field::<*mut CStat>(res, offset_of!(COpResult, stat));
            let st = get(stat_at);
            match o.stat {
                Some(s) if !st.is_null() && o.err == 0 && !o.failed => write_stat(st, &s),
                _ => put(stat_at, ptr::null_mut()),
            }
        }
        _ => {}
    }
}

/// Gives the failed sub-result `{err = rc}` to each of the `n` results.
fn fail_all(results: *mut COpResult, kinds: *const u8, n: usize, rc: i32) {
    let out = OpOut {
        err: rc,
        failed: true,
        path: None,
        stat: None,
    };
    for i in 0..n {
        write_op(results.wrapping_add(i), kind_at(kinds, i), &out);
    }
}

/// The number of caller results that the multi writers touch.
///
/// `None` means no write: no result or no array. Results with no kinds
/// break the contract of `zks_req_new_multi` and abort.
fn multi_len(results: *mut COpResult, kinds: *const u8, count: i32) -> Option<usize> {
    let n = usize::try_from(count).ok().filter(|&n| n != 0)?;
    if results.is_null() {
        return None;
    }
    if kinds.is_null() {
        fail("zk-ffi: NULL multi op kinds");
    }
    Some(n)
}

/// The writer kind of op `i`. The caller checks that `i < count`.
fn kind_at(kinds: *const u8, i: usize) -> u32 {
    // SAFETY: `kinds` holds one entry for each of the `count` ops of the
    // request, and the caller checks `i < count`.
    u32::from(unsafe { kinds.wrapping_add(i).read() })
}

/// The sync multi copy-out from the per-op copies.
fn sync_multi(s: &zkrs_sync_src, d: &zkrs_sync_dst) {
    let results = d.results.cast::<COpResult>();
    let Some(n) = multi_len(results, s.op_kind, d.count) else {
        return;
    };
    // A teardown and a header-only error have no copies. Every slot then
    // gets the rc, so the caller reads no stale slot. Legacy leaves
    // results[] untouched on a teardown, and
    // the spec section "Defined Results in Synchronous Multi-Operations"
    // replaces that rule.
    let teardown = u32::try_from(s.origin) == Ok(ZKRS_ORIGIN_TEARDOWN);
    if teardown || (s.failed != 0 && s.nops <= 0) {
        fail_all(results, s.op_kind, n, s.rc);
        return;
    }
    for (i, c) in records(s.ops, s.nops).iter().take(n).enumerate() {
        let out = OpOut {
            err: c.err,
            failed: c.failed != 0,
            path: str_bytes(c.path, c.path_len),
            stat: (c.has_stat != 0).then_some(c.stat),
        };
        write_op(results.wrapping_add(i), kind_at(s.op_kind, i), &out);
    }
}

/// The DATA copy-out (zookeeper.c:5429-5452).
///
/// `len = data_len <= cap ? data_len : cap` and `*buffer_len = len`.
/// The copy runs only when `len > 0` and the buffer is not NULL. So
/// `cap < -1` reports `cap` and copies nothing, where legacy calls
/// memcpy with a negative length.
fn sync_data(s: &zkrs_sync_src, d: &zkrs_sync_dst) {
    if d.buffer_len.is_null() {
        return;
    }
    let cap = get(d.buffer_len);
    let len = if s.data_len <= cap { s.data_len } else { cap };
    if !d.buffer.is_null() {
        let src = buf_bytes(s.data, s.data_len);
        if let (Ok(n), Some(b)) = (usize::try_from(len), src) {
            copy_to(d.buffer.cast::<u8>(), b.get(..n).unwrap_or(b));
        }
    }
    put(d.buffer_len, len);
}

/// The STRING copy-out (zookeeper.c:5486-5495, 5504-5512).
///
/// A NULL path in the record counts as `""`, where legacy calls strlen
/// on NULL.
fn sync_path(s: &zkrs_sync_src, d: &zkrs_sync_dst) {
    let p = str_bytes(s.path, s.path_len).unwrap_or(&[]);
    copy_c_string(d.path_buffer, d.path_buffer_len, p);
}

/// The stat copy-out: a struct assignment from the record, when both
/// sides are present.
fn sync_stat(s: &zkrs_sync_src, d: &zkrs_sync_dst) {
    if s.stat.is_null() {
        return;
    }
    let st = get(s.stat.cast::<CStat>());
    put(d.stat.cast::<CStat>(), st);
}

/// The legacy truncated string copy (zookeeper.c:4800-4808, 5486-5495).
///
/// `len = min(strlen(p) + 1, cap)`. When `len > 0`, `len - 1` bytes and
/// a NUL go to `dst`. A NULL `dst` gets nothing.
fn copy_c_string(dst: *mut c_char, cap: i32, p: &[u8]) {
    let n = p.iter().position(|&b| b == 0).unwrap_or(p.len());
    let want = i64::try_from(n).unwrap_or(i64::MAX).saturating_add(1);
    let len = want.min(i64::from(cap));
    if len <= 0 || dst.is_null() {
        return;
    }
    let Ok(k) = usize::try_from(len.saturating_sub(1)) else {
        return;
    };
    let d = dst.cast::<u8>();
    copy_to(d, p.get(..k).unwrap_or(p));
    // SAFETY: the caller buffer has `cap >= len = k + 1` writable bytes
    // (legacy contract), so offset `k` is in the buffer.
    unsafe { d.wrapping_add(k).write(0) };
}

/// Writes the DATA buffer and its length (recordio.c:240-260).
fn put_data(v: &zkrs_result_view, d: &zkrs_result_dst) {
    match buf_bytes(v.data.ptr, v.data.len) {
        None => {
            put(d.value, ptr::null_mut());
            put(d.value_len, -1);
        }
        Some(b) => {
            // Allocate only for a destination, so nothing leaks.
            if !d.value.is_null() {
                put(d.value, dup_bytes(b));
            }
            put(d.value_len, len_i32(b.len()));
        }
    }
}

/// Writes the STRING copy and its length.
fn put_str(v: &zkrs_result_view, d: &zkrs_result_dst) {
    let b = str_bytes(v.path.ptr, v.path.len);
    if !d.str.is_null() {
        put(d.str, opt_dup_str(b));
    }
    put(d.str_len, len_i32(b.map_or(0, <[u8]>::len)));
}

/// Writes the `Stat` of a decoded reply.
///
/// A view with no stat gives a zero `Stat`, so C never reads an
/// uninitialized record.
fn put_stat(v: &zkrs_result_view, d: &zkrs_result_dst) {
    let s = opt_stat(v.stat).unwrap_or_default();
    write_stat(d.stat.cast::<CStat>(), &s);
}

/// Writes a `String_vector` with the allocation layout of the generated
/// `deserialize_String_vector` (JRecord.java:203-214).
fn put_strings(v: &zkrs_result_view, d: &zkrs_result_dst) {
    if d.strings.is_null() {
        return;
    }
    let items = records(v.children, v.nchildren);
    let data = c_calloc(v.nchildren, size_of::<*mut c_char>()).cast::<*mut c_char>();
    for (i, s) in items.iter().enumerate() {
        put(data.wrapping_add(i), opt_dup_str(str_bytes(s.ptr, s.len)));
    }
    let sv = CStringVector {
        count: v.nchildren,
        data,
    };
    put(d.strings.cast::<CStringVector>(), sv);
}

/// Writes an `ACL_vector` with the layout of `deserialize_ACL_vector`.
fn put_acl(v: &zkrs_result_view, d: &zkrs_result_dst) {
    if d.acl.is_null() {
        return;
    }
    let items = records(v.acl, v.nacl);
    let data = c_calloc(v.nacl, size_of::<CAcl>()).cast::<CAcl>();
    for (i, a) in items.iter().enumerate() {
        let acl = CAcl {
            perms: a.perms,
            id: CId {
                scheme: opt_dup_str(str_bytes(a.scheme.ptr, a.scheme.len)),
                id: opt_dup_str(str_bytes(a.id.ptr, a.id.len)),
            },
        };
        put(data.wrapping_add(i), acl);
    }
    let av = CAclVector {
        count: v.nacl,
        data,
    };
    put(d.acl.cast::<CAclVector>(), av);
}

/// Writes the per-op copies of a MULTI view into a sync record.
///
/// The record needs both members. With only one of them the count or
/// the array is lost, so nothing is written.
fn put_multi_copies(v: &zkrs_result_view, d: &zkrs_result_dst) {
    if d.ops.is_null() || d.nops.is_null() {
        return;
    }
    let items = records(v.ops, v.nops);
    if items.is_empty() {
        put(d.ops, ptr::null_mut());
        put(d.nops, 0);
        return;
    }
    let ops = c_calloc(v.nops, size_of::<zkrs_multi_copy>()).cast::<zkrs_multi_copy>();
    for (i, o) in items.iter().enumerate() {
        let path = str_bytes(o.path.ptr, o.path.len);
        let stat = opt_stat(o.stat);
        let c = zkrs_multi_copy {
            err: o.err,
            failed: o.failed,
            path: opt_dup_str(path),
            path_len: len_i32(path.map_or(0, <[u8]>::len)),
            has_stat: u32::from(stat.is_some()),
            stat: stat.unwrap_or_default(),
        };
        put(ops.wrapping_add(i), c);
    }
    put(d.ops, ops);
    put(d.nops, v.nops);
}

/// The pointer to the field at byte offset `off` of `*res`. The
/// computation is safe. Only the access through it needs a valid `res`.
fn field<T>(res: *mut COpResult, off: usize) -> *mut T {
    res.wrapping_byte_add(off).cast::<T>()
}

/// Copies a stat view. NULL gives `None`.
fn opt_stat(p: *const zkrs_stat) -> Option<zkrs_stat> {
    if p.is_null() {
        return None;
    }
    Some(get(p))
}

/// The bytes of a string view. A NULL pointer is a jute null string
/// and gives `None`. A negative length counts as 0.
fn str_bytes<'a>(p: *const c_char, len: i32) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    Some(borrow(p, usize::try_from(len).unwrap_or(0)))
}

/// The bytes of a data view. A negative length is null znode data and
/// gives `None`. A zero length gives `&[]` for any pointer.
fn buf_bytes<'a>(p: *const c_char, len: i32) -> Option<&'a [u8]> {
    let n = usize::try_from(len).ok()?;
    if n == 0 {
        return Some(&[]);
    }
    if p.is_null() {
        return None;
    }
    Some(borrow(p, n))
}

/// Borrows `n` bytes at the non-NULL `p` for the writer call.
fn borrow<'a>(p: *const c_char, n: usize) -> &'a [u8] {
    if n == 0 {
        return &[];
    }
    // SAFETY: a view or a record image gives `n` readable bytes at the
    // non-NULL `p` until the writer returns. `n` comes
    // from an i32, so it is at most isize::MAX, and u8 has alignment 1.
    unsafe { std::slice::from_raw_parts(p.cast::<u8>(), n) }
}

/// Borrows a counted array of a view. `count <= 0` gives `&[]`.
///
/// NULL with `count > 0` breaks the view contract and aborts.
fn records<'a, T>(p: *const T, count: i32) -> &'a [T] {
    let Ok(n) = usize::try_from(count) else {
        return &[];
    };
    if n == 0 {
        return &[];
    }
    let fits = n
        .checked_mul(size_of::<T>())
        .is_some_and(|b| isize::try_from(b).is_ok());
    if p.is_null() || !fits {
        fail("zk-ffi: bad array in a result view");
    }
    // SAFETY: the view gives `count` initialized, aligned records at the
    // non-NULL `p` until the writer returns. The size fits in isize.
    unsafe { std::slice::from_raw_parts(p, n) }
}

/// `malloc(len)` and a copy of `b`, as `ia_deserialize_buffer` does.
fn dup_bytes(b: &[u8]) -> *mut c_char {
    let p = c_malloc(b.len());
    copy_to(p, b);
    p.cast::<c_char>()
}

/// `malloc(len + 1)`, a copy of `b` and a NUL, as
/// `ia_deserialize_string` does.
fn dup_str(b: &[u8]) -> *mut c_char {
    let Some(n) = b.len().checked_add(1) else {
        fail("zk-ffi: string too long");
    };
    let p = c_malloc(n);
    copy_to(p, b);
    // SAFETY: `p` has `len + 1` bytes, so offset `len` is in the block.
    unsafe { p.wrapping_add(b.len()).write(0) };
    p.cast::<c_char>()
}

/// [`dup_str`] for a present string. `None` gives NULL.
fn opt_dup_str(b: Option<&[u8]>) -> *mut c_char {
    b.map_or(ptr::null_mut(), dup_str)
}

/// Copies `b` to `dst`. An empty `b` makes no access, so `dst` can be
/// any value then.
fn copy_to(dst: *mut u8, b: &[u8]) {
    if b.is_empty() {
        return;
    }
    // SAFETY: the callers give `dst` with at least `b.len()` writable
    // bytes: a new block of that size, or a caller buffer whose legacy
    // capacity covers the copy. `dst` is not part of `b`.
    unsafe { ptr::copy_nonoverlapping(b.as_ptr(), dst, b.len()) };
}

/// A length that comes from an i32 view, back as an i32.
fn len_i32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// Reads a struct that C passes by pointer. NULL aborts, because the
/// ABI requires the pointer.
fn read_in<T: Copy>(p: *const T, msg: &str) -> T {
    if p.is_null() {
        fail(msg);
    }
    get(p)
}

/// Reads a value at a non-NULL C pointer.
fn get<T: Copy>(p: *const T) -> T {
    // SAFETY: every caller passes a non-NULL, aligned, initialized `T`
    // that C or the view gives for this call.
    unsafe { p.read() }
}

/// Writes `v` at a C destination. NULL means "no output".
fn put<T>(dst: *mut T, v: T) {
    if dst.is_null() {
        return;
    }
    // SAFETY: a non-NULL destination is a valid, aligned, writable `T`
    // for this call. The write makes no reference to C memory.
    unsafe { dst.write(v) };
}

/// Writes `msg` to stderr and aborts. A broken C contract ends here.
///
/// The writers do not use `entry::abort_with`. A standalone harness can
/// then include only this file and its two type files.
fn fail(msg: &str) -> ! {
    let mut e = std::io::stderr().lock();
    // The process aborts next, so a failed write changes nothing.
    let _ = writeln!(e, "{msg}");
    std::process::abort()
}
