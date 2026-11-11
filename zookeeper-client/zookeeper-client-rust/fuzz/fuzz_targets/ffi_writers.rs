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

//! Checks the C result writers of zk-ffi under AddressSanitizer.
//!
//! The target decodes a random server reply for one result kind. It
//! stages the reply as a result view, the way the outbox of zk-ffi does.
//! Then it runs the writers into C destinations, and some destinations
//! are NULL. The writers are the async result writer, the multi writer,
//! the path writer and the sync copy-out. Each buffer has its exact size, so ASan finds a write
//! past its end. The target checks each value against the reply and
//! frees each allocation, so LeakSanitizer finds a lost allocation.
//!
//! The writers are zk-ffi code that the target includes by `#[path]`.
//! They and the checks read and write raw pointers, so this target is
//! the only one that allows unsafe code.

#![no_main]

#[path = "ffi/abi.rs"]
#[allow(dead_code, unreachable_pub, unused_imports)]
mod abi;

use std::ffi::{CStr, c_char};
use std::ptr;

use abi::legacy::{CAcl, CAclVector, COpResult, CStat, CStringVector};
use abi::raw::writers::{c_calloc, c_malloc, sync_copy_out, write_multi, write_path, write_result};
use abi::types::{
    ZKRS_K_ACLLIST, ZKRS_K_DATA, ZKRS_K_MULTI, ZKRS_K_STAT, ZKRS_K_STRING, ZKRS_K_STRING_STAT,
    ZKRS_K_STRINGLIST, ZKRS_K_STRINGLIST_STAT, ZKRS_K_VOID, ZKRS_ORIGIN_REPLY,
    ZKRS_ORIGIN_TEARDOWN, zkrs_acl_view, zkrs_buf, zkrs_multi_copy, zkrs_multi_op, zkrs_result_dst,
    zkrs_result_view, zkrs_stat, zkrs_str, zkrs_sync_dst, zkrs_sync_src,
};
use libfuzzer_sys::fuzz_target;
use zk_fuzz::Cursor;
use zk_jute::data::Stat;
use zk_jute::multi::{MultiBody, MultiItem, MultiKind, decode_multi};
use zk_jute::proto::{
    Create2Response, CreateResponse, ExistsResponse, GetACLResponse, GetChildren2Response,
    GetChildrenResponse, GetDataResponse,
};
use zk_jute::{JString, JVec, Reader, Record, opcode};

/// A marker for a destination that the writer must not touch.
const UNTOUCHED: i32 = i32::MIN;
/// The fill byte of a destination buffer.
const FILL: u8 = 0xA5;

/// One decoded reply. The variants match the replies of the outbox.
enum Reply {
    Void,
    Stat(Stat),
    Data(GetDataResponse),
    Children(GetChildrenResponse),
    Children2(GetChildren2Response),
    Acl(GetACLResponse),
    Path(CreateResponse),
    PathStat(Create2Response),
    Multi(Vec<MultiItem>),
}

/// Decodes a reply body for a result kind. `None` means no decoded body.
fn decode(kind: u32, body: &[u8], nops: usize) -> Option<Reply> {
    Some(match kind {
        ZKRS_K_VOID => Reply::Void,
        ZKRS_K_STAT => Reply::Stat(ExistsResponse::from_bytes(body).ok()?.stat),
        ZKRS_K_DATA => Reply::Data(GetDataResponse::from_bytes(body).ok()?),
        ZKRS_K_STRINGLIST => Reply::Children(GetChildrenResponse::from_bytes(body).ok()?),
        ZKRS_K_STRINGLIST_STAT => Reply::Children2(GetChildren2Response::from_bytes(body).ok()?),
        ZKRS_K_ACLLIST => Reply::Acl(GetACLResponse::from_bytes(body).ok()?),
        ZKRS_K_STRING => Reply::Path(CreateResponse::from_bytes(body).ok()?),
        ZKRS_K_STRING_STAT => Reply::PathStat(Create2Response::from_bytes(body).ok()?),
        ZKRS_K_MULTI => {
            Reply::Multi(decode_multi(&mut Reader::new(body), nops, MultiKind::Multi).ok()?)
        }
        _ => return None,
    })
}

fn stat_view(s: &Stat) -> zkrs_stat {
    zkrs_stat {
        czxid: s.czxid,
        mzxid: s.mzxid,
        ctime: s.ctime,
        mtime: s.mtime,
        version: s.version,
        cversion: s.cversion,
        aversion: s.aversion,
        ephemeralOwner: s.ephemeral_owner,
        dataLength: s.data_length,
        numChildren: s.num_children,
        pzxid: s.pzxid,
    }
}

fn cstat(s: &zkrs_stat) -> CStat {
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

/// A stat that no reply in the target has, to detect a missing write.
fn marker_stat() -> CStat {
    CStat {
        czxid: -0x5a5a,
        version: UNTOUCHED,
        ..CStat::default()
    }
}

fn len_i32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// The storage behind one result view, as the outbox keeps it.
#[derive(Default)]
struct Stage {
    strs: Vec<Box<[u8]>>,
    data: Option<Vec<u8>>,
    stats: Vec<zkrs_stat>,
    children: Vec<zkrs_str>,
    acl: Vec<zkrs_acl_view>,
    ops: Vec<zkrs_multi_op>,
}

impl Stage {
    /// Keeps a NUL-terminated copy and gives its view. The length does
    /// not count the NUL.
    fn jstr(&mut self, s: &JString) -> zkrs_str {
        let Some(b) = s.as_bytes() else {
            return zkrs_str::null();
        };
        let mut v = b.to_vec();
        v.push(0);
        self.strs.push(v.into_boxed_slice());
        let c = self.strs.last().expect("the copy is stored");
        zkrs_str {
            ptr: c.as_ptr().cast(),
            len: len_i32(b.len()),
        }
    }

    fn list(&mut self, c: &JVec<JString>) -> (*const zkrs_str, i32) {
        let Some(items) = c.as_slice() else {
            return (ptr::null(), -1);
        };
        for s in items {
            let v = self.jstr(s);
            self.children.push(v);
        }
        (self.children.as_ptr(), len_i32(self.children.len()))
    }

    /// Builds the view of a reply. Every pointer points into `self`.
    fn view(&mut self, kind: u32, origin: u32, rc: i32, reply: Option<&Reply>) -> zkrs_result_view {
        static EMPTY: u8 = 0;
        let mut v = zkrs_result_view {
            kind,
            origin,
            rc,
            failed: i32::from(reply.is_none()),
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
        };
        let Some(reply) = reply else {
            return v;
        };
        // The stats come first, so their addresses do not change later.
        match reply {
            Reply::Stat(s) => self.stats.push(stat_view(s)),
            Reply::Data(r) => self.stats.push(stat_view(&r.stat)),
            Reply::Children2(r) => self.stats.push(stat_view(&r.stat)),
            Reply::Acl(r) => self.stats.push(stat_view(&r.stat)),
            Reply::PathStat(r) => self.stats.push(stat_view(&r.stat)),
            Reply::Multi(items) => {
                for it in items {
                    if let MultiBody::SetData(r) = &it.body {
                        self.stats.push(stat_view(&r.stat));
                    }
                }
            }
            Reply::Void | Reply::Children(_) | Reply::Path(_) => {}
        }
        if !matches!(reply, Reply::Multi(_)) {
            v.stat = self.stats.first().map_or(ptr::null(), ptr::from_ref);
        }
        match reply {
            Reply::Data(r) => {
                if let Some(b) = r.data.as_bytes() {
                    let d = self.data.insert(b.to_vec());
                    v.data = zkrs_buf {
                        ptr: if d.is_empty() {
                            ptr::from_ref(&EMPTY)
                        } else {
                            d.as_ptr()
                        }
                        .cast(),
                        len: len_i32(d.len()),
                    };
                }
            }
            Reply::Path(r) => v.path = self.jstr(&r.path),
            Reply::PathStat(r) => v.path = self.jstr(&r.path),
            Reply::Children(r) => (v.children, v.nchildren) = self.list(&r.children),
            Reply::Children2(r) => (v.children, v.nchildren) = self.list(&r.children),
            Reply::Acl(r) => {
                if let Some(items) = r.acl.as_slice() {
                    for e in items {
                        let scheme = self.jstr(&e.id.scheme);
                        let id = self.jstr(&e.id.id);
                        self.acl.push(zkrs_acl_view {
                            perms: e.perms,
                            scheme,
                            id,
                        });
                    }
                    (v.acl, v.nacl) = (self.acl.as_ptr(), len_i32(self.acl.len()));
                } else {
                    (v.acl, v.nacl) = (ptr::null(), -1);
                }
            }
            Reply::Multi(items) => {
                let mut next_stat = 0usize;
                for it in items {
                    let (err, path, stat) = match &it.body {
                        MultiBody::Error(e) => (e.err, zkrs_str::null(), ptr::null()),
                        MultiBody::Create(r) => (it.err, self.jstr(&r.path), ptr::null()),
                        MultiBody::Create2(r) => (it.err, self.jstr(&r.path), ptr::null()),
                        MultiBody::SetData(_) => {
                            let p = ptr::from_ref(&self.stats[next_stat]);
                            next_stat += 1;
                            (it.err, zkrs_str::null(), p)
                        }
                        _ => (it.err, zkrs_str::null(), ptr::null()),
                    };
                    self.ops.push(zkrs_multi_op {
                        err,
                        failed: i32::from(it.wire_type == opcode::ERROR),
                        path,
                        stat,
                    });
                }
                (v.ops, v.nops) = (self.ops.as_ptr(), len_i32(self.ops.len()));
            }
            Reply::Void | Reply::Stat(_) => {}
        }
        v
    }
}

/// Gives the bytes of a view string, or `None` for NULL.
fn view_bytes<'a>(s: zkrs_str) -> Option<&'a [u8]> {
    if s.ptr.is_null() {
        return None;
    }
    let n = usize::try_from(s.len).expect("a view length is not negative");
    Some(unsafe { std::slice::from_raw_parts(s.ptr.cast::<u8>(), n) })
}

/// Checks a C string that a writer made and frees it.
fn take_c_string(p: *mut c_char, want: Option<&[u8]>) {
    match want {
        None => assert!(p.is_null(), "a NULL string became a copy"),
        Some(w) => {
            assert!(!p.is_null(), "a string copy is NULL");
            let got = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), w.len() + 1) };
            assert_eq!(&got[..w.len()], w, "a string copy differs");
            assert_eq!(got[w.len()], 0, "a string copy has no NUL");
            unsafe { libc::free(p.cast()) };
        }
    }
}

/// The C buffers of one `write_result` call. Each member starts with a
/// marker, so the checks see which members the writer set.
struct Dst {
    stat: CStat,
    value: *mut c_char,
    value_len: i32,
    strings: CStringVector,
    acl: CAclVector,
    str: *mut c_char,
    str_len: i32,
    ops: *mut zkrs_multi_copy,
    nops: i32,
}

impl Dst {
    fn new() -> Self {
        Self {
            stat: marker_stat(),
            value: ptr::null_mut(),
            value_len: UNTOUCHED,
            strings: CStringVector {
                count: UNTOUCHED,
                data: ptr::null_mut(),
            },
            acl: CAclVector {
                count: UNTOUCHED,
                data: ptr::null_mut(),
            },
            str: ptr::null_mut(),
            str_len: UNTOUCHED,
            ops: ptr::null_mut(),
            nops: UNTOUCHED,
        }
    }
}

/// The NULL members of a destination, one bit for each member.
#[derive(Clone, Copy)]
struct Nulls(u16);

impl Nulls {
    fn has(self, bit: u16) -> bool {
        self.0 & (1 << bit) != 0
    }
}

fn opt<T>(p: *mut T, null: bool) -> *mut T {
    if null { ptr::null_mut() } else { p }
}

/// Runs the async result writer and checks each member.
fn check_write_result(v: &zkrs_result_view, reply: Option<&Reply>, nulls: Nulls, d: &mut Dst) {
    let cd = zkrs_result_dst {
        stat: opt(ptr::from_mut(&mut d.stat).cast(), nulls.has(0)),
        value: opt(&raw mut d.value, nulls.has(1)),
        value_len: opt(&raw mut d.value_len, nulls.has(2)),
        strings: opt(ptr::from_mut(&mut d.strings).cast(), nulls.has(3)),
        acl: opt(ptr::from_mut(&mut d.acl).cast(), nulls.has(4)),
        str: opt(&raw mut d.str, nulls.has(5)),
        str_len: opt(&raw mut d.str_len, nulls.has(6)),
        ops: opt(&raw mut d.ops, nulls.has(7)),
        nops: opt(&raw mut d.nops, nulls.has(8)),
    };
    write_result(v, &cd);

    let untouched = |d: &Dst, multi: bool| {
        assert_eq!(d.stat, marker_stat(), "the stat changed");
        assert!(
            d.value.is_null() && d.value_len == UNTOUCHED,
            "the value changed"
        );
        assert_eq!(d.strings.count, UNTOUCHED, "the strings changed");
        assert_eq!(d.acl.count, UNTOUCHED, "the ACL changed");
        assert!(
            d.str.is_null() && d.str_len == UNTOUCHED,
            "the string changed"
        );
        if !multi {
            assert!(
                d.ops.is_null() && d.nops == UNTOUCHED,
                "the multi copies changed"
            );
        }
    };

    if v.kind == ZKRS_K_MULTI {
        untouched(d, true);
        if cd.ops.is_null() || cd.nops.is_null() {
            assert!(
                d.ops.is_null() && d.nops == UNTOUCHED,
                "a NULL destination got copies"
            );
            return;
        }
        let ops: &[zkrs_multi_op] = if v.nops > 0 {
            unsafe { std::slice::from_raw_parts(v.ops, v.nops as usize) }
        } else {
            &[]
        };
        if ops.is_empty() {
            assert!(d.ops.is_null() && d.nops == 0, "an empty multi has copies");
            return;
        }
        assert_eq!(d.nops, v.nops, "the copy count differs");
        assert!(!d.ops.is_null(), "the copies are NULL");
        let copies = unsafe { std::slice::from_raw_parts(d.ops, ops.len()) };
        for (o, c) in ops.iter().zip(copies) {
            assert_eq!(
                (c.err, c.failed),
                (o.err, o.failed),
                "the copy result differs"
            );
            let p = view_bytes(o.path);
            assert_eq!(
                c.path_len,
                p.map_or(0, |b| len_i32(b.len())),
                "the copy path length differs"
            );
            if let Some(b) = p {
                let got = unsafe { std::slice::from_raw_parts(c.path.cast::<u8>(), b.len() + 1) };
                assert_eq!(&got[..b.len()], b, "the copy path differs");
                assert_eq!(got[b.len()], 0);
            } else {
                assert!(c.path.is_null(), "a NULL path became a copy");
            }
            let stat = (!o.stat.is_null()).then(|| unsafe { *o.stat });
            assert_eq!(c.has_stat, u32::from(stat.is_some()));
            assert_eq!(c.stat, stat.unwrap_or_default(), "the copy stat differs");
        }
        return;
    }
    if v.failed != 0 {
        untouched(d, false);
        return;
    }
    let reply = reply.expect("a result that did not fail has a reply");
    let want_stat = if !v.stat.is_null() {
        unsafe { *v.stat }
    } else {
        Default::default()
    };
    let stat_kinds = [
        ZKRS_K_STAT,
        ZKRS_K_DATA,
        ZKRS_K_STRINGLIST_STAT,
        ZKRS_K_ACLLIST,
        ZKRS_K_STRING_STAT,
    ];
    if stat_kinds.contains(&v.kind) && !cd.stat.is_null() {
        assert_eq!(d.stat, cstat(&want_stat), "the stat differs");
    } else {
        assert_eq!(d.stat, marker_stat(), "the stat changed");
    }
    match reply {
        Reply::Data(r) => match r.data.as_bytes() {
            None => {
                assert!(d.value.is_null());
                if !cd.value_len.is_null() {
                    assert_eq!(d.value_len, -1, "null data has the length -1");
                }
            }
            Some(b) => {
                if !cd.value_len.is_null() {
                    assert_eq!(d.value_len, len_i32(b.len()));
                }
                if !cd.value.is_null() {
                    assert!(!d.value.is_null() || b.is_empty(), "the data copy is NULL");
                    if !b.is_empty() {
                        let got =
                            unsafe { std::slice::from_raw_parts(d.value.cast::<u8>(), b.len()) };
                        assert_eq!(got, b, "the data copy differs");
                    }
                }
            }
        },
        Reply::Children(_) | Reply::Children2(_) => {
            if cd.strings.is_null() {
                assert_eq!(d.strings.count, UNTOUCHED);
            } else {
                assert_eq!(d.strings.count, v.nchildren);
                let n = usize::try_from(v.nchildren).unwrap_or(0);
                if n > 0 {
                    assert!(!d.strings.data.is_null());
                }
            }
        }
        Reply::Acl(_) => {
            if cd.acl.is_null() {
                assert_eq!(d.acl.count, UNTOUCHED);
            } else {
                assert_eq!(d.acl.count, v.nacl);
                if v.nacl > 0 {
                    assert!(!d.acl.data.is_null());
                }
            }
        }
        Reply::Path(_) | Reply::PathStat(_) => {
            if !cd.str_len.is_null() {
                assert_eq!(
                    d.str_len,
                    view_bytes(v.path).map_or(0, |b| len_i32(b.len()))
                );
            }
        }
        Reply::Void | Reply::Stat(_) | Reply::Multi(_) => {}
    }
}

/// Frees what `write_result` made, and checks the lists on the way.
fn free_result(v: &zkrs_result_view, d: &mut Dst) {
    if !d.value.is_null() {
        unsafe { libc::free(d.value.cast()) };
        d.value = ptr::null_mut();
    }
    if d.strings.count != UNTOUCHED {
        let views: &[zkrs_str] = if v.nchildren > 0 {
            unsafe { std::slice::from_raw_parts(v.children, v.nchildren as usize) }
        } else {
            &[]
        };
        for (i, s) in views.iter().enumerate() {
            take_c_string(unsafe { *d.strings.data.add(i) }, view_bytes(*s));
        }
        unsafe { libc::free(d.strings.data.cast()) };
        d.strings = CStringVector {
            count: UNTOUCHED,
            data: ptr::null_mut(),
        };
    }
    if d.acl.count != UNTOUCHED {
        let views: &[zkrs_acl_view] = if v.nacl > 0 {
            unsafe { std::slice::from_raw_parts(v.acl, v.nacl as usize) }
        } else {
            &[]
        };
        for (i, a) in views.iter().enumerate() {
            let c: CAcl = unsafe { *d.acl.data.add(i) };
            assert_eq!(c.perms, a.perms, "the ACL perms differ");
            take_c_string(c.id.scheme, view_bytes(a.scheme));
            take_c_string(c.id.id, view_bytes(a.id));
        }
        unsafe { libc::free(d.acl.data.cast()) };
        d.acl = CAclVector {
            count: UNTOUCHED,
            data: ptr::null_mut(),
        };
    }
    if !d.str.is_null() || d.str_len != UNTOUCHED {
        take_c_string(
            d.str,
            if d.str.is_null() {
                None
            } else {
                view_bytes(v.path)
            },
        );
        d.str = ptr::null_mut();
    }
    if !d.ops.is_null() {
        let n = usize::try_from(d.nops).unwrap_or(0);
        for i in 0..n {
            let c = unsafe { *d.ops.add(i) };
            if !c.path.is_null() {
                unsafe { libc::free(c.path.cast()) };
            }
        }
        unsafe { libc::free(d.ops.cast()) };
        d.ops = ptr::null_mut();
    }
}

/// One result slot of a multi call, with its own buffers.
struct Slot {
    kind: u8,
    cap: i32,
    value: *mut c_char,
    stat: *mut CStat,
}

impl Slot {
    fn read(c: &mut Cursor<'_>) -> Self {
        let kind = match c.u8() % 4 {
            0 => ZKRS_K_STRING as u8,
            1 => ZKRS_K_STAT as u8,
            2 => ZKRS_K_VOID as u8,
            _ => c.u8(),
        };
        let cap = i32::from(c.u8() % 40) - 4;
        let flags = c.u8();
        // The buffer has exactly `cap` bytes, so ASan finds an overrun.
        let value = if flags & 1 == 0 {
            let n = usize::try_from(cap).unwrap_or(0).max(1);
            let p = c_malloc(n);
            unsafe { ptr::write_bytes(p, FILL, n) };
            p.cast::<c_char>()
        } else {
            ptr::null_mut()
        };
        let stat = if flags & 2 == 0 {
            Box::into_raw(Box::new(marker_stat()))
        } else {
            ptr::null_mut()
        };
        Self {
            kind,
            cap,
            value,
            stat,
        }
    }

    fn result(&self) -> COpResult {
        COpResult {
            err: UNTOUCHED,
            value: self.value,
            valuelen: self.cap,
            stat: self.stat,
        }
    }

    fn free(&self) {
        if !self.value.is_null() {
            unsafe { libc::free(self.value.cast()) };
        }
        if !self.stat.is_null() {
            drop(unsafe { Box::from_raw(self.stat) });
        }
    }
}

/// What a multi writer must write into one slot.
struct OpWant<'a> {
    err: i32,
    failed: bool,
    path: Option<&'a [u8]>,
    stat: Option<zkrs_stat>,
}

/// Checks one slot after a multi writer ran.
fn check_slot(s: &Slot, r: &COpResult, want: Option<&OpWant<'_>>) {
    let Some(w) = want else {
        assert_eq!(r.err, UNTOUCHED, "a slot past the results changed");
        assert_eq!(
            (r.value, r.stat),
            (s.value, s.stat),
            "a slot past the results changed"
        );
        return;
    };
    assert_eq!(r.err, w.err, "the slot error differs");
    match u32::from(s.kind) {
        ZKRS_K_STRING => match w.path {
            Some(p) if !s.value.is_null() && !w.failed => {
                assert_eq!(r.value, s.value);
                // The C rule: copy min(strlen + 1, cap) bytes, the last a NUL.
                let n = p.iter().position(|&b| b == 0).unwrap_or(p.len());
                let len = i64::try_from(n).expect("a short path") + 1;
                let len = len.min(i64::from(s.cap));
                let cap = usize::try_from(s.cap).unwrap_or(0);
                let buf = unsafe { std::slice::from_raw_parts(s.value.cast::<u8>(), cap) };
                if len > 0 {
                    let k = usize::try_from(len - 1).expect("a positive length");
                    assert_eq!(&buf[..k], &p[..k], "the slot path differs");
                    assert_eq!(buf[k], 0, "the slot path has no NUL");
                    assert!(
                        buf[k + 1..].iter().all(|&b| b == FILL),
                        "the slot path wrote too far"
                    );
                } else {
                    assert!(buf.iter().all(|&b| b == FILL), "a zero-size slot changed");
                }
            }
            _ => assert!(r.value.is_null(), "a slot without a path keeps its buffer"),
        },
        ZKRS_K_STAT => match w.stat {
            Some(st) if !s.stat.is_null() && w.err == 0 && !w.failed => {
                assert_eq!(r.stat, s.stat);
                assert_eq!(unsafe { *s.stat }, cstat(&st), "the slot stat differs");
            }
            _ => assert!(r.stat.is_null(), "a slot without a stat keeps its stat"),
        },
        _ => assert_eq!((r.value, r.stat), (s.value, s.stat), "a plain slot changed"),
    }
    if !s.stat.is_null() && r.stat.is_null() {
        assert_eq!(
            unsafe { *s.stat },
            marker_stat(),
            "a dropped stat was written"
        );
    }
}

/// Reads the slots of a multi call.
fn read_slots(c: &mut Cursor<'_>) -> Vec<Slot> {
    let n = usize::from(c.u8() % 10);
    (0..n).map(|_| Slot::read(c)).collect()
}

/// Runs the multi writer of the async path and checks the slots.
fn check_write_multi(v: &zkrs_result_view, slots: &[Slot], null_results: bool) {
    let mut results: Vec<COpResult> = slots.iter().map(Slot::result).collect();
    let kinds: Vec<u8> = slots.iter().map(|s| s.kind).collect();
    let count = len_i32(slots.len());
    let rp = if null_results {
        ptr::null_mut()
    } else {
        results.as_mut_ptr()
    };
    write_multi(v, rp, kinds.as_ptr(), count);
    let ops: &[zkrs_multi_op] = if v.nops > 0 {
        unsafe { std::slice::from_raw_parts(v.ops, v.nops as usize) }
    } else {
        &[]
    };
    for (i, (s, r)) in slots.iter().zip(&results).enumerate() {
        let want = if null_results {
            None
        } else if v.failed != 0 && v.nops <= 0 {
            Some(OpWant {
                err: v.rc,
                failed: true,
                path: None,
                stat: None,
            })
        } else {
            ops.get(i).map(|o| OpWant {
                err: o.err,
                failed: o.failed != 0,
                path: view_bytes(o.path),
                stat: (!o.stat.is_null()).then(|| unsafe { *o.stat }),
            })
        };
        check_slot(s, r, want.as_ref());
    }
}

/// Runs the sync copy-out with the outputs of `write_result` as the
/// record, as the sync wrapper of the shim does, and checks it.
fn check_sync(c: &mut Cursor<'_>, v: &zkrs_result_view, d: &Dst, slots: &[Slot]) {
    let flags = c.u8();
    let cap = i32::from(c.u16() % 300) - 2;
    let pcap = i32::from(c.u8()) - 2;
    let rc = if flags & 1 == 0 { 0 } else { c.i32() };

    let st = if d.stat == marker_stat() {
        CStat::default()
    } else {
        d.stat
    };
    let (data, data_len) = if d.value_len == UNTOUCHED {
        (ptr::null(), 0)
    } else {
        (d.value.cast_const(), d.value_len)
    };
    let (path, path_len) = if d.str_len == UNTOUCHED {
        (ptr::null(), 0)
    } else {
        (d.str.cast_const(), d.str_len)
    };
    let (ops, nops) = if d.nops == UNTOUCHED {
        (ptr::null(), 0)
    } else {
        (d.ops.cast_const(), d.nops)
    };
    let kinds: Vec<u8> = slots.iter().map(|s| s.kind).collect();
    let src = zkrs_sync_src {
        kind: v.kind,
        rc,
        failed: v.failed,
        origin: i32::try_from(v.origin).unwrap_or(0),
        data,
        data_len,
        path,
        path_len,
        stat: ptr::from_ref(&st).cast(),
        ops,
        nops,
        op_kind: kinds.as_ptr(),
    };

    let bn = usize::try_from(cap).unwrap_or(0).max(1);
    let buffer = if flags & 2 == 0 {
        c_malloc(bn)
    } else {
        ptr::null_mut()
    };
    if !buffer.is_null() {
        unsafe { ptr::write_bytes(buffer, FILL, bn) };
    }
    let mut buffer_len = cap;
    let pn = usize::try_from(pcap).unwrap_or(0).max(1);
    let path_buffer = if flags & 4 == 0 {
        c_malloc(pn)
    } else {
        ptr::null_mut()
    };
    if !path_buffer.is_null() {
        unsafe { ptr::write_bytes(path_buffer, FILL, pn) };
    }
    let mut out_stat = marker_stat();
    let mut results: Vec<COpResult> = slots.iter().map(Slot::result).collect();
    let dst = zkrs_sync_dst {
        buffer: buffer.cast(),
        buffer_len: opt(&raw mut buffer_len, flags & 8 != 0),
        path_buffer: path_buffer.cast(),
        path_buffer_len: pcap,
        stat: opt(ptr::from_mut(&mut out_stat).cast(), flags & 16 != 0),
        results: if flags & 32 == 0 {
            results.as_mut_ptr().cast()
        } else {
            ptr::null_mut()
        },
        count: len_i32(slots.len()),
    };
    sync_copy_out(&src, &dst);

    let stat_written = !dst.stat.is_null();
    if v.kind == ZKRS_K_MULTI {
        let copies: &[zkrs_multi_copy] = if nops > 0 {
            unsafe { std::slice::from_raw_parts(ops, nops as usize) }
        } else {
            &[]
        };
        let teardown = src.origin == ZKRS_ORIGIN_TEARDOWN as i32;
        for (i, (s, r)) in slots.iter().zip(&results).enumerate() {
            let want = if dst.results.is_null() {
                None
            } else if teardown || (src.failed != 0 && nops <= 0) {
                Some(OpWant {
                    err: rc,
                    failed: true,
                    path: None,
                    stat: None,
                })
            } else {
                copies.get(i).map(|o| OpWant {
                    err: o.err,
                    failed: o.failed != 0,
                    path: (!o.path.is_null()).then(|| unsafe {
                        std::slice::from_raw_parts(
                            o.path.cast::<u8>(),
                            usize::try_from(o.path_len).unwrap_or(0),
                        )
                    }),
                    stat: (o.has_stat != 0).then_some(o.stat),
                })
            };
            check_slot(s, r, want.as_ref());
        }
        assert_eq!(out_stat, marker_stat(), "a multi copy-out wrote the stat");
    } else if rc != 0 || src.failed != 0 || v.kind == ZKRS_K_VOID || v.kind > ZKRS_K_STRING_STAT {
        assert_eq!(out_stat, marker_stat(), "a failed copy-out wrote the stat");
        assert_eq!(buffer_len, cap, "a failed copy-out wrote the length");
    } else {
        if stat_written {
            assert_eq!(out_stat, st, "the copy-out stat differs");
        }
        if v.kind == ZKRS_K_DATA && !dst.buffer_len.is_null() {
            let len = data_len.min(cap);
            assert_eq!(buffer_len, len, "the copy-out length differs");
            if !buffer.is_null() && !data.is_null() {
                let n = usize::try_from(len).unwrap_or(0);
                let got = unsafe { std::slice::from_raw_parts(buffer, bn) };
                let want = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), n) };
                assert_eq!(&got[..n], want, "the copy-out data differs");
                assert!(
                    got[n..].iter().all(|&b| b == FILL),
                    "the copy-out wrote too far"
                );
            }
        }
        if (v.kind == ZKRS_K_STRING || v.kind == ZKRS_K_STRING_STAT) && !path_buffer.is_null() {
            let p: &[u8] = if path.is_null() {
                &[]
            } else {
                unsafe { CStr::from_ptr(path) }.to_bytes()
            };
            let got = unsafe { std::slice::from_raw_parts(path_buffer, pn) };
            let len = (i64::try_from(p.len()).expect("a short path") + 1).min(i64::from(pcap));
            if len > 0 {
                let k = usize::try_from(len - 1).expect("a positive length");
                assert_eq!(&got[..k], &p[..k], "the copy-out path differs");
                assert_eq!(got[k], 0, "the copy-out path has no NUL");
                assert!(
                    got[k + 1..].iter().all(|&b| b == FILL),
                    "the copy-out path wrote too far"
                );
            } else {
                assert!(
                    got.iter().all(|&b| b == FILL),
                    "a zero-size path buffer changed"
                );
            }
        }
    }
    for p in [buffer, path_buffer] {
        if !p.is_null() {
            unsafe { libc::free(p.cast()) };
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let kind = u32::from(c.u8() % 9);
    let origin = if c.bool() {
        ZKRS_ORIGIN_TEARDOWN
    } else {
        ZKRS_ORIGIN_REPLY
    };
    let rc = c.i32();
    let nulls = Nulls(c.u16());
    let nops = usize::from(c.u8() % 8);
    let body = c.lp();

    let reply = decode(kind, body, nops);
    let mut stage = Stage::default();
    let v = stage.view(kind, origin, rc, reply.as_ref());

    let mut d = Dst::new();
    check_write_result(&v, reply.as_ref(), nulls, &mut d);

    // The multi writer of the async path takes the view.
    let slots = read_slots(&mut c);
    if kind == ZKRS_K_MULTI {
        check_write_multi(&v, &slots, nulls.has(9));
    }

    // The sync copy-out takes the outputs of the result writer.
    let slots2 = read_slots(&mut c);
    check_sync(&mut c, &v, &d, &slots2);

    free_result(&v, &mut d);
    for s in slots.iter().chain(&slots2) {
        s.free();
    }

    // The path writer of the watch events.
    let p = c.lp();
    let out = if nulls.has(10) {
        write_path(ptr::null())
    } else {
        let s = zkrs_str {
            ptr: p.as_ptr().cast(),
            len: len_i32(p.len()),
        };
        write_path(&s)
    };
    take_c_string(out, Some(if nulls.has(10) { &[] } else { p }));

    // A negative count gives no allocation.
    assert!(c_calloc(-1, 8).is_null());
});
