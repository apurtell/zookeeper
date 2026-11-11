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

//! Safe interface to the C harness.
//!
//! The C harness has global state: value feeds, a log buffer, a resolver
//! record, an address vector and the watcher tables. A global lock guards
//! that state. [`with_c`] takes the lock and gives a [`CApi`] value to a
//! closure. Values that refer to C memory borrow the [`CApi`] value, so they
//! cannot leave the closure.

#![allow(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_ushort, c_void};
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;
use std::sync::{Mutex, PoisonError};

use crate::ffi;

static LOCK: Mutex<()> = Mutex::new(());

/// Runs a closure with exclusive access to the C harness.
///
/// A panic in an earlier holder of the lock does not block later callers.
pub fn with_c<R>(f: impl FnOnce(&CApi) -> R) -> R {
    let _guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    // SAFETY: The function has no preconditions.
    let native_signed = unsafe { ffi::zkx_char_is_signed() } != 0;
    let api = CApi {
        feeds: RefCell::new(Feeds::default()),
        zt_signed: Cell::new(native_signed),
        _not_send: PhantomData,
    };
    f(&api)
}

#[derive(Default)]
struct Feeds {
    random: Vec<c_long>,
    drand: Vec<f64>,
}

/// Access to the C harness while the global lock is held.
pub struct CApi {
    feeds: RefCell<Feeds>,
    /// The `char` signedness of the watcher table driver that the `zt_`
    /// methods use.
    zt_signed: Cell<bool>,
    _not_send: PhantomData<*const ()>,
}

/// The entry points of one copy of the watcher table driver.
struct ZtFns {
    reset: unsafe extern "C" fn(),
    set_default: unsafe extern "C" fn(c_int, usize),
    set_chroot: unsafe extern "C" fn(*const c_char),
    activate: unsafe extern "C" fn(c_int, *const c_char, c_int, usize),
    event: unsafe extern "C" fn(c_int, *const c_char) -> c_int,
    dlv_get: unsafe extern "C" fn(
        c_int,
        *mut c_int,
        *mut usize,
        *mut c_int,
        *mut *const c_char,
    ) -> c_int,
    has: unsafe extern "C" fn(*const c_char, c_int, c_int, usize) -> c_int,
    remove: unsafe extern "C" fn(*const c_char, c_int, c_int, usize),
    #[allow(clippy::type_complexity)]
    dump: unsafe extern "C" fn(
        c_int,
        *mut *const c_char,
        c_int,
        *mut c_int,
        *mut c_int,
        *mut c_int,
        *mut usize,
        c_int,
    ) -> c_int,
}

/// The driver copy that the build compiles with signed `char`.
const ZT_SIGNED: ZtFns = ZtFns {
    reset: ffi::zts::reset,
    set_default: ffi::zts::set_default,
    set_chroot: ffi::zts::set_chroot,
    activate: ffi::zts::activate,
    event: ffi::zts::event,
    dlv_get: ffi::zts::dlv_get,
    has: ffi::zts::has,
    remove: ffi::zts::remove,
    dump: ffi::zts::dump,
};

/// The driver copy that the build compiles with unsigned `char`.
const ZT_UNSIGNED: ZtFns = ZtFns {
    reset: ffi::ztu::reset,
    set_default: ffi::ztu::set_default,
    set_chroot: ffi::ztu::set_chroot,
    activate: ffi::ztu::activate,
    event: ffi::ztu::event,
    dlv_get: ffi::ztu::dlv_get,
    has: ffi::ztu::has,
    remove: ffi::ztu::remove,
    dump: ffi::ztu::dump,
};

impl Drop for CApi {
    fn drop(&mut self) {
        // SAFETY: A null feed with length 0 is valid. The C side then stops
        // reading the vectors that this value is about to release.
        unsafe { ffi::zkx_set_random_feed(ptr::null(), 0) };
        // SAFETY: As above, for the drand48() feed.
        unsafe { ffi::zkx_set_drand_feed(ptr::null(), 0) };
    }
}

/// One line of the C log buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    /// The level: `ERROR`, `WARN` or `INFO`.
    pub level: String,
    /// The format string of the log call.
    pub fmt: String,
    /// The formatted message.
    pub msg: Vec<u8>,
}

/// One watcher call that the C delivery made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The id of the watcher function, 0 to 3.
    pub func: i32,
    /// The watcher context.
    pub ctx: usize,
    /// The event type.
    pub event_type: i32,
    /// The path that the watcher got.
    pub path: Vec<u8>,
}

/// One path of a C watcher table with its watchers, head first.
pub type ZtEntry = (Vec<u8>, Vec<(i32, usize)>);

/// Makes a C string from bytes. The string ends at the first NUL, as C reads
/// it.
fn cstring(bytes: &[u8]) -> CString {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    CString::new(bytes.get(..end).unwrap_or_default()).unwrap_or_default()
}

/// Copies a C string. A null pointer gives an empty vector.
///
/// # Safety
///
/// `p` is null or points to a NUL-terminated string that stays valid during
/// the call.
unsafe fn copy_cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: The caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

fn to_c_int(v: usize) -> c_int {
    c_int::try_from(v).unwrap_or(c_int::MAX)
}

fn to_c_uint(v: usize) -> c_uint {
    c_uint::try_from(v).unwrap_or(c_uint::MAX)
}

fn decode_addr(family: c_int, ip: &[u8; 16], port: c_ushort) -> Option<SocketAddr> {
    match family {
        4 => {
            let v4 = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
            Some(SocketAddr::new(IpAddr::V4(v4), port))
        }
        6 => Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), port)),
        _ => None,
    }
}

/// A raw C hash table with C string keys and `int` values.
pub struct CHashTable<'a> {
    h: *mut c_void,
    _api: PhantomData<&'a CApi>,
}

impl Drop for CHashTable<'_> {
    fn drop(&mut self) {
        // SAFETY: `h` comes from zkx_ht_new() and is released only here.
        unsafe { ffi::zkx_ht_free(self.h) };
    }
}

impl CHashTable<'_> {
    /// Inserts a key and a value (`hashtable_insert`). Duplicates are allowed.
    pub fn insert(&mut self, key: &[u8], value: i32) -> bool {
        let k = cstring(key);
        // SAFETY: `h` is a live table and `k` is a valid C string.
        unsafe { ffi::zkx_ht_insert(self.h, k.as_ptr(), value) != 0 }
    }

    /// Finds the value of a key (`hashtable_search`).
    pub fn search(&self, key: &[u8]) -> Option<i32> {
        let k = cstring(key);
        let mut out: c_int = 0;
        // SAFETY: `h` is a live table, `k` is a valid C string and `out` is
        // a valid place for the result.
        let found = unsafe { ffi::zkx_ht_search(self.h, k.as_ptr(), &mut out) };
        (found != 0).then_some(out)
    }

    /// Removes the first entry of a key (`hashtable_remove`).
    pub fn remove(&mut self, key: &[u8]) -> Option<i32> {
        let k = cstring(key);
        let mut out: c_int = 0;
        // SAFETY: As for search().
        let found = unsafe { ffi::zkx_ht_remove(self.h, k.as_ptr(), &mut out) };
        (found != 0).then_some(out)
    }

    /// Returns the entry count.
    pub fn count(&self) -> u32 {
        // SAFETY: `h` is a live table.
        unsafe { ffi::zkx_ht_count(self.h) }
    }

    /// Returns the bucket count.
    pub fn table_length(&self) -> u32 {
        // SAFETY: `h` is a live table.
        unsafe { ffi::zkx_ht_table_length(self.h) }
    }

    /// Returns the load limit.
    pub fn load_limit(&self) -> u32 {
        // SAFETY: `h` is a live table.
        unsafe { ffi::zkx_ht_load_limit(self.h) }
    }

    /// Returns the mixed hash of a key.
    pub fn hash(&self, key: &[u8]) -> u32 {
        let k = cstring(key);
        // SAFETY: `h` is a live table and `k` is a valid C string.
        unsafe { ffi::zkx_ht_hash(self.h, k.as_ptr()) }
    }

    /// Lists the keys and values in C iteration order.
    pub fn dump(&self) -> Vec<(Vec<u8>, i32)> {
        let n = usize::try_from(self.count()).unwrap_or(0);
        let mut keys: Vec<*const c_char> = vec![ptr::null(); n];
        let mut vals: Vec<c_int> = vec![0; n];
        // SAFETY: Both buffers hold `n` items, and the cap is `n`.
        let got =
            unsafe { ffi::zkx_ht_dump(self.h, keys.as_mut_ptr(), vals.as_mut_ptr(), to_c_int(n)) };
        let got = usize::try_from(got).unwrap_or(0).min(n);
        keys.iter()
            .zip(vals.iter())
            .take(got)
            // SAFETY: Each key points into the live table, which does not
            // change during the copy.
            .map(|(&k, &v)| (unsafe { copy_cstr(k) }, v))
            .collect()
    }
}

impl CApi {
    /// Returns true when C `char` is signed on this target.
    pub fn char_is_signed(&self) -> bool {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_char_is_signed() != 0 }
    }

    /// Sets the values that C `random()` gives, and resets its call count.
    /// After the last value, `random()` gives 0.
    pub fn set_random_feed(&self, vals: &[i64]) {
        let v: Vec<c_long> = vals
            .iter()
            .map(|&x| c_long::try_from(x).unwrap_or(0))
            .collect();
        // SAFETY: The vector moves into `feeds` below without a change of its
        // heap buffer. It stays there until the next feed or the drop of
        // this value, and both reset the C pointer first.
        unsafe { ffi::zkx_set_random_feed(v.as_ptr(), v.len()) };
        self.feeds.borrow_mut().random = v;
    }

    /// Returns the number of `random()` calls since the last feed.
    pub fn random_calls(&self) -> usize {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_random_calls() }
    }

    /// Sets the values that C `drand48()` gives, and resets its call count.
    /// After the last value, `drand48()` gives 0.
    pub fn set_drand_feed(&self, vals: &[f64]) {
        let v = vals.to_vec();
        // SAFETY: As for set_random_feed().
        unsafe { ffi::zkx_set_drand_feed(v.as_ptr(), v.len()) };
        self.feeds.borrow_mut().drand = v;
    }

    /// Returns the number of `drand48()` calls since the last feed.
    pub fn drand_calls(&self) -> usize {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_drand_calls_get() }
    }

    /// Returns the number of `setup_random()` calls since the start.
    // C `long` is 32 bits on some targets, so the conversion is not always
    // the identity.
    #[allow(clippy::useless_conversion)]
    pub fn setup_random_count(&self) -> u64 {
        // SAFETY: The function has no preconditions.
        u64::from(unsafe { ffi::zkx_setup_random_count() })
    }

    /// Returns the number of `close_zsock()` calls since the start.
    // C `long` is 32 bits on some targets, so the conversion is not always
    // the identity.
    #[allow(clippy::useless_conversion)]
    pub fn close_count(&self) -> u64 {
        // SAFETY: The function has no preconditions.
        u64::from(unsafe { ffi::zkx_close_count() })
    }

    /// Empties the log buffer.
    pub fn log_clear(&self) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_log_clear() };
    }

    /// Returns the lines of the log buffer.
    pub fn logs(&self) -> Vec<LogLine> {
        // SAFETY: The function has no preconditions.
        let n = unsafe { ffi::zkx_log_count() };
        let mut out = Vec::new();
        for i in 0..n {
            let mut level: *const c_char = ptr::null();
            let mut fmt: *const c_char = ptr::null();
            let mut msg: *const c_char = ptr::null();
            // SAFETY: The three out pointers are valid places.
            let ok = unsafe { ffi::zkx_log_get(i, &mut level, &mut fmt, &mut msg) };
            if ok == 0 {
                break;
            }
            // SAFETY: The C side gives static or buffer strings that stay
            // valid while the lock is held.
            let level = unsafe { copy_cstr(level) };
            // SAFETY: As above.
            let fmt = unsafe { copy_cstr(fmt) };
            // SAFETY: As above.
            let msg = unsafe { copy_cstr(msg) };
            out.push(LogLine {
                level: String::from_utf8_lossy(&level).into_owned(),
                fmt: String::from_utf8_lossy(&fmt).into_owned(),
                msg,
            });
        }
        out
    }

    /// Empties the resolver record.
    pub fn gai_clear(&self) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_gai_clear() };
    }

    /// Returns the resolver calls: the host and the service of each call.
    pub fn gai_calls(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        // SAFETY: The function has no preconditions.
        let n = unsafe { ffi::zkx_gai_count() };
        let mut out = Vec::new();
        for i in 0..n {
            let mut host: *const c_char = ptr::null();
            let mut service: *const c_char = ptr::null();
            // SAFETY: The two out pointers are valid places.
            let ok = unsafe { ffi::zkx_gai_get(i, &mut host, &mut service) };
            if ok == 0 {
                break;
            }
            // SAFETY: The strings are in a static buffer.
            let host = unsafe { copy_cstr(host) };
            // SAFETY: As above.
            let service = unsafe { copy_cstr(service) };
            out.push((host, service));
        }
        out
    }

    /// Creates a raw C hash table. The hash function is `string_hash_djb2`
    /// compiled for signed or unsigned `char`.
    pub fn ht_new(&self, min_size: u32, c_char_signed: bool) -> Option<CHashTable<'_>> {
        // SAFETY: The function has no preconditions.
        let h = unsafe { ffi::zkx_ht_new(min_size, c_int::from(!c_char_signed)) };
        (!h.is_null()).then_some(CHashTable {
            h,
            _api: PhantomData,
        })
    }

    /// Computes `string_hash_djb2` for signed or unsigned `char`.
    pub fn djb2(&self, key: &[u8], c_char_signed: bool) -> u32 {
        let k = cstring(key);
        let p = k.as_ptr().cast_mut().cast::<c_void>();
        if c_char_signed {
            // SAFETY: `p` is a valid C string. The function only reads it.
            unsafe { ffi::zkx_djb2_signed(p) }
        } else {
            // SAFETY: As above.
            unsafe { ffi::zkx_djb2_unsigned(p) }
        }
    }

    /// Empties the C address vector (`addrvec_free`).
    pub fn av_clear(&self) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_av_clear() };
    }

    /// Appends an IPv4 address to the C address vector (`addrvec_append`).
    pub fn av_append(&self, ip: u32, port: u16) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_av_append(ip, port) };
    }

    /// Calls `addrvec_next`. A zeroed address gives `None`.
    pub fn av_next(&self) -> Option<(u32, u16)> {
        let mut ip: c_uint = 0;
        let mut port: c_ushort = 0;
        // SAFETY: The out pointers are valid places.
        let family = unsafe { ffi::zkx_av_next(&mut ip, &mut port) };
        (family != 0).then_some((ip, port))
    }

    /// Calls `addrvec_peek`. A zeroed address gives `None`.
    pub fn av_peek(&self) -> Option<(u32, u16)> {
        let mut ip: c_uint = 0;
        let mut port: c_ushort = 0;
        // SAFETY: The out pointers are valid places.
        let family = unsafe { ffi::zkx_av_peek(&mut ip, &mut port) };
        (family != 0).then_some((ip, port))
    }

    /// Calls `addrvec_hasnext`.
    pub fn av_has_next(&self) -> bool {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_av_hasnext() != 0 }
    }

    /// Calls `addrvec_atend`.
    pub fn av_at_end(&self) -> bool {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_av_atend() != 0 }
    }

    /// Returns the cursor of the C address vector.
    pub fn av_cursor(&self) -> u32 {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_av_cursor() }
    }

    /// Returns the items of the C address vector.
    pub fn av_items(&self) -> Vec<(u32, u16)> {
        // SAFETY: The function has no preconditions.
        let n = unsafe { ffi::zkx_av_count() };
        let mut out = Vec::new();
        for i in 0..n {
            let mut ip: c_uint = 0;
            let mut port: c_ushort = 0;
            // SAFETY: The out pointers are valid places.
            unsafe { ffi::zkx_av_get(i, &mut ip, &mut port) };
            out.push((ip, port));
        }
        out
    }

    /// Calls `addrvec_shuffle`, which draws from the `random()` feed.
    pub fn av_shuffle(&self) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_av_shuffle() };
    }

    /// Calls `addrvec_eq` on two lists of IPv4 addresses.
    pub fn av_eq(&self, a: &[(u32, u16)], b: &[(u32, u16)]) -> bool {
        let (a_ips, a_ports): (Vec<c_uint>, Vec<c_ushort>) = a.iter().copied().unzip();
        let (b_ips, b_ports): (Vec<c_uint>, Vec<c_ushort>) = b.iter().copied().unzip();
        // SAFETY: Each pointer refers to a buffer of the given length.
        unsafe {
            ffi::zkx_av_eq(
                a_ips.as_ptr(),
                a_ports.as_ptr(),
                to_c_uint(a.len()),
                b_ips.as_ptr(),
                b_ports.as_ptr(),
                to_c_uint(b.len()),
            ) != 0
        }
    }

    /// Selects the watcher table driver that the `zt_` methods use: the copy
    /// with signed or with unsigned C `char`.
    ///
    /// Each copy has its own tables. The default of each [`with_c`] call is
    /// the signedness of the target. Call [`CApi::zt_reset`] after a change.
    pub fn zt_select(&self, char_signed: bool) {
        self.zt_signed.set(char_signed);
    }

    /// Returns the `char` signedness of the selected watcher table driver.
    pub fn zt_char_signed(&self) -> bool {
        self.zt_signed.get()
    }

    fn zt(&self) -> &'static ZtFns {
        if self.zt_signed.get() {
            &ZT_SIGNED
        } else {
            &ZT_UNSIGNED
        }
    }

    /// Creates three empty C watcher tables and clears the default watcher,
    /// the chroot and the delivery record.
    pub fn zt_reset(&self) {
        // SAFETY: The function has no preconditions.
        unsafe { (self.zt().reset)() };
    }

    /// Sets the default watcher of the handle.
    pub fn zt_set_default(&self, func: i32, ctx: usize) {
        // SAFETY: The function has no preconditions.
        unsafe { (self.zt().set_default)(func, ctx) };
    }

    /// Sets the chroot of the handle that the delivery uses.
    pub fn zt_set_chroot(&self, chroot: Option<&[u8]>) {
        let c = chroot.map(cstring);
        let p = c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        // SAFETY: `p` is null or a valid C string. The C side copies it.
        unsafe { (self.zt().set_chroot)(p) };
    }

    /// Adds a watcher to a table (`activateWatcher`). The tables are 0 for
    /// data, 1 for exist and 2 for child.
    pub fn zt_activate(&self, table: i32, path: &[u8], func: i32, ctx: usize) {
        let p = cstring(path);
        // SAFETY: `p` is a valid C string. The C side copies it.
        unsafe { (self.zt().activate)(table, p.as_ptr(), func, ctx) };
    }

    /// Collects and delivers the watchers of an event (`collectWatchers` and
    /// `deliverWatchers`). Gives the watcher calls in order.
    pub fn zt_event(&self, event_type: i32, path: &[u8]) -> Vec<Delivery> {
        let p = cstring(path);
        let zt = self.zt();
        // SAFETY: `p` is a valid C string. The C side copies it.
        let n = unsafe { (zt.event)(event_type, p.as_ptr()) };
        let mut out = Vec::new();
        for i in 0..n {
            let mut func: c_int = 0;
            let mut ctx: usize = 0;
            let mut ty: c_int = 0;
            let mut path: *const c_char = ptr::null();
            // SAFETY: The out pointers are valid places.
            let ok = unsafe { (zt.dlv_get)(i, &mut func, &mut ctx, &mut ty, &mut path) };
            if ok == 0 {
                break;
            }
            // SAFETY: The path is in a static buffer.
            let path = unsafe { copy_cstr(path) };
            out.push(Delivery {
                func,
                ctx,
                event_type: ty,
                path,
            });
        }
        out
    }

    /// Calls `pathHasWatcher`. `None` stands for a NULL watcher.
    pub fn zt_has(&self, path: &[u8], wtype: i32, watcher: Option<(i32, usize)>) -> bool {
        let p = cstring(path);
        let (func, ctx) = watcher.unwrap_or((-1, 0));
        // SAFETY: `p` is a valid C string.
        unsafe { (self.zt().has)(p.as_ptr(), wtype, func, ctx) != 0 }
    }

    /// Calls `removeWatchers`. `None` stands for a NULL watcher.
    pub fn zt_remove(&self, path: &[u8], wtype: i32, watcher: Option<(i32, usize)>) {
        let p = cstring(path);
        let (func, ctx) = watcher.unwrap_or((-1, 0));
        // SAFETY: `p` is a valid C string.
        unsafe { (self.zt().remove)(p.as_ptr(), wtype, func, ctx) };
    }

    /// Lists a watcher table in C iteration order. Each list is head first.
    pub fn zt_dump(&self, table: i32) -> Vec<ZtEntry> {
        const CAP: usize = 4096;
        let mut keys: Vec<*const c_char> = vec![ptr::null(); CAP];
        let mut nkeys: c_int = 0;
        let mut key_idx: Vec<c_int> = vec![0; CAP];
        let mut funcs: Vec<c_int> = vec![0; CAP];
        let mut ctxs: Vec<usize> = vec![0; CAP];
        let zt = self.zt();
        // SAFETY: Each buffer holds CAP items, and both caps are CAP.
        let n = unsafe {
            (zt.dump)(
                table,
                keys.as_mut_ptr(),
                to_c_int(CAP),
                &mut nkeys,
                key_idx.as_mut_ptr(),
                funcs.as_mut_ptr(),
                ctxs.as_mut_ptr(),
                to_c_int(CAP),
            )
        };
        let nkeys = usize::try_from(nkeys).unwrap_or(0).min(CAP);
        let n = usize::try_from(n).unwrap_or(0).min(CAP);
        let mut out: Vec<ZtEntry> = keys
            .iter()
            .take(nkeys)
            // SAFETY: Each key points into a live table that does not change
            // during the copy.
            .map(|&k| (unsafe { copy_cstr(k) }, Vec::new()))
            .collect();
        for ((&k, &f), &c) in key_idx.iter().zip(funcs.iter()).zip(ctxs.iter()).take(n) {
            if let Some(entry) = usize::try_from(k).ok().and_then(|k| out.get_mut(k)) {
                entry.1.push((f, c));
            }
        }
        out
    }

    /// Calls `isValidPath`. The path ends at the first NUL, as C reads it.
    pub fn is_valid_path(&self, path: &[u8], mode: i32) -> bool {
        let p = cstring(path);
        // SAFETY: `p` is a valid C string.
        unsafe { ffi::zkx_is_valid_path(p.as_ptr(), mode) != 0 }
    }

    /// Evaluates `ZOOKEEPER_IS_SEQUENCE`.
    pub fn is_sequence(&self, mode: i32) -> bool {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_is_sequence(mode) != 0 }
    }

    /// Calls `count_hosts`.
    pub fn count_hosts(&self, hosts: &[u8]) -> i32 {
        let h = cstring(hosts);
        // SAFETY: `h` is a valid C string. The function only reads it.
        unsafe { ffi::zkx_count_hosts(h.as_ptr()) }
    }

    fn chroot_call(
        f: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char,
        chroot: Option<&[u8]>,
        path: &[u8],
    ) -> Vec<u8> {
        let c = chroot.map(cstring);
        let cp = c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let p = cstring(path);
        // SAFETY: `cp` is null or a valid C string, and `p` is a valid C
        // string. The result is a heap string or null.
        let r = unsafe { f(cp, p.as_ptr()) };
        // SAFETY: `r` is null or a valid heap string.
        let out = unsafe { copy_cstr(r) };
        // SAFETY: `r` comes from the C heap, and nothing else frees it.
        unsafe { ffi::zkx_free(r.cast::<c_void>()) };
        out
    }

    /// Calls `prepend_string` with the chroot.
    pub fn prepend(&self, chroot: Option<&[u8]>, path: &[u8]) -> Vec<u8> {
        Self::chroot_call(ffi::zkx_prepend, chroot, path)
    }

    /// Calls `sub_string` with the chroot.
    pub fn sub_string(&self, chroot: Option<&[u8]>, path: &[u8]) -> Vec<u8> {
        Self::chroot_call(ffi::zkx_sub_string, chroot, path)
    }

    /// Calls `strtol(s, &end, 0)` and gives the value and the offset of
    /// `end`.
    // C `long` is 32 bits on some targets, so the conversion is not always
    // the identity.
    #[allow(clippy::useless_conversion)]
    pub fn strtol0(&self, s: &[u8]) -> (i64, usize) {
        let c = cstring(s);
        let mut used: usize = 0;
        // SAFETY: `c` is a valid C string and `used` is a valid place.
        let v = unsafe { ffi::zkx_strtol0(c.as_ptr(), &mut used) };
        (i64::from(v), used)
    }

    /// Converts a C `long` to `int` as C does.
    pub fn long_to_int(&self, v: i64) -> i32 {
        let v = c_long::try_from(v).unwrap_or(0);
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_long_to_int(v) }
    }

    /// Calls `resolve_hosts` and gives the return code and the addresses.
    pub fn resolve(&self, hosts: &[u8], permute: bool) -> (i32, Vec<SocketAddr>) {
        let h = cstring(hosts);
        // SAFETY: `h` is a valid C string.
        let rc = unsafe { ffi::zkx_resolve(h.as_ptr(), c_int::from(permute)) };
        // SAFETY: The function has no preconditions.
        let n = unsafe { ffi::zkx_resolved_count() };
        let mut out = Vec::new();
        for i in 0..n {
            let mut ip = [0_u8; 16];
            let mut port: c_ushort = 0;
            // SAFETY: `ip` holds 16 bytes and `port` is a valid place.
            let family = unsafe { ffi::zkx_resolved_get(i, ip.as_mut_ptr(), &mut port) };
            if let Some(a) = decode_addr(family, &ip, port) {
                out.push(a);
            }
        }
        (rc, out)
    }

    /// Resets the handle that `update_addrs` uses.
    pub fn u_reset(&self) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_reset() };
    }

    /// Sets the socket state of the handle.
    pub fn u_set_connected(&self, connected: bool) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_set_connected(c_int::from(connected)) };
    }

    /// Returns true when the handle has an open socket.
    pub fn u_connected(&self) -> bool {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_connected() != 0 }
    }

    /// Sets the host list and calls `update_addrs`.
    pub fn u_update(&self, hosts: &[u8], permute: bool) -> i32 {
        let h = cstring(hosts);
        // SAFETY: `h` is a valid C string. The C side copies it.
        unsafe { ffi::zkx_u_update(h.as_ptr(), c_int::from(permute)) }
    }

    /// Calls `zoo_cycle_next_server`.
    pub fn u_cycle(&self) {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_cycle() };
    }

    /// Returns the `reconfig` field.
    pub fn u_reconfig(&self) -> bool {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_reconfig() != 0 }
    }

    /// Returns the `pOld` field.
    pub fn u_p_old(&self) -> f64 {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_p_old() }
    }

    /// Returns the `pNew` field.
    pub fn u_p_new(&self) -> f64 {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_p_new() }
    }

    /// Returns the `state` field.
    pub fn u_state(&self) -> i32 {
        // SAFETY: The function has no preconditions.
        unsafe { ffi::zkx_u_state() }
    }

    /// Returns a list of the handle and its cursor. The lists are 0 for
    /// `addrs`, 1 for `addrs_old` and 2 for `addrs_new`.
    pub fn u_vec(&self, which: i32) -> (Vec<SocketAddr>, u32) {
        // SAFETY: The function has no preconditions.
        let n = unsafe { ffi::zkx_u_vec_count(which) };
        let mut out = Vec::new();
        for i in 0..n {
            let mut ip = [0_u8; 16];
            let mut port: c_ushort = 0;
            // SAFETY: `ip` holds 16 bytes and `port` is a valid place.
            let family = unsafe { ffi::zkx_u_vec_get(which, i, ip.as_mut_ptr(), &mut port) };
            if let Some(a) = decode_addr(family, &ip, port) {
                out.push(a);
            }
        }
        // SAFETY: The function has no preconditions.
        let next = unsafe { ffi::zkx_u_vec_next(which) };
        (out, next)
    }

    /// Returns the `addr_cur` field. A zeroed address gives `None`.
    pub fn u_cur(&self) -> Option<SocketAddr> {
        let mut ip = [0_u8; 16];
        let mut port: c_ushort = 0;
        // SAFETY: `ip` holds 16 bytes and `port` is a valid place.
        let family = unsafe { ffi::zkx_u_cur(ip.as_mut_ptr(), &mut port) };
        decode_addr(family, &ip, port)
    }
}
