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

//! The audited raw boundary.
//!
//! Every conversion between C memory and Rust goes through this module.
//! No other module of zk-ffi calls `slice::from_raw_parts`,
//! `CStr::from_ptr`, `Box::from_raw` or a vtable function pointer. Each
//! `unsafe` block has one unsafe operation and a `SAFETY` comment.
//!
//! The signatures are safe. The private ABI is the contract: C passes
//! valid pointers for one call, and C holds a strong handle reference at
//! entry. A NULL pointer where the ABI requires one aborts the process.
//!
//! Inputs are copied into owned buffers. Outputs are raw pointer writes.
//! The module never makes a `&mut` to C memory, because the application
//! can alias it.
//!
//! This module holds the readers, the handle and outbox conversions and
//! the vtable wrappers. The result writers are in [`writers`].

pub(crate) mod writers;

use std::ffi::{CStr, c_char, c_void};
use std::net::SocketAddr;
use std::slice;
use std::sync::Arc;

use zeroize::Zeroizing;
use zk_driver::Unlocked;
use zk_proto::SecretBytes;

use super::entry::{abort_with, ffi_guard};
use super::handle::Inner;
use super::outbox::FfiOutbox;
use super::types::{
    zkrs_bytes, zkrs_handle, zkrs_host_vtable, zkrs_outbox, zkrs_sockaddr_view, zkrs_watcher,
};

/// A C input that breaks a legacy rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawError {
    /// A NULL pointer with a non-zero length.
    NullData,
    /// A value buffer with `len < -1`, or NULL with `len > 0`.
    BadValue,
    /// A length that no Rust slice can hold.
    TooLong,
}

/// Reads `len` bytes at `p` as a borrowed slice.
///
/// `len == 0` gives `&[]` for any `p`. A NULL `p` with `len > 0` gives
/// [`RawError::NullData`], and the caller applies the legacy rule. The
/// caller copies the bytes before the call returns.
pub(crate) fn bytes<'a>(p: *const u8, len: usize) -> Result<&'a [u8], RawError> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(RawError::NullData);
    }
    if isize::try_from(len).is_err() {
        return Err(RawError::TooLong);
    }
    // SAFETY: C gives `len` readable bytes at the non-NULL `p` for this
    // call. `len` is at most isize::MAX, and u8 has alignment 1.
    Ok(unsafe { slice::from_raw_parts(p, len) })
}

/// Reads a legacy `(ptr, i32)` value buffer as a borrowed slice.
///
/// -1 gives `None` and ignores the pointer. 0 gives an empty buffer.
/// A positive length gives a view of the bytes. `len < -1`, or NULL with
/// `len > 0`, gives [`RawError::BadValue`], which becomes an
/// `InputDefect`.
///
/// The caller encodes the bytes into an owned request frame before the
/// call returns. No view of the bytes outlives the call.
pub(crate) fn value_ref<'a>(p: *const c_char, len: i32) -> Result<Option<&'a [u8]>, RawError> {
    match len {
        -1 => Ok(None),
        0 => Ok(Some(&[])),
        n if n < -1 => Err(RawError::BadValue),
        n => {
            let n = usize::try_from(n).map_err(|_| RawError::BadValue)?;
            match bytes(p.cast::<u8>(), n) {
                Ok(b) => Ok(Some(b)),
                Err(_) => Err(RawError::BadValue),
            }
        }
    }
}

/// Copies a NUL-terminated C string without the NUL. NULL gives `None`.
pub(crate) fn cstr_opt(p: *const c_char) -> Option<Vec<u8>> {
    cstr_ref(p).map(<[u8]>::to_vec)
}

/// Reads a NUL-terminated C string without the NUL as a borrowed slice.
/// NULL gives `None`.
///
/// The caller encodes the bytes into an owned request frame before the
/// call returns. No view of the bytes outlives the call.
pub(crate) fn cstr_ref<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a non-NULL string argument of the private ABI is
    // NUL-terminated and readable for this call.
    let s = unsafe { CStr::from_ptr(p) };
    Some(s.to_bytes())
}

/// Copies a NUL-terminated secret straight into zeroizing storage.
///
/// The TLS passphrase uses it. `to_vec` allocates the exact
/// size once, so no other copy of the secret stays in memory.
#[cfg_attr(
    not(feature = "tls"),
    allow(dead_code, reason = "only a TLS build reads a passphrase")
)]
pub(crate) fn cstr_secret(p: *const c_char) -> Option<Zeroizing<Vec<u8>>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: as in `cstr_opt`.
    let s = unsafe { CStr::from_ptr(p) };
    Some(Zeroizing::new(s.to_bytes().to_vec()))
}

/// Copies a `zkrs_bytes` view from C, such as a Cyrus output.
///
/// `is_null` gives `None`. A view with `is_null` and a non-zero length
/// or a non-NULL pointer, a length above `0x7fffffff`, or NULL with a
/// non-zero length gives an error. The copy goes into zeroizing storage.
pub(crate) fn view_bytes(v: &zkrs_bytes) -> Result<Option<SecretBytes>, RawError> {
    if v.is_null != 0 {
        if v.len != 0 || !v.p.is_null() {
            return Err(RawError::BadValue);
        }
        return Ok(None);
    }
    if v.len > 0x7fff_ffff {
        return Err(RawError::TooLong);
    }
    let n = usize::try_from(v.len).map_err(|_| RawError::TooLong)?;
    let b = bytes(v.p, n)?;
    Ok(Some(SecretBytes::new(b.to_vec())))
}

/// Reads a counted array of `repr(C)` records.
///
/// `count <= 0` gives `&[]`. NULL with `count > 0` gives
/// [`RawError::NullData`]. The caller copies what it keeps.
pub(crate) fn array<'a, T>(p: *const T, count: i32) -> Result<&'a [T], RawError> {
    let n = array_len(p, count)?;
    if n == 0 {
        return Ok(&[]);
    }
    // SAFETY: C gives `count` initialized, aligned records at the
    // non-NULL `p` for this call. The size fits in isize.
    Ok(unsafe { slice::from_raw_parts(p, n) })
}

/// Checks a counted array of `repr(C)` records and gives its length.
///
/// The function makes no reference to the records. Thus it also accepts
/// records that are only partly initialized, such as a `zoo_op_t` whose
/// union holds only the member of its type. The errors are those of
/// [`array`].
pub(crate) fn array_len<T>(p: *const T, count: i32) -> Result<usize, RawError> {
    let Ok(n) = usize::try_from(count) else {
        return Ok(0);
    };
    if n == 0 {
        return Ok(0);
    }
    if p.is_null() {
        return Err(RawError::NullData);
    }
    let fits = n
        .checked_mul(size_of::<T>())
        .is_some_and(|b| isize::try_from(b).is_ok());
    if !fits {
        return Err(RawError::TooLong);
    }
    Ok(n)
}

/// Makes an owned, NUL-terminated copy of `b` for a string that C reads
/// (log arguments, `zkrs_str` views, paths).
pub(crate) fn c_bytes(b: &[u8]) -> Box<[u8]> {
    let mut v = Vec::with_capacity(b.len().saturating_add(1));
    v.extend_from_slice(b);
    v.push(0);
    v.into_boxed_slice()
}

/// Turns the handle pointer from C into a new strong reference.
///
/// The function increments the strong count of the `Arc` that
/// `zkrs_handle_new` gave out, then rebuilds an `Arc` from it. The C
/// caller holds a strong reference at entry. NULL aborts.
pub(crate) fn handle_arc(p: *const zkrs_handle) -> Arc<Inner> {
    let p = p.cast::<Inner>();
    if p.is_null() {
        abort_with("zk-ffi: NULL zkrs_handle");
    }
    // SAFETY: `p` comes from `Arc::into_raw` in `handle_into_raw`, and
    // the C caller holds a strong reference, so the count is > 0.
    unsafe { Arc::increment_strong_count(p) };
    // SAFETY: the increment above gives this `Arc` its own reference.
    unsafe { Arc::from_raw(p) }
}

/// Gives the strong reference of `h` to C as a handle pointer.
pub(crate) fn handle_into_raw(h: Arc<Inner>) -> *const zkrs_handle {
    Arc::into_raw(h).cast::<zkrs_handle>()
}

/// Gives back one strong reference that C holds.
///
/// `zkrs_handle_release` and `zkrs_handle_abandon` use it.
/// NULL aborts.
pub(crate) fn handle_release(p: *const zkrs_handle) {
    let p = p.cast::<Inner>();
    if p.is_null() {
        abort_with("zk-ffi: NULL zkrs_handle");
    }
    // SAFETY: `p` comes from `handle_into_raw`, and the caller gives up
    // one strong reference that it holds.
    unsafe { Arc::decrement_strong_count(p) };
}

/// Stores the outbox in `ob->impl`.
///
/// The pointer comes from `Box::into_raw`. No integer-to-pointer cast
/// occurs. NULL `ob` aborts.
pub(crate) fn outbox_into_impl(ob: *mut zkrs_outbox, b: Box<FfiOutbox>) {
    let p = Box::into_raw(b).cast::<c_void>();
    write_out(ob, zkrs_outbox { r#impl: p });
}

/// Takes the outbox out of `ob->impl` and sets `impl` to NULL.
///
/// NULL `impl` gives `None`. The caller owns the box and stores it again
/// with [`outbox_into_impl`], or drops it.
pub(crate) fn outbox_take(ob: *mut zkrs_outbox) -> Option<Box<FfiOutbox>> {
    let cur = read_struct(ob.cast_const());
    let p = cur.r#impl.cast::<FfiOutbox>();
    if p.is_null() {
        return None;
    }
    write_out(
        ob,
        zkrs_outbox {
            r#impl: std::ptr::null_mut(),
        },
    );
    // SAFETY: a non-NULL `impl` comes only from `outbox_into_impl`, and
    // the write above clears it, so this box has one owner.
    Some(unsafe { Box::from_raw(p) })
}

/// Borrows the outbox in `ob->impl` for one call on that outbox.
///
/// NULL `impl` gives `None`. The C thread that made the call is the only
/// one that drains it, so no other reference exists.
pub(crate) fn outbox_from_impl<'a>(ob: *mut zkrs_outbox) -> Option<&'a mut FfiOutbox> {
    let cur = read_struct(ob.cast_const());
    let p = cur.r#impl.cast::<FfiOutbox>();
    // SAFETY: a non-NULL `impl` comes from `outbox_into_impl`. One C
    // thread uses `ob` at a time, so the borrow is unique for the call.
    unsafe { p.as_mut() }
}

/// Writes `v` through the C out-parameter `dst`.
///
/// It is a raw pointer write, never a `&mut` to C memory. NULL aborts,
/// because the ABI states every out-parameter that Rust writes.
pub(crate) fn write_out<T: Copy>(dst: *mut T, v: T) {
    if dst.is_null() {
        abort_with("zk-ffi: NULL out-parameter");
    }
    // SAFETY: C gives a valid, aligned, writable `T` for this call.
    unsafe { dst.write(v) };
}

/// Reads a `repr(C)` struct that C passes by pointer into a copy.
///
/// The pointers inside the copy go through the readers above. NULL
/// aborts.
pub(crate) fn read_struct<T: Copy>(p: *const T) -> T {
    if p.is_null() {
        abort_with("zk-ffi: NULL input struct");
    }
    // SAFETY: C gives a valid, aligned, initialized `T` for this call.
    unsafe { p.read() }
}

/// The addresses and skipped families of one `resolve` call.
#[derive(Debug, Default)]
pub(crate) struct HostAddrs {
    /// The AF_INET and AF_INET6 results, in order, duplicates included.
    pub(crate) addrs: Vec<SocketAddr>,
    /// The raw `ai_family` of every other result, in order.
    pub(crate) skipped_families: Vec<i32>,
}

/// Aborts for a NULL vtable entry. C fills every entry.
fn missing(entry: &str) -> ! {
    abort_with(&format!("zk-ffi: missing host vtable entry {entry}"))
}

/// Calls a `discard_token` function. [`super::tokens::CReq`] keeps the
/// function, so its `Drop` needs no vtable.
pub(crate) fn vt_discard_token_fn(f: unsafe extern "C" fn(usize), token: usize) {
    // SAFETY: `f` is the Pure `discard_token` entry of the vtable that C
    // gave at `zkrs_handle_new`. It takes any token of this
    // handle once.
    unsafe { f(token) }
}

/// Pure: frees a token without a callback.
#[cfg(test)]
pub(crate) fn vt_discard_token(vt: &zkrs_host_vtable, token: usize) {
    let Some(f) = vt.discard_token else {
        missing("discard_token")
    };
    vt_discard_token_fn(f, token);
}

/// Pure: reads the default watcher pair.
pub(crate) fn vt_snapshot_default_watcher(vt: &zkrs_host_vtable, host: usize) -> zkrs_watcher {
    let Some(f) = vt.snapshot_default_watcher else {
        missing("snapshot_default_watcher")
    };
    let mut w = zkrs_watcher::default();
    // SAFETY: the Pure entry writes one `zkrs_watcher` to `out`, which
    // is a valid local, and reads only the handle of `host`.
    unsafe { f(host, &raw mut w) };
    w
}

/// Pure: stores the session id and password in `zh->client_id`.
pub(crate) fn vt_store_client_id(vt: &zkrs_host_vtable, host: usize, id: i64, passwd: &[u8; 16]) {
    let Some(f) = vt.store_client_id else {
        missing("store_client_id")
    };
    // SAFETY: the Pure entry reads 16 bytes at `passwd`, which is a
    // valid array for the call.
    unsafe { f(host, id, passwd.as_ptr()) };
}

/// Pure: the `logLevel` rule of the legacy macros.
pub(crate) fn vt_log_enabled(vt: &zkrs_host_vtable, level: u32) -> bool {
    let Some(f) = vt.log_enabled else {
        missing("log_enabled")
    };
    // SAFETY: the Pure entry reads only the exported logLevel.
    unsafe { f(level) != 0 }
}

/// Pure: `zoo_deterministic_conn_order`.
pub(crate) fn vt_conn_permute_disabled(vt: &zkrs_host_vtable) -> bool {
    let Some(f) = vt.conn_permute_disabled else {
        missing("conn_permute_disabled")
    };
    // SAFETY: the Pure entry reads one C global.
    unsafe { f() != 0 }
}

/// Pure: libc `random()`. The drop-in keeps the global libc PRNG of
/// legacy C.
pub(crate) fn vt_rng_random(vt: &zkrs_host_vtable) -> i64 {
    let Some(f) = vt.rng_random else {
        missing("rng_random")
    };
    // SAFETY: the Pure entry calls libc random().
    let r = unsafe { f() };
    #[allow(clippy::useless_conversion, reason = "c_long is i32 on Windows")]
    i64::from(r)
}

/// Pure: libc `drand48()`.
pub(crate) fn vt_rng_drand48(vt: &zkrs_host_vtable) -> f64 {
    let Some(f) = vt.rng_drand48 else {
        missing("rng_drand48")
    };
    // SAFETY: the Pure entry calls libc drand48().
    unsafe { f() }
}

/// Blocking: the legacy reseed. The proof shows that no lock is held.
pub(crate) fn vt_rng_reseed(vt: &zkrs_host_vtable, _u: &Unlocked) {
    let Some(f) = vt.rng_reseed else {
        missing("rng_reseed")
    };
    // SAFETY: the Blocking entry reads /dev/urandom and seeds libc. No
    // Rust lock is held (the proof).
    unsafe { f() };
}

/// Blocking: `getaddrinfo` for one host entry. The caller holds no Rust
/// lock.
///
/// The results go to `out` through [`resolve_push`] and [`resolve_skip`].
/// It returns `(errno, gai_rc)`.
pub(crate) fn vt_resolve(
    vt: &zkrs_host_vtable,
    _u: &Unlocked,
    name: &CStr,
    port: &CStr,
    out: &mut HostAddrs,
) -> (i32, i32) {
    let Some(f) = vt.resolve else {
        missing("resolve")
    };
    let mut gai_rc: i32 = 0;
    let sink = std::ptr::from_mut(out).cast::<c_void>();
    // SAFETY: the Blocking entry reads the two strings, writes `gai_rc`
    // and calls `push` and `skip` with `sink` until it returns. `out` is
    // not used until then. No Rust lock is held (the proof).
    let err = unsafe {
        f(
            name.as_ptr(),
            port.as_ptr(),
            &raw mut gai_rc,
            Some(resolve_push),
            Some(resolve_skip),
            sink,
        )
    };
    (err, gai_rc)
}

/// Turns the `sink` of a resolve callback back into the [`HostAddrs`]
/// that [`vt_resolve`] passed.
pub(crate) fn sink_from_ptr<'a>(sink: *mut c_void) -> &'a mut HostAddrs {
    let p = sink.cast::<HostAddrs>();
    if p.is_null() {
        abort_with("zk-ffi: NULL resolve sink");
    }
    // SAFETY: `sink` is the `&mut HostAddrs` of the live `vt_resolve`
    // frame. That frame does not use it until `resolve` returns.
    unsafe { &mut *p }
}

/// The `push` callback of `resolve`: one AF_INET or AF_INET6 result.
///
/// cbindgen:ignore
extern "C" fn resolve_push(sink: *mut c_void, addr: *const zkrs_sockaddr_view) {
    ffi_guard(|| {
        let v = read_struct(addr);
        if let Some(a) = v.to_addr() {
            sink_from_ptr(sink).addrs.push(a);
        }
    });
}

/// The `skip` callback of `resolve`: one result of another family.
///
/// cbindgen:ignore
extern "C" fn resolve_skip(sink: *mut c_void, family: i32) {
    ffi_guard(|| sink_from_ptr(sink).skipped_families.push(family));
}

#[cfg(test)]
pub(crate) mod tests;
