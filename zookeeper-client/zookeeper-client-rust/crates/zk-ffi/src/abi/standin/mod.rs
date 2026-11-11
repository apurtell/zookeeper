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

//! A Rust stand-in for the C host vtable, for unit tests only.
//!
//! The entries record their calls in thread-local storage, because the
//! unit tests call the vtable on the test thread. [`recorder`] clears the
//! record and returns a guard that clears it again at the end of the
//! test. `resolve` gives the addresses that [`set_resolve`] stored.

#![allow(unsafe_code, reason = "the resolve stand-in calls the C callbacks")]

use std::cell::RefCell;
use std::ffi::{c_char, c_double, c_int, c_long, c_void};

use super::types::{zkrs_host_vtable, zkrs_sockaddr_view, zkrs_watcher};

/// The value of the `rng_random` stand-in.
pub(crate) const RANDOM: i64 = 4242;

/// The `fn` value of the default watcher that the stand-in gives.
pub(crate) const DEFAULT_WATCHER_FN: usize = 0x10;

#[derive(Default)]
struct Record {
    discarded: Vec<usize>,
    client_ids: Vec<(usize, i64, [u8; 16])>,
    reseeds: u32,
    resolve: (Vec<zkrs_sockaddr_view>, Vec<i32>, c_int, i32),
    resolved: Vec<(Vec<u8>, Vec<u8>)>,
}

thread_local! {
    static REC: RefCell<Record> = RefCell::new(Record::default());
}

/// Clears the record at creation and at drop.
pub(crate) struct Recorder;

impl Drop for Recorder {
    fn drop(&mut self) {
        REC.with(|r| *r.borrow_mut() = Record::default());
    }
}

/// Starts a test with an empty record.
pub(crate) fn recorder() -> Recorder {
    REC.with(|r| *r.borrow_mut() = Record::default());
    Recorder
}

/// The tokens that `discard_token` received, in order.
pub(crate) fn discarded() -> Vec<usize> {
    REC.with(|r| r.borrow().discarded.clone())
}

/// The `(host, id, passwd)` values that `store_client_id` received.
pub(crate) fn client_ids() -> Vec<(usize, i64, [u8; 16])> {
    REC.with(|r| r.borrow().client_ids.clone())
}

/// The number of `rng_reseed` calls.
pub(crate) fn reseeds() -> u32 {
    REC.with(|r| r.borrow().reseeds)
}

/// The `(name, port)` pairs that `resolve` received.
pub(crate) fn resolved() -> Vec<(Vec<u8>, Vec<u8>)> {
    REC.with(|r| r.borrow().resolved.clone())
}

/// Sets the next `resolve` results: addresses, skipped families, errno
/// and `gai_rc`.
pub(crate) fn set_resolve(addrs: Vec<zkrs_sockaddr_view>, skipped: Vec<i32>, err: c_int, gai: i32) {
    REC.with(|r| r.borrow_mut().resolve = (addrs, skipped, err, gai));
}

/// The stand-in vtable.
pub(crate) fn vtable() -> zkrs_host_vtable {
    zkrs_host_vtable {
        discard_token: Some(discard_token),
        snapshot_default_watcher: Some(snapshot_default_watcher),
        store_client_id: Some(store_client_id),
        log_enabled: Some(log_enabled),
        conn_permute_disabled: Some(conn_permute_disabled),
        rng_random: Some(rng_random),
        rng_drand48: Some(rng_drand48),
        rng_reseed: Some(rng_reseed),
        resolve: Some(resolve),
    }
}

/// Records the token.
pub(crate) extern "C" fn discard_token(token: usize) {
    REC.with(|r| r.borrow_mut().discarded.push(token));
}

extern "C" fn snapshot_default_watcher(host: usize, out: *mut zkrs_watcher) {
    let w = zkrs_watcher {
        r#fn: DEFAULT_WATCHER_FN,
        ctx: host,
    };
    // SAFETY: `vt_snapshot_default_watcher` passes a valid local.
    unsafe { out.write(w) };
}

extern "C" fn store_client_id(host: usize, id: i64, passwd: *const u8) {
    let mut p = [0u8; 16];
    // SAFETY: `vt_store_client_id` passes a 16-byte array.
    unsafe { std::ptr::copy_nonoverlapping(passwd, p.as_mut_ptr(), 16) };
    REC.with(|r| r.borrow_mut().client_ids.push((host, id, p)));
}

/// Levels up to WARN are enabled, as with the default `logLevel`.
extern "C" fn log_enabled(level: u32) -> c_int {
    c_int::from(level <= 2)
}

extern "C" fn conn_permute_disabled() -> c_int {
    1
}

extern "C" fn rng_random() -> c_long {
    c_long::try_from(RANDOM).unwrap_or(0)
}

extern "C" fn rng_drand48() -> c_double {
    0.5
}

extern "C" fn rng_reseed() {
    REC.with(|r| {
        let mut r = r.borrow_mut();
        r.reseeds = r.reseeds.saturating_add(1);
    });
}

fn cstr(p: *const c_char) -> Vec<u8> {
    // SAFETY: `vt_resolve` passes NUL-terminated strings.
    unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec()
}

extern "C" fn resolve(
    name: *const c_char,
    port: *const c_char,
    gai_rc: *mut i32,
    push: Option<unsafe extern "C" fn(sink: *mut c_void, addr: *const zkrs_sockaddr_view)>,
    skip: Option<unsafe extern "C" fn(sink: *mut c_void, family: i32)>,
    sink: *mut c_void,
) -> c_int {
    let (n, p) = (cstr(name), cstr(port));
    let (addrs, skipped, err, gai) = REC.with(|r| {
        let mut r = r.borrow_mut();
        r.resolved.push((n, p));
        r.resolve.clone()
    });
    for a in &addrs {
        if let Some(f) = push {
            // SAFETY: `push` is the zk-ffi callback for this `sink`.
            unsafe { f(sink, a) };
        }
    }
    for fam in skipped {
        if let Some(f) = skip {
            // SAFETY: `skip` is the zk-ffi callback for this `sink`.
            unsafe { f(sink, fam) };
        }
    }
    // SAFETY: `vt_resolve` passes a valid local.
    unsafe { gai_rc.write(gai) };
    err
}
