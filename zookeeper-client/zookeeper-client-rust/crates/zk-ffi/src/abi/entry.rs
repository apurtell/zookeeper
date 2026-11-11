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

//! The frame of every export.
//!
//! Each `zkrs_*` body runs inside [`ffi_guard`]. A panic never crosses
//! the C boundary: the guard catches it and aborts the process.
//! [`with_handle`] adds the handle reference and the lock proof.

use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use zk_driver::Unlocked;

use super::handle::Inner;
use super::raw;
use super::types::zkrs_handle;

/// Runs `f` and aborts the process if `f` panics.
///
/// Every export calls it, so no Rust frame unwinds into C.
pub(crate) fn ffi_guard<R>(f: impl FnOnce() -> R) -> R {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => abort_with("zk-ffi: panic at the C boundary"),
    }
}

/// Runs `f` with a strong reference to the handle and the lock proof.
///
/// The C caller holds a strong reference at entry.
/// [`raw::handle_arc`] makes a second one for the call, so the handle
/// stays alive even when `f` runs the final close.
pub(crate) fn with_handle<R>(
    p: *const zkrs_handle,
    f: impl FnOnce(&Arc<Inner>, &mut Unlocked) -> R,
) -> R {
    ffi_guard(|| {
        let h = raw::handle_arc(p);
        let mut u = Unlocked::new_at_entry();
        f(&h, &mut u)
    })
}

/// Writes `msg` to stderr and aborts the process.
///
/// The boundary uses it for broken C contracts: a NULL pointer where the
/// ABI requires one, a missing vtable entry, or a host value of 0 after
/// release.
pub(crate) fn abort_with(msg: &str) -> ! {
    let mut e = std::io::stderr().lock();
    // The process aborts next, so a failed write changes nothing.
    let _ = writeln!(e, "{msg}");
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_guard_returns_the_value() {
        assert_eq!(ffi_guard(|| 7), 7);
    }
}
