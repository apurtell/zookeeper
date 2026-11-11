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

//! The handle registry of the debug builds.
//!
//! A debug build of the shim adds each new handle to a set of live
//! handles, and removes the handle when it closes. Each entry point then
//! checks its handle. A handle that is not in the set shows a use after
//! close or a double close, so the check stops the process with a
//! message. A release build of the shim never calls these functions.
//!
//! The set holds addresses only. The lock is a leaf: no code holds it
//! around a callback or another call into the core. A poisoned lock
//! stays usable, because each change of the set is a single step.

use std::collections::HashSet;
use std::ffi::{c_char, c_void};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use super::entry::{abort_with, ffi_guard};
use super::raw;

/// The addresses of the live handles.
static LIVE: LazyLock<Mutex<HashSet<usize>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn live() -> MutexGuard<'static, HashSet<usize>> {
    LIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Adds `zh` to the live handles. If the set cannot grow, the function
/// writes `handle registry: out of memory` and aborts.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_registry_add(zh: *const c_void) {
    ffi_guard(|| {
        let mut set = live();
        if set.try_reserve(1).is_err() {
            drop(set);
            abort_with("zookeeper: handle registry: out of memory");
        }
        set.insert(zh.addr());
    });
}

/// Removes `zh` from the live handles. A handle that is not live is not
/// an error.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_registry_remove(zh: *const c_void) {
    ffi_guard(|| {
        live().remove(&zh.addr());
    });
}

/// Returns when `zh` is live. Otherwise it writes a message that names
/// the entry point `func` and the handle address, and aborts.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_registry_check(zh: *const c_void, func: *const c_char) {
    ffi_guard(|| {
        if live().contains(&zh.addr()) {
            return;
        }
        let func = raw::cstr_ref(func).map_or_else(|| "(null)".into(), String::from_utf8_lossy);
        abort_with(&format!(
            "zookeeper: {func}: zhandle_t {:#x} is closed or invalid \
             (use after close or double close)",
            zh.addr()
        ));
    });
}
