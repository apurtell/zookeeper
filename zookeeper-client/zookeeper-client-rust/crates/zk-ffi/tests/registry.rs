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

//! The handle registry of the debug builds: add, check and remove.
//!
//! A failed check aborts the process, so those tests run this test binary
//! again as a child process and read its stderr and its signal.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
#![allow(clippy::disallowed_macros)]

use std::env;
use std::ffi::{CStr, c_void};
use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;

use std::ffi::c_char;

// The test calls the exports by their C names, as the shim does.
use zk_ffi as _;

#[allow(unsafe_code, reason = "the declarations of the C exports")]
unsafe extern "C" {
    safe fn zkrs_registry_add(zh: *const c_void);
    safe fn zkrs_registry_remove(zh: *const c_void);
    safe fn zkrs_registry_check(zh: *const c_void, func: *const c_char);
}

/// The child mode: the name of the case that the child runs.
const CHILD: &str = "ZKRS_REGISTRY_CHILD";
const FUNC: &CStr = c"zoo_aget";

/// Returns a distinct address for each live box.
fn handle(b: &u64) -> *const c_void {
    std::ptr::from_ref(b).cast()
}

/// Runs `case` in a child process and returns its stderr. The child must
/// stop with SIGABRT.
fn child_aborts(case: &str) -> String {
    let out = Command::new(env::current_exe().unwrap())
        .args(["child", "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, case)
        .output()
        .unwrap();
    assert_eq!(out.status.signal(), Some(libc::SIGABRT), "{out:?}");
    String::from_utf8(out.stderr).unwrap()
}

/// Rule: a live handle passes the check, and the check does not change
/// the set.
#[test]
fn a_live_handle_passes_the_check() {
    let b = Box::new(1u64);
    let zh = handle(&b);
    zkrs_registry_add(zh);
    zkrs_registry_check(zh, FUNC.as_ptr());
    zkrs_registry_check(zh, FUNC.as_ptr());
    zkrs_registry_remove(zh);
}

/// Rule: the removal of a handle that is not live does nothing.
#[test]
fn removing_an_unknown_handle_does_nothing() {
    let b = Box::new(2u64);
    let other = Box::new(3u64);
    zkrs_registry_add(handle(&b));
    zkrs_registry_remove(handle(&other));
    zkrs_registry_check(handle(&b), FUNC.as_ptr());
    zkrs_registry_remove(handle(&b));
}

/// The child side of the abort tests. Without the variable it does
/// nothing.
#[test]
fn child() {
    let Ok(case) = env::var(CHILD) else {
        return;
    };
    let b = Box::new(4u64);
    let zh = handle(&b);
    eprintln!("addr={:#x}", zh.addr());
    match case.as_str() {
        "unknown" => zkrs_registry_check(zh, FUNC.as_ptr()),
        "closed" => {
            zkrs_registry_add(zh);
            zkrs_registry_check(zh, FUNC.as_ptr());
            zkrs_registry_remove(zh);
            zkrs_registry_check(zh, c"zookeeper_close".as_ptr());
        }
        _ => panic!("unknown case {case}"),
    }
    panic!("the check returned");
}

/// Returns the address line and the message line of the child.
fn lines(err: &str) -> (String, String) {
    let mut it = err.lines();
    let addr = it.next().unwrap().strip_prefix("addr=").unwrap().to_owned();
    (addr, it.next().unwrap_or_default().to_owned())
}

/// Rule: a handle that was never added aborts the check with the
/// message, the entry name and the address in hex.
#[test]
fn an_unknown_handle_aborts_with_the_message() {
    let err = child_aborts("unknown");
    let (addr, msg) = lines(&err);
    assert!(addr.starts_with("0x"), "{err}");
    assert_eq!(
        msg,
        format!(
            "zookeeper: zoo_aget: zhandle_t {addr} is closed or invalid \
             (use after close or double close)"
        )
    );
}

/// Rule: a handle after its removal aborts the check, as a use after
/// close or a double close does.
#[test]
fn a_removed_handle_aborts_the_check() {
    let err = child_aborts("closed");
    let (addr, msg) = lines(&err);
    assert_eq!(
        msg,
        format!(
            "zookeeper: zookeeper_close: zhandle_t {addr} is closed or \
             invalid (use after close or double close)"
        )
    );
}
