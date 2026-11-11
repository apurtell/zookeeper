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

//! An unrelated Rust staticlib for LINK-01.
//!
//! The library has its own copy of std, and it builds with panic=abort.
//! The application links it together with the static Rust core. The
//! link must not give a duplicate symbol, and both copies of std must
//! work in one process. The probe uses the allocator, a thread, a
//! channel, the hash map and a TCP connection.
//!
//! The library has no rustls and no ring. In a TLS configuration the
//! runner builds zklinkring, which contains this file and adds them.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, CStr};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Runs the probe. HOST is "host:port" of a TCP server, or null. The
/// result is 0 when each step works, else the number of the failed step.
///
/// # Safety
///
/// HOST is null or points to a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zklinkrs_probe(host: *const c_char) -> c_int {
    let (tx, rx) = mpsc::channel::<u64>();
    let worker = thread::spawn(move || {
        let mut map: HashMap<String, u64> = HashMap::new();
        for i in 0..1000u64 {
            map.insert(format!("key-{i}"), i);
        }
        let _ = tx.send(map.values().sum());
    });
    if rx.recv_timeout(Duration::from_secs(10)) != Ok(499_500) {
        return 1;
    }
    if worker.join().is_err() {
        return 2;
    }
    if host.is_null() {
        return 0;
    }
    // SAFETY: the caller gives a NUL-terminated string.
    let host = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(h) => h,
        Err(_) => return 3,
    };
    let addr = match host.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return 4,
    };
    match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(_) => 0,
        Err(_) => 5,
    }
}

/// Returns the length of a string that std formats. The application
/// compares it with the expected value.
#[no_mangle]
pub extern "C" fn zklinkrs_format_len(n: c_int) -> c_int {
    let s = format!("zklinkrs:{n:08}");
    c_int::try_from(s.len()).unwrap_or(-1)
}
