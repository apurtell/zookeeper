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

//! The errno values that the core gives as hints.
//!
//! The core has no libc. The values come from the target platform at
//! compile time. The shim sets `errno` from `Connection::take_errno_hint`.

/// `EINVAL`. It has the same value on every supported platform.
pub const EINVAL: i32 = 22;

/// `ENOMEM`. It has the same value on every supported platform.
pub const ENOMEM: i32 = 12;

/// `ESTALE` of Linux and other platforms with the Linux values.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    windows
)))]
pub const ESTALE: i32 = 116;

/// `ETIMEDOUT` of Linux and other platforms with the Linux values.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    windows
)))]
pub const ETIMEDOUT: i32 = 110;

/// `ESTALE` of macOS and the BSDs.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub const ESTALE: i32 = 70;

/// `ETIMEDOUT` of macOS and the BSDs.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub const ETIMEDOUT: i32 = 60;

/// `ESTALE` of the Windows CRT.
#[cfg(windows)]
pub const ESTALE: i32 = 19;

/// `ETIMEDOUT` of Windows: `WSAETIMEDOUT`.
#[cfg(windows)]
pub const ETIMEDOUT: i32 = 10060;

/// `EHOSTDOWN` of Linux and other platforms with the Linux values. The
/// legacy receive path sets it on an end of stream and on a zero frame
/// length (zookeeper.c:101, 1943, 1992).
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    windows
)))]
pub const EHOSTDOWN: i32 = 112;

/// `EHOSTDOWN` of macOS and the BSDs.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub const EHOSTDOWN: i32 = 64;

/// `EHOSTDOWN` of Windows. The C client defines it as `EPIPE`.
#[cfg(windows)]
pub const EHOSTDOWN: i32 = 32;
