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

//! The TCP socket of the drivers.
//!
//! `TcpSock` is a non-blocking stream socket over `rustix::net`. Every
//! send uses `MSG_NOSIGNAL`, or `SO_NOSIGPIPE` on Apple, so no path can
//! raise SIGPIPE.
//!
//! CLOEXEC rule (spec, "Socket abstractions"): the drop-in sets CLOEXEC
//! only when the shim's runtime `sock_cloexec` flag is set. The native
//! drivers always set it. Where `SOCK_CLOEXEC` does not exist (Apple), the
//! code uses `fcntl(F_SETFD)` after `socket()`.

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::OFlags;
use rustix::io::{Errno, FdFlags};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use zk_proto::ConnectStart;

use crate::iocore::RawSock;

/// One non-blocking TCP socket.
#[derive(Debug)]
pub struct TcpSock {
    fd: OwnedFd,
}

/// The result of [`TcpSock::open`].
#[derive(Debug)]
pub struct Opened {
    /// The new socket.
    pub sock: TcpSock,
    /// False when `TCP_NODELAY` failed. The caller then emits the
    /// `LogSite::TcpNoDelay` WARN and goes on (zookeeper.c:2553-2570).
    pub nodelay_ok: bool,
}

/// The send flags of every send.
#[cfg(not(any(target_vendor = "apple", windows)))]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;

/// The send flags of every send. Apple uses the socket option instead.
#[cfg(any(target_vendor = "apple", windows))]
const SEND_FLAGS: SendFlags = SendFlags::empty();

/// The `socket()` flag that makes the socket non-blocking, where the
/// platform has one. The cfg list is the one of rustix.
#[cfg(not(any(
    target_vendor = "apple",
    windows,
    target_os = "aix",
    target_os = "espidf",
    target_os = "haiku",
    target_os = "horizon",
    target_os = "nto",
    target_os = "vita",
)))]
const NONBLOCK_FLAG: Option<SocketFlags> = Some(SocketFlags::NONBLOCK);

/// No `SOCK_NONBLOCK` here. `open` uses `fcntl(F_SETFL)` instead.
#[cfg(any(
    target_vendor = "apple",
    windows,
    target_os = "aix",
    target_os = "espidf",
    target_os = "haiku",
    target_os = "horizon",
    target_os = "nto",
    target_os = "vita",
))]
const NONBLOCK_FLAG: Option<SocketFlags> = None;

/// The `socket()` flag that sets close-on-exec, where the platform has
/// one. The cfg list is the one of rustix.
#[cfg(not(any(
    target_vendor = "apple",
    windows,
    target_os = "aix",
    target_os = "haiku",
)))]
const CLOEXEC_FLAG: Option<SocketFlags> = Some(SocketFlags::CLOEXEC);

/// No `SOCK_CLOEXEC` here. `open` uses `fcntl(F_SETFD)` instead.
#[cfg(any(
    target_vendor = "apple",
    windows,
    target_os = "aix",
    target_os = "haiku",
))]
const CLOEXEC_FLAG: Option<SocketFlags> = None;

/// Sets `O_NONBLOCK` on `fd` and keeps its other status flags.
///
/// The C client uses `fcntl(F_SETFL)` in the same way (zookeeper.c:2538).
/// The code does not use `ioctl(FIONBIO)`. rustix passes its argument
/// through the C variadic as `void *`, but the callee reads an `int *`.
/// Miri reports that type mismatch as undefined behavior.
///
/// # Errors
///
/// Returns the errno of `fcntl(F_GETFL)` or `fcntl(F_SETFL)`.
pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK)
}

impl TcpSock {
    /// Makes a non-blocking stream socket for the family of `addr`.
    ///
    /// Contract (zookeeper.c:2625-2629, 2553-2570):
    /// - `socket_with(family, STREAM, flags, None)`. `flags` has CLOEXEC
    ///   only when `cloexec` is true. Without `SocketFlags::CLOEXEC`
    ///   (Apple) it uses `fcntl_setfd(CLOEXEC)` after the call.
    /// - Non-blocking through `SocketFlags::NONBLOCK` where it exists,
    ///   else [`set_nonblocking`].
    /// - Apple: `SO_NOSIGPIPE` on every socket, the probe socket too.
    /// - `TCP_NODELAY`. A failure does not fail the call. It sets
    ///   `nodelay_ok = false`.
    ///
    /// # Errors
    ///
    /// Returns the errno of `socket()` or of a flag call. The caller
    /// passes it as `TransportFailure::SocketCreate` (ZSYSTEMERROR).
    pub fn open(addr: &SocketAddr, cloexec: bool) -> Result<Opened, Errno> {
        let family = if addr.is_ipv4() {
            AddressFamily::INET
        } else {
            AddressFamily::INET6
        };
        let mut flags = SocketFlags::empty();
        if let Some(f) = NONBLOCK_FLAG {
            flags |= f;
        }
        if cloexec {
            if let Some(f) = CLOEXEC_FLAG {
                flags |= f;
            }
        }
        // The descriptor is owned at once, so an error below closes it.
        let fd = rustix::net::socket_with(family, SocketType::STREAM, flags, None)?;
        if NONBLOCK_FLAG.is_none() {
            set_nonblocking(fd.as_fd())?;
        }
        if cloexec && CLOEXEC_FLAG.is_none() {
            rustix::io::fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        }
        // Apple has no MSG_NOSIGNAL. The socket option stops SIGPIPE for
        // every send on this socket.
        #[cfg(target_vendor = "apple")]
        rustix::net::sockopt::set_socket_nosigpipe(&fd, true)?;
        // C only logs a NODELAY failure and goes on (zookeeper.c:2553-2570).
        let nodelay_ok = rustix::net::sockopt::set_tcp_nodelay(&fd, true).is_ok();
        Ok(Opened {
            sock: Self { fd },
            nodelay_ok,
        })
    }

    /// Starts a non-blocking connect.
    ///
    /// `Ok(Immediate)` when `connect` returns 0. `Ok(InProgress)` for
    /// EINPROGRESS and EWOULDBLOCK (zookeeper.c:2697-2711). EINTR is also
    /// in progress, as POSIX keeps the connect going.
    ///
    /// # Errors
    ///
    /// Returns any other errno. The caller passes it as
    /// `TransportFailure::TcpRefused` (ZCONNECTIONLOSS).
    pub fn start_connect(&self, addr: &SocketAddr) -> Result<ConnectStart, Errno> {
        match rustix::net::connect(&self.fd, addr) {
            Ok(()) => Ok(ConnectStart::Immediate),
            Err(Errno::INPROGRESS | Errno::WOULDBLOCK | Errno::INTR) => {
                Ok(ConnectStart::InProgress)
            }
            Err(e) => Err(e),
        }
    }

    /// Wraps an open socket. Tests and the Windows waker use it.
    #[must_use]
    pub fn from_owned(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Gives back the descriptor.
    #[must_use]
    pub fn into_owned(self) -> OwnedFd {
        self.fd
    }

    /// Returns the descriptor number that the shim reports to C.
    #[must_use]
    pub fn raw(&self) -> RawSock {
        self.fd.as_raw_fd()
    }

    /// Sends bytes with the no-SIGPIPE flags.
    ///
    /// # Errors
    ///
    /// Returns the OS error. `WOULDBLOCK` means "try again on WRITE".
    pub fn send(&self, buf: &[u8]) -> Result<usize, Errno> {
        rustix::net::send(&self.fd, buf, SEND_FLAGS)
    }

    /// Receives bytes. EINTR is retried.
    ///
    /// `Ok(0)` with a non-empty buffer is EOF.
    ///
    /// # Errors
    ///
    /// Returns the OS error. `WOULDBLOCK` means "no bytes now".
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        loop {
            match rustix::net::recv(&self.fd, &mut *buf, RecvFlags::empty()) {
                Err(Errno::INTR) => {}
                Err(e) => return Err(e),
                Ok((n, _)) => return Ok(n),
            }
        }
    }

    /// Reads `SO_ERROR` (zookeeper.c:3079-3110).
    ///
    /// # Errors
    ///
    /// Returns the pending socket error, or the error of the
    /// `getsockopt` call itself.
    pub fn socket_error(&self) -> Result<(), Errno> {
        rustix::net::sockopt::socket_error(&self.fd)?
    }

    /// Returns the local address (`getsockname`). SASL `Start` uses it.
    ///
    /// # Errors
    ///
    /// Returns the OS error, or `AFNOSUPPORT` for a non-IP address.
    pub fn local_addr(&self) -> Result<SocketAddr, Errno> {
        let any = rustix::net::getsockname(&self.fd)?;
        SocketAddr::try_from(any).map_err(|_| Errno::AFNOSUPPORT)
    }

    /// Returns the peer address (`getpeername`). SASL `Start` and
    /// `zkrs_peer_addr` use it.
    ///
    /// # Errors
    ///
    /// Returns the OS error, `NOTCONN` when the kernel gives no address,
    /// or `AFNOSUPPORT` for a non-IP address.
    pub fn peer_addr(&self) -> Result<SocketAddr, Errno> {
        let any = rustix::net::getpeername(&self.fd)?.ok_or(Errno::NOTCONN)?;
        SocketAddr::try_from(any).map_err(|_| Errno::AFNOSUPPORT)
    }
}

impl AsFd for TcpSock {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Returns the raw OS error number of an errno for `TransportFailure`.
#[must_use]
pub fn errno_value(e: Errno) -> i32 {
    e.raw_os_error()
}
