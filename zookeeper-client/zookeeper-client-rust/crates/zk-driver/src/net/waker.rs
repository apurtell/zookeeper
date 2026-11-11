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

//! The coalesced waker of the threaded drivers.
//!
//! The waker is a non-blocking pipe. [`Waker`] is the shared write side.
//! [`WakeRx`] is the read side, and the IO owner keeps it next to its
//! `IoCore`. The split lets the forked-child close drop each end through
//! its own lock without `unsafe` code.
//!
//! An `AtomicBool` coalesces the wakes. Only a change from false to true
//! writes a byte, so at most one byte is in the pipe and the pipe never
//! fills.
//!
//! The drop-in pipe has no CLOEXEC (mt_adaptor.c:244). The native drivers
//! set CLOEXEC on it (spec, "Socket abstractions"). So [`Waker::new`]
//! takes the flag.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::io::{Errno, FdFlags};

use crate::net::sock::set_nonblocking;
use crate::sync::Mutex;
use crate::sync::atomic::{AtomicBool, Ordering};

/// The shared write side of the waker.
#[derive(Debug)]
pub struct Waker {
    pending: AtomicBool,
    tx: Mutex<Option<OwnedFd>>,
}

/// The read side of the waker. Only the IO owner holds it.
#[derive(Debug)]
pub struct WakeRx {
    rx: OwnedFd,
}

impl Waker {
    /// Makes the pipe pair. Both ends are non-blocking.
    ///
    /// `cloexec` sets FD_CLOEXEC on both ends. The drop-in passes false
    /// and the native drivers pass true. A failure gives the errno of the
    /// failed call. `zkrs_handle_new` then logs "Can't make a pipe %d"
    /// (mt_adaptor.c:245) and fails the init with that errno.
    ///
    /// # Errors
    ///
    /// Returns the OS error of `pipe` or `fcntl`.
    pub fn new(cloexec: bool) -> Result<(Self, WakeRx), Errno> {
        let (rx, tx) = rustix::pipe::pipe()?;
        // `fcntl(F_SETFL)` works on every Unix target, so no pipe2 flag
        // set is necessary.
        set_nonblocking(rx.as_fd())?;
        set_nonblocking(tx.as_fd())?;
        if cloexec {
            rustix::io::fcntl_setfd(&rx, FdFlags::CLOEXEC)?;
            rustix::io::fcntl_setfd(&tx, FdFlags::CLOEXEC)?;
        }
        let waker = Self {
            pending: AtomicBool::new(false),
            tx: Mutex::new(Some(tx)),
        };
        Ok((waker, WakeRx { rx }))
    }

    /// Wakes the IO owner. Only a change from false to true writes a byte.
    ///
    /// A write error is ignored. The pipe cannot be full, and a closed
    /// pipe means that the IO owner is gone.
    pub fn wake(&self) {
        if self.pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let tx = self.tx.lock_owner();
        if let Some(fd) = tx.as_ref() {
            let _ = rustix::io::write(fd, &[1]);
        }
    }

    /// Closes the write end. The forked-child close uses it.
    ///
    /// It returns false when another thread holds the lock. The fd then
    /// stays open, because a parent thread may have held the lock at the
    /// fork.
    pub fn close_in_child(&self) -> bool {
        match self.tx.try_lock() {
            Some(mut tx) => {
                drop(tx.take());
                true
            }
            None => false,
        }
    }
}

impl WakeRx {
    /// Empties the pipe, then allows the next wake.
    ///
    /// The IO owner calls it after a poll reports IN on this end, and
    /// then reads the core state under the lock. So no wake is lost: a
    /// waker that sets the flag after the store also writes a new byte.
    pub fn reset(&self, waker: &Waker) {
        let mut buf = [0u8; 16];
        while matches!(rustix::io::read(&self.rx, &mut buf), Ok(n) if n == buf.len()) {}
        waker.pending.store(false, Ordering::Release);
    }
}

impl AsFd for WakeRx {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.rx.as_fd()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    #![allow(clippy::disallowed_macros)]

    use rustix::fs::OFlags;
    use rustix::io::FdFlags;

    use super::*;

    /// Both ends are non-blocking, with and without CLOEXEC. The test
    /// reads the private write end, so it stays in this module. Under
    /// Miri it also checks the variadic types of the flag calls.
    #[test]
    fn both_ends_are_non_blocking() {
        // Miri has no `fcntl(F_SETFD)` and reports each descriptor as
        // CLOEXEC. So under Miri the test makes only the plain pipe.
        let modes: &[bool] = if cfg!(miri) { &[false] } else { &[false, true] };
        for &cloexec in modes {
            let (waker, rx) = Waker::new(cloexec).unwrap();
            let tx = waker.tx.try_lock().unwrap();
            let tx = tx.as_ref().unwrap();
            for fd in [rx.as_fd(), tx.as_fd()] {
                assert!(
                    rustix::fs::fcntl_getfl(fd)
                        .unwrap()
                        .contains(OFlags::NONBLOCK)
                );
                let flags = rustix::io::fcntl_getfd(fd).unwrap();
                if !cfg!(miri) {
                    assert_eq!(flags.contains(FdFlags::CLOEXEC), cloexec);
                }
            }
            // An empty non-blocking pipe gives EAGAIN and does not block.
            let mut buf = [0u8; 1];
            assert_eq!(rustix::io::read(&rx, &mut buf), Err(Errno::AGAIN));
        }
    }
}
