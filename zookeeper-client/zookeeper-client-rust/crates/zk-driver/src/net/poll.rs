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

//! The poll call and the readiness mapping.
//!
//! The IO step polls only through the [`Poll`] trait. The default
//! implementation is [`RustixPoll`]. On Windows zk-ffi may inject its own
//! `WSAPoll` wrapper, because zk-driver contains no `unsafe` code.
//! zk-driver has no Windows build, but the trait keeps the injection
//! point for one.

use rustix::event::{PollFd, PollFlags, Timespec};

/// The readiness poll of the IO owner.
///
/// The call has the contract of `rustix::event::poll`. `timeout_ms` is in
/// whole milliseconds. A negative value waits without a limit, and the
/// drivers never pass one.
pub trait Poll: Send + Sync {
    /// Waits until a descriptor in `fds` is ready or the timeout ends.
    ///
    /// It returns the number of ready descriptors. `Err(INTR)` is a
    /// legal result. The caller treats it as "no events".
    ///
    /// # Errors
    ///
    /// Returns the OS error of the poll call.
    fn poll(&self, fds: &mut [PollFd<'_>], timeout_ms: i32) -> rustix::io::Result<usize>;
}

/// The default [`Poll`]: `rustix::event::poll` (`WSAPoll` on Windows).
#[derive(Clone, Copy, Debug, Default)]
pub struct RustixPoll;

impl Poll for RustixPoll {
    /// Calls `rustix::event::poll` with the timeout as a `Timespec`.
    ///
    /// A negative `timeout_ms` passes no timeout. The call does not retry
    /// on EINTR. The caller decides.
    fn poll(&self, fds: &mut [PollFd<'_>], timeout_ms: i32) -> rustix::io::Result<usize> {
        let ts = timespec(timeout_ms);
        rustix::event::poll(fds, ts.as_ref())
    }
}

/// Converts whole milliseconds to a poll timeout. A negative value
/// gives `None`, which waits without a limit.
fn timespec(timeout_ms: i32) -> Option<Timespec> {
    if timeout_ms < 0 {
        return None;
    }
    let secs = timeout_ms.checked_div(1000).unwrap_or(0);
    // The rest is below 1000 ms, so the nanoseconds fit in an i32.
    let nanos = timeout_ms
        .checked_rem(1000)
        .unwrap_or(0)
        .saturating_mul(1_000_000);
    Some(Timespec {
        tv_sec: i64::from(secs),
        tv_nsec: nanos.into(),
    })
}

/// The readiness of one descriptor, in the legacy interest terms.
///
/// `read` is `ZOOKEEPER_READ` and `write` is `ZOOKEEPER_WRITE`
/// (zookeeper.h: `ZOOKEEPER_WRITE = 1 << 0`, `ZOOKEEPER_READ = 1 << 1`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PollEvents {
    /// The descriptor is ready to read.
    pub read: bool,
    /// The descriptor is ready to write.
    pub write: bool,
}

/// The legacy `ZOOKEEPER_WRITE` bit.
pub const ZOOKEEPER_WRITE: u32 = 1;

/// The legacy `ZOOKEEPER_READ` bit.
pub const ZOOKEEPER_READ: u32 = 2;

impl PollEvents {
    /// No events.
    pub const NONE: Self = Self {
        read: false,
        write: false,
    };

    /// Converts legacy interest bits. Unknown bits are ignored.
    ///
    /// st `zookeeper_process` gets its `events` argument in these bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self {
            read: bits & ZOOKEEPER_READ != 0,
            write: bits & ZOOKEEPER_WRITE != 0,
        }
    }

    /// Returns the legacy interest bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        let r = if self.read { ZOOKEEPER_READ } else { 0 };
        let w = if self.write { ZOOKEEPER_WRITE } else { 0 };
        r | w
    }

    /// Returns true when no bit is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.read && !self.write
    }
}

/// Maps `revents` to legacy events.
///
/// - `IN` gives READ.
/// - `OUT` and `HUP` give WRITE, as `do_io` maps them (mt_adaptor.c:403-404).
/// - `ERR` and `NVAL` give READ and WRITE. The next recv or send then
///   reports the error, so the attempt ends with a ZCONNECTIONLOSS
///   teardown and the loop does not spin to the receive timeout.
#[must_use]
pub fn map_revents(revents: PollFlags) -> PollEvents {
    let error = revents.intersects(PollFlags::ERR | PollFlags::NVAL);
    PollEvents {
        read: error || revents.contains(PollFlags::IN),
        write: error || revents.intersects(PollFlags::OUT | PollFlags::HUP),
    }
}

/// Converts a poll timeout to whole milliseconds for [`Poll::poll`].
///
/// The value is rounded up and clamped to `0..=i32::MAX`.
/// `timeout_ms` is the `i64` of [`crate::iocore::InterestOut`].
#[must_use]
pub fn clamp_timeout_ms(timeout_ms: i64) -> i32 {
    let clamped = timeout_ms.clamp(0, i64::from(i32::MAX));
    i32::try_from(clamped).unwrap_or(i32::MAX)
}

/// Returns the poll flags that ask for the given legacy interest.
///
/// READ asks for `IN`. WRITE asks for `OUT`. The kernel always reports
/// `ERR`, `HUP` and `NVAL`.
#[must_use]
pub fn request_flags(events: PollEvents) -> PollFlags {
    let mut flags = PollFlags::empty();
    if events.read {
        flags |= PollFlags::IN;
    }
    if events.write {
        flags |= PollFlags::OUT;
    }
    flags
}

#[cfg(test)]
mod tests {
    // tv_nsec is an i64 on 64-bit targets and an i32 on 32-bit targets.
    #![allow(clippy::useless_conversion)]

    use super::*;

    #[test]
    fn timespec_splits_the_milliseconds() {
        assert!(timespec(-1).is_none());
        let ts = timespec(1500).unwrap_or(Timespec {
            tv_sec: -1,
            tv_nsec: 0,
        });
        assert_eq!(ts.tv_sec, 1);
        assert_eq!(i64::from(ts.tv_nsec), 500_000_000);
        let max = timespec(i32::MAX).unwrap_or(Timespec {
            tv_sec: -1,
            tv_nsec: 0,
        });
        assert_eq!(max.tv_sec, i64::from(i32::MAX / 1000));
        assert_eq!(i64::from(max.tv_nsec), 647_000_000);
    }
}
