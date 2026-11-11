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

//! Time values and the time arithmetic of the core.
//!
//! The core has no clock. The driver gives a monotonic time stamp with
//! every input. The helpers compute in `i64`, so the C `int` overflow cannot
//! occur, and they keep the truncating division of C.

/// A monotonic time stamp in milliseconds from any origin.
///
/// Drivers map their monotonic clock to this value. Tests use plain
/// integers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Millis(pub u64);

impl Millis {
    /// Returns the time stamp `ms` milliseconds later. The sum saturates.
    #[must_use]
    pub const fn saturating_add_ms(self, ms: u64) -> Self {
        Self(self.0.saturating_add(ms))
    }

    /// Returns the time stamp `ms` milliseconds later, for a signed delay.
    /// A negative delay gives an earlier time stamp. The result saturates.
    #[must_use]
    pub const fn offset_ms(self, ms: i64) -> Self {
        Self(self.0.saturating_add_signed(ms))
    }
}

/// Returns the milliseconds from `then` to `now`, or 0 when `then` is later.
#[must_use]
pub fn elapsed(now: Millis, then: Millis) -> i64 {
    i64::try_from(now.0.saturating_sub(then.0)).unwrap_or(i64::MAX)
}

/// Returns the signed milliseconds from `now` to `deadline`. The value is
/// negative when the deadline is past.
#[must_use]
pub fn until(now: Millis, deadline: Millis) -> i64 {
    if deadline >= now {
        i64::try_from(deadline.0.saturating_sub(now.0)).unwrap_or(i64::MAX)
    } else {
        i64::try_from(now.0.saturating_sub(deadline.0))
            .unwrap_or(i64::MAX)
            .saturating_neg()
    }
}

/// Returns `t * 2 / 3` with the truncating division of C.
#[must_use]
pub fn two_thirds(t: i32) -> i64 {
    i64::from(t).saturating_mul(2).checked_div(3).unwrap_or(0)
}

/// Returns `t / 3` with the truncating division of C.
#[must_use]
pub fn third(t: i32) -> i64 {
    i64::from(t).checked_div(3).unwrap_or(0)
}

/// Clamps a millisecond value to the `u32` range of an interest timeout.
/// Negative values give 0, as the C `get_timeval` does.
#[must_use]
pub fn clamp_timeout(ms: i64) -> u32 {
    u32::try_from(ms.max(0)).unwrap_or(u32::MAX)
}
