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

//! The logical clock of the test kit.
//!
//! The core has no clock. Each input takes a [`Millis`] time stamp. The
//! harness reads that time stamp from a [`ManualClock`], and only the test
//! or the idle rule of the harness moves it.

use zk_proto::Millis;

/// A monotonic clock that moves only when the test moves it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ManualClock {
    now: Millis,
}

impl ManualClock {
    /// Makes a clock that starts at `start`.
    #[must_use]
    pub const fn new(start: Millis) -> Self {
        Self { now: start }
    }

    /// Returns the current time stamp.
    #[must_use]
    pub const fn now(&self) -> Millis {
        self.now
    }

    /// Moves the clock forward by `ms` milliseconds and returns the new
    /// time. The sum saturates.
    pub fn advance(&mut self, ms: u64) -> Millis {
        self.now = self.now.saturating_add_ms(ms);
        self.now
    }

    /// Moves the clock to `t` when `t` is later, and returns the new time.
    /// The clock never moves back.
    pub fn advance_to(&mut self, t: Millis) -> Millis {
        if t > self.now {
            self.now = t;
        }
        self.now
    }
}
