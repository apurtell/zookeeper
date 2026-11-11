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

//! The driver clock.
//!
//! The protocol core reads no clock. The driver reads its [`Clock`] and
//! gives the value to every core call as `now`. TLS certificate validity
//! uses the rustls time provider instead.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use zk_proto::Millis;

/// A monotonic clock in milliseconds.
pub trait Clock: Send + Sync {
    /// Returns the time now. The value never goes back.
    fn now(&self) -> Millis;
}

/// The production clock: monotonic time from a per-handle origin.
#[derive(Clone, Copy, Debug)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    /// Makes a clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Millis {
        Millis(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// A clock that moves only when a test moves it.
#[derive(Debug, Default)]
pub struct TestClock {
    ms: AtomicU64,
}

impl TestClock {
    /// Makes a clock at `start`.
    #[must_use]
    pub const fn new(start: Millis) -> Self {
        Self {
            ms: AtomicU64::new(start.0),
        }
    }

    /// Sets the time.
    pub fn set(&self, now: Millis) {
        self.ms.store(now.0, Ordering::SeqCst);
    }

    /// Moves the time forward by `ms`. The value saturates.
    pub fn advance(&self, ms: u64) {
        let mut cur = self.ms.load(Ordering::SeqCst);
        // A compare-exchange loop, because `fetch_update` is deprecated on
        // new toolchains and `try_update` is not in the MSRV.
        while let Err(seen) = self.ms.compare_exchange_weak(
            cur,
            cur.saturating_add(ms),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            cur = seen;
        }
    }
}

impl Clock for TestClock {
    fn now(&self) -> Millis {
        Millis(self.ms.load(Ordering::SeqCst))
    }
}
