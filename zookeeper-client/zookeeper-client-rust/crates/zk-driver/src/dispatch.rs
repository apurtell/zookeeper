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

//! The bounded hand-off of the native drivers.
//!
//! After each core call the IO side routes the items of its outbox, in
//! order, into the zk-client slots, per-watcher queues and session state
//! through a [`RouteSink`]. The [`ReadGate`] counts the undelivered
//! items. While the count is at or above `dispatch_queue_capacity`, the
//! IO side reads no frames in phase Established. It still sends requests
//! and pings, and the receive timer runs.
//!
//! - The sink tells the driver whether an item counts: results and auth
//!   outcomes with a live receiver, and one-shot watch events. Persistent
//!   watch events do not count.
//! - A receiver that takes or drops a counted item calls
//!   [`ReadGate::taken`]. When the count goes below the capacity, the
//!   caller wakes the IO side.
//! - One `handle_read` call can add the items of one 64 KiB read, so the
//!   count can go over the capacity by at most one read.

use zk_proto::Tokens;

use crate::outbox::Item;
use crate::sync::atomic::{AtomicUsize, Ordering};

/// Routes native items into zk-client.
pub trait RouteSink<T: Tokens>: Send + Sync {
    /// Routes one item, in outbox order. It never blocks.
    ///
    /// It returns true when the item counts against the capacity.
    fn route(&self, item: Item<T>) -> bool;
}

/// The undelivered-item count and its capacity.
#[derive(Debug)]
pub struct ReadGate {
    count: AtomicUsize,
    capacity: usize,
}

impl ReadGate {
    /// Makes an open gate. A capacity of 0 counts as 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            count: AtomicUsize::new(0),
            capacity: capacity.max(1),
        }
    }

    /// Returns true while the count is below the capacity.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.count.load(Ordering::Acquire) < self.capacity
    }

    /// Returns the count.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Records one routed item that counts.
    pub fn routed(&self) {
        let _ = update(&self.count, |c| c.checked_add(1));
    }

    /// Records one taken or dropped item. It returns true when the gate
    /// opened. The caller then wakes the IO side.
    pub fn taken(&self) -> bool {
        update(&self.count, |c| c.checked_sub(1)).is_some_and(|prev| prev == self.capacity)
    }
}

/// Applies `f` to the counter atomically. It returns the old value, or
/// `None` when `f` gives `None`. The loop replaces `fetch_update`, which
/// new toolchains deprecate.
fn update(counter: &AtomicUsize, f: impl Fn(usize) -> Option<usize>) -> Option<usize> {
    let mut cur = counter.load(Ordering::Acquire);
    loop {
        let next = f(cur)?;
        match counter.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(prev) => return Some(prev),
            Err(seen) => cur = seen,
        }
    }
}
