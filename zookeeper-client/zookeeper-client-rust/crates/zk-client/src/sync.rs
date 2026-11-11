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

//! Non-poisoning lock helpers and the IO-side marker.
//!
//! No user code runs under any internal lock, so a poisoned lock holds
//! consistent data. The helpers take the guard out of a `PoisonError`,
//! so poison never becomes a permanent error.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(any(test, feature = "blocking"))]
use std::sync::Condvar;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::Waker;
#[cfg(any(test, feature = "blocking"))]
use std::time::Instant;

/// Locks a `std::sync::Mutex` and ignores poison.
pub(crate) trait LockExt<T> {
    /// Takes the lock. A poisoned lock gives its guard.
    fn lock_unpoisoned(&self) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_unpoisoned(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Calls a waker inside `catch_unwind`. A waker is user code, and a
/// panic in it must not stop the IO side. The caller holds no lock.
pub(crate) fn wake_quietly(w: Waker) {
    let _ = catch_unwind(AssertUnwindSafe(|| w.wake()));
}

/// Waits on `cv` and ignores poison.
#[cfg(any(test, feature = "blocking"))]
pub(crate) fn wait<'a, T>(cv: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    cv.wait(guard).unwrap_or_else(PoisonError::into_inner)
}

/// Waits on `cv` until `deadline` and ignores poison. It returns the
/// guard and true when the deadline passed. A spurious wake gives false,
/// so the caller checks its condition again.
#[cfg(any(test, feature = "blocking"))]
pub(crate) fn wait_until<'a, T>(
    cv: &Condvar,
    guard: MutexGuard<'a, T>,
    deadline: Instant,
) -> (MutexGuard<'a, T>, bool) {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return (guard, true);
    }
    let (guard, result) = cv
        .wait_timeout(guard, left)
        .unwrap_or_else(PoisonError::into_inner);
    (guard, result.timed_out())
}

thread_local! {
    /// The id of the client whose IO side runs on this thread, or 0.
    ///
    /// A `Cell` has no `Drop`, so the thread-local registers no thread
    /// exit destructor. Such a destructor can pin a loaded library.
    static IO_SIDE: Cell<u64> = const { Cell::new(0) };
}

/// Restores the previous IO-side marker when it drops.
#[derive(Debug)]
pub(crate) struct IoSideGuard {
    prev: u64,
}

impl Drop for IoSideGuard {
    fn drop(&mut self) {
        let prev = self.prev;
        IO_SIDE.with(|c| c.set(prev));
    }
}

/// Marks this thread as the IO side of client `client` until the guard
/// drops. The IO thread, the DNS threads and every user hook on the IO
/// side run inside such a guard.
pub(crate) fn enter_io_side(client: u64) -> IoSideGuard {
    let prev = IO_SIDE.with(|c| c.replace(client));
    IoSideGuard { prev }
}

/// Returns true when this thread runs the IO side of any client.
#[cfg(any(test, feature = "blocking"))]
pub(crate) fn on_io_side() -> bool {
    IO_SIDE.with(|c| c.get() != 0)
}

/// Returns true when a blocking wait must fail with `InvalidState`
/// (specification "Execution Runtimes").
///
/// `tokio_driver` is true when the tokio driver runs the client of the
/// wait. A wait on the IO side of any client would deadlock, so the
/// client always refuses it. A wait in a tokio runtime context can stop
/// the driver task of a tokio client, so the client also refuses that
/// wait for a tokio client.
///
/// Tokio has no public test for a worker thread. Thus a tokio client
/// also refuses a wait in a `spawn_blocking` thread. A client on the
/// thread driver has its own IO thread, and a blocked worker cannot
/// stop it. Thus such a client accepts a wait in any tokio context,
/// and `spawn_blocking` works with it.
#[cfg(any(test, feature = "blocking"))]
pub(crate) fn blocking_refused(tokio_driver: bool) -> bool {
    on_io_side() || (tokio_driver && in_tokio_runtime())
}

#[cfg(all(any(test, feature = "blocking"), unix, feature = "tokio"))]
fn in_tokio_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

#[cfg(all(any(test, feature = "blocking"), not(all(unix, feature = "tokio"))))]
fn in_tokio_runtime() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_nests_and_restores() {
        assert!(!on_io_side());
        {
            let _outer = enter_io_side(7);
            assert!(on_io_side());
            {
                let _inner = enter_io_side(9);
                assert!(on_io_side());
            }
            assert!(on_io_side());
        }
        assert!(!on_io_side());
    }

    #[test]
    fn a_poisoned_lock_gives_its_guard() {
        let m = std::sync::Arc::new(Mutex::new(5));
        let m2 = std::sync::Arc::clone(&m);
        let _ = std::panic::catch_unwind(move || {
            let _g = m2.lock_unpoisoned();
            std::panic::panic_any("poison");
        });
        assert_eq!(*m.lock_unpoisoned(), 5);
    }
}
