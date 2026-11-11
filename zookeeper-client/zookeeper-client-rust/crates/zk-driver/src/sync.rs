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

//! The lock facade and the `Unlocked` proof.
//!
//! The drivers take every lock and every shared atomic from this module.
//! A normal build wraps the `std::sync` types. A build with `--cfg loom`
//! wraps the `loom` types instead. The loom models thus explore the
//! interleavings of the real driver code.
//!
//! A `static` and the test clock keep the `std` atomics. Their
//! constructors are `const`, and the `loom` constructors are not. For
//! the same reason, the `new` functions of [`Mutex`] and [`Condvar`] are
//! `const` only without loom. A public signature with a facade atomic
//! also takes the loom type under loom.
//!
//! The lock order is `io` -> `core` -> `fifo`. The `io` lock is the IO
//! owner lock. Only the IO owner takes it, so nobody waits for it in
//! normal running. The `core` lock goes through [`Mutex::lock`], which
//! borrows the [`Unlocked`] proof. A blocking call takes `&Unlocked`, so
//! the compiler rejects a blocking call while the core lock is held.
//!
//! The facade ignores lock poison. The crate does not panic, and a panic
//! in a test thread must not stop the other threads.

use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::{PoisonError, TryLockError};
use std::time::Duration;

#[cfg(loom)]
use loom::sync as imp;
#[cfg(not(loom))]
use std::sync as imp;

/// The atomic types of the drivers.
///
/// A normal build gives the `std` types. A build with `--cfg loom` gives
/// the `loom` types. A `static` keeps the `std` type, because the
/// `loom` constructors are not `const`.
pub mod atomic {
    #[cfg(loom)]
    pub use loom::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    #[cfg(not(loom))]
    pub use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
}

/// The proof that the thread holds no driver lock.
///
/// An API entry makes one proof with [`Unlocked::new_at_entry`]. The
/// [`Mutex::lock`] call borrows it mutably for the life of the guard.
/// The blocking leaves (`resolve`, `rng_reseed`) and
/// `TlsConnector::new_conn` take `&Unlocked`, so they cannot run while a
/// core guard is alive.
///
/// The proof is neither `Send` nor `Sync`. It stays on the thread that
/// made it.
#[derive(Debug)]
pub struct Unlocked {
    _not_send: PhantomData<*const ()>,
}

impl Unlocked {
    /// Makes the proof at an entry point.
    ///
    /// Call it only where the thread holds no driver lock: at the start of
    /// an exported entry, of a library thread or of a test.
    #[must_use]
    pub const fn new_at_entry() -> Self {
        Self {
            _not_send: PhantomData,
        }
    }
}

/// A mutual exclusion lock that ignores poison.
#[derive(Debug, Default)]
pub struct Mutex<T> {
    inner: imp::Mutex<T>,
}

/// The guard of a [`Mutex`].
///
/// The `'a` lifetime also covers the borrow of the [`Unlocked`] proof
/// when the guard comes from [`Mutex::lock`].
#[derive(Debug)]
pub struct Guard<'a, T> {
    inner: imp::MutexGuard<'a, T>,
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> Mutex<T> {
    /// Makes a lock around the value.
    #[cfg(not(loom))]
    pub const fn new(value: T) -> Self {
        Self {
            inner: imp::Mutex::new(value),
        }
    }

    /// Makes a lock around the value. The `loom` constructor is not
    /// `const`.
    #[cfg(loom)]
    pub fn new(value: T) -> Self {
        Self {
            inner: imp::Mutex::new(value),
        }
    }

    /// Takes the lock and borrows the proof for the life of the guard.
    ///
    /// Use it for the `core` lock. No blocking leaf can run while the
    /// guard is alive.
    pub fn lock<'a>(&'a self, proof: &'a mut Unlocked) -> Guard<'a, T> {
        let _ = proof;
        self.lock_owner()
    }

    /// Takes the lock without the proof.
    ///
    /// Use it for the `io` lock, which the IO owner keeps across blocking
    /// work, and for the `fifo` leaf lock, under which no blocking call
    /// runs.
    pub fn lock_owner(&self) -> Guard<'_, T> {
        Guard {
            inner: self.inner.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Takes the lock if it is free.
    ///
    /// The forked-child close uses it, because a parent thread can hold a
    /// lock at fork time.
    pub fn try_lock(&self) -> Option<Guard<'_, T>> {
        match self.inner.try_lock() {
            Ok(g) => Some(Guard { inner: g }),
            Err(TryLockError::Poisoned(p)) => Some(Guard {
                inner: p.into_inner(),
            }),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Returns the value through a unique reference, without locking.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the value and removes the lock.
    pub fn into_inner(self) -> T {
        self.inner
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// A condition variable for [`Guard`] values.
#[derive(Debug, Default)]
pub struct Condvar {
    inner: imp::Condvar,
}

impl Condvar {
    /// Makes a condition variable.
    #[cfg(not(loom))]
    pub const fn new() -> Self {
        Self {
            inner: imp::Condvar::new(),
        }
    }

    /// Makes a condition variable. The `loom` constructor is not
    /// `const`.
    #[cfg(loom)]
    pub fn new() -> Self {
        Self {
            inner: imp::Condvar::new(),
        }
    }

    /// Releases the lock, waits for a notification and takes the lock
    /// again. A wakeup can be spurious, so the caller checks its condition
    /// in a loop.
    pub fn wait<'a, T>(&self, guard: Guard<'a, T>) -> Guard<'a, T> {
        Guard {
            inner: self
                .inner
                .wait(guard.inner)
                .unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Waits as [`Condvar::wait`] does, for at most `timeout`. The flag is
    /// true when the wait timed out. Under `loom` the wait never times
    /// out, so a model must notify every timed waiter.
    pub fn wait_timeout<'a, T>(
        &self,
        guard: Guard<'a, T>,
        timeout: Duration,
    ) -> (Guard<'a, T>, bool) {
        let (g, r) = self
            .inner
            .wait_timeout(guard.inner, timeout)
            .unwrap_or_else(PoisonError::into_inner);
        (Guard { inner: g }, r.timed_out())
    }

    /// Wakes one waiter.
    pub fn notify_one(&self) {
        self.inner.notify_one();
    }

    /// Wakes every waiter.
    pub fn notify_all(&self) {
        self.inner.notify_all();
    }
}
