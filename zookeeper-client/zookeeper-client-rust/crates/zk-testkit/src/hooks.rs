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

//! Log filter and default watcher hooks that a test can change while the
//! core owns them.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use zk_proto::{DefaultWatcher, LogFilter, LogLevel};

use crate::tokens::WatcherId;

/// A fixed log filter: it enables each level up to `max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LevelFilter {
    max: Option<LogLevel>,
}

impl LevelFilter {
    /// Enables the levels up to and including `max`.
    #[must_use]
    pub const fn up_to(max: LogLevel) -> Self {
        Self { max: Some(max) }
    }

    /// Enables no level.
    #[must_use]
    pub const fn off() -> Self {
        Self { max: None }
    }
}

impl LogFilter for LevelFilter {
    fn enabled(&self, level: LogLevel) -> bool {
        self.max.is_some_and(|m| level.code() <= m.code())
    }
}

/// A log filter that the test can change at any time.
///
/// The value is the C `ZOO_LOG_LEVEL_*` code. The value 0 enables no level.
#[derive(Clone, Debug, Default)]
pub struct SharedLogFilter {
    level: Arc<AtomicI32>,
}

impl SharedLogFilter {
    /// Makes a filter that enables the levels up to `max`.
    #[must_use]
    pub fn new(max: Option<LogLevel>) -> Self {
        let f = Self::default();
        f.set(max);
        f
    }

    /// Changes the highest enabled level.
    pub fn set(&self, max: Option<LogLevel>) {
        self.level
            .store(max.map_or(0, LogLevel::code), Ordering::SeqCst);
    }

    /// Returns the highest enabled level code.
    #[must_use]
    pub fn get(&self) -> i32 {
        self.level.load(Ordering::SeqCst)
    }
}

impl LogFilter for SharedLogFilter {
    fn enabled(&self, level: LogLevel) -> bool {
        level.code() <= self.get()
    }
}

/// A default watcher slot that the test can change at any time.
#[derive(Clone, Debug, Default)]
pub struct SharedDefaultWatcher {
    slot: Arc<Mutex<Option<WatcherId>>>,
}

impl SharedDefaultWatcher {
    /// Makes a slot with this watcher.
    #[must_use]
    pub fn new(w: Option<WatcherId>) -> Self {
        let s = Self::default();
        s.set(w);
        s
    }

    /// Changes the default watcher.
    pub fn set(&self, w: Option<WatcherId>) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = w;
    }

    /// Returns the default watcher.
    #[must_use]
    pub fn get(&self) -> Option<WatcherId> {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl DefaultWatcher<WatcherId> for SharedDefaultWatcher {
    fn snapshot(&self) -> Option<WatcherId> {
        self.get()
    }
}
