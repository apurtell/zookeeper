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

//! The token types and the hooks that a driver injects.
//!
//! The core calls the hooks under the driver lock. A hook must not block
//! and must not call application code.

use std::net::SocketAddr;

use crate::action::{SaslError, SaslStep};
use crate::log::LogLevel;

/// The opaque token types of one driver.
///
/// The core moves, compares and clones these values. It never looks
/// inside them.
pub trait Tokens {
    /// The completion of one request: an async callback or a sync waiter.
    /// It enters the core once and leaves it once.
    type Completion;
    /// The identity of a watcher. `==` is the deduplication relation.
    type Watcher: Clone + Eq;
    /// The completion of one `add_auth` call.
    type Auth;
}

/// The randomness source of the host list.
///
/// The drop-in driver forwards to the libc `random()` and `drand48()`
/// functions, so the libc call order stays the order of C.
pub trait Rng: Send {
    /// Marks the reseed point of the C `setup_random()`. The core calls it
    /// just before a shuffle.
    fn on_resolution(&mut self);
    /// Returns the next value of libc `random()`: `0..=2^31-1`.
    fn random(&mut self) -> i64;
    /// Returns the next value of libc `drand48()`: `[0, 1)`.
    fn drand48(&mut self) -> f64;
}

/// The log level filter.
///
/// The core makes a log record only when the filter enables its level.
pub trait LogFilter: Send {
    /// Returns true when records of this level are wanted.
    fn enabled(&self, level: LogLevel) -> bool;
}

/// The source of the default watcher.
///
/// The drop-in driver reads the C `(fn, ctx)` pair cell. The native client
/// returns `None`.
pub trait DefaultWatcher<W>: Send {
    /// Returns the default watcher as it is now.
    fn snapshot(&self) -> Option<W>;
}

/// The native SASL mechanism contract.
///
/// The native driver calls it with no core lock held. The drop-in driver
/// does not implement it: the C glue runs Cyrus SASL instead.
pub trait SaslSession: Send {
    /// Starts the mechanism and returns its name and first step.
    ///
    /// # Errors
    ///
    /// Returns the mechanism error. The core then fails the session.
    fn start(&mut self) -> Result<(String, SaslStep), SaslError>;

    /// Gives a server challenge to the mechanism and returns its answer.
    /// `None` stands for the server token of length -1.
    ///
    /// # Errors
    ///
    /// Returns the mechanism error. The core then fails the session.
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<SaslStep, SaslError>;

    /// Gives the connection of the next [`start`](Self::start).
    ///
    /// The native driver calls it just before `start`, with the
    /// connect-string host of the endpoint and the socket addresses of the
    /// SASL START item. The default ignores them. The zk-client adapter
    /// keeps them for its `SaslContext`.
    fn connection(&mut self, host: &[u8], local: SocketAddr, peer: SocketAddr) {
        let _ = (host, local, peer);
    }
}

/// A [`LogFilter`] that enables every level.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllLevels;

impl LogFilter for AllLevels {
    fn enabled(&self, _level: LogLevel) -> bool {
        true
    }
}

/// A [`LogFilter`] that enables no level.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoLevels;

impl LogFilter for NoLevels {
    fn enabled(&self, _level: LogLevel) -> bool {
        false
    }
}

/// A [`DefaultWatcher`] that has no default watcher.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDefaultWatcher;

impl<W> DefaultWatcher<W> for NoDefaultWatcher {
    fn snapshot(&self) -> Option<W> {
        None
    }
}
