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

//! The host leaves: the services that the driver gets from its host.
//!
//! zk-ffi implements [`HostLeaves`] over the final host vtable for the
//! drop-in drivers. The native drivers use the zk-client `Resolve` adapter
//! or [`crate::host_std::StdHostLeaves`].
//!
//! The Pure leaves never block and never reach application code. The
//! Blocking leaves take the [`Unlocked`] proof, so they run with no driver
//! lock held. No leaf reaches application code or the log
//! callback.

use std::sync::Arc;

use zk_proto::{
    ClientId, Connection, DefaultWatcher, HostResolution, HostSpec, LogArg, LogFilter, LogLevel,
    LogRecord, LogSite, Output, Rng, Tokens,
};

use crate::sync::Unlocked;

/// The token bounds of every driver.
///
/// A driver moves tokens between threads, so each token type is `Send`.
/// The blanket implementation covers every [`Tokens`] type that meets
/// the bounds.
pub trait DriverTokens:
    Tokens<Completion: Send, Watcher: Send, Auth: Send> + Send + Sync + 'static
{
}

impl<T> DriverTokens for T
where
    T: Tokens + Send + Sync + 'static,
    T::Completion: Send,
    T::Watcher: Send,
    T::Auth: Send,
{
}

/// A token that the driver drops without a callback.
///
/// zk-ffi completes a sync record in a dropped completion with ZCLOSING,
/// so a waiter never hangs.
#[derive(Debug)]
pub enum Discarded<T: Tokens> {
    /// A completion token.
    Completion(T::Completion),
    /// A watcher token.
    Watcher(T::Watcher),
    /// An `add_auth` completion token.
    Auth(T::Auth),
}

/// The host services of one handle.
pub trait HostLeaves<T: Tokens>: Send + Sync {
    /// Pure. Releases a token that the driver drops without a callback.
    fn discard_token(&self, token: Discarded<T>);

    /// Pure. Returns the default watcher as it is now.
    fn snapshot_default_watcher(&self) -> Option<T::Watcher>;

    /// Pure. Stores the session identity that the handshake adopted.
    fn store_client_id(&self, id: &ClientId);

    /// Pure. Returns true when the host wants records of this level.
    fn log_enabled(&self, level: LogLevel) -> bool;

    /// Pure. Returns true when the host list must keep its given order.
    fn conn_permute_disabled(&self) -> bool;

    /// Pure. Returns the next value of libc `random()`.
    fn rng_random(&self) -> i64;

    /// Pure. Returns the next value of libc `drand48()`.
    fn rng_drand48(&self) -> f64;

    /// Blocking. Reseeds the libc generators, as C `setup_random` does.
    ///
    /// The driver calls it before `handle_resolved` when the shuffle is on
    /// and at least one address resolved.
    fn rng_reseed(&self, proof: &Unlocked);

    /// Blocking. Resolves one host entry.
    ///
    /// The result is data. The leaf logs nothing: the core emits the
    /// resolver line from the result. `host` is the index of the
    /// entry in the host list.
    fn resolve(&self, proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution;
}

/// The core [`Rng`] over the host leaves.
///
/// `on_resolution` does nothing. The driver calls the `rng_reseed` leaf
/// itself before `handle_resolved`, with no lock held.
pub struct HostRng<T: Tokens> {
    host: Arc<dyn HostLeaves<T>>,
}

impl<T: Tokens> HostRng<T> {
    /// Makes the adapter.
    #[must_use]
    pub fn new(host: Arc<dyn HostLeaves<T>>) -> Self {
        Self { host }
    }
}

impl<T: Tokens> Rng for HostRng<T> {
    fn on_resolution(&mut self) {}

    fn random(&mut self) -> i64 {
        self.host.rng_random()
    }

    fn drand48(&mut self) -> f64 {
        self.host.rng_drand48()
    }
}

/// The core [`LogFilter`] over the `log_enabled` leaf.
pub struct HostLogFilter<T: Tokens> {
    host: Arc<dyn HostLeaves<T>>,
}

impl<T: Tokens> HostLogFilter<T> {
    /// Makes the adapter.
    #[must_use]
    pub fn new(host: Arc<dyn HostLeaves<T>>) -> Self {
        Self { host }
    }
}

impl<T: Tokens> LogFilter for HostLogFilter<T> {
    fn enabled(&self, level: LogLevel) -> bool {
        self.host.log_enabled(level)
    }
}

/// The core [`DefaultWatcher`] over the `snapshot_default_watcher` leaf.
pub struct HostDefaultWatcher<T: Tokens> {
    host: Arc<dyn HostLeaves<T>>,
}

impl<T: Tokens> HostDefaultWatcher<T> {
    /// Makes the adapter.
    #[must_use]
    pub fn new(host: Arc<dyn HostLeaves<T>>) -> Self {
        Self { host }
    }
}

impl<T: Tokens> DefaultWatcher<T::Watcher> for HostDefaultWatcher<T> {
    fn snapshot(&self) -> Option<T::Watcher> {
        self.host.snapshot_default_watcher()
    }
}

/// The three core hooks of `Connection::new`.
pub type ConnectionHooks<T> = (
    Box<dyn Rng>,
    Box<dyn LogFilter>,
    Box<dyn DefaultWatcher<<T as Tokens>::Watcher>>,
);

/// Makes the core hooks of `Connection::new` from the host leaves.
#[must_use]
pub fn connection_hooks<T: DriverTokens>(host: &Arc<dyn HostLeaves<T>>) -> ConnectionHooks<T> {
    (
        Box::new(HostRng::new(Arc::clone(host))),
        Box::new(HostLogFilter::new(Arc::clone(host))),
        Box::new(HostDefaultWatcher::new(Arc::clone(host))),
    )
}

/// Makes a driver log record, or `None` when the host does not want its
/// level.
///
/// The driver emits diagnostics only as core records with a core site.
/// The record has the level of its site.
pub fn log_record<T: Tokens>(
    host: &dyn HostLeaves<T>,
    site: LogSite,
    args: Vec<LogArg>,
) -> Option<LogRecord> {
    let level = site.level();
    host.log_enabled(level)
        .then_some(LogRecord { site, level, args })
}

/// Gives each token that stays in the connection to `discard_token`
/// (legacy `destroy`, zookeeper.c:689-710). The order is the
/// completions, then the auth entries, then the outputs that no pump
/// took.
pub(crate) fn discard_leftovers<T: Tokens>(host: &dyn HostLeaves<T>, conn: Box<Connection<T>>) {
    let left = conn.into_leftovers();
    for token in left.completions {
        host.discard_token(Discarded::Completion(token));
    }
    for token in left.auth {
        host.discard_token(Discarded::Auth(token));
    }
    for output in left.outputs {
        match output {
            Output::Completion { token, .. } => host.discard_token(Discarded::Completion(token)),
            Output::Auth { tokens, .. } => {
                for token in tokens {
                    host.discard_token(Discarded::Auth(token));
                }
            }
            Output::Watch { watchers, .. }
            | Output::Session { watchers, .. }
            | Output::WatchTerminated { watchers, .. } => {
                for w in watchers {
                    host.discard_token(Discarded::Watcher(w));
                }
            }
            Output::AuthLockpoint | Output::ClientId(_) | Output::Log(_) | Output::DrainPoint => {}
        }
    }
}
