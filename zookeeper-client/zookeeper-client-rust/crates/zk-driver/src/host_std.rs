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

//! `StdHostLeaves`: host leaves over std for the native drivers and the
//! tests.
//!
//! zk-client normally gives its `Resolve` adapter. This type is the
//! default when the application gives no resolver: `resolve` uses
//! `std::net::ToSocketAddrs` (`getaddrinfo`), and the other leaves have
//! the native defaults.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use zk_proto::{ClientId, HostResolution, HostSpec, LogLevel, ResolveError, Tokens};

use crate::host::{Discarded, HostLeaves};
use crate::sync::{Mutex, Unlocked};

/// The `getaddrinfo` rc that a failed native resolution reports
/// (`EAI_NONAME`). glibc and musl use -2. The BSDs and macOS use 8.
#[cfg(target_os = "linux")]
pub const EAI_NONAME: i32 = -2;

/// The `getaddrinfo` rc that a failed native resolution reports
/// (`EAI_NONAME`). glibc and musl use -2. The BSDs and macOS use 8.
#[cfg(not(target_os = "linux"))]
pub const EAI_NONAME: i32 = 8;

/// The increment of the SplitMix64 generator.
const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// The bits of `1.0` as an `f64`. The mantissa bits then give [1, 2).
const ONE_BITS: u64 = 0x3FF0_0000_0000_0000;

/// A process-wide counter. Two seeds in the same clock tick differ.
static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Host leaves over std.
#[derive(Debug)]
pub struct StdHostLeaves {
    /// True for `ServerOrder::AsGiven`: no shuffle.
    pub permute_disabled: bool,
    /// The lowest level that the host wants, or `None` for no records.
    pub log_level: Option<LogLevel>,
    /// The state of the leaf random generator.
    pub(crate) rng: Mutex<u64>,
}

impl StdHostLeaves {
    /// Makes the leaves with the shuffle on, no log records and a seed
    /// from the clock and the pid.
    #[must_use]
    pub fn new() -> Self {
        Self {
            permute_disabled: false,
            log_level: None,
            rng: Mutex::new(fresh_seed()),
        }
    }

    /// Returns the next SplitMix64 value.
    fn next_u64(&self) -> u64 {
        let mut state = self.rng.lock_owner();
        *state = state.wrapping_add(GOLDEN_GAMMA);
        mix(*state)
    }
}

impl Default for StdHostLeaves {
    fn default() -> Self {
        Self::new()
    }
}

/// The SplitMix64 output function.
fn mix(mut z: u64) -> u64 {
    z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ z.wrapping_shr(31)
}

/// Makes a seed from the wall clock, the pid and the process counter.
/// The seed is not secret. It only spreads clients over the host list.
fn fresh_seed() -> u64 {
    let clock = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| {
        d.as_secs()
            .wrapping_mul(1_000_000_000)
            .wrapping_add(u64::from(d.subsec_nanos()))
    });
    let pid = u64::from(std::process::id()).rotate_left(32);
    let count = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
    mix(clock ^ pid ^ mix(count))
}

/// Returns the port of one host entry. A legacy port outside `u16`
/// gives `None`.
fn entry_port(spec: &HostSpec) -> Option<u16> {
    match spec {
        HostSpec::Legacy(h) => u16::try_from(h.port).ok(),
        HostSpec::Native(h) => Some(h.port),
    }
}

/// Resolves one host and port with `ToSocketAddrs`, in resolver order.
fn lookup(spec: &HostSpec) -> Result<Vec<SocketAddr>, ResolveError> {
    let not_found = |errno: i32| ResolveError {
        gai_rc: EAI_NONAME,
        errno,
    };
    let host = std::str::from_utf8(spec.host_bytes()).map_err(|_| not_found(0))?;
    let port = entry_port(spec).ok_or_else(|| not_found(0))?;
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| not_found(e.raw_os_error().unwrap_or(0)))?
        .collect();
    if addrs.is_empty() {
        Err(not_found(0))
    } else {
        Ok(addrs)
    }
}

impl<T: Tokens> HostLeaves<T> for StdHostLeaves {
    /// Drops the token. A native token owns no C state.
    fn discard_token(&self, token: Discarded<T>) {
        drop(token);
    }

    /// The native client has no default watcher token.
    fn snapshot_default_watcher(&self) -> Option<T::Watcher> {
        None
    }

    /// The native client reads the identity from the connection.
    fn store_client_id(&self, _id: &ClientId) {}

    fn log_enabled(&self, level: LogLevel) -> bool {
        self.log_level.is_some_and(|max| level.code() <= max.code())
    }

    fn conn_permute_disabled(&self) -> bool {
        self.permute_disabled
    }

    /// The top 31 bits of the next value, as libc `random()` gives.
    fn rng_random(&self) -> i64 {
        i64::try_from(self.next_u64().wrapping_shr(33)).unwrap_or(0)
    }

    /// The top 52 bits of the next value as the mantissa of [1, 2), less
    /// one.
    fn rng_drand48(&self) -> f64 {
        f64::from_bits(ONE_BITS | self.next_u64().wrapping_shr(12)) - 1.0
    }

    /// Mixes a fresh seed into the state, as C `setup_random` reseeds the
    /// libc generators.
    fn rng_reseed(&self, _proof: &Unlocked) {
        let seed = fresh_seed();
        let mut state = self.rng.lock_owner();
        *state = mix(*state ^ seed);
    }

    /// Resolves one entry with `ToSocketAddrs`. An error maps to
    /// `ResolveError{gai_rc: EAI_NONAME, errno}` on the native path. The
    /// leaf logs nothing, because the core logs each failed host entry.
    fn resolve(&self, _proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution {
        HostResolution {
            host,
            result: lookup(spec),
            skipped_families: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use zk_testkit::tokens::TestTokens;

    #[test]
    fn reseed_changes_the_stream() {
        let a = StdHostLeaves::new();
        *a.rng.lock_owner() = 42;
        let b = StdHostLeaves::new();
        *b.rng.lock_owner() = 42;
        assert_eq!(
            HostLeaves::<TestTokens>::rng_random(&a),
            HostLeaves::<TestTokens>::rng_random(&b)
        );
        HostLeaves::<TestTokens>::rng_reseed(&b, &Unlocked::new_at_entry());
        let xs: Vec<i64> = (0..4)
            .map(|_| HostLeaves::<TestTokens>::rng_random(&a))
            .collect();
        let ys: Vec<i64> = (0..4)
            .map(|_| HostLeaves::<TestTokens>::rng_random(&b))
            .collect();
        assert_ne!(xs, ys);
    }

    #[test]
    fn two_new_leaves_have_different_seeds() {
        let a = StdHostLeaves::new();
        let b = StdHostLeaves::new();
        assert_ne!(*a.rng.lock_owner(), *b.rng.lock_owner());
    }
}
