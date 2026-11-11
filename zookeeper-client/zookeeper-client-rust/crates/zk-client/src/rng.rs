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

//! `NativeRng`: the per-client random source.
//!
//! The generator is SplitMix64 over an atomic state, so the host leaves
//! can use it through `&self`. The seed comes from the hasher keys of
//! `RandomState`, which std draws from the OS. No process-wide state
//! changes, so two clients never share a sequence.

use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};

/// The SplitMix64 increment.
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

/// A per-client SplitMix64 generator.
#[derive(Debug)]
pub(crate) struct NativeRng {
    state: AtomicU64,
}

impl NativeRng {
    /// Makes a generator with a seed from `RandomState`.
    pub(crate) fn new() -> Self {
        let seed = std::collections::hash_map::RandomState::new().hash_one(0x5A4B_u64);
        Self::with_seed(seed)
    }

    /// Makes a generator with a fixed seed, for tests.
    pub(crate) fn with_seed(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed),
        }
    }

    /// Returns the next 64 random bits.
    pub(crate) fn next_u64(&self) -> u64 {
        let s = self
            .state
            .fetch_add(GOLDEN, Ordering::Relaxed)
            .wrapping_add(GOLDEN);
        let mut z = s;
        z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ z.wrapping_shr(31)
    }

    /// Returns a value in `0..=2^31-1`, as libc `random()` does.
    pub(crate) fn random(&self) -> i64 {
        i64::try_from(self.next_u64().wrapping_shr(33)).unwrap_or(0)
    }

    /// Returns a value in `[0, 1)`, as libc `drand48()` does.
    pub(crate) fn drand48(&self) -> f64 {
        let bits = 0x3FF0_0000_0000_0000_u64 | self.next_u64().wrapping_shr(12);
        f64::from_bits(bits) - 1.0
    }
}

impl zk_proto::Rng for NativeRng {
    fn on_resolution(&mut self) {}

    fn random(&mut self) -> i64 {
        NativeRng::random(self)
    }

    fn drand48(&mut self) -> f64 {
        NativeRng::drand48(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_stay_in_range() {
        let r = NativeRng::with_seed(1);
        for _ in 0..10_000 {
            let v = r.random();
            assert!((0..=0x7FFF_FFFF).contains(&v));
            let d = r.drand48();
            assert!((0.0..1.0).contains(&d));
        }
    }

    #[test]
    fn two_generators_differ() {
        let a = NativeRng::new();
        let b = NativeRng::new();
        let xa: Vec<u64> = (0..4).map(|_| a.next_u64()).collect();
        let xb: Vec<u64> = (0..4).map(|_| b.next_u64()).collect();
        assert_ne!(xa, xb);
    }

    #[test]
    fn a_fixed_seed_repeats() {
        let a = NativeRng::with_seed(42);
        let b = NativeRng::with_seed(42);
        assert_eq!(a.next_u64(), b.next_u64());
    }
}
