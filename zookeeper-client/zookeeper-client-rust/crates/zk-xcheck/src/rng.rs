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

//! A small seeded generator for the randomized cross-checks.
//!
//! The generator is SplitMix64. It is fast, has no dependencies and gives
//! the same sequence for the same seed on all targets.

/// The SplitMix64 generator.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a generator from a seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Gives the next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Gives a value in `0..n`, or 0 when `n` is 0.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64().checked_rem(n).unwrap_or(0)
    }

    /// Gives an index in `0..n`, or 0 when `n` is 0.
    pub fn index(&mut self, n: usize) -> usize {
        let n64 = u64::try_from(n).unwrap_or(u64::MAX);
        usize::try_from(self.below(n64)).unwrap_or(0)
    }

    /// Gives true with the probability `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    /// Gives a value in the range of C `random()`: 0 to 2^31 - 1.
    pub fn c_random(&mut self) -> i64 {
        i64::try_from(self.next_u64() >> 33).unwrap_or(0)
    }

    /// Gives a value in `[0, 1)` with 53 random bits, as `drand48()` gives.
    pub fn unit_f64(&mut self) -> f64 {
        let bits = self.next_u64() >> 11;
        // 2^53 is exact in f64, and so is each value below it.
        let top = u32::try_from(bits >> 21).unwrap_or(0);
        let low = u32::try_from(bits & 0x1f_ffff).unwrap_or(0);
        (f64::from(top) * 2_097_152.0 + f64::from(low)) / 9_007_199_254_740_992.0
    }

    /// Picks one item of a slice.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.get(self.index(items.len()))
    }
}
