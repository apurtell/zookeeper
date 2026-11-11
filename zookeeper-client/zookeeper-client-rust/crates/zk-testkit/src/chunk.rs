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

//! Chunking plans for the in-memory byte pipe.
//!
//! A real socket splits a byte stream at any point. The chunker gives the
//! same freedom with a fixed plan, so each test run sees the same splits.

use crate::rng::SplitMix;

/// How the pipe splits the bytes of one direction.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Chunking {
    /// Each read or write moves all the available bytes.
    #[default]
    Whole,
    /// Each read or write moves at most this many bytes. The value 0 acts
    /// as 1.
    Fixed(usize),
    /// Each read or write moves a seeded number of bytes in `1..=max`.
    Seeded {
        /// The seed of the boundaries.
        seed: u64,
        /// The largest chunk. The value 0 acts as 1.
        max: usize,
    },
    /// The sizes come from the list in order, and the list repeats. A zero
    /// entry acts as 1. An empty list acts as [`Chunking::Whole`].
    Script(Vec<usize>),
}

impl Chunking {
    /// Each read or write moves one byte.
    pub const ONE_BYTE: Self = Self::Fixed(1);
}

/// Gives the chunk sizes of one [`Chunking`] plan.
#[derive(Clone, Debug)]
pub struct Chunker {
    plan: Chunking,
    rng: SplitMix,
    pos: usize,
}

impl Chunker {
    /// Makes a chunker for this plan.
    #[must_use]
    pub fn new(plan: Chunking) -> Self {
        let seed = match &plan {
            Chunking::Seeded { seed, .. } => *seed,
            Chunking::Whole | Chunking::Fixed(_) | Chunking::Script(_) => 0,
        };
        Self {
            plan,
            rng: SplitMix::new(seed),
            pos: 0,
        }
    }

    /// Returns the plan.
    #[must_use]
    pub const fn plan(&self) -> &Chunking {
        &self.plan
    }

    /// Returns the size of the next chunk.
    ///
    /// The result is in `1..=available`. It is 0 only when `available` is
    /// 0, and then the plan does not move.
    pub fn next_len(&mut self, available: usize) -> usize {
        if available == 0 {
            return 0;
        }
        let want = match &self.plan {
            Chunking::Whole => available,
            Chunking::Fixed(n) => (*n).max(1),
            Chunking::Seeded { max, .. } => self.rng.range_usize(1, (*max).max(1)),
            Chunking::Script(list) => {
                let len = list.len();
                let at = self.pos.checked_rem(len).unwrap_or(0);
                self.pos = self.pos.wrapping_add(1);
                list.get(at).copied().map_or(available, |n| n.max(1))
            }
        };
        want.clamp(1, available)
    }

    /// Splits `bytes` into chunks with this plan.
    pub fn split<'a>(&mut self, bytes: &'a [u8]) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = self.next_len(rest.len());
            let (head, tail) = rest.split_at(n.min(rest.len()));
            out.push(head);
            rest = tail;
        }
        out
    }
}
