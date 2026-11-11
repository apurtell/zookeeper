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

//! A teardown while a large frame is lent.
//!
//! The transmit lends a large plain frame to the driver in place of a
//! copy. The link resets at a random byte of the write stream, under a
//! random write chunk plan. Each request completes once. The client
//! connects again, and a new large set on the next transport reaches the
//! server whole.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod props_common;

use props_common::{Profile, check_once, config_cases, profile};
use proptest::prelude::*;
use zk_proto::{Reply, State};
use zk_testkit::{Chunking, Harness, Ticket};

/// The data length of the first large set. The frame is above the lend
/// limit (512 KiB).
const BIG: usize = 520 * 1024;
/// The data length of the large set on the next transport.
const BIG2: usize = 600 * 1024;
/// The data length of the small sets.
const SMALL: usize = 100;

/// The length of a set frame on the path `/a`: the prefix, the header,
/// the path, the data and the version.
fn set_frame_len(data: usize) -> usize {
    4 + 8 + (4 + 2) + (4 + data) + 4
}

/// Write chunk plans. The chunks are large, so a frame of 520 KiB needs
/// few writes.
fn chunking() -> impl Strategy<Value = Chunking> {
    prop_oneof![
        Just(Chunking::Whole),
        (1000usize..70_000).prop_map(Chunking::Fixed),
        (any::<u64>(), 1000usize..300_000).prop_map(|(seed, max)| Chunking::Seeded { seed, max }),
        proptest::collection::vec(0usize..200_000, 1..6).prop_map(Chunking::Script),
    ]
}

fn fail(e: impl std::fmt::Debug) -> TestCaseError {
    TestCaseError::fail(format!("{e:?}"))
}

fn data_of(h: &mut Harness) -> Result<Vec<u8>, TestCaseError> {
    let ops = h.ops();
    let r = h.call(ops.get_data("/a", None)).map_err(fail)?;
    prop_assert_eq!(r.rc, 0);
    match r.reply {
        Some(Reply::Data { data, .. }) => Ok(data.as_bytes().unwrap_or_default().to_vec()),
        other => Err(fail(other)),
    }
}

fn run(
    p: Profile,
    seed: u64,
    tx: Chunking,
    before: usize,
    after: usize,
    cut: usize,
) -> Result<(), TestCaseError> {
    let mut h = p.builder(seed).tx_chunking(tx).build();
    h.connect().map_err(fail)?;
    h.server_mut().create("/a", b"x", 0).map_err(fail)?;
    let ops = h.ops();
    let mut tickets: Vec<Ticket> = Vec::new();
    for _ in 0..before {
        tickets.push(
            h.submit(ops.set_data("/a", &[1; SMALL], -1))
                .map_err(fail)?,
        );
    }
    let big = vec![0x11; BIG];
    tickets.push(h.submit(ops.set_data("/a", &big, -1)).map_err(fail)?);
    for _ in 0..after {
        tickets.push(
            h.submit(ops.set_data("/a", &[2; SMALL], -1))
                .map_err(fail)?,
        );
    }
    // The cut falls inside the queued frames, so the reset always occurs.
    let total = (before + after) * set_frame_len(SMALL) + set_frame_len(BIG);
    h.reset_after_bytes(cut % total);
    let want = tickets.clone();
    h.run_until(
        move |h| want.iter().all(|t| h.recorder().completion_count(*t) > 0),
        60_000,
    )
    .map_err(fail)?;
    h.run_until(|h| h.state() == State::Connected, 60_000)
        .map_err(fail)?;

    // The next transport carries a new large frame whole.
    let new = vec![0x22; BIG2];
    let r = h.call(ops.set_data("/a", &new, -1)).map_err(fail)?;
    prop_assert_eq!(r.rc, 0);
    prop_assert!(
        data_of(&mut h)? == new,
        "the large set reached the server whole"
    );
    let f = h.finish();
    check_once(&f)?;
    Ok(())
}

proptest! {
    #![proptest_config(config_cases(48, 0x5eed_0b05))]

    // A lent frame stays pinned, and it can fail. The teardown stage T1
    // clears the pins, and T3 takes every frame before the next transport.
    // No byte of the old frames goes onto the next transport.
    #[test]
    fn a_reset_while_a_frame_is_lent_is_safe(
        p in profile(),
        seed in any::<u64>(),
        tx in chunking(),
        before in 0usize..3,
        after in 0usize..3,
        cut in any::<usize>(),
    ) {
        run(p, seed, tx, before, after, cut)?;
    }
}
