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

//! Dispatch of a reply that no request waits for (ledger row DSP-08).
//!
//! C asserts when a normal reply comes and the sent queue is empty. The
//! core tears the connection down instead, and the session goes on.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use common::{Profile, cause, run_to_state};
use zk_proto::{Cause, State};

/// A reply frame with a normal xid: xid 9999, zxid 1, err 0.
fn stray_reply() -> Vec<u8> {
    let mut frame = 16i32.to_be_bytes().to_vec();
    frame.extend_from_slice(&9_999i32.to_be_bytes());
    frame.extend_from_slice(&1i64.to_be_bytes());
    frame.extend_from_slice(&0i32.to_be_bytes());
    frame
}

/// A stray reply with an empty FIFO tears down the link with
/// `Cause::XidMismatch` in every profile. That cause has the rc
/// ZRUNTIMEINCONSISTENCY. The client sends CONNECTING, connects again,
/// and keeps the session. Nothing panics.
///
/// Ledger: DSP-08
#[test]
fn reply_with_an_empty_fifo_tears_down_and_reconnects() {
    for p in Profile::ALL {
        let mut h = p.harness(0xd508);
        h.connect().unwrap();
        let before = h.recorder().session_states().len();
        let link = h.link().unwrap();
        h.server_mut().push_raw(link, stray_reply());
        h.run_until(|h| cause(h).is_some(), 1_000).unwrap();
        assert_eq!(cause(&h), Some(Cause::XidMismatch), "{p:?}");
        run_to_state(&mut h, State::Connected, 10_000);
        let states = h.recorder().session_states();
        assert_eq!(
            states[before..],
            [State::Connecting, State::Connected],
            "{p:?}"
        );
        // The session goes on: a request completes on the new link.
        let ops = h.ops();
        let r = h.call(ops.exists("/", None)).unwrap();
        assert_eq!(r.rc, 0, "{p:?}");
    }
}
