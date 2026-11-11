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

//! Shared helpers of the C parity tests. These tests re-express the
//! legacy C suites TestOperations, TestWatchers, TestZookeeperInit and
//! TestZookeeperClose on the sans-IO harness.

#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use zk_jute::opcode;
use zk_proto::{Output, State};
use zk_testkit::server::InboundKind;
use zk_testkit::{Harness, Ticket, WatcherId};

/// The event types of `WatchedEvent`.
pub(crate) const CREATED: i32 = 1;
pub(crate) const DELETED: i32 = 2;
pub(crate) const CHANGED: i32 = 3;
pub(crate) const CHILD: i32 = 4;

/// The xid of a ping reply.
const PING_XID: i32 = -2;

/// Returns the arrival times of the PING requests at the server.
pub(crate) fn ping_times(h: &Harness) -> Vec<u64> {
    h.server()
        .inbound()
        .iter()
        .filter(|f| matches!(f.kind, InboundKind::Request { op, .. } if op == opcode::PING))
        .map(|f| f.at.0)
        .collect()
}

/// Returns the arrival time of the last frame at the server. The harness
/// moves bytes in the step that writes them, so this is the time of the
/// last client send.
pub(crate) fn last_send_at(h: &Harness) -> u64 {
    h.server().inbound().last().map(|f| f.at.0).unwrap()
}

/// Returns a framed `ConnectResponse` as the C mock `HandshakeResponse`
/// writes it. With `read_only` set to `None`, the frame has no read-only
/// byte, so the body has 36 bytes instead of 37.
pub(crate) fn connect_response(timeout: i32, session: i64, read_only: Option<bool>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_i32.to_be_bytes());
    body.extend_from_slice(&timeout.to_be_bytes());
    body.extend_from_slice(&session.to_be_bytes());
    body.extend_from_slice(&16_i32.to_be_bytes());
    body.extend_from_slice(b"1234567890123456");
    if let Some(ro) = read_only {
        body.push(u8::from(ro));
    }
    framed(&body)
}

/// Returns a framed ping reply: xid -2, zxid 0 and rc 0.
pub(crate) fn ping_reply() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&PING_XID.to_be_bytes());
    body.extend_from_slice(&0_i64.to_be_bytes());
    body.extend_from_slice(&0_i32.to_be_bytes());
    framed(&body)
}

/// Puts the 4-byte length prefix in front of `body`.
pub(crate) fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// Returns the number of watch and session deliveries to `w` after the
/// record mark `mark`.
pub(crate) fn deliveries(h: &Harness, mark: usize, w: WatcherId) -> usize {
    h.recorder()
        .outputs_since(mark)
        .map(|o| match o {
            Output::Watch { watchers, .. } | Output::Session { watchers, .. } => {
                watchers.iter().filter(|x| **x == w).count()
            }
            _ => 0,
        })
        .sum()
}

/// Returns the session events after `mark` as (state, watchers) pairs.
pub(crate) fn sessions_since(h: &Harness, mark: usize) -> Vec<(State, Vec<WatcherId>)> {
    h.recorder()
        .outputs_since(mark)
        .filter_map(|o| match o {
            Output::Session {
                state, watchers, ..
            } => Some((*state, watchers.clone())),
            _ => None,
        })
        .collect()
}

/// Returns the watch events after `mark` as (type, path, watchers).
pub(crate) fn watches_since(h: &Harness, mark: usize) -> Vec<(i32, String, Vec<WatcherId>)> {
    h.recorder()
        .outputs_since(mark)
        .filter_map(|o| match o {
            Output::Watch {
                event, watchers, ..
            } => {
                let p = event.path.as_bytes().unwrap_or_default();
                Some((
                    event.event_type,
                    String::from_utf8_lossy(p).into_owned(),
                    watchers.clone(),
                ))
            }
            _ => None,
        })
        .collect()
}

/// Returns true when the output is the completion of `t`.
pub(crate) fn is_completion_of(o: &Output<zk_testkit::TestTokens>, t: Ticket) -> bool {
    matches!(o, Output::Completion { token, .. } if token.ticket() == t)
}

/// Runs the harness until it is connected and records each new state on
/// the way. The list starts with the state before the first step.
pub(crate) fn connect_states(h: &mut Harness) -> Vec<State> {
    let mut seen = vec![h.state()];
    h.run_until(
        |h| {
            let s = h.state();
            if seen.last() != Some(&s) {
                seen.push(s);
            }
            s.is_connected()
        },
        10_000,
    )
    .unwrap();
    seen
}
