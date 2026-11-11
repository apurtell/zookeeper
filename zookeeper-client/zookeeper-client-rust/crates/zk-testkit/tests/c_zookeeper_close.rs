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

//! Parity tests for the legacy suite TestZookeeperClose.cc
//! (`Zookeeper_close`). The C suite checks with free and pthread mocks
//! that `zookeeper_close` frees the handle once, sends the close request
//! only on a live session, and joins the threads. Rust has no manual
//! free, so these tests check the protocol part on the sans-IO core:
//! the CLOSE request, the transport close, the completions and the
//! leftovers. The conformance case `close.c` checks the thread count
//! after a close (TH-01).

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
mod parity_g2;

use std::cell::Cell;
use std::rc::Rc;

use common::{Profile, connects};
use parity_g2::{connect_states, sessions_since};
use zk_jute::{opcode, rc};
use zk_proto::{CLOSE_FLUSH_MS, CLOSE_WAIT_MS, Output, State};
use zk_testkit::server::{Rule, RuleAction};
use zk_testkit::{ActionRecord, ConnectStyle, Harness, WatcherId};

/// The default watcher of each test.
const W0: WatcherId = WatcherId::new(40, 0);

fn transport_closes(h: &Harness) -> usize {
    h.recorder()
        .actions()
        .filter(|a| matches!(a, ActionRecord::CloseTransport))
        .count()
}

/// Zookeeper_close::testCloseUnconnected. A close before the first step
/// sends nothing and opens no transport. It leaves no completion and no
/// output behind.
#[test]
fn test_close_unconnected() {
    for p in Profile::LEGACY {
        let mut h = p.builder(401).default_watcher(Some(W0)).build();
        assert_eq!(h.state(), State::NotConnected, "{p:?}");
        h.close().unwrap();
        assert_eq!(connects(&h), 0, "{p:?}");
        assert_eq!(transport_closes(&h), 0, "{p:?}");
        assert!(sessions_since(&h, 0).is_empty(), "{p:?}");
        let f = h.finish();
        assert!(f.server.inbound().is_empty(), "{p:?}");
        assert!(f.leftovers.completions.is_empty(), "{p:?}");
        assert!(f.leftovers.outputs.is_empty(), "{p:?}");
    }
}

/// Zookeeper_close::testCloseUnconnected1. The session is connected,
/// but the server reads nothing after the handshake. The close puts one
/// CLOSE request on the wire and does not wait for a reply longer than
/// the C flush and wait bounds.
#[test]
fn test_close_unconnected1() {
    for p in Profile::LEGACY {
        let mut h = p.harness(402);
        h.connect().unwrap();
        h.pause_reads(true);
        let start = h.now().0;
        h.close().unwrap();
        let spent = h.now().0 - start;
        assert!(
            spent <= u64::from(CLOSE_FLUSH_MS + CLOSE_WAIT_MS),
            "{p:?}: {spent}"
        );
        assert_eq!(h.server().request_count(opcode::CLOSE), 1, "{p:?}");
        assert_eq!(transport_closes(&h), 1, "{p:?}");
        let f = h.finish();
        assert!(f.leftovers.completions.is_empty(), "{p:?}");
    }
}

/// Zookeeper_close::testCloseConnected1. The connect goes through
/// NOTCONNECTED, CONNECTING, ASSOCIATING and CONNECTED. The close then
/// sends one CLOSE request, the server ends the session, and the core
/// closes the transport once.
#[test]
fn test_close_connected1() {
    for p in Profile::LEGACY {
        let mut h = p.harness(403);
        // The TCP connect and the handshake reply take time, so that each
        // state is visible to the test for at least one step.
        h.net_mut()
            .set_connect_style(ConnectStyle::InProgress { delay_ms: 5 });
        h.server_mut()
            .add_rule(Rule::on_connect().then(RuleAction::Delay(5)));
        let states = connect_states(&mut h);
        assert_eq!(
            states,
            vec![
                State::NotConnected,
                State::Connecting,
                State::Associating,
                State::Connected
            ],
            "{p:?}"
        );
        assert_eq!(h.server().sessions().len(), 1, "{p:?}");
        h.close().unwrap();
        assert_eq!(h.server().request_count(opcode::CLOSE), 1, "{p:?}");
        assert!(h.server().sessions().is_empty(), "{p:?}");
        assert_eq!(transport_closes(&h), 1, "{p:?}");
        h.expect_exactly_once().unwrap();
    }
}

/// Expires the session at the server and runs until the core reports
/// the expiry. A hook calls `begin_close` from the EXPIRED session event
/// when `close_in_watcher` is set, as the C watcher calls
/// `zookeeper_close`. It returns the record mark before the expiry.
fn expire(h: &mut Harness, close_in_watcher: bool) -> (usize, Rc<Cell<bool>>) {
    let fired = Rc::new(Cell::new(false));
    if close_in_watcher {
        let seen = Rc::clone(&fired);
        h.set_hook(Box::new(move |ctx, o| {
            if matches!(
                o,
                Output::Session {
                    state: State::ExpiredSession,
                    ..
                }
            ) && !seen.get()
            {
                seen.set(true);
                ctx.conn.begin_close(ctx.now);
            }
        }));
    }
    let mark = h.recorder().mark();
    let sid = h.server().sessions()[0];
    h.server_mut().expire_session(sid);
    h.run_until(|h| h.state() == State::ExpiredSession, 20_000)
        .unwrap();
    (mark, fired)
}

/// Zookeeper_close::testCloseFromWatcher1. The session expires, and the
/// default watcher closes the handle from the EXPIRED event. The close
/// sends no CLOSE request, because the session is gone. The core refuses
/// a request after the expiry, and nothing stays behind.
#[test]
fn test_close_from_watcher1() {
    for p in Profile::LEGACY {
        let mut h = p.builder(404).default_watcher(Some(W0)).build();
        h.connect().unwrap();
        let (mark, fired) = expire(&mut h, true);
        assert!(fired.get(), "{p:?}");
        let ops = h.ops();
        let late = h.submit(ops.exists("/", None));
        h.clear_hook();
        h.close().unwrap();
        assert_eq!(
            sessions_since(&h, mark).last(),
            Some(&(State::ExpiredSession, vec![W0])),
            "{p:?}"
        );
        assert_eq!(h.server().request_count(opcode::CLOSE), 0, "{p:?}");
        // The expired session is unrecoverable, so the core refuses the
        // request at the validate stage.
        assert_eq!(
            late.map(|_| ()).map_err(|r| r.code),
            Err(rc::ZINVALIDSTATE),
            "{p:?}"
        );
        h.expect_exactly_once().unwrap();
        let f = h.finish();
        assert!(f.leftovers.completions.is_empty(), "{p:?}");
    }
}

/// Zookeeper_close::testIOThreadStoppedOnExpire (multi-threaded only).
/// After the expiry the default watcher gets one EXPIRED event, and the
/// core makes no new connect. The handle stays valid until the close,
/// and the close sends no CLOSE request.
#[test]
fn test_io_thread_stopped_on_expire() {
    let mut h = Profile::Mt.builder(405).default_watcher(Some(W0)).build();
    h.connect().unwrap();
    let (mark, _) = expire(&mut h, false);
    let expired = sessions_since(&h, mark)
        .iter()
        .filter(|(s, w)| *s == State::ExpiredSession && w == &vec![W0])
        .count();
    assert_eq!(expired, 1);
    let before = connects(&h);
    h.run_for(10_000).unwrap();
    assert_eq!(connects(&h), before);
    assert_eq!(h.state(), State::ExpiredSession);
    assert!(!h.conn().has_transport());
    h.close().unwrap();
    assert_eq!(h.server().request_count(opcode::CLOSE), 0);
    h.expect_exactly_once().unwrap();
    assert!(h.finish().leftovers.completions.is_empty());
}
