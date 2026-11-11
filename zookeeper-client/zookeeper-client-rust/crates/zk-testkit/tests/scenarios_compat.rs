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

//! The rows of the spec table "Compatibility policies" that the other
//! scenario files do not cover. Each test checks one row under both
//! profiles.

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

use common::{Profile, cause, connect_log};
use zk_jute::{JString, rc};
use zk_proto::{Cause, Interest, InterestOutcome, LogSite, Output, State, TerminateReason};
use zk_testkit::server::{Rule, RuleAction};
use zk_testkit::{Event, Harness, WatcherId, server_addr};

/// The C `hash` of hashtable.c over the DJB2 key hash of zk_hashtable.c.
fn c_hash(key: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &c in key {
        h = h.wrapping_mul(33).wrapping_add(u32::from(c));
    }
    let mut i = h;
    i = i.wrapping_add(!(i << 9));
    i ^= i.rotate_right(14);
    i = i.wrapping_add(i << 4);
    i ^= i.rotate_right(10);
    i
}

/// The C iterator order of a 53-bucket table: buckets in index order,
/// and each bucket chain newest first (hashtable_insert puts at head).
fn c_table_order(keys: &[&str]) -> Vec<usize> {
    let mut order: Vec<(u32, usize)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (c_hash(k.as_bytes()) % 53, i))
        .collect();
    order.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    order.into_iter().map(|(_, i)| i).collect()
}

const PATHS: [&str; 8] = ["/q", "/b", "/zz", "/a1", "/m", "/c7", "/k", "/e"];

fn with_watches(p: Profile, seed: u64, w0: WatcherId) -> (Harness, Vec<WatcherId>) {
    let mut h = p.builder(seed).default_watcher(Some(w0)).build();
    h.connect().unwrap();
    let ops = h.ops();
    let mut ws = Vec::new();
    for (i, path) in PATHS.iter().enumerate() {
        let w = WatcherId::new(8, i as u32 + 1);
        h.call(ops.create(path, b"", 0)).unwrap();
        h.call(ops.get_data(path, Some(w))).unwrap();
        ws.push(w);
    }
    (h, ws)
}

// Spec row "Watcher Table Implementation". The C profile walks the DJB2
// table. C copy_table walks the buckets, and add_to_list puts each
// watcher at the head. The default watcher comes last. The native
// tables keep the order in which each path got its first watcher (spec
// "Watcher Table Implementation"). Each path keeps registration order.
// WatchTerminated{Closed} shows it.
#[test]
fn watch_table_order_follows_the_profile() {
    for p in Profile::ALL {
        let w0 = WatcherId::new(8, 0);
        let (mut h, ws) = with_watches(p, 100, w0);
        if p.is_native() {
            // A second watcher on "/m" comes after the first one.
            let w9 = WatcherId::new(8, 9);
            let ops = h.ops();
            h.call(ops.get_data("/m", Some(w9))).unwrap();
            let m = PATHS.iter().position(|p| *p == "/m").unwrap();
            let mut want = ws.clone();
            want.insert(m + 1, w9);
            let mut sorted = PATHS;
            sorted.sort_unstable();
            assert_ne!(sorted, PATHS, "path order differs from insertion order");
            let mark = h.recorder().mark();
            let now = h.now();
            h.conn_mut().destroy(now);
            h.pump(now);
            let got: Vec<Vec<WatcherId>> = h
                .recorder()
                .outputs_since(mark)
                .filter_map(|o| match o {
                    Output::WatchTerminated {
                        watchers,
                        reason: TerminateReason::Closed,
                    } => Some(watchers.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(got, vec![want]);
        } else {
            let mark = h.recorder().mark();
            h.reset_current();
            h.run_until(|h| !h.state().is_connected(), 10_000).unwrap();
            let got: Vec<Vec<WatcherId>> = h
                .recorder()
                .outputs_since(mark)
                .filter_map(|o| match o {
                    Output::Session {
                        state: State::Connecting,
                        watchers,
                        ..
                    } => Some(watchers.clone()),
                    _ => None,
                })
                .collect();
            let mut want: Vec<WatcherId> = c_table_order(&PATHS)
                .into_iter()
                .rev()
                .map(|i| ws[i])
                .collect();
            want.push(w0);
            // The model order must differ from insertion order, or the
            // test proves nothing.
            assert_ne!(want[..ws.len()], ws[..]);
            assert_eq!(got, vec![want], "{p:?}");
        }
    }
}

/// Connects, holds one written request, then queues `raw` from the
/// server. It returns the ticket and the time of the push.
fn push_after_request(h: &mut Harness, raw: Vec<u8>) -> (zk_testkit::Ticket, u64) {
    h.connect().unwrap();
    h.server_mut()
        .add_rule(Rule::on_request().path("/slow").then(RuleAction::Ignore));
    let ops = h.ops();
    let t = h.submit(ops.get_data("/slow", None)).unwrap();
    h.run_for(100).unwrap();
    let link = h.link().unwrap();
    h.server_mut().push_raw(link, raw);
    (t, h.now().0)
}

fn teardown_time(h: &Harness) -> Option<u64> {
    h.recorder().all().iter().find_map(|r| match &r.event {
        Event::Output(Output::Session {
            state: State::Connecting,
            ..
        }) => Some(r.at.0),
        _ => None,
    })
}

// Spec row "Maximum Frame Size". The native profile ends the connection
// at a frame length above 4 MiB. The C profile has no limit and waits
// for the body.
#[test]
fn frame_size_cap_follows_the_profile() {
    let len = zk_proto::compat::NATIVE_MAX_FRAME_LEN + 1;
    for p in Profile::ALL {
        let mut h = p.harness(101);
        let (t, _) = push_after_request(&mut h, len.to_be_bytes().to_vec());
        h.run_for(1_000).unwrap();
        if p.is_native() {
            assert_eq!(cause(&h), Some(Cause::ProtocolError));
            h.expect_completion(t, rc::ZCONNECTIONLOSS).unwrap();
        } else {
            assert_eq!(cause(&h), None, "{p:?}");
            assert!(h.state().is_connected(), "{p:?}");
            assert!(h.recorder().completion(t).is_none(), "{p:?}");
        }
    }
}

// Spec row "Malformed Frame Handling". A negative length stalls the C
// decoder until the receive timeout (2T/3 after the last receive). The
// native profile ends the connection at once.
#[test]
fn negative_frame_length_follows_the_profile() {
    for p in Profile::ALL {
        let mut h = p.harness(102);
        let (t, at) = push_after_request(&mut h, (-2i32).to_be_bytes().to_vec());
        h.run_until(|h| teardown_time(h).is_some(), 10_000).unwrap();
        let spent = teardown_time(&h).unwrap() - at;
        if p.is_native() {
            assert_eq!(cause(&h), Some(Cause::ProtocolError));
            assert!(spent < 10, "{spent}");
            h.expect_completion(t, rc::ZCONNECTIONLOSS).unwrap();
        } else {
            assert_eq!(cause(&h), Some(Cause::RecvTimeout), "{p:?}");
            assert!((6_000..=6_667).contains(&spent), "{p:?} {spent}");
            h.expect_completion(t, rc::ZOPERATIONTIMEOUT).unwrap();
        }
    }
}

// Spec row "Disconnect Return Codes", Cause::rc_for. A reply whose xid
// does not match the FIFO head tears down with XidMismatch. C fails the
// pending work with ZRUNTIMEINCONSISTENCY. The native profile gives
// ZCONNECTIONLOSS.
#[test]
fn xid_mismatch_rc_follows_the_profile() {
    for p in Profile::ALL {
        let mut h = p.harness(103);
        // A ReplyHeader frame: xid 9999, zxid 1, err 0.
        let mut frame = 16i32.to_be_bytes().to_vec();
        frame.extend_from_slice(&9_999i32.to_be_bytes());
        frame.extend_from_slice(&1i64.to_be_bytes());
        frame.extend_from_slice(&0i32.to_be_bytes());
        let (t, _) = push_after_request(&mut h, frame);
        h.run_until(|h| h.recorder().completion(t).is_some(), 1_000)
            .unwrap();
        assert_eq!(cause(&h), Some(Cause::XidMismatch), "{p:?}");
        let want = if p.is_native() {
            rc::ZCONNECTIONLOSS
        } else {
            rc::ZRUNTIMEINCONSISTENCY
        };
        h.expect_completion(t, want).unwrap();
    }
}

// Spec row "Chroot Path Validation", C sub_string. C strips the chroot
// as a byte prefix, so "/apple/x" under "/app" becomes "le/x" with no
// log. A path with no such prefix keeps its raw form and logs the
// mismatch ERROR. The native profile strips on component boundaries and
// drops both events with the ERROR line.
#[test]
fn chroot_strip_follows_the_profile() {
    for p in Profile::ALL {
        let mut h = p
            .builder_with(104, |c| c.chroot = Some(JString::from("/app")))
            .build();
        h.server_mut().create("/app", b"", 0).unwrap();
        h.connect().unwrap();
        let link = h.link().unwrap();
        let mark = h.recorder().mark();
        h.server_mut().push_event(link, 1, "/apple/x", 5);
        h.server_mut().push_event(link, 1, "/other", 6);
        h.run_for(100).unwrap();
        let events: Vec<(Vec<u8>, usize)> = h
            .recorder()
            .outputs_since(mark)
            .filter_map(|o| match o {
                Output::Watch {
                    event,
                    delivery_logs,
                    ..
                } => Some((
                    event.path.as_bytes().unwrap_or_default().to_vec(),
                    delivery_logs
                        .iter()
                        .filter(|l| l.site == LogSite::ChrootMismatch)
                        .count(),
                )),
                _ => None,
            })
            .collect();
        let mismatches = h
            .recorder()
            .outputs_since(mark)
            .filter(|o| matches!(o, Output::Log(l) if l.site == LogSite::ChrootMismatch))
            .count();
        if p.is_native() {
            assert!(events.is_empty(), "{p:?}");
            assert_eq!(mismatches, 2);
        } else {
            assert_eq!(
                events,
                vec![(b"le/x".to_vec(), 0), (b"/other".to_vec(), 1)],
                "{p:?}"
            );
            assert_eq!(mismatches, 0, "{p:?}");
        }
    }
}

// Spec row "Reconnection Backoff". C skips one iteration with a T/60
// timeout after a pass ends. The native profile waits an exponential pause
// that starts at reconnect_delay_ms (here with no jitter) until the next
// connect.
#[test]
fn reconnect_backoff_follows_the_profile() {
    for p in Profile::ALL {
        let mut h = p
            .builder_with(105, |c| {
                c.reconnect_delay_ms = 1_000;
                c.reconnect_jitter_pct = 0;
            })
            .build();
        h.server_mut().set_accepting(server_addr(0), false);
        h.run_until(|h| h.net().connects().len() >= 5, 20_000)
            .unwrap();
        let times: Vec<u64> = connect_log(h.recorder()).iter().map(|(t, _)| *t).collect();
        if p.is_native() {
            // The initial resolution starts a C reconfig pass, so the
            // first two connects come at once. After that each pass of
            // the one server ends with a pause that doubles from 1000 ms.
            assert_eq!(times[0], times[1], "{times:?}");
            let gaps: Vec<u64> = times[1..].windows(2).map(|w| w[1] - w[0]).collect();
            assert_eq!(gaps[..3], [1_000, 2_000, 4_000], "{times:?}");
        } else {
            let delays: Vec<u32> = h
                .recorder()
                .all()
                .iter()
                .filter_map(|r| match r.event {
                    Event::Interest(InterestOutcome {
                        outputs:
                            Some(Interest {
                                has_socket: false,
                                timeout_ms,
                                ..
                            }),
                        ..
                    }) => Some(timeout_ms),
                    _ => None,
                })
                .collect();
            assert!(!delays.is_empty(), "{p:?}");
            assert!(delays.iter().all(|d| *d == 166), "{p:?} {delays:?}");
        }
    }
}
