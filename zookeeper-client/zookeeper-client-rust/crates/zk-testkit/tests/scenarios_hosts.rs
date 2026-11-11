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

//! Host scenarios: the failover order, the DNS generations, the read-only
//! probe and the forced close.

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

use common::{Profile, cause, connect_log, run_to_state, spec};
use std::net::IpAddr;
use zk_jute::{JString, rc};
use zk_proto::{Cause, HostResolution, Interest, InterestOutcome, LogSite, ResolveError, State};
use zk_testkit::net::EAI_AGAIN;
use zk_testkit::{ActionRecord, Event, Harness, server_addr};

fn refusing(p: Profile, seed: u64, n: usize) -> Harness {
    let mut h = p.builder(seed).servers(n).shuffle(false).build();
    for i in 0..n {
        h.server_mut().set_accepting(server_addr(i), false);
    }
    h
}

fn resolves(h: &Harness) -> Vec<(u64, bool, i32)> {
    h.recorder()
        .actions()
        .filter_map(|a| match a {
            ActionRecord::Resolve {
                generation,
                initial,
                rc,
                ..
            } => Some((*generation, *initial, *rc)),
            _ => None,
        })
        .collect()
}

// Source: spec "Host management" (lines 249-250) and "Predictable
// Ensemble Failover Progression". The core moves the cursor once per
// attempt, so two dead servers alternate A, B, A, B under both profiles.
// C would skip every other server.
#[test]
fn failover_alternates_over_two_servers() {
    for p in Profile::ALL {
        let mut h = refusing(p, 61, 2);
        h.run_until(|h| h.net().connects().len() >= 6, 20_000)
            .unwrap();
        let (a, b) = (server_addr(0), server_addr(1));
        assert_eq!(h.net().connects()[..6], [a, b, a, b, a, b], "{p:?}");
    }
}

// Source: spec line 250, C zookeeper_interest. Three dead servers give
// A, B, C, A, B, C. A delay iteration follows only the end of a pass: C
// skips one connect with the "Delaying connection" WARN and an interest
// timeout of T/60. The re-resolution while disconnected starts a C
// reconfig pass first, so the first delay can come after the second
// pass. The harness steps again at once after outputs, so the check reads
// the interest record, not the clock.
#[test]
fn failover_covers_every_server_and_pauses_after_a_pass() {
    for p in Profile::LEGACY {
        let mut h = refusing(p, 62, 3);
        h.run_until(|h| h.net().connects().len() >= 7, 20_000)
            .unwrap();
        let addrs: Vec<_> = connect_log(h.recorder()).iter().map(|(_, a)| *a).collect();
        let (a, b, c) = (server_addr(0), server_addr(1), server_addr(2));
        assert_eq!(addrs[..7], [a, b, c, a, b, c, a], "{p:?}");
        let mut last_connect = None;
        let mut delays = 0;
        let mut after_delay = false;
        for r in h.recorder().all() {
            match &r.event {
                Event::Action(ActionRecord::Connect { addr, .. }) => {
                    if after_delay {
                        assert_eq!(*addr, a, "{p:?}: a pass starts at A");
                        after_delay = false;
                    }
                    last_connect = Some(*addr);
                }
                Event::Interest(InterestOutcome {
                    outputs:
                        Some(Interest {
                            has_socket: false,
                            timeout_ms,
                            ..
                        }),
                    ..
                }) => {
                    // T/60 with T = 10 s is 166 ms.
                    assert_eq!(*timeout_ms, 166, "{p:?}");
                    assert_eq!(last_connect, Some(c), "{p:?}: a delay ends a pass");
                    delays += 1;
                    after_delay = true;
                }
                _ => {}
            }
        }
        assert!(delays >= 1, "{p:?}");
        let warns = h
            .recorder()
            .logs()
            .iter()
            .filter(|l| l.site == LogSite::DelayingConnection)
            .count();
        assert_eq!(warns, delays, "{p:?}");
    }
}

// Source: spec "Compatibility policies", "Resolution Cadence". While
// disconnected, C resolves on every iteration. The native profile
// resolves once per pass. Each resolution has a new generation.
#[test]
fn resolution_cadence_follows_the_profile() {
    for p in Profile::ALL {
        let mut h = refusing(p, 63, 2);
        h.run_until(|h| h.net().connects().len() >= 8, 20_000)
            .unwrap();
        let r = resolves(&h);
        assert!(r[0].1, "the first resolution is the initial one");
        assert!(r.iter().skip(1).all(|x| !x.1));
        assert!(r.windows(2).all(|w| w[1].0 == w[0].0 + 1), "{r:?}");
        let connects = h.net().connects().len();
        if p.is_native() {
            // One resolution per pass of two servers, plus the initial one.
            assert!(r.len() <= connects / 2 + 2, "{p:?}: {} {connects}", r.len());
        } else {
            assert!(r.len() >= connects, "{p:?}: {} {connects}", r.len());
        }
    }
}

// Source: the native reconnect rule. A lost session is not a failed
// address. The native profile reconnects in the same virtual millisecond as
// each loss. It resolves the list once before the reconnect. The legacy
// profiles keep the C delay iteration. From the second loss on, the cursor
// is at the end of the one-server list, so each loss gives one "Delaying
// connection" WARN.
#[test]
fn lost_session_reconnects_at_once() {
    for p in Profile::ALL {
        let native = p.is_native();
        let mut h = p
            .builder_with(69, |c| {
                c.reconnect_delay_ms = 1_000;
                c.reconnect_jitter_pct = 0;
                if native {
                    // The zk-client mapping of DnsRefresh::EachPass.
                    c.resolve_delay_ms = -1;
                }
            })
            .build();
        h.connect().unwrap();
        for loss in 0..3 {
            let before = connect_log(h.recorder()).len();
            let resolved = resolves(&h).len();
            h.reset_current();
            h.run_until(|h| !h.state().is_connected(), 10_000).unwrap();
            let lost_at = h.now().0;
            h.connect().unwrap();
            let (at, _) = connect_log(h.recorder())[before];
            let waited = at - lost_at;
            if native {
                assert_eq!(waited, 0, "{p:?}: loss {loss} waited {waited} ms");
                assert_eq!(resolves(&h).len(), resolved + 1, "{p:?}: loss {loss}");
            }
        }
        let warns = h
            .recorder()
            .logs()
            .iter()
            .filter(|l| l.site == LogSite::DelayingConnection)
            .count();
        let want = if native { 0 } else { 2 };
        assert_eq!(warns, want, "{p:?}");
    }
}

// Source: the native reconnect rule. After a lost session, the next pass
// starts at the cursor and has one attempt per address. The pause follows
// the last attempt of the pass, not the end of the list. Here the second
// loss leaves the cursor on B of A, B, C, so each pass is B, C, A, and the
// first pause has the configured delay.
#[test]
fn pass_after_a_lost_session_tries_each_server_once() {
    let mut h = Profile::Native
        .builder_with(70, |c| {
            c.reconnect_delay_ms = 1_000;
            c.reconnect_jitter_pct = 0;
            c.resolve_delay_ms = -1;
        })
        .servers(3)
        .shuffle(false)
        .build();
    let (a, b, c) = (server_addr(0), server_addr(1), server_addr(2));
    h.connect().unwrap();
    // The first session leaves the cursor on A. The reconnect after the
    // first loss takes A and moves the cursor to B.
    h.reset_current();
    h.run_until(|h| !h.state().is_connected(), 10_000).unwrap();
    h.connect().unwrap();
    assert_eq!(h.conn().current_server(), Some(a));
    for i in 0..3 {
        h.server_mut().set_accepting(server_addr(i), false);
    }
    let mark = connect_log(h.recorder()).len();
    h.reset_current();
    h.run_until(|h| connect_log(h.recorder()).len() >= mark + 6, 20_000)
        .unwrap();
    let log = connect_log(h.recorder());
    let got: Vec<_> = log[mark..mark + 6].iter().map(|(_, x)| *x).collect();
    assert_eq!(got, [b, c, a, b, c, a]);
    let gaps: Vec<u64> = log[mark..mark + 6]
        .windows(2)
        .map(|w| w[1].0 - w[0].0)
        .collect();
    assert_eq!(gaps, [0, 0, 1_000, 0, 0]);
}

// Source: zk-proto handle_resolved. A result of an old generation changes
// nothing. Only the generation that set_servers returned commits.
#[test]
fn stale_resolution_generation_is_ignored() {
    for p in Profile::ALL {
        let mut h = p.builder(64).servers(3).shuffle(false).build();
        h.connect().unwrap();
        let now = h.now();
        let old = h
            .conn_mut()
            .set_servers(vec![spec(p.is_native(), "127.0.0.1", 2182)], now);
        let new = h
            .conn_mut()
            .set_servers(vec![spec(p.is_native(), "127.0.0.1", 2183)], now);
        assert_eq!(new, old + 1);
        // The old generation offers the second server. The core drops it.
        h.conn_mut().handle_host_resolved(
            old,
            HostResolution {
                host: 0,
                result: Ok(vec![server_addr(1)]),
                skipped_families: Vec::new(),
            },
            now,
        );
        assert_eq!(h.conn_mut().handle_resolved(old, false, now), rc::ZOK);
        h.conn_mut().handle_host_resolved(
            new,
            HostResolution {
                host: 0,
                result: Ok(vec![server_addr(2)]),
                skipped_families: Vec::new(),
            },
            now,
        );
        assert_eq!(h.conn_mut().handle_resolved(new, false, now), rc::ZOK);
        // The current server left the list, so the core moves to the
        // new list with a forced close.
        h.connect().unwrap();
        h.run_until(
            |h| h.conn().current_server() == Some(server_addr(2)) && h.state().is_connected(),
            10_000,
        )
        .unwrap();
        assert!(!h.net().connects().contains(&server_addr(1)), "{p:?}");
    }
}

// Source: spec "Compatibility policies", "DNS Failure Resilience". When
// every name fails, C keeps the ZSYSTEMERROR rc and blocks the connect.
// The native profile keeps the last good list and reconnects.
/// Ledger: SRV-06
#[test]
fn dns_failure_follows_the_profile() {
    for p in Profile::ALL {
        let mut h = p
            .builder_with(65, |c| {
                c.hosts = vec![spec(p.is_native(), "zk.test", 2181)];
                c.host_text = JString::from("zk.test:2181");
            })
            .build();
        h.net_mut()
            .add_name("zk.test", vec![IpAddr::from([127_u8, 0, 0, 1])]);
        h.connect().unwrap();
        h.net_mut().fail_name(
            "zk.test",
            ResolveError {
                gai_rc: EAI_AGAIN,
                errno: 0,
            },
            None,
        );
        h.reset_current();
        h.run_until(|h| !h.state().is_connected(), 10_000).unwrap();
        let before = h.net().connects().len();
        h.run_for(3_000).unwrap();
        let failed = resolves(&h).iter().any(|x| x.2 == rc::ZSYSTEMERROR);
        if p.is_native() {
            assert!(h.state().is_connected(), "{p:?}");
            assert!(h.net().connects().len() > before);
        } else {
            assert!(failed, "{p:?}");
            assert!(!h.state().is_connected(), "{p:?}");
            assert_eq!(h.net().connects().len(), before, "{p:?}");
            assert!(h.recorder().all().iter().any(|r| matches!(
                r.event,
                zk_testkit::Event::InterestRefused(_)
            ) || matches!(
                r.event,
                zk_testkit::Event::Interest(_)
            )));
            // A good resolution lifts the block.
            h.net_mut().clear_failure("zk.test");
            h.connect().unwrap();
        }
    }
}

// Source: spec lines 254-256. A read-only server gives state
// 5. The core probes for a read-write server 200 ms later, and the
// interval doubles. A found server tears down with RwServerFound, which
// fails pending work with ZCONNECTIONLOSS, then connects there.
/// Ledger: ST-08, DV-FIX-9, SRV-12
#[test]
fn read_only_session_moves_to_a_found_rw_server() {
    for p in Profile::ALL {
        let mut h = p
            .builder_with(66, |c| c.allow_read_only = true)
            .servers(2)
            .shuffle(false)
            .build();
        let (a, b) = (server_addr(0), server_addr(1));
        h.server_mut().set_read_only(a, true);
        h.server_mut().set_accepting(b, false);
        run_to_state(&mut h, State::ReadOnly, 10_000);
        assert!(h.server().connect_requests()[0].read_only);
        let ro_at = h.now().0;
        let ops = h.ops();
        let r = h.call(ops.create("/w", b"", 0)).unwrap();
        assert_eq!(r.rc, rc::ZNOTREADONLY, "{p:?}");
        // Two probes fail while the second server is down.
        h.run_until(
            |h| {
                h.recorder()
                    .actions()
                    .filter(|a| matches!(a, ActionRecord::ProbeRw { .. }))
                    .count()
                    >= 2
            },
            5_000,
        )
        .unwrap();
        let probes: Vec<u64> = h
            .recorder()
            .all()
            .iter()
            .filter(|r| {
                matches!(
                    r.event,
                    zk_testkit::Event::Action(ActionRecord::ProbeRw { .. })
                )
            })
            .map(|r| r.at.0)
            .collect();
        assert!(
            (probes[0] - ro_at).abs_diff(200) <= 5,
            "{p:?}: {probes:?} {ro_at}"
        );
        assert!(
            (probes[1] - probes[0]).abs_diff(400) <= 5,
            "{p:?}: {probes:?}"
        );
        h.server_mut().add_rule(
            zk_testkit::server::Rule::on_request()
                .path("/slow")
                .then(zk_testkit::server::RuleAction::Ignore),
        );
        let t = h.submit(ops.exists("/slow", None)).unwrap();
        h.server_mut().set_accepting(b, true);
        run_to_state(&mut h, State::Connected, 10_000);
        assert_eq!(h.conn().current_server(), Some(b), "{p:?}");
        h.expect_completion(t, rc::ZCONNECTIONLOSS).unwrap();
        assert_eq!(h.conn().last_teardown_cause(), Some(Cause::RwServerFound));
        // C sends the session id only after it saw a read-write server.
        let reqs = h.server().connect_requests();
        assert_eq!(reqs.last().unwrap().session_id, 0, "{p:?}");
        let r = h.call(ops.create("/w", b"", 0)).unwrap();
        assert_eq!(r.rc, rc::ZOK);
    }
}

// Source: the zk-proto forced close. A set_servers list without the current
// server forces a close. The pending work fails with ZCONNECTIONLOSS, a
// Connecting event goes out, and the core connects to the new list.
#[test]
fn set_servers_forces_a_close_onto_the_new_list() {
    for p in Profile::ALL {
        let mut h = p.builder(67).servers(2).shuffle(false).build();
        h.connect().unwrap();
        let cur = h.conn().current_server().unwrap();
        let other = if cur == server_addr(0) { 1 } else { 0 };
        h.server_mut().add_rule(
            zk_testkit::server::Rule::on_request()
                .path("/slow")
                .then(zk_testkit::server::RuleAction::Ignore),
        );
        let ops = h.ops();
        let t = h.submit(ops.exists("/slow", None)).unwrap();
        h.run_for(10).unwrap();
        let spec_other = h.host_spec(other);
        let (_, rc_set) = h.set_servers(vec![spec_other]);
        assert_eq!(rc_set, rc::ZOK);
        assert_eq!(h.state(), State::NotConnected, "{p:?}");
        h.connect().unwrap();
        assert_eq!(h.conn().current_server(), Some(server_addr(other)), "{p:?}");
        assert_eq!(cause(&h), Some(Cause::ForcedClose));
        h.expect_completion(t, rc::ZCONNECTIONLOSS).unwrap();
        let s = h.recorder().session_states();
        assert_eq!(
            s,
            vec![State::Connected, State::Connecting, State::Connected],
            "{p:?}"
        );
        // The session survives the move.
        assert_eq!(h.server().sessions().len(), 1);
        h.expect_exactly_once().unwrap();
    }
}

// Source: zk-proto handle_forced_close. With no transport it does nothing.
#[test]
fn forced_close_without_transport_is_a_no_op() {
    for p in Profile::ALL {
        let mut h = refusing(p, 68, 1);
        let now = h.now();
        h.conn_mut().handle_forced_close(now);
        assert!(!h.conn_mut().run_pending_teardown(now));
        assert_eq!(h.state(), State::NotConnected);
        assert!(h.recorder().session_states().is_empty());
    }
}
