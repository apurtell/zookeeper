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

//! Integration tests of the drivers against zk-fakeserver: session
//! setup, round trips, watches, timers, reconnect, failover, forced
//! close, DNS, the RW probe, close policies and the outbox contract.
//!
//! Each test body is generic over [`Drv`]. The macro at the end runs it
//! for each flavor: native threaded, tokio, mt and st.

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

mod drv_util;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use drv_util::{
    Drv, Ev, Hook, Opts, RstProxy, cluster, connected, connects, create, exists, get_data, multi,
    path, wait, wait_for,
};
use zk_fakeserver::{Action, Chunking, FakeServer, FrameKind, Rule, ServerOptions};
use zk_jute::multi::MultiBody;
use zk_jute::{JBuffer, JString, opcode};
use zk_proto::rc::{ZCLOSING, ZOK, ZOPERATIONTIMEOUT};
use zk_proto::{InputDefect, LogSite, MultiOp, Reply, State};
use zk_testkit::tokens::WatcherId;

const CONNECTED: i32 = State::Connected.code();
const READ_ONLY: i32 = State::ReadOnly.code();

fn server() -> FakeServer {
    cluster().start_server(ServerOptions::default()).unwrap()
}

/// Waits until the cluster has `n` connect frames and the session is up
/// again. It returns the connect frames.
fn reconnected<D: Drv>(
    d: &D,
    c: &zk_fakeserver::Cluster,
    n: usize,
) -> Vec<zk_fakeserver::FrameRecord> {
    assert!(
        wait(d, |d| connects(c).len() >= n && d.state() == CONNECTED),
        "{}: no connect number {n}, state {}",
        D::NAME,
        d.state()
    );
    connects(c)
}

/// The start options of a test with no rule about time.
///
/// Miri runs the driver very slowly. The 1 s receive timeout of the
/// default session then ends the session before the replies come. So
/// under Miri the session is 120 s. The fake server accepts it, because
/// `cluster_config` raises its session limit under Miri.
fn untimed(hosts: &str) -> Opts {
    let mut o = Opts::new(hosts);
    if cfg!(miri) {
        o.session_ms = 120_000;
    }
    o
}

/// The delay of the /slow reply in the close tests.
///
/// The drop-in drivers fail that request with ZCLOSING at the close.
/// So its reply must not come before the test starts the close. Under
/// Miri the steps before the close can take longer than 300 ms, so the
/// delay there is 20 s. Miri does not run the native drivers, which
/// wait for this reply.
fn slow_delay() -> Duration {
    if cfg!(miri) {
        Duration::from_secs(20)
    } else {
        Duration::from_millis(300)
    }
}

/// Rule: `zookeeper_init` gives a handle that completes the handshake;
/// the session event follows the "session establishment complete" line
/// (zookeeper.c `finalize_session_establishment`).
fn t_connect<D: Drv>() {
    let s = server();
    let d = D::start(untimed(&s.connect_string()));
    connected(&d);
    // `connected` waits only for the state. The dispatch side can record
    // the CONNECTED session event after the state changes, so the test
    // waits for that event.
    assert!(
        wait(&d, |d| d
            .rec()
            .all()
            .iter()
            .any(|e| matches!(e, Ev::Session(CONNECTED)))),
        "{}: no connected session event",
        D::NAME
    );
    assert_ne!(d.client_id().session_id, 0);
    let evs = d.rec().all();
    let est = evs
        .iter()
        .position(|e| matches!(e, Ev::Log(LogSite::SessionEstablished)))
        .expect("the SessionEstablished line");
    let ev = evs
        .iter()
        .position(|e| matches!(e, Ev::Session(CONNECTED)))
        .expect("the connected session event");
    assert!(est < ev, "{}: the log comes before the event", D::NAME);
    assert_eq!(d.close(), ZOK);
}

/// Rule: a request gets its reply, and a multi gets one result per
/// operation (zookeeper.c `zoo_amulti`, `deserialize_multi`).
fn t_round_trip<D: Drv>() {
    let s = server();
    let n = D::NATIVE;
    let d = D::start(untimed(&s.connect_string()));
    connected(&d);
    assert_eq!(d.submit(create(n, 1, "/rt", b"x")), 0);
    assert_eq!(d.submit(get_data(n, 2, "/rt", None)), 0);
    let ops = vec![
        MultiOp::Create {
            op_type: opcode::CREATE,
            path: path(n, "/m"),
            data: JBuffer::Bytes(b"a".to_vec()),
            acl: drv_util::acl(),
            mode: 0,
            ttl: -1,
            defect: InputDefect::default(),
        },
        MultiOp::SetData {
            path: path(n, "/m"),
            data: JBuffer::Bytes(b"b".to_vec()),
            version: -1,
            defect: InputDefect::default(),
        },
        MultiOp::Check {
            path: path(n, "/m"),
            version: 1,
            defect: InputDefect::default(),
        },
    ];
    assert_eq!(d.submit(multi(3, ops)), 0);
    assert!(wait(&d, |d| d.rec().results().len() == 3));
    assert_eq!(d.rec().results(), vec![(1, ZOK), (2, ZOK), (3, ZOK)]);
    match d.rec().result(2) {
        Some((_, Some(Reply::Data { data, .. }))) => {
            assert_eq!(data, JBuffer::Bytes(b"x".to_vec()))
        }
        other => panic!("{}: getData reply {other:?}", D::NAME),
    }
    match d.rec().result(3) {
        Some((_, Some(Reply::Multi(items)))) => {
            assert_eq!(items.len(), 3);
            assert!(items.iter().all(|i| i.err == 0), "{items:?}");
            assert!(
                matches!(items[0].body, MultiBody::Create(_) | MultiBody::Create2(..)),
                "{items:?}"
            );
        }
        other => panic!("{}: multi reply {other:?}", D::NAME),
    }
    assert_eq!(s.cluster().data("/m"), Some(Some(b"b".to_vec())));
    assert_eq!(d.close(), ZOK);
}

/// Rule: a data watch fires once with NodeDataChanged for its watcher
/// (zookeeper.c `process_completions`, `deliverWatchers`).
fn t_watch<D: Drv>() {
    let s = server();
    s.cluster().create("/w", b"1", 0).unwrap();
    let d = D::start(untimed(&s.connect_string()));
    connected(&d);
    let w = WatcherId::new(5, 6);
    assert_eq!(d.submit(get_data(D::NATIVE, 1, "/w", Some(w))), 0);
    assert!(wait(&d, |d| d.rec().result(1).is_some()));
    s.cluster().set_data("/w", b"2").unwrap();
    let watched = |d: &D| {
        d.rec().all().into_iter().find_map(|e| match e {
            Ev::Watch { event, watchers } if event.path == JString::from("/w") => {
                Some((event.event_type, watchers))
            }
            _ => None,
        })
    };
    assert!(
        wait(&d, |d| watched(d).is_some()),
        "{}: no watch event",
        D::NAME
    );
    let (kind, watchers) = watched(&d).unwrap();
    assert_eq!(kind, 3, "NodeDataChanged");
    assert!(watchers.contains(&w), "{watchers:?}");
    assert_eq!(d.close(), ZOK);
}

/// Rule: an idle connected session sends a ping when the send side is
/// idle for T/3 (zookeeper.c `zookeeper_interest`: `send_to =
/// recv_timeout/3 - idle_send`). T = 1500 ms, so the cadence is 500 ms.
fn t_ping_cadence<D: Drv>() {
    let s = server();
    let d = D::start(Opts::new(&s.connect_string()));
    connected(&d);
    let mut seen: Vec<Instant> = Vec::new();
    let pings = |s: &FakeServer| {
        s.transcript()
            .iter()
            .filter(|r| r.op == Some(opcode::PING))
            .count()
    };
    let ok = wait_for(&d, Duration::from_secs(4), &mut |_| {
        while seen.len() < pings(&s) {
            seen.push(Instant::now());
        }
        seen.len() >= 4
    });
    assert!(ok, "{}: {} pings in 4 s", D::NAME, seen.len());
    for pair in seen.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= Duration::from_millis(350) && gap <= Duration::from_millis(850),
            "{}: ping gap {gap:?}, want about 500 ms",
            D::NAME
        );
    }
    assert_eq!(d.close(), ZOK);
}

/// Rule: with no bytes for 2T/3, the attempt ends with "connection
/// timed out" and the client reconnects with the same session
/// (zookeeper.c `zookeeper_interest`: `recv_to = recv_timeout*2/3 -
/// idle_recv`, log line 2759; spec line 233).
fn t_recv_timeout<D: Drv>() {
    let s = server();
    // The server stops all output at the first ping and keeps the
    // socket open.
    s.add_rule(
        Rule::on_request()
            .op(opcode::PING)
            .once()
            .then(Action::Stall),
    );
    // Miri needs a longer session, or the slow handshake can pass the
    // receive deadline. The bound below scales with the session.
    let session_ms = if cfg!(miri) {
        15_000
    } else {
        drv_util::SESSION_MS
    };
    let mut o = Opts::new(&s.connect_string());
    o.session_ms = session_ms;
    let d = D::start(o);
    connected(&d);
    let id = d.client_id().session_id;
    let mut stalled = None;
    assert!(wait(&d, |_| {
        if stalled.is_none() && s.transcript().iter().any(|r| r.op == Some(opcode::PING)) {
            stalled = Some(Instant::now());
        }
        connects(s.cluster()).len() >= 2
    }));
    let gap = stalled.expect("the stalled ping").elapsed();
    // The last bytes came at the handshake, about T/3 before the stalled
    // ping. The deadline is 2T/3 after them, so the reconnect comes
    // within T of the stalled ping.
    let bound = Duration::from_millis(u64::try_from(session_ms).unwrap());
    assert!(gap <= bound, "{}: timeout after {gap:?}", D::NAME);
    let c = reconnected(&d, s.cluster(), 2);
    assert_eq!(c[1].session_id, id, "{}: the session resumes", D::NAME);
    assert!(
        d.rec().has_log(LogSite::SockTimedOut),
        "{}: no timed-out line",
        D::NAME
    );
    assert_eq!(d.close(), ZOK);
}

/// Rule: a server-side close is a recoverable teardown; the next
/// handshake carries the session id and password (zookeeper.c
/// `handle_error`, `prime_connection`).
fn t_reconnect<D: Drv>() {
    let s = server();
    let d = D::start(untimed(&s.connect_string()));
    connected(&d);
    let id = d.client_id().session_id;
    s.drop_connections();
    let c = reconnected(&d, s.cluster(), 2);
    assert_eq!(c[1].session_id, id);
    assert_eq!(d.client_id().session_id, id);
    assert_eq!(d.submit(exists(D::NATIVE, 1, "/")), 0);
    assert!(wait(&d, |d| d.rec().result(1).is_some()));
    assert_eq!(d.rec().result(1).unwrap().0, ZOK);
    assert_eq!(d.close(), ZOK);
}

/// Rule: after each loss the client moves to the next server in list
/// order (zookeeper.c `zoo_cycle_next_server`, `CursorPolicy::SingleAdvance`).
/// A new handle starts in reconfig mode, so the connect after the first
/// loss starts at the cursor again. Two servers thus give A, A, B, A, B.
fn t_failover<D: Drv>() {
    let c = cluster();
    let a = c.start_server(ServerOptions::default()).unwrap();
    let b = c.start_server(ServerOptions::default()).unwrap();
    let servers = [&a, &b];
    let d = D::start(untimed(&format!(
        "{},{}",
        a.connect_string(),
        b.connect_string()
    )));
    let mut order = Vec::new();
    for n in 1..=5 {
        let frames = reconnected(&d, &c, n);
        let on = frames[n - 1].server;
        order.push(on);
        if n > 1 {
            assert_eq!(frames[n - 1].session_id, d.client_id().session_id);
        }
        assert!(wait(&d, |_| !servers[on].connections().is_empty()));
        if n < 5 {
            servers[on].drop_connections();
        }
    }
    assert_eq!(order, vec![0, 0, 1, 0, 1], "{}: server order", D::NAME);
    assert_eq!(d.close(), ZOK);
}

/// Rule: a refused address first and a live server second. Each loss
/// costs one refused connect, and then the client connects to the live
/// server again with the same session. Legacy C
/// advances the cursor twice per failure, so after the loss it tries only
/// the refused address and never connects again. In the
/// drop-in, each loss after the first starts with one delay iteration
/// as in C. The native flavors use a deadline pause, so they log no
/// delay line.
fn t_failover_refused_first<D: Drv>() {
    let s = server();
    // No server listens on this port, as in ledger_d_probe.rs.
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let d = D::start(untimed(&format!("{dead},{}", s.connect_string())));
    let delays = |d: &D| {
        d.rec()
            .all()
            .iter()
            .filter(|e| matches!(e, Ev::Log(LogSite::DelayingConnection)))
            .count()
    };
    let refused = |d: &D| {
        d.rec()
            .all()
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    Ev::Log(LogSite::SockRefused | LogSite::SockConnectFailed)
                )
            })
            .count()
    };
    for n in 1..=4 {
        let frames = reconnected(&d, s.cluster(), n);
        if n > 1 {
            assert_eq!(
                frames[n - 1].session_id,
                d.client_id().session_id,
                "{}: the session resumes",
                D::NAME
            );
        }
        assert!(wait(&d, |_| !s.connections().is_empty()));
        if n < 4 {
            s.drop_connections();
        }
    }
    let want = if D::NATIVE { 0 } else { 2 };
    assert!(wait(&d, |d| delays(d) >= want));
    assert_eq!(delays(&d), want, "{}: delay iterations", D::NAME);
    // The first connect and each of the three losses try the refused
    // address once. The dispatch side can record a log line after the
    // state changes, so the test waits for the count.
    assert!(wait(&d, |d| refused(d) >= 4));
    assert_eq!(refused(&d), 4, "{}: refused connects", D::NAME);
    assert_eq!(d.close(), ZOK);
}

/// Rule: a new host list without the current server is a forced close;
/// the client reconnects to the new list with the same session
/// (zookeeper.c `zoo_set_servers`, `update_addrs`).
fn t_set_servers<D: Drv>() {
    let c = cluster();
    let a = c.start_server(ServerOptions::default()).unwrap();
    let b = c.start_server(ServerOptions::default()).unwrap();
    let d = D::start(untimed(&format!(
        "{},{}",
        a.connect_string(),
        b.connect_string()
    )));
    connected(&d);
    let id = d.client_id().session_id;
    assert_eq!(connects(&c)[0].server, 0);
    assert!(d.set_servers(&b.connect_string()));
    let frames = reconnected(&d, &c, 2);
    assert_eq!(frames[1].server, 1, "{}: the new list", D::NAME);
    assert_eq!(frames[1].session_id, id);
    assert!(
        wait(&d, |_| a.connections().is_empty()),
        "{}: A stays open",
        D::NAME
    );
    assert_eq!(d.close(), ZOK);
}

/// Rule: a host that does not resolve logs the getaddrinfo error and
/// is skipped; the other hosts still connect (zookeeper.c
/// `resolve_hosts`, lines 985/987, `goto next`).
fn t_dns<D: Drv>() {
    let s = server();
    let o = untimed(&format!("nohost.invalid:2181,{}", s.connect_string()));
    let host = Arc::clone(&o.host);
    let d = D::start(o);
    connected(&d);
    let names = host.resolved();
    assert!(names.iter().any(|n| n == "nohost.invalid"), "{names:?}");
    assert!(names.iter().any(|n| n == "127.0.0.1"), "{names:?}");
    assert!(
        d.rec().has_log(LogSite::ResolveGai) || d.rec().has_log(LogSite::ResolveGaiErrno),
        "{}: no getaddrinfo line",
        D::NAME
    );
    assert_eq!(connects(s.cluster()).len(), 1);
    assert_eq!(d.close(), ZOK);
}

/// Rule: in read-only mode the client probes the other servers with
/// `isro`; an "rw" answer moves it to that server (zookeeper.c
/// `ping_rw_server`, log line 2794 "r/w server found").
fn t_rw_probe<D: Drv>() {
    let c = cluster();
    let ro = c
        .start_server(ServerOptions {
            read_only: true,
            ..ServerOptions::default()
        })
        .unwrap();
    let rw = c.start_server(ServerOptions::default()).unwrap();
    let mut o = untimed(&format!("{},{}", ro.connect_string(), rw.connect_string()));
    o.read_only = true;
    let d = D::start(o);
    assert!(
        wait(&d, |d| d.state() == READ_ONLY),
        "{}: state {}",
        D::NAME,
        d.state()
    );
    assert!(
        wait(&d, |d| d.state() == CONNECTED),
        "{}: no move to the rw server, state {}",
        D::NAME,
        d.state()
    );
    assert!(
        rw.transcript()
            .iter()
            .any(|r| r.kind == FrameKind::FourLetter)
    );
    assert!(d.rec().has_log(LogSite::RwServerFound));
    assert_eq!(connects(&c).last().unwrap().server, 1);
    assert_eq!(d.close(), ZOK);
}

/// Rule: a close with requests on the wire completes each token exactly
/// once. `LegacyFailPending` (drop-in) fails them with ZCLOSING at the
/// close request (zookeeper.c `zookeeper_close`, `free_completions`).
/// `Drain` (native) waits for the replies up to the close deadline,
/// then fails the rest with ZCLOSING and reports ZOPERATIONTIMEOUT.
fn t_close_outstanding<D: Drv>() {
    let s = server();
    s.cluster().create("/slow", b"", 0).unwrap();
    s.add_rule(
        Rule::on_request()
            .path("/slow")
            .then(Action::Delay(slow_delay())),
    );
    // The server stops all input and output at /stall, so neither that
    // reply nor the close reply comes.
    s.add_rule(Rule::on_request().path("/stall").then(Action::Stall));
    let mut o = untimed(&s.connect_string());
    o.close_timeout_ms = 1_000;
    let host = Arc::clone(&o.host);
    let d = D::start(o);
    connected(&d);
    let n = D::NATIVE;
    assert_eq!(d.submit(exists(n, 1, "/")), 0);
    assert!(wait(&d, |d| d.rec().result(1).is_some()));
    assert_eq!(d.submit(exists(n, 2, "/slow")), 0);
    assert_eq!(d.submit(exists(n, 3, "/stall")), 0);
    assert!(wait(&d, |_| s
        .transcript()
        .iter()
        .any(|r| r.path.as_deref() == Some("/stall"))));
    let at = Instant::now();
    let rc = d.close();
    let took = at.elapsed();
    let want = if D::NATIVE { ZOPERATIONTIMEOUT } else { ZOK };
    assert_eq!(rc, want, "{}: close rc", D::NAME);
    // The close waits for no reply past its deadlines. Under Miri the
    // driver is slow, so the bound is only the wait budget there.
    let limit = if cfg!(miri) {
        drv_util::WAIT
    } else {
        Duration::from_secs(4)
    };
    assert!(took < limit, "{}: close took {took:?}", D::NAME);
    // The drivers deliver the last items before the close returns.
    let results = d.rec().results();
    let mut ids: Vec<u64> = results.iter().map(|r| r.0).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        vec![1, 2, 3],
        "{}: each token once: {results:?}",
        D::NAME
    );
    let rc_of = |id: u64| results.iter().find(|r| r.0 == id).unwrap().1;
    let slow = if D::NATIVE { ZOK } else { ZCLOSING };
    assert_eq!(rc_of(2), slow, "{}: the delayed reply", D::NAME);
    assert_eq!(rc_of(3), ZCLOSING, "{}: the stalled reply", D::NAME);
    assert!(
        !host.discarded().contains(&"completion"),
        "{}: {:?}",
        D::NAME,
        host.discarded()
    );
}

/// Rule: under `Drain` a close waits for the replies on the wire and
/// then gets the close reply, so it reports ZOK and each request gets
/// its own reply. The drop-in profile fails them at the
/// close request (zookeeper.c `zookeeper_close`).
fn t_close_drain<D: Drv>() {
    let s = server();
    s.cluster().create("/slow", b"", 0).unwrap();
    s.add_rule(
        Rule::on_request()
            .path("/slow")
            .then(Action::Delay(slow_delay())),
    );
    let d = D::start(untimed(&s.connect_string()));
    connected(&d);
    assert_eq!(d.submit(exists(D::NATIVE, 1, "/slow")), 0);
    assert!(wait(&d, |_| s
        .transcript()
        .iter()
        .any(|r| r.path.as_deref() == Some("/slow"))));
    assert_eq!(d.close(), ZOK, "{}: close rc", D::NAME);
    let want = if D::NATIVE { ZOK } else { ZCLOSING };
    assert_eq!(d.rec().results(), vec![(1, want)], "{}", D::NAME);
}

/// Rule: a reset connection (RST) ends the attempt at once, not at the
/// receive timeout, and the client resumes the session (mt_adaptor.c
/// `do_io` POLLERR handling).
fn t_reset<D: Drv>() {
    let s = server();
    let proxy = RstProxy::start(s.addr());
    let d = D::start(Opts::new(&proxy.addr.to_string()));
    connected(&d);
    let id = d.client_id().session_id;
    let at = Instant::now();
    proxy.reset();
    let c = reconnected(&d, s.cluster(), 2);
    let gap = at.elapsed();
    // The receive timeout is 1000 ms. A reset ends the attempt well
    // before it.
    assert!(
        gap < Duration::from_millis(900),
        "{}: reconnect after {gap:?}",
        D::NAME
    );
    assert_eq!(c[1].session_id, id);
    assert_eq!(d.close(), ZOK);
}

/// Rule: the driver assembles a reply that arrives in many small reads,
/// and the next reply still arrives.
fn t_large_reply<D: Drv>() {
    let s = cluster()
        .start_server(ServerOptions {
            chunking: Chunking::Random { max: 1500 },
            ..ServerOptions::default()
        })
        .unwrap();
    let n = D::NATIVE;
    let mut o = untimed(&s.connect_string());
    // Under Miri on a loaded host, one large frame can take longer than
    // the receive timeout of the untimed session. So this test uses the
    // longest session that the fake server accepts under Miri.
    if cfg!(miri) {
        o.session_ms = 300_000;
    }
    let d = D::start(o);
    connected(&d);
    // Miri reads slowly, so it gets a smaller reply. The reply still
    // arrives in many reads.
    let size = if cfg!(miri) { 40_000 } else { 200_000 };
    let data: Vec<u8> = (0..=255u8).cycle().take(size).collect();
    assert_eq!(d.submit(create(n, 1, "/big", &data)), 0);
    assert_eq!(d.submit(get_data(n, 2, "/big", None)), 0);
    assert_eq!(d.submit(exists(n, 3, "/big")), 0);
    let budget = if cfg!(miri) {
        Duration::from_secs(600)
    } else {
        drv_util::WAIT
    };
    let mut all = |d: &D| d.rec().results().len() == 3;
    assert!(
        drv_util::wait_for(&d, budget, &mut all),
        "{}: results {:?}",
        D::NAME,
        d.rec().results()
    );
    assert_eq!(d.rec().results(), vec![(1, ZOK), (2, ZOK), (3, ZOK)]);
    match d.rec().result(2) {
        Some((_, Some(Reply::Data { data: got, .. }))) => {
            assert_eq!(got, JBuffer::Bytes(data), "{}", D::NAME)
        }
        other => panic!("{}: getData reply {other:?}", D::NAME),
    }
    assert_eq!(d.close(), ZOK);
}

/// Rule: a reset of one connection ends only that attempt. A second
/// client in the same process keeps its session and its socket events.
/// The reset reaches the client as an error event, which the driver maps
/// to READ|WRITE.
fn t_two_clients_one_resets<D: Drv>() {
    let s = server();
    let n = D::NATIVE;
    let proxy = RstProxy::start(s.addr());
    let a = D::start(Opts::new(&proxy.addr.to_string()));
    let b = D::start(Opts::new(&s.connect_string()));
    connected(&a);
    connected(&b);
    let id = a.client_id().session_id;
    proxy.reset();
    let c = reconnected(&a, s.cluster(), 3);
    assert!(
        c.iter().skip(2).any(|f| f.session_id == id),
        "{}: no resume of the reset session",
        D::NAME
    );
    assert_eq!(a.submit(exists(n, 1, "/")), 0);
    assert_eq!(b.submit(exists(n, 2, "/")), 0);
    assert!(wait(&a, |a| a.rec().results().len() == 1), "{}", D::NAME);
    assert!(wait(&b, |b| b.rec().results().len() == 1), "{}", D::NAME);
    assert_eq!(a.rec().results(), vec![(1, ZOK)]);
    assert_eq!(b.rec().results(), vec![(2, ZOK)]);
    let b_sessions = b
        .rec()
        .all()
        .iter()
        .filter(|e| matches!(e, Ev::Session(_)))
        .count();
    assert_eq!(
        b_sessions,
        1,
        "{}: the other client lost its session",
        D::NAME
    );
    assert_eq!(a.close(), ZOK);
    assert_eq!(b.close(), ZOK);
}

/// Rule: items reach the handler in order, and no driver lock is held
/// while a handler runs, so a handler can call back into the API. A
/// barrier gives MORE, and the resume continues the step.
fn t_outbox_contract<D: Drv + 'static>() {
    // Under Miri each of the 21 round trips is slow, so the test waits
    // longer.
    let (limit, budget) = if cfg!(miri) {
        (Duration::from_secs(300), Duration::from_secs(120))
    } else {
        (Duration::from_secs(15), drv_util::WAIT)
    };
    drv_util::with_deadline(limit, move || {
        let s = server();
        let seen: Arc<Mutex<Vec<(i32, i32, i64)>>> = Arc::default();
        let hook: Hook = {
            let seen = Arc::clone(&seen);
            Arc::new(move |ev, api| {
                if let Ev::Result { id: 1, .. } = ev {
                    let rc = api.api_submit(exists(D::NATIVE, 100, "/"));
                    let st = api.api_state();
                    let sid = api.api_client_id().session_id;
                    seen.lock().unwrap().push((rc, st, sid));
                }
            })
        };
        let mut o = untimed(&s.connect_string());
        o.hook = Some(hook);
        let d = D::start(o);
        connected(&d);
        for id in 1..=20 {
            assert_eq!(d.submit(exists(D::NATIVE, id, "/")), 0);
        }
        let mut all = |d: &D| d.rec().results().len() == 21;
        assert!(drv_util::wait_for(&d, budget, &mut all));
        let ids: Vec<u64> = d.rec().results().iter().map(|r| r.0).collect();
        let first: Vec<u64> = ids.iter().copied().filter(|i| *i <= 20).collect();
        assert_eq!(
            first,
            (1..=20).collect::<Vec<_>>(),
            "{}: result order",
            D::NAME
        );
        assert!(ids.contains(&100));
        let calls = seen.lock().unwrap().clone();
        assert_eq!(calls, vec![(0, CONNECTED, d.client_id().session_id)]);
        assert_eq!(d.rec().violations(), Vec::<String>::new());
        assert_eq!(d.close(), ZOK);
    });
}

macro_rules! flavor_tests {
    ($m:ident, $d:ty $(, miri_ignore = $skip:literal)?) => {
        mod $m {
            use super::*;

            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn connect() {
                t_connect::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn round_trip_and_multi() {
                t_round_trip::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn watch_delivery() {
                t_watch::<$d>();
            }
            #[test]
            #[cfg_attr(miri, ignore = "Miri is too slow for the 500 ms ping cadence of the test")]
            fn ping_cadence() {
                t_ping_cadence::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn recv_timeout() {
                t_recv_timeout::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn reconnect_resumes() {
                t_reconnect::<$d>();
            }
            /// Failover visits the servers in list order with one advance
            /// per loss.
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn failover_abab() {
                t_failover::<$d>();
            }
            /// A refused first server does not stop the reconnect to the
            /// live server.
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn failover_refused_first() {
                t_failover_refused_first::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn set_servers_forced_close() {
                t_set_servers::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn dns_failure_skips_host() {
                t_dns::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn rw_probe() {
                t_rw_probe::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn close_with_outstanding() {
                t_close_outstanding::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn close_drain() {
                t_close_drain::<$d>();
            }
            /// A reset ends the attempt at once, with no spin until the
            /// receive timeout.
            #[test]
            #[cfg_attr(miri, ignore = "Miri has no SO_LINGER, which makes the reset peer")]
            fn reset_reconnects() {
                t_reset::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn outbox_contract() {
                t_outbox_contract::<$d>();
            }
            #[test]
            $(#[cfg_attr(miri, ignore = $skip)])?
            fn large_reply_in_many_reads() {
                t_large_reply::<$d>();
            }
            #[test]
            #[cfg_attr(miri, ignore = "Miri has no SO_LINGER, which makes the reset peer")]
            fn two_clients_one_resets() {
                t_two_clients_one_resets::<$d>();
            }
        }
    };
}

flavor_tests!(
    native,
    drv_util::NativeDrv,
    miri_ignore =
        "Miri has no fcntl(F_SETFD), and the native driver always sets CLOEXEC on its waker pipe"
);
flavor_tests!(mt, drv_util::MtDrv);
flavor_tests!(st, drv_util::StDrv);
#[cfg(all(unix, feature = "tokio"))]
flavor_tests!(tokio_task, drv_util::TokioDrv);
