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

//! `DistributedLock` against a real server: contention, a lost create,
//! and a lost delete.
//!
//! The servers come from `common::Servers`, so `ZK_TEST_PORT_BASE` and
//! `ZK_TEST_SERVER_VERSION` select them. Each scenario runs on a
//! standalone server and on the three-node ensemble. The ensemble also
//! changes its leader while a client holds the lock. The tests carry
//! `#[ignore = "real-server"]`, and they skip when no server can start.
//!
//! The lost create puts a `common::Proxy` between the client and the
//! server. In one case, the proxy holds the create and then cuts the
//! connection, so the server never sees the create. In the other case,
//! the proxy mutes the replies. It forwards the create and drops the
//! reply, so the server applies the create. Then the proxy cuts the
//! connection. On the ensemble, the proxy stands in front of a follower.
//!
//! The lost delete uses the proxy too. It drops the `delete` of a guard
//! drop and cuts the connection. The guaranteed delete removes the ghost
//! node after the reconnect, and a second client then gets the lock.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // The shared scenario bodies hold several clients and recipes in one
    // future. The 8 KiB budget is for the product code, not the tests.
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use apache_zookeeper::acl::{Acl, Id, OPEN_ACL_UNSAFE, Perms};
use apache_zookeeper::{Client, CreateMode, Error, SessionState};
use apache_zookeeper_recipes::{DistributedLock, LeaderLatch, LockGuard};
use common::{Servers, Topology, session_id};
use tokio::sync::mpsc;

/// The short wait that shows that a waiter does not proceed.
const SHORT: Duration = Duration::from_millis(300);

/// The children of `path` in Curator lock order. The list comes after a
/// `sync`, so a follower shows every write of the leader.
async fn lock_order(observer: &Client, path: &str) -> Vec<String> {
    let mut c = common::synced_children(observer, path).await;
    c.sort_by(|a, b| {
        let key = |s: &str| s.rsplit_once("lock-").map_or(s, |(_, t)| t).to_owned();
        key(a).encode_utf16().cmp(key(b).encode_utf16())
    });
    c
}

/// Polls the server through `observer` until `path` has `n` children.
async fn until_children(observer: &Client, path: &str, n: usize) {
    common::within(async {
        while lock_order(observer, path).await.len() != n {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

/// The data watches of the servers on `ports` by path, from the `wchp`
/// command. A server holds the watches of its own clients, so the map
/// is the union over all the servers.
fn watches_by_path(ports: &[u16]) -> BTreeMap<String, BTreeSet<i64>> {
    let mut out: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    for &port in ports {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"wchp").unwrap();
        let mut text = String::new();
        s.read_to_string(&mut text).unwrap();
        let mut at: Option<String> = None;
        for line in text.lines() {
            if let Some(hex) = line.trim().strip_prefix("0x") {
                let id = u64::from_str_radix(hex, 16).unwrap() as i64;
                out.entry(at.clone().unwrap()).or_default().insert(id);
            } else if line.starts_with('/') {
                at = Some(line.trim().to_owned());
            }
        }
    }
    out
}

/// Polls `wchp` until `pred` holds.
async fn until_watches(ports: &[u16], pred: impl Fn(&BTreeMap<String, BTreeSet<i64>>) -> bool) {
    common::within(async {
        while !pred(&watches_by_path(ports)) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// The watches on the nodes below `path`.
fn lock_watches(
    all: &BTreeMap<String, BTreeSet<i64>>,
    path: &str,
) -> BTreeMap<String, BTreeSet<i64>> {
    let prefix = format!("{path}/");
    all.iter()
        .filter(|(p, _)| p.starts_with(&prefix))
        .map(|(p, s)| (p.clone(), s.clone()))
        .collect()
}

/// Five contenders on a standalone server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_lock_five_contenders() {
    five_contenders(Topology::Standalone).await;
}

/// Five contenders on the ensemble. The clients spread over the servers.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_lock_five_contenders_ensemble() {
    five_contenders(Topology::Ensemble).await;
}

/// Five contenders on real servers. The lock goes in creation
/// order, one holder at a time, and each waiter watches only its
/// predecessor (`wchp`).
async fn five_contenders(topology: Topology) {
    const PATH: &str = "/re12/re01/lock";
    let Some(servers) = Servers::start_or_skip(topology) else {
        return;
    };
    let ports = servers.client_ports();
    let observer = common::connect(&servers.connect_string()).await;
    let mut clients = Vec::new();
    for _ in 0..5 {
        clients.push(common::connect(&servers.connect_string()).await);
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<(usize, LockGuard)>();
    for (n, c) in clients.iter().enumerate() {
        let lock = DistributedLock::new(c, PATH).unwrap();
        let tx = tx.clone();
        tokio::spawn(async move {
            let guard = lock.acquire().await.expect("acquire");
            let _ = tx.send((n, guard));
        });
        until_children(&observer, PATH, n + 1).await;
    }
    let order = lock_order(&observer, PATH).await;
    let sessions: Vec<i64> = clients.iter().map(session_id).collect();

    // Each waiter watches the node just before its own, and nothing
    // else under the lock path.
    // Entry k is the node of contender k and the session of contender
    // k + 1, in creation order.
    let watched: Vec<(String, BTreeSet<i64>)> = (0..4)
        .map(|n| {
            (
                format!("{PATH}/{}", order[n]),
                BTreeSet::from([sessions[n + 1]]),
            )
        })
        .collect();
    let expected: BTreeMap<String, BTreeSet<i64>> = watched.iter().cloned().collect();
    until_watches(&ports, |w| lock_watches(w, PATH) == expected).await;

    for (n, own) in order.iter().enumerate() {
        let (got, guard) = common::within(rx.recv()).await.unwrap();
        assert_eq!(got, n, "the lock goes in creation order");
        assert_eq!(guard.node().name(), Some(own.as_str()));
        assert!(common::still_pending(rx.recv(), SHORT).await, "one holder");
        assert_eq!(lock_order(&observer, PATH).await.first(), Some(own));
        // The watches of the waiters that are left do not change. The
        // server of the new holder removed its watch before the event.
        let left: BTreeMap<String, BTreeSet<i64>> = watched.iter().skip(n).cloned().collect();
        assert_eq!(lock_watches(&watches_by_path(&ports), PATH), left);
        common::within(guard.release()).await.unwrap();
    }
    assert!(lock_order(&observer, PATH).await.is_empty());
    for c in clients {
        common::within(c.close()).await.unwrap();
    }
    common::within(observer.close()).await.unwrap();
}

/// The leader of the ensemble changes while a
/// client holds the lock and another client waits for it.
///
/// Each server drops its clients when the leader goes. The sessions
/// stay, because the timeout is longer than the election. The holder
/// keeps the lock: `lost()` does not resolve, its node stays first, and
/// the waiter does not proceed. The release then passes the lock to the
/// waiter on the new leader.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_lock_held_through_leader_change() {
    const PATH: &str = "/re12/leader-change/lock";
    let Some(servers) = Servers::start_or_skip(Topology::Ensemble) else {
        return;
    };
    let ensemble = servers.ensemble().unwrap();
    let cs = servers.connect_string();
    let connect = || async {
        common::within(
            common::builder(&cs)
                .session_timeout(Duration::from_secs(10))
                .connect(),
        )
        .await
        .expect("connect")
    };
    let holder = connect().await;
    let waiter = connect().await;
    let observer = connect().await;

    let guard = common::within(DistributedLock::new(&holder, PATH).unwrap().acquire())
        .await
        .unwrap();
    let lock = DistributedLock::new(&waiter, PATH).unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<LockGuard>();
    tokio::spawn(async move {
        let g = lock.acquire().await.expect("acquire");
        let _ = tx.send(g);
    });
    until_children(&observer, PATH, 2).await;
    let before = lock_order(&observer, PATH).await;
    assert_eq!(before.first().map(String::as_str), guard.node().name());

    let sessions = [holder.session().0, waiter.session().0];
    let epochs = [holder.state().epoch, waiter.state().epoch];
    let mut states = [holder.state_watcher(), waiter.state_watcher()];
    let old = ensemble.leader().expect("a leader");
    ensemble.stop_node(old).unwrap();
    let new = ensemble.wait_leader(Some(old)).expect("a new leader");
    assert_ne!(new, old);
    for (w, e) in states.iter_mut().zip(epochs) {
        common::wait_state(w, |i| i.state == SessionState::Connected && i.epoch > e).await;
    }
    assert_eq!([holder.session().0, waiter.session().0], sessions);

    // The holder keeps the lock through the election.
    assert!(
        common::still_pending(guard.lost(), SHORT).await,
        "the lock is not lost"
    );
    assert!(common::still_pending(rx.recv(), SHORT).await, "one holder");
    assert_eq!(lock_order(&observer, PATH).await, before);

    // The release passes the lock to the waiter.
    common::within(guard.release()).await.unwrap();
    let next = common::within(rx.recv()).await.unwrap();
    assert_eq!(next.node().name(), Some(before[1].as_str()));
    assert_eq!(lock_order(&observer, PATH).await, before[1..]);
    common::within(next.release()).await.unwrap();
    assert!(lock_order(&observer, PATH).await.is_empty());
    for c in [holder, waiter, observer] {
        common::within(c.close()).await.unwrap();
    }
}

/// The lock and the latch below an ancestor that the
/// client cannot read. The server gives `NoAuth` to `exists` on that
/// ancestor (ZOOKEEPER-2590). The recipes take it as a present level,
/// and make the missing levels below it. This goes past Curator. Its
/// `ZKPaths.mkdirs` fails with `NoAuth` when the deepest level that
/// exists is unreadable, as here.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_parents_below_an_unreadable_ancestor() {
    const TOP: &str = "/re12-noread";
    let Some(servers) = Servers::start_or_skip(Topology::Standalone) else {
        return;
    };
    let client = common::connect(&servers.connect_string()).await;
    let no_read = [Acl {
        perms: Perms::CREATE | Perms::DELETE | Perms::WRITE | Perms::ADMIN,
        id: Id::ANYONE,
    }];
    common::within(client.create(TOP, b"", CreateMode::Persistent, &no_read))
        .await
        .unwrap();
    assert_eq!(common::within(client.exists(TOP)).await, Err(Error::NoAuth));

    let lock = DistributedLock::new(&client, "/re12-noread/locks/job").unwrap();
    let guard = common::within(lock.acquire()).await.unwrap();
    assert!(
        guard
            .node()
            .as_str()
            .starts_with("/re12-noread/locks/job/_c_")
    );
    common::within(guard.release()).await.unwrap();

    let latch = LeaderLatch::new(&client, "/re12-noread/latch", "p1").unwrap();
    let mut latch = common::within(latch.start()).await.unwrap();
    assert!(common::within(latch.changed()).await.unwrap());
    common::within(latch.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// A lost participant create on a standalone server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_lock_create_recovery_through_proxy() {
    create_recovery(Topology::Standalone).await;
}

/// A lost participant create on the ensemble, through a follower.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_lock_create_recovery_through_proxy_ensemble() {
    create_recovery(Topology::Ensemble).await;
}

/// A connection cut during the participant create.
///
/// (a) The proxy forwards the create and drops the reply, so the server
/// applies it. After the cut the client adopts that node. (b) The proxy
/// holds the create, so the server never sees it. After the cut the
/// client creates the node again. In both cases one node exists, and
/// the release leaves none.
async fn create_recovery(topology: Topology) {
    let Some(servers) = Servers::start_or_skip(topology) else {
        return;
    };
    let target = servers.relay_port();
    let observer = common::connect(&servers.connect_string()).await;

    // (a) The create is applied, and the reply is lost.
    const PA: &str = "/re12-re03a";
    common::within(observer.create(PA, &[], CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let relay = common::Proxy::start(target);
    let client = common::connect(&relay.connect_string()).await;
    let mut state = client.state_watcher();
    relay.mute_replies();
    let lock = DistributedLock::new(&client, PA).unwrap();
    let acquire = tokio::spawn(async move { lock.acquire().await });
    until_children(&observer, PA, 1).await;
    let applied = lock_order(&observer, PA).await;
    assert!(applied[0].starts_with("_c_"));
    relay.cut();
    common::wait_state(&mut state, |i| !i.state.is_connected()).await;
    relay.restore();
    let guard = common::within(acquire).await.unwrap().unwrap();
    assert!(state.current().epoch >= 2);
    assert_eq!(guard.node().name(), Some(applied[0].as_str()), "adopted");
    assert_eq!(lock_order(&observer, PA).await, applied, "one node");
    common::within(guard.release()).await.unwrap();
    assert!(lock_order(&observer, PA).await.is_empty());
    common::within(client.close()).await.unwrap();
    drop(relay);

    // (b) The create never reaches the server.
    const PB: &str = "/re12-re03b";
    common::within(observer.create(PB, &[], CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let proxy = common::Proxy::start(target);
    let client = common::connect(&proxy.connect_string()).await;
    let mut state = client.state_watcher();
    proxy.hold();
    let lock = DistributedLock::new(&client, PB).unwrap();
    let acquire = tokio::spawn(async move { lock.acquire().await });
    // The create is out and held. The server has no node.
    tokio::time::sleep(SHORT).await;
    assert!(lock_order(&observer, PB).await.is_empty());
    proxy.cut();
    common::wait_state(&mut state, |i| !i.state.is_connected()).await;
    proxy.restore();
    let guard = common::within(acquire).await.unwrap().unwrap();
    assert!(state.current().epoch >= 2);
    let made = lock_order(&observer, PB).await;
    assert_eq!(made.len(), 1, "one node");
    assert_eq!(guard.node().name(), Some(made[0].as_str()));
    common::within(guard.release()).await.unwrap();
    assert!(lock_order(&observer, PB).await.is_empty());
    common::within(client.close()).await.unwrap();
    common::within(observer.close()).await.unwrap();
}

/// A guard drop whose `delete` is lost, on a standalone server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_lock_lost_delete_through_proxy() {
    lost_delete(Topology::Standalone).await;
}

/// A guard drop whose `delete` is lost, on the ensemble, through a
/// follower.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_lock_lost_delete_through_proxy_ensemble() {
    lost_delete(Topology::Ensemble).await;
}

/// The proxy drops the `delete` of a guard drop and then cuts the
/// connection, so the node stays as a ghost. The client reconnects in
/// the same session. The guaranteed delete then sends the `delete`
/// again with no further call on the lock. A waiter on a second client
/// gets past the ghost and takes the lock.
async fn lost_delete(topology: Topology) {
    const PATH: &str = "/re12/ghost/lock";
    let Some(servers) = Servers::start_or_skip(topology) else {
        return;
    };
    let proxy = common::Proxy::start(servers.relay_port());
    let a = common::connect(&proxy.connect_string()).await;
    let b = common::connect(&servers.connect_string()).await;
    let mut state = a.state_watcher();
    let session = a.session().0;

    let guard = common::within(DistributedLock::new(&a, PATH).unwrap().acquire())
        .await
        .unwrap();
    let ghost = guard.node().name().unwrap().to_owned();
    let lock = DistributedLock::new(&b, PATH).unwrap();
    let mut waiter = tokio::spawn(async move { lock.acquire().await });
    until_children(&b, PATH, 2).await;

    // The `delete` does not reach the server, so the waiter waits.
    let epoch = state.current().epoch;
    proxy.hold();
    drop(guard);
    assert!(common::still_pending(&mut waiter, SHORT).await, "ghost");
    assert!(lock_order(&b, PATH).await.contains(&ghost));
    proxy.cut();
    common::wait_state(&mut state, |i| !i.state.is_connected()).await;
    proxy.restore();
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    assert_eq!(a.session().0, session);

    let next = common::within(waiter).await.unwrap().unwrap();
    assert_eq!(
        lock_order(&b, PATH).await,
        vec![next.node().name().unwrap().to_owned()]
    );
    common::within(next.release()).await.unwrap();
    assert!(lock_order(&b, PATH).await.is_empty());
    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}
