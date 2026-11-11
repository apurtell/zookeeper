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

//! `TreeCache` against a real server: the initial sync, the events and
//! the resync, and the start failure against 3.5.10.
//!
//! The sync, event and resync tests run on a standalone server and on
//! the three-node ensemble. On the ensemble, one more test changes the
//! leader while the initial sync runs.
//!
//! The 3.5.10 test always selects that release, whatever
//! `ZK_TEST_SERVER_VERSION` says. It skips when the release is not in
//! `/tmp/zk-servers` (`dev/get-release-server.sh 3.5.10`).
//!
//! The tests compare the cache with the server through a second client.

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

use std::time::Duration;

use apache_zookeeper::{Client, CreateMode, Error, SessionState, Version, acl};
use apache_zookeeper_recipes::{TreeCache, TreeEvent};
use common::{ProxyGroup, Servers, Topology, label, next, until_mark};

/// A short wait that shows that the cache gives no more events.
const QUIET: Duration = Duration::from_millis(500);

async fn create(c: &Client, path: &str, data: &[u8]) {
    common::within(c.create(path, data, CreateMode::Persistent, acl::OPEN_ACL_UNSAFE))
        .await
        .unwrap_or_else(|e| panic!("create {path}: {e}"));
}

async fn set(c: &Client, path: &str, data: &[u8]) {
    common::within(c.set_data(path, data, Version::ANY))
        .await
        .unwrap_or_else(|e| panic!("set {path}: {e}"));
}

async fn delete(c: &Client, path: &str) {
    common::within(c.delete(path, Version::ANY))
        .await
        .unwrap_or_else(|e| panic!("delete {path}: {e}"));
}

/// The labels of the events until the cache is quiet.
async fn until_quiet(cache: &mut TreeCache) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(item) = tokio::time::timeout(QUIET, cache.next()).await {
        match item {
            Some(Ok(ev)) => out.push(label(&ev)),
            other => panic!("expected an event, got {other:?}"),
        }
    }
    out
}

/// Checks that the cache holds the subtree of the server at `root`
/// down to `max_depth`, with the same stats, children and data.
async fn assert_same(
    cache: &TreeCache,
    c: &Client,
    root: &str,
    data: bool,
    max_depth: Option<usize>,
) {
    let mut todo = vec![(root.to_owned(), 0_usize)];
    while let Some((path, depth)) = todo.pop() {
        let (bytes, stat) = common::within(c.get_data(path.as_str()))
            .await
            .unwrap_or_else(|e| panic!("get_data {path}: {e}"));
        let node = cache
            .get(path.as_str())
            .unwrap_or_else(|| panic!("cache has no {path}"));
        assert_eq!(node.stat.czxid, stat.czxid, "czxid of {path}");
        assert_eq!(node.stat.mzxid, stat.mzxid, "mzxid of {path}");
        if data {
            assert_eq!(
                node.data.as_deref(),
                Some(bytes.as_slice()),
                "data of {path}"
            );
        } else {
            assert_eq!(node.data, None, "data of {path}");
        }
        let kids = cache.children(path.as_str()).unwrap();
        if max_depth.is_some_and(|m| depth >= m) {
            assert!(kids.is_empty(), "children of {path} below the depth limit");
            continue;
        }
        let mut want = common::within(c.get_children(path.as_str()))
            .await
            .unwrap_or_else(|e| panic!("get_children {path}: {e}"));
        want.sort();
        assert_eq!(kids, want, "children of {path}");
        for k in kids {
            todo.push((format!("{path}/{k}"), depth + 1));
        }
    }
}

/// The initial sync and the events on a standalone server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_tree_cache_sync_and_events() {
    sync_and_events(Topology::Standalone).await;
}

/// The initial sync and the events on the ensemble. The writer and the
/// cache can use different servers.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_tree_cache_sync_and_events_ensemble() {
    sync_and_events(Topology::Ensemble).await;
}

/// The initial sync with racing writes, then the
/// events of each kind of change.
async fn sync_and_events(topology: Topology) {
    let Some(servers) = Servers::start_or_skip(topology) else {
        return;
    };
    let ports = servers.client_ports();
    let cs = servers.connect_string();
    let writer = common::connect(&cs).await;
    let client = common::connect(&cs).await;
    for (p, d) in [
        ("/t", "root"),
        ("/t/a", "a"),
        ("/t/b", "b"),
        ("/t/a/x", "x"),
        ("/t/a/y", "y"),
        ("/t/b/z", "z"),
    ] {
        create(&writer, p, d.as_bytes()).await;
    }

    // An initial sync with writes that race it.
    let started = tokio::spawn(TreeCache::builder(&client, "/t").start());
    set(&writer, "/t/a", b"a1").await;
    create(&writer, "/t/b/new", b"new").await;
    set(&writer, "/t/a/x", b"x1").await;
    delete(&writer, "/t/b/z").await;
    let mut cache = common::within(started).await.unwrap().expect("start");
    let initial = until_mark(&mut cache).await;
    assert_eq!(initial.first().map(String::as_str), Some("+/t"));
    assert_eq!(initial.last().map(String::as_str), Some("Initialized"));
    let _ = until_quiet(&mut cache).await;
    common::wait_caught_up(&ports);
    assert_same(&cache, &writer, "/t", true, None).await;

    // Create and set data.
    create(&writer, "/t/n", b"n1").await;
    assert_eq!(label(&next(&mut cache).await), "+/t/n");
    set(&writer, "/t/n", b"n2").await;
    let ev = next(&mut cache).await;
    assert_eq!(label(&ev), "~/t/n");
    let TreeEvent::NodeUpdated { node, .. } = ev else {
        unreachable!()
    };
    assert_eq!(node.data.as_deref(), Some(&b"n2"[..]));

    // The delete of a subtree, deepest first.
    delete(&writer, "/t/a/x").await;
    delete(&writer, "/t/a/y").await;
    delete(&writer, "/t/a").await;
    assert_eq!(
        until_quiet(&mut cache).await,
        ["-/t/a/x", "-/t/a/y", "-/t/a"]
    );

    // A delete and a create make a new node with a new `czxid`.
    let old = cache.get("/t/b").unwrap();
    delete(&writer, "/t/b/new").await;
    delete(&writer, "/t/b").await;
    create(&writer, "/t/b", b"b2").await;
    assert_eq!(
        until_quiet(&mut cache).await,
        ["-/t/b/new", "-/t/b", "+/t/b"]
    );
    assert_ne!(cache.get("/t/b").unwrap().stat.czxid, old.stat.czxid);
    assert_same(&cache, &writer, "/t", true, None).await;

    // A depth limit with no data.
    let mut shallow = common::within(
        TreeCache::builder(&client, "/t")
            .max_depth(Some(1))
            .cache_data(false)
            .start(),
    )
    .await
    .expect("start");
    assert_eq!(
        until_mark(&mut shallow).await,
        ["+/t", "+/t/b", "+/t/n", "Initialized"]
    );
    create(&writer, "/t/n/deep", b"d").await;
    set(&writer, "/t/b", b"b3").await;
    assert_eq!(until_quiet(&mut shallow).await, ["~/t/b"]);
    assert_same(&shallow, &writer, "/t", false, Some(1)).await;
    assert_eq!(until_quiet(&mut cache).await, ["+/t/n/deep", "~/t/b"]);

    // The root of the cache need not exist.
    let mut empty = common::within(TreeCache::builder(&client, "/none").start())
        .await
        .expect("start");
    assert_eq!(until_mark(&mut empty).await, ["Initialized"]);
    create(&writer, "/none", b"").await;
    assert_eq!(label(&next(&mut empty).await), "+/none");
    create(&writer, "/none/k", b"").await;
    assert_eq!(label(&next(&mut empty).await), "+/none/k");
}

/// The resync on a standalone server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_tree_cache_resync() {
    resync(Topology::Standalone).await;
}

/// The resync on the ensemble, with one proxy in front of each
/// server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_tree_cache_resync_ensemble() {
    resync(Topology::Ensemble).await;
}

/// The resync with a proxy cut for the reconnect. Both with watch restore
/// and with `restore_watches(false)`.
async fn resync(topology: Topology) {
    let Some(servers) = Servers::start_or_skip(topology) else {
        return;
    };
    let ports = servers.client_ports();
    let writer = common::connect(&servers.connect_string()).await;
    for (p, d) in [("/t", "root"), ("/t/a", "a"), ("/t/b", "b"), ("/t/c", "c")] {
        create(&writer, p, d.as_bytes()).await;
    }
    for restore in [true, false] {
        let proxy = ProxyGroup::start(&ports);
        let client = common::within(
            common::builder(&proxy.connect_string())
                .restore_watches(restore)
                .connect(),
        )
        .await
        .expect("connect");
        let mut state = client.state_watcher();
        let mut cache = common::within(TreeCache::builder(&client, "/t").start())
            .await
            .expect("start");
        assert_eq!(until_mark(&mut cache).await.last().unwrap(), "Initialized");
        let epoch = client.state().epoch;

        // The changes of the gap give no events. The resync finds them.
        proxy.cut();
        common::wait_state(&mut state, |i| !i.state.is_connected()).await;
        set(&writer, "/t/a", b"a1").await;
        delete(&writer, "/t/b").await;
        create(&writer, "/t/d", b"d").await;
        create(&writer, "/t/c/e", b"e").await;
        // The server of the reconnect must hold the changes of the gap,
        // so the resync finds all of them.
        common::wait_caught_up(&ports);
        proxy.restore();
        common::wait_state(&mut state, |i| i.state.is_connected() && i.epoch > epoch).await;
        assert_eq!(
            until_quiet(&mut cache).await,
            ["-/t/b", "~/t/a", "+/t/d", "+/t/c/e", "Resynced"],
            "restore_watches({restore})"
        );
        assert_same(&cache, &writer, "/t", true, None).await;

        // The watch works after the resync.
        set(&writer, "/t/d", b"d2").await;
        assert_eq!(label(&next(&mut cache).await), "~/t/d");

        // Undo the changes for the next round.
        drop(cache);
        delete(&writer, "/t/c/e").await;
        delete(&writer, "/t/d").await;
        create(&writer, "/t/b", b"b").await;
        common::within(client.close()).await.ok();
    }
}

/// The leader of the ensemble changes while the
/// initial sync of a `TreeCache` runs.
///
/// The cached tree is a chain, so the breadth-first read needs one
/// round trip for each level. The proxies delay each round trip, so the
/// read is still in progress when the leader stops. Every server then
/// drops its clients. The start waits for the next connection, arms
/// the watch again and reads the tree again. The result holds the
/// writes before and after the election, and the cache stays live.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_tree_cache_sync_through_leader_change() {
    const DEPTH: usize = 40;
    let Some(servers) = Servers::start_or_skip(Topology::Ensemble) else {
        return;
    };
    let ensemble = servers.ensemble().unwrap();
    let ports = servers.client_ports();
    // The sessions must outlive the election.
    let connect = |cs: String| async move {
        common::within(
            common::builder(&cs)
                .session_timeout(Duration::from_secs(10))
                .connect(),
        )
        .await
        .expect("connect")
    };
    let writer = connect(servers.connect_string()).await;
    let mut chain = vec!["/lc".to_owned()];
    for k in 1..DEPTH {
        chain.push(format!("{}/n{k}", chain[k - 1]));
    }
    for (k, p) in chain.iter().enumerate() {
        create(&writer, p, k.to_string().as_bytes()).await;
    }

    let proxy = ProxyGroup::start(&ports);
    let client = connect(proxy.connect_string()).await;
    let session = client.session().0;
    let epoch = client.state().epoch;
    let mut state = client.state_watcher();
    let mut writer_state = writer.state_watcher();
    let writer_epoch = writer.state().epoch;
    // Each level of the read takes at least 50 ms, so the read of the
    // chain takes at least 2 s.
    proxy.delay(Duration::from_millis(25));
    let started = tokio::spawn(TreeCache::builder(&client, "/lc").start());
    tokio::time::sleep(Duration::from_millis(300)).await;
    // A write races the read before the election.
    set(&writer, &chain[DEPTH - 1], b"early").await;

    let old = ensemble.leader().expect("a leader");
    ensemble.stop_node(old).unwrap();
    common::wait_state(&mut state, |i| !i.state.is_connected()).await;
    assert!(
        !started.is_finished(),
        "the initial sync runs at the leader change"
    );
    proxy.delay(Duration::ZERO);
    assert!(ensemble.wait_leader(Some(old)).is_some(), "a new leader");

    // Writes after the election, while the cache client reconnects.
    common::wait_state(&mut writer_state, |i| {
        i.state == SessionState::Connected && i.epoch > writer_epoch
    })
    .await;
    set(&writer, &chain[1], b"late").await;
    let late = format!("{}/late", chain[5]);
    create(&writer, &late, b"late").await;

    let mut cache = common::within(started).await.unwrap().expect("start");
    assert!(client.state().epoch > epoch, "the start spans a reconnect");
    assert_eq!(client.session().0, session, "the session stays");
    let initial = until_mark(&mut cache).await;
    assert_eq!(initial.first().map(String::as_str), Some("+/lc"));
    assert_eq!(initial.last().map(String::as_str), Some("Initialized"));
    let _ = until_quiet(&mut cache).await;
    common::wait_caught_up(&ports);
    assert_same(&cache, &writer, "/lc", true, None).await;
    assert!(cache.get(late.as_str()).is_some(), "the late node");

    // The cache is live on the new leader.
    set(&writer, &chain[DEPTH - 1], b"after").await;
    let ev = next(&mut cache).await;
    assert_eq!(label(&ev), format!("~{}", chain[DEPTH - 1]));
    drop(cache);
    common::within(client.close()).await.unwrap();
    common::within(writer.close()).await.unwrap();
}

/// `start` against 3.5.10 fails, because that server has no
/// persistent watches. Expected: `Error::Unimplemented`.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_tree_cache_start_fails_on_3_5_10() {
    let Some(server) = common::RealServer::start_version_or_skip(Some(common::LEGACY_VERSION))
    else {
        return;
    };
    let client = common::connect(&server.connect_string()).await;
    let mut state = client.state_watcher();
    create(&client, "/t", b"root").await;
    let epoch = client.state().epoch;
    let started = common::within(TreeCache::builder(&client, "/t").start()).await;
    assert_eq!(started.err(), Some(Error::Unimplemented));
    // The 3.5 server closes the connection after it answers an unknown
    // opcode (`UnimplementedRequestProcessor`). The session stays, and
    // the client connects again.
    common::wait_state(&mut state, |i| i.state.is_connected() && i.epoch > epoch).await;
    create(&client, "/t/a", b"a").await;
}
