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

//! `TreeCache` against the fake server: the initial sync, the events,
//! the resync, the end states, and the start failure on a server before
//! 3.6.
//!
//! The fake server answers `addWatch` (op 106) like a 3.6 server. A
//! rule with `Action::Reply { err: -6 }` (`ZUNIMPLEMENTED`) on op 106
//! acts as a 3.5 server.
//!
//! Each test compares the cache with the node layout of the model
//! through `server.cluster()`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::time::Duration;

use apache_zookeeper::{Error, WatcherKind};
use apache_zookeeper_recipes::{TreeCache, TreeEvent};
use common::{label, next, until_mark};
use zk_fakeserver::{Action, Cluster, FakeServer, Rule};

/// The opcodes that the tests match.
const EXISTS: i32 = 3;
const GET_DATA: i32 = 4;
/// `get_children` sends `getChildren2`, the form with a stat.
const GET_CHILDREN: i32 = 12;
const ADD_WATCH: i32 = 106;

/// A short wait that shows that the cache gives no more events.
const QUIET: Duration = Duration::from_millis(300);

fn create(c: &Cluster, path: &str, data: &[u8]) {
    c.create(path, data, 0)
        .unwrap_or_else(|e| panic!("create {path}: {e}"));
}

fn set(c: &Cluster, path: &str, data: &[u8]) {
    c.set_data(path, data)
        .unwrap_or_else(|e| panic!("set {path}: {e}"));
}

fn delete(c: &Cluster, path: &str) {
    c.delete(path)
        .unwrap_or_else(|e| panic!("delete {path}: {e}"));
}

/// Shows that the cache gives no event for a while.
async fn assert_quiet(cache: &mut TreeCache) {
    assert!(
        common::still_pending(cache.next(), QUIET).await,
        "the cache gave an event"
    );
}

/// Checks that the cache holds the subtree of the model at `root` down
/// to `max_depth`, with the same stats, children and data.
fn assert_same(cache: &TreeCache, c: &Cluster, root: &str, data: bool, max_depth: Option<usize>) {
    let mut todo = vec![(root.to_owned(), 0_usize)];
    let mut seen = 0;
    if c.node(root).is_none() {
        assert_eq!(cache.get(root), None, "{root}");
        return;
    }
    while let Some((path, depth)) = todo.pop() {
        let info = c
            .node(&path)
            .unwrap_or_else(|| panic!("model has no {path}"));
        let node = cache
            .get(path.as_str())
            .unwrap_or_else(|| panic!("cache has no {path}"));
        assert_eq!(node.stat.czxid.0, info.stat.czxid, "czxid of {path}");
        assert_eq!(node.stat.mzxid.0, info.stat.mzxid, "mzxid of {path}");
        assert_eq!(
            node.stat.version.get(),
            info.stat.version,
            "version of {path}"
        );
        if data {
            let want = info.data.clone().unwrap_or_default();
            assert_eq!(
                node.data.as_deref(),
                Some(want.as_slice()),
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
        assert_eq!(kids, info.children, "children of {path}");
        for k in kids {
            let child = if path == "/" {
                format!("/{k}")
            } else {
                format!("{path}/{k}")
            };
            todo.push((child, depth + 1));
        }
        seen += 1;
    }
    assert!(seen > 0);
}

/// Builds `/r` with the given children, in order.
fn build(server: &FakeServer, nodes: &[&str]) {
    let c = server.cluster();
    create(c, "/r", b"root");
    for n in nodes {
        create(c, n, n.as_bytes());
    }
}

/// Starts a default cache of `/r` and checks the initial events.
async fn start(client: &apache_zookeeper::Client, want: &[&str]) -> TreeCache {
    let mut cache = common::within(TreeCache::builder(client, "/r").start())
        .await
        .expect("start");
    let mut expected: Vec<String> = want.iter().map(|p| format!("+{p}")).collect();
    expected.push("Initialized".to_owned());
    assert_eq!(until_mark(&mut cache).await, expected);
    cache
}

/// The initial sync of a tree with three levels, with writes
/// that race the sync. One `NodeAdded` for each node, then
/// `Initialized`. The `czxid`/`mzxid` rule applies the racing changes,
/// and no change after the watch is set is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn re09_initial_sync_with_racing_writes() {
    let server = common::fake();
    let c = server.cluster();
    build(&server, &["/r/a", "/r/b", "/r/a/x", "/r/a/y", "/r/b/z"]);
    let client = common::connect(&server.connect_string()).await;

    // The replies of the first level wait. The model has read the
    // first level already, so the writes below come after that read
    // and before the read of the second level.
    server.add_rule(
        Rule::on_request()
            .op(GET_DATA)
            .path("/r/a")
            .once()
            .then(Action::Delay(Duration::from_millis(500))),
    );
    let started = tokio::spawn(TreeCache::builder(&client, "/r").start());
    c.wait_for_frame(common::WAIT, |f| {
        f.op == Some(GET_CHILDREN) && f.path.as_deref() == Some("/r/b")
    })
    .expect("the sync reads the first level");
    // The order of the writes is the order of their events.
    set(c, "/r/a", b"a1");
    set(c, "/r/a/x", b"x1");
    create(c, "/r/b/new", b"new");
    delete(c, "/r/b/z");

    let mut cache = common::within(started).await.unwrap().expect("start");
    // The sync saw the old `/r/a`, the new `/r/a/x`, no `/r/b/new` and
    // no `/r/b/z`.
    assert_eq!(
        until_mark(&mut cache).await,
        ["+/r", "+/r/a", "+/r/b", "+/r/a/x", "+/r/a/y", "Initialized"]
    );
    // The events of the writes then apply by the rule. The change of
    // `/r/a/x` is in the cache already, and `/r/b/z` was never in it.
    let ev = next(&mut cache).await;
    assert_eq!(label(&ev), "~/r/a");
    let TreeEvent::NodeUpdated { node, .. } = ev else {
        unreachable!()
    };
    assert_eq!(node.data.as_deref(), Some(&b"a1"[..]));
    assert_eq!(label(&next(&mut cache).await), "+/r/b/new");
    assert_quiet(&mut cache).await;
    assert_same(&cache, c, "/r", true, None);
    // The watch was set before the first read.
    let frames = c.transcript();
    let first = |op: i32| frames.iter().position(|f| f.op == Some(op)).unwrap();
    assert!(first(ADD_WATCH) < first(GET_DATA));
}

/// Create, set data, delete of a subtree (deepest first), delete
/// and re-create of a node (a new `czxid`), and events below
/// `max_depth` (ignored). Also `cache_data(false)`.
#[tokio::test]
async fn re10_events_and_max_depth() {
    let server = common::fake();
    let c = server.cluster();
    build(&server, &["/r/a", "/r/a/b", "/r/a/b/c", "/r/k"]);
    let client = common::connect(&server.connect_string()).await;
    let mut cache = start(&client, &["/r", "/r/a", "/r/k", "/r/a/b", "/r/a/b/c"]).await;

    // Create and set data.
    create(c, "/r/n", b"n1");
    let ev = next(&mut cache).await;
    assert_eq!(label(&ev), "+/r/n");
    set(c, "/r/n", b"n2");
    let ev = next(&mut cache).await;
    assert_eq!(label(&ev), "~/r/n");
    assert_eq!(cache.get("/r/n").unwrap().data.as_deref(), Some(&b"n2"[..]));
    assert_eq!(cache.children("/r").unwrap(), ["a", "k", "n"]);

    // The read after the data change of `/r/a` finds no node, because
    // the whole subtree is gone. The cache then removes the subtree,
    // deepest first. The later delete events find nothing to remove.
    set(c, "/r/a", b"a1");
    delete(c, "/r/a/b/c");
    delete(c, "/r/a/b");
    delete(c, "/r/a");
    assert_eq!(label(&next(&mut cache).await), "-/r/a/b/c");
    assert_eq!(label(&next(&mut cache).await), "-/r/a/b");
    assert_eq!(label(&next(&mut cache).await), "-/r/a");
    assert_eq!(cache.get("/r/a/b"), None);
    assert_eq!(cache.children("/r").unwrap(), ["k", "n"]);

    // A delete and a create make a new node with a new `czxid`.
    let old = cache.get("/r/k").unwrap();
    delete(c, "/r/k");
    create(c, "/r/k", b"k2");
    assert_eq!(label(&next(&mut cache).await), "-/r/k");
    let ev = next(&mut cache).await;
    assert_eq!(label(&ev), "+/r/k");
    let TreeEvent::NodeAdded { node, .. } = ev else {
        unreachable!()
    };
    assert_ne!(node.stat.czxid, old.stat.czxid);
    assert_eq!(node.data.as_deref(), Some(&b"k2"[..]));
    assert_quiet(&mut cache).await;
    assert_same(&cache, c, "/r", true, None);

    // A second cache with a depth limit and no data. It reads with
    // `exists`, and ignores the events below the limit.
    let before = c.transcript().len();
    let mut shallow = common::within(
        TreeCache::builder(&client, "/r")
            .max_depth(Some(1))
            .cache_data(false)
            .start(),
    )
    .await
    .expect("start");
    assert_eq!(
        until_mark(&mut shallow).await,
        ["+/r", "+/r/k", "+/r/n", "Initialized"]
    );
    let frames = c.transcript();
    let ops: Vec<i32> = frames[before..].iter().filter_map(|f| f.op).collect();
    assert!(ops.contains(&EXISTS) && !ops.contains(&GET_DATA), "{ops:?}");
    // `/r/k` is at the limit, so its children are not read.
    let listed: Vec<_> = frames[before..]
        .iter()
        .filter(|f| f.op == Some(GET_CHILDREN))
        .filter_map(|f| f.path.clone())
        .collect();
    assert_eq!(listed, ["/r"]);

    create(c, "/r/n/deep", b"d");
    set(c, "/r/k", b"k3");
    // The event of `/r/n/deep` comes first, and the cache ignores it.
    let ev = next(&mut shallow).await;
    assert_eq!(label(&ev), "~/r/k");
    let TreeEvent::NodeUpdated { node, .. } = ev else {
        unreachable!()
    };
    assert_eq!(node.data, None);
    assert_eq!(shallow.get("/r/n/deep"), None);
    assert_quiet(&mut shallow).await;
    assert_same(&shallow, c, "/r", false, Some(1));
}

/// A reconnect with changes made while disconnected gives a full
/// read, one event for each difference, then `Resynced`. A drop of
/// `next` during the resync loses nothing.
#[tokio::test]
async fn re11_resync_after_reconnect() {
    let mut server = common::fake();
    build(&server, &["/r/a", "/r/b", "/r/c"]);
    let client = common::connect(&server.connect_string()).await;
    let mut state = client.state_watcher();
    let mut cache = start(&client, &["/r", "/r/a", "/r/b", "/r/c"]).await;
    let epoch = client.state().epoch;

    // The first read of the resync waits.
    server.add_rule(
        Rule::on_request()
            .op(GET_DATA)
            .path("/r")
            .once()
            .then(Action::Delay(Duration::from_millis(500))),
    );
    server.stop();
    common::wait_state(&mut state, |i| !i.state.is_connected()).await;
    {
        let c = server.cluster();
        set(c, "/r/a", b"a1");
        delete(c, "/r/b");
        create(c, "/r/d", b"d");
        create(c, "/r/c/e", b"e");
    }
    server.resume().expect("resume");
    common::wait_state(&mut state, |i| i.state.is_connected() && i.epoch > epoch).await;

    // The server sends no events for the changes of the gap. The cache
    // finds them with a full read. A `next` that is dropped while the
    // read waits loses nothing.
    assert!(common::still_pending(cache.next(), Duration::from_millis(100)).await);
    assert_eq!(
        until_mark(&mut cache).await,
        ["-/r/b", "~/r/a", "+/r/d", "+/r/c/e", "Resynced"]
    );
    assert_quiet(&mut cache).await;
    let c = server.cluster();
    assert_same(&cache, c, "/r", true, None);

    // The watch is still armed.
    set(c, "/r/d", b"d2");
    assert_eq!(label(&next(&mut cache).await), "~/r/d");
}

/// `WatchError::Lagged` with a small `persistent_watch_buffer`
/// gives a resync.
#[tokio::test]
async fn re11_resync_after_lag() {
    let server = common::fake();
    let c = server.cluster();
    build(&server, &[]);
    let client = common::within(
        common::builder(&server.connect_string())
            .persistent_watch_buffer(1)
            .connect(),
    )
    .await
    .expect("connect");
    let mut cache = start(&client, &["/r"]).await;

    // The cache does not poll, so the watcher buffer overflows.
    let names = ["/r/n1", "/r/n2", "/r/n3", "/r/n4", "/r/n5"];
    for n in names {
        create(c, n, b"x");
    }
    tokio::time::sleep(QUIET).await;

    // Each new node gives one `NodeAdded`: from the event that the
    // buffer kept, or from the resync. The kept event is older than the
    // resync, so it changes nothing after it.
    let events = until_mark(&mut cache).await;
    assert_eq!(events.last().map(String::as_str), Some("Resynced"));
    let mut added: Vec<String> = events
        .iter()
        .filter_map(|e| e.strip_prefix('+').map(str::to_owned))
        .collect();
    added.sort();
    assert_eq!(added, names);
    assert_eq!(events.len(), names.len() + 1, "{events:?}");
    assert_quiet(&mut cache).await;
    assert_same(&cache, c, "/r", true, None);
}

/// With `restore_watches(false)` the watcher ends with
/// `ConnectionLost` at the disconnect. The cache calls `add_watch` again
/// at the next epoch and resyncs once.
#[tokio::test]
async fn re11_rearm_without_restored_watches() {
    let mut server = common::fake();
    build(&server, &["/r/a"]);
    let client = common::within(
        common::builder(&server.connect_string())
            .restore_watches(false)
            .connect(),
    )
    .await
    .expect("connect");
    let mut state = client.state_watcher();
    let mut cache = start(&client, &["/r", "/r/a"]).await;
    let epoch = client.state().epoch;

    server.stop();
    common::wait_state(&mut state, |i| !i.state.is_connected()).await;
    {
        let c = server.cluster();
        set(c, "/r/a", b"a1");
        create(c, "/r/b", b"b");
    }
    server.resume().expect("resume");
    common::wait_state(&mut state, |i| i.state.is_connected() && i.epoch > epoch).await;

    assert_eq!(until_mark(&mut cache).await, ["~/r/a", "+/r/b", "Resynced"]);
    assert_quiet(&mut cache).await;
    let c = server.cluster();
    assert_same(&cache, c, "/r", true, None);
    // One `addWatch` on each connection, and no watch restore.
    let frames = c.transcript();
    let adds: Vec<u64> = frames
        .iter()
        .filter(|f| f.op == Some(ADD_WATCH))
        .map(|f| f.conn)
        .collect();
    assert_eq!(adds.len(), 2, "{adds:?}");
    assert_ne!(adds[0], adds[1]);
    assert!(!frames.iter().any(|f| matches!(f.op, Some(101 | 105))));

    // The new watch works.
    create(c, "/r/a/k", b"k");
    assert_eq!(label(&next(&mut cache).await), "+/r/a/k");
}

/// The end states: a session expiry gives `Err(SessionExpired)` once,
/// and `remove_watches` gives `Err(NoWatcher)` once. Then `next` gives
/// `None`.
#[tokio::test]
async fn cache_ends_on_terminal_state_and_removed_watch() {
    let server = common::fake();
    let c = server.cluster();
    build(&server, &["/r/a"]);

    // A removed watch.
    let client = common::connect(&server.connect_string()).await;
    let mut cache = start(&client, &["/r", "/r/a"]).await;
    common::within(client.remove_watches("/r", WatcherKind::PersistentRecursive, false))
        .await
        .expect("remove_watches");
    assert_eq!(
        common::within(cache.next()).await,
        Some(Err(Error::NoWatcher))
    );
    assert_eq!(common::within(cache.next()).await, None);
    assert_eq!(common::within(cache.next()).await, None);
    // The copy stays readable.
    assert!(cache.get("/r/a").is_some());

    // A session expiry.
    let mut cache = start(&client, &["/r", "/r/a"]).await;
    assert!(c.expire_session(client.session().0.0));
    assert_eq!(
        common::within(cache.next()).await,
        Some(Err(Error::SessionExpired))
    );
    assert_eq!(common::within(cache.next()).await, None);
    // A start on the expired session fails at once.
    let again = common::within(TreeCache::builder(&client, "/r").start()).await;
    assert_eq!(again.err(), Some(Error::SessionExpired));
}

/// A server before 3.6 answers `addWatch` with `ZUNIMPLEMENTED`. The
/// start fails with `Error::Unimplemented`, before any read.
#[tokio::test]
async fn start_fails_without_persistent_watches() {
    let server = common::fake();
    let c = server.cluster();
    build(&server, &["/r/a"]);
    server.add_rule(
        Rule::on_request()
            .op(ADD_WATCH)
            .then(Action::Reply { err: -6 }),
    );
    let client = common::connect(&server.connect_string()).await;
    let started = common::within(TreeCache::builder(&client, "/r").start()).await;
    assert_eq!(started.err(), Some(Error::Unimplemented));
    let frames = c.transcript();
    assert!(frames.iter().any(|f| f.op == Some(ADD_WATCH)));
    assert!(
        !frames
            .iter()
            .any(|f| matches!(f.op, Some(EXISTS | GET_DATA | GET_CHILDREN)))
    );
}
