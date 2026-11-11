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

//! `DistributedLock` against the fake server: contention, a lost
//! predecessor, a lost create, cancellation, `try_acquire`, session
//! expiry, and the node layout.
//!
//! The fake server is the model level of the recipe tests. A `Rule`
//! injects the faults: `Action::DropReply` with `Action::Close` gives a
//! create that the server applied before the drop. `Action::Close`
//! alone gives a create that it did not apply.
//!
//! Each test checks the node layout through `server.cluster()`, not
//! only the client results. The fake server records the session of
//! each frame, so a test can tell which participant sent a request.

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

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use apache_zookeeper::{Client, Error, SessionState};
use apache_zookeeper_recipes::{DistributedLock, LeaderLatch, LockGuard};
use common::{is_v4, poll_once, session_id};
use tokio::sync::mpsc;
use zk_fakeserver::{Action, FakeServer, FrameRecord, Rule, Script, create_mode};

/// The opcodes that the tests match. The recipes crate has no zk-jute
/// dependency, so the values are written here.
const OP_DELETE: i32 = 2;
const OP_EXISTS: i32 = 3;
const OP_GET_DATA: i32 = 4;
const OP_SYNC: i32 = 9;
/// `get_children` sends `getChildren2`, op 12.
const OP_GET_CHILDREN: i32 = 12;
const OP_CREATE2: i32 = 15;
const OP_CREATE_CONTAINER: i32 = 19;

/// The ephemeral owner value of a container node.
const CONTAINER_OWNER: i64 = i64::MIN;

/// The short wait that shows that a waiter does not proceed.
const SHORT: Duration = Duration::from_millis(300);

/// The error code `NoAuth`.
const ERR_NO_AUTH: i32 = -102;
/// The error code `NotReadOnly`.
const ERR_NOT_READ_ONLY: i32 = -119;

/// The children of `path` on the fake server, in Curator lock order:
/// by the text after the last `lock-`, or by the whole name.
fn lock_order(server: &FakeServer, path: &str) -> Vec<String> {
    let mut c = server.cluster().children(path).unwrap_or_default();
    c.sort_by(|a, b| {
        let key = |s: &str| s.rsplit_once("lock-").map_or(s, |(_, t)| t).to_owned();
        key(a).encode_utf16().cmp(key(b).encode_utf16())
    });
    c
}

/// The number of children of `path` on the fake server.
fn child_count(server: &FakeServer, path: &str) -> usize {
    server.cluster().children(path).map_or(0, |c| c.len())
}

/// Waits until `pred` holds for the fake server. The wait does not
/// block the executor.
async fn until(server: &FakeServer, mut pred: impl FnMut(&FakeServer) -> bool) {
    common::within(async {
        while !pred(server) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

/// The frames with `op` since the last clear of the transcript.
fn frames(server: &FakeServer, op: i32) -> Vec<FrameRecord> {
    server
        .cluster()
        .transcript()
        .into_iter()
        .filter(|r| r.op == Some(op))
        .collect()
}

/// The ephemeral nodes of a session.
fn ephemerals(server: &FakeServer, session: i64) -> Vec<String> {
    server
        .cluster()
        .sessions()
        .into_iter()
        .find(|s| s.id == session)
        .map(|s| s.ephemerals)
        .unwrap_or_default()
}

/// Splits a lock node name `_c_<uuid>-lock-<seq>` into the UUID and
/// the sequence text.
fn split_lock_name(name: &str) -> (String, String) {
    let rest = name.strip_prefix("_c_").expect("protected prefix");
    let (uuid, seq) = rest.split_once("-lock-").expect("lock marker");
    (uuid.to_owned(), seq.to_owned())
}

/// Spawns an `acquire` of `path` on `client`. The guard goes to `tx`
/// with the number `n` of the contender.
fn spawn_acquire(
    client: &Client,
    path: &str,
    n: usize,
    tx: mpsc::UnboundedSender<(usize, LockGuard)>,
) -> tokio::task::JoinHandle<()> {
    let lock = DistributedLock::new(client, path).unwrap();
    tokio::spawn(async move {
        let guard = lock.acquire().await.expect("acquire");
        let _ = tx.send((n, guard));
    })
}

/// Five contenders on one path. Mutual exclusion holds at each
/// step. The lock goes in creation order. Each waiter watches only its
/// predecessor, so a release wakes one waiter (`watch_count`).
#[tokio::test]
async fn re01_five_contenders_in_creation_order() {
    const PATH: &str = "/re01/lock";
    let server = common::fake();
    let mut clients = Vec::new();
    for _ in 0..5 {
        clients.push(common::connect(&server.connect_string()).await);
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    for (n, c) in clients.iter().enumerate() {
        spawn_acquire(c, PATH, n, tx.clone());
        // Each node exists before the next contender starts, so the
        // creation order is the contender order.
        until(&server, |s| child_count(s, PATH) == n + 1).await;
    }
    // Four waiters, each with one data watch.
    until(&server, |s| s.cluster().watch_count() == 4).await;

    // Each waiter watches the node just before its own.
    let order = lock_order(&server, PATH);
    let sessions: Vec<i64> = clients.iter().map(session_id).collect();
    for (n, s) in sessions.iter().enumerate() {
        let own = ephemerals(&server, *s);
        assert_eq!(own, vec![format!("{PATH}/{}", order[n])], "contender {n}");
        let watched: BTreeSet<String> = frames(&server, OP_GET_DATA)
            .into_iter()
            .filter(|r| r.session_id == *s)
            .filter_map(|r| r.path)
            .collect();
        let expected: BTreeSet<String> = match n {
            0 => BTreeSet::new(),
            _ => BTreeSet::from([format!("{PATH}/{}", order[n - 1])]),
        };
        assert_eq!(watched, expected, "contender {n}");
    }

    for n in 0..5 {
        let (got, guard) = common::within(rx.recv()).await.unwrap();
        assert_eq!(got, n, "the lock goes in creation order");
        assert_eq!(guard.node().name(), Some(order[n].as_str()));
        // Mutual exclusion: no other contender holds the lock.
        assert!(common::still_pending(rx.recv(), SHORT).await);
        let waiters = 4 - n;
        assert_eq!(server.cluster().watch_count(), waiters);
        assert_eq!(lock_order(&server, PATH).first(), Some(&order[n]));

        server.cluster().clear_transcript();
        common::within(guard.release()).await.unwrap();
        if n < 4 {
            // The release wakes one waiter: only the next contender
            // lists the lock path again.
            let (next, guard) = common::within(rx.recv()).await.unwrap();
            assert_eq!(next, n + 1);
            let listers: BTreeSet<i64> = frames(&server, OP_GET_CHILDREN)
                .into_iter()
                .map(|r| r.session_id)
                .collect();
            assert_eq!(listers, BTreeSet::from([sessions[n + 1]]));
            // Give the guard back to the loop through the channel.
            tx.send((next, guard)).unwrap();
        }
    }
    assert_eq!(child_count(&server, PATH), 0);
    for c in clients {
        common::within(c.close()).await.unwrap();
    }
}

/// The predecessor goes away while its successor sets the watch.
/// `get_data_watched` gives `NoNode`, and the successor loops at once.
///
/// Part one delays the list reply of the successor, and deletes the
/// predecessor in that gap. The successor then reads a stale list, and
/// the model answers its `get_data_watched` with a real `NoNode`. Part
/// two forges one `NoNode` reply while the predecessor stays. The
/// successor lists again, watches the same predecessor, and its delete
/// wakes the successor.
#[tokio::test]
async fn re02_predecessor_deleted_during_watch() {
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let sb = session_id(&b);

    // Part one: the predecessor is gone before the watch.
    const P1: &str = "/re02a";
    let held = common::within(DistributedLock::new(&a, P1).unwrap().acquire())
        .await
        .unwrap();
    let pred = held.node().to_buf();
    server.cluster().clear_transcript();
    server.add_rule(
        Rule::on_request()
            .op(OP_GET_CHILDREN)
            .path(P1)
            .once()
            .then(Action::Delay(Duration::from_millis(500)))
            .then(Action::Model),
    );
    let (tx, mut rx) = mpsc::unbounded_channel();
    spawn_acquire(&b, P1, 1, tx.clone());
    // The model handled the list with the predecessor in it, and the
    // reply waits. The predecessor goes now.
    until(&server, |s| !frames(s, OP_GET_CHILDREN).is_empty()).await;
    server.cluster().delete(pred.as_str()).unwrap();
    let (_, guard) = common::within(rx.recv()).await.unwrap();
    let watched: Vec<String> = frames(&server, OP_GET_DATA)
        .into_iter()
        .filter(|r| r.session_id == sb)
        .filter_map(|r| r.path)
        .collect();
    assert_eq!(watched, vec![pred.as_str().to_owned()]);
    // The successor listed again at once and found itself first.
    assert_eq!(frames(&server, OP_GET_CHILDREN).len(), 2);
    assert_eq!(server.cluster().watch_count(), 0);
    assert_eq!(lock_order(&server, P1), vec![guard.node().name().unwrap()]);
    drop(held);
    common::within(guard.release()).await.unwrap();
    server.clear_rules();

    // Part two: one forged `NoNode` while the predecessor stays.
    const P2: &str = "/re02b";
    let held = common::within(DistributedLock::new(&a, P2).unwrap().acquire())
        .await
        .unwrap();
    let pred = held.node().to_buf();
    server.cluster().clear_transcript();
    server.add_rule(
        Rule::on_request()
            .op(OP_GET_DATA)
            .path(pred.as_str())
            .once()
            .then(Action::Reply { err: -101 }),
    );
    spawn_acquire(&b, P2, 2, tx);
    until(&server, |s| s.cluster().watch_count() == 1).await;
    let reads = frames(&server, OP_GET_DATA);
    assert_eq!(reads.len(), 2, "the successor read again at once");
    assert!(
        reads
            .iter()
            .all(|r| r.path.as_deref() == Some(pred.as_str()))
    );
    assert_eq!(frames(&server, OP_GET_CHILDREN).len(), 2);
    // No missed wakeup: the successor waits, and the release wakes it.
    assert!(common::still_pending(rx.recv(), SHORT).await);
    common::within(held.release()).await.unwrap();
    let (n, guard) = common::within(rx.recv()).await.unwrap();
    assert_eq!(n, 2);
    assert_eq!(lock_order(&server, P2), vec![guard.node().name().unwrap()]);
    common::within(guard.release()).await.unwrap();

    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// The server applies the participant create, and the
/// connection drops before the reply. After the reconnect the recipe
/// adopts the node with its `_c_<uuid>-` prefix. One node exists.
#[tokio::test]
async fn re03a_create_applied_before_loss_is_adopted() {
    const PATH: &str = "/re03a";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let mut state = client.state_watcher();
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::DropReply)
            .then(Action::Close),
    );
    let guard = common::within(DistributedLock::new(&client, PATH).unwrap().acquire())
        .await
        .unwrap();
    // The create went out once, on the first connection.
    let creates = frames(&server, OP_CREATE2);
    assert_eq!(creates.len(), 1);
    assert_eq!(creates[0].conn_ordinal, 1);
    let sent = creates[0].path.clone().unwrap();
    let name = guard.node().name().unwrap().to_owned();
    assert!(format!("{PATH}/{name}").starts_with(&sent));
    // One node, which the client adopted on the second connection.
    assert_eq!(lock_order(&server, PATH), vec![name.clone()]);
    assert!(state.current().epoch >= 2);
    assert!(
        frames(&server, OP_GET_CHILDREN)
            .iter()
            .any(|r| r.conn_ordinal == 2)
    );
    // The lookup lists after a `sync`, so a lagging follower cannot hide
    // the node.
    let lookup: Vec<i32> = server
        .cluster()
        .transcript()
        .into_iter()
        .filter(|r| r.conn_ordinal == 2 && r.path.as_deref() == Some(PATH))
        .filter_map(|r| r.op)
        .collect();
    assert_eq!(lookup.get(..2), Some(&[OP_SYNC, OP_GET_CHILDREN][..]));
    common::wait_state(&mut state, |i| i.state == SessionState::Connected).await;
    common::within(guard.release()).await.unwrap();
    assert_eq!(child_count(&server, PATH), 0);
    common::within(client.close()).await.unwrap();
}

/// The connection drops before the server applies the create.
/// The recipe creates the node again with the same `<uuid>`.
#[tokio::test]
async fn re03b_create_not_applied_is_sent_again() {
    const PATH: &str = "/re03b";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::Close),
    );
    let guard = common::within(DistributedLock::new(&client, PATH).unwrap().acquire())
        .await
        .unwrap();
    let creates = frames(&server, OP_CREATE2);
    assert_eq!(creates.len(), 2, "the create went out again");
    assert_eq!(creates[0].path, creates[1].path, "the same <uuid>");
    // The rule closed the first connection before the model saw the
    // create. The second create went out on the next connection.
    assert!(creates[0].rule.is_some());
    assert_eq!(creates[0].conn_ordinal, 1);
    assert_eq!(creates[1].conn_ordinal, 2);
    let name = guard.node().name().unwrap().to_owned();
    assert!(format!("{PATH}/{name}").starts_with(creates[1].path.as_deref().unwrap()));
    // No orphan: one node.
    assert_eq!(lock_order(&server, PATH), vec![name]);
    common::within(guard.release()).await.unwrap();
    assert_eq!(child_count(&server, PATH), 0);
    common::within(client.close()).await.unwrap();
}

/// A dropped `acquire` future while it waits, and a
/// dropped `LockGuard`, each submit the delete of the own node. The next
/// participant then gets the lock.
#[tokio::test]
async fn re04_drop_of_acquire_and_guard_deletes_the_node() {
    const PATH: &str = "/re04/lock";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let c = common::connect(&server.connect_string()).await;
    let held = common::within(DistributedLock::new(&a, PATH).unwrap().acquire())
        .await
        .unwrap();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let waiter_b = spawn_acquire(&b, PATH, 1, tx.clone());
    until(&server, |s| {
        child_count(s, PATH) == 2 && s.cluster().watch_count() == 1
    })
    .await;
    spawn_acquire(&c, PATH, 2, tx);
    until(&server, |s| {
        child_count(s, PATH) == 3 && s.cluster().watch_count() == 2
    })
    .await;

    // The drop of the waiting `acquire` of B deletes its node. C then
    // watches the holder.
    waiter_b.abort();
    assert!(waiter_b.await.unwrap_err().is_cancelled());
    until(&server, |s| {
        child_count(s, PATH) == 2 && ephemerals(s, session_id(&b)).is_empty()
    })
    .await;
    until(&server, |s| s.cluster().watch_count() == 1).await;
    assert!(common::still_pending(rx.recv(), SHORT).await);

    // The drop of the guard deletes the node of the holder, and C gets
    // the lock.
    drop(held);
    let (n, guard) = common::within(rx.recv()).await.unwrap();
    assert_eq!(n, 2);
    assert_eq!(
        ephemerals(&server, session_id(&c)),
        vec![guard.node().as_str().to_owned()]
    );
    assert_eq!(
        lock_order(&server, PATH),
        vec![guard.node().name().unwrap()]
    );
    drop(guard);
    until(&server, |s| child_count(s, PATH) == 0).await;

    for client in [a, b, c] {
        common::within(client.close()).await.unwrap();
    }
}

/// `try_acquire` on a free lock gives a guard. On a held lock it
/// deletes its node and gives `Ok(None)`.
#[tokio::test]
async fn re05_try_acquire_free_and_held() {
    const PATH: &str = "/re05";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let lock_a = DistributedLock::new(&a, PATH).unwrap();
    let lock_b = DistributedLock::new(&b, PATH).unwrap();

    let held = common::within(lock_a.try_acquire()).await.unwrap().unwrap();
    assert_eq!(lock_order(&server, PATH), vec![held.node().name().unwrap()]);

    server.cluster().clear_transcript();
    assert!(
        common::within(lock_b.try_acquire())
            .await
            .unwrap()
            .is_none()
    );
    // The delete is confirmed when `try_acquire` returns.
    assert_eq!(lock_order(&server, PATH), vec![held.node().name().unwrap()]);
    let made = frames(&server, OP_CREATE2);
    let deleted = frames(&server, OP_DELETE);
    assert_eq!(made.len(), 1);
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].session_id, session_id(&b));
    assert!(
        deleted[0]
            .path
            .as_deref()
            .unwrap()
            .starts_with(made[0].path.as_deref().unwrap())
    );
    // `try_acquire` never waits, so it leaves no watch.
    assert_eq!(server.cluster().watch_count(), 0);

    common::within(held.release()).await.unwrap();
    let guard = common::within(lock_b.try_acquire()).await.unwrap().unwrap();
    assert_eq!(
        lock_order(&server, PATH),
        vec![guard.node().name().unwrap()]
    );
    common::within(guard.release()).await.unwrap();
    assert_eq!(child_count(&server, PATH), 0);

    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// A session expiry while the lock is held.
/// `LockGuard::lost` gives `SessionExpired`. A delete of the node by
/// another client gives `NoNode`. A dropped connection with no expiry
/// does not resolve it.
#[tokio::test]
async fn re06_lost_on_expiry_and_on_foreign_delete() {
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;

    // A foreign delete gives `NoNode`, also after a reconnect.
    let held_b = common::within(DistributedLock::new(&b, "/re06b").unwrap().acquire())
        .await
        .unwrap();
    {
        let lost = held_b.lost();
        tokio::pin!(lost);
        assert!(common::still_pending(&mut lost, SHORT).await);
        let mut state = b.state_watcher();
        server.drop_connections();
        common::wait_state(&mut state, |i| i.state.is_connected() && i.epoch >= 2).await;
        assert!(common::still_pending(&mut lost, SHORT).await);
        server.cluster().delete(held_b.node().as_str()).unwrap();
        assert_eq!(common::within(&mut lost).await, Error::NoNode);
    }
    // The lock was lost before the release, so `release` reports it.
    assert_eq!(common::within(held_b.release()).await, Err(Error::NoNode));

    // An expiry gives `SessionExpired`, to the holder and to a waiter.
    let held_a = common::within(DistributedLock::new(&a, "/re06a").unwrap().acquire())
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<Result<LockGuard, Error>>();
    let lock_b = DistributedLock::new(&b, "/re06a").unwrap();
    tokio::spawn(async move {
        let _ = tx.send(lock_b.acquire().await);
    });
    until(&server, |s| child_count(s, "/re06a") == 2).await;
    let lost = held_a.lost();
    tokio::pin!(lost);
    assert!(common::still_pending(&mut lost, SHORT).await);
    assert!(server.cluster().expire_session(session_id(&a)));
    assert_eq!(common::within(&mut lost).await, Error::SessionExpired);
    // The ephemeral node of A is gone, so the waiter gets the lock.
    let guard = common::within(rx.recv()).await.unwrap().unwrap();
    assert_eq!(
        lock_order(&server, "/re06a"),
        vec![guard.node().name().unwrap()]
    );
    // A new acquire on the expired client fails at once.
    let again = DistributedLock::new(&a, "/re06a").unwrap();
    assert_eq!(
        common::within(again.acquire()).await.unwrap_err(),
        Error::SessionExpired
    );
    // The expiry of a waiting session ends its `acquire`.
    let (tx, mut rx) = mpsc::unbounded_channel::<Result<LockGuard, Error>>();
    let c = common::connect(&server.connect_string()).await;
    let lock_c = DistributedLock::new(&c, "/re06a").unwrap();
    tokio::spawn(async move {
        let _ = tx.send(lock_c.acquire().await);
    });
    until(&server, |s| child_count(s, "/re06a") == 2).await;
    assert!(server.cluster().expire_session(session_id(&c)));
    assert!(matches!(
        common::within(rx.recv()).await.unwrap(),
        Err(Error::SessionExpired)
    ));
    until(&server, |s| child_count(s, "/re06a") == 1).await;
    common::within(guard.release()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// Another client deletes the node of a waiter.
/// The waiter sees it at the next list, makes a new node with a new
/// `<uuid>`, and then gets the lock.
#[tokio::test]
async fn own_node_deleted_while_waiting_makes_a_new_node() {
    const PATH: &str = "/c1";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let held = common::within(DistributedLock::new(&a, PATH).unwrap().acquire())
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    spawn_acquire(&b, PATH, 1, tx);
    until(&server, |s| s.cluster().watch_count() == 1).await;
    let first = ephemerals(&server, session_id(&b));
    assert_eq!(first.len(), 1);
    server.cluster().delete(&first[0]).unwrap();
    common::within(held.release()).await.unwrap();
    let (_, guard) = common::within(rx.recv()).await.unwrap();
    let (old_uuid, _) = split_lock_name(first[0].rsplit('/').next().unwrap());
    let (new_uuid, _) = split_lock_name(guard.node().name().unwrap());
    assert_ne!(old_uuid, new_uuid);
    assert_eq!(
        lock_order(&server, PATH),
        vec![guard.node().name().unwrap()]
    );
    common::within(guard.release()).await.unwrap();
    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// The lock node layout: `<lock_path>/_c_<uuid>-lock-<seq>` with a
/// lowercase version-4 UUID. Missing parents are containers. Foreign
/// children take part in the order as in Curator.
#[tokio::test]
async fn re08_lock_node_layout_and_order() {
    const PATH: &str = "/re08/a/b/lock";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let session = session_id(&client);

    let lock = DistributedLock::new(&client, PATH)
        .unwrap()
        .node_data(b"owner".to_vec());
    let guard = common::within(lock.acquire()).await.unwrap();
    let name = guard.node().name().unwrap().to_owned();
    assert_eq!(guard.node().as_str(), format!("{PATH}/{name}"));
    let (uuid, seq) = split_lock_name(&name);
    assert!(is_v4(&uuid), "{uuid}");
    assert_eq!(seq.len(), 10);
    assert!(seq.chars().all(|c| c.is_ascii_digit()));
    let node = server.cluster().node(guard.node().as_str()).unwrap();
    assert_eq!(node.data.as_deref(), Some(&b"owner"[..]));
    assert_eq!(node.stat.ephemeral_owner, session);
    // Each missing level is a container, made from the top.
    let levels = ["/re08", "/re08/a", "/re08/a/b", PATH];
    for level in levels {
        let n = server.cluster().node(level).unwrap();
        assert_eq!(n.stat.ephemeral_owner, CONTAINER_OWNER, "{level}");
    }
    let made: Vec<String> = frames(&server, OP_CREATE_CONTAINER)
        .into_iter()
        .filter_map(|r| r.path)
        .collect();
    assert_eq!(made, levels.map(str::to_owned).to_vec());
    // Each id is new.
    let other = common::within(lock.try_acquire()).await.unwrap();
    assert!(other.is_none());
    let creates = frames(&server, OP_CREATE2);
    let uuids: BTreeSet<String> = creates
        .iter()
        .filter_map(|r| r.path.as_deref())
        .map(|p| p.trim_start_matches(&format!("{PATH}/_c_")).to_owned())
        .collect();
    assert_eq!(uuids.len(), 2);
    common::within(guard.release()).await.unwrap();

    // Foreign children: Curator keeps a name with no marker whole, so
    // "000" is before each sequence and "zzz" after each one.
    const FOREIGN: &str = "/re08f";
    server
        .cluster()
        .create(FOREIGN, b"", create_mode::PERSISTENT)
        .unwrap();
    server
        .cluster()
        .create("/re08f/000", b"", create_mode::PERSISTENT)
        .unwrap();
    server
        .cluster()
        .create("/re08f/zzz", b"", create_mode::PERSISTENT)
        .unwrap();
    let foreign = DistributedLock::new(&client, FOREIGN).unwrap();
    assert!(
        common::within(foreign.try_acquire())
            .await
            .unwrap()
            .is_none()
    );
    server.cluster().clear_transcript();
    let (tx, mut rx) = mpsc::unbounded_channel();
    spawn_acquire(&client, FOREIGN, 0, tx);
    until(&server, |s| s.cluster().watch_count() == 1).await;
    let watched: Vec<String> = frames(&server, OP_GET_DATA)
        .into_iter()
        .filter_map(|r| r.path)
        .collect();
    assert_eq!(watched, vec!["/re08f/000".to_owned()]);
    assert!(common::still_pending(rx.recv(), SHORT).await);
    server.cluster().delete("/re08f/000").unwrap();
    let (_, guard) = common::within(rx.recv()).await.unwrap();
    let order = lock_order(&server, FOREIGN);
    assert_eq!(order.len(), 2);
    assert_eq!(order[0], guard.node().name().unwrap());
    assert_eq!(order[1], "zzz");
    common::within(guard.release()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// A waiter keeps its place across a reconnect with no expiry. With
/// the watches restored, it keeps its predecessor watch. With
/// `restore_watches(false)`, the watch ends with `ConnectionLost`, and
/// the waiter lists again and watches again. In both cases the release
/// of the holder wakes it.
#[tokio::test]
async fn waiter_keeps_its_place_across_a_reconnect() {
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    for restore in [true, false] {
        let path = format!("/reconnect-{restore}");
        let b = common::within(
            common::builder(&server.connect_string())
                .restore_watches(restore)
                .connect(),
        )
        .await
        .unwrap();
        let held = common::within(DistributedLock::new(&a, &path).unwrap().acquire())
            .await
            .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn_acquire(&b, &path, 1, tx);
        until(&server, |s| s.cluster().watch_count() == 1).await;
        let own = ephemerals(&server, session_id(&b));

        let mut state = b.state_watcher();
        server.cluster().clear_transcript();
        server.drop_connections();
        common::wait_state(&mut state, |i| i.state.is_connected() && i.epoch >= 2).await;
        // The holder reconnects too. Its node stays.
        let mut state_a = a.state_watcher();
        common::wait_state(&mut state_a, |i| i.state.is_connected()).await;
        until(&server, |s| s.cluster().watch_count() == 1).await;
        assert!(common::still_pending(rx.recv(), SHORT).await, "{restore}");
        assert_eq!(ephemerals(&server, session_id(&b)), own, "{restore}");
        let reads = frames(&server, OP_GET_DATA)
            .into_iter()
            .filter(|r| r.session_id == session_id(&b))
            .count();
        // A restored watch needs no new read.
        assert_eq!(reads, usize::from(!restore), "{restore}");

        common::within(held.release()).await.unwrap();
        let (_, guard) = common::within(rx.recv()).await.unwrap();
        assert_eq!(
            vec![guard.node().as_str().to_owned()],
            own,
            "the waiter kept its node"
        );
        common::within(guard.release()).await.unwrap();
        common::within(b.close()).await.unwrap();
    }
    common::within(a.close()).await.unwrap();
}

/// `release` sends the delete again after a connection loss. When the
/// server applied the first delete, the `NoNode` of the retry is a
/// success. When it did not, the retry deletes the node.
#[tokio::test]
async fn release_after_connection_loss_is_sent_again() {
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    for applied in [true, false] {
        let path = format!("/release-{applied}");
        let guard = common::within(DistributedLock::new(&client, &path).unwrap().acquire())
            .await
            .unwrap();
        let node = guard.node().as_str().to_owned();
        let rule = Rule::on_request().op(OP_DELETE).path(&node).once();
        let rule = if applied {
            rule.then(Action::DropReply).then(Action::Close)
        } else {
            rule.then(Action::Close)
        };
        server.add_rule(rule);
        server.cluster().clear_transcript();
        common::within(guard.release()).await.unwrap();
        let deletes = frames(&server, OP_DELETE);
        assert_eq!(deletes.len(), 2, "{applied}");
        assert!(
            deletes
                .iter()
                .all(|r| r.path.as_deref() == Some(node.as_str()))
        );
        assert_eq!(child_count(&server, &path), 0, "{applied}");
        server.clear_rules();
    }
    common::within(client.close()).await.unwrap();
}

/// A dropped `acquire` whose create reply did not come leaves a node
/// with an unknown name. The late reply gives the name, and the
/// guaranteed delete removes the node with no further call on the lock.
/// Up to that time the orphan blocks the other participants.
#[tokio::test]
async fn dropped_create_in_flight_is_deleted_in_the_background() {
    const PATH: &str = "/orphan/lock";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    server
        .cluster()
        .create("/orphan", b"", create_mode::PERSISTENT)
        .unwrap();
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    // The model applies the create at once and sends the reply late.
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::Delay(Duration::from_millis(500))),
    );
    let lock = DistributedLock::new(&a, PATH).unwrap();
    {
        let mut acquire = std::pin::pin!(lock.acquire());
        assert!(poll_once(acquire.as_mut()).is_pending());
    }
    until(&server, |s| child_count(s, PATH) == 1).await;
    let orphan = server.cluster().children(PATH).unwrap()[0].clone();
    assert_eq!(ephemerals(&server, session_id(&a)).len(), 1);

    // The orphan is first, so another participant does not get the lock.
    let other = DistributedLock::new(&b, PATH).unwrap();
    assert!(common::within(other.try_acquire()).await.unwrap().is_none());

    until(&server, |s| child_count(s, PATH) == 0).await;
    let deleted: Vec<String> = frames(&server, OP_DELETE)
        .into_iter()
        .filter_map(|r| r.path)
        .filter(|p| p.ends_with(&orphan))
        .collect();
    assert_eq!(deleted, vec![format!("{PATH}/{orphan}")]);
    let guard = common::within(other.try_acquire()).await.unwrap().unwrap();
    common::within(guard.release()).await.unwrap();

    // A call with no orphan sends no extra request.
    server.cluster().clear_transcript();
    let guard = common::within(lock.acquire()).await.unwrap();
    assert!(frames(&server, OP_SYNC).is_empty());
    common::within(guard.release()).await.unwrap();
    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// A dropped `acquire` after a connection loss on the create, and before
/// the lookup of the protected node, gives the id to the guaranteed
/// delete. The create was applied, so the background lookup finds the
/// node after a `sync` and deletes it. Another client then gets the
/// lock, with no further call on the first lock.
#[tokio::test]
async fn dropped_lookup_after_connection_loss_is_deleted_in_the_background() {
    const PATH: &str = "/orphan-loss";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let other = common::connect(&server.connect_string()).await;
    let mut state = client.state_watcher();
    let epoch = state.current().epoch;
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::DropReply)
            .then(Action::Close),
    );
    let lock = DistributedLock::new(&client, PATH).unwrap();
    {
        let mut acquire = std::pin::pin!(lock.acquire());
        assert!(poll_once(acquire.as_mut()).is_pending());
        common::wait_state(&mut state, |i| {
            i.state != SessionState::Connected || i.epoch > epoch
        })
        .await;
        // The future takes the connection loss and waits for the
        // lookup. It cannot finish, because no reply came yet.
        assert!(poll_once(acquire.as_mut()).is_pending());
    }
    assert_eq!(child_count(&server, PATH), 1);
    let orphan = server.cluster().children(PATH).unwrap()[0].clone();
    until(&server, |s| child_count(s, PATH) == 0).await;
    let deleted: Vec<String> = frames(&server, OP_DELETE)
        .into_iter()
        .filter_map(|r| r.path)
        .collect();
    assert_eq!(deleted, vec![format!("{PATH}/{orphan}")]);

    let guard = common::within(DistributedLock::new(&other, PATH).unwrap().try_acquire())
        .await
        .unwrap()
        .unwrap();
    common::within(guard.release()).await.unwrap();
    common::within(client.close()).await.unwrap();
    common::within(other.close()).await.unwrap();
}

/// A `release` whose `delete` fails with an error that is not a
/// connection loss gives that error. The node stays at that time, so the
/// guaranteed delete takes it and sends the `delete` once more at once.
/// A second such error would end the job. `try_acquire`
/// hands over its node in the same way. Another client then gets the
/// lock.
#[tokio::test]
async fn release_with_a_failed_delete_hands_the_node_over() {
    const PATH: &str = "/release-throttled";
    const ERR_THROTTLED: i32 = -127;
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let guard = common::within(DistributedLock::new(&a, PATH).unwrap().acquire())
        .await
        .unwrap();
    let node = guard.node().as_str().to_owned();
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::Reply { err: ERR_THROTTLED }),
    );
    server.cluster().clear_transcript();
    assert_eq!(
        common::within(guard.release()).await,
        Err(Error::ThrottledOp)
    );
    until(&server, |s| child_count(s, PATH) == 0).await;
    assert_eq!(frames(&server, OP_DELETE).len(), 2);

    // A `try_acquire` behind a holder deletes its own node.
    let held = common::within(DistributedLock::new(&b, PATH).unwrap().acquire())
        .await
        .unwrap();
    server.clear_rules();
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::Reply { err: ERR_THROTTLED }),
    );
    let lock = DistributedLock::new(&a, PATH).unwrap();
    assert_eq!(
        common::within(lock.try_acquire()).await.err(),
        Some(Error::ThrottledOp)
    );
    until(&server, |s| child_count(s, PATH) == 1).await;
    assert_eq!(lock_order(&server, PATH), vec![held.node().name().unwrap()]);
    common::within(held.release()).await.unwrap();
    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// A full request queue (`max_pending_requests`) refuses a `delete` at
/// once, and the client sends nothing. A `release` gives that error,
/// and its node goes to the guaranteed delete. A guard drop also hands
/// its node over. The guaranteed delete waits for room in the queue and
/// sends the `delete` again, with no new connection. Another client
/// then gets the lock.
#[tokio::test]
async fn refused_delete_is_sent_when_the_queue_has_room() {
    const PATH: &str = "/refused/lock";
    const LIMIT: usize = 2;
    let server = common::fake();
    let a = common::within(
        common::builder(&server.connect_string())
            .max_pending_requests(LIMIT)
            .connect(),
    )
    .await
    .unwrap();
    let b = common::connect(&server.connect_string()).await;
    let epoch = a.state().epoch;
    let lock = DistributedLock::new(&a, PATH).unwrap();
    for drop_guard in [false, true] {
        let guard = common::within(lock.acquire()).await.unwrap();
        server.cluster().clear_transcript();
        server.hold();
        let reads: Vec<_> = (0..LIMIT).map(|_| a.get_data("/")).collect();
        assert_eq!(a.stats().pending, LIMIT);
        if drop_guard {
            drop(guard);
        } else {
            assert_eq!(
                common::within(guard.release()).await,
                Err(Error::TooManyPendingRequests)
            );
        }
        tokio::time::sleep(SHORT).await;
        assert_eq!(child_count(&server, PATH), 1);
        server.release();
        for read in reads {
            common::within(read).await.unwrap();
        }
        until(&server, |s| child_count(s, PATH) == 0).await;
        assert_eq!(frames(&server, OP_DELETE).len(), 1);
    }
    assert_eq!(a.state().epoch, epoch);
    let guard = common::within(DistributedLock::new(&b, PATH).unwrap().try_acquire())
        .await
        .unwrap()
        .unwrap();
    common::within(guard.release()).await.unwrap();
    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// A `release` future that drops while its `delete` is in flight gives
/// the node to the guaranteed delete. Here the server ignores both
/// `delete` requests, and the connection then drops. The guaranteed
/// delete sends the `delete` again after the reconnect, and another
/// client gets the lock.
#[tokio::test]
async fn dropped_release_with_lost_delete_is_sent_again() {
    const PATH: &str = "/release-dropped";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let guard = common::within(DistributedLock::new(&a, PATH).unwrap().acquire())
        .await
        .unwrap();
    let node = guard.node().as_str().to_owned();
    for _ in 0..2 {
        server.add_rule(
            Rule::on_request()
                .op(OP_DELETE)
                .path(&node)
                .once()
                .then(Action::Ignore),
        );
    }
    server.cluster().clear_transcript();
    {
        let mut release = std::pin::pin!(guard.release());
        assert!(poll_once(release.as_mut()).is_pending());
    }
    until(&server, |s| s.script().rules()[1].fired() > 0).await;
    assert_eq!(child_count(&server, PATH), 1);
    server.drop_connections();
    until(&server, |s| child_count(s, PATH) == 0).await;
    assert_eq!(frames(&server, OP_DELETE).len(), 3);
    let guard = common::within(DistributedLock::new(&b, PATH).unwrap().try_acquire())
        .await
        .unwrap()
        .unwrap();
    common::within(guard.release()).await.unwrap();
    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// After `NotReadOnly`, the server did not apply the delete. A `NoNode`
/// on the retry then means that another client deleted the node, so
/// `release` reports the lost lock.
#[tokio::test]
async fn release_after_not_read_only_reports_a_foreign_delete() {
    const PATH: &str = "/release-ro";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let guard = common::within(DistributedLock::new(&client, PATH).unwrap().acquire())
        .await
        .unwrap();
    let node = guard.node().as_str().to_owned();
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::Reply {
                err: ERR_NOT_READ_ONLY,
            })
            .then(Action::Close),
    );
    // Another client deletes the node before the release.
    server.cluster().delete(&node).unwrap();
    server.cluster().clear_transcript();
    let released = common::within(guard.release()).await;
    assert_eq!(released, Err(Error::NoNode));
    assert_eq!(frames(&server, OP_DELETE).len(), 2);
    common::within(client.close()).await.unwrap();
}

/// The server checks the read permission only of a node that exists, so
/// `exists` on an unreadable ancestor gives `NoAuth`. The lock and the
/// latch take that as a present level, and make the missing levels
/// below it. This goes past Curator, which fails with `NoAuth` when the
/// deepest level that exists is unreadable, as here.
#[tokio::test]
async fn parents_below_an_unreadable_ancestor() {
    const TOP: &str = "/noread";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    server
        .cluster()
        .create(TOP, b"", create_mode::PERSISTENT)
        .unwrap();
    server.add_rule(
        Rule::on_request()
            .op(OP_EXISTS)
            .path(TOP)
            .then(Action::Reply { err: ERR_NO_AUTH }),
    );
    let lock = DistributedLock::new(&client, "/noread/locks/job").unwrap();
    let guard = common::within(lock.acquire()).await.unwrap();
    assert!(guard.node().as_str().starts_with("/noread/locks/job/_c_"));
    let made: Vec<String> = frames(&server, OP_CREATE_CONTAINER)
        .into_iter()
        .filter_map(|r| r.path)
        .collect();
    assert_eq!(made, ["/noread/locks", "/noread/locks/job"]);
    common::within(guard.release()).await.unwrap();

    let latch = LeaderLatch::new(&client, "/noread/latch", "p1").unwrap();
    let mut latch = common::within(latch.start()).await.unwrap();
    assert!(common::within(latch.changed()).await.unwrap());
    common::within(latch.close()).await.unwrap();
    assert!(server.script().rules()[0].fired() > 0);
    common::within(client.close()).await.unwrap();
}

/// A guard drop whose `delete` meets a connection loss leaves the
/// node. The guaranteed delete sends it again after the reconnect, with
/// no further call on the lock. Another lock on another client then
/// gets the lock. A drop with no fault adds no request.
#[tokio::test]
async fn guard_drop_with_lost_delete_is_sent_again_after_the_reconnect() {
    const PATH: &str = "/ghost/lock";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let other = common::connect(&server.connect_string()).await;
    let mut state = client.state_watcher();
    let lock = DistributedLock::new(&client, PATH).unwrap();

    let guard = common::within(lock.acquire()).await.unwrap();
    server.cluster().clear_transcript();
    drop(guard);
    let guard = common::within(lock.acquire()).await.unwrap();
    assert_eq!(frames(&server, OP_DELETE).len(), 1);
    assert!(frames(&server, OP_SYNC).is_empty());

    let node = guard.node().as_str().to_owned();
    let epoch = state.current().epoch;
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::Close),
    );
    server.cluster().clear_transcript();
    let waiter = {
        let other = DistributedLock::new(&other, PATH).unwrap();
        tokio::spawn(async move { other.acquire().await })
    };
    until(&server, |s| s.cluster().watch_count() == 1).await;
    drop(guard);
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;

    let guard = common::within(waiter).await.unwrap().unwrap();
    assert_eq!(
        lock_order(&server, PATH),
        vec![guard.node().name().unwrap()]
    );
    let resent = frames(&server, OP_DELETE)
        .into_iter()
        .filter(|r| r.path.as_deref() == Some(node.as_str()))
        .count();
    assert_eq!(resent, 2);
    common::within(guard.release()).await.unwrap();
    common::within(client.close()).await.unwrap();
    common::within(other.close()).await.unwrap();
}

/// An `acquire` future that is dropped while it waits submits the
/// `delete` of its node. When a connection loss stops that `delete`, the
/// guaranteed delete sends it again after the reconnect. The waiter on
/// another client then gets the lock when the holder releases.
#[tokio::test]
async fn waiting_acquire_drop_with_lost_delete_is_sent_again() {
    const PATH: &str = "/ghost-wait/lock";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let c = common::connect(&server.connect_string()).await;
    let mut state = b.state_watcher();
    let held = common::within(DistributedLock::new(&a, PATH).unwrap().acquire())
        .await
        .unwrap();
    let held_name = held.node().name().unwrap().to_owned();
    let lock = DistributedLock::new(&b, PATH).unwrap();
    let epoch = state.current().epoch;
    let mut acquire = Box::pin(lock.acquire());
    common::within(async {
        while server.cluster().watch_count() == 0 {
            assert!(poll_once(acquire.as_mut()).is_pending());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let waiter = lock_order(&server, PATH)
        .into_iter()
        .find(|c| *c != held_name)
        .unwrap();
    let third = {
        let lock = DistributedLock::new(&c, PATH).unwrap();
        tokio::spawn(async move { lock.acquire().await })
    };
    until(&server, |s| s.cluster().watch_count() == 2).await;
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&format!("{PATH}/{waiter}"))
            .once()
            .then(Action::Close),
    );
    drop(acquire);
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    until(&server, |s| child_count(s, PATH) == 2).await;
    assert!(!lock_order(&server, PATH).contains(&waiter));
    common::within(held.release()).await.unwrap();

    let guard = common::within(third).await.unwrap().unwrap();
    assert_eq!(
        lock_order(&server, PATH),
        vec![guard.node().name().unwrap()]
    );
    common::within(guard.release()).await.unwrap();
    common::within(a.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
    common::within(c.close()).await.unwrap();
}

/// A retry that a connection loss stops too goes out again at the next
/// epoch. The guaranteed delete keeps the node until a `delete`
/// succeeds.
#[tokio::test]
async fn lost_retry_is_sent_again_at_the_next_epoch() {
    const PATH: &str = "/ghost-requeue/lock";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let lock = DistributedLock::new(&client, PATH).unwrap();
    let guard = common::within(lock.acquire()).await.unwrap();
    let node = guard.node().as_str().to_owned();
    for _ in 0..2 {
        server.add_rule(
            Rule::on_request()
                .op(OP_DELETE)
                .path(&node)
                .once()
                .then(Action::Close),
        );
    }
    server.cluster().clear_transcript();
    drop(guard);
    until(&server, |s| child_count(s, PATH) == 0).await;
    assert!(server.script().rules()[1].fired() > 0);
    assert_eq!(frames(&server, OP_DELETE).len(), 3);
    common::within(client.close()).await.unwrap();
}

/// Makes a protected create whose outcome stays unknown: the server
/// applies it, the connection drops before the reply, and the `acquire`
/// future drops before the lookup. Gives the name of the orphan node.
async fn lose_create(
    server: &FakeServer,
    client: &Client,
    lock: &DistributedLock,
    path: &str,
) -> String {
    let before = lock_order(server, path);
    let mut state = client.state_watcher();
    let epoch = state.current().epoch;
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{path}/_c_"))
            .once()
            .then(Action::DropReply)
            .then(Action::Close),
    );
    {
        let mut acquire = std::pin::pin!(lock.acquire());
        assert!(poll_once(acquire.as_mut()).is_pending());
        common::wait_state(&mut state, |i| {
            i.state != SessionState::Connected || i.epoch > epoch
        })
        .await;
        assert!(poll_once(acquire.as_mut()).is_pending());
    }
    let after = server.cluster().children(path).unwrap();
    after.into_iter().find(|c| !before.contains(c)).unwrap()
}

/// The background lookup deletes only the children with the exact
/// recorded id. The node of another participant stays, also when its
/// id differs in one character, and when it sorts after the orphan.
#[tokio::test]
async fn background_lookup_keeps_the_nodes_of_other_ids() {
    const PATH: &str = "/orphan-keep/lock";
    const OTHER: &str = "_c_00000000-0000-4000-8000-000000000000-lock-9999999999";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    let mut state = a.state_watcher();
    server
        .cluster()
        .create("/orphan-keep", b"", create_mode::PERSISTENT)
        .unwrap();
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    server
        .cluster()
        .create(&format!("{PATH}/{OTHER}"), b"", create_mode::PERSISTENT)
        .unwrap();
    // Each `sync` fails until the near name exists, so no lookup lists
    // the parent before that time.
    server.add_rule(
        Rule::on_request()
            .op(OP_SYNC)
            .path(PATH)
            .then(Action::Reply {
                err: ERR_NOT_READ_ONLY,
            }),
    );
    let lock = DistributedLock::new(&a, PATH).unwrap();
    let orphan = lose_create(&server, &a, &lock, PATH).await;
    // The near name shares the whole id of the orphan except its last
    // character.
    let id = &orphan[..39];
    let near_last = if id.ends_with('0') { '1' } else { '0' };
    let near = format!("{}{near_last}-lock-9999999998", &id[..38]);
    server
        .cluster()
        .create(&format!("{PATH}/{near}"), b"", create_mode::PERSISTENT)
        .unwrap();
    server.clear_rules();
    let epoch = state.current().epoch;
    server.drop_connections();
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    until(&server, |s| !lock_order(s, PATH).contains(&orphan)).await;
    let kids = lock_order(&server, PATH);
    assert!(kids.contains(&OTHER.to_owned()), "{kids:?}");
    assert!(kids.contains(&near), "{kids:?}");
    assert_eq!(kids.len(), 2, "{kids:?}");
    common::within(a.close()).await.unwrap();
}

/// The background lookup retries after a connection loss on its `sync`
/// and on its `delete`. Each retry waits for the next epoch, lists
/// again, and deletes the orphan at last. `Action::Close` alone applies
/// nothing.
#[tokio::test]
async fn background_lookup_retries_after_a_loss() {
    const PATH: &str = "/orphan-reap-loss";
    let server = common::fake();
    let a = common::connect(&server.connect_string()).await;
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    server.add_rule(
        Rule::on_request()
            .op(OP_SYNC)
            .path(PATH)
            .once()
            .then(Action::Close),
    );
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::Close),
    );
    let lock = DistributedLock::new(&a, PATH).unwrap();
    let orphan = lose_create(&server, &a, &lock, PATH).await;
    until(&server, |s| child_count(s, PATH) == 0).await;
    assert!(server.script().rules()[0].fired() > 0);
    assert!(server.script().rules()[1].fired() > 0);
    let deletes = frames(&server, OP_DELETE)
        .into_iter()
        .filter(|r| r.path.as_deref() == Some(format!("{PATH}/{orphan}").as_str()))
        .count();
    assert_eq!(deletes, 2);
    common::within(a.close()).await.unwrap();
}

/// A full request queue refuses the `sync` of the background lookup.
/// The lookup waits for room in the queue and lists the parent again in
/// the same epoch, so it deletes the orphan with no new connection.
#[tokio::test]
async fn background_lookup_waits_for_room_in_the_queue() {
    const PATH: &str = "/orphan-full";
    const LIMIT: usize = 2;
    let server = common::fake();
    let a = common::within(
        common::builder(&server.connect_string())
            .max_pending_requests(LIMIT)
            .connect(),
    )
    .await
    .unwrap();
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    // No connection succeeds, so the lookup waits for its epoch.
    server.add_rule(Rule::on_connect().then(Action::Close));
    let lock = DistributedLock::new(&a, PATH).unwrap();
    let orphan = lose_create(&server, &a, &lock, PATH).await;
    // These reads wait in the queue and fill it. Their replies come late
    // on the next connection, so the lookup at that epoch is refused.
    let reads: Vec<_> = (0..LIMIT).map(|_| a.get_data("/")).collect();
    assert_eq!(a.stats().pending, LIMIT);
    server.cluster().clear_transcript();
    server.set_script(
        Script::new().rule(
            Rule::on_request()
                .op(OP_GET_DATA)
                .path("/")
                .then(Action::Delay(SHORT)),
        ),
    );
    let mut state = a.state_watcher();
    let connected = common::wait_state(&mut state, |i| i.state == SessionState::Connected).await;
    for read in reads {
        common::within(read).await.unwrap();
    }
    until(&server, |s| child_count(s, PATH) == 0).await;
    assert_eq!(a.state().epoch, connected.epoch);
    let deleted: Vec<String> = frames(&server, OP_DELETE)
        .into_iter()
        .filter_map(|r| r.path)
        .collect();
    assert_eq!(deleted, vec![format!("{PATH}/{orphan}")]);
    common::within(a.close()).await.unwrap();
}

/// A guard drop on a read-only connection gets `NotReadOnly`. The
/// guaranteed delete does not send the `delete` again on a later
/// read-only connection. It sends it at the next read-write connection,
/// and another client then gets the lock.
#[tokio::test]
async fn read_only_connection_does_not_delete() {
    const PATH: &str = "/ro-ghost/lock";
    let server = common::fake();
    let client = common::within(
        common::builder(&server.connect_string())
            .allow_read_only(true)
            .connect(),
    )
    .await
    .unwrap();
    let other = common::connect(&server.connect_string()).await;
    let guard = common::within(DistributedLock::new(&client, PATH).unwrap().acquire())
        .await
        .unwrap();
    let node = guard.node().as_str().to_owned();
    let mut state = client.state_watcher();
    server.set_read_only(true);
    server.drop_connections();
    common::wait_state(&mut state, |i| i.state == SessionState::ConnectedReadOnly).await;
    server.cluster().clear_transcript();
    drop(guard);
    until(&server, |s| !frames(s, OP_DELETE).is_empty()).await;
    // A new read-only epoch sends nothing.
    let epoch = state.current().epoch;
    server.drop_connections();
    common::wait_state(&mut state, |i| {
        i.state == SessionState::ConnectedReadOnly && i.epoch > epoch
    })
    .await;
    tokio::time::sleep(SHORT).await;
    assert_eq!(frames(&server, OP_DELETE).len(), 1);
    assert!(server.cluster().node(&node).is_some());

    server.set_read_only(false);
    server.drop_connections();
    until(&server, |s| s.cluster().node(&node).is_none()).await;
    assert_eq!(frames(&server, OP_DELETE).len(), 2);
    let guard = common::within(DistributedLock::new(&other, PATH).unwrap().try_acquire())
        .await
        .unwrap()
        .unwrap();
    common::within(guard.release()).await.unwrap();
    common::within(other.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// A connection loss, then `NotReadOnly`, then `NoNode`. The first
/// `delete` can have been applied, so the release is a success. The
/// later `NotReadOnly` does not clear that fact.
#[tokio::test]
async fn release_loss_then_not_read_only_then_no_node() {
    const PATH: &str = "/release-loss-ro";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let guard = common::within(DistributedLock::new(&client, PATH).unwrap().acquire())
        .await
        .unwrap();
    let node = guard.node().as_str().to_owned();
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::DropReply)
            .then(Action::Close),
    );
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::Reply {
                err: ERR_NOT_READ_ONLY,
            })
            .then(Action::Close),
    );
    server.cluster().clear_transcript();
    let released = common::within(guard.release()).await;
    assert_eq!(frames(&server, OP_DELETE).len(), 3);
    assert_eq!(released, Ok(()));
    common::within(client.close()).await.unwrap();
}

/// The recovery lookup gets `NotReadOnly` on its `sync`. It waits for
/// the next connection, lists again and adopts the node. It does not
/// fail, and it does not create again.
#[tokio::test]
async fn lookup_sync_not_read_only_waits() {
    const PATH: &str = "/lookup-ro";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    server
        .cluster()
        .create(PATH, b"", create_mode::PERSISTENT)
        .unwrap();
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::DropReply)
            .then(Action::Close),
    );
    server.add_rule(
        Rule::on_request()
            .op(OP_SYNC)
            .path(PATH)
            .once()
            .then(Action::Reply {
                err: ERR_NOT_READ_ONLY,
            })
            .then(Action::Close),
    );
    server.cluster().clear_transcript();
    let guard = common::within(DistributedLock::new(&client, PATH).unwrap().acquire())
        .await
        .unwrap();
    assert!(server.script().rules()[1].fired() > 0);
    assert_eq!(frames(&server, OP_CREATE2).len(), 1);
    assert_eq!(
        lock_order(&server, PATH),
        vec![guard.node().name().unwrap()]
    );
    common::within(guard.release()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// A connection loss on a `delete` that went out on a read-only
/// connection does not make a later `NoNode` a success. A read-only
/// server applies no write, so only another client can have deleted the
/// node, and `release` reports the lost lock.
#[tokio::test]
async fn release_after_loss_on_read_only_reports_a_foreign_delete() {
    const PATH: &str = "/release-ro-loss";
    let server = common::fake();
    let client = common::within(
        common::builder(&server.connect_string())
            .allow_read_only(true)
            .connect(),
    )
    .await
    .unwrap();
    let guard = common::within(DistributedLock::new(&client, PATH).unwrap().acquire())
        .await
        .unwrap();
    let node = guard.node().as_str().to_owned();
    let mut state = client.state_watcher();
    server.set_read_only(true);
    server.drop_connections();
    common::wait_state(&mut state, |i| i.state == SessionState::ConnectedReadOnly).await;
    // The first delete: the read-only model answers `NotReadOnly`.
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::Model),
    );
    // The second delete, on the next read-only connection: the
    // connection closes before the model sees the frame.
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::Close),
    );
    let release = tokio::spawn(guard.release());
    until(&server, |s| s.script().rules()[0].fired() > 0).await;
    server.drop_connections();
    until(&server, |s| s.script().rules()[1].fired() > 0).await;
    // Another client deletes the node in the majority.
    server.cluster().delete(&node).unwrap();
    server.set_read_only(false);
    server.drop_connections();
    let released = common::within(release).await.unwrap();
    assert_eq!(released, Err(Error::NoNode));
    common::within(client.close()).await.unwrap();
}

/// Two waiters on one lock object: `acquire` A waits behind
/// the holder, and `acquire` B on the same lock waits behind A. A drops,
/// and a connection loss stops its `delete`. The client reconnects in
/// the same session. The guaranteed delete sends the lost `delete`
/// again, and B gets the lock after the holder releases. No other call
/// on the lock comes.
#[tokio::test]
async fn waiting_acquire_passes_a_sibling_lost_delete() {
    const PATH: &str = "/ghost-sibling/lock";
    let server = common::fake();
    let h = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let mut state = b.state_watcher();
    let held = common::within(DistributedLock::new(&h, PATH).unwrap().acquire())
        .await
        .unwrap();
    let lock = Arc::new(DistributedLock::new(&b, PATH).unwrap());
    let epoch = state.current().epoch;
    let mut acquire_a = Box::pin(lock.acquire());
    common::within(async {
        while server.cluster().watch_count() == 0 {
            assert!(poll_once(acquire_a.as_mut()).is_pending());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let a_node = format!("{PATH}/{}", lock_order(&server, PATH)[1]);
    let waiter = {
        let lock = Arc::clone(&lock);
        tokio::spawn(async move { lock.acquire().await })
    };
    until(&server, |s| {
        s.cluster().watch_count() == 2 && child_count(s, PATH) == 3
    })
    .await;
    let b_name = lock_order(&server, PATH)[2].clone();
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&a_node)
            .once()
            .then(Action::Close),
    );
    server.cluster().clear_transcript();
    drop(acquire_a);
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    common::within(held.release()).await.unwrap();

    let guard = common::within(waiter).await.unwrap().unwrap();
    assert_eq!(guard.node().name().unwrap(), b_name);
    assert_eq!(lock_order(&server, PATH), vec![b_name]);
    let resent = frames(&server, OP_DELETE)
        .into_iter()
        .filter(|r| r.path.as_deref() == Some(a_node.as_str()))
        .count();
    assert_eq!(resent, 2);
    common::within(guard.release()).await.unwrap();
    common::within(h.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}

/// The guaranteed delete removes only the node that a drop gave up. Two
/// waiters on one lock object wait, and a dropped `acquire` leaves a
/// create whose reply comes late. The late reply gives the node name,
/// and the node goes once. Neither waiter loses its own node, also at a
/// new epoch, so each keeps its place and gets the lock in turn.
#[tokio::test]
async fn guaranteed_delete_keeps_the_own_nodes() {
    const PATH: &str = "/ghost-own/lock";
    let server = common::fake();
    let h = common::connect(&server.connect_string()).await;
    let b = common::connect(&server.connect_string()).await;
    let mut state = b.state_watcher();
    let held = common::within(DistributedLock::new(&h, PATH).unwrap().acquire())
        .await
        .unwrap();
    let lock = Arc::new(DistributedLock::new(&b, PATH).unwrap());
    let spawn = |lock: &Arc<DistributedLock>| {
        let lock = Arc::clone(lock);
        tokio::spawn(async move { lock.acquire().await })
    };
    let first = spawn(&lock);
    until(&server, |s| s.cluster().watch_count() == 1).await;
    let second = spawn(&lock);
    until(&server, |s| s.cluster().watch_count() == 2).await;
    let waiters = lock_order(&server, PATH)[1..].to_vec();
    assert_eq!(waiters.len(), 2);

    server.cluster().clear_transcript();
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::Delay(Duration::from_millis(300))),
    );
    {
        let mut acquire = std::pin::pin!(lock.acquire());
        assert!(poll_once(acquire.as_mut()).is_pending());
    }
    until(&server, |s| {
        child_count(s, PATH) == 3 && !frames(s, OP_DELETE).is_empty()
    })
    .await;
    server.clear_rules();
    let create = frames(&server, OP_CREATE2)[0].path.clone().unwrap();
    let deletes = frames(&server, OP_DELETE);
    assert_eq!(deletes.len(), 1, "{deletes:?}");
    assert!(deletes[0].path.as_deref().unwrap().starts_with(&create));
    assert_eq!(lock_order(&server, PATH)[1..], waiters[..]);

    let epoch = state.current().epoch;
    server.drop_connections();
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    tokio::time::sleep(SHORT).await;
    assert_eq!(frames(&server, OP_DELETE).len(), 1);
    assert_eq!(lock_order(&server, PATH)[1..], waiters[..]);
    assert!(!first.is_finished() && !second.is_finished());

    common::within(held.release()).await.unwrap();
    let guard = common::within(first).await.unwrap().unwrap();
    assert_eq!(guard.node().name().unwrap(), waiters[0]);
    common::within(guard.release()).await.unwrap();
    let guard = common::within(second).await.unwrap().unwrap();
    assert_eq!(guard.node().name().unwrap(), waiters[1]);
    assert_eq!(lock_order(&server, PATH), vec![waiters[1].clone()]);
    common::within(guard.release()).await.unwrap();
    common::within(h.close()).await.unwrap();
    common::within(b.close()).await.unwrap();
}
