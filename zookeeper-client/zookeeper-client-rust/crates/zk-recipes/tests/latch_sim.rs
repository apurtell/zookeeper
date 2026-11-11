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

//! `LeaderLatch` against the fake server: session expiry, leader change
//! and reconnect, the drop of a latch, and the node layout.
//!
//! The fake server is the model level of the recipe tests. Each test
//! checks the node layout through `server.cluster()`, not only the latch
//! results.
//! `drop_connections` ends the connections and keeps the sessions, so
//! the clients reconnect with a new epoch and no expiry.

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

use apache_zookeeper::{Error, SessionState};
use apache_zookeeper_recipes::{Latch, LeaderLatch};
use common::{expect, ids, is_v4, poll_once, session_id, start_latch};
use zk_fakeserver::{Action, FakeServer, Rule};

/// The time that a test gives a waiter to show that it does not
/// proceed.
const QUIET: Duration = Duration::from_millis(200);

/// The `delete` opcode in the transcript.
const OP_DELETE: i32 = 2;

/// The `exists` opcode in the transcript.
const OP_EXISTS: i32 = 3;

/// The `getData` opcode of the predecessor read.
const OP_GET_DATA: i32 = 4;

/// The owner of a container node in the fake model.
const CONTAINER_OWNER: i64 = i64::MIN;

/// The `create2` opcode of an `EphemeralSequential` create.
const OP_CREATE2: i32 = 15;

/// The `getChildren2` opcode of `get_children`.
const OP_GET_CHILDREN: i32 = 12;

/// The children of `path` in sequence order.
fn latch_children(server: &FakeServer, path: &str) -> Vec<String> {
    let mut kids = server.cluster().children(path).unwrap_or_default();
    kids.sort_by(|a, b| sort_key(a).cmp(sort_key(b)));
    kids
}

/// The text after the last `latch-`, as Curator orders the names.
fn sort_key(name: &str) -> &str {
    name.rsplit_once("latch-").map_or(name, |(_, tail)| tail)
}

/// The full path of the child of `path` whose data is `id`.
fn node_of(server: &FakeServer, path: &str, id: &str) -> String {
    latch_children(server, path)
        .into_iter()
        .map(|c| format!("{path}/{c}"))
        .find(|p| server.cluster().data(p) == Some(Some(id.as_bytes().to_vec())))
        .unwrap_or_else(|| panic!("no node of {id} under {path}"))
}

/// Splits `_c_<uuid>-latch-<seq>` into the UUID and the sequence, and
/// checks the form of each part.
fn layout(name: &str) -> (String, String) {
    let rest = name
        .strip_prefix("_c_")
        .unwrap_or_else(|| panic!("no protected prefix: {name}"));
    let (uuid, seq) = rest
        .split_once("-latch-")
        .unwrap_or_else(|| panic!("no latch marker: {name}"));
    assert!(is_v4(uuid), "not a lowercase v4 UUID: {uuid}");
    assert_eq!(seq.len(), 10, "{name}");
    assert!(seq.bytes().all(|b| b.is_ascii_digit()), "{name}");
    (uuid.to_owned(), seq.to_owned())
}

/// Polls `latch` until `done` holds, at most [`common::WAIT`]. The latch
/// must not change its leadership in that time.
async fn drive_until(latch: &mut Latch, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + common::WAIT;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition timed out"
        );
        let r = tokio::time::timeout(Duration::from_millis(20), latch.changed()).await;
        assert!(r.is_err(), "the latch changed: {r:?}");
    }
}

/// The number of `delete` frames for `path` since the last clear of the
/// transcript.
fn deletes_of(server: &FakeServer, path: &str) -> usize {
    server
        .cluster()
        .transcript()
        .iter()
        .filter(|r| r.op == Some(OP_DELETE) && r.path.as_deref() == Some(path))
        .count()
}

/// A dropped `Latch` submits the delete of its
/// node, and the next participant becomes the leader. A dropped
/// `changed` future keeps the latch state.
#[tokio::test]
async fn re04_drop_of_latch_passes_leadership() {
    const PATH: &str = "/re04/latch";
    let server = common::fake();
    let c1 = common::connect(&server.connect_string()).await;
    let c2 = common::connect(&server.connect_string()).await;
    let c3 = common::connect(&server.connect_string()).await;

    let mut a = start_latch(&c1, PATH, "a").await;
    assert!(common::within(a.changed()).await.unwrap());
    assert!(a.is_leader());
    let mut b = start_latch(&c2, PATH, "b").await;
    let mut c = start_latch(&c3, PATH, "c").await;

    // Each dropped wait keeps the step, so the latch sets one watch only.
    for _ in 0..3 {
        assert!(common::still_pending(b.changed(), QUIET).await);
        assert!(common::still_pending(c.changed(), QUIET).await);
    }
    assert!(!b.is_leader());
    assert!(!c.is_leader());
    assert_eq!(server.cluster().watch_count(), 2);

    // The drop of a waiter deletes its node. Its successor then watches
    // the leader, and the leader keeps the leadership.
    let b_node = node_of(&server, PATH, "b");
    drop(b);
    common::wait_fake(&server, |cl| cl.node(&b_node).is_none());
    assert!(common::still_pending(c.changed(), QUIET).await);
    assert!(common::still_pending(a.changed(), QUIET).await);
    assert!(a.is_leader());

    // The drop of the leader passes the leadership to the next node.
    drop(a);
    assert!(common::within(c.changed()).await.unwrap());
    let kids = latch_children(&server, PATH);
    assert_eq!(kids.len(), 1, "{kids:?}");
    assert_eq!(node_of(&server, PATH, "c"), format!("{PATH}/{}", kids[0]));

    drop(c);
    common::wait_fake(&server, |cl| {
        cl.children(PATH).is_some_and(|k| k.is_empty())
    });
    for client in [c1, c2, c3] {
        common::within(client.close()).await.unwrap();
    }
}

/// A session expiry while leading. `changed` gives
/// `Ok(false)`, then `Err(SessionExpired)`, and the same error again.
/// A participant that was not the leader gets the error at once.
#[tokio::test]
async fn re06_expiry_while_leading() {
    const PATH: &str = "/re06/latch";
    let server = common::fake();
    let c1 = common::connect(&server.connect_string()).await;
    let c2 = common::connect(&server.connect_string()).await;
    let c3 = common::connect(&server.connect_string()).await;

    let mut a = start_latch(&c1, PATH, "a").await;
    assert!(common::within(a.changed()).await.unwrap());
    let mut b = start_latch(&c2, PATH, "b").await;
    let mut c = start_latch(&c3, PATH, "c").await;
    assert!(common::still_pending(b.changed(), QUIET).await);

    assert!(server.cluster().expire_session(session_id(&c1)));
    assert_eq!(common::within(a.changed()).await, Ok(false));
    assert!(!a.is_leader());
    for _ in 0..2 {
        assert_eq!(
            common::within(a.changed()).await,
            Err(Error::SessionExpired)
        );
    }
    assert_eq!(
        common::within(a.await_leadership()).await,
        Err(Error::SessionExpired)
    );
    assert_eq!(
        common::within(a.participants()).await,
        Err(Error::SessionExpired)
    );
    assert_eq!(common::within(a.close()).await, Err(Error::SessionExpired));

    // The expiry removed the node of the leader, so the next one leads.
    common::within(b.await_leadership()).await.unwrap();
    assert!(b.is_leader());

    // The expiry of a waiter ends its latch with no revocation first.
    assert!(server.cluster().expire_session(session_id(&c3)));
    assert_eq!(
        common::within(c.changed()).await,
        Err(Error::SessionExpired)
    );
    assert_eq!(
        common::within(c.changed()).await,
        Err(Error::SessionExpired)
    );
    assert!(!c.is_leader());
    drop(c);

    let kids = latch_children(&server, PATH);
    assert_eq!(kids.len(), 1, "{kids:?}");
    assert_eq!(node_of(&server, PATH, "b"), format!("{PATH}/{}", kids[0]));
    assert!(common::still_pending(b.changed(), QUIET).await);
    assert!(b.is_leader());

    common::within(b.close()).await.unwrap();
    common::within(c2.close()).await.unwrap();
}

/// Three participants. The leader closes its latch, and the
/// leadership passes in latch order. Then the connections drop and come
/// back without expiry: each latch reports `false` on `Connecting`,
/// checks its node at the new epoch, and evaluates the order again.
/// `participants` gives the ids in latch order.
#[tokio::test]
async fn re07_three_participants_close_and_reconnect() {
    const PATH: &str = "/re07/latch";
    let server = common::fake();
    let c1 = common::connect(&server.connect_string()).await;
    let c2 = common::connect(&server.connect_string()).await;
    let c3 = common::connect(&server.connect_string()).await;

    let mut l1 = start_latch(&c1, PATH, "p1").await;
    let mut l2 = start_latch(&c2, PATH, "p2").await;
    let mut l3 = start_latch(&c3, PATH, "p3").await;
    assert!(!l1.is_leader(), "no evaluation before the first call");
    assert_eq!(
        ids(&common::within(l3.participants()).await.unwrap()),
        expect(&[("p1", true), ("p2", false), ("p3", false)])
    );

    assert!(common::within(l1.changed()).await.unwrap());
    // A leader in a connected session resolves at once.
    common::within(l1.await_leadership()).await.unwrap();
    assert!(common::still_pending(l2.changed(), QUIET).await);
    assert!(common::still_pending(l3.changed(), QUIET).await);

    // The close passes the leadership in latch order.
    common::within(l1.close()).await.unwrap();
    assert!(common::within(l2.changed()).await.unwrap());
    assert!(common::still_pending(l3.changed(), QUIET).await);
    assert_eq!(
        ids(&common::within(l2.participants()).await.unwrap()),
        expect(&[("p2", true), ("p3", false)])
    );

    // The connections drop, and the sessions stay.
    let n2 = node_of(&server, PATH, "p2");
    let n3 = node_of(&server, PATH, "p3");
    let (s2, s3) = (session_id(&c2), session_id(&c3));
    let (e2, e3) = (c2.state().epoch, c3.state().epoch);
    server.cluster().clear_transcript();
    server.drop_connections();

    // The leader reports the revocation at once.
    assert_eq!(common::within(l2.changed()).await, Ok(false));
    assert!(!l2.is_leader());
    // At the new epoch the latch checks its node and leads again.
    assert!(common::within(l2.changed()).await.unwrap());
    assert!(c2.state().epoch > e2);
    assert_eq!(session_id(&c2), s2);

    // The waiter checks its node too, and waits again.
    let mut w3 = c3.state_watcher();
    common::wait_state(&mut w3, |i| i.state.is_connected() && i.epoch > e3).await;
    let checked = |node: &str| {
        server
            .cluster()
            .transcript()
            .iter()
            .any(|r| r.op == Some(OP_EXISTS) && r.path.as_deref() == Some(node))
    };
    drive_until(&mut l3, || checked(&n3)).await;
    assert!(checked(&n2));
    assert!(!l3.is_leader());
    assert_eq!(session_id(&c3), s3);
    assert_eq!(latch_children(&server, PATH).len(), 2);
    assert_eq!(
        ids(&common::within(l3.participants()).await.unwrap()),
        expect(&[("p2", true), ("p3", false)])
    );

    // The waiter set its watch again, so a close wakes it.
    common::within(l2.close()).await.unwrap();
    assert!(common::within(l3.changed()).await.unwrap());
    assert_eq!(
        ids(&common::within(l3.participants()).await.unwrap()),
        expect(&[("p3", true)])
    );

    common::within(l3.close()).await.unwrap();
    assert_eq!(latch_children(&server, PATH), Vec::<String>::new());
    for client in [c1, c2, c3] {
        common::within(client.close()).await.unwrap();
    }
}

/// A node that is gone at the new epoch (deleted by another
/// client) is made again with a new `<uuid>`.
#[tokio::test]
async fn re07_node_gone_after_reconnect_is_made_again() {
    const PATH: &str = "/re07gone/latch";
    let server = common::fake();
    let c1 = common::connect(&server.connect_string()).await;
    let c2 = common::connect(&server.connect_string()).await;

    let mut l1 = start_latch(&c1, PATH, "p1").await;
    let mut l2 = start_latch(&c2, PATH, "p2").await;
    assert!(common::within(l1.changed()).await.unwrap());
    assert!(common::still_pending(l2.changed(), QUIET).await);

    // Another client deletes the node of the leader, and the connections
    // drop before the leader sees it.
    let old = node_of(&server, PATH, "p1");
    let (old_uuid, old_seq) = layout(old.rsplit('/').next().unwrap());
    server.cluster().delete(&old).unwrap();
    server.drop_connections();

    assert_eq!(common::within(l1.changed()).await, Ok(false));
    drive_until(&mut l1, || latch_children(&server, PATH).len() == 2).await;
    assert!(common::within(l2.changed()).await.unwrap());

    // The new node has a new UUID and comes after the node of p2.
    let new = node_of(&server, PATH, "p1");
    let (new_uuid, new_seq) = layout(new.rsplit('/').next().unwrap());
    assert_ne!(new_uuid, old_uuid);
    assert!(new_seq > old_seq);
    assert_eq!(
        server.cluster().node(&new).unwrap().stat.ephemeral_owner,
        session_id(&c1)
    );
    assert_eq!(
        latch_children(&server, PATH),
        [
            node_of(&server, PATH, "p2").rsplit('/').next().unwrap(),
            new.rsplit('/').next().unwrap()
        ]
    );
    assert_eq!(
        ids(&common::within(l1.participants()).await.unwrap()),
        expect(&[("p2", true), ("p1", false)])
    );
    assert!(common::still_pending(l1.changed(), QUIET).await);

    // The new node is a normal participant.
    common::within(l2.close()).await.unwrap();
    assert!(common::within(l1.changed()).await.unwrap());
    common::within(l1.close()).await.unwrap();
    assert_eq!(latch_children(&server, PATH), Vec::<String>::new());
    for client in [c1, c2] {
        common::within(client.close()).await.unwrap();
    }
}

/// The latch node layout: `<latch_path>/_c_<uuid>-latch-<seq>`, the
/// participant id as the node data, and container parents. The order
/// takes the text after the last marker and keeps foreign children, as
/// Curator does.
#[tokio::test]
async fn re08_latch_node_layout() {
    const PATH: &str = "/re08/a/b/latch";
    let server = common::fake();
    let c1 = common::connect(&server.connect_string()).await;
    let c2 = common::connect(&server.connect_string()).await;

    let mut l1 = start_latch(&c1, PATH, "p1").await;
    let mut l2 = start_latch(&c2, PATH, "p2").await;

    // Each missing parent is a container.
    for parent in ["/re08", "/re08/a", "/re08/a/b", PATH] {
        let node = server.cluster().node(parent).unwrap();
        assert_eq!(node.stat.ephemeral_owner, CONTAINER_OWNER, "{parent}");
    }

    // Each participant node has the protected name, the id as data, and
    // the session as the owner.
    let kids = latch_children(&server, PATH);
    assert_eq!(kids.len(), 2, "{kids:?}");
    let (u1, q1) = layout(&kids[0]);
    let (u2, q2) = layout(&kids[1]);
    assert_ne!(u1, u2);
    assert!(q1 < q2);
    for (kid, id, client) in [(&kids[0], "p1", &c1), (&kids[1], "p2", &c2)] {
        let node = server.cluster().node(&format!("{PATH}/{kid}")).unwrap();
        assert_eq!(node.data.as_deref(), Some(id.as_bytes()));
        assert_eq!(node.stat.ephemeral_owner, session_id(client));
    }

    // Foreign children take part in the order: `-1` sorts before each
    // sequence number, and a name with no marker sorts after them.
    server
        .cluster()
        .create(&format!("{PATH}/f-latch--1"), b"F", 0)
        .unwrap();
    server
        .cluster()
        .create(&format!("{PATH}/nomarker"), b"N", 0)
        .unwrap();
    assert_eq!(
        ids(&common::within(l1.participants()).await.unwrap()),
        expect(&[("F", true), ("p1", false), ("p2", false), ("N", false)])
    );
    assert!(common::still_pending(l1.changed(), QUIET).await);
    assert!(!l1.is_leader());

    // With the foreign first node gone, the first latch node leads.
    server
        .cluster()
        .delete(&format!("{PATH}/f-latch--1"))
        .unwrap();
    assert!(common::within(l1.changed()).await.unwrap());
    assert!(common::still_pending(l2.changed(), QUIET).await);
    assert_eq!(
        ids(&common::within(l2.participants()).await.unwrap()),
        expect(&[("p1", true), ("p2", false), ("N", false)])
    );

    // The latch path is a container: the reaper removes it when the
    // last child is gone.
    common::within(l1.close()).await.unwrap();
    common::within(l2.close()).await.unwrap();
    server
        .cluster()
        .delete(&format!("{PATH}/nomarker"))
        .unwrap();
    assert!(server.cluster().reap().contains(&PATH.to_owned()));
    for client in [c1, c2] {
        common::within(client.close()).await.unwrap();
    }
}

/// `close` sends the delete again after a connection loss, as
/// `LockGuard::release` does. The first delete is applied with a lost
/// reply, or is not applied. Either way the close succeeds, and no node
/// stays to block the next leader.
#[tokio::test]
async fn close_after_connection_loss_is_sent_again() {
    const OP_DELETE: i32 = 2;
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let other = common::connect(&server.connect_string()).await;
    for applied in [true, false] {
        let path = format!("/close-{applied}");
        let mut leader = start_latch(&client, &path, "a").await;
        assert!(common::within(leader.changed()).await.unwrap());
        let mut next = start_latch(&other, &path, "b").await;
        let node = node_of(&server, &path, "a");
        let rule = Rule::on_request().op(OP_DELETE).path(&node).once();
        let rule = if applied {
            rule.then(Action::DropReply).then(Action::Close)
        } else {
            rule.then(Action::Close)
        };
        server.add_rule(rule);
        server.cluster().clear_transcript();
        common::within(leader.close()).await.unwrap();
        let deletes: Vec<_> = server
            .cluster()
            .transcript()
            .into_iter()
            .filter(|r| r.op == Some(OP_DELETE))
            .collect();
        assert_eq!(deletes.len(), 2, "{applied}");
        assert!(
            deletes
                .iter()
                .all(|r| r.path.as_deref() == Some(node.as_str()))
        );
        assert_eq!(latch_children(&server, &path).len(), 1, "{applied}");
        common::within(next.await_leadership()).await.unwrap();
        common::within(next.close()).await.unwrap();
        server.clear_rules();
    }
    common::within(other.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// A dropped `start` whose create reply did not come leaves a node with
/// an unknown name. That node would be the leader with no one to act as
/// leader. The late reply gives the name, and the guaranteed delete
/// removes the node with no further call. A latch on another client
/// then leads.
#[tokio::test]
async fn dropped_start_with_create_in_flight_is_deleted_in_the_background() {
    const PATH: &str = "/orphan/latch";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let other = common::connect(&server.connect_string()).await;
    server
        .cluster()
        .create("/orphan", b"", zk_fakeserver::create_mode::PERSISTENT)
        .unwrap();
    server
        .cluster()
        .create(PATH, b"", zk_fakeserver::create_mode::PERSISTENT)
        .unwrap();
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::Delay(Duration::from_millis(500))),
    );
    let latch = LeaderLatch::new(&client, PATH, "a").unwrap();
    {
        let mut start = std::pin::pin!(latch.start());
        assert!(poll_once(start.as_mut()).is_pending());
    }
    common::wait_fake(&server, |c| c.children(PATH).is_some_and(|k| k.len() == 1));
    let orphan = latch_children(&server, PATH).remove(0);
    common::wait_fake(&server, |c| c.children(PATH).is_some_and(|k| k.is_empty()));
    assert_eq!(deletes_of(&server, &format!("{PATH}/{orphan}")), 1);

    let mut started = start_latch(&other, PATH, "b").await;
    assert!(common::within(started.changed()).await.unwrap());
    common::within(started.close()).await.unwrap();
    common::within(other.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// A `close` whose `delete` fails with an error that is not a
/// connection loss gives that error. The node stays at that time, so the
/// guaranteed delete takes it, and the next participant leads.
#[tokio::test]
async fn close_with_a_failed_delete_hands_the_node_over() {
    const PATH: &str = "/close-throttled/latch";
    const ERR_THROTTLED: i32 = -127;
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let other = common::connect(&server.connect_string()).await;
    let mut leader = start_latch(&client, PATH, "a").await;
    assert!(common::within(leader.changed()).await.unwrap());
    let mut next = start_latch(&other, PATH, "b").await;
    let node = node_of(&server, PATH, "a");
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&node)
            .once()
            .then(Action::Reply { err: ERR_THROTTLED }),
    );
    server.cluster().clear_transcript();
    assert_eq!(
        common::within(leader.close()).await,
        Err(Error::ThrottledOp)
    );
    common::within(next.await_leadership()).await.unwrap();
    assert_eq!(deletes_of(&server, &node), 2);
    common::within(next.close()).await.unwrap();
    common::within(other.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// A read-only server can be in a minority partition, so the latch does
/// not lead on `ConnectedReadOnly`. It reports `false` on the loss of the
/// connection, stays without leadership on the read-only server, and
/// leads again only after a read-write connection.
#[tokio::test]
async fn read_only_connection_does_not_lead() {
    const PATH: &str = "/ro/latch";
    let server = common::fake();
    let client = common::within(
        common::builder(&server.connect_string())
            .allow_read_only(true)
            .connect(),
    )
    .await
    .unwrap();
    let mut state = client.state_watcher();
    let mut latch = start_latch(&client, PATH, "a").await;
    assert!(common::within(latch.changed()).await.unwrap());

    server.set_read_only(true);
    server.drop_connections();
    assert!(!common::within(latch.changed()).await.unwrap());
    common::wait_state(&mut state, |i| i.state == SessionState::ConnectedReadOnly).await;
    let quiet = tokio::time::timeout(QUIET * 2, latch.changed()).await;
    assert!(
        quiet.is_err(),
        "the latch led on a read-only server: {quiet:?}"
    );
    assert!(!latch.is_leader());
    assert!(
        tokio::time::timeout(QUIET, latch.await_leadership())
            .await
            .is_err()
    );

    server.set_read_only(false);
    server.drop_connections();
    assert!(common::within(latch.changed()).await.unwrap());
    assert_eq!(client.state().state, SessionState::Connected);
    common::within(latch.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// The reply that finds the own node first and a loss of the connection
/// can be ready in the same poll. The latch then does not report the
/// leadership. It leads after the next connection, with a `Connected`
/// session.
#[tokio::test]
async fn leadership_found_with_a_lost_connection_is_not_reported() {
    const PATH: &str = "/race/latch";
    let server = common::fake();
    let a_client = common::connect(&server.connect_string()).await;
    let b_client = common::connect(&server.connect_string()).await;
    let mut a = start_latch(&a_client, PATH, "a").await;
    assert!(common::within(a.changed()).await.unwrap());
    let mut b = start_latch(&b_client, PATH, "b").await;
    drive_until(&mut b, || server.cluster().watch_count() == 1).await;

    // The list of B after A goes gets its reply, and then the
    // connection drops.
    server.add_rule(
        Rule::on_request()
            .op(OP_GET_CHILDREN)
            .path(PATH)
            .once()
            .then(Action::Model)
            .then(Action::Close),
    );
    let mut state = b_client.state_watcher();
    let epoch = state.current().epoch;
    common::within(a.close()).await.unwrap();
    {
        let mut changed = std::pin::pin!(b.changed());
        // Poll with no waker until the list went out.
        common::within(async {
            while server.script().rules()[0].fired() == 0 {
                assert!(poll_once(changed.as_mut()).is_pending());
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        common::wait_state(&mut state, |i| {
            i.state != SessionState::Connected || i.epoch > epoch
        })
        .await;
        let r = poll_once(changed.as_mut());
        assert!(r.is_pending(), "{r:?}");
    }
    assert!(!b.is_leader());
    assert!(common::within(b.changed()).await.unwrap());
    let info = b_client.state();
    assert_eq!(info.state, SessionState::Connected);
    assert!(info.epoch > epoch);
    common::within(b.close()).await.unwrap();
    common::within(a_client.close()).await.unwrap();
    common::within(b_client.close()).await.unwrap();
}

/// A latch drop whose `delete` meets a connection loss leaves a
/// leader node with no owner. The guaranteed delete sends the `delete`
/// again after the reconnect, with no further call on the latch. A
/// latch on another client then leads.
#[tokio::test]
async fn latch_drop_with_lost_delete_is_sent_again_after_the_reconnect() {
    const PATH: &str = "/ghost/latch";
    let server = common::fake();
    let client = common::connect(&server.connect_string()).await;
    let other = common::connect(&server.connect_string()).await;
    let mut state = client.state_watcher();
    let leader_latch = LeaderLatch::new(&client, PATH, "a").unwrap();
    let mut latch = common::within(leader_latch.start()).await.unwrap();
    assert!(common::within(latch.changed()).await.unwrap());
    let mut waiter = start_latch(&other, PATH, "b").await;
    let old = format!("{PATH}/{}", latch_children(&server, PATH)[0]);
    let epoch = state.current().epoch;
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&old)
            .once()
            .then(Action::Close),
    );
    server.cluster().clear_transcript();
    drop(latch);
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;

    assert!(common::within(waiter.changed()).await.unwrap());
    assert_eq!(latch_children(&server, PATH).len(), 1);
    assert_eq!(deletes_of(&server, &old), 2);
    common::within(waiter.close()).await.unwrap();
    common::within(other.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}

/// Two latches of one `LeaderLatch`: latch A waits behind
/// the leader of another client, and latch S waits behind A. A drops,
/// and a connection loss stops its `delete`. The client reconnects in
/// the same session. The guaranteed delete sends the lost `delete`
/// again, and S leads after the leader closes. No `start` comes.
#[tokio::test]
async fn waiting_latch_passes_a_sibling_lost_delete() {
    const PATH: &str = "/ghost-sibling/latch";
    let server = common::fake();
    let h_client = common::connect(&server.connect_string()).await;
    let b_client = common::connect(&server.connect_string()).await;
    let mut state = b_client.state_watcher();
    let mut leader = start_latch(&h_client, PATH, "h").await;
    assert!(common::within(leader.changed()).await.unwrap());

    let leader_latch = LeaderLatch::new(&b_client, PATH, "b").unwrap();
    let mut a = common::within(leader_latch.start()).await.unwrap();
    let mut s = common::within(leader_latch.start()).await.unwrap();
    drive_until(&mut a, || server.cluster().watch_count() == 1).await;
    drive_until(&mut s, || server.cluster().watch_count() == 2).await;
    let kids = latch_children(&server, PATH);
    assert_eq!(kids.len(), 3);
    let a_node = format!("{PATH}/{}", kids[1]);
    let epoch = state.current().epoch;
    server.add_rule(
        Rule::on_request()
            .op(OP_DELETE)
            .path(&a_node)
            .once()
            .then(Action::Close),
    );
    server.cluster().clear_transcript();
    drop(a);
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    common::within(leader.close()).await.unwrap();

    assert!(common::within(s.changed()).await.unwrap());
    assert_eq!(latch_children(&server, PATH), vec![kids[2].clone()]);
    let resent = server
        .cluster()
        .transcript()
        .into_iter()
        .filter(|r| r.op == Some(OP_DELETE) && r.path.as_deref() == Some(a_node.as_str()))
        .count();
    assert_eq!(resent, 2);
    common::within(s.close()).await.unwrap();
    common::within(h_client.close()).await.unwrap();
    common::within(b_client.close()).await.unwrap();
}

/// The guaranteed delete removes only the node that a drop gave up.
/// Two latches of one `LeaderLatch` wait, and a dropped `start` leaves
/// a create whose reply comes late. The late reply gives the node name,
/// and the node goes once. Neither latch loses its own node, also at a
/// new epoch, so each keeps its place and leads in turn.
#[tokio::test]
async fn guaranteed_delete_keeps_the_own_nodes() {
    const PATH: &str = "/ghost-own/latch";
    let server = common::fake();
    let h_client = common::connect(&server.connect_string()).await;
    let b_client = common::connect(&server.connect_string()).await;
    let mut state = b_client.state_watcher();
    let mut leader = start_latch(&h_client, PATH, "h").await;
    assert!(common::within(leader.changed()).await.unwrap());

    let leader_latch = LeaderLatch::new(&b_client, PATH, "b").unwrap();
    let mut first = common::within(leader_latch.start()).await.unwrap();
    let mut second = common::within(leader_latch.start()).await.unwrap();
    drive_until(&mut first, || server.cluster().watch_count() == 1).await;
    drive_until(&mut second, || server.cluster().watch_count() == 2).await;
    let waiters = latch_children(&server, PATH)[1..].to_vec();
    assert_eq!(waiters.len(), 2);
    server.add_rule(
        Rule::on_request()
            .op(OP_CREATE2)
            .path_prefix(&format!("{PATH}/_c_"))
            .once()
            .then(Action::Delay(Duration::from_millis(300))),
    );
    server.cluster().clear_transcript();
    {
        let mut start = std::pin::pin!(leader_latch.start());
        assert!(poll_once(start.as_mut()).is_pending());
    }
    let deletes = || {
        server
            .cluster()
            .transcript()
            .into_iter()
            .filter(|r| r.op == Some(OP_DELETE))
            .collect::<Vec<_>>()
    };
    common::wait_fake(&server, |c| {
        c.children(PATH).is_some_and(|k| k.len() == 3)
            && c.transcript().iter().any(|r| r.op == Some(OP_DELETE))
    });
    server.clear_rules();
    let create = server
        .cluster()
        .transcript()
        .into_iter()
        .find(|r| r.op == Some(OP_CREATE2))
        .and_then(|r| r.path)
        .unwrap();
    let deleted = deletes();
    assert_eq!(deleted.len(), 1, "{deleted:?}");
    assert!(deleted[0].path.as_deref().unwrap().starts_with(&create));
    assert_eq!(latch_children(&server, PATH)[1..], waiters[..]);

    let epoch = state.current().epoch;
    server.drop_connections();
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    // Each latch reads its predecessor again after its list.
    let read = |node: &str| {
        server
            .cluster()
            .transcript()
            .iter()
            .any(|r| r.op == Some(OP_GET_DATA) && r.path.as_deref() == Some(node))
    };
    let leader_node = format!("{PATH}/{}", latch_children(&server, PATH)[0]);
    let first_node = format!("{PATH}/{}", waiters[0]);
    drive_until(&mut first, || read(&leader_node)).await;
    drive_until(&mut second, || read(&first_node)).await;
    assert_eq!(deletes().len(), 1);
    assert_eq!(latch_children(&server, PATH)[1..], waiters[..]);
    assert!(!first.is_leader() && !second.is_leader());

    common::within(leader.close()).await.unwrap();
    assert!(common::within(first.changed()).await.unwrap());
    common::within(first.close()).await.unwrap();
    assert!(common::within(second.changed()).await.unwrap());
    assert_eq!(latch_children(&server, PATH), vec![waiters[1].clone()]);
    common::within(second.close()).await.unwrap();
    common::within(h_client.close()).await.unwrap();
    common::within(b_client.close()).await.unwrap();
}

/// A latch drop on a read-only connection gets `NotReadOnly`. The
/// guaranteed delete does not send the `delete` again on a later
/// read-only connection. It sends it at the next read-write connection,
/// and the next participant leads.
#[tokio::test]
async fn read_only_connection_does_not_delete() {
    const PATH: &str = "/ro-ghost/latch";
    let server = common::fake();
    let client = common::within(
        common::builder(&server.connect_string())
            .allow_read_only(true)
            .connect(),
    )
    .await
    .unwrap();
    let other = common::connect(&server.connect_string()).await;
    let mut state = client.state_watcher();
    let mut latch = start_latch(&client, PATH, "a").await;
    assert!(common::within(latch.changed()).await.unwrap());
    let node = node_of(&server, PATH, "a");

    server.set_read_only(true);
    server.drop_connections();
    common::wait_state(&mut state, |i| i.state == SessionState::ConnectedReadOnly).await;
    server.cluster().clear_transcript();
    drop(latch);
    common::wait_fake(&server, |c| {
        c.transcript().iter().any(|r| r.op == Some(OP_DELETE))
    });
    // A new read-only epoch sends nothing.
    let epoch = state.current().epoch;
    server.drop_connections();
    common::wait_state(&mut state, |i| {
        i.state == SessionState::ConnectedReadOnly && i.epoch > epoch
    })
    .await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(deletes_of(&server, &node), 1);
    assert!(server.cluster().node(&node).is_some());

    server.set_read_only(false);
    server.drop_connections();
    common::wait_fake(&server, |c| c.node(&node).is_none());
    assert_eq!(deletes_of(&server, &node), 2);
    let mut next = start_latch(&other, PATH, "b").await;
    assert!(common::within(next.changed()).await.unwrap());
    common::within(next.close()).await.unwrap();
    common::within(other.close()).await.unwrap();
    common::within(client.close()).await.unwrap();
}
