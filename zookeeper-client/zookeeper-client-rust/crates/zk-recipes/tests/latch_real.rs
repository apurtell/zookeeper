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

//! `LeaderLatch` against a real server and against the three-node
//! ensemble.
//!
//! The leader change runs on a standalone server and on the ensemble.
//! Three participants lead in latch order, and then their connections
//! drop and come back in the same session. A proxy cut
//! gives the reconnect without expiry. On the ensemble, the failover
//! tests stop the server of the clients: once a follower, and once the
//! leader of the ensemble.
//!
//! A lost `delete` of a latch drop also runs through a proxy. The
//! guaranteed delete removes the ghost node after the reconnect, and the
//! next participant leads.
//!
//! Each test needs `ZK_TEST_PORT_BASE` and a server that can start. It
//! skips otherwise. `ZK_TEST_SERVER_VERSION` selects a release server.
//! Run them with `--ignored`.

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

use apache_zookeeper::{ServerOrder, SessionState};
use common::{ProxyGroup, Servers, Topology, expect, ids, start_latch};

/// The time that a test gives a waiter to show that it does not
/// proceed.
const QUIET: Duration = Duration::from_millis(300);

/// The leader change on a standalone server, with a proxy cut for the
/// reconnect without expiry.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_latch_three_participants() {
    three_participants(Topology::Standalone).await;
}

/// The leader change on the ensemble, with one proxy in front of each
/// server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_latch_three_participants_ensemble() {
    three_participants(Topology::Ensemble).await;
}

/// Three participants. The leader closes its latch, then the
/// connections of the other two drop and come back in the same session.
async fn three_participants(topology: Topology) {
    const PATH: &str = "/re12/latch/three";
    let Some(servers) = Servers::start_or_skip(topology) else {
        return;
    };
    let proxy = ProxyGroup::start(&servers.client_ports());
    let c1 = common::connect(&servers.connect_string()).await;
    let c2 = common::connect(&proxy.connect_string()).await;
    let c3 = common::connect(&proxy.connect_string()).await;

    let mut l1 = start_latch(&c1, PATH, "p1").await;
    let mut l2 = start_latch(&c2, PATH, "p2").await;
    let mut l3 = start_latch(&c3, PATH, "p3").await;
    // A server of the ensemble can lag behind the leader.
    common::within(c1.sync("/")).await.unwrap();
    assert_eq!(
        ids(&common::within(l1.participants()).await.unwrap()),
        expect(&[("p1", true), ("p2", false), ("p3", false)])
    );

    // The close passes the leadership in latch order.
    assert!(common::within(l1.changed()).await.unwrap());
    assert!(common::still_pending(l2.changed(), QUIET).await);
    assert!(common::still_pending(l3.changed(), QUIET).await);
    common::within(l1.close()).await.unwrap();
    assert!(common::within(l2.changed()).await.unwrap());
    assert!(common::still_pending(l3.changed(), QUIET).await);

    // The proxy cut drops both connections. The sessions stay.
    let (s2, s3) = (c2.session().0, c3.session().0);
    let (e2, e3) = (c2.state().epoch, c3.state().epoch);
    proxy.cut();
    assert_eq!(common::within(l2.changed()).await, Ok(false));
    assert!(!l2.is_leader());
    assert!(common::still_pending(l3.changed(), QUIET).await);
    assert!(!l3.is_leader());
    proxy.restore();

    // At the new epoch the latches check their nodes and evaluate again.
    assert!(common::within(l2.changed()).await.unwrap());
    let mut w3 = c3.state_watcher();
    common::wait_state(&mut w3, |i| i.state.is_connected() && i.epoch > e3).await;
    assert!(common::still_pending(l3.changed(), QUIET).await);
    assert!(!l3.is_leader());
    assert!(c2.state().epoch > e2);
    assert_eq!(c2.session().0, s2);
    assert_eq!(c3.session().0, s3);
    common::within(c3.sync("/")).await.unwrap();
    assert_eq!(
        ids(&common::within(l3.participants()).await.unwrap()),
        expect(&[("p2", true), ("p3", false)])
    );

    // The waiter set its watch again, so a close wakes it.
    common::within(l2.close()).await.unwrap();
    assert!(common::within(l3.changed()).await.unwrap());
    common::within(l3.close()).await.unwrap();
    assert_eq!(
        common::synced_children(&c1, PATH).await,
        Vec::<String>::new()
    );
    for client in [c1, c2, c3] {
        common::within(client.close()).await.unwrap();
    }
}

/// The leader change on the ensemble: the server of the clients is a
/// follower, and it stops. The quorum stays, so no election runs.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_latch_survives_server_failover() {
    failover(false).await;
}

/// The leader change on the ensemble: the server of the clients is the
/// leader of the ensemble, and it stops. Every server drops its clients
/// during the election, and the sessions stay.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_latch_survives_leader_change() {
    failover(true).await;
}

/// The node of the clients stops, and the clients move to another node
/// within the session timeout. With `leader` the stopped node is the
/// leader of the ensemble, otherwise a follower.
async fn failover(leader: bool) {
    const PATH: &str = "/re12/latch/failover";
    let Some(ensemble) = common::Ensemble::start_or_skip() else {
        return;
    };
    let current = ensemble.leader().expect("the ensemble has a leader");
    let stopped = if leader {
        current
    } else {
        (1..=3).find(|&n| n != current).unwrap()
    };
    // The clients use the stopped node first.
    let mut hosts = vec![format!("127.0.0.1:{}", ensemble.client_port(stopped))];
    hosts.extend(
        (1..=3)
            .filter(|&n| n != stopped)
            .map(|n| format!("127.0.0.1:{}", ensemble.client_port(n))),
    );
    let connect_string = hosts.join(",");
    // An election takes longer than the default test timeout allows.
    let connect = || async {
        common::within(
            common::builder(&connect_string)
                .server_order(ServerOrder::AsGiven)
                .session_timeout(Duration::from_secs(10))
                .connect(),
        )
        .await
        .unwrap()
    };
    let c1 = connect().await;
    let c2 = connect().await;
    let c3 = connect().await;

    let mut l1 = start_latch(&c1, PATH, "p1").await;
    let mut l2 = start_latch(&c2, PATH, "p2").await;
    let mut l3 = start_latch(&c3, PATH, "p3").await;
    assert!(common::within(l1.changed()).await.unwrap());
    assert!(common::still_pending(l2.changed(), QUIET).await);

    let sessions: Vec<_> = [&c1, &c2, &c3].iter().map(|c| c.session().0).collect();
    ensemble.stop_node(stopped).unwrap();
    if leader {
        assert!(
            ensemble.wait_leader(Some(stopped)).is_some(),
            "a new leader"
        );
    }

    // The leader reports the revocation, moves to another node in the
    // same session, checks its node, and leads again.
    assert_eq!(common::within(l1.changed()).await, Ok(false));
    assert!(common::within(l1.changed()).await.unwrap());
    assert!(common::still_pending(l2.changed(), QUIET).await);
    assert!(common::still_pending(l3.changed(), QUIET).await);
    let after: Vec<_> = [&c1, &c2, &c3].iter().map(|c| c.session().0).collect();
    assert_eq!(after, sessions);
    common::within(c2.sync("/")).await.unwrap();
    assert_eq!(
        ids(&common::within(l2.participants()).await.unwrap()),
        expect(&[("p1", true), ("p2", false), ("p3", false)])
    );

    // The leadership passes in latch order after the failover.
    common::within(l1.close()).await.unwrap();
    assert!(common::within(l2.changed()).await.unwrap());
    assert!(common::still_pending(l3.changed(), QUIET).await);
    common::within(l2.close()).await.unwrap();
    assert!(common::within(l3.changed()).await.unwrap());
    common::within(l3.close()).await.unwrap();
    for client in [c1, c2, c3] {
        common::within(client.close()).await.unwrap();
    }
}

/// A latch drop whose `delete` is lost, on a standalone server.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_latch_lost_delete_through_proxy() {
    lost_delete(Topology::Standalone).await;
}

/// A latch drop whose `delete` is lost, on the ensemble, through a
/// follower.
#[tokio::test]
#[ignore = "real-server"]
async fn re12_latch_lost_delete_through_proxy_ensemble() {
    lost_delete(Topology::Ensemble).await;
}

/// The proxy drops the `delete` of a latch drop and then cuts the
/// connection, so the node of the leader stays as a ghost. After the
/// reconnect in the same session, the guaranteed delete sends the
/// `delete` again with no further call. The participant on a second
/// client then leads.
async fn lost_delete(topology: Topology) {
    const PATH: &str = "/re12/latch/ghost";
    let Some(servers) = Servers::start_or_skip(topology) else {
        return;
    };
    let proxy = common::Proxy::start(servers.relay_port());
    let c1 = common::connect(&proxy.connect_string()).await;
    let c2 = common::connect(&servers.connect_string()).await;
    let mut state = c1.state_watcher();
    let session = c1.session().0;

    let mut l1 = start_latch(&c1, PATH, "p1").await;
    assert!(common::within(l1.changed()).await.unwrap());
    let mut l2 = start_latch(&c2, PATH, "p2").await;
    assert!(common::still_pending(l2.changed(), QUIET).await);

    // The `delete` does not reach the server, so `p2` does not lead.
    let epoch = state.current().epoch;
    proxy.hold();
    drop(l1);
    assert!(common::still_pending(l2.changed(), QUIET).await, "ghost");
    assert_eq!(common::synced_children(&c2, PATH).await.len(), 2);
    proxy.cut();
    common::wait_state(&mut state, |i| !i.state.is_connected()).await;
    proxy.restore();
    common::wait_state(&mut state, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    assert_eq!(c1.session().0, session);

    assert!(common::within(l2.changed()).await.unwrap());
    common::within(c2.sync("/")).await.unwrap();
    assert_eq!(
        ids(&common::within(l2.participants()).await.unwrap()),
        expect(&[("p2", true)])
    );
    common::within(l2.close()).await.unwrap();
    assert!(common::synced_children(&c2, PATH).await.is_empty());
    common::within(c1.close()).await.unwrap();
    common::within(c2.close()).await.unwrap();
}
