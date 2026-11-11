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

//! Smoke tests of the real-server helpers.
//!
//! The real-server tests start a standalone server and the three-node
//! ensemble with the version of `ZK_TEST_SERVER_VERSION`, and check the
//! client against them. They prove the helpers before the recipe tests
//! use them. They carry `#[ignore = "real-server"]`. Run them with
//! `ZK_TEST_PORT_BASE=<base> cargo test --test real_infra -- --ignored`.
//!
//! The lease tests need no server. They run on a plain `cargo test`
//! against private lease directories, not the lease of a test range.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    clippy::await_holding_lock
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::time::Duration;

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{CreateMode, SessionState};
use common::{Ensemble, Proxy, RealServer, wait_state, within};

/// Checks that the server on `port` runs the release `version`. The
/// server of this source tree (`None`) must report some version.
fn assert_version(port: u16, version: Option<&str>) {
    let reported = common::srvr_version(port).expect("srvr gives a version");
    if let Some(v) = version {
        assert_eq!(reported, v, "the server on {port} runs another release");
    }
}

/// Runs the real-server tests of this binary one at a time. The other
/// test threads wait for the range lease. So after a drop, another test
/// can take the range before the checks of the first test run. Each test
/// holds this guard for its whole run. A failed test poisons the lock,
/// and the next test takes it all the same.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The lease directory of the test range.
fn range_lease() -> std::path::PathBuf {
    common::lease_dir(common::real_port(common::STANDALONE_OFFSET).unwrap())
}

/// A standalone server starts with the selected version, a client
/// connects and writes, and the drop stops the server. The server holds
/// the lease of the range, and a second take on the same thread fails
/// at once.
#[tokio::test]
#[ignore = "real-server"]
async fn standalone_server_starts_and_stops() {
    let _serial = serial();
    let Some(server) = RealServer::start_or_skip() else {
        return;
    };
    let port = server.port();
    assert_eq!(common::srvr_mode(port).as_deref(), Some("standalone"));
    assert_eq!(server.version(), common::server_version().as_deref());
    assert_version(port, server.version());
    assert_eq!(
        common::lease_owner(&range_lease()),
        Some(std::process::id())
    );

    // The lease is not reentrant. The take fails before it waits.
    let again = std::panic::catch_unwind(Ensemble::start_or_skip);
    assert!(again.is_err(), "a second take on one thread must fail");

    let client = common::connect(&server.connect_string()).await;
    let path = "/real-infra-standalone";
    within(client.create(path, b"one", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let (data, _) = within(client.get_data(path)).await.unwrap();
    assert_eq!(data, b"one");
    within(client.delete(path, None)).await.unwrap();
    within(client.close()).await.unwrap();

    drop(server);
    assert!(!common::port_open(port), "the drop stops the server");
    assert_ne!(
        common::lease_owner(&range_lease()),
        Some(std::process::id()),
        "the drop releases the lease"
    );
}

/// `start_version_or_skip` runs the release that it names, whatever
/// `ZK_TEST_SERVER_VERSION` gives. The `TreeCache` tests use 3.5.10 for
/// the start failure.
#[tokio::test]
#[ignore = "real-server"]
async fn release_server_is_selected() {
    let _serial = serial();
    let Some(server) = RealServer::start_version_or_skip(Some(common::LEGACY_VERSION)) else {
        return;
    };
    assert_eq!(server.version(), Some(common::LEGACY_VERSION));
    assert_version(server.port(), Some(common::LEGACY_VERSION));
    let client = common::connect(&server.connect_string()).await;
    let children = within(client.get_children("/")).await.unwrap();
    assert!(children.iter().any(|c| c == "zookeeper"), "{children:?}");
    within(client.close()).await.unwrap();
}

/// The ensemble starts with one leader. A stop of the leader gives a new
/// leader, and the client goes on in the same session. The node comes
/// back with `start_node` and catches up.
#[tokio::test]
#[ignore = "real-server"]
async fn ensemble_starts_and_fails_over() {
    let _serial = serial();
    let Some(ensemble) = Ensemble::start_or_skip() else {
        return;
    };
    let mut leaders = 0;
    for n in 1..=3 {
        let port = ensemble.client_port(n);
        match common::srvr_mode(port).as_deref() {
            Some("leader") => leaders += 1,
            Some("follower") => {}
            other => panic!("node {n} serves as {other:?}"),
        }
        assert_version(port, ensemble.version());
    }
    assert_eq!(leaders, 1, "one leader");
    let old = ensemble.leader().expect("a leader");

    // A longer session survives the election.
    let client = within(
        common::builder(&ensemble.connect_string())
            .session_timeout(Duration::from_secs(10))
            .connect(),
    )
    .await
    .unwrap();
    let path = "/real-infra-ensemble";
    within(client.create(path, b"before", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let (session, _) = client.session();
    let epoch = client.state().epoch;
    let mut states = client.state_watcher();

    ensemble.stop_node(old).unwrap();
    assert!(!common::port_open(ensemble.client_port(old)));
    let new = ensemble.wait_leader(Some(old)).expect("a new leader");
    assert_ne!(new, old);
    // Each node drops its clients when the leader goes, so the client
    // connects again at a new epoch.
    wait_state(&mut states, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    assert_eq!(client.session().0, session, "the session stays");
    within(client.set_data(path, b"after", None)).await.unwrap();

    ensemble.start_node(old).unwrap();
    assert!(matches!(
        common::srvr_mode(ensemble.client_port(old)).as_deref(),
        Some("leader" | "follower")
    ));
    assert!(ensemble.leader().is_some());
    let back = common::connect(&ensemble.node_connect_string(old)).await;
    within(back.sync(path)).await.unwrap();
    let (data, _) = within(back.get_data(path)).await.unwrap();
    assert_eq!(data, b"after", "the node catches up");
    within(back.close()).await.unwrap();
    within(client.close()).await.unwrap();

    let ports: Vec<u16> = (1..=3).map(|n| ensemble.client_port(n)).collect();
    drop(ensemble);
    for p in ports {
        assert!(!common::port_open(p), "the drop stops the node on {p}");
    }
}

/// A proxy cut moves the client to `Connecting`, and keeps it there
/// while the cut lasts. The restore gives `Connected` at a new epoch in
/// the same session, and the ephemeral node of the session stays.
#[tokio::test]
#[ignore = "real-server"]
async fn proxy_cut_reconnects_the_same_session() {
    let _serial = serial();
    let Some(server) = RealServer::start_or_skip() else {
        return;
    };
    let proxy = Proxy::start(server.port());
    let client = common::connect(&proxy.connect_string()).await;
    let path = "/real-infra-proxy";
    within(client.create(path, b"", CreateMode::Ephemeral, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let (session, _) = client.session();
    let epoch = client.state().epoch;
    let mut states = client.state_watcher();

    proxy.cut();
    wait_state(&mut states, |i| i.state == SessionState::Connecting).await;
    // The client tries again many times while the cut lasts.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(client.state().state, SessionState::Connecting);

    proxy.restore();
    let info = wait_state(&mut states, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    assert_eq!(info.epoch, epoch + 1, "one new connection");
    assert_eq!(client.session().0, session, "the session stays");
    assert!(
        within(client.exists(path)).await.unwrap().is_some(),
        "the ephemeral node of the session stays"
    );
    within(client.close()).await.unwrap();
}

/// The lease tests run against private lease directories.
#[cfg(unix)]
mod lease {
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::common::{acquire_lease_at, lease_owner, process_alive, release_lease_at};

    /// A fresh lease directory for the test `name`.
    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zk-recipes-lease-test-{}-{name}",
            std::process::id()
        ));
        // A first run has no directory.
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Makes a lease directory that `pid` owns.
    fn foreign_lease(d: &PathBuf, pid: u32) {
        std::fs::create_dir(d).unwrap();
        std::fs::write(d.join("pid"), pid.to_string()).unwrap();
    }

    /// A free lease is taken at once, and the release removes it.
    #[test]
    fn free_lease_is_taken_and_released() {
        let d = dir("free");
        assert!(acquire_lease_at(&d, Duration::ZERO, Duration::ZERO));
        assert_eq!(lease_owner(&d), Some(std::process::id()));
        release_lease_at(&d);
        assert!(!d.exists());
    }

    /// The lease of a process that is gone is taken over.
    #[test]
    fn lease_of_a_dead_process_is_taken_over() {
        let d = dir("dead");
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(!process_alive(pid));
        foreign_lease(&d, pid);
        assert!(acquire_lease_at(
            &d,
            Duration::from_secs(5),
            Duration::from_secs(5)
        ));
        assert_eq!(lease_owner(&d), Some(std::process::id()));
        release_lease_at(&d);
    }

    /// The lease of a live process stays taken until the wait ends. A
    /// release by another process leaves it. When the owner ends, the
    /// lease is taken over.
    #[test]
    fn lease_of_a_live_process_stays() {
        let d = dir("live");
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        foreign_lease(&d, pid);
        let start = Instant::now();
        assert!(!acquire_lease_at(
            &d,
            Duration::from_millis(300),
            Duration::from_secs(5)
        ));
        assert!(start.elapsed() >= Duration::from_millis(300));
        release_lease_at(&d);
        assert_eq!(lease_owner(&d), Some(pid), "the lease of the owner stays");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(acquire_lease_at(
            &d,
            Duration::from_secs(5),
            Duration::from_secs(5)
        ));
        release_lease_at(&d);
    }

    /// A lease with no process id is taken over after the grace time.
    #[test]
    fn lease_without_an_owner_is_taken_after_the_grace_time() {
        let d = dir("no-owner");
        std::fs::create_dir(&d).unwrap();
        let start = Instant::now();
        assert!(acquire_lease_at(
            &d,
            Duration::from_secs(5),
            Duration::from_millis(200)
        ));
        assert!(start.elapsed() >= Duration::from_millis(200));
        assert_eq!(lease_owner(&d), Some(std::process::id()));
        release_lease_at(&d);
    }
}
