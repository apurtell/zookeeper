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

//! Parity with the C suite `TestReconfigServer.cc`.
//!
//! Each C case starts a new three-node quorum with `reconfigEnabled`
//! and, except one case, the super user `super:test`. Each test here
//! does the same with `dev/test-ensemble.sh`. It then changes the
//! membership with `Client::reconfig` and reads it with
//! `Client::get_config`. Each case runs once with the IO thread and
//! once with a tokio task, each time on a new quorum.
//!
//! The quorum uses the ports at offsets 8 to 16 of `ZK_TEST_PORT_BASE`.
//! The tests share these ports, so a lock runs them one after the
//! other. The tests have `#[ignore = "real-server"]`. Run them with
//! `ZK_TEST_PORT_BASE=<base> cargo test --test c_reconfig_server --
//! --ignored`.

// A scenario is one long async body. It runs on a 2 MiB test or worker
// thread, so the stack frame limit of the library does not apply.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use apache_zookeeper::{
    Client, ClientBuilder, EnsembleConfig, Error, Id, Reconfig, ServerOrder, Stat,
};
use common::{Rt, real_port};

/// The quorum tests use the same ports, so they run one at a time.
static PORTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The port offset of node 1 of the quorum.
const OFFSET: u16 = 8;

/// The number of servers of the quorum (C `NUM_SERVERS`).
const NUM_SERVERS: usize = 3;

/// The wait budget of a step on a quorum. A reconfig and the reconnect
/// after it take longer than a step on a standalone server.
const SLOW: Duration = Duration::from_secs(20);

/// The session timeout of the C suite.
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// The C suite sets this digest of `super:test`.
const SUPER_DIGEST: &str = "super:D/InIHSb7yEEbrWz8b9l71RjZJU=";

/// The config version of a new quorum: the zxid of the first
/// `NEWLEADER`, 1 << 32.
const FIRST_VERSION: i64 = 0x1_0000_0000;

/// The config version after one session and one reconfig.
const RECONFIG_VERSION: i64 = 0x1_0000_0002;

/// A three-node quorum of `dev/test-ensemble.sh`. The drop stops it.
struct Quorum {
    base: u16,
    dir: PathBuf,
}

impl Quorum {
    /// Starts a new quorum with dynamic reconfig. With `super_user`,
    /// the servers accept the C super user `super:test`. It gives
    /// `None` and a note to skip when the quorum does not start.
    fn start(super_user: bool) -> Option<Self> {
        let base = real_port(OFFSET)?;
        let dir = std::env::temp_dir().join(format!("zk-rust-c-reconfig-{base}"));
        // A rerun starts from new data. On a first run the directory
        // does not exist.
        let _ = std::fs::remove_dir_all(&dir);
        let q = Self { base, dir };
        // The last line of a key wins, so these lines replace the
        // static server lines of the script.
        let mut props = String::from("reconfigEnabled=true\n");
        for n in 1..=NUM_SERVERS {
            props.push_str(&q.server_string(n));
            props.push('\n');
        }
        let jvm = if super_user {
            format!("-Dzookeeper.DigestAuthenticationProvider.superDigest={SUPER_DIGEST}")
        } else {
            String::new()
        };
        let status = q
            .script()
            .arg("start")
            .arg(base.to_string())
            .arg(&q.dir)
            .env("ZK_TEST_SERVER_PROPS", props)
            .env("ZK_TEST_SERVER_JVM_OPTS", jvm)
            .stdout(Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => Some(q),
            other => common::skip("the quorum did not start", &format!("{other:?}")),
        }
    }

    fn script(&self) -> Command {
        let mut cmd = Command::new("bash");
        cmd.arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dev/test-ensemble.sh"));
        cmd
    }

    /// The client port of node `n` (1 to 3).
    fn client_port(&self, n: usize) -> u16 {
        self.base + u16::try_from(n).unwrap() - 1
    }

    /// `127.0.0.1:PORT` of node `n`.
    fn host_port(&self, n: usize) -> String {
        format!("127.0.0.1:{}", self.client_port(n))
    }

    /// The config line of node `n`, as the server reports it (C
    /// `getServerString`).
    fn server_string(&self, n: usize) -> String {
        let n16 = u16::try_from(n).unwrap();
        format!(
            "server.{n}=127.0.0.1:{}:{}:participant;127.0.0.1:{}",
            self.base + n16 + 2,
            self.base + n16 + 5,
            self.client_port(n)
        )
    }

    /// The node that leads (C `getLeader`).
    fn leader(&self) -> usize {
        let out = self
            .script()
            .arg("leader")
            .arg(self.base.to_string())
            .arg(&self.dir)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
    }

    /// The nodes that follow, in node order (C `getFollowers`).
    fn followers(&self) -> Vec<usize> {
        let leader = self.leader();
        (1..=NUM_SERVERS).filter(|n| *n != leader).collect()
    }
}

impl Drop for Quorum {
    fn drop(&mut self) {
        let _ = self
            .script()
            .arg("stop")
            .arg(self.base.to_string())
            .arg(&self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Runs `scenario` once per driver, each on a new quorum.
macro_rules! quorum_test {
    ($name:ident, $super_user:expr) => {
        mod $name {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore = "real-server"]
            async fn thread() {
                let _lock = PORTS.lock().await;
                if let Some(q) = Quorum::start($super_user) {
                    super::$name(&q, Rt::Thread).await;
                }
            }

            #[cfg(all(unix, feature = "tokio"))]
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore = "real-server"]
            async fn tokio() {
                let _lock = PORTS.lock().await;
                if let Some(q) = Quorum::start($super_user) {
                    super::$name(&q, Rt::Tokio).await;
                }
            }
        }
    };
}

/// Runs a future with the budget [`SLOW`].
async fn slow<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(SLOW, f).await.expect("timed out")
}

/// A builder for `cs` with the session timeout of the C suite.
fn builder(rt: Rt, cs: &str) -> ClientBuilder {
    rt.apply(common::builder(cs).session_timeout(SESSION_TIMEOUT))
}

/// Connects to the leader.
async fn connect_leader(q: &Quorum, rt: Rt) -> Client {
    slow(builder(rt, &q.host_port(q.leader())).connect())
        .await
        .expect("connect")
}

/// Connects with the list `followers[0], followers[1], leader` in this
/// order, and checks that the client is on the first follower (C
/// `connectFollowers`).
async fn connect_followers(q: &Quorum, rt: Rt, followers: &[usize]) -> Client {
    assert_eq!(followers.len(), NUM_SERVERS - 1);
    let mut hosts: Vec<String> = followers.iter().map(|n| q.host_port(*n)).collect();
    hosts.push(q.host_port(q.leader()));
    let c = slow(
        builder(rt, &hosts.join(","))
            .server_order(ServerOrder::AsGiven)
            .connect(),
    )
    .await
    .expect("connect");
    let at = c.connected_server().expect("a connected server");
    assert_eq!(at.port(), q.client_port(followers[0]));
    c
}

/// The `server.` lines of a config (C `parseConfig`).
fn server_lines(cfg: &EnsembleConfig) -> BTreeSet<String> {
    cfg.raw
        .lines()
        .filter(|l| l.starts_with("server."))
        .map(str::to_owned)
        .collect()
}

/// Checks that the config lists exactly the nodes `nodes`, both in the
/// raw text and in the parsed entries.
fn assert_members(q: &Quorum, cfg: &EnsembleConfig, nodes: &[usize]) {
    let want: BTreeSet<String> = nodes.iter().map(|n| q.server_string(*n)).collect();
    assert_eq!(server_lines(cfg), want, "{}", cfg.raw);
    let ids: BTreeSet<u64> = cfg.servers.iter().map(|s| s.id).collect();
    let want_ids: BTreeSet<u64> = nodes.iter().map(|n| u64::try_from(*n).unwrap()).collect();
    assert_eq!(ids, want_ids, "{cfg:?}");
}

/// All nodes except `gone`.
fn all_but(gone: usize) -> Vec<usize> {
    (1..=NUM_SERVERS).filter(|n| *n != gone).collect()
}

/// Reads the config. A removed server can end the connection of the
/// client, so the read waits for the reconnect on `ConnectionLoss`.
async fn config_after_move(c: &Client) -> (EnsembleConfig, Stat) {
    let deadline = tokio::time::Instant::now() + SLOW;
    loop {
        match slow(c.get_config()).await {
            Err(Error::ConnectionLoss) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            other => return other.unwrap(),
        }
    }
}

/// Removes node `n` and gives the result.
async fn remove(c: &Client, n: usize) -> Result<(EnsembleConfig, Stat), Error> {
    let leave = Reconfig::Incremental {
        joining: Vec::new(),
        leaving: vec![u64::try_from(n).unwrap()],
    };
    slow(c.reconfig(&leave, None)).await
}

/// The C super user digest is the digest of `super:test`.
#[test]
fn super_digest_is_super_test() {
    assert_eq!(Id::digest("super", "test").id, SUPER_DIGEST);
}

quorum_test!(non_incremental, true);
/// `TestReconfigServer::testNonIncremental`: on the leader, a new
/// quorum has config version 1 << 32 and three members. A
/// non-incremental reconfig to the second follower and the leader
/// gives two members at the next version. A second one with all three
/// servers gives three members again.
async fn non_incremental(q: &Quorum, rt: Rt) {
    let leader = q.leader();
    let c = connect_leader(q, rt).await;
    let (cfg, _) = slow(c.get_config()).await.unwrap();
    slow(c.add_auth("digest", b"super:test".to_vec()))
        .await
        .unwrap();
    assert_eq!(cfg.version, Some(FIRST_VERSION), "{}", cfg.raw);
    assert_members(q, &cfg, &[1, 2, 3]);

    let followers = q.followers();
    assert_eq!(followers.len(), NUM_SERVERS - 1);
    let mut members: Vec<String> = followers[1..].iter().map(|n| q.server_string(*n)).collect();
    members.push(q.server_string(leader));
    let set = Reconfig::NonIncremental { members };
    let (cfg, _) = slow(c.reconfig(&set, None)).await.unwrap();
    assert_eq!(cfg.version, Some(RECONFIG_VERSION), "{}", cfg.raw);
    assert_members(q, &cfg, &all_but(followers[0]));

    let all = Reconfig::NonIncremental {
        members: (1..=NUM_SERVERS).map(|n| q.server_string(n)).collect(),
    };
    let (cfg, _) = slow(c.reconfig(&all, None)).await.unwrap();
    assert_members(q, &cfg, &[1, 2, 3]);
    slow(c.close()).await.unwrap();
}

quorum_test!(remove_connected_follower, true);
/// `TestReconfigServer::testRemoveConnectedFollower`: a client on a
/// follower removes that follower. The client then reads a config of
/// two members. The C case does not check the reply of the reconfig,
/// because the removed server can end the connection.
async fn remove_connected_follower(q: &Quorum, rt: Rt) {
    let followers = q.followers();
    let c = connect_followers(q, rt, &followers).await;
    slow(c.add_auth("digest", b"super:test".to_vec()))
        .await
        .unwrap();
    let r = remove(&c, followers[0]).await;
    assert!(matches!(r, Ok(_) | Err(Error::ConnectionLoss)), "{r:?}");
    let (cfg, _) = config_after_move(&c).await;
    assert_members(q, &cfg, &all_but(followers[0]));
    slow(c.close()).await.unwrap();
}

quorum_test!(remove_follower, true);
/// `TestReconfigServer::testRemoveFollower`: on the leader, an
/// incremental reconfig removes a follower and gives two members at the
/// next version. A second one adds the follower back and gives three
/// members.
async fn remove_follower(q: &Quorum, rt: Rt) {
    let c = connect_leader(q, rt).await;
    let (cfg, _) = slow(c.get_config()).await.unwrap();
    slow(c.add_auth("digest", b"super:test".to_vec()))
        .await
        .unwrap();
    assert_eq!(cfg.version, Some(FIRST_VERSION), "{}", cfg.raw);
    assert_members(q, &cfg, &[1, 2, 3]);

    let followers = q.followers();
    assert_eq!(followers.len(), NUM_SERVERS - 1);
    let (cfg, _) = remove(&c, followers[0]).await.unwrap();
    assert_eq!(cfg.version, Some(RECONFIG_VERSION), "{}", cfg.raw);
    assert_members(q, &cfg, &all_but(followers[0]));

    let join = Reconfig::Incremental {
        joining: vec![q.server_string(followers[0])],
        leaving: Vec::new(),
    };
    let (cfg, _) = slow(c.reconfig(&join, None)).await.unwrap();
    assert_members(q, &cfg, &[1, 2, 3]);
    slow(c.close()).await.unwrap();
}

quorum_test!(reconfig_failure_without_auth, true);
/// `TestReconfigServer::testReconfigFailureWithoutAuth` (ZOOKEEPER-2014):
/// only the super user can reconfig. With no auth and with a wrong
/// password the reconfig fails with `NoAuth`. With `super:test` it
/// works, and the config has two members.
async fn reconfig_failure_without_auth(q: &Quorum, rt: Rt) {
    let followers = q.followers();
    let c = connect_followers(q, rt, &followers).await;
    assert_eq!(remove(&c, followers[0]).await.unwrap_err(), Error::NoAuth);
    slow(c.add_auth("digest", b"super:wrong".to_vec()))
        .await
        .unwrap();
    assert_eq!(remove(&c, followers[0]).await.unwrap_err(), Error::NoAuth);
    slow(c.add_auth("digest", b"super:test".to_vec()))
        .await
        .unwrap();
    let (cfg, _) = remove(&c, followers[0]).await.unwrap();
    assert_members(q, &cfg, &all_but(followers[0]));
    let (cfg, _) = config_after_move(&c).await;
    assert_members(q, &cfg, &all_but(followers[0]));
    slow(c.close()).await.unwrap();
}

quorum_test!(
    reconfig_failure_without_server_superuser_password_configured,
    false
);
/// `TestReconfigServer::testReconfigFailureWithoutServerSuperuserPasswordConfigured`:
/// a quorum with no super user digest refuses every reconfig with
/// `NoAuth`: with no auth, with `super:` and with `super:test`.
async fn reconfig_failure_without_server_superuser_password_configured(q: &Quorum, rt: Rt) {
    let followers = q.followers();
    let c = connect_followers(q, rt, &followers).await;
    assert_eq!(remove(&c, followers[0]).await.unwrap_err(), Error::NoAuth);
    for auth in [&b"super:"[..], &b"super:test"[..]] {
        slow(c.add_auth("digest", auth.to_vec())).await.unwrap();
        assert_eq!(remove(&c, followers[0]).await.unwrap_err(), Error::NoAuth);
    }
    let (cfg, _) = slow(c.get_config()).await.unwrap();
    assert_members(q, &cfg, &[1, 2, 3]);
    slow(c.close()).await.unwrap();
}
