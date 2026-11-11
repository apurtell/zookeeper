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

//! Ensemble tests against real servers of this source tree: read-only
//! mode and `reconfig`.
//!
//! Each test starts its own quorum server at port offset 14, with
//! quorum and election ports at offsets 15 to 18 and a second client
//! port at 19. The tests share these ports, so a lock runs them one
//! after the other. The tests have `#[ignore = "real-server"]`. Run them
//! with `ZK_TEST_PORT_BASE=<base> cargo test --test real_ensemble --
//! --ignored`.

// A scenario is one long async body. It runs on a 2 MiB test or worker
// thread, so the stack frame limit of the library does not apply.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::path::PathBuf;
use std::time::Duration;

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{
    AddWatchMode, Client, CreateMode, Error, EventKind, Id, MultiError, MultiReader, MultiWriter,
    ReadResult, Reconfig, ServerRole, SessionState, Version,
};
use common::{RealServer, within};

/// The tests use the same ports, so they run one at a time.
static PORTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The time for a quorum server to serve after it answers `ruok`.
const SERVE_WAIT: Duration = Duration::from_secs(20);

/// The ports of the test ensemble.
struct Ports {
    client: u16,
    q1: u16,
    e1: u16,
    q2: u16,
    e2: u16,
    client2: u16,
}

impl Ports {
    /// The ports from `ZK_TEST_PORT_BASE`, or `None` to skip.
    fn get() -> Option<Self> {
        Some(Self {
            client: common::real_port(14)?,
            q1: common::real_port(15)?,
            e1: common::real_port(16)?,
            q2: common::real_port(17)?,
            e2: common::real_port(18)?,
            client2: common::real_port(19)?,
        })
    }
}

/// A clean server directory with `data/myid` = 1.
fn server_dir(name: &str, port: u16) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zk-rust-test-{name}-{port}"));
    // On a first run the directory does not exist.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data").join("myid"), "1\n").unwrap();
    dir
}

/// Starts server 1, or gives `None` and a note to skip.
fn start(port: u16, dir: PathBuf, props: &str, jvm: &str) -> Option<RealServer> {
    match RealServer::start_with(port, Some(dir), props, jvm) {
        Ok(s) => Some(s),
        Err(e) => common::skip("the quorum server did not start", &e),
    }
}

/// Connects with `b`, with the longer wait of a quorum start.
async fn connect_slow(b: apache_zookeeper::ClientBuilder) -> Client {
    tokio::time::timeout(SERVE_WAIT, b.connect())
        .await
        .expect("timed out")
        .expect("connect")
}

/// Rule: with `allow_read_only`, a client connects to a server that has
/// no quorum, as `ConnectedReadOnly`. Reads work. Writes, `sync` and
/// `multi` fail with `NotReadOnly`. A client without the flag does not
/// connect (ReadOnlyRequestProcessor).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn read_only_server_serves_reads() {
    let _lock = PORTS.lock().await;
    let Some(p) = Ports::get() else { return };
    let dir = server_dir("ro", p.client);
    // Two voters and one live server: the server has no quorum. A
    // read-only server accepts only local sessions
    // (ReadOnlyRequestProcessor). This line overrides the script value,
    // because the last line of a key wins.
    let props = format!(
        "localSessionsEnabled=true\ninitLimit=5\nsyncLimit=2\nserver.1=127.0.0.1:{}:{}\nserver.2=127.0.0.1:{}:{}",
        p.q1, p.e1, p.q2, p.e2
    );
    let Some(server) = start(p.client, dir.clone(), &props, "-Dreadonlymode.enabled=true") else {
        return;
    };
    let cs = server.connect_string();

    let rts = common::all_rts();
    for rt in rts {
        let c = connect_slow(rt.apply(common::builder(&cs)).allow_read_only(true)).await;
        assert_eq!(c.state().state, SessionState::ConnectedReadOnly);
        let kids = within(c.get_children("/")).await.unwrap();
        assert!(kids.iter().any(|k| k == "zookeeper"), "{kids:?}");
        assert!(within(c.exists("/zookeeper")).await.unwrap().is_some());
        let mut reads = MultiReader::new();
        reads.get_children("/").unwrap();
        reads.get_data("/missing").unwrap();
        let r = within(c.multi_read(&reads)).await.unwrap();
        assert!(
            matches!(r.first(), Some(Ok(ReadResult::Children(_)))),
            "{r:?}"
        );
        assert!(matches!(r.get(1), Some(Err(Error::NoNode))), "{r:?}");

        let f = c.create("/w", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE);
        assert_eq!(within(f).await.unwrap_err(), Error::NotReadOnly);
        assert_eq!(
            within(c.set_data("/zookeeper", b"x", None)).await,
            Err(Error::NotReadOnly)
        );
        assert_eq!(within(c.sync("/")).await, Err(Error::NotReadOnly));
        let mut txn = MultiWriter::new();
        txn.check("/zookeeper", Version::ANY).unwrap();
        assert_eq!(
            within(c.multi(&txn)).await.unwrap_err(),
            MultiError::Request(Error::NotReadOnly)
        );
        // Watches work on a read-only server.
        let w = within(c.add_watch("/", AddWatchMode::PersistentRecursive)).await;
        assert!(w.is_ok(), "{w:?}");
        within(c.close()).await.unwrap();
    }

    // A client without the flag stays in `Connecting`.
    let plain = common::builder(&cs).connect();
    let s = plain.state_watcher();
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), plain)
            .await
            .is_err()
    );
    assert_eq!(s.current().state, SessionState::Connecting);

    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rule: `reconfig` adds and removes members, checks the expected
/// config version (`BadVersion`) and needs the super user (`NoAuth`).
/// The reply is the new config, and a config watch fires on the change
/// (Java `ZooKeeperAdmin.reconfigure`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn reconfig_adds_and_removes_an_observer() {
    let _lock = PORTS.lock().await;
    let Some(p) = Ports::get() else { return };
    let dir = server_dir("reconfig", p.client);
    let props = format!(
        "standaloneEnabled=false\nreconfigEnabled=true\ninitLimit=5\nsyncLimit=2\n\
         server.1=127.0.0.1:{}:{}:participant;127.0.0.1:{}",
        p.q1, p.e1, p.client
    );
    let jvm = format!(
        "-Dzookeeper.DigestAuthenticationProvider.superDigest={}",
        Id::digest("super", "sekret").id
    );
    let Some(server) = start(p.client, dir.clone(), &props, &jvm) else {
        return;
    };
    let c = connect_slow(common::builder(&server.connect_string())).await;

    let (cfg, _) = within(c.get_config()).await.unwrap();
    assert_eq!(cfg.servers.len(), 1, "{cfg:?}");
    let one = cfg.servers.first().unwrap();
    assert_eq!((one.id, one.role), (1, ServerRole::Participant));
    assert_eq!(one.client, Some(("127.0.0.1".to_owned(), p.client)));
    let v = cfg.version.expect("config version");

    let join = Reconfig::Incremental {
        joining: vec![format!(
            "server.2=127.0.0.1:{}:{}:observer;127.0.0.1:{}",
            p.q2, p.e2, p.client2
        )],
        leaving: Vec::new(),
    };
    assert_eq!(
        within(c.reconfig(&join, Some(v))).await.unwrap_err(),
        Error::NoAuth
    );
    within(c.add_auth("digest", b"super:sekret".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        within(c.reconfig(&join, Some(v.wrapping_add(7))))
            .await
            .unwrap_err(),
        Error::BadVersion
    );

    let (_, _, w) = within(c.get_config_watched()).await.unwrap();
    let (cfg, _) = within(c.reconfig(&join, Some(v))).await.unwrap();
    assert_eq!(cfg.servers.len(), 2, "{cfg:?}");
    let two = cfg.servers.iter().find(|s| s.id == 2).unwrap();
    assert_eq!(two.role, ServerRole::Observer);
    assert_eq!((two.quorum_port, two.election_port), (p.q2, p.e2));
    let v2 = cfg.version.expect("config version");
    assert!(v2 > v);
    let ev = within(w).await.unwrap();
    assert_eq!(
        (ev.kind, ev.path.as_str()),
        (EventKind::NodeDataChanged, "/zookeeper/config")
    );

    let leave = Reconfig::Incremental {
        joining: Vec::new(),
        leaving: vec![2],
    };
    let (cfg, _) = within(c.reconfig(&leave, None)).await.unwrap();
    assert_eq!(cfg.servers.len(), 1, "{cfg:?}");
    assert!(cfg.version.expect("config version") > v2);
    let (now, _) = within(c.get_config()).await.unwrap();
    assert_eq!(now, cfg);

    within(c.close()).await.unwrap();
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}
