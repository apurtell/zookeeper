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

//! Shared helpers of the C parity tests for the client suites.
//!
//! The C suites `TestClient.cc`, `TestClientRetry.cc` and
//! `TestReadOnlyClient.cc` stop and start their server, use TLS and use
//! a read-only server. These helpers give the long waits, the server
//! restarts and the TLS server settings of those tests.

#![allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apache_zookeeper::{
    Client, ClientBuilder, EventKind, OneshotWatcher, SessionState, WatchedEvent,
};

use crate::common::{self, RealServer, Rt, wait_state};

/// The session timeout of a client that must outlive a server restart.
pub const RESTART_SESSION: Duration = Duration::from_secs(10);

/// The wait for a reconnect after a server restart.
pub const RECONNECT_WAIT: Duration = Duration::from_secs(20);

/// The time that a test waits to show that a watcher has no event.
pub const QUIET: Duration = Duration::from_millis(300);

/// A builder for `cs` with the driver `rt` and a session that outlives
/// a server restart.
pub fn restart_builder(rt: Rt, cs: &str) -> ClientBuilder {
    rt.apply(common::builder(cs))
        .session_timeout(RESTART_SESSION)
}

/// Runs `f` with the wait budget `d`.
pub async fn within_for<F: Future>(d: Duration, f: F) -> F::Output {
    tokio::time::timeout(d, f).await.expect("timed out")
}

/// True when `w` gives no event in [`QUIET`]. The watcher stays usable.
pub async fn is_pending(w: &mut OneshotWatcher) -> bool {
    tokio::time::timeout(QUIET, w).await.is_err()
}

/// Waits for the event of `w` and checks its kind and its path.
pub async fn expect_event(w: OneshotWatcher, kind: EventKind, path: &str) -> WatchedEvent {
    let ev = common::within(w)
        .await
        .unwrap_or_else(|e| panic!("{path}: watch error {e:?}"));
    assert_eq!(ev.kind, kind, "{path}: {ev:?}");
    assert_eq!(ev.path, path, "{ev:?}");
    ev
}

/// Stops `server`, waits until each client is not connected, starts the
/// server again and waits until each client connects again. The
/// sessions stay, because the data directory stays.
pub async fn restart(server: &RealServer, clients: &[&Client]) {
    server.stop_now();
    for c in clients {
        let mut s = c.state_watcher();
        wait_state(&mut s, common::WAIT, |i| {
            i.state == SessionState::Connecting
        })
        .await;
    }
    server.start_again().unwrap();
    for c in clients {
        let mut s = c.state_watcher();
        wait_state(&mut s, RECONNECT_WAIT, |i| i.state.is_connected()).await;
    }
}

/// A clean server directory `zk-rust-test-<name>-<port>` with
/// `data/myid` = 1, for a quorum server.
pub fn quorum_dir(name: &str, port: u16) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zk-rust-test-{name}-{port}"));
    // On a first run the directory does not exist.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data").join("myid"), "1\n").unwrap();
    dir
}

/// Starts a server, or gives `None` and a note to skip. When a server
/// is required, a failed start fails the test.
pub fn start_or_skip(
    port: u16,
    dir: Option<PathBuf>,
    props: &str,
    jvm_opts: &str,
) -> Option<RealServer> {
    match RealServer::start_with(port, dir, props, jvm_opts) {
        Ok(s) => Some(s),
        Err(e) => common::skip("no real ZooKeeper server", &e),
    }
}

/// Starts the server at `base + offset` on an empty tree with extra
/// settings, or gives `None` to skip.
pub fn fresh_server_with(offset: u16, props: &str, jvm_opts: &str) -> Option<RealServer> {
    let port = common::real_port(offset)?;
    // On a first run the directory does not exist.
    let _ = std::fs::remove_dir_all(common::default_server_dir(port).join("data"));
    start_or_skip(port, None, props, jvm_opts)
}

/// The passphrase of the encrypted TLS fixtures (`gen.sh`).
pub const TLS_PASS: &str = "zk-test-pass";

/// A file of the TLS test fixtures (`zk_testkit::fixtures::tls_dir`).
pub fn tls_fixture(name: &str) -> PathBuf {
    zk_testkit::fixtures::tls_dir().join(name)
}

/// The `zoo.cfg` lines of a Netty server with a secure client port on
/// `secure`, the PEM stores of the fixtures and the x509 auth provider.
/// The key store goes into `dir`. `client_auth` is the value of
/// `ssl.clientAuth`.
pub fn tls_props(dir: &Path, secure: u16, client_auth: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    // A PEM key store holds the key and the chain in one file.
    let ks = dir.join("server-keystore.pem");
    let mut pem = std::fs::read(tls_fixture("server.key")).unwrap();
    pem.extend(std::fs::read(tls_fixture("server.pem")).unwrap());
    std::fs::write(&ks, pem).unwrap();
    format!(
        "secureClientPort={secure}\n\
         serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory\n\
         authProvider.x509=org.apache.zookeeper.server.auth.X509AuthenticationProvider\n\
         ssl.keyStore.location={}\n\
         ssl.keyStore.type=PEM\n\
         ssl.trustStore.location={}\n\
         ssl.trustStore.type=PEM\n\
         ssl.clientAuth={client_auth}\n",
        ks.display(),
        tls_fixture("ca.pem").display()
    )
}

/// The C certificate string `ca,cert,key,passphrase` of the fixtures.
/// It is the form of `zookeeper_init_ssl`.
pub fn legacy_cert_string() -> String {
    format!(
        "{},{},{},{TLS_PASS}",
        tls_fixture("ca.pem").display(),
        tls_fixture("client.pem").display(),
        tls_fixture("keys/p8-sha256-aes256.pem").display()
    )
}
