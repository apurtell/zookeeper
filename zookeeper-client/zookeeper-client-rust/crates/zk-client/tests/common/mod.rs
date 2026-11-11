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

//! Shared helpers of the zk-client integration tests.
//!
//! - [`RealServer`]: a Java server of this source tree. It runs
//!   `dev/test-server.sh start PORT [DIR]`, and its drop runs `stop`.
//! - [`SharedServer`]: one real server for all tests of one binary.
//! - [`proxy::Proxy`]: a TCP proxy that a test can cut, to end the
//!   connections of one client while the server stays up.
//! - [`fake`]: a `zk_fakeserver::FakeServer` on a free port.
//! - [`builder`]: a client builder with short timeouts for a test.
//!
//! A real-server test takes its port from [`real_port`]. The port base
//! comes from `ZK_TEST_PORT_BASE`. Parallel test runs or CI jobs on one
//! host each set a different base, so their ports do not collide. With
//! no base, or when the server cannot start, the test
//! skips. Real-server tests also carry `#[ignore = "real-server"]`, so
//! a plain `cargo test` never starts a server. When
//! `ZK_TEST_REQUIRE_SERVER` is set, a missing port base or a server that
//! cannot start fails the test and does not skip it.

#![allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

pub mod proxy;

use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{
    Client, ClientBuilder, CreateMode, DisconnectCause, Runtime, SessionInfo, StateWatcher,
    ThreadOptions,
};
use zk_fakeserver::FakeServer;

/// The wait budget of a test step.
pub const WAIT: Duration = Duration::from_secs(5);

/// The session timeout of a test client.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(4);

/// The environment variable that holds the first port of the range of
/// this test run.
pub const PORT_BASE_ENV: &str = "ZK_TEST_PORT_BASE";

/// The environment variable that makes a missing server a test failure.
pub const REQUIRE_SERVER_ENV: &str = "ZK_TEST_REQUIRE_SERVER";

/// The port `base + offset`, or `None` when `ZK_TEST_PORT_BASE` is not
/// set or not valid. A test returns early on `None`. When a server is
/// required, a missing base fails the test.
pub fn real_port(offset: u16) -> Option<u16> {
    let base = std::env::var(PORT_BASE_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok());
    let Some(base) = base else {
        return skip(
            "no real-server port",
            &format!("{PORT_BASE_ENV} is not valid"),
        );
    };
    base.checked_add(offset)
}

/// Gives true when `ZK_TEST_REQUIRE_SERVER` is set and not empty.
pub fn server_required() -> bool {
    std::env::var(REQUIRE_SERVER_ENV).is_ok_and(|v| !v.trim().is_empty())
}

/// Gives `None` so that the test skips. When a server is required, it
/// fails the test instead.
pub fn skip<T>(what: &str, cause: &dyn std::fmt::Display) -> Option<T> {
    assert!(
        !server_required(),
        "{what}: {cause} ({REQUIRE_SERVER_ENV} is set)"
    );
    eprintln!("skip: {what}: {cause}");
    None
}

/// The path of `dev/test-server.sh`.
pub fn test_server_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dev/test-server.sh")
}

/// A standalone ZooKeeper server. The drop stops it.
#[derive(Debug)]
pub struct RealServer {
    port: u16,
    /// The server directory, or `None` for the script default.
    dir: Option<PathBuf>,
    /// Extra `zoo.cfg` lines (`ZK_TEST_SERVER_PROPS`).
    props: String,
    /// Extra JVM options (`ZK_TEST_SERVER_JVM_OPTS`).
    jvm_opts: String,
}

impl RealServer {
    /// Starts a server on `port` and waits until it serves. A quorum
    /// member is ready when it answers `ruok`.
    ///
    /// # Errors
    ///
    /// The spawn error, or `Other` when the script fails. The usual
    /// cause is a server that is not built (`mvn -DskipTests install
    /// -pl zookeeper-server -am`).
    pub fn start(port: u16) -> io::Result<Self> {
        Self::start_with(port, None, "", "")
    }

    /// Starts a server on `port` with a server directory, extra
    /// `zoo.cfg` lines and extra JVM options. An empty value keeps the
    /// script default.
    ///
    /// # Errors
    ///
    /// As for [`start`](Self::start).
    pub fn start_with(
        port: u16,
        dir: Option<PathBuf>,
        props: &str,
        jvm_opts: &str,
    ) -> io::Result<Self> {
        let s = Self {
            port,
            dir,
            props: props.to_owned(),
            jvm_opts: jvm_opts.to_owned(),
        };
        s.run_start()?;
        Ok(s)
    }

    /// Runs `test-server.sh start` with the settings of this server.
    fn run_start(&self) -> io::Result<()> {
        let mut cmd = Command::new("bash");
        cmd.arg(test_server_script())
            .arg("start")
            .arg(self.port.to_string());
        if let Some(d) = &self.dir {
            cmd.arg(d);
        }
        if !self.props.is_empty() {
            cmd.env("ZK_TEST_SERVER_PROPS", &self.props);
        }
        if !self.jvm_opts.is_empty() {
            cmd.env("ZK_TEST_SERVER_JVM_OPTS", &self.jvm_opts);
        }
        let status = cmd.stdout(Stdio::null()).status()?;
        if status.success() {
            Ok(())
        } else {
            // The script can leave a process after a timeout.
            stop(self.port, self.dir.as_deref());
            Err(io::Error::other(format!(
                "test-server.sh start {} failed: {status}",
                self.port
            )))
        }
    }

    /// Starts a server, or gives `None` and a note when it cannot start.
    /// A test returns early on `None`. When a server is required, a
    /// failed start fails the test.
    pub fn start_or_skip(port: u16) -> Option<Self> {
        match Self::start(port) {
            Ok(s) => Some(s),
            Err(e) => skip("no real ZooKeeper server", &e),
        }
    }

    /// Stops the server and waits until its port is closed. The data
    /// directory stays, so [`start_again`](Self::start_again) restores
    /// the tree and the sessions.
    pub fn stop_now(&self) {
        stop(self.port, self.dir.as_deref());
    }

    /// Starts the server again on the same port and data directory.
    ///
    /// # Errors
    ///
    /// As for [`start`](Self::start).
    pub fn start_again(&self) -> io::Result<()> {
        self.run_start()
    }

    /// The port of the server.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `127.0.0.1:PORT`.
    pub fn connect_string(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

impl Drop for RealServer {
    fn drop(&mut self) {
        stop(self.port, self.dir.as_deref());
    }
}

/// The default server directory of the script for `port`.
pub fn default_server_dir(port: u16) -> PathBuf {
    std::env::temp_dir().join(format!("zk-rust-test-{port}"))
}

/// Starts the server at `base + offset` on an empty tree, or gives
/// `None` to skip. The data of an earlier run is removed first.
pub fn fresh_server(offset: u16) -> Option<RealServer> {
    let port = real_port(offset)?;
    // On a first run the directory does not exist. The helper ignores
    // that error.
    let _ = std::fs::remove_dir_all(default_server_dir(port).join("data"));
    RealServer::start_or_skip(port)
}

/// Stops the server on `port` and waits until the port is closed.
///
/// `test-server.sh stop` sends the signal and does not wait. A server
/// that still exits can answer the `ruok` of the next start on the same
/// port, and then go away. Thus the helper waits up to 10 s here.
fn stop(port: u16, dir: Option<&std::path::Path>) {
    let mut cmd = Command::new("bash");
    cmd.arg(test_server_script())
        .arg("stop")
        .arg(port.to_string());
    if let Some(d) = dir {
        cmd.arg(d);
    }
    let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One server that the tests of one binary share.
///
/// The first [`SharedServer::acquire`] starts it on an empty tree. The
/// last guard stops it. The stop runs under the lock, so a new start
/// never meets a server that still exits. Each test uses its own path
/// prefix.
pub struct SharedServer {
    state: Mutex<(usize, Option<RealServer>)>,
    offset: u16,
}

/// A use of a [`SharedServer`]. The drop of the last guard stops it.
pub struct SharedGuard {
    owner: &'static SharedServer,
    connect_string: String,
}

impl SharedServer {
    /// A shared server at `base + offset`. Put it in a `static`.
    pub const fn new(offset: u16) -> Self {
        Self {
            state: Mutex::new((0, None)),
            offset,
        }
    }

    /// Starts the server if it does not run, or gives `None` to skip.
    pub fn acquire(&'static self) -> Option<SharedGuard> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.1.is_none() {
            st.1 = Some(fresh_server(self.offset)?);
        }
        st.0 += 1;
        let connect_string = st.1.as_ref().map(RealServer::connect_string)?;
        Some(SharedGuard {
            owner: self,
            connect_string,
        })
    }
}

impl SharedGuard {
    /// `127.0.0.1:PORT`.
    pub fn connect_string(&self) -> String {
        self.connect_string.clone()
    }
}

impl Drop for SharedGuard {
    fn drop(&mut self) {
        let mut st = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.0 -= 1;
        if st.0 == 0 {
            // The drop stops the server while the lock is held.
            st.1 = None;
        }
    }
}

/// The `DisconnectCause` in `last_error`, if it is one.
pub fn disconnect_cause(info: &SessionInfo) -> Option<DisconnectCause> {
    info.last_error
        .as_ref()
        .and_then(|e| e.downcast_ref::<DisconnectCause>().copied())
}

/// The `io::ErrorKind` in `last_error`, if it is an `io::Error`.
pub fn io_error_kind(info: &SessionInfo) -> Option<io::ErrorKind> {
    info.last_error
        .as_ref()
        .and_then(|e| e.downcast_ref::<io::Error>().map(io::Error::kind))
}

/// Waits until the state of `w` matches `pred`, at most `d`. It gives
/// the last value.
pub async fn wait_state(
    w: &mut StateWatcher,
    d: Duration,
    pred: impl Fn(&SessionInfo) -> bool,
) -> SessionInfo {
    let deadline = tokio::time::Instant::now() + d;
    loop {
        let info = w.current();
        if pred(&info) {
            return info;
        }
        match tokio::time::timeout_at(deadline, w.changed()).await {
            Ok(_) => {}
            Err(_) => panic!("state wait timed out at {info:?}"),
        }
    }
}

/// Waits until `pred` holds for the session snapshot, within [`WAIT`].
pub async fn wait_info(
    w: &mut StateWatcher,
    mut pred: impl FnMut(&SessionInfo) -> bool,
) -> SessionInfo {
    within(async {
        loop {
            let info = w.current();
            if pred(&info) {
                return info;
            }
            let _ = w.changed().await;
        }
    })
    .await
}

/// Starts a fake server on a free loopback port.
pub fn fake() -> FakeServer {
    FakeServer::start().expect("fake server bind")
}

/// A builder for `connect_string` with the test session timeout and a
/// short reconnect delay.
pub fn builder(connect_string: &str) -> ClientBuilder {
    Client::builder(connect_string)
        .session_timeout(SESSION_TIMEOUT)
        .reconnect_delay(Duration::from_millis(50))
}

/// The driver of a test client.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Rt {
    /// `Runtime::Thread`: one IO thread for the client.
    Thread,
    /// `Runtime::Tokio` on the runtime of the test.
    #[cfg(all(unix, feature = "tokio"))]
    Tokio,
}

impl Rt {
    /// A short name for node paths.
    pub fn name(self) -> &'static str {
        match self {
            Self::Thread => "thread",
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio => "tokio",
        }
    }

    /// Sets this driver on `b`. `Tokio` uses the runtime of the caller.
    pub fn apply(self, b: ClientBuilder) -> ClientBuilder {
        match self {
            Self::Thread => b.runtime(Runtime::Thread(ThreadOptions::default())),
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio => b.runtime(Runtime::Tokio(tokio::runtime::Handle::current())),
        }
    }
}

/// Every driver of this build.
pub fn all_rts() -> Vec<Rt> {
    vec![
        Rt::Thread,
        #[cfg(all(unix, feature = "tokio"))]
        Rt::Tokio,
    ]
}

/// The context of one real-server test: the server, a driver and a
/// node path that only this test uses.
pub struct Ctx {
    /// `127.0.0.1:PORT` of the server.
    pub cs: String,
    /// The root node of this test, for example `/crud-thread`.
    pub root: String,
    /// The driver of the clients of this test.
    pub rt: Rt,
    _guard: SharedGuard,
}

impl Ctx {
    /// Takes the shared server and names the root `/<name>-<rt>`. It
    /// gives `None` when no server can start.
    pub fn new(server: &'static SharedServer, name: &str, rt: Rt) -> Option<Self> {
        let guard = server.acquire()?;
        Some(Self {
            cs: guard.connect_string(),
            root: format!("/{name}-{}", rt.name()),
            rt,
            _guard: guard,
        })
    }

    /// A test builder for the server with the driver of this test.
    pub fn builder(&self) -> ClientBuilder {
        self.rt.apply(builder(&self.cs))
    }

    /// Connects a client with the driver of this test.
    pub async fn connect(&self) -> Client {
        within(self.builder().connect()).await.expect("connect")
    }

    /// The port of the server.
    pub fn port(&self) -> u16 {
        self.cs
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("server port")
    }

    /// `root + rel`. `rel` is empty or starts with `/`.
    pub fn path(&self, rel: &str) -> String {
        format!("{}{rel}", self.root)
    }
}

/// Runs a future with the test budget [`WAIT`].
pub async fn within<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

/// Connects a client with `b` and waits for the session.
pub async fn connect(b: ClientBuilder) -> Client {
    within(b.connect()).await.expect("connect")
}

/// Creates the root node of a test and gives a connected client.
pub async fn setup(ctx: &Ctx) -> Client {
    let c = ctx.connect().await;
    within(c.create(&ctx.root, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    c
}

/// A file of the TLS test fixtures (`zk_testkit::fixtures::tls_dir`).
pub fn fixture(name: &str) -> PathBuf {
    zk_testkit::fixtures::tls_dir().join(name)
}

/// The thread runtime with the default options.
pub fn thread() -> Runtime {
    Runtime::Thread(ThreadOptions::default())
}

/// TLS options with the test CA and no identity.
#[cfg(feature = "tls-rustls")]
pub fn ca_only() -> apache_zookeeper::TlsOptions {
    apache_zookeeper::TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .build()
        .unwrap()
}
