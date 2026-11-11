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

//! Shared helpers of the zk-recipes integration tests.
//!
//! - [`fake`] and [`connect`]: the model level. A test runs the recipes
//!   against a `zk_fakeserver::FakeServer` on a free loopback port.
//! - [`RealServer`]: one standalone Java server. It runs
//!   `dev/test-server.sh`. [`Ensemble`]: three servers. It runs
//!   `dev/test-ensemble.sh`. The drop of each one stops its servers.
//! - [`Servers`]: a [`RealServer`] or an [`Ensemble`], by [`Topology`].
//!   The real-server tests run each scenario on both layouts.
//! - [`Proxy`]: a loopback TCP proxy that a test can cut, to drop the
//!   connections of one client while the server stays up. The lock and
//!   latch tests use it for a lost create and a reconnect. It can also
//!   delay each round trip.
//!   [`ProxyGroup`] puts one proxy in front of each server.
//!
//! The ports of the real servers come from `ZK_TEST_PORT_BASE`. The
//! base must leave ten ports free (base to base + 9), for example
//! 23400. With no base, or when a server cannot start, a test skips.
//!
//! The range holds one standalone server and one ensemble, so only one
//! real server runs at a time. In a test binary, a lock makes the
//! tests take turns. Between processes, a lease directory in the temp
//! directory does the same, so parallel test runs and test binaries can
//! share one range. A test must not hold a `RealServer` and an
//! `Ensemble` at the same time.
//! `ZK_TEST_SERVER_VERSION` selects a release server under
//! `/tmp/zk-servers` (`dev/get-release-server.sh`). With no version, the
//! server comes from this source tree. Real-server tests also carry
//! `#[ignore = "real-server"]`, so a plain `cargo test` starts no server.
//! When `ZK_TEST_REQUIRE_SERVER` is set, a server that cannot start fails
//! the test and does not skip it. `dev/run-recipes-real.sh` sets it.
//!
//! The lease covers one server or one ensemble. Its drop releases the
//! lease, so other processes can use the range between two tests. The
//! first holder after a crash stops the servers that the crashed process
//! left in the range.
//!
//! Each test binary uses a subset of these items.

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

#[path = "../../../zk-client/tests/common/proxy.rs"]
mod proxy;

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use apache_zookeeper::{Client, ClientBuilder, Runtime, SessionInfo, StateWatcher, ThreadOptions};
use apache_zookeeper_recipes::{Latch, LeaderLatch, Participant, TreeCache, TreeEvent};
use zk_fakeserver::FakeServer;

pub use proxy::Proxy;

/// The wait budget of a test step.
pub const WAIT: Duration = Duration::from_secs(10);

/// The session timeout of a test client.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(4);

/// The environment variable with the first port of the range.
pub const PORT_BASE_ENV: &str = "ZK_TEST_PORT_BASE";

/// The environment variable that selects a release server.
pub const SERVER_VERSION_ENV: &str = "ZK_TEST_SERVER_VERSION";

/// The environment variable that makes a server that cannot start a
/// test failure.
pub const REQUIRE_SERVER_ENV: &str = "ZK_TEST_REQUIRE_SERVER";

/// The release that lacks persistent watches.
pub const LEGACY_VERSION: &str = "3.5.10";

/// The port offset of the standalone server.
pub const STANDALONE_OFFSET: u16 = 0;

/// The port offset of the ensemble. Its nine ports are base + 1 to
/// base + 9: clients, then quorum, then election.
pub const ENSEMBLE_OFFSET: u16 = 1;

/// The port `base + offset`, or `None` when `ZK_TEST_PORT_BASE` is not
/// set or not valid.
pub fn real_port(offset: u16) -> Option<u16> {
    let base: u16 = std::env::var(PORT_BASE_ENV).ok()?.trim().parse().ok()?;
    base.checked_add(offset)
}

/// The release version in `ZK_TEST_SERVER_VERSION`, or `None` for the
/// server of this source tree.
pub fn server_version() -> Option<String> {
    std::env::var(SERVER_VERSION_ENV)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// Gives true when `ZK_TEST_REQUIRE_SERVER` is set and not empty.
pub fn server_required() -> bool {
    std::env::var(REQUIRE_SERVER_ENV).is_ok_and(|v| !v.trim().is_empty())
}

/// Gives `None` so that the test skips. When a server is required, it
/// fails the test instead.
fn skip<T>(what: &str, cause: &dyn std::fmt::Display) -> Option<T> {
    assert!(
        !server_required(),
        "{what}: {cause} ({REQUIRE_SERVER_ENV} is set)"
    );
    eprintln!("skip: {what}: {cause}");
    None
}

/// The `dev/` directory of the workspace.
pub fn dev_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dev")
}

/// Starts a fake server on a free loopback port.
pub fn fake() -> FakeServer {
    FakeServer::start().expect("fake server bind")
}

/// A builder for `connect_string` with the test session timeout, a short
/// reconnect delay and the client IO thread. The recipes need no client
/// feature, so the tests use `Runtime::Thread` on every build.
pub fn builder(connect_string: &str) -> ClientBuilder {
    Client::builder(connect_string)
        .session_timeout(SESSION_TIMEOUT)
        .reconnect_delay(Duration::from_millis(50))
        .runtime(Runtime::Thread(ThreadOptions::default()))
}

/// Connects a test client to `connect_string`.
pub async fn connect(connect_string: &str) -> Client {
    within(builder(connect_string).connect())
        .await
        .expect("connect")
}

/// Runs a future with the test budget [`WAIT`].
pub async fn within<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

/// Gives true when `f` is still pending after `d`. A test uses it to
/// show that a waiter does not proceed.
pub async fn still_pending<F: std::future::Future>(f: F, d: Duration) -> bool {
    tokio::time::timeout(d, f).await.is_err()
}

/// Waits until the state of `w` matches `pred`, at most [`WAIT`]. It
/// gives the last value.
pub async fn wait_state(w: &mut StateWatcher, pred: impl Fn(&SessionInfo) -> bool) -> SessionInfo {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let info = w.current();
        if pred(&info) {
            return info;
        }
        if tokio::time::timeout_at(deadline, w.changed())
            .await
            .is_err()
        {
            panic!("state wait timed out at {info:?}");
        }
    }
}

/// Polls the fake server until `pred` holds, at most [`WAIT`].
pub fn wait_fake(server: &FakeServer, pred: impl FnMut(&zk_fakeserver::Cluster) -> bool) {
    assert!(
        server.cluster().wait_until(WAIT, pred),
        "fake server condition timed out"
    );
}

/// Polls `fut` once with a waker that does nothing.
pub fn poll_once<F: std::future::Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    fut.poll(&mut Context::from_waker(Waker::noop()))
}

/// The session id of `client`.
pub fn session_id(client: &Client) -> i64 {
    client.session().0.0
}

/// Tells if `s` is a version-4 UUID with the RFC 4122 variant. The text
/// is canonical and lowercase, as Java's `UUID.randomUUID().toString()`
/// writes it.
pub fn is_v4(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    let lens: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    lens == [8, 4, 4, 4, 12]
        && groups
            .iter()
            .all(|g| g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        && groups[2].starts_with('4')
        && groups[3].starts_with(['8', '9', 'a', 'b'])
}

/// Starts a latch on `path` with the id `id`.
pub async fn start_latch(client: &Client, path: &str, id: &str) -> Latch {
    let latch = LeaderLatch::new(client, path, id).unwrap();
    within(latch.start()).await.unwrap()
}

/// The participants in the form `(id, is_leader)`.
pub fn ids(list: &[Participant]) -> Vec<(String, bool)> {
    list.iter()
        .map(|p| (String::from_utf8(p.id.clone()).unwrap(), p.is_leader))
        .collect()
}

/// Gives the expected participants list of `(id, is_leader)` pairs.
pub fn expect(list: &[(&str, bool)]) -> Vec<(String, bool)> {
    list.iter().map(|(id, l)| ((*id).to_owned(), *l)).collect()
}

/// A short form of a tree cache event: `+path`, `~path`, `-path`,
/// `Initialized` or `Resynced`.
pub fn label(ev: &TreeEvent) -> String {
    match ev {
        TreeEvent::NodeAdded { path, .. } => format!("+{path}"),
        TreeEvent::NodeUpdated { path, .. } => format!("~{path}"),
        TreeEvent::NodeRemoved { path, .. } => format!("-{path}"),
        other => format!("{other:?}"),
    }
}

/// The next event of the cache, within the test budget.
pub async fn next(cache: &mut TreeCache) -> TreeEvent {
    match within(cache.next()).await {
        Some(Ok(ev)) => ev,
        other => panic!("expected an event, got {other:?}"),
    }
}

/// The labels of the events up to and with the first `Initialized` or
/// `Resynced`.
pub async fn until_mark(cache: &mut TreeCache) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let ev = next(cache).await;
        let mark = matches!(ev, TreeEvent::Initialized | TreeEvent::Resynced);
        out.push(label(&ev));
        if mark {
            return out;
        }
    }
}

/// The lock of the port range in this process.
static RANGE: Mutex<()> = Mutex::new(());

/// The thread that holds [`RANGE`]. It turns a second take on the same
/// thread into a clear failure and not a deadlock.
static HOLDER: Mutex<Option<ThreadId>> = Mutex::new(None);

/// The longest wait for the lease of another process.
const LEASE_WAIT: Duration = Duration::from_secs(900);

/// The use of the port range by one server or one ensemble. The drop
/// releases the lease and then the lock.
#[derive(Debug)]
pub struct RangeLease {
    dir: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl Drop for RangeLease {
    fn drop(&mut self) {
        *HOLDER.lock().unwrap_or_else(|e| e.into_inner()) = None;
        release_lease_at(&self.dir);
    }
}

/// The lease directory of the range that starts at `key`.
pub fn lease_dir(key: u16) -> PathBuf {
    std::env::temp_dir().join(format!("zk-recipes-lease-{key}"))
}

/// The lease key: the base of the test range, or `fallback` when
/// `ZK_TEST_PORT_BASE` is not set.
fn range_key(fallback: u16) -> u16 {
    real_port(STANDALONE_OFFSET).unwrap_or(fallback)
}

/// Takes the lock and the lease of the range `key`. Then it stops the
/// servers that an earlier process left in the range.
///
/// # Panics
///
/// When this thread holds the range already. The lease is not
/// reentrant.
fn take_range(key: u16) -> io::Result<RangeLease> {
    let me = std::thread::current().id();
    assert!(
        *HOLDER.lock().unwrap_or_else(|e| e.into_inner()) != Some(me),
        "this thread holds the port range already: drop the RealServer or Ensemble first"
    );
    let guard = RANGE.lock().unwrap_or_else(|e| e.into_inner());
    let dir = lease_dir(key);
    if !acquire_lease_at(&dir, LEASE_WAIT, WAIT) {
        return Err(io::Error::other(format!(
            "no lease of the port range {}",
            dir.display()
        )));
    }
    *HOLDER.lock().unwrap_or_else(|e| e.into_inner()) = Some(me);
    let lease = RangeLease { dir, _guard: guard };
    reap_leftovers(key);
    Ok(lease)
}

/// Makes the lease directory `dir` and writes the process id into it.
/// A lease of a process that is gone is taken over. A lease with no
/// process id is taken over after `grace`, because the owner writes the
/// id just after it makes the directory. It gives false when the lease
/// stays taken for `wait`, or when the directory cannot be made.
pub fn acquire_lease_at(dir: &Path, wait: Duration, grace: Duration) -> bool {
    let start = Instant::now();
    let mut no_owner_since: Option<Instant> = None;
    loop {
        match std::fs::create_dir(dir) {
            Ok(()) => {
                if std::fs::write(dir.join("pid"), std::process::id().to_string()).is_ok() {
                    return true;
                }
                let _ = std::fs::remove_dir_all(dir);
                eprintln!("no lease {}: the pid file cannot be written", dir.display());
                return false;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                eprintln!("no lease {}: {e}", dir.display());
                return false;
            }
        }
        let stale = match lease_owner(dir) {
            Some(pid) => {
                no_owner_since = None;
                !process_alive(pid)
            }
            None => no_owner_since.get_or_insert_with(Instant::now).elapsed() >= grace,
        };
        if stale {
            let _ = std::fs::remove_dir_all(dir);
            no_owner_since = None;
            continue;
        }
        if start.elapsed() >= wait {
            eprintln!("no lease {}: it stays taken", dir.display());
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Removes the lease directory `dir` when this process owns it. A lease
/// of another process stays.
pub fn release_lease_at(dir: &Path) {
    if lease_owner(dir) == Some(std::process::id()) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The process id in the lease directory `dir`.
pub fn lease_owner(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join("pid"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Gives true when the process `pid` runs.
pub fn process_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Stops the servers that an earlier process left in the range `key`.
/// The names of the server directories give the ports. The scripts
/// stop only a ZooKeeper process, so a stale pid file does no harm.
fn reap_leftovers(key: u16) {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    let standalone = key + STANDALONE_OFFSET;
    let ensemble = key + ENSEMBLE_OFFSET;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(STANDALONE_DIR_PREFIX)
            && name.ends_with(&format!("-{standalone}"))
            && path.join("server.pid").exists()
        {
            eprintln!("stop a leftover server in {}", path.display());
            let args = [
                "stop".to_owned(),
                standalone.to_string(),
                path.display().to_string(),
            ];
            let _ = run_script("test-server.sh", &args, None);
        }
        if name.starts_with(ENSEMBLE_DIR_PREFIX)
            && name.ends_with(&format!("-{ensemble}"))
            && (1..=3).any(|n| path.join(format!("node{n}/server.pid")).exists())
        {
            eprintln!("stop a leftover ensemble in {}", path.display());
            let args = [
                "stop".to_owned(),
                ensemble.to_string(),
                path.display().to_string(),
            ];
            let _ = run_script("test-ensemble.sh", &args, None);
        }
    }
}

/// The name prefix of a standalone server directory.
const STANDALONE_DIR_PREFIX: &str = "zk-recipes-test-";

/// The name prefix of an ensemble directory.
const ENSEMBLE_DIR_PREFIX: &str = "zk-recipes-ensemble-";

/// Runs one `dev/` script with `args` and the server version.
fn run_script(script: &str, args: &[String], version: Option<&str>) -> io::Result<()> {
    let mut cmd = Command::new("bash");
    cmd.arg(dev_dir().join(script)).args(args);
    if let Some(v) = version {
        // A home in the environment would win over the version.
        cmd.env(SERVER_VERSION_ENV, v)
            .env_remove("ZK_TEST_SERVER_HOME");
    }
    let status = cmd.stdout(Stdio::null()).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{script} {args:?} failed: {status}"
        )))
    }
}

/// Gives true when a server listens on `127.0.0.1:port`.
pub fn port_open(port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

/// Gives an error when a server listens on one of `ports`. A server of
/// another user of the range would answer the test in place of its own.
fn check_free(ports: impl IntoIterator<Item = u16>) -> io::Result<()> {
    match ports.into_iter().find(|&p| port_open(p)) {
        Some(p) => Err(io::Error::other(format!("the port {p} is in use"))),
        None => Ok(()),
    }
}

/// Waits until the server on `port` serves requests, at most [`WAIT`].
fn wait_serving(port: u16) -> io::Result<()> {
    let deadline = Instant::now() + WAIT;
    while srvr_mode(port).is_none() {
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "the server on {port} does not serve requests"
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Waits until nothing listens on `port`, at most 10 s.
fn wait_closed(port: u16) {
    for _ in 0..100 {
        if !port_open(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A standalone ZooKeeper server. The drop stops it.
#[derive(Debug)]
pub struct RealServer {
    port: u16,
    dir: PathBuf,
    version: Option<String>,
    _range: RangeLease,
}

impl RealServer {
    /// Starts a server on `port` on an empty tree. `version` selects a
    /// release server, and `None` selects the server of this source
    /// tree.
    ///
    /// # Errors
    ///
    /// The error of the script. The usual causes are a server that is
    /// not built, a release that is not downloaded, or a port in use.
    pub fn start(port: u16, version: Option<&str>) -> io::Result<Self> {
        let tag = version.unwrap_or("head");
        let dir = std::env::temp_dir().join(format!("{STANDALONE_DIR_PREFIX}{tag}-{port}"));
        let range = take_range(range_key(port))?;
        let s = Self {
            port,
            dir,
            version: version.map(str::to_owned),
            _range: range,
        };
        // An earlier run can leave a server and data in the directory.
        // The first run has no directory.
        s.stop_now();
        let _ = std::fs::remove_dir_all(s.dir.join("data"));
        check_free([port])?;
        // The server answers `ruok` before it serves requests. The
        // `Mode` line of `srvr` comes only when it serves.
        if let Err(e) = s.run("start").and_then(|()| wait_serving(port)) {
            s.stop_now();
            return Err(e);
        }
        Ok(s)
    }

    /// Starts the standalone server of the test range with the version
    /// of `ZK_TEST_SERVER_VERSION`, or gives `None` to skip.
    pub fn start_or_skip() -> Option<Self> {
        Self::start_version_or_skip(server_version().as_deref())
    }

    /// Starts the standalone server of the test range with `version`,
    /// or gives `None` to skip.
    pub fn start_version_or_skip(version: Option<&str>) -> Option<Self> {
        let what = format!("no real ZooKeeper server {}", version.unwrap_or("head"));
        let Some(port) = real_port(STANDALONE_OFFSET) else {
            return skip(&what, &format!("{PORT_BASE_ENV} is not set"));
        };
        match Self::start(port, version) {
            Ok(s) => Some(s),
            Err(e) => skip(&what, &e),
        }
    }

    fn run(&self, cmd: &str) -> io::Result<()> {
        let args = [
            cmd.to_owned(),
            self.port.to_string(),
            self.dir.display().to_string(),
        ];
        run_script("test-server.sh", &args, self.version.as_deref())
    }

    /// Stops the server and waits until its port is closed.
    pub fn stop_now(&self) {
        let _ = self.run("stop");
        wait_closed(self.port);
    }

    /// `127.0.0.1:PORT`.
    pub fn connect_string(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The port of the server.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The release that runs, or `None` for the server of this source
    /// tree.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl Drop for RealServer {
    fn drop(&mut self) {
        self.stop_now();
    }
}

/// Three ZooKeeper servers in one ensemble. The drop stops them.
///
/// `dev/test-ensemble.sh` gives node `n` (1 to 3) the client port
/// `base + n - 1`, the quorum port `base + n + 2` and the election port
/// `base + n + 5`.
#[derive(Debug)]
pub struct Ensemble {
    base: u16,
    dir: PathBuf,
    version: Option<String>,
    _range: RangeLease,
}

/// The time for an ensemble to elect a new leader.
pub const ELECTION_WAIT: Duration = Duration::from_secs(30);

impl Ensemble {
    /// Starts three servers from port `base` on empty trees, and waits
    /// until each one is a leader or a follower.
    ///
    /// # Errors
    ///
    /// The error of the script, or a port in use.
    pub fn start(base: u16, version: Option<&str>) -> io::Result<Self> {
        let tag = version.unwrap_or("head");
        let dir = std::env::temp_dir().join(format!("{ENSEMBLE_DIR_PREFIX}{tag}-{base}"));
        let range = take_range(range_key(base.saturating_sub(ENSEMBLE_OFFSET)))?;
        let s = Self {
            base,
            dir,
            version: version.map(str::to_owned),
            _range: range,
        };
        // The stop needs the pid files, so it comes before the removal.
        s.stop_all();
        let _ = std::fs::remove_dir_all(&s.dir);
        check_free(base..base + 9)?;
        if let Err(e) = s.run(&["start".to_owned()]) {
            s.stop_all();
            return Err(e);
        }
        Ok(s)
    }

    /// Starts the ensemble of the test range with the version of
    /// `ZK_TEST_SERVER_VERSION`, or gives `None` to skip.
    pub fn start_or_skip() -> Option<Self> {
        Self::start_version_or_skip(server_version().as_deref())
    }

    /// Starts the ensemble of the test range with `version`, or gives
    /// `None` to skip.
    pub fn start_version_or_skip(version: Option<&str>) -> Option<Self> {
        let what = format!("no ZooKeeper ensemble {}", version.unwrap_or("head"));
        let Some(base) = real_port(ENSEMBLE_OFFSET) else {
            return skip(&what, &format!("{PORT_BASE_ENV} is not set"));
        };
        match Self::start(base, version) {
            Ok(s) => Some(s),
            Err(e) => skip(&what, &e),
        }
    }

    fn run(&self, cmd: &[String]) -> io::Result<()> {
        let mut args = cmd.to_vec();
        args.insert(1, self.base.to_string());
        args.push(self.dir.display().to_string());
        run_script("test-ensemble.sh", &args, self.version.as_deref())
    }

    /// The client port of node `n` (1 to 3).
    pub fn client_port(&self, n: u16) -> u16 {
        assert!((1..=3).contains(&n), "no node {n}");
        self.base + n - 1
    }

    /// The connect string of all three nodes.
    pub fn connect_string(&self) -> String {
        (1..=3)
            .map(|n| self.node_connect_string(n))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The connect string of node `n` alone.
    pub fn node_connect_string(&self, n: u16) -> String {
        format!("127.0.0.1:{}", self.client_port(n))
    }

    /// The release that runs, or `None` for the server of this source
    /// tree.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Stops node `n` and waits until its client port is closed.
    pub fn stop_node(&self, n: u16) -> io::Result<()> {
        self.run(&["stop-node".to_owned(), n.to_string()])?;
        wait_closed(self.client_port(n));
        Ok(())
    }

    /// Starts node `n` again on its data directory, and waits until it
    /// is a leader or a follower.
    pub fn start_node(&self, n: u16) -> io::Result<()> {
        self.run(&["start-node".to_owned(), n.to_string()])
    }

    /// The node that is the leader now, from the `srvr` command.
    pub fn leader(&self) -> Option<u16> {
        (1..=3).find(|&n| srvr_mode(self.client_port(n)).as_deref() == Some("leader"))
    }

    /// Waits at most [`ELECTION_WAIT`] for a leader other than `not`. It
    /// gives the leader, or `None` when no such leader comes.
    pub fn wait_leader(&self, not: Option<u16>) -> Option<u16> {
        let deadline = Instant::now() + ELECTION_WAIT;
        loop {
            if let Some(n) = self.leader().filter(|&n| Some(n) != not) {
                return Some(n);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop_all(&self) {
        let _ = self.run(&["stop".to_owned()]);
        for n in 1..=3 {
            wait_closed(self.client_port(n));
        }
    }
}

impl Drop for Ensemble {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// The server layout of a real-server test. Each scenario runs on a
/// standalone server and on the three-node ensemble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    /// One standalone server ([`RealServer`]).
    Standalone,
    /// Three servers in one ensemble ([`Ensemble`]).
    Ensemble,
}

/// The servers of one real-server test. The drop stops them.
#[derive(Debug)]
pub enum Servers {
    /// One standalone server.
    Standalone(RealServer),
    /// The three-node ensemble.
    Ensemble(Ensemble),
}

impl Servers {
    /// Starts the servers of `topology` with the version of
    /// `ZK_TEST_SERVER_VERSION`, or gives `None` to skip.
    pub fn start_or_skip(topology: Topology) -> Option<Self> {
        match topology {
            Topology::Standalone => RealServer::start_or_skip().map(Self::Standalone),
            Topology::Ensemble => Ensemble::start_or_skip().map(Self::Ensemble),
        }
    }

    /// The connect string of every server.
    pub fn connect_string(&self) -> String {
        match self {
            Self::Standalone(s) => s.connect_string(),
            Self::Ensemble(e) => e.connect_string(),
        }
    }

    /// The client port of every server.
    pub fn client_ports(&self) -> Vec<u16> {
        match self {
            Self::Standalone(s) => vec![s.port()],
            Self::Ensemble(e) => (1..=3).map(|n| e.client_port(n)).collect(),
        }
    }

    /// The client port of one server for a relay in front of it: the
    /// standalone server, or a follower of the ensemble. A follower
    /// sends each write to the leader, so the relay tests that path too.
    pub fn relay_port(&self) -> u16 {
        match self {
            Self::Standalone(s) => s.port(),
            Self::Ensemble(e) => {
                let leader = e.leader().expect("the ensemble has a leader");
                let follower = (1..=3).find(|&n| n != leader).expect("a follower");
                e.client_port(follower)
            }
        }
    }

    /// The ensemble, or `None` for a standalone server.
    pub fn ensemble(&self) -> Option<&Ensemble> {
        match self {
            Self::Standalone(_) => None,
            Self::Ensemble(e) => Some(e),
        }
    }
}

/// Gives the children of `path` after a `sync`. A server of the
/// ensemble can lag behind the leader. The `sync` makes the read show
/// every write that the leader applied before it. A missing node gives
/// an empty list.
pub async fn synced_children(client: &Client, path: &str) -> Vec<String> {
    within(client.sync("/")).await.expect("sync");
    match within(client.get_children(path)).await {
        Ok(c) => c,
        Err(apache_zookeeper::Error::NoNode) => Vec::new(),
        Err(e) => panic!("list {path}: {e}"),
    }
}

/// The reply of the four-letter command `cmd` on `127.0.0.1:port`.
pub fn four_letter(port: u16, cmd: &str) -> Option<String> {
    use std::io::{Read, Write};
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(cmd.as_bytes()).ok()?;
    let mut text = String::new();
    s.read_to_string(&mut text).ok()?;
    Some(text)
}

/// The `Mode:` line of the `srvr` four-letter command on `port`:
/// `standalone`, `leader` or `follower`.
pub fn srvr_mode(port: u16) -> Option<String> {
    srvr_field(port, "Mode: ")
}

/// The release number of the server on `port`, from the `Zookeeper
/// version:` line of `srvr`. For `3.9.6-<hash>, built on ...` it gives
/// `3.9.6`.
pub fn srvr_version(port: u16) -> Option<String> {
    let line = srvr_field(port, "Zookeeper version: ")?;
    line.split(['-', ',', ' '])
        .next()
        .map(str::to_owned)
        .filter(|v| !v.is_empty())
}

/// The text after `prefix` on the first matching line of `srvr`.
fn srvr_field(port: u16, prefix: &str) -> Option<String> {
    four_letter(port, "srvr")?
        .lines()
        .find_map(|l| l.strip_prefix(prefix))
        .map(|m| m.trim().to_owned())
}

/// Waits until every server on `ports` that serves requests reports the
/// same last zxid (`srvr`), at most [`WAIT`]. Then a read on any of them
/// shows the writes that came before the call. A server that does not
/// serve requests does not count.
pub fn wait_caught_up(ports: &[u16]) {
    let deadline = Instant::now() + WAIT;
    loop {
        let zxids: Vec<String> = ports
            .iter()
            .filter_map(|&p| srvr_field(p, "Zxid: "))
            .collect();
        if zxids.first().is_some_and(|z| zxids.iter().all(|x| x == z)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the servers do not catch up: {zxids:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The path of a file below the `dev/` directory.
pub fn dev_file(name: &str) -> PathBuf {
    dev_dir().join(Path::new(name))
}

/// One [`Proxy`] in front of each server of a connect string. A client
/// of the group reaches every server, and each call acts on all the
/// proxies. The ensemble tests of the latch and the cache use it for a
/// reconnect.
pub struct ProxyGroup {
    proxies: Vec<Proxy>,
}

impl ProxyGroup {
    /// Starts one proxy for each port of `target_ports`.
    pub fn start(target_ports: &[u16]) -> Self {
        Self {
            proxies: target_ports.iter().map(|&p| Proxy::start(p)).collect(),
        }
    }

    /// The connect string of all the proxies.
    pub fn connect_string(&self) -> String {
        self.proxies
            .iter()
            .map(Proxy::connect_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Cuts every proxy.
    pub fn cut(&self) {
        self.proxies.iter().for_each(Proxy::cut);
    }

    /// Holds every proxy.
    pub fn hold(&self) {
        self.proxies.iter().for_each(Proxy::hold);
    }

    /// Restores every proxy.
    pub fn restore(&self) {
        self.proxies.iter().for_each(Proxy::restore);
    }

    /// Sets the delay of every proxy.
    pub fn delay(&self, d: Duration) {
        for p in &self.proxies {
            p.delay(d);
        }
    }
}
