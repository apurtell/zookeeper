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

//! Shared helpers of the zk-driver integration tests.
//!
//! - [`IpHost`]: host leaves that resolve IP literals with no DNS, and
//!   record the discarded tokens and the stored session identities.
//! - [`legacy_connection`] and [`native_connection`]: a proto connection
//!   for a fake server.
//! - [`env`]: driver services with `RustixPoll`, the monotonic clock and
//!   short close budgets.
//! - [`drain`]: takes every item of an outbox.
//! - [`fixture`]: the path of a TLS fixture in the test cache (see
//!   `zk_testkit::fixtures` and `fixtures/tls/gen.sh`).
//! - [`Collect`], [`TestSpawner`], [`SlowHost`] and the [`exists`]
//!   requests: the sink, the spawner, the host leaves and the requests
//!   that several driver tests share.
//! - With `tls`: [`tls::TlsAcceptor`], a rustls server for
//!   `zk_fakeserver::ServerOptions::acceptor`, and the native and
//!   legacy client connectors over `ca.pem`.
//!
//! A helper that only one test file uses stays in that file.

#![allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use zk_driver::native::{Spawn, ThreadBody};
use zk_driver::outbox::Item;
use zk_driver::{Discarded, DriverConfig, Env, HostLeaves, Outbox, RouteSink, Unlocked};
use zk_jute::JString;
use zk_proto::legacy::connect::parse_init;
use zk_proto::{
    ClientId, Compat, Config, Connection, DriverMode, HostResolution, HostSpec, InputDefect,
    LogLevel, LogSite, Millis, Op, PathIn, Request, ResolveError, Route,
};
use zk_testkit::hooks::{LevelFilter, SharedDefaultWatcher};
use zk_testkit::rng::SeededRng;
use zk_testkit::tokens::{CompletionId, TestTokens, WatcherId};

/// The wait budget of a test step.
pub const WAIT: Duration = Duration::from_secs(5);

/// The `getaddrinfo` rc of [`IpHost`] for a host that is not an IP
/// literal (`EAI_NONAME` on Linux).
pub const EAI_NONAME: i32 = -2;

/// Host leaves with no DNS.
#[derive(Debug, Default)]
pub struct IpHost {
    pub discarded: Mutex<Vec<&'static str>>,
    pub ids: Mutex<Vec<ClientId>>,
    pub level: Option<LogLevel>,
    pub permute_disabled: bool,
}

impl IpHost {
    /// Makes the leaves with Debug records and no shuffle.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            level: Some(LogLevel::Debug),
            permute_disabled: true,
            ..Self::default()
        })
    }

    pub fn discarded(&self) -> Vec<&'static str> {
        self.discarded.lock().unwrap().clone()
    }

    pub fn stored_ids(&self) -> Vec<ClientId> {
        self.ids.lock().unwrap().clone()
    }
}

impl HostLeaves<TestTokens> for IpHost {
    fn discard_token(&self, token: Discarded<TestTokens>) {
        let kind = match token {
            Discarded::Completion(_) => "completion",
            Discarded::Watcher(_) => "watcher",
            Discarded::Auth(_) => "auth",
        };
        self.discarded.lock().unwrap().push(kind);
    }

    fn snapshot_default_watcher(&self) -> Option<WatcherId> {
        None
    }

    fn store_client_id(&self, id: &ClientId) {
        self.ids.lock().unwrap().push(*id);
    }

    fn log_enabled(&self, level: LogLevel) -> bool {
        self.level.is_some_and(|m| level.code() <= m.code())
    }

    fn conn_permute_disabled(&self) -> bool {
        self.permute_disabled
    }

    fn rng_random(&self) -> i64 {
        7
    }

    fn rng_drand48(&self) -> f64 {
        0.5
    }

    fn rng_reseed(&self, _proof: &Unlocked) {}

    fn resolve(&self, _proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution {
        let port = match spec {
            HostSpec::Legacy(h) => u16::try_from(h.port).ok(),
            HostSpec::Native(h) => Some(h.port),
        };
        let ip = std::str::from_utf8(spec.host_bytes())
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok());
        let result = match (ip, port) {
            (Some(ip), Some(port)) => Ok(vec![SocketAddr::new(ip, port)]),
            _ => Err(ResolveError {
                gai_rc: EAI_NONAME,
                errno: 0,
            }),
        };
        HostResolution {
            host,
            result,
            skipped_families: Vec::new(),
        }
    }
}

/// Returns a legacy configuration for `hosts` with a 10 s timeout.
pub fn legacy_config(hosts: &str) -> Config {
    let cs = parse_init(hosts.as_bytes()).expect("valid connect string");
    let mut cfg = Config::legacy(10_000);
    cfg.hosts = cs.hosts.into_iter().map(HostSpec::Legacy).collect();
    cfg.host_text = JString::Bytes(cs.host_text);
    cfg.chroot = cs.chroot.map(JString::Bytes);
    cfg
}

/// Makes a drop-in connection (`Compat::LEGACY_C`) at time 0.
pub fn legacy_connection(hosts: &str, mode: DriverMode) -> Box<Connection<TestTokens>> {
    connection(legacy_config(hosts), Compat::LEGACY_C, mode)
}

/// Makes a native connection (`Compat::NATIVE`, `DriverMode::NATIVE`) at
/// time 0, with the native close timeout of 3 s.
pub fn native_connection(hosts: &str) -> Box<Connection<TestTokens>> {
    let mut cfg = legacy_config(hosts);
    // The native default `close_timeout`. With 0, a `Drain`
    // close ends at once with `ZOPERATIONTIMEOUT`.
    cfg.close_timeout_ms = 3_000;
    connection(cfg, Compat::NATIVE, DriverMode::NATIVE)
}

fn connection(cfg: Config, compat: Compat, mode: DriverMode) -> Box<Connection<TestTokens>> {
    Box::new(Connection::new(
        cfg,
        compat,
        mode,
        Box::new(SeededRng::new(1)),
        Box::new(LevelFilter::up_to(LogLevel::Debug)),
        Box::new(SharedDefaultWatcher::new(None)),
        Millis(0),
    ))
}

/// Makes driver services with short close budgets. `native` sets
/// CLOEXEC, as every native handle does.
pub fn env(host: Arc<IpHost>, native: bool) -> Env<TestTokens> {
    let leaves: Arc<dyn HostLeaves<TestTokens>> = host;
    let mut env = Env::new(leaves);
    env.cfg = DriverConfig {
        close_flush_ms: 200,
        close_wait_ms: 200,
        cloexec: native,
        ..DriverConfig::default()
    };
    env
}

/// Takes every item of `ob`, in order.
pub fn drain(ob: &mut Outbox<TestTokens>) -> Vec<Item<TestTokens>> {
    std::iter::from_fn(|| ob.pop()).collect()
}

/// Returns a short kind name per item, for order checks.
pub fn kinds(items: &[Item<TestTokens>]) -> Vec<&'static str> {
    items
        .iter()
        .map(|i| match i {
            Item::Log(_) => "log",
            Item::Result { .. } => "result",
            Item::AuthResult { .. } => "auth",
            Item::Watch { .. } => "watch",
            Item::Session { .. } => "session",
            Item::WatchTerminated { .. } => "terminated",
            Item::AuthLockpoint => "lockpoint",
            Item::Sasl(_) => "sasl",
            Item::Thread { .. } => "thread",
        })
        .collect()
}

/// Polls `pred` every 5 ms until it is true or `timeout` passes.
pub fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    pred()
}

/// Returns the path of a TLS fixture: `ca.pem`, `server.pem`,
/// `server.key`, `client.pem`, `client.key` or `wrong-ca.pem`.
pub fn fixture(name: &str) -> PathBuf {
    zk_testkit::fixtures::tls_dir().join(name)
}

/// Collects the routed items. Results and auth outcomes count.
#[derive(Default)]
pub struct Collect(pub Mutex<Vec<Item<TestTokens>>>);

impl RouteSink<TestTokens> for Collect {
    fn route(&self, item: Item<TestTokens>) -> bool {
        let counts = matches!(item, Item::Result { .. } | Item::AuthResult { .. });
        self.0.lock().unwrap().push(item);
        counts
    }
}

impl Collect {
    /// The number of routed results.
    pub fn results(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|i| matches!(i, Item::Result { .. }))
            .count()
    }

    /// The rc of the first routed result.
    pub fn result_rc(&self) -> Option<i32> {
        self.0.lock().unwrap().iter().find_map(|i| match i {
            Item::Result { result, .. } => Some(result.rc),
            _ => None,
        })
    }

    /// Tells if the sink got a log record of `site`.
    pub fn has_log(&self, site: LogSite) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|i| matches!(i, Item::Log(r) if r.site == site))
    }
}

/// A test spawner. The library itself starts threads only in
/// `spawn_std`.
pub struct TestSpawner;

impl Spawn for TestSpawner {
    fn spawn(&self, name: &'static str, body: ThreadBody) -> std::io::Result<()> {
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(body)
            .map(drop)
    }
}

/// An `exists` request of `path` with no watch.
pub fn exists_at(id: u64, path: PathIn) -> Request<TestTokens> {
    Request {
        op: Op::Exists { path, watch: None },
        token: CompletionId::new(id),
        route: Route::Queued,
        defect: InputDefect::default(),
    }
}

/// An `exists` request of the legacy root path.
pub fn exists(id: u64) -> Request<TestTokens> {
    exists_at(id, PathIn::Legacy(Some(b"/".to_vec())))
}

/// An `exists` request of the native root path.
pub fn exists_native(id: u64) -> Request<TestTokens> {
    exists_at(id, PathIn::Native("/".into()))
}

/// Host leaves whose resolve blocks for `slow_ms` once the test sets it.
/// It counts the resolve calls.
pub struct SlowHost {
    pub inner: Arc<IpHost>,
    pub slow_ms: AtomicU64,
    pub resolves: AtomicUsize,
}

impl HostLeaves<TestTokens> for SlowHost {
    fn discard_token(&self, token: Discarded<TestTokens>) {
        self.inner.discard_token(token);
    }

    fn snapshot_default_watcher(&self) -> Option<WatcherId> {
        self.inner.snapshot_default_watcher()
    }

    fn store_client_id(&self, id: &ClientId) {
        self.inner.store_client_id(id);
    }

    fn log_enabled(&self, level: LogLevel) -> bool {
        self.inner.log_enabled(level)
    }

    fn conn_permute_disabled(&self) -> bool {
        self.inner.conn_permute_disabled()
    }

    fn rng_random(&self) -> i64 {
        self.inner.rng_random()
    }

    fn rng_drand48(&self) -> f64 {
        self.inner.rng_drand48()
    }

    fn rng_reseed(&self, proof: &Unlocked) {
        self.inner.rng_reseed(proof);
    }

    fn resolve(&self, proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        let ms = self.slow_ms.load(Ordering::SeqCst);
        if ms > 0 {
            std::thread::sleep(Duration::from_millis(ms));
        }
        self.inner.resolve(proof, host, spec)
    }
}

/// A rustls server for the fake server (feature `tls`).
#[cfg(feature = "tls")]
pub mod tls {
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    use zk_driver::Unlocked;
    use zk_driver::net::tls::verify::webpki_verifier;
    use zk_driver::net::tls::{
        LegacyPath, LegacyTlsArgs, NativeConfig, RustlsConnector, TlsConnector, TlsPurpose,
        TlsSetupError,
    };
    use zk_fakeserver::{Acceptor, Transport};
    use zk_proto::compat::TlsVerify;

    use super::fixture;

    /// The crypto provider of the build.
    pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        #[cfg(feature = "tls-ring")]
        let p = rustls::crypto::ring::default_provider();
        #[cfg(all(not(feature = "tls-ring"), feature = "tls-aws-lc-rs-fips"))]
        let p = rustls::crypto::default_fips_provider();
        #[cfg(all(
            not(feature = "tls-ring"),
            not(feature = "tls-aws-lc-rs-fips"),
            feature = "tls-aws-lc-rs"
        ))]
        let p = rustls::crypto::aws_lc_rs::default_provider();
        Arc::new(p)
    }

    /// Reads every certificate of a PEM fixture.
    pub fn certs(name: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(fixture(name))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Reads the private key of a PEM fixture.
    pub fn key(name: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_file(fixture(name)).unwrap()
    }

    /// The legacy path of a fixture.
    #[cfg(unix)]
    pub fn legacy_path(name: &str) -> LegacyPath {
        use std::os::unix::ffi::OsStrExt;
        LegacyPath::new(fixture(name).as_os_str().as_bytes().to_vec())
    }

    /// The native configuration source: one fixed client configuration.
    #[derive(Debug)]
    pub struct Native(pub Arc<rustls::ClientConfig>);

    impl NativeConfig for Native {
        fn client_config(
            &self,
            _proof: &Unlocked,
            _purpose: TlsPurpose,
        ) -> Result<Arc<rustls::ClientConfig>, TlsSetupError> {
            Ok(Arc::clone(&self.0))
        }
    }

    /// Makes the native connector with the WebPki verifier and `ca.pem`.
    pub fn native_connector() -> Arc<dyn TlsConnector> {
        let mut roots = RootCertStore::empty();
        for c in certs("ca.pem") {
            roots.add(c).unwrap();
        }
        let verifier = webpki_verifier(Arc::new(roots), provider()).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Arc::new(RustlsConnector::native(
            Arc::new(Native(Arc::new(cfg))),
            provider(),
        ))
    }

    /// Makes the drop-in connector with `ca.pem` and LegacyChainOnly.
    #[cfg(unix)]
    pub fn legacy_connector() -> Arc<dyn TlsConnector> {
        let args = LegacyTlsArgs {
            ca: Some(legacy_path("ca.pem")),
            cert: None,
            key: None,
            passwd: None,
            env_allowed: false,
            verify: TlsVerify::LegacyChainOnly,
        };
        Arc::new(RustlsConnector::legacy(args, provider()))
    }

    /// The server side of one TLS connection.
    pub struct TlsStream(StreamOwned<ServerConnection, TcpStream>);

    impl Read for TlsStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for TlsStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl Transport for TlsStream {
        fn tcp(&self) -> &TcpStream {
            &self.0.sock
        }
    }

    /// A TLS acceptor with `server.pem`. With `client_auth`, it asks for
    /// a client certificate from `ca.pem` and rejects a missing one.
    #[derive(Debug)]
    pub struct TlsAcceptor {
        config: Arc<ServerConfig>,
    }

    impl TlsAcceptor {
        pub fn new(client_auth: bool) -> Arc<Self> {
            let builder = ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap();
            let builder = if client_auth {
                let mut roots = RootCertStore::empty();
                for c in certs("ca.pem") {
                    roots.add(c).unwrap();
                }
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                        .build()
                        .unwrap();
                builder.with_client_cert_verifier(verifier)
            } else {
                builder.with_no_client_auth()
            };
            let config = builder
                .with_single_cert(certs("server.pem"), key("server.key"))
                .unwrap();
            Arc::new(Self {
                config: Arc::new(config),
            })
        }
    }

    impl Acceptor for TlsAcceptor {
        // The rustls handshake state is large in debug builds. The
        // fake-server threads have the default stack, so the frame is safe.
        #[allow(clippy::large_stack_frames)]
        fn accept(&self, tcp: TcpStream) -> io::Result<Box<dyn Transport>> {
            let conn = ServerConnection::new(Arc::clone(&self.config)).map_err(io::Error::other)?;
            // The stream is on the heap because the rustls state is large.
            let mut s = Box::new(TlsStream(StreamOwned::new(conn, tcp)));
            // Finish the handshake here, so the server loop sees only
            // application data. The fake server sets a short read
            // timeout. A timeout is not a failure until the deadline,
            // because the client verifier can be slow with many roots.
            let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while s.0.conn.is_handshaking() {
                let TlsStream(inner) = &mut *s;
                match inner.conn.complete_io(&mut inner.sock) {
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) && std::time::Instant::now() < end => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(s)
        }
    }
}
