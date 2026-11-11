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

//! API contract tests of TLS through `tls-rustls` against the TLS
//! acceptor of the fake server: the `WebPki` default, trust failures,
//! mutual TLS, the builder checks, the TLS rows of the teardown table,
//! and the environment rule of `add_system_roots`. `tls_fake.rs` covers
//! the reload cache, the server-name options and `legacy_c_compat`.
//!
//! The fixtures come from `zk_testkit::fixtures::tls_dir`. It makes them at
//! test time with the `gen.sh` scripts of `crates/zk-driver/tests/fixtures/tls`.
//! Each test names its rule and the source: "spec" is
//! `design/specification.md`.

#![cfg(feature = "tls-rustls")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use apache_zookeeper::{
    Client, ClientBuilder, DisconnectCause, Error, SessionState, StateWatcher, TlsConfigError,
    TlsOptions,
};
use zk_fakeserver::{ClusterConfig, FakeServer, ServerOptions, TlsAcceptor};

use common::{ca_only, fixture, within};

/// Starts a TLS fake server with the `leaf` fixture. With `client_auth`
/// the server requires a client certificate from the test CA.
fn tls_server(leaf: &str, client_auth: bool) -> (FakeServer, Arc<TlsAcceptor>) {
    let mut b = TlsAcceptor::builder(zk_driver::net::tls::default_provider())
        .cert_chain_pem_file(fixture(&format!("{leaf}.pem")))
        .unwrap()
        .key_pem_file(fixture(&format!("{leaf}.key")))
        .unwrap();
    if client_auth {
        b = b.client_auth_ca_pem_file(fixture("ca.pem")).unwrap();
    }
    let acc = b.build().unwrap();
    let opts = ServerOptions::default().with_acceptor(Arc::clone(&acc) as _);
    let server = FakeServer::start_with(ClusterConfig::default(), opts).unwrap();
    (server, acc)
}

/// A client builder for `cs` with TLS options `tls`.
fn tls_builder(cs: &str, tls: TlsOptions) -> ClientBuilder {
    common::builder(cs).tls(tls)
}

/// Waits until `last_error` matches `pred`, and returns its text.
async fn wait_error(
    w: &StateWatcher,
    mut pred: impl FnMut(&(dyn std::error::Error + Send + Sync + 'static)) -> bool,
) -> String {
    within(async {
        loop {
            if let Some(e) = w.last_error() {
                if pred(e.as_ref()) {
                    return e.to_string();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
}

/// True for the `io::Error` that a TLS failure gives in `last_error`.
fn is_tls_io(e: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    e.downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::InvalidData)
}

/// Rule: the native default verifier is `WebPki`. A server whose chain
/// leads to the CA file and whose IP SAN matches the IP literal of the
/// connect string connects, and the session works (spec "Native
/// Security Configuration").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webpki_accepts_a_good_server_by_its_ip_literal() {
    let (fs, acc) = tls_server("server", false);
    let c: Client = within(tls_builder(&fs.connect_string(), ca_only()).connect())
        .await
        .unwrap();
    assert!(within(c.exists("/")).await.unwrap().is_some());
    assert!(c.state().last_error.is_none());
    within(c.close()).await.unwrap();
    assert_eq!(
        acc.sessions().first().and_then(|s| s.handshake.clone()),
        Some(Ok(()))
    );
}

/// Rule: the default verifier checks the name. A server for another
/// name never connects, and `last_error` names a TLS failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webpki_rejects_another_name() {
    let (fs, _acc) = tls_server("other-name", false);
    let f = tls_builder(&fs.connect_string(), ca_only()).connect();
    let w = f.state_watcher();
    let mut f = Box::pin(f);
    wait_error(&w, is_tls_io).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut f)
            .await
            .is_err()
    );
    assert_eq!(w.current().state, SessionState::Connecting);
}

/// Rule: a chain from an untrusted CA and an expired leaf fail the
/// handshake. The client keeps trying, and `last_error` names the TLS
/// failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_ca_and_an_expired_leaf_fail_the_handshake() {
    for leaf in ["wrong-server", "expired"] {
        let (fs, acc) = tls_server(leaf, false);
        let f = tls_builder(&fs.connect_string(), ca_only()).connect();
        let w = f.state_watcher();
        wait_error(&w, is_tls_io).await;
        // The client tries again after a failed handshake.
        let t0 = Instant::now();
        while acc.sessions().len() < 2 {
            assert!(t0.elapsed() < common::WAIT, "{leaf}: no second attempt");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            acc.sessions()
                .iter()
                .all(|s| !matches!(s.handshake, Some(Ok(())))),
            "{leaf}"
        );
        drop(f);
    }
}

/// Rule: a handshake failure tears the connection down, and the
/// requests that wait fail with `ConnectionLoss`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_handshake_fails_the_waiting_request() {
    let (fs, _acc) = tls_server("wrong-server", false);
    let c = tls_builder(&fs.connect_string(), ca_only())
        .build()
        .unwrap();
    let f = c.get_data("/");
    assert_eq!(within(f).await, Err(Error::ConnectionLoss));
    wait_error(&c.state_watcher(), is_tls_io).await;
    let _ = within(c.close()).await;
}

/// Rule: a server that asks for a client certificate refuses a client
/// with no identity, and accepts a client with the identity of the test
/// CA (spec "Native Security Configuration").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutual_tls_needs_the_client_identity() {
    let (fs, acc) = tls_server("server", true);
    let f = tls_builder(&fs.connect_string(), ca_only()).connect();
    let w = f.state_watcher();
    let mut f = Box::pin(f);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut f)
            .await
            .is_err()
    );
    assert!(
        w.last_error().is_some(),
        "a refused handshake sets last_error"
    );
    drop(f);
    assert!(acc.sessions().iter().all(|s| !s.client_cert));

    let id = TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .client_identity(fixture("client.pem"), fixture("client.key"), None)
        .build()
        .unwrap();
    let c = within(tls_builder(&fs.connect_string(), id).connect())
        .await
        .unwrap();
    assert!(within(c.exists("/")).await.unwrap().is_some());
    within(c.close()).await.unwrap();
    assert!(acc.sessions().iter().any(|s| s.client_cert));
}

/// A temporary file or directory. Drop removes it.
struct Temp(PathBuf);

impl Temp {
    fn path(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("zk-api-tls-{}-{tag}-{n}", std::process::id()))
    }

    fn file(body: &[u8]) -> Self {
        let p = Self::path("f");
        std::fs::write(&p, body).unwrap();
        Self(p)
    }

    fn dir() -> Self {
        let p = Self::path("d");
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Rule: `build` reads and checks every file at the call, and each
/// failed check has its own `TlsConfigError` with the path.
#[test]
fn build_reports_each_file_error() {
    let missing = fixture("no-such.pem");
    let garbage =
        Temp::file(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n");
    let empty = Temp::file(b"");

    for ca in [&missing, &garbage.0, &empty.0] {
        let e = TlsOptions::builder().ca_file(ca).build().unwrap_err();
        assert!(
            matches!(&e, TlsConfigError::CaFile(p) if p == ca),
            "{ca:?}: {e:?}"
        );
        assert!(e.to_string().contains(&*ca.to_string_lossy()), "{e}");
    }

    let e = TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .client_identity(&missing, fixture("client.key"), None)
        .build()
        .unwrap_err();
    assert!(
        matches!(&e, TlsConfigError::CertChain(p) if *p == missing),
        "{e:?}"
    );

    let e = TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .client_identity(fixture("client.pem"), &missing, None)
        .build()
        .unwrap_err();
    assert!(
        matches!(&e, TlsConfigError::PrivateKey(p) if *p == missing),
        "{e:?}"
    );

    // A key of the same type that belongs to another certificate fails at
    // the key step, as `SSL_CTX_use_PrivateKey_file` does.
    let other = fixture("server.key");
    let e = TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .client_identity(fixture("client.pem"), &other, None)
        .build()
        .unwrap_err();
    assert!(
        matches!(&e, TlsConfigError::PrivateKey(p) if *p == other),
        "{e:?}"
    );

    // A chain file with no certificate cannot be a chain.
    let e = TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .client_identity(&empty.0, fixture("client.key"), None)
        .build()
        .unwrap_err();
    assert!(matches!(&e, TlsConfigError::CertChain(_)), "{e:?}");
}

/// Rule: the platform verifier cannot mix with another trust decision.
#[cfg(feature = "tls-platform-verifier")]
#[test]
fn the_platform_verifier_refuses_another_trust_source() {
    let builders = [
        TlsOptions::builder().ca_file(fixture("ca.pem")),
        TlsOptions::builder().add_system_roots(),
        TlsOptions::builder().danger_disable_hostname_verification(),
    ];
    for b in builders {
        let e = b.with_platform_verifier().build().unwrap_err();
        assert!(matches!(e, TlsConfigError::PlatformVerifier(_)), "{e:?}");
    }
}

/// Rule: the platform verifier uses the OS trust store and the OS
/// policy. The test CA is not in that store, so the test server never
/// connects, and `last_error` names a TLS failure. A host with no OS
/// trust store refuses the verifier at `build` with a text.
#[cfg(feature = "tls-platform-verifier")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_platform_verifier_does_not_trust_the_test_ca() {
    let tls = match TlsOptions::builder().with_platform_verifier().build() {
        Ok(tls) => tls,
        Err(TlsConfigError::PlatformVerifier(text)) => {
            assert!(!text.is_empty());
            return;
        }
        Err(e) => panic!("{e:?}"),
    };
    let (fs, acc) = tls_server("server", false);
    let f = tls_builder(&fs.connect_string(), tls).connect();
    let w = f.state_watcher();
    wait_error(&w, is_tls_io).await;
    drop(f);
    assert!(
        acc.sessions()
            .iter()
            .all(|s| !matches!(s.handshake, Some(Ok(()))))
    );
}

/// A TCP listener that accepts and then sends the header of a TLS
/// record of 16 KiB, then one byte of its body every 100 ms. The
/// handshake never completes, but bytes keep arriving.
struct Dribbler {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Dribbler {
    fn start(silent: bool) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut conns = Vec::new();
            while !s.load(Ordering::SeqCst) {
                if let Ok((c, _)) = l.accept() {
                    let _ = c.set_nonblocking(false);
                    conns.push(c);
                    if !silent {
                        if let Some(c) = conns.last_mut() {
                            let _ = c.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]);
                        }
                    }
                }
                if !silent {
                    for c in &mut conns {
                        let _ = c.write_all(&[0]);
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self { addr, stop }
    }
}

impl Drop for Dribbler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Rule: the handshake has a 2/3·T deadline from the TCP connect, so a
/// stuck handshake ends at about 2/3·T. The receive rule also applies in
/// the handshake phase, and it has the same bound from an earlier start.
/// It fires first, so `last_error` is `ReceiveTimeout` for a silent
/// server and for a server that sends bytes but never ends the handshake.
/// Thus the `TlsHandshakeTimeout` cause does not occur here (spec
/// "Session establishment and states").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stuck_handshake_ends_at_two_thirds_of_the_timeout() {
    for silent in [false, true] {
        let d = Dribbler::start(silent);
        let c = common::builder(&d.addr.to_string())
            .session_timeout(Duration::from_millis(1_500))
            .tls(ca_only())
            .build()
            .unwrap();
        let w = c.state_watcher();
        let t0 = Instant::now();
        let text = wait_error(&w, |e| e.downcast_ref::<DisconnectCause>().is_some()).await;
        let took = t0.elapsed();
        let cause = w
            .last_error()
            .and_then(|e| e.downcast_ref::<DisconnectCause>().copied());
        assert!(
            matches!(
                cause,
                Some(DisconnectCause::ReceiveTimeout | DisconnectCause::TlsHandshakeTimeout)
            ),
            "silent {silent}: {text}"
        );
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_millis(3_000),
            "silent {silent}: the deadline came after {took:?}"
        );
        let _ = within(c.close()).await;
    }
}

/// The variable that makes a test run its child part.
const CHILD: &str = "ZK_API_TLS_ENV_CHILD";

/// Runs the test `name` of this binary in a child process with `env`.
/// The child sees `CHILD`, so it runs its child part. It returns true
/// when the child test passed.
fn run_child(name: &str, env: &[(&str, &std::ffi::OsStr)]) -> bool {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env(CHILD, "1")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    out.status.success() && text.contains("1 passed")
}

/// Rule: `add_system_roots` reads `SSL_CERT_FILE` and `SSL_CERT_DIR`
/// when the process is not set-uid or set-gid. A file with the test CA
/// then trusts the test server with no `ca_file` (spec "Trust store
/// ingestion and path evaluation").
///
/// The test runs in a child process, because the test cannot set the
/// variables in its own process with no `unsafe`. The set-uid case
/// needs a set-uid binary, so no test covers it.
#[test]
fn ssl_cert_file_feeds_the_system_roots() {
    if std::env::var_os(CHILD).is_some() {
        let tls = TlsOptions::builder().add_system_roots().build().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (fs, _acc) = tls_server("server", false);
            let c = within(tls_builder(&fs.connect_string(), tls).connect())
                .await
                .unwrap();
            within(c.close()).await.unwrap();
        });
        return;
    }
    let empty_dir = Temp::dir();
    assert!(run_child(
        "ssl_cert_file_feeds_the_system_roots",
        &[
            ("SSL_CERT_FILE", fixture("ca.pem").as_os_str()),
            ("SSL_CERT_DIR", empty_dir.0.as_os_str()),
        ],
    ));
}

/// Rule: with `add_system_roots`, `build` reports `DefaultRoots` when the
/// default locations give no usable root. A set `SSL_CERT_FILE` replaces
/// the compile-time default, even when its target is empty.
#[test]
fn empty_default_locations_give_default_roots() {
    if std::env::var_os(CHILD).is_some() {
        let e = TlsOptions::builder()
            .add_system_roots()
            .build()
            .unwrap_err();
        assert!(matches!(e, TlsConfigError::DefaultRoots), "{e:?}");
        // A CA file does not hide the empty system roots: the user asked
        // for them and must learn that there are none.
        let e = TlsOptions::builder()
            .ca_file(fixture("ca.pem"))
            .add_system_roots()
            .build()
            .unwrap_err();
        assert!(matches!(e, TlsConfigError::DefaultRoots), "{e:?}");
        return;
    }
    let empty = Temp::file(b"");
    let empty_dir = Temp::dir();
    assert!(run_child(
        "empty_default_locations_give_default_roots",
        &[
            ("SSL_CERT_FILE", empty.0.as_os_str()),
            ("SSL_CERT_DIR", empty_dir.0.as_os_str()),
        ],
    ));
}
