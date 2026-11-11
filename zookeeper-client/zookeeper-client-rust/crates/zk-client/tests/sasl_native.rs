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

//! Native DIGEST-MD5 beyond `sasl_fake.rs`: the password source on each
//! authentication, a real server, and the zeroization of the password.
//!
//! The real-server tests have `#[ignore]` and take their ports from
//! `common::real_port`. Run them with `ZK_TEST_PORT_BASE=<base> cargo
//! test --features sasl --test sasl_native -- --ignored`. The server
//! gets a JAAS `Server` section and the SASL provider through
//! `ZK_TEST_SERVER_JVM_OPTS`. The zeroization test also needs the free
//! scanner, so `tests/free_scan/free_scan.sh` runs it.

#![cfg(feature = "sasl")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use apache_zookeeper::acl::CREATOR_ALL_ACL;
use apache_zookeeper::{
    Client, CreateMode, CredentialError, CredentialSource, Error, SaslConfig, SecretString,
    SessionState,
};
use common::{RealServer, Rt, WAIT, all_rts, real_port, within};
use zk_fakeserver::FrameKind;
use zk_jute::opcode;

/// The SASL user of the tests.
const USER: &str = "bob";

/// The password of [`USER`]. It is also the marker of the free scanner
/// (`free_scan.sh`), so no test copies it into a plain heap buffer.
const PASSWORD: &str = "zk-sasl-native-4c1e9b";

/// The new password after a rotation.
const ROTATED: &str = "zk-sasl-native-rotated";

/// A password source that counts its calls. The first call gives the
/// first password, and each later call gives the last password.
struct Counting {
    calls: AtomicUsize,
    passwords: &'static [&'static str],
}

impl Counting {
    fn new(passwords: &'static [&'static str]) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            passwords,
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialSource for Counting {
    fn password(&self) -> Result<SecretString, CredentialError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let p = self
            .passwords
            .get(n)
            .or_else(|| self.passwords.last())
            .ok_or(CredentialError::Permanent)?;
        Ok(SecretString::from(*p))
    }
}

/// The number of SASL requests in the transcript of `fs`.
fn sasl_requests(fs: &zk_fakeserver::FakeServer) -> usize {
    fs.transcript()
        .into_iter()
        .filter(|r| r.kind == FrameKind::Request && r.op == Some(opcode::SASL))
        .count()
}

/// Rule: the client reads the password source on each authentication,
/// so a rotated password applies at the next connection. A reconnect
/// runs a new DIGEST-MD5 exchange with the new password.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_password_source_runs_on_each_authentication() {
    for rt in all_rts() {
        let fs = common::fake();
        fs.set_sasl_digest(USER, PASSWORD);
        let src = Counting::new(&[PASSWORD, ROTATED]);
        let cfg = SaslConfig::digest_md5(USER, src.clone());
        let c = within(
            rt.apply(common::builder(&fs.connect_string()))
                .sasl(cfg)
                .connect(),
        )
        .await
        .unwrap_or_else(|e| panic!("{rt:?}: {e:?}"));
        assert_eq!(src.calls(), 1, "{rt:?}");
        assert_eq!(sasl_requests(&fs), 2, "{rt:?}");

        // The server takes only the new password from now on.
        fs.set_sasl_digest(USER, ROTATED);
        let mut w = c.state_watcher();
        fs.drop_connections();
        let back = common::wait_state(&mut w, WAIT, |i| {
            i.state == SessionState::Connected && i.epoch >= 2
        })
        .await;
        assert!(back.state == SessionState::Connected, "{rt:?}: {back:?}");
        assert_eq!(src.calls(), 2, "{rt:?}");
        assert_eq!(sasl_requests(&fs), 4, "{rt:?}");
        assert!(within(c.exists("/")).await.unwrap().is_some(), "{rt:?}");
        within(c.close()).await.unwrap();
    }
}

/// A real server with a JAAS `Server` section that accepts [`USER`] with
/// [`PASSWORD`]. The drop stops the server.
fn sasl_server(offset: u16) -> Option<RealServer> {
    let port = real_port(offset)?;
    let dir = common::default_server_dir(port);
    // A rerun starts from an empty tree. On a first run the directory
    // does not exist, and the helper ignores that error.
    let _ = std::fs::remove_dir_all(dir.join("data"));
    std::fs::create_dir_all(&dir).unwrap();
    let jaas = dir.join("jaas.conf");
    write_jaas(&jaas).unwrap();
    // The server checks DIGEST-MD5 only with the FIPS mode off.
    let jvm = format!(
        "-Djava.security.auth.login.config={} \
         -Dzookeeper.authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider \
         -Dzookeeper.fips-mode=false",
        jaas.display()
    );
    match RealServer::start_with(port, None, "", &jvm) {
        Ok(s) => Some(s),
        Err(e) => common::skip("no real ZooKeeper server", &e),
    }
}

/// Writes the JAAS file. Each part goes to the file directly, so the
/// password is not copied into a heap buffer that the scanner sees.
fn write_jaas(path: &PathBuf) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(
        b"Server {\n    org.apache.zookeeper.server.auth.DigestLoginModule required\n    user_",
    )?;
    f.write_all(USER.as_bytes())?;
    f.write_all(b"=\"")?;
    f.write_all(PASSWORD.as_bytes())?;
    f.write_all(b"\";\n};\n")?;
    f.sync_all()
}

/// Connects to `cs` as [`USER`] with the password of `src`.
async fn sasl_client(rt: Rt, cs: &str, src: Arc<Counting>) -> Result<Client, Error> {
    let cfg = SaslConfig::digest_md5(USER, src);
    within(rt.apply(common::builder(cs)).sasl(cfg).connect())
        .await
        .map_err(|e| e.error().clone())
}

/// Authenticates on every driver, creates a node with the creator ACL,
/// and checks the `sasl` identity of the session.
async fn authenticate_and_use(cs: &str, root: &str) {
    for rt in all_rts() {
        let src = Counting::new(&[PASSWORD]);
        let c = sasl_client(rt, cs, src.clone())
            .await
            .unwrap_or_else(|e| panic!("{rt:?}: {e:?}"));
        assert_eq!(src.calls(), 1, "{rt:?}");
        let ids = within(c.who_am_i()).await.unwrap();
        assert!(
            ids.iter()
                .any(|i| i.auth_scheme == "sasl" && i.user == USER),
            "{rt:?}: {ids:?}"
        );
        let path = format!("{root}-{}", rt.name());
        within(c.create(&*path, b"s", CreateMode::Persistent, CREATOR_ALL_ACL))
            .await
            .unwrap();
        let (acl, _) = within(c.get_acl(&*path)).await.unwrap();
        assert!(
            acl.iter().any(|a| a.id.scheme == "sasl" && a.id.id == USER),
            "{rt:?}: {acl:?}"
        );
        within(c.close()).await.unwrap();
    }
}

/// Rule: native DIGEST-MD5 authenticates with the Java server. The
/// session has the `sasl` identity, and the creator ACL holds it. A
/// wrong password ends the connect with `AuthFailed` (ZooKeeper
/// Programmer's Guide "Built In ACL Schemes").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn real_digest_md5_authenticates() {
    let Some(srv) = sasl_server(7) else {
        return;
    };
    let cs = srv.connect_string();
    authenticate_and_use(&cs, "/sasl").await;
    for rt in all_rts() {
        let src = Counting::new(&["wrong"]);
        let r = sasl_client(rt, &cs, src.clone()).await;
        assert_eq!(r.err(), Some(Error::AuthFailed), "{rt:?}");
        assert_eq!(src.calls(), 1, "{rt:?}");
    }
}

/// The number of hit lines in the scanner output.
fn scan_hits(out: &std::path::Path) -> usize {
    std::fs::read_to_string(out)
        .map(|s| s.lines().filter(|l| l.starts_with("hit ")).count())
        .unwrap_or(0)
}

/// Rule: no freed heap block holds the password after a native
/// DIGEST-MD5 session. The free scanner reports each freed block that
/// holds the marker. A control buffer shows that the scanner runs.
/// Copies on the stack are out of scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "free-scan"]
async fn secrets_are_zero_before_free() {
    let Some(out) = std::env::var_os("ZK_FREE_SCAN_OUT").map(PathBuf::from) else {
        eprintln!("skip: run tests/free_scan/free_scan.sh");
        return;
    };
    drop(std::hint::black_box(String::from(PASSWORD)));
    let control = scan_hits(&out);
    assert!(control >= 1, "the free scanner does not run");

    let Some(srv) = sasl_server(8) else {
        return;
    };
    authenticate_and_use(&srv.connect_string(), "/scan").await;
    drop(srv);
    assert_eq!(
        scan_hits(&out),
        control,
        "a freed block holds the password (see {})",
        out.display()
    );
}
