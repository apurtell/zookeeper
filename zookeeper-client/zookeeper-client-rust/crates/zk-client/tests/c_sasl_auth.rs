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

//! Parity with the C suite `TestSASLAuth.cc` (`Zookeeper_SASLAuth`).
//!
//! Each C case starts a server that needs SASL for each session
//! (`sessionRequireClientSASLAuth`), with a JAAS `Server` section that
//! accepts `myuser` with `mypassword`. Each test here starts the same
//! server through `dev/test-server.sh` and uses native DIGEST-MD5 with
//! the service `zookeeper` and the server name `zk-sasl-md5`. Each case
//! runs once with the IO thread and once with a tokio task.
//!
//! The server uses the port at offset 1 of `ZK_TEST_PORT_BASE`. The
//! read-only case also uses the quorum ports at offsets 3 to 8. The
//! tests share these ports, so a lock runs them one after the other.
//! The tests have `#[ignore = "real-server"]`. Run them with
//! `ZK_TEST_PORT_BASE=<base> cargo test --features sasl --test
//! c_sasl_auth -- --ignored`. Without `sasl`, only the case with no
//! client SASL runs.

// A scenario is one long async body. It runs on a 2 MiB test or worker
// thread, so the stack frame limit of the library does not apply.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{ClientBuilder, CreateMode, Error};
use common::{RealServer, Rt, real_port};

/// The tests use the same ports, so they run one at a time.
static PORTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The port offset of the client port.
const OFFSET: u16 = 1;

/// The wait budget of a connect, and of a reconnect after a restart.
const SLOW: Duration = Duration::from_secs(20);

/// The session timeout of the C suite.
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// The JAAS file of the C suite.
const JAAS: &str = "Server {\n  org.apache.zookeeper.server.auth.DigestLoginModule required\n    user_myuser=\"mypassword\";\n};\n";

/// Runs `scenario` once per driver. The lock keeps the ports free for
/// one test at a time.
macro_rules! sasl_test {
    ($name:ident) => {
        mod $name {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore = "real-server"]
            async fn thread() {
                let _lock = PORTS.lock().await;
                super::$name(Rt::Thread).await;
            }

            #[cfg(all(unix, feature = "tokio"))]
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore = "real-server"]
            async fn tokio() {
                let _lock = PORTS.lock().await;
                super::$name(Rt::Tokio).await;
            }
        }
    };
}

/// A new server directory for `port`, with `data/myid` = 1.
fn server_dir(port: u16) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zk-rust-c-sasl-{port}"));
    // On a first run the directory does not exist.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data").join("myid"), "1\n").unwrap();
    dir
}

/// The JVM options of C `zkServer.sh startRequireSASLAuth`.
fn jvm_opts(jaas: Option<&Path>, read_only: bool) -> String {
    let mut opts = String::from(
        "-Dzookeeper.sessionRequireClientSASLAuth=true \
         -Dzookeeper.authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider \
         -Dzookeeper.fips-mode=false",
    );
    if let Some(j) = jaas {
        opts.push_str(&format!(
            " -Djava.security.auth.login.config={}",
            j.display()
        ));
    }
    if read_only {
        opts.push_str(" -Dreadonlymode.enabled=true");
    }
    opts
}

/// Starts the server of the C suite (C `startServer`). With `jaas`, the
/// server accepts `myuser`. With `read_only`, the server is node 1 of
/// three, and the other two never start, so the server has no quorum.
/// It gives `None` and a note to skip.
fn start_server(jaas: bool, read_only: bool) -> Option<RealServer> {
    let port = real_port(OFFSET)?;
    let dir = server_dir(port);
    let jaas_file = dir.join("jaas.conf");
    std::fs::write(&jaas_file, JAAS).unwrap();
    let props = if read_only {
        let mut p = String::from("localSessionsEnabled=true\ninitLimit=5\nsyncLimit=2\n");
        for n in 1..=3_u16 {
            let q = real_port(OFFSET + 2 * n)?;
            let e = real_port(OFFSET + 2 * n + 1)?;
            p.push_str(&format!("server.{n}=127.0.0.1:{q}:{e}\n"));
        }
        p
    } else {
        String::new()
    };
    let jvm = jvm_opts(jaas.then_some(jaas_file.as_path()), read_only);
    match RealServer::start_with(port, Some(dir), &props, &jvm) {
        Ok(s) => Some(s),
        Err(e) => common::skip("no real ZooKeeper server", &e),
    }
}

/// A builder for `cs` with the session timeout of the C suite.
fn builder(rt: Rt, cs: &str) -> ClientBuilder {
    rt.apply(common::builder(cs).session_timeout(SESSION_TIMEOUT))
}

sasl_test!(server_require_client_sasl);
/// `Zookeeper_SASLAuth::testServerRequireClientSASL`: a server that
/// needs SASL accepts the connection of a client with no SASL. Its
/// first write then fails with `SessionClosedRequireSaslAuth`.
async fn server_require_client_sasl(rt: Rt) {
    let Some(server) = start_server(false, false) else {
        return;
    };
    let c = tokio::time::timeout(SLOW, builder(rt, &server.connect_string()).connect())
        .await
        .expect("timed out")
        .expect("connect");
    let r = common::within(c.create(
        "/serverRequireClientSASL",
        b"",
        CreateMode::Persistent,
        OPEN_ACL_UNSAFE,
    ))
    .await;
    assert_eq!(r.unwrap_err(), Error::SessionClosedRequireSaslAuth);
    let _ = common::within(c.close()).await;
}

#[cfg(feature = "sasl")]
use sasl::*;

/// The cases with client SASL. They need the `sasl` feature.
#[cfg(feature = "sasl")]
mod sasl {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use apache_zookeeper::{
        Client, CredentialError, CredentialSource, SaslConfig, SecretString, SessionState,
    };

    use super::*;

    /// The SASL user of the C suite.
    pub(super) const USER: &str = "myuser";

    /// The password of [`USER`].
    pub(super) const PASSWORD: &str = "mypassword";

    /// A fixed password, as the C password file `mypassword` gives it.
    pub(super) struct Fixed;

    impl CredentialSource for Fixed {
        fn password(&self) -> Result<SecretString, CredentialError> {
            Ok(SecretString::from(PASSWORD))
        }
    }

    /// A password that the application decrypts from a file on each
    /// authentication. The decryption adds `incr` to each byte, as the
    /// C callbacks `textPasswordCallback` and `binaryPasswordCallback`
    /// do.
    pub(super) struct Decrypting {
        pub(super) file: PathBuf,
        pub(super) incr: u8,
        pub(super) calls: AtomicUsize,
    }

    impl CredentialSource for Decrypting {
        fn password(&self) -> Result<SecretString, CredentialError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let content = std::fs::read(&self.file).map_err(|_| CredentialError::Transient)?;
            let plain: Vec<u8> = content.iter().map(|b| b.wrapping_add(self.incr)).collect();
            String::from_utf8(plain)
                .map(SecretString::from)
                .map_err(|_| CredentialError::Permanent)
        }
    }

    /// A DIGEST-MD5 builder for `cs` with the service `zookeeper` and the
    /// server name `zk-sasl-md5`, as the C suite sets them.
    pub(super) fn sasl_builder(rt: Rt, cs: &str, src: Arc<dyn CredentialSource>) -> ClientBuilder {
        builder(rt, cs).sasl(SaslConfig::digest_md5(USER, src))
    }

    /// Connects with SASL, or fails the test.
    pub(super) async fn sasl_connect(b: ClientBuilder) -> Client {
        tokio::time::timeout(SLOW, b.connect())
            .await
            .expect("timed out")
            .unwrap_or_else(|e| panic!("connect: {e:?}"))
    }

    /// The body of C `testClientSASLHelper`: connect with SASL and leave
    /// a mark. Then stop and start the server again, wait for the
    /// automatic reconnect and the new authentication, and find the
    /// mark.
    pub(super) async fn sasl_helper(
        server: &RealServer,
        rt: Rt,
        cs: &str,
        path: &str,
        src: Arc<dyn CredentialSource>,
    ) {
        let c = sasl_connect(sasl_builder(rt, cs, src)).await;
        common::within(c.create(path, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
            .await
            .unwrap();

        let mut w = c.state_watcher();
        server.stop_now();
        common::wait_state(&mut w, SLOW, |i| !i.state.is_connected()).await;
        server.start_again().unwrap();
        let back = common::wait_state(&mut w, SLOW, |i| {
            i.state == SessionState::Connected && i.epoch >= 2
        })
        .await;
        assert_eq!(back.state, SessionState::Connected);
        // With `sessionRequireClientSASLAuth`, a read works only after
        // the new authentication.
        assert!(common::within(c.exists(path)).await.unwrap().is_some());
        common::within(c.close()).await.unwrap();
    }

    /// The body of the encrypted password cases: the file holds
    /// `mypassword` with `incr` taken from each byte.
    pub(super) async fn encrypted(rt: Rt, content: &[u8], incr: u8, name: &str, path: &str) {
        let Some(server) = start_server(true, false) else {
            return;
        };
        // The file name holds the port, so that runs on other port bases
        // of this host do not share the file.
        let file = std::env::temp_dir().join(format!("{name}-{}-{}", rt.name(), server.port()));
        std::fs::write(&file, content).unwrap();
        let src = Arc::new(Decrypting {
            file: file.clone(),
            incr,
            calls: AtomicUsize::new(0),
        });
        let cs = server.connect_string();
        sasl_helper(&server, rt, &cs, path, src.clone()).await;
        // The client reads the source again for the new connection.
        assert!(src.calls.load(Ordering::SeqCst) >= 2);
        let _ = std::fs::remove_file(&file);
    }
}

#[cfg(feature = "sasl")]
sasl_test!(client_sasl);
/// `Zookeeper_SASLAuth::testClientSASL`: a DIGEST-MD5 session connects
/// and writes. After a server restart, the client reconnects and
/// authenticates again by itself.
#[cfg(feature = "sasl")]
async fn client_sasl(rt: Rt) {
    let Some(server) = start_server(true, false) else {
        return;
    };
    let cs = server.connect_string();
    sasl_helper(&server, rt, &cs, "/clientSASL", std::sync::Arc::new(Fixed)).await;
}

#[cfg(feature = "sasl")]
sasl_test!(client_sasl_with_password_encrypted_text);
/// `Zookeeper_SASLAuth::testClientSASLWithPasswordEncryptedText`: the
/// application decrypts the password from a text file (each byte plus
/// 1), and the session authenticates before and after a restart.
#[cfg(feature = "sasl")]
async fn client_sasl_with_password_encrypted_text(rt: Rt) {
    let content = [0x6C, 0x78, 0x6F, 0x60, 0x72, 0x72, 0x76, 0x6E, 0x71, 0x63];
    encrypted(
        rt,
        &content,
        1,
        "Zookeeper_SASLAuth.password.encrypted.text",
        "/clientSASLWithPasswordEncryptedText",
    )
    .await;
}

#[cfg(feature = "sasl")]
sasl_test!(client_sasl_with_password_encrypted_binary);
/// `Zookeeper_SASLAuth::testClientSASLWithPasswordEncryptedBinary`: the
/// application decrypts the password from a binary file (each byte plus
/// `'a'`), and the session authenticates before and after a restart.
#[cfg(feature = "sasl")]
async fn client_sasl_with_password_encrypted_binary(rt: Rt) {
    let content = [0x0C, 0x18, 0x0F, 0x00, 0x12, 0x12, 0x16, 0x0E, 0x11, 0x03];
    encrypted(
        rt,
        &content,
        b'a',
        "Zookeeper_SASLAuth.password.encrypted.binary",
        "/clientSASLWithPasswordEncryptedBinary",
    )
    .await;
}

#[cfg(feature = "sasl")]
sasl_test!(client_sasl_over_ipv6);
/// `Zookeeper_SASLAuth::testClientSASLOverIPv6`: the SASL session and
/// the restart of `testClientSASL` over the IPv6 loopback. The Rust
/// connect string puts the IPv6 address in brackets.
#[cfg(feature = "sasl")]
async fn client_sasl_over_ipv6(rt: Rt) {
    let Some(server) = start_server(true, false) else {
        return;
    };
    let cs = format!("[::1]:{}", server.port());
    sasl_helper(
        &server,
        rt,
        &cs,
        "/clientSASLOverIPv6",
        std::sync::Arc::new(Fixed),
    )
    .await;
}

#[cfg(feature = "sasl")]
sasl_test!(client_sasl_read_only);
/// `Zookeeper_SASLAuth::testClientSASLReadOnly`: a SASL session with
/// `allow_read_only` connects to a server with no quorum. A read works,
/// and a write fails with `NotReadOnly`.
#[cfg(feature = "sasl")]
async fn client_sasl_read_only(rt: Rt) {
    let Some(server) = start_server(true, true) else {
        return;
    };
    let cs = server.connect_string();
    let b = sasl_builder(rt, &cs, std::sync::Arc::new(Fixed)).allow_read_only(true);
    let c = sasl_connect(b).await;
    assert_eq!(
        c.state().state,
        apache_zookeeper::SessionState::ConnectedReadOnly
    );
    assert!(common::within(c.get_data("/")).await.is_ok());
    let r =
        common::within(c.create("/test", b"hello", CreateMode::Persistent, OPEN_ACL_UNSAFE)).await;
    assert_eq!(r.unwrap_err(), Error::NotReadOnly);
    common::within(c.close()).await.unwrap();
}

#[cfg(feature = "sasl")]
sasl_test!(client_sasl_packet_order);
/// `Zookeeper_SASLAuth::testClientSASLPacketOrder`: a read that the
/// application sends at once after the client starts, before the SASL
/// exchange ends, waits behind it and succeeds. The server needs SASL
/// for each session, so a read before the exchange would fail.
#[cfg(feature = "sasl")]
async fn client_sasl_packet_order(rt: Rt) {
    let Some(server) = start_server(true, false) else {
        return;
    };
    let cs = server.connect_string();
    let c = sasl_builder(rt, &cs, std::sync::Arc::new(Fixed))
        .build()
        .unwrap();
    let r = tokio::time::timeout(SLOW, c.get_data("/"))
        .await
        .expect("timed out");
    assert!(r.is_ok(), "{r:?}");
    common::within(c.close()).await.unwrap();
}
