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

//! TLS tests against a real server of this source tree. The server
//! runs Netty with a secure client port, PEM key and trust stores from
//! the TLS test fixtures, and the x509 auth provider.
//!
//! Each test has `#[ignore = "real-server"]` and takes its ports from
//! `common::real_port`. Run them with `ZK_TEST_PORT_BASE=<base> cargo
//! test --features tls-ring --test tls_real -- --ignored`. A test uses
//! `base + offset` as the plain port and the next port as the secure
//! port.

#![cfg(feature = "tls-rustls")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::time::Duration;

use apache_zookeeper::acl::{CREATOR_ALL_ACL, OPEN_ACL_UNSAFE};
use apache_zookeeper::{Client, CreateMode, Error, SecretString, TlsOptions};
use common::{RealServer, builder, ca_only, fixture, real_port, within};
use rustls::pki_types::ServerName;

/// The passphrase of the encrypted fixtures (`gen.sh`).
const PASS: &str = "zk-test-pass";

/// How long a test waits to show that a client never connects.
const REFUSED: Duration = Duration::from_millis(1_500);

/// A TLS server and its secure connect string.
struct TlsServer {
    _srv: RealServer,
    secure: String,
}

/// Starts a TLS server at `base + offset`, or gives `None` to skip.
/// `client_auth` is the `ssl.clientAuth` value of the server.
fn tls_server(offset: u16, client_auth: &str) -> Option<TlsServer> {
    let port = real_port(offset)?;
    let secure = real_port(offset.checked_add(1)?)?;
    let dir = common::default_server_dir(port);
    // A rerun starts from an empty tree. On a first run the directory
    // does not exist, and the helper ignores that error.
    let _ = std::fs::remove_dir_all(dir.join("data"));
    std::fs::create_dir_all(&dir).unwrap();
    // A PEM key store holds the key and the chain in one file.
    let ks = dir.join("server-keystore.pem");
    let mut pem = std::fs::read(fixture("server.key")).unwrap();
    pem.extend(std::fs::read(fixture("server.pem")).unwrap());
    std::fs::write(&ks, pem).unwrap();
    let props = format!(
        "secureClientPort={secure}\n\
         serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory\n\
         authProvider.x509=org.apache.zookeeper.server.auth.X509AuthenticationProvider\n\
         ssl.keyStore.location={}\n\
         ssl.keyStore.type=PEM\n\
         ssl.trustStore.location={}\n\
         ssl.trustStore.type=PEM\n\
         ssl.clientAuth={client_auth}\n",
        ks.display(),
        fixture("ca.pem").display()
    );
    match RealServer::start_with(port, None, &props, "") {
        Ok(srv) => Some(TlsServer {
            _srv: srv,
            secure: format!("127.0.0.1:{secure}"),
        }),
        Err(e) => common::skip("no real ZooKeeper server", &e),
    }
}

/// TLS options with the test CA and the client identity under the
/// encrypted key `key`.
fn with_identity(key: &str) -> TlsOptions {
    TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .client_identity(
            fixture("client.pem"),
            fixture(key),
            Some(SecretString::from(PASS)),
        )
        .build()
        .unwrap()
}

/// Connects a client to `cs` with `tls`.
async fn connect(cs: &str, tls: TlsOptions) -> Client {
    within(builder(cs).tls(tls).connect())
        .await
        .expect("connect")
}

/// Shows that a client with `tls` does not connect in [`REFUSED`], and
/// that the attempts set `last_error`.
async fn never_connects(cs: &str, tls: TlsOptions, what: &str) {
    let f = builder(cs).tls(tls).connect();
    let w = f.state_watcher();
    let mut f = Box::pin(f);
    assert!(
        tokio::time::timeout(REFUSED, &mut f).await.is_err(),
        "{what}: the client connected"
    );
    assert!(w.last_error().is_some(), "{what}: no last_error");
}

/// True when the session has an x509 identity.
async fn has_x509(c: &Client) -> bool {
    within(c.who_am_i())
        .await
        .unwrap()
        .iter()
        .any(|i| i.auth_scheme == "x509" && !i.user.is_empty())
}

/// Rule: the native client connects to the secure port with the CA file
/// and the default `WebPki` name check. The IP SAN of the server matches
/// the IP literal. An explicit server name must also match, and another
/// CA never connects. With `ssl.clientAuth=want`, a client with no
/// certificate has no x509 identity, so `CREATOR_ALL_ACL` is an invalid
/// ACL. A client certificate under an encrypted key gives the x509
/// identity, and the creator ACL holds it (spec "Native Security
/// Configuration"; ZooKeeper Admin Guide "X509 AuthenticationProvider").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn real_tls_names_and_client_identity() {
    let Some(srv) = tls_server(0, "want") else {
        return;
    };

    let anon = connect(&srv.secure, ca_only()).await;
    within(anon.create("/tls", b"t", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert!(!has_x509(&anon).await);
    assert_eq!(
        within(anon.create("/tls/c", b"", CreateMode::Persistent, CREATOR_ALL_ACL))
            .await
            .err(),
        Some(Error::InvalidAcl)
    );
    within(anon.close()).await.unwrap();

    for key in ["keys/p8-sha256-aes256.pem", "keys/trad-aes256.pem"] {
        let c = connect(&srv.secure, with_identity(key)).await;
        assert!(has_x509(&c).await, "{key}");
        let path = format!("/tls/{}", key.replace(['/', '.'], "-"));
        within(c.create(&*path, b"x", CreateMode::Persistent, CREATOR_ALL_ACL))
            .await
            .unwrap();
        let (acl, _) = within(c.get_acl(&*path)).await.unwrap();
        assert!(acl.iter().any(|a| a.id.scheme == "x509"), "{acl:?}");
        within(c.close()).await.unwrap();
    }

    let localhost = TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .server_name(ServerName::try_from("localhost").unwrap())
        .build()
        .unwrap();
    within(connect(&srv.secure, localhost).await.close())
        .await
        .unwrap();

    let other_name = TlsOptions::builder()
        .ca_file(fixture("ca.pem"))
        .server_name(ServerName::try_from("other.invalid").unwrap())
        .build()
        .unwrap();
    never_connects(&srv.secure, other_name, "another server name").await;

    let other_ca = TlsOptions::builder()
        .ca_file(fixture("wrong-ca.pem"))
        .build()
        .unwrap();
    never_connects(&srv.secure, other_ca, "another CA").await;
}

/// Rule: with `ssl.clientAuth=need` the server refuses a client with no
/// certificate. The `legacy_c_compat` string with a passphrase in the
/// fourth field decrypts the key, and the session gets the x509
/// identity (ZooKeeper Admin Guide "ssl.clientAuth").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn real_tls_needs_the_client_certificate() {
    let Some(srv) = tls_server(2, "need") else {
        return;
    };
    never_connects(&srv.secure, ca_only(), "no client certificate").await;

    let s = format!(
        "{},{},{},{PASS}",
        fixture("ca.pem").display(),
        fixture("client.pem").display(),
        fixture("keys/p8-scrypt.pem").display()
    );
    let c = connect(&srv.secure, TlsOptions::legacy_c_compat(&s).unwrap()).await;
    assert!(has_x509(&c).await);
    assert!(within(c.exists("/")).await.unwrap().is_some());
    within(c.close()).await.unwrap();
}
