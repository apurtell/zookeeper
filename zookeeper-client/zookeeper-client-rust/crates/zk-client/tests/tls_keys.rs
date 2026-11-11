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

//! API tests of encrypted client keys through `TlsOptions`, against the
//! TLS acceptor of the fake server. The server asks for a client
//! certificate from the test CA. The zk-driver tests cover the key
//! parser. These tests cover the path from the public builder and from
//! `legacy_c_compat` to a mutual TLS session.
//!
//! The fixtures come from `zk_testkit::fixtures::tls_dir`. It makes them at
//! test time with the `gen.sh` scripts of `crates/zk-driver/tests/fixtures/tls`.
//! The encrypted keys hold `client.key` under the passphrase of `gen.sh`.

#![cfg(feature = "tls-rustls")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::sync::Arc;

use apache_zookeeper::{SecretString, TlsConfigError, TlsOptions};
use zk_fakeserver::{ClusterConfig, FakeServer, ServerOptions, TlsAcceptor};

/// The passphrase of the encrypted fixtures (`gen.sh`).
const PASS: &str = "zk-test-pass";

/// The encrypted forms of `client.key`: PKCS#8 with PBES2 and PBKDF2,
/// PKCS#8 with scrypt, PKCS#8 with 3DES, and a traditional key with a
/// DEK-Info header.
const KEYS: [&str; 4] = [
    "keys/p8-sha256-aes256.pem",
    "keys/p8-scrypt.pem",
    "keys/p8-des3.pem",
    "keys/trad-aes256.pem",
];

use common::{fixture, within};

/// Starts a TLS fake server that requires a client certificate of the
/// test CA.
fn mtls_server() -> (FakeServer, Arc<TlsAcceptor>) {
    let acc = TlsAcceptor::builder(zk_driver::net::tls::default_provider())
        .cert_chain_pem_file(fixture("server.pem"))
        .unwrap()
        .key_pem_file(fixture("server.key"))
        .unwrap()
        .client_auth_ca_pem_file(fixture("ca.pem"))
        .unwrap()
        .build()
        .unwrap();
    let opts = ServerOptions::default().with_acceptor(Arc::clone(&acc) as _);
    let server = FakeServer::start_with(ClusterConfig::default(), opts).unwrap();
    (server, acc)
}

/// Connects with `tls`, runs one request and closes. The server must
/// see a client certificate.
async fn session_with(fs: &FakeServer, acc: &TlsAcceptor, tls: TlsOptions, what: &str) {
    let before = acc.sessions().iter().filter(|s| s.client_cert).count();
    let c = within(common::builder(&fs.connect_string()).tls(tls).connect())
        .await
        .unwrap_or_else(|e| panic!("{what}: {e:?}"));
    assert!(within(c.exists("/")).await.unwrap().is_some(), "{what}");
    within(c.close()).await.unwrap();
    let after = acc.sessions().iter().filter(|s| s.client_cert).count();
    assert!(
        after > before,
        "{what}: the server saw no client certificate"
    );
}

/// Rule: an encrypted client key loads with its passphrase, and the
/// identity satisfies a server that requires a client certificate (spec
/// "Native Security Configuration").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_encrypted_key_with_its_passphrase_gives_mutual_tls() {
    let (fs, acc) = mtls_server();
    for key in KEYS {
        let tls = TlsOptions::builder()
            .ca_file(fixture("ca.pem"))
            .client_identity(
                fixture("client.pem"),
                fixture(key),
                Some(SecretString::from(PASS)),
            )
            .build()
            .unwrap_or_else(|e| panic!("{key}: {e:?}"));
        session_with(&fs, &acc, tls, key).await;
    }
}

/// Rule: `build` decrypts the key at the call. A missing or wrong
/// passphrase fails with `PrivateKey` and the key path, and the text
/// never shows the passphrase.
#[test]
fn a_missing_or_wrong_passphrase_fails_at_build() {
    for key in KEYS {
        let path = fixture(key);
        for pass in [None, Some("not-the-pass"), Some("")] {
            let e = TlsOptions::builder()
                .ca_file(fixture("ca.pem"))
                .client_identity(fixture("client.pem"), &path, pass.map(SecretString::from))
                .build()
                .unwrap_err();
            assert!(
                matches!(&e, TlsConfigError::PrivateKey(p) if *p == path),
                "{key} {pass:?}: {e:?}"
            );
            let text = format!("{e} {e:?}");
            assert!(!text.contains("not-the-pass"), "{text}");
        }
    }
}

/// Rule: `legacy_c_compat` takes the passphrase from the fourth field
/// of "ca,cert,key,passwd". The encrypted key then gives mutual TLS, as
/// `zookeeper_init_ssl` does (spec "Client Identity Support Without
/// Passwords").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_c_compat_decrypts_the_key_with_the_fourth_field() {
    let (fs, acc) = mtls_server();
    for key in KEYS {
        let s = format!(
            "{},{},{},{PASS}",
            fixture("ca.pem").display(),
            fixture("client.pem").display(),
            fixture(key).display()
        );
        let tls = TlsOptions::legacy_c_compat(&s).unwrap_or_else(|e| panic!("{key}: {e:?}"));
        session_with(&fs, &acc, tls, key).await;

        let no_pass = format!(
            "{},{},{}",
            fixture("ca.pem").display(),
            fixture("client.pem").display(),
            fixture(key).display()
        );
        let e = TlsOptions::legacy_c_compat(&no_pass).unwrap_err();
        assert!(matches!(e, TlsConfigError::PrivateKey(_)), "{key}: {e:?}");
    }
}
