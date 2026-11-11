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

//! Integration tests of the TLS session: `RustlsConnector` and
//! `RustlsConn` against the rustls server of `common::tls`.
//!
//! The tests drive the sans-IO session over a blocking std socket, so
//! they need no `iocore` code. The in-memory tests of the session are in
//! the unit tests of `net::tls`.

#![cfg(all(unix, feature = "tls"))]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use common::tls::{Native, TlsAcceptor, legacy_path};
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;
use zk_driver::Unlocked;
use zk_driver::net::tls::verify::webpki_verifier;
use zk_driver::net::tls::{
    LegacyTlsArgs, RustlsConnector, TlsConfigStep, TlsConn, TlsConnector, TlsFailure, TlsPurpose,
    TlsSetupError, default_provider,
};
use zk_fakeserver::{ClusterConfig, FakeServer, ServerOptions};
use zk_proto::compat::TlsVerify;
use zk_proto::{Endpoint, HostToken, SecretBytes};

fn tls_server(client_auth: bool) -> FakeServer {
    let opts = ServerOptions {
        acceptor: Some(TlsAcceptor::new(client_auth)),
        ..ServerOptions::default()
    };
    FakeServer::start_with(ClusterConfig::default(), opts).unwrap()
}

fn legacy(ca: &str, identity: bool, verify: TlsVerify) -> RustlsConnector {
    let args = LegacyTlsArgs {
        ca: Some(legacy_path(ca)),
        cert: identity.then(|| legacy_path("client.pem")),
        key: identity.then(|| legacy_path("client.key")),
        passwd: identity.then(SecretBytes::empty),
        env_allowed: false,
        verify,
    };
    RustlsConnector::legacy(args, default_provider())
}

fn endpoint(addr: SocketAddr, name: &[u8]) -> Endpoint {
    Endpoint {
        addr,
        host: HostToken {
            index: 0,
            name: name.to_vec(),
        },
    }
}

/// Runs the handshake over a blocking socket. It returns the latched
/// failure, if any.
fn handshake(tcp: &mut TcpStream, tls: &mut dyn TlsConn) -> Result<(), TlsFailure> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while tls.is_handshaking() {
        out.clear();
        tls.take_ciphertext(&mut out);
        if !out.is_empty() {
            tcp.write_all(&out).unwrap();
            continue;
        }
        let n = tcp.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return tls.feed_eof();
        }
        tls.feed(&buf[..n])?;
    }
    out.clear();
    tls.take_ciphertext(&mut out);
    tcp.write_all(&out).unwrap();
    Ok(())
}

/// Sends the `isro` probe in one frame, as `net::probe` does. It returns
/// the plaintext before the latched failure, and the failure.
fn isro(tcp: &mut TcpStream, tls: &mut dyn TlsConn) -> (Vec<u8>, TlsFailure) {
    tls.write_frame(b"isro").unwrap();
    let mut out = Vec::new();
    tls.take_ciphertext(&mut out);
    tcp.write_all(&out).unwrap();
    let mut buf = [0u8; 4096];
    let mut plain = Vec::new();
    // The server answers and closes, so the read ends in a latched
    // failure. The plaintext before the failure comes first.
    loop {
        let n = tcp.read(&mut buf).unwrap_or(0);
        let fed = if n == 0 {
            tls.feed_eof()
        } else {
            tls.feed(&buf[..n])
        };
        loop {
            match tls.read_plaintext(&mut plain) {
                Ok(0) => break,
                Ok(_) => {}
                Err(f) => {
                    assert_eq!(fed, Err(f));
                    return (plain, f);
                }
            }
        }
        assert_eq!(fed, Ok(()));
    }
}

fn connect(server: &FakeServer) -> TcpStream {
    let tcp = TcpStream::connect(server.addr()).unwrap();
    tcp.set_read_timeout(Some(common::WAIT)).unwrap();
    tcp
}

/// The legacy chain-only check accepts a chain that ends at the CA file.
#[test]
fn legacy_chain_only_handshake_succeeds() {
    let server = tls_server(false);
    let connector = legacy("ca.pem", false, TlsVerify::LegacyChainOnly);
    let ep = endpoint(server.addr(), b"127.0.0.1");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap();
    let mut tcp = connect(&server);
    handshake(&mut tcp, tls.as_mut()).unwrap();
    assert!(!tls.is_handshaking());
}

#[test]
fn wrong_ca_latches_a_handshake_failure() {
    let server = tls_server(false);
    let connector = legacy("wrong-ca.pem", false, TlsVerify::LegacyChainOnly);
    let ep = endpoint(server.addr(), b"127.0.0.1");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap();
    let mut tcp = connect(&server);
    assert_eq!(
        handshake(&mut tcp, tls.as_mut()),
        Err(TlsFailure::Handshake)
    );
}

#[test]
fn client_identity_satisfies_client_auth() {
    let server = tls_server(true);
    let connector = legacy("ca.pem", true, TlsVerify::LegacyChainOnly);
    let ep = endpoint(server.addr(), b"127.0.0.1");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap();
    let mut tcp = connect(&server);
    handshake(&mut tcp, tls.as_mut()).unwrap();
    // The server reads the first record only after the handshake, so a
    // frame round trip proves that it accepted the identity.
    assert_eq!(
        isro(&mut tcp, tls.as_mut()),
        (b"rw".to_vec(), TlsFailure::Closed)
    );
}

#[test]
fn missing_ca_file_is_a_config_error() {
    let connector = legacy("absent.pem", false, TlsVerify::LegacyChainOnly);
    let ep = endpoint("127.0.0.1:1".parse().unwrap(), b"127.0.0.1");
    let err = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .err()
        .unwrap();
    assert!(matches!(err, TlsSetupError::Config { .. }), "{err:?}");
}

#[test]
fn first_ciphertext_is_the_client_hello() {
    let connector = legacy("ca.pem", false, TlsVerify::LegacyChainOnly);
    let ep = endpoint("127.0.0.1:1".parse().unwrap(), b"127.0.0.1");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap();
    assert!(tls.has_ciphertext());
    let mut out = Vec::new();
    assert!(tls.take_ciphertext(&mut out) > 0);
    // A TLS handshake record.
    assert_eq!(out.first(), Some(&22));
}

#[test]
fn isro_round_trip_gives_the_answer_before_the_close() {
    let server = tls_server(false);
    let connector = legacy("ca.pem", false, TlsVerify::LegacyChainOnly);
    let ep = endpoint(server.addr(), b"127.0.0.1");
    for purpose in [TlsPurpose::Main, TlsPurpose::Probe] {
        // Each call makes a new session.
        let mut tls = connector
            .new_conn(&Unlocked::new_at_entry(), purpose, &ep)
            .unwrap();
        let mut tcp = connect(&server);
        handshake(&mut tcp, tls.as_mut()).unwrap();
        assert_eq!(
            isro(&mut tcp, tls.as_mut()),
            (b"rw".to_vec(), TlsFailure::Closed)
        );
        // The latch stays.
        assert_eq!(tls.write_frame(b"x"), Err(TlsFailure::Closed));
    }
}

#[test]
fn read_only_server_answers_ro() {
    let server = tls_server(false);
    server.set_isro_answer(Some("ro"));
    let connector = legacy("ca.pem", false, TlsVerify::LegacyChainOnly);
    let ep = endpoint(server.addr(), b"127.0.0.1");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Probe, &ep)
        .unwrap();
    let mut tcp = connect(&server);
    handshake(&mut tcp, tls.as_mut()).unwrap();
    assert_eq!(
        isro(&mut tcp, tls.as_mut()),
        (b"ro".to_vec(), TlsFailure::Closed)
    );
}

#[test]
fn client_auth_without_an_identity_fails() {
    let server = tls_server(true);
    let connector = legacy("ca.pem", false, TlsVerify::LegacyChainOnly);
    let ep = endpoint(server.addr(), b"127.0.0.1");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap();
    let mut tcp = connect(&server);
    // In TLS 1.3 the client ends its handshake first, so the server
    // alert comes after it. OpenSSL reads 0 bytes at that alert, so the
    // latch is Closed, as at an EOF.
    match handshake(&mut tcp, tls.as_mut()) {
        Err(f) => assert_eq!(f, TlsFailure::Handshake),
        Ok(()) => {
            let (plain, f) = isro(&mut tcp, tls.as_mut());
            assert!(plain.is_empty());
            assert_eq!(f, TlsFailure::Closed);
        }
    }
}

#[test]
fn legacy_webpki_ignores_the_host_token() {
    // The drop-in name is the peer IP, which is in the server SAN.
    let server = tls_server(false);
    let connector = legacy("ca.pem", false, TlsVerify::WebPki);
    let ep = endpoint(server.addr(), b"example.com");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap();
    let mut tcp = connect(&server);
    handshake(&mut tcp, tls.as_mut()).unwrap();
}

fn native() -> RustlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for c in common::tls::certs("ca.pem") {
        roots.add(c).unwrap();
    }
    let verifier = webpki_verifier(Arc::new(roots), default_provider()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(default_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    RustlsConnector::native(Arc::new(Native(Arc::new(cfg))), default_provider())
}

#[test]
fn native_webpki_checks_the_host_name() {
    let server = tls_server(false);
    let connector = native();
    for (name, want) in [
        (&b"localhost"[..], Ok(())),
        (b"127.0.0.1", Ok(())),
        (b"example.com", Err(TlsFailure::Handshake)),
    ] {
        let ep = endpoint(server.addr(), name);
        let mut tls = connector
            .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
            .unwrap();
        let mut tcp = connect(&server);
        assert_eq!(handshake(&mut tcp, tls.as_mut()), want, "{name:?}");
    }
}

/// A clock after the validity of the fixtures.
#[derive(Debug)]
struct Late;

impl TimeProvider for Late {
    fn current_time(&self) -> Option<UnixTime> {
        // 2200-01-01T00:00:00Z.
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            7_258_118_400,
        )))
    }
}

#[test]
fn verifier_uses_the_injected_clock() {
    let server = tls_server(false);
    let connector =
        legacy("ca.pem", false, TlsVerify::LegacyChainOnly).with_time_provider(Arc::new(Late));
    let ep = endpoint(server.addr(), b"127.0.0.1");
    let mut tls = connector
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap();
    let mut tcp = connect(&server);
    assert_eq!(
        handshake(&mut tcp, tls.as_mut()),
        Err(TlsFailure::Handshake)
    );
}

#[test]
fn identity_setup_errors_name_the_step_and_the_path() {
    let ep = endpoint("127.0.0.1:1".parse().unwrap(), b"127.0.0.1");
    for (cert, key, step) in [
        ("absent.pem", "client.key", TlsConfigStep::ClientCertChain),
        ("client.pem", "absent.key", TlsConfigStep::ClientKey),
        ("client.pem", "server.key", TlsConfigStep::ClientKey),
    ] {
        let args = LegacyTlsArgs {
            ca: Some(legacy_path("ca.pem")),
            cert: Some(legacy_path(cert)),
            key: Some(legacy_path(key)),
            passwd: Some(SecretBytes::empty()),
            env_allowed: false,
            verify: TlsVerify::LegacyChainOnly,
        };
        let connector = RustlsConnector::legacy(args, default_provider());
        let err = connector
            .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
            .err()
            .unwrap();
        assert_eq!(err, TlsSetupError::Config { step });
        let want = if step == TlsConfigStep::ClientKey {
            legacy_path(key)
        } else {
            legacy_path(cert)
        };
        assert_eq!(connector.path_for(step), Some(want.raw()));
    }
}
