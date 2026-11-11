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

//! Tests of the protocol floor and the suite offer of the drop-in
//! connector.
//!
//! The legacy client offers what the linked OpenSSL allows. The Rust
//! core offers TLS 1.2 and TLS 1.3 only, and only AEAD ECDHE suites in
//! TLS 1.2. The tests read the ClientHello of the connector, and give it
//! a ServerHello of an old protocol. They run in memory.

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

mod tls_util;

use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;

use zk_driver::net::tls::connector::{
    LegacyPath, LegacyTlsArgs, RustlsConnector, default_provider,
};
use zk_driver::net::tls::{TlsConn, TlsConnector, TlsFailure, TlsPurpose};
use zk_driver::sync::Unlocked;
use zk_proto::compat::TlsVerify;
use zk_proto::{Endpoint, HostToken};

use crate::tls_util::{TLS12, TLS13, exchange, fixture, server};

/// The record type of a handshake message.
const HANDSHAKE: u8 = 0x16;
/// The record type of an alert.
const ALERT: u8 = 0x15;
/// The extension type of supported_versions (RFC 8446).
const SUPPORTED_VERSIONS: u16 = 0x002b;
/// The alert description protocol_version.
const PROTOCOL_VERSION: u8 = 70;
/// The TLS 1.2 suites with ECDHE and an AEAD cipher.
const AEAD_ECDHE: &[u16] = &[0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9];
/// The renegotiation SCSV, which is not a suite.
const SCSV: u16 = 0x00ff;

/// A new session of the drop-in connector with the fixture CA.
fn drop_in() -> Box<dyn TlsConn> {
    let args = LegacyTlsArgs {
        ca: Some(LegacyPath::new(
            fixture("ca.pem").as_os_str().as_bytes().to_vec(),
        )),
        cert: None,
        key: None,
        passwd: None,
        env_allowed: false,
        verify: TlsVerify::LegacyChainOnly,
    };
    let ep = Endpoint {
        addr: SocketAddr::from(([127, 0, 0, 1], 2281)),
        host: HostToken {
            index: 0,
            name: b"127.0.0.1".to_vec(),
        },
    };
    RustlsConnector::legacy(args, default_provider())
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .unwrap()
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The fields of a ClientHello that the tests check.
struct Hello {
    legacy_version: u16,
    suites: Vec<u16>,
    versions: Option<Vec<u16>>,
}

/// Reads the ClientHello from the first flight of a session.
fn client_hello(tls: &mut dyn TlsConn) -> Hello {
    let mut ct = Vec::new();
    tls.take_ciphertext(&mut ct);
    assert_eq!(ct[0], HANDSHAKE, "the first record is a handshake");
    let len = usize::from(u16_at(&ct, 3));
    let m = &ct[5..5 + len];
    assert_eq!(m[0], 1, "the first message is a ClientHello");
    let legacy_version = u16_at(m, 4);
    // Type (1), length (3), version (2) and random (32).
    let mut at = 38;
    at += 1 + usize::from(m[at]);
    let n = usize::from(u16_at(m, at));
    let suites = m[at + 2..at + 2 + n]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    at += 2 + n;
    at += 1 + usize::from(m[at]);
    let end = at + 2 + usize::from(u16_at(m, at));
    at += 2;
    let mut versions = None;
    while at < end {
        let ty = u16_at(m, at);
        let n = usize::from(u16_at(m, at + 2));
        let body = &m[at + 4..at + 4 + n];
        if ty == SUPPORTED_VERSIONS {
            let list = &body[1..1 + usize::from(body[0])];
            versions = Some(
                list.chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect(),
            );
        }
        at += 4 + n;
    }
    Hello {
        legacy_version,
        suites,
        versions,
    }
}

/// A ServerHello record of version, with no extensions.
fn server_hello(version: u16, suite: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&[0x5a; 32]);
    body.push(0);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    let mut msg = vec![2, 0, 0, u8::try_from(body.len()).unwrap()];
    msg.extend_from_slice(&body);
    let mut rec = vec![HANDSHAKE];
    rec.extend_from_slice(&version.to_be_bytes());
    rec.extend_from_slice(&u16::try_from(msg.len()).unwrap().to_be_bytes());
    rec.extend_from_slice(&msg);
    rec
}

/// The ClientHello offers TLS 1.3 and TLS 1.2 only.
#[test]
fn the_client_hello_offers_only_tls_1_2_and_tls_1_3() {
    // Rule: the drop-in offers TLS 1.3 and TLS 1.2, and no older
    // protocol. The record and legacy_version fields say TLS
    // 1.2, and supported_versions lists only 1.3 and 1.2.
    let hello = client_hello(drop_in().as_mut());
    assert_eq!(hello.legacy_version, 0x0303);
    assert_eq!(hello.versions, Some(vec![0x0304, 0x0303]));
}

/// A server below TLS 1.2 fails the handshake. This is a known difference.
#[test]
fn a_server_hello_below_tls_1_2_fails_the_handshake() {
    // Rule: a server that selects SSLv3, TLS 1.0 or TLS 1.1 fails the
    // handshake with a protocol_version alert. Legacy
    // connects when the OpenSSL policy allows that protocol.
    for version in [0x0300u16, 0x0301, 0x0302] {
        let mut tls = drop_in();
        let _ = client_hello(tls.as_mut());
        assert_eq!(
            tls.feed(&server_hello(version, 0xc02b)),
            Err(TlsFailure::Handshake),
            "version {version:#06x}"
        );
        let mut alert = Vec::new();
        tls.take_ciphertext(&mut alert);
        assert_eq!(alert[0], ALERT, "version {version:#06x}");
        assert_eq!(alert[5..7], [2, PROTOCOL_VERSION], "version {version:#06x}");
    }
}

/// A server that selects TLS 1.2 or TLS 1.3 connects.
#[test]
fn tls_1_2_and_tls_1_3_servers_connect() {
    // Rule: the floor keeps TLS 1.2 and TLS 1.3. ZooKeeper servers use
    // TLS 1.2 or newer, so the floor does not change them.
    for versions in [TLS12, TLS13] {
        let mut tls = drop_in();
        let mut s = server(versions);
        exchange(tls.as_mut(), &mut s, false).unwrap();
        assert!(!tls.is_handshaking());
        assert!(!s.is_handshaking());
    }
}

/// The TLS 1.2 offer has only AEAD ECDHE suites.
#[test]
fn tls_1_2_suites_are_only_aead_ecdhe() {
    // Rule: the TLS 1.2 offer has only AEAD ECDHE suites. No CBC, static
    // RSA or DHE suite is offered, so a server with only such suites
    // fails. The TLS 1.3 suites are 0x13xx.
    let hello = client_hello(drop_in().as_mut());
    let tls12: Vec<u16> = hello
        .suites
        .iter()
        .copied()
        .filter(|s| s >> 8 != 0x13 && *s != SCSV)
        .collect();
    assert!(!tls12.is_empty());
    for s in &tls12 {
        assert!(AEAD_ECDHE.contains(s), "suite {s:#06x}");
    }
}
