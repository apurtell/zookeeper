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

//! Tests of the `LegacyChainOnly` verifier against the trust-decision
//! corpus (unit tier).
//!
//! `zookeeper-client-rust/c/tests/conformance/tls/gencorpus.sh` makes the
//! corpus with `openssl` at test time. It records the verdict of
//! `openssl verify` for each case. `zk_testkit::fixtures::tls_corpus_dir`
//! keeps the corpus in the test cache. The Rust verdict must equal the
//! recorded `expect` value, and a Rust ACCEPT against an oracle REJECT
//! always fails.
//!
//! The webpki tests run the webpki component of the chain path alone.
//! They show where webpki accepts and the OpenSSL post-checks must reject
//! (TC-16, TC-44). They also show where webpki causes a `DV-TLS-3` tag.

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

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls::RootCertStore;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use zk_driver::net::tls::legacy_verify::LegacyChainOnly;
use zk_driver::net::tls::trust::TrustSet;
use zk_driver::net::tls::{LegacyPath, default_provider};

/// The corpus cases that can carry the `DV-TLS-3` tag. For TC-21 and
/// TC-24, only the variants named here can carry it.
const DV_TLS_3: &[&str] = &[
    "TC-18",
    "TC-21(b)",
    "TC-22",
    "TC-23",
    "TC-24(corrupt)",
    "TC-24(other-subject)",
    "TC-28",
    "TC-33",
    "TC-34",
    "TC-35",
    "TC-36",
    "TC-37",
    "TC-40",
    "TC-42",
    "TC-43",
    "TC-45",
    "TC-46",
    "TC-47",
    "TC-48",
    "TC-52",
    "TC-53",
    "TC-54",
];

/// The verdict key of this build.
const EXPECT_KEY: &str = if cfg!(feature = "tls-ring") {
    "expect"
} else {
    "expect-aws-lc-rs"
};

struct Case {
    name: String,
    dir: PathBuf,
    verdict: BTreeMap<String, String>,
}

impl Case {
    fn get(&self, key: &str) -> &str {
        self.verdict
            .get(key)
            .unwrap_or_else(|| panic!("{}: verdict.txt has no {key}", self.name))
    }

    fn now(&self) -> UnixTime {
        let secs = self.get("attime").parse().expect("attime");
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    fn chain(&self) -> Vec<CertificateDer<'static>> {
        certs(&self.dir.join("chain.pem"))
    }

    fn expect(&self) -> &str {
        self.get(EXPECT_KEY)
    }
}

fn corpus_dir() -> &'static Path {
    zk_testkit::fixtures::tls_corpus_dir()
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for entry in fs::read_dir(corpus_dir()).expect("corpus directory") {
        let dir = entry.unwrap().path();
        let file = dir.join("verdict.txt");
        if !file.is_file() {
            continue;
        }
        let verdict = fs::read_to_string(&file)
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        out.push(Case { name, dir, verdict });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    assert!(
        out.len() > 100,
        "the corpus is incomplete: {} cases",
        out.len()
    );
    out
}

fn case(name: &str) -> Case {
    cases()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no corpus case {name}"))
}

/// Reads the CERTIFICATE blocks of a PEM file. Other labels are skipped.
fn certs(path: &Path) -> Vec<CertificateDer<'static>> {
    let text = fs::read(path).unwrap();
    CertificateDer::pem_slice_iter(&text)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn verdict(ok: bool) -> &'static str {
    if ok { "ACCEPT" } else { "REJECT" }
}

/// Each corpus tag agrees with the verdicts, and no Rust ACCEPT meets an
/// oracle REJECT.
#[test]
fn corpus_verdict_files_are_consistent() {
    for c in cases() {
        let oracle = c.get("oracle");
        assert!(matches!(oracle, "ACCEPT" | "REJECT"), "{}", c.name);
        for (expect, tag) in [("expect", "tag"), ("expect-aws-lc-rs", "tag-aws-lc-rs")] {
            let e = c.get(expect);
            assert!(matches!(e, "ACCEPT" | "REJECT"), "{}", c.name);
            assert!(
                !(e == "ACCEPT" && oracle == "REJECT"),
                "{}: {expect} ACCEPT against an oracle REJECT (unsafe accept)",
                c.name
            );
            let want = if e == oracle { "EXACT" } else { "DV-TLS-3" };
            assert_eq!(c.get(tag), want, "{}: {tag}", c.name);
            if want == "DV-TLS-3" {
                let tc = c.get("tc");
                assert!(
                    DV_TLS_3.iter().any(|d| tc.contains(d)),
                    "{}: {tc} is not a registered DV-TLS-3 case",
                    c.name
                );
            }
        }
        assert!(!c.chain().is_empty(), "{}: empty chain", c.name);
        assert!(c.dir.join("ca.pem").is_file(), "{}: no ca.pem", c.name);
    }
}

/// The verifier gives the expected verdict of each corpus case.
#[test]
fn corpus_verdicts() {
    let provider = default_provider();
    let name = ServerName::try_from("192.0.2.1").unwrap();
    let mut failures = Vec::new();
    for c in cases() {
        let mut trust = TrustSet::default();
        let ca = c.dir.join("ca.pem");
        trust
            .load_ca_file(Some(&LegacyPath::new(ca.as_os_str().as_bytes().to_vec())))
            .unwrap_or_else(|e| panic!("{}: CA file: {e:?}", c.name));
        // The oracle gives SSL_CERT_DIR as "defaults:defaults2" (TC-24).
        for dir in ["defaults", "defaults2"] {
            let defaults = c.dir.join(dir);
            if defaults.is_dir() {
                trust.load_hash_dir(&defaults);
            }
        }
        let verifier = LegacyChainOnly::new(trust, provider.signature_verification_algorithms);
        let chain = c.chain();
        let got = verifier.verify_server_cert(&chain[0], &chain[1..], &name, &[], c.now());
        let v = verdict(got.is_ok());
        if v == "ACCEPT" && c.get("oracle") == "REJECT" {
            failures.push(format!(
                "{}: ACCEPT against an oracle REJECT (unsafe accept)",
                c.name
            ));
        } else if v != c.expect() {
            failures.push(format!(
                "{}: got {v} ({got:?}), expect {} ({})",
                c.name,
                c.expect(),
                c.get("note")
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------
// The webpki component of the chain path.
// ---------------------------------------------------------------------

/// Reads one DER TLV: the tag, the content and the rest.
fn tlv(b: &[u8]) -> (u8, &[u8], &[u8]) {
    let (len, head) = match b[1] {
        n if n < 0x80 => (usize::from(n), 2),
        n => {
            let count = usize::from(n & 0x7f);
            let len = b[2..2 + count]
                .iter()
                .fold(0, |acc, &x| (acc << 8) | usize::from(x));
            (len, 2 + count)
        }
    };
    (b[0], &b[head..head + len], &b[head + len..])
}

/// Tells whether the issuer and subject names of a certificate are equal.
fn self_issued(der: &[u8]) -> bool {
    let (_, cert, _) = tlv(der);
    let (_, mut tbs, _) = tlv(cert);
    if tbs[0] == 0xa0 {
        tbs = tlv(tbs).2;
    }
    let after_serial = tlv(tbs).2;
    let after_alg = tlv(after_serial).2;
    let (_, issuer, rest) = tlv(after_alg);
    let after_validity = tlv(rest).2;
    let (_, subject, _) = tlv(after_validity);
    issuer == subject
}

/// Runs webpki alone, as the chain path runs it. The self-issued trust
/// inputs are the anchors. The other trust inputs and the sent
/// certificates are the intermediates.
fn webpki_alone(c: &Case) -> Result<(), rustls::Error> {
    let mut trust = certs(&c.dir.join("ca.pem"));
    for dir in ["defaults", "defaults2"] {
        let defaults = c.dir.join(dir);
        if defaults.is_dir() {
            for entry in fs::read_dir(&defaults).unwrap() {
                trust.extend(certs(&entry.unwrap().path()));
            }
        }
    }
    let chain = c.chain();
    let mut roots = RootCertStore::empty();
    let mut intermediates = chain[1..].to_vec();
    for der in trust {
        if self_issued(der.as_ref()) {
            roots.add(der).unwrap();
        } else {
            intermediates.push(der);
        }
    }
    let leaf = ParsedCertificate::try_from(&chain[0])?;
    let algs = default_provider().signature_verification_algorithms;
    rustls::client::verify_server_cert_signed_by_trust_anchor(
        &leaf,
        &roots,
        &intermediates,
        c.now(),
        algs.all,
    )
}

/// TC-16: webpki alone accepts a chain through a `CA:TRUE` intermediate
/// whose keyUsage lacks keyCertSign. The keyCertSign post-check exists for
/// this reason. When this test fails, a rustls-webpki change makes the
/// post-check redundant for this case.
#[test]
fn tc16_webpki_accepts_issuer_without_key_cert_sign() {
    let c = case("tc16-noku");
    assert_eq!(c.get("oracle"), "REJECT");
    assert_eq!(c.expect(), "REJECT");
    webpki_alone(&c).expect("webpki accepts the chain");
}

/// TC-44: the chains that webpki alone accepts and the OpenSSL path
/// post-check rejects.
#[test]
fn tc44_webpki_accepts_what_the_post_check_rejects() {
    for name in ["tc16-noku", "tc44b", "tc44c", "tc44d", "tc44e"] {
        let c = case(name);
        assert_eq!(c.get("oracle"), "REJECT", "{name}");
        assert_eq!(c.expect(), "REJECT", "{name}");
        let got = webpki_alone(&c);
        assert!(got.is_ok(), "{name}: webpki rejects: {got:?}");
    }
}

/// The `DV-TLS-3` cases of the chain path where webpki alone rejects and
/// the oracle accepts. In the cases with a leaf key outside the provider
/// set (TC-34, TC-46, TC-54), `leaf_key_usable` rejects and webpki does
/// not.
#[test]
fn dv_tls_3_cases_that_webpki_rejects() {
    let mut names = vec![
        "tc18-dirname",
        "tc35",
        "tc36-leaf",
        "tc36-int",
        "tc37-iap",
        "tc37-pc",
        "tc45-catrue",
        "tc48-ec-sha224",
        "tc48-rsa-sha224",
        "tc52a-v3",
        "tc52b-v3",
        "tc53-case-v3",
        "tc53-print-v3",
        "tc53-space-v3",
    ];
    if cfg!(feature = "tls-ring") {
        names.push("tc48-ec-sha512");
    }
    let mut accepted = Vec::new();
    for name in names {
        let c = case(name);
        assert_eq!(c.get("oracle"), "ACCEPT", "{name}");
        assert_eq!(c.expect(), "REJECT", "{name}");
        if webpki_alone(&c).is_ok() {
            accepted.push(name);
        }
    }
    assert!(accepted.is_empty(), "webpki accepts {accepted:?}");
}

/// webpki alone accepts every chain-path case that the corpus expects to
/// accept. The verdict is an intersection, so this is necessary.
#[test]
fn webpki_accepts_the_path_a_accept_cases() {
    let mut names = vec![
        "tc02-catrue",
        "tc03",
        "tc08",
        "tc10b-anchor-na1",
        "tc10b-int-na1",
        "tc10b-leaf-a-na1",
        "tc10b-leaf-nb",
        "tc14-noeku",
        "tc15",
        "tc20-both",
        "tc24-dir",
        "tc27-order",
        "tc32-v3",
        "tc32-v3-int",
        "tc48-ec-sha256",
        "tc49c-v3",
        "tc51-ed25519",
        "tc51-leaf-in-ca",
    ];
    if !cfg!(feature = "tls-ring") {
        names.extend(["tc34-p521", "tc48-ec-sha512", "tc54-leaf"]);
    }
    for name in names {
        let c = case(name);
        assert_eq!(c.expect(), "ACCEPT", "{name}");
        let got = webpki_alone(&c);
        assert!(got.is_ok(), "{name}: webpki rejects: {got:?}");
    }
}

/// Runs an in-memory handshake of one protocol version with a server
/// fixture of `zk_testkit::fixtures::tls_dir`. The client verifies through
/// [`LegacyChainOnly`] over `ca.pem`. It gives the client result.
#[allow(clippy::large_stack_frames)]
fn handshake(
    server: &str,
    version: &'static rustls::SupportedProtocolVersion,
) -> Result<(), rustls::Error> {
    use std::sync::Arc;

    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

    let dir = zk_testkit::fixtures::tls_dir();
    let provider = default_provider();
    let chain = CertificateDer::pem_file_iter(dir.join(format!("{server}.pem")))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(dir.join(format!("{server}.key"))).unwrap();
    let sc = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let mut trust = TrustSet::default();
    let ca = dir.join("ca.pem");
    trust
        .load_ca_file(Some(&LegacyPath::new(ca.as_os_str().as_bytes().to_vec())))
        .unwrap();
    let verifier = LegacyChainOnly::new(trust, provider.signature_verification_algorithms);
    let cc = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let name = ServerName::try_from("localhost").unwrap();
    let mut client = ClientConnection::new(Arc::new(cc), name).unwrap();
    let mut server = ServerConnection::new(Arc::new(sc)).unwrap();
    for _ in 0..16 {
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut buf.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        buf.clear();
        server.write_tls(&mut buf).unwrap();
        client.read_tls(&mut buf.as_slice()).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() {
            return Ok(());
        }
    }
    panic!("the handshake does not end");
}

/// Rule: on TLS 1.2 an EC or Ed25519 leaf must allow digitalSignature
/// when it has keyUsage, as libssl `ssl_check_srvr_ecc_cert_and_alg`
/// requires. TLS 1.3 has no such rule. `openssl s_client -tls1_2` fails
/// with "ecc cert not for signing" on the `ka-` fixtures and succeeds
/// with `-tls1_3`.
#[test]
fn tls12_ecdsa_leaf_needs_digital_signature() {
    use rustls::version::{TLS12, TLS13};

    let mut servers = vec!["ka-server"];
    if cfg!(not(feature = "tls-aws-lc-rs-fips")) {
        servers.push("ka-ed-server");
    }
    for server in servers {
        let err = handshake(server, &TLS12).expect_err(server);
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::InvalidPurpose)
            ),
            "{server}: {err:?}"
        );
        handshake(server, &TLS13).unwrap_or_else(|e| panic!("{server} TLS 1.3: {e:?}"));
    }
    // The control: a leaf with digitalSignature passes on TLS 1.2.
    handshake("server", &TLS12).unwrap();
}
