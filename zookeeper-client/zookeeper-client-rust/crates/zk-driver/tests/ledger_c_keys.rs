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

//! Tests of the client identity against the key corpus of the
//! conformance suite.
//!
//! `zookeeper-client-rust/c/tests/conformance/tls/keys/cases.tsv` records, for
//! each identity input, the failed step of legacy and of each Rust
//! provider build. `run-keycorpus.sh` runs the rows against both cores.
//! These tests run the rows with fixture inputs against the drop-in
//! connector of this build, and check the tags of the rows. A row whose
//! steps differ must carry a deviation tag. The tag `DV-TLS-2` marks the
//! rows where the OpenSSL policy of legacy refuses an input that the Rust
//! core loads.

#![cfg(all(unix, feature = "tls", feature = "_legacy-keys"))]
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
use std::path::{Path, PathBuf};

use zk_driver::net::tls::connector::{
    LegacyPath, LegacyTlsArgs, RustlsConnector, default_provider,
};
use zk_driver::net::tls::identity::Identity;
use zk_driver::net::tls::{TlsConfigStep, TlsConnector, TlsPurpose, TlsSetupError};
use zk_driver::sync::Unlocked;
use zk_proto::compat::TlsVerify;
use zk_proto::{Endpoint, HostToken, SecretBytes};

use crate::tls_util::fixture;

/// The deviations that a row of the key corpus can carry.
const DEVIATIONS: &[&str] = &["DV-TLS-2", "DV-TLS-5", "DV-FIX-10"];

fn conformance(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../c/tests/conformance")
        .join(rel)
}

fn at(p: &Path) -> LegacyPath {
    LegacyPath::new(p.as_os_str().as_bytes().to_vec())
}

/// One row of `cases.tsv`.
struct Row {
    case: String,
    cert: String,
    legacy: String,
    ring: String,
    aws: String,
    tag: String,
}

fn rows() -> Vec<Row> {
    let path = conformance("tls/keys/cases.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the key corpus needs c/tests/conformance/tls/keys/cases.tsv from the \
             held-back subtree c/tests ({}: {e})",
            path.display()
        )
    });
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert!(f.len() >= 6, "short row: {l}");
            Row {
                case: f[0].to_owned(),
                cert: f[1].to_owned(),
                legacy: f[2].to_owned(),
                ring: f[3].to_owned(),
                aws: f[4].to_owned(),
                tag: f[5].to_owned(),
            }
        })
        .collect()
}

/// The Rust step of this build.
fn expected(r: &Row) -> &str {
    if cfg!(feature = "tls-aws-lc-rs") {
        &r.aws
    } else {
        &r.ring
    }
}

/// The step name of a setup failure, as the corpus writes it.
fn step(res: Result<(), TlsSetupError>) -> &'static str {
    match res {
        Ok(()) => "CONNECT",
        Err(TlsSetupError::Config { step }) => match step {
            TlsConfigStep::CaFile => "CA",
            TlsConfigStep::ClientCertChain => "CERT",
            TlsConfigStep::ClientKey => "KEY",
            TlsConfigStep::CheckPrivateKey => "CHECK",
            other => panic!("unexpected step {other:?}"),
        },
        Err(other) => panic!("not a config error: {other:?}"),
    }
}

/// Runs the setup steps of the drop-in connector for a cert string with
/// only fixture inputs. It gives None for a row with other inputs.
fn run(cert: &str) -> Option<&'static str> {
    if cert.contains("@X") || cert.contains("@LONG") {
        return None;
    }
    let f = fixture("");
    let fields: Vec<PathBuf> = cert
        .split(',')
        .map(|s| PathBuf::from(s.replace("@F/", &format!("{}/", f.display()))))
        .collect();
    let field = |i: usize| fields.get(i).map(|p| at(p));
    let args = LegacyTlsArgs {
        ca: field(0),
        cert: field(1),
        key: field(2),
        passwd: fields
            .get(3)
            .map(|p| SecretBytes::from_slice(p.as_os_str().as_bytes())),
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
    let res = RustlsConnector::legacy(args, default_provider())
        .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &ep)
        .map(drop);
    Some(step(res))
}

/// Each corpus row fails the step that the corpus gives for this build.
#[test]
fn key_corpus_steps_match_this_build() {
    // Rule: the drop-in fails the same setup step as the Rust column of
    // the corpus for this provider. The rows with
    // inputs that run-keycorpus.sh makes are out of scope here.
    let mut ran = 0;
    for r in rows() {
        if let Some(got) = run(&r.cert) {
            assert_eq!(got, expected(&r), "case {}", r.case);
            ran += 1;
        }
    }
    assert!(ran >= 40, "only {ran} rows ran");
}

/// A row whose steps differ between the cores carries a deviation tag.
#[test]
fn rows_where_the_steps_differ_carry_a_deviation() {
    // Rule: a row is EXACT only when legacy and both Rust builds fail
    // the same step. The `DV-TLS-2` rows are the inputs that the OpenSSL
    // policy of legacy refuses: the DES-CBC key and the chain with a SHA-1
    // leaf and an RSA-1024 intermediate. The Rust core loads both.
    let mut dv_tls_2 = Vec::new();
    for r in rows() {
        let same = r.legacy == r.ring && r.legacy == r.aws;
        if r.tag == "EXACT" {
            assert!(same, "case {} differs but is EXACT", r.case);
        } else {
            assert!(DEVIATIONS.contains(&r.tag.as_str()), "case {}", r.case);
        }
        if r.tag == "DV-TLS-2" {
            assert_eq!((r.ring.as_str(), r.aws.as_str()), ("CONNECT", "CONNECT"));
            dv_tls_2.push((r.case, r.legacy));
        }
    }
    assert_eq!(
        dv_tls_2,
        [
            ("trad-des".to_owned(), "KEY".to_owned()),
            ("sha1-rsa1024-chain".to_owned(), "CERT".to_owned()),
        ]
    );
}

/// The client chain loads without an OpenSSL security level check.
#[test]
fn client_chains_are_not_checked_against_a_security_level() {
    // Rule: the client chain loads without an OpenSSL security level
    // check. A chain with a SHA-1-signed leaf, and a chain with an
    // RSA-1024 intermediate, load with their leaf key.
    // The trust corpus has both chains, and legacy at SECLEVEL 2 refuses
    // them.
    let corpus = zk_testkit::fixtures::tls_corpus_dir();
    let key = at(&corpus.join("_keys/leaf.pem"));
    for case in ["tc22-sha1", "tc23-rsa1024-int"] {
        let chain = at(&corpus.join(case).join("chain.pem"));
        let res = Identity::load(
            &chain,
            &key,
            &SecretBytes::from_slice(b""),
            &default_provider(),
        );
        assert!(res.is_ok(), "{case}: {:?}", res.err());
    }
}
