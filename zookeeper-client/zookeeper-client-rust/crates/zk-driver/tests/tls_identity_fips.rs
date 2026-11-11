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

//! Integration tests of the client key formats of the FIPS build. The
//! FIPS build decrypts keys only inside the FIPS module. Thus it rejects
//! the key encryptions that need the RustCrypto crates of the other builds.
//!
//! The fixtures are in `keys/` of `zk_testkit::fixtures::tls_dir`, as in
//! `tls_identity.rs`. Only the `tls-aws-lc-rs-fips` build compiles this
//! file.

#![cfg(all(unix, feature = "tls-aws-lc-rs-fips"))]
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

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use common::fixture;
use zk_driver::net::tls::identity::Identity;
use zk_driver::net::tls::{LegacyPath, TlsConfigStep, TlsSetupError, default_provider};
use zk_proto::SecretBytes;

/// The passphrase of the encrypted fixtures.
const PASS: &[u8] = b"zk-test-pass";

/// Resolves a fixture name. A name with a `keys/` prefix is in `keys/`.
fn named(name: &str) -> LegacyPath {
    let p: PathBuf = match name.strip_prefix("keys/") {
        Some(n) => fixture("keys").join(n),
        None => fixture(name),
    };
    LegacyPath::new(p.as_os_str().as_bytes().to_vec())
}

/// Loads two named fixtures with the fixture passphrase, and gives the
/// failed step.
fn pair(cert: &str, key: &str) -> Result<Identity, TlsConfigStep> {
    Identity::load(
        &named(cert),
        &named(key),
        &SecretBytes::from_slice(PASS),
        &default_provider(),
    )
    .map_err(|e| match e {
        TlsSetupError::Config { step } => step,
        other => panic!("not a config error: {other:?}"),
    })
}

/// The FIPS build loads the key forms that the FIPS module can decrypt.
#[test]
fn fips_build_loads_only_approved_key_forms() {
    for (cert, key) in [
        // Unencrypted PKCS#8, SEC1 and PKCS#1 keys.
        ("client.pem", "client.key"),
        ("client.pem", "keys/client-sec1.pem"),
        ("keys/rsa.pem", "keys/rsa.key"),
        ("keys/rsa.pem", "keys/rsa-pkcs1.pem"),
        // PBES2 with PBKDF2-HMAC-SHA256, -SHA384 or -SHA512 and AES-CBC.
        ("client.pem", "keys/p8-sha256-aes256.pem"),
        ("client.pem", "keys/p8-sha384-aes256.pem"),
        ("client.pem", "keys/p8-sha512-aes128.pem"),
    ] {
        assert!(pair(cert, key).is_ok(), "{cert} {key}");
    }
}

/// The FIPS build rejects the key encryptions that need RustCrypto.
#[test]
fn fips_build_rejects_other_key_encryptions() {
    for key in [
        // Traditional PEM encryption, with any cipher.
        "keys/trad-aes128.pem",
        "keys/trad-aes192.pem",
        "keys/trad-aes256.pem",
        "keys/trad-des3.pem",
        "keys/trad-des.pem",
        // DES-EDE3-CBC, PBKDF2 with HMAC-SHA1 or HMAC-SHA224, and scrypt.
        "keys/p8-des3.pem",
        "keys/p8-sha1-aes128.pem",
        "keys/p8-sha224-aes192.pem",
        "keys/p8-scrypt.pem",
    ] {
        assert_eq!(
            pair("client.pem", key).err(),
            Some(TlsConfigStep::ClientKey),
            "{key}"
        );
    }
    assert_eq!(
        pair("keys/rsa.pem", "keys/rsa-trad-aes256.pem").err(),
        Some(TlsConfigStep::ClientKey)
    );
}
