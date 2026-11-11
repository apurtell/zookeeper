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

//! Integration tests of the client identity: the key formats, the PBES2
//! bounds, the chain-file rule, the key and certificate pair rule, and
//! the order of the setup steps.
//!
//! The fixtures are in `keys/` of `zk_testkit::fixtures::tls_dir`. The
//! script `tests/fixtures/tls/gen.sh keys` makes them at test time. The
//! passphrase of each encrypted fixture is `zk-test-pass`. The tests need
//! the key-decryption crates, so the FIPS build does not run them.

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

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use common::fixture;
use common::tls::{TlsAcceptor, legacy_path};
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::der::Encode as _;
use pkcs8::pkcs5::pbes2::{self, EncryptionScheme, Kdf, Pbkdf2Params, Pbkdf2Prf, ScryptParams};
use zk_driver::Unlocked;
use zk_driver::net::tls::identity::{
    Identity, KeyError, MAX_PASSPHRASE, check_pbes2_params, decrypt_pkcs8,
};
use zk_driver::net::tls::{
    LegacyPath, LegacyTlsArgs, RustlsConnector, TlsConfigStep, TlsConn, TlsConnector, TlsFailure,
    TlsPurpose, TlsSetupError, default_provider,
};
use zk_fakeserver::{ClusterConfig, FakeServer, ServerOptions};
use zk_proto::compat::TlsVerify;
use zk_proto::{Endpoint, HostToken, SecretBytes};

/// The passphrase of the encrypted fixtures.
const PASS: &[u8] = b"zk-test-pass";

/// A path to a fixture in `keys/`.
fn key_path(name: &str) -> LegacyPath {
    at(fixture("keys").join(name))
}

fn at(p: PathBuf) -> LegacyPath {
    LegacyPath::new(p.as_os_str().as_bytes().to_vec())
}

/// Resolves a fixture name. A name with a `keys/` prefix is in `keys/`.
fn named(name: &str) -> LegacyPath {
    match name.strip_prefix("keys/") {
        Some(n) => key_path(n),
        None => legacy_path(name),
    }
}

/// Runs `Identity::load` and gives the failed step.
fn load(cert: &LegacyPath, key: &LegacyPath, pass: &[u8]) -> Result<Identity, TlsConfigStep> {
    Identity::load(
        cert,
        key,
        &SecretBytes::from_slice(pass),
        &default_provider(),
    )
    .map_err(|e| match e {
        TlsSetupError::Config { step } => step,
        other => panic!("not a config error: {other:?}"),
    })
}

/// Loads two named fixtures with the fixture passphrase.
fn pair(cert: &str, key: &str) -> Result<Identity, TlsConfigStep> {
    load(&named(cert), &named(key), PASS)
}

/// Writes a file into the private test directory and gives its path.
fn scratch(name: &str, body: &[u8]) -> LegacyPath {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tls_identity-{}-{name}", std::process::id()));
    std::fs::write(&p, body).unwrap();
    at(p)
}

/// The PKCS#8 DER of `client.key`.
fn client_pkcs8() -> Vec<u8> {
    common::tls::key("client.key").secret_der().to_vec()
}

/// Encrypts `client.key` with PBKDF2-SHA256 and AES-256-CBC, and gives
/// the `ENCRYPTED PRIVATE KEY` PEM text.
fn encrypted_client_key(pass: &[u8]) -> String {
    let salt = [7u8; 16];
    let iv = [9u8; 16];
    let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(1000, &salt, &iv).unwrap();
    let data = params.encrypt(pass, &client_pkcs8()).unwrap();
    let der = EncryptedPrivateKeyInfo {
        encryption_algorithm: params.into(),
        encrypted_data: &data,
    }
    .to_der()
    .unwrap();
    pem_rfc7468::encode_string("ENCRYPTED PRIVATE KEY", pem_rfc7468::LineEnding::LF, &der).unwrap()
}

/// The DER of an `EncryptedPrivateKeyInfo` with these parameters and a
/// placeholder ciphertext.
fn info_der(params: pbes2::Parameters<'_>) -> Vec<u8> {
    info_der_with(params, &[0u8; 32])
}

fn info_der_with(params: pbes2::Parameters<'_>, data: &[u8]) -> Vec<u8> {
    EncryptedPrivateKeyInfo {
        encryption_algorithm: params.into(),
        encrypted_data: data,
    }
    .to_der()
    .unwrap()
}

const SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const IV: [u8; 16] = [3u8; 16];

fn scrypt_der(n: u64, r: u16, p: u16, key_length: Option<u16>) -> Vec<u8> {
    info_der(pbes2::Parameters {
        kdf: Kdf::Scrypt(ScryptParams {
            salt: &SALT,
            cost_parameter: n,
            block_size: r,
            parallelization: p,
            key_length,
        }),
        encryption: EncryptionScheme::Aes256Cbc { iv: &IV },
    })
}

fn pbkdf2_der(iterations: u32, prf: Pbkdf2Prf, key_length: Option<u16>) -> Vec<u8> {
    info_der(pbes2::Parameters {
        kdf: Kdf::Pbkdf2(Pbkdf2Params {
            salt: &SALT,
            iteration_count: iterations,
            key_length,
            prf,
        }),
        encryption: EncryptionScheme::Aes128Cbc { iv: &IV },
    })
}

// Key formats.

/// The unencrypted PKCS#8, SEC1 and PKCS#1 keys load with any passphrase.
#[test]
fn unencrypted_key_forms_load() {
    for (cert, key) in [
        ("client.pem", "client.key"),
        ("client.pem", "keys/client-sec1.pem"),
        ("keys/rsa.pem", "keys/rsa.key"),
        ("keys/rsa.pem", "keys/rsa-pkcs1.pem"),
        ("keys/ed25519.pem", "keys/ed25519.key"),
    ] {
        assert!(pair(cert, key).is_ok(), "{cert} {key}");
        // An unencrypted key ignores the passphrase.
        assert!(load(&named(cert), &named(key), b"").is_ok(), "{cert} {key}");
        assert!(
            load(&named(cert), &named(key), b"wrong").is_ok(),
            "{cert} {key}"
        );
    }
}

/// The accepted encrypted key forms load with the right passphrase.
#[test]
fn encrypted_key_forms_load() {
    for key in [
        "p8-sha256-aes256.pem",
        "p8-sha1-aes128.pem",
        "p8-sha224-aes192.pem",
        "p8-sha384-aes256.pem",
        "p8-sha512-aes128.pem",
        "p8-des3.pem",
        "p8-scrypt.pem",
        "trad-aes128.pem",
        "trad-aes192.pem",
        "trad-aes256.pem",
        "trad-des3.pem",
        "trad-des.pem",
    ] {
        assert!(
            load(&legacy_path("client.pem"), &key_path(key), PASS).is_ok(),
            "{key}"
        );
    }
    assert!(pair("keys/rsa.pem", "keys/rsa-trad-aes256.pem").is_ok());
}

/// A key scheme or key type outside the accepted set fails the key step.
#[test]
fn rejected_schemes_and_key_types_fail_the_key_step() {
    for key in [
        // PRF, PBES1 and cipher outside the accepted set.
        "keys/p8-sha512-256.pem",
        "keys/p8-pkcs12.pem",
        "keys/p8-camellia.pem",
        "keys/trad-cfb.pem",
        "keys/trad-camellia.pem",
        // Key types that no provider signs with.
        "keys/dsa.key",
        "keys/dsa-trad.pem",
        "keys/ed448.key",
        "keys/rsa-pss.key",
        "keys/rsa1024.key",
        // A file without a key block.
        "client.pem",
        "absent.key",
    ] {
        assert_eq!(
            pair("client.pem", key).err(),
            Some(TlsConfigStep::ClientKey),
            "{key}"
        );
    }
}

#[test]
fn wrong_passphrase_fails_the_key_step() {
    for key in [
        "p8-sha256-aes256.pem",
        "p8-scrypt.pem",
        "trad-aes256.pem",
        "trad-des3.pem",
    ] {
        for pass in [&b""[..], b"zk-test-pas", b"zk-test-pass!"] {
            assert_eq!(
                load(&legacy_path("client.pem"), &key_path(key), pass).err(),
                Some(TlsConfigStep::ClientKey),
                "{key}"
            );
        }
    }
}

/// The passphrase is cut to `PEM_BUFSIZE` bytes, as OpenSSL does.
#[test]
fn passphrase_is_cut_to_the_first_1024_bytes() {
    let long: Vec<u8> = (0..1500u32).map(|i| b'a' + (i % 26) as u8).collect();
    let key = scratch(
        "long-pass.pem",
        encrypted_client_key(&long[..MAX_PASSPHRASE]).as_bytes(),
    );
    let cert = legacy_path("client.pem");
    // OpenSSL reads at most 1024 bytes of the passphrase.
    assert!(load(&cert, &key, &long).is_ok());
    assert!(load(&cert, &key, &long[..MAX_PASSPHRASE]).is_ok());
    assert_eq!(
        load(&cert, &key, &long[..MAX_PASSPHRASE - 1]).err(),
        Some(TlsConfigStep::ClientKey)
    );
    // The library function takes the passphrase as given.
    let pem = encrypted_client_key(b"pw");
    let (_, der) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
    assert_eq!(decrypt_pkcs8(&der, b"pw").unwrap().expose(), client_pkcs8());
    assert!(decrypt_pkcs8(&der, b"pw2").is_err());
}

#[test]
fn key_file_may_start_with_a_certificate() {
    let both = key_path("cert-then-key.pem");
    assert!(load(&both, &both, b"").is_ok());
    assert!(load(&legacy_path("client.pem"), &both, b"").is_ok());
}

// Traditional PEM headers (DEK-Info).

/// Rewrites the header lines of `trad-aes128.pem`.
fn trad_with(name: &str, edit: impl Fn(&str) -> String) -> LegacyPath {
    let text = std::fs::read_to_string(fixture("keys/trad-aes128.pem")).unwrap();
    scratch(name, edit(&text).as_bytes())
}

fn dek_iv(text: &str) -> String {
    let line = text.lines().find(|l| l.starts_with("DEK-Info:")).unwrap();
    line.split_once(',').unwrap().1.to_owned()
}

#[test]
fn dek_info_headers_follow_the_openssl_rule() {
    let cert = legacy_path("client.pem");
    // The cipher name ignores case.
    let lower = trad_with("dek-lower.pem", |t| t.replace("AES-128-CBC", "aes-128-cbc"));
    assert!(load(&cert, &lower, PASS).is_ok());
    // Proc-Type comes first and DEK-Info second.
    let swapped = trad_with("dek-swapped.pem", |t| {
        let proc_type = t.lines().find(|l| l.starts_with("Proc-Type:")).unwrap();
        let dek = t.lines().find(|l| l.starts_with("DEK-Info:")).unwrap();
        t.replace(
            &format!("{proc_type}\n{dek}"),
            &format!("{dek}\n{proc_type}"),
        )
    });
    // The IV has exactly one hex pair for each IV byte.
    let short_iv = trad_with("dek-short-iv.pem", |t| {
        let iv = dek_iv(t);
        t.replace(&iv, &iv[..30])
    });
    let bad_hex = trad_with("dek-bad-hex.pem", |t| {
        let iv = dek_iv(t);
        t.replace(&iv, &format!("{}zz", &iv[..30]))
    });
    let unknown = trad_with("dek-unknown.pem", |t| {
        t.replace("AES-128-CBC", "AES-128-XTS")
    });
    let no_dek = trad_with("dek-missing.pem", |t| {
        let dek = t.lines().find(|l| l.starts_with("DEK-Info:")).unwrap();
        t.replace(&format!("{dek}\n"), "")
    });
    for key in [swapped, short_iv, bad_hex, unknown, no_dek] {
        assert_eq!(
            load(&cert, &key, PASS).err(),
            Some(TlsConfigStep::ClientKey),
            "{:?}",
            String::from_utf8_lossy(key.raw())
        );
    }
}

// PBES2 parameter bounds.

#[test]
fn scrypt_parameters_are_bounded() {
    // 128·r·(N + 2) + 128·r·p is at most 32 MiB.
    assert_eq!(check_pbes2_params(&scrypt_der(16384, 8, 1, None)), Ok(()));
    assert_eq!(
        check_pbes2_params(&scrypt_der(32768, 8, 1, None)),
        Err(KeyError::Bounds)
    );
    assert_eq!(
        check_pbes2_params(&scrypt_der(16384, 8, 20000, None)),
        Err(KeyError::Bounds)
    );
    // N is a power of two greater than 1, and log2 N < 16·r.
    for n in [0, 1, 3, 1000, 1 << 63, u64::MAX] {
        assert_eq!(
            check_pbes2_params(&scrypt_der(n, 8, 1, None)),
            Err(KeyError::Bounds),
            "{n}"
        );
    }
    assert_eq!(
        check_pbes2_params(&scrypt_der(1 << 16, 1, 1, None)),
        Err(KeyError::Bounds)
    );
    assert_eq!(check_pbes2_params(&scrypt_der(1 << 15, 1, 1, None)), Ok(()));
    // r and p are positive, and r·p < 2^30.
    assert_eq!(
        check_pbes2_params(&scrypt_der(1024, 0, 1, None)),
        Err(KeyError::Bounds)
    );
    assert_eq!(
        check_pbes2_params(&scrypt_der(1024, 8, 0, None)),
        Err(KeyError::Bounds)
    );
    assert_eq!(
        check_pbes2_params(&scrypt_der(2, u16::MAX, u16::MAX, None)),
        Err(KeyError::Bounds)
    );
    // An explicit key length equals the cipher key length.
    assert_eq!(
        check_pbes2_params(&scrypt_der(1024, 8, 1, Some(32))),
        Ok(())
    );
    assert_eq!(
        check_pbes2_params(&scrypt_der(1024, 8, 1, Some(16))),
        Err(KeyError::Bounds)
    );
}

#[test]
fn pbkdf2_parameters_are_bounded() {
    for prf in [
        Pbkdf2Prf::HmacWithSha1,
        Pbkdf2Prf::HmacWithSha224,
        Pbkdf2Prf::HmacWithSha256,
        Pbkdf2Prf::HmacWithSha384,
        Pbkdf2Prf::HmacWithSha512,
    ] {
        assert_eq!(
            check_pbes2_params(&pbkdf2_der(1, prf, None)),
            Ok(()),
            "{prf:?}"
        );
    }
    assert_eq!(
        check_pbes2_params(&pbkdf2_der(0, Pbkdf2Prf::HmacWithSha256, None)),
        Err(KeyError::Bounds)
    );
    assert_eq!(
        check_pbes2_params(&pbkdf2_der(1, Pbkdf2Prf::HmacWithSha256, Some(16))),
        Ok(())
    );
    assert_eq!(
        check_pbes2_params(&pbkdf2_der(1, Pbkdf2Prf::HmacWithSha256, Some(32))),
        Err(KeyError::Bounds)
    );
    // A bounds failure stops the decryption before the key derivation.
    let der = pbkdf2_der(0, Pbkdf2Prf::HmacWithSha256, None);
    assert_eq!(decrypt_pkcs8(&der, PASS).err(), Some(KeyError::Bounds));
}

#[test]
fn malformed_encrypted_keys_are_rejected() {
    assert_eq!(check_pbes2_params(b""), Err(KeyError::Rejected));
    assert_eq!(
        check_pbes2_params(&[0x30, 0x03, 1, 2, 3]),
        Err(KeyError::Rejected)
    );
    assert_eq!(
        decrypt_pkcs8(&[0x30, 0x80], PASS).err(),
        Some(KeyError::Rejected)
    );
    // A PBES1 scheme is not PBES2.
    let text = std::fs::read(fixture("keys/p8-pkcs12.pem")).unwrap();
    let (_, der) = pem_rfc7468::decode_vec(&text).unwrap();
    assert_eq!(check_pbes2_params(&der), Err(KeyError::Rejected));
    // A ciphertext that is not whole blocks is a bad passphrase.
    let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(1, &SALT, &IV).unwrap();
    for len in [0, 15, 31] {
        let der = info_der_with(params.clone(), &vec![0u8; len]);
        assert_eq!(
            decrypt_pkcs8(&der, PASS).err(),
            Some(KeyError::BadPassphrase),
            "{len}"
        );
    }
}

// The chain file (SSL_CTX_use_certificate_chain_file).

fn chain_len(cert: &str) -> usize {
    pair(cert, "client.key").unwrap().certified_key().cert.len()
}

/// The chain file gives the leaf and its extra certificates, as OpenSSL
/// reads them.
#[test]
fn chain_file_rule() {
    let client = common::tls::certs("client.pem");
    let ca = common::tls::certs("ca.pem");
    assert_eq!(chain_len("client.pem"), 1);
    assert_eq!(chain_len("keys/chain.pem"), 2);
    // A TRUSTED CERTIFICATE block after the leaf is skipped.
    assert_eq!(chain_len("keys/chain-trusted-later.pem"), 1);
    // A TRUSTED CERTIFICATE leaf drops its aux data.
    let id = pair("keys/trusted.pem", "client.key").unwrap();
    assert_eq!(id.certified_key().cert, client);
    let id = pair("keys/trusted-chain.pem", "client.key").unwrap();
    assert_eq!(id.certified_key().cert, [client[0].clone(), ca[0].clone()]);
    // A version 1 leaf loads.
    assert_eq!(chain_len("keys/v1.pem"), 1);
    // No certificate, a missing file, or a bad body fail the chain step.
    let bad = scratch(
        "bad-body.pem",
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    );
    let junk = scratch(
        "bad-base64.pem",
        b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    );
    for cert in [
        legacy_path("client.key"),
        legacy_path("absent.pem"),
        bad,
        junk,
    ] {
        assert_eq!(
            load(&cert, &legacy_path("client.key"), b"").err(),
            Some(TlsConfigStep::ClientCertChain),
            "{:?}",
            String::from_utf8_lossy(cert.raw())
        );
    }
}

// The key and certificate pair (SSL_CTX_check_private_key).

/// A key of the leaf type with another public key fails the key step.
#[test]
fn same_type_mismatch_fails_the_key_step() {
    for (cert, key) in [
        ("client.pem", "server.key"),
        ("client.pem", "keys/p384.key"),
        // The same key, with the point in compressed form in the leaf.
        ("keys/compressed.pem", "client.key"),
        ("keys/rsa.pem", "keys/rsa-e3.key"),
        ("keys/rsa-e3.pem", "keys/rsa.key"),
    ] {
        assert_eq!(
            pair(cert, key).err(),
            Some(TlsConfigStep::ClientKey),
            "{cert} {key}"
        );
    }
}

/// A key of another type than the leaf fails the check step.
#[test]
fn other_type_mismatch_fails_the_check_step() {
    for (cert, key) in [
        ("client.pem", "keys/ed25519.key"),
        ("client.pem", "keys/rsa.key"),
        ("keys/rsa.pem", "client.key"),
        ("keys/ed25519.pem", "client.key"),
        // An RSA-PSS leaf has another key slot than an RSA key.
        ("keys/rsa-pss.pem", "keys/rsa.key"),
    ] {
        assert_eq!(
            pair(cert, key).err(),
            Some(TlsConfigStep::CheckPrivateKey),
            "{cert} {key}"
        );
    }
}

// Keys that the two providers treat differently.

#[test]
fn provider_key_support() {
    // ring signs with P-256, P-384, Ed25519 and RSA keys of 2048 to 4096
    // bits with a public exponent of at least 65537.
    #[cfg(feature = "tls-ring")]
    let want: [(&str, &str, Option<TlsConfigStep>); 5] = [
        (
            "keys/p521.pem",
            "keys/p521.key",
            Some(TlsConfigStep::ClientKey),
        ),
        (
            "keys/rsa6144.pem",
            "keys/rsa6144.key",
            Some(TlsConfigStep::ClientKey),
        ),
        (
            "keys/rsa-e3.pem",
            "keys/rsa-e3.key",
            Some(TlsConfigStep::ClientKey),
        ),
        (
            "client.pem",
            "keys/client-sec1-nopub.pem",
            Some(TlsConfigStep::ClientKey),
        ),
        (
            "client.pem",
            "keys/client-explicit.pem",
            Some(TlsConfigStep::ClientKey),
        ),
    ];
    // aws-lc-rs also signs with these keys, as OpenSSL does.
    #[cfg(not(feature = "tls-ring"))]
    let want: [(&str, &str, Option<TlsConfigStep>); 5] = [
        ("keys/p521.pem", "keys/p521.key", None),
        ("keys/rsa6144.pem", "keys/rsa6144.key", None),
        ("keys/rsa-e3.pem", "keys/rsa-e3.key", None),
        ("client.pem", "keys/client-sec1-nopub.pem", None),
        ("client.pem", "keys/client-explicit.pem", None),
    ];
    for (cert, key, step) in want {
        assert_eq!(pair(cert, key).err(), step, "{cert} {key}");
    }
}

// The setup steps of the connector.

struct Args {
    ca: Option<&'static str>,
    cert: Option<&'static str>,
    key: Option<&'static str>,
    passwd: Option<&'static [u8]>,
    verify: TlsVerify,
}

impl Args {
    fn identity(cert: &'static str, key: &'static str) -> Self {
        Self {
            ca: Some("ca.pem"),
            cert: Some(cert),
            key: Some(key),
            passwd: Some(PASS),
            verify: TlsVerify::LegacyChainOnly,
        }
    }

    fn connector(&self) -> RustlsConnector {
        let args = LegacyTlsArgs {
            ca: self.ca.map(named),
            cert: self.cert.map(named),
            key: self.key.map(named),
            passwd: self.passwd.map(SecretBytes::from_slice),
            env_allowed: false,
            verify: self.verify,
        };
        RustlsConnector::legacy(args, default_provider())
    }
}

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint {
        addr,
        host: HostToken {
            index: 0,
            name: b"127.0.0.1".to_vec(),
        },
    }
}

fn new_conn(c: &RustlsConnector, addr: SocketAddr) -> Result<Box<dyn TlsConn>, TlsSetupError> {
    c.new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &endpoint(addr))
}

fn setup_step(args: &Args) -> Option<TlsConfigStep> {
    let c = args.connector();
    match new_conn(&c, "127.0.0.1:1".parse().unwrap()) {
        Ok(_) => None,
        Err(TlsSetupError::Config { step }) => {
            let want = match step {
                TlsConfigStep::CaFile => args.ca.map(named),
                TlsConfigStep::ClientCertChain => args.cert.map(named),
                TlsConfigStep::ClientKey => args.key.map(named),
                TlsConfigStep::DefaultVerifyPaths | TlsConfigStep::CheckPrivateKey => None,
            };
            assert_eq!(c.path_for(step), want.as_ref().map(LegacyPath::raw));
            Some(step)
        }
        Err(other) => panic!("not a config error: {other:?}"),
    }
}

/// The setup steps run in the legacy order, and the first failure ends
/// the setup.
#[test]
fn setup_steps_run_in_order() {
    for verify in [TlsVerify::LegacyChainOnly, TlsVerify::WebPki] {
        let all_absent = Args {
            ca: Some("absent-ca.pem"),
            cert: Some("absent.pem"),
            key: Some("absent.key"),
            passwd: Some(PASS),
            verify,
        };
        assert_eq!(setup_step(&all_absent), Some(TlsConfigStep::CaFile));
        let chain_and_key = Args {
            ca: Some("ca.pem"),
            ..all_absent
        };
        assert_eq!(
            setup_step(&chain_and_key),
            Some(TlsConfigStep::ClientCertChain)
        );
        let key = Args {
            cert: Some("client.pem"),
            ..chain_and_key
        };
        assert_eq!(setup_step(&key), Some(TlsConfigStep::ClientKey));
        let check = Args {
            key: Some("keys/rsa.key"),
            ..key
        };
        assert_eq!(setup_step(&check), Some(TlsConfigStep::CheckPrivateKey));
        let ok = Args {
            key: Some("keys/p8-scrypt.pem"),
            ..check
        };
        assert_eq!(setup_step(&ok), None);
    }
}

/// The identity loads only when both cert and key are set.
#[test]
fn identity_needs_cert_and_key() {
    // Without cert or key no identity loads, so the missing files of the
    // other fields do not fail the setup.
    for (cert, key, passwd) in [
        (Some("absent.pem"), None, None),
        (Some("absent.pem"), None, Some(PASS)),
        (None, Some("absent.key"), Some(PASS)),
        (None, None, Some(PASS)),
    ] {
        let args = Args {
            ca: Some("ca.pem"),
            cert,
            key,
            passwd,
            verify: TlsVerify::LegacyChainOnly,
        };
        assert_eq!(setup_step(&args), None, "{cert:?} {key:?} {passwd:?}");
    }
    // Without passwd the identity loads with an empty passphrase, so the
    // missing chain file fails its step. Legacy drops the identity here.
    let args = Args {
        ca: Some("ca.pem"),
        cert: Some("absent.pem"),
        key: Some("absent.key"),
        passwd: None,
        verify: TlsVerify::LegacyChainOnly,
    };
    assert_eq!(setup_step(&args), Some(TlsConfigStep::ClientCertChain));
}

// Handshakes with client authentication.

fn tls_server(client_auth: bool) -> FakeServer {
    let opts = ServerOptions {
        acceptor: Some(TlsAcceptor::new(client_auth)),
        ..ServerOptions::default()
    };
    FakeServer::start_with(ClusterConfig::default(), opts).unwrap()
}

/// Runs the handshake over a blocking socket.
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

/// Sends the `isro` probe and gives the plaintext before the latched
/// failure. A server that rejects the client certificate sends an alert
/// in place of the answer.
fn isro(tcp: &mut TcpStream, tls: &mut dyn TlsConn) -> (Vec<u8>, TlsFailure) {
    tls.write_frame(b"isro").unwrap();
    let mut out = Vec::new();
    tls.take_ciphertext(&mut out);
    tcp.write_all(&out).unwrap();
    let mut buf = [0u8; 4096];
    let mut plain = Vec::new();
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
                Err(f) => return (plain, f),
            }
        }
        if let Err(f) = fed {
            return (plain, f);
        }
    }
}

/// Connects with the identity and sends the probe. A frame round trip
/// proves that the server accepted the identity.
fn probe(server: &FakeServer, args: &Args) -> Result<(Vec<u8>, TlsFailure), TlsFailure> {
    let c = args.connector();
    let mut tls = new_conn(&c, server.addr()).unwrap();
    let mut tcp = TcpStream::connect(server.addr()).unwrap();
    tcp.set_read_timeout(Some(common::WAIT)).unwrap();
    handshake(&mut tcp, tls.as_mut())?;
    Ok(isro(&mut tcp, tls.as_mut()))
}

#[test]
fn loaded_identities_satisfy_client_auth() {
    let server = tls_server(true);
    for (cert, key) in [
        ("client.pem", "keys/p8-sha256-aes256.pem"),
        ("client.pem", "keys/p8-scrypt.pem"),
        ("client.pem", "keys/p8-des3.pem"),
        ("client.pem", "keys/trad-des3.pem"),
        ("client.pem", "keys/client-sec1.pem"),
        ("keys/trusted.pem", "client.key"),
        ("keys/chain.pem", "client.key"),
        ("keys/cert-then-key.pem", "keys/cert-then-key.pem"),
        ("keys/rsa.pem", "keys/rsa-trad-aes256.pem"),
        ("keys/rsa.pem", "keys/rsa-pkcs1.pem"),
        ("keys/ed25519.pem", "keys/ed25519.key"),
    ] {
        assert_eq!(
            probe(&server, &Args::identity(cert, key)),
            Ok((b"rw".to_vec(), TlsFailure::Closed)),
            "{cert} {key}"
        );
    }
}

#[test]
fn missing_identity_fails_client_auth() {
    let server = tls_server(true);
    let args = Args {
        cert: None,
        ..Args::identity("client.pem", "client.key")
    };
    let got = probe(&server, &args);
    assert_ne!(got, Ok((b"rw".to_vec(), TlsFailure::Closed)), "{got:?}");
}

/// An identity without passwd passes client auth at the server.
#[test]
fn identity_without_passwd_passes_client_auth() {
    // An unencrypted key needs no passwd.
    let server = tls_server(true);
    let args = Args {
        passwd: None,
        ..Args::identity("client.pem", "client.key")
    };
    assert_eq!(
        probe(&server, &args),
        Ok((b"rw".to_vec(), TlsFailure::Closed))
    );
}

/// Reads the unencrypted RSA key fixture into a stack buffer. The key
/// text stays out of the heap, so only the PEM reader can put it there.
/// A key that fills the buffer is an error, because it can be cut short.
fn read_rsa_pkcs1(buf: &mut [u8; 4096]) -> &[u8] {
    let path = zk_testkit::fixtures::tls_dir().join("keys/rsa-pkcs1.pem");
    let mut file = std::fs::File::open(&path).expect("keys/rsa-pkcs1.pem");
    let mut len = 0;
    loop {
        let n = file.read(&mut buf[len..]).expect("read keys/rsa-pkcs1.pem");
        if n == 0 {
            break;
        }
        len += n;
        assert!(len < buf.len(), "keys/rsa-pkcs1.pem fills the stack buffer");
    }
    &buf[..len]
}

/// Rule: no freed heap block holds key text after the PEM reader runs,
/// on success and on failure. `zk-client/tests/
/// free_scan/free_scan.sh` runs this test with the free scanner. Each
/// cache entry has a new key, so the marker is not fixed. The script and
/// this test use the same rule: the marker is the first 24 characters of
/// line 3 of `keys/rsa-pkcs1.pem`. The scanner removes the marker from
/// the environment, so the test takes it from the key. A heap copy of
/// the marker is the control buffer.
#[test]
#[ignore = "free-scan"]
fn pem_buffers_are_zero_before_free() {
    use zk_driver::net::tls::pem;
    // Without the scanner the test has nothing to check.
    let Some(out) = std::env::var_os("ZK_FREE_SCAN_OUT") else {
        return;
    };
    let hits = || {
        std::fs::read_to_string(&out)
            .map(|t| t.lines().filter(|l| l.starts_with("hit")).count())
            .unwrap_or(0)
    };
    let mut buf = [0u8; 4096];
    let key = read_rsa_pkcs1(&mut buf);
    let marker = key
        .split(|&b| b == b'\n')
        .nth(2)
        .and_then(|line| line.get(..24))
        .expect("keys/rsa-pkcs1.pem has a base64 line 3");
    drop(std::hint::black_box(marker.to_vec()));
    let control = hits();
    assert!(
        control >= 1,
        "the free scanner does not run, or its marker is not the start of \
         line 3 of keys/rsa-pkcs1.pem"
    );

    assert_eq!(pem::read_blocks(key).expect("blocks").len(), 1);
    // The same text without its END line fails after the reader copies
    // the whole body.
    let end = key
        .windows(9)
        .rposition(|w| w == b"-----END ")
        .expect("END line");
    assert!(pem::read_blocks(&key[..end]).is_err());
    assert!(pair("keys/rsa.pem", "keys/rsa-pkcs1.pem").is_ok());
    assert_eq!(hits(), control, "a freed block holds key text");
}
