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

//! Checks the private-key decoders of the drop-in TLS layer.
//!
//! The input is a passphrase and a key file image. The target decrypts
//! each traditional encrypted PEM block and each PKCS#8 encrypted key.
//! Then it loads the image as the key file and the certificate file of
//! a client identity.
//!
//! The product bounds the scrypt memory but not the PBKDF2 iterations.
//! A key file is local configuration, so a slow key is not a defect. The
//! target skips the key derivation for costly parameters, so that each
//! run stays fast.

#![no_main]
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use pkcs5::pbes2::Kdf;
use pkcs8::EncryptedPrivateKeyInfo;
use zk_driver::net::tls::identity::{self, Identity, MAX_PASSPHRASE};
use zk_driver::net::tls::pem::{self, PemKind};
use zk_driver::net::tls::{LegacyPath, default_provider, legacy_pem};
use zk_fuzz::Cursor;
use zk_proto::SecretBytes;

/// The most PBKDF2 iterations that the target runs.
const MAX_ITERATIONS: u32 = 2048;
/// The most scrypt work, as `N * r * p`, that the target runs.
const MAX_SCRYPT_WORK: u64 = 1 << 13;

/// Tells whether the key derivation of a PKCS#8 encrypted key is cheap.
/// An input that does not parse is cheap, because no derivation runs.
fn cheap(der: &[u8]) -> bool {
    let Ok(info) = EncryptedPrivateKeyInfo::try_from(der) else {
        return true;
    };
    let Some(params) = info.encryption_algorithm.pbes2() else {
        return true;
    };
    match &params.kdf {
        Kdf::Pbkdf2(p) => p.iteration_count <= MAX_ITERATIONS,
        Kdf::Scrypt(p) => {
            let work = p
                .cost_parameter
                .checked_mul(u64::from(p.block_size))
                .and_then(|w| w.checked_mul(u64::from(p.parallelization)));
            work.is_some_and(|w| w <= MAX_SCRYPT_WORK)
        }
        _ => true,
    }
}

/// Decrypts one PKCS#8 encrypted key when the cost is low. The parameter
/// check must agree with the decryption.
fn pkcs8(der: &[u8], pass: &[u8]) {
    let pass = pass.get(..MAX_PASSPHRASE).unwrap_or(pass);
    match identity::check_pbes2_params(der) {
        Err(e) => {
            let got = identity::decrypt_pkcs8(der, pass).err();
            assert_eq!(got, Some(e), "the check and the decryption disagree");
        }
        Ok(()) if cheap(der) => {
            if let Ok(plain) = identity::decrypt_pkcs8(der, pass) {
                assert!(
                    plain.expose().len() <= der.len(),
                    "the plaintext is longer than the input"
                );
            }
        }
        Ok(()) => {}
    }
}

/// Gives a file name that is private to this process.
fn scratch() -> &'static PathBuf {
    static F: OnceLock<PathBuf> = OnceLock::new();
    F.get_or_init(|| {
        std::env::temp_dir().join(format!("zk-fuzz-tls-keys-{}.pem", std::process::id()))
    })
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let pass = c.lp();
    let image = c.rest();

    // The image as raw DER.
    pkcs8(image, pass);

    let mut all_cheap = cheap(image);
    if let Ok(blocks) = pem::read_blocks(image) {
        for block in &blocks {
            let body = block.body.expose();
            if legacy_pem::is_encrypted(block)
                && let Ok(plain) = legacy_pem::decrypt(block, pass)
            {
                assert!(
                    plain.expose().len() <= body.len(),
                    "CBC plaintext is longer than the input"
                );
            }
            if pem::classify_label(&block.label) == PemKind::EncryptedPkcs8Key {
                all_cheap &= cheap(body);
                pkcs8(body, pass);
            }
        }
    }

    // The image as the key file and the certificate file of an identity.
    if !all_cheap {
        return;
    }
    let path = scratch();
    if std::fs::write(path, image).is_ok() {
        let p = LegacyPath::new(path.as_os_str().as_encoded_bytes().to_vec());
        let secret = SecretBytes::new(pass.to_vec());
        let provider = default_provider();
        if let Ok(id) = Identity::load(&p, &p, &secret, &provider) {
            assert!(
                !id.certified_key().cert.is_empty(),
                "an identity has a certificate"
            );
        }
        // The file holds key material, so no input leaves it behind.
        let _ = std::fs::remove_file(path);
    }
});
