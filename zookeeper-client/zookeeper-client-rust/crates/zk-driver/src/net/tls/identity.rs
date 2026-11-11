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

//! Client chain and private-key loading.
//!
//! [`Identity::load`] runs the three identity steps of
//! `init_ssl_for_socket` in legacy order: `ClientCertChain`, `ClientKey`
//! and `CheckPrivateKey`. The connector calls it only when cert, key and
//! passwd are all set.
//!
//! - The chain: the first `CERTIFICATE`, `X509 CERTIFICATE` or
//!   `TRUSTED CERTIFICATE` block is the leaf, without its aux data. Later
//!   `CERTIFICATE` and `X509 CERTIFICATE` blocks are the chain, in file
//!   order. rustls does not parse the client's own certificates, so v1
//!   leaves work.
//! - The key: the first private-key block. Encrypted PKCS#8 uses PBES2,
//!   after [`check_pbes2_params`]. A key block with RFC 1421 headers goes
//!   to `legacy_pem`, which accepts only `Proc-Type: 4,ENCRYPTED` with
//!   `DEK-Info`.
//! - The OpenSSL slot rule decides whether a key mismatch fails
//!   `ClientKey` or `CheckPrivateKey`. The leaf SPKI comes from a bounded
//!   DER walk, so the rule also covers v1 leaves.
//!
//! This module derives the PBES2 key itself and does not call
//! `EncryptedPrivateKeyInfo::decrypt`. The reason is that `pkcs5` does not
//! erase its derived key. Here the derived key and the plaintext stay in
//! zeroizing buffers.
//!
//! The FIPS build accepts only PBES2 with PBKDF2-HMAC-SHA256, -SHA384 or
//! -SHA512 and AES-CBC, and decrypts in the FIPS module through
//! `aws_lc_rs::pbkdf2` and `aws_lc_rs::cipher`. It compiles no
//! `legacy_pem` and no RustCrypto cipher or KDF code.
//!
//! Every key byte lives in a [`SecretBytes`] or a zeroizing buffer until
//! the provider has loaded the key. The provider reads the key DER by
//! reference, so no owned copy of the key is left without erasure. The
//! hash, cipher and KDF crates keep some state in their own frames, which
//! this module cannot erase.

use std::sync::Arc;

use der::zeroize::Zeroizing;
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::pkcs5::pbes2::{self, Kdf, Pbkdf2Prf};
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::sign::{CertifiedKey, SigningKey};
use zk_proto::SecretBytes;

use crate::net::tls::connector::{LegacyPath, read_path};
#[cfg(feature = "_legacy-keys")]
use crate::net::tls::legacy_pem::{self, DekCipher};
use crate::net::tls::pem::{self, PemBlock, PemKind};
use crate::net::tls::{TlsConfigStep, TlsSetupError};

/// OpenSSL's `PEM_BUFSIZE`: the passphrase is the first
/// `min(strlen(passwd), MAX_PASSPHRASE)` bytes.
pub const MAX_PASSPHRASE: usize = 1024;

/// The scrypt memory limit, OpenSSL's `SCRYPT_MAX_MEM`.
pub const SCRYPT_MAX_MEM: u64 = 32 * 1024 * 1024;

/// A key load failure. The connector maps every variant to the
/// `ClientKey` step. A key that does not match the certificate fails at
/// the `CheckPrivateKey` step, so it has no variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyError {
    /// The passphrase does not decrypt the key: bad padding or bad DER.
    BadPassphrase,
    /// The key format, cipher, PRF or key type is not accepted.
    Rejected,
    /// The PBES2 parameters are over the bounds.
    Bounds,
}

/// A loaded client identity.
#[derive(Debug)]
pub struct Identity {
    key: Arc<CertifiedKey>,
}

impl Identity {
    /// Runs the steps `ClientCertChain`, `ClientKey` and
    /// `CheckPrivateKey`.
    ///
    /// Each call reads both files again. The passphrase is the first
    /// [`MAX_PASSPHRASE`] bytes of `passwd`, and an unencrypted key
    /// ignores it. The signing key comes from the provider module of the
    /// build feature, which reads the key DER by reference. `provider` is
    /// the connector's provider, which is the same provider.
    ///
    /// # Errors
    ///
    /// Returns `TlsSetupError::Config` with the failed step.
    pub fn load(
        cert: &LegacyPath,
        key: &LegacyPath,
        passwd: &SecretBytes,
        _provider: &CryptoProvider,
    ) -> Result<Self, TlsSetupError> {
        let chain = load_chain(cert).ok_or(config(TlsConfigStep::ClientCertChain))?;
        let signer = load_key(key, passwd).map_err(|_| config(TlsConfigStep::ClientKey))?;
        check_pair(&chain, signer.as_ref())?;
        Ok(Self {
            key: Arc::new(CertifiedKey::new(chain, signer)),
        })
    }

    /// Returns the certified key.
    #[must_use]
    pub fn certified_key(&self) -> &Arc<CertifiedKey> {
        &self.key
    }
}

/// The client certificate resolver of the drop-in.
///
/// It returns the key whenever the key can sign one of the offered
/// schemes and ignores `root_hint_subjects`, as OpenSSL sends its
/// configured certificate regardless of the server's CA list.
#[derive(Debug)]
pub struct LegacyClientCert(pub Arc<CertifiedKey>);

impl ResolvesClientCert for LegacyClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.0
            .key
            .choose_scheme(sigschemes)
            .map(|_| Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Decrypts an `ENCRYPTED PRIVATE KEY` body into PKCS#8 DER.
///
/// The passphrase is already cut to [`MAX_PASSPHRASE`] bytes. The
/// parameters pass [`check_pbes2_params`] before any key derivation runs.
/// The derived key and the plaintext stay in zeroizing buffers.
///
/// # Errors
///
/// Returns [`KeyError::Rejected`] for a scheme outside the accepted set,
/// [`KeyError::Bounds`] for parameters over the bounds, and
/// [`KeyError::BadPassphrase`] for bad padding.
pub fn decrypt_pkcs8(der: &[u8], passwd: &[u8]) -> Result<SecretBytes, KeyError> {
    let info = EncryptedPrivateKeyInfo::try_from(der).map_err(|_| KeyError::Rejected)?;
    let params = info
        .encryption_algorithm
        .pbes2()
        .ok_or(KeyError::Rejected)?;
    check_params(params)?;
    let mut buf = info.encrypted_data.to_vec();
    match decrypt_pbes2(params, passwd, &mut buf) {
        Ok(len) => {
            buf.truncate(len);
            Ok(SecretBytes::new(buf))
        }
        Err(e) => {
            drop(SecretBytes::new(buf));
            Err(e)
        }
    }
}

/// Checks the key-derivation parameters before any decryption runs. For
/// scrypt: `128·r·(N + 2) + 128·r·p` at most [`SCRYPT_MAX_MEM`],
/// `p·r < 2^30`, and `N` a power of two greater than 1. For PBKDF2: an
/// accepted PRF and at
/// least one iteration. An explicit `keyLength` equals the cipher's key
/// length. All arithmetic is checked.
///
/// # Errors
///
/// Returns [`KeyError::Bounds`] or [`KeyError::Rejected`].
pub fn check_pbes2_params(der: &[u8]) -> Result<(), KeyError> {
    let info = EncryptedPrivateKeyInfo::try_from(der).map_err(|_| KeyError::Rejected)?;
    let params = info
        .encryption_algorithm
        .pbes2()
        .ok_or(KeyError::Rejected)?;
    check_params(params)
}

/// Makes a `Config` setup error.
fn config(step: TlsConfigStep) -> TlsSetupError {
    TlsSetupError::Config { step }
}

/// Loads the chain file by the rule of
/// `SSL_CTX_use_certificate_chain_file`. `None` fails the step.
///
/// The file may hold a key, so its image stays in a [`SecretBytes`].
fn load_chain(cert: &LegacyPath) -> Option<Vec<CertificateDer<'static>>> {
    let text = SecretBytes::new(read_path(cert)?);
    let blocks = pem::read_blocks(text.expose()).ok()?;
    let mut chain: Vec<CertificateDer<'static>> = Vec::new();
    for block in &blocks {
        let der = match pem::classify_label(&block.label) {
            PemKind::Certificate => block.body.expose(),
            // Only the leaf may come from a TRUSTED CERTIFICATE block.
            // The aux data after the certificate is dropped.
            PemKind::TrustedCertificate if chain.is_empty() => der_tlv(block.body.expose())?.full,
            _ => continue,
        };
        if !pem::der_is_certificate(der) {
            return None;
        }
        chain.push(CertificateDer::from(der.to_vec()));
    }
    if chain.is_empty() { None } else { Some(chain) }
}

/// The DER form of a decoded key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyForm {
    /// PKCS#8 `PrivateKeyInfo`.
    Pkcs8,
    /// PKCS#1 `RSAPrivateKey`.
    Pkcs1,
    /// SEC1 `ECPrivateKey`.
    Sec1,
}

/// Loads the key file by the rule of `SSL_CTX_use_PrivateKey_file`: the
/// first private-key block, decrypted when necessary.
fn load_key(key: &LegacyPath, passwd: &SecretBytes) -> Result<Arc<dyn SigningKey>, KeyError> {
    let text = SecretBytes::new(read_path(key).ok_or(KeyError::Rejected)?);
    let blocks = pem::read_blocks(text.expose()).map_err(|_| KeyError::Rejected)?;
    drop(text);
    let block = blocks
        .iter()
        .find(|b| is_key_kind(pem::classify_label(&b.label)))
        .ok_or(KeyError::Rejected)?;
    let pass = passwd.expose();
    let pass = pass.get(..MAX_PASSPHRASE).unwrap_or(pass);
    let (form, der) = decode_key(block, pass)?;
    signing_key(form, &der).ok_or(KeyError::Rejected)
}

/// Tells whether a label kind is a private-key kind.
fn is_key_kind(kind: PemKind) -> bool {
    matches!(
        kind,
        PemKind::Pkcs8Key
            | PemKind::RsaKey
            | PemKind::EcKey
            | PemKind::EncryptedPkcs8Key
            | PemKind::DsaKey
    )
}

/// Decodes one key block into key DER and its form.
///
/// A block with headers is a traditional encrypted block. The FIPS build
/// rejects it. An `ENCRYPTED PRIVATE KEY` body then goes through PBES2.
fn decode_key(block: &PemBlock, pass: &[u8]) -> Result<(KeyForm, SecretBytes), KeyError> {
    let form = match pem::classify_label(&block.label) {
        PemKind::Pkcs8Key | PemKind::EncryptedPkcs8Key => KeyForm::Pkcs8,
        PemKind::RsaKey => KeyForm::Pkcs1,
        PemKind::EcKey => KeyForm::Sec1,
        // DSA and every other label fail the step.
        _ => return Err(KeyError::Rejected),
    };
    let body = if block.headers.is_empty() {
        block.body.duplicate()
    } else {
        traditional(block, pass)?
    };
    if pem::classify_label(&block.label) == PemKind::EncryptedPkcs8Key {
        Ok((form, decrypt_pkcs8(body.expose(), pass)?))
    } else {
        Ok((form, body))
    }
}

/// Decrypts a block with traditional PEM encryption.
#[cfg(feature = "_legacy-keys")]
fn traditional(block: &PemBlock, pass: &[u8]) -> Result<SecretBytes, KeyError> {
    legacy_pem::decrypt(block, pass)
}

/// The FIPS build has no traditional PEM decryption.
#[cfg(not(feature = "_legacy-keys"))]
fn traditional(_block: &PemBlock, _pass: &[u8]) -> Result<SecretBytes, KeyError> {
    Err(KeyError::Rejected)
}

/// Makes the signing key of the build provider from key bytes that the
/// caller keeps in a [`SecretBytes`].
///
/// The provider function reads the key by reference, so no copy of the
/// key bytes is left to drop without erasure. The generic
/// `KeyProvider::load_private_key` takes an owned key and does not erase
/// it, so this function does not use it.
fn signing_key(form: KeyForm, der: &SecretBytes) -> Option<Arc<dyn SigningKey>> {
    let key = match form {
        KeyForm::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.expose())),
        KeyForm::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der.expose())),
        KeyForm::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der.expose())),
    };
    #[cfg(feature = "tls-ring")]
    let signer = rustls::crypto::ring::sign::any_supported_type(&key);
    #[cfg(all(
        not(feature = "tls-ring"),
        any(feature = "tls-aws-lc-rs", feature = "tls-aws-lc-rs-fips")
    ))]
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key);
    signer.ok()
}

/// The OpenSSL key slot of a key type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    /// `rsaEncryption`.
    Rsa,
    /// `id-RSASSA-PSS`.
    RsaPss,
    /// `id-ecPublicKey`.
    Ecc,
    /// `id-Ed25519`.
    Ed25519,
    /// `id-Ed448`.
    Ed448,
}

/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-RSASSA-PSS`, 1.2.840.113549.1.1.10.
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `id-Ed25519`, 1.3.101.112.
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// `id-Ed448`, 1.3.101.113.
const OID_ED448: &[u8] = &[0x2b, 0x65, 0x71];
/// The DER encoding of ASN.1 NULL.
const DER_NULL: &[u8] = &[0x05, 0x00];

/// Returns the slot of an SPKI algorithm OID. An unknown OID has its own
/// slot, which no rustls key shares.
fn slot_of_oid(oid: &[u8]) -> Option<Slot> {
    match oid {
        OID_RSA => Some(Slot::Rsa),
        OID_RSA_PSS => Some(Slot::RsaPss),
        OID_EC => Some(Slot::Ecc),
        OID_ED25519 => Some(Slot::Ed25519),
        OID_ED448 => Some(Slot::Ed448),
        _ => None,
    }
}

/// Returns the slot of a rustls key type.
fn slot_of_key(alg: SignatureAlgorithm) -> Option<Slot> {
    match alg {
        SignatureAlgorithm::RSA => Some(Slot::Rsa),
        SignatureAlgorithm::ECDSA => Some(Slot::Ecc),
        SignatureAlgorithm::ED25519 => Some(Slot::Ed25519),
        SignatureAlgorithm::ED448 => Some(Slot::Ed448),
        _ => None,
    }
}

/// Applies the OpenSSL slot rule to the leaf and the key.
///
/// The same slot and another public key fail `ClientKey`, as
/// `ssl_set_pkey` does. Another slot fails `CheckPrivateKey`. A key that
/// cannot give its public key passes, as rustls cannot check it.
fn check_pair(
    chain: &[CertificateDer<'static>],
    key: &dyn SigningKey,
) -> Result<(), TlsSetupError> {
    let Some(key_spki) = key.public_key() else {
        return Ok(());
    };
    let leaf = chain
        .first()
        .and_then(|c| leaf_spki(c.as_ref()))
        .and_then(spki_parts);
    let Some(leaf) = leaf else {
        // OpenSSL cannot get the leaf key, so the pair check fails.
        return Err(config(TlsConfigStep::CheckPrivateKey));
    };
    let leaf_slot = slot_of_oid(leaf.oid);
    if leaf_slot.is_none() || leaf_slot != slot_of_key(key.algorithm()) {
        return Err(config(TlsConfigStep::CheckPrivateKey));
    }
    match spki_parts(key_spki.as_ref()) {
        Some(k) if same_key(&leaf, &k) => Ok(()),
        _ => Err(config(TlsConfigStep::ClientKey)),
    }
}

/// The parts of a DER `SubjectPublicKeyInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpkiParts<'a> {
    /// The algorithm OID content.
    oid: &'a [u8],
    /// The algorithm parameters as whole TLVs, empty when absent.
    params: &'a [u8],
    /// The `subjectPublicKey` BIT STRING content.
    bits: &'a [u8],
}

/// Compares two keys by the OpenSSL rule: the same algorithm, the same
/// parameters (an RSA NULL and absent parameters are alike), and the same
/// public key bits. A compressed EC point does not equal its
/// uncompressed form.
fn same_key(a: &SpkiParts<'_>, b: &SpkiParts<'_>) -> bool {
    let norm = |p: &SpkiParts<'_>| -> Vec<u8> {
        if p.oid == OID_RSA && p.params == DER_NULL {
            Vec::new()
        } else {
            p.params.to_vec()
        }
    };
    a.oid == b.oid && norm(a) == norm(b) && a.bits == b.bits
}

/// Splits an SPKI into its parts.
fn spki_parts(spki: &[u8]) -> Option<SpkiParts<'_>> {
    let outer = der_tlv(spki)?;
    if outer.tag != 0x30 {
        return None;
    }
    let alg = der_tlv(outer.content)?;
    if alg.tag != 0x30 {
        return None;
    }
    let oid = der_tlv(alg.content)?;
    if oid.tag != 0x06 {
        return None;
    }
    let bits = der_tlv(alg.rest)?;
    if bits.tag != 0x03 {
        return None;
    }
    Some(SpkiParts {
        oid: oid.content,
        params: oid.rest,
        bits: bits.content,
    })
}

/// Finds the SPKI TLV of a certificate. The walk takes v1 and v3
/// certificates: `tbsCertificate` has an optional `[0]` version, then the
/// serial, the signature algorithm, the issuer, the validity, the subject
/// and the SPKI.
fn leaf_spki(cert: &[u8]) -> Option<&[u8]> {
    let outer = der_tlv(cert)?;
    if outer.tag != 0x30 {
        return None;
    }
    let tbs = der_tlv(outer.content)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut next = der_tlv(tbs.content)?;
    if next.tag == 0xa0 {
        next = der_tlv(next.rest)?;
    }
    // The serial, then four SEQUENCEs.
    let expect: [u8; 5] = [0x02, 0x30, 0x30, 0x30, 0x30];
    for tag in expect {
        if next.tag != tag {
            return None;
        }
        next = der_tlv(next.rest)?;
    }
    (next.tag == 0x30).then_some(next.full)
}

/// One DER element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tlv<'a> {
    /// The tag byte.
    tag: u8,
    /// The whole element.
    full: &'a [u8],
    /// The content.
    content: &'a [u8],
    /// The bytes after the element.
    rest: &'a [u8],
}

/// Reads one DER element with a one-byte tag and a length of at most four
/// bytes. Every bound is checked, so a hostile input gives `None`.
fn der_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut after) = after_tag.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let (bytes, rest) = after.split_at_checked(count)?;
        after = rest;
        bytes.iter().try_fold(0usize, |acc, &b| {
            acc.checked_mul(256)?.checked_add(usize::from(b))
        })?
    };
    let header = input.len().checked_sub(after.len())?;
    let (content, rest) = after.split_at_checked(len)?;
    let (full, _) = input.split_at_checked(header.checked_add(len)?)?;
    Some(Tlv {
        tag,
        full,
        content,
        rest,
    })
}

/// The PRFs of the build.
fn prf_accepted(prf: Pbkdf2Prf) -> bool {
    #[cfg(feature = "_legacy-keys")]
    let ok = matches!(
        prf,
        Pbkdf2Prf::HmacWithSha1
            | Pbkdf2Prf::HmacWithSha224
            | Pbkdf2Prf::HmacWithSha256
            | Pbkdf2Prf::HmacWithSha384
            | Pbkdf2Prf::HmacWithSha512
    );
    #[cfg(not(feature = "_legacy-keys"))]
    let ok = matches!(
        prf,
        Pbkdf2Prf::HmacWithSha256 | Pbkdf2Prf::HmacWithSha384 | Pbkdf2Prf::HmacWithSha512
    );
    ok
}

/// Returns the key length of an accepted PBES2 cipher.
fn cipher_key_len(enc: &pbes2::EncryptionScheme<'_>) -> Result<usize, KeyError> {
    match enc {
        pbes2::EncryptionScheme::Aes128Cbc { .. }
        | pbes2::EncryptionScheme::Aes192Cbc { .. }
        | pbes2::EncryptionScheme::Aes256Cbc { .. } => Ok(enc.key_size()),
        #[cfg(feature = "_legacy-keys")]
        pbes2::EncryptionScheme::DesEde3Cbc { .. } => Ok(enc.key_size()),
        _ => Err(KeyError::Rejected),
    }
}

/// Checks an explicit `keyLength` against the cipher's key length.
fn key_length_ok(explicit: Option<u16>, key_len: usize) -> Result<(), KeyError> {
    match explicit {
        Some(l) if usize::from(l) != key_len => Err(KeyError::Bounds),
        _ => Ok(()),
    }
}

/// The checks of [`check_pbes2_params`] on parsed parameters.
fn check_params(params: &pbes2::Parameters<'_>) -> Result<(), KeyError> {
    let key_len = cipher_key_len(&params.encryption)?;
    match &params.kdf {
        Kdf::Pbkdf2(k) => {
            if !prf_accepted(k.prf) {
                return Err(KeyError::Rejected);
            }
            if k.iteration_count == 0 {
                return Err(KeyError::Bounds);
            }
            key_length_ok(k.key_length, key_len)
        }
        #[cfg(feature = "_legacy-keys")]
        Kdf::Scrypt(s) => {
            scrypt_bounds(s.cost_parameter, s.block_size, s.parallelization)?;
            key_length_ok(s.key_length, key_len)
        }
        // scrypt in the FIPS build, and any future KDF.
        _ => Err(KeyError::Rejected),
    }
}

/// The scrypt bounds of OpenSSL `EVP_PBE_scrypt_ex` with the default
/// `maxmem`, in checked `u64` arithmetic. `N < 2^(16·r)` is the RFC 7914
/// rule, which the `scrypt` crate also needs.
#[cfg(feature = "_legacy-keys")]
fn scrypt_bounds(n: u64, r: u16, p: u16) -> Result<(), KeyError> {
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
        return Err(KeyError::Bounds);
    }
    let (r, p) = (u64::from(r), u64::from(p));
    let rp = r.checked_mul(p).ok_or(KeyError::Bounds)?;
    if rp >= 1 << 30 {
        return Err(KeyError::Bounds);
    }
    let log_n = u64::from(n.trailing_zeros());
    if log_n >= r.checked_mul(16).ok_or(KeyError::Bounds)? {
        return Err(KeyError::Bounds);
    }
    let r128 = r.checked_mul(128).ok_or(KeyError::Bounds)?;
    let v_len = n
        .checked_add(2)
        .and_then(|n2| r128.checked_mul(n2))
        .ok_or(KeyError::Bounds)?;
    let b_len = r128.checked_mul(p).ok_or(KeyError::Bounds)?;
    match v_len.checked_add(b_len) {
        Some(total) if total <= SCRYPT_MAX_MEM => Ok(()),
        _ => Err(KeyError::Bounds),
    }
}

/// Maps an accepted PBES2 cipher to its CBC cipher and IV.
#[cfg(feature = "_legacy-keys")]
fn pbes2_cipher<'a>(
    enc: &'a pbes2::EncryptionScheme<'_>,
) -> Result<(DekCipher, &'a [u8]), KeyError> {
    match enc {
        pbes2::EncryptionScheme::Aes128Cbc { iv } => Ok((DekCipher::Aes128Cbc, iv.as_slice())),
        pbes2::EncryptionScheme::Aes192Cbc { iv } => Ok((DekCipher::Aes192Cbc, iv.as_slice())),
        pbes2::EncryptionScheme::Aes256Cbc { iv } => Ok((DekCipher::Aes256Cbc, iv.as_slice())),
        pbes2::EncryptionScheme::DesEde3Cbc { iv } => Ok((DekCipher::DesEde3Cbc, iv.as_slice())),
        _ => Err(KeyError::Rejected),
    }
}

/// Derives the key into a zeroizing buffer and decrypts `buf` in place.
/// It returns the plaintext length.
#[cfg(feature = "_legacy-keys")]
fn decrypt_pbes2(
    params: &pbes2::Parameters<'_>,
    pass: &[u8],
    buf: &mut [u8],
) -> Result<usize, KeyError> {
    let (cipher, iv) = pbes2_cipher(&params.encryption)?;
    let mut key = Zeroizing::new(vec![0u8; params.encryption.key_size()]);
    match &params.kdf {
        Kdf::Pbkdf2(k) => {
            let (salt, rounds) = (k.salt, k.iteration_count);
            match k.prf {
                Pbkdf2Prf::HmacWithSha1 => {
                    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pass, salt, rounds, &mut key);
                }
                Pbkdf2Prf::HmacWithSha224 => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha224>(pass, salt, rounds, &mut key);
                }
                Pbkdf2Prf::HmacWithSha256 => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, salt, rounds, &mut key);
                }
                Pbkdf2Prf::HmacWithSha384 => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pass, salt, rounds, &mut key);
                }
                Pbkdf2Prf::HmacWithSha512 => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass, salt, rounds, &mut key);
                }
                _ => return Err(KeyError::Rejected),
            }
        }
        Kdf::Scrypt(s) => {
            let log_n =
                u8::try_from(s.cost_parameter.trailing_zeros()).map_err(|_| KeyError::Bounds)?;
            let sp = scrypt::Params::new(
                log_n,
                u32::from(s.block_size),
                u32::from(s.parallelization),
                key.len(),
            )
            .map_err(|_| KeyError::Bounds)?;
            scrypt_zeroizing(pass, s.salt, &sp, &mut key)?;
        }
        _ => return Err(KeyError::Rejected),
    }
    legacy_pem::cbc_decrypt(cipher, &key, iv, buf)
}

/// scrypt (RFC 7914) with zeroizing working buffers.
///
/// The `scrypt` crate frees its `B`, `V` and `XY` buffers without
/// zeroizing them. `B` comes from one PBKDF2 round of the passphrase, so a
/// freed copy allows a cheap passphrase search. Thus
/// this function uses the crate only for the parameter checks, and it
/// runs ROMix in buffers that are zeroized on drop. The caller checks the
/// memory bound before the call, so each allocation is bounded.
#[cfg(feature = "_legacy-keys")]
fn scrypt_zeroizing(
    pass: &[u8],
    salt: &[u8],
    params: &scrypt::Params,
    out: &mut [u8],
) -> Result<(), KeyError> {
    let block = usize::try_from(params.r())
        .ok()
        .and_then(|r| r.checked_mul(128))
        .ok_or(KeyError::Bounds)?;
    let lanes = usize::try_from(params.p()).map_err(|_| KeyError::Bounds)?;
    let n = 1usize
        .checked_shl(u32::from(params.log_n()))
        .ok_or(KeyError::Bounds)?;
    let b_len = block.checked_mul(lanes).ok_or(KeyError::Bounds)?;
    let v_len = block.checked_mul(n).ok_or(KeyError::Bounds)?;
    let xy_len = block.checked_mul(2).ok_or(KeyError::Bounds)?;
    if block == 0 || lanes == 0 || n < 2 {
        return Err(KeyError::Bounds);
    }
    let mut b = Zeroizing::new(vec![0u8; b_len]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, salt, 1, &mut b);
    let mut v = Zeroizing::new(vec![0u8; v_len]);
    let mut xy = Zeroizing::new(vec![0u8; xy_len]);
    for lane in b.chunks_exact_mut(block) {
        romix(lane, &mut v, &mut xy, n)?;
    }
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, &b, 1, out);
    Ok(())
}

/// `scryptROMix` (RFC 7914, section 5). `v` holds `n` blocks and `xy`
/// holds two.
#[cfg(feature = "_legacy-keys")]
fn romix(lane: &mut [u8], v: &mut [u8], xy: &mut [u8], n: usize) -> Result<(), KeyError> {
    let len = lane.len();
    let (x, y) = xy.split_at_mut(len);
    x.copy_from_slice(lane);
    for slot in v.chunks_exact_mut(len) {
        slot.copy_from_slice(x);
        block_mix(x, y);
        x.copy_from_slice(y);
    }
    let mask =
        u64::try_from(n.checked_sub(1).ok_or(KeyError::Bounds)?).map_err(|_| KeyError::Bounds)?;
    for _ in 0..n {
        let tail = len.checked_sub(64).ok_or(KeyError::Bounds)?;
        let word = x
            .get(tail..tail.saturating_add(8))
            .and_then(|w| <[u8; 8]>::try_from(w).ok())
            .ok_or(KeyError::Bounds)?;
        let j = usize::try_from(u64::from_le_bytes(word) & mask).map_err(|_| KeyError::Bounds)?;
        let start = j.checked_mul(len).ok_or(KeyError::Bounds)?;
        let vj = v
            .get(start..start.saturating_add(len))
            .ok_or(KeyError::Bounds)?;
        for (a, b) in x.iter_mut().zip(vj) {
            *a ^= *b;
        }
        block_mix(x, y);
        x.copy_from_slice(y);
    }
    lane.copy_from_slice(x);
    Ok(())
}

/// `scryptBlockMix` (RFC 7914, section 4). The even outputs fill the
/// first half of `out` and the odd outputs fill the second half.
#[cfg(feature = "_legacy-keys")]
fn block_mix(input: &[u8], out: &mut [u8]) {
    let mut x = [0u32; 16];
    if let Some(last) = input.rchunks_exact(64).next() {
        load_words(&mut x, last);
    }
    let (even, odd) = out.split_at_mut(input.len() / 2);
    let dest = even.chunks_exact_mut(64).zip(odd.chunks_exact_mut(64));
    for (pair, (e, o)) in input.chunks_exact(128).zip(dest) {
        let (first, second) = pair.split_at(64);
        xor_words(&mut x, first);
        salsa20_8(&mut x);
        store_words(&x, e);
        xor_words(&mut x, second);
        salsa20_8(&mut x);
        store_words(&x, o);
    }
    der::zeroize::Zeroize::zeroize(&mut x);
}

#[cfg(feature = "_legacy-keys")]
fn load_words(x: &mut [u32; 16], bytes: &[u8]) {
    for (w, c) in x.iter_mut().zip(bytes.chunks_exact(4)) {
        *w = c.try_into().map_or(0, u32::from_le_bytes);
    }
}

#[cfg(feature = "_legacy-keys")]
fn xor_words(x: &mut [u32; 16], bytes: &[u8]) {
    for (w, c) in x.iter_mut().zip(bytes.chunks_exact(4)) {
        *w ^= c.try_into().map_or(0, u32::from_le_bytes);
    }
}

#[cfg(feature = "_legacy-keys")]
fn store_words(x: &[u32; 16], out: &mut [u8]) {
    for (w, c) in x.iter().zip(out.chunks_exact_mut(4)) {
        c.copy_from_slice(&w.to_le_bytes());
    }
}

/// The Salsa20/8 core (RFC 7914, section 3).
#[cfg(feature = "_legacy-keys")]
fn salsa20_8(block: &mut [u32; 16]) {
    macro_rules! quarter {
        ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
            $x[$b] ^= $x[$a].wrapping_add($x[$d]).rotate_left(7);
            $x[$c] ^= $x[$b].wrapping_add($x[$a]).rotate_left(9);
            $x[$d] ^= $x[$c].wrapping_add($x[$b]).rotate_left(13);
            $x[$a] ^= $x[$d].wrapping_add($x[$c]).rotate_left(18);
        };
    }
    let mut x = *block;
    for _ in 0..4 {
        quarter!(x, 0, 4, 8, 12);
        quarter!(x, 5, 9, 13, 1);
        quarter!(x, 10, 14, 2, 6);
        quarter!(x, 15, 3, 7, 11);
        quarter!(x, 0, 1, 2, 3);
        quarter!(x, 5, 6, 7, 4);
        quarter!(x, 10, 11, 8, 9);
        quarter!(x, 15, 12, 13, 14);
    }
    for (b, v) in block.iter_mut().zip(x) {
        *b = b.wrapping_add(v);
    }
    der::zeroize::Zeroize::zeroize(&mut x);
}

/// Derives the key and decrypts `buf` in place inside the FIPS module. It
/// returns the plaintext length.
///
/// `aws_lc_rs::pbkdf2::derive` has no error return. It fails only on an
/// internal error of the module.
#[cfg(not(feature = "_legacy-keys"))]
fn decrypt_pbes2(
    params: &pbes2::Parameters<'_>,
    pass: &[u8],
    buf: &mut [u8],
) -> Result<usize, KeyError> {
    use aws_lc_rs::{cipher, iv::FixedLength, pbkdf2};
    let Kdf::Pbkdf2(k) = &params.kdf else {
        return Err(KeyError::Rejected);
    };
    let prf = match k.prf {
        Pbkdf2Prf::HmacWithSha256 => pbkdf2::PBKDF2_HMAC_SHA256,
        Pbkdf2Prf::HmacWithSha384 => pbkdf2::PBKDF2_HMAC_SHA384,
        Pbkdf2Prf::HmacWithSha512 => pbkdf2::PBKDF2_HMAC_SHA512,
        _ => return Err(KeyError::Rejected),
    };
    let rounds = std::num::NonZeroU32::new(k.iteration_count).ok_or(KeyError::Bounds)?;
    let (alg, iv) = match &params.encryption {
        pbes2::EncryptionScheme::Aes128Cbc { iv } => (&cipher::AES_128, *iv),
        pbes2::EncryptionScheme::Aes192Cbc { iv } => (&cipher::AES_192, *iv),
        pbes2::EncryptionScheme::Aes256Cbc { iv } => (&cipher::AES_256, *iv),
        _ => return Err(KeyError::Rejected),
    };
    let mut key = Zeroizing::new(vec![0u8; params.encryption.key_size()]);
    pbkdf2::derive(prf, rounds, k.salt, pass, &mut key);
    let unbound = cipher::UnboundCipherKey::new(alg, &key).map_err(|_| KeyError::Rejected)?;
    let dec =
        cipher::PaddedBlockDecryptingKey::cbc_pkcs7(unbound).map_err(|_| KeyError::Rejected)?;
    let ctx = cipher::DecryptionContext::Iv128(FixedLength::from(iv));
    dec.decrypt(buf, ctx)
        .map(|plain| plain.len())
        .map_err(|_| KeyError::BadPassphrase)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use rustls::pki_types::pem::PemObject as _;

    use super::*;

    /// Rule: the zeroizing scrypt gives the test vectors of RFC 7914,
    /// section 12.
    #[cfg(feature = "_legacy-keys")]
    #[test]
    fn scrypt_matches_the_rfc_7914_vectors() {
        let run = |pass: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32| {
            let params = scrypt::Params::new(log_n, r, p, 64).expect("params");
            let mut out = [0u8; 64];
            scrypt_zeroizing(pass, salt, &params, &mut out).expect("scrypt");
            out.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        assert_eq!(
            run(b"", b"", 4, 1, 1),
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        );
        // The second vector needs 16 MiB of mixing work, which is too
        // slow under Miri. The first vector and the crate check remain.
        if !cfg!(miri) {
            assert_eq!(
                run(b"password", b"NaCl", 10, 8, 16),
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
                 2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
            );
        }
        let mut crate_out = [0u8; 32];
        let params = scrypt::Params::new(5, 3, 2, 32).expect("params");
        scrypt::scrypt(b"pw", b"salt", &params, &mut crate_out).expect("crate scrypt");
        let mut own = [0u8; 32];
        scrypt_zeroizing(b"pw", b"salt", &params, &mut own).expect("scrypt");
        assert_eq!(own, crate_out);
    }

    fn cert(name: &str) -> CertificateDer<'static> {
        let path = zk_testkit::fixtures::tls_dir().join(name);
        CertificateDer::from_pem_file(path).unwrap()
    }

    #[test]
    fn der_tlv_reads_both_length_forms() {
        let short = der_tlv(&[0x04, 0x02, 1, 2, 9]).unwrap();
        assert_eq!(short.tag, 0x04);
        assert_eq!(short.content, &[1, 2]);
        assert_eq!(short.full, &[0x04, 0x02, 1, 2]);
        assert_eq!(short.rest, &[9]);

        let mut long = vec![0x30, 0x82, 0x01, 0x00];
        long.extend_from_slice(&[7u8; 256]);
        long.push(0xff);
        let t = der_tlv(&long).unwrap();
        assert_eq!(t.content.len(), 256);
        assert_eq!(t.full.len(), 260);
        assert_eq!(t.rest, &[0xff]);

        let mut one = vec![0x30, 0x81, 0x80];
        one.extend_from_slice(&[0u8; 128]);
        assert_eq!(der_tlv(&one).unwrap().content.len(), 128);
    }

    #[test]
    fn der_tlv_rejects_bad_headers() {
        for bad in [
            &[][..],
            &[0x30],
            // A content shorter than its length.
            &[0x30, 0x03, 0, 0],
            // An indefinite length.
            &[0x30, 0x80, 0, 0],
            // A length of five bytes.
            &[0x30, 0x85, 0, 0, 0, 0, 1, 0],
            // A length larger than the input.
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0],
            // A multi-byte tag.
            &[0x1f, 0x01, 0x00],
            // Length bytes cut short.
            &[0x30, 0x82, 0x01],
        ] {
            assert_eq!(der_tlv(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn leaf_spki_takes_v1_and_v3_certificates() {
        let v3 = cert("client.pem");
        let v1 = cert("keys/v1.pem");
        let a = spki_parts(leaf_spki(v3.as_ref()).unwrap()).unwrap();
        let b = spki_parts(leaf_spki(v1.as_ref()).unwrap()).unwrap();
        assert_eq!(a.oid, OID_EC);
        // Both leaves hold the client key.
        assert!(same_key(&a, &b));
        let rsa = cert("keys/rsa.pem");
        let r = spki_parts(leaf_spki(rsa.as_ref()).unwrap()).unwrap();
        assert_eq!(slot_of_oid(r.oid), Some(Slot::Rsa));
        assert_eq!(r.params, DER_NULL);
        assert!(!same_key(&a, &r));
    }

    #[test]
    fn leaf_spki_rejects_other_shapes() {
        let v3 = cert("client.pem");
        let der = v3.as_ref();
        // Every cut of the certificate fails without a panic.
        for len in 0..der.len() {
            assert_eq!(leaf_spki(&der[..len]), None, "{len}");
        }
        assert_eq!(leaf_spki(&[0x30, 0x03, 0x02, 0x01, 0x00]), None);
        assert_eq!(spki_parts(&[0x30, 0x00]), None);
        assert_eq!(spki_parts(&[0x31, 0x00]), None);
    }

    #[test]
    fn same_key_treats_an_rsa_null_as_absent_parameters() {
        let with_null = SpkiParts {
            oid: OID_RSA,
            params: DER_NULL,
            bits: b"key",
        };
        let absent = SpkiParts {
            params: &[],
            ..with_null
        };
        assert!(same_key(&with_null, &absent));
        // Only RSA has that rule.
        let ec_null = SpkiParts {
            oid: OID_EC,
            ..with_null
        };
        let ec_absent = SpkiParts {
            oid: OID_EC,
            ..absent
        };
        assert!(!same_key(&ec_null, &ec_absent));
        let other_bits = SpkiParts {
            bits: b"kez",
            ..with_null
        };
        assert!(!same_key(&with_null, &other_bits));
        let pss = SpkiParts {
            oid: OID_RSA_PSS,
            ..with_null
        };
        assert!(!same_key(&with_null, &pss));
    }

    #[test]
    fn slots_come_from_the_oid_and_the_key_type() {
        assert_eq!(slot_of_oid(OID_RSA), Some(Slot::Rsa));
        assert_eq!(slot_of_oid(OID_RSA_PSS), Some(Slot::RsaPss));
        assert_eq!(slot_of_oid(OID_EC), Some(Slot::Ecc));
        assert_eq!(slot_of_oid(OID_ED25519), Some(Slot::Ed25519));
        assert_eq!(slot_of_oid(OID_ED448), Some(Slot::Ed448));
        // DSA, 1.2.840.10040.4.1.
        assert_eq!(
            slot_of_oid(&[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01]),
            None
        );
        assert_eq!(slot_of_key(SignatureAlgorithm::RSA), Some(Slot::Rsa));
        assert_eq!(slot_of_key(SignatureAlgorithm::ECDSA), Some(Slot::Ecc));
        assert_eq!(
            slot_of_key(SignatureAlgorithm::ED25519),
            Some(Slot::Ed25519)
        );
        assert_eq!(slot_of_key(SignatureAlgorithm::Anonymous), None);
    }

    #[cfg(feature = "_legacy-keys")]
    #[test]
    fn scrypt_bounds_meet_the_memory_limit_exactly() {
        // 256·(65536 + 2) + 256·65534 is 2^25.
        assert_eq!(scrypt_bounds(65536, 2, 65534), Ok(()));
        assert_eq!(scrypt_bounds(65536, 2, 65535), Err(KeyError::Bounds));
        // log2 N < 16·r.
        assert_eq!(scrypt_bounds(1 << 15, 1, 1), Ok(()));
        assert_eq!(scrypt_bounds(1 << 16, 1, 1), Err(KeyError::Bounds));
        for n in [0, 1, 6, u64::MAX, 1 << 63] {
            assert_eq!(scrypt_bounds(n, 8, 1), Err(KeyError::Bounds), "{n}");
        }
        assert_eq!(scrypt_bounds(2, u16::MAX, u16::MAX), Err(KeyError::Bounds));
    }

    #[test]
    fn prfs_follow_the_build() {
        assert!(prf_accepted(Pbkdf2Prf::HmacWithSha256));
        assert!(prf_accepted(Pbkdf2Prf::HmacWithSha512));
        assert_eq!(
            prf_accepted(Pbkdf2Prf::HmacWithSha1),
            cfg!(feature = "_legacy-keys")
        );
    }

    #[test]
    fn key_length_must_match_the_cipher() {
        assert_eq!(key_length_ok(None, 32), Ok(()));
        assert_eq!(key_length_ok(Some(32), 32), Ok(()));
        assert_eq!(key_length_ok(Some(16), 32), Err(KeyError::Bounds));
    }
}
