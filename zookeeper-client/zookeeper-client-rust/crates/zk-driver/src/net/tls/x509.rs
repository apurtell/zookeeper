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

//! `LegacyCert`: a read-only DER view of a certificate.
//!
//! The view accepts X.509 v1 and v3 certificates, which webpki does not
//! do for v1. It borrows the DER bytes and gives the fields that the trust
//! loader, `LegacyChainOnly` and the v1-leaf verifier read. It also gives
//! the OpenSSL name canonicalization (`X509_NAME_cmp`) and the subject
//! hash (`X509_NAME_hash_ex`) for the `HHHHHHHH.N` directory lookup.
//!
//! The parser reads untrusted input. It is bounded by the input length,
//! it never panics, and it rejects what webpki rejects as malformed. For
//! example, it rejects a negative serial, a duplicate extension, a
//! non-canonical time, or a v1 certificate with extensions. OpenSSL can
//! accept these, so this is a known difference.
//!
//! The module has two decoders. The strict DER decoder backs
//! [`LegacyCert::parse`]. The BER decoder copies the structural test of
//! OpenSSL `d2i_X509`, `d2i_X509_CRL` and `d2i_X509_AUX`. The trust loader
//! uses the BER decoder to decide if a PEM block counts. Both decoders
//! share one TLV reader, and the reader limits the nesting of
//! indefinite lengths.

use std::collections::BTreeSet;
use std::ops::Range;
use std::time::Duration;

use rustls::pki_types::{SubjectPublicKeyInfoDer, UnixTime};

/// keyUsage `digitalSignature`, as a [`LegacyCert::key_usage`] bit.
pub const KU_DIGITAL_SIGNATURE: u16 = 0x0001;
/// keyUsage `nonRepudiation` (`contentCommitment`).
pub const KU_NON_REPUDIATION: u16 = 0x0002;
/// keyUsage `keyEncipherment`.
pub const KU_KEY_ENCIPHERMENT: u16 = 0x0004;
/// keyUsage `dataEncipherment`.
pub const KU_DATA_ENCIPHERMENT: u16 = 0x0008;
/// keyUsage `keyAgreement`.
pub const KU_KEY_AGREEMENT: u16 = 0x0010;
/// keyUsage `keyCertSign`.
pub const KU_KEY_CERT_SIGN: u16 = 0x0020;
/// keyUsage `cRLSign`.
pub const KU_CRL_SIGN: u16 = 0x0040;
/// keyUsage `encipherOnly`.
pub const KU_ENCIPHER_ONLY: u16 = 0x0080;
/// keyUsage `decipherOnly`.
pub const KU_DECIPHER_ONLY: u16 = 0x0100;

/// Netscape cert type `sslClient`, as a [`LegacyCert::ns_cert_type`] bit.
pub const NS_SSL_CLIENT: u8 = 0x01;
/// Netscape cert type `sslServer`.
pub const NS_SSL_SERVER: u8 = 0x02;
/// Netscape cert type `smime`.
pub const NS_SMIME: u8 = 0x04;
/// Netscape cert type `objsign`.
pub const NS_OBJSIGN: u8 = 0x08;
/// Netscape cert type `sslCA`.
pub const NS_SSL_CA: u8 = 0x20;
/// Netscape cert type `smimeCA`.
pub const NS_SMIME_CA: u8 = 0x40;
/// Netscape cert type `objCA`.
pub const NS_OBJSIGN_CA: u8 = 0x80;
/// The Netscape CA bits (OpenSSL `NS_ANY_CA`).
pub const NS_ANY_CA: u8 = 0xE0;

/// The DER content of the serverAuth OID (1.3.6.1.5.5.7.3.1).
pub const OID_SERVER_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// The DER content of the anyExtendedKeyUsage OID (2.5.29.37.0).
pub const OID_ANY_EKU: &[u8] = &[0x55, 0x1D, 0x25, 0x00];
const OID_NS_SGC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x04, 0x01];
const OID_MS_SGC: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x03];

const OID_BC: &[u8] = &[0x55, 0x1D, 0x13];
const OID_KU: &[u8] = &[0x55, 0x1D, 0x0F];
const OID_EKU: &[u8] = &[0x55, 0x1D, 0x25];
const OID_SKID: &[u8] = &[0x55, 0x1D, 0x0E];
const OID_AKID: &[u8] = &[0x55, 0x1D, 0x23];
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];
const OID_NC: &[u8] = &[0x55, 0x1D, 0x1E];
const OID_NS_CERT_TYPE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01];

const PKCS1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01];
const ECDSA_SHA2: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03];
const NIST_SIG: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
const OID_EC_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
const OID_DSA_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03];
const OID_OIW_DSA_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1B];
const OID_OIW_RSA_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1D];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_ED448: &[u8] = &[0x2B, 0x65, 0x71];
const OID_EC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_DSA_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01];

/// The certificate version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertVersion {
    /// X.509 v1: no extensions field.
    V1,
    /// X.509 v3. A v2 certificate is a parse error.
    V3,
}

/// A parse failure of [`LegacyCert::parse`] or [`AuxTrust::parse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum X509Error {
    /// The DER is malformed, or it breaks a webpki encoding rule.
    Malformed,
    /// The certificate uses a form that the view does not take, for
    /// example X.509 v2.
    Unsupported,
}

/// The validity period. OpenSSL accepts `not_before <= now < not_after`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    /// The `notBefore` time.
    pub not_before: UnixTime,
    /// The `notAfter` time.
    pub not_after: UnixTime,
}

impl Validity {
    /// Tells whether `now` is inside the period, by the OpenSSL rule.
    #[must_use]
    pub fn contains(&self, now: UnixTime) -> bool {
        self.not_before.as_secs() <= now.as_secs() && now.as_secs() < self.not_after.as_secs()
    }
}

/// The basicConstraints extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BasicConstraints {
    /// `cA`.
    pub ca: bool,
    /// `pathLenConstraint`, when present.
    pub path_len: Option<u32>,
}

/// The authorityKeyIdentifier extension, as raw DER parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthorityKeyId<'a> {
    /// `keyIdentifier`.
    pub key_id: Option<&'a [u8]>,
    /// `authorityCertIssuer` (GeneralNames content).
    pub issuer: Option<&'a [u8]>,
    /// `authorityCertSerialNumber` (INTEGER content).
    pub serial: Option<&'a [u8]>,
}

/// The parts of a subjectPublicKeyInfo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spki<'a> {
    /// The content of the AlgorithmIdentifier SEQUENCE. It compares with
    /// `SignatureVerificationAlgorithm::public_key_alg_id`.
    pub alg_id_value: &'a [u8],
    /// The subjectPublicKey bits, without the unused-bits octet.
    pub key_bits: &'a [u8],
}

/// The `X509_CERT_AUX` trust settings of a `TRUSTED CERTIFICATE` block.
/// Each list holds the DER content of each OID.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuxTrust {
    /// The trust list. `None` when the field is absent.
    pub trust: Option<Vec<Vec<u8>>>,
    /// The reject list. `None` when the field is absent.
    pub reject: Option<Vec<Vec<u8>>>,
}

impl AuxTrust {
    /// Parses the `X509_CERT_AUX` that follows the certificate in a
    /// `TRUSTED CERTIFICATE` body.
    ///
    /// The decode follows OpenSSL `d2i_X509_CERT_AUX`. It reads one aux
    /// SEQUENCE at the start of `der` and ignores the bytes after it.
    ///
    /// # Errors
    ///
    /// Returns [`X509Error::Malformed`] for invalid DER.
    pub fn parse(der: &[u8]) -> Result<Self, X509Error> {
        ber_aux(der).ok_or(X509Error::Malformed)
    }

    /// Tells whether the reject list names serverAuth or
    /// anyExtendedKeyUsage. Such an input is `Role::Rejected`.
    #[must_use]
    pub fn rejects_server_auth(&self) -> bool {
        names_server_auth(self.reject.as_deref())
    }

    /// Tells whether the trust list names serverAuth or
    /// anyExtendedKeyUsage. Such an input is an anchor.
    #[must_use]
    pub fn trusts_server_auth(&self) -> bool {
        names_server_auth(self.trust.as_deref())
    }

    /// Tells whether a non-empty trust list is present.
    #[must_use]
    pub fn has_trust_list(&self) -> bool {
        self.trust.as_ref().is_some_and(|t| !t.is_empty())
    }
}

fn names_server_auth(list: Option<&[Vec<u8>]>) -> bool {
    list.is_some_and(|l| {
        l.iter()
            .any(|o| o.as_slice() == OID_SERVER_AUTH || o.as_slice() == OID_ANY_EKU)
    })
}

/// The extensions that the view reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Extensions<'a> {
    bc: Option<BasicConstraints>,
    ku: Option<u16>,
    eku: Option<Vec<&'a [u8]>>,
    ns: Option<u8>,
    skid: Option<&'a [u8]>,
    akid: Option<AuthorityKeyId<'a>>,
    san: Option<&'a [u8]>,
    nc: Option<&'a [u8]>,
    critical: Vec<&'a [u8]>,
}

/// A read-only view of one DER certificate.
///
/// The view keeps the whole DER and the byte ranges of its parts. The
/// accessors are cheap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyCert<'a> {
    der: &'a [u8],
    tbs: &'a [u8],
    sig_alg: &'a [u8],
    signature: &'a [u8],
    version: CertVersion,
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    validity: Validity,
    spki_der: &'a [u8],
    spki: Spki<'a>,
    ext: Extensions<'a>,
    canon_subject: Vec<u8>,
    canon_issuer: Vec<u8>,
}

impl<'a> LegacyCert<'a> {
    /// Parses a certificate. v1 and v3 certificates parse.
    ///
    /// The input must be exactly one DER `Certificate`. The parser applies
    /// the webpki encoding rules, and both names must have an OpenSSL
    /// canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`X509Error`] when the DER is malformed or unsupported.
    pub fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        parse_cert(der)
    }

    /// Returns the whole DER.
    #[must_use]
    pub fn der(&self) -> &'a [u8] {
        self.der
    }

    /// Returns the version.
    #[must_use]
    pub fn version(&self) -> CertVersion {
        self.version
    }

    /// Returns the DER of `tbsCertificate`, the signed bytes.
    #[must_use]
    pub fn tbs(&self) -> &'a [u8] {
        self.tbs
    }

    /// Returns the content of the outer signatureAlgorithm. It compares
    /// with `SignatureVerificationAlgorithm::signature_alg_id`.
    #[must_use]
    pub fn signature_alg(&self) -> &'a [u8] {
        self.sig_alg
    }

    /// Returns the signature bits.
    #[must_use]
    pub fn signature(&self) -> &'a [u8] {
        self.signature
    }

    /// Returns the DER of the issuer Name.
    #[must_use]
    pub fn issuer(&self) -> &'a [u8] {
        self.issuer
    }

    /// Returns the DER of the subject Name.
    #[must_use]
    pub fn subject(&self) -> &'a [u8] {
        self.subject
    }

    /// Returns the serial number content.
    #[must_use]
    pub fn serial(&self) -> &'a [u8] {
        self.serial
    }

    /// Returns the validity period.
    #[must_use]
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// Returns basicConstraints, when present.
    #[must_use]
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        self.ext.bc
    }

    /// Returns the keyUsage bits (bit 0 is digitalSignature), when present.
    #[must_use]
    pub fn key_usage(&self) -> Option<u16> {
        self.ext.ku
    }

    /// Returns the extKeyUsage OIDs as DER contents, when present.
    #[must_use]
    pub fn ext_key_usage(&self) -> Option<Vec<&'a [u8]>> {
        self.ext.eku.clone()
    }

    /// Returns the Netscape cert type bits, when present.
    #[must_use]
    pub fn ns_cert_type(&self) -> Option<u8> {
        self.ext.ns
    }

    /// Returns the subjectKeyIdentifier, when present.
    #[must_use]
    pub fn subject_key_id(&self) -> Option<&'a [u8]> {
        self.ext.skid
    }

    /// Returns the authorityKeyIdentifier, when present.
    #[must_use]
    pub fn authority_key_id(&self) -> Option<AuthorityKeyId<'a>> {
        self.ext.akid
    }

    /// Returns the subjectAltName GeneralNames content, when present.
    #[must_use]
    pub fn subject_alt_name(&self) -> Option<&'a [u8]> {
        self.ext.san
    }

    /// Returns the nameConstraints content, when present.
    #[must_use]
    pub fn name_constraints(&self) -> Option<&'a [u8]> {
        self.ext.nc
    }

    /// Returns the OIDs of the critical extensions, as DER contents.
    #[must_use]
    pub fn critical_extensions(&self) -> Vec<&'a [u8]> {
        self.ext.critical.clone()
    }

    /// Returns the subjectPublicKeyInfo parts.
    #[must_use]
    pub fn spki(&self) -> Spki<'a> {
        self.spki
    }

    /// Returns the subjectPublicKeyInfo DER, for
    /// `verify_tls13_signature_with_raw_key`.
    #[must_use]
    pub fn spki_der(&self) -> SubjectPublicKeyInfoDer<'a> {
        SubjectPublicKeyInfoDer::from(self.spki_der)
    }

    /// Tells whether the certificate is valid at `now` (OpenSSL rule).
    #[must_use]
    pub fn valid_at(&self, now: UnixTime) -> bool {
        self.validity().contains(now)
    }

    /// OpenSSL 3.x `EXFLAG_SS`: the canonical subject equals the canonical
    /// issuer, the AKID is consistent with the certificate itself
    /// (`X509_check_akid`), and the signature key type matches the SPKI
    /// key type. The self-signature is never verified.
    #[must_use]
    pub fn openssl_self_signed(&self) -> bool {
        self.canon_subject == self.canon_issuer
            && akid_ok(self, self.ext.akid.as_ref())
            && sig_matches_key(self.sig_alg, &self.spki)
    }

    /// `X509_check_ca`: 0, 1, 3, 4 or 5, as OpenSSL defines.
    ///
    /// A keyUsage without keyCertSign gives 0. A basicConstraints gives
    /// its `cA` value. Without basicConstraints, a self-signed v1
    /// certificate gives 3, a keyUsage gives 4, and a Netscape CA type
    /// gives 5.
    #[must_use]
    pub fn openssl_check_ca(&self) -> u8 {
        if self.ext.ku.is_some_and(|ku| ku & KU_KEY_CERT_SIGN == 0) {
            return 0;
        }
        if let Some(bc) = self.ext.bc {
            return u8::from(bc.ca);
        }
        if self.version == CertVersion::V1 && self.openssl_self_signed() {
            3
        } else if self.ext.ku.is_some() {
            4
        } else if self.ext.ns.is_some_and(|ns| ns & NS_ANY_CA != 0) {
            5
        } else {
            0
        }
    }

    /// `xku_reject(x, XKU_SSL_SERVER|XKU_SGC)` is false: no EKU, or an
    /// EKU with serverAuth, Netscape SGC or Microsoft SGC.
    #[must_use]
    pub fn eku_allows_ssl_server(&self) -> bool {
        self.ext.eku.as_ref().is_none_or(|eku| {
            eku.iter()
                .any(|o| *o == OID_SERVER_AUTH || *o == OID_NS_SGC || *o == OID_MS_SGC)
        })
    }

    /// Returns the OpenSSL canonical form of the subject. Two names are
    /// equal for `X509_NAME_cmp` when their canonical forms are equal.
    #[must_use]
    pub fn canonical_subject(&self) -> Vec<u8> {
        self.canon_subject.clone()
    }

    /// Returns the OpenSSL canonical form of the issuer.
    #[must_use]
    pub fn canonical_issuer(&self) -> Vec<u8> {
        self.canon_issuer.clone()
    }

    /// Returns the OpenSSL subject-name hash (`X509_NAME_hash_ex`): the
    /// first four bytes of the SHA-1 of the canonical subject, read as a
    /// little-endian `u32`. The SHA-1 comes from [`sha1_digest`].
    #[must_use]
    pub fn subject_hash(&self) -> u32 {
        name_hash(&self.canon_subject)
    }
}

/// `ossl_x509_likely_issued(issuer, subject)`: the names match in
/// canonical form, the AKID of `subject` is consistent with `issuer`, and
/// the signature key type of `subject` matches the SPKI key type of
/// `issuer`. No signature is verified.
#[must_use]
pub fn check_issued(issuer: &LegacyCert<'_>, subject: &LegacyCert<'_>) -> bool {
    issuer.canon_subject == subject.canon_issuer
        && akid_ok(issuer, subject.ext.akid.as_ref())
        && sig_matches_key(subject.sig_alg, &issuer.spki)
}

/// SHA-1 for the subject hash, from the provider crate of the build:
/// `ring::digest::SHA1_FOR_LEGACY_USE_ONLY`, or the aws-lc-rs digest. In
/// the FIPS build the FIPS module computes it.
#[must_use]
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    #[cfg(feature = "tls-ring")]
    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    #[cfg(all(
        not(feature = "tls-ring"),
        any(feature = "tls-aws-lc-rs", feature = "tls-aws-lc-rs-fips")
    ))]
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    <[u8; 20]>::try_from(d.as_ref()).unwrap_or([0; 20])
}

/// `X509_NAME_hash_ex` of a canonical name encoding.
pub(crate) fn name_hash(canonical: &[u8]) -> u32 {
    let [a, b, c, d, ..] = sha1_digest(canonical);
    u32::from_le_bytes([a, b, c, d])
}

// ---------------------------------------------------------------------
// The TLV reader.
// ---------------------------------------------------------------------

/// The decode rules of the reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Strict DER: minimal definite lengths and low tag numbers only.
    Der,
    /// The OpenSSL BER rules: long lengths, indefinite lengths for
    /// constructed values, and high tag numbers.
    Ber,
}

/// The OpenSSL limit for nested indefinite lengths
/// (`ASN1_MAX_CONSTRUCTED_NEST`).
const MAX_NEST: u32 = 30;

/// One decoded TLV.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tlv<'a> {
    /// The first identifier octet.
    pub(crate) tag: u8,
    /// The content octets. For an indefinite length the end-of-contents
    /// octets are not part of the content.
    pub(crate) content: &'a [u8],
    /// The whole encoding.
    pub(crate) raw: &'a [u8],
}

fn read_tlv(data: &[u8], mode: Mode, depth: u32) -> Option<(Tlv<'_>, usize)> {
    let (&tag, _) = data.split_first()?;
    let mut pos: usize = 1;
    if tag & 0x1f == 0x1f {
        if mode == Mode::Der {
            return None;
        }
        let mut count: u8 = 0;
        loop {
            let b = *data.get(pos)?;
            pos = pos.checked_add(1)?;
            count = count.checked_add(1)?;
            if b & 0x80 == 0 {
                break;
            }
            if count >= 5 {
                return None;
            }
        }
    }
    let first = *data.get(pos)?;
    pos = pos.checked_add(1)?;
    if first == 0x80 {
        if mode == Mode::Der || tag & 0x20 == 0 || depth >= MAX_NEST {
            return None;
        }
        let start = pos;
        loop {
            let rest = data.get(pos..)?;
            if rest.starts_with(&[0, 0]) {
                return tlv_at(data, tag, start..pos, pos.checked_add(2)?);
            }
            let (_, used) = read_tlv(rest, mode, depth.checked_add(1)?)?;
            pos = pos.checked_add(used)?;
        }
    }
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n > 4 {
            return None;
        }
        let end = pos.checked_add(n)?;
        let bytes = data.get(pos..end)?;
        pos = end;
        let mut v: usize = 0;
        for &b in bytes {
            v = v.checked_mul(256)?.checked_add(usize::from(b))?;
        }
        if mode == Mode::Der && (v < 0x80 || bytes.first() == Some(&0)) {
            return None;
        }
        v
    };
    let end = pos.checked_add(len)?;
    tlv_at(data, tag, pos..end, end)
}

/// Makes the TLV of `data` with the content range `content`. The whole
/// encoding is `..end`.
fn tlv_at(data: &[u8], tag: u8, content: Range<usize>, end: usize) -> Option<(Tlv<'_>, usize)> {
    let content = data.get(content)?;
    let raw = data.get(..end)?;
    Some((Tlv { tag, content, raw }, end))
}

/// A cursor over a sequence of TLVs.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    mode: Mode,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8], mode: Mode) -> Self {
        Self { data, mode }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads the next TLV of any tag.
    pub(crate) fn any(&mut self) -> Option<Tlv<'a>> {
        let (tlv, used) = read_tlv(self.data, self.mode, 0)?;
        self.data = self.data.get(used..)?;
        Some(tlv)
    }

    /// Reads the next TLV, which must have `tag`.
    pub(crate) fn tlv(&mut self, tag: u8) -> Option<Tlv<'a>> {
        if self.peek()? != tag {
            return None;
        }
        self.any()
    }

    /// Reads the content of the next TLV, which must have `tag`.
    pub(crate) fn take(&mut self, tag: u8) -> Option<&'a [u8]> {
        self.tlv(tag).map(|t| t.content)
    }

    /// Reads an optional TLV. The outer `None` is a decode error.
    pub(crate) fn opt(&mut self, tag: u8) -> Option<Option<Tlv<'a>>> {
        if self.peek() == Some(tag) {
            self.any().map(Some)
        } else {
            Some(None)
        }
    }

    /// Succeeds when the reader is at the end.
    pub(crate) fn finish(&self) -> Option<()> {
        self.is_empty().then_some(())
    }
}

// ---------------------------------------------------------------------
// Value rules. They copy the OpenSSL `c2i` checks.
// ---------------------------------------------------------------------

/// A non-empty, minimal INTEGER content.
pub(crate) fn int_ok(c: &[u8]) -> bool {
    match c {
        [] => false,
        [_] => true,
        [a, b, ..] => !((*a == 0 && *b & 0x80 == 0) || (*a == 0xff && *b & 0x80 != 0)),
    }
}

/// A BIT STRING content with at most 7 unused bits.
fn bits_ok(c: &[u8]) -> bool {
    c.first().is_some_and(|u| *u <= 7)
}

/// An OBJECT IDENTIFIER content with complete, minimal subidentifiers.
pub(crate) fn oid_ok(c: &[u8]) -> bool {
    let Some(last) = c.last() else {
        return false;
    };
    if *last & 0x80 != 0 {
        return false;
    }
    let mut start = true;
    for &b in c {
        if start && b == 0x80 {
            return false;
        }
        start = b & 0x80 == 0;
    }
    true
}

/// The OpenSSL rule for an `ANY` value.
fn any_ok(t: &Tlv<'_>) -> bool {
    let tag = t.tag;
    if tag == 0 || tag & 0x1f == 0x1f {
        return false;
    }
    if tag & 0xc0 != 0 {
        return true;
    }
    if tag & 0x20 != 0 {
        return tag == 0x30 || tag == 0x31;
    }
    let c = t.content;
    match tag {
        0x01 => c.len() == 1,
        0x02 | 0x0a => int_ok(c),
        0x03 => bits_ok(c),
        0x05 => c.is_empty(),
        0x06 => oid_ok(c),
        0x1c => c.len() & 3 == 0,
        0x1e => c.len() & 1 == 0,
        _ => true,
    }
}

/// An AlgorithmIdentifier content: an OID and at most one parameter.
pub(crate) fn algid_ok(c: &[u8], mode: Mode) -> Option<()> {
    let mut r = Reader::new(c, mode);
    if !oid_ok(r.take(0x06)?) {
        return None;
    }
    if !r.is_empty() {
        let p = r.any()?;
        if !any_ok(&p) {
            return None;
        }
    }
    r.finish()
}

/// The first OID of an AlgorithmIdentifier content.
fn algid_oid(c: &[u8]) -> Option<&[u8]> {
    Reader::new(c, Mode::Der).take(0x06)
}

/// The OpenSSL rule for a `Time` (3.6 length rule).
fn ber_time_ok(t: &Tlv<'_>) -> bool {
    match t.tag {
        0x17 => t.content.len() >= 13,
        0x18 => t.content.len() >= 15,
        _ => false,
    }
}

// ---------------------------------------------------------------------
// Name canonicalization (`x509_name_canon`).
// ---------------------------------------------------------------------

/// Appends a TLV with a DER length.
pub(crate) fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let used = bytes.get(skip..).unwrap_or(&[]);
        out.push(0x80 | u8::try_from(used.len()).unwrap_or(0));
        out.extend_from_slice(used);
    }
    out.extend_from_slice(content);
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The `asn1_string_canon` text filter over UTF-8 bytes. It drops leading
/// and trailing ASCII white space. It folds each inner run of white space
/// to one space, and it changes ASCII letters to lower case. The bytes of
/// a multi-byte UTF-8 sequence are never white space, so they do not
/// change.
#[derive(Default)]
struct CanonText {
    started: bool,
    pending_space: bool,
}

impl CanonText {
    fn push(&mut self, out: &mut Vec<u8>, b: u8) {
        if is_space(b) {
            self.pending_space = self.started;
            return;
        }
        if self.pending_space {
            out.push(b' ');
            self.pending_space = false;
        }
        out.push(b.to_ascii_lowercase());
        self.started = true;
    }

    fn push_char(&mut self, out: &mut Vec<u8>, c: char) {
        let mut utf8 = [0u8; 4];
        for &b in c.encode_utf8(&mut utf8).as_bytes() {
            self.push(out, b);
        }
    }
}

/// Writes the canonical UTF-8 text of a string value to `out`. It gives
/// `None` when OpenSSL cannot convert the value to UTF-8.
fn canon_string(tag: u8, c: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let mut canon = CanonText::default();
    match tag {
        0x0c => {
            for &b in std::str::from_utf8(c).ok()?.as_bytes() {
                canon.push(out, b);
            }
        }
        0x13 | 0x14 | 0x16 => {
            for &b in c {
                canon.push_char(out, char::from(b));
            }
        }
        0x1c => canon_units::<4>(&mut canon, out, c, u32::from_be_bytes)?,
        0x1e => canon_units::<2>(&mut canon, out, c, |w| u32::from(u16::from_be_bytes(w)))?,
        _ => return None,
    }
    Some(())
}

/// Writes the canonical text of a UniversalString (`N` = 4) or a
/// BMPString (`N` = 2). Each big-endian unit of `N` bytes is one code
/// point. A partial unit or a value that is not a code point gives `None`.
fn canon_units<const N: usize>(
    canon: &mut CanonText,
    out: &mut Vec<u8>,
    c: &[u8],
    unit: impl Fn([u8; N]) -> u32,
) -> Option<()> {
    let units = c.chunks_exact(N);
    if !units.remainder().is_empty() {
        return None;
    }
    for q in units {
        let w = <[u8; N]>::try_from(q).ok()?;
        canon.push_char(out, char::from_u32(unit(w))?);
    }
    Some(())
}

/// Writes the canonical BIT STRING TLV of a checked content. A value
/// without bits keeps only a zero unused-bits octet. Otherwise the unused
/// bits of the last octet become zero.
fn push_canon_bits(out: &mut Vec<u8>, c: &[u8]) {
    let unused = c.first().copied().unwrap_or(0);
    if c.len() <= 1 {
        push_tlv(out, 0x03, &[0]);
        return;
    }
    push_tlv(out, 0x03, c);
    let keep = 0xffu8.checked_shl(u32::from(unused)).unwrap_or(0);
    if let Some(last) = out.last_mut() {
        *last &= keep;
    }
}

/// The DER size of a TLV with `len` content bytes.
fn tlv_size(len: usize) -> usize {
    let head = if len < 0x80 {
        2
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        2usize.saturating_add(bytes.len().saturating_sub(skip))
    };
    head.saturating_add(len)
}

/// Appends a tag and a DER length.
fn push_head(out: &mut Vec<u8>, tag: u8, len: usize) {
    out.push(tag);
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let used = bytes.get(skip..).unwrap_or(&[]);
        out.push(0x80 | u8::try_from(used.len()).unwrap_or(0));
        out.extend_from_slice(used);
    }
}

/// The canonical form of one attribute value. The value is known before
/// it is written, so the attribute head gets its length first.
enum CanonValue<'a> {
    /// A DER value that does not change.
    Raw(&'a [u8]),
    /// A BIT STRING content with a valid unused-bits octet.
    Bits(&'a [u8]),
    /// A value with this tag and this content.
    Tlv(u8, &'a [u8]),
}

impl<'a> CanonValue<'a> {
    /// Gives the canonical form of a value. String values go to `text`
    /// as canonical UTF-8. It gives `None` when OpenSSL cannot decode or
    /// convert the value.
    fn from_tlv(t: &Tlv<'a>, text: &'a mut Vec<u8>) -> Option<Self> {
        let c = t.content;
        Some(match t.tag {
            0x30 => Self::Raw(t.raw),
            0x03 => {
                if *c.first()? > 7 {
                    return None;
                }
                Self::Bits(c)
            }
            0x07 | 0x08 | 0x09 | 0x0b | 0x0d | 0x0e | 0x0f | 0x12 | 0x1d => Self::Tlv(t.tag, c),
            tag => {
                text.clear();
                canon_string(tag, c, text)?;
                Self::Tlv(0x0c, text)
            }
        })
    }

    /// The DER size of the canonical value.
    fn size(&self) -> usize {
        match *self {
            Self::Raw(raw) => raw.len(),
            Self::Bits(c) | Self::Tlv(_, c) => tlv_size(c.len()),
        }
    }

    /// Appends the canonical value to `out`.
    fn push_to(&self, out: &mut Vec<u8>) {
        match *self {
            Self::Raw(raw) => out.extend_from_slice(raw),
            Self::Bits(c) => push_canon_bits(out, c),
            Self::Tlv(tag, c) => push_tlv(out, tag, c),
        }
    }
}

/// The work buffers of one name canonicalization.
///
/// The buffers keep their capacity from one attribute to the next and
/// from one RDN to the next. Each attribute goes straight to `attrs`.
/// Thus a name costs a small fixed number of allocations.
struct NameCanon {
    /// The canonical attributes of the current RDN, one after the other.
    attrs: Vec<u8>,
    /// The byte range of each attribute in `attrs`.
    spans: Vec<(usize, usize)>,
    /// The canonical text of the current string value.
    text: Vec<u8>,
}

impl NameCanon {
    /// Makes the buffers for a name of `len` bytes. The canonical form of
    /// an RDN is seldom longer than the name, so the buffers seldom grow.
    fn with_capacity(len: usize) -> Self {
        Self {
            attrs: Vec::with_capacity(len),
            spans: Vec::new(),
            text: Vec::with_capacity(len),
        }
    }

    /// Canonicalizes the attributes of one RDN into `attrs`. It gives
    /// `None` when the RDN does not decode.
    fn rdn(&mut self, set: &[u8], mode: Mode) -> Option<()> {
        self.attrs.clear();
        self.spans.clear();
        let mut sr = Reader::new(set, mode);
        while !sr.is_empty() {
            let ava = sr.take(0x30)?;
            let mut ar = Reader::new(ava, mode);
            let oid = ar.take(0x06)?;
            if !oid_ok(oid) {
                return None;
            }
            let value = ar.any()?;
            ar.finish()?;
            self.attr(oid, &value)?;
        }
        Some(())
    }

    /// Appends the canonical `SEQUENCE { oid, value }` of one attribute.
    fn attr(&mut self, oid: &[u8], t: &Tlv<'_>) -> Option<()> {
        let value = CanonValue::from_tlv(t, &mut self.text)?;
        let start = self.attrs.len();
        let body = tlv_size(oid.len()).saturating_add(value.size());
        push_head(&mut self.attrs, 0x30, body);
        push_tlv(&mut self.attrs, 0x06, oid);
        value.push_to(&mut self.attrs);
        self.spans.push((start, self.attrs.len()));
        Some(())
    }

    /// Appends the current RDN as a SET to `out`. The SET orders the
    /// attributes by their encodings. An RDN without attributes adds
    /// nothing.
    fn push_rdn(&mut self, out: &mut Vec<u8>) {
        if self.spans.is_empty() {
            return;
        }
        let attrs = &self.attrs;
        let span = |s: &(usize, usize)| attrs.get(s.0..s.1).unwrap_or(&[]);
        self.spans.sort_unstable_by(|a, b| span(a).cmp(span(b)));
        push_head(out, 0x31, attrs.len());
        for s in &self.spans {
            out.extend_from_slice(span(s));
        }
    }
}

/// The canonical encoding of a Name content (the RDN sequence), or `None`
/// when the name does not decode. An empty name gives an empty encoding.
pub(crate) fn canonical_name(name: &[u8], mode: Mode) -> Option<Vec<u8>> {
    let mut r = Reader::new(name, mode);
    let mut out = Vec::with_capacity(name.len());
    let mut canon = NameCanon::with_capacity(name.len());
    while !r.is_empty() {
        canon.rdn(r.take(0x31)?, mode)?;
        canon.push_rdn(&mut out);
    }
    Some(out)
}

// ---------------------------------------------------------------------
// The OpenSSL structural decode (BER).
// ---------------------------------------------------------------------

fn ber_exts_ok(c: &[u8]) -> Option<()> {
    let mut r = Reader::new(c, Mode::Ber);
    while !r.is_empty() {
        let mut er = Reader::new(r.take(0x30)?, Mode::Ber);
        if !oid_ok(er.take(0x06)?) {
            return None;
        }
        if let Some(b) = er.opt(0x01)? {
            if b.content.len() != 1 {
                return None;
            }
        }
        er.take(0x04)?;
        er.finish()?;
    }
    Some(())
}

fn ber_bits(r: &mut Reader<'_>, tag: u8) -> Option<()> {
    bits_ok(r.take(tag)?).then_some(())
}

fn ber_name(r: &mut Reader<'_>) -> Option<()> {
    canonical_name(r.take(0x30)?, Mode::Ber).map(|_| ())
}

fn ber_time(r: &mut Reader<'_>) -> Option<()> {
    ber_time_ok(&r.any()?).then_some(())
}

fn ber_int(r: &mut Reader<'_>) -> Option<()> {
    int_ok(r.take(0x02)?).then_some(())
}

/// An optional explicit `[tag]` that wraps a SEQUENCE of extensions.
fn ber_explicit_exts(r: &mut Reader<'_>, tag: u8) -> Option<()> {
    if let Some(e) = r.opt(tag)? {
        let mut er = Reader::new(e.content, Mode::Ber);
        ber_exts_ok(er.take(0x30)?)?;
        er.finish()?;
    }
    Some(())
}

fn ber_tbs(c: &[u8]) -> Option<()> {
    let mut r = Reader::new(c, Mode::Ber);
    if let Some(v) = r.opt(0xA0)? {
        let mut vr = Reader::new(v.content, Mode::Ber);
        ber_int(&mut vr)?;
        vr.finish()?;
    }
    ber_int(&mut r)?;
    algid_ok(r.take(0x30)?, Mode::Ber)?;
    ber_name(&mut r)?;
    let mut vr = Reader::new(r.take(0x30)?, Mode::Ber);
    ber_time(&mut vr)?;
    ber_time(&mut vr)?;
    vr.finish()?;
    ber_name(&mut r)?;
    let mut sr = Reader::new(r.take(0x30)?, Mode::Ber);
    algid_ok(sr.take(0x30)?, Mode::Ber)?;
    ber_bits(&mut sr, 0x03)?;
    sr.finish()?;
    for tag in [0x81, 0x82] {
        if r.peek() == Some(tag) {
            ber_bits(&mut r, tag)?;
        }
    }
    ber_explicit_exts(&mut r, 0xA3)?;
    r.finish()
}

/// The OpenSSL `d2i_X509` structural test. On success it returns the
/// bytes after the certificate, which `d2i_X509` ignores.
pub(crate) fn ber_certificate(data: &[u8]) -> Option<&[u8]> {
    let mut top = Reader::new(data, Mode::Ber);
    let cert = top.take(0x30)?;
    let mut r = Reader::new(cert, Mode::Ber);
    ber_tbs(r.take(0x30)?)?;
    algid_ok(r.take(0x30)?, Mode::Ber)?;
    ber_bits(&mut r, 0x03)?;
    r.finish()?;
    Some(top.rest())
}

/// The canonical subject of a certificate that passes the `d2i_X509`
/// structural test, or `None` when the subject does not decode. The
/// trust loader uses it for an input that `LegacyCert` refuses.
pub(crate) fn ber_subject(data: &[u8]) -> Option<Vec<u8>> {
    let mut t = ber_tbs_after(data, &[0x02, 0x30, 0x30, 0x30])?;
    canonical_name(t.take(0x30)?, Mode::Ber)
}

/// Opens the TBSCertificate of a certificate, skips the optional
/// version, and then skips one TLV for each tag of `skip`.
fn ber_tbs_after<'a>(data: &'a [u8], skip: &[u8]) -> Option<Reader<'a>> {
    let mut top = Reader::new(data, Mode::Ber);
    let mut r = Reader::new(top.take(0x30)?, Mode::Ber);
    let mut t = Reader::new(r.take(0x30)?, Mode::Ber);
    t.opt(0xA0)?;
    for &tag in skip {
        t.take(tag)?;
    }
    Some(t)
}

/// Tells whether a certificate that passes the `d2i_X509` structural
/// test has two extensions with the same OID. OpenSSL then marks the
/// certificate invalid, and `X509_check_issued` never selects it as an
/// issuer. The trust loader uses it for an input that `LegacyCert`
/// refuses. Any other refusal gives `false`, so that the input stays a
/// possible issuer.
pub(crate) fn ber_duplicate_extension(data: &[u8]) -> bool {
    ber_extension_oids(data).is_some_and(|oids| {
        let distinct: BTreeSet<&[u8]> = oids.iter().copied().collect();
        distinct.len() != oids.len()
    })
}

fn ber_extension_oids(data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut t = ber_tbs_after(data, &[0x02, 0x30, 0x30, 0x30, 0x30, 0x30])?;
    for tag in [0x81, 0x82] {
        if t.peek() == Some(tag) {
            t.any()?;
        }
    }
    let ext = t.opt(0xA3)??;
    let mut er = Reader::new(Reader::new(ext.content, Mode::Ber).take(0x30)?, Mode::Ber);
    let mut oids = Vec::new();
    while !er.is_empty() {
        oids.push(Reader::new(er.take(0x30)?, Mode::Ber).take(0x06)?);
    }
    Some(oids)
}

/// The OpenSSL `d2i_X509_CRL` structural test. It ignores trailing bytes.
pub(crate) fn ber_crl_ok(data: &[u8]) -> bool {
    ber_crl(data).is_some()
}

fn ber_crl(data: &[u8]) -> Option<()> {
    let mut top = Reader::new(data, Mode::Ber);
    let mut r = Reader::new(top.take(0x30)?, Mode::Ber);
    let mut t = Reader::new(r.take(0x30)?, Mode::Ber);
    if let Some(v) = t.opt(0x02)? {
        if !int_ok(v.content) {
            return None;
        }
    }
    algid_ok(t.take(0x30)?, Mode::Ber)?;
    ber_name(&mut t)?;
    ber_time(&mut t)?;
    if matches!(t.peek(), Some(0x17 | 0x18)) {
        ber_time(&mut t)?;
    }
    if t.peek() == Some(0x30) {
        let mut rr = Reader::new(t.take(0x30)?, Mode::Ber);
        while !rr.is_empty() {
            let mut er = Reader::new(rr.take(0x30)?, Mode::Ber);
            ber_int(&mut er)?;
            ber_time(&mut er)?;
            if let Some(x) = er.opt(0x30)? {
                ber_exts_ok(x.content)?;
            }
            er.finish()?;
        }
    }
    ber_explicit_exts(&mut t, 0xA0)?;
    t.finish()?;
    algid_ok(r.take(0x30)?, Mode::Ber)?;
    ber_bits(&mut r, 0x03)?;
    r.finish()
}

/// A list of valid OBJECT IDENTIFIER values. The list can be empty.
fn oid_list(c: &[u8], mode: Mode) -> Option<Vec<&[u8]>> {
    let mut r = Reader::new(c, mode);
    let mut out = Vec::new();
    while !r.is_empty() {
        let oid = r.take(0x06)?;
        if !oid_ok(oid) {
            return None;
        }
        out.push(oid);
    }
    Some(out)
}

fn ber_oid_list(c: &[u8]) -> Option<Vec<Vec<u8>>> {
    Some(
        oid_list(c, Mode::Ber)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect(),
    )
}

/// The OpenSSL `d2i_X509_CERT_AUX` decode. It ignores trailing bytes.
fn ber_aux(data: &[u8]) -> Option<AuxTrust> {
    let mut top = Reader::new(data, Mode::Ber);
    let mut r = Reader::new(top.take(0x30)?, Mode::Ber);
    let trust = match r.opt(0x30)? {
        Some(t) => Some(ber_oid_list(t.content)?),
        None => None,
    };
    let reject = match r.opt(0xA0)? {
        Some(t) => Some(ber_oid_list(t.content)?),
        None => None,
    };
    r.opt(0x0c)?;
    r.opt(0x04)?;
    if let Some(o) = r.opt(0xA1)? {
        let mut or = Reader::new(o.content, Mode::Ber);
        while !or.is_empty() {
            algid_ok(or.take(0x30)?, Mode::Ber)?;
        }
    }
    r.finish()?;
    Some(AuxTrust { trust, reject })
}

// ---------------------------------------------------------------------
// The strict DER parse.
// ---------------------------------------------------------------------

const M: X509Error = X509Error::Malformed;

/// A BIT STRING content with no unused bits.
fn bits_exact(c: &[u8]) -> Option<&[u8]> {
    let (&unused, bits) = c.split_first()?;
    (unused == 0).then_some(bits)
}

/// A serial number that webpki and OpenSSL both take. Zero is valid,
/// because some deployed roots use it. A negative serial is not valid.
fn serial_ok(c: &[u8]) -> bool {
    let Some(&first) = c.first() else {
        return false;
    };
    int_ok(c) && first & 0x80 == 0 && (c.len() <= 20 || (c.len() == 21 && first == 0))
}

fn digits(s: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(u64::from(b & 0x0f))?;
    }
    Some(v)
}

fn is_leap(y: u64) -> Option<bool> {
    Some((y.checked_rem(4)? == 0 && y.checked_rem(100)? != 0) || y.checked_rem(400)? == 0)
}

/// Days from 0001-01-01 to the first day of `year`.
fn days_before_year(year: u64) -> Option<u64> {
    let y = year.checked_sub(1)?;
    y.checked_mul(365)?
        .checked_add(y.checked_div(4)?)?
        .checked_sub(y.checked_div(100)?)?
        .checked_add(y.checked_div(400)?)
}

/// Parses a strict UTCTime or GeneralizedTime. Times before 1970 fail.
fn parse_time(t: &Tlv<'_>) -> Option<UnixTime> {
    const CUM: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    const LEN: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let (year, rest) = match t.tag {
        0x17 if t.content.len() == 13 => {
            let (yy, rest) = t.content.split_at_checked(2)?;
            let yy = digits(yy)?;
            let base = if yy < 50 { 2000 } else { 1900 };
            (yy.checked_add(base)?, rest)
        }
        0x18 if t.content.len() == 15 => {
            let (y, rest) = t.content.split_at_checked(4)?;
            (digits(y)?, rest)
        }
        _ => return None,
    };
    let &[m1, m2, d1, d2, h1, h2, n1, n2, s1, s2, b'Z'] = rest else {
        return None;
    };
    let month = digits(&[m1, m2])?;
    let day = digits(&[d1, d2])?;
    let hour = digits(&[h1, h2])?;
    let min = digits(&[n1, n2])?;
    let sec = digits(&[s1, s2])?;
    if year < 1970 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let mi = usize::try_from(month.checked_sub(1)?).ok()?;
    let leap = is_leap(year)?;
    let mut mlen = *LEN.get(mi)?;
    if leap && month == 2 {
        mlen = 29;
    }
    if day == 0 || day > mlen {
        return None;
    }
    let mut days = days_before_year(year)?
        .checked_sub(719_162)?
        .checked_add(*CUM.get(mi)?)?
        .checked_add(day.checked_sub(1)?)?;
    if leap && month > 2 {
        days = days.checked_add(1)?;
    }
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(min.checked_mul(60)?)?
        .checked_add(sec)?;
    Some(UnixTime::since_unix_epoch(Duration::from_secs(secs)))
}

/// Reads one wrapped value of `tag` that fills `v` exactly.
fn single(v: &[u8], tag: u8) -> Option<&[u8]> {
    let mut r = Reader::new(v, Mode::Der);
    let c = r.take(tag)?;
    r.finish()?;
    Some(c)
}

fn der_bool(t: &Tlv<'_>) -> Option<bool> {
    match t.content {
        [0] => Some(false),
        [0xff] => Some(true),
        _ => None,
    }
}

/// The bytes of a named-bit BIT STRING. Padding bits must be zero.
fn named_bits(v: &[u8]) -> Option<&[u8]> {
    let c = single(v, 0x03)?;
    let (&unused, bytes) = c.split_first()?;
    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return None;
    }
    if let Some(&last) = bytes.last() {
        let keep = 0xffu8.checked_shl(u32::from(unused))?;
        if last & !keep != 0 {
            return None;
        }
    }
    Some(bytes)
}

fn parse_bc(v: &[u8]) -> Option<BasicConstraints> {
    let mut r = Reader::new(single(v, 0x30)?, Mode::Der);
    let ca = match r.opt(0x01)? {
        Some(b) => der_bool(&b)?,
        None => false,
    };
    let path_len = match r.opt(0x02)? {
        Some(i) => {
            let c = i.content;
            if !int_ok(c) || c.first().is_some_and(|b| b & 0x80 != 0) {
                return None;
            }
            let skip = c.iter().take_while(|b| **b == 0).count();
            let mag = c.get(skip..)?;
            if mag.len() > 4 {
                return None;
            }
            let mut n: u32 = 0;
            for &b in mag {
                n = n.checked_mul(256)?.checked_add(u32::from(b))?;
            }
            Some(n)
        }
        None => None,
    };
    r.finish()?;
    Some(BasicConstraints { ca, path_len })
}

fn general_names_ok(c: &[u8]) -> Option<()> {
    let mut r = Reader::new(c, Mode::Der);
    while !r.is_empty() {
        let g = r.any()?;
        match g.tag {
            0xA0 | 0xA3 | 0xA5 | 0x81 | 0x82 | 0x86 | 0x87 | 0x88 => {}
            0xA4 => {
                canonical_name(single(g.content, 0x30)?, Mode::Der)?;
            }
            _ => return None,
        }
    }
    Some(())
}

fn first_dir_name(gn: &[u8]) -> Option<&[u8]> {
    let mut r = Reader::new(gn, Mode::Der);
    while !r.is_empty() {
        let g = r.any()?;
        if g.tag == 0xA4 {
            return single(g.content, 0x30);
        }
    }
    None
}

fn parse_akid(v: &[u8]) -> Option<AuthorityKeyId<'_>> {
    let mut r = Reader::new(single(v, 0x30)?, Mode::Der);
    let key_id = r.opt(0x80)?.map(|t| t.content);
    let issuer = r.opt(0xA1)?.map(|t| t.content);
    if let Some(gn) = issuer {
        general_names_ok(gn)?;
    }
    let serial = r.opt(0x82)?.map(|t| t.content);
    if serial.is_some_and(|s| !int_ok(s)) {
        return None;
    }
    r.finish()?;
    Some(AuthorityKeyId {
        key_id,
        issuer,
        serial,
    })
}

fn parse_eku(v: &[u8]) -> Option<Vec<&[u8]>> {
    oid_list(single(v, 0x30)?, Mode::Der).filter(|oids| !oids.is_empty())
}

fn parse_extensions(list: &[u8]) -> Result<Extensions<'_>, X509Error> {
    let mut r = Reader::new(list, Mode::Der);
    if r.is_empty() {
        return Err(M);
    }
    let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
    let mut x = Extensions::default();
    while !r.is_empty() {
        let mut er = Reader::new(r.take(0x30).ok_or(M)?, Mode::Der);
        let oid = er.take(0x06).ok_or(M)?;
        if !oid_ok(oid) || !seen.insert(oid) {
            return Err(M);
        }
        let critical = match er.opt(0x01).ok_or(M)? {
            Some(b) => der_bool(&b).ok_or(M)?,
            None => false,
        };
        let v = er.take(0x04).ok_or(M)?;
        er.finish().ok_or(M)?;
        if critical {
            x.critical.push(oid);
        }
        if oid == OID_BC {
            x.bc = Some(parse_bc(v).ok_or(M)?);
        } else if oid == OID_KU {
            let b = named_bits(v).ok_or(M)?;
            let lo = b.first().map_or(0, |b| b.reverse_bits());
            let hi = b.get(1).map_or(0, |b| b.reverse_bits());
            x.ku = Some(u16::from_le_bytes([lo, hi]));
        } else if oid == OID_EKU {
            x.eku = Some(parse_eku(v).ok_or(M)?);
        } else if oid == OID_NS_CERT_TYPE {
            let b = named_bits(v).ok_or(M)?;
            x.ns = Some(b.first().map_or(0, |b| b.reverse_bits()));
        } else if oid == OID_SKID {
            x.skid = Some(single(v, 0x04).ok_or(M)?);
        } else if oid == OID_AKID {
            x.akid = Some(parse_akid(v).ok_or(M)?);
        } else if oid == OID_SAN {
            let gn = single(v, 0x30).ok_or(M)?;
            general_names_ok(gn).ok_or(M)?;
            x.san = Some(gn);
        } else if oid == OID_NC {
            let nc = single(v, 0x30).ok_or(M)?;
            let mut nr = Reader::new(nc, Mode::Der);
            nr.opt(0xA0).ok_or(M)?;
            nr.opt(0xA1).ok_or(M)?;
            nr.finish().ok_or(M)?;
            x.nc = Some(nc);
        }
    }
    Ok(x)
}

/// Reads an AlgorithmIdentifier and then a BIT STRING with no unused
/// bits. The two values must end the reader.
fn der_alg_bits<'a>(r: &mut Reader<'a>) -> Option<(&'a [u8], &'a [u8])> {
    let alg = r.take(0x30)?;
    algid_ok(alg, Mode::Der)?;
    let bits = bits_exact(r.take(0x03)?)?;
    r.finish()?;
    Some((alg, bits))
}

/// Reads a Name and gives it with its canonical form.
fn der_name<'a>(r: &mut Reader<'a>) -> Option<(Tlv<'a>, Vec<u8>)> {
    let name = r.tlv(0x30)?;
    let canon = canonical_name(name.content, Mode::Der)?;
    Some((name, canon))
}

/// Reads a strict Time.
fn der_time(r: &mut Reader<'_>) -> Option<UnixTime> {
    parse_time(&r.any()?)
}

fn parse_cert(der: &[u8]) -> Result<LegacyCert<'_>, X509Error> {
    let cert = single(der, 0x30).ok_or(M)?;
    let mut cr = Reader::new(cert, Mode::Der);
    let tbs = cr.tlv(0x30).ok_or(M)?;
    let (sig_alg, signature) = der_alg_bits(&mut cr).ok_or(M)?;

    let mut t = Reader::new(tbs.content, Mode::Der);
    let version = match t.opt(0xA0).ok_or(M)? {
        None => CertVersion::V1,
        Some(v) => {
            let n = single(v.content, 0x02).ok_or(M)?;
            match n {
                [2] => CertVersion::V3,
                [0] => return Err(M),
                _ if int_ok(n) => return Err(X509Error::Unsupported),
                _ => return Err(M),
            }
        }
    };
    let serial = t.take(0x02).ok_or(M)?;
    if !serial_ok(serial) {
        return Err(M);
    }
    if t.take(0x30).ok_or(M)? != sig_alg {
        return Err(M);
    }
    let (issuer, canon_issuer) = der_name(&mut t).ok_or(M)?;
    let mut vr = Reader::new(t.take(0x30).ok_or(M)?, Mode::Der);
    let not_before = der_time(&mut vr).ok_or(M)?;
    let not_after = der_time(&mut vr).ok_or(M)?;
    vr.finish().ok_or(M)?;
    let (subject, canon_subject) = der_name(&mut t).ok_or(M)?;
    let spki_tlv = t.tlv(0x30).ok_or(M)?;
    let (alg_id_value, key_bits) =
        der_alg_bits(&mut Reader::new(spki_tlv.content, Mode::Der)).ok_or(M)?;
    if matches!(t.peek(), Some(0x81 | 0x82 | 0xA1 | 0xA2)) {
        return Err(X509Error::Unsupported);
    }
    let ext = match t.opt(0xA3).ok_or(M)? {
        None => Extensions::default(),
        Some(_) if version == CertVersion::V1 => return Err(M),
        Some(e) => parse_extensions(single(e.content, 0x30).ok_or(M)?)?,
    };
    t.finish().ok_or(M)?;
    Ok(LegacyCert {
        der,
        tbs: tbs.raw,
        sig_alg,
        signature,
        version,
        serial,
        issuer: issuer.raw,
        subject: subject.raw,
        validity: Validity {
            not_before,
            not_after,
        },
        spki_der: spki_tlv.raw,
        spki: Spki {
            alg_id_value,
            key_bits,
        },
        ext,
        canon_subject,
        canon_issuer,
    })
}

// ---------------------------------------------------------------------
// Issuer rules.
// ---------------------------------------------------------------------

/// `X509_check_akid(issuer, akid) == X509_V_OK`.
fn akid_ok(issuer: &LegacyCert<'_>, akid: Option<&AuthorityKeyId<'_>>) -> bool {
    let Some(a) = akid else {
        return true;
    };
    if let (Some(k), Some(s)) = (a.key_id, issuer.ext.skid) {
        if k != s {
            return false;
        }
    }
    if a.serial.is_some_and(|sn| sn != issuer.serial) {
        return false;
    }
    if let Some(name) = a.issuer.and_then(first_dir_name) {
        match canonical_name(name, Mode::Der) {
            Some(c) if c == issuer.canon_issuer => {}
            _ => return false,
        }
    }
    true
}

/// The key types that `check_sig_alg_match` tells apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyType {
    Rsa,
    RsaPss,
    Ec,
    Dsa,
    Ed25519,
    Ed448,
}

/// The key type that a signature algorithm needs. `RsaPss` here means
/// RSASSA-PSS, which matches an RSA or an RSA-PSS key.
fn sig_key_type(alg: &[u8]) -> Option<KeyType> {
    let oid = algid_oid(alg)?;
    let (&last, head) = oid.split_last()?;
    if head == PKCS1 {
        return match last {
            2..=5 | 11..=16 => Some(KeyType::Rsa),
            10 => Some(KeyType::RsaPss),
            _ => None,
        };
    }
    if head == ECDSA_SHA2 {
        return (1..=4).contains(&last).then_some(KeyType::Ec);
    }
    if head == NIST_SIG {
        return match last {
            1..=8 => Some(KeyType::Dsa),
            9..=12 => Some(KeyType::Ec),
            13..=16 => Some(KeyType::Rsa),
            _ => None,
        };
    }
    if oid == OID_EC_SHA1 {
        Some(KeyType::Ec)
    } else if oid == OID_DSA_SHA1 || oid == OID_OIW_DSA_SHA1 {
        Some(KeyType::Dsa)
    } else if oid == OID_OIW_RSA_SHA1 {
        Some(KeyType::Rsa)
    } else if oid == OID_ED25519 {
        Some(KeyType::Ed25519)
    } else if oid == OID_ED448 {
        Some(KeyType::Ed448)
    } else {
        None
    }
}

/// The type of a key that decodes, approximately as `X509_get0_pubkey`.
fn spki_key_type(spki: &Spki<'_>) -> Option<KeyType> {
    let oid = algid_oid(spki.alg_id_value)?;
    let key = spki.key_bits;
    let (&last, head) = oid.split_last()?;
    if head == PKCS1 && (last == 1 || last == 10) {
        let mut r = Reader::new(single(key, 0x30)?, Mode::Der);
        if !int_ok(r.take(0x02)?) || !int_ok(r.take(0x02)?) {
            return None;
        }
        r.finish()?;
        return Some(if last == 1 {
            KeyType::Rsa
        } else {
            KeyType::RsaPss
        });
    }
    if oid == OID_EC_KEY {
        return matches!(key.first(), Some(2..=4)).then_some(KeyType::Ec);
    }
    if oid == OID_DSA_KEY {
        return int_ok(single(key, 0x02)?).then_some(KeyType::Dsa);
    }
    if oid == OID_ED25519 {
        return (key.len() == 32).then_some(KeyType::Ed25519);
    }
    if oid == OID_ED448 {
        return (key.len() == 57).then_some(KeyType::Ed448);
    }
    None
}

/// `check_sig_alg_match(key, cert) == X509_V_OK`.
fn sig_matches_key(sig_alg: &[u8], key: &Spki<'_>) -> bool {
    match (sig_key_type(sig_alg), spki_key_type(key)) {
        (Some(KeyType::RsaPss), Some(KeyType::Rsa | KeyType::RsaPss)) => true,
        (Some(s), Some(k)) => s == k,
        _ => false,
    }
}

#[cfg(test)]
#[path = "canon_diff_tests.rs"]
mod canon_diff_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_limits_indefinite_nesting() {
        let mut deep = Vec::new();
        for _ in 0..40 {
            deep.extend_from_slice(&[0x30, 0x80]);
        }
        for _ in 0..40 {
            deep.extend_from_slice(&[0, 0]);
        }
        assert!(read_tlv(&deep, Mode::Ber, 0).is_none());
        assert!(read_tlv(&deep, Mode::Der, 0).is_none());
        let ok = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00];
        let (t, used) = read_tlv(&ok, Mode::Ber, 0).unwrap_or_else(|| unreachable!());
        assert_eq!(used, ok.len());
        assert_eq!(t.content, &[0x02, 0x01, 0x05]);
    }

    #[test]
    fn der_rejects_long_form_short_length() {
        let v = [0x04, 0x81, 0x01, 0xAA];
        assert!(read_tlv(&v, Mode::Der, 0).is_none());
        assert!(read_tlv(&v, Mode::Ber, 0).is_some());
    }

    #[test]
    fn integer_and_oid_rules() {
        assert!(int_ok(&[0x00]));
        assert!(int_ok(&[0x00, 0x80]));
        assert!(!int_ok(&[0x00, 0x7f]));
        assert!(!int_ok(&[0xff, 0x80]));
        assert!(!int_ok(&[]));
        assert!(oid_ok(&[0x55, 0x1d, 0x13]));
        assert!(!oid_ok(&[0x55, 0x80, 0x01]));
        assert!(!oid_ok(&[0x55, 0x81]));
    }

    /// `asn1_string_canon` on UTF-8 text.
    fn canon_text(text: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut canon = CanonText::default();
        for &b in text {
            canon.push(&mut out, b);
        }
        out
    }

    #[test]
    fn canon_text_folds_space_and_case() {
        assert_eq!(canon_text(b"  Hello \t\n World  "), b"hello world");
        assert_eq!(canon_text(b"   "), b"");
        assert_eq!(canon_text("\u{c4}B".as_bytes()), "\u{c4}b".as_bytes());
    }

    #[test]
    fn time_rules() {
        let t = |tag: u8, s: &[u8]| {
            parse_time(&Tlv {
                tag,
                content: s,
                raw: s,
            })
            .map(|t| t.as_secs())
        };
        assert_eq!(t(0x17, b"700101000000Z"), Some(0));
        assert_eq!(t(0x18, b"20000301000000Z"), Some(951_868_800));
        assert_eq!(t(0x17, b"240229235959Z"), Some(1_709_251_199));
        assert_eq!(t(0x17, b"230229000000Z"), None);
        assert_eq!(t(0x18, b"19691231235959Z"), None);
        assert_eq!(t(0x17, b"240101000060Z"), None);
        assert_eq!(t(0x17, b"2401010000Z"), None);
    }
}
