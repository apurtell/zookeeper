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

//! The v1-leaf verifier and the OpenSSL path post-check.
//!
//! webpki does not parse X.509 v1 certificates. This module applies the
//! OpenSSL 3.x chain rules (`x509_vfy.c`, `v3_purp.c`) with its own path
//! building. `verify` is the acceptance path for v1 leaves.
//! `verify_v3_path` runs the same selection and finish rules after
//! webpki has accepted a v3 leaf, and it can only reject.
//!
//! The rules: trusted-first issuer selection with `check_issued`, then
//! the `find_issuer` order over the sent certificates; no sent issuer
//! above a trusted bridge or a self-signed sent certificate; the
//! ambiguity rule; keyCertSign and the Rejected-input check on each
//! chosen issuer; then `check_ca`, the `ssl_server` CA purpose,
//! pathLenConstraint, name constraints and critical extensions on the
//! finished path. `WORK_BUDGET` bounds the work that hostile same-name
//! certificates can cause.
//!
//! Signatures go only through the provider's
//! `SignatureVerificationAlgorithm` objects. In the FIPS build they run
//! in the FIPS module.
//!
//! The module has a small bounded DER reader of its own. It reads the
//! parts that `LegacyCert` gives as raw bytes: names, subjectAltName and
//! nameConstraints. Every read is checked, so bad input gives a
//! rejection and never a panic.

use rustls::pki_types::{SignatureVerificationAlgorithm, UnixTime};

use crate::net::tls::trust::{Origin, Role, TrustSet, TrustedCert};
use crate::net::tls::x509::{AuxTrust, CertVersion, LegacyCert, check_issued};

/// OpenSSL's default verify depth, in intermediates.
pub(crate) const MAX_DEPTH: usize = 100;

/// The candidate evaluations allowed for one verification.
pub(crate) const WORK_BUDGET: usize = 256;

/// keyUsage digitalSignature. `LegacyCert::key_usage` numbers the bits
/// as the named bits of RFC 5280: bit 0 is digitalSignature.
pub(crate) const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
/// keyUsage keyEncipherment (named bit 2).
pub(crate) const KU_KEY_ENCIPHERMENT: u16 = 1 << 2;
/// keyUsage keyAgreement (named bit 4).
pub(crate) const KU_KEY_AGREEMENT: u16 = 1 << 4;
/// keyUsage keyCertSign (named bit 5).
pub(crate) const KU_KEY_CERT_SIGN: u16 = 1 << 5;

/// Netscape cert type sslServer. The bits use the named-bit numbering
/// of keyUsage: bit 0 is sslClient.
pub(crate) const NS_SSL_SERVER: u8 = 1 << 1;
/// Netscape cert type sslCA (named bit 5).
pub(crate) const NS_SSL_CA: u8 = 1 << 5;

/// OpenSSL's `NAME_CHECK_MAX`: the largest product of names and
/// constraints that one name-constraint check accepts.
const NAME_CHECK_MAX: usize = 1 << 20;

/// The critical extensions that the verifier processes, as OID contents.
const PROCESSED_CRITICAL: [&[u8]; 6] = [
    // basicConstraints
    &[0x55, 0x1d, 0x13],
    // keyUsage
    &[0x55, 0x1d, 0x0f],
    // extKeyUsage
    &[0x55, 0x1d, 0x25],
    // subjectAltName
    &[0x55, 0x1d, 0x11],
    // nameConstraints
    &[0x55, 0x1d, 0x1e],
    // Netscape cert type
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01],
];

/// The commonName attribute type.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// The PKCS #9 emailAddress attribute type.
const OID_EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
/// The SmtpUTF8Mailbox otherName type (RFC 8398).
const OID_SMTP_UTF8_MAILBOX: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x09];

/// DER tags that this module reads.
const TAG_INTEGER: u8 = 0x02;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

/// The GeneralName choices, by context tag number.
const GN_OTHER_NAME: u8 = 0;
const GN_RFC822: u8 = 1;
const GN_DNS: u8 = 2;
const GN_DIRECTORY: u8 = 4;
const GN_URI: u8 = 6;
const GN_IP: u8 = 7;

/// The reason for a rejection. Every variant is a handshake failure; the
/// reason is for tests and DEBUG logs only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum V1Reject {
    /// `check_ca` failed (error 79).
    InvalidCa,
    /// A pathLenConstraint failed (error 25).
    PathLength,
    /// A purpose check failed (error 26).
    Purpose,
    /// A certificate of the path is not valid at `now`.
    Expired,
    /// A signature does not verify, or its algorithm is not supported.
    Signature,
    /// No issuer was found (errors 2, 19 and 20).
    NoIssuer,
    /// A name constraint failed.
    NameConstraints,
    /// An unprocessed critical extension (error 34).
    CriticalExtension,
    /// More than [`MAX_DEPTH`] intermediates (error 22).
    ChainTooLong,
    /// Several time-valid trusted issuers lead to different verdicts.
    Ambiguous,
    /// [`WORK_BUDGET`] is exhausted.
    Budget,
    /// An issuer has keyUsage without keyCertSign (error 32).
    KeyUsage,
    /// The path selects a `Role::Rejected` input (error 28).
    Rejected,
    /// A store lookup sees an input that the verifier cannot decide: a
    /// certificate that `LegacyCert` refuses, a partly loaded hash file,
    /// or copies of one DER with different trust settings.
    Undecided,
}

/// Verifies a v1 leaf that is not OpenSSL-self-signed. The caller first
/// decides the path of a self-signed leaf in the trust set.
///
/// It never accepts where OpenSSL rejects. It can reject where OpenSSL
/// may accept, but only for the known algorithm and encoding cases. Some
/// examples are DSA keys, Ed448 keys and ambiguous trust stores. The FIPS
/// build also rejects the algorithms that its module does not approve.
pub(crate) fn verify(
    leaf: &LegacyCert<'_>,
    sent: &[LegacyCert<'_>],
    trust: &TrustSet,
    now: UnixTime,
    algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), V1Reject> {
    // The caller sends only v1 leaves that are not self-signed here. Any
    // other leaf fails closed.
    if leaf.version() != CertVersion::V1 || leaf.openssl_self_signed() {
        return Err(V1Reject::NoIssuer);
    }
    // A v1 certificate has no extensions field. LegacyCert rejects such a
    // field at parse time, and this check repeats that rule.
    if has_any_extension(leaf) {
        return Err(V1Reject::CriticalExtension);
    }
    check_leaf(leaf, now)?;
    Search::new(leaf, sent, trust, now, algs)?.run()
}

/// The OpenSSL path post-check for a v3 leaf that webpki has accepted.
/// The leaf is v3 and not OpenSSL-self-signed. It never accepts where
/// OpenSSL rejects.
pub(crate) fn verify_v3_path(
    leaf: &LegacyCert<'_>,
    sent: &[LegacyCert<'_>],
    trust: &TrustSet,
    now: UnixTime,
    algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), V1Reject> {
    if leaf.version() != CertVersion::V3 || leaf.openssl_self_signed() {
        return Err(V1Reject::NoIssuer);
    }
    check_leaf(leaf, now)?;
    Search::new(leaf, sent, trust, now, algs)?.run()
}

/// `check_purpose_ssl_server(x, ca = 0)` on the leaf: EKU, keyUsage and
/// nsCertType. `ext_key_usage` is false on the v3 webpki path, which has
/// checked EKU already.
pub(crate) fn ssl_server_purpose(leaf: &LegacyCert<'_>, ext_key_usage: bool) -> bool {
    if ext_key_usage && !leaf.eku_allows_ssl_server() {
        return false;
    }
    if leaf
        .ns_cert_type()
        .is_some_and(|ns| ns & NS_SSL_SERVER == 0)
    {
        return false;
    }
    let server_usage = KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT;
    !leaf.key_usage().is_some_and(|ku| ku & server_usage == 0)
}

/// Tells whether a certificate has a critical extension outside the
/// processed set: basicConstraints, keyUsage, extKeyUsage, nsCertType,
/// subjectAltName and nameConstraints.
pub(crate) fn has_unprocessed_critical(cert: &LegacyCert<'_>) -> bool {
    cert.critical_extensions()
        .iter()
        .any(|oid| !PROCESSED_CRITICAL.contains(oid))
}

/// The checks on the leaf alone: the validity and the leaf purpose.
fn check_leaf(leaf: &LegacyCert<'_>, now: UnixTime) -> Result<(), V1Reject> {
    if !leaf.valid_at(now) {
        return Err(V1Reject::Expired);
    }
    if !ssl_server_purpose(leaf, true) {
        return Err(V1Reject::Purpose);
    }
    Ok(())
}

/// Tells whether the certificate shows any extension.
fn has_any_extension(cert: &LegacyCert<'_>) -> bool {
    cert.basic_constraints().is_some()
        || cert.key_usage().is_some()
        || cert.ext_key_usage().is_some()
        || cert.ns_cert_type().is_some()
        || cert.subject_key_id().is_some()
        || cert.authority_key_id().is_some()
        || cert.subject_alt_name().is_some()
        || cert.name_constraints().is_some()
        || !cert.critical_extensions().is_empty()
}

/// One trust input as the search sees it.
struct Trusted<'a> {
    cert: LegacyCert<'a>,
    role: Role,
    aux_trusts: bool,
    /// The store origins of the copies of this DER.
    origins: Vec<Origin>,
    /// Two copies differ in role or aux settings. The copy that OpenSSL
    /// keeps depends on the lookup order, so the search fails closed.
    conflict: bool,
}

impl Trusted<'_> {
    /// Tells whether the store holds this input once the groups of
    /// `loaded` are read.
    fn visible(&self, loaded: &[usize]) -> bool {
        self.origins.iter().any(|o| TrustSet::visible(*o, loaded))
    }
}

/// One certificate of the chain under construction.
#[derive(Clone, Copy)]
struct Link<'s, 'a> {
    cert: &'s LegacyCert<'a>,
    /// The trust input, when the certificate comes from the trust set.
    trusted: Option<&'s Trusted<'a>>,
}

/// The path search of one verification.
struct Search<'a> {
    leaf: &'a LegacyCert<'a>,
    sent: &'a [LegacyCert<'a>],
    /// The trust inputs in load order, one entry for each distinct DER.
    trust: Vec<Trusted<'a>>,
    /// The store model, for the lookup order of the OpenSSL store.
    store: &'a TrustSet,
    now: UnixTime,
    algs: &'a [&'a dyn SignatureVerificationAlgorithm],
}

/// Adds an issuer name to the closure list when the list does not have it.
fn add_name(names: &mut Vec<Vec<u8>>, name: Vec<u8>) {
    if !names.contains(&name) {
        names.push(name);
    }
}

/// Parses the trust inputs that can be in a chain of `leaf`, and gives
/// them in load order with their parsed form.
///
/// `check_issued` takes an issuer only when its canonical subject equals
/// the canonical issuer of the top certificate. Thus an input can be in a
/// chain only when its subject is the issuer of the leaf, of a sent
/// certificate or of another such input. The other inputs cannot change
/// the result, so the search does not parse them.
fn chain_inputs<'a>(
    leaf: &LegacyCert<'_>,
    sent: &[LegacyCert<'_>],
    inputs: &'a [TrustedCert],
) -> Result<Vec<(&'a TrustedCert, LegacyCert<'a>)>, V1Reject> {
    // Each issuer name is in the list one time, so each name causes one
    // scan of the inputs.
    let mut names: Vec<Vec<u8>> = Vec::with_capacity(sent.len().saturating_add(1));
    add_name(&mut names, leaf.canonical_issuer());
    for cert in sent {
        add_name(&mut names, cert.canonical_issuer());
    }
    let mut parsed: Vec<Option<LegacyCert<'a>>> = inputs.iter().map(|_| None).collect();
    // An input that a scan parses can add the name of its own issuer.
    let mut next = 0usize;
    while next < names.len() {
        for (input, slot) in inputs.iter().zip(parsed.iter_mut()) {
            if slot.is_some()
                || names.get(next).map(Vec::as_slice) != Some(input.canonical_subject())
            {
                continue;
            }
            // TrustedCert::new parses every input, so this parse cannot
            // fail. If it does, the search fails closed.
            let cert = LegacyCert::parse(input.der().as_ref()).map_err(|_| V1Reject::NoIssuer)?;
            add_name(&mut names, cert.canonical_issuer());
            *slot = Some(cert);
        }
        next = next.saturating_add(1);
    }
    Ok(inputs
        .iter()
        .zip(parsed)
        .filter_map(|(input, cert)| cert.map(|cert| (input, cert)))
        .collect())
}

impl<'a> Search<'a> {
    /// Takes the trust inputs that can be in a chain of the leaf. A
    /// duplicate DER keeps the first entry, as the OpenSSL store does. It
    /// becomes Rejected when any copy is Rejected, so that the search
    /// fails closed. Other copies that differ in role or aux settings make
    /// the entry a conflict.
    fn new(
        leaf: &'a LegacyCert<'a>,
        sent: &'a [LegacyCert<'a>],
        trust: &'a TrustSet,
        now: UnixTime,
        algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    ) -> Result<Self, V1Reject> {
        let inputs = chain_inputs(leaf, sent, trust.certs())?;
        let mut list: Vec<Trusted<'a>> = Vec::with_capacity(inputs.len());
        for (input, cert) in inputs {
            let aux_trusts = input.aux().is_some_and(AuxTrust::trusts_server_auth);
            if let Some(first) = list.iter_mut().find(|t| t.cert.der() == cert.der()) {
                if input.role() == Role::Rejected {
                    first.role = Role::Rejected;
                } else if input.role() != first.role || aux_trusts != first.aux_trusts {
                    first.conflict = true;
                }
                first.origins.push(input.origin());
                continue;
            }
            list.push(Trusted {
                cert,
                role: input.role(),
                aux_trusts,
                origins: vec![input.origin()],
                conflict: false,
            });
        }
        Ok(Self {
            leaf,
            sent,
            trust: list,
            store: trust,
            now,
            algs,
        })
    }

    fn run(&self) -> Result<(), V1Reject> {
        let mut chain = vec![Link {
            cert: self.leaf,
            trusted: None,
        }];
        let mut budget = WORK_BUDGET;
        let mut loaded = Vec::new();
        self.extend(&mut chain, &mut budget, &mut loaded)
    }

    /// Finds the issuer of the top certificate, as OpenSSL `build_chain`
    /// does with `X509_V_FLAG_TRUSTED_FIRST`. `loaded` holds the hash
    /// groups that the lookups of this branch have read.
    fn extend<'s>(
        &'s self,
        chain: &mut Vec<Link<'s, 'a>>,
        budget: &mut usize,
        loaded: &mut Vec<usize>,
    ) -> Result<(), V1Reject> {
        let Some(top) = chain.last().copied() else {
            return Err(V1Reject::NoIssuer);
        };
        if chain.len().saturating_sub(1) > MAX_DEPTH {
            return Err(V1Reject::ChainTooLong);
        }
        let x = top.cert;
        // A self-signed top has no issuer above it. A self-signed trust
        // input always ends the chain in `step`, so this top is a sent
        // certificate. OpenSSL takes no sent issuer above it (error 19).
        // A different trust input with its name is an untrusted mimic,
        // which OpenSSL also rejects.
        if x.openssl_self_signed() {
            return Err(V1Reject::NoIssuer);
        }
        // The store lookup decides which inputs OpenSSL can select. The
        // groups that it reads stay loaded for the rest of the branch.
        self.store
            .lookup(&x.canonical_issuer(), loaded)
            .map_err(|_| V1Reject::Undecided)?;
        let issuers: Vec<&'s Trusted<'a>> = self
            .trust
            .iter()
            .filter(|t| {
                t.visible(loaded) && !in_chain(chain, t.cert.der()) && check_issued(&t.cert, x)
            })
            .collect();
        if issuers.iter().any(|t| t.conflict) {
            return Err(V1Reject::Undecided);
        }
        if !issuers.is_empty() {
            let valid: Vec<&'s Trusted<'a>> = issuers
                .into_iter()
                .filter(|t| t.cert.valid_at(self.now))
                .collect();
            return self.step_trusted(chain, &valid, budget, loaded);
        }
        // Once a trust input is in the chain, OpenSSL does not look at the
        // sent certificates again (error 2).
        if chain.iter().any(|l| l.trusted.is_some()) {
            return Err(V1Reject::NoIssuer);
        }
        let issuer = self.find_issuer(chain, x).ok_or(V1Reject::NoIssuer)?;
        self.step(
            chain,
            Link {
                cert: issuer,
                trusted: None,
            },
            budget,
            loaded,
        )
    }

    /// OpenSSL `find_issuer` over the sent certificates: the first
    /// time-valid issuer, else the issuer with the latest notAfter.
    fn find_issuer<'s>(
        &'s self,
        chain: &[Link<'s, 'a>],
        x: &LegacyCert<'_>,
    ) -> Option<&'s LegacyCert<'a>> {
        let mut fallback: Option<&'s LegacyCert<'a>> = None;
        for c in self.sent {
            if in_chain(chain, c.der()) || !check_issued(c, x) {
                continue;
            }
            if c.valid_at(self.now) {
                return Some(c);
            }
            let later = fallback.is_none_or(|f| {
                c.validity().not_after.as_secs() > f.validity().not_after.as_secs()
            });
            if later {
                fallback = Some(c);
            }
        }
        fallback
    }

    /// Applies the ambiguity rule to the time-valid trusted issuers. The
    /// chain is accepted only when every candidate leads to acceptance.
    /// Each candidate starts from the same loaded groups.
    fn step_trusted<'s>(
        &'s self,
        chain: &mut Vec<Link<'s, 'a>>,
        valid: &[&'s Trusted<'a>],
        budget: &mut usize,
        loaded: &mut Vec<usize>,
    ) -> Result<(), V1Reject> {
        // OpenSSL takes an expired store issuer when no time-valid one
        // exists, and the chain then fails.
        if valid.is_empty() {
            return Err(V1Reject::Expired);
        }
        let mut accepted = false;
        let mut first_error = None;
        for t in valid {
            let link = Link {
                cert: &t.cert,
                trusted: Some(*t),
            };
            let mark = loaded.len();
            let result = self.step(chain, link, budget, loaded);
            loaded.truncate(mark);
            match result {
                Ok(()) => accepted = true,
                Err(V1Reject::Budget) => return Err(V1Reject::Budget),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        match (accepted, first_error) {
            (true, None) => Ok(()),
            (false, Some(e)) => Err(e),
            _ => Err(V1Reject::Ambiguous),
        }
    }

    /// Adds the issuer `y` to the chain after the checks that OpenSSL
    /// applies to a chosen issuer, then goes on upward or finishes.
    fn step<'s>(
        &'s self,
        chain: &mut Vec<Link<'s, 'a>>,
        y: Link<'s, 'a>,
        budget: &mut usize,
        loaded: &mut Vec<usize>,
    ) -> Result<(), V1Reject> {
        *budget = budget.checked_sub(1).ok_or(V1Reject::Budget)?;
        let role = y.trusted.map(|t| t.role);
        if role == Some(Role::Rejected) {
            return Err(V1Reject::Rejected);
        }
        if y.cert
            .key_usage()
            .is_some_and(|ku| ku & KU_KEY_CERT_SIGN == 0)
        {
            return Err(V1Reject::KeyUsage);
        }
        let Some(x) = chain.last() else {
            return Err(V1Reject::NoIssuer);
        };
        if !verify_sig(x.cert, y.cert, self.algs) {
            return Err(V1Reject::Signature);
        }
        chain.push(y);
        // A trusted self-signed input or an explicitly trusted input ends
        // the chain, as OpenSSL `check_trust` ends it. `finish` rejects a
        // LeafOnly input, because it fails `check_ca` or the purpose.
        let result = match role {
            Some(Role::Anchor | Role::LeafOnly) => self.finish(chain),
            _ => self.extend(chain, budget, loaded),
        };
        chain.pop();
        result
    }

    /// The OpenSSL rules on the complete chain `[L, c1, ..., cn, A]`.
    fn finish(&self, chain: &[Link<'_, 'a>]) -> Result<(), V1Reject> {
        let Some((anchor, below)) = chain.split_last() else {
            return Err(V1Reject::NoIssuer);
        };
        let intermediates = below.get(1..).unwrap_or_default();
        if chain.iter().any(|l| !l.cert.valid_at(self.now)) {
            return Err(V1Reject::Expired);
        }
        // OpenSSL 3 check_chain requires X509_check_ca == 1 for each
        // intermediate, and a nonzero value for the chain end.
        if intermediates.iter().any(|l| l.cert.openssl_check_ca() != 1) {
            return Err(V1Reject::InvalidCa);
        }
        if anchor.cert.openssl_check_ca() == 0 {
            return Err(V1Reject::InvalidCa);
        }
        // check_purpose consults the aux trust of a store certificate
        // first. An aux trust list that names serverAuth satisfies it.
        let purpose_ok =
            |l: &Link<'_, 'a>| l.trusted.is_some_and(|t| t.aux_trusts) || ca_purpose(l.cert);
        if !intermediates.iter().all(purpose_ok) || !purpose_ok(anchor) {
            return Err(V1Reject::Purpose);
        }
        check_path_length(chain)?;
        check_name_constraints(chain)?;
        if chain.iter().any(|l| has_unprocessed_critical(l.cert)) {
            return Err(V1Reject::CriticalExtension);
        }
        Ok(())
    }
}

/// Tells whether a certificate with this DER is already in the chain.
fn in_chain(chain: &[Link<'_, '_>], der: &[u8]) -> bool {
    chain.iter().any(|l| l.cert.der() == der)
}

/// OpenSSL `EXFLAG_SI`: the canonical subject equals the canonical
/// issuer.
fn self_issued(cert: &LegacyCert<'_>) -> bool {
    cert.canonical_subject() == cert.canonical_issuer()
}

/// `check_purpose_ssl_server(x, ca = 1)`: the EKU rule, then
/// `check_ssl_ca`.
fn ca_purpose(cert: &LegacyCert<'_>) -> bool {
    if !cert.eku_allows_ssl_server() {
        return false;
    }
    match cert.openssl_check_ca() {
        0 => false,
        5 => cert.ns_cert_type().is_some_and(|ns| ns & NS_SSL_CA != 0),
        _ => true,
    }
}

/// Checks the signature of `x` with the key of `y`, as webpki selects the
/// algorithm: the signature algorithm and the key type must both match,
/// and the first such algorithm decides.
fn verify_sig(
    x: &LegacyCert<'_>,
    y: &LegacyCert<'_>,
    algs: &[&dyn SignatureVerificationAlgorithm],
) -> bool {
    if !tbs_signature_matches(x) {
        return false;
    }
    let spki = y.spki();
    let sig_alg = x.signature_alg();
    algs.iter()
        .find(|a| {
            a.signature_alg_id().as_ref() == sig_alg
                && a.public_key_alg_id().as_ref() == spki.alg_id_value
        })
        .is_some_and(|a| {
            a.verify_signature(spki.key_bits, x.tbs(), x.signature())
                .is_ok()
        })
}

/// Tells whether `tbsCertificate.signature` equals the outer
/// signatureAlgorithm, as webpki requires.
fn tbs_signature_matches(x: &LegacyCert<'_>) -> bool {
    let inner = (|| {
        let tbs = single(x.tbs(), TAG_SEQUENCE)?;
        let mut r = DerReader::new(tbs);
        let mut field = r.read()?;
        if field.tag == 0xa0 {
            field = r.read()?;
        }
        if field.tag != TAG_INTEGER {
            return None;
        }
        r.read_tag(TAG_SEQUENCE)
    })();
    inner == Some(x.signature_alg())
}

/// OpenSSL's path-length rule in `check_chain`. A self-issued
/// intermediate does not count.
fn check_path_length(chain: &[Link<'_, '_>]) -> Result<(), V1Reject> {
    let mut plen: u64 = 0;
    for (i, link) in chain.iter().enumerate() {
        if i > 1 {
            let limit = link.cert.basic_constraints().and_then(|bc| bc.path_len);
            if limit.is_some_and(|max| plen > u64::from(max)) {
                return Err(V1Reject::PathLength);
            }
        }
        if i > 0 && !self_issued(link.cert) {
            plen = plen.saturating_add(1);
        }
    }
    Ok(())
}

/// OpenSSL `check_name_constraints`. The constraints of each CA apply to
/// every certificate below it that is not self-issued, and always to the
/// leaf.
fn check_name_constraints(chain: &[Link<'_, '_>]) -> Result<(), V1Reject> {
    for (i, link) in chain.iter().enumerate() {
        if i != 0 && self_issued(link.cert) {
            continue;
        }
        let above = chain.get(i.saturating_add(1)..).unwrap_or_default();
        for ca in above {
            if let Some(nc) = ca.cert.name_constraints() {
                if !name_constraints_ok(link.cert, nc, i == 0) {
                    return Err(V1Reject::NameConstraints);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Name constraints (OpenSSL v3_ncons.c).
// ---------------------------------------------------------------------

/// One GeneralName. For a directoryName, `value` is the Name TLV. For the
/// other choices, `value` is the content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GeneralName<'a> {
    kind: u8,
    value: &'a [u8],
}

/// One GeneralSubtree of a nameConstraints extension.
#[derive(Clone, Copy, Debug)]
struct Subtree<'a> {
    base: GeneralName<'a>,
    /// False when minimum is not zero or maximum is present.
    minmax_valid: bool,
}

/// The parsed nameConstraints extension.
#[derive(Debug, Default)]
struct NameConstraints<'a> {
    permitted: Vec<Subtree<'a>>,
    excluded: Vec<Subtree<'a>>,
}

/// One attribute of a Name.
#[derive(Clone, Copy, Debug)]
struct Attribute<'a> {
    oid: &'a [u8],
    tag: u8,
    content: &'a [u8],
}

/// The result of one subtree match. `Err` is a form that OpenSSL does not
/// support, which fails the chain.
type MatchResult = Result<bool, ()>;

/// `NAME_CONSTRAINTS_check`, plus `NAME_CONSTRAINTS_check_CN` for a leaf
/// without a dNSName SAN. Malformed input fails the check.
fn name_constraints_ok(cert: &LegacyCert<'_>, nc: &[u8], is_leaf: bool) -> bool {
    let Some(nc) = parse_name_constraints(nc) else {
        return false;
    };
    let Some(subject) = parse_name(cert.subject()) else {
        return false;
    };
    let sans = match cert.subject_alt_name() {
        Some(san) => match parse_general_names(san) {
            Some(names) => names,
            None => return false,
        },
        None => Vec::new(),
    };
    let names = subject.len().saturating_add(sans.len());
    let constraints = nc.permitted.len().saturating_add(nc.excluded.len());
    if NAME_CHECK_MAX
        .checked_div(names)
        .is_some_and(|max| constraints > max)
    {
        return false;
    }
    if !subject.is_empty() {
        let dn = GeneralName {
            kind: GN_DIRECTORY,
            value: cert.subject(),
        };
        if !nc_match(&dn, &nc) {
            return false;
        }
        for attr in subject.iter().filter(|a| a.oid == OID_EMAIL_ADDRESS) {
            if attr.tag != TAG_IA5_STRING {
                return false;
            }
            let email = GeneralName {
                kind: GN_RFC822,
                value: attr.content,
            };
            if !nc_match(&email, &nc) {
                return false;
            }
        }
    }
    if !sans.iter().all(|g| nc_match(g, &nc)) {
        return false;
    }
    if is_leaf && !sans.iter().any(|g| g.kind == GN_DNS) {
        return check_cn(&subject, &nc);
    }
    true
}

/// `NAME_CONSTRAINTS_check_CN`: each commonName with host-name syntax is
/// checked as a dNSName.
fn check_cn(subject: &[Attribute<'_>], nc: &NameConstraints<'_>) -> bool {
    for attr in subject.iter().filter(|a| a.oid == OID_COMMON_NAME) {
        let Some(id) = cn_to_dns_id(attr.tag, attr.content) else {
            return false;
        };
        if id.is_empty() {
            continue;
        }
        let dns = GeneralName {
            kind: GN_DNS,
            value: &id,
        };
        if !nc_match(&dns, nc) {
            return false;
        }
    }
    true
}

/// OpenSSL `cn2dnsid`. Returns an empty identifier for a CN that does not
/// look like a host name with two or more labels, and `None` for a CN
/// that cannot be converted or has an embedded NUL.
fn cn_to_dns_id(tag: u8, content: &[u8]) -> Option<Vec<u8>> {
    let mut utf8 = string_to_utf8(tag, content)?;
    while utf8.last() == Some(&0) {
        utf8.pop();
    }
    if utf8.contains(&0) {
        return None;
    }
    let Some(last) = utf8.len().checked_sub(1) else {
        return Some(Vec::new());
    };
    let mut is_dns = false;
    for (i, &c) in utf8.iter().enumerate() {
        if c.is_ascii_alphanumeric() || c == b'_' {
            continue;
        }
        if i > 0 && i < last {
            if c == b'-' {
                continue;
            }
            let prev = utf8.get(i.wrapping_sub(1)).copied();
            let next = utf8.get(i.wrapping_add(1)).copied();
            if c == b'.' && next != Some(b'.') && prev != Some(b'-') && next != Some(b'-') {
                is_dns = true;
                continue;
            }
        }
        is_dns = false;
        break;
    }
    Some(if is_dns { utf8 } else { Vec::new() })
}

/// OpenSSL `nc_match`: a permitted subtree of the same type must match
/// when one exists, and no excluded subtree of the same type may match.
fn nc_match(name: &GeneralName<'_>, nc: &NameConstraints<'_>) -> bool {
    let other_oid = if name.kind == GN_OTHER_NAME {
        match other_name_oid(name.value) {
            Some(oid) => Some(oid),
            None => return false,
        }
    } else {
        None
    };
    // RFC 8398: an SmtpUTF8Mailbox otherName is matched as an email.
    let kind = if other_oid == Some(OID_SMTP_UTF8_MAILBOX) {
        GN_RFC822
    } else {
        name.kind
    };
    let applies = |sub: &Subtree<'_>| {
        sub.base.kind == kind
            && (kind != GN_OTHER_NAME || other_name_oid(sub.base.value) == other_oid)
    };
    let mut seen = false;
    let mut matched = false;
    for sub in nc.permitted.iter().filter(|s| applies(s)) {
        if !sub.minmax_valid {
            return false;
        }
        if matched {
            continue;
        }
        seen = true;
        match match_single(kind, name, &sub.base) {
            Ok(true) => matched = true,
            Ok(false) => {}
            Err(()) => return false,
        }
    }
    if seen && !matched {
        return false;
    }
    for sub in nc.excluded.iter().filter(|s| applies(s)) {
        if !sub.minmax_valid {
            return false;
        }
        match match_single(kind, name, &sub.base) {
            Ok(false) => {}
            Ok(true) | Err(()) => return false,
        }
    }
    true
}

/// OpenSSL `nc_match_single` for one name and one subtree base.
fn match_single(kind: u8, name: &GeneralName<'_>, base: &GeneralName<'_>) -> MatchResult {
    match kind {
        // An SmtpUTF8Mailbox name meets an rfc822Name subtree here. The
        // verifier does not implement nc_email_eai, so it fails closed.
        GN_RFC822 if name.kind == GN_OTHER_NAME => Err(()),
        GN_RFC822 => nc_email(name.value, base.value),
        GN_DNS => Ok(nc_dns(name.value, base.value)),
        GN_DIRECTORY => nc_dn(name.value, base.value),
        GN_URI => nc_uri(name.value, base.value),
        GN_IP => nc_ip(name.value, base.value),
        _ => Err(()),
    }
}

/// OpenSSL `nc_dn`: the canonical base is a prefix of the canonical name.
fn nc_dn(name: &[u8], base: &[u8]) -> MatchResult {
    let name = canonical_name(name).ok_or(())?;
    let base = canonical_name(base).ok_or(())?;
    Ok(name.starts_with(&base))
}

/// OpenSSL `nc_dns`: zero or more labels may come before the base, and
/// the match is ASCII case-insensitive.
fn nc_dns(dns: &[u8], base: &[u8]) -> bool {
    if base.is_empty() {
        return true;
    }
    let Some(start) = dns.len().checked_sub(base.len()) else {
        return false;
    };
    let Some(tail) = dns.get(start..) else {
        return false;
    };
    if start > 0 {
        let before = dns.get(start.wrapping_sub(1)).copied();
        if base.first() != Some(&b'.') && before != Some(b'.') {
            return false;
        }
    }
    ia5_case_eq(tail, base)
}

/// OpenSSL `nc_email`.
fn nc_email(email: &[u8], base: &[u8]) -> MatchResult {
    let Some(email_at) = email.iter().rposition(|&b| b == b'@') else {
        return Err(());
    };
    let base_at = base.iter().rposition(|&b| b == b'@');
    // A base that starts with '.' and has no '@' matches the right-hand
    // side of the address.
    if base_at.is_none() && base.first() == Some(&b'.') {
        if email.len() > base.len() {
            let start = email.len().saturating_sub(base.len());
            let tail = email.get(start..).ok_or(())?;
            return Ok(ia5_case_eq(tail, base));
        }
        return Ok(false);
    }
    let mut base_host = base;
    if let Some(at) = base_at {
        if at != 0 {
            let base_local = base.get(..at).ok_or(())?;
            let email_local = email.get(..email_at).ok_or(())?;
            if base_local.len() != email_local.len() {
                return Ok(false);
            }
            if base_local.contains(&0) || email_local.contains(&0) {
                return Err(());
            }
            // The local part matches case-sensitively.
            if base_local != email_local {
                return Ok(false);
            }
        }
        base_host = base.get(at.saturating_add(1)..).ok_or(())?;
    }
    let email_host = email.get(email_at.saturating_add(1)..).ok_or(())?;
    Ok(ia5_case_eq(base_host, email_host))
}

/// OpenSSL `ia5ncasecmp` on two strings of the same length. The compare
/// ignores ASCII case. It stops at a NUL byte that both strings have at
/// the same position, because OpenSSL compares C strings.
fn ia5_case_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b) {
        if !x.eq_ignore_ascii_case(y) {
            return false;
        }
        if *x == 0 {
            return true;
        }
    }
    true
}

/// OpenSSL `nc_uri`: the host part of `scheme://host[:port][/path]`.
fn nc_uri(uri: &[u8], base: &[u8]) -> MatchResult {
    let colon = uri.iter().position(|&b| b == b':').ok_or(())?;
    let after = uri.get(colon..).ok_or(())?;
    if after.len() < 3 || after.get(1) != Some(&b'/') || after.get(2) != Some(&b'/') {
        return Err(());
    }
    let host_part = after.get(3..).ok_or(())?;
    let end = host_part
        .iter()
        .position(|&b| b == b':')
        .or_else(|| host_part.iter().position(|&b| b == b'/'))
        .unwrap_or(host_part.len());
    let host = host_part.get(..end).ok_or(())?;
    if host.is_empty() {
        return Err(());
    }
    if base.first() == Some(&b'.') {
        if host.len() > base.len() {
            let start = host.len().saturating_sub(base.len());
            let tail = host.get(start..).ok_or(())?;
            return Ok(ia5_case_eq(tail, base));
        }
        return Ok(false);
    }
    Ok(ia5_case_eq(host, base))
}

/// OpenSSL `nc_ip`: the base is an address and a mask of the same family.
fn nc_ip(ip: &[u8], base: &[u8]) -> MatchResult {
    if ip.len() != 4 && ip.len() != 16 {
        return Err(());
    }
    if base.len() != 8 && base.len() != 32 {
        return Err(());
    }
    let Some((addr, mask)) = base.split_at_checked(ip.len()) else {
        return Ok(false);
    };
    if mask.len() != ip.len() {
        return Ok(false);
    }
    Ok(ip
        .iter()
        .zip(addr)
        .zip(mask)
        .all(|((h, b), m)| h & m == b & m))
}

/// Returns the type OID of an otherName, from its content.
fn other_name_oid(value: &[u8]) -> Option<&[u8]> {
    DerReader::new(value).read_tag(TAG_OID)
}

/// Parses nameConstraints. The input is the extension content, or the
/// whole SEQUENCE.
fn parse_name_constraints(bytes: &[u8]) -> Option<NameConstraints<'_>> {
    let content = if bytes.first() == Some(&TAG_SEQUENCE) {
        single(bytes, TAG_SEQUENCE)?
    } else {
        bytes
    };
    let mut nc = NameConstraints::default();
    let mut r = DerReader::new(content);
    while !r.is_empty() {
        let field = r.read()?;
        let list = match field.tag {
            0xa0 => &mut nc.permitted,
            0xa1 => &mut nc.excluded,
            _ => return None,
        };
        let mut subtrees = DerReader::new(field.content);
        while !subtrees.is_empty() {
            list.push(parse_subtree(subtrees.read_tag(TAG_SEQUENCE)?)?);
        }
    }
    Some(nc)
}

/// Parses one GeneralSubtree content.
fn parse_subtree(content: &[u8]) -> Option<Subtree<'_>> {
    let mut r = DerReader::new(content);
    let base = general_name(r.read()?)?;
    let mut minmax_valid = true;
    while !r.is_empty() {
        let field = r.read()?;
        match field.tag {
            // minimum: OpenSSL accepts an explicit zero only.
            0x80 => minmax_valid &= field.content == [0],
            // maximum: OpenSSL supports no maximum.
            0x81 => minmax_valid = false,
            _ => return None,
        }
    }
    Some(Subtree { base, minmax_valid })
}

/// Parses GeneralNames. The input is the SEQUENCE content, or the whole
/// SEQUENCE.
fn parse_general_names(bytes: &[u8]) -> Option<Vec<GeneralName<'_>>> {
    let content = if bytes.first() == Some(&TAG_SEQUENCE) {
        single(bytes, TAG_SEQUENCE)?
    } else {
        bytes
    };
    let mut names = Vec::new();
    let mut r = DerReader::new(content);
    while !r.is_empty() {
        names.push(general_name(r.read()?)?);
    }
    Some(names)
}

/// Converts one GeneralName TLV. Only the encodings of RFC 5280 parse.
fn general_name(tlv: Tlv<'_>) -> Option<GeneralName<'_>> {
    let kind = tlv.tag & 0x1f;
    let expected = match kind {
        0 | 3 | 5 => 0xa0 | kind,
        4 => 0xa4,
        1 | 2 | 6 | 7 | 8 => 0x80 | kind,
        _ => return None,
    };
    if tlv.tag != expected {
        return None;
    }
    if kind == GN_OTHER_NAME && !valid_other_name(tlv.content) {
        return None;
    }
    let value = if kind == GN_DIRECTORY {
        let mut r = DerReader::new(tlv.content);
        let name = r.read()?;
        if name.tag != TAG_SEQUENCE || !r.is_empty() {
            return None;
        }
        name.whole
    } else {
        tlv.content
    };
    Some(GeneralName { kind, value })
}

/// Tells whether an otherName content is `type-id OID, [0] EXPLICIT value`.
fn valid_other_name(content: &[u8]) -> bool {
    let mut r = DerReader::new(content);
    let oid = r.read_tag(TAG_OID).is_some();
    let value = r.read().is_some_and(|v| v.tag == 0xa0);
    oid && value && r.is_empty()
}

/// Parses a Name TLV into its attributes, in order.
fn parse_name(name: &[u8]) -> Option<Vec<Attribute<'_>>> {
    let mut attrs = Vec::new();
    let mut rdns = DerReader::new(single(name, TAG_SEQUENCE)?);
    while !rdns.is_empty() {
        let mut set = DerReader::new(rdns.read_tag(TAG_SET)?);
        if set.is_empty() {
            return None;
        }
        while !set.is_empty() {
            let mut atv = DerReader::new(set.read_tag(TAG_SEQUENCE)?);
            let oid = atv.read_tag(TAG_OID)?;
            let value = atv.read()?;
            if !atv.is_empty() {
                return None;
            }
            attrs.push(Attribute {
                oid,
                tag: value.tag,
                content: value.content,
            });
        }
    }
    Some(attrs)
}

// ---------------------------------------------------------------------
// The OpenSSL canonical name form (x509_name_canon, asn1_string_canon).
// ---------------------------------------------------------------------

/// Returns the OpenSSL canonical form of a Name TLV: each RDN as a DER
/// SET of canonical attributes, concatenated without the outer SEQUENCE.
pub(crate) fn canonical_name(name: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rdns = DerReader::new(single(name, TAG_SEQUENCE)?);
    while !rdns.is_empty() {
        let mut set = DerReader::new(rdns.read_tag(TAG_SET)?);
        if set.is_empty() {
            return None;
        }
        let mut atvs: Vec<Vec<u8>> = Vec::new();
        while !set.is_empty() {
            let mut atv = DerReader::new(set.read_tag(TAG_SEQUENCE)?);
            let oid = atv.read()?;
            let value = atv.read()?;
            if oid.tag != TAG_OID || !atv.is_empty() {
                return None;
            }
            let mut body = oid.whole.to_vec();
            if is_canon_string(value.tag) {
                let text = canonical_string(&string_to_utf8(value.tag, value.content)?);
                push_tlv(&mut body, TAG_UTF8_STRING, &text);
            } else {
                body.extend_from_slice(value.whole);
            }
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, TAG_SEQUENCE, &body);
            atvs.push(encoded);
        }
        // DER orders the members of a SET OF by their encodings.
        atvs.sort();
        push_tlv(&mut out, TAG_SET, &atvs.concat());
    }
    Some(out)
}

/// The string types that `asn1_string_canon` converts (`ASN1_MASK_CANON`).
fn is_canon_string(tag: u8) -> bool {
    matches!(tag, 0x0c | 0x13 | 0x14 | 0x16 | 0x1a | 0x1c | 0x1e)
}

/// OpenSSL `ossl_isspace`.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `asn1_string_canon` on UTF-8: trims white space, collapses each inner
/// run to one space, and lower-cases ASCII letters.
fn canonical_string(utf8: &[u8]) -> Vec<u8> {
    let start = utf8
        .iter()
        .position(|&b| !is_space(b))
        .unwrap_or(utf8.len());
    let end = utf8
        .iter()
        .rposition(|&b| !is_space(b))
        .map_or(start, |p| p.saturating_add(1));
    let trimmed = utf8.get(start..end).unwrap_or_default();
    let mut out = Vec::with_capacity(trimmed.len());
    let mut in_space = false;
    for &b in trimmed {
        if is_space(b) {
            if !in_space {
                out.push(b' ');
            }
            in_space = true;
        } else {
            in_space = false;
            out.push(b.to_ascii_lowercase());
        }
    }
    out
}

/// `ASN1_STRING_to_UTF8` for the string types of a Name. T61String and
/// the other one-byte types map each byte to one code point.
fn string_to_utf8(tag: u8, content: &[u8]) -> Option<Vec<u8>> {
    match tag {
        0x0c => core::str::from_utf8(content)
            .ok()
            .map(|s| s.as_bytes().to_vec()),
        0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x18 | 0x1a => Some(
            content
                .iter()
                .map(|&b| char::from(b))
                .collect::<String>()
                .into_bytes(),
        ),
        0x1e => wide_to_utf8(content, 2),
        0x1c => wide_to_utf8(content, 4),
        _ => None,
    }
}

/// Converts big-endian UCS-2 or UCS-4 to UTF-8. Surrogates and values
/// above U+10FFFF fail, as in OpenSSL 3.
fn wide_to_utf8(content: &[u8], width: usize) -> Option<Vec<u8>> {
    let chunks = content.chunks_exact(width);
    if !chunks.remainder().is_empty() {
        return None;
    }
    let mut s = String::with_capacity(content.len());
    for chunk in chunks {
        let value = chunk
            .iter()
            .fold(0_u32, |acc, &b| (acc << 8) | u32::from(b));
        s.push(char::from_u32(value)?);
    }
    Some(s.into_bytes())
}

// ---------------------------------------------------------------------
// A bounded DER reader.
// ---------------------------------------------------------------------

/// One TLV: the tag, the content and the whole encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) content: &'a [u8],
    pub(crate) whole: &'a [u8],
}

/// Reads DER TLVs one after the other. It takes single-byte tags and
/// minimal definite lengths of up to four bytes only.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DerReader<'a> {
    rest: &'a [u8],
}

impl<'a> DerReader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Reads the next TLV. `None` means malformed or no more input.
    pub(crate) fn read(&mut self) -> Option<Tlv<'a>> {
        let (&tag, after_tag) = self.rest.split_first()?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, mut body) = after_tag.split_first()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return None;
            }
            let (bytes, rest) = body.split_at_checked(count)?;
            body = rest;
            if bytes.first() == Some(&0) {
                return None;
            }
            let len = bytes.iter().try_fold(0_usize, |acc, &b| {
                acc.checked_mul(256)?.checked_add(usize::from(b))
            })?;
            if len < 0x80 {
                return None;
            }
            len
        };
        let (content, rest) = body.split_at_checked(len)?;
        let whole_len = self.rest.len().checked_sub(rest.len())?;
        let whole = self.rest.get(..whole_len)?;
        self.rest = rest;
        Some(Tlv {
            tag,
            content,
            whole,
        })
    }

    /// Reads the next TLV and returns its content when the tag is `tag`.
    pub(crate) fn read_tag(&mut self, tag: u8) -> Option<&'a [u8]> {
        let tlv = self.read()?;
        (tlv.tag == tag).then_some(tlv.content)
    }
}

/// Returns the content of `bytes` when it is exactly one TLV with `tag`.
pub(crate) fn single(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    let mut r = DerReader::new(bytes);
    let content = r.read_tag(tag)?;
    r.is_empty().then_some(content)
}

/// Appends one DER TLV with a minimal length.
fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        // The value is below 0x80, so the cast keeps it.
        out.push(u8::try_from(len).unwrap_or_default());
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let digits = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(digits.len()).unwrap_or_default());
        out.extend_from_slice(digits);
    }
    out.extend_from_slice(content);
}

#[cfg(test)]
#[path = "search_diff_tests.rs"]
mod search_diff_tests;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    const TAG_PRINTABLE: u8 = 0x13;
    const TAG_BMP: u8 = 0x1e;
    const TAG_UNIVERSAL: u8 = 0x1c;

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_tlv(&mut out, tag, content);
        out
    }

    fn atv(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
        der(TAG_SEQUENCE, &[der(TAG_OID, oid), der(tag, value)].concat())
    }

    /// A Name with one RDN for each list of attributes.
    fn name(rdns: &[&[Vec<u8>]]) -> Vec<u8> {
        let sets: Vec<u8> = rdns
            .iter()
            .flat_map(|r| der(TAG_SET, &r.concat()))
            .collect();
        der(TAG_SEQUENCE, &sets)
    }

    fn cn(tag: u8, value: &[u8]) -> Vec<u8> {
        name(&[&[atv(OID_COMMON_NAME, tag, value)]])
    }

    fn subtree(base: Vec<u8>, extra: &[u8]) -> Vec<u8> {
        der(TAG_SEQUENCE, &[base, extra.to_vec()].concat())
    }

    fn constraints(permitted: &[Vec<u8>], excluded: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        if !permitted.is_empty() {
            push_tlv(&mut body, 0xa0, &permitted.concat());
        }
        if !excluded.is_empty() {
            push_tlv(&mut body, 0xa1, &excluded.concat());
        }
        der(TAG_SEQUENCE, &body)
    }

    fn dns(host: &[u8]) -> GeneralName<'_> {
        GeneralName {
            kind: GN_DNS,
            value: host,
        }
    }

    #[test]
    fn der_reader_reads_short_and_long_lengths() {
        for len in [0, 1, 127, 128, 255, 256, 70_000] {
            let content = vec![0x5a; len];
            let mut bytes = der(0x04, &content);
            bytes.push(0x05);
            bytes.push(0x00);
            let mut r = DerReader::new(&bytes);
            let tlv = r.read().unwrap();
            assert_eq!(tlv.tag, 0x04);
            assert_eq!(tlv.content, &content[..]);
            assert_eq!(tlv.whole.len(), bytes.len() - 2);
            assert_eq!(r.read_tag(0x05), Some(&[][..]));
            assert!(r.is_empty());
        }
    }

    #[test]
    fn der_reader_rejects_non_der_lengths_and_truncation() {
        let bad: &[&[u8]] = &[
            &[],
            &[0x04],
            &[0x04, 0x02, 0x00],
            &[0x04, 0x80, 0x00, 0x00],
            &[0x04, 0x81, 0x05, 0, 0, 0, 0, 0],
            &[0x04, 0x82, 0x00, 0x80],
            &[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[0x1f, 0x01, 0x00],
        ];
        for b in bad {
            assert_eq!(DerReader::new(b).read(), None, "{b:02x?}");
        }
    }

    #[test]
    fn single_takes_exactly_one_tlv_with_the_tag() {
        assert_eq!(single(&[0x30, 0x01, 0x05], TAG_SEQUENCE), Some(&[0x05][..]));
        assert_eq!(single(&[0x30, 0x00, 0x05, 0x00], TAG_SEQUENCE), None);
        assert_eq!(single(&[0x31, 0x00], TAG_SEQUENCE), None);
    }

    #[test]
    fn canonical_name_ignores_case_spacing_and_string_type() {
        let a = canonical_name(&cn(TAG_UTF8_STRING, b"Corpus Canon")).unwrap();
        for variant in [
            cn(TAG_UTF8_STRING, b"CORPUS CANON"),
            cn(TAG_UTF8_STRING, b"  Corpus \t\n Canon "),
            cn(TAG_PRINTABLE, b"Corpus Canon"),
            cn(
                TAG_BMP,
                &[
                    0, b'c', 0, b'O', 0, b'R', 0, b'P', 0, b'U', 0, b'S', 0, b' ', 0, b'c', 0,
                    b'a', 0, b'n', 0, b'o', 0, b'n',
                ],
            ),
        ] {
            assert_eq!(canonical_name(&variant).unwrap(), a);
        }
        assert_ne!(
            canonical_name(&cn(TAG_UTF8_STRING, b"Corpus Canan")).unwrap(),
            a
        );
        assert_ne!(
            canonical_name(&cn(TAG_UTF8_STRING, b"CorpusCanon")).unwrap(),
            a
        );
    }

    #[test]
    fn canonical_name_sorts_multi_valued_rdns_and_keeps_rdn_order() {
        let o = atv(&[0x55, 0x04, 0x0a], TAG_UTF8_STRING, b"Org");
        let c = atv(OID_COMMON_NAME, TAG_UTF8_STRING, b"Name");
        let ab = canonical_name(&name(&[&[o.clone(), c.clone()]])).unwrap();
        let ba = canonical_name(&name(&[&[c.clone(), o.clone()]])).unwrap();
        assert_eq!(ab, ba);
        let split =
            canonical_name(&name(&[std::slice::from_ref(&o), std::slice::from_ref(&c)])).unwrap();
        let swapped = canonical_name(&name(&[&[c], &[o]])).unwrap();
        assert_ne!(split, swapped);
        assert_ne!(split, ab);
    }

    #[test]
    fn canonical_name_keeps_other_value_types_and_rejects_malformed_names() {
        let octets = name(&[&[atv(OID_COMMON_NAME, 0x04, b"ABC")]]);
        let canon = canonical_name(&octets).unwrap();
        assert!(
            canon
                .windows(5)
                .any(|w| w == [0x04, 0x03, b'A', b'B', b'C'])
        );
        assert_eq!(canonical_name(&der(TAG_SEQUENCE, &der(TAG_SET, &[]))), None);
        let no_oid = der(
            TAG_SEQUENCE,
            &der(TAG_SET, &der(TAG_SEQUENCE, &der(TAG_UTF8_STRING, b"x"))),
        );
        assert_eq!(canonical_name(&no_oid), None);
        assert_eq!(canonical_name(&cn(TAG_UTF8_STRING, &[0xff, 0xfe])), None);
        assert_eq!(canonical_name(&[0x30, 0x05]), None);
    }

    #[test]
    fn string_to_utf8_converts_one_byte_and_wide_strings() {
        assert_eq!(string_to_utf8(0x14, &[0xe9]).unwrap(), "\u{e9}".as_bytes());
        assert_eq!(
            string_to_utf8(TAG_BMP, &[0x00, 0x41, 0x00, 0xe9]).unwrap(),
            "A\u{e9}".as_bytes()
        );
        assert_eq!(string_to_utf8(TAG_BMP, &[0xd8, 0x00]), None);
        assert_eq!(string_to_utf8(TAG_BMP, &[0x00]), None);
        assert_eq!(
            string_to_utf8(TAG_UNIVERSAL, &[0x00, 0x01, 0xf6, 0x00]).unwrap(),
            "\u{1f600}".as_bytes()
        );
        assert_eq!(
            string_to_utf8(TAG_UNIVERSAL, &[0x00, 0x11, 0x00, 0x00]),
            None
        );
        assert_eq!(string_to_utf8(0x04, b"x"), None);
    }

    #[test]
    fn canonical_string_trims_collapses_and_lowers() {
        assert_eq!(canonical_string(b"\t A  B\n\x0bC "), b"a b c");
        assert_eq!(canonical_string(b" \t "), b"");
        assert_eq!(canonical_string("\u{c9}X".as_bytes()), "\u{c9}x".as_bytes());
    }

    #[test]
    fn cn_to_dns_id_takes_only_host_names_with_two_labels() {
        let id = |s: &[u8]| cn_to_dns_id(TAG_UTF8_STRING, s);
        assert_eq!(id(b"host.example").unwrap(), b"host.example");
        assert_eq!(id(b"a-b.c_d.e").unwrap(), b"a-b.c_d.e");
        assert_eq!(id(b"host.example\0\0").unwrap(), b"host.example");
        for not_dns in [
            &b"localhost"[..],
            b"a..b",
            b".a.b",
            b"a.b.",
            b"a-.b",
            b"a.-b",
            b"-a.b",
            b"a b.c",
            b"",
        ] {
            assert_eq!(id(not_dns).unwrap(), b"", "{not_dns:?}");
        }
        assert_eq!(id(b"a\0b.c"), None);
        assert_eq!(cn_to_dns_id(TAG_UTF8_STRING, &[0xff]), None);
    }

    #[test]
    fn nc_dns_matches_suffix_labels_without_case() {
        assert!(nc_dns(b"any.test", b""));
        assert!(nc_dns(b"www.example.com", b"example.com"));
        assert!(nc_dns(b"WWW.Example.COM", b"example.com"));
        assert!(nc_dns(b"example.com", b"example.com"));
        assert!(!nc_dns(b"badexample.com", b"example.com"));
        assert!(nc_dns(b"www.example.com", b".example.com"));
        assert!(!nc_dns(b"example.com", b".example.com"));
        assert!(!nc_dns(b"example.org", b"example.com"));
    }

    #[test]
    fn nc_email_matches_host_domain_and_mailbox() {
        assert_eq!(nc_email(b"a@x.other.test", b".other.test"), Ok(true));
        assert_eq!(nc_email(b"a@other.test", b".other.test"), Ok(false));
        assert_eq!(nc_email(b"a@Other.Test", b"other.test"), Ok(true));
        assert_eq!(nc_email(b"a@x.other.test", b"other.test"), Ok(false));
        assert_eq!(nc_email(b"a@other.test", b"a@OTHER.test"), Ok(true));
        assert_eq!(nc_email(b"A@other.test", b"a@other.test"), Ok(false));
        assert_eq!(nc_email(b"ab@other.test", b"a@other.test"), Ok(false));
        assert_eq!(nc_email(b"b@other.test", b"@other.test"), Ok(true));
        assert_eq!(nc_email(b"a\0@other.test", b"a\0@other.test"), Err(()));
        assert_eq!(nc_email(b"no-at-sign", b"other.test"), Err(()));
    }

    #[test]
    fn nc_uri_matches_the_host_part() {
        assert_eq!(
            nc_uri(b"https://host.example:443/p", b"host.example"),
            Ok(true)
        );
        assert_eq!(nc_uri(b"https://HOST.example/p", b"host.example"), Ok(true));
        assert_eq!(
            nc_uri(b"https://www.host.example", b".host.example"),
            Ok(true)
        );
        assert_eq!(nc_uri(b"https://host.example", b".host.example"), Ok(false));
        assert_eq!(nc_uri(b"https://other.example", b"host.example"), Ok(false));
        for bad in [
            &b"https:/x"[..],
            b"https://",
            b"https://:1",
            b"mailto:x",
            b"none",
        ] {
            assert_eq!(nc_uri(bad, b"x"), Err(()), "{bad:?}");
        }
    }

    #[test]
    fn nc_ip_matches_address_and_mask_of_one_family() {
        let base = [192, 0, 2, 0, 255, 255, 255, 0];
        assert_eq!(nc_ip(&[192, 0, 2, 1], &base), Ok(true));
        assert_eq!(nc_ip(&[198, 51, 100, 1], &base), Ok(false));
        assert_eq!(nc_ip(&[0; 16], &base), Ok(false));
        assert_eq!(nc_ip(&[192, 0, 2, 1], &[0; 32]), Ok(false));
        assert_eq!(nc_ip(&[0; 16], &[0; 32]), Ok(true));
        assert_eq!(nc_ip(&[0; 5], &base), Err(()));
        assert_eq!(nc_ip(&[192, 0, 2, 1], &[0; 7]), Err(()));
    }

    #[test]
    fn ia5_case_eq_stops_at_a_shared_nul() {
        assert!(ia5_case_eq(b"AbC", b"aBc"));
        assert!(ia5_case_eq(b"a\0x", b"A\0y"));
        assert!(!ia5_case_eq(b"a\0x", b"ab\0"));
        assert!(!ia5_case_eq(b"ab", b"abc"));
    }

    #[test]
    fn parse_name_constraints_reads_subtrees_and_min_max() {
        let ok = subtree(der(0x82, b"ok.test"), &[]);
        let zero_min = subtree(der(0x82, b"bad.ok.test"), &der(0x80, &[0]));
        let nc_der = constraints(std::slice::from_ref(&ok), &[zero_min]);
        let nc = parse_name_constraints(&nc_der).unwrap();
        assert_eq!(nc.permitted.len(), 1);
        assert_eq!(nc.excluded.len(), 1);
        assert!(nc.permitted[0].minmax_valid && nc.excluded[0].minmax_valid);
        assert_eq!(nc.permitted[0].base.value, b"ok.test");
        // The content without the outer SEQUENCE parses too.
        assert!(parse_name_constraints(single(&nc_der, TAG_SEQUENCE).unwrap()).is_some());

        let one_min = subtree(der(0x82, b"ok.test"), &der(0x80, &[1]));
        let max = subtree(der(0x82, b"ok.test"), &der(0x81, &[3]));
        for sub in [one_min, max] {
            let nc_der = constraints(&[sub], &[]);
            assert!(!parse_name_constraints(&nc_der).unwrap().permitted[0].minmax_valid);
        }
        let mut wrong_field = Vec::new();
        push_tlv(&mut wrong_field, 0xa2, &ok);
        assert!(parse_name_constraints(&der(TAG_SEQUENCE, &wrong_field)).is_none());
        let constructed_dns = subtree(der(0xa2, b"ok.test"), &[]);
        assert!(parse_name_constraints(&constraints(&[constructed_dns], &[])).is_none());
    }

    #[test]
    fn general_name_takes_rfc_5280_encodings_only() {
        let dn = cn(TAG_UTF8_STRING, b"x");
        fn gn(b: &[u8]) -> Option<GeneralName<'_>> {
            general_name(DerReader::new(b).read().unwrap())
        }
        assert_eq!(gn(&der(0xa4, &dn)).unwrap().value, &dn[..]);
        assert!(gn(&der(0xa4, &[dn.clone(), dn.clone()].concat())).is_none());
        assert!(gn(&der(0x84, &dn)).is_none());
        assert!(gn(&der(0x81, b"a@b")).is_some());
        assert!(gn(&der(0x89, b"x")).is_none());
        let other = [
            der(TAG_OID, OID_SMTP_UTF8_MAILBOX),
            der(0xa0, &der(TAG_UTF8_STRING, b"a@b")),
        ]
        .concat();
        assert_eq!(gn(&der(0xa0, &other)).unwrap().kind, GN_OTHER_NAME);
        assert!(gn(&der(0xa0, &der(TAG_OID, OID_SMTP_UTF8_MAILBOX))).is_none());
        let seq = der(
            TAG_SEQUENCE,
            &[der(0x82, b"a.test"), der(0x87, &[1, 2, 3, 4])].concat(),
        );
        let names = parse_general_names(&seq).unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[1].kind, GN_IP);
    }

    #[test]
    fn nc_match_applies_permitted_then_excluded_subtrees_of_the_same_type() {
        let nc_der = constraints(
            &[subtree(der(0x82, b".ok.test"), &[])],
            &[subtree(der(0x82, b"bad.ok.test"), &[])],
        );
        let nc = parse_name_constraints(&nc_der).unwrap();
        assert!(nc_match(&dns(b"www.ok.test"), &nc));
        assert!(!nc_match(&dns(b"www.other.test"), &nc));
        assert!(!nc_match(&dns(b"bad.ok.test"), &nc));
        assert!(!nc_match(&dns(b"x.bad.ok.test"), &nc));
        // No subtree of the IP type exists, so an IP name passes.
        let ip = GeneralName {
            kind: GN_IP,
            value: &[192, 0, 2, 1],
        };
        assert!(nc_match(&ip, &nc));

        let bad_minmax = constraints(&[subtree(der(0x82, b"ok.test"), &der(0x80, &[1]))], &[]);
        assert!(!nc_match(
            &dns(b"ok.test"),
            &parse_name_constraints(&bad_minmax).unwrap()
        ));
    }

    #[test]
    fn nc_match_fails_closed_for_smtp_utf8_mailboxes_under_email_subtrees() {
        let value = [
            der(TAG_OID, OID_SMTP_UTF8_MAILBOX),
            der(0xa0, &der(TAG_UTF8_STRING, b"a@ok.test")),
        ]
        .concat();
        let mailbox = GeneralName {
            kind: GN_OTHER_NAME,
            value: &value,
        };
        let email_der = constraints(&[subtree(der(0x81, b"ok.test"), &[])], &[]);
        let email = parse_name_constraints(&email_der).unwrap();
        assert!(!nc_match(&mailbox, &email));
        let dns_der = constraints(&[subtree(der(0x82, b"ok.test"), &[])], &[]);
        let dns_only = parse_name_constraints(&dns_der).unwrap();
        assert!(nc_match(&mailbox, &dns_only));
        let broken = GeneralName {
            kind: GN_OTHER_NAME,
            value: &[0x05, 0x00],
        };
        assert!(!nc_match(&broken, &dns_only));
    }

    #[test]
    fn nc_dn_compares_canonical_prefixes() {
        let o = atv(&[0x55, 0x04, 0x0a], TAG_UTF8_STRING, b"Corpus");
        let c = atv(OID_COMMON_NAME, TAG_UTF8_STRING, b"leaf");
        let base = name(&[&[o]]);
        let full = name(&[
            &[atv(&[0x55, 0x04, 0x0a], TAG_PRINTABLE, b"CORPUS")],
            std::slice::from_ref(&c),
        ]);
        assert_eq!(nc_dn(&full, &base), Ok(true));
        assert_eq!(nc_dn(&name(&[&[c]]), &base), Ok(false));
        assert_eq!(nc_dn(&[0x30, 0x01], &base), Err(()));
    }
}
