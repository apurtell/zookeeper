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

//! Trust-input loading into a `TrustSet`.
//!
//! The loader reads the CA file by the rule of `X509_load_cert_crl_file`,
//! the default verify paths (`SSL_CERT_FILE`, `SSL_CERT_DIR` and the
//! compile-time defaults) and the `HHHHHHHH.N` hash directories of
//! OpenSSL `by_dir`. It classifies each input once per attempt into a
//! [`Role`]. This is the only module of the drop-in that reads the
//! environment.
//!
//! The connector reads every trust file again on each attempt and each
//! RW probe, as C does. The loader is bounded: it reads regular files
//! only, and a failed load adds nothing.
//!
//! A loaded certificate enters the set once. A second copy of the same
//! DER adds nothing, as `X509_STORE_add_cert` ignores it. The first copy
//! keeps its aux settings and its role.
//!
//! The set also models the OpenSSL store order. The CA file and
//! the default file are the store cache. OpenSSL reads a hash directory
//! only when a lookup finds no certificate of the name in the store, and
//! it then adds every certificate of the files that it reads. Each input
//! thus records its origin. The verifiers use `TrustSet::lookup` to find
//! the inputs that OpenSSL can see at each step of a chain. Inputs that
//! OpenSSL can see but the verifier cannot decide make the lookup fail,
//! so that a chain that depends on them fails closed.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};

use crate::net::tls::connector::LegacyPath;
use crate::net::tls::pem::{self, PemBlock, PemError, PemKind};
use crate::net::tls::x509::{self, AuxTrust, LegacyCert, NS_SSL_CA, Validity};

/// The compile-time default certificate file.
/// `None` or an empty value means no default file.
pub const DEFAULT_CERT_FILE: Option<&str> = option_env!("ZK_TLS_DEFAULT_CERT_FILE");

/// The compile-time default certificate directory.
pub const DEFAULT_CERT_DIR: Option<&str> = option_env!("ZK_TLS_DEFAULT_CERT_DIR");

/// The largest trust file that the loader reads.
const MAX_FILE: u64 = 0x0200_0000;

/// The highest `.N` suffix that the hash-directory walk tries.
const MAX_SUFFIX: u32 = 65_536;

/// The role of one trust input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The aux settings reject serverAuth. The input stays an issuer
    /// candidate, and a chain that selects it fails (error 28).
    Rejected,
    /// The input may end a chain, when it is valid at `now`.
    Anchor,
    /// Self-signed but not an anchor. Only path (b) accepts it.
    LeafOnly,
    /// Not self-signed: an intermediate, never a chain end.
    Bridge,
}

/// Where the OpenSSL store gets a trust input from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Origin {
    /// The store cache: the CA file and the default file. OpenSSL loads
    /// it before the first lookup.
    Cache,
    /// The files of one hash in one hash directory, by index in load
    /// order. OpenSSL loads them during a lookup of a name with that hash.
    Group(usize),
}

/// One trust input with its role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedCert {
    der: CertificateDer<'static>,
    aux: Option<AuxTrust>,
    role: Role,
    /// The canonical subject.
    subject: Vec<u8>,
    /// The validity period. The anchor filter reads it on each attempt,
    /// so the filter does not parse the DER again.
    validity: Validity,
    origin: Origin,
    /// The input is in a hash file named for another subject hash.
    foreign: bool,
}

impl TrustedCert {
    /// Makes a trust input. `aux` is the `X509_CERT_AUX` of a
    /// `TRUSTED CERTIFICATE` block.
    ///
    /// The role comes from [`classify`].
    ///
    /// The input comes from the store cache.
    ///
    /// # Errors
    ///
    /// Returns an error when `LegacyCert` does not parse the DER. The
    /// loader then keeps an undecided record of the input, and a chain
    /// whose lookup can see that record fails.
    pub fn new(
        der: CertificateDer<'static>,
        aux: Option<AuxTrust>,
    ) -> Result<Self, crate::net::tls::x509::X509Error> {
        let cert = LegacyCert::parse(der.as_ref())?;
        let role = classify(&cert, aux.as_ref());
        let subject = cert.canonical_subject();
        let validity = cert.validity();
        Ok(Self {
            der,
            aux,
            role,
            subject,
            validity,
            origin: Origin::Cache,
            foreign: false,
        })
    }

    /// Returns the DER.
    #[must_use]
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// Returns the aux trust settings.
    #[must_use]
    pub fn aux(&self) -> Option<&AuxTrust> {
        self.aux.as_ref()
    }

    /// Returns the role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the canonical subject.
    #[must_use]
    pub(crate) fn canonical_subject(&self) -> &[u8] {
        &self.subject
    }

    /// Returns the origin in the OpenSSL store.
    #[must_use]
    pub(crate) fn origin(&self) -> Origin {
        self.origin
    }

    /// Tells whether the input is in a hash file of another subject hash.
    /// Such an input is no trust input of its own. It is only an issuer
    /// candidate that OpenSSL can select once it has read the file.
    #[must_use]
    pub fn foreign(&self) -> bool {
        self.foreign
    }
}

/// A store input that OpenSSL decodes but `LegacyCert` refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Undecided {
    origin: Origin,
    /// The canonical subject. `None` matches every name.
    subject: Option<Vec<u8>>,
    /// OpenSSL can select the input as an issuer. An input that OpenSSL
    /// marks invalid still holds its name in the store.
    selectable: bool,
}

/// The files of one hash in one hash directory.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Group {
    hash: u32,
    /// A file failed after it added certificates to the store.
    partial: bool,
}

/// A lookup that sees an input that the verifier cannot decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct UndecidedInput;

/// A trust-load failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrustLoadError {
    /// No CA file was given.
    NoPath,
    /// The file cannot be opened or read.
    Io,
    /// A PEM block is malformed.
    Pem(PemError),
    /// A certificate, CRL or unencrypted key block has invalid DER.
    Der,
    /// The file has neither a certificate nor a CRL.
    Empty,
    /// The loader could not allocate (the `DefaultVerifyPaths` failure).
    Resource,
}

/// The trust inputs of one attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustSet {
    /// Every trust input with its role, in load order (path (b)).
    certs: Vec<TrustedCert>,
    /// The inputs that may end a chain. The time filter runs at verify
    /// time.
    anchor_candidates: Vec<TrustedCert>,
    /// Trusted inputs that are not self-signed: offered as intermediates.
    bridges: Vec<CertificateDer<'static>>,
    /// `Role::Rejected` inputs.
    rejected: Vec<TrustedCert>,
    /// The number of CRL blocks read. Legacy sets no CRL check.
    crls: usize,
    /// The DER of every input that is filed by role, for the duplicate
    /// rule.
    seen: HashSet<CertificateDer<'static>>,
    /// The foreign inputs, by group.
    seen_foreign: HashSet<(usize, CertificateDer<'static>)>,
    /// The inputs that `LegacyCert` refuses.
    undecided: Vec<Undecided>,
    /// The hash-directory groups, in load order.
    groups: Vec<Group>,
}

impl TrustSet {
    /// Loads the CA file, all or nothing (step `CaFile`).
    ///
    /// The rules: `None` fails; the step succeeds when the file yields at
    /// least one certificate or one CRL; any bad block fails the whole
    /// file. The loader tries the path candidates in
    /// order and skips a candidate that does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`TrustLoadError`]; the connector maps it to
    /// `Config{CaFile}`.
    pub fn load_ca_file(&mut self, ca: Option<&LegacyPath>) -> Result<(), TrustLoadError> {
        let ca = ca.ok_or(TrustLoadError::NoPath)?;
        let text = read_first(ca.candidates())?;
        self.load_ca_text(&text)
    }

    /// Loads the default verify paths (step `DefaultVerifyPaths`).
    ///
    /// When `env_allowed` is true, `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// replace the defaults exactly as given. A missing or bad location
    /// adds nothing and does not fail. The file loads first, then each
    /// directory of the list in order.
    ///
    /// # Errors
    ///
    /// Returns [`TrustLoadError::Resource`] only on a resource error,
    /// which cannot occur in practice.
    pub fn load_default_paths(&mut self, env_allowed: bool) -> Result<(), TrustLoadError> {
        let file = env_path(env_allowed, "SSL_CERT_FILE").or_else(|| {
            DEFAULT_CERT_FILE
                .filter(|f| !f.is_empty())
                .map(PathBuf::from)
        });
        if let Some(file) = file {
            self.load_default_file(&file);
        }
        let dirs = env_path(env_allowed, "SSL_CERT_DIR").or_else(|| {
            DEFAULT_CERT_DIR
                .filter(|d| !d.is_empty())
                .map(PathBuf::from)
        });
        if let Some(dirs) = dirs {
            for dir in split_dir_list(dirs.as_os_str()) {
                self.load_hash_dir(&dir);
            }
        }
        Ok(())
    }

    /// Loads one default file. A file that does not load adds nothing.
    ///
    /// The file follows the CA-file rule (`X509_load_cert_crl_file`).
    pub fn load_default_file(&mut self, path: &Path) {
        if let Ok(text) = read_regular(path) {
            let _ = self.load_ca_text(&text);
        }
    }

    /// Loads one hash directory by the OpenSSL `by_dir` rule: lower-case
    /// `HHHHHHHH.N` names and suffixes from `.0` to the first gap or
    /// failed load.
    ///
    /// The files of one hash form one group, which OpenSSL reads during a
    /// lookup of a name with that hash. A certificate whose subject hash
    /// is not `HHHHHHHH` is a foreign input of the group: no trust input,
    /// but an issuer candidate after the group loads. A file that fails
    /// after some certificates marks the group partial. OpenSSL keeps
    /// those certificates, and a lookup that reads the group fails closed.
    pub fn load_hash_dir(&mut self, dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let hashes: BTreeSet<u32> = entries
            .flatten()
            .filter_map(|e| hash_of_name(&e.file_name()))
            .collect();
        for hash in hashes {
            let group = self.groups.len();
            self.groups.push(Group {
                hash,
                partial: false,
            });
            let origin = Origin::Group(group);
            for k in 0..MAX_SUFFIX {
                let path = dir.join(format!("{hash:08x}.{k}"));
                let (inputs, ok) = load_hash_file(&path);
                if !ok {
                    if !inputs.is_empty() {
                        if let Some(g) = self.groups.last_mut() {
                            g.partial = true;
                        }
                    }
                    break;
                }
                for input in inputs {
                    match input {
                        Input::Cert(mut cert) => {
                            cert.origin = origin;
                            cert.foreign = x509::name_hash(&cert.subject) != hash;
                            self.add(cert);
                        }
                        Input::Undecided {
                            subject,
                            selectable,
                        } => {
                            self.undecided.push(Undecided {
                                origin,
                                subject,
                                selectable,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Tells whether an input of `origin` is in the store once the
    /// groups of `loaded` are read.
    #[must_use]
    pub(crate) fn visible(origin: Origin, loaded: &[usize]) -> bool {
        match origin {
            Origin::Cache => true,
            Origin::Group(g) => loaded.contains(&g),
        }
    }

    /// Tells whether the store holds a certificate of the canonical
    /// `name`, an undecided input included.
    fn holds_name(&self, name: &[u8], loaded: &[usize]) -> bool {
        self.certs
            .iter()
            .any(|c| c.subject == name && Self::visible(c.origin, loaded))
            || self.undecided_name(name, loaded, false)
    }

    /// Tells whether a visible undecided input can have the name. With
    /// `selectable`, only inputs that OpenSSL can select count.
    fn undecided_name(&self, name: &[u8], loaded: &[usize], selectable: bool) -> bool {
        self.undecided.iter().any(|u| {
            Self::visible(u.origin, loaded)
                && (u.selectable || !selectable)
                && u.subject.as_deref().is_none_or(|s| s == name)
        })
    }

    /// The certificate lookup of `X509_STORE_CTX_get_by_subject` for the
    /// canonical `name`.
    ///
    /// The store cache comes first. When the store holds no certificate
    /// of the name, the groups of the name hash load in directory order
    /// until one directory gives the name. `loaded` holds the groups that
    /// earlier lookups of the same verification have read, and the lookup
    /// adds the groups that it reads. The caller then takes the visible
    /// inputs of the name as candidates.
    ///
    /// # Errors
    ///
    /// Returns [`UndecidedInput`] when the lookup reads a partial group,
    /// or when a visible undecided input of the name is one that OpenSSL
    /// can select. The chain then fails closed.
    pub(crate) fn lookup(
        &self,
        name: &[u8],
        loaded: &mut Vec<usize>,
    ) -> Result<(), UndecidedInput> {
        if !self.holds_name(name, loaded) {
            let hash = x509::name_hash(name);
            for (g, group) in self.groups.iter().enumerate() {
                if group.hash != hash {
                    continue;
                }
                if !loaded.contains(&g) {
                    loaded.push(g);
                }
                if group.partial {
                    return Err(UndecidedInput);
                }
                if self.holds_name(name, loaded) {
                    break;
                }
            }
        }
        if self.undecided_name(name, loaded, true) {
            return Err(UndecidedInput);
        }
        Ok(())
    }

    /// Loads a CA-file image into the set, all or nothing.
    fn load_ca_text(&mut self, text: &[u8]) -> Result<(), TrustLoadError> {
        let (inputs, crls) = parse_ca_text(text)?;
        for input in inputs {
            match input {
                Input::Cert(cert) => self.add(cert),
                Input::Undecided {
                    subject,
                    selectable,
                } => self.undecided.push(Undecided {
                    origin: Origin::Cache,
                    subject,
                    selectable,
                }),
            }
        }
        self.crls = self.crls.saturating_add(crls);
        Ok(())
    }

    /// Adds an input unless the store already holds the same DER where
    /// OpenSSL reads it first. A foreign copy is kept once per group,
    /// because the group that loads first is known only at lookup time.
    fn add(&mut self, cert: TrustedCert) {
        if self.seen.contains(&cert.der) {
            return;
        }
        if cert.foreign {
            if let Origin::Group(g) = cert.origin {
                if self.seen_foreign.insert((g, cert.der.clone())) {
                    self.certs.push(cert);
                }
            }
            return;
        }
        self.push(cert);
    }

    /// Adds one input and files it by role.
    pub fn push(&mut self, cert: TrustedCert) {
        match cert.role {
            Role::Rejected => self.rejected.push(cert.clone()),
            Role::Anchor => self.anchor_candidates.push(cert.clone()),
            Role::Bridge => self.bridges.push(cert.der.clone()),
            Role::LeafOnly => {}
        }
        self.seen.insert(cert.der.clone());
        self.certs.push(cert);
    }

    /// Returns every input in load order, foreign inputs included.
    #[must_use]
    pub fn certs(&self) -> &[TrustedCert] {
        &self.certs
    }

    /// Returns the inputs that may end a chain.
    #[must_use]
    pub fn anchor_candidates(&self) -> &[TrustedCert] {
        &self.anchor_candidates
    }

    /// Returns the bridges.
    #[must_use]
    pub fn bridges(&self) -> &[CertificateDer<'static>] {
        &self.bridges
    }

    /// Returns the rejected inputs.
    #[must_use]
    pub fn rejected(&self) -> &[TrustedCert] {
        &self.rejected
    }

    /// Returns the number of CRL blocks read.
    #[must_use]
    pub fn crl_count(&self) -> usize {
        self.crls
    }

    /// Returns the anchors valid at `now` as a root store.
    /// `RootCertStore::add` takes v1 anchors. An anchor that webpki does
    /// not take is left out.
    #[must_use]
    pub fn root_store_at(&self, now: UnixTime) -> RootCertStore {
        let mut store = RootCertStore::empty();
        for anchor in &self.anchor_candidates {
            if anchor.validity.contains(now) {
                let _ = store.add(anchor.der.clone());
            }
        }
        store
    }
}

/// Classifies one trust input.
///
/// The aux settings come first, as `obj_trust` applies them. A trust list
/// without serverAuth and anyExtendedKeyUsage rejects the input, also
/// when the list is empty. A reject list without them has no effect.
/// Otherwise, a self-signed input that passes `check_ssl_ca` and the EKU
/// test is an anchor.
#[must_use]
pub fn classify(cert: &LegacyCert<'_>, aux: Option<&AuxTrust>) -> Role {
    if let Some(aux) = aux {
        if aux.rejects_server_auth() {
            return Role::Rejected;
        }
        if aux.trusts_server_auth() {
            return Role::Anchor;
        }
        if aux.trust.is_some() {
            return Role::Rejected;
        }
    }
    if !cert.openssl_self_signed() {
        return Role::Bridge;
    }
    let ca = cert.openssl_check_ca();
    let ssl_ca = ca != 0 && (ca != 5 || cert.ns_cert_type().is_some_and(|ns| ns & NS_SSL_CA != 0));
    if ssl_ca && cert.eku_allows_ssl_server() {
        Role::Anchor
    } else {
        Role::LeafOnly
    }
}

/// Adds the default verify paths to the set.
///
/// This is the entry that the connector calls. It delegates to
/// [`TrustSet::load_default_paths`] and drops the result, which is never
/// an error in practice.
pub fn add_default_paths(set: &mut TrustSet, env_allowed: bool) {
    let _ = set.load_default_paths(env_allowed);
}

/// Reads an environment path when the caller allows it. A set but empty
/// value counts as set.
fn env_path(env_allowed: bool, name: &str) -> Option<PathBuf> {
    if env_allowed {
        std::env::var_os(name).map(PathBuf::from)
    } else {
        None
    }
}

/// Splits a directory list as `by_dir` does: on `:` (`;` on Windows),
/// without empty entries and without repeats.
fn split_dir_list(list: &OsStr) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in split_os(list) {
        if !dir.as_os_str().is_empty() && !out.contains(&dir) {
            out.push(dir);
        }
    }
    out
}

#[cfg(unix)]
fn split_os(list: &OsStr) -> Vec<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    list.as_bytes()
        .split(|b| *b == b':')
        .map(|p| PathBuf::from(OsStr::from_bytes(p)))
        .collect()
}

#[cfg(windows)]
fn split_os(list: &OsStr) -> Vec<PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let wide: Vec<u16> = list.encode_wide().collect();
    wide.split(|c| *c == u16::from(b';'))
        .map(|p| PathBuf::from(std::ffi::OsString::from_wide(p)))
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn split_os(list: &OsStr) -> Vec<PathBuf> {
    list.to_string_lossy()
        .split(':')
        .map(PathBuf::from)
        .collect()
}

/// The hash of a `by_dir` name: eight lower-case hex digits, a dot and a
/// decimal suffix.
fn hash_of_name(name: &OsStr) -> Option<u32> {
    let name = name.to_str()?;
    let (hash, suffix) = name.split_once('.')?;
    let hex_ok = hash.len() == 8 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let suffix_ok = !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit());
    if hex_ok && suffix_ok {
        u32::from_str_radix(hash, 16).ok()
    } else {
        None
    }
}

/// A file read failure.
enum ReadError {
    /// The path does not exist.
    NotFound,
    /// Any other failure, a non-regular file, or a file over the limit.
    Other,
}

/// Reads one regular file of at most [`MAX_FILE`] bytes. The type check
/// comes before the open, so that a FIFO never blocks the loader.
fn read_regular(path: &Path) -> Result<Vec<u8>, ReadError> {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ReadError::NotFound,
        _ => ReadError::Other,
    })?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err(ReadError::Other);
    }
    let file = File::open(path).map_err(|_| ReadError::Other)?;
    let meta = file.metadata().map_err(|_| ReadError::Other)?;
    if !meta.is_file() {
        return Err(ReadError::Other);
    }
    let mut buf = Vec::new();
    file.take(MAX_FILE.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|_| ReadError::Other)?;
    if u64::try_from(buf.len()).map_or(true, |n| n > MAX_FILE) {
        return Err(ReadError::Other);
    }
    Ok(buf)
}

/// Reads the first candidate that exists.
fn read_first(candidates: &[PathBuf]) -> Result<Vec<u8>, TrustLoadError> {
    for path in candidates {
        match read_regular(path) {
            Ok(text) => return Ok(text),
            Err(ReadError::NotFound) => {}
            Err(ReadError::Other) => return Err(TrustLoadError::Io),
        }
    }
    Err(TrustLoadError::Io)
}

/// Splits a certificate body into the certificate DER and the bytes after
/// it, by the `d2i_X509` test.
fn split_cert(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let rest = x509::ber_certificate(body)?;
    let cut = body.len().checked_sub(rest.len())?;
    body.split_at_checked(cut)
}

/// One certificate that a trust file adds to the store.
enum Input {
    /// A certificate that `LegacyCert` parses.
    Cert(TrustedCert),
    /// A certificate that `LegacyCert` refuses.
    Undecided {
        /// The canonical subject, when it decodes.
        subject: Option<Vec<u8>>,
        /// OpenSSL can select the input as an issuer.
        selectable: bool,
    },
}

/// Makes the store input of a certificate block.
fn input(cert: &[u8], aux: Option<AuxTrust>) -> Input {
    match TrustedCert::new(CertificateDer::from(cert.to_vec()), aux) {
        Ok(t) => Input::Cert(t),
        Err(_) => Input::Undecided {
            subject: x509::ber_subject(cert),
            selectable: !x509::ber_duplicate_extension(cert),
        },
    }
}

/// The `PEM_X509_INFO_read_bio_ex` rule for one CA-file image. It returns
/// the trust inputs and the CRL count, or the first failure.
fn parse_ca_text(text: &[u8]) -> Result<(Vec<Input>, usize), TrustLoadError> {
    let blocks = pem::read_blocks(text).map_err(TrustLoadError::Pem)?;
    let mut found: usize = 0;
    let mut crls: usize = 0;
    let mut certs = Vec::new();
    for block in &blocks {
        let body = block.body.expose();
        let kind = pem::classify_label(&block.label);
        match kind {
            PemKind::Certificate | PemKind::TrustedCertificate => {
                no_headers(block)?;
                let (cert, rest) = split_cert(body).ok_or(TrustLoadError::Der)?;
                let aux = if kind == PemKind::TrustedCertificate && !rest.is_empty() {
                    Some(AuxTrust::parse(rest).map_err(|_| TrustLoadError::Der)?)
                } else {
                    None
                };
                found = found.saturating_add(1);
                certs.push(input(cert, aux));
            }
            PemKind::Crl => {
                no_headers(block)?;
                if !x509::ber_crl_ok(body) {
                    return Err(TrustLoadError::Der);
                }
                found = found.saturating_add(1);
                crls = crls.saturating_add(1);
            }
            _ if block.label.contains("PRIVATE KEY") => {
                if !block.headers.is_empty() {
                    if !pem::cipher_info_ok(&block.headers) {
                        return Err(TrustLoadError::Pem(PemError::Header));
                    }
                } else if block.label != "ENCRYPTED PRIVATE KEY"
                    && !pem::key_block_ok(&block.label, body)
                {
                    return Err(TrustLoadError::Der);
                }
            }
            _ => {}
        }
    }
    if found == 0 {
        return Err(TrustLoadError::Empty);
    }
    Ok((certs, crls))
}

/// A certificate or CRL block with headers fails, because OpenSSL reads
/// the headers as encryption settings.
fn no_headers(block: &PemBlock) -> Result<(), TrustLoadError> {
    if block.headers.is_empty() {
        Ok(())
    } else {
        Err(TrustLoadError::Pem(PemError::Header))
    }
}

/// The `X509_load_cert_file` rule for one hash-directory file. It returns
/// the store inputs read before the first failure, and whether the file
/// loaded. Every certificate label decodes as `d2i_X509_AUX`, so
/// trailing aux settings apply to every label.
fn load_hash_file(path: &Path) -> (Vec<Input>, bool) {
    let Ok(text) = read_regular(path) else {
        return (Vec::new(), false);
    };
    let (blocks, err) = pem::read_blocks_partial(&text);
    let mut certs = Vec::new();
    let mut count: usize = 0;
    for block in &blocks {
        if !matches!(
            pem::classify_label(&block.label),
            PemKind::Certificate | PemKind::TrustedCertificate
        ) {
            continue;
        }
        if !block.headers.is_empty() {
            return (certs, false);
        }
        let Some((cert, rest)) = split_cert(block.body.expose()) else {
            return (certs, false);
        };
        let aux = if rest.is_empty() {
            None
        } else {
            match AuxTrust::parse(rest) {
                Ok(aux) => Some(aux),
                Err(_) => return (certs, false),
            }
        };
        count = count.saturating_add(1);
        certs.push(input(cert, aux));
    }
    let ok = err.is_none() && count > 0;
    (certs, ok)
}
