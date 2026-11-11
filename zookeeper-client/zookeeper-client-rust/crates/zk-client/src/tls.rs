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

//! Native TLS options (feature `tls-rustls`).
//!
//! The options read and check every file in `build`, so a bad file
//! fails early. The driver asks for a `rustls::ClientConfig` at each
//! connection attempt through `zk_driver::net::tls::NativeConfig`.
//! With `ReloadPolicy::OnChange`, the client reads a changed file again
//! at the next attempt. A failed reload fails the attempt. The error goes
//! to `SessionInfo::last_error` through `error_probe`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rustls::client::danger::ServerCertVerifier;
use rustls::client::{ResolvesClientCert, Resumption};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ProtocolVersion, RootCertStore, SignatureScheme, SupportedProtocolVersion,
};
use zk_driver::Unlocked;
use zk_driver::net::tls::identity::{Identity, LegacyClientCert};
use zk_driver::net::tls::legacy_verify::LegacyChainOnly;
use zk_driver::net::tls::trust::{Role, TrustSet, TrustedCert};
use zk_driver::net::tls::verify::{ChainOnlyVerifier, webpki_verifier};
use zk_driver::net::tls::{
    Endpoint, LegacyPath, NativeConfig, RustlsConnector, TlsConfigStep, TlsConn, TlsConnector,
    TlsPurpose, TlsResourceAt, TlsSetupError, default_provider, trust,
};
use zk_proto::SecretBytes;
use zk_proto::compat::TlsVerify;

use crate::error::LastError;
use crate::route::TlsErrorSource;
use crate::secret::SecretString;
use crate::sync::LockExt;

/// When the client reads the TLS files again.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ReloadPolicy {
    /// Read the files again at a connection attempt when they changed.
    #[default]
    OnChange,
    /// Read the files only in `build`.
    Never,
}

/// A TLS configuration error.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TlsConfigError {
    /// The CA file cannot be read, has a bad PEM block, or has no
    /// certificate and no CRL.
    CaFile(PathBuf),
    /// `add_system_roots` found no usable root in the default
    /// locations.
    DefaultRoots,
    /// The client certificate chain cannot be loaded.
    CertChain(PathBuf),
    /// The private key cannot be loaded or decrypted.
    PrivateKey(PathBuf),
    /// The private key does not match the certificate.
    KeyMismatch,
    /// The rustls configuration cannot be made.
    Context,
    /// The platform verifier cannot be used. The text names the cause.
    PlatformVerifier(String),
    /// A FIPS build got a configuration that is not FIPS.
    NotFips,
}

impl std::fmt::Display for TlsConfigError {
    /// A short text that names the file. It never contains a
    /// passphrase.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CaFile(p) => write!(f, "failed to load CA file {}", p.display()),
            Self::DefaultRoots => {
                f.write_str("no usable root certificate in the default locations")
            }
            Self::CertChain(p) => write!(
                f,
                "failed to load client certificate chain from {}",
                p.display()
            ),
            Self::PrivateKey(p) => {
                write!(f, "failed to load client private key from {}", p.display())
            }
            Self::KeyMismatch => {
                f.write_str("the client private key does not match the certificate")
            }
            Self::Context => f.write_str("cannot make the TLS configuration"),
            Self::PlatformVerifier(cause) => write!(f, "cannot use the platform verifier: {cause}"),
            Self::NotFips => f.write_str("the TLS configuration is not FIPS"),
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// The trust and identity sources of the builder.
#[derive(Debug)]
pub(crate) struct FileSources {
    /// The CA file, a pin.
    pub(crate) ca_file: Option<PathBuf>,
    /// True after `add_system_roots`.
    pub(crate) system_roots: bool,
    /// The client certificate chain, key and passphrase.
    pub(crate) identity: Option<(PathBuf, PathBuf, Option<SecretString>)>,
    /// One server name for the whole ensemble.
    pub(crate) server_name: Option<ServerName<'static>>,
    /// True after `danger_disable_hostname_verification`.
    pub(crate) no_hostname_check: bool,
    /// The lowest protocol version.
    pub(crate) min_protocol: &'static SupportedProtocolVersion,
    /// True after `with_platform_verifier`.
    pub(crate) platform_verifier: bool,
}

/// Where the rustls configuration comes from.
#[derive(Debug)]
pub(crate) enum TlsSource {
    /// The builder files. `legacy` is true for `legacy_c_compat`.
    Files {
        /// The files.
        files: FileSources,
        /// True for `legacy_c_compat`: `TlsVerify::LegacyChainOnly`.
        legacy: bool,
    },
    /// A configuration of the application.
    Rustls(Arc<rustls::ClientConfig>),
}

/// The state that every client with these options shares.
pub(crate) struct TlsInner {
    /// The source.
    pub(crate) source: TlsSource,
    /// The reload rule.
    pub(crate) reload: ReloadPolicy,
    /// The last built configuration and the file stamps of its inputs,
    /// for `ReloadPolicy`. It is a leaf lock. No file IO runs while a
    /// thread holds it.
    pub(crate) cache: Mutex<Option<Cached>>,
    /// The error of the last failed reload. `error_probe` reads it.
    pub(crate) last_error: Mutex<Option<TlsConfigError>>,
    /// The `tls_env_allowed` input, computed once.
    pub(crate) env_allowed: bool,
}

impl std::fmt::Debug for TlsInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsInner")
            .field("source", &self.source)
            .field("reload", &self.reload)
            .finish_non_exhaustive()
    }
}

/// TLS options for one or more clients. Cloning is cheap.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    inner: Arc<TlsInner>,
}

impl TlsOptions {
    /// Starts a builder with no trust source.
    pub fn builder() -> TlsOptionsBuilder {
        TlsOptionsBuilder::new()
    }

    /// The drop-in trust decision, for migration.
    ///
    /// It parses the `zookeeper_init_ssl` string "ca,cert,key,passwd".
    /// It selects `TlsVerify::LegacyChainOnly`: the CA file plus the
    /// default locations, no SNI and no name check. It keeps no copy of
    /// the string. The passphrase goes into a [`SecretString`]. It
    /// never reports `DefaultRoots`.
    ///
    /// # Errors
    ///
    /// The [`TlsConfigError`] of the first file that fails.
    pub fn legacy_c_compat(cert_string: &str) -> Result<TlsOptions, TlsConfigError> {
        let [ca, cert, key, passwd] = split_cert_string(cert_string);
        // The identity needs the chain and the key. The passphrase is
        // optional, so an unencrypted key loads without one (spec
        // "Client Identity Support Without Passwords").
        let identity = match (cert, key) {
            (Some(c), Some(k)) => Some((
                PathBuf::from(c),
                PathBuf::from(k),
                passwd.map(SecretString::from),
            )),
            _ => None,
        };
        let files = FileSources {
            ca_file: ca.map(PathBuf::from),
            system_roots: true,
            identity,
            server_name: None,
            no_hostname_check: true,
            min_protocol: &rustls::version::TLS12,
            platform_verifier: false,
        };
        Self::load_new(files, true, ReloadPolicy::OnChange)
    }

    /// Uses `cfg` as it is. The name and SNI policy is what `cfg` does.
    /// `ReloadPolicy` does not apply.
    #[must_use]
    pub fn from_rustls(cfg: Arc<rustls::ClientConfig>) -> TlsOptions {
        Self::from_inner(TlsInner {
            source: TlsSource::Rustls(cfg),
            reload: ReloadPolicy::Never,
            cache: Mutex::new(None),
            last_error: Mutex::new(None),
            env_allowed: false,
        })
    }

    /// Wraps the shared state.
    pub(crate) fn from_inner(inner: TlsInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Computes `tls_env_allowed`, reads and checks every file, and keeps
    /// the result as the first cache entry.
    fn load_new(
        files: FileSources,
        legacy: bool,
        reload: ReloadPolicy,
    ) -> Result<TlsOptions, TlsConfigError> {
        let env_allowed = env_allowed();
        let first = load(&files, legacy, env_allowed)?;
        Ok(Self::from_inner(TlsInner {
            source: TlsSource::Files { files, legacy },
            reload,
            cache: Mutex::new(Some(first)),
            last_error: Mutex::new(None),
            env_allowed,
        }))
    }

    /// The `Compat::tls_verify` value of these options: `LegacyChainOnly`
    /// for `legacy_c_compat`, else `WebPki`.
    pub(crate) fn tls_verify(&self) -> TlsVerify {
        match &self.inner.source {
            TlsSource::Files { legacy: true, .. } => TlsVerify::LegacyChainOnly,
            _ => TlsVerify::WebPki,
        }
    }

    /// Checks the options at `build` and `connect`. A FIPS build refuses a
    /// `from_rustls` configuration that is not FIPS.
    ///
    /// # Errors
    ///
    /// `TlsConfigError::NotFips`.
    pub(crate) fn check(&self) -> Result<(), TlsConfigError> {
        #[cfg(feature = "tls-aws-lc-rs-fips")]
        if let TlsSource::Rustls(cfg) = &self.inner.source {
            if !cfg.fips() {
                return Err(TlsConfigError::NotFips);
            }
        }
        Ok(())
    }

    /// Makes the driver connector over these options, with the provider
    /// of the build (`zk_driver::net::tls::default_provider`).
    pub(crate) fn connector(&self) -> Arc<dyn TlsConnector> {
        let src: Arc<dyn NativeConfig> = Arc::clone(&self.inner) as Arc<dyn NativeConfig>;
        let mut connector = NativeConnector {
            inner: RustlsConnector::native(src, default_provider()),
            name: None,
            ca: None,
            cert: None,
            key: None,
        };
        if let TlsSource::Files { files, legacy } = &self.inner.source {
            connector.name = files.server_name.as_ref().and_then(name_text);
            connector.ca = files.ca_file.as_deref().map(path_bytes);
            if let Some((chain, key, _)) = &files.identity {
                connector.cert = Some(path_bytes(chain));
                connector.key = Some(path_bytes(key));
            }
            // Each client makes its connector once, so the warning comes
            // once per client.
            if files.no_hostname_check && !legacy {
                warn_no_hostname_check();
            }
        }
        Arc::new(connector)
    }

    /// Gives the error of the last failed reload, for the router. The value
    /// is a `TlsConfigError`.
    pub(crate) fn error_probe(&self) -> TlsErrorSource {
        let inner = Arc::clone(&self.inner);
        Arc::new(move || {
            let e = inner.last_error.lock_unpoisoned().clone()?;
            let e: LastError = Arc::new(e);
            Some(e)
        })
    }
}

impl NativeConfig for TlsInner {
    /// Gives the configuration of one connection attempt.
    ///
    /// With `OnChange` it reads the files again when they changed, and
    /// else it uses the cache. A failed reload stores the
    /// `TlsConfigError` in `last_error` and gives the matching
    /// `TlsSetupError` step. A success clears `last_error`.
    fn client_config(
        &self,
        _proof: &Unlocked,
        _purpose: TlsPurpose,
    ) -> Result<Arc<rustls::ClientConfig>, TlsSetupError> {
        let (files, legacy) = match &self.source {
            TlsSource::Rustls(cfg) => return Ok(Arc::clone(cfg)),
            TlsSource::Files { files, legacy } => (files, *legacy),
        };
        // Copy the cache out of its lock. The stat calls and the file
        // reads run with no lock held.
        let cached = self.cache.lock_unpoisoned().as_ref().map(|c| {
            (
                Arc::clone(&c.config),
                Arc::clone(&c.watched),
                c.stamps.clone(),
            )
        });
        if let Some((cfg, watched, stamps)) = cached {
            if self.reload == ReloadPolicy::Never || stamps_of(&watched) == stamps {
                *self.last_error.lock_unpoisoned() = None;
                return Ok(cfg);
            }
        }
        match load(files, legacy, self.env_allowed) {
            Ok(fresh) => {
                let cfg = Arc::clone(&fresh.config);
                *self.cache.lock_unpoisoned() = Some(fresh);
                *self.last_error.lock_unpoisoned() = None;
                Ok(cfg)
            }
            Err(e) => {
                let step = setup_error(&e);
                *self.last_error.lock_unpoisoned() = Some(e);
                Err(step)
            }
        }
    }
}

/// The builder of [`TlsOptions`].
#[derive(Debug)]
#[must_use = "a builder does nothing until build() is called"]
pub struct TlsOptionsBuilder {
    files: FileSources,
    reload: ReloadPolicy,
}

impl TlsOptionsBuilder {
    /// Makes a builder with no trust source, TLS 1.2 as the lowest
    /// version and `ReloadPolicy::OnChange`.
    fn new() -> Self {
        Self {
            files: FileSources {
                ca_file: None,
                system_roots: false,
                identity: None,
                server_name: None,
                no_hostname_check: false,
                min_protocol: &rustls::version::TLS12,
                platform_verifier: false,
            },
            reload: ReloadPolicy::OnChange,
        }
    }

    /// Trusts the roots of this PEM file. It is a pin: only these roots,
    /// unless `add_system_roots` is also set.
    pub fn ca_file(mut self, p: impl Into<PathBuf>) -> Self {
        self.files.ca_file = Some(p.into());
        self
    }

    /// Also trusts the roots in the default locations, by the drop-in
    /// rules.
    pub fn add_system_roots(mut self) -> Self {
        self.files.system_roots = true;
        self
    }

    /// Sets the client certificate chain and key. An encrypted key needs
    /// the passphrase.
    pub fn client_identity(
        mut self,
        chain: impl Into<PathBuf>,
        key: impl Into<PathBuf>,
        passphrase: Option<SecretString>,
    ) -> Self {
        self.files.identity = Some((chain.into(), key.into(), passphrase));
        self
    }

    /// Verifies every server against this one name, and sends it as SNI
    /// when it is a DNS name.
    pub fn server_name(mut self, name: ServerName<'static>) -> Self {
        self.files.server_name = Some(name);
        self
    }

    /// Verifies the chain only, with no name check. The client logs one
    /// warning.
    pub fn danger_disable_hostname_verification(mut self) -> Self {
        self.files.no_hostname_check = true;
        self
    }

    /// Sets the lowest protocol version. The default is TLS 1.2.
    pub fn min_protocol(mut self, v: &'static SupportedProtocolVersion) -> Self {
        self.files.min_protocol = v;
        self
    }

    /// Sets the reload policy. The default is `OnChange`.
    pub fn reload(mut self, r: ReloadPolicy) -> Self {
        self.reload = r;
        self
    }

    /// Uses the OS trust store and the OS policy.
    ///
    /// The OS verifier replaces every trust file. Thus `build` fails with
    /// `TlsConfigError::PlatformVerifier` when this mixes with `ca_file`,
    /// `add_system_roots` or `danger_disable_hostname_verification`. A
    /// set-uid or set-gid process on Linux and the BSDs gets the same
    /// error. The error also occurs when the OS verifier does not start.
    #[cfg(feature = "tls-platform-verifier")]
    pub fn with_platform_verifier(mut self) -> Self {
        self.files.platform_verifier = true;
        self
    }

    /// Reads and checks every file now.
    ///
    /// It computes `tls_env_allowed` once with rustix: the real and
    /// effective uid and gid match. It reports `DefaultRoots` when
    /// `add_system_roots` finds no root. A FIPS build checks
    /// `ClientConfig::fips()`.
    ///
    /// # Errors
    ///
    /// The [`TlsConfigError`] of the first check that fails.
    pub fn build(self) -> Result<TlsOptions, TlsConfigError> {
        check_platform_verifier(&self.files, env_allowed())?;
        TlsOptions::load_new(self.files, false, self.reload)
    }
}

// ---- Private helpers ----

/// One cache entry: a configuration and the stamps of its input files.
pub(crate) struct Cached {
    /// The configuration.
    config: Arc<ClientConfig>,
    /// The files and directories that the configuration came from.
    watched: Arc<[PathBuf]>,
    /// The stamps of `watched`, taken before the files were read.
    stamps: Vec<Option<Stamp>>,
}

/// The change marker of one file or directory.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
    inode: u64,
}

/// Reads the stamp of a path. A path that cannot be read gives `None`.
fn stamp(p: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(p).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0;
    Some(Stamp {
        modified: meta.modified().ok(),
        len: meta.len(),
        inode,
    })
}

/// Reads the stamps of all paths, in order.
fn stamps_of(paths: &[PathBuf]) -> Vec<Option<Stamp>> {
    paths.iter().map(|p| stamp(p)).collect()
}

/// Computes `tls_env_allowed`. A set-uid or set-gid process ignores
/// `SSL_CERT_FILE` and `SSL_CERT_DIR`, as OpenSSL does.
#[cfg(unix)]
fn env_allowed() -> bool {
    use rustix::process::{getegid, geteuid, getgid, getuid};
    getuid() == geteuid() && getgid() == getegid()
}

/// Computes `tls_env_allowed`. Windows always allows the variables, as
/// the drop-in shim does.
#[cfg(not(unix))]
fn env_allowed() -> bool {
    true
}

/// Splits a `zookeeper_init_ssl` string into "ca,cert,key,passwd".
///
/// The rule is the `strtok` rule of the C client: empty fields collapse,
/// whitespace stays, and fields after the fourth do not count. The
/// fields borrow the input, so no copy of the string stays.
fn split_cert_string(s: &str) -> [Option<&str>; 4] {
    let mut fields = s.split(',').filter(|f| !f.is_empty());
    [fields.next(), fields.next(), fields.next(), fields.next()]
}

/// Checks the platform verifier rules of `build`.
///
/// The verifier must not mix with another trust decision, so that
/// combination gets its own text. On Linux and the BSDs the OS trust
/// store reads `SSL_CERT_FILE` and `SSL_CERT_DIR`. A set-uid or set-gid
/// process thus cannot use the verifier there.
fn check_platform_verifier(files: &FileSources, env_allowed: bool) -> Result<(), TlsConfigError> {
    if !files.platform_verifier {
        return Ok(());
    }
    if files.ca_file.is_some() || files.system_roots || files.no_hostname_check {
        return Err(TlsConfigError::PlatformVerifier(
            "with_platform_verifier cannot be combined with ca_file, add_system_roots or \
             danger_disable_hostname_verification"
                .to_owned(),
        ));
    }
    if !env_allowed
        && cfg!(all(
            unix,
            not(target_vendor = "apple"),
            not(target_os = "android")
        ))
    {
        return Err(TlsConfigError::PlatformVerifier(
            "the OS trust store reads the environment, which a set-uid or set-gid process \
             must ignore"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Makes the OS verifier: the OS trust store and the OS verification
/// policy, with the signature checks of the build provider.
#[cfg(feature = "tls-platform-verifier")]
fn platform_verifier(
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, TlsConfigError> {
    match rustls_platform_verifier::Verifier::new(Arc::clone(provider)) {
        Ok(v) => Ok(Arc::new(v)),
        Err(e) => Err(TlsConfigError::PlatformVerifier(e.to_string())),
    }
}

/// A build without the feature has no OS verifier. The builder method
/// does not exist there, so this path does not occur.
#[cfg(not(feature = "tls-platform-verifier"))]
fn platform_verifier(
    _provider: &Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, TlsConfigError> {
    Err(TlsConfigError::PlatformVerifier(
        "the platform verifier is not in this build".to_owned(),
    ))
}

/// Gives the driver step of a configuration error. A file error parks
/// the attempt. A context error is a teardown, as in the driver.
fn setup_error(e: &TlsConfigError) -> TlsSetupError {
    let step = match e {
        TlsConfigError::CaFile(_) => TlsConfigStep::CaFile,
        TlsConfigError::DefaultRoots => TlsConfigStep::DefaultVerifyPaths,
        TlsConfigError::CertChain(_) => TlsConfigStep::ClientCertChain,
        TlsConfigError::PrivateKey(_) => TlsConfigStep::ClientKey,
        TlsConfigError::KeyMismatch => TlsConfigStep::CheckPrivateKey,
        TlsConfigError::Context | TlsConfigError::PlatformVerifier(_) | TlsConfigError::NotFips => {
            return TlsSetupError::Resource {
                at: TlsResourceAt::ContextNew,
            };
        }
    };
    TlsSetupError::Config { step }
}

/// The default trust locations of one load.
#[derive(Debug, Default)]
struct DefaultLocations {
    /// The certificate bundle.
    file: Option<PathBuf>,
    /// The hash-name directories.
    dirs: Vec<PathBuf>,
}

impl DefaultLocations {
    /// Selects the locations.
    ///
    /// A set and allowed `SSL_CERT_FILE` or `SSL_CERT_DIR` replaces the
    /// compile-time default, even when its target is missing. `var`
    /// reads the environment, so tests can give their own values.
    fn select(env_allowed: bool, var: &dyn Fn(&str) -> Option<OsString>) -> Self {
        let env = |name: &str| if env_allowed { var(name) } else { None };
        let file = match env("SSL_CERT_FILE") {
            Some(v) => Some(PathBuf::from(v)),
            None => trust::DEFAULT_CERT_FILE
                .filter(|f| !f.is_empty())
                .map(PathBuf::from),
        };
        let dirs: Vec<PathBuf> = match env("SSL_CERT_DIR") {
            Some(v) => std::env::split_paths(&v).collect(),
            None => trust::DEFAULT_CERT_DIR
                .filter(|d| !d.is_empty())
                .map(|d| std::env::split_paths(d).collect())
                .unwrap_or_default(),
        };
        let dirs = dirs
            .into_iter()
            .filter(|d| !d.as_os_str().is_empty())
            .collect();
        Self { file, dirs }
    }

    /// Adds the trust inputs of the locations to `trust` with the strict
    /// loader. It gives the count of inputs that it added.
    ///
    /// A missing, empty or malformed location adds nothing and does not
    /// fail. A hash-directory file counts only when its name matches the
    /// subject hash of its certificate.
    fn add_to(&self, trust: &mut TrustSet) -> usize {
        let before = trust.certs().len();
        if let Some(file) = &self.file {
            trust.load_default_file(file);
        }
        for dir in &self.dirs {
            trust.load_hash_dir(dir);
        }
        trust
            .certs()
            .get(before..)
            .unwrap_or_default()
            .iter()
            .filter(|c| !c.foreign())
            .count()
    }

    /// The paths whose change starts a reload.
    fn watched(&self) -> impl Iterator<Item = &PathBuf> {
        self.file.iter().chain(self.dirs.iter())
    }
}

/// Makes the loader path of a builder path. The raw bytes are the log
/// text of the path.
fn legacy_path(p: &Path) -> LegacyPath {
    LegacyPath::with_candidates(path_bytes(p), vec![p.to_path_buf()])
}

/// Loads the CA file into `trust` (the `CaFile` step).
///
/// The strict loader of the drop-in reads the file, all or nothing. It
/// accepts the `CERTIFICATE`, `X509 CERTIFICATE` and `TRUSTED
/// CERTIFICATE` labels and DER files. It fails when the file has no
/// certificate and no CRL. CRLs count, but they are not used.
fn load_ca_file(path: &Path, trust: &mut TrustSet) -> Result<(), TlsConfigError> {
    trust
        .load_ca_file(Some(&legacy_path(path)))
        .map_err(|_| TlsConfigError::CaFile(path.to_path_buf()))
}

/// Adds the trust inputs to a root store for the native rule.
///
/// Each input that the aux settings do not reject is a root, as a CA
/// file is in rustls. An input that the verifier cannot parse adds no
/// root. A foreign input of a hash file is no root, because its file
/// name does not match its subject hash. The function gives the count of
/// roots that it added.
fn add_roots(trust: &[TrustedCert], roots: &mut RootCertStore) -> usize {
    trust
        .iter()
        .filter(|c| c.role() != Role::Rejected && !c.foreign())
        .filter(|c| roots.add(c.der().clone()).is_ok())
        .count()
}

/// Loads the client identity with the loader of the drop-in.
///
/// The loader decrypts an encrypted key with the passphrase. Each key
/// copy stays in zeroizing storage. The failed step gives the error.
fn load_identity(
    chain: &Path,
    key: &Path,
    passphrase: Option<&SecretString>,
    provider: &CryptoProvider,
) -> Result<Arc<CertifiedKey>, TlsConfigError> {
    let passwd = match passphrase {
        Some(p) => SecretBytes::from_slice(p.expose().as_bytes()),
        None => SecretBytes::empty(),
    };
    match Identity::load(&legacy_path(chain), &legacy_path(key), &passwd, provider) {
        Ok(identity) => Ok(Arc::clone(identity.certified_key())),
        Err(TlsSetupError::Config {
            step: TlsConfigStep::ClientCertChain,
        }) => Err(TlsConfigError::CertChain(chain.to_path_buf())),
        Err(TlsSetupError::Config {
            step: TlsConfigStep::CheckPrivateKey,
        }) => Err(TlsConfigError::KeyMismatch),
        Err(TlsSetupError::Config {
            step: TlsConfigStep::ClientKey,
        }) => Err(TlsConfigError::PrivateKey(key.to_path_buf())),
        Err(_) => Err(TlsConfigError::Context),
    }
}

/// Reads every file and makes one cache entry.
///
/// The stamps come before the reads. Thus a change during the reads
/// starts one more reload at the next attempt.
fn load(files: &FileSources, legacy: bool, env_allowed: bool) -> Result<Cached, TlsConfigError> {
    let defaults = (legacy || files.system_roots)
        .then(|| DefaultLocations::select(env_allowed, &|name| std::env::var_os(name)));
    let mut watched: Vec<PathBuf> = Vec::new();
    watched.extend(files.ca_file.iter().cloned());
    if let Some((chain, key, _)) = &files.identity {
        watched.push(chain.clone());
        watched.push(key.clone());
    }
    if let Some(d) = &defaults {
        watched.extend(d.watched().cloned());
    }
    let stamps = stamps_of(&watched);
    let config = make_config(files, legacy, defaults.as_ref())?;
    Ok(Cached {
        config,
        watched: watched.into(),
        stamps,
    })
}

/// Makes the configuration from the files.
///
/// The native rule needs a trust source and at least one root. With
/// `add_system_roots` and no root in the default locations it fails
/// with `DefaultRoots`. The legacy rule (`legacy_c_compat`) is the
/// drop-in rule: the CA file must load, the default locations never
/// fail, and `LegacyChainOnly` verifies the chain. The platform verifier
/// uses the OS trust store and reads no trust file.
#[inline(never)]
fn make_config(
    files: &FileSources,
    legacy: bool,
    defaults: Option<&DefaultLocations>,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let provider = default_provider();
    let verifier = if files.platform_verifier {
        platform_verifier(&provider)?
    } else {
        file_verifier(files, legacy, defaults, &provider)?
    };
    let identity = match &files.identity {
        Some((chain, key, pass)) => Some(load_identity(chain, key, pass.as_ref(), &provider)?),
        None => None,
    };
    let versions: &[&'static SupportedProtocolVersion] =
        if files.min_protocol.version == ProtocolVersion::TLSv1_3 {
            &[&rustls::version::TLS13]
        } else {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        };
    finish_config(provider, versions, verifier, identity, legacy)
}

/// Makes the verifier of the trust files.
///
/// The CA file loads before the default locations, as in the drop-in.
/// A CA file with CRLs only gives no root. The native rule then fails
/// on the CA file.
fn file_verifier(
    files: &FileSources,
    legacy: bool,
    defaults: Option<&DefaultLocations>,
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, TlsConfigError> {
    if !legacy && files.ca_file.is_none() && !files.system_roots {
        return Err(TlsConfigError::Context);
    }
    let mut trust = TrustSet::default();
    match &files.ca_file {
        Some(p) => load_ca_file(p, &mut trust)?,
        // The drop-in fails a NULL CA field at the `CaFile` step.
        None if legacy => return Err(TlsConfigError::CaFile(PathBuf::new())),
        None => {}
    }
    let from_file = trust.certs().len();
    if let Some(d) = defaults {
        d.add_to(&mut trust);
    }
    if legacy {
        let algs = provider.signature_verification_algorithms;
        return Ok(Arc::new(LegacyChainOnly::new(trust, algs)));
    }
    let (file_certs, default_certs) = trust
        .certs()
        .split_at_checked(from_file)
        .unwrap_or_default();
    let mut roots = RootCertStore::empty();
    let file_roots = add_roots(file_certs, &mut roots);
    let default_roots = add_roots(default_certs, &mut roots);
    if defaults.is_some() && files.system_roots && default_roots == 0 {
        return Err(TlsConfigError::DefaultRoots);
    }
    if file_roots == 0 && default_roots == 0 {
        return Err(match &files.ca_file {
            Some(p) => TlsConfigError::CaFile(p.clone()),
            None => TlsConfigError::DefaultRoots,
        });
    }
    let roots = Arc::new(roots);
    if files.no_hostname_check {
        Ok(Arc::new(ChainOnlyVerifier::new(
            roots,
            Arc::clone(provider),
        )))
    } else {
        webpki_verifier(roots, Arc::clone(provider)).map_err(|_| TlsConfigError::Context)
    }
}

/// Builds the rustls configuration in its own frame and moves it to the
/// heap.
///
/// The legacy rule sends no SNI and keeps no session state across
/// attempts, as the drop-in does. The native rule keeps the rustls
/// defaults: SNI for DNS names, and resumption.
#[inline(never)]
fn finish_config(
    provider: Arc<CryptoProvider>,
    versions: &[&'static SupportedProtocolVersion],
    verifier: Arc<dyn ServerCertVerifier>,
    identity: Option<Arc<CertifiedKey>>,
    legacy: bool,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|_| TlsConfigError::Context)?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match identity {
        // The legacy rule sends the key only when it can sign an offered
        // scheme, as the drop-in does.
        Some(key) if legacy => builder.with_client_cert_resolver(Arc::new(LegacyClientCert(key))),
        Some(key) => builder.with_client_cert_resolver(Arc::new(FixedIdentity(key))),
        None => builder.with_no_client_auth(),
    };
    if legacy {
        cfg.enable_sni = false;
        cfg.resumption = Resumption::disabled();
    }
    fips_check(&mut cfg)?;
    Ok(Arc::new(cfg))
}

/// The FIPS build requires a FIPS configuration.
#[cfg(feature = "tls-aws-lc-rs-fips")]
fn fips_check(cfg: &mut ClientConfig) -> Result<(), TlsConfigError> {
    cfg.require_ems = true;
    if cfg.fips() {
        Ok(())
    } else {
        Err(TlsConfigError::NotFips)
    }
}

/// The other builds have no FIPS rule.
#[cfg(not(feature = "tls-aws-lc-rs-fips"))]
#[allow(clippy::unnecessary_wraps)]
fn fips_check(_cfg: &mut ClientConfig) -> Result<(), TlsConfigError> {
    Ok(())
}

/// The client identity. It gives the configured identity for every
/// certificate request, and rustls then selects a scheme of the key.
#[derive(Debug)]
struct FixedIdentity(Arc<CertifiedKey>);

impl ResolvesClientCert for FixedIdentity {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The text of a server name, as the driver reads a host token.
fn name_text(name: &ServerName<'static>) -> Option<Vec<u8>> {
    match name {
        ServerName::DnsName(d) => Some(d.as_ref().as_bytes().to_vec()),
        ServerName::IpAddress(ip) => Some(std::net::IpAddr::from(*ip).to_string().into_bytes()),
        _ => None,
    }
}

/// The bytes of a path, for the driver log line.
fn path_bytes(p: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str()).to_vec()
    }
    #[cfg(not(unix))]
    {
        p.to_string_lossy().into_owned().into_bytes()
    }
}

/// Logs the warning of `danger_disable_hostname_verification`.
fn warn_no_hostname_check() {
    #[cfg(feature = "tracing")]
    tracing::warn!(
        target: "apache_zookeeper::session",
        "TLS hostname verification is off; only the certificate chain is checked"
    );
    #[cfg(all(feature = "log", not(feature = "tracing")))]
    log::warn!(
        target: "apache_zookeeper::session",
        "TLS hostname verification is off; only the certificate chain is checked"
    );
}

/// The driver connector of the native options.
///
/// It wraps the zk-driver connector. With `server_name` it gives the
/// driver that name in place of the host token, so the verifier and SNI
/// use the one configured name for every server.
struct NativeConnector {
    /// The zk-driver connector over the options.
    inner: RustlsConnector,
    /// The configured server name, as host-token text.
    name: Option<Vec<u8>>,
    /// The CA file path, for the log line of the `CaFile` step.
    ca: Option<Vec<u8>>,
    /// The chain path, for the log line of the `ClientCertChain` step.
    cert: Option<Vec<u8>>,
    /// The key path, for the log line of the `ClientKey` step.
    key: Option<Vec<u8>>,
}

impl TlsConnector for NativeConnector {
    fn new_conn(
        &self,
        proof: &Unlocked,
        purpose: TlsPurpose,
        peer: &Endpoint,
    ) -> Result<Box<dyn TlsConn>, TlsSetupError> {
        match &self.name {
            Some(name) => {
                let mut named = peer.clone();
                named.host.name.clone_from(name);
                self.inner.new_conn(proof, purpose, &named)
            }
            None => self.inner.new_conn(proof, purpose, peer),
        }
    }

    fn path_for(&self, step: TlsConfigStep) -> Option<&[u8]> {
        match step {
            TlsConfigStep::CaFile => self.ca.as_deref(),
            TlsConfigStep::ClientCertChain => self.cert.as_deref(),
            TlsConfigStep::ClientKey => self.key.as_deref(),
            TlsConfigStep::DefaultVerifyPaths | TlsConfigStep::CheckPrivateKey => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builder_records_its_inputs() {
        let b = TlsOptions::builder()
            .ca_file("/ca.pem")
            .add_system_roots()
            .reload(ReloadPolicy::Never);
        assert_eq!(b.files.ca_file, Some(PathBuf::from("/ca.pem")));
        assert!(b.files.system_roots);
        assert_eq!(b.reload, ReloadPolicy::Never);
    }

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustls::ServerConnection;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use zk_proto::HostToken;

    /// A file of the TLS test fixtures (`zk_testkit::fixtures::tls_dir`).
    fn fixture(name: &str) -> PathBuf {
        zk_testkit::fixtures::tls_dir().join(name)
    }

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(fixture(name)).unwrap()
    }

    /// A temporary file or directory that is removed on drop.
    struct Temp(PathBuf);

    impl Temp {
        fn path() -> PathBuf {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!("zk-client-tls-{}-{n}", std::process::id()))
        }

        fn file(body: &[u8]) -> Self {
            let p = Self::path();
            std::fs::write(&p, body).unwrap();
            Self(p)
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn inner(o: &TlsOptions) -> &TlsInner {
        &o.inner
    }

    fn attempt(o: &TlsOptions) -> Result<Arc<ClientConfig>, TlsSetupError> {
        inner(o).client_config(&Unlocked::new_at_entry(), TlsPurpose::Main)
    }

    fn err_of(r: Result<TlsOptions, TlsConfigError>) -> TlsConfigError {
        r.err().unwrap()
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    // ---- Display, parsing and the environment rule ----

    #[test]
    fn the_cert_string_follows_strtok() {
        assert_eq!(split_cert_string(""), [None; 4]);
        assert_eq!(
            split_cert_string("ca,cert,key,pw"),
            [Some("ca"), Some("cert"), Some("key"), Some("pw")]
        );
        // Empty fields collapse, so the fields shift.
        assert_eq!(
            split_cert_string("ca,,key,pw"),
            [Some("ca"), Some("key"), Some("pw"), None]
        );
        assert_eq!(split_cert_string(",,ca,"), [Some("ca"), None, None, None]);
        // Whitespace stays, and a fifth field does not count.
        assert_eq!(
            split_cert_string(" ca ,b,c,d,e"),
            [Some(" ca "), Some("b"), Some("c"), Some("d")]
        );
    }

    #[test]
    fn a_normal_test_process_allows_the_environment() {
        assert!(env_allowed());
    }

    #[test]
    fn the_environment_replaces_the_defaults_only_when_allowed() {
        let var = |name: &str| match name {
            "SSL_CERT_FILE" => Some(OsString::from("/env/cert.pem")),
            "SSL_CERT_DIR" => Some(OsString::from("/env/a:/env/b")),
            _ => None,
        };
        let allowed = DefaultLocations::select(true, &var);
        assert_eq!(allowed.file, Some(PathBuf::from("/env/cert.pem")));
        #[cfg(unix)]
        assert_eq!(
            allowed.dirs,
            vec![PathBuf::from("/env/a"), PathBuf::from("/env/b")]
        );
        let refused = DefaultLocations::select(false, &var);
        let defaults = DefaultLocations::select(true, &no_env);
        assert_eq!(refused.file, defaults.file);
        assert_eq!(refused.dirs, defaults.dirs);
    }

    #[test]
    fn the_default_locations_use_the_strict_loader() {
        let locs = DefaultLocations {
            file: Some(fixture("ca.pem")),
            dirs: vec![PathBuf::from("/no/such/dir")],
        };
        let mut trust = TrustSet::default();
        assert_eq!(locs.add_to(&mut trust), 1);

        // A bad or missing file adds nothing and does not fail.
        let bad = Temp::file(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n");
        for file in [bad.0.clone(), PathBuf::from("/no/such/file")] {
            let locs = DefaultLocations {
                file: Some(file),
                dirs: Vec::new(),
            };
            let mut trust = TrustSet::default();
            assert_eq!(locs.add_to(&mut trust), 0);
        }
    }

    // ---- build ----

    #[test]
    fn build_reads_a_good_ca_file() {
        let o = TlsOptions::builder()
            .ca_file(fixture("ca.pem"))
            .build()
            .unwrap();
        assert_eq!(o.tls_verify(), TlsVerify::WebPki);
        assert!(o.check().is_ok());
        assert!(attempt(&o).is_ok());
        assert!(o.error_probe()().is_none());
    }

    #[test]
    fn system_roots_with_no_root_fail_with_default_roots() {
        // The selected locations decide. With no root there, build fails
        // with DefaultRoots. With a root, build succeeds.
        let mut trust = TrustSet::default();
        DefaultLocations::select(env_allowed(), &|n| std::env::var_os(n)).add_to(&mut trust);
        let found = add_roots(trust.certs(), &mut RootCertStore::empty());
        let r = TlsOptions::builder().add_system_roots().build();
        if found == 0 {
            assert!(matches!(r, Err(TlsConfigError::DefaultRoots)));
        } else {
            assert!(r.is_ok());
        }
        let files = FileSources {
            system_roots: true,
            ..TlsOptions::builder().files
        };
        let empty = DefaultLocations::default();
        assert!(matches!(
            make_config(&files, false, Some(&empty)),
            Err(TlsConfigError::DefaultRoots)
        ));
        let one = DefaultLocations {
            file: Some(fixture("ca.pem")),
            dirs: Vec::new(),
        };
        assert!(make_config(&files, false, Some(&one)).is_ok());
    }

    #[test]
    fn a_crl_only_ca_file_loads_but_gives_no_root() {
        // A minimal CRL: version 2, an empty issuer and a thisUpdate time.
        // The loader does not check its signature.
        let crl = Temp::file(
            b"-----BEGIN X509 CRL-----\n\
              MDEwIAIBATAKBggqhkjOPQQDAjAAFw0yNTAxMDEwMDAwMDBaMAoGCCqGSM49BAMCAwEA\n\
              -----END X509 CRL-----\n",
        );
        let mut trust = TrustSet::default();
        load_ca_file(&crl.0, &mut trust).unwrap();
        assert!(trust.certs().is_empty());
        assert_eq!(trust.crl_count(), 1);
        // The native rule needs a root, so build fails on the CA file.
        let e = err_of(TlsOptions::builder().ca_file(&crl.0).build());
        assert!(matches!(&e, TlsConfigError::CaFile(p) if *p == crl.0));
        // The legacy rule accepts it, as the drop-in does.
        let files = FileSources {
            ca_file: Some(crl.0.clone()),
            no_hostname_check: true,
            ..TlsOptions::builder().files
        };
        assert!(make_config(&files, true, None).is_ok());
    }

    #[test]
    fn from_rustls_passes_the_check_and_gives_its_config() {
        let cfg = Arc::new(
            ClientConfig::builder_with_provider(default_provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let o = TlsOptions::from_rustls(Arc::clone(&cfg));
        assert!(o.check().is_ok());
        assert_eq!(o.tls_verify(), TlsVerify::WebPki);
        assert!(Arc::ptr_eq(&attempt(&o).unwrap(), &cfg));
    }

    // ---- legacy_c_compat ----

    #[test]
    fn legacy_c_compat_reads_the_fields() {
        let ca = fixture("ca.pem");
        let o = TlsOptions::legacy_c_compat(ca.to_str().unwrap()).unwrap();
        assert_eq!(o.tls_verify(), TlsVerify::LegacyChainOnly);
        let cfg = attempt(&o).unwrap();
        assert!(!cfg.enable_sni);

        // The identity loads with no passphrase.
        let s = format!(
            "{},{},{}",
            ca.display(),
            fixture("client.pem").display(),
            fixture("client.key").display()
        );
        assert!(TlsOptions::legacy_c_compat(&s).is_ok());

        // An unencrypted key ignores the passphrase.
        let s = format!("{s},secret");
        assert!(TlsOptions::legacy_c_compat(&s).is_ok());

        let key = fixture("ca.pem");
        let s = format!(
            "{},{},{}",
            ca.display(),
            fixture("client.pem").display(),
            key.display()
        );
        let e = err_of(TlsOptions::legacy_c_compat(&s));
        assert!(matches!(&e, TlsConfigError::PrivateKey(p) if *p == key));
    }

    #[test]
    fn legacy_c_compat_never_reports_default_roots() {
        let files = FileSources {
            ca_file: Some(fixture("ca.pem")),
            system_roots: true,
            no_hostname_check: true,
            ..TlsOptions::builder().files
        };
        let empty = DefaultLocations::default();
        assert!(make_config(&files, true, Some(&empty)).is_ok());
    }

    // ---- the reload cache ----

    #[test]
    fn on_change_reads_a_changed_file_again() {
        let ca = Temp::file(&read("ca.pem"));
        let o = TlsOptions::builder().ca_file(&ca.0).build().unwrap();
        let first = attempt(&o).unwrap();
        assert!(Arc::ptr_eq(&first, &attempt(&o).unwrap()));

        // Text outside the blocks changes the size, not the roots.
        let mut body = read("ca.pem");
        body.extend_from_slice(b"# rotated\n");
        std::fs::write(&ca.0, &body).unwrap();
        let second = attempt(&o).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(&second, &attempt(&o).unwrap()));
    }

    #[test]
    fn a_failed_reload_fails_the_attempt_and_feeds_the_probe() {
        let ca = Temp::file(&read("ca.pem"));
        let o = TlsOptions::builder().ca_file(&ca.0).build().unwrap();
        let probe = o.error_probe();
        assert!(attempt(&o).is_ok());

        std::fs::write(&ca.0, b"not a certificate").unwrap();
        assert_eq!(
            attempt(&o).err(),
            Some(TlsSetupError::Config {
                step: TlsConfigStep::CaFile
            })
        );
        let e = probe().unwrap();
        assert_eq!(
            e.to_string(),
            format!("failed to load CA file {}", ca.0.display())
        );
        // The next attempt reads the file again and fails again.
        assert!(attempt(&o).is_err());

        std::fs::write(&ca.0, read("ca.pem")).unwrap();
        assert!(attempt(&o).is_ok());
        assert!(probe().is_none());
    }

    #[test]
    fn never_keeps_the_first_configuration() {
        let ca = Temp::file(&read("ca.pem"));
        let o = TlsOptions::builder()
            .ca_file(&ca.0)
            .reload(ReloadPolicy::Never)
            .build()
            .unwrap();
        let first = attempt(&o).unwrap();
        std::fs::write(&ca.0, b"not a certificate").unwrap();
        assert!(Arc::ptr_eq(&first, &attempt(&o).unwrap()));
        assert!(o.error_probe()().is_none());
    }

    #[test]
    fn the_error_steps_follow_the_driver() {
        let p = PathBuf::from("x");
        let cases = [
            (TlsConfigError::CaFile(p.clone()), TlsConfigStep::CaFile),
            (
                TlsConfigError::DefaultRoots,
                TlsConfigStep::DefaultVerifyPaths,
            ),
            (
                TlsConfigError::CertChain(p.clone()),
                TlsConfigStep::ClientCertChain,
            ),
            (TlsConfigError::PrivateKey(p), TlsConfigStep::ClientKey),
            (TlsConfigError::KeyMismatch, TlsConfigStep::CheckPrivateKey),
        ];
        for (e, step) in cases {
            assert_eq!(setup_error(&e), TlsSetupError::Config { step });
        }
        assert_eq!(
            setup_error(&TlsConfigError::Context),
            TlsSetupError::Resource {
                at: TlsResourceAt::ContextNew
            }
        );
    }

    // ---- handshakes through the connector, in memory ----

    fn certs(name: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(&read(name))
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// A rustls server with the `leaf` fixture. With `client_auth` it
    /// requires a client certificate from the test CA.
    fn server(leaf: &str, client_auth: bool) -> ServerConnection {
        let key = PrivateKeyDer::from_pem_slice(&read(&format!("{leaf}.key"))).unwrap();
        let b = rustls::ServerConfig::builder_with_provider(default_provider())
            .with_safe_default_protocol_versions()
            .unwrap();
        let b = if client_auth {
            let mut roots = RootCertStore::empty();
            for c in certs("ca.pem") {
                roots.add(c).unwrap();
            }
            let v =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), default_provider())
                    .build()
                    .unwrap();
            b.with_client_cert_verifier(v)
        } else {
            b.with_no_client_auth()
        };
        let cfg = b
            .with_single_cert(certs(&format!("{leaf}.pem")), key)
            .unwrap();
        ServerConnection::new(Arc::new(cfg)).unwrap()
    }

    fn endpoint(host: &str) -> Endpoint {
        Endpoint {
            addr: SocketAddr::from(([127, 0, 0, 1], 2281)),
            host: HostToken {
                index: 0,
                name: host.as_bytes().to_vec(),
            },
        }
    }

    /// Runs the handshake between the client session and the server.
    fn handshake(o: &TlsOptions, host: &str, server: &mut ServerConnection) -> Result<(), String> {
        let c = o.connector();
        let mut client = c
            .new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &endpoint(host))
            .map_err(|e| format!("{e:?}"))?;
        for _ in 0..16 {
            let mut ct = Vec::new();
            client.take_ciphertext(&mut ct);
            let mut input = &ct[..];
            while !input.is_empty() {
                server.read_tls(&mut input).map_err(|e| e.to_string())?;
                server.process_new_packets().map_err(|e| e.to_string())?;
            }
            let mut back = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut back).map_err(|e| e.to_string())?;
            }
            if !back.is_empty() {
                client.feed(&back).map_err(|e| format!("client {e:?}"))?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Err("no progress".to_owned())
    }

    fn ca_options() -> TlsOptionsBuilder {
        TlsOptions::builder().ca_file(fixture("ca.pem"))
    }

    #[test]
    fn webpki_checks_the_host_token_and_sends_sni() {
        let o = ca_options().build().unwrap();
        let mut s = server("server", false);
        handshake(&o, "localhost", &mut s).unwrap();
        assert_eq!(s.server_name(), Some("localhost"));

        // An IP literal checks the IP SAN and sends no SNI.
        let mut s = server("server", false);
        handshake(&o, "127.0.0.1", &mut s).unwrap();
        assert_eq!(s.server_name(), None);

        // A certificate for another name fails.
        let mut s = server("other-name", false);
        assert!(handshake(&o, "localhost", &mut s).is_err());
    }

    #[test]
    fn webpki_refuses_another_ca_and_an_expired_leaf() {
        let o = ca_options().build().unwrap();
        let mut s = server("wrong-server", false);
        assert!(handshake(&o, "localhost", &mut s).is_err());
        let mut s = server("expired", false);
        assert!(handshake(&o, "localhost", &mut s).is_err());
    }

    #[test]
    fn server_name_replaces_the_host_token() {
        let name = ServerName::try_from("other.invalid").unwrap();
        let o = ca_options().server_name(name).build().unwrap();
        let mut s = server("other-name", false);
        handshake(&o, "localhost", &mut s).unwrap();
        assert_eq!(s.server_name(), Some("other.invalid"));
        let mut s = server("server", false);
        assert!(handshake(&o, "localhost", &mut s).is_err());
    }

    #[test]
    fn no_hostname_check_keeps_the_chain_check() {
        let o = ca_options()
            .danger_disable_hostname_verification()
            .build()
            .unwrap();
        let mut s = server("other-name", false);
        handshake(&o, "localhost", &mut s).unwrap();
        let mut s = server("wrong-server", false);
        assert!(handshake(&o, "localhost", &mut s).is_err());
    }

    #[test]
    fn legacy_c_compat_checks_the_chain_only_with_no_sni() {
        let o = TlsOptions::legacy_c_compat(fixture("ca.pem").to_str().unwrap()).unwrap();
        let mut s = server("other-name", false);
        handshake(&o, "localhost", &mut s).unwrap();
        assert_eq!(s.server_name(), None);
        let mut s = server("wrong-server", false);
        assert!(handshake(&o, "localhost", &mut s).is_err());
    }

    #[test]
    fn the_client_identity_goes_to_the_server() {
        let o = ca_options()
            .client_identity(fixture("client.pem"), fixture("client.key"), None)
            .build()
            .unwrap();
        let mut s = server("server", true);
        handshake(&o, "localhost", &mut s).unwrap();
        assert!(s.peer_certificates().is_some_and(|c| !c.is_empty()));

        let o = ca_options().build().unwrap();
        let mut s = server("server", true);
        assert!(handshake(&o, "localhost", &mut s).is_err());
    }

    #[test]
    fn tls13_only_refuses_a_tls12_server() {
        let o = ca_options()
            .min_protocol(&rustls::version::TLS13)
            .build()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(&read("server.key")).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(default_provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs("server.pem"), key)
            .unwrap();
        let mut s = ServerConnection::new(Arc::new(cfg)).unwrap();
        assert!(handshake(&o, "localhost", &mut s).is_err());
        let mut s = server("server", false);
        handshake(&o, "localhost", &mut s).unwrap();
    }

    #[test]
    fn the_connector_names_the_files_for_the_log() {
        let o = ca_options()
            .client_identity(fixture("client.pem"), fixture("client.key"), None)
            .build()
            .unwrap();
        let c = o.connector();
        assert_eq!(
            c.path_for(TlsConfigStep::CaFile),
            Some(path_bytes(&fixture("ca.pem")).as_slice())
        );
        assert_eq!(
            c.path_for(TlsConfigStep::ClientKey),
            Some(path_bytes(&fixture("client.key")).as_slice())
        );
        assert_eq!(c.path_for(TlsConfigStep::CheckPrivateKey), None);
    }
}
