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

//! `RustlsConnector`: one `ClientConfig` and one `ClientConnection` per
//! attempt and per probe.
//!
//! `new_conn` runs the steps of `init_ssl_for_socket`
//! (zookeeper.c:2847-2935) in the same order and stops at the first
//! failure:
//!
//! | Step | Failure | Legacy line |
//! |---|---|---|
//! | context | `Resource{ContextNew}` | "error creating ssl context" |
//! | `CaFile` | `Config{CaFile}` | "Failed to load CA file %s" |
//! | `DefaultVerifyPaths` | never in Rust | "Call to SSL_CTX_set_default_verify_paths failed" |
//! | `ClientCertChain` (cert and key set) | `Config{ClientCertChain}` | "Failed to load client certificate chain from %s" |
//! | `ClientKey` | `Config{ClientKey}` | "Failed to load client private key from %s" |
//! | `CheckPrivateKey` | `Config{CheckPrivateKey}` | "SSL_CTX_check_private_key failed" |
//! | session | `Resource{ConnectionNew}` | "error creating ssl context" |
//!
//! The steps follow the legacy order. [`TrustSet::load_ca_file`] and
//! [`TrustSet::load_default_paths`] fill one trust set. [`Identity::load`]
//! loads the client identity. The verifier gets the trust set:
//! [`LegacyChainOnly`] for `TlsVerify::LegacyChainOnly`, or the webpki
//! verifier over the anchors that are valid now for `TlsVerify::WebPki`.
//! Every session has SNI off and resumption off, and the FIPS build
//! checks `ClientConfig::fips`.
//!
//! The provider goes to every `ClientConfig`. The process default
//! provider is never installed.

use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ClientConnection};
use zk_proto::SecretBytes;
use zk_proto::compat::TlsVerify;

use crate::net::tls::conn::RustlsConn;
use crate::net::tls::identity::{Identity, LegacyClientCert};
use crate::net::tls::legacy_verify::LegacyChainOnly;
use crate::net::tls::trust::TrustSet;
use crate::net::tls::verify::webpki_verifier;
use crate::net::tls::{
    Endpoint, TlsConfigStep, TlsConn, TlsConnector, TlsPurpose, TlsResourceAt, TlsSetupError,
};
use crate::sync::Unlocked;

/// One cert-string path.
///
/// `raw` is the original bytes, the `path_for` log argument. `open` is
/// the list of paths to try, in order. Unix has one candidate. Windows
/// adds the ANSI code-page conversion from zk-ffi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyPath {
    raw: Vec<u8>,
    open: Vec<PathBuf>,
}

impl LegacyPath {
    /// Makes a path with one candidate: the bytes as an OS path.
    #[cfg(unix)]
    #[must_use]
    pub fn new(raw: Vec<u8>) -> Self {
        use std::os::unix::ffi::OsStrExt;
        let open = vec![PathBuf::from(std::ffi::OsStr::from_bytes(&raw))];
        Self { raw, open }
    }

    /// Makes a path with explicit candidates (the Windows rule).
    #[must_use]
    pub fn with_candidates(raw: Vec<u8>, open: Vec<PathBuf>) -> Self {
        Self { raw, open }
    }

    /// Returns the original bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Returns the candidates to open, in order.
    #[must_use]
    pub fn candidates(&self) -> &[PathBuf] {
        &self.open
    }
}

/// The `zookeeper_init_ssl` fields of a drop-in handle.
///
/// The shim splits the cert string. Each field is nullable, as in C.
#[derive(Debug)]
pub struct LegacyTlsArgs {
    /// The CA file.
    pub ca: Option<LegacyPath>,
    /// The client certificate chain file.
    pub cert: Option<LegacyPath>,
    /// The client key file.
    pub key: Option<LegacyPath>,
    /// The key passphrase. Only the first `min(len, 1024)` bytes count.
    pub passwd: Option<SecretBytes>,
    /// False in set-uid and set-gid processes. Then the loader ignores
    /// `SSL_CERT_FILE` and `SSL_CERT_DIR`.
    pub env_allowed: bool,
    /// The verifier policy (`Compat::tls_verify`).
    pub verify: TlsVerify,
}

/// The native configuration source, built by zk-client from its
/// `TlsOptions`.
///
/// The reload policy of zk-client decides whether a call reads the files
/// again. The call runs with no driver lock held.
pub trait NativeConfig: Send + Sync {
    /// Returns the configuration for one new session.
    ///
    /// # Errors
    ///
    /// Returns the failed step or resource.
    fn client_config(
        &self,
        proof: &Unlocked,
        purpose: TlsPurpose,
    ) -> Result<Arc<rustls::ClientConfig>, TlsSetupError>;
}

/// Where the configuration of each session comes from.
enum ConfigSource {
    /// Drop-in: every `new_conn` reads the files again, as C does.
    Legacy(LegacyTlsArgs),
    /// Native: zk-client builds the configuration.
    Native(Arc<dyn NativeConfig>),
}

/// The rustls connector of both profiles.
pub struct RustlsConnector {
    src: ConfigSource,
    provider: Arc<CryptoProvider>,
    /// The verifier clock. `None` uses the system wall clock. Tests
    /// inject a fixed time.
    time: Option<Arc<dyn TimeProvider>>,
}

impl RustlsConnector {
    /// Makes the drop-in connector. It reads no file.
    #[must_use]
    pub fn legacy(args: LegacyTlsArgs, provider: Arc<CryptoProvider>) -> Self {
        Self {
            src: ConfigSource::Legacy(args),
            provider,
            time: None,
        }
    }

    /// Makes the native connector.
    #[must_use]
    pub fn native(src: Arc<dyn NativeConfig>, provider: Arc<CryptoProvider>) -> Self {
        Self {
            src: ConfigSource::Native(src),
            provider,
            time: None,
        }
    }

    /// Sets the verifier clock. Tests use it.
    #[must_use]
    pub fn with_time_provider(mut self, time: Arc<dyn TimeProvider>) -> Self {
        self.time = Some(time);
        self
    }

    /// Builds the drop-in `ClientConfig` of one attempt (the steps from
    /// context to `CheckPrivateKey`).
    ///
    /// Contract: TLS 1.3 and 1.2, resumption off, `enable_sni = false`,
    /// the verifier of `args.verify`, and the client identity only when
    /// cert and key are both set. In the FIPS build a config whose
    /// `fips()` is false fails as `Resource{ContextNew}`.
    fn legacy_config(&self, args: &LegacyTlsArgs) -> Result<rustls::ClientConfig, TlsSetupError> {
        // Step "context": the SSL_CTX_new analogue.
        let provider = Arc::clone(&self.provider);
        let builder = match &self.time {
            Some(t) => ClientConfig::builder_with_details(Arc::clone(&provider), Arc::clone(t)),
            None => ClientConfig::builder_with_provider(Arc::clone(&provider)),
        };
        let builder = builder
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| resource(TlsResourceAt::ContextNew))?;

        // The file steps, then the first part of step "session": the
        // verifier and the client identity.
        let (verifier, identity) = self.legacy_inputs(args)?;
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let mut cfg = match identity {
            Some(id) => builder.with_client_cert_resolver(Arc::new(LegacyClientCert(Arc::clone(
                id.certified_key(),
            )))),
            None => builder.with_no_client_auth(),
        };
        // Legacy sends no SNI and builds a new context per attempt, so
        // there is no session state across attempts.
        cfg.enable_sni = false;
        cfg.resumption = Resumption::disabled();
        fips_check(&mut cfg)?;
        Ok(cfg)
    }
}

impl RustlsConnector {
    /// Runs the file steps of the drop-in in legacy order, and makes the
    /// verifier of `args.verify`.
    ///
    /// The result is the verifier and the client identity, which is
    /// present when cert and key are set. Passwd is optional. The steps
    /// read every file again on each call.
    #[inline(never)]
    fn legacy_inputs(
        &self,
        args: &LegacyTlsArgs,
    ) -> Result<(Arc<dyn ServerCertVerifier>, Option<Identity>), TlsSetupError> {
        // Step `CaFile`: SSL_CTX_load_verify_locations(ctx, ca, NULL).
        let mut trust = TrustSet::default();
        trust
            .load_ca_file(args.ca.as_ref())
            .map_err(|_| config(TlsConfigStep::CaFile))?;

        // Step `DefaultVerifyPaths`: SSL_CTX_set_default_verify_paths.
        trust
            .load_default_paths(args.env_allowed)
            .map_err(|_| config(TlsConfigStep::DefaultVerifyPaths))?;

        // Steps `ClientCertChain`, `ClientKey` and `CheckPrivateKey`. The
        // legacy client skips the identity when passwd is absent. The
        // drop-in loads it, and an absent passwd is an empty passphrase.
        // Thus an unencrypted key works without passwd, and an encrypted
        // key without passwd fails the `ClientKey` step (spec DV-FIX).
        let identity = match (&args.cert, &args.key) {
            (Some(cert), Some(key)) => {
                let none = SecretBytes::new(Vec::new());
                let passwd = args.passwd.as_ref().unwrap_or(&none);
                Some(Identity::load(cert, key, passwd, &self.provider)?)
            }
            _ => None,
        };

        let verifier: Arc<dyn ServerCertVerifier> = match args.verify {
            TlsVerify::LegacyChainOnly => Arc::new(LegacyChainOnly::new(
                trust,
                self.provider.signature_verification_algorithms,
            )),
            TlsVerify::WebPki => {
                let roots = Arc::new(trust.root_store_at(self.now()));
                webpki_verifier(roots, Arc::clone(&self.provider))?
            }
        };
        Ok((verifier, identity))
    }

    /// Returns the verifier clock: the injected time provider, or else the
    /// system wall clock.
    fn now(&self) -> UnixTime {
        self.time
            .as_ref()
            .and_then(|t| t.current_time())
            .unwrap_or_else(UnixTime::now)
    }

    /// Builds the drop-in configuration in its own frame and moves it to
    /// the heap.
    #[inline(never)]
    fn legacy_shared(&self, args: &LegacyTlsArgs) -> Result<Arc<ClientConfig>, TlsSetupError> {
        self.legacy_config(args).map(Arc::new)
    }
}

/// Makes the session and moves it to the heap. The session goes into the
/// box from its own frame, so the caller frame stays small.
#[inline(never)]
fn new_session(
    cfg: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> Result<Box<dyn TlsConn>, TlsSetupError> {
    match ClientConnection::new(cfg, name).map(boxed_conn) {
        Ok(conn) => Ok(conn),
        Err(_) => Err(resource(TlsResourceAt::ConnectionNew)),
    }
}

/// Wraps the session and moves it to the heap, in its own frame.
#[inline(never)]
fn boxed_conn(conn: ClientConnection) -> Box<dyn TlsConn> {
    Box::new(RustlsConn::new(conn))
}

/// Makes a `Config` setup error.
fn config(step: TlsConfigStep) -> TlsSetupError {
    TlsSetupError::Config { step }
}

/// Makes a `Resource` setup error.
fn resource(at: TlsResourceAt) -> TlsSetupError {
    TlsSetupError::Resource { at }
}

/// The FIPS build requires a FIPS configuration. The other builds keep
/// `require_ems` false, as OpenSSL does not require EMS.
#[cfg(feature = "tls-aws-lc-rs-fips")]
fn fips_check(cfg: &mut ClientConfig) -> Result<(), TlsSetupError> {
    cfg.require_ems = true;
    if cfg.fips() {
        Ok(())
    } else {
        Err(resource(TlsResourceAt::ContextNew))
    }
}

/// The FIPS build requires a FIPS configuration. The other builds keep
/// `require_ems` false, as OpenSSL does not require EMS.
#[cfg(not(feature = "tls-aws-lc-rs-fips"))]
#[allow(clippy::unnecessary_wraps)]
fn fips_check(_cfg: &mut ClientConfig) -> Result<(), TlsSetupError> {
    Ok(())
}

/// Reads the file of a cert-string path. It tries the candidates in
/// order and gives the first file that it can read.
pub(crate) fn read_path(path: &LegacyPath) -> Option<Vec<u8>> {
    path.candidates()
        .iter()
        .find_map(|candidate| std::fs::read(candidate).ok())
}

/// Makes the server name of a native session from the host token.
///
/// An IP literal gives an IP name, and rustls then sends no SNI. A DNS
/// name gives a DNS name, with SNI and the name check of the `WebPki`
/// verifier. IPv6 brackets are removed. A token that is not a valid name
/// fails as `Resource{ConnectionNew}`.
fn native_name(peer: &Endpoint) -> Result<ServerName<'static>, TlsSetupError> {
    let err = resource(TlsResourceAt::ConnectionNew);
    let host = std::str::from_utf8(&peer.host.name).map_err(|_| err)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    ServerName::try_from(host.to_owned()).map_err(|_| err)
}

impl TlsConnector for RustlsConnector {
    /// Contract:
    /// - Drop-in: `legacy_config`, then `ClientConnection::new(cfg,
    ///   ServerName::IpAddress(peer ip))`. No SNI and no name check.
    /// - Native: `client_config`, then the server name from
    ///   `peer.host` (`WebPki`). SNI goes out for DNS names.
    /// - A `ClientConnection::new` failure is `Resource{ConnectionNew}`.
    /// - The result is a boxed [`crate::net::tls::RustlsConn`].
    fn new_conn(
        &self,
        proof: &Unlocked,
        purpose: TlsPurpose,
        peer: &Endpoint,
    ) -> Result<Box<dyn TlsConn>, TlsSetupError> {
        // Two separate frames build the configuration and the session.
        // So no frame holds the large rustls values of both.
        let (cfg, name) = match &self.src {
            // The peer IP is a placeholder name. The verifier never
            // checks it, and no SNI goes out.
            ConfigSource::Legacy(args) => (
                self.legacy_shared(args)?,
                ServerName::IpAddress(peer.addr.ip().into()),
            ),
            ConfigSource::Native(src) => (src.client_config(proof, purpose)?, native_name(peer)?),
        };
        new_session(cfg, name)
    }

    fn path_for(&self, step: TlsConfigStep) -> Option<&[u8]> {
        match &self.src {
            ConfigSource::Legacy(args) => match step {
                TlsConfigStep::CaFile => args.ca.as_ref().map(LegacyPath::raw),
                TlsConfigStep::ClientCertChain => args.cert.as_ref().map(LegacyPath::raw),
                TlsConfigStep::ClientKey => args.key.as_ref().map(LegacyPath::raw),
                TlsConfigStep::DefaultVerifyPaths | TlsConfigStep::CheckPrivateKey => None,
            },
            ConfigSource::Native(_) => None,
        }
    }
}

/// Returns the crypto provider of the selected provider feature.
///
/// `tls-ring` gives the ring provider. `tls-aws-lc-rs` gives the
/// aws-lc-rs provider. `tls-aws-lc-rs-fips` gives the FIPS provider.
/// zk-ffi and zk-client build it once per handle.
#[must_use]
pub fn default_provider() -> Arc<CryptoProvider> {
    #[cfg(feature = "tls-ring")]
    let provider = rustls::crypto::ring::default_provider();
    #[cfg(feature = "tls-aws-lc-rs")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "tls-aws-lc-rs-fips")]
    let provider = rustls::crypto::default_fips_provider();
    Arc::new(provider)
}

// The tests build paths from Unix bytes.
#[cfg(all(test, unix))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::large_stack_frames
)]
mod tests {
    use std::net::SocketAddr;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustls::SignatureScheme;
    use zk_proto::{Endpoint, HostToken};

    use super::*;
    use crate::net::tls::conn::testing::{self, fixture};

    /// A PKCS#8 Ed25519 key. The client leaf has a P-256 key.
    const ED25519_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIFZsce3s/dPi6fmIVU4czLVxub7EWvhZWLqePPyi6WQ/\n\
        -----END PRIVATE KEY-----\n";

    /// A temporary file that is removed on drop.
    struct Temp(PathBuf);

    impl Temp {
        fn new(body: &[u8]) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("zk-driver-tls-{}-{n}.pem", std::process::id()));
            std::fs::write(&p, body).unwrap();
            Self(p)
        }

        fn path(&self) -> LegacyPath {
            LegacyPath::new(self.0.as_os_str().as_bytes().to_vec())
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn path(name: &str) -> LegacyPath {
        LegacyPath::new(fixture(name).as_os_str().as_bytes().to_vec())
    }

    fn args(ca: Option<LegacyPath>) -> LegacyTlsArgs {
        LegacyTlsArgs {
            ca,
            cert: None,
            key: None,
            passwd: None,
            env_allowed: false,
            verify: TlsVerify::LegacyChainOnly,
        }
    }

    fn identity_args(cert: LegacyPath, key: LegacyPath) -> LegacyTlsArgs {
        LegacyTlsArgs {
            cert: Some(cert),
            key: Some(key),
            passwd: Some(SecretBytes::empty()),
            ..args(Some(path("ca.pem")))
        }
    }

    fn legacy_cfg(args: LegacyTlsArgs) -> Result<ClientConfig, TlsSetupError> {
        RustlsConnector::legacy(args, default_provider()).legacy_config_for_test()
    }

    fn endpoint(name: &[u8]) -> Endpoint {
        Endpoint {
            addr: SocketAddr::from(([127, 0, 0, 1], 2281)),
            host: HostToken {
                index: 0,
                name: name.to_vec(),
            },
        }
    }

    fn new_conn(c: &RustlsConnector, name: &[u8]) -> Result<Box<dyn TlsConn>, TlsSetupError> {
        c.new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &endpoint(name))
    }

    const CA_FILE: TlsSetupError = TlsSetupError::Config {
        step: TlsConfigStep::CaFile,
    };
    const CHAIN: TlsSetupError = TlsSetupError::Config {
        step: TlsConfigStep::ClientCertChain,
    };
    const KEY: TlsSetupError = TlsSetupError::Config {
        step: TlsConfigStep::ClientKey,
    };
    const CHECK: TlsSetupError = TlsSetupError::Config {
        step: TlsConfigStep::CheckPrivateKey,
    };

    impl RustlsConnector {
        fn legacy_config_for_test(&self) -> Result<ClientConfig, TlsSetupError> {
            match &self.src {
                ConfigSource::Legacy(args) => self.legacy_config(args),
                ConfigSource::Native(_) => panic!("not a legacy connector"),
            }
        }
    }

    #[test]
    fn legacy_config_has_the_drop_in_settings() {
        let cfg = legacy_cfg(args(Some(path("ca.pem")))).unwrap();
        assert!(!cfg.enable_sni);
        assert!(!cfg.enable_early_data);
        assert!(cfg.alpn_protocols.is_empty());
        assert!(!cfg.client_auth_cert_resolver.has_certs());
        assert!(
            !cfg.crypto_provider()
                .signature_verification_algorithms
                .all
                .is_empty()
        );
    }

    #[test]
    fn missing_ca_file_is_a_config_error() {
        assert_eq!(legacy_cfg(args(None)).err(), Some(CA_FILE));
        let missing = path("no-such-file.pem");
        assert_eq!(legacy_cfg(args(Some(missing))).err(), Some(CA_FILE));
        // No candidate at all.
        let none = LegacyPath::with_candidates(b"x".to_vec(), Vec::new());
        assert_eq!(legacy_cfg(args(Some(none))).err(), Some(CA_FILE));
        // The setup error comes out of new_conn too.
        let c = RustlsConnector::legacy(args(None), default_provider());
        assert_eq!(new_conn(&c, b"127.0.0.1").err(), Some(CA_FILE));
    }

    #[test]
    fn ca_file_without_certificates_is_a_config_error() {
        for body in [
            &b"not a pem file\n"[..],
            b"",
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nMIIB\n",
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            let t = Temp::new(body);
            assert_eq!(legacy_cfg(args(Some(t.path()))).err(), Some(CA_FILE));
        }
        // A key block is not a trust anchor.
        assert_eq!(legacy_cfg(args(Some(path("ca.key")))).err(), Some(CA_FILE));
    }

    #[test]
    fn ca_file_with_only_a_crl_loads() {
        legacy_cfg(args(Some(path("crl.pem")))).unwrap();
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "the client key load reaches the native code of ring, which Miri cannot run"
    )]
    fn identity_loads_with_cert_and_key() {
        let cfg = legacy_cfg(identity_args(path("client.pem"), path("client.key"))).unwrap();
        assert!(cfg.client_auth_cert_resolver.has_certs());
        let chain = cfg
            .client_auth_cert_resolver
            .resolve(&[], &[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();
        assert_eq!(chain.cert, testing::certs("client.pem"));

        // An absent passwd is an empty passphrase. Legacy drops the
        // identity instead, so this is a deliberate fix.
        let cfg = legacy_cfg(LegacyTlsArgs {
            passwd: None,
            ..identity_args(path("client.pem"), path("client.key"))
        })
        .unwrap();
        assert!(cfg.client_auth_cert_resolver.has_certs());
        let no_files = LegacyTlsArgs {
            passwd: None,
            ..identity_args(path("no-such-cert.pem"), path("no-such-key.pem"))
        };
        assert_eq!(legacy_cfg(no_files).err(), Some(CHAIN));

        for args in [
            LegacyTlsArgs {
                cert: None,
                ..identity_args(path("client.pem"), path("client.key"))
            },
            LegacyTlsArgs {
                key: None,
                ..identity_args(path("client.pem"), path("client.key"))
            },
        ] {
            // Without both cert and key, the files are not read at all.
            let cfg = legacy_cfg(LegacyTlsArgs {
                cert: args.cert.map(|_| path("no-such-cert.pem")),
                key: args.key.map(|_| path("no-such-key.pem")),
                ..args
            })
            .unwrap();
            assert!(!cfg.client_auth_cert_resolver.has_certs());
        }
    }

    #[test]
    fn bad_client_chain_is_a_chain_error() {
        let junk = Temp::new(b"junk");
        let bad = Temp::new(b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n");
        for cert in [
            path("no-such-cert.pem"),
            junk.path(),
            bad.path(),
            path("client.key"),
        ] {
            assert_eq!(
                legacy_cfg(identity_args(cert, path("client.key"))).err(),
                Some(CHAIN)
            );
        }
        // The CA step runs first.
        let a = LegacyTlsArgs {
            ca: None,
            ..identity_args(path("no-such-cert.pem"), path("client.key"))
        };
        assert_eq!(legacy_cfg(a).err(), Some(CA_FILE));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "the client key load reaches the native code of ring, which Miri cannot run"
    )]
    fn bad_client_key_is_a_key_error() {
        let junk = Temp::new(b"junk");
        let bad = Temp::new(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        for key in [
            path("no-such-key.pem"),
            junk.path(),
            bad.path(),
            path("client.pem"),
        ] {
            assert_eq!(
                legacy_cfg(identity_args(path("client.pem"), key)).err(),
                Some(KEY)
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "the client key load reaches the native code of ring, which Miri cannot run"
    )]
    fn key_of_another_leaf_is_a_key_error() {
        // The same key type as the leaf: OpenSSL fails the key load.
        assert_eq!(
            legacy_cfg(identity_args(path("client.pem"), path("server.key"))).err(),
            Some(KEY)
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "the client key load reaches the native code of ring, which Miri cannot run"
    )]
    fn key_of_another_type_is_a_check_error() {
        // Another key type: OpenSSL fails at SSL_CTX_check_private_key.
        let ed = Temp::new(ED25519_KEY.as_bytes());
        assert_eq!(
            legacy_cfg(identity_args(path("client.pem"), ed.path())).err(),
            Some(CHECK)
        );
    }

    /// A clock far after the end of every real certificate.
    #[derive(Debug)]
    struct FarFuture;

    impl TimeProvider for FarFuture {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                1 << 40,
            )))
        }
    }

    #[test]
    fn legacy_webpki_without_roots_is_a_context_failure() {
        // The build default paths can hold system roots. At this time no
        // root is valid, so the root store is empty on every host.
        let a = LegacyTlsArgs {
            verify: TlsVerify::WebPki,
            ..args(Some(path("crl.pem")))
        };
        let c =
            RustlsConnector::legacy(a, default_provider()).with_time_provider(Arc::new(FarFuture));
        assert_eq!(
            c.legacy_config_for_test().err(),
            Some(TlsSetupError::Resource {
                at: TlsResourceAt::ContextNew
            })
        );
    }
}
