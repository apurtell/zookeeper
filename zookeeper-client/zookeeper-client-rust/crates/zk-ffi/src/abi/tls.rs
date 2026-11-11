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

//! The drop-in TLS configuration.
//!
//! `zookeeper_init_ssl` splits the cert string in C and passes the four
//! fields in `zkrs_init_args`. This module copies them during
//! `zkrs_handle_new`. The paths are owned bytes, and the passphrase goes
//! straight into zeroizing storage with `raw::cstr_secret`. The module
//! then makes the legacy `RustlsConnector` with the provider of the
//! build. The connector reads the files again on each attempt, as legacy
//! C does, so init itself reads no file.
//!
//! `zkrs_handle_new` calls `setup` for each handle with `a->tls == 1`.
//! A NULL field stays NULL. Thus each attempt fails at the same step as
//! legacy, and the log line prints the same argument. A bad file never
//! fails the init. It fails each attempt.

use std::ffi::c_int;
use std::sync::Arc;

use zk_driver::net::tls::{
    LegacyPath, LegacyTlsArgs, RustlsConnector, TlsConnector, default_provider,
};
use zk_proto::compat::TlsVerify;
use zk_proto::{Config, SecretBytes};

use super::raw;
use super::types::zkrs_init_args;

/// Sets up the TLS of a `zookeeper_init_ssl` handle.
///
/// The function sets `cfg.tls` and returns the connector of `Env::tls`.
/// An error is the init errno, and init then returns NULL. The function
/// reads no file, because the connector reads the files on each attempt.
/// No current build has a setup error. The FIPS build aborts when its
/// provider is not in FIPS mode, because that is a build defect.
pub(crate) fn setup(
    a: &zkrs_init_args,
    cfg: &mut Config,
    verify: TlsVerify,
) -> Result<Arc<dyn TlsConnector>, c_int> {
    let c = connector(a, verify);
    cfg.tls = true;
    Ok(c)
}

/// Copies the TLS fields of `a`.
///
/// Each NULL field is `None`. `tls_env_allowed` decides whether the
/// default paths may read `SSL_CERT_FILE` and `SSL_CERT_DIR`. The
/// passphrase never leaves zeroizing storage.
pub(crate) fn legacy_args(a: &zkrs_init_args, verify: TlsVerify) -> LegacyTlsArgs {
    LegacyTlsArgs {
        ca: raw::cstr_opt(a.tls_ca).map(legacy_path),
        cert: raw::cstr_opt(a.tls_cert).map(legacy_path),
        key: raw::cstr_opt(a.tls_key).map(legacy_path),
        // The vector moves out of the zeroizing wrapper, so no second
        // copy of the passphrase exists. The wrapper keeps an empty vector.
        passwd: raw::cstr_secret(a.tls_passwd)
            .map(|mut p| SecretBytes::new(std::mem::take(&mut *p))),
        env_allowed: a.tls_env_allowed != 0,
        verify,
    }
}

/// Makes the connector of a `zookeeper_init_ssl` handle.
///
/// The provider is `zk_driver::net::tls::default_provider`, so the
/// provider feature of the build decides it. The handle builds the
/// provider once, and each attempt reads only the files again.
pub(crate) fn connector(a: &zkrs_init_args, verify: TlsVerify) -> Arc<dyn TlsConnector> {
    let provider = default_provider();
    // A provider that is not in FIPS mode is a build defect.
    #[cfg(feature = "tls-aws-lc-rs-fips")]
    if !provider.fips() {
        super::entry::abort_with("zk-ffi: the TLS provider is not in FIPS mode");
    }
    Arc::new(RustlsConnector::legacy(legacy_args(a, verify), provider))
}

/// Marks a zk-ffi build with TLS. It always returns 1.
///
/// Only a build with the `tls` feature defines this symbol. A shim built
/// with `ZKS_WITH_TLS` calls it. Thus a TLS shim and a plain core give an
/// undefined reference, and the prelink check fails. The build checks of
/// a prebuilt staticlib look for the symbol with `nm`.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_feature_tls() -> u32 {
    1
}

/// Makes the path of one cert-string field. Unix opens the bytes as they
/// are.
#[cfg(unix)]
fn legacy_path(raw: Vec<u8>) -> LegacyPath {
    LegacyPath::new(raw)
}

/// Makes the path of one cert-string field. A field that is not UTF-8
/// has no candidate, so its step fails with the legacy line. The ANSI
/// code-page candidate is part of the Windows work.
#[cfg(not(unix))]
fn legacy_path(raw: Vec<u8>) -> LegacyPath {
    let open = std::str::from_utf8(&raw)
        .map(std::path::PathBuf::from)
        .into_iter()
        .collect();
    LegacyPath::with_candidates(raw, open)
}

// The tests build the arguments from Unix bytes.
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::ffi::CString;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use zk_driver::Unlocked;
    use zk_driver::net::tls::{TlsConfigStep, TlsPurpose, TlsSetupError};
    use zk_proto::{Compat, Endpoint, HostToken};

    use super::*;
    use crate::abi::handle::test_support::init_args;

    /// The C strings of one cert string. `None` is a NULL field.
    struct Fields {
        ca: Option<CString>,
        cert: Option<CString>,
        key: Option<CString>,
        passwd: Option<CString>,
    }

    fn c(s: Option<&str>) -> Option<CString> {
        s.map(|s| CString::new(s).unwrap())
    }

    fn fields(ca: Option<&str>, cert: Option<&str>, key: Option<&str>, pw: Option<&str>) -> Fields {
        Fields {
            ca: c(ca),
            cert: c(cert),
            key: c(key),
            passwd: c(pw),
        }
    }

    fn ptr(s: &Option<CString>) -> *const std::ffi::c_char {
        s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr())
    }

    /// The init arguments of a TLS handle. The pointers borrow `f`.
    fn args(f: &Fields, env_allowed: u32) -> zkrs_init_args {
        zkrs_init_args {
            tls: 1,
            tls_ca: ptr(&f.ca),
            tls_cert: ptr(&f.cert),
            tls_key: ptr(&f.key),
            tls_passwd: ptr(&f.passwd),
            tls_env_allowed: env_allowed,
            ..init_args(c"127.0.0.1:2181")
        }
    }

    /// A file of the TLS test fixtures (`zk_testkit::fixtures::tls_dir`).
    fn fixture(name: &str) -> String {
        zk_testkit::fixtures::tls_dir()
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn new_conn(c: &dyn TlsConnector) -> Result<(), TlsSetupError> {
        let peer = Endpoint {
            addr: SocketAddr::from(([127, 0, 0, 1], 2281)),
            host: HostToken {
                index: 0,
                name: b"127.0.0.1".to_vec(),
            },
        };
        c.new_conn(&Unlocked::new_at_entry(), TlsPurpose::Main, &peer)
            .map(drop)
    }

    #[test]
    fn null_fields_are_none() {
        let f = fields(None, None, None, None);
        let la = legacy_args(&args(&f, 0), TlsVerify::LegacyChainOnly);
        assert!(la.ca.is_none() && la.cert.is_none() && la.key.is_none());
        assert!(la.passwd.is_none());
        assert!(!la.env_allowed);
        assert_eq!(la.verify, TlsVerify::LegacyChainOnly);
    }

    #[test]
    fn fields_are_copied_as_bytes() {
        let f = fields(
            Some(" ca.pem"),
            Some("c.pem"),
            Some("k.pem"),
            Some("pass word"),
        );
        let la = legacy_args(&args(&f, 1), TlsVerify::WebPki);
        drop(f);
        let ca = la.ca.as_ref().unwrap();
        assert_eq!(ca.raw(), b" ca.pem");
        assert_eq!(ca.candidates(), [PathBuf::from(" ca.pem")]);
        assert_eq!(la.cert.as_ref().unwrap().raw(), b"c.pem");
        assert_eq!(la.key.as_ref().unwrap().raw(), b"k.pem");
        assert_eq!(la.passwd.as_ref().unwrap().expose(), b"pass word");
        assert!(la.env_allowed);
        assert_eq!(la.verify, TlsVerify::WebPki);
    }

    #[test]
    fn a_long_passphrase_is_copied_whole() {
        // The connector applies the 1024-byte limit of PEM_def_callback.
        let long = "p".repeat(1500);
        let f = fields(None, None, None, Some(&long));
        let la = legacy_args(&args(&f, 0), TlsVerify::LegacyChainOnly);
        assert_eq!(la.passwd.unwrap().len(), 1500);
    }

    #[test]
    fn setup_sets_tls_and_reads_no_file() {
        let f = fields(Some("/nonexistent/zkrs/ca.pem"), None, None, None);
        let mut cfg = Config::legacy(30_000);
        assert!(!cfg.tls);
        let c = setup(&args(&f, 0), &mut cfg, Compat::LEGACY_C.tls_verify).unwrap();
        assert!(cfg.tls);
        assert_eq!(
            c.path_for(TlsConfigStep::CaFile),
            Some(&b"/nonexistent/zkrs/ca.pem"[..])
        );
    }

    #[test]
    fn path_for_names_the_field_of_each_step() {
        let f = fields(Some("a"), Some("b"), Some("c"), Some("d"));
        let conn = connector(&args(&f, 0), TlsVerify::LegacyChainOnly);
        assert_eq!(conn.path_for(TlsConfigStep::CaFile), Some(&b"a"[..]));
        assert_eq!(
            conn.path_for(TlsConfigStep::ClientCertChain),
            Some(&b"b"[..])
        );
        assert_eq!(conn.path_for(TlsConfigStep::ClientKey), Some(&b"c"[..]));
        assert_eq!(conn.path_for(TlsConfigStep::DefaultVerifyPaths), None);
        assert_eq!(conn.path_for(TlsConfigStep::CheckPrivateKey), None);
        let none = fields(None, None, None, None);
        let conn = connector(&args(&none, 0), TlsVerify::LegacyChainOnly);
        assert_eq!(conn.path_for(TlsConfigStep::CaFile), None);
    }

    #[test]
    fn a_null_or_missing_ca_fails_the_ca_step() {
        let ca_step = Err(TlsSetupError::Config {
            step: TlsConfigStep::CaFile,
        });
        for ca in [None, Some("/nonexistent/zkrs/ca.pem")] {
            let f = fields(ca, None, None, None);
            let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
            assert_eq!(new_conn(&*conn), ca_step);
        }
    }

    #[test]
    fn the_identity_needs_cert_and_key() {
        let ca = fixture("ca.pem");
        let key = fixture("client.key");
        // All three fields: the missing chain file fails its step.
        let f = fields(
            Some(&ca),
            Some("/nonexistent/zkrs/c.pem"),
            Some(&key),
            Some("pw"),
        );
        let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
        assert_eq!(
            new_conn(&*conn),
            Err(TlsSetupError::Config {
                step: TlsConfigStep::ClientCertChain
            })
        );
        // No passwd: the identity still loads with an empty passphrase,
        // so the missing chain file fails its step.
        let f = fields(Some(&ca), Some("/nonexistent/zkrs/c.pem"), Some(&key), None);
        let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
        assert_eq!(
            new_conn(&*conn),
            Err(TlsSetupError::Config {
                step: TlsConfigStep::ClientCertChain
            })
        );
        // No key: no identity loads, so the session starts.
        let f = fields(Some(&ca), Some("/nonexistent/zkrs/c.pem"), None, Some("pw"));
        let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
        assert_eq!(new_conn(&*conn), Ok(()));
    }

    #[test]
    fn a_valid_identity_makes_a_session() {
        let f = fields(
            Some(&fixture("ca.pem")),
            Some(&fixture("client.pem")),
            Some(&fixture("client.key")),
            Some("pw"),
        );
        let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
        assert_eq!(new_conn(&*conn), Ok(()));
    }

    #[test]
    fn a_missing_key_fails_the_key_step() {
        let f = fields(
            Some(&fixture("ca.pem")),
            Some(&fixture("client.pem")),
            Some("/nonexistent/zkrs/k.pem"),
            Some("pw"),
        );
        let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
        assert_eq!(
            new_conn(&*conn),
            Err(TlsSetupError::Config {
                step: TlsConfigStep::ClientKey
            })
        );
    }

    #[test]
    fn a_key_in_the_slot_of_the_leaf_fails_the_key_step() {
        // OpenSSL keeps one key per type. A key of the same type
        // as the leaf replaces it, and the key step fails.
        let f = fields(
            Some(&fixture("ca.pem")),
            Some(&fixture("client.pem")),
            Some(&fixture("server.key")),
            Some("pw"),
        );
        let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
        assert_eq!(
            new_conn(&*conn),
            Err(TlsSetupError::Config {
                step: TlsConfigStep::ClientKey
            })
        );
    }

    #[test]
    fn a_key_in_another_slot_fails_the_check_step() {
        // An Ed25519 key from a fixed seed. The leaf has an EC key, so the
        // key goes in another slot and the check step fails.
        let pem = "-----BEGIN PRIVATE KEY-----\n\
                   MC4CAQAwBQYDK2VwBCIEIEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9g\n\
                   -----END PRIVATE KEY-----\n";
        let dir = std::env::temp_dir().join(format!("zkrs-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("ed25519.key");
        std::fs::write(&key, pem).unwrap();
        let f = fields(
            Some(&fixture("ca.pem")),
            Some(&fixture("client.pem")),
            Some(key.to_str().unwrap()),
            Some("pw"),
        );
        let conn = connector(&args(&f, 0), Compat::LEGACY_C.tls_verify);
        let got = new_conn(&*conn);
        drop(std::fs::remove_dir_all(&dir));
        assert_eq!(
            got,
            Err(TlsSetupError::Config {
                step: TlsConfigStep::CheckPrivateKey
            })
        );
    }
}
