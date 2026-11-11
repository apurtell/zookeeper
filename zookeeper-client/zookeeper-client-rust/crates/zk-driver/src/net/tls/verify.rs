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

//! The webpki-based verifiers.
//!
//! - `WebPki` (`NATIVE`) is the rustls webpki verifier with a name check
//!   against the host token.
//! - `ChainOnlyVerifier` checks that the leaf chains to a configured
//!   root at `now`. It does not check the name. The native client uses
//!   it when the application turns off the name check.
//!
//! The drop-in uses
//! [`LegacyChainOnly`](crate::net::tls::legacy_verify::LegacyChainOnly)
//! for `LEGACY_C`. That verifier applies the OpenSSL trust decision.
//!
//! Handshake signatures are checked with the provider's
//! `signature_verification_algorithms`.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_cert_signed_by_trust_anchor};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::net::tls::{TlsResourceAt, TlsSetupError};

/// A webpki chain check to a configured root, with no name check.
#[derive(Debug)]
pub struct ChainOnlyVerifier {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
}

impl ChainOnlyVerifier {
    /// Makes the verifier.
    #[must_use]
    pub fn new(roots: Arc<RootCertStore>, provider: Arc<CryptoProvider>) -> Self {
        Self { roots, provider }
    }
}

impl ServerCertVerifier for ChainOnlyVerifier {
    /// Contract: `verify_server_cert_signed_by_trust_anchor` over the
    /// leaf and the intermediates at `now`. The server name and the OCSP
    /// response are ignored.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The server name is the peer IP placeholder and is never
        // checked. rustls has no OCSP policy here, as legacy has none.
        let leaf = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &leaf,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Makes the `WebPki` verifier over the roots.
///
/// # Errors
///
/// Returns `Resource{ContextNew}` when rustls cannot build the verifier
/// (for example, no roots).
pub fn webpki_verifier(
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, TlsSetupError> {
    match WebPkiServerVerifier::builder_with_provider(roots, provider).build() {
        Ok(v) => Ok(v),
        Err(_) => Err(TlsSetupError::Resource {
            at: TlsResourceAt::ContextNew,
        }),
    }
}
