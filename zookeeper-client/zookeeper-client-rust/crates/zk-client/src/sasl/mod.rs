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

//! Native SASL.
//!
//! The public types are the mechanism contract of the native client. The
//! built-in mechanisms are DIGEST-MD5 in safe Rust (`sasl`) and GSSAPI
//! through `libgssapi` (`sasl-gssapi`). An application can also give its
//! own mechanism through [`SaslConfig::Custom`]. Cyrus SASL is never
//! linked into a native build.
//!
//! zk-proto owns the rules of ZooKeeper SASL: the op 102 framing, the
//! send gate, the deferred `CONNECTED`, the empty initial response of
//! DIGEST-MD5 and the final GSSAPI packet. This module only makes the
//! mechanism tokens. The private adapter connects a [`SaslMechanism`]
//! to `zk_proto::SaslSession`.
//!
//! Every SASL failure is terminal. The session goes to `AuthFailed`, and
//! the client does not try SASL again on the next server.
//! `SessionInfo::last_error` then carries the [`SaslError`] of the
//! mechanism, or a [`SaslErrorKind::ServerRejected`] error when the
//! server refused the client.

mod adapter;
mod digest_md5;
#[cfg(feature = "sasl-gssapi")]
mod gssapi;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::secret::SecretString;

// The adapter is private. `ClientBuilder::start` gives it to the driver.
pub(crate) use adapter::{LastSaslError, NativeSasl};

/// The SASL configuration of a client.
#[non_exhaustive]
pub enum SaslConfig {
    /// Safe-Rust DIGEST-MD5 with `qop=auth`.
    ///
    /// The usual service is `zookeeper`, and the usual server name is
    /// `zk-sasl-md5`, as in the Java server.
    DigestMd5 {
        /// The authentication identity.
        username: String,
        /// The source of the password. The client reads it on each
        /// authentication, so a new password applies at the next
        /// connection.
        password: Arc<dyn CredentialSource>,
        /// The service of the `digest-uri`.
        service: String,
        /// The host of the `digest-uri`.
        server_name: String,
    },
    /// GSSAPI (Kerberos) through `libgssapi`.
    ///
    /// The credentials come from the GSSAPI default, a credential cache or
    /// a keytab.
    #[cfg(feature = "sasl-gssapi")]
    Gssapi {
        /// The service of the server principal.
        service: String,
        /// The host of the server principal. `None` means the host of the
        /// connect string for the current server.
        server_name: Option<String>,
    },
    /// A mechanism of the application.
    Custom(Arc<dyn SaslMechanismFactory>),
}

impl SaslConfig {
    /// Makes a DIGEST-MD5 configuration with the service `zookeeper` and
    /// the server name `zk-sasl-md5`.
    #[must_use]
    pub fn digest_md5(username: impl Into<String>, password: Arc<dyn CredentialSource>) -> Self {
        Self::DigestMd5 {
            username: username.into(),
            password,
            service: DEFAULT_SERVICE.to_owned(),
            server_name: DEFAULT_DIGEST_SERVER.to_owned(),
        }
    }
}

/// The service of the server principal or `digest-uri`.
pub(crate) const DEFAULT_SERVICE: &str = "zookeeper";

/// The DIGEST-MD5 server name of the Java server.
pub(crate) const DEFAULT_DIGEST_SERVER: &str = "zk-sasl-md5";

impl std::fmt::Debug for SaslConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DigestMd5 {
                username,
                service,
                server_name,
                ..
            } => f
                .debug_struct("DigestMd5")
                .field("username", username)
                .field("password", &"<redacted>")
                .field("service", service)
                .field("server_name", server_name)
                .finish(),
            #[cfg(feature = "sasl-gssapi")]
            Self::Gssapi {
                service,
                server_name,
            } => f
                .debug_struct("Gssapi")
                .field("service", service)
                .field("server_name", server_name)
                .finish(),
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

/// The source of a password.
///
/// The client calls it on each authentication, so a rotated password
/// applies at the next connection. The call runs with no client lock
/// held, on the IO thread or through `spawn_blocking`. A panic counts as
/// a mechanism error.
pub trait CredentialSource: Send + Sync + 'static {
    /// Returns the current password.
    ///
    /// # Errors
    ///
    /// Returns the kind of the failure. Both kinds end the session.
    fn password(&self) -> Result<SecretString, CredentialError>;
}

/// The kind of a credential failure.
///
/// The client does not retry either kind. The kind tells the application
/// if a new client can succeed.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CredentialError {
    /// The failure can go away, for example an unreadable file or an
    /// unreachable KDC.
    Transient,
    /// The failure stays.
    Permanent,
}

/// Makes a mechanism for one connection.
pub trait SaslMechanismFactory: Send + Sync + 'static {
    /// Makes a new mechanism. The client calls it once per connection, so
    /// no state carries over from an earlier attempt.
    ///
    /// # Errors
    ///
    /// Returns the error that ends the session.
    fn create(&self, ctx: &SaslContext) -> Result<Box<dyn SaslMechanism>, SaslError>;
}

/// One mechanism session.
pub trait SaslMechanism: Send {
    /// Returns the mechanism name, for example `DIGEST-MD5`.
    fn name(&self) -> &str;

    /// Returns the initial response.
    ///
    /// # Errors
    ///
    /// Returns the error that ends the session.
    fn start(&mut self) -> Result<SaslStep, SaslError>;

    /// Answers one server challenge. `None` means that the server sent a
    /// token of length -1.
    ///
    /// # Errors
    ///
    /// Returns the error that ends the session.
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<SaslStep, SaslError>;
}

/// One result of a mechanism. It has the shape of `zk_proto::SaslStep`.
#[derive(Clone, PartialEq, Eq)]
pub struct SaslStep {
    /// The token to send, or `None`.
    pub token: Option<Vec<u8>>,
    /// True when the mechanism is complete.
    pub done: bool,
}

impl std::fmt::Debug for SaslStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaslStep")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("done", &self.done)
            .finish()
    }
}

/// The connection that a mechanism authenticates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaslContext {
    /// The connect-string host of the server.
    pub server_host: String,
    /// The peer address of the socket.
    pub server_addr: SocketAddr,
    /// The local address of the socket.
    pub local_addr: SocketAddr,
}

/// A SASL failure. `SessionInfo::last_error` carries it after the
/// session ends in `AuthFailed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaslError {
    /// The kind of the failure.
    pub kind: SaslErrorKind,
    /// The text of the failure. It contains no secret.
    pub message: String,
}

impl SaslError {
    /// Makes an error of `kind` with `message`.
    #[must_use]
    pub fn new(kind: SaslErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// The kind of a [`SaslError`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaslErrorKind {
    /// The mechanism failed or panicked.
    Mechanism,
    /// The server refused the authentication.
    ServerRejected,
    /// The credential source failed with this kind.
    Credential(CredentialError),
}

impl std::fmt::Display for SaslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.kind {
            SaslErrorKind::Mechanism => "mechanism error",
            SaslErrorKind::ServerRejected => "rejected by the server",
            SaslErrorKind::Credential(CredentialError::Transient) => "transient credential error",
            SaslErrorKind::Credential(CredentialError::Permanent) => "permanent credential error",
        };
        write!(f, "SASL {kind}: {}", self.message)
    }
}

impl std::error::Error for SaslError {}

/// The entry point of the DIGEST-MD5 fuzz target.
///
/// Only a build with `--cfg fuzzing`, such as `cargo fuzz`, has this
/// module. The mechanism is private, and no public call reaches it
/// without a live server. The fixed client nonce makes each fuzz run
/// repeatable.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use super::SaslMechanism;
    use crate::secret::SecretString;

    /// Makes a DIGEST-MD5 session with a fixed client nonce.
    #[must_use]
    pub fn digest_md5(
        username: String,
        password: SecretString,
        digest_uri: String,
        cnonce: String,
    ) -> Box<dyn SaslMechanism> {
        Box::new(super::digest_md5::DigestMd5::new(
            username, password, digest_uri, cnonce,
        ))
    }
}
