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

//! The TLS contract of the drivers (spec "TLS transport integration").
//!
//! This file is always compiled, so the I/O path and the tests can use
//! the traits without the `tls` feature. The rustls implementation is in
//! the submodules, under the `tls` feature.
//!
//! - [`TlsConn`] is a sans-IO client session. The driver owns the socket.
//!   The session never sees it. The trait is the spec trait. It has no
//!   `wants_read` and no `handshake` method: rustls advances the
//!   handshake inside `feed`, and the driver moves the flight out with
//!   `take_ciphertext`.
//! - [`TlsConnector`] makes one session per attempt and per probe, with
//!   no driver lock held.
//! - [`TlsTransport`] is the driver-side state of one TLS transport.
//!
//! Latch contract: `feed` and `feed_eof` never discard plaintext. A
//! fatal error, an alert, close_notify or EOF is latched.
//! `read_plaintext` first gives the plaintext that came before the
//! failure. Only the call after that gives the failure.

use zk_jute::JString;
pub use zk_proto::{Endpoint, TlsConfigStep, TlsResourceAt};

use crate::net::sock::TcpSock;
use crate::sync::Unlocked;

#[cfg(feature = "tls")]
pub mod conn;
#[cfg(feature = "tls")]
pub mod connector;
#[cfg(feature = "tls")]
pub mod identity;
#[cfg(feature = "tls")]
pub mod legacy_pem;
#[cfg(feature = "tls")]
pub mod legacy_verify;
#[cfg(feature = "tls")]
pub mod pem;
#[cfg(feature = "tls")]
pub mod trust;
#[cfg(feature = "tls")]
pub mod v1_leaf;
#[cfg(feature = "tls")]
pub mod verify;
#[cfg(feature = "tls")]
pub mod x509;

#[cfg(feature = "tls")]
pub use conn::RustlsConn;
#[cfg(feature = "tls")]
pub use connector::{LegacyPath, LegacyTlsArgs, NativeConfig, RustlsConnector, default_provider};

/// A sans-IO TLS client session for one attempt or one RW probe.
///
/// The one implementation is `RustlsConn` (feature `tls`), in both
/// profiles. Tests use scripted fakes.
pub trait TlsConn: Send {
    /// Returns true until the handshake is complete.
    fn is_handshaking(&self) -> bool;

    /// Returns true when ciphertext waits for [`Self::take_ciphertext`].
    fn has_ciphertext(&self) -> bool;

    /// Takes all ciphertext bytes. It never discards plaintext.
    ///
    /// A fatal error, an alert or close_notify is latched. A session in
    /// the handshake reports every failure as [`TlsFailure::Handshake`].
    ///
    /// # Errors
    ///
    /// Returns the latched failure. Plaintext that came before it stays
    /// readable.
    fn feed(&mut self, ciphertext: &[u8]) -> Result<(), TlsFailure>;

    /// Records the peer EOF. It latches `Closed`, or `Handshake` while
    /// handshaking.
    ///
    /// # Errors
    ///
    /// Returns the latched failure.
    fn feed_eof(&mut self) -> Result<(), TlsFailure>;

    /// Appends the plaintext that was decrypted before a latched failure.
    ///
    /// It returns `Ok(n)` while plaintext is buffered, and `Ok(0)` when
    /// none is buffered and nothing is latched.
    ///
    /// # Errors
    ///
    /// Returns the latched failure, but only when no plaintext is left.
    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> Result<usize, TlsFailure>;

    /// Gives one chunk of plaintext to the session. One call per
    /// `poll_transmit` chunk. The session takes the whole chunk.
    ///
    /// # Errors
    ///
    /// Returns a failure when the session cannot take the chunk.
    fn write_frame(&mut self, plaintext: &[u8]) -> Result<(), TlsFailure>;

    /// Moves all queued ciphertext to the end of `out`. It returns the
    /// number of bytes. The first call after `new_conn` gives the
    /// ClientHello.
    fn take_ciphertext(&mut self, out: &mut Vec<u8>) -> usize;

    /// Queues the close_notify alert for [`Self::take_ciphertext`].
    /// Only the graceful close calls it.
    fn send_close_notify(&mut self);
}

/// Moves all bytes of `from` to the end of `out`, for `take_ciphertext`.
///
/// An empty `out` takes the bytes by a buffer swap, so no byte is copied
/// again. Then `from` keeps the old buffer of `out` for the next records.
#[cfg(any(test, feature = "tls"))]
pub(crate) fn move_ciphertext(out: &mut Vec<u8>, from: &mut Vec<u8>) {
    if out.is_empty() {
        std::mem::swap(out, from);
    } else {
        out.append(from);
    }
}

/// The class of a latched TLS failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsFailure {
    /// A failure during the handshake.
    Handshake,
    /// A data-phase failure: a bad record, an alert or a protocol error.
    Data,
    /// The peer sent close_notify, or the TCP stream ended.
    Closed,
}

/// The failure of [`TlsConnector::new_conn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsSetupError {
    /// A configuration step failed. The main connection parks the
    /// attempt with errno EINVAL, as C does.
    Config {
        /// The failed step.
        step: TlsConfigStep,
    },
    /// The context or the session could not be made. This is a teardown.
    Resource {
        /// Where it failed.
        at: TlsResourceAt,
    },
}

/// The use of a new session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsPurpose {
    /// The main connection of an attempt.
    Main,
    /// One RW probe.
    Probe,
}

/// Makes one TLS session per attempt and per probe.
pub trait TlsConnector: Send + Sync {
    /// Makes a new session.
    ///
    /// The drop-in reads all files again on each call, as C does. Natively
    /// the reload policy of zk-client decides. The call takes the
    /// [`Unlocked`] proof, so no driver lock is held. It takes no time
    /// argument: the verifier uses the rustls time provider.
    ///
    /// # Errors
    ///
    /// Returns the failed step or resource.
    fn new_conn(
        &self,
        proof: &Unlocked,
        purpose: TlsPurpose,
        peer: &Endpoint,
    ) -> Result<Box<dyn TlsConn>, TlsSetupError>;

    /// Returns the `%s` log argument of a step: the connector's own copy
    /// of the cert-string field. `None` for a NULL field and for steps
    /// that print no path.
    fn path_for(&self, step: TlsConfigStep) -> Option<&[u8]>;
}

/// A latched transport failure that the driver acts on after the frame
/// loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadFailure {
    /// close_notify or EOF. It gives `TransportFailure::Eof`.
    Closed,
    /// A TLS data failure. It gives `TransportFailure::Io`.
    Data,
    /// A recv error. It gives `TransportFailure::Io` with this errno.
    Io(i32),
}

impl From<TlsFailure> for ReadFailure {
    fn from(f: TlsFailure) -> Self {
        match f {
            TlsFailure::Closed => Self::Closed,
            TlsFailure::Handshake | TlsFailure::Data => Self::Data,
        }
    }
}

/// The driver-side state of one TLS transport.
///
/// The I/O path (`crate::iocore`) owns the logic. This type only holds
/// the state, so the probe and the I/O path share one shape.
pub struct TlsTransport {
    /// The socket. The driver owns it.
    pub(crate) sock: TcpSock,
    /// The session.
    pub(crate) tls: Box<dyn TlsConn>,
    /// Ciphertext taken from the session that the kernel has not taken.
    /// It is empty when the kernel has taken every byte. Then the next
    /// take can swap buffers with the session.
    pub(crate) ct_out: Vec<u8>,
    /// The count of bytes at the start of `ct_out` that are on the wire.
    /// A partial send moves this cursor and moves no bytes.
    pub(crate) ct_sent: usize,
    /// Plaintext given to the session whose ciphertext is not fully sent.
    pub(crate) unacked: usize,
    /// A latched TLS failure or recv error, acted on after the frame loop.
    pub(crate) pending: Option<ReadFailure>,
}

impl TlsTransport {
    /// Makes the state for a new session on a connected socket.
    #[must_use]
    pub fn new(sock: TcpSock, tls: Box<dyn TlsConn>) -> Self {
        Self {
            sock,
            tls,
            ct_out: Vec::new(),
            ct_sent: 0,
            unacked: 0,
            pending: None,
        }
    }

    /// Returns the socket.
    #[must_use]
    pub fn sock(&self) -> &TcpSock {
        &self.sock
    }

    /// Returns true while ciphertext waits in `ct_out` or in the session.
    #[must_use]
    pub fn has_unsent(&self) -> bool {
        !self.ct_out.is_empty() || self.tls.has_ciphertext()
    }

    /// Returns the bytes of `ct_out` that the kernel has not taken.
    pub(crate) fn unsent(&self) -> &[u8] {
        self.ct_out.get(self.ct_sent..).unwrap_or_default()
    }

    /// Records that the kernel took `n` more bytes of `ct_out`. When all
    /// bytes are out, it empties `ct_out` and resets the cursor.
    pub(crate) fn mark_sent(&mut self, n: usize) {
        self.ct_sent = self.ct_sent.saturating_add(n);
        if self.ct_sent >= self.ct_out.len() {
            self.ct_out.clear();
            self.ct_sent = 0;
        }
    }

    /// Gives the socket back and drops the session with no close_notify.
    #[must_use]
    pub fn into_sock(self) -> TcpSock {
        self.sock
    }
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport")
            .field("sock", &self.sock)
            .field("ct_out", &self.ct_out.len())
            .field("ct_sent", &self.ct_sent)
            .field("unacked", &self.unacked)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

/// Turns a `path_for` result into the proto `JString`. `None` becomes
/// `JString::Null`, which the shim prints as "(null)".
#[must_use]
pub fn jstring(path: Option<&[u8]>) -> JString {
    path.map_or(JString::Null, JString::from)
}

/// Makes one attempt to send the fatal alert that the session queued.
///
/// The rule is the same in every flavor, in the handshake, in the data
/// phase and on the probe. When `ct_out` is empty, the alert gets one
/// non-blocking send. The result is ignored, and an unsent rest is lost.
/// When earlier ciphertext still waits, the alert stays off the wire.
/// In both cases the session holds no ciphertext after the call.
pub fn alert_attempt(sock: &TcpSock, tls: &mut dyn TlsConn, ct_out: &[u8]) {
    let mut scratch = Vec::new();
    tls.take_ciphertext(&mut scratch);
    if ct_out.is_empty() && !scratch.is_empty() {
        let _ = sock.send(&scratch);
    }
}
