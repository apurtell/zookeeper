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

//! TLS listeners (feature `tls`).
//!
//! [`TlsAcceptor`] is an [`Acceptor`] with a rustls server session. The
//! protocol loop reads and writes plaintext, so the model and the rules
//! do not change. The caller gives the crypto provider, so the crate
//! selects no provider of its own.
//!
//! The acceptor records each connection as a [`TlsSession`]: the
//! handshake result, the client certificate, the close_notify that the
//! server sent, and how the peer ended the stream. Tests use the record
//! to check the TLS close rules of the client.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, SupportedProtocolVersion};

use crate::transport::{Acceptor, Transport};

/// The default time that the server gives a client to end its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How the peer ended the TLS stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEnd {
    /// The peer sent close_notify.
    CloseNotify,
    /// The TCP stream ended or failed with no close_notify.
    Eof,
    /// The peer sent a bad record or an alert. The text is the rustls
    /// error.
    Error(String),
}

/// The record of one TLS connection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsSession {
    /// The handshake result: `None` while it runs, then `Ok` or the
    /// error text.
    pub handshake: Option<Result<(), String>>,
    /// True when the client sent a certificate that the server accepted.
    pub client_cert: bool,
    /// The negotiated protocol version, for example `TLSv1_3`.
    pub version: Option<String>,
    /// True when the server sent close_notify.
    pub sent_close_notify: bool,
    /// How the peer ended the stream, when the server saw it.
    pub peer_end: Option<PeerEnd>,
}

/// The records of an acceptor and a condition for waits.
#[derive(Debug, Default)]
struct Log {
    sessions: Mutex<Vec<TlsSession>>,
    changed: Condvar,
}

impl Log {
    fn lock(&self) -> MutexGuard<'_, Vec<TlsSession>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds a record and returns its index.
    fn open(&self) -> usize {
        let mut g = self.lock();
        g.push(TlsSession::default());
        g.len().saturating_sub(1)
    }

    /// Changes the record at `at` and wakes the waiters.
    fn update(&self, at: usize, f: impl FnOnce(&mut TlsSession)) {
        if let Some(s) = self.lock().get_mut(at) {
            f(s);
        }
        self.changed.notify_all();
    }

    /// Records the first peer end of the record at `at`.
    fn peer_end(&self, at: usize, end: PeerEnd) {
        self.update(at, |s| {
            if s.peer_end.is_none() {
                s.peer_end = Some(end);
            }
        });
    }

    fn has_peer_end(&self, at: usize) -> bool {
        self.lock().get(at).is_some_and(|s| s.peer_end.is_some())
    }
}

/// Builds a [`TlsAcceptor`].
///
/// The server certificate chain and key are required. A client-auth CA
/// makes the server ask for a client certificate and reject a client
/// with none.
pub struct TlsAcceptorBuilder {
    provider: Arc<CryptoProvider>,
    chain: Vec<CertificateDer<'static>>,
    key: Option<PrivateKeyDer<'static>>,
    client_roots: Option<Vec<CertificateDer<'static>>>,
    versions: Option<&'static [&'static SupportedProtocolVersion]>,
    close_notify: bool,
    linger: Duration,
    handshake_timeout: Duration,
}

impl fmt::Debug for TlsAcceptorBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptorBuilder")
            .field("chain", &self.chain.len())
            .field("key", &self.key.is_some())
            .field("client_roots", &self.client_roots.as_ref().map(Vec::len))
            .field("close_notify", &self.close_notify)
            .field("linger", &self.linger)
            .finish_non_exhaustive()
    }
}

/// Makes an `InvalidInput` error with the text.
fn invalid(text: impl fmt::Display) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, text.to_string())
}

/// Reads every certificate of a PEM file.
fn pem_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(invalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    if certs.is_empty() {
        return Err(invalid(format!("no certificate in {}", path.display())));
    }
    Ok(certs)
}

impl TlsAcceptorBuilder {
    /// Starts a builder with the crypto provider of the test build.
    #[must_use]
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            chain: Vec::new(),
            key: None,
            client_roots: None,
            versions: None,
            close_notify: true,
            linger: Duration::ZERO,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }

    /// Sets the server certificate chain, leaf first.
    #[must_use]
    pub fn cert_chain(mut self, chain: Vec<CertificateDer<'static>>) -> Self {
        self.chain = chain;
        self
    }

    /// Reads the server certificate chain from a PEM file, leaf first.
    ///
    /// # Errors
    ///
    /// Returns an error when the file has no readable certificate.
    pub fn cert_chain_pem_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let chain = pem_certs(path.as_ref())?;
        Ok(self.cert_chain(chain))
    }

    /// Sets the server private key.
    #[must_use]
    pub fn key(mut self, key: PrivateKeyDer<'static>) -> Self {
        self.key = Some(key);
        self
    }

    /// Reads the server private key from a PEM file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file has no readable key.
    pub fn key_pem_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let key = PrivateKeyDer::from_pem_file(path.as_ref()).map_err(invalid)?;
        Ok(self.key(key))
    }

    /// Makes the server require a client certificate from these roots.
    #[must_use]
    pub fn client_auth_roots(mut self, roots: Vec<CertificateDer<'static>>) -> Self {
        self.client_roots = Some(roots);
        self
    }

    /// Makes the server require a client certificate from the CAs of a
    /// PEM file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file has no readable certificate.
    pub fn client_auth_ca_pem_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let roots = pem_certs(path.as_ref())?;
        Ok(self.client_auth_roots(roots))
    }

    /// Limits the protocol versions. The default is the rustls default
    /// set: TLS 1.3 and TLS 1.2.
    #[must_use]
    pub fn versions(mut self, versions: &'static [&'static SupportedProtocolVersion]) -> Self {
        self.versions = Some(versions);
        self
    }

    /// Sets whether a graceful server close sends close_notify. The
    /// default is true. With false the server ends the TCP stream only.
    #[must_use]
    pub const fn close_notify(mut self, send: bool) -> Self {
        self.close_notify = send;
        self
    }

    /// Sets how long a graceful server close waits for the peer to end
    /// its stream. The default is zero.
    ///
    /// The wait lets the server see the client close_notify that comes
    /// after the last reply. The wait ends early at the peer end.
    #[must_use]
    pub const fn linger(mut self, wait: Duration) -> Self {
        self.linger = wait;
        self
    }

    /// Sets the time that a client has to end its handshake. The default
    /// is 5 s.
    #[must_use]
    pub const fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Makes the acceptor.
    ///
    /// # Errors
    ///
    /// Returns an error when the chain or the key is missing, or when
    /// rustls rejects the settings.
    pub fn build(self) -> io::Result<Arc<TlsAcceptor>> {
        let key = self.key.ok_or_else(|| invalid("no server key"))?;
        if self.chain.is_empty() {
            return Err(invalid("no server certificate chain"));
        }
        let builder = ServerConfig::builder_with_provider(Arc::clone(&self.provider));
        let builder = match self.versions {
            Some(v) => builder.with_protocol_versions(v),
            None => builder.with_safe_default_protocol_versions(),
        }
        .map_err(invalid)?;
        let builder = match self.client_roots {
            Some(certs) => {
                let mut roots = RootCertStore::empty();
                for c in certs {
                    roots.add(c).map_err(invalid)?;
                }
                let verifier = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::clone(&self.provider),
                )
                .build()
                .map_err(invalid)?;
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let config = builder.with_single_cert(self.chain, key).map_err(invalid)?;
        Ok(Arc::new(TlsAcceptor {
            config: Arc::new(config),
            close_notify: self.close_notify,
            linger: self.linger,
            handshake_timeout: self.handshake_timeout,
            log: Arc::new(Log::default()),
        }))
    }
}

/// A TLS [`Acceptor`] with a rustls server session.
///
/// Give it to [`ServerOptions::with_acceptor`](crate::ServerOptions::with_acceptor).
/// The connection thread runs the handshake, so a slow client does not
/// block the listener.
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    close_notify: bool,
    linger: Duration,
    handshake_timeout: Duration,
    log: Arc<Log>,
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor")
            .field("close_notify", &self.close_notify)
            .field("linger", &self.linger)
            .field("sessions", &self.log.lock().len())
            .finish_non_exhaustive()
    }
}

impl TlsAcceptor {
    /// Starts a builder.
    #[must_use]
    pub fn builder(provider: Arc<CryptoProvider>) -> TlsAcceptorBuilder {
        TlsAcceptorBuilder::new(provider)
    }

    /// Returns the records of all connections, in accept order.
    #[must_use]
    pub fn sessions(&self) -> Vec<TlsSession> {
        self.log.lock().clone()
    }

    /// Waits until `pred` is true for the records, or `timeout` passes.
    /// It returns the last result of `pred`.
    pub fn wait_sessions(
        &self,
        timeout: Duration,
        mut pred: impl FnMut(&[TlsSession]) -> bool,
    ) -> bool {
        let end = Instant::now().checked_add(timeout);
        let mut g = self.log.lock();
        loop {
            if pred(&g) {
                return true;
            }
            let left = end.map_or(timeout, |e| e.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                return false;
            }
            g = self
                .log
                .changed
                .wait_timeout(g, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Runs the server handshake on a blocking socket with a short read
    /// timeout. It returns the error text on a failure.
    fn handshake(&self, conn: &mut ServerConnection, tcp: &mut TcpStream) -> Result<(), String> {
        let end = Instant::now().checked_add(self.handshake_timeout);
        while conn.is_handshaking() {
            write_all_tls(conn, tcp).map_err(|e| e.to_string())?;
            if !conn.is_handshaking() {
                break;
            }
            match conn.read_tls(tcp) {
                Ok(0) => return Err("EOF in the handshake".to_owned()),
                Ok(_) => {
                    if let Err(e) = conn.process_new_packets() {
                        // The alert goes out on a best-effort basis.
                        drop(write_all_tls(conn, tcp));
                        return Err(e.to_string());
                    }
                }
                Err(e) if is_timeout(&e) => {
                    if end.is_some_and(|e| Instant::now() >= e) {
                        return Err("handshake timeout".to_owned());
                    }
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        write_all_tls(conn, tcp).map_err(|e| e.to_string())
    }
}

impl Acceptor for TlsAcceptor {
    // The rustls session is large in debug builds. The fake-server
    // threads have the default stack, so the frame is safe.
    #[allow(clippy::large_stack_frames)]
    fn accept(&self, tcp: TcpStream) -> io::Result<Box<dyn Transport>> {
        let at = self.log.open();
        let mut conn = match ServerConnection::new(Arc::clone(&self.config)) {
            Ok(c) => Box::new(c),
            Err(e) => {
                self.log
                    .update(at, |s| s.handshake = Some(Err(e.to_string())));
                return Err(io::Error::other(e));
            }
        };
        let mut tcp = tcp;
        let result = self.handshake(&mut conn, &mut tcp);
        let client_cert = conn.peer_certificates().is_some_and(|c| !c.is_empty());
        let version = conn.protocol_version().map(|v| format!("{v:?}"));
        let failed = result.as_ref().err().cloned();
        self.log.update(at, |s| {
            s.handshake = Some(result);
            s.client_cert = client_cert;
            s.version = version;
        });
        if let Some(text) = failed {
            return Err(io::Error::other(text));
        }
        Ok(Box::new(TlsStream {
            conn,
            tcp,
            at,
            log: Arc::clone(&self.log),
            close_notify: self.close_notify,
            linger: self.linger,
        }))
    }
}

/// Returns true for the errors of a read timeout.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// Writes all queued TLS records to the socket.
fn write_all_tls(conn: &mut ServerConnection, tcp: &mut TcpStream) -> io::Result<()> {
    while conn.wants_write() {
        if conn.write_tls(tcp)? == 0 {
            return Err(ErrorKind::WriteZero.into());
        }
    }
    Ok(())
}

/// The server side of one TLS connection.
struct TlsStream {
    conn: Box<ServerConnection>,
    tcp: TcpStream,
    at: usize,
    log: Arc<Log>,
    close_notify: bool,
    linger: Duration,
}

impl TlsStream {
    /// Reads one batch of records. A peer end goes into the record.
    fn read_records(&mut self) -> io::Result<()> {
        match self.conn.read_tls(&mut self.tcp) {
            // The reader reports the end after the last plaintext byte.
            Ok(_) => {}
            Err(e) if is_timeout(&e) => return Err(e),
            Err(e) => {
                self.log.peer_end(self.at, PeerEnd::Eof);
                return Err(e);
            }
        }
        if let Err(e) = self.conn.process_new_packets() {
            drop(write_all_tls(&mut self.conn, &mut self.tcp));
            self.log.peer_end(self.at, PeerEnd::Error(e.to_string()));
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }
        Ok(())
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.conn.reader().read(buf) {
                Ok(0) if !buf.is_empty() => {
                    self.log.peer_end(self.at, PeerEnd::CloseNotify);
                    return Ok(0);
                }
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        self.log.peer_end(self.at, PeerEnd::Eof);
                    }
                    return Err(e);
                }
            }
            self.read_records()?;
            // A key update or a ticket may need an answer.
            write_all_tls(&mut self.conn, &mut self.tcp)?;
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.conn.writer().write(buf)?;
        write_all_tls(&mut self.conn, &mut self.tcp)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        write_all_tls(&mut self.conn, &mut self.tcp)
    }
}

impl Transport for TlsStream {
    fn tcp(&self) -> &TcpStream {
        &self.tcp
    }

    fn finish(&mut self, graceful: bool) {
        if !graceful {
            return;
        }
        if self.close_notify {
            self.conn.send_close_notify();
            let sent = write_all_tls(&mut self.conn, &mut self.tcp).is_ok();
            self.log.update(self.at, |s| s.sent_close_notify = sent);
        }
        // The wait reads and drops plaintext until the peer ends its
        // stream. So the record shows a close_notify that comes late.
        let Some(end) = Instant::now().checked_add(self.linger) else {
            return;
        };
        let mut scratch = vec![0u8; 4096];
        while Instant::now() < end && !self.log.has_peer_end(self.at) {
            match self.read(&mut scratch) {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) if is_timeout(&e) => {}
                Err(_) => return,
            }
        }
    }
}
