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

//! `RustlsConn`: one rustls client session over memory buffers.
//!
//! The session never sees the socket. The driver gives it ciphertext with
//! `feed`, takes plaintext with `read_plaintext`, and moves its output to
//! the socket with `take_ciphertext`.
//!
//! The latch keeps the first failure. Plaintext that rustls decrypted
//! before the failure moves to `rx` first, so the driver always gets the
//! data before the failure. rustls keeps the plaintext of good records
//! when a later record in the same batch is bad, so `feed_all` gives the
//! ciphertext in large batches.

use std::io::{BufRead, ErrorKind, Write};

use rustls::ClientConnection;

use crate::net::tls::{TlsConn, TlsFailure};

/// One rustls client session over memory buffers.
///
/// The struct is always boxed as a `Box<dyn TlsConn>`, so the
/// `ClientConnection` lives on the heap and not on the stack of a
/// C-created thread.
pub struct RustlsConn {
    /// The session. Its send buffer limit is off, so `write_frame` never
    /// writes short.
    conn: ClientConnection,
    /// Ciphertext for the socket.
    tx: Vec<u8>,
    /// Plaintext not yet given to the driver.
    rx: Vec<u8>,
    /// The first fatal error, alert, close_notify or EOF.
    latched: Option<TlsFailure>,
}

impl RustlsConn {
    /// Wraps a new session.
    ///
    /// Contract: it turns the send buffer limit off
    /// (`set_buffer_limit(None)`), and moves the ClientHello into `tx`, so
    /// the first `take_ciphertext` gives it.
    #[must_use]
    pub fn new(mut conn: ClientConnection) -> Self {
        conn.set_buffer_limit(None);
        // The struct is built last, in the return place, so the frame
        // holds one copy of the session only.
        let mut tx = Vec::new();
        pump(&mut conn, &mut tx);
        Self {
            conn,
            tx,
            rx: Vec::new(),
            latched: None,
        }
    }

    /// Gives ciphertext to rustls.
    ///
    /// Contract: it takes the plaintext of each batch out before it acts
    /// on an error, so no plaintext is lost. A `read_tls` error processes
    /// the buffered records and feeding goes on. A second error with no
    /// progress in between latches `Data`. No busy loop.
    fn feed_all(&mut self, ct: &[u8]) -> Result<(), TlsFailure> {
        let mut ct = ct;
        let mut stalled = false;
        while !ct.is_empty() && self.latched.is_none() {
            match self.conn.read_tls(&mut ct) {
                // rustls takes no more bytes after close_notify. The
                // peer must not send more, so the rest is dropped and
                // the session latches the close.
                Ok(0) => self.latch(TlsFailure::Closed),
                Ok(_) => {
                    stalled = false;
                    self.process();
                }
                Err(_) if stalled => self.latch(TlsFailure::Data),
                Err(_) => {
                    stalled = true;
                    self.process();
                }
            }
        }
        self.latched.map_or(Ok(()), Err)
    }

    /// Processes the buffered records, takes out their plaintext, and
    /// queues any alert into `tx`.
    fn process(&mut self) {
        let r = self.conn.process_new_packets();
        // The records before a bad record were good. Their plaintext
        // stays readable after the error, so take it first.
        self.take_plaintext();
        match r {
            // OpenSSL ends the stream at a fatal alert of the peer, so
            // legacy reads 0 bytes and logs EHOSTDOWN.
            Err(rustls::Error::AlertReceived(_)) => self.latch(TlsFailure::Closed),
            Err(_) => self.latch(TlsFailure::Data),
            Ok(_) => {}
        }
        // A fatal error queues an alert. The driver decides with
        // `alert_attempt` whether it goes on the wire.
        self.pump_out();
    }

    /// Latches the first failure. Later failures are ignored.
    fn latch(&mut self, f: TlsFailure) {
        if self.latched.is_none() {
            // The handshake phase has one failure class.
            let f = if self.conn.is_handshaking() {
                TlsFailure::Handshake
            } else {
                f
            };
            self.latched = Some(f);
        }
    }

    /// Moves all decrypted bytes to `rx`. The end of the stream latches
    /// `Closed`: rustls gives an empty chunk after close_notify, and an
    /// `UnexpectedEof` error after a TCP EOF with no close_notify.
    fn take_plaintext(&mut self) {
        let mut closed = false;
        let mut reader = self.conn.reader();
        loop {
            match reader.fill_buf() {
                Ok([]) => {
                    closed = true;
                    break;
                }
                Ok(chunk) => {
                    let n = chunk.len();
                    self.rx.extend_from_slice(chunk);
                    reader.consume(n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    closed = true;
                    break;
                }
            }
        }
        if closed {
            self.latch(TlsFailure::Closed);
        }
    }

    /// Moves all records that rustls queued into `tx`.
    fn pump_out(&mut self) {
        pump(&mut self.conn, &mut self.tx);
    }
}

/// Moves all records that rustls queued to the end of `tx`. A write into
/// a `Vec` cannot fail, so the loop ends when rustls has no more bytes.
fn pump(conn: &mut ClientConnection, tx: &mut Vec<u8>) {
    while conn.wants_write() {
        match conn.write_tls(tx) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

impl TlsConn for RustlsConn {
    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn has_ciphertext(&self) -> bool {
        !self.tx.is_empty() || self.conn.wants_write()
    }

    fn feed(&mut self, ciphertext: &[u8]) -> Result<(), TlsFailure> {
        self.feed_all(ciphertext)
    }

    fn feed_eof(&mut self) -> Result<(), TlsFailure> {
        if self.latched.is_none() {
            // An empty read records the peer EOF in rustls. Then the
            // reader reports the end of the stream after the last
            // plaintext byte.
            let _ = self.conn.read_tls(&mut &[][..]);
            self.process();
            // A truncated record gives no reader error, so the close is
            // latched here too. It is a no-op when `process` latched.
            self.latch(TlsFailure::Closed);
        }
        self.latched.map_or(Ok(()), Err)
    }

    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> Result<usize, TlsFailure> {
        if !self.rx.is_empty() {
            let n = self.rx.len();
            out.append(&mut self.rx);
            return Ok(n);
        }
        self.latched.map_or(Ok(0), Err)
    }

    fn write_frame(&mut self, plaintext: &[u8]) -> Result<(), TlsFailure> {
        if let Some(f) = self.latched {
            return Err(f);
        }
        // The buffer limit is off, so rustls takes the whole chunk in one
        // call. A refusal means that the session is broken.
        if self.conn.writer().write_all(plaintext).is_err() {
            self.latch(TlsFailure::Data);
            return self.latched.map_or(Err(TlsFailure::Data), Err);
        }
        self.pump_out();
        Ok(())
    }

    fn take_ciphertext(&mut self, out: &mut Vec<u8>) -> usize {
        self.pump_out();
        let n = self.tx.len();
        super::move_ciphertext(out, &mut self.tx);
        n
    }

    fn send_close_notify(&mut self) {
        // A failed or unfinished session sends nothing.
        if self.latched.is_some() || self.conn.is_handshaking() {
            return;
        }
        self.conn.send_close_notify();
        self.pump_out();
    }
}

/// Test helpers of the `tls` modules: fixtures, an in-memory rustls
/// server, and a loop that moves the flights between two sessions.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::large_stack_frames
)]
pub(crate) mod testing {
    use std::io::Read;
    use std::path::PathBuf;
    use std::sync::Arc;

    use rustls::client::danger::ServerCertVerifier;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, IpAddr, PrivateKeyDer, ServerName};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
        SupportedProtocolVersion,
    };

    use super::RustlsConn;
    use crate::net::tls::connector::default_provider;
    use crate::net::tls::verify::ChainOnlyVerifier;
    use crate::net::tls::{TlsConn, TlsFailure};

    /// TLS 1.3 only.
    pub(crate) const TLS13: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
    /// TLS 1.2 only.
    pub(crate) const TLS12: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];

    pub(crate) fn fixture(name: &str) -> PathBuf {
        zk_testkit::fixtures::tls_dir().join(name)
    }

    pub(crate) fn provider() -> Arc<CryptoProvider> {
        default_provider()
    }

    pub(crate) fn certs(name: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(fixture(name))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    pub(crate) fn key(name: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_file(fixture(name)).unwrap()
    }

    pub(crate) fn roots(name: &str) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        for c in certs(name) {
            roots.add(c).unwrap();
        }
        Arc::new(roots)
    }

    /// A server session with `server.pem` and no client auth.
    pub(crate) fn server(versions: &[&'static SupportedProtocolVersion]) -> Box<ServerConnection> {
        let cfg = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs("server.pem"), key("server.key"))
            .unwrap();
        let mut s = Box::new(ServerConnection::new(Arc::new(cfg)).unwrap());
        s.set_buffer_limit(None);
        s
    }

    /// A client session with TLS 1.3 and 1.2 over `verifier`, with the
    /// drop-in name rule.
    pub(crate) fn client_with(verifier: Arc<dyn ServerCertVerifier>) -> Box<RustlsConn> {
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        cfg.enable_sni = false;
        let name = ServerName::IpAddress(IpAddr::from(std::net::IpAddr::from([127, 0, 0, 1])));
        Box::new(RustlsConn::new(
            ClientConnection::new(Arc::new(cfg), name).unwrap(),
        ))
    }

    /// A chain-only client that trusts `ca`.
    pub(crate) fn client(ca: &str) -> Box<RustlsConn> {
        client_with(Arc::new(ChainOnlyVerifier::new(roots(ca), provider())))
    }

    /// Takes all server ciphertext.
    pub(crate) fn server_out(s: &mut ServerConnection) -> Vec<u8> {
        let mut out = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut out).unwrap();
        }
        out
    }

    /// Gives ciphertext to the server and returns the plaintext that it
    /// reads. The server buffer is small, so this reads after each record.
    /// A server error stops the input, so its alert still goes to the client.
    pub(crate) fn server_in(s: &mut ServerConnection, mut ct: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while !ct.is_empty() {
            if s.read_tls(&mut ct).unwrap() == 0 {
                break;
            }
            if s.process_new_packets().is_err() {
                break;
            }
            out.extend_from_slice(&server_read(s));
        }
        out
    }

    /// Reads all plaintext that the server has.
    pub(crate) fn server_read(s: &mut ServerConnection) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match s.reader().read(&mut buf) {
                Ok(0) | Err(_) => return out,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Moves the flights between the sessions until neither has output.
    /// It returns the plaintext that the server reads. With `split`, the
    /// client gets the server bytes one at a time.
    pub(crate) fn exchange(
        c: &mut dyn TlsConn,
        s: &mut ServerConnection,
        split: bool,
    ) -> Result<Vec<u8>, TlsFailure> {
        let mut got = Vec::new();
        loop {
            let mut ct = Vec::new();
            c.take_ciphertext(&mut ct);
            got.extend_from_slice(&server_in(s, &ct));
            let sct = server_out(s);
            if ct.is_empty() && sct.is_empty() {
                return Ok(got);
            }
            if split {
                for b in &sct {
                    c.feed(std::slice::from_ref(b))?;
                }
            } else {
                c.feed(&sct)?;
            }
        }
    }

    /// Runs a full handshake and checks that both sides are done.
    pub(crate) fn connected(
        versions: &[&'static SupportedProtocolVersion],
    ) -> (Box<RustlsConn>, Box<ServerConnection>) {
        let mut c = client("ca.pem");
        let mut s = server(versions);
        exchange(c.as_mut(), &mut s, false).unwrap();
        assert!(!c.is_handshaking());
        assert!(!s.is_handshaking());
        (c, s)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::large_stack_frames
)]
mod tests {
    use super::testing::{TLS12, TLS13, connected};

    #[test]
    #[cfg_attr(
        miri,
        ignore = "the handshake reaches the native code of ring, which Miri cannot run"
    )]
    fn handshake_completes_in_memory_with_tls13_and_tls12() {
        for (versions, want) in [
            (TLS13, rustls::ProtocolVersion::TLSv1_3),
            (TLS12, rustls::ProtocolVersion::TLSv1_2),
        ] {
            let (c, s) = connected(versions);
            assert_eq!(s.protocol_version(), Some(want));
            assert_eq!(c.conn.protocol_version(), Some(want));
            // The drop-in sends no SNI.
            assert_eq!(s.server_name(), None);
        }
    }

    /// Rule: an empty `out` takes the records by a buffer swap, and a
    /// full `out` takes them by an append. The server reads the chunks in
    /// the write order, and the swap gives the old buffer to the session.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "the handshake reaches the native code of ring, which Miri cannot run"
    )]
    fn take_ciphertext_swaps_into_an_empty_buffer_in_order() {
        use super::testing::server_in;
        use crate::net::tls::TlsConn;

        let (mut c, mut s) = connected(TLS13);
        let first: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let second: Vec<u8> = (0..30_000u32).map(|i| (i % 241) as u8).collect();
        let mut out = Vec::with_capacity(8);
        let spare = out.as_ptr();
        c.write_frame(&first).unwrap();
        let n1 = c.take_ciphertext(&mut out);
        assert!(n1 > first.len() && out.len() == n1);
        assert!(c.tx.is_empty() && c.tx.as_ptr() == spare, "the swap");
        c.write_frame(&second).unwrap();
        let n2 = c.take_ciphertext(&mut out);
        assert_eq!(out.len(), n1 + n2, "the append keeps the first chunk");
        let mut want = first.clone();
        want.extend_from_slice(&second);
        assert_eq!(server_in(&mut s, &out), want);

        // A sent buffer swaps again, and the session reuses its capacity.
        let held = out.as_ptr();
        out.clear();
        c.write_frame(&second).unwrap();
        assert_eq!(c.take_ciphertext(&mut out), n2);
        assert!(out.len() == n2 && c.tx.as_ptr() == held);
        assert_eq!(server_in(&mut s, &out), second);
    }
}
