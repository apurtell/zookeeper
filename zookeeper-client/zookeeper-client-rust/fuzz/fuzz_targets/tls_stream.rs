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

//! Checks the TLS session wrapper of the driver with hostile ciphertext.
//!
//! The raw mode gives the input bytes to a new client session as server
//! ciphertext. The session mode completes a real handshake with an
//! in-memory server first. Then the input controls the records of both
//! peers, the cut points of the stream, and the damage to the stream.
//!
//! The target checks the latch contract of the wrapper: after the first
//! failure each call gives the same failure. The client must only read a
//! prefix of the server plaintext. With no damage it must read all of it.
//!
//! The certificates come from the test kit, which runs OpenSSL once and
//! caches the result.

#![no_main]
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, IpAddr, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use zk_driver::net::tls::verify::ChainOnlyVerifier;
use zk_driver::net::tls::{RustlsConn, TlsConn, TlsFailure, default_provider};
use zk_fuzz::Cursor;

/// The most commands of one input.
const MAX_COMMANDS: usize = 256;

/// The fixed configurations of the target.
struct Material {
    client: Arc<ClientConfig>,
    server13: Arc<ServerConfig>,
    server12: Arc<ServerConfig>,
}

fn material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| {
        let dir = zk_testkit::fixtures::tls_dir();
        let certs = |name: &str| -> Vec<CertificateDer<'static>> {
            CertificateDer::pem_file_iter(dir.join(name))
                .expect("the fixture opens")
                .collect::<Result<_, _>>()
                .expect("the fixture parses")
        };
        let mut roots = RootCertStore::empty();
        for c in certs("ca.pem") {
            roots.add(c).expect("the CA loads");
        }
        let provider = default_provider();
        let verifier = Arc::new(ChainOnlyVerifier::new(
            Arc::new(roots),
            Arc::clone(&provider),
        ));
        let mut client = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("the versions are valid")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        // The drop-in sends no server name.
        client.enable_sni = false;
        let server = |v: &'static rustls::SupportedProtocolVersion| {
            let key = PrivateKeyDer::from_pem_file(dir.join("server.key")).expect("the key loads");
            Arc::new(
                ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_protocol_versions(&[v])
                    .expect("the version is valid")
                    .with_no_client_auth()
                    .with_single_cert(certs("server.pem"), key)
                    .expect("the server identity is valid"),
            )
        };
        Material {
            client: Arc::new(client),
            server13: server(&rustls::version::TLS13),
            server12: server(&rustls::version::TLS12),
        }
    })
}

/// A client session and the state that the checks need.
struct Client {
    conn: RustlsConn,
    /// The failure that the session reported first.
    latched: Option<TlsFailure>,
    /// All plaintext that the session gave.
    got: Vec<u8>,
}

impl Client {
    fn new() -> Self {
        let name = ServerName::IpAddress(IpAddr::from(std::net::IpAddr::from([127, 0, 0, 1])));
        let conn = ClientConnection::new(Arc::clone(&material().client), name)
            .expect("the session starts");
        Self {
            conn: RustlsConn::new(conn),
            latched: None,
            got: Vec::new(),
        }
    }

    /// Records a result. After a failure, each result must be that failure.
    fn note(&mut self, r: Result<(), TlsFailure>) {
        match (self.latched, r) {
            (Some(f), r) => assert_eq!(r, Err(f), "the session lost its latched failure"),
            (None, Err(f)) => self.latched = Some(f),
            (None, Ok(())) => {}
        }
    }

    fn feed(&mut self, ct: &[u8]) {
        let r = self.conn.feed(ct);
        self.note(r);
    }

    fn feed_eof(&mut self) {
        let r = self.conn.feed_eof();
        assert!(r.is_err(), "the end of the stream is a failure");
        self.note(r);
    }

    fn read(&mut self) {
        let before = self.got.len();
        match self.conn.read_plaintext(&mut self.got) {
            Ok(n) => {
                assert_eq!(
                    self.got.len() - before,
                    n,
                    "the count differs from the bytes"
                );
                if n == 0 {
                    assert!(self.latched.is_none(), "a failed session gave Ok(0)");
                }
            }
            Err(f) => assert_eq!(Some(f), self.latched, "the read gave another failure"),
        }
    }

    /// Writes a frame. It tells whether the session took the frame.
    fn write(&mut self, pt: &[u8]) -> bool {
        let r = self.conn.write_frame(pt);
        let ok = r.is_ok();
        self.note(r);
        ok
    }

    fn take(&mut self, out: &mut Vec<u8>) {
        let before = out.len();
        let n = self.conn.take_ciphertext(out);
        assert_eq!(out.len() - before, n, "the count differs from the bytes");
        assert!(
            !self.conn.has_ciphertext(),
            "ciphertext is left after a take"
        );
    }
}

/// Moves all queued server records to the end of `out`.
fn server_out(s: &mut ServerConnection, out: &mut Vec<u8>) {
    while s.wants_write() {
        match s.write_tls(out) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Gives client records to the server. It returns false when the server
/// fails.
fn server_in(s: &mut ServerConnection, mut ct: &[u8], got: &mut Vec<u8>) -> bool {
    while !ct.is_empty() {
        match s.read_tls(&mut ct) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
        if s.process_new_packets().is_err() {
            return false;
        }
        let mut buf = [0u8; 4096];
        loop {
            match s.reader().read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    }
    true
}

/// Gives arbitrary bytes to a new session, with driver calls in between.
fn raw(c: &mut Cursor<'_>) {
    let mut client = Client::new();
    let mut wire = Vec::new();
    client.take(&mut wire);
    assert!(!wire.is_empty(), "the first take gives the ClientHello");
    for _ in 0..MAX_COMMANDS {
        if c.is_empty() {
            break;
        }
        match c.u8() % 6 {
            0 | 1 => client.feed(c.lp()),
            2 => client.feed_eof(),
            3 => client.read(),
            4 => {
                let _ = client.write(c.lp());
            }
            _ => {
                if c.bool() {
                    client.conn.send_close_notify();
                }
                client.take(&mut wire);
                wire.clear();
            }
        }
    }
    assert!(
        client.got.is_empty(),
        "a session with no handshake gave plaintext"
    );
}

/// Runs a real session and lets the input damage it.
fn session(c: &mut Cursor<'_>, tls12: bool) {
    let m = material();
    let cfg = if tls12 { &m.server12 } else { &m.server13 };
    let mut server = ServerConnection::new(Arc::clone(cfg)).expect("the server session starts");
    server.set_buffer_limit(None);
    let mut client = Client::new();

    // The handshake, with no damage.
    let mut server_got = Vec::new();
    for _ in 0..16 {
        let mut ct = Vec::new();
        client.take(&mut ct);
        assert!(
            server_in(&mut server, &ct, &mut server_got),
            "the server refused the handshake"
        );
        let mut sct = Vec::new();
        server_out(&mut server, &mut sct);
        if ct.is_empty() && sct.is_empty() {
            break;
        }
        client.feed(&sct);
    }
    assert!(
        client.latched.is_none(),
        "the handshake failed: {:?}",
        client.latched
    );
    assert!(
        !client.conn.is_handshaking() && !server.is_handshaking(),
        "the handshake did not end"
    );

    let mut s2c: Vec<u8> = Vec::new();
    let mut sent: Vec<u8> = Vec::new();
    let mut c2s_sent: Vec<u8> = Vec::new();
    let mut damaged = false;
    let mut client_eof = false;
    let mut server_ok = true;
    let mut server_closed = false;
    // The driver sends close_notify last and never reads after it. A
    // read after it can trip a debug assertion in rustls, so the
    // session ends there.
    let mut client_closed = false;
    for _ in 0..MAX_COMMANDS {
        if c.is_empty() || client_closed {
            break;
        }
        match c.u8() % 12 {
            0 | 1 if !server_closed => {
                // The server refuses data after it gets a fatal alert.
                let pt = c.lp();
                if server.writer().write_all(pt).is_ok() {
                    sent.extend_from_slice(pt);
                    server_out(&mut server, &mut s2c);
                } else {
                    server_closed = true;
                }
            }
            2 => {
                let n = usize::from(c.u16()).min(s2c.len());
                let chunk: Vec<u8> = s2c.drain(..n).collect();
                client.feed(&chunk);
            }
            3 => {
                let chunk = std::mem::take(&mut s2c);
                client.feed(&chunk);
            }
            4 if !s2c.is_empty() => {
                let at = usize::from(c.u16()) % s2c.len();
                s2c[at] ^= c.u8() | 1;
                damaged = true;
            }
            5 => {
                s2c.extend_from_slice(c.lp());
                damaged = true;
            }
            6 => client.read(),
            7 => {
                let pt = c.lp();
                if client.write(pt) {
                    c2s_sent.extend_from_slice(pt);
                }
            }
            8 => {
                let mut ct = Vec::new();
                client.take(&mut ct);
                if server_ok {
                    server_ok = server_in(&mut server, &ct, &mut server_got);
                }
            }
            9 => {
                server.send_close_notify();
                server_out(&mut server, &mut s2c);
                server_closed = true;
            }
            10 => {
                client.feed_eof();
                client_eof = true;
            }
            11 => {
                client.conn.send_close_notify();
                client_closed = true;
            }
            _ => {}
        }
        assert!(
            sent.starts_with(&client.got),
            "the client read bytes that the server did not send"
        );
        assert!(
            c2s_sent.starts_with(&server_got),
            "the server read bytes that the client did not send"
        );
    }

    // The end: all records arrive.
    if !client_closed {
        let chunk = std::mem::take(&mut s2c);
        client.feed(&chunk);
    }
    client.read();
    assert!(
        sent.starts_with(&client.got),
        "the client read bytes that the server did not send"
    );
    if !damaged && !client_eof && !client_closed {
        assert!(
            matches!(client.latched, None | Some(TlsFailure::Closed)),
            "an undamaged stream failed: {:?}",
            client.latched
        );
        assert_eq!(client.got.len(), sent.len(), "the client lost plaintext");
    }
    let mut ct = Vec::new();
    client.take(&mut ct);
    if server_ok && server_in(&mut server, &ct, &mut server_got) && !client_closed {
        assert_eq!(server_got, c2s_sent, "the server lost plaintext");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    match c.u8() % 3 {
        0 => raw(&mut c),
        1 => session(&mut c, false),
        _ => session(&mut c, true),
    }
});
