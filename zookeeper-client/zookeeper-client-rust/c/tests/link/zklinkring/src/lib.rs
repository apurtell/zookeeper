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

//! The unrelated Rust staticlib of LINK-01 for the TLS configurations.
//!
//! The library has its own std, rustls and ring, and it builds with
//! panic=abort. It also contains the std probe of `zklinkrs.rs`. The
//! application links it together with the static Rust core, whose
//! provider objects the prelink localizes. Thus the link must give no
//! duplicate symbol.
//!
//! The probe checks that each copy uses its own crypto provider. This
//! library installs its own process default, and the core installs
//! none. The TLS server of this library then accepts a mutual
//! TLS handshake from the core. Both providers thus work in one
//! process.

#[path = "../../zklinkrs.rs"]
mod std_probe;

use std::ffi::{c_char, c_int, CStr};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

/// SHA-256("abc") (FIPS 180-2, appendix B.1).
const SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

/// The secret key of RFC 8032 section 7.1, test 1.
const ED25519_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// The public key of RFC 8032 section 7.1, test 1.
const ED25519_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// The signature of the empty message of RFC 8032 section 7.1, test 1.
const ED25519_SIG: [u8; 64] = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

/// The state of the TLS server: 0 while it runs, 1 when the core
/// completed the handshake with a client certificate and sent a frame,
/// and a negative step number when a step failed.
static SERVER: AtomicI32 = AtomicI32::new(0);

/// Runs the known-answer tests of ring and installs the rustls default
/// provider of this library. The result is 0 when each step works,
/// else the number of the failed step.
#[no_mangle]
pub extern "C" fn zklinkring_probe() -> c_int {
    let d = ring::digest::digest(&ring::digest::SHA256, b"abc");
    if d.as_ref() != SHA256_ABC {
        return 1;
    }
    let kp = match ring::signature::Ed25519KeyPair::from_seed_and_public_key(
        &ED25519_SEED,
        &ED25519_PUBLIC,
    ) {
        Ok(kp) => kp,
        Err(_) => return 2,
    };
    if kp.sign(b"").as_ref() != ED25519_SIG {
        return 3;
    }
    let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, ED25519_PUBLIC);
    if pk.verify(b"", &ED25519_SIG).is_err() || pk.verify(b"x", &ED25519_SIG).is_ok() {
        return 4;
    }
    // The core installs no process default. This copy of rustls
    // has its own static, so it starts with none, and then it keeps the
    // provider of this library.
    if CryptoProvider::get_default().is_some() {
        return 5;
    }
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        return 6;
    }
    match CryptoProvider::get_default() {
        Some(p) if p.cipher_suites == rustls::crypto::ring::DEFAULT_CIPHER_SUITES => 0,
        _ => 7,
    }
}

/// Makes the server configuration of this library from the PEM files
/// in `dir`. It asks for a client certificate of the test CA.
fn server_config(dir: &Path) -> Result<ServerConfig, i32> {
    let provider = match CryptoProvider::get_default() {
        Some(p) => Arc::clone(p),
        None => return Err(-1),
    };
    let chain: Vec<CertificateDer<'static>> =
        match CertificateDer::pem_file_iter(dir.join("server.pem")) {
            Ok(it) => it.filter_map(Result::ok).collect(),
            Err(_) => return Err(-2),
        };
    let key = PrivateKeyDer::from_pem_file(dir.join("server.key")).map_err(|_| -3)?;
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_file_iter(dir.join("ca.pem")).map_err(|_| -4)? {
        roots.add(ca.map_err(|_| -4)?).map_err(|_| -4)?;
    }
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .map_err(|_| -5)?;
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| -6)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| -7)
}

/// Accepts one connection, runs the handshake and reads the length of
/// the first frame. A ConnectRequest frame has a body of 44 or 45 bytes.
fn serve(listener: TcpListener, cfg: ServerConfig) -> i32 {
    let tcp: TcpStream = match listener.accept() {
        Ok((s, _)) => s,
        Err(_) => return -8,
    };
    if tcp.set_read_timeout(Some(Duration::from_secs(10))).is_err() {
        return -8;
    }
    let conn = match ServerConnection::new(Arc::new(cfg)) {
        Ok(c) => c,
        Err(_) => return -9,
    };
    let mut tls = StreamOwned::new(conn, tcp);
    let mut len = [0u8; 4];
    if let Err(e) = tls.read_exact(&mut len) {
        eprintln!("zklinkring: the TLS read fails: {e}");
        return -10;
    }
    if tls.conn.peer_certificates().map_or(0, |c| c.len()) == 0 {
        return -11;
    }
    match u32::from_be_bytes(len) {
        44 | 45 => 1,
        _ => -12,
    }
}

/// Starts the TLS server on 127.0.0.1 with the fixtures in `dir`. The
/// result is the port, or a negative step number.
///
/// # Safety
///
/// DIR points to a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zklinkring_server_start(dir: *const c_char) -> c_int {
    if dir.is_null() {
        return -1;
    }
    // SAFETY: the caller gives a NUL-terminated string.
    let dir = match unsafe { CStr::from_ptr(dir) }.to_str() {
        Ok(d) => Path::new(d).to_path_buf(),
        Err(_) => return -1,
    };
    let cfg = match server_config(&dir) {
        Ok(c) => c,
        Err(step) => return step,
    };
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return -13,
    };
    let port = match listener.local_addr() {
        Ok(a) => c_int::from(a.port()),
        Err(_) => return -13,
    };
    SERVER.store(0, Ordering::SeqCst);
    thread::spawn(move || SERVER.store(serve(listener, cfg), Ordering::SeqCst));
    port
}

/// The state of the TLS server: 0 while it runs, 1 on success, or a
/// negative step number.
#[no_mangle]
pub extern "C" fn zklinkring_server_state() -> c_int {
    SERVER.load(Ordering::SeqCst)
}
