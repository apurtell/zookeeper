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

//! Shared unit-test helpers.
//!
//! The unit tests of every module use these helpers. Thus a unit test
//! does not depend on the code of another module:
//!
//! - [`TestHost`]: host leaves with a fixed address table.
//! - [`test_connection`]: a proto `Connection` with one host.
//! - [`socket_pair`]: two connected loopback sockets, with no use of
//!   `TcpSock::open`.
//! - [`RealPoll`]: a [`Poll`] over `rustix::event::poll`, with no use of
//!   `RustixPoll`.
//! - [`NullTls`] and [`FakeConnector`]: a scripted TLS session with a
//!   null cipher, so the TLS I/O path runs without the `tls` feature.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rustix::event::{PollFd, Timespec};
use zk_jute::JString;
use zk_proto::legacy::connect::parse_init;
use zk_proto::{
    ClientId, Compat, Config, Connection, DriverMode, HostResolution, HostSpec, InputDefect,
    LogLevel, Millis, Op, PathIn, Request, ResolveError, Route,
};
use zk_testkit::hooks::{LevelFilter, SharedDefaultWatcher};
use zk_testkit::rng::SeededRng;
use zk_testkit::tokens::CompletionId;
use zk_testkit::tokens::{TestTokens, WatcherId};

use crate::host::{Discarded, HostLeaves};
use crate::net::poll::Poll;
use crate::net::sock::TcpSock;
use crate::net::tls::{
    Endpoint, TlsConfigStep, TlsConn, TlsConnector, TlsFailure, TlsPurpose, TlsSetupError,
};
use crate::sync::{Mutex, Unlocked};

/// The `getaddrinfo` rc of [`TestHost`] for an unknown host (`EAI_NONAME`
/// on Linux).
pub const TEST_EAI_NONAME: i32 = -2;

/// Host leaves for unit tests.
///
/// - The log level starts at Warn. `None` disables every level.
/// - `rng_random` gives 7 and `rng_drand48` gives 0.5.
/// - `resolve` reads the address table. An unknown host gives
///   [`TEST_EAI_NONAME`].
pub struct TestHost {
    level: Mutex<Option<LogLevel>>,
    addrs: Mutex<HashMap<Vec<u8>, Vec<SocketAddr>>>,
    discarded: Mutex<Vec<&'static str>>,
    ids: Mutex<Vec<ClientId>>,
    permute_disabled: AtomicBool,
    resolves: AtomicUsize,
    reseeds: AtomicUsize,
}

impl TestHost {
    /// Makes the host with an empty address table.
    pub fn new() -> Self {
        Self {
            level: Mutex::new(Some(LogLevel::Warn)),
            addrs: Mutex::new(HashMap::new()),
            discarded: Mutex::new(Vec::new()),
            ids: Mutex::new(Vec::new()),
            permute_disabled: AtomicBool::new(false),
            resolves: AtomicUsize::new(0),
            reseeds: AtomicUsize::new(0),
        }
    }

    /// Sets the highest enabled level. `None` disables every level.
    pub fn set_log_level(&self, level: Option<LogLevel>) {
        *self.level.lock_owner() = level;
    }

    /// Sets the addresses of a host name.
    pub fn set_addrs(&self, host: &[u8], addrs: Vec<SocketAddr>) {
        self.addrs.lock_owner().insert(host.to_vec(), addrs);
    }

    /// Sets the `conn_permute_disabled` answer.
    pub fn set_permute_disabled(&self, v: bool) {
        self.permute_disabled.store(v, Ordering::Relaxed);
    }

    /// Returns the kinds of the discarded tokens, in order.
    pub fn discarded(&self) -> Vec<&'static str> {
        self.discarded.lock_owner().clone()
    }

    /// Returns the stored session identities, in order.
    pub fn stored_ids(&self) -> Vec<ClientId> {
        self.ids.lock_owner().clone()
    }

    /// Returns the number of `resolve` calls.
    pub fn resolves(&self) -> usize {
        self.resolves.load(Ordering::Relaxed)
    }

    /// Returns the number of `rng_reseed` calls.
    pub fn reseeds(&self) -> usize {
        self.reseeds.load(Ordering::Relaxed)
    }
}

impl Default for TestHost {
    fn default() -> Self {
        Self::new()
    }
}

impl HostLeaves<TestTokens> for TestHost {
    fn discard_token(&self, token: Discarded<TestTokens>) {
        let kind = match token {
            Discarded::Completion(_) => "completion",
            Discarded::Watcher(_) => "watcher",
            Discarded::Auth(_) => "auth",
        };
        self.discarded.lock_owner().push(kind);
    }

    fn snapshot_default_watcher(&self) -> Option<WatcherId> {
        None
    }

    fn store_client_id(&self, id: &ClientId) {
        self.ids.lock_owner().push(*id);
    }

    fn log_enabled(&self, level: LogLevel) -> bool {
        self.level
            .lock_owner()
            .is_some_and(|m| level.code() <= m.code())
    }

    fn conn_permute_disabled(&self) -> bool {
        self.permute_disabled.load(Ordering::Relaxed)
    }

    fn rng_random(&self) -> i64 {
        7
    }

    fn rng_drand48(&self) -> f64 {
        0.5
    }

    fn rng_reseed(&self, _proof: &Unlocked) {
        self.reseeds.fetch_add(1, Ordering::Relaxed);
    }

    fn resolve(&self, _proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution {
        self.resolves.fetch_add(1, Ordering::Relaxed);
        let result = match self.addrs.lock_owner().get(spec.host_bytes()) {
            Some(a) => Ok(a.clone()),
            None => Err(ResolveError {
                gai_rc: TEST_EAI_NONAME,
                errno: 0,
            }),
        };
        HostResolution {
            host,
            result,
            skipped_families: Vec::new(),
        }
    }
}

/// Returns a legacy configuration for the connect string `hosts`.
pub fn test_config(hosts: &[u8]) -> Config {
    let cs = parse_init(hosts).expect("valid connect string");
    let mut cfg = Config::legacy(10_000);
    cfg.hosts = cs.hosts.into_iter().map(HostSpec::Legacy).collect();
    cfg.host_text = JString::Bytes(cs.host_text);
    cfg.chroot = cs.chroot.map(JString::Bytes);
    cfg
}

/// Makes a drop-in `Connection` for "127.0.0.1:2181" at time 0. Its
/// first `poll_action` gives `Resolve{initial: true}`.
pub fn test_connection(mode: DriverMode) -> Connection<TestTokens> {
    Connection::new(
        test_config(b"127.0.0.1:2181"),
        Compat::LEGACY_C,
        mode,
        Box::new(SeededRng::new(1)),
        Box::new(LevelFilter::up_to(LogLevel::Debug)),
        Box::new(SharedDefaultWatcher::new(None)),
        Millis(0),
    )
}

/// Makes a native `Connection` for "127.0.0.1:2181" at time 0, with the
/// native compat profile and driver mode.
pub fn native_connection() -> Box<Connection<TestTokens>> {
    Box::new(Connection::new(
        test_config(b"127.0.0.1:2181"),
        Compat::NATIVE,
        DriverMode::NATIVE,
        Box::new(SeededRng::new(1)),
        Box::new(LevelFilter::up_to(LogLevel::Debug)),
        Box::new(SharedDefaultWatcher::new(None)),
        Millis(0),
    ))
}

/// Makes a queued `Exists` request with no watch for `path`. The
/// completion token is `id`.
pub fn exists_request(path: PathIn, id: u64) -> Request<TestTokens> {
    Request {
        op: Op::Exists { path, watch: None },
        token: CompletionId::new(id),
        route: Route::Queued,
        defect: InputDefect::default(),
    }
}

/// Returns two connected loopback sockets. Both are blocking. Call
/// `net::sock::set_nonblocking` to make one non-blocking.
pub fn socket_pair() -> (TcpSock, TcpSock) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = TcpStream::connect(l.local_addr().expect("addr")).expect("connect");
    let (b, _) = l.accept().expect("accept");
    (
        TcpSock::from_owned(OwnedFd::from(a)),
        TcpSock::from_owned(OwnedFd::from(b)),
    )
}

/// A [`Poll`] over `rustix::event::poll`. It is independent of
/// `RustixPoll`, so tests of other modules do not need it.
pub struct RealPoll;

impl Poll for RealPoll {
    fn poll(&self, fds: &mut [PollFd<'_>], timeout_ms: i32) -> rustix::io::Result<usize> {
        let ts = (timeout_ms >= 0).then(|| Timespec {
            tv_sec: i64::from(timeout_ms / 1000),
            tv_nsec: i64::from(timeout_ms % 1000) * 1_000_000,
        });
        rustix::event::poll(fds, ts.as_ref())
    }
}

/// A scripted TLS session with a null cipher.
///
/// - The first `take_ciphertext` gives `b"HELLO"`.
/// - In the handshake, fed bytes end the handshake. A fed `b'F'` latches
///   `Handshake` instead. A fed `b'A'` latches `Handshake` and queues the
///   alert `b"ALERT"`.
/// - After the handshake, ciphertext is plaintext. A fed `b'!'` latches
///   `Data`. `write_frame` queues its bytes as ciphertext.
/// - `send_close_notify` queues `b"CN"`.
pub struct NullTls {
    handshaking: bool,
    out: Vec<u8>,
    plain: Vec<u8>,
    latched: Option<TlsFailure>,
}

impl NullTls {
    /// Makes a session in the handshake with the ClientHello queued.
    pub fn new() -> Self {
        Self {
            handshaking: true,
            out: b"HELLO".to_vec(),
            plain: Vec::new(),
            latched: None,
        }
    }
}

impl Default for NullTls {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConn for NullTls {
    fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    fn has_ciphertext(&self) -> bool {
        !self.out.is_empty()
    }

    fn feed(&mut self, ciphertext: &[u8]) -> Result<(), TlsFailure> {
        if let Some(f) = self.latched {
            return Err(f);
        }
        for &b in ciphertext {
            if self.handshaking {
                match b {
                    b'F' => self.latched = Some(TlsFailure::Handshake),
                    b'A' => {
                        self.out.extend_from_slice(b"ALERT");
                        self.latched = Some(TlsFailure::Handshake);
                    }
                    _ => self.handshaking = false,
                }
            } else if b == b'!' {
                self.latched = Some(TlsFailure::Data);
            } else {
                self.plain.push(b);
            }
            if let Some(f) = self.latched {
                return Err(f);
            }
        }
        Ok(())
    }

    fn feed_eof(&mut self) -> Result<(), TlsFailure> {
        let f = if self.handshaking {
            TlsFailure::Handshake
        } else {
            TlsFailure::Closed
        };
        let f = *self.latched.get_or_insert(f);
        Err(f)
    }

    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> Result<usize, TlsFailure> {
        if !self.plain.is_empty() {
            let n = self.plain.len();
            out.append(&mut self.plain);
            return Ok(n);
        }
        self.latched.map_or(Ok(0), Err)
    }

    fn write_frame(&mut self, plaintext: &[u8]) -> Result<(), TlsFailure> {
        if let Some(f) = self.latched {
            return Err(f);
        }
        self.out.extend_from_slice(plaintext);
        Ok(())
    }

    fn take_ciphertext(&mut self, out: &mut Vec<u8>) -> usize {
        let n = self.out.len();
        // The bytes move as in the rustls session.
        crate::net::tls::move_ciphertext(out, &mut self.out);
        n
    }

    fn send_close_notify(&mut self) {
        self.out.extend_from_slice(b"CN");
    }
}

/// A [`TlsConnector`] that gives [`NullTls`] sessions, or scripted setup
/// failures in order.
pub struct FakeConnector {
    script: Mutex<VecDeque<TlsSetupError>>,
    made: AtomicUsize,
}

impl FakeConnector {
    /// Makes a connector whose calls fail with `failures` first.
    pub fn new(failures: Vec<TlsSetupError>) -> Self {
        Self {
            script: Mutex::new(failures.into()),
            made: AtomicUsize::new(0),
        }
    }

    /// Returns the number of `new_conn` calls.
    pub fn calls(&self) -> usize {
        self.made.load(Ordering::Relaxed)
    }
}

impl TlsConnector for FakeConnector {
    fn new_conn(
        &self,
        _proof: &Unlocked,
        _purpose: TlsPurpose,
        _peer: &Endpoint,
    ) -> Result<Box<dyn TlsConn>, TlsSetupError> {
        self.made.fetch_add(1, Ordering::Relaxed);
        match self.script.lock_owner().pop_front() {
            Some(e) => Err(e),
            None => Ok(Box::new(NullTls::new())),
        }
    }

    fn path_for(&self, step: TlsConfigStep) -> Option<&[u8]> {
        match step {
            TlsConfigStep::CaFile => Some(b"ca.pem"),
            TlsConfigStep::ClientCertChain => Some(b"cert.pem"),
            TlsConfigStep::ClientKey => Some(b"key.pem"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_tls_latches_after_plaintext() {
        let mut t = NullTls::new();
        let mut ct = Vec::new();
        assert_eq!(t.take_ciphertext(&mut ct), 5);
        t.feed(b"s").unwrap();
        assert!(!t.is_handshaking());
        assert_eq!(t.feed(b"ab!c"), Err(TlsFailure::Data));
        let mut pt = Vec::new();
        assert_eq!(t.read_plaintext(&mut pt), Ok(2));
        assert_eq!(t.read_plaintext(&mut pt), Err(TlsFailure::Data));
    }

    #[test]
    fn host_resolves_from_the_table() {
        let host = TestHost::new();
        let cfg = test_config(b"a:1,b:2");
        host.set_addrs(b"a", vec!["127.0.0.1:1".parse().unwrap()]);
        let proof = Unlocked::new_at_entry();
        assert!(host.resolve(&proof, 0, &cfg.hosts[0]).result.is_ok());
        assert!(host.resolve(&proof, 1, &cfg.hosts[1]).result.is_err());
        assert_eq!(host.resolves(), 2);
    }
}
