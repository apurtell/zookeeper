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

//! TLS driver tests with the st flavor and the drop-in profile.
//!
//! The test is the application loop of `libzookeeper_st`: `interest`,
//! a poll and `process`. The st return codes show the rc of each TLS
//! failure, as `zookeeper_interest` and `zookeeper_process` return it.
//! The server is the fake server with `zk_fakeserver::TlsAcceptor`. Its
//! session records show the close_notify rules.

#![cfg(all(unix, feature = "tls"))]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use common::tls::{legacy_path, provider};
use common::{IpHost, WAIT, env, exists, fixture};
use zk_driver::net::tls::{LegacyPath, LegacyTlsArgs, RustlsConnector, TlsConnector};
use zk_driver::outbox::{Flavor, Item};
use zk_driver::{Init, InitArgs, InitStep, InterestOut, Outbox, Polled, Step, Unlocked};
use zk_fakeserver::{
    Action, ClusterConfig, FakeServer, PeerEnd, Rule, ServerOptions, TlsAcceptor,
    TlsAcceptorBuilder,
};
use zk_jute::opcode;
use zk_proto::compat::TlsVerify;
use zk_proto::rc::{ZCONNECTIONLOSS, ZOK, ZOPERATIONTIMEOUT, ZSSLCONNECTIONERROR};
use zk_proto::{Compat, Config, DriverMode, LogSite, SecretBytes, State};
use zk_testkit::tokens::{CompletionId, TestTokens};

/// A session timeout that keeps the connected tests far from a timer.
const T_LONG: i32 = 3_000;

/// A session timeout for the timer tests. The receive timeout is
/// `T*2/3`, so 1000 ms.
const T_SHORT: i32 = 1_500;

/// The client side of a test.
struct Client {
    ca: LegacyPath,
    identity: bool,
    verify: TlsVerify,
    timeout: i32,
}

impl Client {
    fn new(ca: &str, verify: TlsVerify) -> Self {
        Self {
            ca: legacy_path(ca),
            identity: false,
            verify,
            timeout: T_LONG,
        }
    }
}

/// Makes the drop-in connector. `verify` goes to the connector and to
/// `Compat::tls_verify`, as zk-ffi sets both from one setting.
fn connector(c: &Client) -> Arc<dyn TlsConnector> {
    let args = LegacyTlsArgs {
        ca: Some(c.ca.clone()),
        cert: c.identity.then(|| legacy_path("client.pem")),
        key: c.identity.then(|| legacy_path("client.key")),
        passwd: c.identity.then(SecretBytes::empty),
        env_allowed: false,
        verify: c.verify,
    };
    Arc::new(RustlsConnector::legacy(args, provider()))
}

/// Makes a ready st handle with TLS for `hosts`.
fn handle(hosts: &str, c: &Client) -> Polled<TestTokens> {
    let mut cfg = Config::legacy(c.timeout);
    cfg.tls = true;
    let mut compat = Compat::LEGACY_C;
    compat.tls_verify = c.verify;
    let args = InitArgs {
        cfg,
        host_string: hosts.as_bytes().to_vec(),
        compat,
        mode: DriverMode::ST,
        flavor: Flavor::St,
    };
    let mut e = env(IpHost::new(), false);
    e.tls = Some(connector(c));
    let mut ob = Outbox::new();
    let mut init = Init::new(args, e, &mut ob).unwrap();
    let mut proof = Unlocked::new_at_entry();
    loop {
        match init.step(&mut proof, &mut ob) {
            InitStep::More | InitStep::SaslPoint => {
                common::drain(&mut ob);
            }
            InitStep::Ready => break,
            InitStep::Failed(e) => panic!("init failed: {e:?}"),
        }
    }
    Polled::from_init(init)
}

/// What the application saw: the items in order, and each final rc of
/// `interest` and `process` with its time.
#[derive(Default)]
struct Seen {
    items: Vec<Item<TestTokens>>,
    rcs: Vec<(Instant, i32)>,
}

impl Seen {
    fn has_rc(&self, rc: i32) -> bool {
        self.rcs.iter().any(|&(_, r)| r == rc)
    }

    fn first_rc(&self, rc: i32) -> Option<Instant> {
        self.rcs.iter().find(|&&(_, r)| r == rc).map(|&(t, _)| t)
    }

    fn log_pos(&self, site: LogSite) -> Option<usize> {
        self.items
            .iter()
            .position(|i| matches!(i, Item::Log(r) if r.site == site))
    }

    fn result_pos(&self, id: u64) -> Option<(usize, i32)> {
        self.items.iter().enumerate().find_map(|(n, i)| match i {
            Item::Result { token, result, .. } if *token == CompletionId::new(id) => {
                Some((n, result.rc))
            }
            _ => None,
        })
    }
}

/// Runs a driving call to its end and records its items and rc.
fn finish(
    h: &Polled<TestTokens>,
    mut step: Step,
    ob: &mut Outbox<TestTokens>,
    out: &mut InterestOut,
    rc: &mut i32,
    seen: &mut Seen,
) -> Step {
    while step == Step::More {
        seen.items.extend(common::drain(ob));
        step = h.resume(ob, out, rc);
    }
    seen.items.extend(common::drain(ob));
    seen.rcs.push((Instant::now(), *rc));
    step
}

/// One round of the application loop.
fn round(h: &Polled<TestTokens>, seen: &mut Seen) {
    let mut ob = h.outbox();
    let mut out = InterestOut::UNWRITTEN;
    let mut rc = 0;
    let step = h.interest(&mut ob, &mut out, &mut rc);
    finish(h, step, &mut ob, &mut out, &mut rc, seen);
    if out.fd < 0 {
        std::thread::sleep(Duration::from_millis(2));
        return;
    }
    let events = h.wait_events(&out, 20);
    let mut ob = h.outbox();
    let mut rc = 0;
    let step = h.process(events, &mut ob, &mut rc);
    finish(h, step, &mut ob, &mut out, &mut rc, seen);
}

/// Runs rounds until `pred` is true or `timeout` passes.
fn run_until(
    h: &Polled<TestTokens>,
    seen: &mut Seen,
    timeout: Duration,
    mut pred: impl FnMut(&Polled<TestTokens>, &Seen) -> bool,
) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        round(h, seen);
        if pred(h, seen) {
            return true;
        }
    }
    false
}

fn connected(h: &Polled<TestTokens>, seen: &mut Seen) -> bool {
    run_until(h, seen, WAIT, |h, _| h.state() == State::Connected.code())
}

/// Runs the final close and returns its rc.
fn close(h: &Polled<TestTokens>, seen: &mut Seen) -> i32 {
    let mut ob = h.outbox();
    let mut out = InterestOut::UNWRITTEN;
    let mut rc = -1;
    let step = h.close(&mut ob, &mut rc);
    let step = finish(h, step, &mut ob, &mut out, &mut rc, seen);
    assert_eq!(step, Step::Release);
    rc
}

/// A server acceptor with `leaf.pem` and `leaf.key`.
fn acceptor(leaf: &str) -> TlsAcceptorBuilder {
    TlsAcceptor::builder(provider())
        .cert_chain_pem_file(fixture(&format!("{leaf}.pem")))
        .unwrap()
        .key_pem_file(fixture(&format!("{leaf}.key")))
        .unwrap()
}

fn tls_server(acceptor: Arc<TlsAcceptor>) -> FakeServer {
    let opts = ServerOptions::default().with_acceptor(acceptor);
    FakeServer::start_with(ClusterConfig::default(), opts).unwrap()
}

/// A TCP listener that accepts and never answers. It keeps every socket
/// open and records the accept times.
struct Silent {
    addr: String,
    accepts: Arc<Mutex<Vec<Instant>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Silent {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepts = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let accepts = Arc::clone(&accepts);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut held: Vec<TcpStream> = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((s, _)) => {
                            accepts.lock().unwrap().push(Instant::now());
                            held.push(s);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(1)),
                    }
                }
            })
        };
        Self {
            addr,
            accepts,
            stop,
            thread: Some(thread),
        }
    }

    fn accepts(&self) -> Vec<Instant> {
        self.accepts.lock().unwrap().clone()
    }
}

impl Drop for Silent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

/// Checks that a handshake with `leaf` fails with the C rc and line of a
/// failed `SSL_connect`, and that the session never connects.
fn assert_handshake_fails(leaf: &str, client: &Client) {
    let acc = acceptor(leaf).build().unwrap();
    let server = tls_server(Arc::clone(&acc));
    let h = handle(&server.connect_string(), client);
    let mut seen = Seen::default();
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s.has_rc(ZSSLCONNECTIONERROR)));
    assert!(seen.log_pos(LogSite::SockTlsConnect).is_some());
    assert_ne!(h.state(), State::Connected.code());
    assert!(acc.wait_sessions(WAIT, |s| {
        s.first()
            .is_some_and(|s| matches!(s.handshake, Some(Err(_))))
    }));
    close(&h, &mut seen);
}

/// The legacy chain-only check accepts a leaf with another host name.
#[test]
fn legacy_chain_only_accepts_a_host_name_mismatch() {
    // Rule: LegacyChainOnly checks the chain to the CA and no name, as C
    // does with SSL_VERIFY_PEER and no host check (zookeeper.c
    // init_ssl_for_socket). The leaf names only other.invalid.
    let acc = acceptor("other-name").build().unwrap();
    let server = tls_server(Arc::clone(&acc));
    let h = handle(
        &server.connect_string(),
        &Client::new("ca.pem", TlsVerify::LegacyChainOnly),
    );
    let mut seen = Seen::default();
    assert!(connected(&h, &mut seen));
    assert!(!seen.has_rc(ZSSLCONNECTIONERROR));
    assert_eq!(close(&h, &mut seen), ZOK);
    assert!(acc.sessions()[0].handshake == Some(Ok(())));
}

#[test]
fn webpki_accepts_a_leaf_with_the_peer_ip_in_its_san() {
    // Rule: WebPki checks the chain and the name. The drop-in name is the
    // peer IP. server.pem has SAN IP:127.0.0.1.
    let acc = acceptor("server").build().unwrap();
    let server = tls_server(acc);
    let h = handle(
        &server.connect_string(),
        &Client::new("ca.pem", TlsVerify::WebPki),
    );
    let mut seen = Seen::default();
    assert!(connected(&h, &mut seen));
    let mut ob = h.outbox();
    h.submit(exists(1), &mut ob).ok().unwrap();
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s
        .result_pos(1)
        .is_some()));
    assert_eq!(seen.result_pos(1).unwrap().1, ZOK);
    assert_eq!(close(&h, &mut seen), ZOK);
}

#[test]
fn webpki_rejects_a_host_name_mismatch() {
    // Rule: WebPki fails on a name mismatch. A failed handshake gives
    // ZSSLCONNECTIONERROR and the SSL_connect line (zookeeper.c
    // init_ssl_for_socket).
    assert_handshake_fails("other-name", &Client::new("ca.pem", TlsVerify::WebPki));
}

#[test]
fn unknown_ca_fails_the_handshake() {
    // Rule: a leaf from an unknown CA fails under both policies with
    // ZSSLCONNECTIONERROR (zookeeper.c init_ssl_for_socket).
    // wrong-server.pem is from wrong-ca.
    assert_handshake_fails(
        "wrong-server",
        &Client::new("ca.pem", TlsVerify::LegacyChainOnly),
    );
    assert_handshake_fails("wrong-server", &Client::new("ca.pem", TlsVerify::WebPki));
}

#[test]
fn expired_leaf_fails_the_handshake() {
    // Rule: LegacyChainOnly checks the validity time, as OpenSSL does
    // with SSL_VERIFY_PEER.
    assert_handshake_fails(
        "expired",
        &Client::new("ca.pem", TlsVerify::LegacyChainOnly),
    );
}

#[test]
fn handshake_deadline_is_two_thirds_of_the_timeout() {
    // Rule: a handshake that does not end in T*2/3 is a timeout with
    // ZOPERATIONTIMEOUT and the timed-out line of zookeeper_interest, and
    // the client then tries the next attempt (spec line 233, zookeeper.c
    // zookeeper_interest). The server takes the ClientHello and never
    // answers.
    let silent = Silent::start();
    let mut client = Client::new("ca.pem", TlsVerify::LegacyChainOnly);
    client.timeout = T_SHORT;
    let h = handle(&silent.addr, &client);
    let mut seen = Seen::default();
    assert!(run_until(&h, &mut seen, WAIT, |h, _| h.state()
        == State::SslConnecting.code()));
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s.has_rc(ZOPERATIONTIMEOUT)));
    let fired = seen.first_rc(ZOPERATIONTIMEOUT).unwrap();
    let accepted = silent.accepts()[0];
    let waited = fired.duration_since(accepted);
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_millis(1_600),
        "the timeout fired after {waited:?}"
    );
    assert!(seen.log_pos(LogSite::SockTimedOut).is_some());
    assert!(!seen.has_rc(ZSSLCONNECTIONERROR));
    // The next attempt connects again.
    assert!(run_until(&h, &mut seen, WAIT, |_, _| silent
        .accepts()
        .len()
        >= 2));
    close(&h, &mut seen);
}

#[test]
fn missing_ca_file_parks_the_attempt_until_the_receive_timeout() {
    // Rule: a CA file that does not load gives ZSSLCONNECTIONERROR once
    // and the "Failed to load CA file" line. C keeps the socket and does
    // not tear down, so the next attempt comes at the receive timeout
    // with ZOPERATIONTIMEOUT (zookeeper.c init_ssl_for_socket and
    // zookeeper_interest).
    let silent = Silent::start();
    let mut client = Client::new("ca.pem", TlsVerify::LegacyChainOnly);
    client.ca = LegacyPath::new(b"/nonexistent/zk-tls-test/ca.pem".to_vec());
    client.timeout = T_SHORT;
    let h = handle(&silent.addr, &client);
    let mut seen = Seen::default();
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s.has_rc(ZSSLCONNECTIONERROR)));
    let failed = seen.first_rc(ZSSLCONNECTIONERROR).unwrap();
    let ca_line = seen.log_pos(LogSite::TlsCaFile).expect("the CA file line");
    assert!(seen.log_pos(LogSite::SockTlsConnect).is_none());
    // No teardown: the attempt stays until the receive timeout.
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s.has_rc(ZOPERATIONTIMEOUT)));
    let fired = seen.first_rc(ZOPERATIONTIMEOUT).unwrap();
    let rcs: Vec<i32> = seen.rcs.iter().map(|&(_, r)| r).collect();
    assert_eq!(
        rcs.iter().filter(|&&r| r == ZSSLCONNECTIONERROR).count(),
        1,
        "the parked attempt gives the rc once before the timeout: {rcs:?}"
    );
    let waited = fired.duration_since(failed);
    assert!(
        waited >= Duration::from_millis(850) && waited < Duration::from_millis(1_600),
        "the failover came after {waited:?}"
    );
    let timed_out = seen
        .log_pos(LogSite::SockTimedOut)
        .expect("the timeout line");
    assert!(ca_line < timed_out);
    assert_eq!(silent.accepts().len(), 1);
    assert!(run_until(&h, &mut seen, WAIT, |_, _| silent
        .accepts()
        .len()
        >= 2));
    close(&h, &mut seen);
}

#[test]
fn graceful_close_sends_close_notify() {
    // Rule: the final close sends close_notify after the close flush. C
    // calls SSL_free with no SSL_shutdown (zookeeper.c close_zsock). The
    // Rust driver sends the alert. The server waits for it after its
    // CLOSE reply.
    let acc = acceptor("server")
        .close_notify(false)
        .linger(Duration::from_secs(2))
        .build()
        .unwrap();
    let server = tls_server(Arc::clone(&acc));
    let h = handle(
        &server.connect_string(),
        &Client::new("ca.pem", TlsVerify::LegacyChainOnly),
    );
    let mut seen = Seen::default();
    assert!(connected(&h, &mut seen));
    assert_eq!(close(&h, &mut seen), ZOK);
    assert!(acc.wait_sessions(WAIT, |s| s.first().is_some_and(|s| s.peer_end.is_some())));
    assert_eq!(acc.sessions()[0].peer_end, Some(PeerEnd::CloseNotify));
}

#[test]
fn teardown_sends_no_close_notify() {
    // Rule: a teardown closes the socket with no close_notify. A reply
    // with a wrong xid is a teardown
    // (zookeeper.c check_events, ZRUNTIMEINCONSISTENCY).
    let acc = acceptor("server").build().unwrap();
    let server = tls_server(Arc::clone(&acc));
    server.add_rule(
        Rule::on_request()
            .op(opcode::EXISTS)
            .then(Action::RewriteXid(4_242)),
    );
    let h = handle(
        &server.connect_string(),
        &Client::new("ca.pem", TlsVerify::LegacyChainOnly),
    );
    let mut seen = Seen::default();
    assert!(connected(&h, &mut seen));
    let mut ob = h.outbox();
    h.submit(exists(1), &mut ob).ok().unwrap();
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s
        .result_pos(1)
        .is_some()));
    assert_ne!(seen.result_pos(1).unwrap().1, ZOK);
    assert!(acc.wait_sessions(WAIT, |s| s.first().is_some_and(|s| s.peer_end.is_some())));
    assert_eq!(acc.sessions()[0].peer_end, Some(PeerEnd::Eof));
    close(&h, &mut seen);
}

/// Sends a request that the server answers before it closes, and checks
/// that the reply is processed before the end of the stream.
fn reply_then_close(server_close_notify: bool) {
    let acc = acceptor("server")
        .close_notify(server_close_notify)
        .build()
        .unwrap();
    let server = tls_server(Arc::clone(&acc));
    server.add_rule(
        Rule::on_request()
            .op(opcode::EXISTS)
            .then(Action::Model)
            .then(Action::Close),
    );
    let h = handle(
        &server.connect_string(),
        &Client::new("ca.pem", TlsVerify::LegacyChainOnly),
    );
    let mut seen = Seen::default();
    assert!(connected(&h, &mut seen));
    let mut ob = h.outbox();
    h.submit(exists(1), &mut ob).ok().unwrap();
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s
        .log_pos(LogSite::SockRecvFailed)
        .is_some()));
    // The reply is decoded before the teardown, so it has ZOK and not
    // ZCONNECTIONLOSS. The completion may come after the teardown lines,
    // because st delivers queued completions in the cleanup, as C does
    // (zookeeper.c cleanup, process_completions).
    let (_, rc) = seen.result_pos(1).expect("the reply");
    assert_eq!(rc, ZOK);
    let queued = seen
        .log_pos(LogSite::QueueingAsync)
        .expect("the queue line");
    let eof = seen.log_pos(LogSite::SockRecvFailed).unwrap();
    assert!(queued < eof, "the reply is decoded before the teardown");
    assert!(seen.has_rc(ZCONNECTIONLOSS));
    assert!(acc.wait_sessions(WAIT, |s| {
        s.first()
            .is_some_and(|s| s.sent_close_notify == server_close_notify)
    }));
    close(&h, &mut seen);
}

/// A close_notify after a buffered reply ends the session only after the
/// reply. C can stall on such a reply until more bytes arrive.
#[test]
fn data_phase_close_notify_comes_after_the_buffered_reply() {
    // Rule: the frame loop handles all decrypted plaintext first. The
    // latched end acts after the loop and gives Eof.
    reply_then_close(true);
}

#[test]
fn data_phase_eof_comes_after_the_buffered_reply() {
    // Rule: as above for a FIN with no close_notify. A TCP end with no
    // alert is also Eof, not a TLS data error.
    reply_then_close(false);
}

#[test]
fn mutual_tls_sends_the_client_certificate() {
    // Rule: the drop-in identity is the cert and key files of the
    // connect string. The server asks for a certificate from ca.pem
    // (zookeeper.c init_ssl_for_socket, SSL_CTX_use_certificate_chain_file).
    let acc = acceptor("server")
        .client_auth_ca_pem_file(fixture("ca.pem"))
        .unwrap()
        .build()
        .unwrap();
    let server = tls_server(Arc::clone(&acc));
    let mut client = Client::new("ca.pem", TlsVerify::LegacyChainOnly);
    client.identity = true;
    let h = handle(&server.connect_string(), &client);
    let mut seen = Seen::default();
    assert!(connected(&h, &mut seen));
    let mut ob = h.outbox();
    h.submit(exists(1), &mut ob).ok().unwrap();
    assert!(run_until(&h, &mut seen, WAIT, |_, s| s
        .result_pos(1)
        .is_some()));
    assert_eq!(seen.result_pos(1).unwrap().1, ZOK);
    let s = &acc.sessions()[0];
    assert_eq!(s.handshake, Some(Ok(())));
    assert!(s.client_cert);
    assert_eq!(close(&h, &mut seen), ZOK);
}

#[test]
fn mutual_tls_without_a_client_certificate_never_connects() {
    // Rule: a server that requires a client certificate rejects a client
    // with none, so the session does not connect.
    let acc = acceptor("server")
        .client_auth_ca_pem_file(fixture("ca.pem"))
        .unwrap()
        .build()
        .unwrap();
    let server = tls_server(Arc::clone(&acc));
    let h = handle(
        &server.connect_string(),
        &Client::new("ca.pem", TlsVerify::LegacyChainOnly),
    );
    let mut seen = Seen::default();
    // The record lock is not held while the client runs.
    assert!(common::wait_until(WAIT, || {
        round(&h, &mut seen);
        acc.sessions()
            .first()
            .is_some_and(|s| matches!(s.handshake, Some(Err(_))))
    }));
    run_until(&h, &mut seen, Duration::from_millis(300), |_, _| false);
    assert_ne!(h.state(), State::Connected.code());
    assert!(!acc.sessions()[0].client_cert);
    close(&h, &mut seen);
}
