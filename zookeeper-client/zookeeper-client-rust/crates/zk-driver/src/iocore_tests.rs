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

//! Tests of `IoCore`.
//!
//! The step functions are `pub(crate)`, so these tests are unit tests
//! of the crate, not files in `tests/`.
//!
//! - The socket-pair tests install the transport directly. The driver end
//!   of `testutil::socket_pair` replaces the TCP connect, and proto calls
//!   by hand replace the resolver loop. `NullTls` replaces the TLS
//!   session. These tests do not depend on the socket or TLS modules.
//! - The fake-server tests drive one handle in the st way with real
//!   sockets, `TcpSock::open` and the resolver loop.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use rustix::event::{PollFd, PollFlags};
use zk_fakeserver::FakeServer;
use zk_proto::{Compat, Connection, DriverMode, LogLevel, LogSite, Millis, State};
use zk_testkit::hooks::{LevelFilter, SharedDefaultWatcher};
use zk_testkit::rng::SeededRng;
use zk_testkit::tokens::TestTokens;

use crate::host::HostLeaves;
use crate::iocore::{DeferPolicy, InterestOut, IoCore, Progress};
use crate::net::poll::{Poll, PollEvents, ZOOKEEPER_READ, ZOOKEEPER_WRITE};
use crate::outbox::{Flavor, Item, Outbox, discard_item};
use crate::state::{Core, Env};
use crate::sync::{Mutex, Unlocked};
use crate::testutil::{RealPoll, TestHost, test_config};

/// One st-style handle over a fake server.
struct Harness {
    host: Arc<TestHost>,
    env: Env<TestTokens>,
    core: Mutex<Core<TestTokens>>,
    io: IoCore,
}

impl Harness {
    fn new(server: &FakeServer) -> Self {
        let host = Arc::new(TestHost::new());
        host.set_log_level(Some(LogLevel::Debug));
        host.set_addrs(b"127.0.0.1", vec![server.addr()]);
        let conn = Connection::new(
            test_config(server.connect_string().as_bytes()),
            Compat::LEGACY_C,
            DriverMode::ST,
            Box::new(SeededRng::new(1)),
            Box::new(LevelFilter::up_to(LogLevel::Debug)),
            Box::new(SharedDefaultWatcher::new(None)),
            Millis(0),
        );
        let leaves: Arc<dyn HostLeaves<TestTokens>> = host.clone();
        let mut env = Env::new(leaves);
        env.poll = Arc::new(RealPoll);
        Self {
            host,
            env,
            core: Mutex::new(Core::new(Box::new(conn))),
            io: IoCore::new(),
        }
    }

    /// Runs one interest call to its end, draining at each `More`.
    fn interest(&mut self) -> InterestOut {
        let cx = self
            .env
            .step_ctx(&self.core, Flavor::St, DeferPolicy::NONE, None, None, None);
        let mut proof = Unlocked::new_at_entry();
        let mut ob = Outbox::new();
        let mut out = InterestOut::UNWRITTEN;
        let mut p = self.io.interest_step(&cx, &mut proof, &mut ob, &mut out);
        while p == Progress::More {
            ob.finish(&*self.host);
            p = self.io.resume(&cx, &mut proof, &mut ob, &mut out);
        }
        ob.finish(&*self.host);
        out
    }

    /// Polls the interest, then runs one process call to its end.
    fn process(&mut self, out: InterestOut) -> Progress {
        let events = self.poll(out);
        let cx = self
            .env
            .step_ctx(&self.core, Flavor::St, DeferPolicy::NONE, None, None, None);
        let mut proof = Unlocked::new_at_entry();
        let mut ob = Outbox::new();
        let mut unused = InterestOut::UNWRITTEN;
        let mut p = self.io.process_step(&cx, &mut proof, events, &mut ob);
        while p == Progress::More {
            ob.finish(&*self.host);
            p = self.io.resume(&cx, &mut proof, &mut ob, &mut unused);
        }
        ob.finish(&*self.host);
        p
    }

    fn poll(&self, out: InterestOut) -> PollEvents {
        if out.fd < 0 {
            return PollEvents::NONE;
        }
        let mut flags = PollFlags::empty();
        if out.bits & ZOOKEEPER_READ != 0 {
            flags |= PollFlags::IN;
        }
        if out.bits & ZOOKEEPER_WRITE != 0 {
            flags |= PollFlags::OUT;
        }
        let sock = self.io.conn.sock().unwrap();
        let mut fds = [PollFd::new(sock, flags)];
        let timeout = i32::try_from(out.timeout_ms.clamp(0, 50)).unwrap();
        RealPoll.poll(&mut fds, timeout).unwrap();
        let r = fds[0].revents();
        let mut bits = 0;
        if r.intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP) {
            bits |= ZOOKEEPER_READ;
        }
        if r.intersects(PollFlags::OUT | PollFlags::ERR | PollFlags::HUP) {
            bits |= ZOOKEEPER_WRITE;
        }
        PollEvents::from_bits(bits)
    }

    fn state(&self) -> State {
        let mut proof = Unlocked::new_at_entry();
        self.core
            .lock(&mut proof)
            .conn
            .as_ref()
            .map_or(State::Closed, |c| c.state())
    }

    /// Runs interest and process until `state` or 200 rounds.
    fn run_until(&mut self, state: State) -> bool {
        for _ in 0..200 {
            if self.state() == state {
                return true;
            }
            let out = self.interest();
            self.process(out);
        }
        self.state() == state
    }
}

#[test]
fn plaintext_session_connects() {
    let server = FakeServer::start().unwrap();
    let mut h = Harness::new(&server);
    assert!(h.run_until(State::Connected));
    assert_eq!(server.cluster().sessions().len(), 1);
    assert_eq!(h.host.stored_ids().len(), 1);
}

#[test]
fn dropped_connection_reconnects() {
    let server = FakeServer::start().unwrap();
    let mut h = Harness::new(&server);
    assert!(h.run_until(State::Connected));
    server.drop_connections();
    // The teardown sets state 0 and the next interest call reconnects.
    // A round can pass through Connecting, so the test checks for any
    // state other than Connected.
    let mut lost = false;
    for _ in 0..200 {
        let out = h.interest();
        h.process(out);
        if h.state() != State::Connected {
            lost = true;
            break;
        }
    }
    assert!(lost, "the drop is not seen");
    assert!(h.run_until(State::Connected));
    // The client resumes the same session.
    assert_eq!(server.cluster().sessions().len(), 1);
}

// ---------------------------------------------------------------------
// Socket-pair tests. They install the transport directly, so they run
// with no `TcpSock::open`, no resolver loop, no probe and no RustixPoll.
// ---------------------------------------------------------------------

use std::os::fd::AsFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustix::io::Errno;
use zk_jute::JBuffer;
use zk_jute::proto::ConnectResponse;
use zk_proto::rc::{
    ZCONNECTIONLOSS, ZINVALIDSTATE, ZNOTHING, ZOK, ZOPERATIONTIMEOUT, ZSYSTEMERROR,
};
use zk_proto::{Action, ConnectStart, HostResolution, TlsResourceAt};
use zk_testkit::server::codec::connect_response_frame;

use crate::clock::{Clock, TestClock};
use crate::iocore::{Cont, FlushError, Job, JobCtx, JobDone, Transport, run_job, wait_writable};
use crate::net::sock::TcpSock;
use crate::net::tls::{TlsConfigStep, TlsConnector, TlsSetupError};
use crate::testutil::{FakeConnector, socket_pair};

/// A poll that moves the test clock past the timeout and gives a fixed
/// result. It stands in for a peer that never drains its socket.
struct ClockPoll {
    clock: Arc<TestClock>,
    result: Result<usize, Errno>,
    calls: AtomicUsize,
}

impl Poll for ClockPoll {
    fn poll(&self, _fds: &mut [PollFd<'_>], timeout_ms: i32) -> rustix::io::Result<usize> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let ms = u64::try_from(timeout_ms).unwrap_or(0);
        self.clock.advance(ms + 1);
        self.result
    }
}

/// One st handle with a socket pair in place of the TCP connect.
struct Rig {
    host: Arc<TestHost>,
    clock: Arc<TestClock>,
    connector: Arc<FakeConnector>,
    env: Env<TestTokens>,
    core: Mutex<Core<TestTokens>>,
    io: IoCore,
    peer: TcpSock,
    defer: DeferPolicy,
    flavor: Flavor,
}

/// The ConnectResponse frame of an accepted session.
fn accept_frame() -> Vec<u8> {
    connect_response_frame(
        &ConnectResponse {
            protocol_version: 0,
            time_out: 10_000,
            session_id: 0x1234,
            passwd: JBuffer::Bytes(vec![7; 16]),
            read_only: false,
        },
        false,
    )
}

fn nonblocking(sock: &TcpSock) {
    crate::net::sock::set_nonblocking(sock.as_fd()).unwrap();
}

impl Rig {
    /// Makes the handle and drives proto by hand to the `Connect` action
    /// with `ConnectStart::InProgress`. The driver end of a socket pair
    /// waits in `Transport::Connecting`.
    fn new(tls: bool, failures: Vec<TlsSetupError>) -> Self {
        Self::with_compat(tls, failures, Compat::LEGACY_C)
    }

    /// Makes the rig as [`Rig::new`] does, with the given compat.
    fn with_compat(tls: bool, failures: Vec<TlsSetupError>, compat: Compat) -> Self {
        Self::with_mode(tls, failures, compat, DriverMode::ST)
    }

    /// Makes the rig as [`Rig::new`] does, with the given compat and
    /// driver mode.
    fn with_mode(
        tls: bool,
        failures: Vec<TlsSetupError>,
        compat: Compat,
        mode: DriverMode,
    ) -> Self {
        let host = Arc::new(TestHost::new());
        host.set_log_level(Some(LogLevel::Debug));
        let clock = Arc::new(TestClock::new(Millis(0)));
        let mut cfg = test_config(b"127.0.0.1:2181");
        cfg.resolve_delay_ms = -1;
        cfg.tls = tls;
        let mut conn = Connection::new(
            cfg,
            compat,
            mode,
            Box::new(SeededRng::new(1)),
            Box::new(LevelFilter::up_to(LogLevel::Debug)),
            Box::new(SharedDefaultWatcher::new(None)),
            Millis(0),
        );
        let (ours, peer) = socket_pair();
        nonblocking(&ours);
        nonblocking(&peer);
        let addr = peer.local_addr().unwrap();
        let now = Millis(0);
        conn.begin_interest(now).unwrap();
        let mut target = None;
        while let Some(a) = conn.poll_action(now) {
            match a {
                Action::Resolve { generation, .. } => {
                    let r = HostResolution {
                        host: 0,
                        result: Ok(vec![addr]),
                        skipped_families: vec![],
                    };
                    conn.handle_host_resolved(generation, r, now);
                    let _ = conn.handle_resolved(generation, false, now);
                }
                Action::Connect { endpoint, tls } => {
                    conn.handle_connect_started(ConnectStart::InProgress, now);
                    target = Some((endpoint, tls));
                    break;
                }
                other => panic!("unexpected action {other:?}"),
            }
        }
        let _ = conn.finish_interest(now);
        let (ep, verify) = target.expect("a Connect action");
        assert_eq!(verify.is_some(), tls);
        assert!(conn.has_transport());
        let connector = Arc::new(FakeConnector::new(failures));
        let leaves: Arc<dyn HostLeaves<TestTokens>> = host.clone();
        let mut env = Env::new(leaves);
        env.poll = Arc::new(RealPoll);
        env.clock = clock.clone();
        env.cfg.close_wait_ms = 20;
        if tls {
            let c: Arc<dyn TlsConnector> = connector.clone();
            env.tls = Some(c);
        }
        let mut io = IoCore::new();
        io.conn = Transport::Connecting {
            sock: ours,
            ep,
            tls: verify,
        };
        Self {
            host,
            clock,
            connector,
            env,
            core: Mutex::new(Core::new(Box::new(conn))),
            io,
            peer,
            defer: DeferPolicy::NONE,
            flavor: Flavor::St,
        }
    }

    fn cx(&self) -> crate::iocore::StepCtx<'_, TestTokens> {
        self.env
            .step_ctx(&self.core, self.flavor, self.defer, None, None, None)
    }

    /// Runs one process call to its end. It returns the result and the
    /// number of barriers.
    fn process(&mut self, events: PollEvents) -> (Progress, usize) {
        if events.read {
            self.wait_readable();
        }
        let cx = self
            .env
            .step_ctx(&self.core, self.flavor, self.defer, None, None, None);
        let mut proof = Unlocked::new_at_entry();
        let mut ob = Outbox::new();
        let mut unused = InterestOut::UNWRITTEN;
        let mut mores = 0;
        let mut p = self.io.process_step(&cx, &mut proof, events, &mut ob);
        while p == Progress::More {
            mores += 1;
            assert!(mores < 100, "no end of barriers");
            ob.finish(&*self.host);
            p = self.io.resume(&cx, &mut proof, &mut ob, &mut unused);
        }
        ob.finish(&*self.host);
        (p, mores)
    }

    /// Runs one interest call to its end.
    fn interest(&mut self) -> (InterestOut, Progress) {
        let cx = self
            .env
            .step_ctx(&self.core, self.flavor, self.defer, None, None, None);
        let mut proof = Unlocked::new_at_entry();
        let mut ob = Outbox::new();
        let mut out = InterestOut::UNWRITTEN;
        let mut mores = 0;
        let mut p = self.io.interest_step(&cx, &mut proof, &mut ob, &mut out);
        while p == Progress::More {
            mores += 1;
            assert!(mores < 100, "no end of barriers");
            ob.finish(&*self.host);
            p = self.io.resume(&cx, &mut proof, &mut ob, &mut out);
        }
        ob.finish(&*self.host);
        (out, p)
    }

    fn state(&self) -> State {
        let mut proof = Unlocked::new_at_entry();
        self.core
            .lock(&mut proof)
            .conn
            .as_ref()
            .map_or(State::Closed, |c| c.state())
    }

    /// Waits up to 200 ms until the driver socket is readable, so a
    /// READ event follows the bytes that the peer sent.
    fn wait_readable(&self) {
        if let Some(sock) = self.io.conn.sock() {
            let mut fds = [PollFd::new(sock, PollFlags::IN)];
            let _ = RealPoll.poll(&mut fds, 200);
        }
    }

    fn has_transport(&self) -> bool {
        let mut proof = Unlocked::new_at_entry();
        self.core
            .lock(&mut proof)
            .conn
            .as_ref()
            .is_some_and(|c| c.has_transport())
    }

    fn queue_close_op(&self) -> bool {
        let mut proof = Unlocked::new_at_entry();
        self.core
            .lock(&mut proof)
            .conn
            .as_deref_mut()
            .unwrap()
            .queue_close_op()
    }

    /// Sends `bytes` from the peer end.
    fn peer_send(&self, bytes: &[u8]) {
        let mut off = 0;
        while off < bytes.len() {
            match self.peer.send(&bytes[off..]) {
                Ok(n) => off += n,
                Err(Errno::WOULDBLOCK | Errno::INTR) => {}
                Err(e) => panic!("peer send: {e}"),
            }
        }
    }

    /// Reads what the driver sent, waiting up to 1 s for the first byte.
    /// It returns the bytes and true at EOF or a reset.
    /// It stops when no byte comes for 50 ms.
    fn peer_recv(&self) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut wait = 1000;
        loop {
            let mut fds = [PollFd::new(&self.peer, PollFlags::IN)];
            if RealPoll.poll(&mut fds, wait).unwrap() == 0 {
                return (out, false);
            }
            wait = 50;
            loop {
                match self.peer.recv(&mut buf) {
                    Ok(0) => return (out, true),
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                    Err(Errno::WOULDBLOCK) => break,
                    Err(Errno::INTR) => {}
                    Err(_) => return (out, true),
                }
            }
        }
    }

    /// Gives one WRITE event to the plaintext connect and returns the
    /// ConnectRequest frame that the peer got.
    fn plain_established(&mut self) -> Vec<u8> {
        let (p, _) = self.process(PollEvents::from_bits(ZOOKEEPER_WRITE));
        assert_eq!(p, Progress::Done(ZOK));
        assert!(matches!(self.io.conn, Transport::Plain(_)));
        let (req, eof) = self.peer_recv();
        assert!(!eof);
        assert!(req.len() > 4);
        let len = i32::from_be_bytes(req[..4].try_into().unwrap());
        assert_eq!(usize::try_from(len).unwrap(), req.len() - 4);
        req
    }

    /// Takes a plaintext rig to `Connected`.
    fn plain_connected(&mut self) {
        let _req = self.plain_established();
        self.peer_send(&accept_frame());
        for _ in 0..4 {
            if self.state() == State::Connected {
                break;
            }
            let _ = self.process(PollEvents::from_bits(ZOOKEEPER_READ));
        }
        assert_eq!(self.state(), State::Connected);
    }

    /// Takes a TLS rig through the ClientHello and the handshake, then
    /// to `Connected`.
    fn tls_connected(&mut self) {
        let (p, _) = self.process(PollEvents::from_bits(ZOOKEEPER_WRITE));
        assert_eq!(p, Progress::Done(ZOK));
        assert_eq!(self.peer_recv().0, b"HELLO");
        let mut flight = b"s".to_vec();
        flight.extend_from_slice(&accept_frame());
        self.peer_send(&flight);
        let (p, _) = self.process(PollEvents::from_bits(ZOOKEEPER_READ));
        assert_eq!(p, Progress::Done(ZOK));
        assert_eq!(self.state(), State::Connected);
        let (req, _) = self.peer_recv();
        assert!(req.len() > 4, "the ConnectRequest went out");
    }
}

fn read_ev() -> PollEvents {
    PollEvents::from_bits(ZOOKEEPER_READ)
}

fn write_ev() -> PollEvents {
    PollEvents::from_bits(ZOOKEEPER_WRITE)
}

#[test]
fn plain_connect_sends_the_connect_request() {
    let mut r = Rig::new(false, vec![]);
    let _req = r.plain_established();
    assert!(r.has_transport());
    assert_ne!(r.state(), State::Connected);
}

#[test]
fn process_without_write_keeps_the_connect_pending() {
    let mut r = Rig::new(false, vec![]);
    let (p, _) = r.process(PollEvents::NONE);
    assert_eq!(p, Progress::Done(ZOK));
    assert!(matches!(r.io.conn, Transport::Connecting { .. }));
}

impl Rig {
    /// Runs one process call as [`Rig::process`] does. It returns the
    /// result and the log sites of the call, in order.
    fn process_sites(&mut self, events: PollEvents) -> (Progress, Vec<LogSite>) {
        if events.read {
            self.wait_readable();
        }
        let cx = self
            .env
            .step_ctx(&self.core, self.flavor, self.defer, None, None, None);
        let mut proof = Unlocked::new_at_entry();
        let mut ob = Outbox::new();
        let mut unused = InterestOut::UNWRITTEN;
        let mut sites = Vec::new();
        let mut mores = 0;
        let mut p = self.io.process_step(&cx, &mut proof, events, &mut ob);
        loop {
            while let Some(item) = ob.pop() {
                match item {
                    Item::Log(rec) => sites.push(rec.site),
                    other => discard_item(&*self.host, other),
                }
            }
            if p != Progress::More {
                break;
            }
            mores += 1;
            assert!(mores < 100, "no end of barriers");
            p = self.io.resume(&cx, &mut proof, &mut ob, &mut unused);
        }
        (p, sites)
    }
}

/// READ with no WRITE while the TCP connect runs reads the frame
/// length, as C does. A peer EOF ends the attempt in this call.
#[test]
fn process_read_without_write_sees_the_peer_eof() {
    let mut r = Rig::new(false, vec![]);
    rustix::net::shutdown(&r.peer, rustix::net::Shutdown::Write).unwrap();
    let (p, sites) = r.process_sites(read_ev());
    assert_eq!(p, Progress::Done(ZCONNECTIONLOSS));
    assert!(!r.has_transport());
    assert!(matches!(r.io.conn, Transport::None));
    assert!(sites.contains(&LogSite::SockRecvFailed), "{sites:?}");
}

/// A reset stands in for a refused connect. The length read fails with
/// an error, and the attempt ends in this call. The log line is the
/// receive line of C, not the SO_ERROR line.
#[test]
#[cfg_attr(miri, ignore = "Miri has no SO_LINGER, which makes the reset peer")]
fn process_read_without_write_sees_a_socket_error() {
    let mut r = Rig::new(false, vec![]);
    reset_peer(&mut r);
    let (p, sites) = r.process_sites(read_ev());
    assert_eq!(p, Progress::Done(ZCONNECTIONLOSS));
    assert!(!r.has_transport());
    assert!(sites.contains(&LogSite::SockRecvFailed), "{sites:?}");
    assert!(!sites.contains(&LogSite::SockRefused), "{sites:?}");
}

/// With no socket error, READ with no WRITE gives ZNOTHING, and the
/// connect stays pending. The step discards early bytes. WRITE then
/// completes the connect as usual.
#[test]
fn process_read_without_write_keeps_a_live_connect() {
    let mut r = Rig::new(false, vec![]);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZNOTHING));
    assert!(matches!(r.io.conn, Transport::Connecting { .. }));
    r.peer_send(b"xy");
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZNOTHING));
    assert!(matches!(r.io.conn, Transport::Connecting { .. }));
    // The early bytes are gone from the socket.
    let sock = r.io.conn.sock().unwrap();
    let mut fds = [PollFd::new(sock, PollFlags::IN)];
    assert_eq!(RealPoll.poll(&mut fds, 0).unwrap(), 0);
    // Bytes that stay in the socket break the length of the accept frame.
    r.plain_connected();
}

/// In state 7 the length read uses the TCP socket, because C has no TLS
/// session yet. The TLS connector does not run.
#[test]
fn tls_process_read_without_write_reads_the_tcp_socket() {
    let mut r = Rig::new(true, vec![]);
    assert_eq!(r.state(), State::SslConnecting);
    rustix::net::shutdown(&r.peer, rustix::net::Shutdown::Write).unwrap();
    let (p, sites) = r.process_sites(read_ev());
    assert_eq!(p, Progress::Done(ZCONNECTIONLOSS));
    assert!(!r.has_transport());
    assert_eq!(r.connector.calls(), 0);
    assert!(sites.contains(&LogSite::SockRecvFailed), "{sites:?}");
}

#[test]
fn response_split_at_every_byte() {
    let mut r = Rig::new(false, vec![]);
    let _req = r.plain_established();
    let frame = accept_frame();
    let last = frame.len() - 1;
    for (i, b) in frame.iter().enumerate() {
        r.peer_send(&[*b]);
        let (p, _) = r.process(read_ev());
        if i < last {
            assert_eq!(p, Progress::Done(ZNOTHING), "byte {i}");
            assert_ne!(r.state(), State::Connected, "byte {i}");
        } else {
            assert_eq!(p, Progress::Done(ZOK));
        }
    }
    assert_eq!(r.state(), State::Connected);
    assert!(r.io.rx_pending.is_empty());
}

#[test]
fn st_reads_the_length_and_the_body_in_one_call() {
    let mut r = Rig::new(false, vec![]);
    let _req = r.plain_established();
    let mut bytes = accept_frame();
    bytes.extend_from_slice(&[0, 0, 0, 16]);
    r.peer_send(&bytes);
    // One read call takes the length and the body of the first frame only.
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.state(), State::Connected);
    assert!(r.io.rx_pending.is_empty());
    // The next call takes the next length. The body is not there yet.
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZNOTHING));
    assert_eq!(r.state(), State::Connected);
}

/// A read that fills its request and leaves the frame open gives more
/// reads in the same call. They stop at the end of that frame.
#[test]
fn mt_reads_the_rest_of_a_frame_in_one_call() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.env.cfg.max_read = 8;
    let _req = r.plain_established();
    let mut bytes = accept_frame();
    bytes.extend_from_slice(&[0, 0, 0, 16]);
    r.peer_send(&bytes);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.state(), State::Connected);
    assert!(r.io.rx_pending.is_empty());
    // The next length stays in the socket for the next call.
    let sock = r.io.conn.sock().unwrap();
    let mut fds = [PollFd::new(sock, PollFlags::IN)];
    assert_eq!(RealPoll.poll(&mut fds, 0).unwrap(), 1);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZNOTHING));
    assert_eq!(r.state(), State::Connected);
}

/// A read of the rest of a frame that blocks stops those reads for that
/// frame. The next call reads once. A complete frame ends the stop.
#[test]
fn mt_stops_reading_the_rest_after_a_blocked_read() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.env.cfg.max_read = 8;
    let _req = r.plain_established();
    let frame = accept_frame();
    assert!(frame.len() > 32);
    r.peer_send(&frame[..16]);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZNOTHING));
    assert!(r.io.rx_more_blocked);
    // Two parts arrive. The call reads one part, and one part stays.
    r.peer_send(&frame[16..32]);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZNOTHING));
    let sock = r.io.conn.sock().unwrap();
    let mut fds = [PollFd::new(sock, PollFlags::IN)];
    assert_eq!(RealPoll.poll(&mut fds, 0).unwrap(), 1);
    r.peer_send(&frame[32..]);
    for _ in 0..8 {
        if r.state() == State::Connected {
            break;
        }
        let _ = r.process(read_ev());
    }
    assert_eq!(r.state(), State::Connected);
    assert!(!r.io.rx_more_blocked);
}

/// st makes its body read after the length read, also when an earlier
/// read of the rest of the frame blocked.
#[test]
fn st_reads_the_body_after_a_blocked_read() {
    let mut r = Rig::new(false, vec![]);
    let _req = r.plain_established();
    r.io.rx_more_blocked = true;
    r.peer_send(&accept_frame());
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.state(), State::Connected);
    assert!(!r.io.rx_more_blocked);
}

/// st reads the body straight into the frame. Only the length goes
/// through `rx`, so the rest of `rx` keeps its old bytes.
#[test]
fn st_reads_the_body_straight_into_the_frame() {
    let mut r = Rig::new(false, vec![]);
    let _req = r.plain_established();
    r.io.rx.fill(0xA5);
    r.peer_send(&accept_frame());
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.state(), State::Connected);
    assert!(r.io.rx[4..].iter().all(|b| *b == 0xA5));
    assert!(r.io.rx_pending.is_empty());
}

/// mt reads the rest of a frame straight into the frame body after its
/// first read into `rx`. So `rx` keeps the bytes of that first read.
#[test]
fn mt_reads_the_rest_straight_into_the_frame() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.env.cfg.max_read = 8;
    let _req = r.plain_established();
    r.io.rx.fill(0xA5);
    let frame = accept_frame();
    assert!(frame.len() > 16);
    r.peer_send(&frame);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.state(), State::Connected);
    assert_eq!(&r.io.rx[..8], &frame[..8]);
    assert!(r.io.rx[8..].iter().all(|b| *b == 0xA5));
}

#[test]
fn native_reads_the_whole_frame_at_once() {
    let mut r = Rig::new(false, vec![]);
    r.flavor = Flavor::Native;
    let _req = r.plain_established();
    r.peer_send(&accept_frame());
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.state(), State::Connected);
}

#[test]
fn barrier_stores_the_continuation_and_resume_ends_it() {
    let mut r = Rig::new(false, vec![]);
    let _req = r.plain_established();
    r.peer_send(&accept_frame());
    r.wait_readable();
    // The frame read connects the session. Its outputs stop the step.
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    let mut ob = Outbox::new();
    let p = r.io.process_step(&cx, &mut proof, read_ev(), &mut ob);
    assert_eq!(p, Progress::More, "the session event is a barrier");
    assert_ne!(r.io.cont, Cont::None);
    // A new step while one is suspended is refused, with no output.
    let mut out = InterestOut::UNWRITTEN;
    let mut ob2 = Outbox::new();
    assert_eq!(
        r.io.interest_step(&cx, &mut proof, &mut ob2, &mut out),
        Progress::Done(ZINVALIDSTATE)
    );
    assert_eq!(out, InterestOut::UNWRITTEN);
    let mut p = p;
    let mut n = 0;
    while p == Progress::More {
        n += 1;
        assert!(n < 100);
        ob.finish(&*r.host);
        p = r.io.resume(&cx, &mut proof, &mut ob, &mut out);
    }
    ob.finish(&*r.host);
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.io.cont, Cont::None);
    assert_eq!(r.state(), State::Connected);
    // A resume with nothing suspended repeats the last rc.
    assert_eq!(
        r.io.resume(&cx, &mut proof, &mut ob, &mut out),
        Progress::Done(ZOK)
    );
}

/// An mt read that proto takes whole goes to proto in place. It does not
/// pass through `rx_pending`, so that buffer gets no memory.
#[test]
fn a_whole_read_does_not_use_rx_pending() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    let _req = r.plain_established();
    r.peer_send(&accept_frame());
    for _ in 0..4 {
        if r.state() == State::Connected {
            break;
        }
        let _ = r.process(read_ev());
    }
    assert_eq!(r.state(), State::Connected);
    assert_eq!(r.io.rx_pending.capacity(), 0);
}

/// One mt read holds a connect response and part of the next length.
/// The auth lockpoint stops the frame loop after the first frame. The rest
/// of the read moves to `rx_pending`, and the resume takes it.
#[test]
fn a_barrier_keeps_the_rest_of_a_fresh_read() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    let _req = r.plain_established();
    let mut bytes = accept_frame();
    bytes.extend_from_slice(&[0, 0]);
    r.peer_send(&bytes);
    r.wait_readable();
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    let mut ob = Outbox::new();
    let mut out = InterestOut::UNWRITTEN;
    let mut p = r.io.process_step(&cx, &mut proof, read_ev(), &mut ob);
    assert_eq!(p, Progress::More, "the auth lockpoint is a barrier");
    assert_eq!(r.io.rx_pending, [0u8, 0]);
    let mut n = 0;
    while p == Progress::More {
        n += 1;
        assert!(n < 100);
        ob.finish(&*r.host);
        p = r.io.resume(&cx, &mut proof, &mut ob, &mut out);
    }
    ob.finish(&*r.host);
    assert_ne!(p, Progress::More);
    assert!(r.io.rx_pending.is_empty());
    assert_eq!(r.state(), State::Connected);
}

/// A negative frame length stops the reads until the receive timeout,
/// with no busy loop.
#[test]
fn negative_length_stalls_the_reader() {
    let mut r = Rig::new(false, vec![]);
    let _req = r.plain_established();
    r.peer_send(&[0xff, 0xff, 0xff, 0xfe]);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZNOTHING));
    assert!(r.io.rx_stalled);
    assert!(r.has_transport());
    // The stalled reader asks for no READ and reads no more bytes.
    let (out, p) = r.interest();
    assert_eq!(p, Progress::Done(ZOK));
    assert!(out.written);
    assert_eq!(out.bits & ZOOKEEPER_READ, 0);
    // A READ event on a stalled reader reads nothing. The call reports
    // no read, so its rc is ZOK.
    r.peer_send(&accept_frame());
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert!(r.io.rx_pending.is_empty());
    assert_ne!(r.state(), State::Connected);
}

#[test]
fn write_interest_while_bytes_wait() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    let (out, _) = r.interest();
    assert!(out.written);
    assert!(out.fd >= 0);
    assert_ne!(out.bits & ZOOKEEPER_READ, 0);
    let base = out.bits & ZOOKEEPER_WRITE;
    // A partly sent frame in the copy buffer asks for WRITE.
    r.io.tx_copy.extend_from_slice(b"rest");
    let (out, _) = r.interest();
    assert_ne!(out.bits & ZOOKEEPER_WRITE, 0);
    assert_eq!(base, 0, "the idle session asks for no WRITE");
}

#[test]
fn tls_write_interest_while_ciphertext_waits() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    let (out, _) = r.interest();
    assert_eq!(out.bits & ZOOKEEPER_WRITE, 0);
    if let Transport::Tls(t) = &mut r.io.conn {
        t.ct_out.extend_from_slice(b"rest");
    }
    let (out, _) = r.interest();
    assert_ne!(out.bits & ZOOKEEPER_WRITE, 0);
}

#[test]
fn connecting_socket_asks_for_write() {
    let mut r = Rig::new(false, vec![]);
    let (out, p) = r.interest();
    assert_eq!(p, Progress::Done(ZOK));
    assert!(out.fd >= 0);
    assert_ne!(out.bits & ZOOKEEPER_WRITE, 0);
}

#[test]
fn flush_once_fails_after_shutdown() {
    let mut r = Rig::new(false, vec![]);
    // Make the transport plaintext with the ConnectRequest unsent.
    let sock = match std::mem::replace(&mut r.io.conn, Transport::None) {
        Transport::Connecting { sock, .. } => sock,
        _ => unreachable!(),
    };
    {
        let mut proof = Unlocked::new_at_entry();
        let mut g = r.core.lock(&mut proof);
        let c = g.conn.as_deref_mut().unwrap();
        c.handle_tcp_connected(Millis(0));
        c.handle_transport_ready(Millis(0));
    }
    rustix::net::shutdown(&sock, rustix::net::Shutdown::Write).unwrap();
    r.io.conn = Transport::Plain(sock);
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert!(!r.io.flush_once(&cx, &mut proof));
}

#[test]
fn flush_once_sends_and_succeeds() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert!(r.io.flush_once(&cx, &mut proof));
}

#[test]
fn tls_hello_goes_out_on_write() {
    let mut r = Rig::new(true, vec![]);
    let (p, _) = r.process(write_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert_eq!(r.connector.calls(), 1);
    assert!(matches!(r.io.conn, Transport::Tls(_)));
    assert_eq!(r.peer_recv().0, b"HELLO");
    // The handshake asks for READ.
    let (out, _) = r.interest();
    assert_ne!(out.bits & ZOOKEEPER_READ, 0);
}

#[test]
fn tls_handshake_failure_sends_no_alert() {
    let mut r = Rig::new(true, vec![]);
    let _ = r.process(write_ev());
    assert_eq!(r.peer_recv().0, b"HELLO");
    r.peer_send(b"F");
    let (p, _) = r.process(read_ev());
    let Progress::Done(rc) = p else {
        panic!("{p:?}")
    };
    assert_ne!(rc, ZOK);
    assert!(!r.has_transport());
    assert!(matches!(r.io.conn, Transport::None));
    let (bytes, eof) = r.peer_recv();
    assert!(bytes.is_empty());
    assert!(eof);
}

#[test]
fn tls_handshake_alert_goes_to_the_peer() {
    let mut r = Rig::new(true, vec![]);
    let _ = r.process(write_ev());
    assert_eq!(r.peer_recv().0, b"HELLO");
    r.peer_send(b"A");
    let (p, _) = r.process(read_ev());
    assert!(matches!(p, Progress::Done(rc) if rc != ZOK));
    assert!(!r.has_transport());
    let (bytes, eof) = r.peer_recv();
    assert_eq!(bytes, b"ALERT");
    assert!(eof);
}

#[test]
fn tls_data_latch_acts_after_the_frames() {
    let mut r = Rig::new(true, vec![]);
    let _ = r.process(write_ev());
    assert_eq!(r.peer_recv().0, b"HELLO");
    r.peer_send(b"s");
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZOK));
    let (req, _) = r.peer_recv();
    assert!(req.len() > 4);
    // The frame comes before the latch, so the session connects first.
    let mut flight = accept_frame();
    flight.push(b'!');
    r.peer_send(&flight);
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZCONNECTIONLOSS));
    assert_eq!(r.host.stored_ids().len(), 1);
    assert!(!r.has_transport());
    assert!(matches!(r.io.conn, Transport::None));
}

#[test]
fn tls_response_split_at_every_byte() {
    let mut r = Rig::new(true, vec![]);
    let _ = r.process(write_ev());
    let _ = r.peer_recv();
    r.peer_send(b"s");
    let _ = r.process(read_ev());
    let _ = r.peer_recv();
    let frame = accept_frame();
    let last = frame.len() - 1;
    for (i, b) in frame.iter().enumerate() {
        r.peer_send(&[*b]);
        let (p, _) = r.process(read_ev());
        if i < last {
            assert_eq!(p, Progress::Done(ZNOTHING), "byte {i}");
        } else {
            assert_eq!(p, Progress::Done(ZOK));
        }
    }
    assert_eq!(r.state(), State::Connected);
}

#[test]
fn tls_last_flight_frames_are_read_in_the_handshake_step() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    assert!(r.has_transport());
}

#[test]
fn tls_peer_eof_is_a_teardown() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    rustix::net::shutdown(&r.peer, rustix::net::Shutdown::Write).unwrap();
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZCONNECTIONLOSS));
    assert!(!r.has_transport());
}

#[test]
fn tls_config_failure_parks_the_socket() {
    let mut r = Rig::new(
        true,
        vec![TlsSetupError::Config {
            step: TlsConfigStep::CaFile,
        }],
    );
    let _ = r.process(write_ev());
    assert!(matches!(r.io.conn, Transport::Parked(_)));
    assert_eq!(r.connector.calls(), 1);
    // The parked socket asks for READ only, to see the peer EOF.
    let (out, _) = r.interest();
    assert!(out.fd >= 0);
    assert_eq!(out.bits & ZOOKEEPER_WRITE, 0);
    rustix::net::shutdown(&r.peer, rustix::net::Shutdown::Write).unwrap();
    let (p, _) = r.process(read_ev());
    assert_eq!(p, Progress::Done(ZCONNECTIONLOSS));
    assert!(!r.has_transport());
    assert!(matches!(r.io.conn, Transport::None));
}

#[test]
fn tls_resource_failure_is_a_teardown() {
    let mut r = Rig::new(
        true,
        vec![TlsSetupError::Resource {
            at: TlsResourceAt::ConnectionNew,
        }],
    );
    let (p, _) = r.process(write_ev());
    assert!(matches!(p, Progress::Done(rc) if rc != ZOK));
    assert!(!r.has_transport());
    assert!(matches!(r.io.conn, Transport::None));
}

#[test]
fn deferred_new_conn_waits_for_the_job() {
    let mut r = Rig::new(true, vec![]);
    r.defer = DeferPolicy {
        resolve: false,
        new_conn: true,
        probe: false,
    };
    let (p, _) = r.process(write_ev());
    assert_eq!(p, Progress::Wait);
    assert_eq!(r.connector.calls(), 0);
    // Both steps wait while the job runs.
    assert_eq!(r.process(read_ev()).0, Progress::Wait);
    assert_eq!(r.interest().1, Progress::Wait);
    let jobs = r.io.take_jobs();
    assert_eq!(jobs.len(), 1);
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    let jcx = JobCtx {
        host: &*r.host,
        probe: cx.probe_ctx(),
    };
    let mut done = None;
    for job in jobs {
        assert!(matches!(job, Job::NewConn { .. }));
        done = Some(run_job(&jcx, &proof, job));
    }
    assert_eq!(r.connector.calls(), 1);
    let mut ob = Outbox::new();
    let mut out = InterestOut::UNWRITTEN;
    let mut p =
        r.io.complete_job(&cx, &mut proof, done.unwrap(), &mut ob, &mut out);
    while p == Progress::More {
        ob.finish(&*r.host);
        p = r.io.resume(&cx, &mut proof, &mut ob, &mut out);
    }
    ob.finish(&*r.host);
    assert_eq!(p, Progress::Done(ZOK));
    assert!(matches!(r.io.conn, Transport::Tls(_)));
    assert_eq!(r.peer_recv().0, b"HELLO");
}

#[test]
fn deferred_new_conn_failure_is_a_teardown() {
    let mut r = Rig::new(
        true,
        vec![TlsSetupError::Resource {
            at: TlsResourceAt::ContextNew,
        }],
    );
    r.defer = DeferPolicy::ALL;
    assert_eq!(r.process(write_ev()).0, Progress::Wait);
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    let jcx = JobCtx {
        host: &*r.host,
        probe: cx.probe_ctx(),
    };
    let mut jobs = r.io.take_jobs();
    assert_eq!(jobs.len(), 1);
    let done = run_job(&jcx, &proof, jobs.remove(0));
    let mut ob = Outbox::new();
    let mut out = InterestOut::UNWRITTEN;
    let mut p = r.io.complete_job(&cx, &mut proof, done, &mut ob, &mut out);
    while p == Progress::More {
        ob.finish(&*r.host);
        p = r.io.resume(&cx, &mut proof, &mut ob, &mut out);
    }
    ob.finish(&*r.host);
    assert!(matches!(p, Progress::Done(rc) if rc != ZOK));
    assert!(!r.has_transport());
    assert!(matches!(r.io.conn, Transport::None));
    assert!(r.io.job.is_none());
}

#[test]
fn a_closing_connection_runs_no_resolve() {
    for defer in [DeferPolicy::NONE, DeferPolicy::DNS_THREAD] {
        let mut r = Rig::with_compat(false, vec![], Compat::NATIVE);
        r.defer = defer;
        r.plain_connected();
        {
            let mut proof = Unlocked::new_at_entry();
            let mut g = r.core.lock(&mut proof);
            g.conn.as_deref_mut().unwrap().begin_close(Millis(0));
            g.set_servers = Some((9, test_config(b"127.0.0.1:2181").hosts));
        }
        let (_out, p) = r.interest();
        assert_ne!(p, Progress::Wait);
        assert_eq!(r.host.resolves(), 0);
        assert!(r.io.job.is_none());
        assert!(r.io.deferred.is_empty());
        assert!(
            r.core
                .lock(&mut Unlocked::new_at_entry())
                .set_servers
                .is_none()
        );
    }
}

/// Makes a resolve result with one failed host. Proto logs the
/// getaddrinfo ERROR line only for the newest generation.
fn failed_resolution(generation: u64) -> JobDone {
    JobDone::Resolved {
        generation,
        results: vec![HostResolution {
            host: 0,
            result: Err(zk_proto::ResolveError {
                gai_rc: -2,
                errno: 0,
            }),
            skipped_families: vec![],
        }],
    }
}

/// Returns true when `ob` holds the getaddrinfo ERROR line.
fn has_gai_line(ob: &mut Outbox<TestTokens>) -> bool {
    let mut found = false;
    while let Some(item) = ob.pop() {
        if let Item::Log(rec) = item {
            found = found
                || matches!(
                    rec.site,
                    LogSite::ResolveGai | LogSite::ResolveGaiErrno | LogSite::ResolveWin32
                );
        }
    }
    found
}

impl Rig {
    /// Makes a connected native rig with the DNS thread policy and a
    /// resolve on each interest call.
    fn dns_connected() -> Self {
        let mut r = Rig::with_compat(false, vec![], Compat::NATIVE);
        r.defer = DeferPolicy::DNS_THREAD;
        r.plain_connected();
        let mut proof = Unlocked::new_at_entry();
        let mut g = r.core.lock(&mut proof);
        assert_eq!(g.conn.as_deref_mut().unwrap().set_resolve_delay(0), ZOK);
        drop(g);
        r
    }

    /// Gives a background resolve result to the core and drains.
    fn complete_bg(&mut self, done: JobDone) -> (Progress, Outbox<TestTokens>) {
        let cx = self
            .env
            .step_ctx(&self.core, self.flavor, self.defer, None, None, None);
        let mut proof = Unlocked::new_at_entry();
        let mut ob = Outbox::new();
        let mut out = InterestOut::UNWRITTEN;
        let mut p = self
            .io
            .complete_resolve(&cx, &mut proof, done, &mut ob, &mut out);
        let mut mores = 0;
        while p == Progress::More {
            mores += 1;
            assert!(mores < 100, "no end of barriers");
            p = self.io.resume(&cx, &mut proof, &mut ob, &mut out);
        }
        (p, ob)
    }
}

#[test]
fn a_resolve_with_an_open_socket_runs_in_the_background() {
    let mut r = Rig::dns_connected();
    let (_out, p) = r.interest();
    assert!(matches!(p, Progress::Done(_)), "the step goes on: {p:?}");
    assert!(r.io.job.is_none());
    assert!(r.io.take_jobs().is_empty());
    let Some(Job::Resolve { generation, .. }) = r.io.take_bg_job() else {
        panic!("no background resolve job");
    };
    // The socket I/O goes on while the job runs.
    assert!(r.io.has_socket());
    let (p, _) = r.process(PollEvents::NONE);
    assert_ne!(p, Progress::Wait);
    // A second resolve action joins the job that runs.
    let (_out, p) = r.interest();
    assert!(matches!(p, Progress::Done(_)));
    assert!(r.io.take_bg_job().is_none());
    // The result applies to the newest generation, so proto logs the
    // failed host.
    let (p, mut ob) = r.complete_bg(failed_resolution(generation));
    assert!(matches!(p, Progress::Done(_)));
    assert!(has_gai_line(&mut ob));
    assert!(r.io.dns.is_none());
    // The next resolve action starts a new job.
    let (_out, _p) = r.interest();
    assert!(r.io.take_bg_job().is_some());
}

#[test]
fn a_new_host_list_starts_after_the_running_resolve() {
    let mut r = Rig::dns_connected();
    let (_out, _p) = r.interest();
    let Some(Job::Resolve { generation, .. }) = r.io.take_bg_job() else {
        panic!("no background resolve job");
    };
    let hosts = test_config(b"127.0.0.2:2181").hosts;
    {
        let mut proof = Unlocked::new_at_entry();
        let mut g = r.core.lock(&mut proof);
        let next = g
            .conn
            .as_deref_mut()
            .unwrap()
            .set_servers(hosts.clone(), Millis(0));
        g.set_servers = Some((next, hosts.clone()));
    }
    let (_out, p) = r.interest();
    assert!(matches!(p, Progress::Done(_)));
    assert!(r.io.take_bg_job().is_none());
    // The old result is stale. The job of the new list starts.
    let (_p, mut ob) = r.complete_bg(failed_resolution(generation));
    assert!(!has_gai_line(&mut ob));
    let Some(Job::Resolve { hosts: got, .. }) = r.io.take_bg_job() else {
        panic!("the new list does not resolve");
    };
    assert_eq!(got, hosts);
}

#[test]
fn a_resolve_with_no_socket_waits_for_the_running_job() {
    let mut r = Rig::dns_connected();
    let (_out, _p) = r.interest();
    let Some(Job::Resolve { generation, .. }) = r.io.take_bg_job() else {
        panic!("no background resolve job");
    };
    r.io.drop_transport();
    let hosts = test_config(b"127.0.0.2:2181").hosts;
    {
        let mut proof = Unlocked::new_at_entry();
        let mut g = r.core.lock(&mut proof);
        let conn = g.conn.as_deref_mut().unwrap();
        let _rc = conn.handle_transport_failed(
            zk_proto::TransportFailure::Io {
                errno: Errno::CONNRESET.raw_os_error(),
            },
            Millis(0),
        );
        let next = conn.set_servers(hosts.clone(), Millis(0));
        g.set_servers = Some((next, hosts.clone()));
    }
    // With no socket the step waits for the job that runs. It starts no
    // second job.
    let (_out, p) = r.interest();
    assert_eq!(p, Progress::Wait);
    assert!(r.io.take_jobs().is_empty());
    assert!(r.io.take_bg_job().is_none());
    // The old result is stale. The step goes on waiting for the job of
    // the new list.
    let (p, mut ob) = r.complete_bg(failed_resolution(generation));
    assert_eq!(p, Progress::Wait);
    assert!(!has_gai_line(&mut ob));
    let jobs = r.io.take_jobs();
    let [
        Job::Resolve {
            generation: next,
            hosts: got,
            ..
        },
    ] = &jobs[..]
    else {
        panic!("the new list does not resolve");
    };
    assert_eq!(got, &hosts);
    // The set_servers resolution is also the `EachPass` resolution after
    // the lost session. The step does not resolve the new list again.
    let (p, mut ob) = r.complete_bg(failed_resolution(*next));
    assert_ne!(p, Progress::Wait);
    assert!(r.io.job.is_none());
    assert!(r.io.dns.is_none());
    assert!(has_gai_line(&mut ob));
}

#[test]
fn run_job_resolves_and_reseeds() {
    let host = TestHost::new();
    let addr: std::net::SocketAddr = "127.0.0.1:2181".parse().unwrap();
    host.set_addrs(b"127.0.0.1", vec![addr]);
    let hosts = test_config(b"127.0.0.1:2181").hosts;
    let probe_poll = RealPoll;
    let clock = TestClock::new(Millis(0));
    let jcx = JobCtx::<TestTokens> {
        host: &host,
        probe: crate::net::probe::ProbeCtx {
            poll: &probe_poll,
            clock: &clock,
            tls: None,
            wake: None,
            abort: None,
            phase_ms: 1,
            cloexec: false,
        },
    };
    let proof = Unlocked::new_at_entry();
    let done = run_job(
        &jcx,
        &proof,
        Job::Resolve {
            generation: 3,
            hosts: hosts.clone(),
            shuffle: true,
        },
    );
    let JobDone::Resolved {
        generation,
        results,
    } = done
    else {
        panic!("not a resolution")
    };
    assert_eq!(generation, 3);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].result.as_deref().unwrap(), &[addr][..]);
    assert_eq!(host.resolves(), 1);
    assert_eq!(host.reseeds(), 1);
    let _ = run_job(
        &jcx,
        &proof,
        Job::Resolve {
            generation: 4,
            hosts,
            shuffle: false,
        },
    );
    assert_eq!(host.resolves(), 2);
    assert_eq!(host.reseeds(), 1);
}

#[test]
fn run_job_new_conn_without_a_connector_fails() {
    let mut r = Rig::new(false, vec![]);
    let ep = match &r.io.conn {
        Transport::Connecting { ep, .. } => ep.clone(),
        _ => unreachable!(),
    };
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let proof = Unlocked::new_at_entry();
    let jcx = JobCtx {
        host: &*r.host,
        probe: cx.probe_ctx(),
    };
    let done = run_job(
        &jcx,
        &proof,
        Job::NewConn {
            purpose: crate::net::tls::TlsPurpose::Main,
            endpoint: ep,
        },
    );
    assert!(matches!(
        done,
        JobDone::NewConn(Err(TlsSetupError::Resource {
            at: TlsResourceAt::ContextNew
        }))
    ));
    let _ = &mut r;
}

#[test]
#[cfg_attr(
    miri,
    ignore = "Miri keeps a socket readable until a read gives EAGAIN, so the close wait ends early"
)]
fn close_flush_sends_the_close_frame() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    assert!(r.queue_close_op());
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    let mut ob = Outbox::new();
    assert_eq!(r.io.close_flush(&cx, &mut proof, &mut ob), ZOK);
    let (bytes, _) = r.peer_recv();
    assert!(bytes.len() > 4, "the CloseSession frame went out");
    // The peer never closes, so the wait times out and logs it.
    let mut sites = Vec::new();
    while let Some(item) = ob.pop() {
        if let Item::Log(rec) = item {
            sites.push(rec.site);
        }
    }
    assert_eq!(sites, vec![LogSite::CloseWaitTimeout]);
}

#[test]
fn close_flush_without_a_session_is_ok() {
    let mut r = Rig::new(false, vec![]);
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert_eq!(r.io.close_flush(&cx, &mut proof, &mut Outbox::new()), ZOK);
}

#[test]
fn close_flush_times_out_on_the_poll() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    assert!(r.queue_close_op());
    let poll = Arc::new(ClockPoll {
        clock: r.clock.clone(),
        result: Ok(0),
        calls: AtomicUsize::new(0),
    });
    r.env.poll = poll.clone();
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert_eq!(
        r.io.close_flush(&cx, &mut proof, &mut Outbox::new()),
        ZOPERATIONTIMEOUT
    );
    assert_eq!(poll.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn wait_writable_times_out_on_the_clock() {
    let (ours, _peer) = socket_pair();
    let clock = Arc::new(TestClock::new(Millis(100)));
    let poll = ClockPoll {
        clock: clock.clone(),
        result: Err(Errno::INTR),
        calls: AtomicUsize::new(0),
    };
    // A deadline in the past gives the timeout with no poll.
    assert!(matches!(
        wait_writable(&*clock, &poll, &ours, Millis(99)),
        Err(FlushError::Timeout)
    ));
    assert_eq!(poll.calls.load(Ordering::SeqCst), 0);
    // An interrupted poll retries. The clock then passes the deadline.
    assert!(matches!(
        wait_writable(&*clock, &poll, &ours, Millis(150)),
        Err(FlushError::Timeout)
    ));
    assert_eq!(poll.calls.load(Ordering::SeqCst), 1);
    assert!(clock.now().0 > 150);
}

#[test]
fn wait_writable_reports_the_poll_result() {
    let (ours, _peer) = socket_pair();
    let clock = TestClock::new(Millis(0));
    assert!(wait_writable(&clock, &RealPoll, &ours, Millis(1000)).is_ok());
    let failing = ClockPoll {
        clock: Arc::new(TestClock::new(Millis(0))),
        result: Err(Errno::INVAL),
        calls: AtomicUsize::new(0),
    };
    assert!(matches!(
        wait_writable(&clock, &failing, &ours, Millis(1000)),
        Err(FlushError::Poll(Errno::INVAL))
    ));
}

#[test]
fn close_flush_poll_error_is_a_system_error() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    assert!(r.queue_close_op());
    r.env.poll = Arc::new(ClockPoll {
        clock: r.clock.clone(),
        result: Err(Errno::INVAL),
        calls: AtomicUsize::new(0),
    });
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert_eq!(
        r.io.close_flush(&cx, &mut proof, &mut Outbox::new()),
        ZSYSTEMERROR
    );
}

#[test]
fn close_flush_send_error_is_a_connection_loss() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    assert!(r.queue_close_op());
    rustix::net::shutdown(r.io.conn.sock().unwrap(), rustix::net::Shutdown::Write).unwrap();
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert_eq!(
        r.io.close_flush(&cx, &mut proof, &mut Outbox::new()),
        ZCONNECTIONLOSS
    );
}

/// Resets the peer end of the rig: a zero linger makes the close send a
/// RST, so the driver socket reports `POLLERR` with write readiness.
fn reset_peer(r: &mut Rig) {
    let (spare, _other) = socket_pair();
    let peer = std::mem::replace(&mut r.peer, spare);
    rustix::net::sockopt::set_socket_linger(&peer, Some(std::time::Duration::ZERO)).unwrap();
    drop(peer);
    std::thread::sleep(std::time::Duration::from_millis(50));
}

#[test]
#[cfg_attr(miri, ignore = "Miri has no SO_LINGER, which makes the reset peer")]
fn wait_writable_gives_ok_for_a_reset_socket() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    reset_peer(&mut r);
    let sock = r.io.conn.sock().unwrap();
    let mut fds = [PollFd::new(sock, PollFlags::OUT)];
    assert_eq!(RealPoll.poll(&mut fds, 0).unwrap(), 1);
    // Linux reports POLLERR here and macOS reports POLLHUP. In both cases
    // the socket is ready, and the error comes from the send (C rc 1).
    let clock = TestClock::new(Millis(0));
    assert!(wait_writable(&clock, &RealPoll, sock, Millis(1000)).is_ok());
}

#[test]
#[cfg_attr(miri, ignore = "Miri has no SO_LINGER, which makes the reset peer")]
fn close_flush_to_a_reset_peer_is_a_connection_loss() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    assert!(r.queue_close_op());
    reset_peer(&mut r);
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert_eq!(
        r.io.close_flush(&cx, &mut proof, &mut Outbox::new()),
        ZCONNECTIONLOSS
    );
}

#[test]
fn tls_close_flush_sends_close_notify() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    assert!(r.queue_close_op());
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert_eq!(r.io.close_flush(&cx, &mut proof, &mut Outbox::new()), ZOK);
    let (bytes, _) = r.peer_recv();
    assert!(bytes.len() > 6);
    assert!(bytes.ends_with(b"CN"));
}

#[test]
fn tls_close_flush_after_a_latch_is_a_connection_loss() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    assert!(r.queue_close_op());
    if let Transport::Tls(t) = &mut r.io.conn {
        t.pending = Some(crate::net::tls::ReadFailure::Data);
    }
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    assert_eq!(
        r.io.close_flush(&cx, &mut proof, &mut Outbox::new()),
        ZCONNECTIONLOSS
    );
    let (bytes, _) = r.peer_recv();
    assert!(!bytes.ends_with(b"CN"));
}

#[test]
fn sasl_addrs_name_the_failed_call() {
    let mut r = Rig::new(false, vec![]);
    let (local, peer) = r.io.sasl_addrs().unwrap();
    assert_eq!(peer, r.peer.local_addr().unwrap());
    assert_eq!(local, r.peer.peer_addr().unwrap());
    r.io.conn = Transport::None;
    assert_eq!(r.io.sasl_addrs(), Err(zk_proto::SaslAddr::Local));
}

// ---------------------------------------------------------------------
// The mt close from an auth callback. The socket pair feeds the threaded
// driver, so the auth reply and a later reply come in one read.
// ---------------------------------------------------------------------

use zk_jute::JString;
use zk_jute::rc::ZCLOSING;
use zk_proto::{InputDefect, Op, PathIn, Request, Route, SecretBytes};
use zk_testkit::server::codec::{decode_client_frame, encode_reply, split_frames};
use zk_testkit::tokens::{AuthId, CompletionId};

use crate::outbox::{Publish, Step, ThreadOp, ThreadRole};
use crate::threaded::{Role, Shared};

/// An async exists request of "/".
fn queued_exists(id: u64) -> Request<TestTokens> {
    Request {
        op: Op::Exists {
            path: PathIn::Legacy(Some(b"/".to_vec())),
            watch: None,
        },
        token: CompletionId::new(id),
        route: Route::Queued,
        defect: InputDefect::default(),
    }
}

fn mt_label(item: &Item<TestTokens>) -> String {
    match item {
        Item::Thread { op, role } => format!("{op:?} {role:?}"),
        Item::AuthResult { token, rc } => format!("AuthResult {} {rc}", token.id()),
        Item::Result { token, result, .. } => format!("Result {} {}", token.id(), result.rc),
        other => format!("{other:?}"),
    }
}

/// Drives one mt call to its end, as C does. `on` sees each item when C
/// takes it.
fn mt_drive(
    s: &Shared<TestTokens>,
    first: Step,
    ob: &mut Outbox<TestTokens>,
    rc: &mut i32,
    mut on: impl FnMut(&Item<TestTokens>),
) -> (Step, Vec<String>) {
    let mut seen = Vec::new();
    let mut step = first;
    loop {
        while let Some(item) = ob.pop() {
            on(&item);
            seen.push(mt_label(&item));
        }
        if step != Step::More {
            return (step, seen);
        }
        step = s.resume(ob, rc);
    }
}

/// The xids of the exists requests that the peer receives.
fn exists_xids(sent: &[u8]) -> Vec<i32> {
    split_frames(sent)
        .unwrap()
        .iter()
        .map(|f| decode_client_frame(f).unwrap().0)
        .filter(|h| h.r#type == 3)
        .map(|h| h.xid)
        .collect()
}

/// Runs the threaded driver on a rig whose socket has replies to read. A
/// callback on the IO thread closes the handle when `trigger` accepts an
/// item. The result has the items of the outer IO call and the items that
/// the dispatch thread delivers. The function also checks that the final
/// close runs on the IO thread and discards no token.
fn close_from_an_io_callback(
    r: Rig,
    trigger: impl Fn(&Item<TestTokens>) -> bool,
) -> (Vec<String>, Vec<String>) {
    let before = r.host.discarded();
    let Rig {
        host,
        env,
        core,
        io,
        peer: _peer,
        ..
    } = r;
    let mut ob = Outbox::new();
    let s = Shared::new(core.into_inner(), env, &mut ob).unwrap();
    s.io.lock_owner().io = io;
    s.thread_enter(Role::Io);
    s.thread_enter(Role::Dispatch);
    let waiter = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || {
            let mut got = Vec::new();
            loop {
                let mut ob = s.outbox();
                if s.wait_dispatch(&mut ob) == Step::Exit {
                    break;
                }
                while let Some(item) = ob.pop() {
                    got.push(mt_label(&item));
                }
            }
            let mut ob = s.outbox();
            let mut rc = -1;
            assert_eq!(
                s.thread_exit(Role::Dispatch, &mut ob, &mut rc),
                Step::Done(ZOK)
            );
            got
        })
    };
    let mut waiter = Some(waiter);
    let mut got = None;
    let mut nested = Vec::new();
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.io_step(&mut ob, &mut rc);
    let (_, outer) = mt_drive(&s, first, &mut ob, &mut rc, |item| {
        if waiter.is_some() && trigger(item) {
            let mut ob = s.outbox();
            let mut rc = -1;
            let first = s.close(Role::Io, &mut ob, &mut rc);
            let (end, seen) = mt_drive(&s, first, &mut ob, &mut rc, |item| {
                if let Item::Thread {
                    op: ThreadOp::Join,
                    role: ThreadRole::Dispatch,
                } = item
                {
                    got = Some(waiter.take().unwrap().join().unwrap());
                }
            });
            assert_eq!(end, Step::Done(ZOK));
            nested = seen;
        }
    });
    assert!(nested.contains(&"Detach Io".to_owned()), "{nested:?}");
    let got = got.expect("the callback closed the handle");
    // The IO thread leaves its loop and runs the final close.
    let mut ob = s.outbox();
    let mut rc = -1;
    assert_eq!(s.io_step(&mut ob, &mut rc), Step::Exit);
    let first = s.thread_exit(Role::Io, &mut ob, &mut rc);
    let (end, _) = mt_drive(&s, first, &mut ob, &mut rc, |_| {});
    assert_eq!(end, Step::Release);
    assert_eq!(host.discarded(), before);
    (outer, got)
}

/// A successful auth reply and the reply after it come in one read. The
/// auth callback closes the handle on the IO thread. The dispatch thread
/// still delivers the result of the later request, and the close discards
/// no token.
#[test]
fn a_close_from_an_auth_callback_delivers_the_next_reply() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.plain_connected();
    {
        let now = r.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let mut core = r.core.lock(&mut proof);
        let conn = core.conn.as_deref_mut().unwrap();
        let cred = SecretBytes::from(b"u:p".to_vec());
        assert!(
            conn.add_auth(JString::from("digest"), cred, Some(AuthId::new(1)), now)
                .is_ok()
        );
        assert!(conn.submit(queued_exists(2), now).is_ok());
    }
    let _ = r.interest();
    let _ = r.process(write_ev());
    let (sent, _) = r.peer_recv();
    let xid = exists_xids(&sent)[0];
    // Both replies go out in one write, so one read takes both.
    let mut replies = encode_reply(-4, 0, ZOK, &[]);
    replies.extend_from_slice(&encode_reply(xid, 5, -101, &[]));
    r.peer_send(&replies);
    r.wait_readable();

    let (outer, got) = close_from_an_io_callback(r, |item| matches!(item, Item::AuthResult { .. }));
    assert!(outer.contains(&format!("AuthResult 1 {ZOK}")), "{outer:?}");
    // The pump stops after the auth items, so the core does not process
    // the next reply before the close. The close fails that request with
    // ZCLOSING, as C does. The dispatch thread delivers the result.
    assert_eq!(got, [format!("Result 2 {ZCLOSING}")]);
}

/// Two replies come in one read. The log callback of the first reply
/// closes the handle on the IO thread. The dispatch thread delivers one
/// result for each request, and the close discards no token.
#[test]
fn a_close_from_a_log_callback_delivers_every_decoded_reply() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.plain_connected();
    {
        let now = r.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let mut core = r.core.lock(&mut proof);
        let conn = core.conn.as_deref_mut().unwrap();
        assert!(conn.submit(queued_exists(2), now).is_ok());
        assert!(conn.submit(queued_exists(3), now).is_ok());
    }
    let _ = r.interest();
    let _ = r.process(write_ev());
    let (sent, _) = r.peer_recv();
    let xids = exists_xids(&sent);
    assert_eq!(xids.len(), 2, "{xids:?}");
    // Both replies go out in one write, so one read takes both.
    let mut replies = encode_reply(xids[0], 5, -101, &[]);
    replies.extend_from_slice(&encode_reply(xids[1], 6, -101, &[]));
    r.peer_send(&replies);
    r.wait_readable();

    let (outer, got) = close_from_an_io_callback(
        r,
        |item| matches!(item, Item::Log(rec) if rec.site == LogSite::QueueingAsync),
    );
    // The outer call gives C only the first log line. The later outputs
    // stay in the core, and the close publishes them before its mark.
    assert_eq!(outer, ["Log"]);
    // Each request gets exactly one result, in request order.
    assert_eq!(got, ["Result 2 -101", "Result 3 -101"]);
}

/// Records the order of the publish entries and the items of C.
#[derive(Default)]
struct OrderFifo(Mutex<Vec<String>>);

impl Publish<TestTokens> for OrderFifo {
    fn publish(&self, item: Item<TestTokens>) {
        self.0.lock_owner().push(format!("pub {}", mt_label(&item)));
    }
}

/// Three replies come in one read, with debug lines on. In each mt
/// segment, C takes no item before a publish entry of that segment. So
/// a callback of an item never runs while a later result waits in the
/// outbox.
#[test]
fn an_mt_segment_has_no_publish_entry_behind_an_item() {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.plain_connected();
    {
        let now = r.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let mut core = r.core.lock(&mut proof);
        let conn = core.conn.as_deref_mut().unwrap();
        for id in 2..5 {
            assert!(conn.submit(queued_exists(id), now).is_ok());
        }
    }
    let _ = r.interest();
    let _ = r.process(write_ev());
    let (sent, _) = r.peer_recv();
    let xids = exists_xids(&sent);
    assert_eq!(xids.len(), 3, "{xids:?}");
    let mut replies = Vec::new();
    for (n, xid) in (5..).zip(&xids) {
        replies.extend_from_slice(&encode_reply(*xid, n, -101, &[]));
    }
    r.peer_send(&replies);
    r.wait_readable();

    let fifo = Arc::new(OrderFifo::default());
    let publish: Arc<dyn Publish<TestTokens>> = fifo.clone();
    let mut ob = Outbox::with_publish(publish);
    let cx = r.env.step_ctx(&r.core, r.flavor, r.defer, None, None, None);
    let mut proof = Unlocked::new_at_entry();
    let mut unused = InterestOut::UNWRITTEN;
    let mut p = r.io.process_step(&cx, &mut proof, read_ev(), &mut ob);
    let mut segments = Vec::new();
    loop {
        while let Some(item) = ob.pop() {
            fifo.0.lock_owner().push(mt_label(&item));
        }
        segments.push(std::mem::take(&mut *fifo.0.lock_owner()));
        if p != Progress::More {
            break;
        }
        assert!(segments.len() < 100, "no end of barriers");
        p = r.io.resume(&cx, &mut proof, &mut ob, &mut unused);
    }
    for seg in &segments {
        let first_item = seg.iter().position(|e| !e.starts_with("pub "));
        if let Some(at) = first_item {
            assert!(
                seg.iter().skip(at).all(|e| !e.starts_with("pub ")),
                "{segments:?}"
            );
        }
    }
    let published: Vec<&String> = segments
        .iter()
        .flatten()
        .filter(|e| e.starts_with("pub "))
        .collect();
    assert_eq!(
        published,
        [
            "pub Result 2 -101",
            "pub Result 3 -101",
            "pub Result 4 -101"
        ],
        "{segments:?}"
    );
}

// ---------------------------------------------------------------------
// The close tail of the mt driver: the CLOSE_OP, the flush and wait, and
// `destroy`. The results of the tail go to the dispatch thread.
// ---------------------------------------------------------------------

/// Takes an mt rig to `Connected` and sends one queued exists request
/// for `id`. The peer does not reply yet. It returns the xid.
fn mt_rig_with_a_pending_request(id: u64) -> (Rig, i32) {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.plain_connected();
    // The wait ends at the first POLLIN, so the reply ends it.
    r.env.cfg.close_wait_ms = 2_000;
    {
        let now = r.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let mut core = r.core.lock(&mut proof);
        let conn = core.conn.as_deref_mut().unwrap();
        assert!(conn.submit(queued_exists(id), now).is_ok());
    }
    let _ = r.interest();
    let _ = r.process(write_ev());
    let (sent, _) = r.peer_recv();
    let xids = exists_xids(&sent);
    assert_eq!(xids.len(), 1, "{xids:?}");
    (r, xids[0])
}

/// The threaded handle over the rig, with the refs of both threads.
fn mt_handle(r: Rig) -> (Arc<Shared<TestTokens>>, Arc<TestHost>, TcpSock) {
    let Rig {
        host,
        env,
        core,
        io,
        peer,
        ..
    } = r;
    let mut ob = Outbox::new();
    let s = Shared::new(core.into_inner(), env, &mut ob).unwrap();
    s.io.lock_owner().io = io;
    s.thread_enter(Role::Io);
    s.thread_enter(Role::Dispatch);
    (s, host, peer)
}

/// Sends `bytes` from the peer end of the rig.
fn send_from_peer(peer: &TcpSock, bytes: &[u8]) {
    let mut off = 0;
    while off < bytes.len() {
        match peer.send(&bytes[off..]) {
            Ok(n) => off += n,
            Err(Errno::WOULDBLOCK | Errno::INTR) => {}
            Err(e) => panic!("peer send: {e}"),
        }
    }
}

/// Adds an auth with a completion, as `zoo_add_auth` does.
fn add_auth_with(s: &Shared<TestTokens>, id: u64) {
    let cred = SecretBytes::from(b"u:p".to_vec());
    assert!(
        s.add_auth(JString::from("digest"), cred, Some(AuthId::new(id)))
            .is_ok()
    );
}

fn is_closing_line(item: &Item<TestTokens>) -> bool {
    matches!(item, Item::Log(rec) if rec.site == LogSite::Closing)
}

fn is_result(label: &str) -> bool {
    label.starts_with("Result") || label.starts_with("AuthResult")
}

/// Plays the dispatch thread on a new thread. It delivers each batch
/// until `wait_dispatch` gives `Exit`, then it gives back its ref.
fn spawn_dispatch(s: &Arc<Shared<TestTokens>>) -> std::thread::JoinHandle<Vec<String>> {
    let s = Arc::clone(s);
    std::thread::spawn(move || {
        let got = dispatch_until_exit(&s);
        let mut ob = s.outbox();
        let mut rc = -1;
        assert_eq!(
            s.thread_exit(Role::Dispatch, &mut ob, &mut rc),
            Step::Done(ZOK)
        );
        got
    })
}

/// Runs the dispatch loop on this thread until `wait_dispatch` gives
/// `Exit`. It returns the labels of the items.
fn dispatch_until_exit(s: &Shared<TestTokens>) -> Vec<String> {
    let mut got = Vec::new();
    loop {
        let mut ob = s.outbox();
        if s.wait_dispatch(&mut ob) == Step::Exit {
            return got;
        }
        while let Some(item) = ob.pop() {
            got.push(mt_label(&item));
        }
    }
}

/// Lets the IO thread leave its loop, as C does at the IO join.
fn exit_io_thread(s: &Shared<TestTokens>) {
    let mut ob = s.outbox();
    let mut rc = -1;
    assert_eq!(s.io_step(&mut ob, &mut rc), Step::Exit);
    assert_eq!(s.thread_exit(Role::Io, &mut ob, &mut rc), Step::Done(ZOK));
}

/// Runs a foreign close with a dispatch thread. `on` sees each item that
/// the closer takes. The result has the end, the items of the closer and
/// the items of the dispatch thread.
fn foreign_close(
    s: &Arc<Shared<TestTokens>>,
    mut on: impl FnMut(&Item<TestTokens>),
) -> (Step, i32, Vec<String>, Vec<String>) {
    let mut waiter = Some(spawn_dispatch(s));
    let mut got = Vec::new();
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.close(Role::Foreign, &mut ob, &mut rc);
    let (end, seen) = mt_drive(s, first, &mut ob, &mut rc, |item| {
        match item {
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Io,
            } => {
                exit_io_thread(s);
            }
            Item::Thread {
                op: ThreadOp::Join,
                role: ThreadRole::Dispatch,
            } => {
                got = waiter.take().unwrap().join().unwrap();
            }
            _ => {}
        }
        on(item);
    });
    (end, rc, seen, got)
}

/// The peer replies to the pending request after the "Closing" line, so
/// the reply comes during the flush and wait. The flush reads no reply,
/// so the request has only the ZCLOSING result of `begin_close`, on the
/// dispatch thread. The log callback of that line also adds an auth, and
/// only `destroy` fails it. Like an auth callback of legacy
/// `free_completions`, it runs on the closing thread. No token goes to
/// `discard_token`.
#[test]
fn a_reply_during_the_close_flush_gives_no_second_result() {
    let (r, xid) = mt_rig_with_a_pending_request(2);
    let (s, host, peer) = mt_handle(r);
    let (end, rc, seen, got) = foreign_close(&s, |item| {
        if is_closing_line(item) {
            add_auth_with(&s, 7);
            send_from_peer(&peer, &encode_reply(xid, 6, -101, &[]));
        }
    });
    assert_eq!((end, rc), (Step::Release, ZOK));
    let results: Vec<_> = seen.iter().filter(|l| is_result(l)).collect();
    assert_eq!(results, [&format!("AuthResult 7 {ZCLOSING}")]);
    assert_eq!(got, [format!("Result 2 {ZCLOSING}")]);
    assert!(host.discarded().is_empty(), "{:?}", host.discarded());
}

/// A foreign close runs its tail only after the dispatch thread has run
/// the callbacks of the results that are already queued. A slow callback
/// gets the ZCLOSING result of `begin_close`. The "Closing" line of the
/// tail comes after that callback returns, as in C, where the close joins
/// the completion thread before the final close.
#[test]
fn a_foreign_close_runs_its_tail_after_the_queued_callbacks() {
    let (mut r, _xid) = mt_rig_with_a_pending_request(2);
    // The peer does not reply, so the wait runs to its end.
    r.env.cfg.close_wait_ms = 20;
    let (s, host, _peer) = mt_handle(r);
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut waiter = {
        let s = Arc::clone(&s);
        let order = Arc::clone(&order);
        Some(std::thread::spawn(move || {
            loop {
                let mut ob = s.outbox();
                if s.wait_dispatch(&mut ob) == Step::Exit {
                    break;
                }
                while let Some(item) = ob.pop() {
                    if matches!(item, Item::Result { .. }) {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    order.lock().unwrap().push(mt_label(&item));
                }
            }
            let mut ob = s.outbox();
            let mut rc = -1;
            assert_eq!(
                s.thread_exit(Role::Dispatch, &mut ob, &mut rc),
                Step::Done(ZOK)
            );
        }))
    };
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.close(Role::Foreign, &mut ob, &mut rc);
    let (end, _) = mt_drive(&s, first, &mut ob, &mut rc, |item| match item {
        Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Io,
        } => exit_io_thread(&s),
        Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Dispatch,
        } => waiter.take().unwrap().join().unwrap(),
        Item::Log(rec) if matches!(rec.site, LogSite::Closing | LogSite::Freeing) => {
            order.lock().unwrap().push(format!("{:?}", rec.site));
        }
        _ => {}
    });
    assert_eq!((end, rc), (Step::Release, ZOK));
    let order = order.lock().unwrap().clone();
    assert_eq!(
        order,
        [
            format!("Result 2 {ZCLOSING}"),
            "Closing".to_owned(),
            "Freeing".to_owned()
        ]
    );
    assert!(host.discarded().is_empty(), "{:?}", host.discarded());
}

/// A sync exists request of "/".
fn direct_exists(id: u64) -> Request<TestTokens> {
    Request {
        route: Route::Direct,
        ..queued_exists(id)
    }
}

/// Leaves a handle with a teardown that stops for good. The peer ends
/// the stream, so the IO thread fails the sync request 1 at a barrier.
/// The drain of the IO thread then unwinds, as when a log callback
/// throws, and C requeues the outbox. No resume follows, so the queued
/// request 2 and the auth 3 stay in the stopped teardown. `begin_close`
/// defers, and only `destroy` fails them.
fn handle_with_a_stopped_teardown() -> (Arc<Shared<TestTokens>>, Arc<TestHost>) {
    let mut r = Rig::with_mode(false, vec![], Compat::LEGACY_C, DriverMode::MT);
    r.flavor = Flavor::Mt;
    r.plain_connected();
    submit_a_sync_and_a_queued_request(&mut r);
    let _ = r.peer_recv();
    rustix::net::shutdown(&r.peer, rustix::net::Shutdown::Write).unwrap();
    let (s, host, _peer) = mt_handle(r);
    stop_the_teardown(&s);
    (s, host)
}

/// Sends the sync request 1, the queued request 2 and the auth 3. The
/// peer does not reply.
fn submit_a_sync_and_a_queued_request(r: &mut Rig) {
    {
        let now = r.clock.now();
        let mut proof = Unlocked::new_at_entry();
        let mut core = r.core.lock(&mut proof);
        let conn = core.conn.as_deref_mut().unwrap();
        assert!(conn.submit(direct_exists(1), now).is_ok());
        assert!(conn.submit(queued_exists(2), now).is_ok());
        let cred = SecretBytes::from(b"u:p".to_vec());
        let auth = conn.add_auth(JString::from("digest"), cred, Some(AuthId::new(3)), now);
        assert!(auth.is_ok());
    }
    let _ = r.interest();
    let _ = r.process(write_ev());
}

/// Runs the IO step that reads the end of the stream. C takes the sync
/// result of the teardown, and then its drain unwinds. The teardown
/// stays stopped.
fn stop_the_teardown(s: &Shared<TestTokens>) {
    let mut ob = s.outbox();
    let mut rc = -1;
    let mut step = s.io_step(&mut ob, &mut rc);
    let lost = format!("Result 1 {ZCONNECTIONLOSS}");
    'drain: for _ in 0..8 {
        while let Some(item) = ob.pop() {
            if mt_label(&item) == lost {
                break 'drain;
            }
        }
        assert_eq!(step, Step::More);
        step = s.resume(&mut ob, &mut rc);
    }
    s.requeue(ob.requeue());
    let mut proof = Unlocked::new_at_entry();
    let core = s.core.lock(&mut proof);
    assert!(core.conn.as_deref().unwrap().is_suspended());
}

/// A foreign close runs its tail while the dispatch thread is alive. The
/// result that only `destroy` gives thus goes to the dispatch thread
/// before the close mark. The closer runs only the auth completion, as
/// legacy `free_completions` does. No token goes to `discard_token`.
#[test]
fn a_foreign_close_gives_the_results_of_destroy_to_the_dispatch_thread() {
    let (s, host) = handle_with_a_stopped_teardown();
    let (end, rc, seen, got) = foreign_close(&s, |_| {});
    assert_eq!((end, rc), (Step::Release, ZOK));
    let results: Vec<_> = seen.iter().filter(|l| is_result(l)).collect();
    assert_eq!(results, [&format!("AuthResult 3 {ZCLOSING}")]);
    assert_eq!(got, ["Session".to_owned(), format!("Result 2 {ZCLOSING}")]);
    assert!(host.discarded().is_empty(), "{:?}", host.discarded());
}

/// A close from a completion callback leaves the tail to the exit of the
/// dispatch thread. That thread first delivers the rest of the FIFO. At
/// its exit it runs the tail and delivers the results that only
/// `destroy` gives: the request first, then the auth. No token goes to
/// `discard_token`.
#[test]
fn a_close_from_a_completion_callback_delivers_the_results_of_destroy() {
    let (s, host) = handle_with_a_stopped_teardown();
    // The test thread plays the dispatch thread. A completion callback
    // closes the handle.
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.close(Role::Dispatch, &mut ob, &mut rc);
    let (end, nested) = mt_drive(&s, first, &mut ob, &mut rc, |item| {
        if let Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Io,
        } = item
        {
            exit_io_thread(&s);
        }
    });
    assert_eq!(end, Step::Done(ZOK));
    assert_eq!(nested, ["Join Io", "Detach Dispatch"]);
    // The callback returns. The dispatch loop drains the FIFO and exits.
    assert_eq!(dispatch_until_exit(&s), ["Session"]);
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.thread_exit(Role::Dispatch, &mut ob, &mut rc);
    let (end, at_exit) = mt_drive(&s, first, &mut ob, &mut rc, |_| {});
    assert_eq!((end, rc), (Step::Release, ZOK));
    let results: Vec<_> = at_exit.iter().filter(|l| is_result(l)).collect();
    assert_eq!(
        results,
        [
            &format!("Result 2 {ZCLOSING}"),
            &format!("AuthResult 3 {ZCLOSING}")
        ]
    );
    assert!(host.discarded().is_empty(), "{:?}", host.discarded());
}

/// A close from an IO callback joins the dispatch thread before the close
/// tail, because the close returns to the callback only after that join.
/// The final close then runs on the IO thread, and no completion thread
/// is left. The request result that only `destroy` gives thus goes to
/// `discard_token` once, as legacy `destroy` frees it with no callback.
/// The auth completion runs on the IO thread, as in `free_completions`.
#[test]
fn a_close_from_an_io_callback_discards_a_destroy_result() {
    let (s, host) = handle_with_a_stopped_teardown();
    let mut waiter = Some(spawn_dispatch(&s));
    let mut got = Vec::new();
    // The test thread plays the IO thread. An IO callback closes.
    let mut ob = s.outbox();
    let mut rc = -1;
    let first = s.close(Role::Io, &mut ob, &mut rc);
    let (end, nested) = mt_drive(&s, first, &mut ob, &mut rc, |item| {
        if let Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Dispatch,
        } = item
        {
            got = waiter.take().unwrap().join().unwrap();
        }
    });
    assert_eq!(end, Step::Done(ZOK));
    assert_eq!(nested, ["Detach Io", "Join Dispatch"]);
    assert_eq!(got, ["Session"]);
    // The callback returns. The IO loop exits and runs the final close.
    let mut ob = s.outbox();
    let mut rc = -1;
    assert_eq!(s.io_step(&mut ob, &mut rc), Step::Exit);
    let first = s.thread_exit(Role::Io, &mut ob, &mut rc);
    let (end, at_exit) = mt_drive(&s, first, &mut ob, &mut rc, |_| {});
    assert_eq!((end, rc), (Step::Release, ZOK));
    let results: Vec<_> = at_exit.iter().filter(|l| is_result(l)).collect();
    assert_eq!(results, [&format!("AuthResult 3 {ZCLOSING}")]);
    assert_eq!(host.discarded(), ["completion"]);
}

// The transmit copy buffer and secret frames (spec "send queue"). The
// marker is the credential of an auth packet. The packet
// goes on the wire as plaintext, so `tx_copy` holds the marker.

/// The credential of the auth packets in the `tx_copy` tests.
const TX_MARKER: &[u8] = b"zk-tx-copy-secret-7b3e91";

impl Rig {
    /// Queues an auth packet with `TX_MARKER` as its credential.
    fn add_marker_auth(&self) {
        let mut proof = Unlocked::new_at_entry();
        let mut g = self.core.lock(&mut proof);
        let conn = g.conn.as_deref_mut().unwrap();
        let cred = SecretBytes::from_slice(TX_MARKER);
        conn.add_auth(JString::from("digest"), cred, None, Millis(0))
            .unwrap();
    }

    /// Queues a plaintext request with `len` data bytes.
    fn add_set(&self, len: usize) {
        self.add_set_data(vec![0x5a; len]);
    }

    /// Queues a plaintext request with `data` as its data.
    fn add_set_data(&self, data: Vec<u8>) {
        let mut proof = Unlocked::new_at_entry();
        let mut g = self.core.lock(&mut proof);
        let conn = g.conn.as_deref_mut().unwrap();
        let req = Request {
            op: Op::SetData {
                path: PathIn::Legacy(Some(b"/a".to_vec())),
                data: JBuffer::Bytes(data),
                version: -1,
            },
            token: CompletionId::new(1),
            route: Route::Queued,
            defect: InputDefect::default(),
        };
        assert!(conn.submit(req, Millis(0)).is_ok());
    }

    /// Copies the released bytes into `tx_copy` as the flush does, with
    /// no send.
    fn copy_released(&mut self) -> usize {
        let mut proof = Unlocked::new_at_entry();
        let mut g = self.core.lock(&mut proof);
        let conn = g.conn.as_deref_mut().unwrap();
        conn.poll_transmit(&mut self.io.tx_copy, crate::iocore::TX_LEND_MAX)
    }
}

/// Returns true when `bytes` holds `TX_MARKER`.
fn holds_marker(bytes: &[u8]) -> bool {
    bytes.windows(TX_MARKER.len()).any(|w| w == TX_MARKER)
}

/// Rule: a plaintext flush sends the auth packet and leaves no bytes in
/// `tx_copy`. A reset does the same with unsent bytes. The free-scan test
/// below checks the freed memory.
#[test]
fn flush_and_reset_empty_the_copy_buffer() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    r.add_marker_auth();
    let (p, _) = r.process(write_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert!(holds_marker(&r.peer_recv().0), "the auth packet went out");
    assert!(r.io.tx_copy.is_empty());

    r.add_marker_auth();
    assert!(r.copy_released() > 0);
    assert!(holds_marker(&r.io.tx_copy));
    r.io.drop_transport();
    assert!(r.io.tx_copy.is_empty());
}

/// Rule: the TLS write path also leaves no bytes in `tx_copy` after it
/// gives an auth packet to the session.
#[test]
fn tls_write_empties_the_copy_buffer() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    r.add_marker_auth();
    let (p, _) = r.process(write_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert!(holds_marker(&r.peer_recv().0), "the auth packet went out");
    assert!(r.io.tx_copy.is_empty());
}

/// Rule: no freed heap block holds the credential of a sent auth packet
/// (spec "send queue"). `zk-client/tests/free_scan/
/// free_scan.sh` runs this test with the free scanner, which scans each
/// block before free and each block that realloc leaves. A heap copy of
/// the marker is the control buffer.
///
/// To see the state of `tx_copy` at each point, the test frees the
/// buffer as a plain `Vec`, with no erase on drop. The cases are a sent
/// packet, a reset with an unsent packet, a growth of `tx_copy` in one
/// copy after the packet, a growth in a later copy, and a drop of the
/// whole core.
///
/// The test covers only the plaintext path. The fake TLS session of the
/// rig keeps its own copies of the plaintext. Thus
/// `tls_tx_copy_is_zero_before_free` checks the TLS path with a masked
/// session.
#[test]
#[ignore = "free-scan"]
fn tx_copy_is_zero_before_free() {
    // Without the scanner the test has nothing to check.
    let Some(out) = std::env::var_os("ZK_FREE_SCAN_OUT") else {
        return;
    };
    let hits = || {
        std::fs::read_to_string(&out)
            .map(|t| t.lines().filter(|l| l.starts_with("hit")).count())
            .unwrap_or(0)
    };
    drop(std::hint::black_box(TX_MARKER.to_vec()));
    let control = hits();
    assert!(control >= 1, "the free scanner does not run");

    // A sent auth packet. The last copy of the flush erases the old
    // bytes. The peer does not read, so the test makes no heap copy of
    // the marker.
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    r.add_marker_auth();
    let (p, _) = r.process(write_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert!(r.io.tx_copy.is_empty() && r.io.tx_copy.capacity() > 0);
    drop(std::mem::take(&mut *r.io.tx_copy));
    assert_eq!(hits(), control, "a sent auth packet stays in tx_copy");

    // A reset with the packet unsent. The buffer keeps the old bytes
    // until the next copy, as the next flush does.
    r.add_marker_auth();
    assert!(r.copy_released() > 0);
    r.io.drop_transport();
    assert_eq!(r.copy_released(), 0);
    drop(std::mem::take(&mut *r.io.tx_copy));
    assert_eq!(hits(), control, "a reset leaves the auth packet");

    // One copy that starts with no capacity grows the buffer after the
    // auth packet: a second packet, then a large request.
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    drop(std::mem::take(&mut *r.io.tx_copy));
    r.add_marker_auth();
    r.add_marker_auth();
    r.add_set(8 * 1024);
    assert!(r.copy_released() > 8 * 1024);
    assert!(holds_marker(&r.io.tx_copy));
    assert_eq!(hits(), control, "a growth frees a copy of the packet");
    r.io.tx_copy.clear();
    assert_eq!(r.copy_released(), 0);
    drop(std::mem::take(&mut *r.io.tx_copy));
    assert_eq!(hits(), control, "a clear leaves the auth packet");

    // A later copy grows a buffer that holds the unsent packet.
    r.add_marker_auth();
    assert!(r.copy_released() > 0);
    r.add_set(8 * 1024);
    assert!(r.copy_released() > 8 * 1024);
    assert!(holds_marker(&r.io.tx_copy));
    assert_eq!(hits(), control, "a later growth frees the packet");

    // The drop of the core with the packet unsent.
    drop(r);
    assert_eq!(hits(), control, "the drop leaves the auth packet");
}

// The TLS write buffers: the send cursor of `ct_out`, the
// buffer swap with the session, and the release of large buffers.

use crate::iocore::READ_BUFFER_LEN;
use crate::iocore_tls::{MAX_CHUNK, SMALL_BURSTS, WriteBursts, release_large_buffers};
use crate::net::tls::{TlsConn, TlsFailure, TlsTransport};

impl Rig {
    /// Reads what the peer can read now, after a wait of up to 200 ms
    /// for the first byte. It does not wait for more.
    fn peer_drain(&self, into: &mut Vec<u8>) {
        let mut fds = [PollFd::new(&self.peer, PollFlags::IN)];
        let _ = RealPoll.poll(&mut fds, 200);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match self.peer.recv(&mut buf) {
                Ok(0) | Err(Errno::WOULDBLOCK) => return,
                Ok(n) => into.extend_from_slice(&buf[..n]),
                Err(Errno::INTR) => {}
                Err(e) => panic!("peer recv: {e}"),
            }
        }
    }

    /// Returns the TLS transport.
    fn tls(&self) -> &TlsTransport {
        match &self.io.conn {
            Transport::Tls(t) => t,
            _ => panic!("no TLS transport"),
        }
    }

    /// Returns the capacity of the buffer that the session holds. A swap
    /// with an empty buffer shows it, and a second swap gives it back.
    fn session_capacity(&mut self) -> usize {
        let Transport::Tls(t) = &mut self.io.conn else {
            panic!("no TLS transport");
        };
        assert!(!t.tls.has_ciphertext());
        let mut probe = Vec::new();
        let _ = t.tls.take_ciphertext(&mut probe);
        let cap = probe.capacity();
        let _ = t.tls.take_ciphertext(&mut probe);
        cap
    }

    /// Gives WRITE events and reads the peer until the peer has `len`
    /// bytes. `each` sees the transport after each event.
    fn tls_send_all(&mut self, len: usize, mut each: impl FnMut(&TlsTransport)) -> Vec<u8> {
        let mut got = Vec::new();
        for _ in 0..1000 {
            let (p, _) = self.process(write_ev());
            assert_eq!(p, Progress::Done(ZOK));
            each(self.tls());
            self.peer_drain(&mut got);
            if got.len() >= len {
                break;
            }
        }
        assert_eq!(got.len(), len, "the peer got the whole frame");
        got
    }
}

/// The frame of a `setData` of `data` on `/a` as the peer gets it.
fn set_frame_len(data: usize) -> usize {
    // len, xid, type, path, data length, data, version.
    4 + 4 + 4 + (4 + 2) + 4 + data + 4
}

/// The frame of the `TX_MARKER` auth packet as the peer gets it.
fn auth_frame_len() -> usize {
    // len, xid, type, auth type, scheme "digest", credential.
    4 + 4 + 4 + 4 + (4 + 6) + (4 + TX_MARKER.len())
}

/// Rule: a partial send of TLS ciphertext moves a cursor and moves no
/// bytes. When all bytes of a chunk are out, `ct_out` is empty, so the
/// next chunk comes in by a buffer swap. The peer gets the bytes in order.
#[test]
#[cfg_attr(miri, ignore = "Miri has no SO_SNDBUF, which forces the partial sends")]
fn tls_partial_sends_move_a_cursor() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    let sock = r.io.conn.sock().unwrap();
    rustix::net::sockopt::set_socket_send_buffer_size(sock, 16 * 1024).unwrap();
    rustix::net::sockopt::set_socket_recv_buffer_size(&r.peer, 16 * 1024).unwrap();
    let data: Vec<u8> = (0..2 * MAX_CHUNK + 1000).map(|i| (i % 251) as u8).collect();
    r.add_set_data(data.clone());
    let len = set_frame_len(data.len());

    // Each entry is the buffer, its length and the cursor.
    let mut seen: Vec<(usize, usize, usize)> = Vec::new();
    let got = r.tls_send_all(len, |t| {
        if !t.ct_out.is_empty() {
            assert!(t.ct_sent < t.ct_out.len());
            seen.push((t.ct_out.as_ptr() as usize, t.ct_out.len(), t.ct_sent));
        }
    });
    assert_eq!(got[got.len() - 4 - data.len()..got.len() - 4], data[..]);
    let t = r.tls();
    assert!(t.ct_out.is_empty() && t.ct_sent == 0 && !t.has_unsent());

    // A partial send of a full chunk keeps the buffer and its length.
    let partial: Vec<_> = seen.iter().filter(|s| s.1 == MAX_CHUNK).collect();
    assert!(partial.iter().any(|s| s.2 > 0), "partial sends: {seen:?}");
    for w in seen.windows(2) {
        if w[0].0 == w[1].0 && w[0].1 == w[1].1 {
            assert!(w[1].2 >= w[0].2, "the cursor moves forward: {w:?}");
        }
    }
    // The chunks go between two buffers, one for each swap.
    let mut bufs: Vec<usize> = partial.iter().map(|s| s.0).collect();
    bufs.dedup();
    assert!(bufs.len() >= 2, "the second chunk came by a swap: {seen:?}");
}

/// Rule: the large TLS write buffers stay while large frames go out,
/// and go back after a run of small bursts. The small tail chunk of a
/// large frame frees nothing. One release frees `tx_copy`, `ct_out` and
/// the buffer that the session holds.
#[test]
fn tls_large_write_buffers_go_back_after_small_writes() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    for _ in 0..2 {
        r.add_set(MAX_CHUNK + 100);
        r.tls_send_all(set_frame_len(MAX_CHUNK + 100), |_| {});
        assert!(
            r.io.tx_copy.capacity() >= MAX_CHUNK,
            "the tail chunk frees nothing"
        );
    }
    let large = |r: &mut Rig| {
        let ct = r.io.tx_copy.capacity().max(r.tls().ct_out.capacity());
        ct.max(r.session_capacity()) > READ_BUFFER_LEN
    };
    assert!(
        r.session_capacity() >= MAX_CHUNK,
        "the session holds a buffer"
    );
    for i in 1..SMALL_BURSTS {
        r.add_set(10);
        r.tls_send_all(set_frame_len(10), |_| {});
        assert!(r.io.tx_copy.capacity() >= MAX_CHUNK, "small burst {i}");
    }
    r.add_set(10);
    r.tls_send_all(set_frame_len(10), |_| {});
    assert!(!large(&mut r), "one release frees all three buffers");
    r.add_set(10);
    r.tls_send_all(set_frame_len(10), |_| {});
    assert!(!large(&mut r));

    // A large frame grows the buffers again.
    r.add_set(MAX_CHUNK);
    r.tls_send_all(set_frame_len(MAX_CHUNK), |_| {});
    assert!(large(&mut r));
}

/// Rule: a burst is small when its largest chunk fills less than half of
/// the largest buffer. A run of `SMALL_BURSTS` small bursts gives a
/// release. A large burst starts the run again. An end with no chunk is
/// not a burst.
#[test]
fn tls_writes_count_small_bursts_in_a_row() {
    let cap = MAX_CHUNK;
    let mut w = WriteBursts::default();
    let burst = |w: &mut WriteBursts, chunks: &[usize]| {
        for &n in chunks {
            assert!(!w.release(n, cap));
        }
        w.release(0, cap)
    };
    for _ in 1..SMALL_BURSTS {
        assert!(!burst(&mut w, &[100, 200]));
        assert!(!w.release(0, cap), "an end with no chunk");
    }
    assert!(!burst(&mut w, &[MAX_CHUNK, 44]), "a large burst");
    for _ in 1..SMALL_BURSTS {
        assert!(!burst(&mut w, &[cap / 2 - 1]));
    }
    assert!(burst(&mut w, &[cap / 2 - 1]));
    assert!(burst(&mut w, &[10]), "the run stays at its end");
    assert!(!burst(&mut w, &[cap / 2]), "half of the buffer is large");
}

/// Rule: a TLS chunk is at most `MAX_CHUNK` bytes, so proto never lends
/// a frame to the TLS path. A large frame is copied into the
/// buffer that `tx_copy` has, and that buffer stays.
#[test]
fn tls_large_frames_are_copied_in_chunks() {
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    let cap = TX_LEND_MAX;
    r.io.tx_copy = Zeroizing::new(Vec::with_capacity(cap));
    let at = r.io.tx_copy.as_ptr();
    // Miri interprets slowly. Its frame is smaller, but still spans more
    // than one chunk.
    let len = if cfg!(miri) { 320 * 1024 } else { 1024 * 1024 };
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    r.add_set_data(data.clone());
    let got = r.tls_send_all(set_frame_len(data.len()), |_| {});
    assert_eq!(got[got.len() - 4 - data.len()..got.len() - 4], data[..]);
    assert_eq!((r.io.tx_copy.as_ptr(), r.io.tx_copy.capacity()), (at, cap));
}

// The plaintext write path: the send cursor of
// `tx_copy`, the lend of large frames, and the release of a large
// `tx_copy`.

use crate::iocore::TX_LEND_MAX;
use zeroize::Zeroizing;

/// Returns the data size of a large plaintext frame. Proto lends a plain
/// frame of 512 KiB or more. Miri interprets slowly, so its frame is just
/// above that limit.
fn large_frame() -> usize {
    if cfg!(miri) { 520 * 1024 } else { 1024 * 1024 }
}

impl Rig {
    /// Gives WRITE events and reads the peer until the peer has `len`
    /// bytes. `each` sees the core after each event. It returns the
    /// bytes.
    fn plain_send_all(&mut self, len: usize, each: impl FnMut(&IoCore)) -> Vec<u8> {
        let mut got = Vec::new();
        self.plain_send_into(len, each, |b| got.extend_from_slice(b));
        got
    }

    /// Does what [`Rig::plain_send_all`] does, and gives the bytes to
    /// `sink`. The peer reads into a stack buffer, so the read makes no
    /// heap copy.
    fn plain_send_into(
        &mut self,
        len: usize,
        mut each: impl FnMut(&IoCore),
        mut sink: impl FnMut(&[u8]),
    ) {
        let mut got = 0;
        let mut buf = [0u8; 16 * 1024];
        for _ in 0..1000 {
            let (p, _) = self.process(write_ev());
            assert_eq!(p, Progress::Done(ZOK));
            each(&self.io);
            let mut fds = [PollFd::new(&self.peer, PollFlags::IN)];
            let _ = RealPoll.poll(&mut fds, 200);
            loop {
                match self.peer.recv(&mut buf) {
                    Ok(0) | Err(Errno::WOULDBLOCK) => break,
                    Ok(n) => {
                        sink(&buf[..n]);
                        got += n;
                    }
                    Err(Errno::INTR) => {}
                    Err(e) => panic!("peer recv: {e}"),
                }
            }
            if got >= len {
                break;
            }
        }
        assert_eq!(got, len, "the peer got every byte");
    }

    /// Sends `len` bytes as [`Rig::plain_send_into`] does, and drops the
    /// bytes.
    fn plain_send_discard(&mut self, len: usize, each: impl FnMut(&IoCore)) {
        self.plain_send_into(len, each, |_| {});
    }

    /// Puts a Unix socket pair with a 16 KiB send buffer in place of the
    /// loopback pair, so each large send is partial. The window of a
    /// loopback TCP pair can grow past the frame length, and the kernel
    /// can then take a whole frame in one send. A Unix stream takes at
    /// most its send buffer. Call it before [`Rig::plain_connected`].
    fn small_socket_buffers(&mut self) {
        use rustix::net::{AddressFamily, SocketFlags, SocketType};
        let (ours, peer) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::empty(),
            None,
        )
        .unwrap();
        rustix::net::sockopt::set_socket_send_buffer_size(&ours, 16 * 1024).unwrap();
        let (ours, peer) = (TcpSock::from_owned(ours), TcpSock::from_owned(peer));
        nonblocking(&ours);
        nonblocking(&peer);
        match &mut self.io.conn {
            Transport::Connecting { sock, .. } => *sock = ours,
            _ => panic!("the rig is not in the connect step"),
        }
        self.peer = peer;
    }
}

/// Rule: a partial plaintext send moves the cursor `tx_sent` and moves no
/// bytes. The buffer and its length stay until every byte is out. Then
/// `tx_copy` is empty and the cursor is 0. The peer gets the bytes in
/// order. The frame fits in one copy, so one buffer holds all of it.
#[test]
#[cfg_attr(miri, ignore = "Miri has no SO_SNDBUF, which forces the partial sends")]
fn plain_partial_sends_move_a_cursor() {
    let mut r = Rig::new(false, vec![]);
    r.small_socket_buffers();
    r.plain_connected();
    let data: Vec<u8> = (0..60 * 1024).map(|i| (i % 251) as u8).collect();
    r.add_set_data(data.clone());
    let len = set_frame_len(data.len());

    // Each entry is the buffer, its length and the cursor.
    let mut seen: Vec<(usize, usize, usize)> = Vec::new();
    let got = r.plain_send_all(len, |io| {
        if !io.tx_copy.is_empty() {
            assert!(io.sent_len() < io.tx_copy.len());
            seen.push((
                io.tx_copy.as_ptr() as usize,
                io.tx_copy.len(),
                io.sent_len(),
            ));
        }
    });
    assert_eq!(got[got.len() - 4 - data.len()..got.len() - 4], data[..]);
    assert!(r.io.tx_copy.is_empty() && r.io.tx_sent == 0);
    assert!(seen.len() >= 2 && seen[0].2 > 0, "partial sends: {seen:?}");
    for w in seen.windows(2) {
        assert_eq!((w[0].0, w[0].1), (w[1].0, w[1].1), "no bytes move");
        assert!(w[1].2 >= w[0].2, "the cursor moves forward: {w:?}");
    }
    assert!(seen.windows(2).any(|w| w[1].2 > w[0].2), "{seen:?}");

    // A reset drops the unsent bytes and the cursor.
    r.add_set(300 * 1024);
    let (p, _) = r.process(write_ev());
    assert_eq!(p, Progress::Done(ZOK));
    assert!(r.io.tx_sent > 0);
    r.io.drop_transport();
    assert!(r.io.tx_copy.is_empty() && r.io.tx_sent == 0);
}

/// Rule: a whole large frame goes out from its own buffer, with no copy.
/// The frame buffer replaces `tx_copy`, so the capacity of `tx_copy` is
/// then the exact frame length. A small frame before it goes out first,
/// and the bytes stay in order.
#[test]
fn plain_large_frames_are_lent() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    let big = large_frame();
    r.io.tx_copy = Zeroizing::new(Vec::with_capacity(TX_LEND_MAX));
    r.add_set(10);
    let data: Vec<u8> = (0..big).map(|i| (i % 251) as u8).collect();
    r.add_set_data(data.clone());
    let len = set_frame_len(10) + set_frame_len(big);
    let got = r.plain_send_all(len, |io| {
        if !io.tx_copy.is_empty() {
            assert_eq!(io.tx_copy.capacity(), set_frame_len(big), "a lent buffer");
        }
    });
    // The small frame comes first: its prefix, its header and its data.
    let be = |at: usize| i32::from_be_bytes(got[at..at + 4].try_into().unwrap());
    let small = set_frame_len(10);
    assert_eq!(be(0), i32::try_from(small - 4).unwrap());
    let xid = be(4);
    assert_eq!(be(8), zk_jute::opcode::SET_DATA);
    assert_eq!(got[small - 14..small - 4], [0x5a; 10]);
    // The large frame follows with the next xid.
    assert_eq!(be(small), i32::try_from(set_frame_len(big) - 4).unwrap());
    assert_eq!(
        (be(small + 4), be(small + 8)),
        (xid + 1, zk_jute::opcode::SET_DATA)
    );
    assert_eq!(got[got.len() - 4 - big..got.len() - 4], data[..]);
    assert_eq!(r.io.tx_copy.capacity(), set_frame_len(big));
    assert!(r.io.tx_copy.is_empty());
}

/// Rule: a large `tx_copy` stays while large frames go out, and goes back
/// after `SMALL_BURSTS` small bursts in a row, with the rule of the TLS
/// path. A small `tx_copy` stays.
#[test]
fn plain_large_tx_copy_goes_back_after_small_writes() {
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    let big = large_frame();
    r.add_set(big);
    r.plain_send_all(set_frame_len(big), |_| {});
    assert_eq!(r.io.tx_copy.capacity(), set_frame_len(big));
    for i in 1..SMALL_BURSTS {
        r.add_set(10);
        r.plain_send_all(set_frame_len(10), |_| {});
        assert_eq!(
            r.io.tx_copy.capacity(),
            set_frame_len(big),
            "small burst {i}"
        );
    }
    r.add_set(10);
    r.plain_send_all(set_frame_len(10), |_| {});
    assert_eq!(r.io.tx_copy.capacity(), 0, "the release ran");
    for _ in 0..2 * SMALL_BURSTS {
        r.add_set(10);
        r.plain_send_all(set_frame_len(10), |_| {});
        let cap = r.io.tx_copy.capacity();
        assert!(cap > 0 && cap <= READ_BUFFER_LEN, "a small buffer stays");
    }
}

/// Rule: no freed heap block holds the credential of an auth packet that
/// went out on the plaintext path with large frames (spec "send queue").
/// The cases are partial sends with the cursor, the lend of a
/// large frame after the packet, and the release of a large `tx_copy`.
/// `zk-client/tests/free_scan/free_scan.sh` runs this test with the free
/// scanner, as for `tx_copy_is_zero_before_free`.
#[test]
#[ignore = "free-scan"]
fn plain_large_tx_copy_is_zero_before_free() {
    let Some(out) = std::env::var_os("ZK_FREE_SCAN_OUT") else {
        return;
    };
    let hits = || {
        std::fs::read_to_string(&out)
            .map(|t| t.lines().filter(|l| l.starts_with("hit")).count())
            .unwrap_or(0)
    };
    drop(std::hint::black_box(TX_MARKER.to_vec()));
    let control = hits();
    assert!(control >= 1, "the free scanner does not run");

    // Partial sends of the packet and a request in one copy. The peer
    // reads into a stack buffer, so the test makes no heap copy of the
    // marker.
    let mut r = Rig::new(false, vec![]);
    r.small_socket_buffers();
    r.plain_connected();
    r.add_marker_auth();
    r.add_set(300 * 1024);
    let mut partial = false;
    r.plain_send_discard(auth_frame_len() + set_frame_len(300 * 1024), |io| {
        partial |= io.tx_sent > 0;
    });
    assert!(partial, "a send was partial");
    drop(std::mem::take(&mut *r.io.tx_copy));
    assert_eq!(
        hits(),
        control,
        "the cursor path frees a copy of the packet"
    );

    // The packet goes out first. The next copy erases it, then lends a
    // large frame, and frees the old buffer as a plain `Vec`.
    let mut r = Rig::new(false, vec![]);
    r.plain_connected();
    r.io.tx_copy = Zeroizing::new(Vec::with_capacity(TX_LEND_MAX));
    r.add_marker_auth();
    r.add_set(1024 * 1024);
    r.plain_send_discard(auth_frame_len() + set_frame_len(1024 * 1024), |_| {});
    assert_eq!(r.io.tx_copy.capacity(), set_frame_len(1024 * 1024));
    assert_eq!(hits(), control, "the lend frees a copy of the packet");

    // An old copy of the packet in the large lent buffer. The run of
    // small bursts then frees the buffer.
    r.add_marker_auth();
    r.plain_send_discard(auth_frame_len(), |_| {});
    for _ in 0..SMALL_BURSTS {
        r.add_set(10);
        r.plain_send_discard(set_frame_len(10), |_| {});
    }
    assert!(
        r.io.tx_copy.capacity() <= READ_BUFFER_LEN,
        "the release ran"
    );
    assert_eq!(hits(), control, "the release frees a copy of the packet");
    drop(r);
    assert_eq!(hits(), control, "the drop leaves the auth packet");
}

/// A TLS session for the free-scan test. Its cipher is an XOR mask, so
/// no buffer of the session holds plaintext. The handshake is complete,
/// and `take_ciphertext` swaps buffers as rustls does.
#[derive(Default)]
struct MaskTls {
    out: Vec<u8>,
    plain: Vec<u8>,
}

/// The XOR mask of [`MaskTls`].
const MASK: u8 = 0xa5;

impl TlsConn for MaskTls {
    fn is_handshaking(&self) -> bool {
        false
    }

    fn has_ciphertext(&self) -> bool {
        !self.out.is_empty()
    }

    fn feed(&mut self, ciphertext: &[u8]) -> Result<(), TlsFailure> {
        self.plain.extend(ciphertext.iter().map(|b| b ^ MASK));
        Ok(())
    }

    fn feed_eof(&mut self) -> Result<(), TlsFailure> {
        Err(TlsFailure::Closed)
    }

    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> Result<usize, TlsFailure> {
        let n = self.plain.len();
        out.append(&mut self.plain);
        Ok(n)
    }

    fn write_frame(&mut self, plaintext: &[u8]) -> Result<(), TlsFailure> {
        self.out.extend(plaintext.iter().map(|b| b ^ MASK));
        Ok(())
    }

    fn take_ciphertext(&mut self, out: &mut Vec<u8>) -> usize {
        let n = self.out.len();
        crate::net::tls::move_ciphertext(out, &mut self.out);
        n
    }

    fn send_close_notify(&mut self) {}
}

/// Rule: no freed heap block holds the credential of an auth packet that
/// went out on TLS (spec "send queue"). The cases are a large
/// chunk that holds the packet and comes in by a buffer swap, a release
/// after real small flushes, and the release of a large `tx_copy` that
/// holds an old copy of the packet.
/// `zk-client/tests/free_scan/free_scan.sh` runs this test with the free
/// scanner, as for `tx_copy_is_zero_before_free`.
#[test]
#[ignore = "free-scan"]
fn tls_tx_copy_is_zero_before_free() {
    let Some(out) = std::env::var_os("ZK_FREE_SCAN_OUT") else {
        return;
    };
    let hits = || {
        std::fs::read_to_string(&out)
            .map(|t| t.lines().filter(|l| l.starts_with("hit")).count())
            .unwrap_or(0)
    };
    drop(std::hint::black_box(TX_MARKER.to_vec()));
    let control = hits();
    assert!(control >= 1, "the free scanner does not run");

    // The masked session replaces the null session after the handshake.
    let mut r = Rig::new(true, vec![]);
    r.tls_connected();
    let Transport::Tls(t) = std::mem::replace(&mut r.io.conn, Transport::None) else {
        panic!("no TLS transport");
    };
    r.io.conn = Transport::Tls(TlsTransport::new(t.into_sock(), Box::<MaskTls>::default()));

    // The packet and a large request in one chunk, then the tail chunk.
    r.add_marker_auth();
    r.add_set(MAX_CHUNK);
    let got = r.tls_send_all(auth_frame_len() + set_frame_len(MAX_CHUNK), |_| {});
    drop(got);
    assert!(r.io.tx_copy.capacity() >= MAX_CHUNK);
    assert_eq!(hits(), control, "the swap path frees a copy of the packet");

    // Real flushes of small bursts give the release.
    for _ in 0..SMALL_BURSTS {
        r.add_set(10);
        r.tls_send_all(set_frame_len(10), |_| {});
    }
    assert_eq!(r.io.tx_copy.capacity(), 0, "the flush released tx_copy");
    assert!(r.tls().ct_out.capacity() <= READ_BUFFER_LEN);
    assert!(r.session_capacity() <= READ_BUFFER_LEN);
    assert_eq!(hits(), control, "the flush release frees the packet");

    // An old copy of the packet in a large buffer. The release must
    // erase it.
    r.add_set(MAX_CHUNK);
    r.tls_send_all(set_frame_len(MAX_CHUNK), |_| {});
    r.add_marker_auth();
    assert!(r.copy_released() > 0);
    assert!(holds_marker(&r.io.tx_copy));
    r.io.tx_copy.clear();
    for _ in 0..SMALL_BURSTS {
        release_large_buffers(&mut r.io, 10);
        release_large_buffers(&mut r.io, 0);
    }
    assert_eq!(r.io.tx_copy.capacity(), 0, "the release ran");
    assert_eq!(hits(), control, "the release frees a copy of the packet");
    drop(r);
    assert_eq!(hits(), control, "the drop leaves the auth packet");
}

// The loom models. They use the rig of this file, so they are a child
// module.
#[cfg(loom)]
#[path = "loom_models.rs"]
mod loom_models;
