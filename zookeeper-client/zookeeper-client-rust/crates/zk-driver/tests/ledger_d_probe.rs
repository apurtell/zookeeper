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

//! The RW probe closes its socket on every path.
//!
//! Legacy leaks the probe socket when the connect fails. This test runs
//! many probes on each end of a probe and counts the open descriptors of
//! the process before and after. The file has one test, so no other test
//! opens descriptors at the same time.

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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use zk_driver::clock::MonotonicClock;
use zk_driver::net::poll::RustixPoll;
use zk_driver::net::probe::{ProbeCtx, ProbeEnd, probe};
use zk_driver::sync::Unlocked;
use zk_proto::{Endpoint, HostToken, ProbeOutcome};

/// The number of probes on each path.
const ROUNDS: usize = 20;

/// What the fake server does with one probe connection.
#[derive(Clone, Copy)]
enum Server {
    /// Read `isro`, then send the reply and close.
    Reply(&'static [u8]),
    /// Read until the client closes. The probe ends at its phase budget.
    Silent,
}

/// Counts the open descriptors of the process.
fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

fn ep(addr: SocketAddr) -> Endpoint {
    Endpoint {
        addr,
        host: HostToken::default(),
    }
}

fn run(addr: SocketAddr, phase_ms: u64) -> ProbeEnd {
    let clock = MonotonicClock::new();
    let cx = ProbeCtx {
        poll: &RustixPoll,
        clock: &clock,
        wake: None,
        abort: None,
        tls: None,
        // Miri has no `fcntl(F_SETFD)`, so it opens the socket with no
        // CLOEXEC.
        cloexec: !cfg!(miri),
        phase_ms,
    };
    probe(&cx, &Unlocked::new_at_entry(), &ep(addr), None)
}

/// Runs one probe against a server thread that follows `server`.
fn probe_server(server: Server, phase_ms: u64) -> ProbeEnd {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 4];
        match server {
            Server::Reply(reply) => {
                s.read_exact(&mut buf).unwrap();
                s.write_all(reply).unwrap();
            }
            Server::Silent => {
                let mut rest = Vec::new();
                let _ = s.read_to_end(&mut rest);
            }
        }
    });
    let end = run(addr, phase_ms);
    t.join().unwrap();
    end
}

/// A port where no server listens.
fn closed_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

/// The probe closes its socket after a failed connect, a timeout, an
/// EOF and a reply, so the descriptor count of the process stays the same.
#[test]
fn probe_closes_its_socket_on_every_path() {
    let before = open_fds();
    for _ in 0..ROUNDS {
        let addr = closed_port();
        assert_eq!(run(addr, 1000), ProbeEnd::Done(ProbeOutcome::Failed(None)));
    }
    assert_eq!(open_fds(), before, "a failed connect leaks the socket");
    for _ in 0..ROUNDS {
        assert_eq!(
            probe_server(Server::Silent, 50),
            ProbeEnd::Done(ProbeOutcome::Failed(None))
        );
    }
    assert_eq!(open_fds(), before, "a timeout leaks the socket");
    for _ in 0..ROUNDS {
        assert_eq!(
            probe_server(Server::Reply(b""), 1000),
            ProbeEnd::Done(ProbeOutcome::NotReadWrite)
        );
        assert_eq!(
            probe_server(Server::Reply(b"rw"), 1000),
            ProbeEnd::Done(ProbeOutcome::ReadWrite)
        );
        assert_eq!(
            probe_server(Server::Reply(b"ro"), 1000),
            ProbeEnd::Done(ProbeOutcome::NotReadWrite)
        );
    }
    assert_eq!(open_fds(), before, "a reply or an EOF leaks the socket");
}
