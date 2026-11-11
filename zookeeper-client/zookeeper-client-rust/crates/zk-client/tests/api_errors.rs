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

//! API contract tests of the error mapping: each wire reply code to its
//! `Error`, and the teardown causes that `fault_connection.rs` does not
//! cover. That file covers `Eof`, `RecvTimeout`, `XidMismatch`,
//! `ProtocolError`, `ConnectFailed`, `SessionExpired` and `AuthFailed`.
//! `api_tls.rs` covers the TLS causes.
//!
//! Each test names its rule and the source: "spec" is
//! `design/specification.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use apache_zookeeper::{
    Client, ClientBuilder, Error, Resolve, ServerOrder, SessionState, StateWatcher,
};
use zk_fakeserver::{Action, Cluster, ClusterConfig, Rule, ServerOptions};
use zk_jute::opcode;

use common::{connect, within};

/// Waits until `pred` holds for the state.
async fn wait_state(w: &mut StateWatcher, want: SessionState) {
    within(async {
        while w.current().state != want {
            let _ = w.changed().await;
        }
    })
    .await;
}

/// Every reply code of the server and the client codes that a reply
/// can carry. The list follows the `Error` enum.
const CODES: [i32; 35] = [
    -1, -2, -3, -4, -5, -6, -7, -8, -9, -12, -13, -14, -15, -100, -101, -102, -103, -108, -110,
    -111, -112, -113, -114, -115, -116, -117, -118, -119, -120, -121, -122, -123, -124, -125, -127,
];

/// Rule: a non-zero reply code reaches the caller as
/// `Error::from_code(rc)`. A code outside the table stays as
/// `Error::Unknown(rc)`, as C passes reply codes through (spec
/// "Operations, Result Types, and Error Handling").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_reply_code_maps_to_its_error() {
    let fs = common::fake();
    for rc in CODES.iter().copied().chain([-77, -200]) {
        fs.add_rule(
            Rule::on_request()
                .op(opcode::GET_DATA)
                .path("/rc")
                .once()
                .then(Action::Reply { err: rc }),
        );
    }
    let c = connect(common::builder(&fs.connect_string())).await;
    for rc in CODES.iter().copied().chain([-77, -200]) {
        let want = Error::from_code(rc).unwrap();
        let got = within(c.get_data("/rc")).await;
        assert_eq!(got.err(), Some(want), "rc {rc}");
    }
    // A reply code does not end the session.
    assert_eq!(c.state().state, SessionState::Connected);
    assert_eq!(c.state().epoch, 1);
    within(c.close()).await.unwrap();
}

/// Rule: the error of a reply with a body is the code, not the body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rewritten_code_wins_over_the_body() {
    let fs = common::fake();
    fs.add_rule(
        Rule::on_request()
            .op(opcode::GET_DATA)
            .once()
            .then(Action::RewriteErr(-102)),
    );
    let c = connect(common::builder(&fs.connect_string())).await;
    assert_eq!(within(c.get_data("/")).await.err(), Some(Error::NoAuth));
    within(c.get_data("/")).await.unwrap();
    within(c.close()).await.unwrap();
}

/// A resolver that gives no address.
struct Empty;

impl Resolve for Empty {
    fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(Vec::new())
    }
}

/// Rule: with no address to try, the teardown cause is `SocketCreate`,
/// and `last_error` is an `io::Error`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_address_gives_an_io_last_error() {
    let c = common::builder("zk.invalid:2181")
        .resolver(Empty)
        .reconnect_delay(Duration::from_millis(20))
        .build()
        .unwrap();
    let w = c.state_watcher();
    let e = within(async {
        loop {
            if let Some(e) = w.last_error() {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let io = e.downcast_ref::<io::Error>().expect("an io::Error");
    assert_eq!(io.kind(), io::ErrorKind::AddrNotAvailable, "{io}");
    assert_eq!(c.state().state, SessionState::Connecting);
    // A request in this state waits. The next failed pass fails it with
    // `ConnectionLoss`, or the close fails it with `Closing`.
    let f = c.get_data("/");
    within(c.close()).await.ok();
    let r = within(f).await;
    assert!(
        matches!(r, Err(Error::Closing | Error::ConnectionLoss)),
        "{r:?}"
    );
}

/// Rule: a move by `update_servers` is a forced close. Pending requests
/// get `ConnectionLoss`, and `last_error` stays as it was: a forced move
/// is not an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forced_move_keeps_last_error() {
    let cluster = Cluster::new(ClusterConfig::default());
    let a = cluster.start_server(ServerOptions::default()).unwrap();
    let b = cluster.start_server(ServerOptions::default()).unwrap();
    let c = connect(common::builder(&a.connect_string())).await;
    let mut w = c.state_watcher();
    assert!(w.last_error().is_none());
    a.hold();
    let pending = c.get_data("/");
    c.update_servers(&b.connect_string()).unwrap();
    assert_eq!(within(pending).await, Err(Error::ConnectionLoss));
    within(async {
        while c.connected_server() != Some(b.addr()) {
            let _ = w.changed().await;
        }
    })
    .await;
    assert!(w.last_error().is_none(), "{:?}", w.last_error());
    a.release();
    within(c.close()).await.unwrap();
}

/// Rule: a client on a read-only server moves to a read-write server
/// when its probe finds one. The switch is not an error, so
/// `last_error` stays as it was (spec "Read-write probing and mode
/// switching").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_write_switch_keeps_last_error() {
    let cluster = Cluster::new(ClusterConfig::default());
    let ro = cluster
        .start_server(ServerOptions {
            read_only: true,
            ..ServerOptions::default()
        })
        .unwrap();
    let mut rw = cluster.start_server(ServerOptions::default()).unwrap();
    let rw_addr = rw.addr();
    rw.stop();
    let c = connect(
        common::builder(&format!("{},{}", ro.addr(), rw_addr))
            .server_order(ServerOrder::AsGiven)
            .allow_read_only(true),
    )
    .await;
    let mut w = c.state_watcher();
    assert_eq!(w.current().state, SessionState::ConnectedReadOnly);
    assert!(w.last_error().is_none());
    rw.resume().unwrap();
    within(async {
        while !(w.current().state == SessionState::Connected
            && c.connected_server() == Some(rw_addr))
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(w.last_error().is_none(), "{:?}", w.last_error());
    wait_state(&mut w, SessionState::Connected).await;
    within(c.close()).await.unwrap();
}

/// A zero session or connect timeout expires at once, so the client
/// would never connect. `build` refuses it with `InvalidArgument`. The
/// default connect timeout is a third of the session timeout, so it
/// counts too.
#[test]
fn a_zero_timeout_is_refused() {
    let refused = |b: ClientBuilder| match b.build() {
        Err(e) => matches!(e.error(), Error::InvalidArgument(_)),
        Ok(_) => false,
    };
    let b = || Client::builder("127.0.0.1:1");
    assert!(refused(b().session_timeout(Duration::ZERO)));
    assert!(refused(b().session_timeout(Duration::from_micros(900))));
    assert!(refused(b().connect_timeout(Duration::ZERO)));
    assert!(refused(b().session_timeout(Duration::from_millis(2))));
    assert!(!refused(
        b().session_timeout(Duration::from_millis(2))
            .connect_timeout(Duration::from_millis(1))
    ));
}
