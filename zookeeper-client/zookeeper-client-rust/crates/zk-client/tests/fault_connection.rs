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

//! Fault tests of the connection: a loss in the middle of a request,
//! the receive deadline, bad frames, the frame cap, and the mapping of
//! each teardown cause to the request error and to `last_error`.
//!
//! Each test names its rule and the source: "spec" is
//! `design/specification.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{
    CreateMode, DisconnectCause, Error, EventKind, Metrics, OpKind, Runtime, SessionState,
    StateWatcher, WatchError,
};
use zk_fakeserver::{
    Action, AuthPolicy, ClusterConfig, FakeServer, FrameKind, Malformed, Rule, ServerOptions,
};
use zk_jute::opcode;

use common::{connect, thread, wait_info, within};

/// A fake server whose cluster accepts session timeouts down to 1 s.
fn short_fake() -> FakeServer {
    let cfg = ClusterConfig {
        min_session_timeout_ms: 1_000,
        ..ClusterConfig::default()
    };
    FakeServer::start_with(cfg, ServerOptions::default()).expect("fake server bind")
}

/// The `DisconnectCause` in `last_error`, if it is one.
fn cause_of(w: &StateWatcher) -> Option<DisconnectCause> {
    w.last_error()
        .and_then(|e| e.downcast_ref::<DisconnectCause>().copied())
}

/// Waits until `last_error` holds `want`.
async fn wait_cause(w: &StateWatcher, want: DisconnectCause) {
    within(async {
        while cause_of(w) != Some(want) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

/// A metrics hook that counts the completions of each request kind.
#[derive(Default)]
struct Completions(Mutex<Vec<(OpKind, Result<(), Error>)>>);

struct Hook(Arc<Completions>);

impl Metrics for Hook {
    fn request_completed(&self, op: OpKind, result: Result<(), &Error>, _latency: Duration) {
        self.0
            .0
            .lock()
            .unwrap()
            .push((op, result.map_err(Clone::clone)));
    }
}

impl Completions {
    fn of(&self, op: OpKind) -> Vec<Result<(), Error>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(o, _)| *o == op)
            .map(|(_, r)| r.clone())
            .collect()
    }
}

/// Rule: on a disconnect, every request in flight or queued fails, and
/// natively the error is `ConnectionLoss` (spec "Operations, Result
/// Types, and Error Handling"). Each future gives its error once and
/// the client does not send the request again after the reconnect.
async fn loss_mid_request(rt: Option<Runtime>) {
    let fs = common::fake();
    let seen = Arc::new(Completions::default());
    let mut b = common::builder(&fs.connect_string()).metrics(Hook(Arc::clone(&seen)));
    if let Some(rt) = rt {
        b = b.runtime(rt);
    }
    let c = connect(b).await;
    let mut w = c.state_watcher();
    let epoch = w.current().epoch;

    // The server holds the frames, so the requests stay in flight.
    fs.hold();
    let create = c.create("/lost", b"x", CreateMode::Persistent, OPEN_ACL_UNSAFE);
    let get = c.get_data("/");
    let exists = c.exists("/");
    tokio::time::sleep(Duration::from_millis(100)).await;
    fs.drop_connections();
    fs.release();

    assert_eq!(within(create).await, Err(Error::ConnectionLoss));
    assert_eq!(within(get).await.err(), Some(Error::ConnectionLoss));
    assert_eq!(within(exists).await, Err(Error::ConnectionLoss));

    // The client reconnects in the same session, and new requests work.
    wait_info(&mut w, |i| {
        i.state == SessionState::Connected && i.epoch > epoch
    })
    .await;
    assert!(within(c.exists("/")).await.unwrap().is_some());

    // Each lost request completed once, with ConnectionLoss.
    assert_eq!(seen.of(OpKind::Create), vec![Err(Error::ConnectionLoss)]);
    assert_eq!(seen.of(OpKind::GetData), vec![Err(Error::ConnectionLoss)]);
    // The client never sent the lost create again.
    let creates = fs
        .transcript()
        .iter()
        .filter(|r| r.op == Some(opcode::CREATE2) && r.path.as_deref() == Some("/lost"))
        .count();
    assert!(creates <= 1, "the create went out {creates} times");
    within(c.close()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loss_fails_every_pending_request_once_default_runtime() {
    loss_mid_request(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loss_fails_every_pending_request_once_thread_runtime() {
    loss_mid_request(Some(thread())).await;
}

/// Rule: a server close at one request fails that request and every
/// request behind it with `ConnectionLoss`. Earlier replies stay good.
/// `last_error` is `DisconnectCause::ServerClosed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_close_fails_the_request_and_those_behind_it() {
    let fs = common::fake();
    fs.cluster().create("/a", b"1", 0).unwrap();
    let c = connect(common::builder(&fs.connect_string())).await;
    let w = c.state_watcher();
    fs.add_rule(Rule::on_request().path("/boom").once().then(Action::Close));
    let before = c.get_data("/a");
    let boom = c.get_data("/boom");
    let after = c.exists("/a");
    assert_eq!(within(before).await.unwrap().0, b"1");
    assert_eq!(within(boom).await.err(), Some(Error::ConnectionLoss));
    assert_eq!(within(after).await, Err(Error::ConnectionLoss));
    wait_cause(&w, DisconnectCause::ServerClosed).await;
    // The next request waits for the reconnect and works.
    assert!(within(c.exists("/a")).await.unwrap().is_some());
    within(c.close()).await.unwrap();
}

/// Rule: no frame within 2/3 of the session timeout ends the
/// connection. The pending request fails with `ConnectionLoss` and
/// `last_error` is `DisconnectCause::ReceiveTimeout`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_server_hits_the_receive_deadline() {
    let fs = short_fake();
    let c = connect(
        common::builder(&fs.connect_string()).session_timeout(Duration::from_millis(2_000)),
    )
    .await;
    assert_eq!(c.negotiated_timeout(), Some(Duration::from_millis(2_000)));
    let mut w = c.state_watcher();
    fs.add_rule(Rule::on_request().path("/stall").once().then(Action::Stall));
    let start = Instant::now();
    let r = within(c.get_data("/stall")).await;
    let took = start.elapsed();
    assert_eq!(r.err(), Some(Error::ConnectionLoss));
    // The deadline is 2/3 of 2 s. Allow for the timer and the scheduler.
    assert!(
        took >= Duration::from_millis(1_000) && took < Duration::from_millis(2_500),
        "the request failed after {took:?}"
    );
    assert_eq!(cause_of(&w), Some(DisconnectCause::ReceiveTimeout));
    // The session survives: the reconnect is within the session timeout.
    let (id, _) = c.session();
    wait_info(&mut w, |i| {
        i.state == SessionState::Connected && i.epoch >= 2
    })
    .await;
    assert_eq!(c.session().0, id);
    within(c.close()).await.unwrap();
}

/// Rule: a reply that does not match the oldest pending xid is a
/// protocol error: `ConnectionLoss` for the requests, and `last_error`
/// is `DisconnectCause::XidMismatch`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_xid_tears_down_with_xid_mismatch() {
    let fs = common::fake();
    let c = connect(common::builder(&fs.connect_string())).await;
    let w = c.state_watcher();
    fs.add_rule(
        Rule::on_request()
            .op(opcode::GET_DATA)
            .once()
            .then(Action::RewriteXid(0x7777)),
    );
    assert_eq!(
        within(c.get_data("/")).await.err(),
        Some(Error::ConnectionLoss)
    );
    wait_cause(&w, DisconnectCause::XidMismatch).await;
    assert!(within(c.exists("/")).await.unwrap().is_some());
    within(c.close()).await.unwrap();
}

/// Rule: a frame that cannot be decoded is a protocol error:
/// `ConnectionLoss`, and `last_error` is
/// `DisconnectCause::MalformedFrame`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_frame_tears_down_with_malformed_frame() {
    for bad in [
        Malformed::NegativeLength(-7),
        Malformed::ShortHeader(vec![0, 0, 0, 1]),
    ] {
        let fs = common::fake();
        let c = connect(common::builder(&fs.connect_string())).await;
        let w = c.state_watcher();
        fs.add_rule(
            Rule::on_request()
                .op(opcode::GET_DATA)
                .once()
                .then(Action::Malformed(bad.clone())),
        );
        assert_eq!(
            within(c.get_data("/")).await.err(),
            Some(Error::ConnectionLoss),
            "{bad:?}"
        );
        wait_cause(&w, DisconnectCause::MalformedFrame).await;
        assert!(within(c.exists("/")).await.unwrap().is_some());
        within(c.close()).await.unwrap();
    }
}

/// Rule: an inbound frame above `max_frame_size` is a protocol error
/// with `ConnectionLoss` and `DisconnectCause::MalformedFrame`. Smaller
/// frames pass (spec "Client Construction and Configuration": "bounding
/// maximum inbound frame sizes").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_frame_size_caps_the_inbound_frames() {
    let fs = common::fake();
    fs.cluster().create("/small", &[7u8; 100], 0).unwrap();
    fs.cluster().create("/big", &[9u8; 4_096], 0).unwrap();
    let c = connect(common::builder(&fs.connect_string()).max_frame_size(1_024)).await;
    let w = c.state_watcher();
    assert_eq!(within(c.get_data("/small")).await.unwrap().0.len(), 100);
    assert_eq!(
        within(c.get_data("/big")).await.err(),
        Some(Error::ConnectionLoss)
    );
    wait_cause(&w, DisconnectCause::MalformedFrame).await;
    // The cap applies to each frame, so small reads go on.
    assert_eq!(within(c.get_data("/small")).await.unwrap().0.len(), 100);
    within(c.close()).await.unwrap();

    // The default cap of 4 MiB passes the same reply.
    let d = connect(common::builder(&fs.connect_string())).await;
    assert_eq!(within(d.get_data("/big")).await.unwrap().0.len(), 4_096);
    within(d.close()).await.unwrap();
}

/// Rule: a refused TCP connect gives an `io::Error` in `last_error`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_connect_shows_an_io_error() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let c = common::builder(&format!("127.0.0.1:{port}"))
        .connect_timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let w = c.state_watcher();
    within(async {
        loop {
            if let Some(e) = w.last_error() {
                if let Some(io) = e.downcast_ref::<std::io::Error>() {
                    assert_eq!(io.kind(), std::io::ErrorKind::ConnectionRefused, "{io}");
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert_eq!(c.state().state, SessionState::Connecting);
    within(c.close()).await.unwrap();
}

/// Rule: expiry is terminal. Requests fail with `SessionExpired`, the
/// state is `Expired`, and `last_error` is cleared. Watchers end with
/// `WatchError::SessionExpired`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_is_terminal_and_clears_last_error() {
    let fs = common::fake();
    let c = connect(common::builder(&fs.connect_string())).await;
    let mut w = c.state_watcher();
    let (_, watcher) = within(c.exists_watched("/x")).await.unwrap();
    fs.add_rule(
        Rule::on_request()
            .path("/expire")
            .once()
            .then(Action::ExpireSession),
    );
    // The connection closes first, so this request sees the loss.
    let r = within(c.get_data("/expire")).await;
    assert_eq!(r.err(), Some(Error::ConnectionLoss));
    wait_info(&mut w, |i| i.state == SessionState::Expired).await;
    assert!(w.last_error().is_none(), "{:?}", w.last_error());
    assert_eq!(within(watcher).await, Err(WatchError::SessionExpired));
    let f = c.exists("/");
    assert!(f.is_ready(), "a request after expiry fails at once");
    assert_eq!(within(f).await, Err(Error::SessionExpired));
    // The state stays terminal, and a close completes at once.
    within(c.close()).await.unwrap();
    assert_eq!(c.state().state, SessionState::Expired);
}

/// Rule: a refused digest auth is terminal. Requests fail with
/// `AuthFailed`, the state is `AuthFailed`, and `last_error` is
/// cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_auth_is_terminal() {
    let cfg = ClusterConfig {
        auth: AuthPolicy::RejectAll,
        ..ClusterConfig::default()
    };
    let fs = FakeServer::start_with(cfg, ServerOptions::default()).unwrap();
    let c = connect(common::builder(&fs.connect_string())).await;
    let mut w = c.state_watcher();
    let (_, watcher) = within(c.exists_watched("/x")).await.unwrap();
    assert_eq!(
        within(c.add_auth("digest", b"u:p".to_vec())).await,
        Err(Error::AuthFailed)
    );
    wait_info(&mut w, |i| i.state == SessionState::AuthFailed).await;
    assert!(w.last_error().is_none());
    assert_eq!(within(watcher).await, Err(WatchError::AuthFailed));
    assert_eq!(within(c.exists("/")).await, Err(Error::AuthFailed));
}

/// Rule: a one-shot watch survives a reconnect when `restore_watches`
/// is on, and the event after the reconnect still arrives (spec
/// "Watcher Abstractions": "registered watches survive transport
/// reconnections").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watch_survives_a_loss_and_fires_after_the_reconnect() {
    let fs = common::fake();
    let c = connect(common::builder(&fs.connect_string())).await;
    let mut w = c.state_watcher();
    let (_, watcher) = within(c.exists_watched("/later")).await.unwrap();
    fs.drop_connections();
    wait_info(&mut w, |i| {
        i.state == SessionState::Connected && i.epoch >= 2
    })
    .await;
    assert!(
        fs.wait_for(common::WAIT, |r| r.kind == FrameKind::Request
            && (r.op == Some(opcode::SET_WATCHES)
                || r.op == Some(opcode::SET_WATCHES2)))
            .is_some()
    );
    fs.cluster().create("/later", b"", 0).unwrap();
    let ev = within(watcher).await.unwrap();
    assert_eq!(ev.kind, EventKind::NodeCreated);
    within(c.close()).await.unwrap();
}
