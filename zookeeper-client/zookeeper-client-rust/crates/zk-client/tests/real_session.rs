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

//! Session tests against a real server of this source tree: resume,
//! expiry, the disconnect causes, `close` and `detach`.
//!
//! All tests of this file share one server at port offset 13. A test
//! that must break the connection of one client puts a [`Proxy`] in
//! front of the server. The tests have `#[ignore = "real-server"]`.
//! Run them with
//! `ZK_TEST_PORT_BASE=<base> cargo test --test real_session -- --ignored`.

// A scenario is one long async body. It runs on a 2 MiB test or worker
// thread, so the stack frame limit of the library does not apply.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::io::ErrorKind;
use std::time::Duration;

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{
    AddWatchMode, Client, ClientBuilder, CreateMode, DisconnectCause, EphemeralKind, Error,
    EventKind, SessionInfo, SessionState, WatchError,
};
use common::proxy::Proxy;
use common::{Ctx, Rt, SharedServer, WAIT, setup, wait_state, within};

/// The server of this file.
static SERVER: SharedServer = SharedServer::new(13);

/// Runs `scenario` once per driver, each on a multi-thread runtime.
macro_rules! real_test {
    ($name:ident) => {
        mod $name {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore = "real-server"]
            async fn thread() {
                if let Some(ctx) = Ctx::new(&SERVER, stringify!($name), Rt::Thread) {
                    super::$name(ctx).await;
                }
            }

            #[cfg(all(unix, feature = "tokio"))]
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore = "real-server"]
            async fn tokio() {
                if let Some(ctx) = Ctx::new(&SERVER, stringify!($name), Rt::Tokio) {
                    super::$name(ctx).await;
                }
            }
        }
    };
}

/// A test builder for `proxy` with the driver of `ctx`.
fn via(ctx: &Ctx, proxy: &Proxy) -> ClientBuilder {
    ctx.rt.apply(common::builder(&proxy.connect_string()))
}

/// True when the end of a connection by the peer explains `info`. A
/// clean end is `ServerClosed`. A reset during a write is an io error.
fn peer_closed(info: &SessionInfo) -> bool {
    common::disconnect_cause(info) == Some(DisconnectCause::ServerClosed)
        || matches!(
            common::io_error_kind(info),
            Some(ErrorKind::ConnectionReset | ErrorKind::BrokenPipe)
        )
}

/// Creates an ephemeral node with no data.
async fn ephemeral(c: &Client, path: &str) {
    within(c.create(path, b"", CreateMode::Ephemeral, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
}

real_test!(detach_keeps_the_session);
/// Rule: `detach` fails the pending requests with `Closing`, ends the
/// watchers with `Closed`, and keeps the session. `ClientBuilder::session`
/// resumes it with its ephemerals.
async fn detach_keeps_the_session(ctx: Ctx) {
    let admin = setup(&ctx).await;
    let eph = ctx.path("/eph");
    let proxy = Proxy::start(ctx.port());
    let c = within(via(&ctx, &proxy).connect()).await.unwrap();
    ephemeral(&c, &eph).await;
    let (_, _, w) = within(c.get_data_watched(&eph)).await.unwrap();
    let mut p = within(c.add_watch(&ctx.root, AddWatchMode::Persistent))
        .await
        .unwrap();
    let mut s = c.state_watcher();

    // The held connection keeps the request pending.
    proxy.hold();
    let pending = c.get_data(&eph);
    let (id, pw) = c.detach();
    assert_eq!(within(pending).await, Err(Error::Closing));
    assert_eq!(within(w).await, Err(WatchError::Closed));
    assert_eq!(within(p.next()).await, Some(Err(WatchError::Closed)));
    assert_eq!(within(p.next()).await, None);
    wait_state(&mut s, WAIT, |i| i.state == SessionState::Closed).await;

    // The session lives on, and so does its ephemeral.
    let (_, st) = within(admin.get_data(&eph)).await.unwrap();
    assert_eq!(st.ephemeral_kind(), EphemeralKind::Session(id));
    let r = within(ctx.builder().session(id, pw).connect())
        .await
        .unwrap();
    assert_eq!(r.session().0, id);
    let mine = within(r.get_ephemerals(&ctx.root)).await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine.first().map(|p| p.as_str()), Some(eph.as_str()));
    // `close` ends the session at once, with no wait for the timeout.
    within(r.close()).await.unwrap();
    assert_eq!(within(admin.exists(&eph)).await, Ok(None));
}

real_test!(close_drains_then_ends);
/// Rule: `close` lets the queued requests finish, then refuses new
/// requests with `Closing` and ends the watchers with `Closed`. A
/// second `close` gives the same result. The server deletes the
/// ephemerals at once (`close_mode = Drain`).
async fn close_drains_then_ends(ctx: Ctx) {
    let admin = setup(&ctx).await;
    let eph = ctx.path("/eph");
    let c = ctx.connect().await;
    ephemeral(&c, &eph).await;
    let (_, w) = within(c.exists_watched(ctx.path("/none"))).await.unwrap();
    // The recursive watch is on a quiet path, so it gets no event.
    let mut p = within(c.add_watch(ctx.path("/quiet"), AddWatchMode::PersistentRecursive))
        .await
        .unwrap();
    let clone = c.clone();
    let queued = c.set_data(&eph, b"last", None);
    let first = c.close();
    assert_eq!(within(c.get_data(&eph)).await, Err(Error::Closing));
    assert!(within(queued).await.is_ok());
    assert_eq!(within(first).await, Ok(()));
    assert_eq!(within(clone.close()).await, Ok(()));
    assert_eq!(c.state().state, SessionState::Closed);
    assert_eq!(within(w).await, Err(WatchError::Closed));
    assert_eq!(within(p.next()).await, Some(Err(WatchError::Closed)));
    assert_eq!(within(p.next()).await, None);
    assert_eq!(within(admin.exists(&eph)).await, Ok(None));
}

real_test!(resume_moves_the_session);
/// Rule: `ClientBuilder::session` resumes a session. The session keeps
/// its id, its password and its ephemerals, and new watches of the new
/// client fire (Java `ZooKeeper(..., sessionId, passwd)`). The
/// old client detaches first. A live client takes the session back at
/// its next reconnect.
async fn resume_moves_the_session(ctx: Ctx) {
    let admin = setup(&ctx).await;
    let eph = ctx.path("/eph");
    let a = ctx.connect().await;
    ephemeral(&a, &eph).await;
    let (id, pw) = a.detach();
    let b = within(ctx.builder().session(id, pw.clone()).connect())
        .await
        .unwrap();
    assert_eq!(b.session(), (id, pw));
    assert!(b.negotiated_timeout().is_some());
    // B can delete the ephemeral, because the session owns it.
    within(b.delete(&eph, None)).await.unwrap();
    ephemeral(&b, &eph).await;
    let (_, st) = within(admin.get_data(&eph)).await.unwrap();
    assert_eq!(st.ephemeral_kind(), EphemeralKind::Session(id));
    let (_, w) = within(b.exists_watched(ctx.path("/n"))).await.unwrap();
    within(admin.create(ctx.path("/n"), b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(within(w).await.unwrap().kind, EventKind::NodeCreated);
    within(b.close()).await.unwrap();
    assert_eq!(within(admin.exists(&eph)).await, Ok(None));
}

real_test!(expiry_ends_everything);
/// Rule: on expiry the state becomes `Expired`, every one-shot watcher
/// gives `SessionExpired`, a persistent watcher gives it once and then
/// `None`, and every request fails with `SessionExpired`. A closed
/// session cannot resume.
///
/// The test expires the session with no wait: the proxy cuts client A,
/// client B resumes the session and closes it, and then A reconnects.
async fn expiry_ends_everything(ctx: Ctx) {
    let admin = setup(&ctx).await;
    let eph = ctx.path("/eph");
    let proxy = Proxy::start(ctx.port());
    let a = within(via(&ctx, &proxy).connect()).await.unwrap();
    ephemeral(&a, &eph).await;
    let (_, _, w) = within(a.get_data_watched(&ctx.root)).await.unwrap();
    let mut p = within(a.add_watch(&ctx.root, AddWatchMode::Persistent))
        .await
        .unwrap();
    let mut s = a.state_watcher();
    let (id, pw) = a.session();

    proxy.cut();
    let info = wait_state(&mut s, WAIT, |i| i.state == SessionState::Connecting).await;
    assert!(info.disconnected_since.is_some(), "{info:?}");
    let b = within(ctx.builder().session(id, pw.clone()).connect())
        .await
        .unwrap();
    within(b.close()).await.unwrap();
    // The close deletes the ephemeral. A sees no event, because its
    // connection is down.
    assert_eq!(within(admin.exists(&eph)).await, Ok(None));
    proxy.restore();

    let info = wait_state(&mut s, WAIT, |i| i.state.is_terminal()).await;
    assert_eq!(info.state, SessionState::Expired, "{info:?}");
    assert_eq!(within(w).await, Err(WatchError::SessionExpired));
    assert_eq!(
        within(p.next()).await,
        Some(Err(WatchError::SessionExpired))
    );
    assert_eq!(within(p.next()).await, None);
    assert_eq!(within(a.get_data(&eph)).await, Err(Error::SessionExpired));
    assert_eq!(
        within(a.add_watch(&ctx.root, AddWatchMode::Persistent))
            .await
            .unwrap_err(),
        Error::SessionExpired
    );
    // `close` after a terminal state completes at once.
    let _ = within(a.close()).await;

    let e = within(ctx.builder().session(id, pw).connect())
        .await
        .unwrap_err();
    assert_eq!(e.error(), &Error::SessionExpired);
}

real_test!(teardown_causes);
/// Rule: `SessionInfo::last_error` names the cause of the last
/// teardown. The end of the connection by the peer is `ServerClosed`.
/// No frame within 2/3 of the session timeout is `ReceiveTimeout`. The
/// epoch grows by one per established connection.
async fn teardown_causes(ctx: Ctx) {
    let proxy = Proxy::start(ctx.port());
    let c = within(
        via(&ctx, &proxy)
            .session_timeout(Duration::from_secs(2))
            .connect(),
    )
    .await
    .unwrap();
    let mut s = c.state_watcher();
    let first = s.current();
    assert_eq!((first.state, first.epoch), (SessionState::Connected, 1));
    assert!(first.disconnected_since.is_none());

    proxy.cut();
    let info = wait_state(&mut s, WAIT, |i| i.state == SessionState::Connecting).await;
    assert!(peer_closed(&info), "{info:?}");
    assert!(info.disconnected_since.is_some());
    // A request while the proxy is cut fails at the next failed connect
    // attempt.
    assert_eq!(
        within(c.exists(&ctx.root)).await,
        Err(Error::ConnectionLoss)
    );
    proxy.restore();
    let info = wait_state(&mut s, WAIT, |i| i.state == SessionState::Connected).await;
    assert_eq!(info.epoch, 2);
    assert!(info.disconnected_since.is_none());

    // The held connection gets no ping reply.
    proxy.hold();
    let info = wait_state(&mut s, WAIT, |i| i.state == SessionState::Connecting).await;
    assert_eq!(
        common::disconnect_cause(&info),
        Some(DisconnectCause::ReceiveTimeout),
        "{info:?}"
    );
    proxy.restore();
    // The server can expire the session first, because it saw no ping
    // for most of the timeout.
    let info = wait_state(&mut s, WAIT, |i| {
        i.state == SessionState::Connected || i.state.is_terminal()
    })
    .await;
    if info.state == SessionState::Connected {
        assert_eq!(info.epoch, 3);
    } else {
        assert_eq!(info.state, SessionState::Expired);
    }
    let _ = within(c.close()).await;
}
