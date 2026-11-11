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

//! Watch fake-server tests: one-shot and persistent watchers, the
//! detach rule, `Lagged` and the session state watcher.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::time::Duration;

use apache_zookeeper::{
    AddWatchMode, Client, EventKind, SessionState, StateWatcher, WatchError, WatchedEvent,
    WatcherKind,
};
use zk_fakeserver::{Action, FakeServer, Rule};
use zk_jute::opcode;

use common::{connect, within};

/// A round trip on the connection. Replies and events share one
/// connection in wire order, so every event that the server sent
/// before this call is routed when it returns.
async fn round_trip(c: &Client) {
    within(c.exists("/")).await.expect("round trip");
}

/// Waits until the watcher reports `want`.
async fn wait_state(w: &mut StateWatcher, want: SessionState) -> u64 {
    within(async {
        loop {
            let info = w.current();
            if info.state == want {
                return info.epoch;
            }
            let _ = w.changed().await;
        }
    })
    .await
}

/// True when the server recorded a `RemoveWatches` request for `path`.
fn sent_remove(srv: &FakeServer, path: &str, wait: Duration) -> bool {
    srv.wait_for(wait, |r| {
        r.op == Some(opcode::REMOVE_WATCHES) && r.path.as_deref() == Some(path)
    })
    .is_some()
}

fn assert_event(ev: &WatchedEvent, kind: EventKind, path: &str) {
    assert_eq!(ev.kind, kind);
    assert_eq!(ev.path.as_str(), path);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exist_watch_arms_on_a_missing_node() {
    let srv = common::fake();
    let c = connect(common::builder(&srv.connect_string())).await;
    let (stat, w) = within(c.exists_watched("/a")).await.unwrap();
    assert!(stat.is_none());
    assert_eq!(w.path().as_str(), "/a");
    assert_eq!(w.kind(), WatcherKind::Data);
    srv.cluster().create("/a", b"x", 0).unwrap();
    let ev = within(w).await.unwrap();
    assert_event(&ev, EventKind::NodeCreated, "/a");
    assert!(ev.zxid.is_some_and(|z| z.0 > 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn data_and_child_watches_fire_once() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let (data, _, dw) = within(c.get_data_watched("/a")).await.unwrap();
    assert_eq!(data, b"x");
    let (kids, _, cw) = within(c.get_children_watched("/a")).await.unwrap();
    assert!(kids.is_empty());
    assert_eq!(cw.kind(), WatcherKind::Children);
    srv.cluster().set_data("/a", b"y").unwrap();
    srv.cluster().create("/a/k", b"", 0).unwrap();
    let mut dw = dw;
    let ev = within(&mut dw).await.unwrap();
    assert_event(&ev, EventKind::NodeDataChanged, "/a");
    // A one-shot watcher gives one outcome. A later poll gives Closed.
    assert_eq!(within(&mut dw).await, Err(WatchError::Closed));
    let ev = within(cw).await.unwrap();
    assert_event(&ev, EventKind::NodeChildrenChanged, "/a");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_event_right_after_the_reply_is_not_lost() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    srv.add_rule(
        Rule::on_request()
            .op(opcode::GET_DATA)
            .path("/a")
            .once()
            .then(Action::Model)
            .then(Action::Notify {
                event_type: 3,
                state: 3,
                path: "/a".to_owned(),
            }),
    );
    let c = connect(common::builder(&srv.connect_string())).await;
    // The future is not polled until the event is routed.
    let pending = c.get_data_watched("/a");
    round_trip(&c).await;
    let (_, _, w) = within(pending).await.unwrap();
    let ev = within(w).await.unwrap();
    assert_event(&ev, EventKind::NodeDataChanged, "/a");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_read_arms_no_watcher() {
    let srv = common::fake();
    let c = connect(common::builder(&srv.connect_string())).await;
    let e = within(c.get_data_watched("/missing")).await.unwrap_err();
    assert_eq!(e, apache_zookeeper::Error::NoNode);
    // No local user is left, so nothing asks the server to remove a
    // watch that it never set.
    round_trip(&c).await;
    assert!(!sent_remove(&srv, "/missing", Duration::from_millis(200)));
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_sends_remove_watches_for_the_last_user_only() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let (_, _, w1) = within(c.get_data_watched("/a")).await.unwrap();
    let (_, _, w2) = within(c.get_data_watched("/a")).await.unwrap();
    // Another local user remains: no request goes out.
    within(w1.remove()).await.unwrap();
    round_trip(&c).await;
    assert!(!sent_remove(&srv, "/a", Duration::from_millis(200)));
    // The last user removes the server watch and gets the result.
    within(w2.remove()).await.unwrap();
    assert!(sent_remove(&srv, "/a", common::WAIT));
    assert!(
        srv.cluster()
            .wait_until(common::WAIT, |c| c.watch_count() == 0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drop_detaches_and_the_last_drop_removes_the_server_watch() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let (_, _, w1) = within(c.get_data_watched("/a")).await.unwrap();
    let (_, _, w2) = within(c.get_data_watched("/a")).await.unwrap();
    drop(w1);
    round_trip(&c).await;
    assert!(!sent_remove(&srv, "/a", Duration::from_millis(200)));
    // The other watcher still fires.
    srv.cluster().set_data("/a", b"y").unwrap();
    let ev = within(w2).await.unwrap();
    assert_event(&ev, EventKind::NodeDataChanged, "/a");

    let (_, _, w3) = within(c.get_data_watched("/a")).await.unwrap();
    drop(w3);
    assert!(sent_remove(&srv, "/a", common::WAIT));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_persistent_watcher_gives_every_event_in_order() {
    let srv = common::fake();
    let c = connect(common::builder(&srv.connect_string())).await;
    let mut w = within(c.add_watch("/p", AddWatchMode::Persistent))
        .await
        .unwrap();
    assert_eq!(w.mode(), AddWatchMode::Persistent);
    srv.cluster().create("/p", b"", 0).unwrap();
    srv.cluster().set_data("/p", b"1").unwrap();
    srv.cluster().create("/p/k", b"", 0).unwrap();
    srv.cluster().delete("/p/k").unwrap();
    srv.cluster().delete("/p").unwrap();
    let want = [
        EventKind::NodeCreated,
        EventKind::NodeDataChanged,
        EventKind::NodeChildrenChanged,
        EventKind::NodeChildrenChanged,
        EventKind::NodeDeleted,
    ];
    for kind in want {
        let ev = within(w.next()).await.unwrap().unwrap();
        assert_event(&ev, kind, "/p");
    }
    // The watch stays after a delete.
    srv.cluster().create("/p", b"", 0).unwrap();
    let ev = within(w.next()).await.unwrap().unwrap();
    assert_event(&ev, EventKind::NodeCreated, "/p");
    within(w.remove()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_recursive_watcher_sees_descendants() {
    let srv = common::fake();
    srv.cluster().create("/r", b"", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let mut w = within(c.add_watch("/r", AddWatchMode::PersistentRecursive))
        .await
        .unwrap();
    srv.cluster().create("/r/x", b"", 0).unwrap();
    srv.cluster().set_data("/r/x", b"1").unwrap();
    srv.cluster().delete("/r/x").unwrap();
    let want = [
        (EventKind::NodeCreated, "/r/x"),
        (EventKind::NodeDataChanged, "/r/x"),
        (EventKind::NodeDeleted, "/r/x"),
    ];
    for (kind, path) in want {
        let ev = within(w.next()).await.unwrap().unwrap();
        assert_event(&ev, kind, path);
    }
    drop(w);
    assert!(sent_remove(&srv, "/r", common::WAIT));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_persistent_buffer_gives_lagged() {
    let srv = common::fake();
    srv.cluster().create("/p", b"", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string()).persistent_watch_buffer(2)).await;
    let mut w = within(c.add_watch("/p", AddWatchMode::Persistent))
        .await
        .unwrap();
    for i in 0..5u8 {
        srv.cluster().set_data("/p", &[i]).unwrap();
    }
    round_trip(&c).await;
    let first = within(w.next()).await.unwrap();
    assert_eq!(first, Err(WatchError::Lagged { missed: 3 }));
    for _ in 0..2 {
        let ev = within(w.next()).await.unwrap().unwrap();
        assert_event(&ev, EventKind::NodeDataChanged, "/p");
    }
    // The watcher stays active after Lagged.
    srv.cluster().set_data("/p", b"z").unwrap();
    let ev = within(w.next()).await.unwrap().unwrap();
    assert_event(&ev, EventKind::NodeDataChanged, "/p");
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_watches_ends_the_local_watchers() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let (_, _, w) = within(c.get_data_watched("/a")).await.unwrap();
    let mut p = within(c.add_watch("/a", AddWatchMode::Persistent))
        .await
        .unwrap();
    within(c.remove_watches("/a", WatcherKind::Data, false))
        .await
        .unwrap();
    assert_eq!(within(w).await, Err(WatchError::Removed));
    within(c.remove_watches("/a", WatcherKind::Persistent, true))
        .await
        .unwrap();
    assert_eq!(within(p.next()).await, Some(Err(WatchError::Removed)));
    assert_eq!(within(p.next()).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn watches_are_restored_after_a_reconnect() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let mut sw = c.state_watcher();
    let epoch = wait_state(&mut sw, SessionState::Connected).await;
    let (_, _, w) = within(c.get_data_watched("/a")).await.unwrap();
    let mut p = within(c.add_watch("/a", AddWatchMode::Persistent))
        .await
        .unwrap();
    srv.drop_connections();
    // The epoch shows the reconnect, even when the states merge.
    within(async {
        loop {
            let info = sw.current();
            if info.state == SessionState::Connected && info.epoch > epoch {
                return;
            }
            let _ = sw.changed().await;
        }
    })
    .await;
    let rec = srv
        .wait_for(common::WAIT, |r| r.op == Some(opcode::SET_WATCHES2))
        .expect("SetWatches2 after the reconnect");
    match rec.detail {
        zk_fakeserver::Detail::SetWatches(set) => {
            assert_eq!(set.data, vec!["/a".to_owned()]);
            assert_eq!(set.persistent, vec!["/a".to_owned()]);
        }
        other => panic!("unexpected detail {other:?}"),
    }
    srv.cluster().set_data("/a", b"y").unwrap();
    let ev = within(w).await.unwrap();
    assert_event(&ev, EventKind::NodeDataChanged, "/a");
    let ev = within(p.next()).await.unwrap().unwrap();
    assert_event(&ev, EventKind::NodeDataChanged, "/a");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_restore_a_reconnect_ends_the_watchers() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string()).restore_watches(false)).await;
    let (_, _, w) = within(c.get_data_watched("/a")).await.unwrap();
    let mut p = within(c.add_watch("/a", AddWatchMode::Persistent))
        .await
        .unwrap();
    srv.drop_connections();
    assert_eq!(within(w).await, Err(WatchError::ConnectionLost));
    assert_eq!(
        within(p.next()).await,
        Some(Err(WatchError::ConnectionLost))
    );
    assert_eq!(within(p.next()).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_ends_every_watcher_and_the_state_stays_terminal() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let mut sw = c.state_watcher();
    let (_, _, w) = within(c.get_data_watched("/a")).await.unwrap();
    let mut p = within(c.add_watch("/a", AddWatchMode::Persistent))
        .await
        .unwrap();
    let (id, _) = c.session();
    assert!(srv.cluster().expire_session(id.0));
    wait_state(&mut sw, SessionState::Expired).await;
    assert_eq!(within(w).await, Err(WatchError::SessionExpired));
    assert_eq!(
        within(p.next()).await,
        Some(Err(WatchError::SessionExpired))
    );
    assert_eq!(within(p.next()).await, None);
    // After a terminal state `changed` resolves at once, always.
    for _ in 0..3 {
        let info = within(sw.changed()).await;
        assert_eq!(info.state, SessionState::Expired);
    }
    // A watched read now fails and arms nothing.
    let e = within(c.get_data_watched("/a")).await.unwrap_err();
    assert_eq!(e, apache_zookeeper::Error::SessionExpired);
}

#[tokio::test(flavor = "multi_thread")]
async fn close_ends_every_watcher_with_closed() {
    let srv = common::fake();
    srv.cluster().create("/a", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let mut sw = c.state_watcher();
    let (_, _, w) = within(c.get_data_watched("/a")).await.unwrap();
    let mut p = within(c.add_watch("/a", AddWatchMode::Persistent))
        .await
        .unwrap();
    within(c.close()).await.unwrap();
    assert_eq!(within(w).await, Err(WatchError::Closed));
    assert_eq!(within(p.next()).await, Some(Err(WatchError::Closed)));
    assert_eq!(within(p.next()).await, None);
    wait_state(&mut sw, SessionState::Closed).await;
}

#[cfg(feature = "stream")]
#[tokio::test(flavor = "multi_thread")]
async fn a_persistent_watcher_is_a_stream() {
    use std::pin::Pin;

    use futures_core::Stream;

    let srv = common::fake();
    srv.cluster().create("/s", b"", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let mut w = within(c.add_watch("/s", AddWatchMode::Persistent))
        .await
        .unwrap();
    srv.cluster().set_data("/s", b"1").unwrap();
    let item = within(std::future::poll_fn(|cx| Pin::new(&mut w).poll_next(cx))).await;
    assert_event(&item.unwrap().unwrap(), EventKind::NodeDataChanged, "/s");
}

#[cfg(feature = "blocking")]
#[test]
fn the_blocking_waits_take_events() {
    let srv = common::fake();
    srv.cluster().create("/b", b"x", 0).unwrap();
    let c = common::builder(&srv.connect_string())
        .connect()
        .wait()
        .unwrap();
    let mut sw = c.state_watcher();
    assert!(sw.current().state.is_connected());
    let (_, _, w) = c.get_data_watched("/b").wait().unwrap();
    let mut p = c.add_watch("/b", AddWatchMode::Persistent).wait().unwrap();
    srv.cluster().set_data("/b", b"y").unwrap();
    assert_event(&w.wait().unwrap(), EventKind::NodeDataChanged, "/b");
    assert_event(
        &p.recv().unwrap().unwrap(),
        EventKind::NodeDataChanged,
        "/b",
    );
    c.close().wait().unwrap();
    assert_eq!(p.recv(), Some(Err(WatchError::Closed)));
    assert_eq!(p.recv(), None);
    assert_eq!(sw.wait_changed().unwrap().state, SessionState::Closed);
}

/// A blocking wait inside a tokio runtime fails at once and does not
/// stall the runtime (specification "Execution Runtimes").
#[cfg(feature = "blocking")]
#[tokio::test(flavor = "multi_thread")]
async fn a_blocking_wait_in_a_runtime_is_refused() {
    let srv = common::fake();
    srv.cluster().create("/b", b"x", 0).unwrap();
    let c = connect(common::builder(&srv.connect_string())).await;
    let mut p = within(c.add_watch("/b", AddWatchMode::Persistent))
        .await
        .unwrap();
    let mut sw = c.state_watcher();
    if cfg!(feature = "tokio") {
        assert_eq!(p.recv(), Some(Err(WatchError::InvalidState)));
        assert_eq!(
            sw.wait_changed().unwrap_err(),
            apache_zookeeper::Error::InvalidState
        );
        let (_, _, w) = within(c.get_data_watched("/b")).await.unwrap();
        assert_eq!(w.wait(), Err(WatchError::InvalidState));
    }
    // The watcher stays usable after the refusal.
    srv.cluster().set_data("/b", b"y").unwrap();
    let ev = within(p.next()).await.unwrap().unwrap();
    assert_event(&ev, EventKind::NodeDataChanged, "/b");
}
