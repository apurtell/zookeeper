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

//! Fake-server tests of the tokio task driver (Unix only).

#![cfg(all(unix, feature = "tokio"))]
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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Collect, IpHost, SlowHost, WAIT, env, exists_native, native_connection};
use zk_driver::outbox::Item;
use zk_fakeserver::FakeServer;
use zk_proto::State;
use zk_testkit::tokens::TestTokens;

#[test]
fn session_connects_routes_a_result_and_closes() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = FakeServer::start().unwrap();
    let sink = Arc::new(Collect::default());
    let h = zk_driver::tokio::spawn(
        native_connection(&server.connect_string()),
        env(IpHost::new(), true),
        sink.clone(),
        None,
        rt.handle(),
    );
    rt.block_on(async {
        let start = tokio::time::Instant::now();
        while h.state() != State::Connected.code() {
            assert!(start.elapsed() < WAIT, "no session");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        h.submit(exists_native(1)).ok().unwrap();
        while !sink
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|i| matches!(i, Item::Result { .. }))
        {
            assert!(start.elapsed() < WAIT, "no result");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        h.close();
        let _rc = h.closed().await;
    });
}

/// Waits until the session is connected.
async fn connected(h: &zk_driver::tokio::TaskHandle<TestTokens>) {
    let start = tokio::time::Instant::now();
    while h.state() != State::Connected.code() {
        assert!(start.elapsed() < WAIT, "no session");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn graceful_close_gives_zok_and_a_second_close_does_nothing() {
    let rt = runtime();
    let server = FakeServer::start().unwrap();
    let sink = Arc::new(Collect::default());
    let h = zk_driver::tokio::spawn(
        native_connection(&server.connect_string()),
        env(IpHost::new(), true),
        sink,
        None,
        rt.handle(),
    );
    rt.block_on(async {
        connected(&h).await;
        h.close();
        h.close();
        let rc = tokio::time::timeout(WAIT, h.closed()).await.unwrap();
        assert_eq!(rc, zk_proto::rc::ZOK);
        // Each waiter sees the same exit value.
        assert_eq!(h.closed().await, rc);
    });
    assert_eq!(h.state(), 0);
    assert!(h.submit(exists_native(9)).is_err());
}

#[test]
fn detach_ends_the_task_with_no_close_request() {
    let rt = runtime();
    let server = FakeServer::start().unwrap();
    let sink = Arc::new(Collect::default());
    let h = zk_driver::tokio::spawn(
        native_connection(&server.connect_string()),
        env(IpHost::new(), true),
        sink,
        None,
        rt.handle(),
    );
    rt.block_on(async {
        connected(&h).await;
        let id = h.client_id();
        h.detach();
        let rc = tokio::time::timeout(WAIT, h.closed()).await.unwrap();
        assert_eq!(rc, zk_proto::rc::ZOK);
        assert_ne!(id, zk_proto::ClientId::default());
    });
    assert_eq!(h.state(), 0);
}

#[test]
fn close_with_no_server_completes_at_once() {
    let rt = runtime();
    // A port with no listener: every connect fails.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let h = zk_driver::tokio::spawn(
        native_connection(&format!("127.0.0.1:{port}")),
        env(IpHost::new(), true),
        Arc::new(Collect::default()),
        None,
        rt.handle(),
    );
    rt.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        h.close();
        let rc = tokio::time::timeout(WAIT, h.closed()).await.unwrap();
        assert_eq!(rc, zk_proto::rc::ZOK);
    });
}

#[test]
fn read_gate_closes_at_capacity_and_taken_reopens_it() {
    let rt = runtime();
    let server = FakeServer::start().unwrap();
    let sink = Arc::new(Collect::default());
    let mut e = env(IpHost::new(), true);
    e.cfg.dispatch_queue_capacity = 1;
    let h = zk_driver::tokio::spawn(
        native_connection(&server.connect_string()),
        e,
        sink.clone(),
        None,
        rt.handle(),
    );
    let results = |s: &Collect| {
        s.0.lock()
            .unwrap()
            .iter()
            .filter(|i| matches!(i, Item::Result { .. }))
            .count()
    };
    rt.block_on(async {
        connected(&h).await;
        h.submit(exists_native(1)).ok().unwrap();
        h.submit(exists_native(2)).ok().unwrap();
        let start = tokio::time::Instant::now();
        while results(&sink) == 0 {
            assert!(start.elapsed() < WAIT, "no result");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(!h.gate().is_open());
        // The receiver takes the item, so the gate opens and the second
        // reply comes.
        h.taken();
        while results(&sink) < 2 {
            assert!(start.elapsed() < WAIT, "no second result");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        // The receiver takes the second item, so the CLOSE_OP reply is
        // read before the close deadline.
        h.taken();
        h.close();
        assert_eq!(h.closed().await, zk_proto::rc::ZOK);
    });
}

/// A slow resolver on the blocking pool must not stop the socket I/O of
/// a connected session. The legacy resolve delay of 0 resolves on each
/// pass while connected.
#[test]
fn a_slow_resolve_does_not_stop_requests_or_the_close() {
    let rt = runtime();
    let server = FakeServer::start().unwrap();
    let sink = Arc::new(Collect::default());
    let host = Arc::new(SlowHost {
        inner: IpHost::new(),
        slow_ms: AtomicU64::new(0),
        resolves: AtomicUsize::new(0),
    });
    let mut e = env(IpHost::new(), true);
    e.host = host.clone();
    let h = zk_driver::tokio::spawn(
        native_connection(&server.connect_string()),
        e,
        sink.clone(),
        None,
        rt.handle(),
    );
    let results = |sink: &Collect| {
        sink.0
            .lock()
            .unwrap()
            .iter()
            .filter(|i| matches!(i, Item::Result { .. }))
            .count()
    };
    rt.block_on(async {
        connected(&h).await;
        host.slow_ms.store(1_500, Ordering::SeqCst);
        let before = host.resolves.load(Ordering::SeqCst);
        h.submit(exists_native(1)).ok().unwrap();
        let start = Instant::now();
        while host.resolves.load(Ordering::SeqCst) == before {
            assert!(start.elapsed() < WAIT, "no resolve");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let t0 = Instant::now();
        h.submit(exists_native(2)).ok().unwrap();
        while results(&sink) < 2 {
            assert!(t0.elapsed() < WAIT, "no result");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            t0.elapsed() < Duration::from_millis(1_000),
            "the request waited for the resolver: {:?}",
            t0.elapsed()
        );
        let t1 = Instant::now();
        h.close();
        let rc = tokio::time::timeout(WAIT, h.closed()).await.unwrap();
        assert_eq!(rc, zk_proto::rc::ZOK);
        assert!(t1.elapsed() < Duration::from_millis(1_000));
    });
}
