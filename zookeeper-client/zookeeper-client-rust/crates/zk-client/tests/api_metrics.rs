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

//! API contract tests of the `Metrics` hook: the lag and pending-count
//! calls, the result that a request reports, and the rule that a panic
//! disables the hook. `host_observe.rs` covers the basic calls.
//!
//! Each test names its rule and the source: "spec" is
//! `design/specification.md`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apache_zookeeper::{
    AddWatchMode, Error, EventKind, Metrics, OpKind, Runtime, SessionState, ThreadOptions,
    WatchError,
};

use common::{connect, within};

/// One recorded hook call.
#[derive(Clone, Debug, PartialEq)]
enum Call {
    Request(OpKind, Result<(), Error>),
    State(SessionState),
    Event(EventKind),
    Lagged(u64),
    Pending(usize),
}

/// A hook that records each call. With `panic_on_state`, the first
/// `state_changed` call panics.
#[derive(Default)]
struct Rec {
    calls: Mutex<Vec<Call>>,
    entered: AtomicUsize,
    panic_on_state: bool,
}

#[derive(Clone)]
struct Hook(Arc<Rec>);

impl Hook {
    fn push(&self, c: Call) {
        self.0.entered.fetch_add(1, Ordering::SeqCst);
        self.0.calls.lock().unwrap().push(c);
    }

    fn calls(&self) -> Vec<Call> {
        self.0.calls.lock().unwrap().clone()
    }
}

impl Metrics for Hook {
    fn request_completed(&self, op: OpKind, result: Result<(), &Error>, _latency: Duration) {
        self.push(Call::Request(op, result.map_err(Clone::clone)));
    }
    fn state_changed(&self, state: SessionState) {
        if self.0.panic_on_state {
            self.0.entered.fetch_add(1, Ordering::SeqCst);
            panic!("a test hook panics in state_changed");
        }
        self.push(Call::State(state));
    }
    fn watch_event(&self, kind: EventKind) {
        self.push(Call::Event(kind));
    }
    fn watch_lagged(&self, missed: u64) {
        self.push(Call::Lagged(missed));
    }
    fn pending_requests(&self, n: usize) {
        self.push(Call::Pending(n));
    }
}

fn hook() -> Hook {
    Hook(Arc::new(Rec::default()))
}

/// Rule: when a full persistent queue drops an event, the hook gets
/// `watch_lagged` with the count of dropped events so far. The watcher
/// gives the same count in `Lagged`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_persistent_event_reports_the_lag() {
    let fs = common::fake();
    fs.cluster().create("/p", b"", 0).unwrap();
    let h = hook();
    let c = connect(
        common::builder(&fs.connect_string())
            .persistent_watch_buffer(2)
            .metrics(h.clone()),
    )
    .await;
    let mut w = within(c.add_watch("/p", AddWatchMode::Persistent))
        .await
        .unwrap();
    for i in 0..5u8 {
        fs.cluster().set_data("/p", &[i]).unwrap();
    }
    within(c.sync("/")).await.unwrap();
    assert_eq!(
        within(w.next()).await.unwrap(),
        Err(WatchError::Lagged { missed: 3 })
    );
    let lags: Vec<u64> = h
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Lagged(n) => Some(n),
            _ => None,
        })
        .collect();
    assert_eq!(lags, vec![1, 2, 3]);
    within(c.close()).await.unwrap();
}

/// Rule: after each completed request the hook gets the pending count.
/// The count falls to 0 when the queue drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pending_count_falls_as_replies_arrive() {
    let fs = common::fake();
    let h = hook();
    let c = connect(common::builder(&fs.connect_string()).metrics(h.clone())).await;
    fs.hold();
    let reads: Vec<_> = (0..4).map(|_| c.get_data("/")).collect();
    fs.release();
    for f in reads {
        within(f).await.unwrap();
    }
    // The library reports the pending count after it delivers each reply.
    // So the last report can come after the last read completes, and the
    // test waits for all four reports.
    let pending = || -> Vec<usize> {
        h.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Pending(n) => Some(n),
                _ => None,
            })
            .collect()
    };
    let deadline = std::time::Instant::now() + common::WAIT;
    while pending().len() < 4 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let counts = pending();
    assert_eq!(counts.len(), 4, "{counts:?}");
    assert!(counts.windows(2).all(|w| w[0] >= w[1]), "{counts:?}");
    assert_eq!(counts.last(), Some(&0));
    within(c.close()).await.unwrap();
}

/// Rule: the hook sees the result of the API call: `exists` on a
/// missing node is a success, and a failed read gives its error. A
/// request that a loss fails reports `ConnectionLoss`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hook_sees_the_api_result() {
    let fs = common::fake();
    let h = hook();
    let c = connect(common::builder(&fs.connect_string()).metrics(h.clone())).await;
    assert_eq!(within(c.exists("/none")).await, Ok(None));
    assert_eq!(within(c.get_data("/none")).await.err(), Some(Error::NoNode));
    fs.hold();
    let lost = c.sync("/");
    fs.drop_connections();
    fs.release();
    assert_eq!(within(lost).await, Err(Error::ConnectionLoss));
    let reqs: Vec<Call> = h
        .calls()
        .into_iter()
        .filter(|c| matches!(c, Call::Request(..)))
        .collect();
    assert_eq!(
        reqs,
        vec![
            Call::Request(OpKind::Exists, Ok(())),
            Call::Request(OpKind::GetData, Err(Error::NoNode)),
            Call::Request(OpKind::Sync, Err(Error::ConnectionLoss)),
        ]
    );
    within(c.close()).await.unwrap();
}

/// Rule: a panic in any hook method disables the hook for the client.
/// The client keeps its function, and no later call reaches the hook
/// (spec "Lock-Free User Execution").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panic_in_state_changed_disables_the_hook_on_both_runtimes() {
    for thread in [false, true] {
        let fs = common::fake();
        let h = Hook(Arc::new(Rec {
            panic_on_state: true,
            ..Rec::default()
        }));
        let mut b = common::builder(&fs.connect_string()).metrics(h.clone());
        if thread {
            b = b.runtime(Runtime::Thread(ThreadOptions::default()));
        }
        let c = connect(b).await;
        for _ in 0..3 {
            within(c.get_data("/")).await.unwrap();
        }
        fs.drop_connections();
        let mut w = c.state_watcher();
        within(async {
            while w.current().epoch < 2 {
                let _ = w.changed().await;
            }
        })
        .await;
        within(c.close()).await.unwrap();
        assert_eq!(h.0.entered.load(Ordering::SeqCst), 1, "thread {thread}");
        assert!(h.calls().is_empty(), "thread {thread}: {:?}", h.calls());
    }
}
