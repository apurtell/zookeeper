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

//! Fake-server tests of the mt driver: `threaded::Shared` with
//! an IO thread and a dispatch thread, as zk-ffi runs them.
//!
//! The test threads stand in for the C threads: they loop on
//! `io_step` and `wait_dispatch`, drain each outbox in order and call
//! `resume` after `Step::More`.

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
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use common::{IpHost, WAIT, env, exists};
use zk_driver::outbox::{Flavor, Item};
use zk_driver::{Init, InitArgs, InitStep, Outbox, Role, Shared, Step, Unlocked};
use zk_fakeserver::FakeServer;
use zk_proto::{Compat, Config, DriverMode, State};
use zk_testkit::tokens::TestTokens;

/// Makes a ready mt handle for `server`.
fn handle(server: &FakeServer, host: Arc<IpHost>) -> Arc<Shared<TestTokens>> {
    let args = InitArgs {
        cfg: Config::legacy(10_000),
        host_string: server.connect_string().into_bytes(),
        compat: Compat::LEGACY_C,
        mode: DriverMode::MT,
        flavor: Flavor::Mt,
    };
    let mut ob = Outbox::new();
    let mut init = Init::new(args, env(host, false), &mut ob).unwrap();
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
    Shared::from_init(init, &mut ob).unwrap()
}

/// Runs one driving call to its end. Items go to `sink`.
fn drive(
    shared: &Shared<TestTokens>,
    first: impl FnOnce(&mut Outbox<TestTokens>, &mut i32) -> Step,
    sink: &mpsc::Sender<Item<TestTokens>>,
) -> Step {
    let mut ob = shared.outbox();
    let mut rc = 0;
    let mut step = first(&mut ob, &mut rc);
    loop {
        while let Some(item) = ob.pop() {
            let _ = sink.send(item);
        }
        if step != Step::More {
            return step;
        }
        step = shared.resume(&mut ob, &mut rc);
    }
}

/// The IO and dispatch threads of one handle.
///
/// A failed assertion unwinds the test with both threads still live.
/// The drop then closes the handle and joins the threads, so no live
/// thread runs on into the next test. Under Miri all threads share one
/// interpreter, and Miri fails the run when a thread outlives the main
/// thread.
struct Threads {
    shared: Arc<Shared<TestTokens>>,
    handles: Vec<JoinHandle<()>>,
}

impl Threads {
    /// Closes the handle from a foreign thread and joins both threads.
    fn close(mut self) -> Step {
        let (tx, _keep) = mpsc::channel();
        let s = Arc::clone(&self.shared);
        let end = drive(&s, |ob, rc| s.close(Role::Foreign, ob, rc), &tx);
        // Join every thread before any panic. A panic of one thread then
        // does not leave the other thread live.
        let joined: Vec<_> = std::mem::take(&mut self.handles)
            .into_iter()
            .map(JoinHandle::join)
            .collect();
        for r in joined {
            r.unwrap();
        }
        end
    }
}

impl Drop for Threads {
    /// Runs only when the test did not close, or when its close panicked
    /// before the joins. It checks nothing, and it joins only the threads
    /// that end within [`WAIT`], so it cannot panic or hang during an
    /// unwind.
    fn drop(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        let (tx, _keep) = mpsc::channel();
        let s = Arc::clone(&self.shared);
        let _ = drive(&s, |ob, rc| s.close(Role::Foreign, ob, rc), &tx);
        let end = Instant::now() + WAIT;
        for t in std::mem::take(&mut self.handles) {
            while !t.is_finished() && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            if t.is_finished() {
                let _ = t.join();
            }
        }
    }
}

/// Starts the IO and dispatch threads. Dispatched items go to the
/// returned receiver.
fn start_threads(shared: &Arc<Shared<TestTokens>>) -> (mpsc::Receiver<Item<TestTokens>>, Threads) {
    let (tx, rx) = mpsc::channel();
    shared.thread_enter(Role::Io);
    shared.thread_enter(Role::Dispatch);
    let io = {
        let s = Arc::clone(shared);
        let tx = tx.clone();
        std::thread::spawn(move || {
            while drive(&s, |ob, rc| s.io_step(ob, rc), &tx) != Step::Exit {}
            drive(&s, |ob, rc| s.thread_exit(Role::Io, ob, rc), &tx);
        })
    };
    let dispatch = {
        let s = Arc::clone(shared);
        std::thread::spawn(move || {
            loop {
                let mut ob = s.outbox();
                if s.wait_dispatch(&mut ob) == Step::Exit {
                    break;
                }
                while let Some(item) = ob.pop() {
                    let _ = tx.send(item);
                }
            }
            let mut rc = 0;
            let mut ob = s.outbox();
            let _ = s.thread_exit(Role::Dispatch, &mut ob, &mut rc);
        })
    };
    let threads = Threads {
        shared: Arc::clone(shared),
        handles: vec![io, dispatch],
    };
    (rx, threads)
}

#[test]
fn session_connects_and_a_request_completes() {
    let server = FakeServer::start().unwrap();
    let shared = handle(&server, IpHost::new());
    let (rx, threads) = start_threads(&shared);
    assert!(common::wait_until(WAIT, || shared.state() == State::Connected.code()));
    shared.submit(exists(1)).ok().unwrap();
    let got = std::iter::from_fn(|| rx.recv_timeout(WAIT).ok())
        .find(|i| matches!(i, Item::Result { .. }))
        .unwrap();
    assert!(matches!(got, Item::Result { result, .. } if result.rc == 0));
    let end = threads.close();
    assert!(matches!(end, Step::Done(_) | Step::Release));
}

#[test]
fn exported_interest_reports_no_socket() {
    let server = FakeServer::start().unwrap();
    let shared = handle(&server, IpHost::new());
    let out = shared.interest_exported();
    assert_eq!(out.fd, -1);
    assert_eq!(shared.process_exported(), zk_proto::rc::ZINVALIDSTATE);
}
