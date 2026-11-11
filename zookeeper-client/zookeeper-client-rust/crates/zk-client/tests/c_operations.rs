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

//! Parity tests for the multi-threaded cases of the legacy suite
//! TestOperations.cc (`Zookeeper_operations`). In C, many threads share
//! one handle and call the sync API, while a mock server answers or goes
//! down. Here many threads share one client on the thread driver and use
//! the blocking facade. The single-threaded cases are in
//! `zk-testkit/tests/c_operations.rs`.
//!
//! The tests need the `blocking` feature.

#![cfg(feature = "blocking")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{Client, CreateMode, Error, Runtime, ThreadOptions};
use common::{WAIT, builder};

/// The number of threads of each job set, as in the C job manager.
const THREADS: usize = 10;

/// Connects a client on the thread driver.
fn connect(cs: &str) -> Client {
    builder(cs)
        .runtime(Runtime::Thread(ThreadOptions::default()))
        .connect()
        .wait()
        .unwrap()
}

/// Reads `path` once with the test budget. A read that does not finish
/// in time fails the test.
fn get(c: &Client, path: &str) -> Result<Vec<u8>, Error> {
    match c.get_data(path).wait_timeout(WAIT) {
        Ok(r) => r.map(|(d, _)| d),
        Err(_) => panic!("get_data {path} did not finish in {WAIT:?}"),
    }
}

/// Runs `reps` reads of `path` on each of `THREADS` threads. It returns
/// the first result that is not `Ok` on each thread, or `Ok` when every
/// read passed.
fn read_jobs(c: &Client, path: &'static str, reps: usize) -> Vec<Result<(), Error>> {
    let jobs: Vec<_> = (0..THREADS)
        .map(|_| {
            let c = c.clone();
            thread::spawn(move || {
                for _ in 0..reps {
                    get(&c, path)?;
                }
                Ok(())
            })
        })
        .collect();
    jobs.into_iter().map(|j| j.join().unwrap()).collect()
}

/// Zookeeper_operations::testConcurrentOperations1 (multi-threaded).
/// Ten threads share one client and read the same node many times. Every
/// read passes, in each of several rounds.
#[test]
fn test_concurrent_operations1_mt() {
    for _ in 0..5 {
        let fs = common::fake();
        fs.cluster().create("/x", b"", 0).unwrap();
        fs.cluster().create("/x/y", b"", 0).unwrap();
        fs.cluster().create("/x/y/z", b"1", 0).unwrap();
        let c = connect(&fs.connect_string());
        for r in read_jobs(&c, "/x/y/z", 100) {
            assert_eq!(r, Ok(()));
        }
        c.close().wait().unwrap();
    }
}

/// Zookeeper_operations::testOperationsAndDisconnectConcurrently1
/// (multi-threaded). Ten threads read in a loop, and the server goes
/// down while the reads run. The first failed read of each thread gives
/// the connection loss error, and no read hangs.
#[test]
fn test_operations_and_disconnect_concurrently1_mt() {
    for _ in 0..5 {
        let mut fs = common::fake();
        fs.cluster().create("/x", b"", 0).unwrap();
        fs.cluster().create("/x/y", b"", 0).unwrap();
        fs.cluster().create("/x/y/z", b"1", 0).unwrap();
        let c = connect(&fs.connect_string());
        let started = Arc::new(AtomicBool::new(false));
        let jobs: Vec<_> = (0..THREADS)
            .map(|_| {
                let c = c.clone();
                let started = Arc::clone(&started);
                thread::spawn(move || {
                    // The loop stops at the first error. The bound only
                    // stops a run in which the server never goes down.
                    for _ in 0..1_000_000_u32 {
                        get(&c, "/x/y/z")?;
                        started.store(true, Ordering::Release);
                    }
                    Ok::<(), Error>(())
                })
            })
            .collect();
        while !started.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
        thread::sleep(Duration::from_millis(4));
        // New connects fail at once, and the open connections end.
        fs.stop();
        for j in jobs {
            assert_eq!(j.join().unwrap(), Err(Error::ConnectionLoss));
        }
        drop(c);
    }
}

/// Zookeeper_operations::testOperationsAndDisconnectConcurrently2
/// (multi-threaded, real server). One client creates /xyz. Then, in each
/// round, a new client is shared by ten threads that read /xyz many
/// times. Every read passes.
#[test]
#[ignore = "real-server"]
fn test_operations_and_disconnect_concurrently2_mt() {
    let Some(server) = common::fresh_server(9) else {
        return;
    };
    let cs = server.connect_string();
    let c = connect(&cs);
    match c
        .create("/xyz", b"1", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .wait()
    {
        Ok(_) | Err(Error::NodeExists) => {}
        Err(e) => panic!("create /xyz: {e:?}"),
    }
    c.close().wait().unwrap();
    for _ in 0..5 {
        let c = connect(&cs);
        for r in read_jobs(&c, "/xyz", 200) {
            assert_eq!(r, Ok(()));
        }
        c.close().wait().unwrap();
    }
    drop(server);
}
