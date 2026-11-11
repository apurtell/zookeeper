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

//! C parity test of `TestClientRetry.cc` (suite `Zookeeper_clientretry`).
//!
//! The server at port offset 11 accepts one connection from each
//! address (`maxClientCnxns=1`), as the C suite sets it. The test has
//! `#[ignore = "real-server"]`. Run it with `ZK_TEST_PORT_BASE=<base>
//! cargo test --test c_client_retry -- --ignored`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;
mod parity_g1;

use std::time::Duration;

use apache_zookeeper::SessionState;
use common::within;
use parity_g1::{RECONNECT_WAIT, fresh_server_with, within_for};

/// The port offset of the server of this file.
const OFFSET: u16 = 11;

/// The time that the second client waits while the first client holds
/// the only connection slot.
const REFUSED: Duration = Duration::from_millis(1_500);

/// C case `Zookeeper_clientretry::testRetry`: the server refuses a
/// second connection from the same address while the first client is
/// connected. The second client keeps its connect attempts. When the
/// first client closes, the second client connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn second_client_connects_after_the_first_closes() {
    let Some(server) = fresh_server_with(OFFSET, "maxClientCnxns=1", "") else {
        return;
    };
    let cs = server.connect_string();
    for rt in common::all_rts() {
        // The server can still count the connection of an earlier
        // client for a short time, so the first connect waits longer.
        let zk1 = within_for(RECONNECT_WAIT, rt.apply(common::builder(&cs)).connect())
            .await
            .unwrap();
        let f = rt.apply(common::builder(&cs)).connect();
        let w = f.state_watcher();
        let mut f = Box::pin(f);
        assert!(
            tokio::time::timeout(REFUSED, &mut f).await.is_err(),
            "the second client connected while the first held the slot"
        );
        assert_eq!(w.current().state, SessionState::Connecting);

        within(zk1.close()).await.unwrap();
        let zk2 = within_for(RECONNECT_WAIT, f).await.unwrap();
        assert!(zk2.state().state.is_connected());
        assert!(within(zk2.exists("/")).await.unwrap().is_some());
        within(zk2.close()).await.unwrap();
    }
}
