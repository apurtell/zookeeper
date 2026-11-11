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

//! C parity test of `TestReadOnlyClient.cc` (suite
//! `Zookeeper_readOnly`). `testReadOnly` maps to
//! `real_ensemble::read_only_server_serves_reads`.
//!
//! The server is one of two voters, so it has no quorum and serves in
//! read-only mode. It uses the client port at offset 12, the secure
//! port at offset 13, and quorum and election ports at offsets 14 to
//! 17. The test has `#[ignore = "real-server"]`. Run it with
//! `ZK_TEST_PORT_BASE=<base> cargo test --features tls-ring --test
//! c_read_only_client -- --ignored`.

#![cfg(feature = "tls-rustls")]
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

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{CreateMode, Error, SessionState, TlsOptions};
use common::{real_port, within};
use parity_g1::{legacy_cert_string, quorum_dir, start_or_skip, tls_props, within_for};

/// The time for a quorum server to serve after it answers `ruok`.
const SERVE_WAIT: Duration = Duration::from_secs(20);

/// C case `Zookeeper_readOnly::testReadOnlyWithSSL`: a client that
/// allows read-only servers connects over TLS with the C certificate
/// string and a client certificate (`ssl.clientAuth=need`). The server
/// has no quorum, so the session is read-only. A read of `/` succeeds,
/// and a create fails with `NotReadOnly`. The C case connects to
/// `localhost`, and so does this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn read_only_server_serves_reads_over_tls() {
    let (Some(client), Some(secure), Some(q1), Some(e1), Some(q2), Some(e2)) = (
        real_port(12),
        real_port(13),
        real_port(14),
        real_port(15),
        real_port(16),
        real_port(17),
    ) else {
        return;
    };
    let dir = quorum_dir("ro-tls", client);
    // Two voters and one live server: the server has no quorum. A
    // read-only server accepts only local sessions. This line overrides
    // the script value, because the last line of a key wins.
    let props = format!(
        "localSessionsEnabled=true\ninitLimit=5\nsyncLimit=2\n\
         server.1=127.0.0.1:{q1}:{e1}\nserver.2=127.0.0.1:{q2}:{e2}\n{}",
        tls_props(&dir, secure, "need")
    );
    let Some(_server) = start_or_skip(client, Some(dir), &props, "-Dreadonlymode.enabled=true")
    else {
        return;
    };
    let cs = format!("localhost:{secure}");
    for rt in common::all_rts() {
        let tls = TlsOptions::legacy_c_compat(&legacy_cert_string()).unwrap();
        let b = rt
            .apply(common::builder(&cs))
            .tls(tls)
            .allow_read_only(true);
        let c = within_for(SERVE_WAIT, b.connect()).await.unwrap();
        assert_eq!(c.state().state, SessionState::ConnectedReadOnly);
        assert!(within(c.get_data("/")).await.is_ok());
        let r = within(c.create("/testSSL", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)).await;
        assert_eq!(r.err(), Some(Error::NotReadOnly));
        within(c.close()).await.unwrap();
    }
}
