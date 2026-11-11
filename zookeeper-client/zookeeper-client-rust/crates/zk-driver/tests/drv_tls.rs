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

//! Integration tests of the TLS handshake with each driver flavor:
//! native threaded, tokio, mt and st. The native flavors use the native
//! connector (WebPki with `ca.pem`). The drop-in flavors use the legacy
//! connector (`LegacyChainOnly` with `ca.pem`).

#![cfg(all(unix, feature = "tls"))]
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
mod drv_util;

use std::sync::Arc;
use std::time::Duration;

use common::fixture;
use common::tls::{legacy_connector, native_connector, provider};
use drv_util::{Drv, Opts, WAIT, cluster, connected, connects, exists, wait};
use zk_driver::net::tls::TlsConnector;
use zk_fakeserver::{FakeServer, PeerEnd, ServerOptions, TlsAcceptor};
use zk_proto::LogSite;
use zk_proto::State;
use zk_proto::rc::ZOK;

const CONNECTED: i32 = State::Connected.code();

/// The connector of the flavor: native WebPki or legacy chain-only,
/// both with `ca.pem` as the only root.
fn connector(native: bool) -> Arc<dyn TlsConnector> {
    if native {
        native_connector()
    } else {
        legacy_connector()
    }
}

/// Starts a TLS server with the `leaf` certificate. A server close
/// waits for the close_notify of the client.
fn tls_server(c: &zk_fakeserver::Cluster, leaf: &str) -> (FakeServer, Arc<TlsAcceptor>) {
    let acc = TlsAcceptor::builder(provider())
        .cert_chain_pem_file(fixture(&format!("{leaf}.pem")))
        .unwrap()
        .key_pem_file(fixture(&format!("{leaf}.key")))
        .unwrap()
        .close_notify(false)
        .linger(Duration::from_secs(2))
        .build()
        .unwrap();
    let opts = ServerOptions::default().with_acceptor(Arc::clone(&acc) as _);
    (c.start_server(opts).unwrap(), acc)
}

fn tls_opts<D: Drv>(s: &FakeServer) -> Opts {
    let mut o = Opts::new(&s.connect_string());
    o.tls = Some(connector(D::NATIVE));
    o
}

/// Rule: the client completes the TLS handshake before the ZooKeeper
/// handshake, and each reconnect makes a new TLS session that resumes
/// the ZooKeeper session (zookeeper.c `init_ssl_for_socket`). A graceful
/// close sends close_notify. The C client omits it.
fn t_tls_session<D: Drv>() {
    let c = cluster();
    let (s, acc) = tls_server(&c, "server");
    let d = D::start(tls_opts::<D>(&s));
    connected(&d);
    let id = d.client_id().session_id;
    assert_eq!(d.submit(exists(D::NATIVE, 1, "/")), 0);
    assert!(wait(&d, |d| d.rec().result(1).is_some()));
    assert_eq!(d.rec().result(1).unwrap().0, ZOK);
    s.drop_connections();
    assert!(
        wait(&d, |d| connects(&c).len() >= 2 && d.state() == CONNECTED),
        "{}: no TLS reconnect",
        D::NAME
    );
    assert_eq!(
        connects(&c)[1].session_id,
        id,
        "{}: the session resumes",
        D::NAME
    );
    assert_eq!(d.submit(exists(D::NATIVE, 2, "/")), 0);
    assert!(wait(&d, |d| d.rec().result(2).is_some()));
    assert_eq!(d.rec().result(2).unwrap().0, ZOK);
    assert_eq!(d.close(), ZOK, "{}: close rc", D::NAME);
    let sessions = acc.sessions();
    assert!(
        sessions.len() >= 2,
        "{}: {} TLS sessions",
        D::NAME,
        sessions.len()
    );
    assert!(sessions.iter().all(|t| matches!(t.handshake, Some(Ok(())))));
    assert!(
        acc.wait_sessions(WAIT, |t| t.len() >= 2 && t[1].peer_end.is_some()),
        "{}: the last session does not end",
        D::NAME
    );
    assert_eq!(
        acc.sessions()[1].peer_end,
        Some(PeerEnd::CloseNotify),
        "{}",
        D::NAME
    );
}

/// Rule: a server certificate from another CA fails the handshake with
/// the SSL_connect line, and the session never connects (zookeeper.c
/// `init_ssl_for_socket`). The close still ends the handle.
fn t_tls_untrusted<D: Drv>() {
    let c = cluster();
    let (s, acc) = tls_server(&c, "wrong-server");
    let d = D::start(tls_opts::<D>(&s));
    // The st flavor moves only when the test drives it, so the wait
    // drives the client.
    let failed = |a: &TlsAcceptor| {
        a.sessions()
            .iter()
            .any(|t| matches!(t.handshake, Some(Err(_))))
    };
    assert!(
        wait(&d, |_| failed(&acc)),
        "{}: no failed handshake",
        D::NAME
    );
    assert!(
        wait(&d, |d| d.rec().has_log(LogSite::SockTlsConnect)),
        "{}: no SSL_connect line",
        D::NAME
    );
    assert_ne!(d.state(), CONNECTED);
    assert!(
        connects(&c).is_empty(),
        "{}: a ZooKeeper connect frame",
        D::NAME
    );
    let _rc = d.close();
}

macro_rules! tls_tests {
    ($m:ident, $d:ty) => {
        mod $m {
            use super::*;

            #[test]
            fn tls_session_reconnect_and_close() {
                t_tls_session::<$d>();
            }
            #[test]
            fn tls_untrusted_server() {
                t_tls_untrusted::<$d>();
            }
        }
    };
}

tls_tests!(native, drv_util::NativeDrv);
tls_tests!(mt, drv_util::MtDrv);
tls_tests!(st, drv_util::StDrv);
#[cfg(feature = "tokio")]
tls_tests!(tokio_task, drv_util::TokioDrv);
