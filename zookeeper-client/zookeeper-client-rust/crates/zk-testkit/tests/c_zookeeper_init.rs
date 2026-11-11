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

//! Parity tests for the legacy suite TestZookeeperInit.cc
//! (`Zookeeper_init`). C resolves the host list in `zookeeper_init` and
//! checks the handle fields directly. The sans-IO core parses the string
//! with `parse_init` and resolves it later through a `Resolve` action.
//! Thus these tests check the parse result, the first state, and the
//! connect targets that the harness network records. The drop-in shim
//! resolves at init time, and its own inline tests check that path.

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
mod parity_g2;

use std::net::SocketAddr;

use common::Profile;
use parity_g2::sessions_since;
use zk_jute::{JString, rc};
use zk_proto::legacy::connect::{ConnectString, HostParseErrorKind, parse_init};
use zk_proto::{ClientId, Config, HostSpec, State};
use zk_testkit::{ActionRecord, Harness, HarnessBuilder, RngChoice, WatcherId, server_addr};

/// The default watcher of each test.
const W0: WatcherId = WatcherId::new(50, 0);

/// The C `EINVAL` value.
const EINVAL: i32 = 22;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Puts the parsed host list of `text` into the config, as
/// `zookeeper_init` does.
fn use_hosts(c: &mut Config, text: &str) -> ConnectString {
    let cs = parse_init(text.as_bytes()).unwrap();
    c.hosts = cs.hosts.iter().cloned().map(HostSpec::Legacy).collect();
    c.host_text = JString::from(std::str::from_utf8(&cs.host_text).unwrap());
    cs
}

/// Returns a builder whose config has the host list of `text`. The
/// connect order is the order of the string, as with
/// `zoo_deterministic_conn_order(1)`.
fn with_hosts(p: Profile, seed: u64, text: &str) -> HarnessBuilder {
    p.builder_with(seed, |c| {
        let _ = use_hosts(c, text);
    })
    .shuffle(false)
}

fn resolves(h: &Harness) -> Vec<(usize, bool, i32)> {
    h.recorder()
        .actions()
        .filter_map(|a| match a {
            ActionRecord::Resolve {
                hosts, initial, rc, ..
            } => Some((*hosts, *initial, *rc)),
            _ => None,
        })
        .collect()
}

/// Checks that `text` fails the parse with `EINVAL`, as
/// `zookeeper_init` does.
fn assert_einval(text: &[u8], kind: HostParseErrorKind) {
    let e = parse_init(text).unwrap_err();
    assert_eq!(e.kind, kind, "{text:?}");
    assert_eq!(e.rc, rc::ZBADARGUMENTS, "{text:?}");
    assert_eq!(e.errno, Some(EINVAL), "{text:?}");
}

/// Zookeeper_init::testBasic. A new handle keeps the host text, the
/// client id and the timeout. It has one host entry, no transport, a
/// zero zxid and the NOTCONNECTED state. The CONNECTED event goes to the
/// default watcher.
#[test]
fn test_basic() {
    const HOST: &str = "127.0.0.1:2121";
    let cid = ClientId {
        session_id: i64::from_ne_bytes([0xFE; 8]),
        passwd: [0xFE; 16],
    };
    for p in Profile::LEGACY {
        let mut hosts = None;
        let h = p
            .builder_with(501, |c| {
                hosts = Some(use_hosts(c, HOST));
                c.client_id = cid;
            })
            .default_watcher(Some(W0))
            .build();
        let cs = hosts.unwrap();
        assert_eq!(cs.hosts.len(), 1, "{p:?}");
        assert_eq!(cs.host_text, HOST.as_bytes(), "{p:?}");
        assert_eq!(cs.chroot, None, "{p:?}");
        assert_eq!(h.state(), State::NotConnected, "{p:?}");
        assert_eq!(h.conn().recv_timeout(), 10_000, "{p:?}");
        assert_eq!(h.conn().client_id(), cid, "{p:?}");
        assert_eq!(h.conn().last_zxid(), 0, "{p:?}");
        assert!(h.link().is_none(), "{p:?}");
        assert!(h.net().connects().is_empty(), "{p:?}");

        // A fresh session at the same address reports CONNECTED to the
        // default watcher only.
        let mut h = with_hosts(p, 502, HOST).default_watcher(Some(W0)).build();
        h.server_mut().add_listener(addr(HOST), false);
        h.connect().unwrap();
        assert_eq!(
            sessions_since(&h, 0),
            vec![(State::Connected, vec![W0])],
            "{p:?}"
        );
        assert_eq!(h.net().connects(), [addr(HOST)], "{p:?}");
    }
}

/// Zookeeper_init::testAddressResolution. The single entry resolves to
/// 127.0.0.1 port 2121, and the first connect goes there.
#[test]
fn test_address_resolution() {
    for p in Profile::LEGACY {
        let mut h = with_hosts(p, 503, "127.0.0.1:2121").build();
        h.run_until(|h| !h.net().connects().is_empty(), 5_000)
            .unwrap();
        assert_eq!(resolves(&h).first(), Some(&(1, true, rc::ZOK)), "{p:?}");
        assert_eq!(h.net().connects()[0], addr("127.0.0.1:2121"), "{p:?}");
    }
}

/// Zookeeper_init::testMultipleAddressResolution. Two entries resolve
/// in the order of the string, each with its own port.
#[test]
fn test_multiple_address_resolution() {
    for p in Profile::LEGACY {
        let mut h = with_hosts(p, 504, "127.0.0.1:2121,127.0.0.2:3434").build();
        h.run_until(|h| h.net().connects().len() >= 2, 10_000)
            .unwrap();
        assert_eq!(resolves(&h).first(), Some(&(2, true, rc::ZOK)), "{p:?}");
        assert_eq!(
            h.net().connects()[..2],
            [addr("127.0.0.1:2121"), addr("127.0.0.2:3434")],
            "{p:?}"
        );
    }
}

/// Zookeeper_init::testNullAddressString. Rust has no NULL string. The
/// nearest input, a string that ends at once, fails with `EINVAL`.
#[test]
fn test_null_address_string() {
    assert_einval(b"\0", HostParseErrorKind::Empty);
}

/// Zookeeper_init::testEmptyAddressString. An empty string fails with
/// `EINVAL`.
#[test]
fn test_empty_address_string() {
    assert_einval(b"", HostParseErrorKind::Empty);
}

/// Zookeeper_init::testOneSpaceAddressString. A single space has no port
/// and fails with `EINVAL`.
#[test]
fn test_one_space_address_string() {
    assert_einval(b" ", HostParseErrorKind::NoPort);
}

/// Zookeeper_init::testTwoSpacesAddressString. Two spaces have no port
/// and fail with `EINVAL`.
#[test]
fn test_two_spaces_address_string() {
    assert_einval(b"  ", HostParseErrorKind::NoPort);
}

/// Zookeeper_init::testInvalidAddressString1. An entry with no port
/// fails with `EINVAL`.
#[test]
fn test_invalid_address_string1() {
    assert_einval(b"host1", HostParseErrorKind::NoPort);
}

/// Zookeeper_init::testInvalidAddressString2. The last colon splits the
/// entry, so the host name is "host1:1111+host". That name does not
/// resolve, the resolution fails, and no connect follows.
#[test]
fn test_invalid_address_string2() {
    const TEXT: &str = "host1:1111+host:123";
    let cs = parse_init(TEXT.as_bytes()).unwrap();
    assert_eq!(cs.hosts.len(), 1);
    assert_eq!(cs.hosts[0].host, b"host1:1111+host");
    assert_eq!(cs.hosts[0].port, 123);
    for p in Profile::LEGACY {
        let mut h = with_hosts(p, 505, TEXT).build();
        h.run_for(3_000).unwrap();
        let first = resolves(&h).first().copied();
        assert!(
            matches!(first, Some((1, true, r)) if r != rc::ZOK),
            "{p:?}: {first:?}"
        );
        assert!(h.net().connects().is_empty(), "{p:?}");
        assert!(!h.state().is_connected(), "{p:?}");
    }
}

/// Zookeeper_init::testNonexistentHost. A name that does not resolve
/// fails the first resolution, and no connect follows.
#[test]
fn test_nonexistent_host() {
    for p in Profile::LEGACY {
        let mut h = with_hosts(p, 506, "host1.blabadibla.bla.:1111").build();
        h.run_for(3_000).unwrap();
        let first = resolves(&h).first().copied();
        assert!(
            matches!(first, Some((1, true, r)) if r != rc::ZOK),
            "{p:?}: {first:?}"
        );
        assert!(h.net().connects().is_empty(), "{p:?}");
        assert!(!h.state().is_connected(), "{p:?}");
    }
}

/// Zookeeper_init::testPermuteAddrsList. With the `random()` values 0, 1
/// and 1, the Fisher-Yates shuffle turns the four addresses into the
/// order 3, 2, 1, 0. The connects follow that order.
#[test]
fn test_permute_addrs_list() {
    for p in Profile::LEGACY {
        let mut h = p
            .builder(507)
            .servers(4)
            .shuffle(true)
            .rng(RngChoice::Scripted {
                randoms: vec![0, 1, 1],
                drands: vec![],
            })
            .build();
        for i in 0..4 {
            h.server_mut().set_accepting(server_addr(i), false);
        }
        h.run_until(|h| h.net().connects().len() >= 4, 20_000)
            .unwrap();
        let want: Vec<_> = (0..4).rev().map(server_addr).collect();
        assert_eq!(h.net().connects()[..4], want[..], "{p:?}");
    }
}
