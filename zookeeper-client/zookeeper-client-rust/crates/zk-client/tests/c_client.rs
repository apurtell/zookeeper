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

//! C parity tests of `TestClient.cc` (suite `Zookeeper_simpleSystem`).
//! Each test names its C case.
//!
//! The tests use a real server of this source tree:
//!
//! - Offset 0: one shared server. Each scenario uses its own root node
//!   and runs once per driver.
//! - Offset 1: a port with no server, for `testFirstServerDown`.
//! - Offset 2: a dedicated server for the tests that stop and start
//!   their server, or that need a quiet zxid. A lock runs these tests
//!   one after the other.
//! - Offset 3: a server with a short container check, for TTL nodes.
//! - Offsets 4 and 5: a TLS server with `ssl.clientAuth=none`.
//!
//! The tests have `#[ignore = "real-server"]`. Run them with
//! `ZK_TEST_PORT_BASE=<base> cargo test --test c_client -- --ignored`.
//! Add `--features tls-ring` for the TLS test.

// A scenario is one long async body. It runs on a 2 MiB test or worker
// thread, so the stack frame limit of the library does not apply.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;
mod parity_g1;

use std::io;
use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use apache_zookeeper::acl::{CREATOR_ALL_ACL, OPEN_ACL_UNSAFE, READ_ACL_UNSAFE};
use apache_zookeeper::{
    Client, CreateMode, Error, EventKind, Perms, Resolve, ServerOrder, SessionState, Ttl,
    WatchError, WatcherKind,
};
use common::{Ctx, Rt, SharedServer, WAIT, real_port, wait_state, within};
use parity_g1::{
    RECONNECT_WAIT, expect_event, fresh_server_with, is_pending, restart, restart_builder,
    within_for,
};

/// The shared server of this file.
static SERVER: SharedServer = SharedServer::new(0);

/// The port offset with no server.
const DOWN_OFFSET: u16 = 1;

/// The port offset of the dedicated server.
const DEDICATED_OFFSET: u16 = 2;

/// The port offset of the TTL server.
const TTL_OFFSET: u16 = 3;

/// The plain port offset of the TLS server.
#[cfg(feature = "tls-rustls")]
const TLS_OFFSET: u16 = 4;

/// The secure port offset of the TLS server.
#[cfg(feature = "tls-rustls")]
const TLS_SECURE_OFFSET: u16 = 5;

/// The dedicated server has one port, so its tests run one at a time.
static DEDICATED: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Runs `scenario` once per driver on the shared server, each on a
/// multi-thread runtime.
macro_rules! shared_test {
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

/// Creates a persistent node with no data.
async fn mk(c: &Client, path: &str) {
    within(c.create(path, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap_or_else(|e| panic!("create {path}: {e:?}"));
}

/// Shows that the client refuses the create of `path` with `mode`
/// before it sends a request.
async fn create_refused(c: &Client, path: &str, mode: CreateMode) {
    let f = c.create(path, b"", mode, OPEN_ACL_UNSAFE);
    assert!(f.is_ready(), "{path:?} {mode:?}: the request went out");
    assert!(
        matches!(f.await, Err(Error::InvalidPath(_))),
        "{path:?} {mode:?}"
    );
}

/// Shows that the create of `path` with `mode` succeeds.
async fn create_ok(c: &Client, path: &str, mode: CreateMode) {
    let r = within(c.create(path, b"", mode, OPEN_ACL_UNSAFE)).await;
    assert!(r.is_ok(), "{path:?} {mode:?}: {r:?}");
}

/// Takes the dedicated server lock and starts the dedicated server on
/// an empty tree, or gives `None` to skip.
async fn dedicated() -> Option<(tokio::sync::MutexGuard<'static, ()>, common::RealServer)> {
    let lock = DEDICATED.lock().await;
    let server = common::fresh_server(DEDICATED_OFFSET)?;
    Some((lock, server))
}

// ---- host list ----

shared_test!(first_host_down_connects_to_the_next);
/// C case `Zookeeper_simpleSystem::testFirstServerDown`: with the
/// given host order, a first host with no server does not stop the
/// connect. The client connects to the second host.
async fn first_host_down_connects_to_the_next(ctx: Ctx) {
    let down = real_port(DOWN_OFFSET).unwrap();
    let cs = format!("127.0.0.1:{down},{}", ctx.cs);
    let b = ctx
        .rt
        .apply(common::builder(&cs))
        .server_order(ServerOrder::AsGiven);
    let c = within(b.connect()).await.unwrap();
    assert_eq!(c.connected_server().map(|a| a.port()), Some(ctx.port()));
    assert!(within(c.exists("/")).await.unwrap().is_some());
    within(c.close()).await.unwrap();
}

/// A resolver that fails the host `jimmy` and uses the system resolver
/// for each other host.
///
/// The system resolver can take 30 s to fail an unknown name. The C
/// client also resolves the names before it connects, so it has the
/// same wait. This resolver gives the failure at once, so the test does
/// not depend on the DNS setup of the host.
struct UnknownJimmy;

impl Resolve for UnknownJimmy {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == "jimmy" {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown host jimmy",
            ));
        }
        (host, port).to_socket_addrs().map(Iterator::collect)
    }
}

shared_test!(unknown_host_name_does_not_block_the_connect);
/// C case `Zookeeper_simpleSystem::testNonexistentHost`: a first host
/// name that does not resolve does not block the connect. With the
/// given host order, the client skips the name and connects to the
/// next host.
async fn unknown_host_name_does_not_block_the_connect(ctx: Ctx) {
    let cs = format!("jimmy:5555,{}", ctx.cs);
    let b = ctx
        .rt
        .apply(common::builder(&cs))
        .resolver(UnknownJimmy)
        .server_order(ServerOrder::AsGiven);
    let c = within(b.connect()).await.unwrap();
    assert_eq!(c.connected_server().map(|a| a.port()), Some(ctx.port()));
    within(c.close()).await.unwrap();
}

shared_test!(ipv6_literal_host_connects);
/// C case `Zookeeper_simpleSystem::testIPV6`: the bare IPv6 literal
/// `::1:PORT` names the host `::1` and the port. The client connects
/// over IPv6 and creates a node. The test skips when the server does
/// not listen on `[::1]`.
async fn ipv6_literal_host_connects(ctx: Ctx) {
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, ctx.port()));
    if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err() {
        eprintln!("skip: the server does not listen on {addr}");
        return;
    }
    let cs = format!("::1:{}", ctx.port());
    let c = within(ctx.rt.apply(common::builder(&cs)).connect())
        .await
        .unwrap();
    assert_eq!(c.connected_server(), Some(addr));
    // The C case creates the node with NULL data. The native API has
    // no NULL data, so the node has empty data.
    mk(&c, &ctx.root).await;
    within(c.close()).await.unwrap();
}

// ---- create modes and paths ----

/// C case `Zookeeper_simpleSystem::testCreateTtl`: a node with a TTL of
/// 1 ms and no children goes away after its TTL. The server checks
/// containers and TTL nodes every 100 ms, as `zkServer.sh` of the C
/// tests sets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn ttl_node_goes_away_after_its_ttl() {
    let Some(server) = fresh_server_with(TTL_OFFSET, "", "-Dznode.container.checkIntervalMs=100")
    else {
        return;
    };
    let cs = server.connect_string();
    for rt in common::all_rts() {
        let c = within(rt.apply(common::builder(&cs)).connect())
            .await
            .unwrap();
        let p = format!("/testTtl-{}", rt.name());
        let ttl = Ttl::from_millis(1).unwrap();
        let (created, _) = within(c.create(
            &*p,
            b"",
            CreateMode::PersistentWithTtl(ttl),
            OPEN_ACL_UNSAFE,
        ))
        .await
        .unwrap();
        assert_eq!(created, p.as_str());
        within_for(Duration::from_secs(10), async {
            while within(c.exists(&*p)).await.unwrap().is_some() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert_eq!(within(c.exists(&*p)).await, Ok(None));
        within(c.close()).await.unwrap();
    }
}

shared_test!(two_creates_give_their_paths_and_different_stats);
/// C case `Zookeeper_simpleSystem::testCreate`: a create gives the
/// created path and the stat of the new node. The stat has a zxid and a
/// time. Two creates give two different stats.
async fn two_creates_give_their_paths_and_different_stats(ctx: Ctx) {
    let c = ctx.connect().await;
    mk(&c, &ctx.root).await;
    let a = ctx.path("/testcreateA");
    let b = ctx.path("/testcreateB");
    let (pa, sa) = within(c.create(&*a, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let (pb, sb) = within(c.create(&*b, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(pa, a.as_str());
    assert_eq!(pb, b.as_str());
    for st in [&sa, &sb] {
        assert!(st.czxid.0 > 0, "{st:?}");
        assert!(st.mtime > 0, "{st:?}");
    }
    assert_ne!(sa, sb);
    within(c.close()).await.unwrap();
}

shared_test!(get_acl_reads_back_each_set_acl);
/// C case `Zookeeper_simpleSystem::testAcl`: `get_acl` of a new node
/// gives the ACL of the create. After `set_acl`, `get_acl` gives the new
/// ACL.
async fn get_acl_reads_back_each_set_acl(ctx: Ctx) {
    let c = ctx.connect().await;
    mk(&c, &ctx.root).await;
    let (acl, _) = within(c.get_acl(&*ctx.root)).await.unwrap();
    assert_eq!(acl, OPEN_ACL_UNSAFE);
    within(c.set_acl(&*ctx.root, READ_ACL_UNSAFE, None))
        .await
        .unwrap();
    let (acl, _) = within(c.get_acl(&*ctx.root)).await.unwrap();
    assert_eq!(acl, READ_ACL_UNSAFE);
    within(c.close()).await.unwrap();
}

shared_test!(child_list_stat_matches_the_exists_stat);
/// C case `Zookeeper_simpleSystem::testGetChildren2`: the stat of a
/// child list with stat is the stat that `exists` gives for the same
/// node, and it counts the four children.
async fn child_list_stat_matches_the_exists_stat(ctx: Ctx) {
    let c = ctx.connect().await;
    mk(&c, &ctx.root).await;
    for k in ["a", "b", "c", "d"] {
        mk(&c, &ctx.path(&format!("/child_{k}"))).await;
    }
    let (kids, st_a) = within(c.get_children_with_stat(&*ctx.root)).await.unwrap();
    assert_eq!(kids.len(), 4, "{kids:?}");
    let st_b = within(c.exists(&*ctx.root)).await.unwrap().unwrap();
    assert_eq!(st_a, st_b);
    assert_eq!(st_a.num_children, 4);
    within(c.close()).await.unwrap();
}

shared_test!(path_rules_match_the_c_table);
/// C case `Zookeeper_simpleSystem::testPathValidation`: the client
/// refuses each bad path of the C table before it sends a request. A
/// sequential create checks the path with a suffix, so a trailing `/`,
/// `/.` or `/..` is a valid prefix. Names that start or end with dots
/// are valid. The C case also passes a NULL path. The native API has no
/// NULL path. The client has a chroot, so the nodes stay under the
/// root node of the test.
async fn path_rules_match_the_c_table(ctx: Ctx) {
    let admin = ctx.connect().await;
    mk(&admin, &ctx.root).await;
    let c = within(ctx.builder().chroot(ctx.root.as_str()).connect())
        .await
        .unwrap();

    for bad in [
        "",
        "//",
        "///",
        "////",
        "/.",
        "/..",
        "/./",
        "/../",
        "/foo/./",
        "/foo/../",
        "/foo/.",
        "/foo/..",
        "/./.",
        "/../..",
        "/foo/bar/",
        "/foo//bar",
        "/foo/bar//",
        "foo",
        "a",
    ] {
        create_refused(&c, bad, CreateMode::Persistent).await;
    }

    create_ok(&c, "/createseq", CreateMode::Persistent).await;
    create_refused(&c, "/createseq/", CreateMode::Persistent).await;
    for ok in ["/createseq/", "/createseq/.", "/createseq/.."] {
        create_ok(&c, ok, CreateMode::PersistentSequential).await;
    }
    for bad in ["/createseq//", "/createseq/./", "/createseq/../"] {
        create_refused(&c, bad, CreateMode::PersistentSequential).await;
    }

    for ok in [
        "/.foo", "/.f.", "/..f", "/..f..", "/f.c", "/f", "/f/.f", "/f/f.", "/f/..f", "/f/f..",
        "/f/.f/f", "/f/f./f",
    ] {
        create_ok(&c, ok, CreateMode::Persistent).await;
    }
    assert_eq!(c.stats().pending, 0);
    within(c.close()).await.unwrap();
    within(admin.close()).await.unwrap();
}

// ---- session ----

shared_test!(idle_session_stays_while_another_client_deletes);
/// C case `Zookeeper_simpleSystem::testPing`: a client with 30 exists
/// watches sends no request for longer than its session timeout. Its
/// pings keep the session. The other client deletes the nodes one by
/// one, and each watch fires. The idle client stays on its first
/// connection. The C case waits 15 s with a 10 s timeout. This test
/// waits 6 s with a 4 s timeout.
async fn idle_session_stays_while_another_client_deletes(ctx: Ctx) {
    let idle = ctx.connect().await;
    let creator = ctx.connect().await;
    mk(&creator, &ctx.root).await;
    let paths: Vec<String> = (0..30).map(|i| ctx.path(&format!("/{i}"))).collect();
    for p in &paths {
        mk(&creator, p).await;
    }
    let first = idle.state();
    let (id, _) = idle.session();
    let mut watchers = Vec::new();
    for p in &paths {
        let (st, w) = within(idle.exists_watched(p)).await.unwrap();
        assert!(st.is_some(), "{p}");
        watchers.push(w);
    }

    for p in &paths {
        tokio::time::sleep(Duration::from_millis(200)).await;
        within(creator.delete(p, None)).await.unwrap();
    }

    let now = idle.state();
    assert_eq!(now.state, SessionState::Connected);
    assert_eq!(now.epoch, first.epoch, "the idle client reconnected");
    assert_eq!(idle.session().0, id);
    assert_eq!(within(idle.exists(paths.first().unwrap())).await, Ok(None));
    for (w, p) in watchers.into_iter().zip(&paths) {
        expect_event(w, EventKind::NodeDeleted, p).await;
    }
    within(idle.close()).await.unwrap();
    within(creator.close()).await.unwrap();
}

// ---- chroot ----

shared_test!(chroot_client_sees_paths_below_its_root);
/// C case `Zookeeper_simpleSystem::testChroot`: a chroot client sees
/// the chroot node as `/`. Reads, creates, deletes, sets, ACL calls and
/// child lists use paths below the chroot. Watch events and create
/// results give the path without the chroot (ZOOKEEPER-1027). The C
/// case also passes a NULL handle. The native API has no NULL handle.
async fn chroot_client_sees_paths_below_its_root(ctx: Ctx) {
    let admin = ctx.connect().await;
    let ch1 = ctx.path("/testch1");
    let base = ctx.path("/testch1/mahadev");
    mk(&admin, &ctx.root).await;
    mk(&admin, &ch1).await;
    within(admin.create(&base, b"garbage", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let c = within(ctx.builder().chroot(base.as_str()).connect())
        .await
        .unwrap();

    let (data, _) = within(c.get_data("/")).await.unwrap();
    assert_eq!(data, b"garbage");

    // An exists watch on a missing node fires on the create.
    let (st, w) = within(c.exists_watched("/chroot")).await.unwrap();
    assert!(st.is_none());
    let (created, _) = within(c.create("/chroot", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(created, "/chroot");
    expect_event(w, EventKind::NodeCreated, "/chroot").await;

    // Create and delete act below the chroot.
    let full_child = format!("{base}/chroot/child");
    mk(&c, "/chroot/child").await;
    assert!(within(admin.exists(&full_child)).await.unwrap().is_some());
    within(c.delete("/chroot/child", None)).await.unwrap();
    assert_eq!(within(admin.exists(&full_child)).await, Ok(None));

    // A data watch fires on the set.
    let (_, _, w) = within(c.get_data_watched("/chroot")).await.unwrap();
    within(c.set_data("/chroot", b"gar", None)).await.unwrap();
    expect_event(w, EventKind::NodeDataChanged, "/chroot").await;

    let kids = within(c.get_children("/")).await.unwrap();
    assert_eq!(kids, vec!["chroot".to_owned()]);

    let (acl, _) = within(c.get_acl("/")).await.unwrap();
    assert_eq!(acl.len(), 1, "{acl:?}");
    assert_eq!(acl.first().map(|a| a.perms), Some(Perms::ALL));

    // A read-only ACL refuses a child create.
    within(c.set_acl("/chroot", READ_ACL_UNSAFE, None))
        .await
        .unwrap();
    let r = within(c.create(
        "/chroot/child1",
        b"",
        CreateMode::Persistent,
        OPEN_ACL_UNSAFE,
    ))
    .await;
    assert_eq!(r.err(), Some(Error::NoAuth));

    // A child watch on the chroot node gives the path `/`.
    let (_, _, w) = within(c.get_children_watched("/")).await.unwrap();
    mk(&c, "/child2").await;
    expect_event(w, EventKind::NodeChildrenChanged, "/").await;

    for p in ["/child3", "/zookeeper1027", "/zookeeper2282"] {
        let (created, _) = within(c.create(p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
            .await
            .unwrap();
        assert_eq!(created, p);
    }
    within(c.close()).await.unwrap();
    within(admin.close()).await.unwrap();
}

// ---- close ----

shared_test!(close_ends_a_task_that_rearms_a_child_watch);
/// C case `Zookeeper_simpleSystem::testHangingClient`: `close` does not
/// hang while another task re-arms a child watch after each event. The
/// close ends the session, and the task ends with an error. The C case
/// re-arms from the default watcher of the handle. The native API has
/// no default watcher, so a task does the same work.
async fn close_ends_a_task_that_rearms_a_child_watch(ctx: Ctx) {
    let c = ctx.connect().await;
    let root = ctx.root.clone();
    within(c.create(&*root, b"testall", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let (_, _, first) = within(c.get_children_watched(&*root)).await.unwrap();
    let events = Arc::new(AtomicUsize::new(0));
    let task = {
        let c = c.clone();
        let root = root.clone();
        let events = Arc::clone(&events);
        tokio::spawn(async move {
            let mut w = first;
            loop {
                if w.await.is_err() {
                    return;
                }
                events.fetch_add(1, Ordering::SeqCst);
                match c.get_children_watched(&*root).await {
                    Ok((_, _, next)) => w = next,
                    Err(_) => return,
                }
            }
        })
    };

    let child = ctx.path("/test1");
    mk(&c, &child).await;
    within(async {
        while events.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    within(c.delete(&*child, None)).await.unwrap();
    within(c.close()).await.unwrap();
    within(task).await.unwrap();
    assert!(events.load(Ordering::SeqCst) >= 1);
}

// ---- auth ----

/// C case `Zookeeper_simpleSystem::testAuth`: digest auth gives access
/// to a node with the creator ACL. An empty digest is accepted. A wrong
/// password gives `NoAuth`, and a later correct auth gives access. The
/// auth goes out before a read that follows it. After a server restart
/// the client sends its auth again (ZOOKEEPER-1108 covers an auth that
/// is added before the connect). While the server is down the client
/// has no connected server. The NULL handle and NULL scheme checks of
/// the C case are C API checks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn digest_auth_gives_access_and_survives_a_restart() {
    let Some((_lock, server)) = dedicated().await else {
        return;
    };
    let cs = server.connect_string();
    for rt in common::all_rts() {
        let node = format!("/tauth1-{}", rt.name());
        let connect = || async { within(restart_builder(rt, &cs).connect()).await.unwrap() };

        let c1 = connect().await;
        within(c1.add_auth("digest", "pat:passwd")).await.unwrap();
        within(c1.create(&*node, b"", CreateMode::Persistent, CREATOR_ALL_ACL))
            .await
            .unwrap();

        let c4 = connect().await;
        within(c4.add_auth("digest", "")).await.unwrap();
        within(c4.add_auth("digest", "")).await.unwrap();

        let c2 = connect().await;
        within(c2.add_auth("digest", "pat:passwd2")).await.unwrap();
        assert_eq!(
            within(c2.get_data(&*node)).await.map(|_| ()),
            Err(Error::NoAuth)
        );
        // The read follows the auth on the wire, so it sees the auth.
        let auth = c2.add_auth("digest", "pat:passwd");
        let read = c2.get_data(&*node);
        assert!(within(read).await.is_ok());
        within(auth).await.unwrap();

        let c3 = connect().await;
        within(c3.add_auth("digest", "pat:passwd")).await.unwrap();
        within(c3.add_auth("ip", "none")).await.unwrap();
        let c5 = connect().await;

        server.stop_now();
        for c in [&c3, &c5] {
            let mut s = c.state_watcher();
            wait_state(&mut s, WAIT, |i| i.state == SessionState::Connecting).await;
        }
        assert_eq!(c5.connected_server(), None);
        server.start_again().unwrap();
        for c in [&c3, &c5] {
            let mut s = c.state_watcher();
            wait_state(&mut s, RECONNECT_WAIT, |i| i.state.is_connected()).await;
        }
        assert_eq!(c5.connected_server().map(|a| a.port()), Some(server.port()));

        // The client sends the auth again on the new connection.
        assert!(within(c3.get_data(&*node)).await.is_ok());
        let (acl, _) = within(c3.get_acl("/")).await.unwrap();
        assert_eq!(acl.len(), 1, "{acl:?}");
        assert_eq!(acl.first().map(|a| a.perms), Some(Perms::ALL));
        within(c3.set_acl("/", CREATOR_ALL_ACL, None))
            .await
            .unwrap();
        within(c3.set_acl("/", OPEN_ACL_UNSAFE, None))
            .await
            .unwrap();

        // ZOOKEEPER-1108: an auth added before the connect goes out
        // when the connection is up.
        let early = restart_builder(rt, &cs).build().unwrap();
        within_for(RECONNECT_WAIT, early.add_auth("digest", "pat:passwd"))
            .await
            .unwrap();
        assert!(within(early.get_data(&*node)).await.is_ok());

        for c in [c1, c2, c3, c4, c5, early] {
            within(c.close()).await.unwrap();
        }
    }
}

// ---- watches across server restarts ----

/// C case `Zookeeper_simpleSystem::testAsyncWatcherAutoReset`: 100
/// exists watches go out in one burst. The creates of the first half
/// fire their watches. Then 900 creates of other nodes are in flight
/// when the server stops. A create that fails with `ConnectionLoss` runs
/// again, as the C completion does. The nodes of the second half are
/// created only after the restart. Thus their watches fire only if the
/// client sends its watches again on the reconnect. The C case creates
/// these nodes before the stop, so it does not prove this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn exists_watches_fire_across_a_restart_with_creates_in_flight() {
    let Some((_lock, server)) = dedicated().await else {
        return;
    };
    let cs = server.connect_string();
    for rt in common::all_rts() {
        let c = within(restart_builder(rt, &cs).connect()).await.unwrap();
        let path = |i: usize| format!("/awar-{}-{i}", rt.name());

        let arms: Vec<_> = (0..100).map(|i| c.exists_watched(path(i))).collect();
        let mut watchers = Vec::new();
        for f in arms {
            let (st, w) = within(f).await.unwrap();
            assert!(st.is_none());
            watchers.push(w);
        }
        let creates: Vec<_> = (0..50)
            .map(|i| c.create(path(i), b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
            .collect();
        for f in creates {
            within(f).await.unwrap();
        }
        let second = watchers.split_off(50);
        for (i, w) in watchers.into_iter().enumerate() {
            expect_event(w, EventKind::NodeCreated, &path(i)).await;
        }

        let in_flight: Vec<_> = (100..1000)
            .map(|i| {
                let f = c.create(path(i), b"", CreateMode::Persistent, OPEN_ACL_UNSAFE);
                (i, f)
            })
            .collect();
        restart(&server, &[&c]).await;
        for (i, f) in in_flight {
            match within_for(RECONNECT_WAIT, f).await {
                Ok(_) => {}
                Err(Error::ConnectionLoss) => {
                    let r = within(c.create(path(i), b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
                        .await;
                    assert!(
                        matches!(r, Ok(_) | Err(Error::NodeExists)),
                        "{}: {r:?}",
                        path(i)
                    );
                }
                Err(e) => panic!("{}: {e:?}", path(i)),
            }
        }

        // The server lost its watches in the restart. Only the watches
        // that the client sent again can see these creates.
        let late: Vec<_> = (51..100)
            .map(|i| c.create(path(i), b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
            .collect();
        for f in late {
            within(f).await.unwrap();
        }

        let mut second = second.into_iter();
        // Node 50 is never created, so its watch stays.
        let mut w50 = second.next().unwrap();
        for (i, w) in (51..100).zip(second) {
            expect_event(w, EventKind::NodeCreated, &path(i)).await;
        }
        assert!(is_pending(&mut w50).await);
        within(c.close()).await.unwrap();
    }
}

/// C cases `Zookeeper_simpleSystem::testWatcherAutoResetWithGlobal` and
/// `Zookeeper_simpleSystem::testWatcherAutoResetWithLocal`: a chroot
/// client arms child, data and exists watches. The watches stay across
/// three server restarts, and each fires once with the path below the
/// chroot. An ephemeral node stays, because the session stays. The two
/// C cases differ only in the watcher function: the default watcher of
/// the handle or a watcher of the call. The native API has only watchers
/// of the call, so one test covers both bodies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn watches_stay_across_three_server_restarts() {
    let Some((_lock, server)) = dedicated().await else {
        return;
    };
    let cs = server.connect_string();
    for rt in common::all_rts() {
        let base = format!("/testarw-{}", rt.name());
        let chroot = format!("{base}/arw");
        let admin = within(common::builder(&cs).connect()).await.unwrap();
        mk(&admin, &base).await;
        mk(&admin, &chroot).await;
        within(admin.close()).await.unwrap();

        let c = within(restart_builder(rt, &cs).chroot(chroot.as_str()).connect())
            .await
            .unwrap();
        mk(&c, "/watchtest").await;
        within(c.create(
            "/watchtest/child",
            b"",
            CreateMode::Ephemeral,
            OPEN_ACL_UNSAFE,
        ))
        .await
        .unwrap();

        let (_, _, mut wc) = within(c.get_children_watched("/watchtest")).await.unwrap();
        let (_, _, mut wd) = within(c.get_data_watched("/watchtest/child"))
            .await
            .unwrap();
        let (st, mut we) = within(c.exists_watched("/watchtest/child2")).await.unwrap();
        assert!(st.is_none());
        assert!(is_pending(&mut wc).await);

        restart(&server, &[&c]).await;
        assert!(is_pending(&mut wc).await);
        assert!(is_pending(&mut wd).await);
        assert!(is_pending(&mut we).await);

        within(c.set_data("/watchtest/child", b"1", None))
            .await
            .unwrap();
        let s1 = within(c.set_data("/watchtest/child", b"1", None))
            .await
            .unwrap();
        assert!(s1.version.get() >= 0);
        let s2 = within(c.set_data("/watchtest/child", b"1", s1.version))
            .await
            .unwrap();
        within(c.set_data("/watchtest/child", b"1", s2.version))
            .await
            .unwrap();
        mk(&c, "/watchtest/child2").await;
        expect_event(wd, EventKind::NodeDataChanged, "/watchtest/child").await;
        expect_event(we, EventKind::NodeCreated, "/watchtest/child2").await;
        expect_event(wc, EventKind::NodeChildrenChanged, "/watchtest").await;

        restart(&server, &[&c]).await;
        let (_, _, wc) = within(c.get_children_watched("/watchtest")).await.unwrap();
        let (_, _, mut wd) = within(c.get_data_watched("/watchtest/child"))
            .await
            .unwrap();
        let (st, we) = within(c.exists_watched("/watchtest/child2")).await.unwrap();
        assert!(st.is_some());
        within(c.delete("/watchtest/child2", None)).await.unwrap();
        expect_event(we, EventKind::NodeDeleted, "/watchtest/child2").await;
        expect_event(wc, EventKind::NodeChildrenChanged, "/watchtest").await;
        assert!(is_pending(&mut wd).await);

        restart(&server, &[&c]).await;
        within(c.delete("/watchtest/child", None)).await.unwrap();
        within(c.delete("/watchtest", None)).await.unwrap();
        expect_event(wd, EventKind::NodeDeleted, "/watchtest/child").await;
        within(c.close()).await.unwrap();
    }
}

// ---- zxid ----

/// C case `Zookeeper_simpleSystem::testLastZxid` (ZOOKEEPER-1417): the
/// last zxid of a client changes only on a reply to a request. A ping
/// reply and a watch event do not change it. The test needs a server
/// with no other clients, because each reply carries the last zxid of
/// the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn last_zxid_follows_replies_and_not_pings_or_events() {
    let Some((_lock, server)) = dedicated().await else {
        return;
    };
    let cs = server.connect_string();
    for rt in common::all_rts() {
        let node = format!("/lastzxid-{}", rt.name());
        let zk1 = within(rt.apply(common::builder(&cs)).connect())
            .await
            .unwrap();
        let zk2 = within(rt.apply(common::builder(&cs)).connect())
            .await
            .unwrap();
        let original = zk2.last_zxid();

        mk(&zk1, &node).await;
        // The wait is more than half of the session timeout, so zk2 sends
        // at least one ping.
        tokio::time::sleep(Duration::from_millis(2_500)).await;

        let st = within(zk1.exists(&*node)).await.unwrap().unwrap();
        assert_eq!(zk1.last_zxid(), st.czxid);
        assert_eq!(zk2.last_zxid(), original);

        let (st, w) = within(zk2.exists_watched(&*node)).await.unwrap();
        let updated = zk2.last_zxid();
        assert_eq!(updated, st.unwrap().czxid);

        within(zk1.set_data(&*node, b"", None)).await.unwrap();
        expect_event(w, EventKind::NodeDataChanged, &node).await;
        assert_eq!(zk2.last_zxid(), updated);

        within(zk1.close()).await.unwrap();
        within(zk2.close()).await.unwrap();
    }
}

// ---- remove watches ----

/// C case `Zookeeper_simpleSystem::testRemoveWatchers`: `Any` removes
/// all watchers of a path, and a later set fires none. A remove with no
/// watcher gives `NoWatcher`, for data and child watches. A server
/// remove while the server is down gives `ConnectionLoss`. A local
/// remove while the server is down succeeds once per watcher, and then
/// gives `NoWatcher`. The C case selects a watcher by its function and
/// context. The native API removes all watchers of a kind, so each path
/// has one watcher here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn remove_watches_follow_the_c_results_with_the_server_down() {
    let Some((_lock, server)) = dedicated().await else {
        return;
    };
    let cs = server.connect_string();
    for rt in common::all_rts() {
        let path = format!("/something-{}", rt.name());
        let path2 = format!("/something2-{}", rt.name());
        let c = within(restart_builder(rt, &cs).connect()).await.unwrap();
        mk(&c, &path).await;
        mk(&c, &path2).await;

        let (_, _, w1) = within(c.get_data_watched(&*path)).await.unwrap();
        let (_, _, w2) = within(c.get_data_watched(&*path)).await.unwrap();
        within(c.remove_watches(&*path, WatcherKind::Any, false))
            .await
            .unwrap();
        within(c.set_data(&*path, b"nowatch", None)).await.unwrap();
        assert_eq!(within(w1).await, Err(WatchError::Removed));
        assert_eq!(within(w2).await, Err(WatchError::Removed));

        assert_eq!(
            within(c.remove_watches(&*path, WatcherKind::Data, false)).await,
            Err(Error::NoWatcher)
        );
        let (_, _, w) = within(c.get_data_watched(&*path)).await.unwrap();
        within(c.remove_watches(&*path, WatcherKind::Data, false))
            .await
            .unwrap();
        assert_eq!(within(w).await, Err(WatchError::Removed));

        assert_eq!(
            within(c.remove_watches(&*path, WatcherKind::Children, false)).await,
            Err(Error::NoWatcher)
        );
        let (_, _, w) = within(c.get_children_watched(&*path)).await.unwrap();
        within(c.remove_watches(&*path, WatcherKind::Children, false))
            .await
            .unwrap();
        assert_eq!(within(w).await, Err(WatchError::Removed));

        // A server remove fails while the server is down.
        let (_, _, _w) = within(c.get_data_watched(&*path)).await.unwrap();
        server.stop_now();
        let mut s = c.state_watcher();
        wait_state(&mut s, WAIT, |i| i.state == SessionState::Connecting).await;
        assert_eq!(
            within_for(
                RECONNECT_WAIT,
                c.remove_watches(&*path, WatcherKind::Data, false)
            )
            .await,
            Err(Error::ConnectionLoss)
        );
        // The C case closes the handle while the server is down.
        let _ = within_for(RECONNECT_WAIT, c.close()).await;

        server.start_again().unwrap();
        let c = within_for(RECONNECT_WAIT, restart_builder(rt, &cs).connect())
            .await
            .unwrap();
        let (_, _, w1) = within(c.get_data_watched(&*path)).await.unwrap();
        let (_, _, w2) = within(c.get_data_watched(&*path2)).await.unwrap();
        server.stop_now();
        within(c.remove_watches(&*path, WatcherKind::Data, true))
            .await
            .unwrap();
        assert_eq!(within(w1).await, Err(WatchError::Removed));
        assert_eq!(
            within(c.remove_watches(&*path, WatcherKind::Data, true)).await,
            Err(Error::NoWatcher)
        );
        within(c.remove_watches(&*path2, WatcherKind::Data, true))
            .await
            .unwrap();
        assert_eq!(within(w2).await, Err(WatchError::Removed));

        server.start_again().unwrap();
        let mut s = c.state_watcher();
        wait_state(&mut s, RECONNECT_WAIT, |i| i.state.is_connected()).await;
        within(c.close()).await.unwrap();
    }
}

// ---- TLS ----

/// C case `Zookeeper_simpleSystem::testSSLServerOnly`: with
/// `ssl.clientAuth=none`, a client with only the CA file and no client
/// certificate connects to the secure port and creates a node.
#[cfg(feature = "tls-rustls")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn tls_server_auth_only_accepts_a_client_without_a_certificate() {
    use apache_zookeeper::TlsOptions;
    use parity_g1::{start_or_skip, tls_fixture, tls_props};

    let (Some(port), Some(secure)) = (real_port(TLS_OFFSET), real_port(TLS_SECURE_OFFSET)) else {
        return;
    };
    let dir = common::default_server_dir(port);
    // A rerun starts from an empty tree. On a first run the directory
    // does not exist.
    let _ = std::fs::remove_dir_all(dir.join("data"));
    let props = tls_props(&dir, secure, "none");
    let Some(_server) = start_or_skip(port, None, &props, "") else {
        return;
    };
    let cs = format!("127.0.0.1:{secure}");
    for rt in common::all_rts() {
        let tls = TlsOptions::builder()
            .ca_file(tls_fixture("ca.pem"))
            .build()
            .unwrap();
        let c = within(rt.apply(common::builder(&cs)).tls(tls).connect())
            .await
            .unwrap();
        let p = format!("/ssl-server-only-{}", rt.name());
        mk(&c, &p).await;
        within(c.close()).await.unwrap();
    }
}
