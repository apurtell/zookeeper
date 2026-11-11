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

//! Operation tests against a real server of this source tree: CRUD,
//! create modes, versions, ACLs, the 3.6+ reads, transactions, chroot,
//! call order and the blocking waits.
//!
//! All tests of this file share one server at port offset 10. Each
//! test uses its own root node. Each scenario runs once with the IO
//! thread and once with a tokio task. The tests have
//! `#[ignore = "real-server"]`. Run them with
//! `ZK_TEST_PORT_BASE=<base> cargo test --test real_ops -- --ignored`.

// A scenario is one long async body. It runs on a 2 MiB test or worker
// thread, so the stack frame limit of the library does not apply.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use apache_zookeeper::acl::{CREATOR_ALL_ACL, OPEN_ACL_UNSAFE, READ_ACL_UNSAFE};
use apache_zookeeper::{
    Acl, CreateMode, EphemeralKind, Error, Id, MultiError, MultiReader, MultiWriter, OpResult,
    Perms, ReadResult, Reconfig, SessionState, Ttl, Version,
};
use common::{Ctx, Rt, SharedServer, setup, within};

/// The server of this file.
static SERVER: SharedServer = SharedServer::new(10);

/// Runs `scenario` once per driver, each on a multi-thread runtime.
macro_rules! real_test {
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

// ---- CRUD and versions ----

real_test!(crud_and_versions);
/// Rule: each op gives its typed result, and a version or existence
/// conflict gives its own error code (spec "Operations, Result Types,
/// and Error Handling").
async fn crud_and_versions(ctx: Ctx) {
    let c = setup(&ctx).await;
    let n = ctx.path("/n");
    let (p, st) = within(c.create(&n, b"a", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(p.as_str(), n);
    assert_eq!((st.version, st.data_length), (Version::new(0), 1));
    assert_eq!(st.ephemeral_kind(), EphemeralKind::None);
    assert!(c.last_zxid() >= st.czxid);

    // Existence conflicts.
    let again = c.create(&n, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE);
    assert_eq!(within(again).await.unwrap_err(), Error::NodeExists);
    let orphan = ctx.path("/none/child");
    let orphan = c.create(&orphan, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE);
    assert_eq!(within(orphan).await.unwrap_err(), Error::NoNode);

    // Reads.
    let (data, st2) = within(c.get_data(&n)).await.unwrap();
    assert_eq!((data.as_slice(), st2), (&b"a"[..], st));
    assert_eq!(
        within(c.get_data_opt(&n)).await.unwrap().0,
        Some(b"a".to_vec())
    );
    assert_eq!(within(c.exists(&n)).await.unwrap(), Some(st));
    assert_eq!(within(c.exists(ctx.path("/none"))).await, Ok(None));
    assert_eq!(
        within(c.get_data(ctx.path("/none"))).await.unwrap_err(),
        Error::NoNode
    );

    // Versions: a wrong version, an exact version, `None` and `ANY`.
    let bad = c.set_data(&n, b"x", Version::new(5));
    assert_eq!(within(bad).await.unwrap_err(), Error::BadVersion);
    let st = within(c.set_data(&n, b"b", Some(Version::new(0))))
        .await
        .unwrap();
    assert_eq!(st.version, Version::new(1));
    let st = within(c.set_data(&n, b"c", None)).await.unwrap();
    assert_eq!(st.version, Version::new(2));
    let st = within(c.set_data(&n, b"", Version::ANY)).await.unwrap();
    assert_eq!((st.version, st.data_length), (Version::new(3), 0));
    // The native client writes empty data, never null data.
    assert_eq!(
        within(c.get_data_opt(&n)).await.unwrap().0,
        Some(Vec::new())
    );
    let missing = c.set_data(ctx.path("/none"), b"", None);
    assert_eq!(within(missing).await.unwrap_err(), Error::NoNode);

    // Deletes: NotEmpty, BadVersion, NoNode, then success.
    let child = ctx.path("/n/c");
    within(c.create(&child, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(within(c.delete(&n, None)).await, Err(Error::NotEmpty));
    assert_eq!(
        within(c.delete(&child, Version::new(3))).await,
        Err(Error::BadVersion)
    );
    within(c.delete(&child, Version::new(0))).await.unwrap();
    assert_eq!(within(c.delete(&child, None)).await, Err(Error::NoNode));
    within(c.delete(&n, Version::new(3))).await.unwrap();
    assert_eq!(within(c.exists(&n)).await, Ok(None));
    within(c.close()).await.unwrap();
}

real_test!(bad_paths_send_nothing);
/// Rule: path validation runs before submit; a bad path gives a ready
/// `InvalidPath` and sends nothing (spec "Operations, Result Types, and
/// Error Handling", first execution step).
async fn bad_paths_send_nothing(ctx: Ctx) {
    let c = ctx.connect().await;
    for bad in ["", "rel", "/a/", "/a//b", "/a/./b", "/a/..", "/a\u{0}b"] {
        let f = c.get_data(bad);
        assert!(f.is_ready(), "{bad:?}");
        assert!(matches!(f.await, Err(Error::InvalidPath(_))), "{bad:?}");
    }
    // A sequential create checks `path + "1"`, so a trailing `/` is a
    // valid prefix. The parent is missing here, so the server says NoNode.
    let f = c.create(
        ctx.path("/"),
        b"",
        CreateMode::PersistentSequential,
        OPEN_ACL_UNSAFE,
    );
    assert_eq!(within(f).await.unwrap_err(), Error::NoNode);
    assert_eq!(c.stats().pending, 0);
    within(c.close()).await.unwrap();
}

// ---- create modes ----

real_test!(create_modes);
/// Rule: each `CreateMode` maps to its server node type, and the stat
/// shows it (the server runs with `extendedTypesEnabled=true`).
async fn create_modes(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (id, _) = c.session();

    let (_, st) = within(c.create(ctx.path("/e"), b"", CreateMode::Ephemeral, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(st.ephemeral_kind(), EphemeralKind::Session(id));
    assert_eq!(st.ephemeral_owner, id.0);
    let under = c.create(
        ctx.path("/e/c"),
        b"",
        CreateMode::Persistent,
        OPEN_ACL_UNSAFE,
    );
    assert_eq!(
        within(under).await.unwrap_err(),
        Error::NoChildrenForEphemerals
    );

    // Sequential names have a 10-digit counter from the parent cversion.
    let mut seq = Vec::new();
    for mode in [
        CreateMode::PersistentSequential,
        CreateMode::EphemeralSequential,
        CreateMode::PersistentSequentialWithTtl(Ttl::from_millis(60_000).unwrap()),
    ] {
        let (p, _) = within(c.create(ctx.path("/s-"), b"", mode, OPEN_ACL_UNSAFE))
            .await
            .unwrap();
        seq.push(p.into_string());
    }
    for (i, p) in seq.iter().enumerate() {
        let suffix = p.strip_prefix(&ctx.path("/s-")).unwrap();
        assert_eq!(suffix.len(), 10, "{p}");
        assert!(suffix.parse::<u32>().is_ok(), "{p}");
        if let Some(prev) = i.checked_sub(1).and_then(|j| seq.get(j)) {
            assert!(p > prev, "{p} after {prev}");
        }
    }

    let (_, st) = within(c.create(ctx.path("/k"), b"", CreateMode::Container, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    // The server hides the owner of container and TTL nodes. It sends 0
    // for every owner that is not a session (DataNode.getClientEphemeralOwner).
    assert_eq!(st.ephemeral_kind(), EphemeralKind::None);
    let ttl = CreateMode::PersistentWithTtl(Ttl::new(std::time::Duration::from_secs(90)).unwrap());
    let (_, st) = within(c.create(ctx.path("/t"), b"", ttl, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(st.ephemeral_kind(), EphemeralKind::None);
    assert!(Ttl::from_millis(0).is_err());

    // The ephemerals of this session, by string prefix.
    let mut eph: Vec<String> = within(c.get_ephemerals(&ctx.root))
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.into_string())
        .collect();
    eph.sort();
    let want = vec![ctx.path("/e"), seq.get(1).unwrap().clone()];
    assert_eq!(eph, want);
    let all = within(c.get_ephemerals_all()).await.unwrap();
    assert!(all.iter().any(|p| p.as_str() == ctx.path("/e")), "{all:?}");

    // Ephemerals go with the session at close.
    let other = ctx.connect().await;
    within(c.close()).await.unwrap();
    assert_eq!(within(other.exists(ctx.path("/e"))).await, Ok(None));
    assert!(
        within(other.exists(seq.first().unwrap()))
            .await
            .unwrap()
            .is_some()
    );
    within(other.close()).await.unwrap();
}

real_test!(children_and_counts);
/// Rule: `get_children` gives names, `get_children_with_stat` (op 12)
/// adds the parent stat, and `get_all_children_number` (op 104) counts
/// every descendant.
async fn children_and_counts(ctx: Ctx) {
    let c = setup(&ctx).await;
    for rel in ["/a", "/b", "/a/x", "/a/y", "/a/x/z"] {
        within(c.create(ctx.path(rel), b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
            .await
            .unwrap();
    }
    let mut names = within(c.get_children(&ctx.root)).await.unwrap();
    names.sort();
    assert_eq!(names, vec!["a".to_owned(), "b".to_owned()]);
    let (mut names, st) = within(c.get_children_with_stat(ctx.path("/a")))
        .await
        .unwrap();
    names.sort();
    assert_eq!(names, vec!["x".to_owned(), "y".to_owned()]);
    assert_eq!((st.num_children, st.cversion), (2, Version::new(2)));
    assert_eq!(within(c.get_all_children_number(&ctx.root)).await, Ok(5));
    assert_eq!(
        within(c.get_all_children_number(ctx.path("/b"))).await,
        Ok(0)
    );
    assert_eq!(
        within(c.get_children(ctx.path("/none"))).await,
        Err(Error::NoNode)
    );
    within(c.close()).await.unwrap();
}

// ---- ACLs and auth ----

real_test!(acls_and_digest_auth);
/// Rule: ACLs gate access, `add_auth` adds a digest identity in call
/// order, and `set_acl` checks the ACL version.
async fn acls_and_digest_auth(ctx: Ctx) {
    let owner = setup(&ctx).await;
    let secure = ctx.path("/secure");
    // `auth:` needs an identity first.
    let f = owner.create(&secure, b"s", CreateMode::Persistent, CREATOR_ALL_ACL);
    assert_eq!(within(f).await.unwrap_err(), Error::InvalidAcl);
    within(owner.add_auth("digest", b"alice:pw".to_vec()))
        .await
        .unwrap();
    within(owner.create(&secure, b"s", CreateMode::Persistent, CREATOR_ALL_ACL))
        .await
        .unwrap();
    let (acl, st) = within(owner.get_acl(&secure)).await.unwrap();
    let alice = Acl {
        perms: Perms::ALL,
        id: Id::digest("alice", "pw"),
    };
    assert_eq!((acl, st.aversion), (vec![alice.clone()], Version::new(0)));
    let ids = within(owner.who_am_i()).await.unwrap();
    assert!(
        ids.iter()
            .any(|i| i.auth_scheme == "digest" && i.user == "alice"),
        "{ids:?}"
    );

    // Another session has no rights. This server also checks READ on
    // `exists` (FinalRequestProcessor).
    let other = ctx.connect().await;
    assert_eq!(within(other.exists(&secure)).await, Err(Error::NoAuth));
    assert_eq!(within(other.get_data(&secure)).await, Err(Error::NoAuth));
    assert_eq!(
        within(other.set_data(&secure, b"x", None)).await,
        Err(Error::NoAuth)
    );
    // A digest with the wrong password is accepted, but it is another
    // identity.
    within(other.add_auth("digest", b"alice:wrong".to_vec()))
        .await
        .unwrap();
    assert_eq!(within(other.get_data(&secure)).await, Err(Error::NoAuth));

    // `add_auth` takes its place in call order: the read before it has
    // the old identity, the read after it has the new one.
    let before = other.get_data(&secure);
    let auth = other.add_auth("digest", b"alice:pw".to_vec());
    let after = other.get_data(&secure);
    assert_eq!(within(after).await.unwrap().0, b"s");
    assert_eq!(within(auth).await, Ok(()));
    assert_eq!(within(before).await, Err(Error::NoAuth));

    // `set_acl` checks the ACL version and gives the new stat.
    let bad = other.set_acl(&secure, READ_ACL_UNSAFE, Version::new(3));
    assert_eq!(within(bad).await.unwrap_err(), Error::BadVersion);
    let st = within(other.set_acl(&secure, READ_ACL_UNSAFE, Version::new(0)))
        .await
        .unwrap();
    assert_eq!(st.aversion, Version::new(1));
    // Now world can read, but nobody can write.
    assert_eq!(
        within(owner.set_data(&secure, b"x", None)).await,
        Err(Error::NoAuth)
    );
    assert_eq!(
        within(owner.get_acl(&secure)).await.unwrap().0,
        READ_ACL_UNSAFE.to_vec()
    );
    within(owner.close()).await.unwrap();
    within(other.close()).await.unwrap();
}

real_test!(refused_auth_is_terminal);
/// Rule: a refused auth is the terminal `AuthFailed` state; later
/// requests fail with `AuthFailed`, and `connect()` reports a refused
/// builder entry.
async fn refused_auth_is_terminal(ctx: Ctx) {
    let e = within(ctx.builder().auth("nosuch", b"x".to_vec()).connect())
        .await
        .unwrap_err();
    assert_eq!(e.error(), &Error::AuthFailed);

    let c = ctx.connect().await;
    let (_, _, w) = within(c.get_children_watched("/")).await.unwrap();
    assert_eq!(
        within(c.add_auth("nosuch", b"x".to_vec())).await,
        Err(Error::AuthFailed)
    );
    let mut sw = c.state_watcher();
    common::wait_state(&mut sw, common::WAIT, |i| i.state.is_terminal()).await;
    assert_eq!(c.state().state, SessionState::AuthFailed);
    assert_eq!(
        within(w).await,
        Err(apache_zookeeper::WatchError::AuthFailed)
    );
    assert_eq!(within(c.exists("/")).await, Err(Error::AuthFailed));
    // A close after a terminal state completes at once.
    let _ = within(c.close()).await;
    assert_eq!(c.state().state, SessionState::AuthFailed);
}

// ---- transactions ----

real_test!(multi_commits_and_aborts);
/// Rule: a multi applies all ops or none; an abort names the first
/// failing op and gives a code per op (spec "Transactions").
async fn multi_commits_and_aborts(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (a, b, s, k, t) = (
        ctx.path("/a"),
        ctx.path("/a/b"),
        ctx.path("/s-"),
        ctx.path("/k"),
        ctx.path("/t"),
    );
    let ttl = CreateMode::PersistentWithTtl(Ttl::from_millis(60_000).unwrap());
    let mut txn = MultiWriter::new();
    let ha = txn
        .create(&a, b"1", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let hb = txn
        .create(&b, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let hs = txn
        .create(&s, b"", CreateMode::PersistentSequential, OPEN_ACL_UNSAFE)
        .unwrap();
    let hk = txn
        .create(&k, b"", CreateMode::Container, OPEN_ACL_UNSAFE)
        .unwrap();
    let ht = txn.create(&t, b"", ttl, OPEN_ACL_UNSAFE).unwrap();
    let hset = txn.set_data(&a, b"2", Version::new(0)).unwrap();
    let hcheck = txn.check(&a, Version::new(1)).unwrap();
    let hdel = txn.delete(&b, Version::ANY).unwrap();
    let r = within(c.multi(&txn)).await.unwrap();
    assert_eq!(r.get(ha).unwrap().path.as_str(), a);
    assert_eq!(r.get(hb).unwrap().path.as_str(), b);
    assert!(r.get(hs).unwrap().path.as_str().starts_with(&s));
    // The server sends owner 0 for container and TTL nodes.
    assert_eq!(
        r.get(hk).unwrap().stat.ephemeral_kind(),
        EphemeralKind::None
    );
    assert_eq!(
        r.get(ht).unwrap().stat.ephemeral_kind(),
        EphemeralKind::None
    );
    assert_eq!(r.get(hset).unwrap().version, Version::new(1));
    assert_eq!(r.get(hcheck), Some(&()));
    assert_eq!(r.get(hdel), Some(&()));
    assert_eq!(r.iter().count(), 8);
    assert!(matches!(r.iter().last(), Some(OpResult::Delete)));
    // A handle of another writer gives `None`.
    let mut other = MultiWriter::new();
    let foreign = other.check(&a, Version::ANY).unwrap();
    assert_eq!(r.get(foreign), None);

    // An abort in the middle: ops before it report None, ops after it
    // report RuntimeInconsistency, and nothing is applied.
    let new = ctx.path("/new");
    let mut bad = MultiWriter::new();
    bad.create(&new, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    bad.check(&a, Version::new(7)).unwrap();
    bad.delete(&a, Version::ANY).unwrap();
    match within(c.multi(&bad)).await {
        Err(MultiError::Aborted {
            index,
            error,
            per_op,
        }) => {
            assert_eq!((index, error), (1, Error::BadVersion));
            assert_eq!(
                per_op,
                vec![
                    None,
                    Some(Error::BadVersion),
                    Some(Error::RuntimeInconsistency)
                ]
            );
        }
        other => panic!("expected an abort: {other:?}"),
    }
    assert_eq!(within(c.exists(&new)).await, Ok(None));

    // Each failure class at index 0.
    let none = ctx.path("/none");
    for (op, want) in [
        ("exists", Error::NodeExists),
        ("nonode", Error::NoNode),
        ("notempty", Error::NotEmpty),
    ] {
        let mut m = MultiWriter::new();
        match op {
            "exists" => drop(m.create(&a, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)),
            "nonode" => drop(m.set_data(&none, b"", Version::ANY)),
            _ => drop(m.delete(&ctx.root, Version::ANY)),
        }
        let e = within(c.multi(&m)).await.unwrap_err();
        assert!(
            matches!(&e, MultiError::Aborted { index: 0, error, .. } if *error == want),
            "{op}: {e:?}"
        );
        // `From<MultiError> for Error` gives the failing code.
        assert_eq!(Error::from(e), want);
    }

    // An empty transaction commits nothing.
    let empty = within(c.multi(&MultiWriter::new())).await.unwrap();
    assert_eq!(empty.iter().count(), 0);
    within(c.close()).await.unwrap();
}

real_test!(multi_read_is_per_op);
/// Rule: `multi_read` (op 22) gives one result per op; a failed read
/// does not abort the others.
async fn multi_read_is_per_op(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (d, secret) = (ctx.path("/d"), ctx.path("/secret"));
    within(c.create(&d, b"v", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    within(c.create(
        ctx.path("/d/x"),
        b"",
        CreateMode::Persistent,
        OPEN_ACL_UNSAFE,
    ))
    .await
    .unwrap();
    let only_bob = [Acl {
        perms: Perms::ALL,
        id: Id::digest("bob", "pw"),
    }];
    within(c.create(&secret, b"", CreateMode::Persistent, &only_bob))
        .await
        .unwrap();

    let none = ctx.path("/none");
    let mut r = MultiReader::new();
    r.get_data(&d).unwrap();
    r.get_children(&d).unwrap();
    r.get_data(&none).unwrap();
    r.get_children(&none).unwrap();
    r.get_data(&secret).unwrap();
    r.get_children(&ctx.root).unwrap();
    let out = within(c.multi_read(&r)).await.unwrap();
    assert_eq!(out.len(), 6);
    assert!(
        matches!(out.first(), Some(Ok(ReadResult::Data { data, stat })) if data == b"v" && stat.num_children == 1)
    );
    assert_eq!(
        out.get(1),
        Some(&Ok(ReadResult::Children(vec!["x".to_owned()])))
    );
    assert_eq!(out.get(2), Some(&Err(Error::NoNode)));
    assert_eq!(out.get(3), Some(&Err(Error::NoNode)));
    assert_eq!(out.get(4), Some(&Err(Error::NoAuth)));
    assert!(matches!(out.get(5), Some(Ok(ReadResult::Children(n))) if n.len() == 2));
    within(c.close()).await.unwrap();
}

// ---- consistency, identity and configuration ----

real_test!(sync_who_am_i_and_config);
/// Rule: `sync` (op 9), `who_am_i` (op 107) and `get_config` work on a
/// standalone server; `reconfig` there is refused with a server code.
async fn sync_who_am_i_and_config(ctx: Ctx) {
    let c = setup(&ctx).await;
    within(c.sync(&ctx.root)).await.unwrap();
    within(c.sync("/")).await.unwrap();
    let ids = within(c.who_am_i()).await.unwrap();
    assert!(
        ids.iter()
            .any(|i| i.auth_scheme == "ip" && i.user == "127.0.0.1"),
        "{ids:?}"
    );
    let (cfg, _) = within(c.get_config()).await.unwrap();
    assert!(cfg.servers.is_empty(), "{cfg:?}");
    let change = Reconfig::Incremental {
        joining: Vec::new(),
        leaving: vec![9],
    };
    // A standalone server has `reconfigEnabled=false`.
    assert_eq!(
        within(c.reconfig(&change, None)).await.unwrap_err(),
        Error::ReconfigDisabled
    );
    let stats = c.stats();
    assert_eq!(stats.pending, 0);
    within(c.close()).await.unwrap();
}

// ---- chroot ----

real_test!(chroot_applies_both_ways);
/// Rule: a chroot is joined on submit and stripped from every returned
/// path and event, on component boundaries only; `/zookeeper/config` is
/// never chrooted.
async fn chroot_applies_both_ways(ctx: Ctx) {
    let root = setup(&ctx).await;
    // The connect-string suffix, then the builder override.
    let chrooted = format!("{}{}", ctx.cs, ctx.root);
    let c = within(ctx.rt.apply(common::builder(&chrooted)).connect())
        .await
        .unwrap();
    let d = within(ctx.builder().chroot(ctx.root.as_str()).connect())
        .await
        .unwrap();

    let (p, _) = within(c.create("/a", b"1", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert_eq!(p.as_str(), "/a");
    let (q, _) = within(c.create("/q-", b"", CreateMode::EphemeralSequential, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    assert!(q.as_str().starts_with("/q-"), "{q}");
    assert_eq!(within(root.get_data(ctx.path("/a"))).await.unwrap().0, b"1");
    assert_eq!(within(d.get_children("/")).await.unwrap().len(), 2);
    let st = within(d.exists("/")).await.unwrap().unwrap();
    assert_eq!(st.num_children, 2);
    assert_eq!(within(c.get_ephemerals_all()).await.unwrap(), vec![q]);

    // A watch event path is stripped.
    let (_, _, w) = within(d.get_data_watched("/a")).await.unwrap();
    within(root.set_data(ctx.path("/a"), b"2", None))
        .await
        .unwrap();
    assert_eq!(within(w).await.unwrap().path.as_str(), "/a");

    // Multi results are stripped.
    let mut txn = MultiWriter::new();
    let h = txn
        .create("/m", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let r = within(c.multi(&txn)).await.unwrap();
    assert_eq!(r.get(h).unwrap().path.as_str(), "/m");
    // The config node keeps its absolute path.
    let (cfg_c, _) = within(c.get_config()).await.unwrap();
    let (cfg_root, _) = within(root.get_config()).await.unwrap();
    assert_eq!(cfg_c, cfg_root);

    // The server matches an ephemeral prefix as a string, so a sibling
    // whose name starts with the chroot matches too. The client keeps
    // only paths inside the chroot. One session owns an ephemeral on
    // each side; a chrooted client resumes it.
    let sib = format!("{}x", ctx.root);
    within(root.create(&sib, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let owner = ctx.connect().await;
    for e in [format!("{sib}/e"), ctx.path("/o")] {
        within(owner.create(e, b"", CreateMode::Ephemeral, OPEN_ACL_UNSAFE))
            .await
            .unwrap();
    }
    let all = within(owner.get_ephemerals(&ctx.root)).await.unwrap();
    assert_eq!(all.len(), 2, "{all:?}");
    let (id, pw) = owner.detach();
    let e = within(
        ctx.rt
            .apply(common::builder(&chrooted))
            .session(id, pw)
            .connect(),
    )
    .await
    .unwrap();
    let mine = within(e.get_ephemerals_all()).await.unwrap();
    assert_eq!(
        mine.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        vec!["/o"]
    );

    // A chroot that does not exist gives NoNode for a create below it.
    let gone = within(ctx.builder().chroot(ctx.path("/none")).connect())
        .await
        .unwrap();
    let f = gone.create("/a", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE);
    assert_eq!(within(f).await.unwrap_err(), Error::NoNode);
    for cl in [c, d, e, gone, root] {
        within(cl.close()).await.unwrap();
    }
}

// ---- call order ----

real_test!(call_order_is_wire_order);
/// Rule: requests are submitted at call time, so call order is xid and
/// wire order, and futures become ready in that order, whatever the
/// await order (spec "Eager Request Submission").
async fn call_order_is_wire_order(ctx: Ctx) {
    let c = setup(&ctx).await;
    let n = ctx.path("/n");
    // Interleaved calls, none awaited yet.
    let create = c.create(&n, b"0", CreateMode::Persistent, OPEN_ACL_UNSAFE);
    let set1 = c.set_data(&n, b"1", Version::new(0));
    let seq: Vec<_> = (0..5)
        .map(|_| {
            c.create(
                ctx.path("/s-"),
                b"",
                CreateMode::PersistentSequential,
                OPEN_ACL_UNSAFE,
            )
        })
        .collect();
    let set2 = c.set_data(&n, b"2", Version::new(1));
    let read = c.get_data(&n);

    // Await the last call first. Every earlier future is then ready.
    let (data, st_read) = within(read).await.unwrap();
    assert_eq!(
        (data.as_slice(), st_read.version),
        (&b"2"[..], Version::new(2))
    );
    assert!(create.is_ready() && set1.is_ready() && set2.is_ready());
    assert!(seq.iter().all(apache_zookeeper::ResponseFuture::is_ready));

    let st2 = within(set2).await.unwrap();
    let mut names = Vec::new();
    for f in seq.into_iter().rev() {
        names.push(within(f).await.unwrap().0.into_string());
    }
    names.reverse();
    let st1 = within(set1).await.unwrap();
    let (_, st0) = within(create).await.unwrap();
    // Zxids grow in call order.
    assert!(
        st0.czxid < st1.mzxid && st1.mzxid < st2.mzxid,
        "{st0:?} {st1:?} {st2:?}"
    );
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "sequence numbers follow the call order");

    // Clones share the order: a call on a clone after a call on the
    // original goes out later.
    let c2 = c.clone();
    let a = c.set_data(&n, b"a", Version::new(2));
    let b = c2.set_data(&n, b"b", Version::new(3));
    assert_eq!(within(b).await.unwrap().version, Version::new(4));
    assert_eq!(within(a).await.unwrap().version, Version::new(3));
    within(c.close()).await.unwrap();
}

// ---- blocking waits ----

// The client sees a tokio runtime only with its `tokio` feature.
#[cfg(all(feature = "blocking", unix, feature = "tokio"))]
real_test!(waits_in_a_tokio_worker_follow_the_driver);
/// Rule: a blocking wait in a tokio runtime thread fails at once with
/// `InvalidState` when the tokio driver runs the client, because the
/// wait can stall the driver task. The request still went out at call
/// time. A client of the thread driver gives the normal result, because
/// the wait cannot stop its driver (spec "Execution Runtimes").
#[cfg(all(feature = "blocking", unix, feature = "tokio"))]
async fn waits_in_a_tokio_worker_follow_the_driver(ctx: Ctx) {
    let c = setup(&ctx).await;
    let n = ctx.path("/n");
    // The blocking facade always uses the thread driver.
    let bc = apache_zookeeper::blocking::Client::connect(ctx.builder()).unwrap();
    assert!(bc.exists(&ctx.root).unwrap().is_some());
    assert_eq!(bc.as_async().close().wait(), Ok(()));
    if ctx.rt == Rt::Thread {
        thread_driver_waits(&ctx, c, &n);
    } else {
        tokio_driver_waits_are_refused(&ctx, c, &n).await;
    }
}

/// The waits of a thread-driver client in a tokio worker.
#[cfg(all(feature = "blocking", unix, feature = "tokio"))]
fn thread_driver_waits(ctx: &Ctx, c: apache_zookeeper::Client, n: &str) {
    use apache_zookeeper::AddWatchMode;
    c.create(n, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .wait()
        .unwrap();
    assert!(matches!(
        c.exists(n).wait_timeout(std::time::Duration::from_secs(5)),
        Ok(Ok(Some(_)))
    ));
    let (_, _, w) = c.get_data_watched(n).wait().unwrap();
    let mut pw = c.add_watch(n, AddWatchMode::Persistent).wait().unwrap();
    c.set_data(n, b"x", None).wait().unwrap();
    assert!(w.wait().is_ok());
    assert!(pw.recv().unwrap().is_ok());
    let other = ctx.builder().connect().wait().unwrap();
    assert_eq!(other.close().wait(), Ok(()));
    let mut sw = c.state_watcher();
    assert_eq!(c.close().wait(), Ok(()));
    assert_eq!(sw.wait_changed().unwrap().state, SessionState::Closed);
}

/// The waits of a tokio-driver client in a worker of its runtime.
#[cfg(all(feature = "blocking", unix, feature = "tokio"))]
async fn tokio_driver_waits_are_refused(ctx: &Ctx, c: apache_zookeeper::Client, n: &str) {
    use apache_zookeeper::{AddWatchMode, WatchError};
    let f = c.create(n, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE);
    assert_eq!(f.wait(), Err(Error::InvalidState));
    // The create was sent before the refused wait.
    within(c.sync(n)).await.unwrap();
    assert!(within(c.exists(n)).await.unwrap().is_some());
    assert!(matches!(
        c.exists(n).wait_timeout(std::time::Duration::from_secs(1)),
        Ok(Err(Error::InvalidState))
    ));

    let (_, _, w) = within(c.get_data_watched(n)).await.unwrap();
    assert_eq!(w.wait(), Err(WatchError::InvalidState));
    let mut pw = within(c.add_watch(n, AddWatchMode::Persistent))
        .await
        .unwrap();
    assert_eq!(pw.recv(), Some(Err(WatchError::InvalidState)));
    // `InvalidState` is not terminal: the watcher still works.
    within(c.set_data(n, b"x", None)).await.unwrap();
    assert!(within(pw.next()).await.unwrap().is_ok());
    assert_eq!(
        c.state_watcher().wait_changed().unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(
        ctx.builder().connect().wait().unwrap_err().error(),
        &Error::InvalidState
    );
    assert_eq!(c.close().wait(), Err(Error::InvalidState));
    // The refused close wait still closed the client.
    assert_eq!(within(c.close()).await, Ok(()));
    assert_eq!(c.state().state, SessionState::Closed);
}

/// Rule: outside any runtime, `wait` blocks for the result and
/// `wait_timeout` gives the future back unchanged after the timeout.
#[cfg(feature = "blocking")]
#[test]
#[ignore = "real-server"]
fn waits_on_a_plain_thread() {
    use std::time::Duration;
    let Some(guard) = SERVER.acquire() else {
        return;
    };
    let c = common::builder(&guard.connect_string())
        .connect()
        .wait()
        .unwrap();
    c.create("/wait-plain", b"v", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .wait()
        .unwrap();
    let r = c
        .get_data("/wait-plain")
        .wait_timeout(WAIT_LONG)
        .ok()
        .unwrap();
    assert_eq!(r.unwrap().0, b"v");

    // A server that accepts and never answers keeps a request pending.
    let hole = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let held = common::builder(&hole.local_addr().unwrap().to_string())
        .session_timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let f = held.exists("/");
    let f = f.wait_timeout(Duration::from_millis(200)).unwrap_err();
    assert!(!f.is_ready());
    // The receive deadline (2/3 of the session timeout) ends the attempt,
    // and the queued request fails with ConnectionLoss.
    assert_eq!(f.wait(), Err(Error::ConnectionLoss));
    // With no connection, the close sends nothing. Its result can be a
    // connection-loss error, so only the state is checked.
    let _ = held.close().wait();
    assert_eq!(held.state().state, SessionState::Closed);
    c.delete("/wait-plain", None).wait().unwrap();
    assert_eq!(c.close().wait(), Ok(()));
}

/// The budget of a plain-thread wait.
#[cfg(feature = "blocking")]
const WAIT_LONG: std::time::Duration = common::WAIT;

/// Rule: for a client of the tokio driver, the refusal covers every
/// thread with a tokio runtime context. Tokio has no public test that
/// tells a worker from a `spawn_blocking` thread, so a wait there is
/// refused too. A plain thread started from a worker can wait. A client
/// of the thread driver can wait in `spawn_blocking` (spec "Execution
/// Runtimes"). The spec names only worker threads.
#[cfg(all(feature = "blocking", unix, feature = "tokio"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-server"]
async fn waits_off_the_workers() {
    let Some(ctx) = Ctx::new(&SERVER, "waits_off_the_workers", Rt::Tokio) else {
        return;
    };
    let c = setup(&ctx).await;
    let c1 = c.clone();
    let root = ctx.root.clone();
    let r = tokio::task::spawn_blocking(move || c1.exists(&root).wait())
        .await
        .unwrap();
    assert_eq!(r, Err(Error::InvalidState));
    let c2 = c.clone();
    let root = ctx.root.clone();
    let r = std::thread::spawn(move || c2.exists(&root).wait())
        .join()
        .unwrap();
    assert!(r.unwrap().is_some());
    within(c.close()).await.unwrap();

    let t = within(
        ctx.builder()
            .runtime(apache_zookeeper::Runtime::Thread(
                apache_zookeeper::ThreadOptions::default(),
            ))
            .connect(),
    )
    .await
    .unwrap();
    let t1 = t.clone();
    let root = ctx.root.clone();
    let r = tokio::task::spawn_blocking(move || t1.exists(&root).wait())
        .await
        .unwrap();
    assert!(r.unwrap().is_some());
    within(t.close()).await.unwrap();
}
