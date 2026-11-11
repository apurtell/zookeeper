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

//! Parity with the C suite `TestMulti.cc` (`Zookeeper_multi`).
//!
//! Each C case runs a transaction on a real standalone server. Each
//! test here runs the same transaction through `Client::multi`, once
//! with the IO thread and once with a tokio task. The C paths such as
//! `/multi1` move under the root node of the test, so the tests can
//! share one server.
//!
//! All tests of this file share one server at port offset 0. They
//! have `#[ignore = "real-server"]`. Run them with
//! `ZK_TEST_PORT_BASE=<base> cargo test --test c_multi -- --ignored`.

// A scenario is one long async body. It runs on a 2 MiB test or worker
// thread, so the stack frame limit of the library does not apply.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::large_stack_frames
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{Client, CreateMode, Error, MultiError, MultiWriter, SessionState, Version};
use common::{Ctx, Rt, SharedServer, setup, within};

/// The server of this file.
static SERVER: SharedServer = SharedServer::new(0);

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

/// Runs `txn` and gives the abort, or fails when the transaction
/// commits or fails as a whole.
async fn abort_of(c: &Client, txn: &MultiWriter<'_>) -> (usize, Error, Vec<Option<Error>>) {
    match within(c.multi(txn)).await {
        Err(MultiError::Aborted {
            index,
            error,
            per_op,
        }) => (index, error, per_op),
        other => panic!("expected an abort: {other:?}"),
    }
}

real_test!(create);
/// `Zookeeper_multi::testCreate`: three creates in one transaction
/// commit, and each result gives the created path.
async fn create(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (p1, p2, p3) = (
        ctx.path("/multi1"),
        ctx.path("/multi1/a"),
        ctx.path("/multi1/b"),
    );
    let mut txn = MultiWriter::new();
    let h1 = txn
        .create(&p1, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let h2 = txn
        .create(&p2, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let h3 = txn
        .create(&p3, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let r = within(c.multi(&txn)).await.unwrap();
    assert_eq!(r.iter().count(), 3);
    assert_eq!(r.get(h1).unwrap().path.as_str(), p1);
    assert_eq!(r.get(h2).unwrap().path.as_str(), p2);
    assert_eq!(r.get(h3).unwrap().path.as_str(), p3);
    within(c.close()).await.unwrap();
}

real_test!(create_delete);
/// `Zookeeper_multi::testCreateDelete`: a create and a delete of the
/// same node commit, and the node does not exist after it.
async fn create_delete(ctx: Ctx) {
    let c = setup(&ctx).await;
    let p = ctx.path("/multi2");
    let mut txn = MultiWriter::new();
    txn.create(&p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    txn.delete(&p, Version::new(0)).unwrap();
    within(c.multi(&txn)).await.unwrap();
    assert_eq!(within(c.exists(&p)).await, Ok(None));
    within(c.close()).await.unwrap();
}

real_test!(invalid_version);
/// `Zookeeper_multi::testInvalidVersion`: a delete with a wrong version
/// aborts the transaction with `BadVersion`. The op before it reports
/// success and the ops after it report `RuntimeInconsistency`.
async fn invalid_version(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (p, child) = (ctx.path("/multi3"), ctx.path("/multi3/a"));
    let mut txn = MultiWriter::new();
    txn.create(&p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    txn.delete(&p, Version::new(1)).unwrap();
    txn.create(&p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    txn.create(&child, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let (index, error, per_op) = abort_of(&c, &txn).await;
    assert_eq!((index, error), (1, Error::BadVersion));
    assert_eq!(
        per_op,
        vec![
            None,
            Some(Error::BadVersion),
            Some(Error::RuntimeInconsistency),
            Some(Error::RuntimeInconsistency)
        ]
    );
    assert_eq!(within(c.exists(&p)).await, Ok(None));
    within(c.close()).await.unwrap();
}

real_test!(nested_create);
/// `Zookeeper_multi::testNestedCreate`: later ops see the nodes of
/// earlier ops. A tree of three nodes is created and deleted in one
/// transaction, and no node remains.
async fn nested_create(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (a, b, d) = (
        ctx.path("/multi4"),
        ctx.path("/multi4/a"),
        ctx.path("/multi4/a/1"),
    );
    let mut txn = MultiWriter::new();
    for p in [&a, &b, &d] {
        txn.create(p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap();
    }
    for p in [&d, &b, &a] {
        txn.delete(p, Version::new(0)).unwrap();
    }
    let r = within(c.multi(&txn)).await.unwrap();
    assert_eq!(r.iter().count(), 6);
    for p in [&d, &b, &a] {
        assert_eq!(within(c.exists(p)).await, Ok(None), "{p}");
    }
    within(c.close()).await.unwrap();
}

real_test!(set_data);
/// `Zookeeper_multi::testSetData`: a transaction of two creates
/// commits. A second transaction sets the data of both nodes at
/// version 0, and a read gives the new data.
async fn set_data(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (a, b) = (ctx.path("/multi5"), ctx.path("/multi5/a"));
    let mut txn = MultiWriter::new();
    txn.create(&a, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    txn.create(&b, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    within(c.multi(&txn)).await.unwrap();

    let mut sets = MultiWriter::new();
    let ha = sets.set_data(&a, b"1", Version::new(0)).unwrap();
    let hb = sets.set_data(&b, b"2", Version::new(0)).unwrap();
    let r = within(c.multi(&sets)).await.unwrap();
    assert_eq!(r.get(ha).unwrap().version, Version::new(1));
    assert_eq!(r.get(hb).unwrap().version, Version::new(1));
    assert_eq!(within(c.get_data(&a)).await.unwrap().0, b"1");
    assert_eq!(within(c.get_data(&b)).await.unwrap().0, b"2");
    within(c.close()).await.unwrap();
}

real_test!(update_conflict);
/// `Zookeeper_multi::testUpdateConflict`: two sets at version 0 in one
/// transaction conflict, so it aborts with `BadVersion`. With version 1
/// on the second set, the transaction commits in order and the last
/// data stays.
async fn update_conflict(ctx: Ctx) {
    let c = setup(&ctx).await;
    let p = ctx.path("/multi6");
    let build = |second: Version| {
        let mut txn = MultiWriter::new();
        txn.create(&p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap();
        txn.set_data(&p, b"X", Version::new(0)).unwrap();
        txn.set_data(&p, b"Y", second).unwrap();
        txn
    };
    let (index, error, _) = abort_of(&c, &build(Version::new(0))).await;
    assert_eq!((index, error), (2, Error::BadVersion));
    assert_eq!(within(c.exists(&p)).await, Ok(None));

    // The order of the ops matters.
    within(c.multi(&build(Version::new(1)))).await.unwrap();
    let (data, st) = within(c.get_data(&p)).await.unwrap();
    assert_eq!((data.as_slice(), st.version), (&b"Y"[..], Version::new(2)));
    within(c.close()).await.unwrap();
}

real_test!(delete_update_conflict);
/// `Zookeeper_multi::testDeleteUpdateConflict`: a set after a delete of
/// the same node aborts with `NoNode`, and the node of the first op is
/// never created.
async fn delete_update_conflict(ctx: Ctx) {
    let c = setup(&ctx).await;
    let p = ctx.path("/multi7");
    let mut txn = MultiWriter::new();
    txn.create(&p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    txn.delete(&p, Version::new(0)).unwrap();
    txn.set_data(&p, b"Y", Version::new(0)).unwrap();
    let (index, error, per_op) = abort_of(&c, &txn).await;
    assert_eq!((index, error), (2, Error::NoNode));
    assert_eq!(per_op, vec![None, None, Some(Error::NoNode)]);
    assert_eq!(within(c.exists(&p)).await, Ok(None));
    within(c.close()).await.unwrap();
}

real_test!(async_multi);
/// `Zookeeper_multi::testAsyncMulti`: the asynchronous form
/// (`zoo_amulti`) of `testCreate`. The client sends the transaction,
/// does other work, and takes the result later.
async fn async_multi(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (p1, p2, p3) = (
        ctx.path("/multi8"),
        ctx.path("/multi8/a"),
        ctx.path("/multi8/b"),
    );
    let mut txn = MultiWriter::new();
    let hs = [&p1, &p2, &p3].map(|p| {
        txn.create(p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap()
    });
    // The client sends the request when the call returns. A read sent
    // after it completes after it, because the server keeps the order.
    let pending = c.multi(&txn);
    let after = within(c.exists(&p3)).await.unwrap();
    assert!(after.is_some());
    let r = within(pending).await.unwrap();
    for (h, p) in hs.into_iter().zip([&p1, &p2, &p3]) {
        assert_eq!(r.get(h).unwrap().path.as_str(), p.as_str());
    }
    within(c.close()).await.unwrap();
}

real_test!(multi_fail);
/// `Zookeeper_multi::testMultiFail`: a second create of the same path
/// aborts the transaction with `NodeExists`.
async fn multi_fail(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (p, child) = (ctx.path("/multi9"), ctx.path("/multi9/b"));
    let mut txn = MultiWriter::new();
    for q in [&p, &p, &child] {
        txn.create(q, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap();
    }
    let (index, error, _) = abort_of(&c, &txn).await;
    assert_eq!((index, error), (1, Error::NodeExists));
    assert_eq!(within(c.exists(&p)).await, Ok(None));
    within(c.close()).await.unwrap();
}

real_test!(check);
/// `Zookeeper_multi::testCheck`: a version check guards a create. The
/// right version commits the create. A wrong version aborts with
/// `BadVersion`, the create reports `RuntimeInconsistency`, and its
/// node does not exist.
async fn check(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (p, a, b) = (
        ctx.path("/multi0"),
        ctx.path("/multi0/a"),
        ctx.path("/multi0/b"),
    );
    within(c.create(&p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();

    let mut ok = MultiWriter::new();
    let hc = ok.check(&p, Version::new(0)).unwrap();
    ok.create(&a, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let r = within(c.multi(&ok)).await.unwrap();
    assert_eq!(r.get(hc), Some(&()));
    assert!(within(c.exists(&a)).await.unwrap().is_some());

    let mut bad = MultiWriter::new();
    bad.check(&p, Version::new(10)).unwrap();
    bad.create(&b, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let (index, error, per_op) = abort_of(&c, &bad).await;
    assert_eq!((index, error), (0, Error::BadVersion));
    assert_eq!(
        per_op,
        vec![Some(Error::BadVersion), Some(Error::RuntimeInconsistency)]
    );
    assert_eq!(within(c.exists(&b)).await, Ok(None));
    within(c.close()).await.unwrap();
}

real_test!(watch);
/// `Zookeeper_multi::testWatch`: a data watch fires on a set. The code
/// that takes the event then runs a transaction and a read on the same
/// client, and both complete.
async fn watch(ctx: Ctx) {
    let c = setup(&ctx).await;
    let p = ctx.path("/multiwatch");
    within(c.create(&p, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    let (_, _, w) = within(c.get_data_watched(&p)).await.unwrap();

    // The task stands for the C watcher callback.
    let (c2, p2) = (c.clone(), p.clone());
    let task = tokio::spawn(async move {
        let ev = w.await.unwrap();
        assert_eq!(ev.path.as_str(), p2);
        let mut txn = MultiWriter::new();
        txn.set_data(&p2, b"1", Version::ANY).unwrap();
        let r = c2.multi(&txn).await.unwrap();
        assert_eq!(r.iter().count(), 1);
        let (data, _) = c2.get_data(&p2).await.unwrap();
        assert_eq!(data, b"1");
    });

    within(c.set_data(&p, b"", Version::ANY)).await.unwrap();
    within(task).await.unwrap();
    within(c.close()).await.unwrap();
}

real_test!(big_async_multi);
/// `Zookeeper_multi::testBigAsyncMulti` (ZOOKEEPER-1636): a transaction
/// above the 1 MiB `jute.maxbuffer` of the server makes the server
/// close the connection without a reply. The transaction fails with
/// `ConnectionLoss`. The client then reconnects, and a new request
/// completes.
async fn big_async_multi(ctx: Ctx) {
    let c = setup(&ctx).await;
    let x = ctx.path("/x");
    let buff = vec![0_u8; 1024];
    let mut txn = MultiWriter::new();
    for _ in 0..500 {
        txn.set_data(&x, &buff, Version::ANY).unwrap();
        txn.create(&x, &buff, CreateMode::PersistentSequential, OPEN_ACL_UNSAFE)
            .unwrap();
        txn.delete(&x, Version::ANY).unwrap();
    }
    assert_eq!(txn.len(), 1500);
    let mut sw = c.state_watcher();
    assert_eq!(
        within(c.multi(&txn)).await.unwrap_err(),
        MultiError::Request(Error::ConnectionLoss)
    );

    // The handle recovers by itself.
    common::wait_state(&mut sw, common::WAIT, |i| {
        i.state == SessionState::Connected && i.epoch >= 2
    })
    .await;
    let target = ctx.path("/target");
    within(c.create(&target, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE))
        .await
        .unwrap();
    within(c.close()).await.unwrap();
}

real_test!(sequential_node_create_in_async_multi);
/// `Zookeeper_multi::testSequentialNodeCreateInAsyncMulti`
/// (ZOOKEEPER-1624): four transactions of a sequential create and a
/// create of `/dup` are in flight at once. The first commits. Each
/// later one aborts at `/dup` with `NodeExists`, and its sequential
/// create reports success. The server rolls back the sequence number
/// of each abort, so the next sequential name follows the first
/// commit.
async fn sequential_node_create_in_async_multi(ctx: Ctx) {
    let c = setup(&ctx).await;
    let (node, dup) = (ctx.path("/node-"), ctx.path("/dup"));
    let mut txn = MultiWriter::new();
    let hn = txn
        .create(
            &node,
            b"",
            CreateMode::PersistentSequential,
            OPEN_ACL_UNSAFE,
        )
        .unwrap();
    txn.create(&dup, b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
        .unwrap();
    let pending: Vec<_> = (0..4).map(|_| c.multi(&txn)).collect();
    let mut results = Vec::new();
    for f in pending {
        results.push(within(f).await);
    }
    let mut it = results.into_iter();
    let first = it.next().unwrap().unwrap();
    assert_eq!(
        first.get(hn).unwrap().path.as_str(),
        format!("{node}0000000000")
    );
    for r in it {
        match r {
            Err(MultiError::Aborted {
                index,
                error,
                per_op,
            }) => {
                assert_eq!((index, error), (1, Error::NodeExists));
                assert_eq!(per_op, vec![None, Some(Error::NodeExists)]);
            }
            other => panic!("expected an abort: {other:?}"),
        }
    }
    // The root had two children created, so the next number is 2.
    let (next, _) = within(c.create(
        &node,
        b"",
        CreateMode::PersistentSequential,
        OPEN_ACL_UNSAFE,
    ))
    .await
    .unwrap();
    assert_eq!(next.as_str(), format!("{node}0000000002"));
    within(c.close()).await.unwrap();
}
