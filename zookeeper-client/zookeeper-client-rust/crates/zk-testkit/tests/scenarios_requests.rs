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

//! Request and reply scenarios for every operation shape.

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

use common::{Profile, connected};
use zk_jute::multi::MultiBody;
use zk_jute::rc;
use zk_proto::{InputDefect, Reply, Route, Stage};
use zk_testkit::server::InboundKind;

fn text(s: &zk_jute::JString) -> String {
    String::from_utf8(s.as_bytes().unwrap().to_vec()).unwrap()
}

// Each create form gives its reply shape: create gives Path, create2 gives
// PathStat, and a sequential create gets a ten-digit suffix.
#[test]
fn create_forms_give_their_reply_shapes() {
    for p in Profile::ALL {
        let mut h = connected(p, 21);
        let ops = h.ops();
        let r = h.call(ops.create("/a", b"x", 0)).unwrap();
        assert_eq!(r.rc, rc::ZOK);
        assert!(
            matches!(&r.reply, Some(Reply::Path(s)) if text(s) == "/a"),
            "{p:?}"
        );
        let r = h.call(ops.create2("/b", b"y", 0)).unwrap();
        match &r.reply {
            Some(Reply::PathStat(s, st)) => {
                assert_eq!(text(s), "/b");
                assert_eq!(st.data_length, 1);
            }
            other => panic!("{p:?}: {other:?}"),
        }
        let r = h.call(ops.create("/s-", b"", 2)).unwrap();
        match &r.reply {
            Some(Reply::Path(s)) => {
                let s = text(s);
                assert_eq!(s.len(), "/s-".len() + 10, "{s}");
                assert!(s["/s-".len()..].bytes().all(|b| b.is_ascii_digit()));
            }
            other => panic!("{p:?}: {other:?}"),
        }
        let r = h.call(ops.create("/a", b"x", 0)).unwrap();
        assert_eq!(r.rc, rc::ZNODEEXISTS);
        assert!(r.reply.is_none());
        h.expect_exactly_once().unwrap();
    }
}

// exists, getData, setData, getChildren, getChildren2, getACL, setACL, sync
// and delete give Stat, Data, Stat, Children, Children2, Acl, Void, Path
// and Void.
#[test]
fn read_and_write_ops_give_their_reply_shapes() {
    for p in Profile::ALL {
        let mut h = connected(p, 22);
        let ops = h.ops();
        h.call(ops.create("/n", b"v0", 0)).unwrap();
        h.call(ops.create("/n/c1", b"", 0)).unwrap();
        h.call(ops.create("/n/c2", b"", 0)).unwrap();

        let r = h.call(ops.exists("/n", None)).unwrap();
        assert!(
            matches!(&r.reply, Some(Reply::Stat(st)) if st.num_children == 2),
            "{p:?}"
        );
        let r = h.call(ops.exists("/none", None)).unwrap();
        assert_eq!(r.rc, rc::ZNONODE);

        let r = h.call(ops.get_data("/n", None)).unwrap();
        match &r.reply {
            Some(Reply::Data { data, stat }) => {
                assert_eq!(data.as_bytes(), Some(&b"v0"[..]));
                assert_eq!(stat.version, 0);
            }
            other => panic!("{p:?}: {other:?}"),
        }
        let r = h.call(ops.set_data("/n", b"v1", 0)).unwrap();
        assert!(
            matches!(&r.reply, Some(Reply::Stat(st)) if st.version == 1),
            "{p:?}"
        );
        let r = h.call(ops.set_data("/n", b"v2", 0)).unwrap();
        assert_eq!(r.rc, rc::ZBADVERSION);

        let r = h.call(ops.get_children("/n", None)).unwrap();
        match &r.reply {
            Some(Reply::Children(v)) => {
                let mut names: Vec<String> = v.iter().map(text).collect();
                names.sort();
                assert_eq!(names, vec!["c1", "c2"]);
            }
            other => panic!("{p:?}: {other:?}"),
        }
        let r = h.call(ops.get_children2("/n", None)).unwrap();
        assert!(
            matches!(&r.reply, Some(Reply::Children2(v, st)) if v.len() == 2 && st.num_children == 2),
            "{p:?}"
        );

        let r = h.call(ops.get_acl("/n")).unwrap();
        assert!(
            matches!(&r.reply, Some(Reply::Acl(a, _)) if a.len() == 1),
            "{p:?}"
        );
        let acl = zk_testkit::Ops::open_acl().iter().cloned().collect();
        let r = h.call(ops.set_acl("/n", acl, 0)).unwrap();
        // C zoo_aset_acl takes a void completion, so the reply is Void.
        assert!(matches!(r.reply, Some(Reply::Void)), "{p:?}");
        let r = h.call(ops.get_acl("/n")).unwrap();
        assert!(
            matches!(&r.reply, Some(Reply::Acl(_, st)) if st.aversion == 1),
            "{p:?}"
        );

        let r = h.call(ops.sync("/n")).unwrap();
        assert!(
            matches!(&r.reply, Some(Reply::Path(s)) if text(s) == "/n"),
            "{p:?}"
        );

        let r = h.call(ops.delete("/n", -1)).unwrap();
        assert_eq!(r.rc, rc::ZNOTEMPTY);
        h.call(ops.delete("/n/c1", -1)).unwrap();
        h.call(ops.delete("/n/c2", -1)).unwrap();
        let r = h.call(ops.delete("/n", -1)).unwrap();
        assert_eq!(r.rc, rc::ZOK);
        assert!(matches!(r.reply, Some(Reply::Void)), "{p:?}");
        h.expect_exactly_once().unwrap();
    }
}

// Source: zk-jute multi decoding. A good multi gives one result per op with
// err 0. A failed check fails the whole transaction with its code and
// changes nothing.
#[test]
fn multi_commits_or_fails_as_one() {
    for p in Profile::ALL {
        let mut h = connected(p, 23);
        let ops = h.ops();
        h.call(ops.create("/m", b"", 0)).unwrap();
        let r = h
            .call(ops.multi(vec![
                ops.m_create("/m/a", b"1", 0),
                ops.m_set_data("/m", b"2", 0),
                ops.m_check("/m", 1),
                ops.m_delete("/m/a", 0),
            ]))
            .unwrap();
        assert_eq!(r.rc, rc::ZOK, "{p:?}");
        match &r.reply {
            Some(Reply::Multi(items)) => {
                assert_eq!(items.len(), 4);
                assert!(items.iter().all(|i| i.err == rc::ZOK));
                assert!(matches!(items[0].body, MultiBody::Create(_)));
                assert!(matches!(items[1].body, MultiBody::SetData(_)));
            }
            other => panic!("{p:?}: {other:?}"),
        }
        let r = h
            .call(ops.multi(vec![ops.m_create("/m/b", b"", 0), ops.m_check("/m", 7)]))
            .unwrap();
        assert_eq!(r.rc, rc::ZBADVERSION, "{p:?}");
        // C cleanup_failed_multi gives an async multi no results.
        assert!(r.reply.is_none(), "{p:?}");
        let r = h.call(ops.exists("/m/b", None)).unwrap();
        assert_eq!(r.rc, rc::ZNONODE, "the failed multi changed the tree");
        h.expect_exactly_once().unwrap();
    }
}

// Source: C process_sync_completion. A sync (Direct) multi decodes the
// results of a failed transaction, so each op gets its own code.
#[test]
fn direct_failed_multi_keeps_the_results() {
    let mut h = connected(Profile::Mt, 27);
    let ops = h.ops();
    h.call(ops.create("/m", b"", 0)).unwrap();
    let t = h
        .submit_with(
            ops.multi(vec![ops.m_create("/m/b", b"", 0), ops.m_check("/m", 7)]),
            Route::Direct,
            InputDefect::default(),
        )
        .unwrap();
    let r = h.wait_for(t).unwrap();
    assert_eq!(r.rc, rc::ZBADVERSION);
    match &r.reply {
        Some(Reply::Multi(items)) => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[1].err, rc::ZBADVERSION);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(h.recorder().completion_route(t), Some(Route::Direct));
    h.expect_exactly_once().unwrap();
}

// Source: spec "Compatibility policies", "Protocol Operations". The
// native profile sends multi-read, getEphemerals, getAllChildrenNumber
// and whoAmI and decodes their replies.
#[test]
fn native_only_ops_work_under_native() {
    let mut h = connected(Profile::Native, 24);
    let ops = h.ops();
    h.call(ops.create("/q", b"d", 0)).unwrap();
    h.call(ops.create("/q/k", b"", 1)).unwrap();
    let r = h
        .call(ops.multi_read(vec![
            ops.m_get_data("/q"),
            ops.m_get_children("/q"),
            ops.m_get_data("/none"),
        ]))
        .unwrap();
    assert_eq!(r.rc, rc::ZOK);
    match &r.reply {
        Some(Reply::MultiRead(items)) => {
            assert_eq!(items.len(), 3);
            assert!(
                matches!(&items[0].body, MultiBody::GetData(g) if g.data.as_bytes() == Some(&b"d"[..]))
            );
            assert!(matches!(&items[1].body, MultiBody::GetChildren(g) if g.children.len() == 1));
            assert_eq!(items[2].err, rc::ZNONODE);
        }
        other => panic!("{other:?}"),
    }
    let r = h.call(ops.get_ephemerals("/q")).unwrap();
    assert!(
        matches!(&r.reply, Some(Reply::Ephemerals(v)) if v.iter().map(text).collect::<Vec<_>>() == ["/q/k"]),
        "{:?}",
        r.reply
    );
    let r = h.call(ops.get_all_children_number("/q")).unwrap();
    assert!(
        matches!(r.reply, Some(Reply::ChildrenCount(1))),
        "{:?}",
        r.reply
    );
    let r = h.call(ops.who_am_i()).unwrap();
    assert_eq!(r.rc, rc::ZOK);
    assert!(matches!(r.reply, Some(Reply::WhoAmI(_))), "{:?}", r.reply);
    h.expect_exactly_once().unwrap();
}

// Source: spec "Compatibility policies", "Protocol Operations"; submit
// contract. The C profile refuses the native-only ops at once with
// Stage::NotEnabled and ZUNIMPLEMENTED. Nothing reaches the wire.
#[test]
fn native_only_ops_are_refused_under_legacy() {
    for p in Profile::LEGACY {
        let mut h = connected(p, 25);
        let ops = h.ops();
        let before = h.server().inbound().len();
        for op in [
            ops.multi_read(vec![ops.m_get_data("/")]),
            ops.get_ephemerals("/"),
            ops.get_all_children_number("/"),
            ops.who_am_i(),
            ops.add_watch("/", 0, zk_testkit::WatcherId::new(1, 1)),
        ] {
            let e = h.submit(op).unwrap_err();
            assert_eq!(e.stage, Stage::NotEnabled, "{p:?}");
            assert_eq!(e.code, rc::ZUNIMPLEMENTED, "{p:?}");
        }
        h.run_for(100).unwrap();
        assert_eq!(h.server().inbound().len(), before);
        h.expect_exactly_once().unwrap();
    }
}

// The wire order is the FIFO order. Xids rise from the seed by one per
// request, and the replies complete in submit order.
#[test]
fn xids_rise_and_completions_keep_submit_order() {
    for p in Profile::ALL {
        let mut h = connected(p, 26);
        let ops = h.ops();
        let tickets: Vec<_> = (0..20)
            .map(|i| h.submit(ops.create(&format!("/x{i}"), b"", 0)).unwrap())
            .collect();
        for t in &tickets {
            h.wait_for(*t).unwrap();
        }
        let xids: Vec<i32> = h
            .server()
            .inbound()
            .iter()
            .filter_map(|f| match &f.kind {
                InboundKind::Request { xid, op, .. } if *op == zk_jute::opcode::CREATE => {
                    Some(*xid)
                }
                _ => None,
            })
            .collect();
        assert_eq!(xids.len(), 20);
        assert!(xids.windows(2).all(|w| w[1] == w[0] + 1), "{p:?}: {xids:?}");
        assert_eq!(h.recorder().completion_order(), tickets, "{p:?}");
        h.expect_exactly_once().unwrap();
    }
}
