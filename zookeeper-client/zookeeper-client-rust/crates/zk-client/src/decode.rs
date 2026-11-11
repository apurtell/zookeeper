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

//! Reply decoders: `RawResult` to public types.
//!
//! A decoder runs in `ResponseFuture::poll` or `wait`, on the task of
//! the caller. Thus the IO side stays light. Proto strips the chroot from
//! every reply path, so no decoder needs the chroot.
//!
//! Every decoder follows the same rules:
//! - An `rc` other than 0 gives `Error::from_code(rc)`.
//! - A missing reply, or a reply of the wrong variant, gives
//!   `Error::MarshallingError`. A decoder never panics.
//! - A null jute string or vector gives an empty value, except where the
//!   function says otherwise.

use zk_jute::{JString, JVec, rc};
use zk_proto::Reply;

use crate::acl::Acl;
use crate::auth::ClientInfo;
use crate::config::{self, EnsembleConfig};
use crate::error::Error;
use crate::ops;
use crate::path::ZPathBuf;
use crate::shared::{OneshotReg, PersistentReg};
use crate::tokens::RawResult;
use crate::types::Stat;
use crate::watch::{OneshotWatcher, PersistentWatcher};

/// Converts the raw result of one request into its public value.
pub(crate) type Decoder<T, E = Error> = Box<dyn FnOnce(RawResult) -> Result<T, E> + Send + Sync>;

/// Boxes a plain decoder function.
///
/// The parameter type is generic. Thus a named function stays a
/// zero-sized value, and its box makes no allocation. A `fn` pointer
/// parameter puts eight bytes on the heap for each request.
pub(crate) fn boxed<T: 'static, E: 'static, F>(f: F) -> Decoder<T, E>
where
    F: FnOnce(RawResult) -> Result<T, E> + Send + Sync + 'static,
{
    Box::new(f)
}

/// Gives the reply of a result whose `rc` is 0, or the error of the
/// `rc`. A zero `rc` with no reply gives `MarshallingError`.
pub(crate) fn reply_of(r: RawResult) -> Result<Reply, Error> {
    if r.rc != rc::ZOK {
        return Err(rc_error(r.rc));
    }
    r.reply.ok_or(Error::MarshallingError)
}

/// The error of a result code that is not 0. The check of the code
/// comes first, so the caller never gives 0 here. A code of 0 still gives
/// `MarshallingError`, because a result with no reply and no error is
/// malformed.
pub(crate) fn rc_error(code: i32) -> Error {
    Error::from_code(code).unwrap_or(Error::MarshallingError)
}

/// Converts a path that the server sent. A null or empty path is not a
/// valid path, so it gives `MarshallingError`, as bytes that are not
/// UTF-8 do.
pub(crate) fn server_path(p: JString) -> Result<ZPathBuf, Error> {
    match p.into_bytes() {
        Some(b) if !b.is_empty() => ZPathBuf::from_server(b),
        _ => Err(Error::MarshallingError),
    }
}

/// Converts a list of child names. A null list or a null name gives an
/// empty value. A name that is not UTF-8 makes the reply malformed,
/// because a lossy name does not address the node.
pub(crate) fn names(v: JVec<JString>) -> Result<Vec<String>, Error> {
    v.into_vec()
        .unwrap_or_default()
        .into_iter()
        .map(|n| String::from_utf8(n.into_bytes().unwrap_or_default()))
        .collect::<Result<Vec<String>, _>>()
        .map_err(|_| Error::MarshallingError)
}

/// `Reply::Void`. Delete, sync, set-watches, remove-watches, add-watch
/// and the `Local` result of a local watch removal.
///
/// A sync reply carries the synced path, and the caller does not need
/// it. Thus `Reply::Path` is also a valid reply here.
pub(crate) fn void(r: RawResult) -> Result<(), Error> {
    match reply_of(r)? {
        Reply::Void | Reply::Path(_) => Ok(()),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::PathStat` of a create2, or `Reply::Path` of a create with no
/// stat. The path is the created path with the chroot stripped.
/// `Path` gives a zero `Stat`.
pub(crate) fn create(r: RawResult) -> Result<(ZPathBuf, Stat), Error> {
    match reply_of(r)? {
        Reply::PathStat(p, s) => Ok((server_path(p)?, Stat::from_jute(&s))),
        Reply::Path(p) => Ok((server_path(p)?, Stat::default())),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Stat` of exists. `NoNode` gives `Ok(None)`.
pub(crate) fn exists(r: RawResult) -> Result<Option<Stat>, Error> {
    if r.rc == rc::ZNONODE {
        return Ok(None);
    }
    match reply_of(r)? {
        Reply::Stat(s) => Ok(Some(Stat::from_jute(&s))),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Data`. A null buffer gives an empty vector.
pub(crate) fn get_data(r: RawResult) -> Result<(Vec<u8>, Stat), Error> {
    get_data_opt(r).map(|(d, s)| (d.unwrap_or_default(), s))
}

/// `Reply::Data`. A null buffer gives `None`.
pub(crate) fn get_data_opt(r: RawResult) -> Result<(Option<Vec<u8>>, Stat), Error> {
    match reply_of(r)? {
        Reply::Data { data, stat } => Ok((data.into_bytes(), Stat::from_jute(&stat))),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Stat` of set_data and set_acl.
pub(crate) fn stat(r: RawResult) -> Result<Stat, Error> {
    match reply_of(r)? {
        Reply::Stat(s) => Ok(Stat::from_jute(&s)),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Children` or `Reply::Children2`, as names only.
pub(crate) fn children(r: RawResult) -> Result<Vec<String>, Error> {
    match reply_of(r)? {
        Reply::Children(v) | Reply::Children2(v, _) => names(v),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Children2`: the names and the stat of the parent.
pub(crate) fn children2(r: RawResult) -> Result<(Vec<String>, Stat), Error> {
    match reply_of(r)? {
        Reply::Children2(v, s) => Ok((names(v)?, Stat::from_jute(&s))),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Acl`. Each entry maps through `ops::acl_from_jute`.
pub(crate) fn acl(r: RawResult) -> Result<(Vec<Acl>, Stat), Error> {
    match reply_of(r)? {
        Reply::Acl(v, s) => Ok((ops::acl_from_jute(v), Stat::from_jute(&s))),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::ChildrenCount`. A negative count gives `MarshallingError`.
pub(crate) fn children_count(r: RawResult) -> Result<u32, Error> {
    match reply_of(r)? {
        Reply::ChildrenCount(n) => u32::try_from(n).map_err(|_| Error::MarshallingError),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Ephemerals`. Each path goes through `ZPathBuf::from_server`.
///
/// A null list gives an empty vector. A null path in the list gives
/// `MarshallingError`, because it is not a valid path.
pub(crate) fn ephemerals(r: RawResult) -> Result<Vec<ZPathBuf>, Error> {
    match reply_of(r)? {
        Reply::Ephemerals(v) => v
            .into_vec()
            .unwrap_or_default()
            .into_iter()
            .map(server_path)
            .collect(),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::WhoAmI`. Each entry maps through `ClientInfo::from_jute`.
pub(crate) fn who_am_i(r: RawResult) -> Result<Vec<ClientInfo>, Error> {
    match reply_of(r)? {
        Reply::WhoAmI(v) => Ok(v.iter().map(ClientInfo::from_jute).collect()),
        _ => Err(Error::MarshallingError),
    }
}

/// `Reply::Data` of `/zookeeper/config`, parsed by
/// `config::parse_config`. A parse error gives `MarshallingError`.
///
/// Null data parses as empty text.
pub(crate) fn config(r: RawResult) -> Result<(EnsembleConfig, Stat), Error> {
    let (data, stat) = get_data(r)?;
    let cfg = config::parse_config(&data).map_err(|_| Error::MarshallingError)?;
    Ok((cfg, stat))
}

/// Wraps a decoder of a watched read.
///
/// On `Ok` it arms the registration and joins the value with the new
/// watcher. On `Err` it drops the registration, and the drop removes the
/// sink. Thus a watcher exists only when its request succeeded. `exists`
/// gives `Ok(None)` for `NoNode`, so an exist watch arms on a missing
/// node.
pub(crate) fn with_oneshot<B, T>(
    base: fn(RawResult) -> Result<B, Error>,
    reg: OneshotReg,
    join: fn(B, OneshotWatcher) -> T,
) -> Decoder<T>
where
    B: 'static,
    T: 'static,
{
    Box::new(move |r| base(r).map(|b| join(b, reg.arm())))
}

/// Wraps the `void` decoder of `add_watch`. On `Ok` it arms the
/// registration. On `Err` it drops it.
pub(crate) fn with_persistent(reg: PersistentReg) -> Decoder<PersistentWatcher> {
    Box::new(move |r| void(r).map(|()| reg.arm()))
}

#[cfg(test)]
mod tests {
    use zk_jute::data::{ACL, Id as JId};
    use zk_jute::{JBuffer, JString, JVec};
    use zk_proto::{Origin, Reply};

    use super::*;
    use crate::acl::Perms;
    use crate::types::Version;

    fn ok(reply: Reply) -> RawResult {
        RawResult {
            rc: 0,
            zxid: 9,
            origin: Origin::Reply,
            reply: Some(reply),
        }
    }

    fn missing() -> RawResult {
        RawResult {
            rc: 0,
            zxid: 0,
            origin: Origin::Reply,
            reply: None,
        }
    }

    fn failed(rc: i32) -> RawResult {
        RawResult {
            rc,
            zxid: 0,
            origin: Origin::Reply,
            reply: None,
        }
    }

    fn jstat(version: i32) -> zk_jute::data::Stat {
        zk_jute::data::Stat {
            czxid: 1,
            mzxid: 2,
            ctime: 3,
            mtime: 4,
            version,
            cversion: 5,
            aversion: 6,
            ephemeral_owner: 7,
            data_length: 8,
            num_children: 9,
            pzxid: 10,
        }
    }

    fn jnames(names: &[&str]) -> JVec<JString> {
        JVec::Items(names.iter().map(|n| JString::from(*n)).collect())
    }

    /// A reply variant that no decoder of this module accepts as its own
    /// result, except `who_am_i`.
    fn alien() -> RawResult {
        ok(Reply::WhoAmI(JVec::Null))
    }

    /// Each decoder, as a function that drops the value.
    type Check = fn(RawResult) -> Result<(), Error>;

    fn all_decoders() -> Vec<(&'static str, Check)> {
        vec![
            ("void", void as Check),
            ("create", (|r| create(r).map(drop)) as Check),
            ("exists", (|r| exists(r).map(drop)) as Check),
            ("get_data", (|r| get_data(r).map(drop)) as Check),
            ("get_data_opt", (|r| get_data_opt(r).map(drop)) as Check),
            ("stat", (|r| stat(r).map(drop)) as Check),
            ("children", (|r| children(r).map(drop)) as Check),
            ("children2", (|r| children2(r).map(drop)) as Check),
            ("acl", (|r| acl(r).map(drop)) as Check),
            ("children_count", (|r| children_count(r).map(drop)) as Check),
            ("ephemerals", (|r| ephemerals(r).map(drop)) as Check),
            ("config", (|r| config(r).map(drop)) as Check),
        ]
    }

    #[test]
    fn missing_reply_is_marshalling_error() {
        for (name, f) in all_decoders() {
            assert_eq!(f(missing()), Err(Error::MarshallingError), "{name}");
        }
        assert_eq!(who_am_i(missing()), Err(Error::MarshallingError));
        assert_eq!(reply_of(missing()), Err(Error::MarshallingError));
    }

    #[test]
    fn wrong_variant_is_marshalling_error() {
        for (name, f) in all_decoders() {
            assert_eq!(f(alien()), Err(Error::MarshallingError), "{name}");
        }
        assert_eq!(
            who_am_i(ok(Reply::Void)),
            Err(Error::MarshallingError),
            "who_am_i"
        );
    }

    #[test]
    fn error_rc_gives_its_error() {
        for (name, f) in all_decoders() {
            assert_eq!(f(failed(rc::ZNOAUTH)), Err(Error::NoAuth), "{name}");
            // An error rc wins over a reply body.
            let mut r = ok(Reply::Void);
            r.rc = rc::ZBADVERSION;
            assert_eq!(f(r), Err(Error::BadVersion), "{name}");
        }
        assert_eq!(who_am_i(failed(rc::ZNOAUTH)), Err(Error::NoAuth));
        assert_eq!(void(failed(rc::ZNONODE)), Err(Error::NoNode));
        assert_eq!(get_data(failed(rc::ZNONODE)), Err(Error::NoNode));
        assert_eq!(
            reply_of(RawResult::teardown(rc::ZCONNECTIONLOSS)),
            Err(Error::ConnectionLoss)
        );
    }

    #[test]
    fn void_accepts_void_and_sync_path() {
        assert_eq!(void(ok(Reply::Void)), Ok(()));
        assert_eq!(void(ok(Reply::Path(JString::from("/a")))), Ok(()));
    }

    #[test]
    fn create_gives_path_and_stat() {
        let (p, s) = create(ok(Reply::PathStat(JString::from("/a0001"), jstat(0)))).unwrap();
        assert_eq!(p, "/a0001");
        assert_eq!(s, Stat::from_jute(&jstat(0)));
        let (p, s) = create(ok(Reply::Path(JString::from("/b")))).unwrap();
        assert_eq!(p, "/b");
        assert_eq!(s, Stat::default());
    }

    #[test]
    fn create_refuses_bad_paths() {
        for bad in [
            JString::Null,
            JString::from(""),
            JString::Bytes(vec![b'/', 0xff]),
        ] {
            assert_eq!(
                create(ok(Reply::PathStat(bad, jstat(0)))),
                Err(Error::MarshallingError)
            );
        }
    }

    #[test]
    fn exists_maps_no_node_to_none() {
        assert_eq!(exists(failed(rc::ZNONODE)), Ok(None));
        let s = exists(ok(Reply::Stat(jstat(4)))).unwrap().unwrap();
        assert_eq!(s.version, Version::new(4));
        assert_eq!(s.czxid.0, 1);
        assert_eq!(s.pzxid.0, 10);
    }

    #[test]
    fn get_data_keeps_or_hides_null() {
        let null = || {
            ok(Reply::Data {
                data: JBuffer::Null.into(),
                stat: jstat(1),
            })
        };
        let empty = || {
            ok(Reply::Data {
                data: JBuffer::Bytes(Vec::new()).into(),
                stat: jstat(1),
            })
        };
        assert_eq!(get_data(null()).unwrap().0, Vec::<u8>::new());
        assert_eq!(get_data(empty()).unwrap().0, Vec::<u8>::new());
        assert_eq!(get_data_opt(null()).unwrap().0, None);
        assert_eq!(get_data_opt(empty()).unwrap().0, Some(Vec::new()));
        let (d, s) = get_data(ok(Reply::Data {
            data: JBuffer::from(b"abc".to_vec()).into(),
            stat: jstat(2),
        }))
        .unwrap();
        assert_eq!(d, b"abc");
        assert_eq!(s.version, Version::new(2));
    }

    #[test]
    fn stat_decodes() {
        assert_eq!(
            stat(ok(Reply::Stat(jstat(3)))).unwrap().version,
            Version::new(3)
        );
    }

    #[test]
    fn children_accept_both_shapes() {
        assert_eq!(
            children(ok(Reply::Children(jnames(&["a", "b"])))).unwrap(),
            ["a", "b"]
        );
        assert_eq!(
            children(ok(Reply::Children2(jnames(&["c"]), jstat(0)))).unwrap(),
            ["c"]
        );
        assert!(
            children(ok(Reply::Children(JVec::Null)))
                .unwrap()
                .is_empty()
        );
        let (names, s) = children2(ok(Reply::Children2(jnames(&["x"]), jstat(1)))).unwrap();
        assert_eq!(names, ["x"]);
        assert_eq!(s.num_children, 9);
        // getChildren2 decodes only its own shape, because it needs the stat.
        assert_eq!(
            children2(ok(Reply::Children(jnames(&["x"])))),
            Err(Error::MarshallingError)
        );
    }

    #[test]
    fn children_names_must_be_utf8() {
        let v = JVec::Items(vec![JString::from("ok"), JString::Bytes(vec![0xc3])]);
        assert_eq!(
            children(ok(Reply::Children(v))),
            Err(Error::MarshallingError)
        );
        let v = JVec::Items(vec![JString::Null]);
        assert_eq!(children(ok(Reply::Children(v))).unwrap(), [""]);
    }

    #[test]
    fn acl_decodes_entries() {
        let v = JVec::Items(vec![ACL {
            perms: 0x1f,
            id: JId {
                scheme: JString::from("world"),
                id: JString::from("anyone"),
            },
        }]);
        let (list, s) = acl(ok(Reply::Acl(v, jstat(0)))).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list.first().unwrap().perms, Perms::ALL);
        assert_eq!(list.first().unwrap().id, crate::acl::Id::ANYONE);
        assert_eq!(s.aversion, Version::new(6));
        let (list, _) = acl(ok(Reply::Acl(JVec::Null, jstat(0)))).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn children_count_refuses_negative() {
        assert_eq!(children_count(ok(Reply::ChildrenCount(12))), Ok(12));
        assert_eq!(children_count(ok(Reply::ChildrenCount(0))), Ok(0));
        assert_eq!(
            children_count(ok(Reply::ChildrenCount(-1))),
            Err(Error::MarshallingError)
        );
    }

    #[test]
    fn ephemerals_decode_paths() {
        let got = ephemerals(ok(Reply::Ephemerals(jnames(&["/e1", "/a/e2"])))).unwrap();
        assert_eq!(got, ["/e1", "/a/e2"]);
        assert!(
            ephemerals(ok(Reply::Ephemerals(JVec::Null)))
                .unwrap()
                .is_empty()
        );
        let bad = JVec::Items(vec![JString::from("/e"), JString::Null]);
        assert_eq!(
            ephemerals(ok(Reply::Ephemerals(bad))),
            Err(Error::MarshallingError)
        );
    }

    #[test]
    fn who_am_i_decodes_entries() {
        let v = JVec::Items(vec![
            zk_jute::data::ClientInfo {
                auth_scheme: JString::from("ip"),
                user: JString::from("127.0.0.1"),
            },
            zk_jute::data::ClientInfo {
                auth_scheme: JString::from("digest"),
                user: JString::Null,
            },
        ]);
        let got = who_am_i(ok(Reply::WhoAmI(v))).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got.first().unwrap().auth_scheme, "ip");
        assert_eq!(got.first().unwrap().user, "127.0.0.1");
        assert_eq!(got.get(1).unwrap().user, "");
        assert!(who_am_i(ok(Reply::WhoAmI(JVec::Null))).unwrap().is_empty());
    }

    #[test]
    fn config_parses_the_data() {
        let text = "server.1=127.0.0.1:2888:3888:participant;0.0.0.0:2181\nversion=100000000\n";
        let (cfg, s) = config(ok(Reply::Data {
            data: JBuffer::from(text.as_bytes().to_vec()).into(),
            stat: jstat(1),
        }))
        .unwrap();
        assert_eq!(s.version, Version::new(1));
        assert_eq!(cfg.raw, text);
        assert_eq!(cfg.servers.len(), 1);
        let (cfg, _) = config(ok(Reply::Data {
            data: JBuffer::Null.into(),
            stat: jstat(1),
        }))
        .unwrap();
        assert!(cfg.servers.is_empty());
    }
}
