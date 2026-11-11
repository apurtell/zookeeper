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

//! Request builders: public arguments to `zk_proto::Op`.
//!
//! A builder takes a path that `path::checked` already validated, so it
//! never fails. It wraps the path as `PathIn::Native`, and proto joins
//! the chroot. Every builder is pure and runs before the core lock.

use zk_jute::data::ACL;
use zk_jute::{JBuffer, JString, JVec, opcode};
use zk_proto::{Op, PathIn, RemoveHint};

use crate::acl::{Acl, Id, Perms};
use crate::auth::lossy;
use crate::tokens::WatchId;
use crate::types::CreateMode;

/// An operation with native watcher tokens.
pub(crate) type NativeOp = Op<WatchId>;

/// Wraps a validated path for proto.
pub(crate) fn path_in(p: &str) -> PathIn {
    PathIn::Native(JString::from(p))
}

/// The wire `mode` and `ttl` of a create mode.
///
/// The Java `CreateMode` values: persistent 0, ephemeral 1, persistent
/// sequential 2, ephemeral sequential 3, container 4, persistent with
/// TTL 5, persistent sequential with TTL 6. The TTL is -1 for a mode
/// with no TTL.
pub(crate) fn create_mode_wire(mode: &CreateMode) -> (i32, i64) {
    match mode {
        CreateMode::Persistent => (0, NO_TTL),
        CreateMode::Ephemeral => (1, NO_TTL),
        CreateMode::PersistentSequential => (2, NO_TTL),
        CreateMode::EphemeralSequential => (3, NO_TTL),
        CreateMode::Container => (4, NO_TTL),
        CreateMode::PersistentWithTtl(t) => (5, ttl_wire(t.as_millis())),
        CreateMode::PersistentSequentialWithTtl(t) => (6, ttl_wire(t.as_millis())),
    }
}

/// The wire TTL of a create mode with no TTL.
const NO_TTL: i64 = -1;

/// Converts a TTL in ms to the wire value. `Ttl` keeps the value at
/// most 0xFF_FFFF_FFFF, so the conversion cannot fail. The fallback
/// value is out of range, and proto then refuses the create.
fn ttl_wire(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

/// The wire op of a create in a transaction: container 19, a TTL mode
/// 21, and create2 (15) for the other modes. A single create does not
/// use this function, because proto selects its op.
pub(crate) fn create_op_code(mode: &CreateMode) -> i32 {
    match mode {
        CreateMode::Container => opcode::CREATE_CONTAINER,
        CreateMode::PersistentWithTtl(_) | CreateMode::PersistentSequentialWithTtl(_) => {
            opcode::CREATE_TTL
        }
        _ => opcode::CREATE2,
    }
}

/// Converts public ACL entries to jute records. The list is always
/// present, never `JVec::Null`.
pub(crate) fn acl_to_jute(acl: &[Acl]) -> JVec<ACL> {
    JVec::Items(
        acl.iter()
            .map(|a| ACL {
                perms: a.perms.bits(),
                id: zk_jute::data::Id {
                    scheme: JString::from(a.id.scheme.as_ref()),
                    id: JString::from(a.id.id.as_ref()),
                },
            })
            .collect(),
    )
}

/// Converts jute ACL records to public entries. Unknown permission bits
/// are kept. Text that is not UTF-8 is converted lossily. A null list
/// gives an empty vector.
pub(crate) fn acl_from_jute(v: JVec<ACL>) -> Vec<Acl> {
    v.into_vec()
        .unwrap_or_default()
        .into_iter()
        .map(|a| Acl {
            perms: Perms::from_bits_retain(a.perms),
            id: Id::new(lossy(&a.id.scheme), lossy(&a.id.id)),
        })
        .collect()
}

/// A create. Proto selects the op from the mode: op 19 for a container,
/// op 21 for a TTL mode, and create2 (op 15) for the rest.
///
/// The op holds no data. The caller gives the data to
/// `Shared::request_with_data` as a borrowed slice, and the core encodes
/// it straight into the request frame. Thus the data is not copied twice.
pub(crate) fn create(path: &str, mode: &CreateMode, acl: &[Acl]) -> NativeOp {
    let (mode, ttl) = create_mode_wire(mode);
    // `create2` asks for the path and stat reply. Proto keeps that reply
    // shape for the container and TTL ops too.
    Op::Create {
        path: path_in(path),
        data: JBuffer::Null,
        acl: acl_to_jute(acl),
        mode,
        ttl,
        create2: true,
    }
}

/// A delete (op 2).
pub(crate) fn delete(path: &str, version: i32) -> NativeOp {
    Op::Delete {
        path: path_in(path),
        version,
    }
}

/// An exists (op 3) with an optional exist watch.
pub(crate) fn exists(path: &str, watch: Option<WatchId>) -> NativeOp {
    Op::Exists {
        path: path_in(path),
        watch,
    }
}

/// A get_data (op 4) with an optional data watch.
pub(crate) fn get_data(path: &str, watch: Option<WatchId>) -> NativeOp {
    Op::GetData {
        path: path_in(path),
        watch,
    }
}

/// A get_config: a get_data of `/zookeeper/config` that proto never
/// chroots.
pub(crate) fn get_config(watch: Option<WatchId>) -> NativeOp {
    Op::GetConfig { watch }
}

/// A set_data (op 5). The op holds no data. The data goes to the core as
/// a borrowed slice, as for [`create`].
pub(crate) fn set_data(path: &str, version: i32) -> NativeOp {
    Op::SetData {
        path: path_in(path),
        data: JBuffer::Null,
        version,
    }
}

/// A get_acl (op 6).
pub(crate) fn get_acl(path: &str) -> NativeOp {
    Op::GetAcl {
        path: path_in(path),
    }
}

/// A set_acl (op 7). The native form gives the stat of the reply.
pub(crate) fn set_acl(path: &str, acl: &[Acl], version: i32) -> NativeOp {
    Op::SetAclStat {
        path: path_in(path),
        acl: acl_to_jute(acl),
        version,
    }
}

/// A get_children (op 8), or a get_children2 (op 12) when `with_stat`
/// is true, with an optional child watch.
pub(crate) fn get_children(path: &str, watch: Option<WatchId>, with_stat: bool) -> NativeOp {
    Op::GetChildren {
        path: path_in(path),
        watch,
        with_stat,
    }
}

/// A sync (op 9).
pub(crate) fn sync(path: &str) -> NativeOp {
    Op::Sync {
        path: path_in(path),
    }
}

/// A reconfig (op 16). The strings come from `Reconfig::wire`.
pub(crate) fn reconfig(
    joining: JString,
    leaving: JString,
    members: JString,
    version: i64,
) -> NativeOp {
    Op::Reconfig {
        joining,
        leaving,
        members,
        version,
    }
}

/// A `remove_watches` call (op 18) for every local watcher of `wtype`
/// on `path`.
pub(crate) fn remove_watches(path: &str, wtype: i32, local: bool) -> NativeOp {
    Op::RemoveWatches {
        path: path_in(path),
        wtype,
        watcher: None,
        local,
        all: true,
    }
}

/// The server removal of a watch class whose last local user left. The
/// hint path is in client form, and proto adds the chroot again.
pub(crate) fn remove_hint(hint: RemoveHint) -> NativeOp {
    Op::RemoveWatches {
        path: PathIn::Native(hint.path),
        wtype: hint.wtype,
        watcher: None,
        local: false,
        all: true,
    }
}

/// An add_watch (op 106).
pub(crate) fn add_watch(path: &str, mode: i32, watch: WatchId) -> NativeOp {
    Op::AddWatch {
        path: path_in(path),
        mode,
        watch,
    }
}

/// A get_ephemerals (op 103). The server matches `prefix` as a string
/// prefix.
pub(crate) fn get_ephemerals(prefix: &str) -> NativeOp {
    Op::GetEphemerals {
        prefix: path_in(prefix),
    }
}

/// A get_all_children_number (op 104).
pub(crate) fn get_all_children_number(path: &str) -> NativeOp {
    Op::GetAllChildrenNumber {
        path: path_in(path),
    }
}

/// A who_am_i (op 107).
pub(crate) fn who_am_i() -> NativeOp {
    Op::WhoAmI
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_builders_wrap_native_paths() {
        match delete("/a", 3) {
            Op::Delete { path, version } => {
                assert_eq!(path, PathIn::Native(JString::from("/a")));
                assert_eq!(version, 3);
            }
            _ => panic!("not a delete"),
        }
        assert!(matches!(who_am_i(), Op::WhoAmI));
    }

    use crate::acl::{CREATOR_ALL_ACL, OPEN_ACL_UNSAFE, READ_ACL_UNSAFE};
    use crate::types::Ttl;

    fn ttl(ms: u64) -> Ttl {
        Ttl::from_millis(ms).unwrap()
    }

    #[test]
    fn create_modes_use_the_java_flags() {
        let cases = [
            (CreateMode::Persistent, (0, -1), opcode::CREATE2),
            (CreateMode::Ephemeral, (1, -1), opcode::CREATE2),
            (CreateMode::PersistentSequential, (2, -1), opcode::CREATE2),
            (CreateMode::EphemeralSequential, (3, -1), opcode::CREATE2),
            (CreateMode::Container, (4, -1), opcode::CREATE_CONTAINER),
            (
                CreateMode::PersistentWithTtl(ttl(1000)),
                (5, 1000),
                opcode::CREATE_TTL,
            ),
            (
                CreateMode::PersistentSequentialWithTtl(Ttl::MAX),
                (6, 0xFF_FFFF_FFFF),
                opcode::CREATE_TTL,
            ),
        ];
        for (mode, wire, op) in cases {
            assert_eq!(create_mode_wire(&mode), wire, "{mode:?}");
            assert_eq!(create_op_code(&mode), op, "{mode:?}");
            // A TTL is valid only for a TTL mode, as proto checks it.
            assert_eq!(
                zk_proto::check_ttl(wire.0, wire.1),
                Ok(()),
                "{mode:?} gives a TTL that proto refuses"
            );
        }
    }

    #[test]
    fn create_asks_for_the_stat_reply() {
        let op = create(
            "/a",
            &CreateMode::PersistentWithTtl(ttl(5)),
            OPEN_ACL_UNSAFE,
        );
        match op {
            Op::Create {
                path,
                data,
                acl,
                mode,
                ttl,
                create2,
            } => {
                assert_eq!(path, PathIn::Native(JString::from("/a")));
                // The data travels apart, as a borrowed slice.
                assert_eq!(data, JBuffer::Null);
                assert_eq!(acl.len(), 1);
                assert_eq!((mode, ttl), (5, 5));
                assert!(create2);
            }
            _ => panic!("not a create"),
        }
        match create("/b", &CreateMode::Ephemeral, CREATOR_ALL_ACL) {
            Op::Create { mode, ttl, .. } => {
                assert_eq!((mode, ttl), (1, -1));
            }
            _ => panic!("not a create"),
        }
    }

    #[test]
    fn acl_round_trip() {
        let mut list = Vec::new();
        list.extend_from_slice(OPEN_ACL_UNSAFE);
        list.extend_from_slice(READ_ACL_UNSAFE);
        list.extend_from_slice(CREATOR_ALL_ACL);
        list.push(Acl {
            perms: Perms::READ | Perms::ADMIN,
            id: Id::ip("10.0.0.0/8"),
        });
        list.push(Acl {
            perms: Perms::WRITE,
            id: Id::new("digest", "u:abc="),
        });
        let wire = acl_to_jute(&list);
        let first = wire.iter().next().unwrap();
        assert_eq!(first.perms, 0x1f);
        assert_eq!(first.id.scheme, JString::from("world"));
        assert_eq!(first.id.id, JString::from("anyone"));
        assert_eq!(acl_from_jute(wire), list);
    }

    #[test]
    fn empty_acl_is_present() {
        assert_eq!(acl_to_jute(&[]), JVec::Items(Vec::new()));
        assert!(acl_from_jute(JVec::Null).is_empty());
    }

    #[test]
    fn acl_from_jute_keeps_unknown_bits_and_converts_lossily() {
        let wire = JVec::Items(vec![ACL {
            perms: 0x41,
            id: zk_jute::data::Id {
                scheme: JString::Bytes(vec![b'x', 0xff]),
                id: JString::Null,
            },
        }]);
        let acl = acl_from_jute(wire);
        let a = acl.first().unwrap();
        assert_eq!(a.perms.bits(), 0x41);
        assert!(a.perms.contains(Perms::READ));
        assert_eq!(a.id.scheme, "x\u{fffd}");
        assert_eq!(a.id.id, "");
    }
}
