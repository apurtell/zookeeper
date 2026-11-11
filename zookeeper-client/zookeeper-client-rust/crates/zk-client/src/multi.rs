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

//! Transactions: `MultiWriter`, `MultiReader` and their results.
//!
//! Paths are checked when an op is added, so `?` names the failing op.
//! The data stays borrowed: `Client::multi` encodes the whole
//! transaction under the core lock at call time and keeps no reference.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

use zk_jute::multi::{MultiBody, MultiItem};
use zk_jute::{opcode, rc};
use zk_proto::{InputDefect, MultiOp, MultiOpRef, Reply};

use crate::acl::Acl;
use crate::decode::{names, rc_error, server_path};
use crate::error::{Error, MultiError};
use crate::ops;
use crate::path::{self, ZPathBuf};
use crate::tokens::RawResult;
use crate::types::{CreateMode, Stat, Version};

/// The source of `MultiWriter` ids. Each writer has its own id, so a
/// handle of another writer is detected.
static NEXT_WRITER_ID: AtomicU64 = AtomicU64::new(1);

/// Gives the next writer id. It wraps after 2^64 writers.
fn next_writer_id() -> u64 {
    NEXT_WRITER_ID.fetch_add(1, Ordering::Relaxed)
}

/// One write op, with borrowed inputs.
#[derive(Clone, Debug)]
enum WriteOp<'a> {
    Create {
        path: &'a str,
        data: &'a [u8],
        mode: CreateMode,
        acl: &'a [Acl],
    },
    Delete {
        path: &'a str,
        version: Version,
    },
    SetData {
        path: &'a str,
        data: &'a [u8],
        version: Version,
    },
    Check {
        path: &'a str,
        version: Version,
    },
}

/// A transaction under construction.
#[derive(Clone, Debug)]
pub struct MultiWriter<'a> {
    ops: Vec<WriteOp<'a>>,
    writer_id: u64,
}

impl Default for MultiWriter<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> MultiWriter<'a> {
    /// Makes an empty transaction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            writer_id: next_writer_id(),
        }
    }

    /// Adds a create. A create2 sub-op (15), a container sub-op (19) or a
    /// TTL sub-op (21), as the mode selects.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` for a path that is not valid. A sequential
    /// mode accepts a path that ends with `/`.
    pub fn create(
        &mut self,
        path: &'a str,
        data: &'a [u8],
        mode: CreateMode,
        acl: &'a [Acl],
    ) -> Result<OpHandle<Created>, Error> {
        path::checked(&path, mode.is_sequential())?;
        Ok(self.push(WriteOp::Create {
            path,
            data,
            mode,
            acl,
        }))
    }

    /// Adds a delete.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` for a path that is not valid.
    pub fn delete(&mut self, path: &'a str, version: Version) -> Result<OpHandle<()>, Error> {
        path::checked(&path, false)?;
        Ok(self.push(WriteOp::Delete { path, version }))
    }

    /// Adds a set_data.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` for a path that is not valid.
    pub fn set_data(
        &mut self,
        path: &'a str,
        data: &'a [u8],
        version: Version,
    ) -> Result<OpHandle<Stat>, Error> {
        path::checked(&path, false)?;
        Ok(self.push(WriteOp::SetData {
            path,
            data,
            version,
        }))
    }

    /// Adds a version check.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` for a path that is not valid.
    pub fn check(&mut self, path: &'a str, version: Version) -> Result<OpHandle<()>, Error> {
        path::checked(&path, false)?;
        Ok(self.push(WriteOp::Check { path, version }))
    }

    /// Appends a checked op and gives the handle of its index.
    fn push<T>(&mut self, op: WriteOp<'a>) -> OpHandle<T> {
        let index = self.ops.len();
        self.ops.push(op);
        OpHandle::new(index, self.writer_id)
    }

    /// The number of ops.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// True when the transaction has no op.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The id that the handles of this writer carry.
    pub(crate) fn writer_id(&self) -> u64 {
        self.writer_id
    }

    /// Gives the ops as borrowed proto sub-ops, in order. Each path and
    /// each data buffer stays in the writer. The core encodes them
    /// straight into the request frame, so neither is copied first. The
    /// create modes map through `ops::create_mode_wire`.
    pub(crate) fn to_ops(&self) -> Vec<MultiOpRef<'_>> {
        let defect = InputDefect::default();
        self.ops
            .iter()
            .map(|op| match op {
                WriteOp::Create {
                    path,
                    data,
                    mode,
                    acl,
                } => {
                    let (wire_mode, ttl) = ops::create_mode_wire(mode);
                    MultiOpRef::Create {
                        op_type: ops::create_op_code(mode),
                        path: Some(path.as_bytes()),
                        data: Some(data),
                        acl: ops::acl_to_jute(acl),
                        mode: wire_mode,
                        ttl,
                        defect,
                    }
                }
                WriteOp::Delete { path, version } => MultiOpRef::Delete {
                    path: Some(path.as_bytes()),
                    version: version.get(),
                    defect,
                },
                WriteOp::SetData {
                    path,
                    data,
                    version,
                } => MultiOpRef::SetData {
                    path: Some(path.as_bytes()),
                    data: Some(data),
                    version: version.get(),
                    defect,
                },
                WriteOp::Check { path, version } => MultiOpRef::Check {
                    path: Some(path.as_bytes()),
                    version: version.get(),
                    defect,
                },
            })
            .collect()
    }
}

/// A typed reference to one op of a [`MultiWriter`].
#[derive(Debug)]
pub struct OpHandle<T> {
    index: usize,
    writer_id: u64,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for OpHandle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OpHandle<T> {}

impl<T> OpHandle<T> {
    /// Makes a handle for op `index` of writer `writer_id`.
    pub(crate) fn new(index: usize, writer_id: u64) -> Self {
        Self {
            index,
            writer_id,
            _t: PhantomData,
        }
    }

    /// The index of the op in its transaction.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }
}

/// The result of a create in a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Created {
    /// The created path, with the chroot stripped.
    pub path: ZPathBuf,
    /// The stat of the new node.
    pub stat: Stat,
}

/// The result of one op of a committed transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpResult {
    /// A create.
    Create(Created),
    /// A delete.
    Delete,
    /// A set_data, with the new stat.
    SetData(Stat),
    /// A version check.
    Check,
}

/// The results of a committed transaction, in op order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiResults {
    results: Vec<OpResult>,
    writer_id: u64,
}

impl MultiResults {
    /// Makes the results of writer `writer_id`.
    pub(crate) fn new(results: Vec<OpResult>, writer_id: u64) -> Self {
        Self { results, writer_id }
    }

    /// Typed access to the result of `h`.
    ///
    /// It returns `None` when `h` comes from another writer, or when the
    /// result at its index has another type. The crate never panics, so
    /// the misuse gives `None`.
    #[must_use]
    pub fn get<T: FromOpResult>(&self, h: OpHandle<T>) -> Option<&T> {
        if h.writer_id != self.writer_id {
            return None;
        }
        self.results.get(h.index).and_then(T::from_op_result)
    }

    /// The results in op order.
    pub fn iter(&self) -> std::slice::Iter<'_, OpResult> {
        self.results.iter()
    }

    /// The results as a vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<OpResult> {
        self.results
    }
}

mod sealed {
    /// Seals [`FromOpResult`](super::FromOpResult).
    pub trait Sealed {}
}

/// The result types that an [`OpHandle`] can name. It is sealed.
pub trait FromOpResult: sealed::Sealed + Sized {
    /// Borrows the typed value of `r`, or `None` for another type.
    fn from_op_result(r: &OpResult) -> Option<&Self>;
}

impl sealed::Sealed for Created {}
impl FromOpResult for Created {
    fn from_op_result(r: &OpResult) -> Option<&Self> {
        match r {
            OpResult::Create(c) => Some(c),
            _ => None,
        }
    }
}

impl sealed::Sealed for Stat {}
impl FromOpResult for Stat {
    fn from_op_result(r: &OpResult) -> Option<&Self> {
        match r {
            OpResult::SetData(s) => Some(s),
            _ => None,
        }
    }
}

impl sealed::Sealed for () {}
impl FromOpResult for () {
    fn from_op_result(r: &OpResult) -> Option<&Self> {
        match r {
            OpResult::Delete | OpResult::Check => Some(&()),
            _ => None,
        }
    }
}

/// One read op.
#[derive(Clone, Debug)]
enum ReadOp<'a> {
    GetData(&'a str),
    GetChildren(&'a str),
}

/// A batch of reads that the server runs as one snapshot (op 22).
#[derive(Clone, Debug, Default)]
pub struct MultiReader<'a> {
    ops: Vec<ReadOp<'a>>,
}

impl<'a> MultiReader<'a> {
    /// Makes an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Adds a get_data and returns its index in the results.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` for a path that is not valid.
    pub fn get_data(&mut self, path: &'a str) -> Result<usize, Error> {
        path::checked(&path, false)?;
        Ok(self.push(ReadOp::GetData(path)))
    }

    /// Adds a get_children and returns its index in the results.
    ///
    /// # Errors
    ///
    /// `Error::InvalidPath` for a path that is not valid.
    pub fn get_children(&mut self, path: &'a str) -> Result<usize, Error> {
        path::checked(&path, false)?;
        Ok(self.push(ReadOp::GetChildren(path)))
    }

    /// Appends a checked op and gives its index.
    fn push(&mut self, op: ReadOp<'a>) -> usize {
        let index = self.ops.len();
        self.ops.push(op);
        index
    }

    /// The number of ops.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// True when the batch has no op.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Converts the ops to proto sub-ops, in order.
    pub(crate) fn to_ops(&self) -> Vec<MultiOp> {
        self.ops
            .iter()
            .map(|op| match op {
                ReadOp::GetData(p) => MultiOp::GetData {
                    path: ops::path_in(p),
                },
                ReadOp::GetChildren(p) => MultiOp::GetChildren {
                    path: ops::path_in(p),
                },
            })
            .collect()
    }
}

/// The result of one read op.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadResult {
    /// A get_data. A null buffer gives an empty vector.
    Data {
        /// The data.
        data: Vec<u8>,
        /// The stat.
        stat: Stat,
    },
    /// A get_children: the child names.
    Children(Vec<String>),
}

/// Decodes the reply of a multi.
///
/// - `rc` 0 with `Reply::Multi` gives one `OpResult` per item, by the
///   wire type of each item.
/// - A rolled-back transaction gives `MultiError::Aborted`. `index` is
///   the first item whose error is not 0 and not
///   `RuntimeInconsistency`. `per_op` follows the server codes.
/// - An `rc` with no multi reply, for example a header-only
///   `NotReadOnly`, gives `MultiError::Request`, never a partial
///   decode.
/// - A malformed reply gives `MultiError::Request(MarshallingError)`.
pub(crate) fn decode_multi(r: RawResult, writer_id: u64) -> Result<MultiResults, MultiError> {
    let items = match r.reply {
        Some(Reply::Multi(items)) => items,
        Some(_) => return Err(MultiError::Request(Error::MarshallingError)),
        None => return Err(MultiError::Request(no_reply_error(r.rc))),
    };
    // The server sends an error item for every op of a rolled-back
    // transaction, and no error item for a committed one.
    let rolled_back = r.rc != rc::ZOK
        || items
            .iter()
            .any(|i| matches!(i.body, MultiBody::Error(_)) || i.err != rc::ZOK);
    if rolled_back {
        return Err(aborted(&items, r.rc));
    }
    items
        .into_iter()
        .map(write_result)
        .collect::<Result<Vec<_>, Error>>()
        .map(|results| MultiResults::new(results, writer_id))
        .map_err(MultiError::Request)
}

/// The error of a result with no reply. A zero `rc` with no reply is a
/// malformed result.
fn no_reply_error(code: i32) -> Error {
    if code == rc::ZOK {
        Error::MarshallingError
    } else {
        rc_error(code)
    }
}

/// The result code of one item: the code of its error body, else the
/// code of its header.
fn item_code(i: &MultiItem) -> i32 {
    match &i.body {
        MultiBody::Error(e) => e.err,
        _ => i.err,
    }
}

/// Builds the error of a rolled-back transaction.
///
/// The failed op is the first item whose code is not 0 and not
/// `RuntimeInconsistency`, as proto computes the `rc`. When no item has
/// such a code, the first item with any error code is the failed op.
/// When no item has an error code, the request failed as a whole.
fn aborted(items: &[MultiItem], code: i32) -> MultiError {
    let codes: Vec<i32> = items.iter().map(item_code).collect();
    let index = codes
        .iter()
        .position(|&c| c != rc::ZOK && c != rc::ZRUNTIMEINCONSISTENCY)
        .or_else(|| codes.iter().position(|&c| c != rc::ZOK));
    let Some(index) = index else {
        return MultiError::Request(no_reply_error(code));
    };
    let error = codes
        .get(index)
        .map_or(Error::MarshallingError, |&c| rc_error(c));
    let per_op = codes
        .iter()
        .map(|&c| (c != rc::ZOK).then(|| rc_error(c)))
        .collect();
    MultiError::Aborted {
        index,
        error,
        per_op,
    }
}

/// Converts one item of a committed transaction by its wire type.
fn write_result(i: MultiItem) -> Result<OpResult, Error> {
    match (i.wire_type, i.body) {
        (opcode::CREATE, MultiBody::Create(c)) => Ok(OpResult::Create(Created {
            path: server_path(c.path)?,
            stat: Stat::default(),
        })),
        (opcode::CREATE2, MultiBody::Create2(c)) => Ok(OpResult::Create(Created {
            path: server_path(c.path)?,
            stat: Stat::from_jute(&c.stat),
        })),
        (opcode::SET_DATA, MultiBody::SetData(s)) => {
            Ok(OpResult::SetData(Stat::from_jute(&s.stat)))
        }
        (opcode::DELETE, MultiBody::Empty) => Ok(OpResult::Delete),
        (opcode::CHECK, MultiBody::Empty) => Ok(OpResult::Check),
        _ => Err(Error::MarshallingError),
    }
}

/// Decodes the reply of a multi_read. A sub-op error does not abort the
/// others, so each item has its own result. An `rc` with no reply gives
/// the error of the `rc`.
pub(crate) fn decode_multi_read(r: RawResult) -> Result<Vec<Result<ReadResult, Error>>, Error> {
    match r.reply {
        Some(Reply::MultiRead(items)) => Ok(items.into_iter().map(read_result).collect()),
        Some(_) => Err(Error::MarshallingError),
        None => Err(no_reply_error(r.rc)),
    }
}

/// Converts one item of a multi_read by its body. An error item with
/// the code 0 is malformed.
fn read_result(i: MultiItem) -> Result<ReadResult, Error> {
    match i.body {
        MultiBody::Error(e) => Err(no_reply_error(e.err)),
        MultiBody::GetData(d) => Ok(ReadResult::Data {
            data: d.data.into_bytes().unwrap_or_default(),
            stat: Stat::from_jute(&d.stat),
        }),
        MultiBody::GetChildren(c) => names(c.children).map(ReadResult::Children),
        _ => Err(Error::MarshallingError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writers_have_their_own_ids() {
        let a = MultiWriter::new();
        let b = MultiWriter::default();
        assert_ne!(a.writer_id(), b.writer_id());
        assert!(a.is_empty());
        assert_eq!(b.len(), 0);
    }

    use zk_jute::data::Stat as JStat;
    use zk_jute::proto::{
        Create2Response, CreateResponse, ErrorResponse, GetChildrenResponse, GetDataResponse,
        SetDataResponse,
    };
    use zk_jute::{JBuffer, JString, JVec};
    use zk_proto::{Origin, PathIn};

    use crate::acl::OPEN_ACL_UNSAFE;
    use crate::types::Ttl;

    fn np(p: &str) -> PathIn {
        PathIn::Native(JString::from(p))
    }

    fn jstat(version: i32) -> JStat {
        JStat {
            version,
            ..JStat::default()
        }
    }

    fn item(wire_type: i32, err: i32, body: MultiBody) -> MultiItem {
        MultiItem {
            wire_type,
            err,
            body,
        }
    }

    fn error_item(err: i32) -> MultiItem {
        item(opcode::ERROR, err, MultiBody::Error(ErrorResponse { err }))
    }

    fn result(rc: i32, reply: Option<Reply>) -> RawResult {
        RawResult {
            rc,
            zxid: 0,
            origin: Origin::Reply,
            reply,
        }
    }

    #[test]
    fn writer_adds_ops_in_order() {
        let ttl = Ttl::from_millis(100).unwrap();
        let mut w = MultiWriter::new();
        let c = w
            .create("/a", b"d", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap();
        let s = w.set_data("/a", b"e", Version::new(0)).unwrap();
        let k = w.check("/a", Version::new(1)).unwrap();
        let d = w.delete("/a", Version::ANY).unwrap();
        let t = w
            .create(
                "/t",
                b"",
                CreateMode::PersistentWithTtl(ttl),
                OPEN_ACL_UNSAFE,
            )
            .unwrap();
        let x = w
            .create("/x", b"", CreateMode::Container, OPEN_ACL_UNSAFE)
            .unwrap();
        let q = w
            .create("/q/", b"", CreateMode::EphemeralSequential, &[])
            .unwrap();
        assert_eq!(
            [
                c.index(),
                s.index(),
                k.index(),
                d.index(),
                t.index(),
                x.index(),
                q.index()
            ],
            [0, 1, 2, 3, 4, 5, 6]
        );
        assert_eq!(w.len(), 7);
        let ops = w.to_ops();
        let types: Vec<i32> = ops.iter().map(MultiOpRef::op_type).collect();
        assert_eq!(
            types,
            [
                opcode::CREATE2,
                opcode::SET_DATA,
                opcode::CHECK,
                opcode::DELETE,
                opcode::CREATE_TTL,
                opcode::CREATE_CONTAINER,
                opcode::CREATE2
            ]
        );
        match ops.first().unwrap() {
            MultiOpRef::Create {
                path,
                data,
                acl,
                mode,
                ttl,
                defect,
                ..
            } => {
                assert_eq!(*path, Some(b"/a".as_slice()));
                assert_eq!(*data, Some(b"d".as_slice()));
                assert_eq!(acl.len(), 1);
                assert_eq!((*mode, *ttl), (0, -1));
                assert!(!defect.any());
            }
            other => panic!("not a create: {other:?}"),
        }
        assert!(matches!(
            ops.get(1).unwrap(),
            MultiOpRef::SetData { version: 0, .. }
        ));
        assert!(matches!(
            ops.get(2).unwrap(),
            MultiOpRef::Check { version: 1, .. }
        ));
        assert!(matches!(
            ops.get(3).unwrap(),
            MultiOpRef::Delete { version: -1, .. }
        ));
        assert!(matches!(
            ops.get(4).unwrap(),
            MultiOpRef::Create {
                mode: 5,
                ttl: 100,
                ..
            }
        ));
        assert!(matches!(
            ops.get(5).unwrap(),
            MultiOpRef::Create {
                mode: 4,
                ttl: -1,
                ..
            }
        ));
        match ops.get(6).unwrap() {
            MultiOpRef::Create {
                path, mode, acl, ..
            } => {
                assert_eq!(*path, Some(b"/q/".as_slice()));
                assert_eq!(*mode, 3);
                // An empty ACL list is present, so the server refuses it.
                assert_eq!(*acl, JVec::Items(Vec::new()));
            }
            other => panic!("not a create: {other:?}"),
        }
    }

    #[test]
    fn reader_adds_ops_in_order() {
        let mut r = MultiReader::new();
        assert_eq!(r.get_data("/a").unwrap(), 0);
        assert_eq!(r.get_children("/").unwrap(), 1);
        assert_eq!(r.get_data("/b").unwrap(), 2);
        assert_eq!(r.len(), 3);
        assert_eq!(
            r.to_ops(),
            vec![
                MultiOp::GetData { path: np("/a") },
                MultiOp::GetChildren { path: np("/") },
                MultiOp::GetData { path: np("/b") },
            ]
        );
    }

    fn committed() -> Reply {
        Reply::Multi(vec![
            item(
                opcode::CREATE2,
                0,
                MultiBody::Create2(Create2Response {
                    path: JString::from("/a0000000001"),
                    stat: jstat(0),
                }),
            ),
            item(
                opcode::CREATE,
                0,
                MultiBody::Create(CreateResponse {
                    path: JString::from("/b"),
                }),
            ),
            item(
                opcode::SET_DATA,
                0,
                MultiBody::SetData(SetDataResponse { stat: jstat(3) }),
            ),
            item(opcode::CHECK, 0, MultiBody::Empty),
            item(opcode::DELETE, 0, MultiBody::Empty),
        ])
    }

    #[test]
    fn decode_multi_gives_typed_results() {
        let mut w = MultiWriter::new();
        let c = w
            .create("/a", b"", CreateMode::PersistentSequential, OPEN_ACL_UNSAFE)
            .unwrap();
        let c1 = w
            .create("/b", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap();
        let s = w.set_data("/a", b"", Version::ANY).unwrap();
        let k = w.check("/a", Version::ANY).unwrap();
        let d = w.delete("/a", Version::ANY).unwrap();
        let res = decode_multi(result(0, Some(committed())), w.writer_id()).unwrap();
        let created = res.get(c).unwrap();
        assert_eq!(created.path, "/a0000000001");
        assert_eq!(res.get(c1).unwrap().path, "/b");
        assert_eq!(res.get(c1).unwrap().stat, Stat::default());
        assert_eq!(res.get(s).unwrap().version, Version::new(3));
        assert!(res.get(k).is_some());
        assert!(res.get(d).is_some());
        let all = res.clone().into_vec();
        assert_eq!(all.len(), 5);
        assert_eq!(all.get(3), Some(&OpResult::Check));
        assert_eq!(all.get(4), Some(&OpResult::Delete));
        assert_eq!(res.iter().count(), 5);
    }

    #[test]
    fn get_refuses_other_writers_and_types() {
        let mut w = MultiWriter::new();
        let c = w
            .create("/a", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap();
        let res = decode_multi(result(0, Some(committed())), w.writer_id()).unwrap();
        assert!(res.get(c).is_some());
        // The same index from another writer.
        let mut other = MultiWriter::new();
        let oc = other
            .create("/a", b"", CreateMode::Persistent, OPEN_ACL_UNSAFE)
            .unwrap();
        assert!(res.get(oc).is_none());
        // A handle of the right writer and the wrong type.
        let wrong: OpHandle<Stat> = OpHandle::new(0, w.writer_id());
        assert!(res.get(wrong).is_none());
        // An index past the end.
        let past: OpHandle<()> = OpHandle::new(9, w.writer_id());
        assert!(res.get(past).is_none());
    }

    #[test]
    fn decode_multi_refuses_bad_replies() {
        let id = 1;
        let req = |r| decode_multi(r, id);
        assert_eq!(
            req(result(0, None)),
            Err(MultiError::Request(Error::MarshallingError))
        );
        assert_eq!(
            req(result(0, Some(Reply::Void))),
            Err(MultiError::Request(Error::MarshallingError))
        );
        assert_eq!(
            req(result(0, Some(Reply::MultiRead(Vec::new())))),
            Err(MultiError::Request(Error::MarshallingError))
        );
        // A body that does not match the wire type.
        let bad = Reply::Multi(vec![item(
            opcode::DELETE,
            0,
            MultiBody::SetData(SetDataResponse { stat: jstat(0) }),
        )]);
        assert_eq!(
            req(result(0, Some(bad))),
            Err(MultiError::Request(Error::MarshallingError))
        );
        // A create path that is not UTF-8.
        let bad = Reply::Multi(vec![item(
            opcode::CREATE,
            0,
            MultiBody::Create(CreateResponse {
                path: JString::Bytes(vec![0xff]),
            }),
        )]);
        assert_eq!(
            req(result(0, Some(bad))),
            Err(MultiError::Request(Error::MarshallingError))
        );
        // An empty transaction commits with no results.
        let res = req(result(0, Some(Reply::Multi(Vec::new())))).unwrap();
        assert_eq!(res.iter().count(), 0);
    }

    #[test]
    fn decode_multi_reports_the_failed_op() {
        // Java DataTree: 0 before the failure, the error at it, and
        // RuntimeInconsistency after it.
        let items = vec![
            error_item(0),
            error_item(rc::ZNONODE),
            error_item(rc::ZRUNTIMEINCONSISTENCY),
        ];
        let got = decode_multi(result(rc::ZNONODE, Some(Reply::Multi(items))), 1);
        assert_eq!(
            got,
            Err(MultiError::Aborted {
                index: 1,
                error: Error::NoNode,
                per_op: vec![None, Some(Error::NoNode), Some(Error::RuntimeInconsistency)],
            })
        );
        let e: Error = got.unwrap_err().into();
        assert_eq!(e, Error::NoNode);
    }

    #[test]
    fn decode_multi_aborts_on_error_items_with_a_zero_rc() {
        let items = vec![
            error_item(rc::ZRUNTIMEINCONSISTENCY),
            error_item(rc::ZBADVERSION),
        ];
        match decode_multi(result(0, Some(Reply::Multi(items))), 1) {
            Err(MultiError::Aborted { index, error, .. }) => {
                assert_eq!(index, 1);
                assert_eq!(error, Error::BadVersion);
            }
            other => panic!("not aborted: {other:?}"),
        }
        // Only RuntimeInconsistency: the first error item failed.
        let items = vec![error_item(0), error_item(rc::ZRUNTIMEINCONSISTENCY)];
        match decode_multi(result(0, Some(Reply::Multi(items))), 1) {
            Err(MultiError::Aborted { index, error, .. }) => {
                assert_eq!(index, 1);
                assert_eq!(error, Error::RuntimeInconsistency);
            }
            other => panic!("not aborted: {other:?}"),
        }
    }

    #[test]
    fn decode_multi_request_errors() {
        // A header-only reply, for example NotReadOnly, never decodes
        // partially.
        assert_eq!(
            decode_multi(result(rc::ZNOTREADONLY, None), 1),
            Err(MultiError::Request(Error::NotReadOnly))
        );
        assert_eq!(
            decode_multi(RawResult::teardown(rc::ZCONNECTIONLOSS), 1),
            Err(MultiError::Request(Error::ConnectionLoss))
        );
        // An error rc with only zero codes is a failed request.
        let items = vec![error_item(0)];
        assert_eq!(
            decode_multi(result(rc::ZSESSIONMOVED, Some(Reply::Multi(items))), 1),
            Err(MultiError::Request(Error::SessionMoved))
        );
    }

    fn read_items() -> Vec<MultiItem> {
        vec![
            item(
                opcode::GET_DATA,
                0,
                MultiBody::GetData(GetDataResponse {
                    data: JBuffer::from(b"v".to_vec()),
                    stat: jstat(2),
                }),
            ),
            item(
                opcode::GET_CHILDREN,
                0,
                MultiBody::GetChildren(GetChildrenResponse {
                    children: JVec::Items(vec![JString::from("c1"), JString::from("c2")]),
                }),
            ),
            item(
                opcode::GET_DATA,
                0,
                MultiBody::GetData(GetDataResponse {
                    data: JBuffer::Null,
                    stat: jstat(0),
                }),
            ),
        ]
    }

    #[test]
    fn decode_multi_read_gives_each_result() {
        let got = decode_multi_read(result(0, Some(Reply::MultiRead(read_items())))).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(
            got.first().unwrap(),
            &Ok(ReadResult::Data {
                data: b"v".to_vec(),
                stat: Stat::from_jute(&jstat(2)),
            })
        );
        assert_eq!(
            got.get(1).unwrap(),
            &Ok(ReadResult::Children(vec!["c1".to_owned(), "c2".to_owned()]))
        );
        // Null data reads as an empty vector.
        assert!(matches!(
            got.get(2).unwrap(),
            Ok(ReadResult::Data { data, .. }) if data.is_empty()
        ));
    }

    #[test]
    fn decode_multi_read_refuses_bad_replies() {
        assert_eq!(
            decode_multi_read(result(0, None)),
            Err(Error::MarshallingError)
        );
        assert_eq!(
            decode_multi_read(result(0, Some(Reply::Multi(Vec::new())))),
            Err(Error::MarshallingError)
        );
        // A bad item fails alone.
        let mut items = read_items();
        items.push(item(opcode::DELETE, 0, MultiBody::Empty));
        items.push(item(
            opcode::GET_CHILDREN,
            0,
            MultiBody::GetChildren(GetChildrenResponse {
                children: JVec::Items(vec![JString::Bytes(vec![0xfe])]),
            }),
        ));
        items.push(error_item(0));
        let got = decode_multi_read(result(0, Some(Reply::MultiRead(items)))).unwrap();
        assert_eq!(got.len(), 6);
        assert!(got.first().unwrap().is_ok());
        assert_eq!(got.get(3).unwrap(), &Err(Error::MarshallingError));
        assert_eq!(got.get(4).unwrap(), &Err(Error::MarshallingError));
        assert_eq!(got.get(5).unwrap(), &Err(Error::MarshallingError));
    }

    #[test]
    fn decode_multi_read_mixed_results() {
        let mut items = read_items();
        items.insert(1, error_item(rc::ZNONODE));
        items.push(error_item(rc::ZNOAUTH));
        let got = decode_multi_read(result(0, Some(Reply::MultiRead(items)))).unwrap();
        assert_eq!(got.len(), 5);
        assert!(got.first().unwrap().is_ok());
        assert_eq!(got.get(1).unwrap(), &Err(Error::NoNode));
        assert!(got.get(2).unwrap().is_ok());
        assert!(got.get(3).unwrap().is_ok());
        assert_eq!(got.get(4).unwrap(), &Err(Error::NoAuth));
        // An rc with no reply fails the whole batch.
        assert_eq!(
            decode_multi_read(result(rc::ZNOTREADONLY, None)),
            Err(Error::NotReadOnly)
        );
    }
}
