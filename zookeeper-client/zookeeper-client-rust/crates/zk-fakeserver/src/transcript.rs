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

//! The record of every client frame.
//!
//! The server decodes each frame far enough to name it: the opcode, the
//! xid, the path, and the fields that tests check most. The raw body stays
//! in the record, so a test can decode any other field with zk-jute.

use zk_jute::data::ACL;
use zk_jute::proto::{
    AddWatchRequest, AuthPacket, CheckWatchesRequest, CreateRequest, CreateTTLRequest,
    DeleteRequest, GetDataRequest, GetSASLRequest, MultiHeader, SetACLRequest, SetDataRequest,
    SetWatches, SetWatches2,
};
use zk_jute::{DecodeError, JString, JVec, Reader, Record, opcode};

/// The kind of a recorded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// A connect request.
    Connect,
    /// A request after the handshake.
    Request,
    /// A four-letter word, such as `isro`, sent instead of a handshake.
    FourLetter,
    /// A frame that the server cannot parse, or a bad length prefix.
    Unparsable,
}

/// The fields of a connect request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectInfo {
    /// The protocol version.
    pub protocol_version: i32,
    /// The last zxid that the client saw.
    pub last_zxid_seen: i64,
    /// The requested timeout in milliseconds.
    pub time_out: i32,
    /// The session to resume, or 0.
    pub session_id: i64,
    /// The password. `None` is a null buffer.
    pub passwd: Option<Vec<u8>>,
    /// The read-only flag. `None` when an old client leaves it out.
    pub read_only: Option<bool>,
}

impl ConnectInfo {
    /// Decodes a connect request body. The read-only flag is optional, as
    /// in the Java server.
    ///
    /// # Errors
    ///
    /// Returns the decode error for a body that is too short.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        let protocol_version = r.read_i32()?;
        let last_zxid_seen = r.read_i64()?;
        let time_out = r.read_i32()?;
        let session_id = r.read_i64()?;
        let passwd = zk_jute::JBuffer::decode(&mut r)?.into_bytes();
        let read_only = if r.is_empty() {
            None
        } else {
            Some(r.read_bool()?)
        };
        Ok(Self {
            protocol_version,
            last_zxid_seen,
            time_out,
            session_id,
            passwd,
            read_only,
        })
    }
}

/// The watch lists of a SetWatches or SetWatches2 request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchSet {
    /// The relative zxid.
    pub relative_zxid: i64,
    /// Data watches.
    pub data: Vec<String>,
    /// Exist watches.
    pub exist: Vec<String>,
    /// Child watches.
    pub child: Vec<String>,
    /// Persistent watches. Empty for SetWatches.
    pub persistent: Vec<String>,
    /// Persistent recursive watches. Empty for SetWatches.
    pub persistent_recursive: Vec<String>,
}

/// Decoded fields of a frame, by kind.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Detail {
    /// Nothing more.
    #[default]
    None,
    /// A connect request.
    Connect(ConnectInfo),
    /// An auth request.
    Auth {
        /// The auth type field.
        auth_type: i32,
        /// The scheme.
        scheme: String,
        /// The credential bytes.
        auth: Vec<u8>,
    },
    /// A SetWatches or SetWatches2 request.
    SetWatches(WatchSet),
    /// A create request of any kind.
    Create {
        /// The create flags.
        flags: i32,
        /// The ACL list.
        acl: Vec<ACL>,
        /// The TTL of a createTTL request.
        ttl: Option<i64>,
        /// The data length, or -1 for null data.
        data_len: i64,
    },
    /// A read with a watch flag: getData, exists, getChildren.
    Watch(bool),
    /// A request with an expected version: setData, delete, check, setACL.
    Version(i32),
    /// A watch type: checkWatches, removeWatches.
    WatchType(i32),
    /// An addWatch mode.
    AddWatch(i32),
    /// The operations of a multi or multiRead, as opcode and path.
    Multi(Vec<(i32, Option<String>)>),
    /// A SASL token length.
    Sasl(usize),
    /// The reason why the frame cannot be parsed.
    Error(String),
}

/// One recorded client frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRecord {
    /// The order of the frame over the whole cluster, from 0.
    pub seq: u64,
    /// The listener index.
    pub server: usize,
    /// The connection id. It is unique in the cluster.
    pub conn: u64,
    /// The 1-based connection number on the listener.
    pub conn_ordinal: u64,
    /// The request number on the connection. The connect request is 0.
    pub frame: u64,
    /// The frame kind.
    pub kind: FrameKind,
    /// The session of the connection, or the session in a connect request.
    pub session_id: i64,
    /// The xid.
    pub xid: Option<i32>,
    /// The opcode.
    pub op: Option<i32>,
    /// The path.
    pub path: Option<String>,
    /// More decoded fields.
    pub detail: Detail,
    /// The frame body, without the length prefix. For a request it starts
    /// with the request header.
    pub body: Vec<u8>,
    /// The index of the rule that fired for the frame.
    pub rule: Option<usize>,
    /// False when the frame arrived on a stalled connection and was not
    /// handled.
    pub handled: bool,
}

fn text(s: &JString) -> Option<String> {
    s.as_bytes()
        .map(|b| String::from_utf8_lossy(b).into_owned())
}

fn texts(v: &JVec<JString>) -> Vec<String> {
    v.iter().filter_map(text).collect()
}

/// Returns the path and the detail of a request body, which is the part
/// after the request header.
pub(crate) fn describe(op: i32, body: &[u8]) -> (Option<String>, Detail) {
    match describe_inner(op, body) {
        Ok(v) => v,
        Err(e) => (None, Detail::Error(e.to_string())),
    }
}

/// Decodes one record and maps it. Each record type gets its own small
/// function, which keeps the stack frame of the caller small.
fn one<T: Record>(
    r: &mut Reader<'_>,
    f: impl FnOnce(T) -> (Option<String>, Detail),
) -> Result<(Option<String>, Detail), DecodeError> {
    T::decode(r).map(f)
}

fn describe_inner(op: i32, body: &[u8]) -> Result<(Option<String>, Detail), DecodeError> {
    let mut r = Reader::new(body);
    // Requests with the same wire layout share one record type, so the
    // decode and its errors stay the same.
    match op {
        opcode::CREATE | opcode::CREATE2 | opcode::CREATE_CONTAINER => {
            one(&mut r, |q: CreateRequest| {
                create(&q.path, q.flags, q.acl, None, &q.data)
            })
        }
        opcode::CREATE_TTL => one(&mut r, |q: CreateTTLRequest| {
            create(&q.path, q.flags, q.acl, Some(q.ttl), &q.data)
        }),
        opcode::DELETE | opcode::DELETE_CONTAINER | opcode::CHECK => {
            one(&mut r, |q: DeleteRequest| {
                (text(&q.path), Detail::Version(q.version))
            })
        }
        opcode::EXISTS | opcode::GET_DATA | opcode::GET_CHILDREN | opcode::GET_CHILDREN2 => {
            one(&mut r, |q: GetDataRequest| {
                (text(&q.path), Detail::Watch(q.watch))
            })
        }
        opcode::SET_DATA => one(&mut r, |q: SetDataRequest| {
            (text(&q.path), Detail::Version(q.version))
        }),
        opcode::SET_ACL => one(&mut r, |q: SetACLRequest| {
            (text(&q.path), Detail::Version(q.version))
        }),
        opcode::GET_ACL
        | opcode::SYNC
        | opcode::GET_ALL_CHILDREN_NUMBER
        | opcode::GET_EPHEMERALS => one(&mut r, |q: JString| (text(&q), Detail::None)),
        opcode::CHECK_WATCHES | opcode::REMOVE_WATCHES => one(&mut r, |q: CheckWatchesRequest| {
            (text(&q.path), Detail::WatchType(q.r#type))
        }),
        opcode::ADD_WATCH => one(&mut r, |q: AddWatchRequest| {
            (text(&q.path), Detail::AddWatch(q.mode))
        }),
        opcode::SET_AUTH => one(&mut r, |q: AuthPacket| {
            (
                None,
                Detail::Auth {
                    auth_type: q.r#type,
                    scheme: text(&q.scheme).unwrap_or_default(),
                    auth: q.auth.into_bytes().unwrap_or_default(),
                },
            )
        }),
        opcode::SET_WATCHES => one(&mut r, |q: SetWatches| watch_set(widen(q))),
        opcode::SET_WATCHES2 => one(&mut r, watch_set),
        opcode::MULTI | opcode::MULTI_READ => Ok((None, Detail::Multi(multi_ops(&mut r)?))),
        opcode::SASL => one(&mut r, |q: GetSASLRequest| {
            (None, Detail::Sasl(q.token.len()))
        }),
        _ => Ok((None, Detail::None)),
    }
}

/// Maps the fields of a create request of any kind.
fn create(
    path: &JString,
    flags: i32,
    acl: JVec<ACL>,
    ttl: Option<i64>,
    data: &zk_jute::JBuffer,
) -> (Option<String>, Detail) {
    (
        text(path),
        Detail::Create {
            flags,
            acl: acl.into_vec().unwrap_or_default(),
            ttl,
            data_len: data_len(data),
        },
    )
}

/// Maps the watch lists of a SetWatches2 request.
fn watch_set(q: SetWatches2) -> (Option<String>, Detail) {
    (
        None,
        Detail::SetWatches(WatchSet {
            relative_zxid: q.relative_zxid,
            data: texts(&q.data_watches),
            exist: texts(&q.exist_watches),
            child: texts(&q.child_watches),
            persistent: texts(&q.persistent_watches),
            persistent_recursive: texts(&q.persistent_recursive_watches),
        }),
    )
}

/// Returns a SetWatches request as a SetWatches2 request with null
/// persistent lists.
pub(crate) fn widen(w: SetWatches) -> SetWatches2 {
    SetWatches2 {
        relative_zxid: w.relative_zxid,
        data_watches: w.data_watches,
        exist_watches: w.exist_watches,
        child_watches: w.child_watches,
        ..SetWatches2::default()
    }
}

fn data_len(b: &zk_jute::JBuffer) -> i64 {
    if b.is_null() {
        -1
    } else {
        i64::try_from(b.len()).unwrap_or(i64::MAX)
    }
}

/// Lists the opcode and path of each operation in a multi body.
fn multi_ops(r: &mut Reader<'_>) -> Result<Vec<(i32, Option<String>)>, DecodeError> {
    let mut out = Vec::new();
    loop {
        let h = MultiHeader::decode(r)?;
        if h.done {
            break;
        }
        let path = match h.r#type {
            opcode::CREATE | opcode::CREATE2 | opcode::CREATE_CONTAINER => {
                text(&CreateRequest::decode(r)?.path)
            }
            opcode::CREATE_TTL => text(&CreateTTLRequest::decode(r)?.path),
            opcode::DELETE | opcode::DELETE_CONTAINER | opcode::CHECK => {
                text(&DeleteRequest::decode(r)?.path)
            }
            opcode::SET_DATA => text(&SetDataRequest::decode(r)?.path),
            opcode::GET_DATA | opcode::GET_CHILDREN => text(&GetDataRequest::decode(r)?.path),
            other => {
                out.push((other, None));
                break;
            }
        };
        out.push((h.r#type, path));
    }
    Ok(out)
}
