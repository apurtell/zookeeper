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

//! Application requests and the results of `submit` and `add_auth`.
//!
//! A [`Request`] carries one operation and one completion token. The core
//! validates it in C order, gives it an xid and queues its frame.

use core::fmt;

use zk_jute::data::ACL;
use zk_jute::{JBuffer, JString, JVec};

use crate::hooks::Tokens;

/// How the completion of a request reaches the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    /// Through the per-handle dispatch queue.
    Queued,
    /// At once, on the thread that pops the output. The output is a
    /// barrier. Only the multi-threaded drop-in uses it, for sync calls.
    Direct,
}

/// Faults of the raw input that the shim found while it read C memory.
///
/// The core reports each one at the stage where C reaches the same input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct InputDefect {
    /// The value buffer is not valid.
    pub bad_value_buffer: bool,
    /// The ACL is NULL or not valid.
    pub bad_acl: bool,
    /// The shim could not allocate while it read the input.
    pub marshal_oom: bool,
}

impl InputDefect {
    /// Returns true when any fault is set.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.bad_value_buffer || self.bad_acl || self.marshal_oom
    }
}

/// A request path as the driver gives it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathIn {
    /// The raw bytes of a C caller, before the first NUL. `None` is a NULL
    /// pointer. The core validates them with the legacy rules.
    Legacy(Option<Vec<u8>>),
    /// A path that the native client already validated.
    Native(JString),
}

/// One operation of a multi request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiOp {
    /// A create. `op_type` is the wire type of the caller: 1, 15, 19 or 21.
    Create {
        /// The wire type.
        op_type: i32,
        /// The path.
        path: PathIn,
        /// The data.
        data: JBuffer,
        /// The ACL.
        acl: JVec<ACL>,
        /// The create mode.
        mode: i32,
        /// The TTL, for the TTL modes.
        ttl: i64,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// A delete (type 2).
    Delete {
        /// The path.
        path: PathIn,
        /// The expected version.
        version: i32,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// A set data (type 5).
    SetData {
        /// The path.
        path: PathIn,
        /// The data.
        data: JBuffer,
        /// The expected version.
        version: i32,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// A version check (type 13).
    Check {
        /// The path.
        path: PathIn,
        /// The expected version.
        version: i32,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// A get data (type 4). Only `MultiRead` accepts it.
    GetData {
        /// The path.
        path: PathIn,
    },
    /// A get children (type 8). Only `MultiRead` accepts it.
    GetChildren {
        /// The path.
        path: PathIn,
    },
    /// An operation of another type. A legacy multi returns
    /// `ZUNIMPLEMENTED` for it.
    Other {
        /// The wire type of the caller.
        op_type: i32,
    },
}

impl MultiOp {
    /// Returns the wire type of the operation.
    #[must_use]
    pub const fn op_type(&self) -> i32 {
        match self {
            Self::Create { op_type, .. } | Self::Other { op_type } => *op_type,
            Self::Delete { .. } => zk_jute::opcode::DELETE,
            Self::SetData { .. } => zk_jute::opcode::SET_DATA,
            Self::Check { .. } => zk_jute::opcode::CHECK,
            Self::GetData { .. } => zk_jute::opcode::GET_DATA,
            Self::GetChildren { .. } => zk_jute::opcode::GET_CHILDREN,
        }
    }
}

/// One write operation of a multi request whose path and data are
/// borrowed.
///
/// `Connection::submit_multi_ref` takes these sub-ops. It encodes each
/// path and each data buffer straight into the owned request body. The
/// borrow ends when that call returns, and the core keeps no view of
/// the caller's bytes. The checks and the encoding are those of the
/// matching [`MultiOp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiOpRef<'a> {
    /// A create. `op_type` is the wire type of the caller: 1, 15, 19 or 21.
    Create {
        /// The wire type.
        op_type: i32,
        /// The client path bytes. `None` is a NULL path.
        path: Option<&'a [u8]>,
        /// The data. `None` is the jute null buffer.
        data: Option<&'a [u8]>,
        /// The ACL.
        acl: JVec<ACL>,
        /// The create mode.
        mode: i32,
        /// The TTL, for the TTL modes.
        ttl: i64,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// A delete (type 2).
    Delete {
        /// The client path bytes. `None` is a NULL path.
        path: Option<&'a [u8]>,
        /// The expected version.
        version: i32,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// A set data (type 5).
    SetData {
        /// The client path bytes. `None` is a NULL path.
        path: Option<&'a [u8]>,
        /// The data. `None` is the jute null buffer.
        data: Option<&'a [u8]>,
        /// The expected version.
        version: i32,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// A version check (type 13).
    Check {
        /// The client path bytes. `None` is a NULL path.
        path: Option<&'a [u8]>,
        /// The expected version.
        version: i32,
        /// The input faults of this operation.
        defect: InputDefect,
    },
    /// An operation of another type. A multi returns `ZUNIMPLEMENTED`
    /// for it.
    Other {
        /// The wire type of the caller.
        op_type: i32,
    },
}

impl MultiOpRef<'_> {
    /// Returns the wire type of the operation.
    #[must_use]
    pub const fn op_type(&self) -> i32 {
        match self {
            Self::Create { op_type, .. } | Self::Other { op_type } => *op_type,
            Self::Delete { .. } => zk_jute::opcode::DELETE,
            Self::SetData { .. } => zk_jute::opcode::SET_DATA,
            Self::Check { .. } => zk_jute::opcode::CHECK,
        }
    }
}

/// One application operation. `W` is the watcher token type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op<W> {
    /// `create`, `create2`, `createContainer` or `createTTL`.
    Create {
        /// The path.
        path: PathIn,
        /// The data.
        data: JBuffer,
        /// The ACL.
        acl: JVec<ACL>,
        /// The create mode.
        mode: i32,
        /// The TTL. Non-TTL modes need a negative value.
        ttl: i64,
        /// True for the `Create2` reply shape (path and `Stat`).
        create2: bool,
    },
    /// `delete`.
    Delete {
        /// The path.
        path: PathIn,
        /// The expected version.
        version: i32,
    },
    /// `exists`, with an optional watch.
    Exists {
        /// The path.
        path: PathIn,
        /// The watcher to arm.
        watch: Option<W>,
    },
    /// `getData`, with an optional watch.
    GetData {
        /// The path.
        path: PathIn,
        /// The watcher to arm.
        watch: Option<W>,
    },
    /// `getConfig`. The path is `/zookeeper/config` with no chroot.
    GetConfig {
        /// The watcher to arm.
        watch: Option<W>,
    },
    /// `setData`.
    SetData {
        /// The path.
        path: PathIn,
        /// The data.
        data: JBuffer,
        /// The expected version.
        version: i32,
    },
    /// `getACL`.
    GetAcl {
        /// The path.
        path: PathIn,
    },
    /// `setACL`.
    SetAcl {
        /// The path.
        path: PathIn,
        /// The ACL.
        acl: JVec<ACL>,
        /// The expected ACL version.
        version: i32,
    },
    /// `getChildren` or `getChildren2`, with an optional watch.
    GetChildren {
        /// The path.
        path: PathIn,
        /// The watcher to arm.
        watch: Option<W>,
        /// True for the `getChildren2` reply shape.
        with_stat: bool,
    },
    /// `sync`.
    Sync {
        /// The path.
        path: PathIn,
    },
    /// `reconfig`.
    Reconfig {
        /// The joining servers.
        joining: JString,
        /// The leaving servers.
        leaving: JString,
        /// The new member list.
        members: JString,
        /// The expected config version.
        version: i64,
    },
    /// `multi`.
    Multi {
        /// The operations, in order.
        ops: Vec<MultiOp>,
    },
    /// Remove watches, local or on the server.
    RemoveWatches {
        /// The path.
        path: PathIn,
        /// The watch type: 1 child, 2 data, 3 any; 4 and 5 natively.
        wtype: i32,
        /// The watcher, or `None` for every watcher.
        watcher: Option<W>,
        /// True to remove the local registration only.
        local: bool,
        /// True for `zoo_remove_all_watches`.
        all: bool,
    },
    /// `addWatch` (native only).
    AddWatch {
        /// The path.
        path: PathIn,
        /// 0 persistent, 1 persistent recursive.
        mode: i32,
        /// The watcher.
        watch: W,
    },
    /// `multiRead` (native only).
    MultiRead {
        /// The read operations, in order.
        ops: Vec<MultiOp>,
    },
    /// `getEphemerals` (native only).
    GetEphemerals {
        /// The path prefix.
        prefix: PathIn,
    },
    /// `getAllChildrenNumber` (native only).
    GetAllChildrenNumber {
        /// The path.
        path: PathIn,
    },
    /// `whoAmI` (native only).
    WhoAmI,
    /// `setACL` that gives the stat of the reply (native only). The
    /// wire request is that of [`Op::SetAcl`]. Only the reply shape is
    /// different: `Stat`, not `Void`.
    SetAclStat {
        /// The path.
        path: PathIn,
        /// The ACL.
        acl: JVec<ACL>,
        /// The expected ACL version.
        version: i32,
    },
}

impl<W> Op<W> {
    /// Returns true for the operations that need `Compat::native_ops`.
    #[must_use]
    pub const fn is_native_only(&self) -> bool {
        matches!(
            self,
            Self::AddWatch { .. }
                | Self::MultiRead { .. }
                | Self::GetEphemerals { .. }
                | Self::GetAllChildrenNumber { .. }
                | Self::WhoAmI
                | Self::SetAclStat { .. }
        )
    }
}

/// One request: the operation, its completion token and its route.
pub struct Request<T: Tokens> {
    /// The operation.
    pub op: Op<T::Watcher>,
    /// The completion. It leaves the core exactly once.
    pub token: T::Completion,
    /// The delivery route.
    pub route: Route,
    /// The input faults of the operation.
    pub defect: InputDefect,
}

/// The success of `submit`.
pub enum Submitted<T: Tokens> {
    /// The request is queued with this xid.
    Queued {
        /// The xid.
        xid: i32,
    },
    /// A local watch removal completed at once. The caller completes the
    /// token with `ZOK`.
    Local(T::Completion),
}

/// The stage of a failed `submit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Argument and state checks. The st driver does not flush.
    Validate,
    /// Serialization and queueing. The st driver flushes.
    Enqueue,
    /// A native-only operation with `native_ops` off (`ZUNIMPLEMENTED`).
    NotEnabled,
    /// The `max_pending` limit (`ZTHROTTLEDOP`).
    TooManyPending,
}

/// The failure of `submit`. The token goes back to the caller.
pub struct SubmitError<T: Tokens> {
    /// The stage.
    pub stage: Stage,
    /// The final legacy return value.
    pub code: i32,
    /// The completion token. The core never delivers it.
    pub token: T::Completion,
}

/// The failure of `add_auth`. The token goes back to the caller.
pub struct AddAuthError<T: Tokens> {
    /// The legacy return value.
    pub code: i32,
    /// The completion token. The core never delivers it.
    pub done: Option<T::Auth>,
}

impl<T: Tokens> fmt::Debug for Request<T>
where
    T::Watcher: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("op", &self.op)
            .field("route", &self.route)
            .field("defect", &self.defect)
            .finish_non_exhaustive()
    }
}

impl<T: Tokens> fmt::Debug for Submitted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued { xid } => f.debug_struct("Queued").field("xid", xid).finish(),
            Self::Local(_) => f.write_str("Local(..)"),
        }
    }
}

impl<T: Tokens> fmt::Debug for SubmitError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmitError")
            .field("stage", &self.stage)
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl<T: Tokens> fmt::Debug for AddAuthError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddAuthError")
            .field("code", &self.code)
            .field("done", &self.done.is_some())
            .finish()
    }
}

/// The largest TTL in milliseconds: `0xFF_FFFF_FFFF`.
pub const MAX_TTL: i64 = 0xFF_FFFF_FFFF;

/// Checks the TTL rule of a create. It is the first submit check.
///
/// The TTL modes (5 and 6) need a TTL in `1..=MAX_TTL`. The other modes
/// need a negative TTL. The shim calls it before its NULL handle check.
///
/// # Errors
///
/// Returns `ZBADARGUMENTS` when the rule fails.
pub fn check_ttl(mode: i32, ttl: i64) -> Result<(), i32> {
    let ok = if crate::legacy::path::is_ttl(mode) {
        (1..=MAX_TTL).contains(&ttl)
    } else {
        ttl < 0
    };
    if ok {
        Ok(())
    } else {
        Err(zk_jute::rc::ZBADARGUMENTS)
    }
}
