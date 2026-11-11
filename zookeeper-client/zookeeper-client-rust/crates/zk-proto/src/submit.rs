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

//! Request validation, serialization and queueing.
//!
//! `submit` runs its checks in C order. Then it draws
//! an xid, encodes the frame, appends the frame to `tx` and appends the
//! pending entry to the FIFO, in one step.

use std::borrow::Cow;

use zk_jute::data::ACL;
use zk_jute::multi::{self, MultiKind};
use zk_jute::proto::{
    AddWatchRequest, CheckVersionRequest, CheckWatchesRequest, CreateRequest, CreateTTLRequest,
    DeleteRequest, ExistsRequest, GetACLRequest, GetAllChildrenNumberRequest, GetChildren2Request,
    GetChildrenRequest, GetDataRequest, GetEphemeralsRequest, ReconfigRequest,
    RemoveWatchesRequest, SetACLRequest, SetDataRequest, SyncRequest,
};
use zk_jute::rc::{
    ZBADARGUMENTS, ZCLOSING, ZINVALIDSTATE, ZMARSHALLINGERROR, ZTHROTTLEDOP, ZUNIMPLEMENTED,
};
use zk_jute::{JString, JVec, Record, opcode};

use crate::compat::{ChrootPolicy, CloseMode};
use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::legacy::chroot::{CONFIG_NODE, join_component, join_legacy};
use crate::legacy::path::{is_sequence, is_ttl, validate_path_strict};
use crate::log::{LogArg, LogRecord, LogSite};
use crate::request::{
    InputDefect, MultiOp, MultiOpRef, Op, PathIn, Request, Stage, SubmitError, Submitted, check_ttl,
};
use crate::requests::{
    FrameKind, OutFrame, Pending, REQUEST_HEAD_LEN, Shape, Unwatch, WatchKind, WatchReg,
};
use crate::time::Millis;

/// An operation that passed validation and has its encoded body.
pub(crate) struct Prepared<W> {
    /// The wire operation type.
    pub(crate) op_type: i32,
    /// The encoded request record. When `framed` is true, the record
    /// follows [`REQUEST_HEAD_LEN`] placeholder bytes for the length
    /// prefix and the request header. Else it has no head.
    pub(crate) body: Vec<u8>,
    /// True when `body` starts with the placeholder head.
    pub(crate) framed: bool,
    /// The reply shape.
    pub(crate) shape: Shape,
    /// The watch to arm on the reply.
    pub(crate) watch: Option<WatchReg<W>>,
    /// The local removal to apply on a successful reply.
    pub(crate) unwatch: Option<Unwatch<W>>,
    /// The DEBUG "Sending request" record of the op, if the filter
    /// enables it. `submit` pushes it after the frame is queued.
    pub(crate) log: Option<LogRecord>,
}

/// The result of the validation stage of one operation.
pub(crate) enum Checked<W> {
    /// The operation goes to the server.
    Send(Prepared<W>),
    /// A local watch removal completed at once.
    Local,
}

/// The borrowed input of one submit.
///
/// The core encodes the borrowed bytes straight into the owned request
/// body. Thus the caller makes no owned copy first. The borrow ends when
/// the submit returns.
#[derive(Clone, Copy)]
pub(crate) enum Input<'b> {
    /// No borrowed input. The op holds all of its fields.
    Owned,
    /// The data of a create or a set data.
    Data(&'b [u8]),
    /// The sub-ops of a write multi.
    Multi(&'b [MultiOpRef<'b>]),
}

impl<'b> Input<'b> {
    /// The borrowed data of a create or a set data, if any.
    fn data(self) -> Option<&'b [u8]> {
        match self {
            Self::Data(d) => Some(d),
            Self::Owned | Self::Multi(_) => None,
        }
    }
}

/// The wire type, the reply shape and the "Sending request" log site of
/// an operation. The native-only operations have no log site.
type Spec = (i32, Shape, Option<LogSite>);

/// The code and the stage of a failed check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rejected {
    /// The stage.
    pub(crate) stage: Stage,
    /// The legacy return value.
    pub(crate) code: i32,
}

impl<T: Tokens> Connection<T> {
    /// Validates, encodes and queues one request.
    ///
    /// Contract:
    /// - A native-only op with `compat.native_ops == false` fails with
    ///   `Stage::NotEnabled` and `ZUNIMPLEMENTED`.
    /// - With `cfg.max_pending == Some(n)` and `n` entries in the FIFO, it
    ///   fails with `Stage::TooManyPending` and `ZTHROTTLEDOP`.
    /// - Under `close_mode == Drain`, after `begin_close`, it fails with
    ///   `Stage::Validate` and `ZCLOSING`.
    /// - Then `check_op` runs. A failure returns the token in
    ///   `SubmitError`, and the core never delivers it.
    /// - `Checked::Local` returns `Submitted::Local(token)`.
    /// - `Checked::Send` draws the xid, makes the frame with
    ///   `body_frame`, pushes it at the tail of `tx`, pushes the
    ///   `Pending` entry at the tail of the FIFO, then pushes the
    ///   "Sending request" log output. It returns `Submitted::Queued`.
    /// - A failed submit draws no xid and changes no queue.
    ///
    /// # Errors
    ///
    /// Returns the stage, the legacy code and the token.
    pub fn submit(&mut self, req: Request<T>, now: Millis) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_with_data(req, None, now)
    }

    /// Validates, encodes and queues one request whose data is borrowed.
    ///
    /// Contract:
    /// - With `Some(bytes)`, a create or a set data encodes `bytes` as its
    ///   data. The data field of the op is not used, and the caller gives
    ///   `JBuffer::Null` there.
    /// - The bytes go straight into the owned request frame. Thus the
    ///   caller makes no owned copy of the data before the call.
    /// - With `None`, or for another op, the call is the same as
    ///   [`Self::submit`].
    /// - The gates, the checks and their order are those of
    ///   [`Self::submit`]. The borrow ends when the call returns.
    ///
    /// # Errors
    ///
    /// Returns the stage, the legacy code and the token.
    pub fn submit_with_data(
        &mut self,
        req: Request<T>,
        data: Option<&[u8]>,
        now: Millis,
    ) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_input(req, data.map_or(Input::Owned, Input::Data), now)
    }

    /// Validates, encodes and queues one write multi whose sub-ops are
    /// borrowed.
    ///
    /// Contract:
    /// - With an `Op::Multi`, `ops` gives the sub-ops. The sub-ops of the
    ///   op are not used, and the caller gives an empty vector there.
    /// - Each path and each data buffer goes straight into the owned
    ///   request body. Thus the caller makes no owned copy of them
    ///   before the call.
    /// - The scan, the checks, the codes and the log output are those of
    ///   the same sub-ops as [`MultiOp`] values.
    /// - For another op, `ops` is not used, and the call is the same as
    ///   [`Self::submit`].
    /// - The gates and their order are those of [`Self::submit`]. The
    ///   borrow ends when the call returns.
    ///
    /// # Errors
    ///
    /// Returns the stage, the legacy code and the token.
    pub fn submit_multi_ref(
        &mut self,
        req: Request<T>,
        ops: &[MultiOpRef<'_>],
        now: Millis,
    ) -> Result<Submitted<T>, SubmitError<T>> {
        self.submit_input(req, Input::Multi(ops), now)
    }

    /// Runs the gates, the checks and the queue step of one submit with
    /// its borrowed input.
    fn submit_input(
        &mut self,
        req: Request<T>,
        input: Input<'_>,
        now: Millis,
    ) -> Result<Submitted<T>, SubmitError<T>> {
        // Validation and queueing read no clock. The parameter keeps the
        // driver API uniform with the other inputs.
        let _ = now;
        let Request {
            op,
            token,
            route,
            defect,
        } = req;
        let gate = if op.is_native_only() && !self.compat.native_ops {
            Some((Stage::NotEnabled, ZUNIMPLEMENTED))
        } else if self
            .cfg
            .max_pending
            .is_some_and(|n| self.requests.fifo.len() >= n)
        {
            Some((Stage::TooManyPending, ZTHROTTLEDOP))
        } else if self.compat.close_mode == CloseMode::Drain && self.close.closing {
            Some((Stage::Validate, ZCLOSING))
        } else {
            None
        };
        if let Some((stage, code)) = gate {
            return Err(SubmitError { stage, code, token });
        }
        let prepared = match self.check_op(op, defect, input) {
            Ok(Checked::Send(p)) => p,
            Ok(Checked::Local) => return Ok(Submitted::Local(token)),
            Err(r) => {
                return Err(SubmitError {
                    stage: r.stage,
                    code: r.code,
                    token,
                });
            }
        };
        // The xid is drawn only here, so a failed submit draws none. The
        // frame and the FIFO entry go in together, so wire order is FIFO
        // order.
        let xid = self.requests.next_xid();
        let frame = Self::body_frame(xid, prepared.op_type, prepared.body, prepared.framed);
        self.requests
            .push_tail(OutFrame::plain(FrameKind::Request { xid }, frame));
        self.requests.push_pending(Pending {
            xid,
            shape: prepared.shape,
            route,
            token,
            watch: prepared.watch,
            unwatch: prepared.unwatch,
            written: false,
        });
        // `check_op` makes the record before the xid exists. Every send
        // site has the xid as its first argument.
        let log = prepared.log.map(|mut r| {
            if let Some(first) = r.args.first_mut() {
                *first = LogArg::I64(i64::from(xid));
            }
            r
        });
        self.out.push_log(log);
        Ok(Submitted::Queued { xid })
    }

    /// Runs the submit checks for one operation and encodes it.
    ///
    /// Contract:
    /// - The rows run in table order: TTL, path, state, multi scan,
    ///   remove-watches, serialization. The first failing row wins.
    /// - Row 4 failures other than `ZUNIMPLEMENTED`, and row 6 failures,
    ///   are `Stage::Enqueue` with `ZMARSHALLINGERROR`. The others are
    ///   `Stage::Validate`.
    /// - A local remove-watches removes the registration through
    ///   `check_remove_watches` and returns `Checked::Local`.
    /// - The shape follows the op.
    /// - It changes no queue. It may push log outputs (the
    ///   "Unimplemented sub-op" site).
    /// - A borrowed `input` replaces the data of a create or a set data,
    ///   or the sub-ops of a write multi. [`Self::submit_with_data`] and
    ///   [`Self::submit_multi_ref`] tell the rules.
    pub(crate) fn check_op(
        &mut self,
        op: Op<T::Watcher>,
        defect: InputDefect,
        input: Input<'_>,
    ) -> Result<Checked<T::Watcher>, Rejected> {
        // Each helper runs rows 1 to 5 and encodes the body. The input and
        // close checks of row 6 run here, after every earlier row. One
        // helper for each operation keeps each stack frame small.
        let prepared = match op {
            Op::Create {
                path,
                data: own,
                acl,
                mode,
                ttl,
                create2,
            } => self.submit_create(
                path,
                input.data().or(own.as_bytes()),
                acl,
                mode,
                ttl,
                create2,
            ),
            Op::Delete { path, version } => self.submit_delete(path, version),
            Op::Exists { path, watch } => self.submit_exists(path, watch),
            Op::GetData { path, watch } => self.submit_get_data(path, watch),
            Op::GetConfig { watch } => self.submit_get_config(watch),
            Op::SetData {
                path,
                data: own,
                version,
            } => self.submit_set_data(path, input.data().or(own.as_bytes()), version),
            Op::GetAcl { path } => self.submit_get_acl(path),
            Op::SetAcl { path, acl, version } => {
                self.submit_set_acl(path, acl, version, Shape::Void)
            }
            Op::SetAclStat { path, acl, version } => {
                self.submit_set_acl(path, acl, version, Shape::Stat)
            }
            Op::GetChildren {
                path,
                watch,
                with_stat,
            } => self.submit_get_children(path, watch, with_stat),
            Op::Sync { path } => self.submit_sync(path),
            Op::Reconfig {
                joining,
                leaving,
                members,
                version,
            } => self.submit_reconfig(joining, leaving, members, version),
            Op::Multi { ops } => self.submit_write_multi(ops, input),
            Op::RemoveWatches {
                path,
                wtype,
                watcher,
                local,
                all,
            } => match self.submit_remove_watches(path, wtype, watcher, local, all)? {
                Some(p) => Ok(p),
                None => return Ok(Checked::Local),
            },
            Op::AddWatch { path, mode, watch } => self.submit_add_watch(path, mode, watch),
            Op::MultiRead { ops } => self.submit_multi(ops, true),
            Op::GetEphemerals { prefix } => self.submit_get_ephemerals(prefix),
            Op::GetAllChildrenNumber { path } => self.submit_children_count(path),
            Op::WhoAmI => self.submit_who_am_i(),
        }?;
        if defect.any() || self.close.closing {
            return Err(MARSHAL);
        }
        Ok(Checked::Send(prepared))
    }

    /// Prepares a create. Row 1 checks the TTL, and row 2 checks the path
    /// with the create mode.
    fn submit_create(
        &self,
        path: PathIn,
        data: Option<&[u8]>,
        acl: JVec<ACL>,
        mode: i32,
        ttl: i64,
        create2: bool,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        check_ttl(mode, ttl).map_err(validate)?;
        let (default, shape, site) = if create2 {
            (opcode::CREATE2, Shape::PathStat, LogSite::SendCreate2)
        } else {
            (opcode::CREATE, Shape::Path, LogSite::SendCreate)
        };
        let log = self.submit_path_log(site, &path);
        let server = self.server_path_owned(path, mode).map_err(validate)?;
        self.submit_check_state()?;
        let spec = (create_op_type(mode, default), shape);
        let tail = if is_ttl(mode) {
            DataTail::CreateTtl {
                acl: &acl,
                flags: mode,
                ttl,
            }
        } else {
            DataTail::Create {
                acl: &acl,
                flags: mode,
            }
        };
        Self::submit_data(server, log, spec, data, tail)
    }

    /// Prepares a delete.
    fn submit_delete(&self, path: PathIn, version: i32) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::DELETE, Shape::Void, Some(LogSite::SendDelete));
        self.submit_path_op(path, spec, None, |path, _| DeleteRequest { path, version })
    }

    /// Prepares an exists. The watch registers in the data table. The
    /// reply moves it to the exist table on `ZNONODE`.
    fn submit_exists(
        &self,
        path: PathIn,
        watch: Option<T::Watcher>,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::EXISTS, Shape::Stat, Some(LogSite::SendExists));
        let watch = Some(WatchKind::Exist).zip(watch);
        self.submit_path_op(path, spec, watch, |path, watch| ExistsRequest {
            path,
            watch,
        })
    }

    /// Prepares a get data.
    fn submit_get_data(
        &self,
        path: PathIn,
        watch: Option<T::Watcher>,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::GET_DATA, Shape::Data, Some(LogSite::SendGetData));
        let watch = Some(WatchKind::Data).zip(watch);
        self.submit_path_op(path, spec, watch, |path, watch| GetDataRequest {
            path,
            watch,
        })
    }

    /// Prepares a set data. The checks are those of
    /// [`Self::submit_path_op`].
    fn submit_set_data(
        &self,
        path: PathIn,
        data: Option<&[u8]>,
        version: i32,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let log = self.submit_path_log(LogSite::SendSetData, &path);
        let server = self.submit_path_state(path)?;
        let spec = (opcode::SET_DATA, Shape::Stat);
        Self::submit_data(server, log, spec, data, DataTail::SetData { version })
    }

    /// Prepares a get ACL.
    fn submit_get_acl(&self, path: PathIn) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::GET_ACL, Shape::Acl, Some(LogSite::SendGetAcl));
        self.submit_path_op(path, spec, None, |path, _| GetACLRequest { path })
    }

    /// Prepares a set ACL. A bad ACL is an input defect of row 6.
    ///
    /// C gives no stat to its setACL completion, so `Op::SetAcl` skips
    /// the body (`Shape::Void`). The native `Op::SetAclStat` reads the
    /// stat of the reply (`Shape::Stat`).
    fn submit_set_acl(
        &self,
        path: PathIn,
        acl: JVec<ACL>,
        version: i32,
        shape: Shape,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::SET_ACL, shape, Some(LogSite::SendSetAcl));
        self.submit_path_op(path, spec, None, |path, _| SetACLRequest {
            path,
            acl,
            version,
        })
    }

    /// Prepares a sync.
    fn submit_sync(&self, path: PathIn) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::SYNC, Shape::Path, Some(LogSite::SendSync));
        self.submit_path_op(path, spec, None, |path, _| SyncRequest { path })
    }

    /// Prepares a get ephemerals (native only). The prefix takes the
    /// chroot like any other path. The native-only operations have no
    /// legacy log site.
    fn submit_get_ephemerals(&self, prefix: PathIn) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::GET_EPHEMERALS, Shape::Ephemerals, None);
        self.submit_path_op(prefix, spec, None, |prefix_path, _| GetEphemeralsRequest {
            prefix_path,
        })
    }

    /// Prepares a get all children number (native only).
    fn submit_children_count(&self, path: PathIn) -> Result<Prepared<T::Watcher>, Rejected> {
        let spec = (opcode::GET_ALL_CHILDREN_NUMBER, Shape::ChildrenCount, None);
        self.submit_path_op(path, spec, None, |path, _| GetAllChildrenNumberRequest {
            path,
        })
    }

    /// Prepares a who am I (native only). The request has no body.
    fn submit_who_am_i(&self) -> Result<Prepared<T::Watcher>, Rejected> {
        self.submit_check_state()?;
        Ok(Prepared {
            op_type: opcode::WHO_AM_I,
            body: Vec::new(),
            framed: false,
            shape: Shape::WhoAmI,
            watch: None,
            unwatch: None,
            log: None,
        })
    }

    /// Prepares a get config. The config node is a server path, so the
    /// chroot never applies, and the path check always passes.
    fn submit_get_config(
        &self,
        watch: Option<T::Watcher>,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        self.submit_check_state()?;
        let log = self.log.record(LogSite::SendGetConfig, || {
            vec![
                LogArg::I64(0),
                crate::log::str_arg(CONFIG_NODE),
                LogArg::Endpoint(self.current_server()),
            ]
        });
        self.submit_encoded(
            CONFIG_NODE.to_vec(),
            log,
            (opcode::GET_DATA, Shape::Data),
            Some(WatchKind::Data).zip(watch),
            |path, watch| GetDataRequest { path, watch },
        )
    }

    /// Prepares a get children, with or without the `Stat`.
    fn submit_get_children(
        &self,
        path: PathIn,
        watch: Option<T::Watcher>,
        with_stat: bool,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let watch = Some(WatchKind::Child).zip(watch);
        if with_stat {
            self.submit_path_op(
                path,
                (
                    opcode::GET_CHILDREN2,
                    Shape::Children2,
                    Some(LogSite::SendGetChildren2),
                ),
                watch,
                |path, watch| GetChildren2Request { path, watch },
            )
        } else {
            self.submit_path_op(
                path,
                (
                    opcode::GET_CHILDREN,
                    Shape::Children,
                    Some(LogSite::SendGetChildren),
                ),
                watch,
                |path, watch| GetChildrenRequest { path, watch },
            )
        }
    }

    /// Prepares a reconfig. It has no path, so only row 3 runs.
    fn submit_reconfig(
        &self,
        joining: JString,
        leaving: JString,
        members: JString,
        version: i64,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        self.submit_check_state()?;
        let body = encode(&ReconfigRequest {
            joining_servers: joining,
            leaving_servers: leaving,
            new_members: members,
            cur_config_id: version,
        })?;
        Ok(Prepared {
            op_type: opcode::RECONFIG,
            body,
            framed: false,
            shape: Shape::Data,
            watch: None,
            unwatch: None,
            log: self.log.record(LogSite::SendReconfig, || {
                vec![LogArg::I64(0), LogArg::Endpoint(self.current_server())]
            }),
        })
    }

    /// Prepares a write multi. Borrowed sub-ops replace the owned sub-ops
    /// of the op, as [`Self::submit_multi_ref`] tells.
    fn submit_write_multi(
        &mut self,
        ops: Vec<MultiOp>,
        input: Input<'_>,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        match input {
            Input::Multi(refs) => self.submit_multi(refs, false),
            Input::Owned | Input::Data(_) => self.submit_multi(ops, false),
        }
    }

    /// Prepares a multi or a multi read. Row 3 does not run here. The
    /// encoder checks the state after its scan instead.
    fn submit_multi<I>(&mut self, ops: I, read: bool) -> Result<Prepared<T::Watcher>, Rejected>
    where
        I: IntoIterator<Item: SubOp, IntoIter: ExactSizeIterator>,
    {
        let ops = ops.into_iter();
        let count = i64::try_from(ops.len()).unwrap_or(i64::MAX);
        let (body, op_types) = self.encode_multi(ops, read)?;
        let (op_type, kind, log) = if read {
            // No legacy site exists for a multi read.
            (opcode::MULTI_READ, MultiKind::MultiRead, None)
        } else {
            let log = self.log.record(LogSite::SendMulti, || {
                vec![
                    LogArg::I64(0),
                    LogArg::I64(count),
                    LogArg::Endpoint(self.current_server()),
                ]
            });
            (opcode::MULTI, MultiKind::Multi, log)
        };
        Ok(Prepared {
            op_type,
            body,
            framed: false,
            shape: Shape::Multi { op_types, kind },
            watch: None,
            unwatch: None,
            log,
        })
    }

    /// Prepares a remove watches. It returns `None` when a local removal
    /// completed (row 5). A local removal touches no server, so row 3 does
    /// not run for it.
    fn submit_remove_watches(
        &mut self,
        path: PathIn,
        wtype: i32,
        watcher: Option<T::Watcher>,
        local: bool,
        all: bool,
    ) -> Result<Option<Prepared<T::Watcher>>, Rejected> {
        let server = self.server_path(&path, 0).map_err(validate)?;
        if !local {
            self.submit_check_state()?;
        }
        // A native removal of every watcher goes to the server with no
        // local check. The removal hint of `detach_watcher` uses it after
        // the last local user is gone, so no local watcher remains. The
        // server then gives the result.
        let server_only = self.compat.native_ops && !local && all && watcher.is_none();
        if !server_only {
            self.check_remove_watches(&server, wtype, watcher.as_ref(), local)
                .map_err(validate)?;
        }
        if local {
            return Ok(None);
        }
        let req_path = JString::Bytes(server.clone());
        let (op_type, body) = if all {
            let body = encode(&RemoveWatchesRequest {
                path: req_path,
                r#type: wtype,
            })?;
            (opcode::REMOVE_WATCHES, body)
        } else {
            let body = encode(&CheckWatchesRequest {
                path: req_path,
                r#type: wtype,
            })?;
            (opcode::CHECK_WATCHES, body)
        };
        Ok(Some(Prepared {
            op_type,
            body,
            framed: false,
            shape: Shape::Void,
            watch: None,
            unwatch: Some(Unwatch {
                path: server,
                wtype,
                watcher,
            }),
            log: self.submit_path_log(LogSite::SendRemoveWatches, &path),
        }))
    }

    /// Prepares an add watch (native only). Mode 0 is persistent and mode 1
    /// is persistent recursive. Any other mode is a bad argument.
    fn submit_add_watch(
        &self,
        path: PathIn,
        mode: i32,
        watch: T::Watcher,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let server = self.submit_path_state(path)?;
        let kind = match mode {
            0 => WatchKind::Persistent,
            1 => WatchKind::PersistentRecursive,
            _ => return Err(validate(ZBADARGUMENTS)),
        };
        self.submit_encoded(
            server,
            None,
            (opcode::ADD_WATCH, Shape::Void),
            Some((kind, watch)),
            |path, _| AddWatchRequest { path, mode },
        )
    }

    /// Prepares an operation on a plain path. The path checks of rows 2
    /// and 3 run first, and then the request gets its encoding.
    fn submit_path_op<R: Record>(
        &self,
        path: PathIn,
        (op_type, shape, site): Spec,
        watch: Option<(WatchKind, T::Watcher)>,
        make: impl FnOnce(JString, bool) -> R,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        // The record shows the client path. Thus it comes before the path
        // moves into the request. A failed check drops the record, and no
        // log output occurs.
        let log = site.and_then(|site| self.submit_path_log(site, &path));
        let server = self.submit_path_state(path)?;
        self.submit_encoded(server, log, (op_type, shape), watch, make)
    }

    /// Encodes the request record of an operation that passed its checks.
    ///
    /// `make` builds the record from the server path and the watch flag.
    /// A watch registers on the server path, as C
    /// `create_watcher_registration` does. The caller makes the "Sending
    /// request" record `log` before the client path moves into `server`.
    fn submit_encoded<R: Record>(
        &self,
        server: Vec<u8>,
        log: Option<LogRecord>,
        (op_type, shape): (i32, Shape),
        watch: Option<(WatchKind, T::Watcher)>,
        make: impl FnOnce(JString, bool) -> R,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let watch = watch.map(|(kind, watcher)| WatchReg {
            kind,
            path: server.clone(),
            watcher,
        });
        let body = encode_framed(&make(JString::Bytes(server), watch.is_some()))?;
        Ok(Prepared {
            op_type,
            body,
            framed: true,
            shape,
            watch,
            unwatch: None,
            log,
        })
    }

    /// Encodes the record of a create or a set data that passed its
    /// checks. The data goes from the borrowed slice straight into the
    /// request frame. These ops register no watch.
    fn submit_data(
        server: Vec<u8>,
        log: Option<LogRecord>,
        (op_type, shape): (i32, Shape),
        data: Option<&[u8]>,
        tail: DataTail<'_>,
    ) -> Result<Prepared<T::Watcher>, Rejected> {
        let record = DataRecord {
            path: Some(&server),
            data,
            tail,
        };
        let body = framed_with(record.encoded_len(), |out| record.encode(out))?;
        Ok(Prepared {
            op_type,
            body,
            framed: true,
            shape,
            watch: None,
            unwatch: None,
            log,
        })
    }

    /// Joins the chroot to a request path and checks it.
    ///
    /// Contract:
    /// - `PathIn::Legacy(None)` fails with `ZBADARGUMENTS`.
    /// - Under `ChrootPolicy::LegacyConcatNoEscape` it uses
    ///   `legacy::chroot::join_legacy`, which also validates with `mode`.
    /// - Under `ChrootPolicy::Component` it uses
    ///   `legacy::chroot::join_component` on a validated native path.
    /// - It returns the server path bytes.
    pub(crate) fn server_path(&self, path: &PathIn, mode: i32) -> Result<Vec<u8>, i32> {
        self.server_path_cow(path, mode).map(Cow::into_owned)
    }

    /// Gives the server path of an owned request path.
    ///
    /// The checks are the same as in [`Self::server_path`]. When the join
    /// does not change the path, the result is the buffer of `path`. Thus
    /// the function makes no copy.
    fn server_path_owned(&self, path: PathIn, mode: i32) -> Result<Vec<u8>, i32> {
        let joined = match self.server_path_cow(&path, mode)? {
            Cow::Owned(v) => Some(v),
            Cow::Borrowed(_) => None,
        };
        if let Some(v) = joined {
            return Ok(v);
        }
        match path {
            PathIn::Legacy(Some(bytes)) | PathIn::Native(JString::Bytes(bytes)) => Ok(bytes),
            PathIn::Legacy(None) | PathIn::Native(JString::Null) => Err(ZBADARGUMENTS),
        }
    }

    /// Runs the checks and the join of [`Self::server_path`]. A borrowed
    /// result is the whole request path with no change.
    fn server_path_cow<'p>(&self, path: &'p PathIn, mode: i32) -> Result<Cow<'p, [u8]>, i32> {
        let raw: &[u8] = match path {
            PathIn::Legacy(Some(bytes)) => bytes,
            PathIn::Legacy(None) => return Err(ZBADARGUMENTS),
            PathIn::Native(s) => s.as_bytes().ok_or(ZBADARGUMENTS)?,
        };
        self.server_path_raw(raw, mode)
    }

    /// Runs the checks and the join of [`Self::server_path`] on the bytes
    /// of a client path. A borrowed result is `raw` with no change.
    fn server_path_raw<'p>(&self, raw: &'p [u8], mode: i32) -> Result<Cow<'p, [u8]>, i32> {
        let chroot = self.cfg.chroot.as_ref().and_then(JString::as_bytes);
        match self.compat.chroot {
            ChrootPolicy::LegacyConcatNoEscape => {
                join_legacy(chroot, raw, mode).map_err(|e| e.rc())
            }
            ChrootPolicy::Component => join_native(chroot, raw, mode),
        }
    }

    /// Encodes the sub-operations of a multi or multiRead body.
    ///
    /// Contract:
    /// - It scans `ops` in order. A type outside the allowed set returns
    ///   `ZUNIMPLEMENTED` at once and logs the `MultiUnimplemented` site.
    ///   The legacy set is {1, 19, 2, 5, 13}; native adds 15 and 21.
    /// - Any other path, state or defect failure of a sub-op gives
    ///   `Stage::Enqueue` with `ZMARSHALLINGERROR`, after the scan.
    /// - An unrecoverable state gives the same error also when `ops` is
    ///   empty. Legacy queues an empty multi that no reply completes, so
    ///   a sync caller waits forever (spec "Defined Results in
    ///   Synchronous Multi-Operations").
    /// - It returns the body and the wire types in request order.
    /// - Owned and borrowed sub-ops share this scan, so both get the same
    ///   checks in the same order.
    pub(crate) fn encode_multi<I>(
        &mut self,
        ops: I,
        read: bool,
    ) -> Result<(Vec<u8>, Vec<i32>), Rejected>
    where
        I: IntoIterator<Item: SubOp, IntoIter: ExactSizeIterator>,
    {
        let ops = ops.into_iter();
        let mut types: Vec<i32> = Vec::new();
        if types.try_reserve_exact(ops.len()).is_err() {
            return Err(MARSHAL);
        }
        let mut body = Vec::new();
        // C keeps the first failure and continues the scan, so a later
        // type outside the allowed set still wins (row 4).
        let mut failed = false;
        for op in ops {
            let op_type = op.op_type();
            if !op.allowed(self, read) {
                self.emit_log(LogSite::MultiUnimplemented, || {
                    vec![LogArg::I64(i64::from(op_type))]
                });
                return Err(validate(ZUNIMPLEMENTED));
            }
            types.push(op_type);
            if !failed && !op.append(self, &mut body) {
                failed = true;
            }
        }
        // With ops, the scan already gave `failed` for this state.
        if failed
            || self.core.state.is_unrecoverable()
            || body.try_reserve_exact(MULTI_HEADER_LEN).is_err()
        {
            return Err(MARSHAL);
        }
        multi::encode_end(&mut body);
        Ok((body, types))
    }

    /// Returns true when the multi scan accepts the operation. A write
    /// multi takes the write types of the profile. A read multi takes
    /// get data and get children only.
    fn submit_multi_allowed(&self, op: &MultiOp, read: bool) -> bool {
        match op {
            MultiOp::Create { op_type, .. } => !read && self.multi_create_allowed(*op_type),
            MultiOp::Delete { .. } | MultiOp::SetData { .. } | MultiOp::Check { .. } => !read,
            MultiOp::GetData { .. } | MultiOp::GetChildren { .. } => read,
            MultiOp::Other { .. } => false,
        }
    }

    /// Returns true when the multi scan accepts a borrowed operation. The
    /// rules are those of [`Self::submit_multi_allowed`]. A borrowed
    /// operation is always a write.
    fn multi_ref_allowed(&self, op: &MultiOpRef<'_>, read: bool) -> bool {
        !read
            && match op {
                MultiOpRef::Create { op_type, .. } => self.multi_create_allowed(*op_type),
                MultiOpRef::Delete { .. }
                | MultiOpRef::SetData { .. }
                | MultiOpRef::Check { .. } => true,
                MultiOpRef::Other { .. } => false,
            }
    }

    /// Returns true when a write multi takes a create of this wire type.
    /// The native profile adds create2 and the TTL create.
    fn multi_create_allowed(&self, op_type: i32) -> bool {
        match op_type {
            opcode::CREATE | opcode::CREATE_CONTAINER => true,
            opcode::CREATE2 | opcode::CREATE_TTL => self.compat.native_ops,
            _ => false,
        }
    }

    /// Checks one accepted multi operation and appends its header and its
    /// record to `out`. It returns false on a path, state, TTL, input or
    /// allocation failure. The caller reports all of them as one
    /// `ZMARSHALLINGERROR`.
    fn submit_multi_append(&self, op: MultiOp, out: &mut Vec<u8>) -> bool {
        let op_type = op.op_type();
        // Each record takes the fields of the operation. Thus the encoding
        // makes no second copy of a path or of the data.
        match op {
            MultiOp::Create {
                path,
                data,
                acl,
                mode,
                ttl,
                defect,
                ..
            } => {
                let Some(path) = self.multi_path(path, mode, defect) else {
                    return false;
                };
                if op_type == opcode::CREATE_TTL {
                    check_ttl(mode, ttl).is_ok()
                        && append(
                            op_type,
                            &CreateTTLRequest {
                                path,
                                data,
                                acl,
                                flags: mode,
                                ttl,
                            },
                            out,
                        )
                } else {
                    append(
                        op_type,
                        &CreateRequest {
                            path,
                            data,
                            acl,
                            flags: mode,
                        },
                        out,
                    )
                }
            }
            MultiOp::Delete {
                path,
                version,
                defect,
            } => self
                .multi_path(path, 0, defect)
                .is_some_and(|path| append(op_type, &DeleteRequest { path, version }, out)),
            MultiOp::SetData {
                path,
                data,
                version,
                defect,
            } => self.multi_path(path, 0, defect).is_some_and(|path| {
                append(
                    op_type,
                    &SetDataRequest {
                        path,
                        data,
                        version,
                    },
                    out,
                )
            }),
            MultiOp::Check {
                path,
                version,
                defect,
            } => self
                .multi_path(path, 0, defect)
                .is_some_and(|path| append(op_type, &CheckVersionRequest { path, version }, out)),
            MultiOp::GetData { path } => self
                .multi_path(path, 0, InputDefect::default())
                .is_some_and(|path| append(op_type, &GetDataRequest { path, watch: false }, out)),
            MultiOp::GetChildren { path } => self
                .multi_path(path, 0, InputDefect::default())
                .is_some_and(|path| {
                    append(op_type, &GetChildrenRequest { path, watch: false }, out)
                }),
            MultiOp::Other { .. } => false,
        }
    }

    /// Checks one borrowed multi operation and appends its header and its
    /// record to `out`.
    ///
    /// The checks, their order and the bytes are those of
    /// [`Self::submit_multi_append`]. The path and the data go from the
    /// borrowed slices straight into `out`, so the encoding makes no
    /// copy of them first.
    fn multi_ref_append(&self, op: &MultiOpRef<'_>, out: &mut Vec<u8>) -> bool {
        let op_type = op.op_type();
        match *op {
            MultiOpRef::Create {
                path,
                data,
                ref acl,
                mode,
                ttl,
                defect,
                ..
            } => {
                let Some(server) = self.multi_ref_path(path, mode, defect) else {
                    return false;
                };
                let tail = if op_type == opcode::CREATE_TTL {
                    if check_ttl(mode, ttl).is_err() {
                        return false;
                    }
                    DataTail::CreateTtl {
                        acl,
                        flags: mode,
                        ttl,
                    }
                } else {
                    DataTail::Create { acl, flags: mode }
                };
                append_data(op_type, Some(&server), data, tail, out)
            }
            MultiOpRef::SetData {
                path,
                data,
                version,
                defect,
            } => self.multi_ref_path(path, 0, defect).is_some_and(|server| {
                append_data(
                    op_type,
                    Some(&server),
                    data,
                    DataTail::SetData { version },
                    out,
                )
            }),
            MultiOpRef::Delete {
                path,
                version,
                defect,
            }
            | MultiOpRef::Check {
                path,
                version,
                defect,
            } => self.multi_ref_path(path, 0, defect).is_some_and(|server| {
                let record = VersionRecord {
                    path: &server,
                    version,
                };
                append_with(op_type, record.encoded_len(), out, |o| record.encode(o))
            }),
            MultiOpRef::Other { .. } => false,
        }
    }

    /// Runs the path, state and input checks of one borrowed multi
    /// operation, as [`Self::multi_path`] does. A path that the join does
    /// not change stays borrowed, so the check makes no copy.
    fn multi_ref_path<'p>(
        &self,
        path: Option<&'p [u8]>,
        mode: i32,
        defect: InputDefect,
    ) -> Option<Cow<'p, [u8]>> {
        let server = self.server_path_raw(path?, mode).ok()?;
        if self.core.state.is_unrecoverable() || defect.any() {
            return None;
        }
        Some(server)
    }

    /// Runs the path, state and input checks of one multi operation, and
    /// returns the server path. `None` is a check failure.
    fn multi_path(&self, path: PathIn, mode: i32, defect: InputDefect) -> Option<JString> {
        let server = self.server_path_owned(path, mode).ok()?;
        if self.core.state.is_unrecoverable() || defect.any() {
            return None;
        }
        Some(JString::Bytes(server))
    }

    /// Runs rows 2 and 3 for an operation with a plain path, and returns
    /// the server path.
    fn submit_path_state(&self, path: PathIn) -> Result<Vec<u8>, Rejected> {
        let server = self.server_path_owned(path, 0).map_err(validate)?;
        self.submit_check_state()?;
        Ok(server)
    }

    /// Runs row 3: an unrecoverable session state rejects the operation.
    fn submit_check_state(&self) -> Result<(), Rejected> {
        if self.core.state.is_unrecoverable() {
            Err(validate(ZINVALIDSTATE))
        } else {
            Ok(())
        }
    }

    /// Makes the DEBUG "Sending request" record of a site with a path. The
    /// first argument holds a dummy xid, and `submit` sets the real one.
    fn submit_path_log(&self, site: LogSite, path: &PathIn) -> Option<LogRecord> {
        self.log.record(site, || {
            vec![
                LogArg::I64(0),
                path_arg(path),
                LogArg::Endpoint(self.current_server()),
            ]
        })
    }
}

/// Validates a native client path and joins it with the chroot on a
/// component boundary. A borrowed result is the whole client path.
fn join_native<'p>(chroot: Option<&[u8]>, raw: &'p [u8], mode: i32) -> Result<Cow<'p, [u8]>, i32> {
    let client = core::str::from_utf8(raw).map_err(|_| ZBADARGUMENTS)?;
    let sequential = is_sequence(mode);
    validate_path_strict(client, sequential).map_err(|_| ZBADARGUMENTS)?;
    let root = match chroot {
        None => None,
        Some(c) => Some(core::str::from_utf8(c).map_err(|_| ZBADARGUMENTS)?),
    };
    // A sequential create on `/` under a chroot would make a
    // node outside the chroot.
    let effective = root.is_some_and(|r| r.len() > 1);
    if effective && sequential && client == "/" {
        return Err(ZBADARGUMENTS);
    }
    Ok(match join_component(root, client) {
        Cow::Borrowed(b) => Cow::Borrowed(b.as_bytes()),
        Cow::Owned(o) => Cow::Owned(o.into_bytes()),
    })
}

/// The encoded length of one `MultiHeader`: type, done and err.
const MULTI_HEADER_LEN: usize = 9;

/// The row 6 failure: `Stage::Enqueue` with `ZMARSHALLINGERROR`.
const MARSHAL: Rejected = Rejected {
    stage: Stage::Enqueue,
    code: ZMARSHALLINGERROR,
};

/// Makes a validation failure with the legacy code.
fn validate(code: i32) -> Rejected {
    Rejected {
        stage: Stage::Validate,
        code,
    }
}

/// Encodes a request record into a buffer of exact size. A failed
/// allocation is a row 6 failure, not an abort.
fn encode<R: Record>(record: &R) -> Result<Vec<u8>, Rejected> {
    let mut body = Vec::new();
    if body.try_reserve_exact(record.encoded_len()).is_err() {
        return Err(MARSHAL);
    }
    record.encode(&mut body);
    Ok(body)
}

/// Encodes a request record after a placeholder head, into a buffer of
/// exact frame size. `submit` writes the head in place, so the record is
/// not copied again. A failed allocation is a row 6 failure.
fn encode_framed<R: Record>(record: &R) -> Result<Vec<u8>, Rejected> {
    framed_with(record.encoded_len(), |out| record.encode(out))
}

/// Makes a frame of exact size for a record of `len` bytes. `encode`
/// appends the record after the placeholder head. A failed allocation is
/// a row 6 failure.
fn framed_with(len: usize, encode: impl FnOnce(&mut Vec<u8>)) -> Result<Vec<u8>, Rejected> {
    let mut frame = Vec::new();
    if frame
        .try_reserve_exact(len.saturating_add(REQUEST_HEAD_LEN))
        .is_err()
    {
        return Err(MARSHAL);
    }
    frame.resize(REQUEST_HEAD_LEN, 0);
    encode(&mut frame);
    Ok(frame)
}

/// The record of a create or a set data, with borrowed data.
///
/// The generated records own their data, so a caller must copy borrowed
/// data into them first. This record borrows the data instead. Its
/// encoding is the same as the encoding of the generated record.
struct DataRecord<'a> {
    /// The server path. `None` is the jute null string.
    path: Option<&'a [u8]>,
    /// The data. `None` is the jute null buffer.
    data: Option<&'a [u8]>,
    /// The fields after the data.
    tail: DataTail<'a>,
}

/// The fields of a [`DataRecord`] that come after the data.
enum DataTail<'a> {
    /// `SetDataRequest`: the version.
    SetData { version: i32 },
    /// `CreateRequest`: the ACL and the flags.
    Create { acl: &'a JVec<ACL>, flags: i32 },
    /// `CreateTTLRequest`: the ACL, the flags and the TTL.
    CreateTtl {
        acl: &'a JVec<ACL>,
        flags: i32,
        ttl: i64,
    },
}

impl DataRecord<'_> {
    /// The exact number of bytes that [`Self::encode`] appends.
    fn encoded_len(&self) -> usize {
        let tail = match &self.tail {
            DataTail::SetData { version } => version.encoded_len(),
            DataTail::Create { acl, flags } => {
                acl.encoded_len().saturating_add(flags.encoded_len())
            }
            DataTail::CreateTtl { acl, flags, ttl } => acl
                .encoded_len()
                .saturating_add(flags.encoded_len())
                .saturating_add(ttl.encoded_len()),
        };
        wire_len(self.path)
            .saturating_add(wire_len(self.data))
            .saturating_add(tail)
    }

    /// Appends the fields in the order of the generated record.
    fn encode(&self, out: &mut Vec<u8>) {
        put_wire(self.path, out);
        put_wire(self.data, out);
        match &self.tail {
            DataTail::SetData { version } => version.encode(out),
            DataTail::Create { acl, flags } => {
                acl.encode(out);
                flags.encode(out);
            }
            DataTail::CreateTtl { acl, flags, ttl } => {
                acl.encode(out);
                flags.encode(out);
                ttl.encode(out);
            }
        }
    }
}

/// The record of a server path and a version, with a borrowed path. Its
/// encoding is the same as the encoding of `DeleteRequest` and of
/// `CheckVersionRequest`.
struct VersionRecord<'a> {
    /// The server path.
    path: &'a [u8],
    /// The expected version.
    version: i32,
}

impl VersionRecord<'_> {
    /// The exact number of bytes that [`Self::encode`] appends.
    fn encoded_len(&self) -> usize {
        wire_len(Some(self.path)).saturating_add(self.version.encoded_len())
    }

    /// Appends the path and the version.
    fn encode(&self, out: &mut Vec<u8>) {
        put_wire(Some(self.path), out);
        self.version.encode(out);
    }
}

/// The encoded length of a jute string or buffer. `None` is the null
/// value.
fn wire_len(b: Option<&[u8]>) -> usize {
    b.map_or(4, |b| wire_buffer(b).1.len().saturating_add(4))
}

/// Appends a jute string or buffer from borrowed bytes. `None` is the
/// null value.
fn put_wire(b: Option<&[u8]>, out: &mut Vec<u8>) {
    let (len, bytes) = b.map_or((-1, &[][..]), wire_buffer);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Gives the wire length and the wire bytes of a jute buffer. The rule
/// is the zk-jute rule: a buffer over `i32::MAX` bytes is cut to
/// `i32::MAX` bytes.
fn wire_buffer(b: &[u8]) -> (i32, &[u8]) {
    let len = i32::try_from(b.len()).unwrap_or(i32::MAX);
    let n = usize::try_from(len).unwrap_or(0);
    (len, b.get(..n).unwrap_or(b))
}

/// Appends the header and the record of one multi operation. It returns
/// false when the allocation fails.
fn append<R: Record>(op_type: i32, record: &R, out: &mut Vec<u8>) -> bool {
    append_with(op_type, record.encoded_len(), out, |o| record.encode(o))
}

/// Appends the header of one multi operation and a record of `len`
/// bytes that `encode` writes. It returns false when the allocation
/// fails.
fn append_with(
    op_type: i32,
    len: usize,
    out: &mut Vec<u8>,
    encode: impl FnOnce(&mut Vec<u8>),
) -> bool {
    if out
        .try_reserve(len.saturating_add(MULTI_HEADER_LEN))
        .is_err()
    {
        return false;
    }
    multi::encode_op_header(op_type, out);
    encode(out);
    true
}

/// Appends the header and the borrowed record of a create or a set data
/// in a multi. It returns false when the allocation fails.
fn append_data(
    op_type: i32,
    path: Option<&[u8]>,
    data: Option<&[u8]>,
    tail: DataTail<'_>,
    out: &mut Vec<u8>,
) -> bool {
    let record = DataRecord { path, data, tail };
    append_with(op_type, record.encoded_len(), out, |o| record.encode(o))
}

/// One sub-op that the multi scan of [`Connection::encode_multi`] takes.
///
/// The owned [`MultiOp`] and the borrowed [`MultiOpRef`] share the scan.
/// Thus both get the same type rules, checks and error codes.
pub(crate) trait SubOp {
    /// The wire type of the operation.
    fn op_type(&self) -> i32;
    /// True when the scan accepts the operation.
    fn allowed<T: Tokens>(&self, conn: &Connection<T>, read: bool) -> bool;
    /// Checks the operation and appends its header and its record. False
    /// is a check or an allocation failure.
    fn append<T: Tokens>(self, conn: &Connection<T>, out: &mut Vec<u8>) -> bool;
}

impl SubOp for MultiOp {
    fn op_type(&self) -> i32 {
        Self::op_type(self)
    }

    fn allowed<T: Tokens>(&self, conn: &Connection<T>, read: bool) -> bool {
        conn.submit_multi_allowed(self, read)
    }

    fn append<T: Tokens>(self, conn: &Connection<T>, out: &mut Vec<u8>) -> bool {
        conn.submit_multi_append(self, out)
    }
}

impl SubOp for &MultiOpRef<'_> {
    fn op_type(&self) -> i32 {
        MultiOpRef::op_type(self)
    }

    fn allowed<T: Tokens>(&self, conn: &Connection<T>, read: bool) -> bool {
        conn.multi_ref_allowed(self, read)
    }

    fn append<T: Tokens>(self, conn: &Connection<T>, out: &mut Vec<u8>) -> bool {
        conn.multi_ref_append(self, out)
    }
}

/// Selects the wire type of a create from the mode, as C
/// `get_create_op_type` does.
fn create_op_type(mode: i32, default: i32) -> i32 {
    if mode == CONTAINER_MODE {
        opcode::CREATE_CONTAINER
    } else if is_ttl(mode) {
        opcode::CREATE_TTL
    } else {
        default
    }
}

/// The C create mode `ZOO_CONTAINER`.
const CONTAINER_MODE: i32 = 4;

/// Returns the client path as a log argument. The send sites print the
/// path of the caller, without the chroot.
fn path_arg(path: &PathIn) -> LogArg {
    match path {
        PathIn::Legacy(Some(bytes)) => crate::log::str_arg(bytes),
        PathIn::Legacy(None) => LogArg::Str(JString::Null),
        PathIn::Native(s) => LogArg::Str(s.clone()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::hooks::{AllLevels, NoDefaultWatcher, Rng};
    use crate::output::Output;
    use crate::request::Route;
    use crate::state::State;
    use zk_jute::JBuffer;

    struct Tk;
    impl Tokens for Tk {
        type Completion = u32;
        type Watcher = u32;
        type Auth = u32;
    }

    struct FixedRng;
    impl Rng for FixedRng {
        fn on_resolution(&mut self) {}
        fn random(&mut self) -> i64 {
            0
        }
        fn drand48(&mut self) -> f64 {
            0.0
        }
    }

    fn conn_with(cfg: Config, compat: Compat) -> Connection<Tk> {
        Connection::new(
            cfg,
            compat,
            DriverMode::ST,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(NoDefaultWatcher),
            Millis(0),
        )
    }

    fn legacy() -> Connection<Tk> {
        conn_with(Config::legacy(30_000), Compat::LEGACY_C)
    }

    fn chrooted(compat: Compat) -> Connection<Tk> {
        let mut cfg = Config::legacy(30_000);
        cfg.chroot = Some(JString::from("/app"));
        conn_with(cfg, compat)
    }

    fn lp(p: &str) -> PathIn {
        PathIn::Legacy(Some(p.as_bytes().to_vec()))
    }

    fn np(p: &str) -> PathIn {
        PathIn::Native(JString::from(p))
    }

    const DEFECT: InputDefect = InputDefect {
        bad_value_buffer: true,
        bad_acl: false,
        marshal_oom: false,
    };

    fn create(path: PathIn, mode: i32, ttl: i64) -> Op<u32> {
        Op::Create {
            path,
            data: JBuffer::Bytes(vec![1]),
            acl: JVec::from(Vec::new()),
            mode,
            ttl,
            create2: false,
        }
    }

    fn req(op: Op<u32>, defect: InputDefect) -> Request<Tk> {
        Request {
            op,
            token: 7,
            route: Route::Queued,
            defect,
        }
    }

    /// Submits and returns the stage and code of the failure.
    fn fails(c: &mut Connection<Tk>, op: Op<u32>, defect: InputDefect) -> (Stage, i32) {
        match c.submit(req(op, defect), Millis(0)) {
            Err(e) => {
                assert_eq!(e.token, 7);
                (e.stage, e.code)
            }
            Ok(s) => panic!("submit passed: {s:?}"),
        }
    }

    fn queued(c: &mut Connection<Tk>, op: Op<u32>) -> i32 {
        match c.submit(req(op, InputDefect::default()), Millis(0)) {
            Ok(Submitted::Queued { xid }) => xid,
            Ok(Submitted::Local(_)) => panic!("local"),
            Err(e) => panic!("submit failed: {e:?}"),
        }
    }

    fn logs(c: &mut Connection<Tk>) -> Vec<LogRecord> {
        let mut v = Vec::new();
        while let Some(o) = c.poll_output() {
            if let Output::Log(r) = o {
                v.push(r);
            }
        }
        v
    }

    fn assert_untouched(c: &Connection<Tk>) {
        assert!(c.requests.tx.is_empty());
        assert!(c.requests.fifo.is_empty());
    }

    fn mdelete(path: PathIn) -> MultiOp {
        MultiOp::Delete {
            path,
            version: -1,
            defect: InputDefect::default(),
        }
    }

    fn mcheck(path: PathIn) -> MultiOp {
        MultiOp::Check {
            path,
            version: 3,
            defect: InputDefect::default(),
        }
    }

    const VALIDATE_BAD: (Stage, i32) = (Stage::Validate, ZBADARGUMENTS);
    const VALIDATE_STATE: (Stage, i32) = (Stage::Validate, ZINVALIDSTATE);
    const ENQUEUE: (Stage, i32) = (Stage::Enqueue, ZMARSHALLINGERROR);

    #[test]
    fn row1_ttl_wins_over_state_and_serialization() {
        let mut c = legacy();
        c.set_state(State::ExpiredSession);
        c.close.closing = true;
        assert_eq!(fails(&mut c, create(lp("/a"), 0, 0), DEFECT), VALIDATE_BAD);
        assert_eq!(fails(&mut c, create(lp("/a"), 5, 0), DEFECT), VALIDATE_BAD);
        assert_untouched(&c);
    }

    #[test]
    fn row2_path_wins_over_state_and_serialization() {
        let mut c = legacy();
        c.set_state(State::ExpiredSession);
        c.close.closing = true;
        let get = |path| Op::GetData { path, watch: None };
        assert_eq!(
            fails(&mut c, get(PathIn::Legacy(None)), DEFECT),
            VALIDATE_BAD
        );
        assert_eq!(fails(&mut c, get(lp("a")), DEFECT), VALIDATE_BAD);
        assert_eq!(fails(&mut c, get(lp("/a/")), DEFECT), VALIDATE_BAD);
        // A trailing slash is valid for a sequential create, so row 3 runs.
        assert_eq!(
            fails(&mut c, create(lp("/a/"), 2, -1), DEFECT),
            VALIDATE_STATE
        );
        assert_untouched(&c);
    }

    #[test]
    fn row3_state_wins_over_serialization() {
        let mut c = legacy();
        c.set_state(State::AuthFailed);
        c.close.closing = true;
        let ops = [
            Op::Sync { path: lp("/a") },
            Op::GetConfig { watch: None },
            Op::Reconfig {
                joining: JString::Null,
                leaving: JString::Null,
                members: JString::Null,
                version: -1,
            },
            Op::RemoveWatches {
                path: lp("/a"),
                wtype: 3,
                watcher: None,
                local: false,
                all: false,
            },
        ];
        for op in ops {
            assert_eq!(fails(&mut c, op, DEFECT), VALIDATE_STATE);
        }
        assert_untouched(&c);
    }

    #[test]
    fn row5_runs_after_path_and_state() {
        // Rows 2 and 3 fail before the remove-watches check runs.
        let mut c = legacy();
        let rw = |path, local| Op::RemoveWatches {
            path,
            wtype: 1,
            watcher: Some(3),
            local,
            all: true,
        };
        assert_eq!(fails(&mut c, rw(lp("/a/"), true), DEFECT), VALIDATE_BAD);
        c.set_state(State::ExpiredSession);
        assert_eq!(fails(&mut c, rw(lp("/a"), false), DEFECT), VALIDATE_STATE);
        assert_untouched(&c);
    }

    #[test]
    fn row4_unimplemented_wins_over_earlier_and_later_rows() {
        let mut c = legacy();
        c.set_state(State::ExpiredSession);
        c.close.closing = true;
        let ops = vec![
            mdelete(PathIn::Legacy(None)),
            MultiOp::Other { op_type: 4 },
            MultiOp::Other { op_type: 99 },
        ];
        assert_eq!(
            fails(&mut c, Op::Multi { ops }, DEFECT),
            (Stage::Validate, ZUNIMPLEMENTED)
        );
        let logs = logs(&mut c);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].site, LogSite::MultiUnimplemented);
        assert_eq!(logs[0].args, [LogArg::I64(4)]);
        assert_untouched(&c);
    }

    #[test]
    fn row4_sub_op_failures_are_enqueue_errors() {
        let mut c = legacy();
        let bad_path = vec![mdelete(lp("/a")), mcheck(PathIn::Legacy(None))];
        assert_eq!(
            fails(&mut c, Op::Multi { ops: bad_path }, InputDefect::default()),
            ENQUEUE
        );
        let defect = vec![MultiOp::SetData {
            path: lp("/a"),
            data: JBuffer::Null,
            version: 0,
            defect: DEFECT,
        }];
        assert_eq!(
            fails(&mut c, Op::Multi { ops: defect }, InputDefect::default()),
            ENQUEUE
        );
        // Valid sub-ops with a defect of the request fail at row 6.
        let ok = vec![mcheck(lp("/a"))];
        assert_eq!(
            fails(&mut c, Op::Multi { ops: ok.clone() }, DEFECT),
            ENQUEUE
        );
        c.set_state(State::ExpiredSession);
        assert_eq!(
            fails(&mut c, Op::Multi { ops: ok }, InputDefect::default()),
            ENQUEUE
        );
        assert!(logs(&mut c).is_empty());
        assert_untouched(&c);
        // An empty multi checks the state too, so no reply is lost.
        assert_eq!(
            fails(
                &mut c,
                Op::Multi { ops: Vec::new() },
                InputDefect::default()
            ),
            ENQUEUE
        );
        assert_untouched(&c);
        c.set_state(State::Connected);
        assert_eq!(queued(&mut c, Op::Multi { ops: Vec::new() }), 1);
    }

    #[test]
    fn row6_input_and_close_failures() {
        let mut c = legacy();
        let acl = InputDefect {
            bad_acl: true,
            ..InputDefect::default()
        };
        let set_acl = Op::SetAcl {
            path: lp("/a"),
            acl: JVec::Null,
            version: 0,
        };
        assert_eq!(fails(&mut c, set_acl, acl), ENQUEUE);
        c.close.closing = true;
        let op = Op::Delete {
            path: lp("/a"),
            version: 0,
        };
        assert_eq!(fails(&mut c, op, InputDefect::default()), ENQUEUE);
        assert_untouched(&c);
    }

    #[test]
    fn submit_gates_run_before_check_op() {
        let mut c = legacy();
        let who = fails(&mut c, Op::WhoAmI, InputDefect::default());
        assert_eq!(who, (Stage::NotEnabled, ZUNIMPLEMENTED));
        let add = Op::AddWatch {
            path: PathIn::Legacy(None),
            mode: 0,
            watch: 1,
        };
        assert_eq!(
            fails(&mut c, add, DEFECT),
            (Stage::NotEnabled, ZUNIMPLEMENTED)
        );

        let mut cfg = Config::legacy(30_000);
        cfg.max_pending = Some(1);
        let mut c = conn_with(cfg, Compat::LEGACY_C);
        assert_eq!(queued(&mut c, Op::Sync { path: lp("/a") }), 1);
        let sync = Op::Sync {
            path: PathIn::Legacy(None),
        };
        assert_eq!(
            fails(&mut c, sync, DEFECT),
            (Stage::TooManyPending, ZTHROTTLEDOP)
        );

        let mut compat = Compat::LEGACY_C;
        compat.close_mode = CloseMode::Drain;
        let mut c = conn_with(Config::legacy(30_000), compat);
        c.close.closing = true;
        let op = create(lp("/a"), 0, 0);
        assert_eq!(fails(&mut c, op, DEFECT), (Stage::Validate, ZCLOSING));
        assert_untouched(&c);
    }

    #[test]
    fn queued_request_has_frame_entry_and_log() {
        let mut c = chrooted(Compat::LEGACY_C);
        let op = Op::GetData {
            path: lp("/a"),
            watch: Some(5),
        };
        assert_eq!(queued(&mut c, op), 1);
        let body = GetDataRequest {
            path: JString::from("/app/a"),
            watch: true,
        }
        .to_bytes();
        let f = &c.requests.tx[0];
        assert_eq!(f.kind, FrameKind::Request { xid: 1 });
        assert_eq!(
            f.bytes.as_slice(),
            Connection::<Tk>::request_frame(1, opcode::GET_DATA, &body)
        );
        let p = &c.requests.fifo[0];
        assert_eq!((p.xid, p.token), (1, 7));
        assert_eq!(p.shape, Shape::Data);
        assert!(!p.written);
        let w = p.watch.as_ref().unwrap();
        assert_eq!(
            (w.kind, w.path.as_slice(), w.watcher),
            (WatchKind::Data, &b"/app/a"[..], 5)
        );
        let logs = logs(&mut c);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].site, LogSite::SendGetData);
        assert_eq!(logs[0].args[0], LogArg::I64(1));
        assert_eq!(logs[0].args[1], LogArg::Str(JString::from("/a")));
    }

    #[test]
    fn op_types_and_shapes() {
        let mut c = chrooted(Compat::LEGACY_C);
        let mut check = |op: Op<u32>, op_type: i32, shape: Shape| match c.check_op(
            op,
            InputDefect::default(),
            Input::Owned,
        ) {
            Ok(Checked::Send(p)) => {
                assert_eq!((p.op_type, &p.shape), (op_type, &shape));
                // A framed body starts with the placeholder head.
                p.body[usize::from(p.framed) * REQUEST_HEAD_LEN..].to_vec()
            }
            _ => panic!("check_op failed"),
        };
        check(create(lp("/a"), 0, -1), opcode::CREATE, Shape::Path);
        check(
            create(lp("/a"), 4, -1),
            opcode::CREATE_CONTAINER,
            Shape::Path,
        );
        check(create(lp("/a"), 5, 10), opcode::CREATE_TTL, Shape::Path);
        let c2 = Op::Create {
            path: lp("/a"),
            data: JBuffer::Null,
            acl: JVec::Null,
            mode: 0,
            ttl: -1,
            create2: true,
        };
        check(c2, opcode::CREATE2, Shape::PathStat);
        let e = Op::Exists {
            path: lp("/a"),
            watch: None,
        };
        check(e, opcode::EXISTS, Shape::Stat);
        check(Op::Sync { path: lp("/a") }, opcode::SYNC, Shape::Path);
        check(Op::GetAcl { path: lp("/a") }, opcode::GET_ACL, Shape::Acl);
        let d = Op::Delete {
            path: lp("/a"),
            version: 1,
        };
        check(d, opcode::DELETE, Shape::Void);
        let s = Op::SetData {
            path: lp("/a"),
            data: JBuffer::Null,
            version: 1,
        };
        check(s, opcode::SET_DATA, Shape::Stat);
        let a = Op::SetAcl {
            path: lp("/a"),
            acl: JVec::Null,
            version: 1,
        };
        check(a, opcode::SET_ACL, Shape::Void);
        let g = Op::GetChildren {
            path: lp("/a"),
            watch: None,
            with_stat: true,
        };
        check(g, opcode::GET_CHILDREN2, Shape::Children2);
        let g = Op::GetChildren {
            path: lp("/a"),
            watch: None,
            with_stat: false,
        };
        check(g, opcode::GET_CHILDREN, Shape::Children);
        let r = Op::Reconfig {
            joining: JString::Null,
            leaving: JString::Null,
            members: JString::Null,
            version: -1,
        };
        check(r, opcode::RECONFIG, Shape::Data);
        // The config node never takes the chroot.
        let body = check(Op::GetConfig { watch: None }, opcode::GET_DATA, Shape::Data);
        let want = GetDataRequest {
            path: JString::Bytes(CONFIG_NODE.to_vec()),
            watch: false,
        };
        assert_eq!(body, want.to_bytes());
    }

    #[test]
    fn native_ops_and_shapes() {
        let mut c = chrooted(Compat::NATIVE);
        let add = Op::AddWatch {
            path: np("/a"),
            mode: 1,
            watch: 4,
        };
        assert_eq!(queued(&mut c, add), 1);
        let w = c.requests.fifo[0].watch.as_ref().unwrap();
        assert_eq!(
            (w.kind, w.path.as_slice()),
            (WatchKind::PersistentRecursive, &b"/app/a"[..])
        );
        let bad = Op::AddWatch {
            path: np("/a"),
            mode: 2,
            watch: 4,
        };
        assert_eq!(fails(&mut c, bad, InputDefect::default()), VALIDATE_BAD);
        // The plain setACL skips the body, and `SetAclStat` reads the
        // stat of the reply.
        for (stat, shape) in [(false, Shape::Void), (true, Shape::Stat)] {
            let (path, acl, version) = (np("/a"), JVec::Null, 1);
            let a = if stat {
                Op::SetAclStat { path, acl, version }
            } else {
                Op::SetAcl { path, acl, version }
            };
            match c.check_op(a, InputDefect::default(), Input::Owned) {
                Ok(Checked::Send(p)) => assert_eq!((p.op_type, p.shape), (opcode::SET_ACL, shape)),
                _ => panic!("check_op failed"),
            }
        }
        // A removal hint has no local watcher left, and it still goes out.
        let hint = Op::RemoveWatches {
            path: np("/gone"),
            wtype: 2,
            watcher: None,
            local: false,
            all: true,
        };
        match c.check_op(hint, InputDefect::default(), Input::Owned) {
            Ok(Checked::Send(p)) => assert_eq!(p.op_type, opcode::REMOVE_WATCHES),
            _ => panic!("check_op failed"),
        }
        let mut check = |op: Op<u32>, op_type: i32, shape: Shape| match c.check_op(
            op,
            InputDefect::default(),
            Input::Owned,
        ) {
            Ok(Checked::Send(p)) => assert_eq!(
                (p.op_type, p.shape, p.log.is_none()),
                (op_type, shape, true)
            ),
            _ => panic!("check_op failed"),
        };
        check(Op::WhoAmI, opcode::WHO_AM_I, Shape::WhoAmI);
        check(
            Op::GetEphemerals { prefix: np("/") },
            opcode::GET_EPHEMERALS,
            Shape::Ephemerals,
        );
        check(
            Op::GetAllChildrenNumber { path: np("/a") },
            opcode::GET_ALL_CHILDREN_NUMBER,
            Shape::ChildrenCount,
        );
        let ops = vec![
            MultiOp::GetData { path: np("/a") },
            MultiOp::GetChildren { path: np("/b") },
        ];
        check(
            Op::MultiRead { ops },
            opcode::MULTI_READ,
            Shape::Multi {
                op_types: vec![opcode::GET_DATA, opcode::GET_CHILDREN],
                kind: MultiKind::MultiRead,
            },
        );
    }

    #[test]
    fn legacy_chroot_join() {
        let c = chrooted(Compat::LEGACY_C);
        assert_eq!(c.server_path(&lp("/x"), 0), Ok(b"/app/x".to_vec()));
        assert_eq!(c.server_path(&lp("/"), 0), Ok(b"/app".to_vec()));
        assert_eq!(c.server_path(&lp("/"), 2), Err(ZBADARGUMENTS));
        assert_eq!(c.server_path(&lp("x"), 0), Err(ZBADARGUMENTS));
        assert_eq!(c.server_path(&PathIn::Legacy(None), 0), Err(ZBADARGUMENTS));
        assert_eq!(legacy().server_path(&lp("/x/"), 2), Ok(b"/x/".to_vec()));
    }

    #[test]
    fn component_chroot_join() {
        let c = chrooted(Compat::NATIVE);
        assert_eq!(c.server_path(&np("/x"), 0), Ok(b"/app/x".to_vec()));
        assert_eq!(c.server_path(&np("/"), 0), Ok(b"/app".to_vec()));
        assert_eq!(c.server_path(&np("/"), 2), Err(ZBADARGUMENTS));
        assert_eq!(c.server_path(&np("/x/."), 0), Err(ZBADARGUMENTS));
        let null = PathIn::Native(JString::Null);
        assert_eq!(c.server_path(&null, 0), Err(ZBADARGUMENTS));
        let raw = PathIn::Native(JString::Bytes(vec![b'/', 0xff]));
        assert_eq!(c.server_path(&raw, 0), Err(ZBADARGUMENTS));
        let plain = conn_with(Config::legacy(30_000), Compat::NATIVE);
        assert_eq!(plain.server_path(&np("/"), 2), Ok(b"/".to_vec()));
    }

    #[test]
    fn owned_server_path_reuses_the_request_buffer() {
        let ptr = |p: &PathIn| match p {
            PathIn::Legacy(Some(b)) | PathIn::Native(JString::Bytes(b)) => b.as_ptr(),
            _ => panic!("no bytes"),
        };
        // With no effective chroot, the request buffer becomes the server path.
        let plain = [
            (legacy(), lp("/x")),
            (conn_with(Config::legacy(30_000), Compat::NATIVE), np("/x")),
        ];
        for (c, p) in plain {
            let at = ptr(&p);
            let out = c.server_path_owned(p, 0).unwrap();
            assert_eq!((out.as_slice(), out.as_ptr()), (&b"/x"[..], at));
        }
        // The owned form gives the same result as the borrowed form.
        for (c, p) in [
            (chrooted(Compat::LEGACY_C), lp("/x")),
            (chrooted(Compat::LEGACY_C), lp("/")),
            (chrooted(Compat::LEGACY_C), lp("x")),
            (chrooted(Compat::LEGACY_C), PathIn::Legacy(None)),
            (chrooted(Compat::NATIVE), np("/x")),
            (chrooted(Compat::NATIVE), np("/x/.")),
            (chrooted(Compat::NATIVE), PathIn::Native(JString::Null)),
        ] {
            for mode in [0, 2] {
                let want = c.server_path(&p, mode);
                assert_eq!(c.server_path_owned(p.clone(), mode), want);
            }
        }
    }

    #[test]
    fn send_log_shows_the_client_path_and_failed_checks_log_nothing() {
        let mut c = chrooted(Compat::LEGACY_C);
        assert_eq!(queued(&mut c, create(lp("/a"), 0, -1)), 1);
        let logs1 = logs(&mut c);
        assert_eq!(logs1.len(), 1);
        assert_eq!(logs1[0].site, LogSite::SendCreate);
        assert_eq!(logs1[0].args[1], LogArg::Str(JString::from("/a")));
        // Rows 1, 2 and 3 fail after the record exists. It has no output.
        assert_eq!(
            fails(&mut c, create(lp("/a"), 5, 0), InputDefect::default()),
            VALIDATE_BAD
        );
        let get = |path| Op::GetData { path, watch: None };
        assert_eq!(
            fails(&mut c, get(lp("a")), InputDefect::default()),
            VALIDATE_BAD
        );
        c.set_state(State::ExpiredSession);
        assert_eq!(
            fails(&mut c, get(lp("/a")), InputDefect::default()),
            VALIDATE_STATE
        );
        assert_eq!(
            fails(
                &mut c,
                Op::GetConfig { watch: None },
                InputDefect::default()
            ),
            VALIDATE_STATE
        );
        assert!(logs(&mut c).is_empty());
    }

    #[test]
    fn encode_multi_layout() {
        let mut c = legacy();
        let ops = vec![
            MultiOp::Create {
                op_type: opcode::CREATE,
                path: lp("/a"),
                data: JBuffer::Bytes(vec![1, 2]),
                acl: JVec::Null,
                mode: 0,
                ttl: -1,
                defect: InputDefect::default(),
            },
            mcheck(lp("/b")),
        ];
        let (body, types) = c.encode_multi(ops, false).unwrap();
        assert_eq!(types, [opcode::CREATE, opcode::CHECK]);
        let mut want = Vec::new();
        multi::encode_op_header(opcode::CREATE, &mut want);
        CreateRequest {
            path: JString::from("/a"),
            data: JBuffer::Bytes(vec![1, 2]),
            acl: JVec::Null,
            flags: 0,
        }
        .encode(&mut want);
        multi::encode_op_header(opcode::CHECK, &mut want);
        CheckVersionRequest {
            path: JString::from("/b"),
            version: 3,
        }
        .encode(&mut want);
        multi::encode_end(&mut want);
        assert_eq!(body, want);
        assert_eq!(
            c.encode_multi(Vec::<MultiOp>::new(), false)
                .unwrap()
                .0
                .len(),
            MULTI_HEADER_LEN
        );
    }

    #[test]
    fn encode_multi_unimplemented_and_late_path_failure() {
        let mut c = legacy();
        // A bad path, then a type outside the set: the type wins.
        let ops = vec![mdelete(PathIn::Legacy(None)), MultiOp::Other { op_type: 7 }];
        let r = c.encode_multi(ops, false);
        assert_eq!(r, Err(validate(ZUNIMPLEMENTED)));
        assert_eq!(logs(&mut c).len(), 1);
        // A bad path with only valid types fails after the scan.
        let ops = vec![mcheck(lp("/a")), mdelete(lp("bad")), mcheck(lp("/c"))];
        assert_eq!(c.encode_multi(ops, false), Err(MARSHAL));
        assert!(logs(&mut c).is_empty());
        // The legacy set has no create2 and no TTL create.
        let ttl = MultiOp::Create {
            op_type: opcode::CREATE_TTL,
            path: lp("/a"),
            data: JBuffer::Null,
            acl: JVec::Null,
            mode: 5,
            ttl: 10,
            defect: InputDefect::default(),
        };
        let r = c.encode_multi(vec![ttl.clone()], false);
        assert_eq!(r, Err(validate(ZUNIMPLEMENTED)));
        // A read multi takes reads only, and a write multi takes no reads.
        let get = MultiOp::GetData { path: lp("/a") };
        let r = c.encode_multi(vec![get], false);
        assert_eq!(r, Err(validate(ZUNIMPLEMENTED)));
        let r = c.encode_multi(vec![mcheck(lp("/a"))], true);
        assert_eq!(r, Err(validate(ZUNIMPLEMENTED)));

        let mut n = conn_with(Config::legacy(30_000), Compat::NATIVE);
        let (_, types) = n.encode_multi(vec![ttl], false).unwrap();
        assert_eq!(types, [opcode::CREATE_TTL]);
        let bad_ttl = MultiOp::Create {
            op_type: opcode::CREATE_TTL,
            path: np("/a"),
            data: JBuffer::Null,
            acl: JVec::Null,
            mode: 5,
            ttl: 0,
            defect: InputDefect::default(),
        };
        assert_eq!(n.encode_multi(vec![bad_ttl], false), Err(MARSHAL));
    }

    /// Encodes `rec` and checks it against the bytes of a generated
    /// record.
    fn same_bytes(rec: &DataRecord<'_>, want: &[u8]) {
        let mut out = Vec::new();
        rec.encode(&mut out);
        assert_eq!(out, want);
        assert_eq!(rec.encoded_len(), want.len());
    }

    #[test]
    fn data_records_encode_as_the_generated_records() {
        let entry = ACL {
            perms: 31,
            id: zk_jute::data::Id {
                scheme: JString::from("world"),
                id: JString::from("anyone"),
            },
        };
        let acls = [
            JVec::Null,
            JVec::Items(Vec::new()),
            JVec::Items(vec![entry]),
        ];
        let datas: [Option<&[u8]>; 3] = [None, Some(b""), Some(b"xyz")];
        let paths = [JString::Null, JString::from("/app/a")];
        for (data, path) in datas
            .into_iter()
            .flat_map(|d| paths.iter().map(move |p| (d, p)))
        {
            let buf = JBuffer::from(data.map(<[u8]>::to_vec));
            let set = DataRecord {
                path: path.as_bytes(),
                data,
                tail: DataTail::SetData { version: -7 },
            };
            let want = SetDataRequest {
                path: path.clone(),
                data: buf.clone(),
                version: -7,
            };
            same_bytes(&set, &want.to_bytes());
            for acl in &acls {
                let create = DataRecord {
                    path: path.as_bytes(),
                    data,
                    tail: DataTail::Create { acl, flags: 3 },
                };
                let want = CreateRequest {
                    path: path.clone(),
                    data: buf.clone(),
                    acl: acl.clone(),
                    flags: 3,
                };
                same_bytes(&create, &want.to_bytes());
                let ttl = DataRecord {
                    path: path.as_bytes(),
                    data,
                    tail: DataTail::CreateTtl {
                        acl,
                        flags: 5,
                        ttl: 0x00ff_0000_0001,
                    },
                };
                let want = CreateTTLRequest {
                    path: path.clone(),
                    data: buf.clone(),
                    acl: acl.clone(),
                    flags: 5,
                    ttl: 0x00ff_0000_0001,
                };
                same_bytes(&ttl, &want.to_bytes());
            }
        }
        assert_eq!(wire_buffer(b"abc"), (3, &b"abc"[..]));
        assert_eq!(wire_buffer(b""), (0, &b""[..]));
    }

    /// The data ops of the borrowed entry: a set data, a create, a
    /// create2 and a TTL create.
    fn data_ops(path: &str, data: JBuffer) -> Vec<Op<u32>> {
        let create = |mode, ttl, create2| Op::Create {
            path: lp(path),
            data: data.clone(),
            acl: JVec::Items(Vec::new()),
            mode,
            ttl,
            create2,
        };
        vec![
            Op::SetData {
                path: lp(path),
                data: data.clone(),
                version: 4,
            },
            create(0, -1, false),
            create(2, -1, true),
            create(5, 10, false),
            create(4, -1, false),
        ]
    }

    /// Gives the queued frame and the log records of one submit, or the
    /// stage and code of its failure.
    fn outcome(
        c: &mut Connection<Tk>,
        op: Op<u32>,
        defect: InputDefect,
        data: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<LogRecord>), (Stage, i32)> {
        let r = match data {
            None => c.submit(req(op, defect), Millis(0)),
            Some(d) => c.submit_with_data(req(op, defect), Some(d), Millis(0)),
        };
        match r {
            Ok(Submitted::Queued { .. }) => {
                let f = c.requests.tx.pop_back().unwrap();
                let _ = c.requests.fifo.pop_back();
                Ok((f.bytes.as_slice().to_vec(), logs(c)))
            }
            Ok(Submitted::Local(_)) => panic!("local"),
            Err(e) => {
                assert_eq!(e.token, 7);
                assert!(logs(c).is_empty());
                Err((e.stage, e.code))
            }
        }
    }

    #[test]
    fn borrowed_data_encodes_as_owned_data() {
        for compat in [Compat::LEGACY_C, Compat::NATIVE] {
            let mut owned = chrooted(compat);
            let mut borrowed = chrooted(compat);
            for value in [&b"payload"[..], b""] {
                let ops = data_ops("/a", JBuffer::from(value));
                for (o, b) in ops.into_iter().zip(data_ops("/a", JBuffer::Null)) {
                    let want = outcome(&mut owned, o, InputDefect::default(), None);
                    let got = outcome(&mut borrowed, b, InputDefect::default(), Some(value));
                    assert!(want.is_ok());
                    assert_eq!(got, want);
                }
            }
            // `None` keeps the data of the op, the null buffer here.
            for op in data_ops("/a", JBuffer::Null) {
                let want = outcome(&mut owned, op, InputDefect::default(), None);
                let (frame, _) = want.unwrap();
                assert_eq!(
                    &frame[REQUEST_HEAD_LEN + 4 + 6..][..4],
                    &(-1i32).to_be_bytes()
                );
            }
        }
    }

    #[test]
    fn borrowed_data_keeps_the_stage_order() {
        // Each case is a connection set-up, an op path, a TTL and a defect.
        let closing = |c: &mut Connection<Tk>| c.close.closing = true;
        let expired = |c: &mut Connection<Tk>| c.set_state(State::ExpiredSession);
        let drain = || {
            let mut compat = Compat::LEGACY_C;
            compat.close_mode = CloseMode::Drain;
            let mut c = conn_with(Config::legacy(30_000), compat);
            c.close.closing = true;
            c
        };
        let throttled = || {
            let mut cfg = Config::legacy(30_000);
            cfg.max_pending = Some(0);
            conn_with(cfg, Compat::LEGACY_C)
        };
        let setups: [&dyn Fn() -> Connection<Tk>; 5] = [
            &legacy,
            &drain,
            &throttled,
            &|| {
                let mut c = legacy();
                expired(&mut c);
                c
            },
            &|| {
                let mut c = legacy();
                closing(&mut c);
                c
            },
        ];
        for setup in setups {
            for path in ["/a", "a", "/a/"] {
                for defect in [InputDefect::default(), DEFECT] {
                    let owned = data_ops(path, JBuffer::from(&b"v"[..]));
                    for (o, b) in owned.into_iter().zip(data_ops(path, JBuffer::Null)) {
                        let want = outcome(&mut setup(), o, defect, None);
                        let got = outcome(&mut setup(), b, defect, Some(b"v"));
                        assert_eq!(got, want, "{path} {defect:?}");
                    }
                }
            }
        }
        // A bad TTL fails at row 1 on both entries.
        let mut c = legacy();
        let op = create(lp("/a"), 5, 0);
        assert_eq!(outcome(&mut c, op, DEFECT, Some(b"v")), Err(VALIDATE_BAD));
        assert_untouched(&c);
    }

    /// The borrowed form of an owned sub-op. A read sub-op has no
    /// borrowed form, and a write multi rejects it with its type, as
    /// `MultiOpRef::Other` does.
    fn as_ref_op(op: &MultiOp) -> MultiOpRef<'_> {
        fn path(p: &PathIn) -> Option<&[u8]> {
            match p {
                PathIn::Legacy(b) => b.as_deref(),
                PathIn::Native(s) => s.as_bytes(),
            }
        }
        match op {
            MultiOp::Create {
                op_type,
                path: p,
                data,
                acl,
                mode,
                ttl,
                defect,
            } => MultiOpRef::Create {
                op_type: *op_type,
                path: path(p),
                data: data.as_bytes(),
                acl: acl.clone(),
                mode: *mode,
                ttl: *ttl,
                defect: *defect,
            },
            MultiOp::Delete {
                path: p,
                version,
                defect,
            } => MultiOpRef::Delete {
                path: path(p),
                version: *version,
                defect: *defect,
            },
            MultiOp::SetData {
                path: p,
                data,
                version,
                defect,
            } => MultiOpRef::SetData {
                path: path(p),
                data: data.as_bytes(),
                version: *version,
                defect: *defect,
            },
            MultiOp::Check {
                path: p,
                version,
                defect,
            } => MultiOpRef::Check {
                path: path(p),
                version: *version,
                defect: *defect,
            },
            other => MultiOpRef::Other {
                op_type: other.op_type(),
            },
        }
    }

    /// A write multi sub-op set: creates with data, null data and empty
    /// data, an ACL, a sequential and a container create, set data with
    /// data and with null data, a check and a delete.
    fn ref_sub_ops(path: fn(&str) -> PathIn) -> Vec<MultiOp> {
        let entry = ACL {
            perms: 31,
            id: zk_jute::data::Id {
                scheme: JString::from("world"),
                id: JString::from("anyone"),
            },
        };
        let mk = |op_type, p: &str, data, acl, mode| MultiOp::Create {
            op_type,
            path: path(p),
            data,
            acl,
            mode,
            ttl: -1,
            defect: InputDefect::default(),
        };
        vec![
            mk(
                opcode::CREATE,
                "/a",
                JBuffer::Bytes(vec![1, 2]),
                JVec::Null,
                0,
            ),
            mk(
                opcode::CREATE,
                "/c",
                JBuffer::Null,
                JVec::Items(vec![entry]),
                2,
            ),
            mk(
                opcode::CREATE_CONTAINER,
                "/k",
                JBuffer::Bytes(Vec::new()),
                JVec::Items(Vec::new()),
                4,
            ),
            MultiOp::SetData {
                path: path("/s"),
                data: JBuffer::Bytes(vec![7; 8]),
                version: -1,
                defect: InputDefect::default(),
            },
            MultiOp::SetData {
                path: path("/n"),
                data: JBuffer::Null,
                version: 4,
                defect: InputDefect::default(),
            },
            mcheck(path("/b")),
            mdelete(path("/d")),
        ]
    }

    /// The native create2 and TTL creates of a write multi.
    fn native_creates(ttl: i64) -> Vec<MultiOp> {
        let mk = |op_type, mode, ttl| MultiOp::Create {
            op_type,
            path: np("/t"),
            data: JBuffer::Bytes(vec![9]),
            acl: JVec::Items(Vec::new()),
            mode,
            ttl,
            defect: InputDefect::default(),
        };
        vec![mk(opcode::CREATE2, 0, -1), mk(opcode::CREATE_TTL, 5, ttl)]
    }

    /// Encodes `ops` as owned and as borrowed sub-ops on two equal
    /// connections. It checks that both give the same result and the
    /// same log output, and returns the result.
    fn same_multi(
        mk: &dyn Fn() -> Connection<Tk>,
        ops: Vec<MultiOp>,
        expired: bool,
    ) -> Result<(Vec<u8>, Vec<i32>), Rejected> {
        let (mut owned, mut borrowed) = (mk(), mk());
        if expired {
            owned.set_state(State::ExpiredSession);
            borrowed.set_state(State::ExpiredSession);
        }
        let refs: Vec<MultiOpRef<'_>> = ops.iter().map(as_ref_op).collect();
        let got = borrowed.encode_multi(&refs, false);
        let want = owned.encode_multi(ops, false);
        assert_eq!(got, want);
        assert_eq!(logs(&mut borrowed), logs(&mut owned));
        want
    }

    #[test]
    fn ref_encoder_matches_the_owned_encoder() {
        let legacy_conns: [&dyn Fn() -> Connection<Tk>; 2] =
            [&legacy, &|| chrooted(Compat::LEGACY_C)];
        let native_conns: [&dyn Fn() -> Connection<Tk>; 2] = [
            &|| conn_with(Config::legacy(30_000), Compat::NATIVE),
            &|| chrooted(Compat::NATIVE),
        ];
        for mk in legacy_conns {
            let r = same_multi(mk, ref_sub_ops(lp), false);
            assert_eq!(r.map(|(_, t)| t.len()), Ok(7));
            // The legacy set has no create2 and no TTL create.
            let r = same_multi(mk, native_creates(10), false);
            assert_eq!(r, Err(validate(ZUNIMPLEMENTED)));
        }
        for mk in native_conns {
            let mut ops = ref_sub_ops(np);
            ops.extend(native_creates(10));
            let r = same_multi(mk, ops, false);
            assert_eq!(r.map(|(_, t)| t.len()), Ok(9));
            // A bad TTL fails after the scan.
            let r = same_multi(mk, native_creates(0), false);
            assert_eq!(r, Err(MARSHAL));
        }
        for mk in legacy_conns {
            // A NULL path, a bad path, a defect and a bad value buffer.
            let null = vec![mcheck(lp("/a")), mdelete(PathIn::Legacy(None))];
            assert_eq!(same_multi(mk, null, false), Err(MARSHAL));
            let bad = vec![mdelete(lp("bad")), mcheck(lp("/c"))];
            assert_eq!(same_multi(mk, bad, false), Err(MARSHAL));
            let mut defect = ref_sub_ops(lp);
            if let Some(MultiOp::SetData { defect: d, .. }) = defect.get_mut(3) {
                *d = DEFECT;
            }
            assert_eq!(same_multi(mk, defect, false), Err(MARSHAL));
            // A type outside the set wins over an earlier failure, and
            // logs the unimplemented site once.
            let unimpl = vec![
                mdelete(lp("bad")),
                MultiOp::Other { op_type: 7 },
                mcheck(lp("/c")),
            ];
            assert_eq!(same_multi(mk, unimpl, false), Err(validate(ZUNIMPLEMENTED)));
            let read = vec![MultiOp::GetData { path: lp("/a") }];
            assert_eq!(same_multi(mk, read, false), Err(validate(ZUNIMPLEMENTED)));
            // An unrecoverable state fails with ops and with no ops.
            assert_eq!(same_multi(mk, ref_sub_ops(lp), true), Err(MARSHAL));
            assert_eq!(same_multi(mk, Vec::new(), true), Err(MARSHAL));
        }
        // A read multi takes no borrowed sub-op.
        let mut c = legacy();
        let check = mcheck(lp("/a"));
        let refs = [as_ref_op(&check)];
        assert_eq!(c.encode_multi(&refs, true), Err(validate(ZUNIMPLEMENTED)));
    }

    /// Submits a write multi. With `refs`, it uses the borrowed entry and
    /// an op with no sub-ops. It gives the frame and the logs, or the
    /// stage and the code.
    fn multi_outcome(
        c: &mut Connection<Tk>,
        ops: Vec<MultiOp>,
        refs: Option<&[MultiOpRef<'_>]>,
        defect: InputDefect,
    ) -> Result<(Vec<u8>, Vec<LogRecord>), (Stage, i32)> {
        let r = match refs {
            None => c.submit(req(Op::Multi { ops }, defect), Millis(0)),
            Some(r) => {
                let op = Op::Multi { ops: Vec::new() };
                c.submit_multi_ref(req(op, defect), r, Millis(0))
            }
        };
        match r {
            Ok(Submitted::Queued { .. }) => {
                let f = c.requests.tx.pop_back().unwrap();
                let _ = c.requests.fifo.pop_back();
                Ok((f.bytes.as_slice().to_vec(), logs(c)))
            }
            Ok(Submitted::Local(_)) => panic!("local"),
            Err(e) => {
                assert_eq!(e.token, 7);
                Err((e.stage, e.code))
            }
        }
    }

    #[test]
    fn borrowed_multi_submits_as_owned_multi() {
        for compat in [Compat::LEGACY_C, Compat::NATIVE] {
            let mut owned = chrooted(compat);
            let mut borrowed = chrooted(compat);
            let path = if compat.native_ops { np } else { lp };
            let ops = ref_sub_ops(path);
            let refs: Vec<MultiOpRef<'_>> = ops.iter().map(as_ref_op).collect();
            let want = multi_outcome(&mut owned, ops.clone(), None, InputDefect::default());
            let got = multi_outcome(
                &mut borrowed,
                Vec::new(),
                Some(&refs),
                InputDefect::default(),
            );
            assert!(want.as_ref().is_ok_and(|(_, l)| l.len() == 1));
            assert_eq!(got, want);
            // A request defect fails at the serialization stage.
            let want = multi_outcome(&mut owned, ops.clone(), None, DEFECT);
            let got = multi_outcome(&mut borrowed, Vec::new(), Some(&refs), DEFECT);
            assert_eq!(want, Err((Stage::Enqueue, ZMARSHALLINGERROR)));
            assert_eq!(got, want);
            // A bad sub-op path fails at the serialization stage.
            let bad = vec![mdelete(path("bad"))];
            let bad_refs: Vec<MultiOpRef<'_>> = bad.iter().map(as_ref_op).collect();
            let want = multi_outcome(&mut owned, bad.clone(), None, InputDefect::default());
            let got = multi_outcome(
                &mut borrowed,
                Vec::new(),
                Some(&bad_refs),
                InputDefect::default(),
            );
            assert_eq!(want, Err((Stage::Enqueue, ZMARSHALLINGERROR)));
            assert_eq!(got, want);
            assert_untouched(&owned);
            assert_untouched(&borrowed);
        }
        // For another op the borrowed sub-ops are not used.
        let check = mcheck(lp("/a"));
        let refs = [as_ref_op(&check)];
        let mut owned = legacy();
        let mut borrowed = legacy();
        let op = Op::Delete {
            path: lp("/x"),
            version: 2,
        };
        let want = owned.submit(req(op.clone(), InputDefect::default()), Millis(0));
        let got = borrowed.submit_multi_ref(req(op, InputDefect::default()), &refs, Millis(0));
        assert!(matches!(want, Ok(Submitted::Queued { xid: 1 })));
        assert!(matches!(got, Ok(Submitted::Queued { xid: 1 })));
        let frame = |c: &Connection<Tk>| c.requests.tx.back().map(|f| f.bytes.as_slice().to_vec());
        assert_eq!(frame(&borrowed), frame(&owned));
    }
}
