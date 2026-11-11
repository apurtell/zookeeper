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

//! The receive pipeline.
//!
//! The module owns [`Recv`]. `handle_read` feeds bytes to the frame
//! decoder and dispatches each complete frame by phase and by xid.
//! It also builds the completion outputs and
//! their delivery log lines.

use core::ops::Range;

use zeroize::Zeroize;
use zk_jute::data::Stat;
use zk_jute::multi::{self, MultiBody, MultiKind};
use zk_jute::proto::{
    Create2Response, CreateResponse, GetACLResponse, GetAllChildrenNumberResponse,
    GetChildren2Response, GetChildrenResponse, GetDataResponse, GetEphemeralsResponse, ReplyHeader,
    SetDataResponse, WhoAmIResponse,
};
use zk_jute::rc::{ZINVALIDSTATE, ZMARSHALLINGERROR, ZNOTHING, ZOK, ZRUNTIMEINCONSISTENCY};
use zk_jute::{FrameDecoder, FrameError, JString, JVec, Pushed, Reader, Record, opcode, xid};

use crate::action::ReadOutcome;
use crate::compat::{ChrootPolicy, CloseMode, NegativeLen};
use crate::connection::Connection;
use crate::errno::EHOSTDOWN;
use crate::hooks::Tokens;
use crate::legacy::chroot::{self, Stripped};
use crate::log::{LogArg, LogRecord, LogSite, str_arg};
use crate::output::{OpResult, Origin, Output, Reply, Work};
use crate::request::Route;
use crate::requests::{Pending, Shape};
use crate::responses::{LARGE, Spares};
use crate::state::{Cause, Phase};
use crate::time::{self, Millis};

/// What the dispatch of one frame tells the read loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    /// The frame is done. The loop continues with the next frame.
    Continue,
    /// The loop stops with `ZOK`: a barrier is pending, or the phase waits
    /// for mechanism work.
    Stop,
    /// The loop stops with this rc: a teardown rc, `ZINVALIDSTATE`,
    /// `ZAUTHFAILED` or a SASL rc.
    Done(i32),
}

/// The receive state.
pub(crate) struct Recv {
    /// The frame decoder. Its limit is `Compat::max_frame_len`.
    pub(crate) decoder: FrameDecoder,
    /// True after a negative frame length under `StallUntilTimeout`. The
    /// decoder reads nothing until the next transport.
    pub(crate) stalled: bool,
    /// The spare slot. A large DATA reply can take the frame body, and
    /// the slot then gives the decoder a spare buffer in its place.
    pub(crate) spares: Spares,
}

impl Recv {
    /// Makes a receive state with the frame length limit.
    pub(crate) fn new(max_frame_len: Option<u32>) -> Self {
        Self {
            decoder: FrameDecoder::new(max_frame_len),
            stalled: false,
            spares: Spares::default(),
        }
    }

    /// Drops every partial frame. A teardown calls it at T1.
    pub(crate) fn reset(&mut self) {
        self.decoder.reset();
        self.stalled = false;
        self.spares.reset();
    }
}

/// What one decoder result tells the read loop of `handle_read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Took {
    /// A complete frame was processed.
    frame: bool,
    /// The loop goes on with the next bytes.
    next: bool,
    /// The stop rc, if any.
    rc: Option<i32>,
}

impl Took {
    /// The decoder needs more bytes.
    const STOP: Self = Self {
        frame: false,
        next: false,
        rc: None,
    };
}

/// The handler that takes a complete frame in the current phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameRoute {
    /// The frame is the `ConnectResponse`.
    Connect,
    /// The frame is a SASL reply. It has no xid check.
    Sasl,
    /// The frame starts with a `ReplyHeader`.
    Header,
}

/// Selects the frame handler from the phase.
fn frame_route(phase: Phase, handshake_pending: bool) -> FrameRoute {
    match phase {
        Phase::Associating if handshake_pending => FrameRoute::Connect,
        Phase::Sasl(_) => FrameRoute::Sasl,
        _ => FrameRoute::Header,
    }
}

/// The handler of a frame with a `ReplyHeader`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XidRoute {
    /// A ping reply.
    Ping,
    /// A watch event.
    Watcher,
    /// A SetWatches reply.
    SetWatches,
    /// An AUTH reply.
    Auth,
    /// A reply to a request in the FIFO.
    Reply,
}

/// Selects the handler from the special xids.
fn xid_route(x: i32) -> XidRoute {
    match x {
        xid::PING => XidRoute::Ping,
        xid::WATCHER_EVENT => XidRoute::Watcher,
        xid::SET_WATCHES => XidRoute::SetWatches,
        xid::AUTH => XidRoute::Auth,
        _ => XidRoute::Reply,
    }
}

/// What the read loop does after a frame length error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LenAction {
    /// The decoder stops until the next transport.
    Stall,
    /// The connection tears down with this cause and errno.
    Teardown(Cause, i32),
}

/// Selects the action for a frame length error.
///
/// A negative length follows the profile. A zero length acts as in C: the
/// receive of 0 bytes is an end of stream with `EHOSTDOWN`. A
/// length over the limit is a protocol error.
fn len_action(e: FrameError, policy: NegativeLen) -> LenAction {
    match (e, policy) {
        (FrameError::Negative(_), NegativeLen::StallUntilTimeout) => LenAction::Stall,
        (FrameError::Negative(_), NegativeLen::Disconnect) | (FrameError::TooLarge(_), _) => {
            LenAction::Teardown(Cause::ProtocolError, 0)
        }
        (FrameError::Empty, _) => LenAction::Teardown(Cause::Eof, EHOSTDOWN),
    }
}

/// How a reply relates to the FIFO head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadMatch {
    /// The reply answers the CLOSE_OP of a `Drain` close.
    CloseReply,
    /// A close cleared the FIFO. The frame is dropped.
    ClosingDrop,
    /// The FIFO is empty and no close runs.
    NoHead,
    /// The head is not written, or it has another xid.
    Mismatch,
    /// The reply answers the head.
    Hit,
}

/// Why a reply body did not decode.
#[derive(Debug)]
enum DecodeFail {
    /// The body is not valid. The connection tears down.
    Malformed,
    /// A path is outside the chroot under `ChrootPolicy::Component`. The
    /// request fails with `ZMARSHALLINGERROR`. The value holds the ERROR
    /// lines.
    Outside(Vec<LogRecord>),
}

/// A decoded reply body and its strip log lines.
#[derive(Debug)]
struct Decoded {
    /// The reply, with the chroot stripped from its paths.
    reply: Reply,
    /// The rc of a multi, else `ZOK`.
    rc: i32,
    /// The strip lines of the reply path. They follow the first delivery
    /// line.
    head_logs: Vec<LogRecord>,
    /// The strip lines of each multi result. Each list follows the line of
    /// its sub-op.
    item_logs: Vec<Vec<LogRecord>>,
}

/// Returns the legacy log site of a multi sub-op from its request op type
/// (zookeeper.c:3298-3336). A create gives STRING, setData gives STAT, and
/// delete and check give VOID. Other types have no legacy line.
fn sub_op_site(op_type: i32) -> Option<LogSite> {
    match op_type {
        opcode::CREATE | opcode::CREATE2 | opcode::CREATE_CONTAINER | opcode::CREATE_TTL => {
            Some(LogSite::CompletionString)
        }
        opcode::SET_DATA => Some(LogSite::CompletionStat),
        opcode::DELETE | opcode::CHECK => Some(LogSite::CompletionVoid),
        _ => None,
    }
}

/// Decodes one record from the reader.
fn read_record<R: Record>(r: &mut Reader<'_>) -> Result<R, DecodeFail> {
    R::decode(r).map_err(|_| DecodeFail::Malformed)
}

/// Reads the value of a `GetDataResponse` with no copy, as the `JBuffer`
/// decoder reads it. It gives the range of the value in the reader input,
/// or `None` for null data.
fn read_data_range(r: &mut Reader<'_>) -> Result<Option<Range<usize>>, DecodeFail> {
    let len = r.read_i32().map_err(|_| DecodeFail::Malformed)?;
    if len == -1 {
        return Ok(None);
    }
    let n = usize::try_from(len).map_err(|_| DecodeFail::Malformed)?;
    let start = r.position();
    r.read_bytes(n).map_err(|_| DecodeFail::Malformed)?;
    Ok(Some(start..start.saturating_add(n)))
}

/// Returns the three integer arguments of a delivery line.
fn int_args(a: i64, b: i64, c: i64) -> Vec<LogArg> {
    vec![LogArg::I64(a), LogArg::I64(b), LogArg::I64(c)]
}

impl<T: Tokens> Connection<T> {
    /// Returns the number of bytes that complete the current frame part.
    ///
    /// The single-threaded driver reads exactly this many bytes, so it
    /// reads one frame per call as C does. The value is 0 while the
    /// decoder is stalled.
    #[must_use]
    pub fn read_hint(&self) -> usize {
        self.recv.decoder.want()
    }

    /// Processes received bytes.
    ///
    /// Contract:
    /// - With no transport, or while a stage is suspended, it consumes
    ///   nothing and returns `rc = ZINVALIDSTATE`.
    /// - It pushes bytes to the decoder. Each complete frame sets
    ///   `timers.on_recv(now)` and goes to `dispatch_body`.
    /// - It stops after a `Flow::Stop` or `Flow::Done`, after a direct
    ///   reply, or when `sasl_awaiting_mechanism` is true. The bytes it did
    ///   not consume stay with the caller: `consumed` counts only the bytes
    ///   the decoder took.
    /// - A frame length error follows `Compat::negative_frame_len`: a
    ///   stall (no read interest until the receive timeout), or a teardown
    ///   with `Cause::ProtocolError`. A zero length tears down with
    ///   `ZCONNECTIONLOSS`.
    /// - `rc` is `ZOK` when a frame was
    ///   processed, `ZNOTHING` for a partial frame, else the stop rc.
    pub fn handle_read(&mut self, bytes: &[u8], now: Millis) -> ReadOutcome {
        if !self.core.has_transport || self.out.is_suspended() {
            return ReadOutcome {
                frames: 0,
                consumed: 0,
                rc: ZINVALIDSTATE,
            };
        }
        let mut frames = 0usize;
        let mut consumed = 0usize;
        let mut stop_rc = None;
        loop {
            if self.recv.stalled || self.recv_waits_for_mechanism() {
                break;
            }
            let rest = bytes.get(consumed..).unwrap_or_default();
            let (n, pushed) = self.recv.decoder.push(rest);
            consumed = consumed.saturating_add(n);
            let took = self.take_pushed(pushed, now);
            if took.frame {
                frames = frames.saturating_add(1);
            }
            stop_rc = took.rc;
            if !took.next {
                break;
            }
        }
        let rc = stop_rc.unwrap_or(if frames > 0 { ZOK } else { ZNOTHING });
        ReadOutcome {
            frames,
            consumed,
            rc,
        }
    }

    /// Returns the free part of the current frame body, so that the driver
    /// can read straight into it. The part has at most `max` bytes, and
    /// never more than 64 KiB or the rest of the body.
    ///
    /// The part is empty when `handle_read` would take no bytes now: with
    /// no transport, while a stage is suspended, while the decoder stalls,
    /// or while a SASL reply waits for the mechanism. It is also empty
    /// outside a body, for example in the length prefix. The driver then
    /// reads into its own buffer and calls `handle_read`.
    pub fn body_room(&mut self, max: usize) -> &mut [u8] {
        if !self.core.has_transport
            || self.out.is_suspended()
            || self.recv.stalled
            || self.recv_waits_for_mechanism()
        {
            return Default::default();
        }
        self.recv.decoder.body_room(max)
    }

    /// Processes `n` bytes that the driver wrote at the start of the last
    /// [`Connection::body_room`] part. It follows the contract of
    /// `handle_read`. One call completes at most one frame, because the
    /// part ends at the end of the body.
    pub fn handle_body_read(&mut self, n: usize, now: Millis) -> ReadOutcome {
        if !self.core.has_transport || self.out.is_suspended() {
            return ReadOutcome {
                frames: 0,
                consumed: 0,
                rc: ZINVALIDSTATE,
            };
        }
        let pushed = self.recv.decoder.commit(n);
        let took = self.take_pushed(pushed, now);
        let frames = usize::from(took.frame);
        let rc = took.rc.unwrap_or(if took.frame { ZOK } else { ZNOTHING });
        ReadOutcome {
            frames,
            consumed: n,
            rc,
        }
    }

    /// Acts on one decoder result. A complete frame goes to
    /// `dispatch_body`, and its buffer then goes back to the decoder. A
    /// length error stalls the decoder or tears down, by the compat rule.
    fn take_pushed(&mut self, pushed: Pushed, now: Millis) -> Took {
        match pushed {
            Pushed::NeedMore => Took::STOP,
            Pushed::Frame(mut body) => {
                self.timers.on_recv(now);
                let small = body.len() < LARGE;
                let flow = self.dispatch_body(&mut body, now);
                // The secret routes clear their body in dispatch_body.
                // A large DATA reply can swap the body for a spare. The
                // decoder can then use the memory for the next frame.
                // After a teardown it takes no buffer from the old link.
                if self.core.has_transport {
                    self.recv.decoder.recycle(body);
                }
                if small {
                    self.recv.spares.release();
                }
                let (next, rc) = match flow {
                    Flow::Continue => (!self.out.is_suspended() && self.core.has_transport, None),
                    Flow::Stop => (false, None),
                    Flow::Done(rc) => (false, Some(rc)),
                };
                Took {
                    frame: true,
                    next,
                    rc,
                }
            }
            Pushed::Error(e) => {
                let rc = match len_action(e, self.compat.negative_frame_len) {
                    LenAction::Stall => {
                        self.recv.decoder.stall();
                        self.recv.stalled = true;
                        None
                    }
                    LenAction::Teardown(cause, errno) => Some(self.teardown(cause, errno, now)),
                };
                Took {
                    frame: false,
                    next: false,
                    rc,
                }
            }
        }
    }

    /// Dispatches one complete frame body.
    ///
    /// Contract:
    /// - Associating with the handshake pending: `on_connect_response`.
    /// - Sasl phase: `on_sasl_reply`, with no xid check.
    /// - Otherwise it peeks the `ReplyHeader`. Fewer than 16 bytes tears
    ///   down with `Cause::ProtocolError`.
    /// - xid -2: the latency DEBUG log, then drop.
    /// - xid -1: `on_watcher_event`.
    /// - xid -8: the DEBUG log, then drop.
    /// - xid -4: `on_auth_reply`.
    /// - Any other xid: `dispatch_reply`.
    ///
    /// The connect response holds the session password, and a SASL reply
    /// holds a server token. The core clears these bodies before it frees
    /// them. The caller owns the body. This function clears the body after
    /// a secret route.
    fn dispatch_body(&mut self, body: &mut Vec<u8>, now: Millis) -> Flow {
        match frame_route(self.core.phase, self.session.handshake_pending) {
            FrameRoute::Connect => {
                let flow = self.on_connect_response(body, now);
                body.zeroize();
                return flow;
            }
            FrameRoute::Sasl => {
                let flow = self.on_sasl_reply(body, now);
                body.zeroize();
                return flow;
            }
            FrameRoute::Header => {}
        }
        let Ok((hdr, rest)) = ReplyHeader::peek(body) else {
            return Flow::Done(self.teardown(Cause::ProtocolError, 0, now));
        };
        let at = body.len().saturating_sub(rest.len());
        match xid_route(hdr.xid) {
            XidRoute::Ping => {
                let ms = time::elapsed(now, self.timers.last_ping);
                self.emit_log(LogSite::PingResponse, || vec![LogArg::I64(ms)]);
                Flow::Continue
            }
            XidRoute::Watcher => self.on_watcher_event(hdr.zxid, rest, now),
            XidRoute::SetWatches => {
                self.emit_log(LogSite::ProcessingSetWatches, Vec::new);
                Flow::Continue
            }
            XidRoute::Auth => {
                self.emit_log(LogSite::ProcessingAuth, Vec::new);
                self.on_auth_reply(hdr.err, now)
            }
            XidRoute::Reply => self.dispatch_reply(hdr, body, at, now),
        }
    }

    /// Matches a reply to the FIFO head and emits its completion.
    ///
    /// Contract:
    /// - An empty FIFO or an unwritten head: under `Drain`, the recorded
    ///   CLOSE_OP xid goes to `on_close_reply`. Any other reply while
    ///   closing logs, drops the frame and returns `Done(ZINVALIDSTATE)`.
    ///   Otherwise it tears down with `Cause::XidMismatch`.
    /// - A head with another xid tears down with `Cause::XidMismatch`. The
    ///   head stays in the FIFO.
    /// - A match pops the head. A `zxid > 0` sets `core.last_zxid`, also
    ///   for error replies. Then `arm_watch` and `apply_unwatch` (when
    ///   `err == 0`) run before the completion is pushed.
    /// - The reply decodes by shape through `decode_reply`. An error reply
    ///   does not decode, except a `Direct` multi with bytes after the
    ///   header. A decode failure puts the head
    ///   back and tears down with `Cause::ProtocolError`.
    /// - It pushes `Output::Completion` with `completion_logs`. A direct
    ///   completion parks `Work::Hold` and returns `Flow::Stop`.
    ///
    /// The reply body starts at `at` in `body`. A large DATA reply can
    /// take `body` and leave a spare buffer in its place.
    pub(crate) fn dispatch_reply(
        &mut self,
        hdr: ReplyHeader,
        body: &mut Vec<u8>,
        at: usize,
        now: Millis,
    ) -> Flow {
        match self.recv_head_match(hdr.xid) {
            HeadMatch::CloseReply => return self.on_close_reply(now),
            HeadMatch::ClosingDrop => {
                self.emit_log(LogSite::ClearedByClose, Vec::new);
                return Flow::Done(ZINVALIDSTATE);
            }
            // C asserts here. The core tears down instead.
            HeadMatch::NoHead => {
                return Flow::Done(self.teardown(Cause::XidMismatch, 0, now));
            }
            HeadMatch::Mismatch => {
                self.emit_log(LogSite::UnexpectedResponse, Vec::new);
                let head_xid = self.requests.fifo.front().map_or(0, |p| p.xid);
                return Flow::Done(self.teardown_xid_mismatch(hdr.xid, head_xid, 0, now));
            }
            HeadMatch::Hit => {}
        }
        let Some(mut pending) = self.requests.fifo.pop_front() else {
            return Flow::Done(self.teardown(Cause::XidMismatch, 0, now));
        };
        if hdr.zxid > 0 {
            self.core.last_zxid = hdr.zxid;
        }
        // The body decodes before the watch tables change. A decode failure
        // thus leaves no armed watch for an entry that the teardown fails.
        let Some((result, delivery_logs)) = self.recv_reply_result(&pending, &hdr, body, at) else {
            self.requests.fifo.push_front(pending);
            return Flow::Done(self.teardown(Cause::ProtocolError, 0, now));
        };
        if let Some(reg) = pending.watch.take() {
            self.arm_watch(reg, hdr.err);
        }
        if let Some(u) = pending.unwatch.take() {
            if hdr.err == ZOK {
                self.apply_unwatch(u);
            }
        }
        let route = pending.route;
        // C logs this line at receipt, before it queues the completion.
        if route == Route::Queued {
            self.emit_log(LogSite::QueueingAsync, Vec::new);
        }
        self.out.push(Output::Completion {
            token: pending.token,
            route,
            result,
            delivery_logs,
        });
        if route == Route::Direct {
            self.out.park(Work::Hold);
            return Flow::Stop;
        }
        Flow::Continue
    }

    /// Decodes a reply body by shape and strips the chroot from its paths.
    ///
    /// Contract:
    /// - Each shape decodes its response record. A multi uses
    ///   `zk_jute::multi::decode_multi` with the sub-op count.
    /// - Paths pass through `strip_path`, which appends the mismatch
    ///   ERROR to `logs`.
    /// - Under `ChrootPolicy::Component`, a path outside the chroot fails
    ///   with `ZMARSHALLINGERROR` and an ERROR log. Ephemeral entries
    ///   outside the chroot are dropped with no log.
    ///
    /// # Errors
    ///
    /// Returns the rc of the failure: a decode error tears down, and
    /// `ZMARSHALLINGERROR` fails the request.
    ///
    /// `dispatch_reply` uses the richer `recv_reply_result`, which keeps
    /// the path lines apart from the item lines. This form exists for the
    /// unit tests of the decode rules.
    #[cfg(test)]
    pub(crate) fn decode_reply(
        &self,
        shape: &Shape,
        rest: &[u8],
        logs: &mut Vec<LogRecord>,
    ) -> Result<(Reply, i32), i32> {
        match self.recv_decode_record(shape, rest) {
            Ok(d) => {
                logs.extend(d.head_logs);
                logs.extend(d.item_logs.into_iter().flatten());
                Ok((d.reply, d.rc))
            }
            Err(DecodeFail::Malformed) => {
                Err(Cause::ProtocolError.rc_for(self.compat.disconnect_rc))
            }
            Err(DecodeFail::Outside(lines)) => {
                logs.extend(lines);
                Err(ZMARSHALLINGERROR)
            }
        }
    }

    /// Strips the chroot from a server path.
    ///
    /// Contract: legacy uses `legacy::chroot::strip_c`
    /// rules. A mismatch keeps the raw path and appends the ERROR "server
    /// path %s does not include chroot path %s" to `logs`. Under
    /// `Component` it uses `legacy::chroot::strip` and returns `None` for
    /// a path outside the chroot.
    pub(crate) fn strip_path(&self, server: &[u8], logs: &mut Vec<LogRecord>) -> Option<JString> {
        let root = self.recv_chroot();
        let stripped = self.recv_strip_rule(root, server);
        if stripped.mismatch {
            let record = self.log.record(LogSite::ChrootMismatch, || {
                vec![str_arg(server), str_arg(root.unwrap_or_default())]
            });
            logs.extend(record);
            if self.compat.chroot == ChrootPolicy::Component {
                return None;
            }
        }
        Some(JString::Bytes(stripped.path.into_owned()))
    }

    /// Returns the delivery log lines that come before a completion.
    ///
    /// Contract:
    /// - `Route::Queued`: "Calling COMPLETION_X for xid=%#x failed=%d
    ///   rc=%d", from `Shape::legacy_kind`. A multi adds one line per
    ///   sub-op.
    /// - `Route::Direct`: "Processing sync_completion with type=%d
    ///   xid=%#x rc=%d", and for a multi the same sub-op lines.
    /// - Each record obeys the log filter.
    pub(crate) fn completion_logs(
        &self,
        pending: &Pending<T>,
        failed: bool,
        rc: i32,
        reply: Option<&Reply>,
    ) -> Vec<LogRecord> {
        self.recv_delivery_logs(pending, failed, rc, reply, Vec::new(), Vec::new())
    }

    /// Builds the failure completion of a FIFO entry that a teardown or a
    /// close fails.
    ///
    /// Contract: the result is `OpResult::teardown(rc)`.
    /// A `Queued` entry carries the "Calling COMPLETION_X ... failed=1
    /// rc=%d" line. A `Direct` entry carries no line. The watch
    /// registration is dropped.
    pub(crate) fn teardown_completion(&self, pending: Pending<T>, rc: i32) -> Output<T> {
        let delivery_logs = match pending.route {
            Route::Queued => self.completion_logs(&pending, true, rc, None),
            Route::Direct => Vec::new(),
        };
        Output::Completion {
            token: pending.token,
            route: pending.route,
            result: OpResult::teardown(rc),
            delivery_logs,
        }
    }
}

// Private helpers of the receive pipeline.
impl<T: Tokens> Connection<T> {
    /// Returns true when the read loop waits for SASL mechanism work.
    ///
    /// The check applies only in the Sasl phase. A stale result of an old
    /// transport then cannot block the next handshake.
    fn recv_waits_for_mechanism(&self) -> bool {
        matches!(self.core.phase, Phase::Sasl(_)) && self.sasl_awaiting_mechanism()
    }

    /// Classifies a reply against the FIFO head.
    fn recv_head_match(&self, reply_xid: i32) -> HeadMatch {
        let head = self.requests.fifo.front();
        match head {
            Some(p) if p.written => {
                if p.xid == reply_xid {
                    HeadMatch::Hit
                } else {
                    HeadMatch::Mismatch
                }
            }
            _ if self.close.closing => {
                if self.compat.close_mode == CloseMode::Drain
                    && self.close.close_xid == Some(reply_xid)
                {
                    HeadMatch::CloseReply
                } else {
                    HeadMatch::ClosingDrop
                }
            }
            Some(_) => HeadMatch::Mismatch,
            None => HeadMatch::NoHead,
        }
    }

    /// Builds the result and the delivery lines of a matched reply.
    ///
    /// An error reply has no body, except a Direct multi with bytes after
    /// the header, as `process_sync_completion` decodes it. It returns
    /// `None` when the body is not valid, so the caller tears down.
    fn recv_reply_result(
        &self,
        pending: &Pending<T>,
        hdr: &ReplyHeader,
        body: &mut Vec<u8>,
        at: usize,
    ) -> Option<(OpResult, Vec<LogRecord>)> {
        let failed = hdr.err != ZOK;
        let is_multi = matches!(pending.shape, Shape::Multi { .. });
        let has_rest = body.len() > at;
        let decode = !failed || (is_multi && pending.route == Route::Direct && has_rest);
        let fail = |rc: i32| OpResult {
            rc,
            zxid: hdr.zxid,
            origin: Origin::Reply,
            reply: None,
        };
        if !decode {
            let logs = self.completion_logs(pending, true, hdr.err, None);
            return Some((fail(hdr.err), logs));
        }
        match self.recv_decode_body(&pending.shape, body, at) {
            Ok(d) => {
                let rc = if is_multi { d.rc } else { hdr.err };
                let logs = self.recv_delivery_logs(
                    pending,
                    failed,
                    hdr.err,
                    Some(&d.reply),
                    d.head_logs,
                    d.item_logs,
                );
                let result = OpResult {
                    rc,
                    zxid: hdr.zxid,
                    origin: Origin::Reply,
                    reply: Some(d.reply),
                };
                Some((result, logs))
            }
            Err(DecodeFail::Malformed) => None,
            Err(DecodeFail::Outside(lines)) => {
                let mut logs = self.completion_logs(pending, true, ZMARSHALLINGERROR, None);
                logs.extend(lines);
                Some((fail(ZMARSHALLINGERROR), logs))
            }
        }
    }

    /// Decodes the reply body at `at` in `body`. A DATA reply can take a
    /// large value straight from `body`, with no copy. Every other shape
    /// decodes from a borrowed slice.
    fn recv_decode_body(
        &self,
        shape: &Shape,
        body: &mut Vec<u8>,
        at: usize,
    ) -> Result<Decoded, DecodeFail> {
        if !matches!(shape, Shape::Data) {
            return self.recv_decode_record(shape, body.get(at..).unwrap_or_default());
        }
        let mut r = Reader::new(body.get(at..).unwrap_or_default());
        let range = read_data_range(&mut r)?;
        let stat: Stat = read_record(&mut r)?;
        let range = range.map(|v| v.start.saturating_add(at)..v.end.saturating_add(at));
        let data = self
            .recv
            .spares
            .data_of(body, range)
            .ok_or(DecodeFail::Malformed)?;
        Ok(Decoded {
            reply: Reply::Data { data, stat },
            rc: ZOK,
            head_logs: Vec::new(),
            item_logs: Vec::new(),
        })
    }

    /// Decodes a reply body by shape and strips the chroot from its paths.
    /// The DATA shape copies its value here.
    fn recv_decode_record(&self, shape: &Shape, rest: &[u8]) -> Result<Decoded, DecodeFail> {
        let mut r = Reader::new(rest);
        let mut head_logs = Vec::new();
        let reply = match shape {
            Shape::Void => Reply::Void,
            // C reads every STAT reply with the SetDataResponse layout.
            Shape::Stat => Reply::Stat(read_record::<SetDataResponse>(&mut r)?.stat),
            Shape::Data => {
                let v: GetDataResponse = read_record(&mut r)?;
                Reply::Data {
                    data: v.data.into(),
                    stat: v.stat,
                }
            }
            Shape::Path => {
                let v: CreateResponse = read_record(&mut r)?;
                Reply::Path(self.recv_strip_field(v.path, &mut head_logs)?)
            }
            Shape::PathStat => {
                let v: Create2Response = read_record(&mut r)?;
                Reply::PathStat(self.recv_strip_field(v.path, &mut head_logs)?, v.stat)
            }
            Shape::Children => {
                Reply::Children(read_record::<GetChildrenResponse>(&mut r)?.children)
            }
            Shape::Children2 => {
                let v: GetChildren2Response = read_record(&mut r)?;
                Reply::Children2(v.children, v.stat)
            }
            Shape::Acl => {
                let v: GetACLResponse = read_record(&mut r)?;
                Reply::Acl(v.acl, v.stat)
            }
            Shape::Multi { op_types, kind } => {
                return self.recv_decode_multi(&mut r, op_types.len(), *kind);
            }
            Shape::Ephemerals => {
                let v: GetEphemeralsResponse = read_record(&mut r)?;
                Reply::Ephemerals(self.recv_strip_list(v.ephemerals))
            }
            Shape::ChildrenCount => Reply::ChildrenCount(
                read_record::<GetAllChildrenNumberResponse>(&mut r)?.total_number,
            ),
            Shape::WhoAmI => Reply::WhoAmI(read_record::<WhoAmIResponse>(&mut r)?.client_info),
        };
        Ok(Decoded {
            reply,
            rc: ZOK,
            head_logs,
            item_logs: Vec::new(),
        })
    }

    /// Decodes a multi body, strips the create paths and computes the rc.
    ///
    /// The rc of a transaction is the first error result other than `ZOK`
    /// and `ZRUNTIMEINCONSISTENCY` (zookeeper.c:3319-3328). A multiRead
    /// does not fail as a whole, so its rc is `ZOK`.
    fn recv_decode_multi(
        &self,
        r: &mut Reader<'_>,
        expected: usize,
        kind: MultiKind,
    ) -> Result<Decoded, DecodeFail> {
        let mut items =
            multi::decode_multi(r, expected, kind).map_err(|_| DecodeFail::Malformed)?;
        let mut rc = ZOK;
        let mut item_logs = Vec::with_capacity(items.len());
        for item in &mut items {
            let mut logs = Vec::new();
            match &mut item.body {
                MultiBody::Create(c) => {
                    let path = core::mem::replace(&mut c.path, JString::Null);
                    c.path = self.recv_strip_field(path, &mut logs)?;
                }
                MultiBody::Create2(c) => {
                    let path = core::mem::replace(&mut c.path, JString::Null);
                    c.path = self.recv_strip_field(path, &mut logs)?;
                }
                MultiBody::Error(e) => {
                    if rc == ZOK && e.err != ZOK && e.err != ZRUNTIMEINCONSISTENCY {
                        rc = e.err;
                    }
                }
                MultiBody::SetData(_)
                | MultiBody::Empty
                | MultiBody::GetData(_)
                | MultiBody::GetChildren(_) => {}
            }
            item_logs.push(logs);
        }
        let reply = match kind {
            MultiKind::Multi => Reply::Multi(items),
            MultiKind::MultiRead => {
                rc = ZOK;
                Reply::MultiRead(items)
            }
        };
        Ok(Decoded {
            reply,
            rc,
            head_logs: Vec::new(),
            item_logs,
        })
    }

    /// Strips the chroot from one path field. A null path stays null.
    fn recv_strip_field(
        &self,
        path: JString,
        logs: &mut Vec<LogRecord>,
    ) -> Result<JString, DecodeFail> {
        let stripped = path.as_bytes().map(|b| self.strip_path(b, logs));
        match stripped {
            None => Ok(path),
            Some(Some(p)) => Ok(p),
            Some(None) => Err(DecodeFail::Outside(core::mem::take(logs))),
        }
    }

    /// Strips the chroot from each ephemeral path. A path outside the
    /// chroot is dropped with no log line.
    fn recv_strip_list(&self, list: JVec<JString>) -> JVec<JString> {
        let root = self.recv_chroot();
        let Some(items) = list.into_vec() else {
            return JVec::Null;
        };
        let kept = items
            .into_iter()
            .filter_map(|p| match p.as_bytes() {
                None => Some(JString::Null),
                Some(b) => {
                    let s = self.recv_strip_rule(root, b);
                    if s.mismatch {
                        None
                    } else {
                        Some(JString::Bytes(s.path.into_owned()))
                    }
                }
            })
            .collect();
        JVec::Items(kept)
    }

    /// Returns the chroot bytes. C stores a chroot of "/" as no chroot.
    fn recv_chroot(&self) -> Option<&[u8]> {
        self.cfg
            .chroot
            .as_ref()
            .and_then(JString::as_bytes)
            .filter(|c| c.len() > 1)
    }

    /// Strips a server path under the chroot rule of the profile.
    fn recv_strip_rule<'a>(&self, root: Option<&[u8]>, server: &'a [u8]) -> Stripped<'a> {
        match self.compat.chroot {
            ChrootPolicy::LegacyConcatNoEscape => chroot::strip_c(root, server),
            ChrootPolicy::Component => chroot::strip(root, server),
        }
    }

    /// Builds the delivery lines of a completion.
    ///
    /// The first line names the completion. The strip lines of the reply
    /// path follow it. A multi transaction then has one line per sub-op,
    /// and each line has the strip lines of its result after it.
    fn recv_delivery_logs(
        &self,
        pending: &Pending<T>,
        failed: bool,
        rc: i32,
        reply: Option<&Reply>,
        head_logs: Vec<LogRecord>,
        item_logs: Vec<Vec<LogRecord>>,
    ) -> Vec<LogRecord> {
        let mut logs = Vec::new();
        let x = i64::from(pending.xid);
        if let Some((ctype, site)) = pending.shape.legacy_kind() {
            let record = match pending.route {
                Route::Queued => self
                    .log
                    .record(site, || int_args(x, i64::from(failed), i64::from(rc))),
                Route::Direct => self.log.record(LogSite::SyncCompletion, || {
                    int_args(i64::from(ctype), x, i64::from(rc))
                }),
            };
            logs.extend(record);
        }
        logs.extend(head_logs);
        match (&pending.shape, reply) {
            (
                Shape::Multi {
                    op_types,
                    kind: MultiKind::Multi,
                },
                Some(Reply::Multi(items)),
            ) => {
                let mut extra = item_logs.into_iter();
                for (op, item) in op_types.iter().zip(items) {
                    let item_failed = item.wire_type == opcode::ERROR;
                    let item_rc = match &item.body {
                        MultiBody::Error(e) => e.err,
                        _ => item.err,
                    };
                    if let Some(site) = sub_op_site(*op) {
                        let record = self.log.record(site, || {
                            int_args(x, i64::from(item_failed), i64::from(item_rc))
                        });
                        logs.extend(record);
                    }
                    logs.extend(extra.next().into_iter().flatten());
                }
                logs.extend(extra.flatten());
            }
            (
                Shape::Multi {
                    op_types,
                    kind: MultiKind::Multi,
                },
                _,
            ) => {
                // A failed multi fakes a failed result for every sub-op
                // (cleanup_failed_multi, zookeeper.c:3298-3306).
                for op in op_types {
                    if let Some(site) = sub_op_site(*op) {
                        let record = self.log.record(site, || int_args(x, 1, i64::from(rc)));
                        logs.extend(record);
                    }
                }
                logs.extend(item_logs.into_iter().flatten());
            }
            _ => logs.extend(item_logs.into_iter().flatten()),
        }
        logs
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::hooks::{AllLevels, NoDefaultWatcher, Rng};
    use crate::requests::completion;
    use crate::state::SaslNegotiation;
    use zk_jute::data::{ACL, ClientInfo, Stat};
    use zk_jute::proto::{ErrorResponse, MultiHeader};
    use zk_jute::rc::{ZCONNECTIONLOSS, ZNONODE};
    use zk_jute::{JBuffer, encode_frame};

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

    /// Makes an established connection with a transport.
    fn conn_with(compat: Compat, chroot: Option<&str>) -> Connection<Tk> {
        let mut cfg = Config::legacy(30_000);
        cfg.chroot = chroot.map(JString::from);
        let mut c = Connection::new(
            cfg,
            compat,
            DriverMode::ST,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(NoDefaultWatcher),
            Millis(0),
        );
        c.core.has_transport = true;
        c.core.phase = Phase::Established;
        c
    }

    fn conn() -> Connection<Tk> {
        conn_with(Compat::LEGACY_C, None)
    }

    fn component() -> Compat {
        let mut c = Compat::LEGACY_C;
        c.chroot = ChrootPolicy::Component;
        c
    }

    fn pending(xid: i32, _op_type: i32, shape: Shape, route: Route) -> Pending<Tk> {
        Pending {
            xid,
            shape,
            route,
            token: u32::try_from(xid).unwrap_or(0),
            watch: None,
            unwatch: None,
            written: true,
        }
    }

    fn enc<R: Record>(r: &R) -> Vec<u8> {
        let mut v = Vec::new();
        r.encode(&mut v);
        v
    }

    /// Encodes one framed reply.
    fn reply_frame(x: i32, zxid: i64, err: i32, body: &[u8]) -> Vec<u8> {
        let mut b = enc(&ReplyHeader { xid: x, zxid, err });
        b.extend_from_slice(body);
        let mut f = Vec::new();
        encode_frame(&b, &mut f);
        f
    }

    /// Encodes a multi body from (type, err, body) results.
    fn multi_body(items: &[(i32, i32, Vec<u8>)]) -> Vec<u8> {
        let mut v = Vec::new();
        for (t, err, body) in items {
            MultiHeader {
                r#type: *t,
                done: false,
                err: *err,
            }
            .encode(&mut v);
            v.extend_from_slice(body);
        }
        MultiHeader {
            r#type: -1,
            done: true,
            err: -1,
        }
        .encode(&mut v);
        v
    }

    fn create(path: &str) -> Vec<u8> {
        enc(&CreateResponse {
            path: JString::from(path),
        })
    }

    fn error(err: i32) -> Vec<u8> {
        enc(&ErrorResponse { err })
    }

    fn stat(czxid: i64) -> Stat {
        Stat {
            czxid,
            ..Stat::default()
        }
    }

    fn drain(c: &mut Connection<Tk>) -> Vec<Output<Tk>> {
        let mut v = Vec::new();
        while let Some(o) = c.poll_output() {
            v.push(o);
        }
        v
    }

    fn sites(logs: &[LogRecord]) -> Vec<LogSite> {
        logs.iter().map(|r| r.site).collect()
    }

    fn ints(r: &LogRecord) -> Vec<i64> {
        r.args
            .iter()
            .filter_map(|a| match a {
                LogArg::I64(v) => Some(*v),
                _ => None,
            })
            .collect()
    }

    /// Returns the only completion of the outputs and the log sites
    /// before it.
    fn completion_of(
        outs: Vec<Output<Tk>>,
    ) -> (u32, Route, OpResult, Vec<LogRecord>, Vec<LogSite>) {
        let mut before = Vec::new();
        for o in outs {
            match o {
                Output::Log(r) => before.push(r.site),
                Output::Completion {
                    token,
                    route,
                    result,
                    delivery_logs,
                } => return (token, route, result, delivery_logs, before),
                other => panic!("unexpected output {other:?}"),
            }
        }
        panic!("no completion")
    }

    #[test]
    fn secret_frame_bodies_are_cleared() {
        // A short connect response is a protocol error, but the body is
        // still cleared.
        let mut c = conn();
        c.core.phase = Phase::Associating;
        c.session.handshake_pending = true;
        let mut body = vec![0xAB; 36];
        let _ = c.dispatch_body(&mut body, Millis(1));
        assert!(body.is_empty(), "connect body kept");

        let mut c = conn();
        c.core.phase = Phase::Sasl(SaslNegotiation::default());
        let mut body = vec![0xCD; 24];
        let _ = c.dispatch_body(&mut body, Millis(1));
        assert!(body.is_empty(), "sasl body kept");

        // Other frames carry no secret and are not cleared.
        let mut c = conn();
        let mut body = reply_frame(-2, 0, 0, &[]).split_off(4);
        let _ = c.dispatch_body(&mut body, Millis(1));
        assert_eq!(body.len(), 16);
    }

    #[test]
    fn frame_route_follows_phase() {
        assert_eq!(frame_route(Phase::Associating, true), FrameRoute::Connect);
        assert_eq!(frame_route(Phase::Associating, false), FrameRoute::Header);
        let sasl = Phase::Sasl(SaslNegotiation::default());
        assert_eq!(frame_route(sasl, true), FrameRoute::Sasl);
        assert_eq!(frame_route(sasl, false), FrameRoute::Sasl);
        assert_eq!(frame_route(Phase::Established, true), FrameRoute::Header);
    }

    #[test]
    fn xid_route_covers_every_branch() {
        assert_eq!(xid_route(-2), XidRoute::Ping);
        assert_eq!(xid_route(-1), XidRoute::Watcher);
        assert_eq!(xid_route(-8), XidRoute::SetWatches);
        assert_eq!(xid_route(-4), XidRoute::Auth);
        assert_eq!(xid_route(7), XidRoute::Reply);
        assert_eq!(xid_route(-3), XidRoute::Reply);
    }

    #[test]
    fn no_transport_or_suspended_is_invalid_state() {
        let mut c = conn();
        c.core.has_transport = false;
        let f = reply_frame(-2, 0, 0, &[]);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!((r.frames, r.consumed, r.rc), (0, 0, ZINVALIDSTATE));

        let mut c = conn();
        c.out.park(Work::Hold);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!((r.frames, r.consumed, r.rc), (0, 0, ZINVALIDSTATE));
    }

    #[test]
    fn partial_frame_is_nothing() {
        let mut c = conn();
        let f = reply_frame(-2, 0, 0, &[]);
        let r = c.handle_read(&f[..6], Millis(1));
        assert_eq!((r.frames, r.consumed, r.rc), (0, 6, ZNOTHING));
        assert_eq!(c.read_hint(), f.len() - 6);
        let r = c.handle_read(&f[6..], Millis(1));
        assert_eq!((r.frames, r.rc), (1, ZOK));
    }

    #[test]
    fn ping_logs_latency_and_continues() {
        let mut c = conn();
        c.timers.last_ping = Millis(100);
        let mut bytes = reply_frame(-2, 0, 0, &[]);
        bytes.extend(reply_frame(-2, 0, 0, &[]));
        let r = c.handle_read(&bytes, Millis(130));
        assert_eq!((r.frames, r.consumed, r.rc), (2, bytes.len(), ZOK));
        assert_eq!(c.timers.last_recv, Millis(130));
        let outs = drain(&mut c);
        assert_eq!(outs.len(), 2);
        let Output::Log(rec) = &outs[0] else {
            panic!("not a log")
        };
        assert_eq!(rec.site, LogSite::PingResponse);
        assert_eq!(ints(rec), vec![30]);
    }

    #[test]
    fn set_watches_reply_logs_and_drops() {
        let mut c = conn();
        let f = reply_frame(-8, 0, ZNONODE, &[]);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!((r.frames, r.rc), (1, ZOK));
        let outs = drain(&mut c);
        assert!(matches!(&outs[..], [Output::Log(r)] if r.site == LogSite::ProcessingSetWatches));
    }

    #[test]
    fn queued_reply_completes_and_reading_continues() {
        let mut c = conn();
        c.requests
            .fifo
            .push_back(pending(1, opcode::EXISTS, Shape::Stat, Route::Queued));
        let mut bytes = reply_frame(1, 7, 0, &enc(&SetDataResponse { stat: stat(3) }));
        bytes.extend(reply_frame(-2, 0, 0, &[]));
        let r = c.handle_read(&bytes, Millis(5));
        assert_eq!((r.frames, r.consumed, r.rc), (2, bytes.len(), ZOK));
        assert_eq!(c.last_zxid(), 7);
        assert!(c.requests.fifo.is_empty());
        let outs = drain(&mut c);
        let (token, route, result, logs, before) = completion_of(outs);
        assert_eq!((token, route), (1, Route::Queued));
        assert_eq!(before, vec![LogSite::QueueingAsync]);
        assert_eq!(result.rc, ZOK);
        assert_eq!(result.zxid, 7);
        assert_eq!(result.origin, Origin::Reply);
        assert_eq!(result.reply, Some(Reply::Stat(stat(3))));
        assert_eq!(sites(&logs), vec![LogSite::CompletionStat]);
        assert_eq!(ints(&logs[0]), vec![1, 0, 0]);
    }

    #[test]
    fn error_reply_sets_zxid_and_has_no_reply() {
        let mut c = conn();
        c.core.last_zxid = 4;
        c.requests
            .fifo
            .push_back(pending(1, opcode::GET_DATA, Shape::Data, Route::Queued));
        c.requests
            .fifo
            .push_back(pending(2, opcode::GET_DATA, Shape::Data, Route::Queued));
        let mut bytes = reply_frame(1, 9, ZNONODE, &[]);
        bytes.extend(reply_frame(2, 0, ZNONODE, &[]));
        let r = c.handle_read(&bytes, Millis(5));
        assert_eq!((r.frames, r.rc), (2, ZOK));
        // The second reply has zxid 0, so the value stays.
        assert_eq!(c.last_zxid(), 9);
        let outs: Vec<Output<Tk>> = drain(&mut c)
            .into_iter()
            .filter(|o| !matches!(o, Output::Log(_)))
            .collect();
        assert_eq!(outs.len(), 2);
        for o in outs {
            let Output::Completion {
                result,
                delivery_logs,
                ..
            } = o
            else {
                panic!("not a completion")
            };
            assert_eq!(result.rc, ZNONODE);
            assert_eq!(result.reply, None);
            assert_eq!(sites(&delivery_logs), vec![LogSite::CompletionData]);
            assert_eq!(ints(&delivery_logs[0])[1..], [1, i64::from(ZNONODE)]);
        }
    }

    #[test]
    fn direct_reply_parks_hold_and_stops_the_loop() {
        let mut c = conn();
        c.requests
            .fifo
            .push_back(pending(3, opcode::SET_DATA, Shape::Stat, Route::Direct));
        let first = reply_frame(3, 11, 0, &enc(&SetDataResponse { stat: stat(1) }));
        let mut bytes = first.clone();
        bytes.extend(reply_frame(-2, 0, 0, &[]));
        let r = c.handle_read(&bytes, Millis(5));
        assert_eq!((r.frames, r.consumed, r.rc), (1, first.len(), ZOK));
        assert!(c.is_suspended());
        // The suspended stage blocks the next read.
        let r = c.handle_read(&bytes[first.len()..], Millis(5));
        assert_eq!((r.frames, r.consumed, r.rc), (0, 0, ZINVALIDSTATE));
        let Some(Output::Completion {
            route,
            result,
            delivery_logs,
            ..
        }) = c.poll_output()
        else {
            panic!("no completion")
        };
        assert_eq!(route, Route::Direct);
        assert_eq!(result.reply, Some(Reply::Stat(stat(1))));
        assert_eq!(sites(&delivery_logs), vec![LogSite::SyncCompletion]);
        assert_eq!(
            ints(&delivery_logs[0]),
            vec![i64::from(completion::STAT), 3, 0]
        );
        assert!(c.poll_output().is_none());
        let stopped = c.take_stopped().unwrap();
        c.resume(stopped, Millis(6));
        assert!(!c.is_suspended());
        let r = c.handle_read(&bytes[first.len()..], Millis(6));
        assert_eq!((r.frames, r.rc), (1, ZOK));
    }

    #[test]
    fn head_match_classifies_replies() {
        let mut c = conn();
        assert_eq!(c.recv_head_match(1), HeadMatch::NoHead);
        let mut p = pending(1, opcode::DELETE, Shape::Void, Route::Queued);
        p.written = false;
        c.requests.fifo.push_back(p);
        assert_eq!(c.recv_head_match(1), HeadMatch::Mismatch);
        c.requests.fifo.front_mut().unwrap().written = true;
        assert_eq!(c.recv_head_match(1), HeadMatch::Hit);
        assert_eq!(c.recv_head_match(2), HeadMatch::Mismatch);

        // Closing with an empty FIFO or an unwritten head.
        let mut c = conn();
        c.close.closing = true;
        c.close.close_xid = Some(9);
        assert_eq!(c.recv_head_match(9), HeadMatch::ClosingDrop);
        let mut d = Compat::LEGACY_C;
        d.close_mode = CloseMode::Drain;
        let mut c = conn_with(d, None);
        c.close.closing = true;
        c.close.close_xid = Some(9);
        assert_eq!(c.recv_head_match(9), HeadMatch::CloseReply);
        assert_eq!(c.recv_head_match(8), HeadMatch::ClosingDrop);
        let mut p = pending(5, opcode::DELETE, Shape::Void, Route::Queued);
        p.written = false;
        c.requests.fifo.push_back(p);
        assert_eq!(c.recv_head_match(9), HeadMatch::CloseReply);
        assert_eq!(c.recv_head_match(5), HeadMatch::ClosingDrop);
    }

    /// Rule: a reply while closing with an empty FIFO is dropped with
    /// `ZINVALIDSTATE`.
    #[test]
    fn reply_after_close_cleared_the_fifo_is_dropped() {
        let mut c = conn();
        c.close.closing = true;
        let f = reply_frame(4, 3, 0, &[]);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!((r.frames, r.consumed, r.rc), (1, f.len(), ZINVALIDSTATE));
        assert_eq!(c.last_zxid(), 0);
        let outs = drain(&mut c);
        assert!(matches!(&outs[..], [Output::Log(r)] if r.site == LogSite::ClearedByClose));

        // An unwritten head while closing also drops the frame.
        let mut c = conn();
        c.close.closing = true;
        let mut p = pending(4, opcode::DELETE, Shape::Void, Route::Queued);
        p.written = false;
        c.requests.fifo.push_back(p);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!(r.rc, ZINVALIDSTATE);
        assert_eq!(c.requests.fifo.len(), 1);
    }

    #[test]
    fn length_errors_follow_the_profile() {
        let stall = NegativeLen::StallUntilTimeout;
        let cut = NegativeLen::Disconnect;
        assert_eq!(
            len_action(FrameError::Negative(-1), stall),
            LenAction::Stall
        );
        assert_eq!(
            len_action(FrameError::Negative(-1), cut),
            LenAction::Teardown(Cause::ProtocolError, 0)
        );
        for p in [stall, cut] {
            assert_eq!(
                len_action(FrameError::Empty, p),
                LenAction::Teardown(Cause::Eof, EHOSTDOWN)
            );
            assert_eq!(
                len_action(FrameError::TooLarge(9), p),
                LenAction::Teardown(Cause::ProtocolError, 0)
            );
        }
        assert_eq!(
            Cause::Eof.rc_for(Compat::LEGACY_C.disconnect_rc),
            ZCONNECTIONLOSS
        );
    }

    /// Rule: a negative frame length stalls the decoder.
    #[test]
    fn negative_length_stalls_the_decoder() {
        let mut c = conn();
        let mut bytes = (-5i32).to_be_bytes().to_vec();
        bytes.extend(reply_frame(-2, 0, 0, &[]));
        let r = c.handle_read(&bytes, Millis(1));
        assert_eq!((r.frames, r.consumed, r.rc), (0, 4, ZNOTHING));
        assert!(c.recv.stalled);
        assert!(c.recv.decoder.is_stalled());
        assert_eq!(c.read_hint(), 0);
        let r = c.handle_read(&bytes[4..], Millis(2));
        assert_eq!((r.frames, r.consumed, r.rc), (0, 0, ZNOTHING));
        c.recv.reset();
        assert!(!c.recv.stalled);
        assert_eq!(c.read_hint(), 4);
    }

    #[test]
    fn sasl_mechanism_work_stops_reading() {
        let mut c = conn();
        c.core.phase = Phase::Sasl(SaslNegotiation::default());
        c.sasl.outstanding = true;
        let f = reply_frame(-2, 0, 0, &[]);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!((r.frames, r.consumed, r.rc), (0, 0, ZNOTHING));
        // Outside the Sasl phase the flag does not stop the loop.
        c.core.phase = Phase::Established;
        let r = c.handle_read(&f, Millis(1));
        assert_eq!((r.frames, r.rc), (1, ZOK));
    }

    /// Rule: the legacy strip compares bytes, as C `sub_string` does.
    #[test]
    fn strip_path_legacy_rules() {
        let c = conn_with(Compat::LEGACY_C, Some("/app"));
        let mut logs = Vec::new();
        assert_eq!(
            c.strip_path(b"/app/x", &mut logs),
            Some(JString::from("/x"))
        );
        assert_eq!(c.strip_path(b"/app", &mut logs), Some(JString::from("/")));
        // C compares bytes with no component boundary.
        assert_eq!(
            c.strip_path(b"/apple", &mut logs),
            Some(JString::from("le"))
        );
        assert!(logs.is_empty());
        assert_eq!(
            c.strip_path(b"/other", &mut logs),
            Some(JString::from("/other"))
        );
        assert_eq!(sites(&logs), vec![LogSite::ChrootMismatch]);
        assert_eq!(
            logs[0].args,
            vec![
                LogArg::Str(JString::from("/other")),
                LogArg::Str(JString::from("/app"))
            ]
        );
        // A chroot of "/" is no chroot, as in C.
        let c = conn_with(Compat::LEGACY_C, Some("/"));
        let mut logs = Vec::new();
        assert_eq!(c.strip_path(b"/a", &mut logs), Some(JString::from("/a")));
        let c = conn();
        assert_eq!(c.strip_path(b"/a", &mut logs), Some(JString::from("/a")));
        assert!(logs.is_empty());
    }

    #[test]
    fn strip_path_component_rules() {
        let c = conn_with(component(), Some("/app"));
        let mut logs = Vec::new();
        assert_eq!(
            c.strip_path(b"/app/x", &mut logs),
            Some(JString::from("/x"))
        );
        assert_eq!(c.strip_path(b"/app", &mut logs), Some(JString::from("/")));
        assert!(logs.is_empty());
        assert_eq!(c.strip_path(b"/apple", &mut logs), None);
        assert_eq!(c.strip_path(b"/other", &mut logs), None);
        assert_eq!(
            sites(&logs),
            vec![LogSite::ChrootMismatch, LogSite::ChrootMismatch]
        );
    }

    /// Rule: each reply shape decodes to its `Reply`, with paths stripped.
    #[test]
    fn decode_reply_each_shape() {
        let c = conn_with(Compat::LEGACY_C, Some("/app"));
        let mut logs = Vec::new();
        let ok = |shape: Shape, body: Vec<u8>, logs: &mut Vec<LogRecord>| {
            c.decode_reply(&shape, &body, logs).unwrap()
        };
        assert_eq!(ok(Shape::Void, vec![], &mut logs), (Reply::Void, ZOK));
        assert_eq!(
            ok(
                Shape::Stat,
                enc(&SetDataResponse { stat: stat(2) }),
                &mut logs
            ),
            (Reply::Stat(stat(2)), ZOK)
        );
        let data = GetDataResponse {
            data: JBuffer::Bytes(b"v".to_vec()),
            stat: stat(3),
        };
        assert_eq!(
            ok(Shape::Data, enc(&data), &mut logs).0,
            Reply::Data {
                data: JBuffer::Bytes(b"v".to_vec()).into(),
                stat: stat(3)
            }
        );
        assert_eq!(
            ok(Shape::Path, create("/app/n"), &mut logs).0,
            Reply::Path(JString::from("/n"))
        );
        let c2 = Create2Response {
            path: JString::from("/app/m"),
            stat: stat(4),
        };
        assert_eq!(
            ok(Shape::PathStat, enc(&c2), &mut logs).0,
            Reply::PathStat(JString::from("/m"), stat(4))
        );
        let kids: JVec<JString> = JVec::from(vec![JString::from("a"), JString::from("b")]);
        assert_eq!(
            ok(
                Shape::Children,
                enc(&GetChildrenResponse {
                    children: kids.clone()
                }),
                &mut logs
            )
            .0,
            Reply::Children(kids.clone())
        );
        let k2 = GetChildren2Response {
            children: kids.clone(),
            stat: stat(5),
        };
        assert_eq!(
            ok(Shape::Children2, enc(&k2), &mut logs).0,
            Reply::Children2(kids, stat(5))
        );
        let acl = GetACLResponse {
            acl: JVec::from(vec![ACL::default()]),
            stat: stat(6),
        };
        assert_eq!(
            ok(Shape::Acl, enc(&acl), &mut logs).0,
            Reply::Acl(JVec::from(vec![ACL::default()]), stat(6))
        );
        let eph = GetEphemeralsResponse {
            ephemerals: JVec::from(vec![JString::from("/app/e"), JString::from("/zz")]),
        };
        assert_eq!(
            ok(Shape::Ephemerals, enc(&eph), &mut logs).0,
            Reply::Ephemerals(JVec::from(vec![JString::from("/e")]))
        );
        let n = GetAllChildrenNumberResponse { total_number: 12 };
        assert_eq!(
            ok(Shape::ChildrenCount, enc(&n), &mut logs).0,
            Reply::ChildrenCount(12)
        );
        let who = WhoAmIResponse {
            client_info: JVec::from(vec![ClientInfo::default()]),
        };
        assert_eq!(
            ok(Shape::WhoAmI, enc(&who), &mut logs).0,
            Reply::WhoAmI(JVec::from(vec![ClientInfo::default()]))
        );
        // Ephemeral entries outside the chroot drop with no log line.
        assert!(logs.is_empty());

        // A path outside the chroot logs under the legacy rule.
        let _ = ok(Shape::Path, create("/x"), &mut logs);
        assert_eq!(sites(&logs), vec![LogSite::ChrootMismatch]);

        // A malformed body is a teardown rc.
        let mut logs = Vec::new();
        assert_eq!(
            c.decode_reply(&Shape::Stat, &[0; 3], &mut logs),
            Err(ZCONNECTIONLOSS)
        );
    }

    #[test]
    fn decode_reply_component_outside_fails_the_request() {
        let c = conn_with(component(), Some("/app"));
        let mut logs = Vec::new();
        assert_eq!(
            c.decode_reply(&Shape::Path, &create("/apple"), &mut logs),
            Err(ZMARSHALLINGERROR)
        );
        assert_eq!(sites(&logs), vec![LogSite::ChrootMismatch]);
        let eph = GetEphemeralsResponse {
            ephemerals: JVec::from(vec![JString::from("/apple"), JString::from("/app/b")]),
        };
        let mut logs = Vec::new();
        assert_eq!(
            c.decode_reply(&Shape::Ephemerals, &enc(&eph), &mut logs),
            Ok((
                Reply::Ephemerals(JVec::from(vec![JString::from("/b")])),
                ZOK
            ))
        );
        assert!(logs.is_empty());
    }

    fn multi_shape(ops: &[i32]) -> Shape {
        Shape::Multi {
            op_types: ops.to_vec(),
            kind: MultiKind::Multi,
        }
    }

    #[test]
    fn decode_reply_multi_rc() {
        let c = conn_with(Compat::LEGACY_C, Some("/app"));
        let mut logs = Vec::new();
        // The first error other than 0 and ZRUNTIMEINCONSISTENCY wins.
        let body = multi_body(&[
            (-1, -1, error(ZRUNTIMEINCONSISTENCY)),
            (-1, -1, error(ZNONODE)),
            (-1, -1, error(-110)),
        ]);
        let (reply, rc) = c
            .decode_reply(&multi_shape(&[1, 2, 5]), &body, &mut logs)
            .unwrap();
        assert_eq!(rc, ZNONODE);
        assert!(matches!(reply, Reply::Multi(ref v) if v.len() == 3));

        let body = multi_body(&[(-1, -1, error(0)), (-1, -1, error(ZRUNTIMEINCONSISTENCY))]);
        let (_, rc) = c
            .decode_reply(&multi_shape(&[2, 13]), &body, &mut logs)
            .unwrap();
        assert_eq!(rc, ZOK);

        // Create paths are stripped.
        let body = multi_body(&[(1, 0, create("/app/a")), (2, 0, vec![])]);
        let (reply, rc) = c
            .decode_reply(&multi_shape(&[1, 2]), &body, &mut logs)
            .unwrap();
        assert_eq!(rc, ZOK);
        let Reply::Multi(items) = reply else {
            panic!("not a multi")
        };
        assert_eq!(
            items[0].body,
            MultiBody::Create(CreateResponse {
                path: JString::from("/a")
            })
        );
        assert!(logs.is_empty());

        // A multiRead does not fail as a whole.
        let read = Shape::Multi {
            op_types: vec![4],
            kind: MultiKind::MultiRead,
        };
        let body = multi_body(&[(-1, -1, error(ZNONODE))]);
        let (reply, rc) = c.decode_reply(&read, &body, &mut logs).unwrap();
        assert_eq!(rc, ZOK);
        assert!(matches!(reply, Reply::MultiRead(_)));

        // A count mismatch is malformed.
        let body = multi_body(&[(2, 0, vec![])]);
        assert_eq!(
            c.decode_reply(&multi_shape(&[2, 2]), &body, &mut logs),
            Err(ZCONNECTIONLOSS)
        );
    }

    #[test]
    fn queued_multi_lines_interleave_strip_errors() {
        let mut c = conn_with(Compat::LEGACY_C, Some("/app"));
        c.requests.fifo.push_back(pending(
            6,
            opcode::MULTI,
            multi_shape(&[1, 2, 5]),
            Route::Queued,
        ));
        let body = multi_body(&[
            (1, 0, create("/x")),
            (2, 0, vec![]),
            (5, 0, enc(&SetDataResponse { stat: stat(1) })),
        ]);
        let f = reply_frame(6, 20, 0, &body);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!(r.rc, ZOK);
        let (_, _, result, logs, _) = completion_of(drain(&mut c));
        assert_eq!(result.rc, ZOK);
        assert!(matches!(result.reply, Some(Reply::Multi(_))));
        assert_eq!(
            sites(&logs),
            vec![
                LogSite::CompletionMulti,
                LogSite::CompletionString,
                LogSite::ChrootMismatch,
                LogSite::CompletionVoid,
                LogSite::CompletionStat,
            ]
        );
        assert_eq!(ints(&logs[0]), vec![6, 0, 0]);
        assert_eq!(ints(&logs[1]), vec![6, 0, 0]);
    }

    #[test]
    fn failed_queued_multi_fakes_every_sub_op() {
        let mut c = conn();
        c.requests.fifo.push_back(pending(
            7,
            opcode::MULTI,
            multi_shape(&[1, 13]),
            Route::Queued,
        ));
        let body = multi_body(&[(-1, -1, error(ZNONODE)), (-1, -1, error(-2))]);
        let f = reply_frame(7, 0, ZNONODE, &body);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!(r.rc, ZOK);
        let (_, _, result, logs, _) = completion_of(drain(&mut c));
        assert_eq!((result.rc, result.reply), (ZNONODE, None));
        let n = i64::from(ZNONODE);
        assert_eq!(
            sites(&logs),
            vec![
                LogSite::CompletionMulti,
                LogSite::CompletionString,
                LogSite::CompletionVoid
            ]
        );
        for l in &logs {
            assert_eq!(ints(l), vec![7, 1, n]);
        }
    }

    #[test]
    fn direct_multi_decodes_an_error_body() {
        let mut c = conn();
        c.requests.fifo.push_back(pending(
            8,
            opcode::MULTI,
            multi_shape(&[2, 13]),
            Route::Direct,
        ));
        let body = multi_body(&[(-1, -1, error(ZNONODE)), (-1, -1, error(-2))]);
        let f = reply_frame(8, 0, ZNONODE, &body);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!(r.rc, ZOK);
        let (_, route, result, logs, _) = completion_of(drain(&mut c));
        assert_eq!(route, Route::Direct);
        assert_eq!(result.rc, ZNONODE);
        assert!(matches!(result.reply, Some(Reply::Multi(_))));
        assert_eq!(
            sites(&logs),
            vec![
                LogSite::SyncCompletion,
                LogSite::CompletionVoid,
                LogSite::CompletionVoid
            ]
        );
        let n = i64::from(ZNONODE);
        assert_eq!(ints(&logs[0]), vec![i64::from(completion::MULTI), 8, n]);
        assert_eq!(ints(&logs[1]), vec![8, 1, n]);
        assert_eq!(ints(&logs[2]), vec![8, 1, -2]);
    }

    #[test]
    fn header_only_direct_multi_has_no_reply() {
        let mut c = conn();
        c.requests
            .fifo
            .push_back(pending(9, opcode::MULTI, multi_shape(&[2]), Route::Direct));
        let f = reply_frame(9, 0, ZNONODE, &[]);
        let r = c.handle_read(&f, Millis(1));
        assert_eq!(r.rc, ZOK);
        let (_, _, result, logs, _) = completion_of(drain(&mut c));
        assert_eq!((result.rc, result.reply), (ZNONODE, None));
        assert_eq!(
            sites(&logs),
            vec![LogSite::SyncCompletion, LogSite::CompletionVoid]
        );
        assert_eq!(ints(&logs[1]), vec![9, 1, i64::from(ZNONODE)]);
    }

    #[test]
    fn component_outside_path_fails_with_marshalling_error() {
        let mut c = conn_with(component(), Some("/app"));
        c.requests
            .fifo
            .push_back(pending(2, opcode::CREATE, Shape::Path, Route::Queued));
        let f = reply_frame(2, 5, 0, &create("/apple"));
        let r = c.handle_read(&f, Millis(1));
        assert_eq!(r.rc, ZOK);
        let (_, _, result, logs, _) = completion_of(drain(&mut c));
        assert_eq!(result.rc, ZMARSHALLINGERROR);
        assert_eq!(result.origin, Origin::Reply);
        assert_eq!(result.reply, None);
        assert_eq!(
            sites(&logs),
            vec![LogSite::CompletionString, LogSite::ChrootMismatch]
        );
    }

    #[test]
    fn completion_logs_skip_native_shapes() {
        let c = conn();
        let p = pending(3, opcode::GET_EPHEMERALS, Shape::Ephemerals, Route::Queued);
        assert!(c.completion_logs(&p, false, 0, None).is_empty());
        let p = pending(3, opcode::SYNC, Shape::Path, Route::Queued);
        let logs = c.completion_logs(&p, false, 0, None);
        assert_eq!(sites(&logs), vec![LogSite::CompletionString]);
    }

    #[test]
    fn teardown_completion_lines_by_route() {
        let c = conn();
        let p = pending(4, opcode::MULTI, multi_shape(&[1, 5]), Route::Queued);
        let Output::Completion {
            token,
            route,
            result,
            delivery_logs,
        } = c.teardown_completion(p, ZCONNECTIONLOSS)
        else {
            panic!("not a completion")
        };
        assert_eq!((token, route), (4, Route::Queued));
        assert_eq!(result, OpResult::teardown(ZCONNECTIONLOSS));
        assert_eq!(
            sites(&delivery_logs),
            vec![
                LogSite::CompletionMulti,
                LogSite::CompletionString,
                LogSite::CompletionStat
            ]
        );
        for l in &delivery_logs {
            assert_eq!(ints(l), vec![4, 1, i64::from(ZCONNECTIONLOSS)]);
        }
        let p = pending(5, opcode::GET_DATA, Shape::Data, Route::Direct);
        let Output::Completion {
            result,
            delivery_logs,
            ..
        } = c.teardown_completion(p, ZCONNECTIONLOSS)
        else {
            panic!("not a completion")
        };
        assert_eq!(result.origin, Origin::Teardown);
        assert!(delivery_logs.is_empty());
    }

    #[test]
    fn disabled_levels_make_no_lines() {
        let mut c = conn();
        c.log = crate::log::Logger::new(Box::new(crate::hooks::NoLevels));
        let p = pending(4, opcode::GET_DATA, Shape::Data, Route::Queued);
        assert!(c.completion_logs(&p, true, ZNONODE, None).is_empty());
        let c = conn_with(Compat::LEGACY_C, Some("/app"));
        let mut c = c;
        c.log = crate::log::Logger::new(Box::new(crate::hooks::NoLevels));
        let mut logs = Vec::new();
        assert_eq!(c.strip_path(b"/x", &mut logs), Some(JString::from("/x")));
        assert!(logs.is_empty());
    }
}
