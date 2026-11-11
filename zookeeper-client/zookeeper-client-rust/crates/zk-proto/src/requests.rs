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

//! The send queue, the pending FIFO and the xid counter.
//!
//! The module owns [`Requests`]. Every frame that goes to the server passes
//! through its `tx` queue. Every request that waits for a reply sits in its
//! `fifo`.

use std::collections::VecDeque;

use zeroize::Zeroize;
use zk_jute::Record;
use zk_jute::multi::MultiKind;
use zk_jute::proto::RequestHeader;

use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::log::LogSite;
use crate::request::Route;
use crate::secret::SecretBytes;
use crate::state::Phase;

/// The bytes of one outgoing frame, with its length prefix.
pub(crate) enum FrameBytes {
    /// A frame with no secret.
    Plain(Vec<u8>),
    /// A frame with a secret: Connect, Auth or Sasl. The bytes are zeroed
    /// on drop.
    Secret(SecretBytes),
}

/// The smallest plain frame that `poll_transmit` lends to the caller in
/// place of a copy. Frames of 64 KiB and similar sizes stay copied, so
/// many of them go out in one send.
pub(crate) const LEND_MIN: usize = 512 * 1024;

/// The most bytes that one `poll_transmit` call copies on a plaintext
/// connection. The limit keeps the copy under the lock short, and keeps
/// the priority window of the copy path at its legacy size.
pub(crate) const PLAIN_COPY_MAX: usize = 64 * 1024;

impl FrameBytes {
    /// Returns the bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Plain(v) => v,
            Self::Secret(s) => s.expose(),
        }
    }

    /// Returns the length in bytes.
    pub(crate) fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns true for a frame with a secret.
    pub(crate) fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }
}

/// The limits of one `poll_transmit` call.
#[derive(Clone, Copy)]
struct TxLimits {
    /// The most bytes that the call copies.
    copy: usize,
    /// The largest frame that the call lends. A value of 0 stops all lends.
    lend: usize,
}

/// The kind of an outgoing frame. The phase gate and the priority rule
/// read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FrameKind {
    /// The `ConnectRequest`.
    Connect,
    /// An application request or a SASL-free internal request.
    Request {
        /// The xid of the request.
        xid: i32,
    },
    /// A ping (xid -2).
    Ping,
    /// An auth packet (xid -4).
    Auth {
        /// The index of its entry in the auth list. The send records it,
        /// so the AUTH replies follow the wire order.
        entry: usize,
    },
    /// A SetWatches packet (xid -8).
    SetWatches,
    /// A SASL request.
    Sasl,
    /// The CLOSE_OP request.
    Close,
}

/// One outgoing frame.
pub(crate) struct OutFrame {
    /// The bytes. A lent frame keeps an empty buffer here.
    pub(crate) bytes: FrameBytes,
    /// The length of a frame that `poll_transmit` lent, else 0. Use
    /// [`OutFrame::len`] for the frame length, because a lent frame has
    /// no bytes in `bytes`. The field is a `u32`, so it fits in the free
    /// space of the struct and the frame queue does not grow.
    pub(crate) lent: u32,
    /// The number of bytes that `handle_transmitted` acknowledged.
    pub(crate) written: usize,
    /// True when `poll_transmit` copied bytes of this frame.
    pub(crate) pinned: bool,
    /// The kind.
    pub(crate) kind: FrameKind,
}

impl OutFrame {
    /// Makes a frame with no secret.
    pub(crate) fn plain(kind: FrameKind, bytes: Vec<u8>) -> Self {
        Self {
            bytes: FrameBytes::Plain(bytes),
            lent: 0,
            written: 0,
            pinned: false,
            kind,
        }
    }

    /// Makes a frame with a secret.
    pub(crate) fn secret(kind: FrameKind, bytes: Vec<u8>) -> Self {
        Self {
            bytes: FrameBytes::Secret(SecretBytes::new(bytes)),
            lent: 0,
            written: 0,
            pinned: false,
            kind,
        }
    }

    /// Returns the frame length in bytes, also for a lent frame.
    pub(crate) fn len(&self) -> usize {
        let lent = usize::try_from(self.lent).unwrap_or(usize::MAX);
        self.bytes.len().max(lent)
    }

    /// Returns true for a frame that `poll_transmit` lent. Only the
    /// invariant checks of the tests ask.
    #[cfg(test)]
    pub(crate) fn is_lent(&self) -> bool {
        self.lent > 0
    }

    /// Returns true when no byte of the frame was copied or acknowledged.
    pub(crate) fn is_untouched(&self) -> bool {
        self.written == 0 && !self.pinned
    }

    /// Returns true when every byte is acknowledged.
    pub(crate) fn is_complete(&self) -> bool {
        self.written >= self.len()
    }

    /// Returns true when `poll_transmit` can lend the frame: a whole
    /// plain frame from [`LEND_MIN`] to `lend_max` bytes, with no byte
    /// copied. A secret frame never leaves the zeroing buffer of its
    /// frame. A lent frame has no bytes, so it is never lent
    /// again. The length must fit in the `lent` field.
    fn lendable(&self, start: usize, lend_max: usize) -> bool {
        let len = self.bytes.len();
        let fits = (LEND_MIN..=lend_max).contains(&len) && u32::try_from(len).is_ok();
        start == 0 && fits && matches!(self.bytes, FrameBytes::Plain(_))
    }

    /// Gives the walk step of `poll_transmit` for a lendable frame.
    ///
    /// It returns `None` when the walk copies the bytes as usual. Else
    /// the walk stops after it adds the returned count:
    /// - After other bytes of this call, the count is 0. The caller sends
    ///   those bytes first, and the next call lends the frame.
    /// - With an empty `out`, the frame buffer becomes `out`, and the old
    ///   buffer of `out` goes away. The frame stays pinned, and the count
    ///   is its length.
    ///
    /// When `out` holds bytes from the caller, the walk copies, so each
    /// call makes progress.
    fn try_lend(
        &mut self,
        out: &mut Vec<u8>,
        start: usize,
        copied: usize,
        lend_max: usize,
    ) -> Option<usize> {
        if !self.lendable(start, lend_max) || (copied == 0 && !out.is_empty()) {
            return None;
        }
        if copied > 0 {
            return Some(0);
        }
        if let FrameBytes::Plain(v) = &mut self.bytes {
            *out = core::mem::take(v);
            self.lent = u32::try_from(out.len()).unwrap_or(u32::MAX);
            self.pinned = true;
        }
        Some(out.len())
    }

    /// Gives the next walk step of `poll_transmit`: the count of lent
    /// bytes and the bytes to copy. The copy takes at most `left` bytes
    /// from `start`, within the copy limit. With no bytes to copy, the
    /// walk stops.
    fn next_chunk(
        &mut self,
        out: &mut Vec<u8>,
        start: usize,
        left: usize,
        copied: usize,
        lim: TxLimits,
    ) -> (usize, Option<&[u8]>) {
        // A lend needs no erase: `out` is empty, so the entry erase set
        // the secret end to 0.
        if let Some(lent) = self.try_lend(out, start, copied, lim.lend) {
            return (lent, None);
        }
        // The teardown order keeps the walk away from a lent frame (see
        // `Requests::clear_pins`). Production code never panics, so only
        // the tests check this. Else the walk finds no bytes and stops.
        #[cfg(test)]
        assert!(!self.is_lent(), "the bytes of a lent frame are read");
        let take = left.min(lim.copy.saturating_sub(copied));
        (
            0,
            self.bytes.as_slice().get(start..start.saturating_add(take)),
        )
    }
}

/// The reply shape of a request. It selects the decoder and the legacy
/// completion type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Shape {
    /// No body.
    Void,
    /// A `Stat`.
    Stat,
    /// Data and a `Stat`.
    Data,
    /// A path.
    Path,
    /// A path and a `Stat`.
    PathStat,
    /// A child list.
    Children,
    /// A child list and a `Stat`.
    Children2,
    /// An ACL and a `Stat`.
    Acl,
    /// A multi response. `op_types` lists the wire type of each operation.
    Multi {
        /// The wire types, in request order.
        op_types: Vec<i32>,
        /// The response kind.
        kind: MultiKind,
    },
    /// An ephemeral list (native only).
    Ephemerals,
    /// A child count (native only).
    ChildrenCount,
    /// A client info list (native only).
    WhoAmI,
}

/// The legacy completion types (zookeeper.c:203-212).
pub(crate) mod completion {
    /// `COMPLETION_WATCH`.
    pub(crate) const WATCH: i32 = -1;
    /// `COMPLETION_VOID`.
    pub(crate) const VOID: i32 = 0;
    /// `COMPLETION_STAT`.
    pub(crate) const STAT: i32 = 1;
    /// `COMPLETION_DATA`.
    pub(crate) const DATA: i32 = 2;
    /// `COMPLETION_STRINGLIST`.
    pub(crate) const STRINGLIST: i32 = 3;
    /// `COMPLETION_STRINGLIST_STAT`.
    pub(crate) const STRINGLIST_STAT: i32 = 4;
    /// `COMPLETION_ACLLIST`.
    pub(crate) const ACLLIST: i32 = 5;
    /// `COMPLETION_STRING`.
    pub(crate) const STRING: i32 = 6;
    /// `COMPLETION_MULTI`.
    pub(crate) const MULTI: i32 = 7;
    /// `COMPLETION_STRING_STAT`.
    pub(crate) const STRING_STAT: i32 = 8;
}

impl Shape {
    /// Returns the legacy completion type and the "Calling COMPLETION_X"
    /// log site, or `None` for the native-only shapes.
    pub(crate) const fn legacy_kind(&self) -> Option<(i32, LogSite)> {
        match self {
            Self::Void => Some((completion::VOID, LogSite::CompletionVoid)),
            Self::Stat => Some((completion::STAT, LogSite::CompletionStat)),
            Self::Data => Some((completion::DATA, LogSite::CompletionData)),
            Self::Children => Some((completion::STRINGLIST, LogSite::CompletionStringList)),
            Self::Children2 => Some((
                completion::STRINGLIST_STAT,
                LogSite::CompletionStringListStat,
            )),
            Self::Acl => Some((completion::ACLLIST, LogSite::CompletionAclList)),
            Self::Path => Some((completion::STRING, LogSite::CompletionString)),
            Self::PathStat => Some((completion::STRING_STAT, LogSite::CompletionStringStat)),
            Self::Multi {
                kind: MultiKind::Multi,
                ..
            } => Some((completion::MULTI, LogSite::CompletionMulti)),
            Self::Multi {
                kind: MultiKind::MultiRead,
                ..
            }
            | Self::Ephemerals
            | Self::ChildrenCount
            | Self::WhoAmI => None,
        }
    }
}

/// The watch table that a registration targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WatchKind {
    /// The data table. getData registers with this kind.
    Data,
    /// The exists registration. On `ZOK` it arms the data table, and on
    /// `ZNONODE` it arms the exist table.
    Exist,
    /// The child table.
    Child,
    /// A persistent watch (native only).
    Persistent,
    /// A persistent recursive watch (native only).
    PersistentRecursive,
}

/// A watch that the reply of a request arms.
///
/// `exists` registers with `kind == Exist`, so the arming rule can tell it
/// apart from getData. The rule arms the data table on `ZOK` and the exist
/// table on `ZNONODE`.
pub(crate) struct WatchReg<W> {
    /// The table.
    pub(crate) kind: WatchKind,
    /// The server path, with the chroot.
    pub(crate) path: Vec<u8>,
    /// The watcher.
    pub(crate) watcher: W,
}

/// A local removal that a successful removeWatches reply applies.
pub(crate) struct Unwatch<W> {
    /// The server path, with the chroot.
    pub(crate) path: Vec<u8>,
    /// The watch type.
    pub(crate) wtype: i32,
    /// The watcher, or `None` for every watcher.
    pub(crate) watcher: Option<W>,
}

/// One request that waits for its reply.
pub(crate) struct Pending<T: Tokens> {
    /// The xid.
    pub(crate) xid: i32,
    /// The reply shape.
    pub(crate) shape: Shape,
    /// The delivery route.
    pub(crate) route: Route,
    /// The completion token.
    pub(crate) token: T::Completion,
    /// The watch to arm on the reply.
    pub(crate) watch: Option<WatchReg<T::Watcher>>,
    /// The local removal to apply on a successful reply.
    pub(crate) unwatch: Option<Unwatch<T::Watcher>>,
    /// True when the last byte of the frame is acknowledged.
    pub(crate) written: bool,
}

/// The send queue, the FIFO and the xid counter.
pub(crate) struct Requests<T: Tokens> {
    /// The frames to send, in wire order.
    pub(crate) tx: VecDeque<OutFrame>,
    /// The requests that wait for a reply, in xid order.
    pub(crate) fifo: VecDeque<Pending<T>>,
    /// The next xid to give.
    next_xid: i32,
    /// The bytes that `poll_transmit` copied and the driver did not
    /// acknowledge yet. A transport loss sets it to 0, so a late
    /// acknowledgement is ignored.
    pub(crate) unacked: usize,
    /// The end of the secret bytes in the caller's copy buffer, or 0 when
    /// the buffer holds none. Past the length of the buffer, these bytes
    /// are old copies that the next `poll_transmit` erases.
    secret_end: usize,
}

impl<T: Tokens> Requests<T> {
    /// Makes empty queues. A seed of 0 or less gives a first xid of 1.
    pub(crate) fn new(xid_seed: i32) -> Self {
        Self {
            tx: VecDeque::new(),
            fifo: VecDeque::new(),
            next_xid: if xid_seed <= 0 { 1 } else { xid_seed },
            unacked: 0,
            secret_end: 0,
        }
    }

    /// Returns the next xid and advances the counter. It wraps from
    /// `i32::MAX` to 1, so it never gives 0 or a negative value.
    pub(crate) fn next_xid(&mut self) -> i32 {
        let xid = self.next_xid;
        self.next_xid = match xid.checked_add(1) {
            Some(n) if n > 0 => n,
            _ => 1,
        };
        xid
    }

    /// Appends a frame at the tail.
    pub(crate) fn push_tail(&mut self, frame: OutFrame) {
        self.tx.push_back(frame);
    }

    /// Inserts a frame before the first frame that has no copied byte.
    /// Successive calls therefore come out in reverse call order. A
    /// started or pinned frame is never split.
    ///
    /// An unsent `Connect` frame always stays ahead of the insert. C writes
    /// the handshake before it enters the associating state, so no packet
    /// goes before it. In that state the send gate stops at the first
    /// frame that is not `Connect`, so an earlier frame stops the handshake.
    pub(crate) fn push_priority(&mut self, frame: OutFrame) {
        let at = self
            .tx
            .iter()
            .position(|f| f.is_untouched() && f.kind != FrameKind::Connect)
            .unwrap_or(self.tx.len());
        self.tx.insert(at, frame);
    }

    /// Appends a pending entry at the tail of the FIFO.
    pub(crate) fn push_pending(&mut self, pending: Pending<T>) {
        self.fifo.push_back(pending);
    }

    /// Returns true when `tx` holds a byte that was not acknowledged.
    pub(crate) fn has_unsent(&self) -> bool {
        self.tx.iter().any(|f| !f.is_complete())
    }

    /// Returns true when a `Connect` frame is queued and not complete.
    pub(crate) fn connect_frame_unwritten(&self) -> bool {
        self.tx
            .iter()
            .any(|f| f.kind == FrameKind::Connect && !f.is_complete())
    }

    /// Clears every pin and the unacknowledged count. Teardown stage T1
    /// calls it when the transport goes away.
    ///
    /// A lent frame stays in `tx` with no bytes. This is safe because T1
    /// always comes before a `take_all`, which drops every frame, and a
    /// new transport opens only after that `take_all`:
    /// - A normal teardown takes the T3 snapshot. While its job waits at
    ///   the T2 barrier, the connection is suspended and gives no connect
    ///   action.
    /// - The forced close and the abandon run `take_all` in the same call.
    pub(crate) fn clear_pins(&mut self) {
        for f in &mut self.tx {
            f.pinned = false;
        }
        self.unacked = 0;
    }

    /// Moves out `tx` and the FIFO whole, as one snapshot.
    pub(crate) fn take_all(&mut self) -> (VecDeque<OutFrame>, VecDeque<Pending<T>>) {
        self.unacked = 0;
        (
            core::mem::take(&mut self.tx),
            core::mem::take(&mut self.fifo),
        )
    }

    /// Moves out the FIFO and keeps `tx`. A legacy close fails the
    /// pending requests but still flushes the queued frames.
    pub(crate) fn take_fifo(&mut self) -> VecDeque<Pending<T>> {
        core::mem::take(&mut self.fifo)
    }
}

/// Erases the old copies of secret bytes past the length of `out`, up to
/// `end`. A drain from the front or a clear removes bytes, and leaves
/// old copies of them in the free part. Returns the new end of the secret
/// bytes.
///
/// The erase covers only the bytes that the removal freed, so its cost
/// follows the size of the secret copy and not the buffer capacity.
fn erase_stale(out: &mut Vec<u8>, end: usize) -> usize {
    let stale = end.saturating_sub(out.len());
    if stale > 0 {
        let spare = out.spare_capacity_mut();
        let k = stale.min(spare.len());
        if let Some(s) = spare.get_mut(..k) {
            s.zeroize();
        }
    }
    end.min(out.len())
}

/// Makes room for `extra` more bytes in `out`. A growth moves the bytes
/// to a new buffer and erases the old buffer before it is freed.
///
/// The capacity at least doubles, as in the growth of `Vec`, so a run of
/// copies stays linear in time.
fn reserve_erased(out: &mut Vec<u8>, extra: usize) {
    let need = out.len().saturating_add(extra);
    if need <= out.capacity() {
        return;
    }
    let mut grown = Vec::with_capacity(need.max(out.capacity().saturating_mul(2)));
    grown.extend_from_slice(out);
    out.zeroize();
    *out = grown;
}

impl<T: Tokens> Connection<T> {
    /// Copies sendable bytes into `out`, at most `max` bytes, and returns
    /// the count.
    ///
    /// Contract:
    /// - It returns 0 with no transport.
    /// - It walks `tx` from the head. Each frame must pass `may_send`. The
    ///   walk stops at the first frame that fails the gate.
    /// - It copies from offset `written + already copied` of each frame
    ///   and pins every frame it copies.
    /// - It adds the count to `requests.unacked`.
    /// - When it copies the first byte of an auth packet, it records the
    ///   entry of that packet as the next AUTH reply of the transport.
    ///   The copy order is the wire order, so each reply finds its packet.
    /// - It changes nothing else. The bytes are not sent until
    ///   `handle_transmitted` acknowledges them.
    ///
    /// Secret frames (Connect, Auth, Sasl):
    /// - The caller gives the same buffer to each call. It removes bytes
    ///   only with a drain from the front or a clear. Its drop of the
    ///   buffer erases the whole buffer.
    /// - The call records where the secret bytes that it copies end. The
    ///   next call first erases the old copies that a removal left past
    ///   the end of `out`. This occurs also when no transport exists.
    /// - When `out` holds bytes on entry or after a secret copy, a growth
    ///   of `out` erases the old buffer before it is freed.
    /// - Other frames cause no erase, so the common path does no extra
    ///   work.
    ///
    /// Limits and large plain frames:
    /// - On TLS, the call copies at most `max` bytes and never lends.
    /// - On plaintext, the call copies at most `PLAIN_COPY_MAX` bytes. It
    ///   does not copy a whole plain frame from `LEND_MIN` to `max` bytes.
    ///   When `out` is empty, the frame buffer becomes `out`, and the walk
    ///   frees the old buffer. The erase at entry removed its secret copies.
    /// - When the call copied other bytes before such a frame, it stops.
    ///   The next call, with an empty `out`, lends the frame.
    pub fn poll_transmit(&mut self, out: &mut Vec<u8>, max: usize) -> usize {
        if self.requests.secret_end > 0 {
            self.requests.secret_end = erase_stale(out, self.requests.secret_end);
        }
        if !self.core.has_transport {
            return 0;
        }
        // The copied bytes that wait for an acknowledgement are a prefix of
        // `tx`, after the `written` offset of each frame. The walk skips
        // them and continues from the first byte that is not copied.
        let mut skip = self.requests.unacked;
        let mut copied = 0usize;
        // Bytes in `out` can be secret, so a growth must not free them.
        let mut guard = !out.is_empty();
        let mut secret_end = self.requests.secret_end;
        let lim = self.tx_limits(max);
        for i in 0..self.requests.tx.len() {
            if copied >= lim.copy {
                break;
            }
            let Some(frame) = self.requests.tx.get(i) else {
                break;
            };
            let remaining = frame.len().saturating_sub(frame.written);
            let in_flight = skip.min(remaining);
            skip = skip.saturating_sub(in_flight);
            if in_flight >= remaining {
                continue;
            }
            if !self.may_send(frame.kind) {
                break;
            }
            let Some(frame) = self.requests.tx.get_mut(i) else {
                break;
            };
            let start = frame.written.saturating_add(in_flight);
            let left = remaining.saturating_sub(in_flight);
            let (lent, chunk) = frame.next_chunk(out, start, left, copied, lim);
            copied = copied.saturating_add(lent);
            let Some(chunk) = chunk else {
                break;
            };
            let take = chunk.len();
            if guard {
                reserve_erased(out, chunk.len());
            }
            out.extend_from_slice(chunk);
            if frame.bytes.is_secret() {
                guard = true;
                secret_end = out.len();
            }
            frame.pinned = true;
            copied = copied.saturating_add(take);
            // The copy of the first byte fixes the wire position of an
            // auth packet. The server answers in that order.
            if let (0, FrameKind::Auth { entry }) = (start, frame.kind) {
                self.auth_record_sent(entry);
            }
        }
        self.requests.unacked = self.requests.unacked.saturating_add(copied);
        self.requests.secret_end = secret_end;
        copied
    }

    /// Gives the limits of one `poll_transmit` call with the budget `max`.
    /// The TLS path copies every chunk into the session, so a lend saves
    /// nothing there.
    fn tx_limits(&self, max: usize) -> TxLimits {
        if self.cfg.tls {
            TxLimits { copy: max, lend: 0 }
        } else {
            TxLimits {
                copy: max.min(PLAIN_COPY_MAX),
                lend: max,
            }
        }
    }

    /// Acknowledges `n` bytes that the last `poll_transmit` calls copied.
    ///
    /// Contract:
    /// - It caps `n` at `requests.unacked`. With no unacknowledged bytes
    ///   (for example after a transport loss) it does nothing.
    /// - It advances `written` of the head frames in order.
    /// - A frame completes only when its last byte is acknowledged. Then
    ///   it leaves `tx`, its secret bytes are zeroed, and
    ///   `timers.on_send(now)` runs.
    /// - A completed `Request{xid}` frame marks the FIFO entry of that xid
    ///   `written`.
    /// - A completed `Connect` frame tells `session` (`on_connect_sent`).
    pub fn handle_transmitted(&mut self, n: usize, now: crate::time::Millis) {
        // A transport loss sets `unacked` to 0. A late acknowledgement of
        // the old transport therefore changes nothing.
        let mut left = n.min(self.requests.unacked);
        self.requests.unacked = self.requests.unacked.saturating_sub(left);
        while left > 0 {
            let Some(frame) = self.requests.tx.front_mut() else {
                break;
            };
            let take = frame.len().saturating_sub(frame.written).min(left);
            frame.written = frame.written.saturating_add(take);
            left = left.saturating_sub(take);
            if !frame.is_complete() {
                break;
            }
            // The drop of the frame zeroes the bytes of a secret frame.
            let Some(done) = self.requests.tx.pop_front() else {
                break;
            };
            self.timers.on_send(now);
            match done.kind {
                FrameKind::Request { xid } => {
                    if let Some(p) = self.requests.fifo.iter_mut().find(|p| p.xid == xid) {
                        p.written = true;
                    }
                }
                FrameKind::Connect => self.on_connect_sent(),
                FrameKind::Ping
                | FrameKind::Auth { .. }
                | FrameKind::SetWatches
                | FrameKind::Sasl
                | FrameKind::Close => {}
            }
        }
    }

    /// Returns the number of requests that wait for a reply. The native
    /// `max_pending` limit uses it.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.requests.fifo.len()
    }

    /// Returns true when the phase gate lets a frame of this kind go out.
    ///
    /// Contract:
    /// - Established: every kind.
    /// - Sasl phase: `Sasl` only.
    /// - Associating with no SASL: `Connect` only.
    /// - Closing flush: every kind, when `close.flush_established` is true
    ///   and the transport that queued the CLOSE_OP is still live.
    /// - Any other phase, or no transport: none.
    pub(crate) fn may_send(&self, kind: FrameKind) -> bool {
        if !self.core.has_transport {
            return false;
        }
        if self.close_flush_open() {
            return true;
        }
        match self.core.phase {
            Phase::Established => true,
            Phase::Sasl(_) => kind == FrameKind::Sasl,
            // The `Sasl` phase starts only after the `ConnectResponse`. In
            // `Associating` the `Connect` frame must therefore go out with
            // or without SASL.
            Phase::Associating => kind == FrameKind::Connect,
            Phase::Idle
            | Phase::TcpConnecting
            | Phase::TlsHandshaking { .. }
            | Phase::TlsConfigFailed => false,
        }
    }

    /// Fails FIFO entries from the front of `entries` with `rc`.
    ///
    /// Contract:
    /// - It pops entries in order and pushes one teardown completion per
    ///   entry, built by `teardown_completion`.
    /// - It stops right after the last `Route::Direct` entry and returns
    ///   true. The entries left are all `Queued`. The caller then parks a
    ///   job that holds them and stops.
    /// - With no `Direct` entry it fails every entry and returns false.
    /// - Watch registrations of the failed entries are dropped.
    pub(crate) fn fail_pending_run(&mut self, entries: &mut VecDeque<Pending<T>>, rc: i32) -> bool {
        requests_fail_run(entries, |p| {
            let done = self.teardown_completion(p, rc);
            self.out.push(done);
        })
    }

    /// Makes the frame of a request body from `check_op`. A framed body
    /// gets its head in place. Another body moves to a new frame buffer.
    pub(crate) fn body_frame(xid: i32, op_type: i32, body: Vec<u8>, framed: bool) -> Vec<u8> {
        if framed {
            Self::frame_in_place(xid, op_type, body)
        } else {
            Self::request_frame(xid, op_type, &body)
        }
    }

    /// Completes a frame that starts with [`REQUEST_HEAD_LEN`] placeholder
    /// bytes. It writes the length prefix and the `RequestHeader` into the
    /// placeholder, so the record stays where it is and is not copied.
    pub(crate) fn frame_in_place(xid: i32, op_type: i32, mut frame: Vec<u8>) -> Vec<u8> {
        // The same length rule as `zk_jute::finish_frame`.
        let body_len = frame.len().saturating_sub(FRAME_PREFIX_LEN);
        let len = i32::try_from(body_len).unwrap_or(i32::MAX);
        let fields = [len, xid, op_type];
        if let Some(head) = frame.get_mut(..REQUEST_HEAD_LEN) {
            for (slot, field) in head.chunks_exact_mut(4).zip(fields) {
                slot.copy_from_slice(&field.to_be_bytes());
            }
        }
        frame
    }

    /// Wraps a request body in its frame: length prefix, `RequestHeader`
    /// with `xid` and `op_type`, then `body`.
    pub(crate) fn request_frame(xid: i32, op_type: i32, body: &[u8]) -> Vec<u8> {
        let header = RequestHeader {
            xid,
            r#type: op_type,
        };
        let cap = FRAME_PREFIX_LEN
            .saturating_add(header.encoded_len())
            .saturating_add(body.len());
        let mut out = Vec::with_capacity(cap);
        let start = zk_jute::begin_frame(&mut out);
        header.encode(&mut out);
        out.extend_from_slice(body);
        zk_jute::finish_frame(&mut out, start);
        out
    }
}

/// The length of the frame length prefix.
const FRAME_PREFIX_LEN: usize = 4;

/// The length of the frame length prefix and the `RequestHeader`.
pub(crate) const REQUEST_HEAD_LEN: usize = FRAME_PREFIX_LEN + 8;

/// Fails entries from the front of `entries` up to and with the last
/// `Route::Direct` entry, or every entry when no entry is `Direct`.
///
/// The `fail` closure makes and pushes the completion of one entry. The
/// closure keeps the run rule apart from the completion format, so a test
/// can check the rule alone. It returns true when a `Direct` entry failed.
fn requests_fail_run<T: Tokens, F: FnMut(Pending<T>)>(
    entries: &mut VecDeque<Pending<T>>,
    mut fail: F,
) -> bool {
    let last_direct = entries.iter().rposition(|p| p.route == Route::Direct);
    let count = match last_direct {
        Some(i) => i.saturating_add(1),
        None => entries.len(),
    };
    for _ in 0..count {
        let Some(p) = entries.pop_front() else {
            break;
        };
        fail(p);
    }
    last_direct.is_some()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::hooks::{AllLevels, NoDefaultWatcher, Rng};
    use crate::state::SaslNegotiation;
    use crate::time::Millis;

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

    /// A connection with a transport in the given phase.
    fn conn(phase: Phase) -> Connection<Tk> {
        let mut c = Connection::new(
            Config::legacy(30_000),
            Compat::LEGACY_C,
            DriverMode::ST,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(NoDefaultWatcher),
            Millis(0),
        );
        c.open_transport();
        c.core.phase = phase;
        c
    }

    fn frame(kind: FrameKind, bytes: &[u8]) -> OutFrame {
        OutFrame::plain(kind, bytes.to_vec())
    }

    fn pending(xid: i32, route: Route) -> Pending<Tk> {
        Pending {
            xid,
            shape: Shape::Data,
            route,
            token: u32::try_from(xid).unwrap(),
            watch: None,
            unwatch: None,
            written: false,
        }
    }

    /// Queues one 2-byte frame of each kind and returns the kinds that a
    /// poll copies.
    fn sendable(c: &mut Connection<Tk>, kinds: &[FrameKind]) -> Vec<FrameKind> {
        for &k in kinds {
            c.requests.push_tail(frame(k, &[1, 2]));
        }
        let mut out = Vec::new();
        let n = c.poll_transmit(&mut out, usize::MAX);
        assert_eq!(n, out.len());
        assert_eq!(c.requests.unacked, n);
        c.requests
            .tx
            .iter()
            .filter(|f| f.pinned)
            .map(|f| f.kind)
            .collect()
    }

    const ALL: [FrameKind; 7] = [
        FrameKind::Connect,
        FrameKind::Sasl,
        FrameKind::Auth { entry: 0 },
        FrameKind::SetWatches,
        FrameKind::Request { xid: 1 },
        FrameKind::Ping,
        FrameKind::Close,
    ];

    #[test]
    fn poll_gates_by_phase() {
        let mut c = conn(Phase::Established);
        c.lose_transport();
        assert!(sendable(&mut c, &ALL).is_empty());

        for phase in [
            Phase::Idle,
            Phase::TcpConnecting,
            Phase::TlsHandshaking {
                deadline: Millis(9),
            },
            Phase::TlsConfigFailed,
        ] {
            assert!(sendable(&mut conn(phase), &ALL).is_empty());
        }

        assert_eq!(
            sendable(&mut conn(Phase::Associating), &ALL),
            vec![FrameKind::Connect]
        );
        let sasl = Phase::Sasl(SaslNegotiation::default());
        let mut c = conn(sasl);
        assert_eq!(
            sendable(&mut c, &[FrameKind::Sasl, FrameKind::Sasl, FrameKind::Ping]),
            vec![FrameKind::Sasl, FrameKind::Sasl]
        );
        // The walk stops at the first frame that fails the gate.
        assert!(sendable(&mut conn(sasl), &[FrameKind::Ping, FrameKind::Sasl]).is_empty());

        assert_eq!(sendable(&mut conn(Phase::Established), &ALL), ALL.to_vec());
        let mut c = conn(Phase::Idle);
        c.close.flush_established = true;
        c.close.op_epoch = c.core.epoch;
        assert_eq!(sendable(&mut c, &ALL), ALL.to_vec());
        // A later transport keeps the normal gate: in Associating only
        // the Connect frame goes out.
        let mut c = conn(Phase::Associating);
        c.close.flush_established = true;
        c.close.op_epoch = c.core.epoch.wrapping_sub(1);
        assert_eq!(sendable(&mut c, &ALL), vec![FrameKind::Connect]);
    }

    #[test]
    fn poll_copies_from_offset_and_pins() {
        let mut c = conn(Phase::Established);
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 1 }, &[0, 1, 2, 3, 4, 5]));
        c.requests
            .push_tail(frame(FrameKind::Ping, &[10, 11, 12, 13]));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, 0), 0);
        assert!(!c.requests.tx[0].pinned);

        assert_eq!(c.poll_transmit(&mut out, 4), 4);
        assert_eq!(out, [0, 1, 2, 3]);
        assert!(c.requests.tx[0].pinned && !c.requests.tx[1].pinned);

        out.clear();
        assert_eq!(c.poll_transmit(&mut out, 4), 4);
        assert_eq!(out, [4, 5, 10, 11]);
        assert!(c.requests.tx[1].pinned);
        assert_eq!(c.requests.unacked, 8);

        c.handle_transmitted(3, Millis(5));
        assert_eq!(c.requests.tx[0].written, 3);
        assert_eq!(c.requests.unacked, 5);
        assert_eq!(c.timers.last_send, Millis(0));

        // The copy continues after the copied bytes, not after `written`.
        out.clear();
        assert_eq!(c.poll_transmit(&mut out, 10), 2);
        assert_eq!(out, [12, 13]);
        assert_eq!(c.requests.unacked, 7);
        assert_eq!(c.poll_transmit(&mut out, 10), 0);

        c.handle_transmitted(7, Millis(9));
        assert!(c.requests.tx.is_empty());
        assert_eq!(c.requests.unacked, 0);
        assert_eq!(c.timers.last_send, Millis(9));
    }

    #[test]
    fn transmitted_caps_at_unacked_and_marks_written() {
        let mut c = conn(Phase::Established);
        c.requests.push_tail(frame(FrameKind::Connect, &[0; 4]));
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 7 }, &[7; 5]));
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 8 }, &[8; 5]));
        c.requests.push_pending(pending(7, Route::Queued));
        c.requests.push_pending(pending(8, Route::Queued));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, 6), 6);

        c.handle_transmitted(100, Millis(3));
        assert!(c.session.connect_sent);
        assert_eq!(c.requests.tx.len(), 2);
        assert_eq!(c.requests.tx[0].written, 2);
        assert!(!c.requests.fifo[0].written);
        assert_eq!(c.requests.unacked, 0);

        // Nothing is copied, so nothing can be acknowledged.
        c.handle_transmitted(5, Millis(4));
        assert_eq!(c.requests.tx[0].written, 2);
        assert_eq!(c.timers.last_send, Millis(3));

        assert_eq!(c.poll_transmit(&mut out, 100), 8);
        c.handle_transmitted(8, Millis(5));
        assert!(c.requests.tx.is_empty());
        assert!(c.requests.fifo.iter().all(|p| p.written));
    }

    #[test]
    fn transmitted_after_transport_loss_is_ignored() {
        let mut c = conn(Phase::Established);
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 1 }, &[1; 6]));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, 4), 4);
        c.requests.clear_pins();
        c.lose_transport();
        c.handle_transmitted(4, Millis(2));
        assert_eq!(c.requests.tx.len(), 1);
        assert_eq!(c.requests.tx[0].written, 0);
        assert!(c.requests.tx[0].is_untouched());
        assert_eq!(c.timers.last_send, Millis(0));
        assert_eq!(c.poll_transmit(&mut out, 4), 0);
    }

    /// Rule: a secret copy records the end of its secret bytes, and a
    /// plain copy records nothing. Each later call erases the
    /// old copies past the length of `out` and moves the end back.
    #[test]
    fn secret_copy_records_the_end_of_its_bytes() {
        let mut c = conn(Phase::Established);
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 1 }, &[1; 6]));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, 100), 6);
        assert_eq!(c.requests.secret_end, 0);
        c.handle_transmitted(6, Millis(1));
        out.clear();

        c.requests
            .push_tail(OutFrame::secret(FrameKind::Connect, vec![9; 8]));
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 2 }, &[2; 4]));
        assert_eq!(c.poll_transmit(&mut out, 100), 12);
        assert_eq!(c.requests.secret_end, 8, "the request is not secret");

        // A partial send leaves secret bytes at the front of `out`.
        out.drain(..5);
        c.handle_transmitted(5, Millis(2));
        assert_eq!(c.poll_transmit(&mut out, 100), 0);
        assert_eq!(c.requests.secret_end, 7);
        assert_eq!(out, [9, 9, 9, 2, 2, 2, 2]);

        out.clear();
        c.handle_transmitted(7, Millis(3));
        assert_eq!(c.poll_transmit(&mut out, 100), 0);
        assert_eq!(c.requests.secret_end, 0);
    }

    /// Rule: a call with no transport also erases the old secret copies.
    /// A reset of the driver thus leaves no secret bytes after the next
    /// flush.
    #[test]
    fn a_call_with_no_transport_erases_old_copies() {
        let mut c = conn(Phase::Established);
        c.requests
            .push_tail(OutFrame::secret(FrameKind::Connect, vec![9; 8]));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, 100), 8);
        assert_eq!(c.requests.secret_end, 8);
        c.requests.clear_pins();
        c.lose_transport();
        out.clear();
        assert_eq!(c.poll_transmit(&mut out, 100), 0);
        assert_eq!(c.requests.secret_end, 0);
    }

    /// Rule: a copy into a buffer that holds bytes keeps them in front,
    /// also when the buffer grows.
    #[test]
    fn a_copy_after_held_bytes_keeps_the_order() {
        let mut c = conn(Phase::Established);
        c.requests
            .push_tail(OutFrame::secret(FrameKind::Connect, vec![9; 8]));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, 100), 8);
        out.shrink_to_fit();
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 1 }, &[1; 64]));
        assert_eq!(c.poll_transmit(&mut out, 100), 64);
        assert!(out.capacity() >= 72);
        assert_eq!(out[..8], [9; 8]);
        assert_eq!(out[8..], [1; 64]);
        assert_eq!(c.requests.secret_end, 8);
    }

    #[test]
    fn fail_run_stops_after_last_direct() {
        let routes = [
            Route::Queued,
            Route::Direct,
            Route::Queued,
            Route::Direct,
            Route::Queued,
        ];
        let mut entries: VecDeque<Pending<Tk>> =
            (1..=5).zip(routes).map(|(x, r)| pending(x, r)).collect();
        let mut failed = Vec::new();
        assert!(requests_fail_run(&mut entries, |p| failed.push(p.xid)));
        assert_eq!(failed, [1, 2, 3, 4]);
        assert_eq!(entries.len(), 1);

        failed.clear();
        assert!(!requests_fail_run(&mut entries, |p| failed.push(p.xid)));
        assert_eq!(failed, [5]);
        assert!(entries.is_empty());
        assert!(!requests_fail_run(&mut entries, |p| failed.push(p.xid)));
        assert_eq!(failed, [5]);
    }

    #[test]
    fn request_frame_layout() {
        let f = Connection::<Tk>::request_frame(0x10, 4, &[9, 9]);
        assert_eq!(f, [0, 0, 0, 10, 0, 0, 0, 0x10, 0, 0, 0, 4, 9, 9]);
        // A head in place gives the same bytes, in the same buffer.
        let mut body = vec![0xee; REQUEST_HEAD_LEN];
        body.extend_from_slice(&[9, 9]);
        let at = body.as_ptr();
        let g = Connection::<Tk>::frame_in_place(0x10, 4, body);
        assert_eq!((g.as_slice(), g.as_ptr()), (f.as_slice(), at));
        let neg = Connection::<Tk>::frame_in_place(-2, 11, vec![0; REQUEST_HEAD_LEN]);
        assert_eq!(neg, Connection::<Tk>::request_frame(-2, 11, &[]));
    }

    /// Rule: a new transport with a lent frame left in `tx` breaks the
    /// teardown order. The test check stops at the open.
    #[test]
    #[should_panic(expected = "a lent frame outlives its transport")]
    fn a_lent_frame_left_at_the_next_open_is_caught() {
        let mut c = conn(Phase::Established);
        let bytes = vec![0; LEND_MIN];
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 1 }, &bytes));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, usize::MAX), LEND_MIN);
        assert!(c.requests.tx[0].is_lent());
        c.requests.clear_pins();
        c.lose_transport();
        let _ = c.open_transport();
    }

    /// Rule: the copy path never reads a lent frame. A walk that reaches a
    /// lent frame breaks the teardown order, and the test check stops it.
    #[test]
    #[should_panic(expected = "the bytes of a lent frame are read")]
    fn a_walk_that_reaches_a_lent_frame_is_caught() {
        let mut c = conn(Phase::Established);
        let bytes = vec![0; LEND_MIN];
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 1 }, &bytes));
        let mut out = Vec::new();
        assert_eq!(c.poll_transmit(&mut out, usize::MAX), LEND_MIN);
        c.requests.clear_pins();
        out.clear();
        let _ = c.poll_transmit(&mut out, usize::MAX);
    }

    /// Rule: a secret frame never leaves its zeroing buffer, also when it
    /// is large enough for a lend (spec "send queue"). An auth
    /// packet of 600 KiB goes out as copies into the buffer of the caller.
    #[test]
    fn a_large_secret_frame_is_copied() {
        let mut c = conn(Phase::Established);
        let len = 600 * 1024;
        c.requests.push_tail(OutFrame::secret(
            FrameKind::Auth { entry: 0 },
            vec![0x6b; len],
        ));
        let mut wire = Vec::new();
        let mut out = Vec::with_capacity(len);
        let at = out.as_ptr();
        loop {
            let n = c.poll_transmit(&mut out, usize::MAX);
            if n == 0 {
                break;
            }
            assert!(n <= PLAIN_COPY_MAX, "a copy, at most the copy limit");
            assert_eq!((out.as_ptr(), out.capacity()), (at, len), "no lend");
            let head = &c.requests.tx[0];
            assert!(head.bytes.is_secret() && !head.is_lent());
            wire.extend_from_slice(&out);
            out.clear();
            c.handle_transmitted(n, Millis(0));
        }
        assert_eq!(wire, vec![0x6b; len]);
        assert!(c.requests.tx.is_empty());
    }

    /// Rule: a TLS connection never lends. It copies up to `max` bytes,
    /// because the TLS path copies each chunk into the session anyway.
    #[test]
    fn a_tls_connection_copies_large_frames() {
        let mut c = conn(Phase::Established);
        c.cfg.tls = true;
        let len = 1024 * 1024;
        c.requests
            .push_tail(frame(FrameKind::Request { xid: 1 }, &vec![3; len]));
        let mut out = Vec::with_capacity(len);
        let at = out.as_ptr();
        let chunk = 256 * 1024;
        assert_eq!(c.poll_transmit(&mut out, chunk), chunk);
        assert_eq!((out.as_ptr(), out.capacity()), (at, len));
        assert!(!c.requests.tx[0].is_lent());
        out.clear();
        assert_eq!(c.poll_transmit(&mut out, usize::MAX), len - chunk);
        assert_eq!((out.as_ptr(), out.capacity()), (at, len));
        assert!(!c.requests.tx[0].is_lent());
    }

    /// Rule: the xid counter starts at 1 for a seed of 0 and wraps to 1.
    #[test]
    fn xid_seed_and_wrap() {
        let mut r: Requests<Tk> = Requests::new(0);
        assert_eq!(r.next_xid(), 1);
        let mut r: Requests<Tk> = Requests::new(i32::MAX);
        assert_eq!(r.next_xid(), i32::MAX);
        assert_eq!(r.next_xid(), 1);
    }

    /// Rule: priority inserts at the boundary come out in reverse order.
    #[test]
    fn priority_inserts_reverse_at_boundary() {
        let mut r: Requests<Tk> = Requests::new(1);
        let mut head = OutFrame::plain(FrameKind::Ping, vec![0; 8]);
        head.pinned = true;
        r.push_tail(head);
        r.push_tail(OutFrame::plain(FrameKind::Request { xid: 1 }, vec![0; 8]));
        r.push_priority(OutFrame::plain(FrameKind::SetWatches, vec![1]));
        r.push_priority(OutFrame::plain(FrameKind::Auth { entry: 0 }, vec![2]));
        let kinds: Vec<FrameKind> = r.tx.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FrameKind::Ping,
                FrameKind::Auth { entry: 0 },
                FrameKind::SetWatches,
                FrameKind::Request { xid: 1 }
            ]
        );
    }

    #[test]
    fn priority_inserts_stay_after_an_unsent_connect() {
        let mut r: Requests<Tk> = Requests::new(1);
        r.push_tail(OutFrame::plain(FrameKind::Request { xid: 1 }, vec![0; 8]));
        r.push_priority(OutFrame::plain(FrameKind::Connect, vec![0; 8]));
        r.push_priority(OutFrame::plain(FrameKind::Auth { entry: 0 }, vec![1]));
        let kinds: Vec<FrameKind> = r.tx.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FrameKind::Connect,
                FrameKind::Auth { entry: 0 },
                FrameKind::Request { xid: 1 }
            ]
        );
    }
}
