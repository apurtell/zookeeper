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

//! The length-prefix frame codec.
//!
//! Every message on a ZooKeeper connection is a frame: a four-byte
//! big-endian signed length and a body of that length. The decoder takes
//! bytes as they arrive and gives one complete body at a time.

use core::fmt;

/// The size of the frame length prefix.
const HEADER_LEN: usize = 4;

/// The largest growth step below which the body buffer grows in fixed steps.
/// Above it the buffer doubles, so copy work stays linear.
const GROW_STEP: usize = 64 * 1024;

/// The largest buffer that [`FrameDecoder::recycle`] keeps. A larger
/// buffer goes back to the allocator, so one large frame does not hold
/// memory for the life of the decoder.
const RECYCLE_MAX: usize = 4 * 1024 * 1024;

/// A frame length that the decoder does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// The length is zero. The C client sees this as a closed connection
    /// and the core tears down with `ZCONNECTIONLOSS`.
    Empty,
    /// The length is negative. The drop-in core stalls the decoder until the
    /// receive timeout fires. The native core disconnects.
    Negative(i32),
    /// The length is above the configured maximum.
    TooLarge(u32),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("zero frame length"),
            Self::Negative(len) => write!(f, "negative frame length {len}"),
            Self::TooLarge(len) => write!(f, "frame length {len} is above the maximum"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The result of one [`FrameDecoder::push`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pushed {
    /// The input ended before the frame ended. The decoder keeps the
    /// partial frame. A stalled decoder also gives this result.
    NeedMore,
    /// A complete frame body, without its length prefix.
    Frame(Vec<u8>),
    /// The frame length is not valid. The decoder keeps this error until
    /// [`FrameDecoder::stall`] or [`FrameDecoder::reset`].
    Error(FrameError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Reading the length prefix. The value is the number of prefix bytes
    /// already read.
    Header(usize),
    /// Reading a body of length `len`. `got` body bytes are in place.
    Body {
        /// The body length.
        len: usize,
        /// The number of body bytes that the decoder has.
        got: usize,
        /// The size of the last part that `body_room` gave. `commit`
        /// takes no more bytes than this.
        room: usize,
    },
    /// The caller stopped the decoder.
    Stalled,
    /// The last length was not valid.
    Failed(FrameError),
}

/// An incremental decoder for length-prefixed frames.
///
/// The decoder never reserves memory for a length that it has only read in
/// a prefix. The body buffer grows as body bytes arrive, so a hostile length
/// costs new memory only in proportion to the bytes that the peer really
/// sends.
///
/// [`FrameDecoder::recycle`] gives a used body back to the decoder. The
/// decoder can keep that buffer between frames, and the next frame uses
/// it. This kept buffer is the only memory that the decoder holds when no
/// frame is in progress.
///
/// A driver can also read straight into the body. [`FrameDecoder::body_room`]
/// gives the free part of the body, and [`FrameDecoder::commit`] takes the
/// bytes that the driver wrote there. Thus a large frame needs no copy
/// from a read buffer.
///
/// The length of `body` is the initialised part of the buffer. Its first
/// `got` bytes belong to the current frame. The bytes after them are old
/// bytes that the next writes replace. A kept buffer keeps its initialised
/// part, so the next frame of the same size zero-fills nothing.
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    max_len: Option<u32>,
    state: State,
    header: [u8; HEADER_LEN],
    body: Vec<u8>,
}

impl FrameDecoder {
    /// Creates a decoder. `max_len` is the largest body length that the
    /// decoder accepts; `None` means no limit, as in the C client.
    #[must_use]
    pub const fn new(max_len: Option<u32>) -> Self {
        Self {
            max_len,
            state: State::Header(0),
            header: [0; HEADER_LEN],
            body: Vec::new(),
        }
    }

    /// Returns the number of bytes that complete the current part of the
    /// frame: the rest of the length prefix, or the rest of the body.
    ///
    /// A single-threaded driver reads exactly this many bytes, so that it
    /// reads one frame per call as the C client does. The value is zero
    /// while the decoder is stalled or failed.
    #[must_use]
    pub fn want(&self) -> usize {
        match self.state {
            State::Header(got) => HEADER_LEN.saturating_sub(got),
            State::Body { len, got, .. } => len.saturating_sub(got),
            State::Stalled | State::Failed(_) => 0,
        }
    }

    /// Returns true when the decoder is at a frame boundary with no partial
    /// frame.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self.state, State::Header(0))
    }

    /// Returns true when the decoder is stalled.
    #[must_use]
    pub const fn is_stalled(&self) -> bool {
        matches!(self.state, State::Stalled)
    }

    /// Feeds bytes to the decoder.
    ///
    /// The decoder consumes bytes up to the end of one frame at most, and
    /// returns the number of bytes that it consumed with the result. The
    /// caller keeps the bytes that the decoder did not consume and pushes
    /// them again after it handles the frame.
    pub fn push(&mut self, input: &[u8]) -> (usize, Pushed) {
        let mut consumed = 0usize;
        loop {
            let rest = input.get(consumed..).unwrap_or_default();
            match self.state {
                State::Stalled => return (consumed, Pushed::NeedMore),
                State::Failed(e) => return (consumed, Pushed::Error(e)),
                State::Header(got) => {
                    if rest.is_empty() {
                        return (consumed, Pushed::NeedMore);
                    }
                    let mut got = got;
                    for (slot, b) in self.header.iter_mut().skip(got).zip(rest) {
                        *slot = *b;
                        got = got.saturating_add(1);
                        consumed = consumed.saturating_add(1);
                    }
                    if got < HEADER_LEN {
                        self.state = State::Header(got);
                        return (consumed, Pushed::NeedMore);
                    }
                    match self.check_len(i32::from_be_bytes(self.header)) {
                        Ok(len) => {
                            // A recycled buffer keeps its capacity and its
                            // initialised part for the new frame.
                            self.state = State::Body {
                                len,
                                got: 0,
                                room: 0,
                            };
                        }
                        Err(e) => {
                            self.state = State::Failed(e);
                            return (consumed, Pushed::Error(e));
                        }
                    }
                }
                State::Body { len, got, .. } => {
                    if rest.is_empty() {
                        return (consumed, Pushed::NeedMore);
                    }
                    let take = self.push_body(len, got, rest);
                    consumed = consumed.saturating_add(take);
                    return (consumed, self.advance(len, got, take));
                }
            }
        }
    }

    /// Copies the next body bytes from `input` and returns their count.
    /// The copy first replaces the old bytes of the initialised part. Only
    /// the rest goes to the end of the buffer.
    fn push_body(&mut self, len: usize, got: usize, input: &[u8]) -> usize {
        let left = len.saturating_sub(got);
        let take = left.min(input.len());
        self.grow(left, take);
        let init = self.body.len().saturating_sub(got).min(take);
        let end = got.saturating_add(init);
        if let (Some(dst), Some(src)) = (self.body.get_mut(got..end), input.get(..init)) {
            dst.copy_from_slice(src);
        }
        self.body
            .extend_from_slice(input.get(init..take).unwrap_or_default());
        take
    }

    /// Records `n` new body bytes. A complete body leaves the decoder as
    /// the frame, cut to its length.
    fn advance(&mut self, len: usize, got: usize, n: usize) -> Pushed {
        let got = got.saturating_add(n);
        if got < len {
            self.state = State::Body { len, got, room: 0 };
            return Pushed::NeedMore;
        }
        self.state = State::Header(0);
        self.body.truncate(len);
        Pushed::Frame(core::mem::take(&mut self.body))
    }

    /// Returns the free part of the current body, for a read straight into
    /// the frame. The part has at most `max` bytes, and never more than
    /// 64 KiB or the rest of the body. It is empty outside a body.
    ///
    /// The buffer grows with the rule of `push`, so it grows only a little
    /// ahead of the delivered bytes. No unsafe code is used, so the part
    /// is always initialised. Only the first use of a byte zero-fills it.
    /// A kept buffer of the same size therefore needs no fill. The caller
    /// writes bytes at the start of the part, then calls
    /// [`FrameDecoder::commit`].
    pub fn body_room(&mut self, max: usize) -> &mut [u8] {
        let State::Body { len, got, .. } = self.state else {
            return Default::default();
        };
        let left = len.saturating_sub(got);
        let n = left.min(max).min(GROW_STEP);
        self.state = State::Body { len, got, room: n };
        if n == 0 {
            return Default::default();
        }
        self.grow(left, n);
        let end = got.saturating_add(n);
        if self.body.len() < end {
            self.body.resize(end, 0);
        }
        self.body.get_mut(got..end).unwrap_or_default()
    }

    /// Takes the first `n` bytes of the last [`FrameDecoder::body_room`]
    /// part as body bytes, and gives the result as `push` does. The count
    /// is cut to the size of that part, so old bytes after the part never
    /// become frame bytes. A second commit, or a commit after `push`,
    /// takes nothing. Outside a body it takes nothing.
    pub fn commit(&mut self, n: usize) -> Pushed {
        match self.state {
            State::Body { len, got, room } => {
                let n = n.min(room).min(self.body.len().saturating_sub(got));
                self.advance(len, got, n)
            }
            State::Failed(e) => Pushed::Error(e),
            State::Header(_) | State::Stalled => Pushed::NeedMore,
        }
    }

    /// Stops the decoder. A stalled decoder consumes nothing and wants
    /// nothing until [`FrameDecoder::reset`]. The drop-in core stalls on a
    /// negative length instead of the busy loop of the C client.
    pub fn stall(&mut self) {
        self.state = State::Stalled;
        wipe(&mut self.body);
        self.body = Vec::new();
    }

    /// Discards any partial frame and any error, for a new connection.
    pub fn reset(&mut self) {
        self.state = State::Header(0);
        self.header = [0; HEADER_LEN];
        wipe(&mut self.body);
        self.body = Vec::new();
    }

    /// Gives a used frame body back, so that the next frame can use its
    /// memory.
    ///
    /// The caller clears any secret in the body first. The decoder keeps
    /// the buffer only between two frames, and only when it has no buffer
    /// of its own. The capacity must be at most 4 MiB. A capacity above
    /// 64 KiB must also be at most twice the length of the body. Thus a
    /// large buffer stays only while the frames stay large. In all other
    /// cases the decoder drops the buffer. `stall`, `reset` and drop wipe
    /// a kept buffer over its whole capacity.
    ///
    /// The decoder keeps the bytes of the buffer as its initialised part.
    /// The next frame writes over them, so a read into the body needs no
    /// new zero-fill.
    pub fn recycle(&mut self, buf: Vec<u8>) {
        let cap = buf.capacity();
        let used = cap <= GROW_STEP || buf.len().saturating_mul(2) >= cap;
        if matches!(self.state, State::Header(_))
            && self.body.capacity() == 0
            && cap <= RECYCLE_MAX
            && used
        {
            self.body = buf;
        }
    }

    fn check_len(&self, len: i32) -> Result<usize, FrameError> {
        let ulen = u32::try_from(len).map_err(|_| FrameError::Negative(len))?;
        if ulen == 0 {
            return Err(FrameError::Empty);
        }
        if self.max_len.is_some_and(|max| ulen > max) {
            return Err(FrameError::TooLarge(ulen));
        }
        usize::try_from(ulen).map_err(|_| FrameError::TooLarge(ulen))
    }

    /// Makes room for `take` more body bytes after the `got` bytes of the
    /// frame. `left` is the number of body bytes still due, `take`
    /// included. The step is at least 64 KiB, or the current capacity when
    /// that is larger, and never more than `left`. When a step from a
    /// capacity of 64 KiB or more leaves less than 64 KiB of the body, the
    /// buffer takes the whole body at once. Thus, for a frame that starts
    /// with no recycled buffer, the capacity stays below twice the
    /// delivered bytes plus 64 KiB. The room for a read into the body comes
    /// before its bytes, so it can add one part of at most 64 KiB.
    ///
    /// A body can hold secrets, such as the session password or a SASL
    /// token. The decoder therefore moves the bytes to a new buffer itself
    /// and wipes the old buffer. A reallocation in place would free the old
    /// bytes without a wipe.
    fn grow(&mut self, left: usize, take: usize) {
        let got = self.got();
        let cap = self.body.capacity();
        let spare = cap.saturating_sub(got);
        if spare >= take {
            return;
        }
        let mut step = GROW_STEP.max(cap).min(left).max(take);
        if cap >= GROW_STEP && left.saturating_sub(step) < GROW_STEP {
            step = left;
        }
        let mut next = Vec::with_capacity(got.saturating_add(step));
        next.extend_from_slice(self.body.get(..got).unwrap_or_default());
        wipe(&mut self.body);
        self.body = next;
    }

    /// The number of body bytes of the current frame.
    const fn got(&self) -> usize {
        match self.state {
            State::Body { got, .. } => got,
            State::Header(_) | State::Stalled | State::Failed(_) => 0,
        }
    }
}

/// Overwrites the bytes of a buffer with zeros, including its spare
/// capacity. The crate has no dependencies, so it cannot use `zeroize`.
/// `black_box` keeps the optimizer from removing the writes.
fn wipe(buf: &mut Vec<u8>) {
    zero_all(buf);
    core::hint::black_box(buf.as_slice());
    buf.clear();
}

/// Writes zeros over the whole capacity of a buffer, the initialised
/// part included. The buffer is then full.
fn zero_all(buf: &mut Vec<u8>) {
    buf.clear();
    buf.resize(buf.capacity(), 0);
}

impl Drop for FrameDecoder {
    fn drop(&mut self) {
        wipe(&mut self.body);
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Returns the wire length of a body and the number of body bytes that go
/// on the wire. A body longer than `i32::MAX` is cut, so the frame stays
/// well-formed.
fn body_len(len: usize) -> (i32, usize) {
    match i32::try_from(len) {
        Ok(l) => (l, len),
        Err(_) => (i32::MAX, 0x7fff_ffff),
    }
}

/// Appends a frame with the given body to `out`.
pub fn encode_frame(body: &[u8], out: &mut Vec<u8>) {
    let (len, n) = body_len(body.len());
    out.reserve(n.saturating_add(HEADER_LEN));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body.get(..n).unwrap_or(body));
}

/// The position of a frame that [`begin_frame`] opened.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a frame must be closed with finish_frame"]
pub struct FrameStart(usize);

/// Appends a length placeholder to `out` and returns its position. The
/// caller then appends the body, for example with
/// [`Record::encode`](crate::Record::encode), and calls [`finish_frame`].
/// This puts a frame into a buffer without a copy of the body.
pub fn begin_frame(out: &mut Vec<u8>) -> FrameStart {
    let at = out.len();
    out.extend_from_slice(&[0; HEADER_LEN]);
    FrameStart(at)
}

/// Writes the length of a frame that [`begin_frame`] opened. The body is
/// every byte after the placeholder. A body longer than `i32::MAX` gets
/// the length `i32::MAX`, and the caller must not send it.
pub fn finish_frame(out: &mut [u8], start: FrameStart) {
    let FrameStart(at) = start;
    let Some(body_at) = at.checked_add(HEADER_LEN) else {
        return;
    };
    let (len, _) = body_len(out.len().saturating_sub(body_at));
    if let Some(slot) = out.get_mut(at..body_at) {
        for (dst, src) in slot.iter_mut().zip(len.to_be_bytes()) {
            *dst = src;
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{FrameDecoder, GROW_STEP, Pushed, wipe, zero_all};

    /// Writes `n` bytes of `b` into the body room and commits them.
    fn room_write(dec: &mut FrameDecoder, max: usize, b: u8) -> (usize, Pushed) {
        let room = dec.body_room(max);
        room.fill(b);
        let n = room.len();
        (n, dec.commit(n))
    }

    #[test]
    fn growth_keeps_the_body_bytes() {
        let len = 3 * GROW_STEP + 17;
        let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut wire = i32::try_from(len).unwrap().to_be_bytes().to_vec();
        wire.extend_from_slice(&body);
        let mut dec = FrameDecoder::new(None);
        let mut frame = None;
        for chunk in wire.chunks(4093) {
            if let (_, Pushed::Frame(f)) = dec.push(chunk) {
                frame = Some(f);
            }
        }
        assert_eq!(frame.unwrap(), body);
    }

    #[test]
    fn wipe_keeps_the_capacity_and_empties_the_buffer() {
        let mut buf = vec![0xAAu8; 64];
        buf.truncate(10);
        let cap = buf.capacity();
        wipe(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), cap);
    }

    #[test]
    fn capacity_follows_delivered_bytes() {
        let mut dec = FrameDecoder::new(None);
        assert_eq!(dec.push(&i32::MAX.to_be_bytes()), (4, Pushed::NeedMore));
        assert_eq!(dec.body.capacity(), 0);
        let chunk = vec![0u8; 1000];
        let mut sent = 0usize;
        for _ in 0..600 {
            assert_eq!(dec.push(&chunk), (chunk.len(), Pushed::NeedMore));
            sent += chunk.len();
            assert!(dec.body.capacity() <= 2 * sent + GROW_STEP);
        }
    }

    #[test]
    fn small_frame_reserves_only_its_length() {
        let mut dec = FrameDecoder::new(None);
        assert_eq!(dec.push(&[0, 0, 0, 3, 1]), (5, Pushed::NeedMore));
        assert!(dec.body.capacity() <= 3);
    }

    /// A 1 MiB body with a short tail grows in 5 steps, and its last step
    /// takes the tail. The capacity bound holds after each push.
    #[test]
    fn a_large_body_grows_in_few_steps() {
        let len = 16 * GROW_STEP + 88;
        let mut dec = FrameDecoder::new(None);
        let header = i32::try_from(len).unwrap().to_be_bytes();
        assert_eq!(dec.push(&header), (4, Pushed::NeedMore));
        let chunk = vec![5u8; GROW_STEP];
        let mut caps: Vec<usize> = vec![];
        let mut sent = 0;
        let mut frame = None;
        while frame.is_none() {
            let n = GROW_STEP.min(len - sent);
            let (m, pushed) = dec.push(&chunk[..n]);
            assert_eq!(m, n);
            sent += n;
            match pushed {
                Pushed::Frame(f) => frame = Some(f),
                p => assert_eq!(p, Pushed::NeedMore),
            }
            let cap = frame.as_ref().map_or(dec.body.capacity(), Vec::capacity);
            assert!(cap <= 2 * sent + GROW_STEP);
            if caps.last() != Some(&cap) {
                caps.push(cap);
            }
        }
        assert_eq!(caps.len(), 5, "{caps:?}");
        assert_eq!(caps.last(), Some(&len));
        assert_eq!(frame.map(|f| f.len()), Some(len));
    }

    /// Reads into the body follow spec 103. A hostile length gets no
    /// large buffer, each part is at most 64 KiB, and the capacity stays
    /// within twice the delivered bytes plus two parts.
    #[test]
    fn body_room_grows_with_the_delivered_bytes() {
        let mut dec = FrameDecoder::new(None);
        assert_eq!(dec.push(&i32::MAX.to_be_bytes()), (4, Pushed::NeedMore));
        assert_eq!(dec.body.capacity(), 0);
        let mut sent = 0usize;
        for _ in 0..600 {
            let room = dec.body_room(usize::MAX);
            assert_eq!(room.len(), GROW_STEP);
            room.get_mut(..1000).unwrap().fill(7);
            assert_eq!(dec.commit(1000), Pushed::NeedMore);
            sent += 1000;
            assert!(dec.body.capacity() <= 2 * sent + 2 * GROW_STEP);
        }
        // A room that gets no bytes, as after a blocked read, does not
        // grow the buffer again.
        let cap = dec.body.capacity();
        let _ = dec.body_room(GROW_STEP);
        let _ = dec.body_room(GROW_STEP);
        assert_eq!(dec.body.capacity(), cap);
        assert_eq!(dec.want(), i32::MAX as usize - sent);
    }

    /// The first frame zero-fills only the bytes that its parts use. A
    /// kept buffer then serves a frame of the same size with no fill: its
    /// initialised part does not grow, and the frame holds only new bytes.
    #[test]
    fn a_kept_body_needs_no_zero_fill() {
        let len = 16 * GROW_STEP;
        let header = i32::try_from(len).unwrap().to_be_bytes();
        let mut dec = FrameDecoder::new(None);
        assert_eq!(dec.push(&header), (4, Pushed::NeedMore));
        let mut first = None;
        while first.is_none() {
            let (n, p) = room_write(&mut dec, GROW_STEP, 1);
            assert_eq!(n, GROW_STEP);
            assert!(dec.body.len() <= len);
            if let Pushed::Frame(f) = p {
                first = Some(f);
            }
        }
        let first = first.unwrap();
        let (at, cap) = (first.as_ptr(), first.capacity());
        dec.recycle(first);
        assert_eq!(dec.body.len(), len);

        assert_eq!(dec.push(&header), (4, Pushed::NeedMore));
        let mut second = None;
        while second.is_none() {
            let (_, p) = room_write(&mut dec, GROW_STEP, 2);
            if let Pushed::Frame(f) = p {
                second = Some(f);
            } else {
                assert_eq!(dec.body.len(), len, "no new fill");
            }
        }
        let second = second.unwrap();
        assert_eq!((second.as_ptr(), second.capacity()), (at, cap));
        assert_eq!(second.len(), len);
        assert!(second.iter().all(|b| *b == 2));
    }

    /// A push after a kept buffer writes over the old bytes, and a later
    /// read into the body uses the rest of the initialised part.
    #[test]
    fn push_and_body_room_share_a_kept_body() {
        let mut dec = FrameDecoder::new(None);
        dec.recycle(vec![0xEE; 300]);
        let mut wire = 200i32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[1u8; 50]);
        assert_eq!(dec.push(&wire), (54, Pushed::NeedMore));
        assert_eq!(dec.body.len(), 300);
        let (n, p) = room_write(&mut dec, 1000, 2);
        assert_eq!(n, 150);
        assert!(matches!(p, Pushed::Frame(_)), "no frame: {p:?}");
        let Pushed::Frame(f) = p else {
            return;
        };
        assert_eq!(dec.body.capacity(), 0);
        assert_eq!(&f[..50], &[1u8; 50]);
        assert_eq!(&f[50..], &[2u8; 150]);
    }

    /// A stall and a reset wipe and drop a body that a read filled in
    /// place. Then the decoder gives no room.
    #[test]
    fn stall_and_reset_drop_a_body_read_in_place() {
        for stall in [true, false] {
            let mut dec = FrameDecoder::new(None);
            dec.recycle(vec![0xEE; 4096]);
            assert_eq!(dec.push(&1000i32.to_be_bytes()), (4, Pushed::NeedMore));
            assert_eq!(room_write(&mut dec, 100, 9), (100, Pushed::NeedMore));
            assert!(dec.body.capacity() > 0);
            if stall {
                dec.stall();
                assert!(dec.is_stalled());
            } else {
                dec.reset();
                assert!(dec.is_idle());
            }
            assert_eq!(dec.body.capacity(), 0);
            assert!(dec.body_room(100).is_empty());
            assert_eq!(dec.commit(100), Pushed::NeedMore);
            assert_eq!(dec.body.capacity(), 0);
        }
    }

    /// The wipe writes zeros over the whole capacity: the initialised
    /// part, the old bytes after the length, and the spare capacity.
    #[test]
    fn zero_all_covers_the_whole_capacity() {
        let mut buf = vec![0xAAu8; 64];
        buf.truncate(10);
        buf.reserve_exact(64);
        let cap = buf.capacity();
        zero_all(&mut buf);
        assert_eq!(buf.len(), cap);
        assert!(buf.iter().all(|b| *b == 0));
    }
}
