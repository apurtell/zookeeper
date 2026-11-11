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

//! The znode data of a DATA reply.
//!
//! A large value stays in the received frame body. The reply takes the
//! body, and the frame decoder takes a spare buffer of the same size in
//! its place. Thus a large get makes no copy of the value in the core.
//!
//! A dropped reply gives its buffer back as the next spare. The spare
//! lives in a slot that the connection and its replies share. A reply can
//! go to another thread, so the slot has a lock. The connection takes
//! the lock only for a large value, and for a small frame while a spare
//! exists.

use core::fmt;
use core::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use zk_jute::JBuffer;

/// The smallest value that stays in the frame body. The reply copies a
/// smaller value, because the copy costs less than the slot lock.
pub(crate) const LARGE: usize = 64 * 1024;

/// The largest spare that the slot keeps. The frame decoder keeps no
/// larger buffer, so a larger spare has no use.
const SPARE_MAX: usize = 4 * 1024 * 1024;

/// The znode data of a DATA reply. It can be null.
///
/// A small value is an exact copy. A large value is a range of a buffer
/// that the reply owns, which is the frame body or a copy with the
/// capacity of the frame. When the reply drops, that buffer becomes the
/// spare of its connection, so the next large frame needs no new buffer.
/// The type has the size of a `Vec`, so a `Reply` does not grow.
#[derive(Default)]
pub struct ReplyData(Repr);

/// The forms of [`ReplyData`].
#[derive(Default)]
enum Repr {
    /// Null data.
    #[default]
    Null,
    /// An exact copy, with no slot.
    Owned(Vec<u8>),
    /// A large value in a buffer that goes back to the slot.
    Linked(Box<Linked>),
}

/// A large value and the slot that takes its buffer back.
struct Linked {
    /// The buffer that holds the value.
    buf: Vec<u8>,
    /// The range of the value in `buf`.
    range: Range<usize>,
    /// The slot that takes `buf` back when the value drops.
    home: Home,
}

impl Drop for Linked {
    fn drop(&mut self) {
        self.home.give(core::mem::take(&mut self.buf));
    }
}

impl ReplyData {
    /// Returns true for null data.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self.0, Repr::Null)
    }

    /// Returns the bytes, or `None` for null data.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.0 {
            Repr::Null => None,
            Repr::Owned(b) => Some(b),
            Repr::Linked(l) => Some(l.buf.get(l.range.clone()).unwrap_or_default()),
        }
    }

    /// Returns the bytes, or `None` for null data. A value that fills its
    /// buffer moves out with no copy. A value in a frame body moves out
    /// as a copy, and the body then becomes the spare of its connection.
    #[must_use]
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self.0 {
            Repr::Null => None,
            Repr::Owned(b) => Some(b),
            Repr::Linked(mut l) => {
                if l.range.start == 0 && l.range.end == l.buf.len() {
                    // The slot then gets an empty buffer, which it ignores.
                    return Some(core::mem::take(&mut l.buf));
                }
                Some(l.buf.get(l.range.clone()).unwrap_or_default().to_vec())
            }
        }
    }

    /// Makes the data of a large value at `range` in `buf`, linked to
    /// the slot `home`.
    fn linked(buf: Vec<u8>, range: Range<usize>, home: Home) -> Self {
        Self(Repr::Linked(Box::new(Linked { buf, range, home })))
    }
}

impl From<JBuffer> for ReplyData {
    fn from(b: JBuffer) -> Self {
        Self(b.into_bytes().map_or(Repr::Null, Repr::Owned))
    }
}

impl Clone for ReplyData {
    /// The clone is an exact copy of the value. It has no slot.
    fn clone(&self) -> Self {
        Self(
            self.as_bytes()
                .map_or(Repr::Null, |b| Repr::Owned(b.to_vec())),
        )
    }
}

impl PartialEq for ReplyData {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ReplyData {}

impl PartialEq<JBuffer> for ReplyData {
    fn eq(&self, other: &JBuffer) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl fmt::Debug for ReplyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReplyData").field(&self.as_bytes()).finish()
    }
}

/// The link from a reply to the slot of its connection.
struct Home {
    /// The shared slot.
    shared: Arc<Shared>,
    /// The transport epoch of the reply.
    epoch: u64,
}

impl Home {
    /// Puts `buf` into the slot. The slot takes it only in the same
    /// transport epoch, only when it is empty, and only when the frame
    /// decoder can keep the buffer.
    fn give(&self, buf: Vec<u8>) {
        let cap = buf.capacity();
        let used = cap <= LARGE || buf.len().saturating_mul(2) >= cap;
        if cap == 0 || cap > SPARE_MAX || !used {
            return;
        }
        if let Ok(mut slot) = self.shared.slot.lock() {
            if slot.epoch == self.epoch && slot.spare.is_none() {
                slot.spare = Some(buf);
                self.shared.full.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// The spare buffer and the transport epoch.
#[derive(Default)]
struct Slot {
    /// The epoch of the current transport.
    epoch: u64,
    /// The buffer that the next large value gives to the decoder.
    spare: Option<Vec<u8>>,
}

/// The slot and a flag that tells, with no lock, that it holds a spare.
#[derive(Default)]
struct Shared {
    /// The slot.
    slot: Mutex<Slot>,
    /// True while the slot holds a spare.
    full: AtomicBool,
}

/// The spare slot of one connection.
#[derive(Default)]
pub(crate) struct Spares(Arc<Shared>);

impl Spares {
    /// Makes the data of the value at `at` in `body`. `None` in `at` is
    /// null data. When a spare exists, a large value takes `body`, and
    /// the spare takes its place. Otherwise the reply takes a copy, and
    /// `body` stays with the decoder. A small value is always a copy. It
    /// returns `None` when `at` is not in `body`.
    pub(crate) fn data_of(
        &self,
        body: &mut Vec<u8>,
        at: Option<Range<usize>>,
    ) -> Option<ReplyData> {
        let Some(at) = at else {
            return Some(ReplyData::default());
        };
        let value = body.get(at.clone())?;
        if value.len() < LARGE {
            return Some(ReplyData(Repr::Owned(value.to_vec())));
        }
        let (spare, epoch) = self.take();
        let home = Home {
            shared: Arc::clone(&self.0),
            epoch,
        };
        let Some(spare) = spare else {
            // The copy has the capacity of the frame. When the reply
            // drops, the next frame of this size fits in it.
            let mut copy = Vec::with_capacity(body.len());
            copy.extend_from_slice(value);
            let all = 0..copy.len();
            return Some(ReplyData::linked(copy, all, home));
        };
        Some(ReplyData::linked(core::mem::replace(body, spare), at, home))
    }

    /// Drops the spare after a small frame. A large spare thus stays only
    /// while large frames arrive, as the kept decoder buffer does.
    pub(crate) fn release(&self) {
        if !self.0.full.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(mut slot) = self.0.slot.lock() {
            slot.spare = None;
            self.0.full.store(false, Ordering::Relaxed);
        }
    }

    /// Starts a new transport epoch and drops the spare. A reply of the
    /// old transport then gives no buffer to the new one.
    pub(crate) fn reset(&self) {
        if let Ok(mut slot) = self.0.slot.lock() {
            slot.epoch = slot.epoch.wrapping_add(1);
            slot.spare = None;
            self.0.full.store(false, Ordering::Relaxed);
        }
    }

    /// Takes the spare and gives the current epoch.
    fn take(&self) -> (Option<Vec<u8>>, u64) {
        match self.0.slot.lock() {
            Ok(mut slot) => {
                let spare = slot.spare.take();
                self.0.full.store(false, Ordering::Relaxed);
                (spare, slot.epoch)
            }
            // A poisoned lock gives no spare and an epoch that no slot
            // has, so the reply gives nothing back.
            Err(_) => (None, u64::MAX),
        }
    }

    /// Returns true while the slot holds a spare.
    #[cfg(test)]
    pub(crate) fn has_spare(&self) -> bool {
        self.0.slot.lock().is_ok_and(|slot| slot.spare.is_some())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The buffer of a value, if the value is linked to a slot.
    fn linked_buf(d: &ReplyData) -> Option<&Vec<u8>> {
        match &d.0 {
            Repr::Linked(l) => Some(&l.buf),
            Repr::Null | Repr::Owned(_) => None,
        }
    }

    #[test]
    fn the_data_has_the_size_of_a_vec() {
        assert_eq!(size_of::<ReplyData>(), size_of::<Vec<u8>>());
    }

    #[test]
    fn a_small_value_is_an_exact_copy() {
        let s = Spares::default();
        let mut b = body(100);
        let d = s.data_of(&mut b, Some(10..20)).unwrap();
        assert_eq!(d.as_bytes(), b.get(10..20));
        assert_eq!(b.len(), 100, "the body stays");
        drop(d);
        assert!(!s.has_spare(), "a small copy is no spare");
    }

    #[test]
    fn null_and_empty_values_keep_their_meaning() {
        let s = Spares::default();
        let mut b = body(100);
        let null = s.data_of(&mut b, None).unwrap();
        assert!(null.is_null());
        assert_eq!(null.as_bytes(), None);
        assert_eq!(null.into_bytes(), None);
        let empty = s.data_of(&mut b, Some(20..20)).unwrap();
        assert_eq!(empty.as_bytes(), Some(&[][..]));
        assert_eq!(empty.into_bytes(), Some(Vec::new()));
        assert!(s.data_of(&mut b, Some(90..101)).is_none());
    }

    #[test]
    fn a_large_value_takes_the_body_when_a_spare_exists() {
        let s = Spares::default();
        let n = LARGE + 100;
        let at = 20..20 + LARGE;
        // The first value has no spare, so it is a copy with the
        // capacity of the frame.
        let mut b = body(n);
        let first = s.data_of(&mut b, Some(at.clone())).unwrap();
        assert_eq!(first.as_bytes(), b.get(at.clone()));
        assert_eq!(b.len(), n, "the body stays with the decoder");
        assert!(linked_buf(&first).unwrap().capacity() >= n);
        drop(first);
        assert!(s.has_spare());
        // The second value takes the body, and the spare takes its place.
        let frame = b.clone();
        let mut b = frame.clone();
        let at_ptr = b.as_ptr();
        let second = s.data_of(&mut b, Some(at.clone())).unwrap();
        assert!(!s.has_spare());
        assert_eq!(second.as_bytes(), frame.get(at.clone()));
        assert_eq!(
            linked_buf(&second).unwrap().as_ptr(),
            at_ptr,
            "no copy of the value"
        );
        assert!(b.capacity() >= n, "the decoder gets the spare");
        // A value in a body is copied out, and the body becomes the spare.
        assert_eq!(second.into_bytes().as_deref(), frame.get(at));
        assert!(s.has_spare());
    }

    #[test]
    fn a_small_frame_releases_the_spare() {
        let s = Spares::default();
        let mut b = body(LARGE * 2);
        drop(s.data_of(&mut b, Some(0..LARGE)));
        assert!(s.has_spare());
        s.release();
        assert!(!s.has_spare());
        s.release();
    }

    #[test]
    fn a_reply_of_an_old_transport_gives_no_spare() {
        let s = Spares::default();
        let mut b = body(LARGE * 2);
        let d = s.data_of(&mut b, Some(0..LARGE)).unwrap();
        s.reset();
        drop(d);
        assert!(!s.has_spare());
        let d = s.data_of(&mut b, Some(0..LARGE)).unwrap();
        drop(d);
        assert!(s.has_spare(), "the new epoch takes a spare");
    }

    #[test]
    fn the_slot_keeps_no_buffer_that_the_decoder_drops() {
        let s = Spares::default();
        // A frame of more than 4 MiB gives no spare.
        let mut b = vec![1u8; SPARE_MAX + 1];
        drop(s.data_of(&mut b, Some(0..LARGE)));
        assert!(!s.has_spare());
        // A clone has no slot.
        let mut b = body(LARGE * 2);
        let d = s.data_of(&mut b, Some(0..LARGE)).unwrap();
        let c = d.clone();
        assert_eq!(c, d);
        assert!(linked_buf(&c).is_none());
        drop(c);
        assert!(!s.has_spare());
        drop(d);
        assert!(s.has_spare());
    }

    #[test]
    fn a_full_copy_moves_out() {
        let d = ReplyData::from(JBuffer::Bytes(b"abc".to_vec()));
        let p = d.as_bytes().unwrap().as_ptr();
        assert_eq!(d, JBuffer::Bytes(b"abc".to_vec()));
        let v = d.into_bytes().unwrap();
        assert_eq!((v.as_ptr(), v.as_slice()), (p, &b"abc"[..]));
        assert!(ReplyData::from(JBuffer::Null).is_null());
        // A large copy that fills its buffer also moves out, and then
        // gives no spare.
        let s = Spares::default();
        let mut b = body(LARGE + 30);
        let d = s.data_of(&mut b, Some(0..LARGE + 30)).unwrap();
        let p = d.as_bytes().unwrap().as_ptr();
        let v = d.into_bytes().unwrap();
        assert_eq!((v.as_ptr(), v.as_slice()), (p, b.as_slice()));
        assert!(!s.has_spare());
    }
}
