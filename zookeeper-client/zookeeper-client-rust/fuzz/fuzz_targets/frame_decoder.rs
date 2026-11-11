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

//! Splits a byte stream into frames with `FrameDecoder`.
//!
//! The input selects the length limit, a plan of read sizes and the
//! stream. The target reads the stream with `push`, with `body_room` and
//! `commit`, and with recycled buffers. The frames and the first length
//! error must agree with a simple reference splitter.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use zk_fuzz::Cursor;
use zk_jute::{FrameDecoder, FrameError, Pushed};

/// The result of the reference splitter.
#[derive(Debug, Default)]
struct Expected {
    frames: Vec<Vec<u8>>,
    error: Option<FrameError>,
    /// The bytes that the decoder still wants at the end of the stream.
    want: usize,
    idle: bool,
}

fn reference(stream: &[u8], max: Option<u32>) -> Expected {
    let mut e = Expected::default();
    let mut rest = stream;
    loop {
        if rest.len() < 4 {
            e.want = 4 - rest.len();
            e.idle = rest.is_empty();
            return e;
        }
        let len = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        rest = &rest[4..];
        let err = if len < 0 {
            Some(FrameError::Negative(len))
        } else if len == 0 {
            Some(FrameError::Empty)
        } else if max.is_some_and(|m| len.unsigned_abs() > m) {
            Some(FrameError::TooLarge(len.unsigned_abs()))
        } else {
            None
        };
        if let Some(err) = err {
            e.error = Some(err);
            return e;
        }
        let len = len.unsigned_abs() as usize;
        if rest.len() < len {
            e.want = len - rest.len();
            e.idle = false;
            return e;
        }
        e.frames.push(rest[..len].to_vec());
        rest = &rest[len..];
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let max = match c.u8() % 4 {
        0 => None,
        1 => Some(16),
        2 => Some(1024),
        _ => Some(u32::from(c.u16())),
    };
    let plan_len = usize::from(c.u8() % 32) + 1;
    let plan = c.bytes(plan_len).to_vec();
    let stream = c.rest();
    let want = reference(stream, max);

    let mut d = FrameDecoder::new(max);
    let mut got = Vec::new();
    let mut error = None;
    let mut at = 0usize;
    let mut step = 0usize;
    while at < stream.len() && error.is_none() {
        let p = plan.get(step % plan.len()).copied().unwrap_or(0);
        step += 1;
        let size = usize::from(p >> 2) + 1;
        let end = stream.len().min(at + size);
        let chunk = &stream[at..end];
        let room_len = if p & 1 == 1 {
            d.body_room(size).len()
        } else {
            0
        };
        let pushed = if room_len > 0 {
            assert!(room_len <= size, "body_room gave more room than asked");
            let n = room_len.min(chunk.len());
            let room = d.body_room(size);
            room[..n].copy_from_slice(&chunk[..n]);
            at += n;
            d.commit(n)
        } else {
            let (used, pushed) = d.push(chunk);
            assert!(used <= chunk.len(), "push used more bytes than it got");
            if used == 0 && matches!(pushed, Pushed::NeedMore) {
                panic!("push made no progress on {} bytes", chunk.len());
            }
            at += used;
            pushed
        };
        match pushed {
            Pushed::NeedMore => {}
            Pushed::Frame(f) => {
                got.push(f.clone());
                if p & 2 == 2 {
                    d.recycle(f);
                }
            }
            Pushed::Error(e) => error = Some(e),
        }
    }
    assert_eq!(got, want.frames, "the frames differ from the reference");
    assert_eq!(
        error, want.error,
        "the length error differs from the reference"
    );
    if error.is_none() {
        assert_eq!(d.want(), want.want, "want() differs from the reference");
        assert_eq!(
            d.is_idle(),
            want.idle,
            "is_idle() differs from the reference"
        );
    } else {
        assert_eq!(d.want(), 0, "a failed decoder wants no bytes");
        let (used, again) = d.push(b"more");
        assert_eq!(used, 0, "a failed decoder consumes nothing");
        assert_eq!(again, Pushed::Error(error.unwrap_or(FrameError::Empty)));
        d.reset();
        assert!(d.is_idle(), "reset gives an idle decoder");
    }
});
