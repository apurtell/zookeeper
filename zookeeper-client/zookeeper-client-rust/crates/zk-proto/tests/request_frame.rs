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

//! Request frame tests through the public `Connection` API. The tests
//! check the wire layout of the request frames, and the transmit of
//! large frames with no copy.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use common::{Tk, conn_with};
use zk_jute::{
    JBuffer, JString, Reader, Record, opcode,
    proto::{GetDataRequest, RequestHeader, SetDataRequest},
};
use zk_proto::{
    Connection, SecretBytes,
    action::ConnectStart,
    compat::Compat,
    config::Config,
    request::{InputDefect, MultiOp, Op, PathIn, Request, Route, Submitted},
    time::Millis,
};

/// The smallest frame that the transmit gives as its own buffer.
const LEND_MIN: usize = 512 * 1024;

/// The most bytes that one transmit call copies on plaintext.
const COPY_MAX: usize = 64 * 1024;

fn lp(p: &str) -> PathIn {
    PathIn::Legacy(Some(p.as_bytes().to_vec()))
}

/// Queues `op` and returns its xid.
fn queue(c: &mut Connection<Tk>, op: Op<u32>) -> i32 {
    let req = Request {
        op,
        token: 7,
        route: Route::Queued,
        defect: InputDefect::default(),
    };
    match c.submit(req, Millis(0)) {
        Ok(Submitted::Queued { xid }) => xid,
        other => panic!("submit: {other:?}"),
    }
}

fn set(len: usize) -> Op<u32> {
    Op::SetData {
        path: lp("/a"),
        data: JBuffer::Bytes(vec![0x5a; len]),
        version: 3,
    }
}

/// Makes a connection, sends its `Connect` frame and reads the
/// `ConnectResponse`. Requests can then go out.
fn established() -> Connection<Tk> {
    let mut c = conn_with(Config::legacy(30_000), Compat::LEGACY_C);
    c.handle_connect_started(ConnectStart::InProgress, Millis(0));
    c.handle_tcp_connected(Millis(0));
    c.handle_transport_ready(Millis(0));
    let mut out = Vec::new();
    let n = c.poll_transmit(&mut out, usize::MAX);
    c.handle_transmitted(n, Millis(0));
    let mut body = Vec::new();
    body.extend_from_slice(&0i32.to_be_bytes());
    body.extend_from_slice(&30_000i32.to_be_bytes());
    body.extend_from_slice(&0x55i64.to_be_bytes());
    body.extend_from_slice(&16i32.to_be_bytes());
    body.extend_from_slice(&[0xAB; 16]);
    body.push(0);
    let mut frame = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    assert_eq!(c.handle_read(&frame, Millis(0)).frames, 1);
    loop {
        if c.poll_output().is_some() {
            continue;
        }
        match c.take_stopped() {
            Some(s) => c.resume(s, Millis(0)),
            None => break,
        }
    }
    c
}

/// Splits one frame into its length prefix, its header and a reader of
/// the record. It checks that the prefix gives the frame length.
fn split(frame: &[u8]) -> (RequestHeader, Reader<'_>) {
    let mut r = Reader::new(frame);
    let len = r.read_i32().unwrap();
    assert_eq!(usize::try_from(len).unwrap(), frame.len() - 4);
    let hdr = RequestHeader::decode(&mut r).unwrap();
    (hdr, r)
}

/// Takes every sendable byte, acknowledges it and returns the bytes.
/// Each call adds its bytes to the end of an empty buffer.
fn send_all(c: &mut Connection<Tk>) -> Vec<u8> {
    let mut wire = Vec::new();
    loop {
        let mut out = Vec::new();
        let n = c.poll_transmit(&mut out, usize::MAX);
        if n == 0 {
            return wire;
        }
        assert_eq!(n, out.len());
        c.handle_transmitted(n, Millis(0));
        wire.extend_from_slice(&out);
    }
}

/// Rule: a request frame is the length prefix, the `RequestHeader` and
/// the record, for each way that the core builds a frame. The prefix
/// counts every byte after it.
#[test]
fn request_frame_layout() {
    let mut c = established();

    let xid = queue(
        &mut c,
        Op::GetData {
            path: lp("/w"),
            watch: Some(9),
        },
    );
    let wire = send_all(&mut c);
    let (hdr, mut r) = split(&wire);
    assert_eq!((hdr.xid, hdr.r#type), (xid, opcode::GET_DATA));
    let rec = GetDataRequest::decode(&mut r).unwrap();
    assert_eq!((rec.path, rec.watch), (JString::from("/w"), true));
    assert_eq!(r.remaining(), 0);

    for len in [0, 100, LEND_MIN - 64, LEND_MIN, 1024 * 1024] {
        let xid = queue(&mut c, set(len));
        let wire = send_all(&mut c);
        let (hdr, mut r) = split(&wire);
        assert_eq!((hdr.xid, hdr.r#type), (xid, opcode::SET_DATA), "{len}");
        let rec = SetDataRequest::decode(&mut r).unwrap();
        assert_eq!(rec.path, JString::from("/a"));
        assert_eq!(rec.data.as_bytes(), Some(&vec![0x5a; len][..]));
        assert_eq!(rec.version, 3);
        assert_eq!(r.remaining(), 0);
    }

    // A multi builds its body apart from the frame.
    let xid = queue(
        &mut c,
        Op::Multi {
            ops: vec![MultiOp::Delete {
                path: lp("/d"),
                version: -1,
                defect: InputDefect::default(),
            }],
        },
    );
    let wire = send_all(&mut c);
    let (hdr, _) = split(&wire);
    assert_eq!((hdr.xid, hdr.r#type), (xid, opcode::MULTI));
}

/// Rule: a whole large plain frame goes to an empty buffer as its own
/// buffer. Its bytes are not copied, so the old capacity of the buffer
/// goes away. Smaller frames and partial frames are copied, at most
/// `COPY_MAX` bytes in one call.
#[test]
fn large_frames_lend_their_buffer() {
    let mut c = established();
    let large = 1024 * 1024;
    let frame_len = |data: usize| 4 + 4 + 4 + (4 + 2) + 4 + data + 4;

    // A copy keeps the capacity of the buffer.
    queue(&mut c, set(LEND_MIN - 64));
    let mut out = Vec::with_capacity(4 * large);
    let mut sent = 0;
    while sent < frame_len(LEND_MIN - 64) {
        out.clear();
        let n = c.poll_transmit(&mut out, usize::MAX);
        assert!(n > 0 && n <= COPY_MAX, "{n}");
        assert_eq!(out.capacity(), 4 * large);
        c.handle_transmitted(n, Millis(0));
        sent += n;
    }
    assert_eq!(sent, frame_len(LEND_MIN - 64));

    // A lend gives the exact buffer of the frame.
    queue(&mut c, set(large));
    let mut out = Vec::with_capacity(4 * large);
    let n = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!((n, out.len(), out.capacity()), (frame_len(large), n, n));
    // The lent frame stays pinned until its last byte is acknowledged.
    let mut again = Vec::new();
    assert_eq!(c.poll_transmit(&mut again, usize::MAX), 0);
    c.handle_transmitted(1000, Millis(0));
    assert_eq!(c.poll_transmit(&mut again, usize::MAX), 0);
    c.handle_transmitted(n - 1000, Millis(0));

    // After other bytes, the walk stops before a large frame. The next
    // call lends it.
    let small = queue(&mut c, set(10));
    let big = queue(&mut c, set(large));
    let mut out = Vec::new();
    let n = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!(n, frame_len(10));
    assert_eq!(split(&out).0.xid, small);
    c.handle_transmitted(n, Millis(0));
    out.clear();
    out.reserve(4 * large);
    let n = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!((n, out.capacity()), (frame_len(large), frame_len(large)));
    assert_eq!(split(&out).0.xid, big);
    c.handle_transmitted(n, Millis(0));

    // A limit below the frame length gives a copy of a part. A started
    // frame is never lent, so the rest is copied too.
    queue(&mut c, set(large));
    let mut out = Vec::with_capacity(4 * large);
    let n = c.poll_transmit(&mut out, 256 * 1024);
    assert_eq!((n, out.capacity()), (COPY_MAX, 4 * large));
    c.handle_transmitted(n, Millis(0));
    out.extend_from_slice(&send_all(&mut c));
    assert_eq!(out.len(), frame_len(large));
    let (_, mut r) = split(&out);
    let rec = SetDataRequest::decode(&mut r).unwrap();
    assert_eq!(rec.data.as_bytes(), Some(&vec![0x5a; large][..]));
}

/// Rule: when the buffer holds bytes of the caller on entry, a whole
/// large frame is copied after them. Each call then makes progress, and
/// the caller bytes stay first.
#[test]
fn a_large_frame_after_held_bytes_is_copied() {
    let mut c = established();
    let large = 1024 * 1024;
    let xid = queue(&mut c, set(large));
    let mut out = Vec::with_capacity(4 * large);
    out.extend_from_slice(b"held");
    let at = out.as_ptr();
    let n = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!(n, COPY_MAX);
    assert_eq!((out.as_ptr(), out.len()), (at, 4 + COPY_MAX), "a copy");
    assert_eq!(&out[..4], b"held");
    c.handle_transmitted(n, Millis(0));
    let mut wire = out.split_off(4);
    wire.extend_from_slice(&send_all(&mut c));
    let (hdr, mut r) = split(&wire);
    assert_eq!(hdr.xid, xid);
    let rec = SetDataRequest::decode(&mut r).unwrap();
    assert_eq!(rec.data.as_bytes(), Some(&vec![0x5a; large][..]));
}

/// Gives the xid of each frame in `wire`.
fn xids(wire: &[u8]) -> Vec<i32> {
    let mut all = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        let len = usize::try_from(i32::from_be_bytes(rest[..4].try_into().unwrap())).unwrap();
        all.push(i32::from_be_bytes(rest[4..8].try_into().unwrap()));
        rest = &rest[4 + len..];
    }
    all
}

/// Adds a digest auth entry. The connection is connected, so its packet
/// goes to the priority place.
fn auth(c: &mut Connection<Tk>) {
    let cred = SecretBytes::new(b"u:pw".to_vec());
    assert!(
        c.add_auth(JString::from("digest"), cred, None, Millis(0))
            .is_ok()
    );
}

/// Rule: a priority insert goes behind the frames that the copied bytes
/// pinned, and before all other frames. One
/// plaintext call copies at most `COPY_MAX` bytes. Thus an `add_auth`
/// among pipelined 64 KiB sets goes behind one set only. A lent frame pins
/// only itself, as the copy of its first bytes does.
#[test]
fn an_auth_goes_behind_the_pinned_frames_only() {
    const AUTH_XID: i32 = -4;
    let mut c = established();
    let sets: Vec<i32> = (0..4).map(|_| queue(&mut c, set(COPY_MAX))).collect();
    let mut out = Vec::new();
    let n = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!(n, COPY_MAX);
    auth(&mut c);
    c.handle_transmitted(n, Millis(0));
    out.extend_from_slice(&send_all(&mut c));
    assert_eq!(xids(&out), [sets[0], AUTH_XID, sets[1], sets[2], sets[3]]);

    let big = queue(&mut c, set(LEND_MIN));
    let tail = queue(&mut c, set(10));
    let mut out = Vec::new();
    let n = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!(n, out.len());
    assert_eq!(xids(&out), [big], "a lent frame");
    auth(&mut c);
    c.handle_transmitted(n, Millis(0));
    out.extend_from_slice(&send_all(&mut c));
    assert_eq!(xids(&out), [big, AUTH_XID, tail]);
}
