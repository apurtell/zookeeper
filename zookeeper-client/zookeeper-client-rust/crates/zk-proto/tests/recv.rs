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

//! Receive path tests that need only the public API.

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
use zk_jute::data::Stat;
use zk_jute::proto::{GetDataResponse, ReplyHeader};
use zk_jute::{JBuffer, Record, encode_frame};
use zk_proto::{
    Connection, Output, Reply,
    action::ConnectStart,
    compat::Compat,
    config::Config,
    request::{InputDefect, Op, PathIn, Request, Route, Submitted},
    time::Millis,
};

/// The bytes of one framed connect response for a 30 s session.
fn connect_response() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0i32.to_be_bytes());
    body.extend_from_slice(&30_000i32.to_be_bytes());
    body.extend_from_slice(&0x55i64.to_be_bytes());
    body.extend_from_slice(&16i32.to_be_bytes());
    body.extend_from_slice(&[0xAB; 16]);
    body.push(0);
    let mut frame = Vec::new();
    encode_frame(&body, &mut frame);
    frame
}

/// Gives the frame to the connection as a driver that reads each body
/// part straight into the body does. Only the length prefix goes through
/// `handle_read`. It returns the frame count of each call.
fn read_in_place(c: &mut Connection<Tk>, frame: &[u8], part: usize) -> Vec<usize> {
    let mut counts = vec![c.handle_read(&frame[..4], Millis(0)).frames];
    let mut at = 4;
    while at < frame.len() {
        let room = c.body_room(part);
        assert!(!room.is_empty() && room.len() <= part);
        let n = room.len();
        room.copy_from_slice(&frame[at..at + n]);
        at += n;
        let r = c.handle_body_read(n, Millis(0));
        assert_eq!(r.consumed, n);
        counts.push(r.frames);
    }
    counts
}

/// Sends every queued byte.
fn send_all(c: &mut Connection<Tk>) {
    loop {
        let mut out = Vec::new();
        let n = c.poll_transmit(&mut out, usize::MAX);
        if n == 0 {
            return;
        }
        c.handle_transmitted(n, Millis(0));
    }
}

/// Takes every output and resumes every barrier. It returns the outputs.
fn drain(c: &mut Connection<Tk>) -> Vec<Output<Tk>> {
    let mut outs = Vec::new();
    loop {
        if let Some(o) = c.poll_output() {
            outs.push(o);
            continue;
        }
        match c.take_stopped() {
            Some(s) => c.resume(s, Millis(0)),
            None => return outs,
        }
    }
}

/// A connection gives no body room without a transport, nor in a length
/// prefix. Reads straight into the body then connect the session and
/// give a large get reply, as `handle_read` does.
#[test]
fn reads_into_the_body_give_the_frames() {
    let mut c = conn_with(Config::legacy(30_000), Compat::LEGACY_C);
    assert!(c.body_room(100).is_empty());
    c.handle_connect_started(ConnectStart::InProgress, Millis(0));
    c.handle_tcp_connected(Millis(0));
    c.handle_transport_ready(Millis(0));
    send_all(&mut c);
    assert!(c.body_room(100).is_empty(), "no length yet");
    let counts = read_in_place(&mut c, &connect_response(), 8);
    assert_eq!(counts.iter().sum::<usize>(), 1);
    assert_eq!(counts.last(), Some(&1));
    let _ = drain(&mut c);

    let req = Request {
        op: Op::GetData {
            path: PathIn::Legacy(Some(b"/a".to_vec())),
            watch: None,
        },
        token: 7,
        route: Route::Queued,
        defect: InputDefect::default(),
    };
    let Ok(Submitted::Queued { xid }) = c.submit(req, Millis(0)) else {
        panic!("submit");
    };
    send_all(&mut c);
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut body = Vec::new();
    ReplyHeader {
        xid,
        zxid: 9,
        err: 0,
    }
    .encode(&mut body);
    GetDataResponse {
        data: JBuffer::Bytes(data.clone()),
        stat: Stat::default(),
    }
    .encode(&mut body);
    let mut frame = Vec::new();
    encode_frame(&body, &mut frame);
    let counts = read_in_place(&mut c, &frame, 64 * 1024);
    assert_eq!(counts.iter().sum::<usize>(), 1);
    assert_eq!(counts.last(), Some(&1));
    let got = drain(&mut c).into_iter().find_map(|o| match o {
        Output::Completion {
            token: 7, result, ..
        } => Some(result),
        _ => None,
    });
    let result = got.expect("a completion");
    assert_eq!(result.rc, 0);
    let Some(Reply::Data { data: d, .. }) = result.reply else {
        panic!("no data reply");
    };
    assert_eq!(d.as_bytes(), Some(data.as_slice()));
}

/// Makes a connection with a session, through reads into the body.
fn connected() -> Connection<Tk> {
    let mut c = conn_with(Config::legacy(30_000), Compat::LEGACY_C);
    c.handle_connect_started(ConnectStart::InProgress, Millis(0));
    c.handle_tcp_connected(Millis(0));
    c.handle_transport_ready(Millis(0));
    send_all(&mut c);
    let _ = read_in_place(&mut c, &connect_response(), 64 * 1024);
    let _ = drain(&mut c);
    c
}

/// Submits a get, reads its reply with `data` straight into the body,
/// and gives the result and the address of the first body part.
fn get_in_place(c: &mut Connection<Tk>, data: Option<&[u8]>) -> (zk_proto::OpResult, usize) {
    let req = Request {
        op: Op::GetData {
            path: PathIn::Legacy(Some(b"/a".to_vec())),
            watch: None,
        },
        token: 7,
        route: Route::Queued,
        defect: InputDefect::default(),
    };
    let Ok(Submitted::Queued { xid }) = c.submit(req, Millis(0)) else {
        panic!("submit");
    };
    send_all(c);
    let mut body = Vec::new();
    ReplyHeader {
        xid,
        zxid: 9,
        err: 0,
    }
    .encode(&mut body);
    GetDataResponse {
        data: data.map(<[u8]>::to_vec).into(),
        stat: Stat {
            version: 5,
            data_length: 77,
            ..Stat::default()
        },
    }
    .encode(&mut body);
    let mut frame = Vec::new();
    encode_frame(&body, &mut frame);
    assert_eq!(c.handle_read(&frame[..4], Millis(0)).frames, 0);
    let room = c.body_room(64 * 1024);
    let first = room.as_ptr() as usize;
    let n = room.len();
    room.copy_from_slice(&frame[4..4 + n]);
    let mut frames = c.handle_body_read(n, Millis(0)).frames;
    if frames == 0 {
        frames = c.handle_read(&frame[4 + n..], Millis(0)).frames;
    }
    assert_eq!(frames, 1);
    let result = drain(c)
        .into_iter()
        .find_map(|o| match o {
            Output::Completion {
                token: 7, result, ..
            } => Some(result),
            _ => None,
        })
        .expect("a completion");
    (result, first)
}

/// The data of a result, or `None` for null data.
fn data_of(r: &zk_proto::OpResult) -> Option<&[u8]> {
    match &r.reply {
        Some(Reply::Data { data, stat }) => {
            assert_eq!((stat.version, stat.data_length), (5, 77));
            data.as_bytes()
        }
        other => panic!("no data reply: {other:?}"),
    }
}

/// Rule: a get gives the same bytes and stat for every value
/// size. A large value stays in the frame body once a dropped reply has
/// left a spare buffer. Until then the reply takes a copy.
#[test]
fn a_large_value_stays_in_the_frame_body() {
    let mut c = connected();
    for len in [0usize, 1, 64 * 1024 - 1, 64 * 1024, 1 << 20] {
        let data: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
        let (r, _) = get_in_place(&mut c, Some(&data));
        assert_eq!(data_of(&r), Some(data.as_slice()), "len {len}");
    }
    let (r, _) = get_in_place(&mut c, None);
    assert_eq!(data_of(&r), None);

    let data: Vec<u8> = (0..1u32 << 20).map(|i| (i % 241) as u8).collect();
    // The data starts after the reply header and the length prefix.
    let at = |r: &zk_proto::OpResult| data_of(r).map(|d| d.as_ptr() as usize);
    let (one, _) = get_in_place(&mut c, Some(&data));
    let (two, first) = get_in_place(&mut c, Some(&data));
    assert_ne!(at(&two), Some(first + 20), "no spare yet: a copy");
    drop(one);
    let (three, first) = get_in_place(&mut c, Some(&data));
    assert_eq!(at(&three), Some(first + 20), "the reply keeps the body");
    assert_eq!(data_of(&three), Some(data.as_slice()));
    drop(two);
    drop(three);
    let (four, first) = get_in_place(&mut c, Some(&data));
    assert_eq!(at(&four), Some(first + 20));
    assert_eq!(data_of(&four), Some(data.as_slice()));
}

#[test]
fn short_header_needs_a_teardown() {
    // A frame of fewer than 16 bytes fails the header peek. The test
    // checks the peek only, so it does not reach the teardown.
    assert!(ReplyHeader::peek(&[0; 15]).is_err());
    assert!(ReplyHeader::peek(&[0; 16]).is_ok());
}

/// Two replies come in one read. No stage stops, so each `poll_output`
/// call after a true `has_output` gives an output. A driver can thus stop
/// between two outputs and leave the rest in the connection.
#[test]
fn has_output_tells_when_poll_output_gives_more() {
    let mut c = connected();
    assert!(!c.has_output());
    let mut frames = Vec::new();
    for token in [7, 8] {
        let req = Request {
            op: Op::Exists {
                path: PathIn::Legacy(Some(b"/a".to_vec())),
                watch: None,
            },
            token,
            route: Route::Queued,
            defect: InputDefect::default(),
        };
        let Ok(Submitted::Queued { xid }) = c.submit(req, Millis(0)) else {
            panic!("submit");
        };
        let mut body = Vec::new();
        ReplyHeader {
            xid,
            zxid: 9,
            err: -101,
        }
        .encode(&mut body);
        encode_frame(&body, &mut frames);
    }
    send_all(&mut c);
    assert_eq!(c.handle_read(&frames, Millis(0)).frames, 2);
    let mut tokens = Vec::new();
    while c.has_output() {
        match c.poll_output() {
            Some(Output::Completion { token, result, .. }) => {
                assert_eq!(result.rc, -101);
                tokens.push(token);
            }
            Some(_) => {}
            None => panic!("has_output promised an output"),
        }
    }
    assert!(c.poll_output().is_none());
    assert!(c.take_stopped().is_none());
    assert_eq!(tokens, [7, 8]);
}
