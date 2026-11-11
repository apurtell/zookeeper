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

//! Auth list tests through the public `Connection` API. The tests
//! drive the core as a driver does and check the wire order of the auth
//! packets and the auth completions.

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
    JBuffer, JString, Record,
    proto::{AuthPacket, RequestHeader},
    rc, xid,
};
use zk_proto::{
    Connection,
    action::ConnectStart,
    compat::Compat,
    config::Config,
    log::{LogArg, LogSite},
    output::Output,
    request::{AddAuthError, InputDefect, Op, PathIn, Request, Route},
    secret::SecretBytes,
    state::State,
    time::Millis,
};

fn conn(compat: Compat, sasl: bool) -> Connection<Tk> {
    let mut cfg = Config::legacy(30_000);
    cfg.sasl = sasl;
    conn_with(cfg, compat)
}

/// Decodes an auth frame into its xid, op and scheme. It also checks
/// the length prefix and the credential bytes.
fn decode_auth(bytes: &[u8], cred: &[u8]) -> (i32, i32, JString) {
    let mut r = zk_jute::Reader::new(bytes);
    let len = r.read_i32().unwrap();
    assert_eq!(usize::try_from(len).unwrap(), bytes.len() - 4);
    let hdr = RequestHeader::decode(&mut r).unwrap();
    let pkt = AuthPacket::decode(&mut r).unwrap();
    assert_eq!(pkt.r#type, 0);
    assert_eq!(pkt.auth.as_bytes(), Some(cred));
    assert_eq!(r.remaining(), 0);
    (hdr.xid, hdr.r#type, pkt.scheme)
}

fn add(c: &mut Connection<Tk>, scheme: &str, tok: u32) -> Result<(), AddAuthError<Tk>> {
    c.add_auth(
        JString::from(scheme),
        SecretBytes::from_slice(b"pw"),
        Some(tok),
        Millis(0),
    )
}

// The helpers below drive the core as a driver does. The tests then
// see the wire order that the server sees.

/// One output of interest for the reply tests.
#[derive(Debug, PartialEq, Eq)]
enum Ev {
    /// An auth result line with its scheme.
    Scheme(LogSite, JString),
    /// An auth completion: tokens, rc, barrier.
    Auth(Vec<u32>, i32, bool),
    /// `AuthLockpoint`.
    Lockpoint,
    /// A session event with its state.
    Session(i32),
}

/// Pops every output and resumes at each stop. It keeps the outputs
/// of interest.
fn run(c: &mut Connection<Tk>) -> Vec<Ev> {
    let mut evs = Vec::new();
    loop {
        if let Some(o) = c.poll_output() {
            match o {
                Output::Log(r)
                    if matches!(
                        r.site,
                        LogSite::AuthSchemeSucceeded | LogSite::AuthSchemeFailed
                    ) =>
                {
                    let scheme = match r.args.as_slice() {
                        [LogArg::Str(s)] => s.clone(),
                        a => panic!("unexpected args {a:?}"),
                    };
                    evs.push(Ev::Scheme(r.site, scheme));
                }
                Output::Auth {
                    tokens,
                    rc,
                    barrier,
                } => evs.push(Ev::Auth(tokens, rc, barrier)),
                Output::AuthLockpoint => evs.push(Ev::Lockpoint),
                Output::Session { state, .. } => evs.push(Ev::Session(state.code())),
                _ => {}
            }
            continue;
        }
        match c.take_stopped() {
            Some(s) => c.resume(s, Millis(0)),
            None => break,
        }
    }
    evs
}

fn ok(scheme: &str) -> Ev {
    Ev::Scheme(LogSite::AuthSchemeSucceeded, JString::from(scheme))
}

fn failed(scheme: &str) -> Ev {
    Ev::Scheme(LogSite::AuthSchemeFailed, JString::from(scheme))
}

/// Sends up to `max` bytes and acknowledges them. It returns the
/// copied bytes.
fn send_some(c: &mut Connection<Tk>, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let n = c.poll_transmit(&mut out, max);
    c.handle_transmitted(n, Millis(0));
    out
}

/// Splits sent bytes into frames. An auth frame gives its scheme, and
/// any other frame gives `None`.
fn wire(bytes: &[u8]) -> Vec<Option<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let len = i32::from_be_bytes(rest[..4].try_into().unwrap());
        let (frame, tail) = rest.split_at(4 + usize::try_from(len).unwrap());
        let auth = frame[4..8] == xid::AUTH.to_be_bytes();
        frames.push(auth.then(|| decode_auth(frame, b"pw").2.into_bytes().unwrap()));
        rest = tail;
    }
    frames
}

/// Sends every sendable byte and returns the frames on the wire.
fn send(c: &mut Connection<Tk>) -> Vec<Option<Vec<u8>>> {
    wire(&send_some(c, usize::MAX))
}

fn schemes(names: &[&str]) -> Vec<Option<Vec<u8>>> {
    names.iter().map(|n| Some(n.as_bytes().to_vec())).collect()
}

/// Opens a transport and sends the `Connect` frame.
fn connect(c: &mut Connection<Tk>) {
    c.handle_connect_started(ConnectStart::InProgress, Millis(0));
    c.handle_tcp_connected(Millis(0));
    c.handle_transport_ready(Millis(0));
    assert_eq!(send(c), vec![None]);
}

/// Reads the `ConnectResponse` of session 0x55. Under SASL the core
/// then waits in the Sasl phase. Otherwise finalize runs.
fn respond(c: &mut Connection<Tk>, read_only: bool) -> Vec<Ev> {
    let body = response(30_000, 0x55, read_only);
    let mut frame = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    assert_eq!(c.handle_read(&frame, Millis(0)).frames, 1);
    run(c)
}

/// Connects and finishes finalize.
fn establish(c: &mut Connection<Tk>, read_only: bool) -> Vec<Ev> {
    connect(c);
    respond(c, read_only)
}

/// Reads one AUTH reply with `err` and runs it to the end.
fn reply(c: &mut Connection<Tk>, err: i32) -> Vec<Ev> {
    let mut frame = 16_i32.to_be_bytes().to_vec();
    frame.extend_from_slice(&xid::AUTH.to_be_bytes());
    frame.extend_from_slice(&0_i64.to_be_bytes());
    frame.extend_from_slice(&err.to_be_bytes());
    assert_eq!(c.handle_read(&frame, Millis(0)).frames, 1);
    run(c)
}

/// Builds a 37-byte `ConnectResponse` body.
fn response(timeout: i32, session_id: i64, read_only: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0i32.to_be_bytes());
    b.extend_from_slice(&timeout.to_be_bytes());
    b.extend_from_slice(&session_id.to_be_bytes());
    b.extend_from_slice(&16i32.to_be_bytes());
    b.extend_from_slice(&[0xAB; 16]);
    b.push(u8::from(read_only));
    b
}

#[test]
fn an_add_before_the_connect_send_keeps_the_connect_first() {
    let mut c = conn(Compat::LEGACY_C, false);
    c.handle_connect_started(ConnectStart::InProgress, Millis(0));
    c.handle_tcp_connected(Millis(0));
    c.handle_transport_ready(Millis(0));
    // The driver can run the add before its first send. The packet
    // goes after the `Connect` frame, so the handshake goes out.
    add(&mut c, "a", 1).unwrap();
    assert_eq!(send(&mut c), vec![None]);
    let _ = respond(&mut c, false);
    assert_eq!(send(&mut c), schemes(&["a", "a"]));
    assert_eq!(
        reply(&mut c, 0),
        vec![Ev::Lockpoint, ok("a"), Ev::Auth(vec![1], 0, false)]
    );
    assert_eq!(reply(&mut c, 0), vec![Ev::Lockpoint, ok("a")]);
}

#[test]
fn native_duplicate_goes_after_the_resend() {
    let mut compat = Compat::NATIVE;
    compat.auth_dup_while_associating = true;
    let mut c = conn(compat, false);
    connect(&mut c);
    add(&mut c, "a", 1).unwrap();
    let _ = respond(&mut c, false);
    assert_eq!(send(&mut c), schemes(&["a", "a"]));
    assert_eq!(reply(&mut c, 0), vec![ok("a"), Ev::Auth(vec![1], 0, false)]);
    assert_eq!(reply(&mut c, 0), vec![ok("a")]);
}

#[test]
fn native_failure_completes_only_the_rejected_token() {
    let mut c = conn(Compat::NATIVE, false);
    let _ = establish(&mut c, false);
    add(&mut c, "a", 1).unwrap();
    add(&mut c, "bogus", 2).unwrap();
    add(&mut c, "c", 3).unwrap();
    assert_eq!(send(&mut c), schemes(&["a", "bogus", "c"]));
    assert_eq!(reply(&mut c, 0), vec![ok("a"), Ev::Auth(vec![1], 0, false)]);
    let evs = reply(&mut c, rc::ZAUTHFAILED);
    assert_eq!(
        evs,
        vec![
            failed("bogus"),
            Ev::Auth(vec![2], rc::ZAUTHFAILED, false),
            Ev::Session(State::AuthFailed.code()),
            Ev::Auth(vec![3], rc::ZAUTHFAILED, false),
        ]
    );
    assert_eq!(c.state(), State::AuthFailed);
}

/// Rule: the reply to a rejected credential completes only its own token.
/// The teardown then fails the other tokens.
#[test]
fn legacy_failure_completes_only_the_rejected_token() {
    let mut c = conn(Compat::LEGACY_C, false);
    let _ = establish(&mut c, false);
    add(&mut c, "a", 1).unwrap();
    add(&mut c, "bogus", 2).unwrap();
    assert_eq!(send(&mut c), schemes(&["bogus", "a"]));
    let evs = reply(&mut c, rc::ZAUTHFAILED);
    assert_eq!(
        evs,
        vec![
            Ev::Lockpoint,
            failed("bogus"),
            Ev::Auth(vec![2], rc::ZAUTHFAILED, true),
            Ev::Session(State::AuthFailed.code()),
            Ev::Lockpoint,
            Ev::Auth(vec![1], rc::ZAUTHFAILED, true),
        ]
    );
    assert_eq!(c.state(), State::AuthFailed);
}

/// Queues a `setData` request with `len` data bytes.
fn queue_set(c: &mut Connection<Tk>, len: usize) {
    let req = Request {
        op: Op::SetData {
            path: PathIn::Legacy(Some(b"/a".to_vec())),
            data: JBuffer::Bytes(vec![0x5a; len]),
            version: -1,
        },
        token: 7,
        route: Route::Queued,
        defect: InputDefect::default(),
    };
    assert!(c.submit(req, Millis(0)).is_ok());
}

/// Rule: a copy buffer keeps the wire bytes in order when it grows
/// after a secret frame. The growth occurs in the copy of the
/// secret frame, and in a later copy into a buffer that holds bytes.
#[test]
fn secret_copies_keep_the_wire_order() {
    let mut c = conn(Compat::LEGACY_C, false);
    establish(&mut c, false);

    add(&mut c, "digest", 1).unwrap();
    queue_set(&mut c, 4096);
    let mut out = Vec::new();
    let n = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!(n, out.len());
    assert_eq!(wire(&out), vec![Some(b"digest".to_vec()), None]);
    // The data field comes just before the version field.
    assert_eq!(out[out.len() - 4 - 4096..out.len() - 4], [0x5a; 4096]);
    c.handle_transmitted(n, Millis(0));
    out.clear();

    // The second copy appends to a buffer that holds an auth frame.
    add(&mut c, "digest", 2).unwrap();
    let first = c.poll_transmit(&mut out, usize::MAX);
    out.shrink_to_fit();
    queue_set(&mut c, 8192);
    let second = c.poll_transmit(&mut out, usize::MAX);
    assert_eq!(first + second, out.len());
    assert_eq!(wire(&out), vec![Some(b"digest".to_vec()), None]);
    assert_eq!(out[out.len() - 4 - 8192..out.len() - 4], [0x5a; 8192]);
}
