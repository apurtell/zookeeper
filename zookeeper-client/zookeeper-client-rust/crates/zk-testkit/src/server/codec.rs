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

//! Frame codecs for both ends of the wire.
//!
//! The server model uses the reply encoders and the request decoders. A
//! test uses the request encoders and the reply decoders to talk to the
//! model directly, with no core in between.

use zk_jute::proto::{ConnectRequest, ConnectResponse, ReplyHeader, RequestHeader};
use zk_jute::{
    DecodeError, FrameDecoder, FrameError, JBuffer, Pushed, Reader, Record, encode_frame,
};

/// Encodes one length-prefixed reply frame with a header and a body.
#[must_use]
pub fn encode_reply(xid: i32, zxid: i64, err: i32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    ReplyHeader { xid, zxid, err }.encode(&mut b);
    b.extend_from_slice(body);
    let mut out = Vec::new();
    encode_frame(&b, &mut out);
    out
}

/// Encodes one length-prefixed reply frame with a record body, or with no
/// body.
#[must_use]
pub fn encode_record_reply<R: Record>(xid: i32, zxid: i64, err: i32, body: Option<&R>) -> Vec<u8> {
    let bytes = body.map(Record::to_bytes).unwrap_or_default();
    encode_reply(xid, zxid, err, &bytes)
}

/// Encodes one length-prefixed request frame, as a client sends it.
#[must_use]
pub fn request_frame<R: Record>(xid: i32, op: i32, body: Option<&R>) -> Vec<u8> {
    let mut b = Vec::new();
    RequestHeader { xid, r#type: op }.encode(&mut b);
    if let Some(r) = body {
        r.encode(&mut b);
    }
    let mut out = Vec::new();
    encode_frame(&b, &mut out);
    out
}

/// Encodes one length-prefixed request frame with a raw body.
#[must_use]
pub fn raw_request_frame(xid: i32, op: i32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    RequestHeader { xid, r#type: op }.encode(&mut b);
    b.extend_from_slice(body);
    let mut out = Vec::new();
    encode_frame(&b, &mut out);
    out
}

/// Encodes the length-prefixed `ConnectRequest` frame of a client.
#[must_use]
pub fn connect_frame(req: &ConnectRequest) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(&req.to_bytes(), &mut out);
    out
}

/// Encodes the length-prefixed `ConnectResponse` frame. With `short` the
/// frame has no `read_only` byte, as an old server sends it.
#[must_use]
pub fn connect_response_frame(resp: &ConnectResponse, short: bool) -> Vec<u8> {
    let mut b = resp.to_bytes();
    if short {
        b.pop();
    }
    let mut out = Vec::new();
    encode_frame(&b, &mut out);
    out
}

/// Decodes a `ConnectRequest` body. The `read_only` byte is optional, as
/// in the Java server.
///
/// # Errors
///
/// Returns a [`DecodeError`] for a truncated body.
pub fn decode_connect_request(body: &[u8]) -> Result<ConnectRequest, DecodeError> {
    let mut r = Reader::new(body);
    let protocol_version = r.read_i32()?;
    let last_zxid_seen = r.read_i64()?;
    let time_out = r.read_i32()?;
    let session_id = r.read_i64()?;
    let passwd = JBuffer::decode(&mut r)?;
    let read_only = if r.is_empty() { false } else { r.read_bool()? };
    Ok(ConnectRequest {
        protocol_version,
        last_zxid_seen,
        time_out,
        session_id,
        passwd,
        read_only,
    })
}

/// Decodes a `ConnectResponse` body. The `read_only` byte is optional.
///
/// # Errors
///
/// Returns a [`DecodeError`] for a truncated body.
pub fn decode_connect_response(body: &[u8]) -> Result<ConnectResponse, DecodeError> {
    let mut r = Reader::new(body);
    let protocol_version = r.read_i32()?;
    let time_out = r.read_i32()?;
    let session_id = r.read_i64()?;
    let passwd = JBuffer::decode(&mut r)?;
    let read_only = if r.is_empty() { false } else { r.read_bool()? };
    Ok(ConnectResponse {
        protocol_version,
        time_out,
        session_id,
        passwd,
        read_only,
    })
}

/// Splits a request frame body into its header and the rest.
///
/// # Errors
///
/// Returns a [`DecodeError`] when the body has no full header.
pub fn decode_client_frame(body: &[u8]) -> Result<(RequestHeader, &[u8]), DecodeError> {
    let mut r = Reader::new(body);
    let h = RequestHeader::decode(&mut r)?;
    Ok((h, r.rest()))
}

/// Splits a reply frame body into its header and the rest.
///
/// # Errors
///
/// Returns a [`DecodeError`] when the body has no full header.
pub fn decode_reply(body: &[u8]) -> Result<(ReplyHeader, &[u8]), DecodeError> {
    ReplyHeader::peek(body)
}

/// Splits a byte stream into frame bodies. A partial frame at the end
/// stays in the decoder and is not returned.
///
/// # Errors
///
/// Returns the [`FrameError`] of a bad length prefix.
pub fn split_frames(bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
    let mut d = FrameDecoder::new(None);
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (n, p) = d.push(rest);
        rest = rest.get(n..).unwrap_or_default();
        match p {
            Pushed::Frame(f) => out.push(f),
            Pushed::Error(e) => return Err(e),
            Pushed::NeedMore => {
                if n == 0 {
                    break;
                }
            }
        }
    }
    Ok(out)
}
