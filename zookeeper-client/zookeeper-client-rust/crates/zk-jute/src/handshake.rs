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

//! The fixed-layout session handshake codec.
//!
//! The C client does not use jute for the handshake. It writes and reads
//! fixed layouts with a 16-byte password (`serialize_prime_connect` and
//! `deserialize_prime_response` in `zookeeper.c`). This module gives the
//! same bytes.

use core::fmt;

/// The size of the session password.
pub const PASSWD_LEN: usize = 16;

/// The size of a `ConnectRequest` body.
pub const CONNECT_REQUEST_LEN: usize = 45;

/// The size of a `ConnectRequest` frame: the body and its length prefix.
pub const CONNECT_REQUEST_FRAME_LEN: usize = 49;

/// The size of a `ConnectResponse` body.
pub const CONNECT_RESPONSE_LEN: usize = 37;

/// The size of a `ConnectResponse` body from a server that does not send
/// the read-only flag.
pub const CONNECT_RESPONSE_OLD_LEN: usize = 36;

/// The body length that goes in the `ConnectRequest` frame prefix.
const CONNECT_REQUEST_WIRE_LEN: i32 = 45;

/// The password length that goes in the `ConnectRequest` body.
const PASSWD_WIRE_LEN: i32 = 16;

/// The handshake request that opens or resumes a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectRequest {
    /// The protocol version. The C client always sends 0.
    pub protocol_version: i32,
    /// The last zxid that the client saw.
    pub last_zxid_seen: i64,
    /// The requested session timeout in milliseconds.
    pub time_out: i32,
    /// The session to resume, or 0 for a new session.
    pub session_id: i64,
    /// The session password.
    pub passwd: [u8; PASSWD_LEN],
    /// True when the client accepts a read-only server.
    pub read_only: bool,
}

/// Copies `src` into `dst` at `*at` and moves `*at` past it.
fn put(dst: &mut [u8], at: &mut usize, src: &[u8]) {
    let Some(end) = at.checked_add(src.len()) else {
        return;
    };
    if let Some(slot) = dst.get_mut(*at..end) {
        for (d, s) in slot.iter_mut().zip(src) {
            *d = *s;
        }
        *at = end;
    }
}

impl ConnectRequest {
    /// Writes the body: the protocol version, the last zxid, the timeout,
    /// the session id, the password length 16, the password and the
    /// read-only byte. The bytes are the ones of the C client.
    pub fn write_body(&self, out: &mut [u8; CONNECT_REQUEST_LEN]) {
        self.write_fields(out, 0);
    }

    /// Writes the frame: the length prefix 45 and the body. The frame holds
    /// the password, so the caller can supply a buffer that it clears after
    /// the send.
    pub fn write_frame(&self, out: &mut [u8; CONNECT_REQUEST_FRAME_LEN]) {
        let mut at = 0usize;
        put(out, &mut at, &CONNECT_REQUEST_WIRE_LEN.to_be_bytes());
        self.write_fields(out, at);
    }

    fn write_fields(&self, out: &mut [u8], start: usize) {
        let mut at = start;
        put(out, &mut at, &self.protocol_version.to_be_bytes());
        put(out, &mut at, &self.last_zxid_seen.to_be_bytes());
        put(out, &mut at, &self.time_out.to_be_bytes());
        put(out, &mut at, &self.session_id.to_be_bytes());
        put(out, &mut at, &PASSWD_WIRE_LEN.to_be_bytes());
        put(out, &mut at, &self.passwd);
        put(out, &mut at, &[u8::from(self.read_only)]);
    }

    /// Returns the body.
    #[must_use]
    pub fn encode_body(&self) -> [u8; CONNECT_REQUEST_LEN] {
        let mut out = [0u8; CONNECT_REQUEST_LEN];
        self.write_body(&mut out);
        out
    }

    /// Returns the frame.
    #[must_use]
    pub fn encode_frame(&self) -> [u8; CONNECT_REQUEST_FRAME_LEN] {
        let mut out = [0u8; CONNECT_REQUEST_FRAME_LEN];
        self.write_frame(&mut out);
        out
    }
}

/// The handshake response of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectResponse {
    /// The protocol version. The C client ignores it.
    pub protocol_version: i32,
    /// The negotiated session timeout in milliseconds.
    pub time_out: i32,
    /// The session id. Zero means that the server rejected the session.
    pub session_id: i64,
    /// The password length on the wire. The C client ignores it and always
    /// reads 16 password bytes.
    pub passwd_len: i32,
    /// The session password.
    pub passwd: [u8; PASSWD_LEN],
    /// True when the server is in read-only mode. A server that does not
    /// send the flag is not read-only.
    pub read_only: bool,
}

/// A `ConnectResponse` body with a length that the client does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandshakeError {
    /// The body length.
    pub len: usize,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConnectResponse body has {} bytes, expected {CONNECT_RESPONSE_LEN} or {CONNECT_RESPONSE_OLD_LEN}",
            self.len
        )
    }
}

impl std::error::Error for HandshakeError {}

/// Decodes a `ConnectResponse` frame body.
///
/// The body has 37 bytes, or 36 bytes from an old server that does not send
/// the read-only flag. The core tears down the connection with
/// `ZCONNECTIONLOSS` on any other length.
///
/// # Errors
///
/// Returns [`HandshakeError`] when the body length is not 36 or 37.
pub fn decode_connect_response(body: &[u8]) -> Result<ConnectResponse, HandshakeError> {
    let err = HandshakeError { len: body.len() };
    if body.len() != CONNECT_RESPONSE_LEN && body.len() != CONNECT_RESPONSE_OLD_LEN {
        return Err(err);
    }
    let mut r = crate::Reader::new(body);
    let protocol_version = r.read_i32().map_err(|_| err)?;
    let time_out = r.read_i32().map_err(|_| err)?;
    let session_id = r.read_i64().map_err(|_| err)?;
    let passwd_len = r.read_i32().map_err(|_| err)?;
    let mut passwd = [0u8; PASSWD_LEN];
    let bytes = r.read_bytes(PASSWD_LEN).map_err(|_| err)?;
    for (d, s) in passwd.iter_mut().zip(bytes) {
        *d = *s;
    }
    let read_only = r.read_u8().is_ok_and(|b| b != 0);
    Ok(ConnectResponse {
        protocol_version,
        time_out,
        session_id,
        passwd_len,
        passwd,
        read_only,
    })
}
