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

//! Shared parts of the fuzz targets.
//!
//! [`Cursor`] reads a fuzz input as a stream of small values. [`Enc`]
//! writes the same stream, so the seed generator can make inputs that the
//! targets read as intended. [`sim`] drives a `zk_proto::Connection` the
//! way a driver does, with the server bytes and the driver choices taken
//! from the input.
//!
//! The fuzz harness may panic. A panic or an abort is the signal of a
//! defect, so the checks of the targets use `assert!`.

#![forbid(unsafe_code)]

pub mod sim;

/// Calls `$m!(module, Record)` for each jute record of the client.
///
/// The jute target, the seed generator and the fixtures of zk-jute use
/// the same list of records.
#[macro_export]
macro_rules! for_each_record {
    ($m:ident) => {
        $m!(data, ACL);
        $m!(data, ClientInfo);
        $m!(data, Id);
        $m!(data, Stat);
        $m!(data, StatPersisted);
        $m!(proto, AddWatchRequest);
        $m!(proto, AuthPacket);
        $m!(proto, CheckVersionRequest);
        $m!(proto, CheckWatchesRequest);
        $m!(proto, ConnectRequest);
        $m!(proto, ConnectResponse);
        $m!(proto, Create2Response);
        $m!(proto, CreateRequest);
        $m!(proto, CreateResponse);
        $m!(proto, CreateTTLRequest);
        $m!(proto, DeleteRequest);
        $m!(proto, ErrorResponse);
        $m!(proto, ExistsRequest);
        $m!(proto, ExistsResponse);
        $m!(proto, GetACLRequest);
        $m!(proto, GetACLResponse);
        $m!(proto, GetAllChildrenNumberRequest);
        $m!(proto, GetAllChildrenNumberResponse);
        $m!(proto, GetChildren2Request);
        $m!(proto, GetChildren2Response);
        $m!(proto, GetChildrenRequest);
        $m!(proto, GetChildrenResponse);
        $m!(proto, GetDataRequest);
        $m!(proto, GetDataResponse);
        $m!(proto, GetEphemeralsRequest);
        $m!(proto, GetEphemeralsResponse);
        $m!(proto, GetMaxChildrenRequest);
        $m!(proto, GetMaxChildrenResponse);
        $m!(proto, GetSASLRequest);
        $m!(proto, MultiHeader);
        $m!(proto, ReconfigRequest);
        $m!(proto, RemoveWatchesRequest);
        $m!(proto, ReplyHeader);
        $m!(proto, RequestHeader);
        $m!(proto, SetACLRequest);
        $m!(proto, SetACLResponse);
        $m!(proto, SetDataRequest);
        $m!(proto, SetDataResponse);
        $m!(proto, SetMaxChildrenRequest);
        $m!(proto, SetSASLRequest);
        $m!(proto, SetSASLResponse);
        $m!(proto, SetWatches);
        $m!(proto, SetWatches2);
        $m!(proto, SyncRequest);
        $m!(proto, SyncResponse);
        $m!(proto, WatcherEvent);
        $m!(proto, WhoAmIResponse);
    };
}

/// Reads values from a fuzz input.
///
/// A read past the end gives zero bytes, so every input is a complete
/// program. [`Cursor::is_empty`] tells the caller when to stop.
#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// Makes a cursor over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Tells whether the input is used up.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Gives the bytes that are not read yet, and uses them up.
    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.data)
    }

    /// Reads up to `n` bytes. The result is short at the end of the input.
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.data.len());
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        head
    }

    /// Reads a fixed array. Missing bytes are zero.
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let got = self.bytes(N);
        out[..got.len()].copy_from_slice(got);
        out
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    /// Reads a big-endian `u16`.
    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    /// Reads a big-endian `u32`.
    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    /// Reads a big-endian `i32`.
    pub fn i32(&mut self) -> i32 {
        i32::from_be_bytes(self.array())
    }

    /// Reads a big-endian `i64`.
    pub fn i64(&mut self) -> i64 {
        i64::from_be_bytes(self.array())
    }

    /// Reads one byte as a flag.
    pub fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    /// Reads a `u16` length and then that many bytes.
    pub fn lp(&mut self) -> &'a [u8] {
        let n = usize::from(self.u16());
        self.bytes(n)
    }
}

/// Writes values in the format that [`Cursor`] reads.
#[derive(Clone, Debug, Default)]
pub struct Enc {
    /// The bytes so far.
    pub out: Vec<u8>,
}

impl Enc {
    /// Makes an empty encoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes one byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.out.push(v);
        self
    }

    /// Writes a big-endian `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.out.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Writes a big-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.out.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Writes a big-endian `i32`.
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.out.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Writes a big-endian `i64`.
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.out.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Writes raw bytes.
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.out.extend_from_slice(b);
        self
    }

    /// Writes a `u16` length and the bytes. Bytes past `u16::MAX` are cut.
    pub fn lp(&mut self, b: &[u8]) -> &mut Self {
        let b = &b[..b.len().min(usize::from(u16::MAX))];
        self.u16(u16::try_from(b.len()).unwrap_or(u16::MAX));
        self.raw(b)
    }

    /// Gives the bytes.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }
}

/// Puts a 4-byte big-endian length in front of `body`.
pub fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    zk_jute::encode_frame(body, &mut out);
    out
}
