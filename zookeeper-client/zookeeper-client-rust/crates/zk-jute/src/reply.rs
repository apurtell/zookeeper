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

//! Access to the reply header at the start of every reply frame.

use crate::proto::ReplyHeader;
use crate::{DecodeError, Reader, Record};

/// The size of an encoded `ReplyHeader`: xid, zxid and err.
pub const REPLY_HEADER_LEN: usize = 16;

impl ReplyHeader {
    /// Decodes the reply header at the start of a frame body and returns it
    /// with the bytes that follow it.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when the frame has fewer than 16
    /// bytes. The core tears down the connection in that case.
    pub fn peek(frame: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let mut r = Reader::new(frame);
        let header = Self::decode(&mut r)?;
        Ok((header, r.rest()))
    }
}
