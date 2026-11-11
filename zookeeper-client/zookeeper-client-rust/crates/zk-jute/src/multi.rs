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

//! The multi-transaction stream codec.
//!
//! A multi request is a sequence of operations. A `MultiHeader` comes before
//! each operation, and a terminator header ends the sequence. The response
//! has the same shape. The decoder reads each result by the type in its wire
//! header, not by the type of the request operation. Thus a create2,
//! createTTL or createContainer result, which carries a `Stat`, cannot
//! desynchronize the stream as it does in the C client.

use core::fmt;

use crate::proto::{
    Create2Response, CreateResponse, ErrorResponse, GetChildrenResponse, GetDataResponse,
    MultiHeader, SetDataResponse,
};
use crate::{DecodeError, Reader, Record, opcode};

/// The smallest size of an encoded `MultiHeader`.
const MULTI_HEADER_LEN: usize = 9;

/// The kind of multi request that a response answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MultiKind {
    /// A `multi` transaction (op 14).
    Multi,
    /// A `multiRead` request (op 22). Only the native client sends it.
    MultiRead,
}

/// The body of one multi result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiBody {
    /// Type -1: the operation failed with the code in the body.
    Error(ErrorResponse),
    /// Type 1: a create result with the created path.
    Create(CreateResponse),
    /// Type 15: a create2, createTTL or createContainer result with the
    /// created path and the `Stat`.
    Create2(Create2Response),
    /// Type 5: a setData result with the `Stat`.
    SetData(SetDataResponse),
    /// Types 2 and 13: a delete or check result with no body.
    Empty,
    /// Type 4: a getData result (`multiRead` only).
    GetData(GetDataResponse),
    /// Type 8: a getChildren result (`multiRead` only).
    GetChildren(GetChildrenResponse),
}

/// One result of a multi response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiItem {
    /// The type in the wire header.
    pub wire_type: i32,
    /// The error code in the wire header.
    pub err: i32,
    /// The decoded body.
    pub body: MultiBody,
}

/// A failure to decode a multi response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MultiError {
    /// A header or a body is not valid, or the input ends before the
    /// terminator header.
    Decode(DecodeError),
    /// A result has a type that the response kind does not allow.
    UnexpectedType(i32),
    /// The number of results differs from the number of operations.
    CountMismatch {
        /// The number of operations in the request.
        expected: usize,
        /// The number of results in the response, or the count at which
        /// the decoder stopped.
        got: usize,
    },
}

impl From<DecodeError> for MultiError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl fmt::Display for MultiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "multi response: {e}"),
            Self::UnexpectedType(t) => write!(f, "multi response: unexpected result type {t}"),
            Self::CountMismatch { expected, got } => {
                write!(f, "multi response: {got} results for {expected} operations")
            }
        }
    }
}

impl std::error::Error for MultiError {}

/// Appends the header that comes before one operation of a multi request:
/// the operation type, `done` false and `err` -1.
pub fn encode_op_header(op_type: i32, out: &mut Vec<u8>) {
    MultiHeader {
        r#type: op_type,
        done: false,
        err: -1,
    }
    .encode(out);
}

/// Appends the header that ends a multi request: type -1, `done` true and
/// `err` -1.
pub fn encode_end(out: &mut Vec<u8>) {
    MultiHeader {
        r#type: -1,
        done: true,
        err: -1,
    }
    .encode(out);
}

fn decode_body(
    r: &mut Reader<'_>,
    wire_type: i32,
    kind: MultiKind,
) -> Result<MultiBody, MultiError> {
    let read_only = kind == MultiKind::MultiRead;
    Ok(match wire_type {
        opcode::ERROR => MultiBody::Error(ErrorResponse::decode(r)?),
        opcode::CREATE if !read_only => MultiBody::Create(CreateResponse::decode(r)?),
        opcode::CREATE2 if !read_only => MultiBody::Create2(Create2Response::decode(r)?),
        opcode::SET_DATA if !read_only => MultiBody::SetData(SetDataResponse::decode(r)?),
        opcode::DELETE | opcode::CHECK if !read_only => MultiBody::Empty,
        opcode::GET_DATA if read_only => MultiBody::GetData(GetDataResponse::decode(r)?),
        opcode::GET_CHILDREN if read_only => {
            MultiBody::GetChildren(GetChildrenResponse::decode(r)?)
        }
        other => return Err(MultiError::UnexpectedType(other)),
    })
}

/// Decodes a multi response body that follows the `ReplyHeader`.
///
/// `expected` is the number of operations in the request. A `multi`
/// response accepts the result types -1, 1, 2, 5, 13 and 15. A `multiRead`
/// response accepts the result types -1, 4 and 8. The decoder stops at the
/// terminator header and ignores any bytes after it.
///
/// # Errors
///
/// Returns [`MultiError`] for a header or body that is not valid, for a
/// result type that the kind does not allow, for input that ends before
/// the terminator, and for a result count that differs from `expected`.
pub fn decode_multi(
    r: &mut Reader<'_>,
    expected: usize,
    kind: MultiKind,
) -> Result<Vec<MultiItem>, MultiError> {
    let fit = r.remaining().checked_div(MULTI_HEADER_LEN).unwrap_or(0);
    let mut items = Vec::with_capacity(expected.min(fit));
    loop {
        let header = MultiHeader::decode(r)?;
        if header.done {
            break;
        }
        if items.len() >= expected {
            return Err(MultiError::CountMismatch {
                expected,
                got: items.len().saturating_add(1),
            });
        }
        let body = decode_body(r, header.r#type, kind)?;
        items.push(MultiItem {
            wire_type: header.r#type,
            err: header.err,
            body,
        });
    }
    if items.len() != expected {
        return Err(MultiError::CountMismatch {
            expected,
            got: items.len(),
        });
    }
    Ok(items)
}
