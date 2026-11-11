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

//! The jute binary encoding: the `Record` trait, the bounded reader and the
//! null-preserving wire types.
//!
//! The encoding is the one of the Java `BinaryOutputArchive` and the C
//! `recordio.c`. Integers are big-endian. A boolean is one byte. A string,
//! a buffer and a vector have a four-byte length prefix, and the length -1
//! means null. The decoders accept the same input as the C decoders and give
//! errors that map to the same C return codes.

use core::fmt;

/// The errno value of `E2BIG` on every supported platform.
const E2BIG: i32 = 7;
/// The errno value of `ENOMEM` on every supported platform.
const ENOMEM: i32 = 12;
/// The errno value of `EINVAL` on every supported platform.
const EINVAL: i32 = 22;

/// A failure to decode a jute value.
///
/// A decoder never reads past its input. Each error matches one failure of
/// the C `ia_deserialize_*` functions, and [`DecodeError::c_rc`] gives the C
/// return code for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeError {
    /// The input ends before the value ends.
    Truncated {
        /// The number of bytes that the value needs at this point.
        need: usize,
        /// The number of bytes that remain in the input.
        have: usize,
    },
    /// A string has a length below -1.
    NegativeString(i32),
    /// A buffer has a length below -1.
    NegativeBuffer(i32),
    /// A vector has an element count below -1.
    NegativeCount(i32),
}

impl DecodeError {
    /// Returns the code that the C `ia_deserialize_*` functions give for the
    /// same input (`recordio.c`).
    ///
    /// A truncated input gives `-E2BIG`. A negative string length gives
    /// `-EINVAL`. A buffer length below -1 gives `-ENOMEM`, because C fails
    /// to allocate the negative size. A vector count below -1 also gives
    /// `-ENOMEM`, but this is a decision of the specification. The generated
    /// C vector decoder ignores element errors and always returns 0. Only a
    /// SASL reply decode error goes back to the caller of
    /// `zookeeper_process`, and a SASL reply carries a buffer, not a vector.
    #[must_use]
    pub const fn c_rc(self) -> i32 {
        match self {
            Self::Truncated { .. } => -E2BIG,
            Self::NegativeString(_) => -EINVAL,
            Self::NegativeBuffer(_) | Self::NegativeCount(_) => -ENOMEM,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated jute input: need {need} bytes, have {have}")
            }
            Self::NegativeString(len) => write!(f, "negative jute string length {len}"),
            Self::NegativeBuffer(len) => write!(f, "negative jute buffer length {len}"),
            Self::NegativeCount(count) => write!(f, "negative jute vector count {count}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A cursor over a byte slice for jute decoding.
///
/// The reader never reads past its slice. It does not require that the
/// decoder uses all bytes: a caller can decode a prefix and ignore the rest.
/// The C client relies on this, for example when it decodes a
/// `Create2Response` as a `CreateResponse`.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader at the start of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the number of bytes that the reader has consumed.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Returns the number of bytes that remain.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns true when no bytes remain.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the bytes that remain, without consuming them.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }

    /// Consumes and returns the next `n` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when fewer than `n` bytes remain.
    /// The reader does not move on error.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let have = self.remaining();
        let bytes = self
            .pos
            .checked_add(n)
            .and_then(|end| self.buf.get(self.pos..end))
            .ok_or(DecodeError::Truncated { need: n, have })?;
        self.pos = self.pos.saturating_add(n);
        Ok(bytes)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let have = self.remaining();
        let bytes = self.read_bytes(N)?;
        <[u8; N]>::try_from(bytes).map_err(|_| DecodeError::Truncated { need: N, have })
    }

    /// Consumes one byte.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] at the end of the input.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let [b] = self.read_array::<1>()?;
        Ok(b)
    }

    /// Consumes a big-endian 32-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when fewer than four bytes remain.
    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        self.read_array::<4>().map(i32::from_be_bytes)
    }

    /// Consumes a big-endian 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when fewer than eight bytes remain.
    pub fn read_i64(&mut self) -> Result<i64, DecodeError> {
        self.read_array::<8>().map(i64::from_be_bytes)
    }

    /// Consumes a one-byte boolean. Any byte other than zero is true, as in
    /// the C decoder.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] at the end of the input.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        self.read_u8().map(|b| b != 0)
    }

    /// Consumes a length prefix and the bytes that follow it. The result is
    /// `None` for the null length -1. The caller maps a length below -1 to
    /// its own error.
    fn read_len_prefixed(
        &mut self,
        negative: fn(i32) -> DecodeError,
    ) -> Result<Option<&'a [u8]>, DecodeError> {
        let len = self.read_i32()?;
        if len == -1 {
            return Ok(None);
        }
        // C checks the remaining size before the sign, so a long length is
        // a truncation and only then a negative length is an error.
        match usize::try_from(len) {
            Ok(n) => self.read_bytes(n).map(Some),
            Err(_) => Err(negative(len)),
        }
    }
}

/// A value with a jute binary encoding.
///
/// The generated records implement this trait. The primitive field types
/// (`i32`, `i64`, `bool`) and the wrapper types ([`JString`], [`JBuffer`],
/// [`JVec`]) implement it too, so the generated code treats every field the
/// same way.
pub trait Record: Sized {
    /// The smallest number of bytes that an encoded value occupies. The
    /// vector decoder uses it to limit the capacity that it reserves before
    /// the elements arrive.
    const MIN_ENCODED_LEN: usize = 0;

    /// Appends the encoding of the value to `out`.
    ///
    /// Encoding cannot fail. A string, buffer or vector that has more than
    /// `i32::MAX` elements is cut to `i32::MAX` elements, so the output stays
    /// well-formed.
    fn encode(&self, out: &mut Vec<u8>);

    /// Decodes a value from the reader.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] when the input is not a valid encoding.
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    /// Returns the exact number of bytes that [`Record::encode`] appends.
    fn encoded_len(&self) -> usize;

    /// Returns the encoding of the value in a new vector of exact size.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out);
        out
    }

    /// Decodes a value from the start of `buf` and ignores trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] when the input is not a valid encoding.
    fn from_bytes(buf: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(&mut Reader::new(buf))
    }
}

impl Record for i32 {
    const MIN_ENCODED_LEN: usize = 4;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.read_i32()
    }

    fn encoded_len(&self) -> usize {
        4
    }
}

impl Record for i64 {
    const MIN_ENCODED_LEN: usize = 8;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.read_i64()
    }

    fn encoded_len(&self) -> usize {
        8
    }
}

impl Record for bool {
    const MIN_ENCODED_LEN: usize = 1;

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.read_bool()
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

/// The largest element count that the wire can carry.
const MAX_WIRE_LEN: usize = i32::MAX as usize;

/// Returns the element count that goes on the wire for `len` elements.
fn wire_len(len: usize) -> (i32, usize) {
    let n = len.min(MAX_WIRE_LEN);
    (i32::try_from(n).unwrap_or(i32::MAX), n)
}

/// Writes a length prefix and the bytes, or -1 for null.
fn encode_bytes(bytes: Option<&[u8]>, out: &mut Vec<u8>) {
    match bytes {
        None => out.extend_from_slice(&(-1i32).to_be_bytes()),
        Some(b) => {
            let (len, n) = wire_len(b.len());
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(b.get(..n).unwrap_or(b));
        }
    }
}

fn bytes_encoded_len(bytes: Option<&[u8]>) -> usize {
    bytes.map_or(4, |b| wire_len(b.len()).1.saturating_add(4))
}

/// Defines a null-preserving byte wrapper type and its trait impls.
macro_rules! byte_wrapper {
    ($(#[$doc:meta])* $name:ident, $negative:path) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub enum $name {
            /// The null value. It has the wire length -1.
            #[default]
            Null,
            /// A present value. It can be empty.
            Bytes(Vec<u8>),
        }

        impl $name {
            /// Returns true for the null value.
            #[must_use]
            pub const fn is_null(&self) -> bool {
                matches!(self, Self::Null)
            }

            /// Returns the bytes, or `None` for the null value.
            #[must_use]
            pub fn as_bytes(&self) -> Option<&[u8]> {
                match self {
                    Self::Null => None,
                    Self::Bytes(b) => Some(b),
                }
            }

            /// Returns the bytes, or `None` for the null value.
            #[must_use]
            pub fn into_bytes(self) -> Option<Vec<u8>> {
                match self {
                    Self::Null => None,
                    Self::Bytes(b) => Some(b),
                }
            }

            /// Returns the number of bytes. The null value has none.
            #[must_use]
            pub fn len(&self) -> usize {
                self.as_bytes().map_or(0, <[u8]>::len)
            }

            /// Returns true when the value is null or has no bytes.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(b: Vec<u8>) -> Self {
                Self::Bytes(b)
            }
        }

        impl From<&[u8]> for $name {
            fn from(b: &[u8]) -> Self {
                Self::Bytes(b.to_vec())
            }
        }

        impl From<Option<Vec<u8>>> for $name {
            fn from(b: Option<Vec<u8>>) -> Self {
                b.map_or(Self::Null, Self::Bytes)
            }
        }

        impl Record for $name {
            const MIN_ENCODED_LEN: usize = 4;

            fn encode(&self, out: &mut Vec<u8>) {
                encode_bytes(self.as_bytes(), out);
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                Ok(r.read_len_prefixed($negative)?
                    .map_or(Self::Null, |b| Self::Bytes(b.to_vec())))
            }

            fn encoded_len(&self) -> usize {
                bytes_encoded_len(self.as_bytes())
            }
        }
    };
}

byte_wrapper!(
    /// A jute `ustring`: a length-prefixed byte string that can be null.
    ///
    /// The decoder does not check UTF-8, as the C client does not. A length
    /// of -1 is [`JString::Null`]. The C decoder rejects -1 with `-EINVAL`
    /// but a server never sends it in a field that the client reads.
    JString,
    DecodeError::NegativeString
);

byte_wrapper!(
    /// A jute `buffer`: length-prefixed bytes that can be null.
    JBuffer,
    DecodeError::NegativeBuffer
);

impl JString {
    /// Returns the text, or `None` for the null value or for bytes that are
    /// not valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| core::str::from_utf8(b).ok())
    }
}

impl From<&str> for JString {
    fn from(s: &str) -> Self {
        Self::Bytes(s.as_bytes().to_vec())
    }
}

impl From<String> for JString {
    fn from(s: String) -> Self {
        Self::Bytes(s.into_bytes())
    }
}

impl From<Option<&str>> for JString {
    fn from(s: Option<&str>) -> Self {
        s.map_or(Self::Null, Self::from)
    }
}

/// A jute `vector<T>`: a counted sequence that can be null.
///
/// A count of -1 is [`JVec::Null`], which stays distinct from an empty
/// vector. The C shim gives it to applications as `data == NULL` and
/// `count == -1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum JVec<T> {
    /// The null vector. It has the wire count -1.
    #[default]
    Null,
    /// A present vector. It can be empty.
    Items(Vec<T>),
}

impl<T> JVec<T> {
    /// Returns true for the null vector.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns the elements, or `None` for the null vector.
    #[must_use]
    pub fn as_slice(&self) -> Option<&[T]> {
        match self {
            Self::Null => None,
            Self::Items(v) => Some(v),
        }
    }

    /// Returns the elements, or `None` for the null vector.
    #[must_use]
    pub fn into_vec(self) -> Option<Vec<T>> {
        match self {
            Self::Null => None,
            Self::Items(v) => Some(v),
        }
    }

    /// Returns the number of elements. The null vector has none.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().map_or(0, <[T]>::len)
    }

    /// Returns true when the vector is null or has no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the elements. The null vector has none.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().unwrap_or_default().iter()
    }
}

impl<T> From<Vec<T>> for JVec<T> {
    fn from(v: Vec<T>) -> Self {
        Self::Items(v)
    }
}

impl<T> From<Option<Vec<T>>> for JVec<T> {
    fn from(v: Option<Vec<T>>) -> Self {
        v.map_or(Self::Null, Self::Items)
    }
}

impl<'a, T> IntoIterator for &'a JVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The largest number of bytes that the vector decoder reserves before the
/// elements arrive. A larger vector grows as its elements arrive.
const PREALLOC_BYTES: usize = 1 << 20;

/// Returns the capacity that the vector decoder reserves for `count`
/// elements when `remaining` input bytes are left.
///
/// The wire count comes from the peer, so it cannot set the reservation
/// alone. The input bytes that remain limit the number of elements that can
/// arrive. A fixed byte budget also limits the reservation, because an
/// element can be much larger in memory than on the wire. This budget keeps
/// the request below `isize::MAX` bytes on 32-bit targets, so the decoder
/// cannot panic.
fn prealloc_len<T: Record>(count: usize, remaining: usize) -> usize {
    let fit = remaining
        .checked_div(T::MIN_ENCODED_LEN.max(1))
        .unwrap_or(0);
    let budget = PREALLOC_BYTES
        .checked_div(core::mem::size_of::<T>().max(1))
        .unwrap_or(0);
    count.min(fit).min(budget)
}

impl<T: Record> Record for JVec<T> {
    const MIN_ENCODED_LEN: usize = 4;

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.extend_from_slice(&(-1i32).to_be_bytes()),
            Self::Items(v) => {
                let (count, n) = wire_len(v.len());
                out.extend_from_slice(&count.to_be_bytes());
                for item in v.iter().take(n) {
                    item.encode(out);
                }
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let count = r.read_i32()?;
        if count == -1 {
            return Ok(Self::Null);
        }
        let n = usize::try_from(count).map_err(|_| DecodeError::NegativeCount(count))?;
        let mut items = Vec::with_capacity(prealloc_len::<T>(n, r.remaining()));
        for _ in 0..n {
            items.push(T::decode(r)?);
        }
        Ok(Self::Items(items))
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Null => 4,
            Self::Items(v) => {
                let (_, n) = wire_len(v.len());
                v.iter()
                    .take(n)
                    .fold(4usize, |acc, item| acc.saturating_add(item.encoded_len()))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn hostile_count_reserves_only_what_the_input_can_fill() {
        // A count of i32::MAX with 5 bytes left fits one string at most.
        let n = usize::try_from(i32::MAX).unwrap();
        assert_eq!(prealloc_len::<JString>(n, 5), 5 / JString::MIN_ENCODED_LEN);
        assert_eq!(prealloc_len::<i64>(n, 7), 0);
        assert_eq!(prealloc_len::<i32>(3, 400), 3);
        let mut bytes = i32::MAX.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 1, b'x']);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_i32().unwrap(), i32::MAX);
        let items: Vec<JString> = Vec::with_capacity(prealloc_len::<JString>(n, r.remaining()));
        assert!(items.capacity() <= 1);
    }

    #[test]
    fn reservation_stays_inside_the_byte_budget() {
        // An element can be much larger in memory than on the wire. A large
        // input must not reserve more than the fixed byte budget.
        let n = usize::try_from(i32::MAX).unwrap();
        for remaining in [usize::MAX, isize::MAX as usize, 1 << 30] {
            let cap = prealloc_len::<JString>(n, remaining);
            assert!(cap * core::mem::size_of::<JString>() <= PREALLOC_BYTES);
            let cap = prealloc_len::<bool>(n, remaining);
            assert!(cap * core::mem::size_of::<bool>() <= PREALLOC_BYTES);
        }
    }
}
