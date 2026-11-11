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

//! Path validation: the legacy C rule (`isValidPath`) and the strict Java rule
//! (`PathUtils.validatePath`) that the native client uses.

use std::fmt;

/// The C create mode `ZOO_PERSISTENT_SEQUENTIAL`.
pub const PERSISTENT_SEQUENTIAL: i32 = 2;
/// The C create mode `ZOO_EPHEMERAL_SEQUENTIAL`.
pub const EPHEMERAL_SEQUENTIAL: i32 = 3;
/// The C create mode `ZOO_PERSISTENT_WITH_TTL`.
pub const PERSISTENT_WITH_TTL: i32 = 5;
/// The C create mode `ZOO_PERSISTENT_SEQUENTIAL_WITH_TTL`.
pub const PERSISTENT_SEQUENTIAL_WITH_TTL: i32 = 6;

/// Returns true for the sequential create modes (`ZOOKEEPER_IS_SEQUENCE`).
///
/// C tests the mode for equality with 2, 3 and 6. It does not test a bit.
pub fn is_sequence(mode: i32) -> bool {
    matches!(
        mode,
        PERSISTENT_SEQUENTIAL | EPHEMERAL_SEQUENTIAL | PERSISTENT_SEQUENTIAL_WITH_TTL
    )
}

/// Returns true for the TTL create modes (`ZOOKEEPER_IS_TTL`).
pub fn is_ttl(mode: i32) -> bool {
    matches!(mode, PERSISTENT_WITH_TTL | PERSISTENT_SEQUENTIAL_WITH_TTL)
}

/// The legacy path check (`isValidPath` in `zookeeper.c`).
///
/// The input is the bytes of the C string, without the terminating NUL. A
/// NUL byte in the input makes the path invalid, so that the check never
/// accepts bytes that differ from the bytes that the caller sends. See the
/// NUL rules in [`crate::legacy`]. The rule is:
///
/// - The path is not empty and starts with `/`.
/// - A trailing `/` is valid only for a sequential mode.
/// - No empty component (`//`).
/// - No `.` or `..` component. A final `.` or `..` is valid for a sequential
///   mode.
/// - No byte in 0x01 to 0x1E. The bytes 0x1F, 0x7F and 0x80 to 0xFF are
///   valid, for both signed and unsigned C `char`.
pub fn is_valid_path(path: &[u8], mode: i32) -> bool {
    let seq = is_sequence(mode);
    let len = path.len();
    // C reads the terminating NUL as 0 past the end.
    let at = |i: Option<usize>| i.and_then(|i| path.get(i)).copied().unwrap_or(0);
    if path.first() != Some(&b'/') {
        return false;
    }
    if len == 1 {
        return true;
    }
    if path.last() == Some(&b'/') && !seq {
        return false;
    }
    let mut last = b'/';
    for (i, &c) in path.iter().enumerate().skip(1) {
        let at_end = i.checked_add(1) == Some(len);
        let next_is_slash = at(i.checked_add(1)) == b'/';
        if c == 0 || (c == b'/' && last == b'/') {
            return false;
        } else if c == b'.' && last == b'.' {
            if at(i.checked_sub(2)) == b'/' && ((at_end && !seq) || next_is_slash) {
                return false;
            }
        } else if c == b'.' {
            if at(i.checked_sub(1)) == b'/' && ((at_end && !seq) || next_is_slash) {
                return false;
            }
        } else if (0x01..0x1f).contains(&c) {
            return false;
        }
        last = c;
    }
    true
}

/// The kind of a strict path error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathErrorKind {
    /// The path is empty.
    Empty,
    /// The path does not start with `/`.
    NotAbsolute,
    /// The path ends with `/`.
    TrailingSlash,
    /// The path holds a NUL character.
    NulCharacter,
    /// The path holds an empty component.
    EmptyComponent,
    /// The path holds a `.` or `..` component.
    RelativeComponent,
    /// The path holds a character that the rule does not permit.
    InvalidCharacter,
}

/// A strict path error, with the messages of the Java client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathError {
    /// The kind of the error.
    pub kind: PathErrorKind,
    /// The UTF-16 index of the bad character, as Java reports it.
    pub index: Option<usize>,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i = self.index.unwrap_or(0);
        match self.kind {
            PathErrorKind::Empty => f.write_str("Path length must be > 0"),
            PathErrorKind::NotAbsolute => f.write_str("Path must start with / character"),
            PathErrorKind::TrailingSlash => f.write_str("Path must not end with / character"),
            PathErrorKind::NulCharacter => write!(f, "null character not allowed @{i}"),
            PathErrorKind::EmptyComponent => write!(f, "empty node name specified @{i}"),
            PathErrorKind::RelativeComponent => write!(f, "relative paths not allowed @{i}"),
            PathErrorKind::InvalidCharacter => write!(f, "invalid character @{i}"),
        }
    }
}

impl std::error::Error for PathError {}

/// Returns true for the UTF-16 code units that Java rejects in a path.
fn java_invalid_unit(c: u16) -> bool {
    (0x0001..=0x001f).contains(&c)
        || (0x007f..=0x009f).contains(&c)
        || (0xd800..=0xf8ff).contains(&c)
        || c >= 0xfff0
}

/// The UTF-16 code unit of `/`.
const SLASH: u16 = 0x002f;
/// The UTF-16 code unit of `.`.
const DOT: u16 = 0x002e;

/// Checks one UTF-16 unit that follows the first unit of a path.
///
/// It gives the error kind, or `None` for a valid unit. `before` and `last`
/// are the two units in front of `c`. `next` is the unit after `c`. The
/// first unit is always `/`, so `last` always has a value.
fn strict_unit_error(
    c: u16,
    before: Option<u16>,
    last: u16,
    next: Option<u16>,
) -> Option<PathErrorKind> {
    let ends_component = matches!(next, None | Some(SLASH));
    if c == 0 {
        Some(PathErrorKind::NulCharacter)
    } else if c == SLASH && last == SLASH {
        Some(PathErrorKind::EmptyComponent)
    } else if c == DOT && last == DOT {
        (before == Some(SLASH) && ends_component).then_some(PathErrorKind::RelativeComponent)
    } else if c == DOT {
        (last == SLASH && ends_component).then_some(PathErrorKind::RelativeComponent)
    } else if java_invalid_unit(c) {
        Some(PathErrorKind::InvalidCharacter)
    } else {
        None
    }
}

/// The strict path check of the Java client (`PathUtils.validatePath`).
///
/// For a sequential create the check applies to `path + "1"`, as in Java, so
/// a trailing `/` is valid there. Java checks UTF-16 code units, so each
/// character above U+FFFF is invalid, because its surrogates are in the
/// rejected range. Private use characters U+E000 to U+F8FF are also invalid.
pub fn validate_path_strict(path: &str, sequential: bool) -> Result<(), PathError> {
    // The check reads the UTF-16 units as a stream, with one unit of look
    // ahead. Thus it makes no allocation.
    let tail = sequential.then_some(u16::from(b'1'));
    let mut units = path.encode_utf16().chain(tail).peekable();
    let err = |kind, index| Err(PathError { kind, index });
    match units.next() {
        None => return err(PathErrorKind::Empty, None),
        Some(SLASH) => {}
        Some(_) => return err(PathErrorKind::NotAbsolute, None),
    }
    if units.peek().is_none() {
        return Ok(());
    }
    // A sequential path ends with the unit `1`. Otherwise the last unit is
    // `/` only when the last byte is `/`.
    if !sequential && path.ends_with('/') {
        return err(PathErrorKind::TrailingSlash, None);
    }
    let mut before = None;
    let mut last = SLASH;
    let mut i: usize = 1;
    while let Some(c) = units.next() {
        if let Some(kind) = strict_unit_error(c, before, last, units.peek().copied()) {
            return err(kind, Some(i));
        }
        before = Some(last);
        last = c;
        i = i.saturating_add(1);
    }
    Ok(())
}
