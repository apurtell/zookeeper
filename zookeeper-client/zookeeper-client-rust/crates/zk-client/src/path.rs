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

//! Validated ZooKeeper paths.
//!
//! The module wraps `zk_proto::native::validate_path_strict`.
//! It also holds the const validator and the component helpers.
//!
//! `ZPath` is a sized, `Copy`, borrowed wrapper. An unsized `ZPath(str)`
//! needs a pointer cast, and `#![forbid(unsafe_code)]` does not allow it.

use zk_proto::native::{PathErrorKind, validate_path_strict};

use crate::error::Error;

/// A valid absolute ZooKeeper path, borrowed from a string.
///
/// Invariant: the text passes the Java `PathUtils.validatePath` rules for
/// a non-sequential path.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZPath<'a>(&'a str);

/// An owned valid path. It has the invariant of [`ZPath`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZPathBuf(String);

/// Why a path is not valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathError {
    /// The path as given.
    pub path: String,
    /// The byte offset of the fault in `path`. It is 0 for an empty path
    /// or a path without a leading `/`.
    pub index: usize,
    /// The rule that the path breaks.
    pub reason: PathErrorReason,
}

/// The rule that a path breaks.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathErrorReason {
    /// The path is empty.
    Empty,
    /// The path does not start with `/`.
    NotAbsolute,
    /// The path has `//`.
    EmptyComponent,
    /// The path ends with `/` and is not the root.
    TrailingSlash,
    /// The path has a `.` or `..` component.
    RelativeComponent,
    /// The path has a character that Java rejects. U+0000 is here too.
    InvalidChar(char),
}

impl std::fmt::Display for PathErrorReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("path length must be > 0"),
            Self::NotAbsolute => f.write_str("path must start with / character"),
            Self::EmptyComponent => f.write_str("empty node name specified"),
            Self::TrailingSlash => f.write_str("path must not end with / character"),
            Self::RelativeComponent => f.write_str("relative paths not allowed"),
            Self::InvalidChar(c) => write!(f, "invalid character {:?}", c),
        }
    }
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid path string {:?} caused by {} @{}",
            self.path, self.reason, self.index
        )
    }
}

impl std::error::Error for PathError {}

/// Returns the byte offset of UTF-16 unit `utf16` in `s`, or `s.len()`.
fn byte_offset(s: &str, utf16: usize) -> usize {
    let mut units = 0usize;
    for (at, c) in s.char_indices() {
        if units >= utf16 {
            return at;
        }
        units = units.saturating_add(c.len_utf16());
    }
    s.len()
}

/// Converts a proto path error to the public form.
fn convert(path: &str, e: &zk_proto::native::PathError) -> PathError {
    let index = e.index.map_or(0, |i| byte_offset(path, i));
    let reason = match e.kind {
        PathErrorKind::Empty => PathErrorReason::Empty,
        PathErrorKind::NotAbsolute => PathErrorReason::NotAbsolute,
        PathErrorKind::TrailingSlash => PathErrorReason::TrailingSlash,
        PathErrorKind::NulCharacter => PathErrorReason::InvalidChar('\0'),
        PathErrorKind::EmptyComponent => PathErrorReason::EmptyComponent,
        PathErrorKind::RelativeComponent => PathErrorReason::RelativeComponent,
        PathErrorKind::InvalidCharacter => PathErrorReason::InvalidChar(
            path.get(index..)
                .and_then(|rest| rest.chars().next())
                .unwrap_or(char::REPLACEMENT_CHARACTER),
        ),
    };
    let index = match e.kind {
        PathErrorKind::TrailingSlash => path.len().saturating_sub(1),
        _ => index,
    };
    PathError {
        path: path.to_owned(),
        index,
        reason,
    }
}

/// Checks `path` by the strict Java rules. `sequential` checks
/// `path + "1"`, so `/jobs/` is a valid sequential prefix.
pub(crate) fn check(path: &str, sequential: bool) -> Result<(), PathError> {
    validate_path_strict(path, sequential).map_err(|e| convert(path, &e))
}

/// The const form of the strict check, for [`ZPath::from_static`].
///
/// Contract: the same verdict as `validate_path_strict(s, false)`, over
/// bytes with a manual UTF-8 decode, because a const fn cannot call the
/// proto check. A unit test compares the two checks over a proptest
/// corpus.
///
/// The check works on whole components. The Java check works on UTF-16
/// units, but both give the same verdict: a component must not be empty,
/// `.` or `..`, and every character must be valid.
const fn check_static(s: &str) -> bool {
    let mut rest = match s.as_bytes() {
        [b'/', tail @ ..] => tail,
        _ => return false,
    };
    if rest.is_empty() {
        return true;
    }
    // The number of characters in the current component, and whether
    // each one is a dot.
    let mut len = 0usize;
    let mut dots = true;
    while let Some((c, tail)) = decode_utf8(rest) {
        rest = tail;
        if c == 0x2f {
            if !component_ok(len, dots) {
                return false;
            }
            len = 0;
            dots = true;
        } else {
            if java_invalid_char(c) {
                return false;
            }
            len = len.saturating_add(1);
            dots = dots && c == 0x2e;
        }
    }
    // A decode failure stops the loop with bytes left. A `&str` always
    // holds valid UTF-8, so this case does not occur.
    rest.is_empty() && component_ok(len, dots)
}

/// True for a component that is not empty, `.` or `..`.
const fn component_ok(len: usize, dots: bool) -> bool {
    len != 0 && !(dots && len <= 2)
}

/// True for the characters that the Java check rejects: U+0000 to
/// U+001F, U+007F to U+009F, U+D800 to U+F8FF, U+FFF0 to U+FFFF, and
/// every character above U+FFFF, because Java sees its surrogates.
// `RangeInclusive::contains` is not a const fn.
#[allow(clippy::manual_range_contains)]
const fn java_invalid_char(c: u32) -> bool {
    c <= 0x1f || (c >= 0x7f && c <= 0x9f) || (c >= 0xd800 && c <= 0xf8ff) || c >= 0xfff0
}

/// Decodes the first character of `b`. It gives the code point and the
/// bytes after it, or `None` for an empty or malformed input.
const fn decode_utf8(b: &[u8]) -> Option<(u32, &[u8])> {
    match b {
        [b0, tail @ ..] if *b0 < 0x80 => Some((widen(*b0), tail)),
        [b0, b1, tail @ ..] if *b0 >= 0xc0 && *b0 < 0xe0 && is_cont(*b1) => {
            Some((bits(*b0, 0x1f, 6) | bits(*b1, 0x3f, 0), tail))
        }
        [b0, b1, b2, tail @ ..] if *b0 >= 0xe0 && *b0 < 0xf0 && is_cont(*b1) && is_cont(*b2) => {
            Some((
                bits(*b0, 0x0f, 12) | bits(*b1, 0x3f, 6) | bits(*b2, 0x3f, 0),
                tail,
            ))
        }
        [b0, b1, b2, b3, tail @ ..]
            if *b0 >= 0xf0 && *b0 < 0xf8 && is_cont(*b1) && is_cont(*b2) && is_cont(*b3) =>
        {
            Some((
                bits(*b0, 0x07, 18) | bits(*b1, 0x3f, 12) | bits(*b2, 0x3f, 6) | bits(*b3, 0x3f, 0),
                tail,
            ))
        }
        _ => None,
    }
}

/// True for a UTF-8 continuation byte.
const fn is_cont(b: u8) -> bool {
    b & 0xc0 == 0x80
}

/// Widens a byte to `u32` in a const context, with no `as` cast.
const fn widen(b: u8) -> u32 {
    u32::from_le_bytes([b, 0, 0, 0])
}

/// Masks a byte and moves the bits to their place in the code point.
const fn bits(b: u8, mask: u8, shift: u32) -> u32 {
    widen(b & mask).wrapping_shl(shift)
}

impl<'a> ZPath<'a> {
    /// The root path `/`.
    pub const ROOT: ZPath<'static> = ZPath("/");

    /// Validates `s`.
    ///
    /// # Errors
    ///
    /// The [`PathError`] of the first rule that `s` breaks.
    pub fn new(s: &'a str) -> Result<ZPath<'a>, PathError> {
        check(s, false)?;
        Ok(ZPath(s))
    }

    /// Validates a literal with a const fn.
    ///
    /// It gives `None` for a bad literal and never panics. Use
    /// [`ZPath::new`] to get the [`PathError`] with its reason.
    ///
    /// In a `const` item, `.unwrap()` on the result turns a bad literal
    /// into a compile error. The check then costs nothing at run time.
    ///
    /// ```
    /// use apache_zookeeper::ZPath;
    /// const LOCKS: ZPath<'static> = ZPath::from_static("/app/locks").unwrap();
    /// assert_eq!(LOCKS.name(), Some("locks"));
    /// assert!(ZPath::from_static("/app/").is_none());
    /// ```
    ///
    /// A bad literal in a `const` item does not compile:
    ///
    /// ```compile_fail
    /// use apache_zookeeper::ZPath;
    /// const BAD: ZPath<'static> = ZPath::from_static("/app/").unwrap();
    /// assert_eq!(BAD.as_str(), "/app/");
    /// ```
    #[must_use]
    pub const fn from_static(s: &'static str) -> Option<ZPath<'static>> {
        if check_static(s) {
            Some(ZPath(s))
        } else {
            None
        }
    }

    /// Wraps text that is already valid. Only crate code that checked
    /// the text calls it.
    pub(crate) const fn new_unchecked(s: &'a str) -> ZPath<'a> {
        ZPath(s)
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Returns the parent path, or `None` for the root.
    #[must_use]
    pub fn parent(self) -> Option<ZPath<'a>> {
        if self.is_root() {
            return None;
        }
        match self.0.rfind('/') {
            Some(0) => Some(ZPath::ROOT),
            Some(at) => self.0.get(..at).map(ZPath),
            None => None,
        }
    }

    /// Returns the last component, or `None` for the root.
    #[must_use]
    pub fn name(self) -> Option<&'a str> {
        if self.is_root() {
            return None;
        }
        self.0.rsplit('/').next()
    }

    /// Returns the components in order. The root has none.
    #[must_use]
    pub fn components(self) -> Components<'a> {
        Components { rest: self.0 }
    }

    /// Appends one or more components. `child` has no leading `/`, for
    /// example `"a"` or `"a/b"`.
    ///
    /// # Errors
    ///
    /// The [`PathError`] of the joined path.
    pub fn join(self, child: &str) -> Result<ZPathBuf, PathError> {
        let mut joined =
            String::with_capacity(self.0.len().saturating_add(child.len()).saturating_add(1));
        joined.push_str(self.0);
        if !self.is_root() {
            joined.push('/');
        }
        joined.push_str(child);
        if child.is_empty() {
            // The root and an empty child give `/`, which is valid. The
            // join still adds no component, so it is an error.
            let index = joined.len().saturating_sub(1);
            return Err(PathError {
                path: joined,
                index,
                reason: PathErrorReason::EmptyComponent,
            });
        }
        ZPathBuf::new(joined)
    }

    /// True when `base` is this path or one of its ancestors, compared
    /// component by component. `/app` is not a base of `/app2`.
    #[must_use]
    pub fn starts_with(self, base: ZPath<'_>) -> bool {
        if base.is_root() {
            return true;
        }
        match self.0.strip_prefix(base.0) {
            Some(rest) => rest.is_empty() || rest.starts_with('/'),
            None => false,
        }
    }

    /// True for `/`.
    #[must_use]
    pub fn is_root(self) -> bool {
        self.0 == "/"
    }

    /// Returns an owned copy.
    #[must_use]
    pub fn to_buf(self) -> ZPathBuf {
        ZPathBuf(self.0.to_owned())
    }
}

/// The components of a [`ZPath`], from the root down.
#[derive(Clone, Debug)]
pub struct Components<'a> {
    /// The text that is left, with its leading `/`.
    rest: &'a str,
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a str;

    /// Returns the next component. The root path gives none.
    fn next(&mut self) -> Option<&'a str> {
        let body = self.rest.strip_prefix('/')?;
        if body.is_empty() {
            self.rest = body;
            return None;
        }
        match body.find('/').and_then(|at| body.split_at_checked(at)) {
            Some((name, rest)) => {
                self.rest = rest;
                Some(name)
            }
            None => {
                self.rest = "";
                Some(body)
            }
        }
    }
}

impl ZPathBuf {
    /// Validates `s`.
    ///
    /// # Errors
    ///
    /// The [`PathError`] of the first rule that `s` breaks.
    pub fn new(s: String) -> Result<ZPathBuf, PathError> {
        check(&s, false)?;
        Ok(ZPathBuf(s))
    }

    /// Wraps a path that the server sent. It checks UTF-8 only: the server
    /// writes Java strings, and zk-proto already stripped the chroot.
    ///
    /// # Errors
    ///
    /// `Error::MarshallingError` for bytes that are not UTF-8.
    pub(crate) fn from_server(bytes: Vec<u8>) -> Result<ZPathBuf, Error> {
        String::from_utf8(bytes)
            .map(ZPathBuf)
            .map_err(|_| Error::MarshallingError)
    }

    /// Borrows the path.
    #[must_use]
    pub fn as_path(&self) -> ZPath<'_> {
        ZPath(&self.0)
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the inner string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for ZPathBuf {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ZPathBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for ZPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl PartialEq<str> for ZPathBuf {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for ZPathBuf {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

mod sealed {
    use super::PathError;

    /// Seals [`super::PathArg`]. Crate code uses `checked` for the
    /// sequential rule.
    pub trait Sealed {
        /// Returns the text after the strict check. `sequential` applies
        /// the rule to `path + "1"`. A `ZPath` or `ZPathBuf` skips the
        /// check, because its invariant implies both verdicts.
        fn checked(&self, sequential: bool) -> Result<&str, PathError>;
    }
}

/// A path argument (sealed). It is implemented for `&str`, `String`,
/// `&String`, `ZPath<'_>`, `ZPathBuf` and `&ZPathBuf`.
///
/// Text arguments are checked at submit. A bad path gives a ready
/// `Err(Error::InvalidPath(..))`, and nothing goes to the server.
pub trait PathArg: sealed::Sealed {
    /// Returns the validated path.
    ///
    /// # Errors
    ///
    /// The [`PathError`] of a text argument that is not valid.
    fn to_zpath(&self) -> Result<ZPath<'_>, PathError>;
}

/// Returns the checked text of a path argument (crate use only).
pub(crate) fn checked(p: &impl PathArg, sequential: bool) -> Result<&str, PathError> {
    sealed::Sealed::checked(p, sequential)
}

impl sealed::Sealed for &str {
    fn checked(&self, sequential: bool) -> Result<&str, PathError> {
        check(self, sequential).map(|()| *self)
    }
}
impl PathArg for &str {
    fn to_zpath(&self) -> Result<ZPath<'_>, PathError> {
        ZPath::new(self)
    }
}

impl sealed::Sealed for String {
    fn checked(&self, sequential: bool) -> Result<&str, PathError> {
        check(self, sequential).map(|()| self.as_str())
    }
}
impl PathArg for String {
    fn to_zpath(&self) -> Result<ZPath<'_>, PathError> {
        ZPath::new(self)
    }
}

impl sealed::Sealed for &String {
    fn checked(&self, sequential: bool) -> Result<&str, PathError> {
        check(self, sequential).map(|()| self.as_str())
    }
}
impl PathArg for &String {
    fn to_zpath(&self) -> Result<ZPath<'_>, PathError> {
        ZPath::new(self)
    }
}

impl sealed::Sealed for ZPath<'_> {
    fn checked(&self, _sequential: bool) -> Result<&str, PathError> {
        Ok(self.0)
    }
}
impl PathArg for ZPath<'_> {
    fn to_zpath(&self) -> Result<ZPath<'_>, PathError> {
        Ok(*self)
    }
}

impl sealed::Sealed for ZPathBuf {
    fn checked(&self, _sequential: bool) -> Result<&str, PathError> {
        Ok(&self.0)
    }
}
impl PathArg for ZPathBuf {
    fn to_zpath(&self) -> Result<ZPath<'_>, PathError> {
        Ok(self.as_path())
    }
}

impl sealed::Sealed for &ZPathBuf {
    fn checked(&self, _sequential: bool) -> Result<&str, PathError> {
        Ok(&self.0)
    }
}
impl PathArg for &ZPathBuf {
    fn to_zpath(&self) -> Result<ZPath<'_>, PathError> {
        Ok(self.as_path())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn sequential_prefix_may_end_with_slash() {
        assert!(checked(&"/jobs/", true).is_ok());
        assert!(checked(&"/jobs/", false).is_err());
    }

    #[test]
    fn server_paths_check_utf8_only() {
        assert!(ZPathBuf::from_server(b"/a".to_vec()).is_ok());
        assert_eq!(
            ZPathBuf::from_server(vec![0x2f, 0xff]).unwrap_err(),
            Error::MarshallingError
        );
    }

    /// The const check and the proto check give the same verdict.
    fn same_verdict(s: &str) {
        assert_eq!(
            check_static(s),
            validate_path_strict(s, false).is_ok(),
            "verdicts differ for {s:?}"
        );
    }

    #[test]
    fn const_check_matches_proto_on_edge_cases() {
        let cases = [
            "",
            "/",
            "//",
            "a",
            "a/b",
            "/a",
            "/a/",
            "/a//b",
            "/.",
            "/..",
            "/...",
            "/.a",
            "/a.",
            "/..a",
            "/a/.",
            "/a/..",
            "/a/./b",
            "/a/../b",
            "/a/.../b",
            "/a\0",
            "/a\u{0}b",
            "/\u{1}",
            "/\u{1f}",
            "/ ",
            "/~",
            "/\u{7f}",
            "/\u{80}",
            "/\u{9f}",
            "/\u{a0}",
            "/\u{e9}t\u{e9}",
            "/\u{d7ff}",
            "/\u{e000}",
            "/\u{f8ff}",
            "/\u{f900}",
            "/\u{ffef}",
            "/\u{fff0}",
            "/\u{ffff}",
            "/\u{10000}",
            "/\u{10ffff}",
            "/zookeeper/config",
            "/a/b/c/d",
        ];
        for c in cases {
            same_verdict(c);
        }
    }

    #[test]
    fn reserved_range_and_nul() {
        for c in [
            '\0',
            '\u{1}',
            '\u{7f}',
            '\u{9f}',
            '\u{e000}',
            '\u{fff0}',
            '\u{10000}',
        ] {
            let s = format!("/a{c}");
            let e = ZPath::new(&s).unwrap_err();
            assert_eq!(e.index, 2, "{s:?}");
            assert!(!check_static(&s));
        }
        assert!(ZPath::new("/a\u{a0}").is_ok());
        assert!(ZPath::new("/a\u{f900}").is_ok());
    }

    proptest::proptest! {
        #![proptest_config(crate::test_config::proptest())]
        #[test]
        fn const_check_matches_proto(s in "\\PC{0,12}") {
            same_verdict(&s);
        }

        #[test]
        fn const_check_matches_proto_on_path_like_text(
            s in "(/[a.\u{0}\u{1f}\u{7f}\u{9f}\u{e000}\u{fff0}\u{1f600}é/]{0,4}){0,4}"
        ) {
            same_verdict(&s);
            let _ = ZPath::new(&s);
        }

        #[test]
        fn new_never_panics(s in proptest::prelude::any::<String>()) {
            same_verdict(&s);
            if let Ok(p) = ZPath::new(&s) {
                let _ = p.parent();
                let _ = p.name();
                assert_eq!(p.components().count(), s.matches('/').count() - usize::from(p.is_root()));
            }
        }
    }
}
