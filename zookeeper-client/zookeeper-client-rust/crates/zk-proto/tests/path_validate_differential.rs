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

//! A differential test of the strict path check. The test compares
//! `validate_path_strict` with a reference copy of the earlier algorithm.
//! The reference collects the UTF-16 units in a vector and reads them by
//! index. The result must be the same for each input: accept or reject,
//! the error kind, the index and the message.

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

use zk_proto::legacy::path::{PathError, PathErrorKind, validate_path_strict};

/// The rejected UTF-16 units of the Java rule.
fn reference_invalid_unit(c: u16) -> bool {
    (0x0001..=0x001f).contains(&c)
        || (0x007f..=0x009f).contains(&c)
        || (0xd800..=0xf8ff).contains(&c)
        || c >= 0xfff0
}

/// The earlier algorithm, kept as the reference. This copy stays the same as
/// the earlier code, so it keeps the earlier complexity. The limit of
/// cyclomatic 15 does not apply here, because this is test code only.
fn reference(path: &str, sequential: bool) -> Result<(), PathError> {
    let mut units: Vec<u16> = path.encode_utf16().collect();
    if sequential {
        units.push(u16::from(b'1'));
    }
    let err = |kind, index| Err(PathError { kind, index });
    let slash = u16::from(b'/');
    let dot = u16::from(b'.');
    let Some(&first) = units.first() else {
        return err(PathErrorKind::Empty, None);
    };
    if first != slash {
        return err(PathErrorKind::NotAbsolute, None);
    }
    let len = units.len();
    if len == 1 {
        return Ok(());
    }
    if units.last() == Some(&slash) {
        return err(PathErrorKind::TrailingSlash, None);
    }
    let at = |i: Option<usize>| i.and_then(|i| units.get(i)).copied();
    let mut last = slash;
    for (i, &c) in units.iter().enumerate().skip(1) {
        let at_end = i.checked_add(1) == Some(len);
        let next_is_slash = at(i.checked_add(1)) == Some(slash);
        if c == 0 {
            return err(PathErrorKind::NulCharacter, Some(i));
        } else if c == slash && last == slash {
            return err(PathErrorKind::EmptyComponent, Some(i));
        } else if c == dot && last == dot {
            if at(i.checked_sub(2)) == Some(slash) && (at_end || next_is_slash) {
                return err(PathErrorKind::RelativeComponent, Some(i));
            }
        } else if c == dot {
            if at(i.checked_sub(1)) == Some(slash) && (at_end || next_is_slash) {
                return err(PathErrorKind::RelativeComponent, Some(i));
            }
        } else if reference_invalid_unit(c) {
            return err(PathErrorKind::InvalidCharacter, Some(i));
        }
        last = c;
    }
    Ok(())
}

/// Compares both checks for one path and both create kinds. It gives the
/// number of compared cases.
fn compare(path: &str) -> usize {
    for sequential in [false, true] {
        let got = validate_path_strict(path, sequential);
        let want = reference(path, sequential);
        assert_eq!(got, want, "path {path:?} sequential {sequential}");
        assert_eq!(
            got.map_err(|e| e.to_string()),
            want.map_err(|e| e.to_string()),
            "message of {path:?} sequential {sequential}"
        );
    }
    2
}

/// Compares all strings over `alphabet` up to `max_len` characters. Each
/// string is also compared with a leading `/`, so most strings reach the
/// per-unit loop.
fn exhaustive(alphabet: &[char], max_len: u32) -> usize {
    let mut cases = 0;
    let mut s = String::new();
    for len in 0..=max_len {
        let total = alphabet.len().pow(len);
        for mut n in 0..total {
            s.clear();
            for _ in 0..len {
                s.push(alphabet[n % alphabet.len()]);
                n /= alphabet.len();
            }
            cases += compare(&s);
            s.insert(0, '/');
            cases += compare(&s);
        }
    }
    cases
}

/// The edge characters of each rule, and plain characters.
const WIDE: &[char] = &[
    '/',
    '.',
    'a',
    '1',
    '\0',
    '\u{1}',
    '\u{1f}',
    '\u{20}',
    '\u{7e}',
    '\u{7f}',
    '\u{9f}',
    '\u{a0}',
    '\u{e9}',
    '\u{d7ff}',
    '\u{e000}',
    '\u{f8ff}',
    '\u{f900}',
    '\u{ffef}',
    '\u{fff0}',
    '\u{ffff}',
    '\u{10000}',
    '\u{10ffff}',
];

/// The characters of the component rules.
const NARROW: &[char] = &['/', '.', 'a', '\0', '\u{10000}'];

#[test]
fn short_paths_match_the_reference() {
    // The exact count shows that the alphabets and lengths do not shrink.
    // Each string is bare and with a leading slash, for both create kinds.
    // Miri interprets slowly, so it checks shorter strings.
    if cfg!(miri) {
        let cases = exhaustive(WIDE, 2) + exhaustive(NARROW, 4);
        assert_eq!(cases, 5_152);
    } else {
        let cases = exhaustive(WIDE, 4) + exhaustive(NARROW, 7);
        assert_eq!(cases, 1_372_268);
    }
}

/// A fixed-seed xorshift generator, so that a failure repeats.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn long_random_paths_match_the_reference() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut cases = 0;
    let mut s = String::new();
    // Miri interprets slowly, so it runs fewer rounds.
    let rounds = if cfg!(miri) { 200 } else { 20_000 };
    for round in 0..rounds {
        s.clear();
        if round % 8 != 0 {
            s.push('/');
        }
        let len = 1 + rng.below(300);
        for _ in 0..len {
            // Most characters are plain, so that long paths often stay valid
            // up to a late error.
            let c = match rng.below(16) {
                0..=7 => 'a',
                8..=10 => '/',
                11 | 12 => '.',
                _ => WIDE[rng.below(WIDE.len())],
            };
            s.push(c);
        }
        cases += compare(&s);
        // Remove the empty components, so that more paths are valid.
        let cleaned = s.replace("//", "/");
        cases += compare(&cleaned);
    }
    assert_eq!(cases, 4 * rounds);
}
