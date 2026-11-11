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

//! The participant order of Apache Curator.
//!
//! Curator reduces each child name to the text after the last
//! occurrence of the marker, or keeps the whole name when the marker is
//! absent (`StandardLockInternalsDriver.fixForSorting`). It then sorts
//! the reduced names with `String.compareTo`, a stable sort. With the
//! 10-digit sequence suffix of the server, this order is the creation
//! order. The children are not filtered, so both languages agree on the
//! order also when foreign nodes exist under the path.
//!
//! `String.compareTo` compares UTF-16 code units. The comparison here
//! does the same, so the order is equal for each name, also for names
//! with characters outside the Basic Multilingual Plane.

use std::cmp::Ordering;

/// The marker of `InterProcessMutex` (`InterProcessMutex.LOCK_NAME`).
pub(crate) const LOCK_MARKER: &str = "lock-";

/// The marker of `LeaderLatch` (`LeaderLatch.LOCK_NAME`).
pub(crate) const LATCH_MARKER: &str = "latch-";

/// The sort key of one child name: the text after the last marker, or
/// the whole name.
pub(crate) fn sort_key<'a>(name: &'a str, marker: &str) -> &'a str {
    name.rsplit_once(marker).map_or(name, |(_, tail)| tail)
}

/// Compares two child names in Curator order.
pub(crate) fn compare(a: &str, b: &str, marker: &str) -> Ordering {
    sort_key(a, marker)
        .encode_utf16()
        .cmp(sort_key(b, marker).encode_utf16())
}

/// Sorts child names in Curator order. The sort is stable, as Java's
/// `Collections.sort` is.
pub(crate) fn sort_children(children: &mut [String], marker: &str) {
    children.sort_by(|a, b| compare(a, b, marker));
}

/// The place of `own` in a sorted child list, or `None` when it is
/// absent.
pub(crate) fn position(sorted: &[String], own: &str) -> Option<usize> {
    sorted.iter().position(|c| c == own)
}

/// The child just before `own` in a sorted child list. It is `None`
/// when `own` is first or absent.
pub(crate) fn predecessor<'a>(sorted: &'a [String], own: &str) -> Option<&'a str> {
    let i = position(sorted, own)?;
    let before = i.checked_sub(1)?;
    sorted.get(before).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn key_is_text_after_last_marker() {
        assert_eq!(sort_key("_c_x-lock-0000000007", LOCK_MARKER), "0000000007");
        // A UUID can hold the marker text only in its own form, but a
        // foreign name can hold it twice.
        assert_eq!(
            sort_key("lock-a-lock-0000000001", LOCK_MARKER),
            "0000000001"
        );
        assert_eq!(sort_key("foreign", LOCK_MARKER), "foreign");
        assert_eq!(sort_key("x-lock-", LOCK_MARKER), "");
    }

    #[test]
    fn order_is_creation_order_across_uuids() {
        let mut c = names(&[
            "_c_ffffffff-0000-4000-8000-000000000000-lock-0000000003",
            "_c_00000000-0000-4000-8000-000000000000-lock-0000000010",
            "_c_88888888-0000-4000-8000-000000000000-lock-0000000001",
        ]);
        sort_children(&mut c, LOCK_MARKER);
        assert!(c[0].ends_with("0000000001"));
        assert!(c[1].ends_with("0000000003"));
        assert!(c[2].ends_with("0000000010"));
    }

    #[test]
    fn foreign_children_take_part() {
        // Curator keeps foreign names whole, so "zzz" sorts after the
        // digits and "000" sorts before "0000000001".
        let mut c = names(&["zzz", "a-latch-0000000002", "000", "b-latch-0000000001"]);
        sort_children(&mut c, LATCH_MARKER);
        assert_eq!(
            c,
            names(&["000", "b-latch-0000000001", "a-latch-0000000002", "zzz"])
        );
    }

    #[test]
    fn utf16_order_as_java() {
        // U+FF61 is one UTF-16 unit (0xFF61). U+10000 is the pair
        // 0xD800 0xDC00. Java orders the pair first; UTF-8 byte order
        // puts it last.
        let mut c = names(&["\u{FF61}", "\u{10000}"]);
        sort_children(&mut c, LOCK_MARKER);
        assert_eq!(c, names(&["\u{10000}", "\u{FF61}"]));
    }

    #[test]
    fn predecessor_and_position() {
        let c = names(&["a-lock-1", "b-lock-2", "c-lock-3"]);
        assert_eq!(position(&c, "b-lock-2"), Some(1));
        assert_eq!(predecessor(&c, "a-lock-1"), None);
        assert_eq!(predecessor(&c, "c-lock-3"), Some("b-lock-2"));
        assert_eq!(predecessor(&c, "missing"), None);
    }
}
