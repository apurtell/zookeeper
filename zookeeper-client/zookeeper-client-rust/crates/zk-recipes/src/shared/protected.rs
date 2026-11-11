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

//! Protected-mode names.
//!
//! Apache Curator puts the prefix `_c_<uuid>-` in front of the name of
//! a protected node. After a `ConnectionLoss` on the create, the prefix
//! lets the creator find its node in the child list of the parent. The
//! `<uuid>` is a random version-4 UUID in the canonical lowercase
//! 8-4-4-4-12 form, as Java's `UUID.randomUUID().toString()` writes it.
//!
//! The UUID must be unique, not secret. The bits come from the hasher
//! keys of `RandomState`, which std draws from the OS, as zk-client
//! seeds its `NativeRng`. Thus the crate needs no `getrandom`
//! and no UUID crate.

use std::collections::hash_map::RandomState;
use std::fmt::Write as _;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The protected-mode marker of Curator (`CreateBuilderImpl.PROTECTED_PREFIX`).
pub(crate) const PROTECTED_PREFIX: &str = "_c_";

/// The separator after the UUID (`CreateBuilderImpl.PROTECTED_SEPARATOR`).
pub(crate) const PROTECTED_SEPARATOR: &str = "-";

/// The bits of the version field: the high nibble of byte 6.
const VERSION_MASK: u128 = 0x0000_0000_0000_F000_0000_0000_0000_0000;
/// Version 4 (random).
const VERSION_4: u128 = 0x0000_0000_0000_4000_0000_0000_0000_0000;
/// The bits of the variant field: the two high bits of byte 8.
const VARIANT_MASK: u128 = 0x0000_0000_0000_0000_C000_0000_0000_0000;
/// The RFC 4122 variant (binary `10`).
const VARIANT_RFC4122: u128 = 0x0000_0000_0000_0000_8000_0000_0000_0000;

/// The count of UUIDs that this process made. It makes each hash input
/// different, also when two `RandomState` values have the same keys.
static MADE: AtomicU64 = AtomicU64::new(0);

/// The protected id of one participant: a version-4 UUID.
///
/// A participant keeps the same id across the retries of one create,
/// so the recovery can find the node. A latch that makes a new node
/// after its node is gone takes a new id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProtectedId {
    uuid: String,
}

impl ProtectedId {
    /// Makes a new random id.
    pub(crate) fn new() -> Self {
        Self::from_bits(random_u128())
    }

    /// Makes the id of 128 bits. It sets the version and variant bits.
    pub(crate) fn from_bits(bits: u128) -> Self {
        let v = (bits & !VERSION_MASK & !VARIANT_MASK) | VERSION_4 | VARIANT_RFC4122;
        let mut uuid = String::with_capacity(36);
        for (i, b) in v.to_be_bytes().iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                uuid.push('-');
            }
            // A write to a String cannot fail.
            let _ = write!(uuid, "{b:02x}");
        }
        Self { uuid }
    }

    /// The UUID text. Only the inline tests read it.
    #[cfg(test)]
    pub(crate) fn uuid(&self) -> &str {
        &self.uuid
    }

    /// The protected prefix `_c_<uuid>-`. Each child of the parent whose
    /// name starts with it belongs to this participant.
    pub(crate) fn prefix(&self) -> String {
        format!("{PROTECTED_PREFIX}{}{PROTECTED_SEPARATOR}", self.uuid)
    }

    /// The name that the create sends: the prefix, then the marker, for
    /// example `_c_<uuid>-lock-`. The server adds the 10-digit sequence.
    pub(crate) fn node_name(&self, marker: &str) -> String {
        format!("{}{marker}", self.prefix())
    }

    /// The first child whose name starts with the prefix of this id.
    pub(crate) fn find_in<'a>(&self, children: &'a [String]) -> Option<&'a str> {
        children.iter().map(String::as_str).find(|c| self.owns(c))
    }

    /// True when the child name `name` starts with the prefix of this
    /// id.
    pub(crate) fn owns(&self, name: &str) -> bool {
        name.strip_prefix(PROTECTED_PREFIX)
            .and_then(|rest| rest.strip_prefix(self.uuid.as_str()))
            .is_some_and(|rest| rest.starts_with(PROTECTED_SEPARATOR))
    }
}

/// Returns true when `s` is a canonical lowercase version-4 UUID with
/// the RFC 4122 variant. Only the inline tests use it.
#[cfg(test)]
pub(crate) fn is_canonical_v4(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    let lens_ok = groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]);
    let hex_ok = s
        .chars()
        .all(|c| c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c));
    let version_ok = groups.get(2).is_some_and(|g| g.starts_with('4'));
    let variant_ok = groups
        .get(3)
        .and_then(|g| g.chars().next())
        .is_some_and(|c| matches!(c, '8' | '9' | 'a' | 'b'));
    lens_ok && hex_ok && version_ok && variant_ok
}

/// Returns 128 random bits from two `RandomState` hashers.
fn random_u128() -> u128 {
    let n = MADE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let hi = RandomState::new().hash_one((n, nanos, 0x5A4B_u16));
    let lo = RandomState::new().hash_one((n, nanos, 0xB4A5_u16));
    u128::from(hi).wrapping_shl(64) | u128::from(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_is_canonical_v4() {
        for _ in 0..1000 {
            let id = ProtectedId::new();
            assert!(is_canonical_v4(id.uuid()), "{}", id.uuid());
        }
    }

    #[test]
    fn uuid_sets_version_and_variant_bits() {
        assert_eq!(
            ProtectedId::from_bits(0).uuid(),
            "00000000-0000-4000-8000-000000000000"
        );
        assert_eq!(
            ProtectedId::from_bits(u128::MAX).uuid(),
            "ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
    }

    #[test]
    fn uuids_differ() {
        let a: std::collections::BTreeSet<String> = (0..1000)
            .map(|_| ProtectedId::new().uuid().to_owned())
            .collect();
        assert_eq!(a.len(), 1000);
    }

    #[test]
    fn names_follow_curator() {
        let id = ProtectedId::from_bits(0);
        assert_eq!(id.prefix(), "_c_00000000-0000-4000-8000-000000000000-");
        assert_eq!(
            id.node_name("lock-"),
            "_c_00000000-0000-4000-8000-000000000000-lock-"
        );
        let children = vec![
            "_c_11111111-0000-4000-8000-000000000000-lock-0000000001".to_owned(),
            "_c_00000000-0000-4000-8000-000000000000-lock-0000000002".to_owned(),
        ];
        assert_eq!(id.find_in(&children), children.get(1).map(String::as_str));
        assert_eq!(id.find_in(&children[..1]), None);
    }

    #[test]
    fn canonical_check_rejects_other_forms() {
        assert!(!is_canonical_v4("00000000-0000-1000-8000-000000000000"));
        assert!(!is_canonical_v4("00000000-0000-4000-7000-000000000000"));
        assert!(!is_canonical_v4("00000000-0000-4000-8000-00000000000A"));
        assert!(!is_canonical_v4("000000000000-4000-8000-000000000000"));
    }
}
