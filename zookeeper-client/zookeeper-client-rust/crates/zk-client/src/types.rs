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

//! Identifiers, versions, `Stat`, TTLs and create modes.
//!
//! These are plain values. The wire mapping of `CreateMode` is in
//! `ops.rs`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::error::Error;

/// A ZooKeeper transaction id.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct Zxid(pub i64);

/// A session id. `Debug` and `Display` print `0x` and 16 hex digits, as
/// the Java client logs it.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct SessionId(pub i64);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// A session password. It is wiped on drop, and `Debug` prints
/// `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionPassword(Zeroizing<[u8; 16]>);

impl SessionPassword {
    /// Wraps the 16 password bytes of a session.
    #[must_use]
    pub fn from_bytes(b: [u8; 16]) -> Self {
        Self(Zeroizing::new(b))
    }

    /// Returns the password bytes. Callers must not log them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for SessionPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A znode version. [`Version::ANY`] is the wire value -1. The default
/// is version 0, the version of a new node.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct Version(i32);

impl Version {
    /// Matches any version (wire -1).
    pub const ANY: Version = Version(-1);

    /// Wraps a wire version.
    #[must_use]
    pub const fn new(v: i32) -> Self {
        Self(v)
    }

    /// Returns the wire version.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

mod sealed {
    /// Seals [`super::VersionArg`].
    pub trait Sealed {
        /// The wire version: -1 for any version.
        fn wire_version(&self) -> i32;
    }
}

/// A version argument: a [`Version`] or an `Option<Version>` (sealed).
///
/// The specification passes `Option<Version>`, where `None` matches any
/// version. A plain `Version` with [`Version::ANY`] is also common. Both
/// forms are accepted, so `set_data(p, d, stat.version)` and
/// `delete(p, None)` both work.
pub trait VersionArg: sealed::Sealed {}

impl sealed::Sealed for Version {
    fn wire_version(&self) -> i32 {
        self.0
    }
}
impl VersionArg for Version {}

impl sealed::Sealed for Option<Version> {
    fn wire_version(&self) -> i32 {
        self.map_or(Version::ANY.0, |v| v.0)
    }
}
impl VersionArg for Option<Version> {}

/// Returns the wire value of a version argument.
pub(crate) fn wire_version(v: &impl VersionArg) -> i32 {
    sealed::Sealed::wire_version(v)
}

/// The metadata of a znode. It is the fixed jute `Stat` record, so it
/// is not `#[non_exhaustive]`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stat {
    /// The zxid of the create.
    pub czxid: Zxid,
    /// The zxid of the last data change.
    pub mzxid: Zxid,
    /// The zxid of the last change of the children.
    pub pzxid: Zxid,
    /// The create time, in ms since the Unix epoch.
    pub ctime: i64,
    /// The time of the last data change, in ms since the Unix epoch.
    pub mtime: i64,
    /// The data version.
    pub version: Version,
    /// The version of the children list.
    pub cversion: Version,
    /// The ACL version.
    pub aversion: Version,
    /// The raw wire owner value. See [`Stat::ephemeral_kind`].
    pub ephemeral_owner: i64,
    /// The data length in bytes.
    pub data_length: i32,
    /// The number of children.
    pub num_children: i32,
}

/// The marker byte of an extended owner value (Java `EphemeralType`).
const EXTENDED_MARK: u64 = 0xFF;
/// The low 40 bits of an extended owner value: the TTL in ms.
const TTL_MASK: u64 = 0x00FF_FFFF_FFFF;
/// The 16-bit extended type field.
const EXTENDED_TYPE_MASK: u64 = 0xFFFF;

/// Converts a wire time in ms to a `SystemTime`. Values out of range
/// give the epoch.
fn ms_to_time(ms: i64) -> SystemTime {
    let abs = Duration::from_millis(ms.unsigned_abs());
    let t = if ms >= 0 {
        UNIX_EPOCH.checked_add(abs)
    } else {
        UNIX_EPOCH.checked_sub(abs)
    };
    t.unwrap_or(UNIX_EPOCH)
}

impl Stat {
    /// The create time.
    #[must_use]
    pub fn ctime(&self) -> SystemTime {
        ms_to_time(self.ctime)
    }

    /// The time of the last data change.
    #[must_use]
    pub fn mtime(&self) -> SystemTime {
        ms_to_time(self.mtime)
    }

    /// Decodes `ephemeral_owner` by the Java `EphemeralType` rules. The
    /// value 0 is a plain node, and `i64::MIN` is a container. A 0xFF
    /// high byte with extended type 0 is a TTL node. Any other value is
    /// a session.
    ///
    /// A real server sends 0 for container and TTL nodes. Thus a stat
    /// from a server reply gives `Container` or `Ttl` only when the
    /// server changes this rule.
    #[must_use]
    pub fn ephemeral_kind(&self) -> EphemeralKind {
        let owner = self.ephemeral_owner;
        if owner == 0 {
            return EphemeralKind::None;
        }
        if owner == i64::MIN {
            return EphemeralKind::Container;
        }
        let bits = u64::from_be_bytes(owner.to_be_bytes());
        if bits.wrapping_shr(56) == EXTENDED_MARK && bits.wrapping_shr(40) & EXTENDED_TYPE_MASK == 0
        {
            return EphemeralKind::Ttl(Duration::from_millis(bits & TTL_MASK));
        }
        EphemeralKind::Session(SessionId(owner))
    }

    /// Converts the jute record.
    pub(crate) fn from_jute(s: &zk_jute::data::Stat) -> Self {
        Self {
            czxid: Zxid(s.czxid),
            mzxid: Zxid(s.mzxid),
            pzxid: Zxid(s.pzxid),
            ctime: s.ctime,
            mtime: s.mtime,
            version: Version(s.version),
            cversion: Version(s.cversion),
            aversion: Version(s.aversion),
            ephemeral_owner: s.ephemeral_owner,
            data_length: s.data_length,
            num_children: s.num_children,
        }
    }
}

/// The kind of owner of a znode.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EphemeralKind {
    /// A plain persistent node.
    None,
    /// An ephemeral node of this session.
    Session(SessionId),
    /// A container node.
    Container,
    /// A persistent node with this TTL.
    Ttl(Duration),
}

/// A TTL in ms, `1..=0xFF_FFFF_FFFF`. The upper bound is the server
/// `EphemeralType.TTL` maximum, about 34.8 years.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ttl(u64);

impl Ttl {
    /// The largest TTL that the server accepts.
    pub const MAX: Ttl = Ttl(0xFF_FFFF_FFFF);

    /// Makes a TTL from a duration, truncated to ms.
    ///
    /// # Errors
    ///
    /// `Error::InvalidArgument` when the value is 0 ms or above
    /// [`Ttl::MAX`].
    pub fn new(d: Duration) -> Result<Ttl, Error> {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        Self::from_millis(ms)
    }

    /// Makes a TTL from ms.
    ///
    /// # Errors
    ///
    /// `Error::InvalidArgument` when `ms` is 0 or above [`Ttl::MAX`].
    pub fn from_millis(ms: u64) -> Result<Ttl, Error> {
        if ms == 0 || ms > Self::MAX.0 {
            return Err(Error::InvalidArgument(
                "TTL must be in 1..=0xFF_FFFF_FFFF ms".into(),
            ));
        }
        Ok(Ttl(ms))
    }

    /// Returns the TTL in ms.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Returns the TTL as a duration.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

/// The mode of a create. The TTL is part of the variant, so a TTL mode
/// without a TTL cannot be written.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum CreateMode {
    /// A persistent node.
    Persistent,
    /// A persistent node with a sequence suffix.
    PersistentSequential,
    /// A node that the session owns.
    Ephemeral,
    /// A session-owned node with a sequence suffix.
    EphemeralSequential,
    /// A container node (3.5.3+).
    Container,
    /// A persistent node with a TTL (3.5.3+).
    PersistentWithTtl(Ttl),
    /// A sequential persistent node with a TTL (3.5.3+).
    PersistentSequentialWithTtl(Ttl),
}

impl CreateMode {
    /// True for the modes that add a sequence suffix.
    #[must_use]
    pub fn is_sequential(&self) -> bool {
        matches!(
            self,
            Self::PersistentSequential
                | Self::EphemeralSequential
                | Self::PersistentSequentialWithTtl(_)
        )
    }

    /// True for the modes that the session owns.
    #[must_use]
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral | Self::EphemeralSequential)
    }

    /// The TTL of a TTL mode.
    #[must_use]
    pub fn ttl(&self) -> Option<Ttl> {
        match self {
            Self::PersistentWithTtl(t) | Self::PersistentSequentialWithTtl(t) => Some(*t),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_args() {
        assert_eq!(wire_version(&Version::new(3)), 3);
        assert_eq!(wire_version(&None::<Version>), -1);
        assert_eq!(wire_version(&Some(Version::new(4))), 4);
        assert_eq!(Version::ANY.get(), -1);
    }
}
