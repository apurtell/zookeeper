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

//! ACL types and the standard ACL lists.
//!
//! The digest helper behind [`Id::digest`] is in `auth.rs`. The jute
//! conversions are in `ops.rs` and `decode.rs`.

use std::borrow::Cow;

bitflags::bitflags! {
    /// ZooKeeper permission bits. Unknown bits from the server are kept
    /// (`Perms::from_bits_retain`).
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct Perms: i32 {
        /// Read the data and list the children.
        const READ = 1;
        /// Set the data.
        const WRITE = 2;
        /// Create children.
        const CREATE = 4;
        /// Delete children.
        const DELETE = 8;
        /// Set the ACL.
        const ADMIN = 16;
        /// Every permission.
        const ALL = 0x1f;
    }
}

/// An ACL identity: a scheme and an id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Id {
    /// The scheme, for example `world`, `auth`, `digest` or `ip`.
    pub scheme: Cow<'static, str>,
    /// The id within the scheme.
    pub id: Cow<'static, str>,
}

impl Id {
    /// `world:anyone`.
    pub const ANYONE: Id = Id {
        scheme: Cow::Borrowed("world"),
        id: Cow::Borrowed("anyone"),
    };

    /// `auth:`: the identities that the session authenticated.
    pub const AUTH_IDS: Id = Id {
        scheme: Cow::Borrowed("auth"),
        id: Cow::Borrowed(""),
    };

    /// Makes an identity.
    #[must_use]
    pub fn new(scheme: impl Into<Cow<'static, str>>, id: impl Into<Cow<'static, str>>) -> Id {
        Id {
            scheme: scheme.into(),
            id: id.into(),
        }
    }

    /// An `ip` identity for an address or a CIDR block.
    #[must_use]
    pub fn ip(cidr: &str) -> Id {
        Id::new("ip", cidr.to_owned())
    }

    /// A `digest` identity: `user:base64(sha1(user:password))`, as Java
    /// `DigestAuthenticationProvider.generateDigest` makes it.
    #[must_use]
    pub fn digest(user: &str, password: &str) -> Id {
        Id::new("digest", crate::auth::digest_id(user, password))
    }
}

/// One ACL entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Acl {
    /// The permissions.
    pub perms: Perms,
    /// The identity.
    pub id: Id,
}

/// Every permission for anyone.
pub const OPEN_ACL_UNSAFE: &[Acl] = &[Acl {
    perms: Perms::ALL,
    id: Id::ANYONE,
}];

/// Read permission for anyone.
pub const READ_ACL_UNSAFE: &[Acl] = &[Acl {
    perms: Perms::READ,
    id: Id::ANYONE,
}];

/// Every permission for the identities of the creating session.
pub const CREATOR_ALL_ACL: &[Acl] = &[Acl {
    perms: Perms::ALL,
    id: Id::AUTH_IDS,
}];
