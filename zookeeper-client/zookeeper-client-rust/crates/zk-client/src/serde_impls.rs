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

//! The `serde` support of the value types (feature `serde`).
//!
//! `Stat`, `Acl`, `Id`, `Zxid`, `SessionId`, `Version` and `CreateMode`
//! derive the traits. The derives of the id and version types are
//! transparent, so each one is its wire integer. This file has the
//! two types that need their own rule:
//!
//! - `Perms` is its wire `i32` bit mask. Unknown bits stay, as the
//!   server can send them.
//! - `Ttl` is its value in milliseconds. A deserialized value must be
//!   in the range of `Ttl::from_millis`, so a bad value is an error and
//!   not a TTL that the server refuses later.

use serde::de::{Deserialize, Deserializer, Error as _};
use serde::ser::{Serialize, Serializer};

use crate::acl::Perms;
use crate::types::Ttl;

impl Serialize for Perms {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i32(self.bits())
    }
}

impl<'de> Deserialize<'de> for Perms {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        i32::deserialize(d).map(Perms::from_bits_retain)
    }
}

impl Serialize for Ttl {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.as_millis())
    }
}

impl<'de> Deserialize<'de> for Ttl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ms = u64::deserialize(d)?;
        Ttl::from_millis(ms).map_err(|_| {
            D::Error::invalid_value(
                serde::de::Unexpected::Unsigned(ms),
                &"a TTL in 1..=0xFF_FFFF_FFFF ms",
            )
        })
    }
}
