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

//! The cross-language layout check of the drop-in ABI.
//!
//! The crate compares the C compiler view and the rustc view of each
//! type and value that crosses the C boundary of the drop-in library:
//!
//! - The `repr(C)` mirrors of the public records in
//!   `zk-ffi/src/abi/legacy.rs`, against `include/zookeeper.h` and the
//!   generated `zookeeper.jute.h`.
//! - The `repr(C)` types, enum values and constants of
//!   `zk-ffi/src/abi/types.rs`, against `c/shim/zkrs.h`.
//! - The result codes of `zk-jute/src/rc.rs`, against `enum ZOO_ERRORS`.
//! - The operation codes of `zk-jute/src/opcode.rs`, against `proto.h`.
//!
//! The facts are the size and the alignment of each type, and the
//! offset and the size of each field. The values are the enum variants
//! and the integer constants. The crate includes the Rust sources by
//! `#[path]`, so it checks the same definitions that zk-ffi compiles.
//!
//! The build script compiles a C probe for each configuration of the
//! public headers: `plain`, `ssl`, `sasl` and `full`. The public types
//! differ between them. The probe runs on the build host and prints the
//! C facts. The tests in `tests/` compare the two tables.
//!
//! Other layout checks cover other parts. `cargo xtask layout gen` writes
//! the public probe `c/tests/abi/layout/probe.c`. This crate reads the
//! member lists of the public types from it. `cargo xtask layout expect`
//! records the public facts of a target in a golden file, and
//! `c/tests/abi/layout_check.c` checks the headers against it. That pair
//! detects a header change on any target. `c/shim/zks_layout_check.c`
//! pins the `zkrs.h` layout of the 64-bit and the 32-bit targets at
//! compile time. This crate is the only check that compares C with Rust.

#![forbid(unsafe_code)]
// The unit tests of the included zk-ffi sources may assert and panic.
#![cfg_attr(test, allow(clippy::disallowed_macros))]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::mem::offset_of;
use std::sync::OnceLock;

#[path = "../../zk-ffi/src/abi/legacy.rs"]
mod legacy;

#[path = "../../zk-ffi/src/abi/types.rs"]
#[allow(dead_code, unreachable_pub, reason = "the tables use only the layout")]
mod types;

#[path = "../../zk-jute/src/rc.rs"]
#[allow(dead_code, unreachable_pub, reason = "the tables use only the values")]
mod rc;

#[path = "../../zk-jute/src/opcode.rs"]
#[allow(dead_code, unreachable_pub, reason = "the tables use only the values")]
mod opcode;

/// The type name of the `ZKRS_*` constants of `zkrs.h`.
pub const ZKRS_DEFINES: &str = "zkrs.h";
/// The type name of the operation codes of `proto.h`.
pub const OPCODES: &str = "proto.h";
/// The type name of the public result codes.
pub const ZOO_ERRORS: &str = "enum ZOO_ERRORS";

/// One layout fact or value of a type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fact {
    /// `sizeof`, `alignof`, `offsetof`, `fieldsize`, `signed` or `value`.
    pub fact: &'static str,
    /// The C type, for example `struct Stat`, or the name of a value set.
    pub ty: &'static str,
    /// The member, the variant or the constant, or `-` for the type.
    pub member: &'static str,
    /// The value in bytes, or the integer value.
    pub value: i64,
}

impl Fact {
    /// Makes a fact.
    #[must_use]
    pub const fn new(
        fact: &'static str,
        ty: &'static str,
        member: &'static str,
        value: i64,
    ) -> Self {
        Self {
            fact,
            ty,
            member,
            value,
        }
    }

    /// Returns true when the fact is a value, not a layout fact.
    fn is_value(&self) -> bool {
        self.fact == "value"
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} = {}",
            self.fact, self.ty, self.member, self.value
        )
    }
}

/// The C facts of one configuration.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    /// `plain`, `ssl`, `sasl` or `full`.
    pub config: &'static str,
    /// The defines and the header flags of the configuration.
    pub cflags: &'static str,
    /// The compiler output when the probe did not build, otherwise empty.
    pub error: &'static str,
    /// The facts that the probe printed.
    pub facts: &'static [Fact],
}

/// Converts a byte count. No ABI type comes near the limit.
const fn n(v: usize) -> i64 {
    if v > i64::MAX as usize { -1 } else { v as i64 }
}

/// Returns the size of the field that `_get` selects.
const fn field_size<T, F>(_get: fn(&T) -> &F) -> i64 {
    n(size_of::<F>())
}

include!(concat!(env!("OUT_DIR"), "/facts.rs"));

/// Returns the C facts of each configuration that the build selected.
#[must_use]
pub fn probes() -> &'static [Probe] {
    C_PROBES
}

/// Returns the offset of a member field from the offset of the member
/// and the offset of the field in the member.
const fn nested(member: usize, field: usize) -> i64 {
    match member.checked_add(field) {
        Some(v) => n(v),
        None => -1,
    }
}

/// Writes the facts of one union member of `zoo_op_t`. Each member
/// starts at the offset of `create_op`, the largest member. The `head`
/// form gives the offset and the size of the member itself.
macro_rules! zoo_op_member {
    (head $m:literal, $t:ty) => {
        [
            Fact::new("offsetof", "zoo_op_t", $m, n(offset_of!(legacy::CZooOp, create_op))),
            Fact::new("fieldsize", "zoo_op_t", $m, n(size_of::<$t>())),
        ]
    };
    ($m:literal, $t:ty, [$($f:ident),*]) => {
        [$(
            Fact::new(
                "offsetof",
                "zoo_op_t",
                concat!($m, ".", stringify!($f)),
                nested(offset_of!(legacy::CZooOp, create_op), offset_of!($t, $f)),
            ),
            Fact::new(
                "fieldsize",
                "zoo_op_t",
                concat!($m, ".", stringify!($f)),
                field_size(|v: &$t| &v.$f),
            ),
        )*]
    };
}

/// The facts of the union members of `zoo_op_t`. The build script
/// writes the facts of `type` and `create_op` from the parent mirror.
static ZOO_OP_FACTS: &[&[Fact]] = &[
    &zoo_op_member!(
        "create_op",
        legacy::CCreateOp,
        [path, data, datalen, buf, buflen, acl, flags, ttl]
    ),
    &zoo_op_member!(head "delete_op", legacy::CDeleteOp),
    &zoo_op_member!("delete_op", legacy::CDeleteOp, [path, version]),
    &zoo_op_member!(head "set_op", legacy::CSetOp),
    &zoo_op_member!("set_op", legacy::CSetOp, [path, data, datalen, version, stat]),
    &zoo_op_member!(head "check_op", legacy::CCheckOp),
    &zoo_op_member!("check_op", legacy::CCheckOp, [path, version]),
];

/// Returns the Rust facts: the generated table and the union members of
/// `zoo_op_t`.
#[must_use]
pub fn rust_facts() -> &'static [Fact] {
    static ALL: OnceLock<Vec<Fact>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mut all = RUST_FACTS.to_vec();
        for part in ZOO_OP_FACTS {
            all.extend_from_slice(part);
        }
        all
    })
}

/// Returns true when a C group needs a Rust definition: each `zkrs.h`
/// type and each value set. A public type needs one only when zk-ffi
/// mirrors it.
fn needs_rust(is_value: bool, ty: &str) -> bool {
    ty.starts_with("zkrs_") || (is_value && [ZKRS_DEFINES, ZOO_ERRORS, OPCODES].contains(&ty))
}

/// Returns true when the Rust side may have values that C does not
/// define. The native client uses operation codes that the C client
/// never sends.
fn rust_may_add(ty: &str) -> bool {
    ty == OPCODES
}

/// Normalizes a member name. The legacy mirrors use snake case for the
/// camel case members, and the Rust operation codes split the words of
/// the C names.
fn norm(member: &str) -> String {
    member
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The key of a fact for the comparison.
type Key = (&'static str, &'static str, String);

fn key(f: &Fact) -> Key {
    (f.fact, f.ty, norm(f.member))
}

/// Compares the C facts with the Rust facts and returns one line for
/// each difference.
///
/// The layout facts and the values of a type form two groups. When Rust
/// defines a group, each C fact of the group must have an equal Rust
/// fact. Each Rust fact must also have a C fact. A C group that Rust does
/// not define is a difference only for the private types and the value
/// sets.
#[must_use]
pub fn compare(c: &[Fact], rust: &[Fact]) -> Vec<String> {
    let mut bad = Vec::new();
    let mut rmap: BTreeMap<Key, i64> = BTreeMap::new();
    for f in rust {
        if rmap.insert(key(f), f.value).is_some() {
            bad.push(format!(
                "Rust has two facts for {} {} {}",
                f.fact, f.ty, f.member
            ));
        }
    }
    let rgroups: BTreeSet<(bool, &str)> = rust.iter().map(|f| (f.is_value(), f.ty)).collect();
    let cgroups: BTreeSet<(bool, &str)> = c.iter().map(|f| (f.is_value(), f.ty)).collect();
    let mut seen: BTreeSet<Key> = BTreeSet::new();
    let mut missing: BTreeSet<(bool, &str)> = BTreeSet::new();
    for f in c {
        let group = (f.is_value(), f.ty);
        if !rgroups.contains(&group) {
            if needs_rust(f.is_value(), f.ty) && missing.insert(group) {
                bad.push(format!(
                    "C {} {} has no Rust definition",
                    f.ty,
                    kind(f.is_value())
                ));
            }
            continue;
        }
        let k = key(f);
        match rmap.get(&k) {
            Some(v) if *v == f.value => {}
            Some(v) => bad.push(format!(
                "{} {} {}: C {}, Rust {v}",
                f.fact, f.ty, f.member, f.value
            )),
            None => bad.push(format!("C {f} has no Rust counterpart")),
        }
        seen.insert(k);
    }
    for f in rust {
        let group = (f.is_value(), f.ty);
        if seen.contains(&key(f)) || rust_may_add(f.ty) {
            continue;
        }
        if !cgroups.contains(&group) {
            if missing.insert(group) {
                bad.push(format!(
                    "Rust {} {} has no C definition",
                    f.ty,
                    kind(f.is_value())
                ));
            }
        } else {
            bad.push(format!("Rust {f} has no C counterpart"));
        }
    }
    bad
}

fn kind(is_value: bool) -> &'static str {
    if is_value { "values" } else { "layout" }
}
