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

//! Checks that the crate version is the version of the C client.
//!
//! The drop-in library reports `ZOO_VERSION` from
//! `zookeeper-client-c/include/zookeeper_version.h`. The Rust
//! core must come from the same release, so the build fails when the two
//! versions differ. A crate built outside the source tree has no C header
//! and skips the check. The build script generates nothing.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

const HEADER: &str = "../../../zookeeper-client-c/include/zookeeper_version.h";

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() -> ExitCode {
    println!("cargo:rerun-if-changed={HEADER}");
    println!("cargo:rerun-if-changed=build.rs");
    let root = std::env::var_os("CARGO_MANIFEST_DIR").map_or_else(PathBuf::new, PathBuf::from);
    let want = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let Ok(text) = std::fs::read_to_string(root.join(HEADER)) else {
        return ExitCode::SUCCESS;
    };
    let have = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("#define ZOO_VERSION"))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .next();
    match have {
        Some(v) if v == want => ExitCode::SUCCESS,
        Some(v) => {
            eprintln!("zk-ffi {want} does not match ZOO_VERSION {v} in {HEADER}");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("no ZOO_VERSION line in {HEADER}");
            ExitCode::FAILURE
        }
    }
}
