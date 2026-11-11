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
//! Checks that the C cross-checks are present.
//!
//! The other test files compile only when the build script builds the C
//! code. This file has no such condition, so a silent loss of the C build
//! makes the test run fail on Unix.

// The assertion is on a build-time constant on purpose.
#![allow(clippy::panic, clippy::assertions_on_constants, missing_docs)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

#[cfg(unix)]
#[test]
fn c_harness_is_built_on_unix() {
    assert!(
        zk_xcheck::C_AVAILABLE,
        "the build script did not build the C sources, so the C cross-checks are off; \
         check the cargo warnings of zk-xcheck and ZKX_C_SRC"
    );
    assert!(
        !zk_xcheck::manifest::ZOOKEEPER_C_EXTRACTS.is_empty(),
        "the C extract manifest is empty"
    );
}
