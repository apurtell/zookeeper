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

//! Prints the directories of the test-time TLS material.
//!
//! Usage: `zk-fixtures tls|corpus...`. The program prints one directory
//! for each argument and makes the material when the cache has none. The
//! shell runners use it, so the cache key rule exists only in Rust.
//! A failure has the same message as in the tests, and exit code 101.

// Unit tests may assert and panic.
#![cfg_attr(test, allow(clippy::disallowed_macros))]

use std::process::ExitCode;

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the program writes the paths to stdout and its usage to stderr"
)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a != "tls" && a != "corpus") {
        eprintln!("usage: zk-fixtures tls|corpus...");
        return ExitCode::from(2);
    }
    for arg in &args {
        let dir = if arg == "tls" {
            zk_testkit::fixtures::tls_dir()
        } else {
            zk_testkit::fixtures::tls_corpus_dir()
        };
        println!("{}", dir.display());
    }
    ExitCode::SUCCESS
}
