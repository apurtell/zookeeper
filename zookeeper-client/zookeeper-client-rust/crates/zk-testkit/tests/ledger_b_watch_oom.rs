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

//! Watch registration under the OOM rule (ledger row WAT-17). An allocation
//! failure in the Rust core aborts the process.
//!
//! Legacy drops a watch with a LOG_ERROR line when an allocation fails
//! during the registration. The Rust core has no such path. An allocation
//! failure in the core aborts the process, so the legacy line has no
//! emitter. These tests check that each registration lands and that no
//! drop-in source emits the line.

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

mod common;

use std::path::{Path, PathBuf};

use common::Profile;
use zk_jute::rc;
use zk_proto::{LogLevel, LogSite};
use zk_testkit::WatcherId;

/// The watcher type of the data and exist tables in `has_watcher`.
const WTYPE_DATA: i32 = 2;

/// The number of watches that the registration test arms.
const WATCHES: u32 = 500;

/// Each registration of a large watch set lands in the table, and the
/// core logs no "dropped the watcher" line.
///
/// Ledger: WAT-17
#[test]
fn watch_registration_never_drops_a_watch() {
    for p in Profile::ALL {
        let mut h = p.harness(71);
        h.connect().unwrap();
        let ops = h.ops();
        for i in 0..WATCHES {
            let path = format!("/oom/{i:04}");
            let w = WatcherId::new(1, i);
            let r = h.call(ops.exists(&path, Some(w))).unwrap();
            assert_eq!(r.rc, rc::ZNONODE, "{p:?} {path}");
        }
        for i in 0..WATCHES {
            let path = format!("/oom/{i:04}");
            let w = WatcherId::new(1, i);
            assert!(
                h.conn().has_watcher(path.as_bytes(), WTYPE_DATA, Some(&w)),
                "{p:?}: the watch on {path} is missing"
            );
        }
        let dropped = h
            .recorder()
            .logs()
            .iter()
            .filter(|r| r.site == LogSite::WatcherOom)
            .count();
        assert_eq!(dropped, 0, "{p:?}");
    }
}

/// The legacy line stays in the site tables, so the golden site list
/// keeps it. No drop-in source emits it: the core aborts on OOM instead.
///
/// Ledger: WAT-17
#[test]
fn watcher_oom_line_has_no_emitter() {
    assert_eq!(LogSite::WatcherOom.level(), LogLevel::Error);
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let shim = crates.join("../c/shim");
    let mut files = Vec::new();
    for dir in ["zk-proto/src", "zk-driver/src", "zk-ffi/src"] {
        collect(&crates.join(dir), &mut files);
    }
    collect(&shim, &mut files);
    assert!(files.len() > 20, "the source scan found too few files");
    let mut hits = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let n = text.matches("WatcherOom").count();
        if n > 0 {
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            hits.push((name, n));
        }
    }
    hits.sort();
    // One entry in the zk-proto site table and one in the shim site table.
    assert_eq!(
        hits,
        vec![("log.rs".to_owned(), 1), ("zks_log_sites.h".to_owned(), 1)]
    );
}

/// Adds the Rust and C sources below `dir` to `out`.
fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect(&p, out);
        } else if p
            .extension()
            .is_some_and(|x| x == "rs" || x == "c" || x == "h")
        {
            out.push(p);
        }
    }
}
