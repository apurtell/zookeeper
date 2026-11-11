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

//! Keeps the unsafe code of zk-ffi in the audited modules.
//!
//! The crate denies `unsafe_code`. Only `abi::raw` and the test stand-in
//! allow it for the full module. Each C export allows it on the item, for
//! `#[unsafe(no_mangle)]` only. The lint cannot see the difference
//! between that attribute and an unsafe block under the same allow. Thus
//! this test reads the source and fails on an unsafe block, fn, impl,
//! trait or extern block in another file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

use std::fs;
use std::path::{Path, PathBuf};

/// The files that can hold unsafe code, relative to `src`.
fn is_audited(rel: &Path) -> bool {
    rel == Path::new("abi/raw.rs") || rel.starts_with("abi/raw") || rel.starts_with("abi/standin")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Removes a line comment and the text of string literals. The quote
/// characters stay, so `extern "C"` becomes `extern ""`.
fn code_only(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_str = false;
    let mut escaped = false;
    let mut prev_slash = false;
    for c in line.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
                out.push(c);
            }
            continue;
        }
        if c == '/' && prev_slash {
            out.pop();
            break;
        }
        prev_slash = c == '/';
        if c == '"' {
            in_str = true;
        }
        out.push(c);
    }
    out
}

/// Tells if the `unsafe` keyword at the start of `rest` is allowed
/// outside the audited modules. The allowed forms are the export
/// attribute and a function pointer type.
fn allowed_use(rest: &str) -> bool {
    let rest = rest.trim_start();
    if rest.starts_with("(no_mangle)") {
        return true;
    }
    let rest = rest.strip_prefix("extern").map_or(rest, |r| {
        let r = r.trim_start();
        r.strip_prefix("\"\"").unwrap_or(r).trim_start()
    });
    rest.strip_prefix("fn")
        .is_some_and(|r| r.trim_start().starts_with('('))
}

/// Gives the 1-based numbers of the lines that use unsafe code.
fn violations(text: &str) -> Vec<usize> {
    let mut bad = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = code_only(line);
        let mut from = 0;
        while let Some(i) = code.get(from..).and_then(|s| s.find("unsafe")) {
            let at = from.saturating_add(i);
            let end = at.saturating_add("unsafe".len());
            let before = code.get(..at).and_then(|s| s.chars().next_back());
            let after = code.get(end..).unwrap_or("");
            let ident = |c: char| c.is_alphanumeric() || c == '_';
            let word = !before.is_some_and(ident) && !after.chars().next().is_some_and(ident);
            if word && !allowed_use(after) {
                bad.push(n.saturating_add(1));
                break;
            }
            from = end;
        }
    }
    bad
}

#[test]
fn scanner_finds_unsafe_code() {
    assert_eq!(violations("let x = unsafe { f() };"), vec![1]);
    assert_eq!(violations("pub unsafe fn f() {}"), vec![1]);
    assert_eq!(violations("unsafe impl Send for X {}"), vec![1]);
    assert_eq!(violations("unsafe trait T {}"), vec![1]);
    assert_eq!(violations("pub unsafe extern \"C\" fn f() {}"), vec![1]);
    assert_eq!(violations("unsafe extern \"C\" {\n}"), vec![1]);
    assert_eq!(violations("ok();\nunsafe {}"), vec![2]);
}

#[test]
fn scanner_skips_allowed_forms() {
    assert!(violations("#[unsafe(no_mangle)]").is_empty());
    assert!(violations("f: Option<unsafe extern \"C\" fn(usize)>,").is_empty());
    assert!(violations("f: unsafe fn(u8) -> u8,").is_empty());
    assert!(violations("#![deny(unsafe_code)]").is_empty());
    assert!(violations("// unsafe { f() }").is_empty());
    assert!(violations("/// SAFETY: unsafe { x }").is_empty());
    assert!(violations("let s = \"unsafe { }\";").is_empty());
    assert!(violations("is_unsafe(); unsafety();").is_empty());
}

#[test]
fn unsafe_code_stays_in_the_audited_modules() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty());
    let mut bad = Vec::new();
    for f in files {
        let rel = f.strip_prefix(&src).unwrap().to_path_buf();
        if is_audited(&rel) {
            continue;
        }
        let text = fs::read_to_string(&f).unwrap();
        for n in violations(&text) {
            bad.push(format!("{}:{n}", rel.display()));
        }
    }
    assert!(bad.is_empty(), "unsafe code outside abi::raw: {bad:?}");
}
