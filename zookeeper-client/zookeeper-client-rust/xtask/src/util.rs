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

//! Shared helpers: errors, files, output and TSV parsing.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// An xtask failure.
#[derive(Debug)]
pub(crate) enum Error {
    /// The command line is not valid. The exit status is 2.
    Usage(String),
    /// The task failed. The exit status is 1.
    Failed(String),
}

impl Error {
    /// Makes a task failure.
    pub(crate) fn msg(s: impl Into<String>) -> Self {
        Self::Failed(s.into())
    }

    /// Makes a usage error.
    pub(crate) fn usage(s: impl Into<String>) -> Self {
        Self::Usage(s.into())
    }

    /// Makes a task failure for an I/O error on a path.
    pub(crate) fn io(path: &Path, e: &std::io::Error) -> Self {
        Self::Failed(format!("{}: {e}", path.display()))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(s) | Self::Failed(s) => f.write_str(s),
        }
    }
}

/// The ASF license header for files with `#` comments.
const LICENSE: &str = "\
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
\"License\"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an \"AS IS\" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
";

/// Returns the license header with a `#` prefix on each line.
pub(crate) fn tsv_license() -> String {
    comment_license("#")
}

/// Returns the license header with `prefix` on each line.
pub(crate) fn comment_license(prefix: &str) -> String {
    let mut s = String::new();
    for l in LICENSE.lines() {
        if l.is_empty() {
            s.push_str(prefix);
        } else {
            s.push_str(prefix);
            s.push(' ');
            s.push_str(l);
        }
        s.push('\n');
    }
    s.push('\n');
    s
}

/// Reads a text file.
pub(crate) fn read(path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|e| Error::io(path, &e))
}

/// Reads a binary file.
pub(crate) fn read_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|e| Error::io(path, &e))
}

/// Writes a text file.
pub(crate) fn write(path: &Path, text: &str) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, &e))?;
    }
    std::fs::write(path, text).map_err(|e| Error::io(path, &e))
}

/// Returns a path for messages.
pub(crate) fn rel(path: &Path) -> String {
    path.display().to_string()
}

/// Writes text to standard output.
pub(crate) fn out(s: &str) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(s.as_bytes());
    let _ = o.flush();
}

/// Writes text to standard error.
pub(crate) fn err(s: &str) {
    let mut o = std::io::stderr().lock();
    let _ = o.write_all(s.as_bytes());
}

/// Returns the value after an option.
pub(crate) fn value<'a>(
    it: &mut impl Iterator<Item = &'a String>,
    opt: &str,
) -> Result<&'a str, Error> {
    it.next()
        .map(String::as_str)
        .ok_or_else(|| Error::usage(format!("{opt} needs a value")))
}

/// Returns the Cargo workspace directory.
pub(crate) fn workspace_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf)
}

/// Returns the legacy C tree, `zookeeper-client-c`. It holds the legacy
/// headers, sources and tests.
pub(crate) fn c_client_dir() -> PathBuf {
    workspace_dir().join("../zookeeper-client-c")
}

/// Returns the Rust C tree, `zookeeper-client-rust/c`. It holds the shim,
/// the build files, the ABI goldens and the C tests.
pub(crate) fn rust_c_dir() -> PathBuf {
    workspace_dir().join("c")
}

/// Returns the commit of the C sources, with `+dirty` when the library
/// sources differ from it.
pub(crate) fn git_head(c_dir: &Path) -> String {
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(c_dir)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    let Some(head) = run(&["rev-parse", "HEAD"]) else {
        return "unknown".to_owned();
    };
    let dirty = run(&["status", "--porcelain", "--", "src", "include", "generated"])
        .is_some_and(|s| !s.is_empty());
    if dirty { format!("{head}+dirty") } else { head }
}

/// Splits a TSV file into rows. Lines that start with `#` and empty lines
/// are skipped. The first other line must be the column header.
pub(crate) fn tsv_rows<'a>(
    text: &'a str,
    header: &str,
) -> Result<Vec<(usize, Vec<&'a str>)>, Error> {
    let mut rows = Vec::new();
    let mut seen_header = false;
    for (i, line) in text.lines().enumerate() {
        let n = i.saturating_add(1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !seen_header {
            if line != header {
                return Err(Error::msg(format!(
                    "line {n}: expected the column header `{header}`"
                )));
            }
            seen_header = true;
            continue;
        }
        rows.push((n, line.split('\t').collect()));
    }
    if seen_header {
        Ok(rows)
    } else {
        Err(Error::msg("no column header".to_owned()))
    }
}
