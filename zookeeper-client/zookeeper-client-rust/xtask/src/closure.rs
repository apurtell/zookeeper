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

//! The dependency closure inventories: `cargo xtask closure update` and
//! `cargo xtask closure check`.
//!
//! An inventory lists each crate that one shipped package resolves for one
//! target and one feature set. `cargo tree` gives the crates, with the
//! feature resolution of a `cargo build -p` of the package. `Cargo.lock`
//! gives the source of each crate. Dev-dependencies are not in a closure.
//!
//! A `target` crate compiles into the shipped artifact. A `host` crate
//! runs only during the build, as a build script or a procedural macro.
//!
//! The task also applies the dependency rules of the specification to
//! each closure. A closure that breaks a rule stops both subcommands.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{self, Error};

/// The supported targets of the three tiers, without Windows. Keep this
/// list equal to `graph.targets` in deny.toml and deny-fips.toml.
const TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "i686-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "s390x-unknown-linux-gnu",
    "armv7-unknown-linux-gnueabihf",
    "x86_64-unknown-freebsd",
];

/// The kind of library that a configuration builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    /// The C drop-in libraries, from `zk-ffi`.
    DropIn,
    /// The native Rust client and the recipes.
    Native,
}

/// One build configuration of one shipped package.
#[derive(Debug)]
struct Config {
    /// The file stem of the inventory.
    name: &'static str,
    /// The Cargo package name.
    package: &'static str,
    /// True when the build keeps the default features.
    default_features: bool,
    /// The features, separated by commas, or empty.
    features: &'static str,
    /// The library kind.
    family: Family,
}

/// The configurations of the shipped libraries. The drop-in entries use
/// the feature lists that Autotools and CMake pass to Cargo: one optional
/// TLS provider and an optional `sasl`.
const CONFIGS: &[Config] = &[
    Config {
        name: "dropin-plain",
        package: "zk-ffi",
        default_features: true,
        features: "",
        family: Family::DropIn,
    },
    Config {
        name: "dropin-sasl",
        package: "zk-ffi",
        default_features: true,
        features: "sasl",
        family: Family::DropIn,
    },
    Config {
        name: "dropin-tls-ring",
        package: "zk-ffi",
        default_features: true,
        features: "tls-ring",
        family: Family::DropIn,
    },
    Config {
        name: "dropin-tls-aws-lc-rs",
        package: "zk-ffi",
        default_features: true,
        features: "tls-aws-lc-rs",
        family: Family::DropIn,
    },
    Config {
        name: "dropin-tls-aws-lc-rs-fips",
        package: "zk-ffi",
        default_features: true,
        features: "tls-aws-lc-rs-fips",
        family: Family::DropIn,
    },
    Config {
        name: "dropin-full",
        package: "zk-ffi",
        default_features: true,
        features: "tls-ring,sasl",
        family: Family::DropIn,
    },
    Config {
        name: "dropin-full-aws-lc-rs",
        package: "zk-ffi",
        default_features: true,
        features: "tls-aws-lc-rs,sasl",
        family: Family::DropIn,
    },
    Config {
        name: "dropin-full-aws-lc-rs-fips",
        package: "zk-ffi",
        default_features: true,
        features: "tls-aws-lc-rs-fips,sasl",
        family: Family::DropIn,
    },
    Config {
        name: "native-minimal",
        package: "apache-zookeeper",
        default_features: false,
        features: "",
        family: Family::Native,
    },
    Config {
        name: "native-default",
        package: "apache-zookeeper",
        default_features: true,
        features: "",
        family: Family::Native,
    },
    Config {
        name: "native-tls-ring",
        package: "apache-zookeeper",
        default_features: true,
        features: "tls-ring",
        family: Family::Native,
    },
    Config {
        name: "native-tls-aws-lc-rs",
        package: "apache-zookeeper",
        default_features: true,
        features: "tls-aws-lc-rs",
        family: Family::Native,
    },
    Config {
        name: "native-tls-aws-lc-rs-fips",
        package: "apache-zookeeper",
        default_features: true,
        features: "tls-aws-lc-rs-fips",
        family: Family::Native,
    },
    Config {
        name: "native-sasl",
        package: "apache-zookeeper",
        default_features: true,
        features: "sasl",
        family: Family::Native,
    },
    Config {
        name: "native-full",
        package: "apache-zookeeper",
        default_features: true,
        features: "blocking,log,serde,tls-ring,tls-platform-verifier,sasl-gssapi",
        family: Family::Native,
    },
    Config {
        name: "native-full-aws-lc-rs",
        package: "apache-zookeeper",
        default_features: true,
        features: "blocking,log,serde,tls-aws-lc-rs,tls-platform-verifier,sasl-gssapi",
        family: Family::Native,
    },
    Config {
        name: "recipes",
        package: "apache-zookeeper-recipes",
        default_features: true,
        features: "",
        family: Family::Native,
    },
];

/// Crates that no closure contains.
const FORBIDDEN: &[&str] = &[
    "openssl",
    "openssl-sys",
    "native-tls",
    "rustls-pemfile",
    "webpki-roots",
];

/// Test and development crates. They never enter a production closure.
const TEST_ONLY: &[&str] = &[
    "proptest",
    "proptest-state-machine",
    "arbitrary",
    "loom",
    "object",
    "serde_json",
    "ctest",
    "zk-testkit",
    "zk-fakeserver",
    "zk-xcheck",
    "xtask",
];

/// Crates that the drop-in closures never contain. The drop-in libraries
/// use no async runtime, no OS trust store and no native client code.
const NOT_DROP_IN: &[&str] = &[
    "apache-zookeeper",
    "apache-zookeeper-recipes",
    "tokio",
    "mio",
    "rustls-platform-verifier",
    "rustls-native-certs",
    "openssl-probe",
    "libgssapi",
];

/// Crates that only run during the build. They never compile into an
/// artifact.
const HOST_ONLY: &[&str] = &["cc", "cmake", "bindgen"];

/// The FIPS module. Only a FIPS feature set contains it.
const FIPS_MODULE: &str = "aws-lc-fips-sys";

/// The crates.io index, as `Cargo.lock` names it.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// The columns of an inventory.
const COLUMNS: &str = "name\tversion\tsource\tkind";

/// One crate of a closure.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Row {
    /// The package name.
    name: String,
    /// The exact version, or `workspace` for a workspace crate.
    version: String,
    /// `crates-io` or `path`.
    source: String,
    /// `target` or `host`.
    kind: String,
}

impl Row {
    /// Returns the row as one TSV line.
    fn line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.name, self.version, self.source, self.kind
        )
    }

    /// Returns the row with the version reduced to its semver-compatible
    /// series. `1.4.2` gives `1`, `0.10.3` gives `0.10`, and `0.0.7` gives
    /// `0.0.7`.
    fn compatible(&self) -> Self {
        let mut r = self.clone();
        r.version = compat_series(&self.version);
        r
    }
}

/// Returns the semver-compatible series of a version.
fn compat_series(v: &str) -> String {
    let core = v.split(['+', '-']).next().unwrap_or(v);
    let mut parts = core.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("0"), Some("0"), Some(p)) => format!("0.0.{p}"),
        (Some("0"), Some(m), _) => format!("0.{m}"),
        (Some(major), _, _) => major.to_owned(),
        (None, _, _) => v.to_owned(),
    }
}

/// The command line of a closure task.
#[derive(Debug, Default)]
struct Opts {
    /// The inventory directory.
    dir: Option<PathBuf>,
    /// Cargo configuration files that each `cargo tree` call gets, such as
    /// the crate sources of a vendor or system-crates build.
    config: Vec<PathBuf>,
    /// Passes `--offline` to Cargo.
    offline: bool,
    /// Compares semver-compatible series, not exact versions.
    semver_compatible: bool,
    /// Prints each inventory as it is done.
    verbose: bool,
}

/// Runs `closure update` or `closure check`.
pub(crate) fn run(args: &[String]) -> Result<(), Error> {
    let (sub, rest) = args
        .split_first()
        .ok_or_else(|| Error::usage("closure needs update or check".to_owned()))?;
    let mut opts = Opts::default();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => opts.dir = Some(PathBuf::from(util::value(&mut it, a)?)),
            "--config" => {
                // Cargo runs in the workspace directory, so a relative path
                // must not depend on it.
                let p = PathBuf::from(util::value(&mut it, a)?);
                let p = std::path::absolute(&p).map_err(|e| Error::io(&p, &e))?;
                opts.config.push(p);
            }
            "--offline" => opts.offline = true,
            "--semver-compatible" => opts.semver_compatible = true,
            "--verbose" => opts.verbose = true,
            other => return Err(Error::usage(format!("closure: unknown option {other}"))),
        }
    }
    let ws = util::workspace_dir();
    let dir = opts
        .dir
        .clone()
        .unwrap_or_else(|| ws.join("supply-chain/closure"));
    match sub.as_str() {
        "update" => {
            if opts.semver_compatible {
                return Err(Error::usage(
                    "closure update writes exact versions; --semver-compatible applies to check"
                        .to_owned(),
                ));
            }
            update(&ws, &dir, &opts)
        }
        "check" => check(&ws, &dir, &opts),
        other => Err(Error::usage(format!("closure: unknown subcommand {other}"))),
    }
}

/// One generated inventory.
struct Inventory {
    /// The file, relative to the inventory directory.
    rel: PathBuf,
    /// The rows in file order.
    rows: Vec<Row>,
    /// The file text.
    text: String,
}

/// Resolves all inventories and applies the dependency rules.
fn generate(ws: &Path, opts: &Opts) -> Result<Vec<Inventory>, Error> {
    let lock = lock_sources(&util::read(&ws.join("Cargo.lock"))?)?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut out = Vec::new();
    let mut problems = Vec::new();
    for target in TARGETS {
        for cfg in CONFIGS {
            let rows = resolve(&cargo, ws, cfg, target, &lock, opts)?;
            for p in rule_problems(cfg, &rows) {
                problems.push(format!("{target}/{}: {p}", cfg.name));
            }
            let rel = Path::new(target).join(format!("{}.tsv", cfg.name));
            let text = render(cfg, target, &rows);
            if opts.verbose {
                util::err(&format!(
                    "closure: {} has {} crates\n",
                    rel.display(),
                    rows.len()
                ));
            }
            out.push(Inventory { rel, rows, text });
        }
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(Error::msg(format!(
            "the closures break the dependency rules:\n  {}",
            problems.join("\n  ")
        )))
    }
}

/// Writes all inventories and removes inventories of retired
/// configurations.
fn update(ws: &Path, dir: &Path, opts: &Opts) -> Result<(), Error> {
    let inv = generate(ws, opts)?;
    let wanted: BTreeSet<PathBuf> = inv.iter().map(|i| i.rel.clone()).collect();
    for rel in existing(dir)? {
        if !wanted.contains(&rel) {
            let p = dir.join(&rel);
            std::fs::remove_file(&p).map_err(|e| Error::io(&p, &e))?;
        }
    }
    for i in &inv {
        util::write(&dir.join(&i.rel), &i.text)?;
    }
    util::out(&format!(
        "closure: wrote {} inventories to {}\n",
        inv.len(),
        util::rel(dir)
    ));
    Ok(())
}

/// Compares the committed inventories with a new resolution.
fn check(ws: &Path, dir: &Path, opts: &Opts) -> Result<(), Error> {
    let inv = generate(ws, opts)?;
    let mut drift = Vec::new();
    let wanted: BTreeSet<PathBuf> = inv.iter().map(|i| i.rel.clone()).collect();
    for rel in existing(dir)? {
        if !wanted.contains(&rel) {
            drift.push(format!(
                "{}: no configuration makes this file",
                rel.display()
            ));
        }
    }
    for i in &inv {
        let path = dir.join(&i.rel);
        if !path.exists() {
            drift.push(format!("{}: the file is missing", i.rel.display()));
            continue;
        }
        let text = util::read(&path)?;
        if !opts.semver_compatible && text == i.text {
            continue;
        }
        let old = match parse(&text) {
            Ok(rows) => rows,
            Err(e) => {
                drift.push(format!("{}: {e}", i.rel.display()));
                continue;
            }
        };
        let (old, new): (BTreeSet<Row>, BTreeSet<Row>) = if opts.semver_compatible {
            (
                old.iter().map(Row::compatible).collect(),
                i.rows.iter().map(Row::compatible).collect(),
            )
        } else {
            (old.into_iter().collect(), i.rows.iter().cloned().collect())
        };
        let mut lines = Vec::new();
        for r in old.difference(&new) {
            lines.push(format!("    - {}", r.line().replace('\t', " ")));
        }
        for r in new.difference(&old) {
            lines.push(format!("    + {}", r.line().replace('\t', " ")));
        }
        if lines.is_empty() {
            if !opts.semver_compatible {
                drift.push(format!(
                    "{}: the rows match, but the comments or the row order differ",
                    i.rel.display()
                ));
            }
        } else {
            drift.push(format!("{}:\n{}", i.rel.display(), lines.join("\n")));
        }
    }
    if drift.is_empty() {
        util::out(&format!(
            "closure: {} inventories match {}\n",
            inv.len(),
            util::rel(dir)
        ));
        Ok(())
    } else {
        Err(Error::msg(format!(
            "the dependency closures differ from {}:\n  {}\nReview the change. Then run `cargo xtask closure update` and commit the result.",
            util::rel(dir),
            drift.join("\n  ")
        )))
    }
}

/// Lists the inventory files under `dir`, relative to `dir`.
fn existing(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut out = Vec::new();
    let Ok(targets) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for t in targets {
        let t = t.map_err(|e| Error::io(dir, &e))?;
        let tpath = t.path();
        if !tpath.is_dir() {
            continue;
        }
        let files = std::fs::read_dir(&tpath).map_err(|e| Error::io(&tpath, &e))?;
        for f in files {
            let f = f.map_err(|e| Error::io(&tpath, &e))?;
            let fpath = f.path();
            if fpath.extension().is_some_and(|x| x == "tsv") {
                out.push(Path::new(&t.file_name()).join(f.file_name()));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Maps each `(name, version)` in `Cargo.lock` to its source. A package
/// without a source line is a path package.
fn lock_sources(text: &str) -> Result<BTreeMap<(String, String), Option<String>>, Error> {
    /// The fields of one `[[package]]` table.
    #[derive(Default)]
    struct Pkg {
        name: Option<String>,
        version: Option<String>,
        source: Option<String>,
    }
    fn field(line: &str, key: &str) -> Option<String> {
        let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
        let v = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
        Some(v.to_owned())
    }
    let mut out = BTreeMap::new();
    let mut cur: Option<Pkg> = None;
    let mut flush = |p: Option<Pkg>| -> Result<(), Error> {
        if let Some(p) = p {
            match (p.name, p.version) {
                (Some(n), Some(v)) => {
                    out.insert((n, v), p.source);
                }
                _ => {
                    return Err(Error::msg(
                        "Cargo.lock: a package has no name or no version".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    };
    for line in text.lines() {
        if line.starts_with('[') {
            flush(cur.take())?;
            if line == "[[package]]" {
                cur = Some(Pkg::default());
            }
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        if let Some(v) = field(line, "name") {
            p.name = Some(v);
        } else if let Some(v) = field(line, "version") {
            p.version = Some(v);
        } else if let Some(v) = field(line, "source") {
            p.source = Some(v);
        }
    }
    flush(cur.take())?;
    Ok(out)
}

/// Returns the `cargo tree` arguments that select `cfg` for `target`.
fn tree_args(cfg: &Config, target: &str, edges: &str, opts: &Opts) -> Vec<String> {
    let mut a: Vec<String> = [
        "tree",
        "--locked",
        "--package",
        cfg.package,
        "--target",
        target,
        "--edges",
        edges,
        "--prefix",
        "none",
        "--format",
        "{p}",
        "--color",
        "never",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    if opts.offline {
        a.push("--offline".to_owned());
    }
    for c in &opts.config {
        a.push("--config".to_owned());
        a.push(c.display().to_string());
    }
    if !cfg.default_features {
        a.push("--no-default-features".to_owned());
    }
    if !cfg.features.is_empty() {
        a.push("--features".to_owned());
        a.push(cfg.features.to_owned());
    }
    a
}

/// Runs `cargo tree` and returns the `(name, version)` set it prints.
fn tree(cargo: &OsString, ws: &Path, args: &[String]) -> Result<BTreeSet<(String, String)>, Error> {
    let o = Command::new(cargo)
        .current_dir(ws)
        .args(args)
        .output()
        .map_err(|e| Error::msg(format!("cannot run cargo tree: {e}")))?;
    if !o.status.success() {
        return Err(Error::msg(format!(
            "cargo {} failed:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim_end()
        )));
    }
    parse_tree(&String::from_utf8_lossy(&o.stdout))
}

/// Parses `cargo tree --prefix none --format {p}` output.
fn parse_tree(text: &str) -> Result<BTreeSet<(String, String)>, Error> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let mut w = line.split_whitespace();
        let Some(name) = w.next() else { continue };
        let version = w
            .next()
            .and_then(|v| v.strip_prefix('v'))
            .ok_or_else(|| Error::msg(format!("cargo tree: cannot parse `{line}`")))?;
        out.insert((name.to_owned(), version.to_owned()));
    }
    Ok(out)
}

/// Resolves the closure of `cfg` for `target`.
fn resolve(
    cargo: &OsString,
    ws: &Path,
    cfg: &Config,
    target: &str,
    lock: &BTreeMap<(String, String), Option<String>>,
    opts: &Opts,
) -> Result<Vec<Row>, Error> {
    let all = tree(cargo, ws, &tree_args(cfg, target, "normal,build", opts))?;
    let linked = tree(
        cargo,
        ws,
        &tree_args(cfg, target, "normal,no-proc-macro", opts),
    )?;
    let mut rows = Vec::new();
    for key in &all {
        let (name, version) = key;
        let source = lock
            .get(key)
            .ok_or_else(|| Error::msg(format!("{name} {version} is not in Cargo.lock")))?;
        let (version, source) = match source.as_deref() {
            None => ("workspace".to_owned(), "path".to_owned()),
            Some(CRATES_IO) => (version.clone(), "crates-io".to_owned()),
            Some(other) => {
                return Err(Error::msg(format!(
                    "{name} {version} comes from {other}; crates.io is the only allowed source"
                )));
            }
        };
        let kind = if linked.contains(key) {
            "target"
        } else {
            "host"
        };
        rows.push(Row {
            name: name.clone(),
            version,
            source,
            kind: kind.to_owned(),
        });
    }
    if let Some((n, v)) = linked.difference(&all).next() {
        return Err(Error::msg(format!(
            "{target}/{}: {n} {v} is linked but not in the full tree",
            cfg.name
        )));
    }
    rows.sort();
    Ok(rows)
}

/// Returns the dependency rule violations of one closure.
fn rule_problems(cfg: &Config, rows: &[Row]) -> Vec<String> {
    let mut out = Vec::new();
    let fips = cfg.features.contains("fips");
    for r in rows {
        let n = r.name.as_str();
        if FORBIDDEN.contains(&n) {
            out.push(format!("{n} is a forbidden crate"));
        }
        if TEST_ONLY.contains(&n) {
            out.push(format!("{n} is a test crate"));
        }
        if cfg.family == Family::DropIn && NOT_DROP_IN.contains(&n) {
            out.push(format!("{n} must not enter the drop-in libraries"));
        }
        if HOST_ONLY.contains(&n) && r.kind != "host" {
            out.push(format!("{n} must run only on the build host"));
        }
        if n == FIPS_MODULE && !fips {
            out.push(format!("{n} needs a FIPS feature set"));
        }
    }
    out
}

/// Returns the features that `cfg` passes to Cargo, for the file header.
fn feature_text(cfg: &Config) -> String {
    let mut s = String::new();
    if !cfg.default_features {
        s.push_str("--no-default-features");
    }
    if !cfg.features.is_empty() {
        if !s.is_empty() {
            s.push(' ');
        }
        let _ = write!(s, "--features {}", cfg.features);
    }
    if s.is_empty() {
        s.push_str("(default)");
    }
    s
}

/// Renders one inventory file.
fn render(cfg: &Config, target: &str, rows: &[Row]) -> String {
    let mut s = util::tsv_license();
    let _ = writeln!(
        s,
        "# The resolved crates of one shipped build. `cargo xtask closure update`\n\
         # writes this file, and `cargo xtask closure check` compares it.\n\
         # Do not edit it.\n\
         #\n\
         # package: {}\n\
         # features: {}\n\
         # target: {target}\n",
        cfg.package,
        feature_text(cfg)
    );
    s.push_str(COLUMNS);
    s.push('\n');
    for r in rows {
        s.push_str(&r.line());
        s.push('\n');
    }
    s
}

/// Parses an inventory file into rows.
fn parse(text: &str) -> Result<Vec<Row>, Error> {
    let mut out = Vec::new();
    for (n, cols) in util::tsv_rows(text, COLUMNS)? {
        match cols.as_slice() {
            [name, version, source, kind] => out.push(Row {
                name: (*name).to_owned(),
                version: (*version).to_owned(),
                source: (*source).to_owned(),
                kind: (*kind).to_owned(),
            }),
            _ => return Err(Error::msg(format!("line {n}: expected four columns"))),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"libc\"\nversion = \"0.2.191\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ab\"\n\n[[package]]\nname = \"zk-ffi\"\nversion = \"3.10.0\"\ndependencies = [\n \"libc\",\n]\n";

    fn row(name: &str, kind: &str) -> Row {
        Row {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source: "crates-io".to_owned(),
            kind: kind.to_owned(),
        }
    }

    fn cfg(name: &str) -> Option<&'static Config> {
        CONFIGS.iter().find(|c| c.name == name)
    }

    #[test]
    fn reads_lock_sources() {
        let m = lock_sources(LOCK).unwrap_or_default();
        assert_eq!(m.len(), 2);
        assert_eq!(
            m.get(&("libc".to_owned(), "0.2.191".to_owned())),
            Some(&Some(CRATES_IO.to_owned()))
        );
        assert_eq!(
            m.get(&("zk-ffi".to_owned(), "3.10.0".to_owned())),
            Some(&None)
        );
    }

    #[test]
    fn parses_tree_output() {
        let t = parse_tree(
            "zk-ffi v3.10.0 (/x/zk-ffi)\nlibc v0.2.191\nlibc v0.2.191 (*)\nserde_derive v1.0.1 (proc-macro)\n\n",
        );
        let t = t.unwrap_or_default();
        assert_eq!(t.len(), 3);
        assert!(t.contains(&("serde_derive".to_owned(), "1.0.1".to_owned())));
        assert!(parse_tree("garbage\n").is_err());
    }

    #[test]
    fn compatible_series() {
        assert_eq!(compat_series("1.4.2"), "1");
        assert_eq!(compat_series("0.10.3"), "0.10");
        assert_eq!(compat_series("0.0.7"), "0.0.7");
        assert_eq!(compat_series("0.11.1+wasi-snapshot-preview1"), "0.11");
        assert_eq!(compat_series("workspace"), "workspace");
    }

    #[test]
    fn render_round_trips() {
        let c = cfg("dropin-plain");
        assert!(c.is_some());
        let Some(c) = c else { return };
        let rows = vec![row("bitflags", "target"), row("cc", "host")];
        let text = render(c, "x86_64-unknown-linux-gnu", &rows);
        assert!(text.starts_with("# Licensed to the Apache Software Foundation"));
        assert_eq!(parse(&text).ok(), Some(rows));
    }

    #[test]
    fn rules_reject_bad_closures() {
        let all = (
            cfg("dropin-tls-ring"),
            cfg("native-full"),
            cfg("dropin-tls-aws-lc-rs-fips"),
            cfg("native-full-aws-lc-rs"),
        );
        assert!(all.0.is_some() && all.1.is_some() && all.2.is_some() && all.3.is_some());
        let (Some(dropin), Some(native), Some(fips), Some(native_aws)) = all else {
            return;
        };
        let good = vec![row("rustls", "target"), row("cc", "host")];
        assert!(rule_problems(dropin, &good).is_empty());
        assert_eq!(rule_problems(dropin, &[row("tokio", "target")]).len(), 1);
        assert!(rule_problems(native, &[row("tokio", "target")]).is_empty());
        assert!(rule_problems(native_aws, &[row("tokio", "target")]).is_empty());
        assert_eq!(
            rule_problems(native_aws, &[row(FIPS_MODULE, "target")]).len(),
            1
        );
        assert_eq!(
            rule_problems(native, &[row("openssl-sys", "target")]).len(),
            1
        );
        assert_eq!(rule_problems(native, &[row("proptest", "target")]).len(), 1);
        assert_eq!(rule_problems(native, &[row("cc", "target")]).len(), 1);
        assert_eq!(
            rule_problems(dropin, &[row(FIPS_MODULE, "target")]).len(),
            1
        );
        assert!(rule_problems(fips, &[row(FIPS_MODULE, "target")]).is_empty());
    }

    #[test]
    fn configurations_are_unique() {
        let names: BTreeSet<&str> = CONFIGS.iter().map(|c| c.name).collect();
        assert_eq!(names.len(), CONFIGS.len());
    }
}
