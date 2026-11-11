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

//! The build rules of the drop-in libraries.
//!
//! The CMake tests configure the C client and build nothing. A probe
//! application includes the C client with add_subdirectory() and prints
//! the usage requirements of the zookeeper target. Thus the tests see the
//! compile definitions and the link interface of an application. A host
//! without cmake skips these tests with a message.
//!
//! The other tests read the build files. The panic rule has no runtime
//! test, because no C entry point can cause a Rust panic on purpose.

#![cfg(unix)]
#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The Rust workspace.
fn ws_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// The legacy C tree. The tests configure it as a CMake project, because
/// it is the entry point of both cores.
fn c_dir() -> PathBuf {
    ws_dir()
        .join("../zookeeper-client-c")
        .canonicalize()
        .unwrap()
}

/// The Rust C tree. It holds the build modules of the Rust core.
fn rust_c_dir() -> PathBuf {
    ws_dir().join("c").canonicalize().unwrap()
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// A fresh work directory of one test.
fn work_dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ledger_e")
        .join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// The cmake program, or None with a skip message.
fn cmake() -> Option<String> {
    let exe = std::env::var("ZK_CMAKE").unwrap_or_else(|_| "cmake".to_owned());
    match Command::new(&exe).arg("--version").output() {
        Ok(o) if o.status.success() => Some(exe),
        _ => {
            eprintln!("skip: no cmake program ({exe})");
            None
        }
    }
}

/// An installation prefix: the variable, else the default when it exists.
fn prefix(var: &str, default: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => Path::new(default).is_dir().then(|| default.to_owned()),
    }
}

/// The result of one configure step.
struct Configured {
    ok: bool,
    log: String,
    defs: Vec<String>,
    libs: Vec<String>,
}

/// The list of a probe line, without the -NOTFOUND value of an unset property.
fn probe_list(log: &str, key: &str) -> Vec<String> {
    let tag = format!("ZKPROBE {key}=");
    log.lines()
        .find_map(|l| l.split_once(&tag).map(|(_, v)| v.trim().to_owned()))
        .filter(|v| !v.ends_with("-NOTFOUND"))
        .map(|v| {
            v.split(';')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Configures SOURCE in the work directory NAME with the options ARGS.
fn configure(exe: &str, name: &str, source: &Path, args: &[String]) -> Configured {
    let b = work_dir(name);
    let out = Command::new(exe)
        .arg("-S")
        .arg(source)
        .arg("-B")
        .arg(&b)
        .arg(format!("-DZK_C_SOURCE_DIR={}", c_dir().display()))
        .arg("-DWANT_CPPUNIT=OFF")
        .args(args)
        .output()
        .unwrap();
    let mut log = String::from_utf8_lossy(&out.stdout).into_owned();
    log.push_str(&String::from_utf8_lossy(&out.stderr));
    fs::write(b.join("configure.log"), &log).unwrap();
    Configured {
        ok: out.status.success(),
        defs: probe_list(&log, "defs"),
        libs: probe_list(&log, "libs"),
        log,
    }
}

/// Configures the probe application, or gives None with a skip message
/// when the host has no crate sources. The configure step of the Rust
/// core runs `cargo fetch --locked`, which needs network access or a
/// full CARGO_HOME. Any other configure failure fails the test.
fn probe(exe: &str, name: &str, args: &[String]) -> Option<Configured> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ledger_e/cmake-probe");
    let c = configure(exe, name, &src, args);
    if !c.ok
        && c.log
            .contains("no crate source: cargo fetch --locked failed")
    {
        eprintln!("skip: {name}: no crate sources for the Rust core (cargo fetch --locked failed)");
        return None;
    }
    assert!(c.ok, "{name}: the configure step fails:\n{}", c.log);
    Some(c)
}

/// True when the find modules of the legacy build are present. The C
/// client finds Cyrus SASL only with them.
fn have_find_modules() -> bool {
    c_dir()
        .join("../../tools/cmake/Modules/FindCyrusSASL.cmake")
        .is_file()
}

/// True when an entry of the link interface names OpenSSL.
fn names_openssl(libs: &[String]) -> bool {
    libs.iter().any(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("openssl")
            || l.contains("libssl")
            || l.contains("libcrypto")
            || l == "-lssl"
            || l == "-lcrypto"
    })
}

fn has(list: &[String], item: &str) -> bool {
    list.iter().any(|s| s == item)
}

/// A TLS and SASL build of the Rust core gives the consumers both legacy
/// feature macros as PUBLIC definitions. The link interface names the
/// native libraries and never OpenSSL.
#[test]
fn abi16_rust_core_tls_sasl_public_definitions() {
    let Some(exe) = cmake() else { return };
    let ossl =
        prefix("OPENSSL_PREFIX", "/opt/homebrew/opt/openssl@3").unwrap_or_else(|| "ON".to_owned());
    let sasl =
        prefix("SASL_PREFIX", "/opt/homebrew/opt/cyrus-sasl").unwrap_or_else(|| "ON".to_owned());
    let Some(c) = probe(
        &exe,
        "rust-full",
        &[
            "-DWITH_RUST_CLIENT=ON".to_owned(),
            format!("-DWITH_OPENSSL={ossl}"),
            format!("-DWITH_CYRUS_SASL={sasl}"),
        ],
    ) else {
        return;
    };
    assert!(
        c.log
            .contains("The TLS and SASL build of the Rust client: tls=ON"),
        "the probe finds no OpenSSL:\n{}",
        c.log
    );
    assert!(has(&c.defs, "HAVE_OPENSSL_H"), "defs {:?}", c.defs);
    assert!(
        !names_openssl(&c.libs),
        "the link interface names OpenSSL: {:?}",
        c.libs
    );
    assert!(has(&c.libs, "Threads::Threads"), "libs {:?}", c.libs);
    if have_find_modules() {
        assert!(has(&c.defs, "HAVE_CYRUS_SASL_H"), "defs {:?}", c.defs);
        assert!(has(&c.libs, "CyrusSASL"), "libs {:?}", c.libs);
    } else {
        eprintln!("skip: the SASL part needs tools/cmake/Modules/FindCyrusSASL.cmake");
    }
}

/// WITH_RUST_TLS=ON builds TLS without an OpenSSL installation. The
/// consumers then also get HAVE_OPENSSL_H.
#[test]
fn abi16_rust_tls_without_openssl_defines_have_openssl_h() {
    let Some(exe) = cmake() else { return };
    let Some(c) = probe(
        &exe,
        "rust-rusttls",
        &[
            "-DWITH_RUST_CLIENT=ON".to_owned(),
            "-DWITH_RUST_TLS=ON".to_owned(),
            "-DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE".to_owned(),
            "-DWITH_CYRUS_SASL=OFF".to_owned(),
        ],
    ) else {
        return;
    };
    assert!(
        c.log.contains("WITH_RUST_TLS=ON builds SSL support"),
        "the probe finds OpenSSL, or TLS is off:\n{}",
        c.log
    );
    assert!(has(&c.defs, "HAVE_OPENSSL_H"), "defs {:?}", c.defs);
    assert!(!has(&c.defs, "HAVE_CYRUS_SASL_H"), "defs {:?}", c.defs);
    assert!(
        !names_openssl(&c.libs),
        "the link interface names OpenSSL: {:?}",
        c.libs
    );
}

/// A plain build of the Rust core defines neither feature macro.
#[test]
fn abi16_rust_core_plain_has_no_feature_definitions() {
    let Some(exe) = cmake() else { return };
    let Some(c) = probe(
        &exe,
        "rust-plain",
        &[
            "-DWITH_RUST_CLIENT=ON".to_owned(),
            "-DWITH_OPENSSL=OFF".to_owned(),
            "-DWITH_CYRUS_SASL=OFF".to_owned(),
        ],
    ) else {
        return;
    };
    assert!(!has(&c.defs, "HAVE_OPENSSL_H"), "defs {:?}", c.defs);
    assert!(!has(&c.defs, "HAVE_CYRUS_SASL_H"), "defs {:?}", c.defs);
    assert!(
        !names_openssl(&c.libs),
        "the link interface names OpenSSL: {:?}",
        c.libs
    );
}

/// The reference: the legacy core gives the same PUBLIC definitions, and
/// it links OpenSSL through the link interface.
#[test]
fn abi16_legacy_core_reference_definitions() {
    let Some(exe) = cmake() else { return };
    let Some(ossl) = prefix("OPENSSL_PREFIX", "/opt/homebrew/opt/openssl@3") else {
        eprintln!("skip: no OpenSSL prefix (set OPENSSL_PREFIX)");
        return;
    };
    let sasl =
        prefix("SASL_PREFIX", "/opt/homebrew/opt/cyrus-sasl").unwrap_or_else(|| "ON".to_owned());
    // The legacy branch does not pass WITH_OPENSSL=DIR to the probe, so
    // the test gives OPENSSL_ROOT_DIR. The legacy module path uses
    // CMAKE_SOURCE_DIR, which is the probe application here. Thus the
    // test gives the path of the Find modules, as an application must.
    let modules = c_dir().join("../../tools/cmake/Modules");
    let Some(c) = probe(
        &exe,
        "legacy-full",
        &[
            "-DWITH_RUST_CLIENT=OFF".to_owned(),
            format!("-DOPENSSL_ROOT_DIR={ossl}"),
            format!("-DWITH_CYRUS_SASL={sasl}"),
            format!("-DCMAKE_MODULE_PATH={}", modules.display()),
        ],
    ) else {
        return;
    };
    assert!(has(&c.defs, "HAVE_OPENSSL_H"), "defs {:?}", c.defs);
    assert!(has(&c.libs, "OpenSSL::SSL"), "libs {:?}", c.libs);
    if have_find_modules() {
        assert!(has(&c.defs, "HAVE_CYRUS_SASL_H"), "defs {:?}", c.defs);
    }
}

/// Writes a fake tool that prints a version line.
fn fake_tool(dir: &Path, name: &str, line: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, format!("#!/bin/sh\necho '{line}'\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// Configures the C client with fake rustc and cargo of the given versions.
fn old_toolchain(exe: &str, name: &str, mode: &str, rustc: &str, cargo: &str) -> Configured {
    let tools = work_dir(&format!("{name}-tools"));
    let r = fake_tool(
        &tools,
        "rustc",
        &format!("rustc {rustc} (0000000 2025-01-01)"),
    );
    let k = fake_tool(
        &tools,
        "cargo",
        &format!("cargo {cargo} (0000000 2025-01-01)"),
    );
    configure(
        exe,
        name,
        &c_dir(),
        &[
            format!("-DWITH_RUST_CLIENT={mode}"),
            format!("-DRUSTC_EXECUTABLE={}", r.display()),
            format!("-DCARGO_EXECUTABLE={}", k.display()),
            "-DWITH_OPENSSL=OFF".to_owned(),
            "-DWITH_CYRUS_SASL=OFF".to_owned(),
        ],
    )
}

/// With a toolchain older than Rust 1.85, AUTO selects the legacy core
/// with a notice. Both cargo and rustc must be 1.85 or later.
#[test]
fn dv_bld4_old_toolchain_auto_selects_legacy() {
    let Some(exe) = cmake() else { return };
    let notice = "-- building the legacy C client: cargo and rustc 1.85 or later not found";
    for (name, rustc, cargo) in [
        ("auto-184", "1.84.0", "1.84.0"),
        ("auto-cargo-184", "1.85.0", "1.84.1"),
    ] {
        let c = old_toolchain(&exe, name, "AUTO", rustc, cargo);
        assert!(
            c.ok,
            "{name}: AUTO must configure the legacy core:\n{}",
            c.log
        );
        assert!(c.log.contains(notice), "{name}: no notice:\n{}", c.log);
    }
}

/// With a toolchain older than Rust 1.85, WITH_RUST_CLIENT=ON stops.
#[test]
fn dv_bld4_old_toolchain_on_stops() {
    let Some(exe) = cmake() else { return };
    let c = old_toolchain(&exe, "on-184", "ON", "1.84.0", "1.84.0");
    assert!(!c.ok, "ON must stop with an old toolchain:\n{}", c.log);
    assert!(
        c.log
            .contains("WITH_RUST_CLIENT=ON: cargo and rustc 1.85 or later not found"),
        "no error message:\n{}",
        c.log
    );
}

/// The declared minimums: Rust 1.85 for the workspace, and the same 1.85
/// check in configure and in CMake. The legacy CMakeLists.txt keeps CMake
/// 3.5, and the Rust core check needs CMake 3.15.
#[test]
fn dv_bld4_declared_minimums() {
    let ws = read(&ws_dir().join("Cargo.toml"));
    assert!(
        ws.lines().any(|l| l.trim() == "rust-version = \"1.85\""),
        "the workspace does not declare rust-version 1.85"
    );
    let cm = read(&c_dir().join("CMakeLists.txt"));
    assert!(
        cm.lines()
            .any(|l| l.trim() == "cmake_minimum_required(VERSION 3.5)"),
        "CMakeLists.txt does not keep the legacy CMake 3.5 minimum"
    );
    let detect = read(&rust_c_dir().join("cmake/ZkRustDetect.cmake"));
    assert!(
        detect.contains("if(CMAKE_VERSION VERSION_LESS 3.15)")
            && detect.contains("the Rust client needs CMake 3.15 or later"),
        "ZkRustDetect.cmake does not require CMake 3.15 for the Rust core"
    );
    assert!(
        detect.contains("v1 LESS 1085 OR v2 LESS 1085"),
        "ZkRustDetect.cmake"
    );
    let m4 = read(&rust_c_dir().join("m4/zk_rust.m4"));
    assert!(
        m4.contains("test \"$zk_rust_v1\" -ge 1085 && test \"$zk_rust_v2\" -ge 1085"),
        "m4/zk_rust.m4"
    );
}

/// The lines of one table of a TOML file, up to the next table.
fn toml_table<'a>(text: &'a str, header: &str) -> Vec<&'a str> {
    text.lines()
        .skip_while(|l| l.trim() != header)
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .map(str::trim)
        .collect()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// A panic aborts the process in every build type, after std writes its
/// message to fd 2. Both C library profiles set panic = "abort", and
/// both build systems select only these profiles. The library crates
/// install no panic hook and no allocation error hook, and they use no
/// unstable feature, so a stable toolchain builds them.
#[test]
fn dv_bld5_panic_aborts_without_hook() {
    let ws = read(&ws_dir().join("Cargo.toml"));
    for t in ["[profile.capi]", "[profile.capi-dev]"] {
        let lines = toml_table(&ws, t);
        assert!(!lines.is_empty(), "no table {t}");
        assert!(
            lines.contains(&"panic = \"abort\""),
            "{t} does not abort: {lines:?}"
        );
    }
    let cmake_rust = read(&rust_c_dir().join("cmake/ZkRust.cmake"));
    assert!(
        cmake_rust.contains("set(ZKRS_PROFILE capi-dev)"),
        "ZkRust.cmake debug profile"
    );
    assert!(
        cmake_rust.contains("set(ZKRS_PROFILE capi)"),
        "ZkRust.cmake release profile"
    );
    let ac = read(&rust_c_dir().join("m4/zk_rust.m4"));
    assert!(
        ac.contains("ZKRS_PROFILE=capi\n"),
        "m4/zk_rust.m4 release profile"
    );
    assert!(
        ac.contains("ZKRS_PROFILE=capi-dev;"),
        "m4/zk_rust.m4 debug profile"
    );

    for f in ["rust-toolchain", "rust-toolchain.toml"] {
        let p = ws_dir().join(f);
        if p.exists() {
            assert!(
                !read(&p).contains("nightly"),
                "{f} selects a nightly toolchain"
            );
        }
    }
    let mut files = Vec::new();
    for c in ["zk-ffi", "zk-driver", "zk-proto", "zk-jute"] {
        rust_sources(&ws_dir().join("crates").join(c).join("src"), &mut files);
    }
    assert!(!files.is_empty());
    for f in &files {
        let text = read(f);
        for bad in [
            "panic::set_hook",
            "panic::take_hook",
            "panic::update_hook",
            "set_alloc_error_hook",
            "#![feature",
        ] {
            assert!(!text.contains(bad), "{} has {bad}", f.display());
        }
    }
}
