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

//! Builds the legacy C sources for the cross-checks.
//!
//! The build compiles the C hash table, the C address vector and the C
//! watcher tables without change. It also extracts functions from
//! `zookeeper.c` without change and compiles them with stub headers. The
//! stubs replace the parts of the client that the checks do not need.
//!
//! The extraction finds each function by its signature line and copies the
//! text up to the first `}` in column 0. A `#line` directive keeps the
//! original file and line for compiler messages. A change of a signature
//! line stops the build, so the extracts cannot drift silently.
//!
//! The build compiles the watcher table driver two times, once with signed
//! and once with unsigned C `char`. A prefix on each external name keeps the
//! two copies apart. The tests can thus compare the watcher tables with the
//! Rust port for both signednesses on one target.
//!
//! The build does nothing on targets that are not Unix, or when the C
//! sources are not present. The crate then has no C checks. When the
//! environment variable `ZKX_REQUIRE_C` is `1`, a missing C build stops the
//! build instead. Continuous integration sets this variable.

use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

type BuildResult<T> = Result<T, Box<dyn Error>>;

/// The way to find the end of an extract.
#[derive(Clone, Copy)]
enum End {
    /// Up to and with the first line that is exactly `}`.
    Function,
    /// Up to and with the first line that is exactly this text.
    Line(&'static str),
    /// Up to and with the first line that does not end with `\`.
    Macro,
}

/// One extract: a name, the first line, and the end rule.
struct Extract {
    name: &'static str,
    start: &'static str,
    end: End,
}

/// The extracts from `zookeeper.c`, in file order.
const ZOOKEEPER_C_EXTRACTS: &[Extract] = &[
    Extract {
        name: "create mode constants",
        start: "const int ZOO_PERSISTENT = 0;",
        end: End::Line("const int ZOO_PERSISTENT_SEQUENTIAL_WITH_TTL = 6;"),
    },
    Extract {
        name: "ZOOKEEPER_IS_SEQUENCE",
        start: "#define ZOOKEEPER_IS_SEQUENCE(mode) \\",
        end: End::Macro,
    },
    Extract {
        name: "getaddrinfo_errno",
        start: "static int getaddrinfo_errno(int rc) {",
        end: End::Function,
    },
    Extract {
        name: "count_hosts",
        start: "static int count_hosts(char *hosts)",
        end: End::Function,
    },
    Extract {
        name: "resolve_hosts",
        start: "static int resolve_hosts(const zhandle_t *zh, const char *hosts_in, addrvec_t *avec)",
        end: End::Function,
    },
    Extract {
        name: "update_addrs",
        start: "int update_addrs(zhandle_t *zh, const struct timeval *ref_time)",
        end: End::Function,
    },
    Extract {
        name: "get_next_server_in_reconfig",
        start: "static int get_next_server_in_reconfig(zhandle_t *zh)",
        end: End::Function,
    },
    Extract {
        name: "zoo_cycle_next_server",
        start: "void zoo_cycle_next_server(zhandle_t *zh)",
        end: End::Function,
    },
    Extract {
        name: "free_duplicate_path",
        start: "void free_duplicate_path(const char *free_path, const char* path) {",
        end: End::Function,
    },
    Extract {
        name: "prepend_string",
        start: "static char* prepend_string(zhandle_t *zh, const char* client_path) {",
        end: End::Function,
    },
    Extract {
        name: "sub_string",
        start: "char* sub_string(zhandle_t *zh, const char* server_path) {",
        end: End::Function,
    },
    Extract {
        name: "isValidPath",
        start: "static int isValidPath(const char* path, const int mode) {",
        end: End::Function,
    },
];

/// The hash function of the watcher tables, from `zk_hashtable.c`.
const DJB2_EXTRACT: Extract = Extract {
    name: "string_hash_djb2",
    start: "static unsigned int string_hash_djb2(void *str) ",
    end: End::Function,
};

/// The external names of `zkx_zt.c` and of the `zk_hashtable.c` copy that it
/// includes. Each copy of the driver gets its own prefix on these names. A
/// missing name gives a duplicate symbol at link time, so the list cannot
/// drift silently.
const ZT_EXTERNAL_NAMES: &[&str] = &[
    "zkx_zt_reset",
    "zkx_zt_set_default",
    "zkx_zt_set_chroot",
    "zkx_zt_activate",
    "zkx_zt_event",
    "zkx_dlv_get",
    "zkx_zt_has",
    "zkx_zt_remove",
    "zkx_zt_dump",
    "getImpl",
    "getFirstWatcher",
    "clone_watcher_object",
    "create_zk_hashtable",
    "destroy_zk_hashtable",
    "collect_keys",
    "collectWatchers",
    "deliverWatchers",
    "free_watcher_object_list",
    "activateWatcher",
    "deactivateWatcher",
    "removeWatchers",
    "pathHasWatcher",
];

/// Gives the name of an external symbol in the driver copy with `prefix`.
///
/// The driver names lose their `zkx_zt_` or `zkx_` part, so that
/// `zkx_zt_reset` becomes `zkx_zts_reset` for the prefix `zkx_zts_`.
fn prefixed(prefix: &str, name: &str) -> String {
    let base = name
        .strip_prefix("zkx_zt_")
        .or_else(|| name.strip_prefix("zkx_"))
        .unwrap_or(name);
    format!("{prefix}{base}")
}

/// Compiles the DJB2 extract two times, with signed and with unsigned
/// `char`, and gives the objects.
fn compile_djb2(
    gen_dir: &Path,
    zk_hashtable_c: &Path,
    djb2: &Located,
) -> BuildResult<Vec<PathBuf>> {
    let djb2_lit = c_string_literal(zk_hashtable_c);
    let mut objects = Vec::new();
    for (suffix, flag) in [("signed", "-fsigned-char"), ("unsigned", "-funsigned-char")] {
        let file = gen_dir.join(format!("zkx_djb2_{suffix}.c"));
        let text = format!(
            "#line {} \"{djb2_lit}\"\n{}\nunsigned int zkx_djb2_{suffix}(void *key)\n{{\n    return string_hash_djb2(key);\n}}\n",
            djb2.first, djb2.text
        );
        fs::write(&file, text)?;
        objects.extend(compile_intermediates(&[], &file, flag)?);
    }

    Ok(objects)
}

/// Compiles the two copies of the watcher table driver and gives the objects.
fn compile_zt_drivers(
    stub: &Path,
    csrc: &Path,
    gen_dir: &Path,
    c_src: &Path,
) -> BuildResult<Vec<PathBuf>> {
    let zt_lit = c_string_literal(&csrc.join("zkx_zt.c"));
    let mut objects = Vec::new();
    for (prefix, flag) in [
        ("zkx_zts_", "-fsigned-char"),
        ("zkx_ztu_", "-funsigned-char"),
    ] {
        let mut text = String::new();
        for name in ZT_EXTERNAL_NAMES {
            writeln!(text, "#define {name} {}", prefixed(prefix, name))?;
        }
        writeln!(text, "#include \"{zt_lit}\"")?;
        let file = gen_dir.join(format!("{prefix}driver.c"));
        fs::write(&file, text)?;
        let includes = [stub, csrc, gen_dir, c_src];
        objects.extend(compile_intermediates(&includes, &file, flag)?);
    }
    Ok(objects)
}

/// Compiles one generated file with the `char` signedness flag `flag`,
/// and gives the objects. The include directories keep their order.
fn compile_intermediates(includes: &[&Path], file: &Path, flag: &str) -> BuildResult<Vec<PathBuf>> {
    cc::Build::new()
        .includes(includes)
        .file(file)
        .flag(flag)
        .warnings(false)
        .cargo_metadata(false)
        .try_compile_intermediates()
        .map_err(Into::into)
}

/// A located extract: the text and the 1-based first and last lines.
struct Located {
    text: String,
    first: usize,
    last: usize,
}

fn locate(source: &str, file: &str, ex: &Extract) -> BuildResult<Located> {
    let lines: Vec<&str> = source.lines().collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| **l == ex.start)
        .map(|(i, _)| i)
        .collect();
    let start = match starts.as_slice() {
        [one] => *one,
        [] => return Err(format!("{file}: no line for extract {}", ex.name).into()),
        _ => return Err(format!("{file}: more than one line for extract {}", ex.name).into()),
    };
    let mut end = None;
    for (i, line) in lines.iter().enumerate().skip(start) {
        let done = match ex.end {
            End::Function => *line == "}",
            End::Line(text) => *line == text,
            End::Macro => !line.ends_with('\\'),
        };
        if done {
            end = Some(i);
            break;
        }
    }
    let end = end.ok_or_else(|| format!("{file}: no end for extract {}", ex.name))?;
    // The range is never empty, because the end line is at or after the
    // start line.
    let mut text = lines.get(start..=end).unwrap_or_default().join("\n");
    text.push('\n');
    Ok(Located {
        text,
        first: start.saturating_add(1),
        last: end.saturating_add(1),
    })
}

fn c_string_literal(path: &Path) -> String {
    let s = path.display().to_string();
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() -> BuildResult<()> {
    println!("cargo::rustc-check-cfg=cfg(zkx_c)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=csrc");
    println!("cargo::rerun-if-env-changed=ZKX_C_SRC");
    println!("cargo::rerun-if-env-changed=ZKX_REQUIRE_C");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out = PathBuf::from(env::var("OUT_DIR")?);
    let manifest_rs = out.join("extract_manifest.rs");

    let c_src = match env::var_os("ZKX_C_SRC") {
        Some(p) => PathBuf::from(p),
        None => manifest.join("../../../zookeeper-client-c/src"),
    };
    let is_unix = env::var_os("CARGO_CFG_UNIX").is_some();
    if !is_unix || !c_src.join("zookeeper.c").is_file() {
        if env::var("ZKX_REQUIRE_C").as_deref() == Ok("1") {
            return Err(format!(
                "zk-xcheck: ZKX_REQUIRE_C=1, but the C sources at {} cannot be built on this target",
                c_src.display()
            )
            .into());
        }
        println!("cargo::warning=zk-xcheck: C sources not built; the C cross-checks are off");
        fs::write(
            &manifest_rs,
            "/// The extracts from `zookeeper.c`. The list is empty because the C sources are not built.\n\
             pub const ZOOKEEPER_C_EXTRACTS: &[(&str, usize, usize)] = &[];\n",
        )?;
        return Ok(());
    }

    let zookeeper_c = c_src.join("zookeeper.c");
    let zk_hashtable_c = c_src.join("zk_hashtable.c");
    for f in [
        &zookeeper_c,
        &zk_hashtable_c,
        &c_src.join("addrvec.c"),
        &c_src.join("addrvec.h"),
        &c_src.join("zk_hashtable.h"),
        &c_src.join("hashtable"),
    ] {
        println!("cargo::rerun-if-changed={}", f.display());
    }

    let gen_dir = out.join("zkx");
    fs::create_dir_all(&gen_dir)?;

    // The copy keeps zk_hashtable.c away from the real zk_adaptor.h, which
    // a quoted include would find next to the original file.
    let zk_hashtable = fs::read_to_string(&zk_hashtable_c)?;
    fs::write(gen_dir.join("zk_hashtable.c"), &zk_hashtable)?;

    let source = fs::read_to_string(&zookeeper_c)?;
    let mut unit = String::from("#include \"zkx_extract_prelude.h\"\n\n");
    let mut rs = String::from(
        "/// The extracts from `zookeeper.c`: the name, the first line and the last line.\n\
         pub const ZOOKEEPER_C_EXTRACTS: &[(&str, usize, usize)] = &[\n",
    );
    let lit = c_string_literal(&zookeeper_c);
    for ex in ZOOKEEPER_C_EXTRACTS {
        let found = locate(&source, "zookeeper.c", ex)?;
        writeln!(
            unit,
            "/* zookeeper.c lines {}-{}: {} */",
            found.first, found.last, ex.name
        )?;
        writeln!(unit, "#line {} \"{lit}\"", found.first)?;
        unit.push_str(&found.text);
        unit.push('\n');
        writeln!(rs, "    ({:?}, {}, {}),", ex.name, found.first, found.last)?;
    }
    rs.push_str("];\n");
    unit.push_str("#include \"zkx_extract_tail.inc\"\n");
    fs::write(gen_dir.join("zookeeper_extract.c"), unit)?;

    let djb2 = locate(&zk_hashtable, "zk_hashtable.c", &DJB2_EXTRACT)?;
    writeln!(
        rs,
        "/// The extract of `string_hash_djb2` from `zk_hashtable.c`: the first line and the last line.\n\
         pub const DJB2_EXTRACT: (usize, usize) = ({}, {});",
        djb2.first, djb2.last
    )?;
    fs::write(&manifest_rs, rs)?;

    let mut objects = compile_djb2(&gen_dir, &zk_hashtable_c, &djb2)?;

    let stub = manifest.join("csrc/stub");
    let csrc = manifest.join("csrc");
    objects.extend(compile_zt_drivers(&stub, &csrc, &gen_dir, &c_src)?);

    let mut build = cc::Build::new();
    build
        .include(&stub)
        .include(&csrc)
        .include(&gen_dir)
        .include(&c_src)
        // addrvec_shuffle() draws from the harness feed.
        .define("random", "zkx_random")
        .warnings(false)
        .file(c_src.join("hashtable/hashtable.c"))
        .file(c_src.join("hashtable/hashtable_itr.c"))
        .file(c_src.join("addrvec.c"))
        .file(gen_dir.join("zookeeper_extract.c"))
        .file(csrc.join("zkx_harness.c"))
        .objects(objects);
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        build.define("_GNU_SOURCE", None);
    }
    build.try_compile("zkx_c")?;
    println!("cargo::rustc-cfg=zkx_c");
    Ok(())
}
