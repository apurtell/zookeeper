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

//! `cargo xtask log-sites`: the pinned table of legacy log sites.
//!
//! The generator reads the legacy library sources and writes one row for
//! each `LOG_ERROR`, `LOG_WARN`, `LOG_INFO` and `LOG_DEBUG` call and for
//! each `handle_socket_error_msg` call. The check mode compares the table
//! with the hand-written `LogSite` table of zk-proto and lists each
//! difference. It reads the zk-proto source as text, so xtask builds no
//! library crate.
//!
//! A row has two lines. `line` is the line of the macro name, which zk-proto
//! pins. `line_end` is the line of the closing parenthesis. Clang expands
//! `__LINE__` in a macro call to that line, so a clang build prints it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::clex::{self, FuncTracker, Kind, Token};
use crate::util::{Error, read, rel, tsv_rows};

/// The text that `handle_socket_error_msg` puts before the site format.
const SOCKET_PREFIX: &str = "Socket %s zk retcode=%d, errno=%d(%s): ";

/// One log site of the legacy sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Site {
    /// `<func>#<n>`, where `n` counts the sites of the function from 1.
    pub(crate) id: String,
    /// The file, relative to `zookeeper-client-c`.
    pub(crate) file: String,
    /// The line of the macro name or of the `__LINE__` argument.
    pub(crate) line: u32,
    /// The line of the closing parenthesis of a macro call.
    pub(crate) line_end: u32,
    /// The enclosing function.
    pub(crate) func: String,
    /// `ERROR`, `WARN`, `INFO` or `DEBUG`.
    pub(crate) level: String,
    /// The format, with C escape sequences as in the source.
    pub(crate) format: String,
    /// The conversion specifications of the format.
    pub(crate) convs: String,
    /// The conditional compilation context, or `-`.
    pub(crate) cond: String,
}

/// The column names of `tests/abi/log-sites.tsv`.
const COLUMNS: &str = "site_id\tfile\tline\tline_end\tfunc\tlevel\tformat\tconvs\tcond";

/// Returns the library sources of the legacy core, relative to `c_dir`.
fn library_sources(c_dir: &Path) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for dir in ["src", "src/hashtable"] {
        let mut names = Vec::new();
        for e in std::fs::read_dir(c_dir.join(dir)).map_err(|e| Error::io(&c_dir.join(dir), &e))? {
            let e = e.map_err(|e| Error::io(&c_dir.join(dir), &e))?;
            let name = e.file_name().to_string_lossy().into_owned();
            let is_src = name.ends_with(".c") || name.ends_with(".h");
            // cli.c and load_gen.c are programs, not library code.
            if is_src && name != "cli.c" && name != "load_gen.c" {
                names.push(format!("{dir}/{name}"));
            }
        }
        names.sort();
        out.append(&mut names);
    }
    out.push("generated/zookeeper.jute.c".to_owned());
    Ok(out)
}

/// Extracts the log sites of the legacy library sources.
pub(crate) fn extract(c_dir: &Path) -> Result<Vec<Site>, Error> {
    let mut sites = Vec::new();
    for file in library_sources(c_dir)? {
        let src = read(&c_dir.join(&file))?;
        extract_file(&file, &src, &mut sites)?;
    }
    Ok(sites)
}

/// Extracts the log sites of one file.
fn extract_file(file: &str, src: &str, out: &mut Vec<Site>) -> Result<(), Error> {
    let lx = clex::lex(src);
    let toks = &lx.tokens;
    let mut ft = FuncTracker::default();
    let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for (i, t) in toks.iter().enumerate() {
        let func = ft.feed(t).map(str::to_owned);
        if t.kind != Kind::Ident {
            continue;
        }
        let level = match t.text.as_str() {
            "LOG_ERROR" => "ERROR",
            "LOG_WARN" => "WARN",
            "LOG_INFO" => "INFO",
            "LOG_DEBUG" => "DEBUG",
            "handle_socket_error_msg" => "SOCKET",
            _ => continue,
        };
        let open = i.saturating_add(1);
        if !toks.get(open).is_some_and(|t| t.is_punct('(')) {
            continue;
        }
        let Some((args, close)) = clex::call_args(toks, open) else {
            return Err(Error::msg(format!("{file}:{}: unbalanced call", t.line)));
        };
        let (line, line_end, fmt_arg, prefix) = if level == "SOCKET" {
            // The definition and the prototype pass `line`, not `__LINE__`.
            let Some(line_tok) = args
                .get(1)
                .and_then(|r| toks.get(r.clone()))
                .and_then(<[Token]>::first)
            else {
                continue;
            };
            if !line_tok.is_ident("__LINE__") {
                continue;
            }
            (line_tok.line, line_tok.line, args.get(4), SOCKET_PREFIX)
        } else {
            let end = toks.get(close).map_or(t.line, |c| c.line);
            (t.line, end, args.get(1), "")
        };
        let Some(func) = func else {
            return Err(Error::msg(format!(
                "{file}:{line}: log site outside a function"
            )));
        };
        let fmt_toks = fmt_arg
            .and_then(|r| toks.get(r.clone()))
            .unwrap_or_default();
        let format = format!("{prefix}{}", format_text(fmt_toks));
        let n = counts.entry(func.clone()).or_insert(0);
        *n = n.saturating_add(1);
        let cond = lx.cond_of(t);
        out.push(Site {
            id: format!("{func}#{n}"),
            file: file.to_owned(),
            line,
            line_end,
            func,
            level: if level == "SOCKET" { "ERROR" } else { level }.to_owned(),
            convs: conversions(&format).join(","),
            format,
            cond: if cond.is_empty() {
                "-".to_owned()
            } else {
                cond.to_owned()
            },
        });
    }
    Ok(())
}

/// Returns the text of a format argument. Adjacent literals are joined.
/// A macro name between literals, such as `PRId64`, appears as `{NAME}`.
/// A format that is not a literal appears as `<expr>`.
fn format_text(toks: &[Token]) -> String {
    let mut out = String::new();
    if toks
        .iter()
        .all(|t| t.kind == Kind::Str || t.kind == Kind::Ident)
        && toks.iter().any(|t| t.kind == Kind::Str)
    {
        for t in toks {
            if t.kind == Kind::Str {
                out.push_str(&t.text);
            } else {
                let _ = write!(out, "{{{}}}", t.text);
            }
        }
    } else {
        let expr: Vec<&str> = toks.iter().map(|t| t.text.as_str()).collect();
        let _ = write!(out, "<{}>", expr.join(""));
    }
    out
}

/// Returns the printf conversion specifications of a format.
fn conversions(fmt: &str) -> Vec<String> {
    let b = fmt.as_bytes();
    let mut out = Vec::new();
    let mut i = 0_usize;
    while let Some(&c) = b.get(i) {
        i = i.saturating_add(1);
        if c != b'%' {
            continue;
        }
        if b.get(i) == Some(&b'%') {
            i = i.saturating_add(1);
            continue;
        }
        let start = i.saturating_sub(1);
        while b.get(i).is_some_and(|c| b"-+ #0".contains(c)) {
            i = i.saturating_add(1);
        }
        while b
            .get(i)
            .is_some_and(|c| c.is_ascii_digit() || *c == b'*' || *c == b'.')
        {
            i = i.saturating_add(1);
        }
        while b.get(i).is_some_and(|c| b"hlLqjzt".contains(c)) {
            i = i.saturating_add(1);
        }
        if b.get(i) == Some(&b'{') {
            // A macro such as PRId64 gives the length and the conversion.
            while b.get(i).is_some_and(|c| *c != b'}') {
                i = i.saturating_add(1);
            }
        }
        i = i.saturating_add(1);
        out.push(
            String::from_utf8_lossy(b.get(start..i.min(b.len())).unwrap_or_default()).into_owned(),
        );
    }
    out
}

/// Renders the table.
pub(crate) fn render(sites: &[Site], pin: &str) -> String {
    let mut s = String::new();
    s.push_str(&crate::util::tsv_license());
    let _ = writeln!(
        s,
        "# Log sites of the legacy C core. Generated by `cargo xtask log-sites`. Do not edit."
    );
    let _ = writeln!(s, "# Source commit: {pin}");
    let _ = writeln!(
        s,
        "# line is the line of the LOG_* macro name or of the __LINE__ argument."
    );
    let _ = writeln!(
        s,
        "# line_end is the line of the closing parenthesis; clang expands __LINE__ to it."
    );
    let _ = writeln!(
        s,
        "# format keeps the C escape sequences; {{NAME}} is a macro between literals."
    );
    let _ = writeln!(s, "{COLUMNS}");
    for x in sites {
        let _ = writeln!(
            s,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            x.id,
            x.file,
            x.line,
            x.line_end,
            x.func,
            x.level,
            x.format,
            if x.convs.is_empty() { "-" } else { &x.convs },
            x.cond
        );
    }
    s
}

/// Parses the table.
pub(crate) fn parse(text: &str) -> Result<Vec<Site>, Error> {
    let mut out = Vec::new();
    for (n, cols) in tsv_rows(text, COLUMNS)? {
        let [id, file, line, line_end, func, level, format, convs, cond] = cols.as_slice() else {
            return Err(Error::msg(format!("log-sites.tsv:{n}: expected 9 columns")));
        };
        let num = |s: &str| {
            s.parse::<u32>()
                .map_err(|_| Error::msg(format!("log-sites.tsv:{n}: bad line {s}")))
        };
        out.push(Site {
            id: (*id).to_owned(),
            file: (*file).to_owned(),
            line: num(line)?,
            line_end: num(line_end)?,
            func: (*func).to_owned(),
            level: (*level).to_owned(),
            format: (*format).to_owned(),
            convs: if *convs == "-" {
                String::new()
            } else {
                (*convs).to_owned()
            },
            cond: (*cond).to_owned(),
        });
    }
    Ok(out)
}

/// One site of the zk-proto `LogSite` table.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProtoSite {
    name: String,
    level: String,
    file: String,
    func: String,
    line: u32,
    /// The format after Rust unescaping.
    format: Vec<u8>,
}

/// Parses the `log_sites!` invocation of `zk-proto/src/log.rs`.
pub(crate) fn parse_proto(src: &str) -> Result<Vec<ProtoSite>, Error> {
    let body = src
        .split_once("log_sites! {")
        .map(|(_, b)| b)
        .ok_or_else(|| Error::msg("zk-proto log.rs: no `log_sites! {` invocation".to_owned()))?;
    let body = body.split_once("\n}").map_or(body, |(b, _)| b);
    let mut out = Vec::new();
    for (n, l) in body.lines().enumerate() {
        let l = l.trim();
        if l.is_empty() || l.starts_with("//") {
            continue;
        }
        let site = parse_proto_line(l).ok_or_else(|| {
            Error::msg(format!(
                "zk-proto log.rs: cannot parse site line {}: {l}",
                n.saturating_add(1)
            ))
        })?;
        out.push(site);
    }
    Ok(out)
}

/// Parses `Name => (Level, "file", "func", line, "fmt");`.
fn parse_proto_line(l: &str) -> Option<ProtoSite> {
    let (name, rest) = l.split_once("=>")?;
    let rest = rest.trim().strip_prefix('(')?;
    let (level, rest) = rest.split_once(',')?;
    let (file, rest) = rust_str(rest.trim())?;
    let rest = rest.trim().strip_prefix(',')?;
    let (func, rest) = rust_str(rest.trim())?;
    let rest = rest.trim().strip_prefix(',')?;
    let (line, rest) = rest.split_once(',')?;
    let (format, rest) = rust_str(rest.trim())?;
    if rest.trim() != ");" {
        return None;
    }
    Some(ProtoSite {
        name: name.trim().to_owned(),
        level: level.trim().to_ascii_uppercase(),
        file: String::from_utf8_lossy(&file).into_owned(),
        func: String::from_utf8_lossy(&func).into_owned(),
        line: line.trim().parse().ok()?,
        format,
    })
}

/// Reads a Rust string literal at the start of `s`. Returns the value and
/// the rest of `s`.
fn rust_str(s: &str) -> Option<(Vec<u8>, &str)> {
    let body = s.strip_prefix('"')?;
    let mut out = Vec::new();
    let mut it = body.char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '"' => return Some((out, body.get(i.saturating_add(1)..)?)),
            '\\' => {
                let (_, e) = it.next()?;
                match e {
                    'n' => out.push(b'\n'),
                    't' => out.push(b'\t'),
                    'r' => out.push(b'\r'),
                    '0' => out.push(0),
                    '\\' | '"' | '\'' => out.push(u8::try_from(e).ok()?),
                    'x' => {
                        let h: String = [it.next()?.1, it.next()?.1].iter().collect();
                        out.push(u8::from_str_radix(&h, 16).ok()?);
                    }
                    _ => return None,
                }
            }
            _ => {
                let mut buf = [0_u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    None
}

/// Returns the bytes of a C string literal body.
fn c_unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0_usize;
    while let Some(&c) = b.get(i) {
        i = i.saturating_add(1);
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let Some(&e) = b.get(i) else { break };
        i = i.saturating_add(1);
        let v = match e {
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'a' => 0x07,
            b'b' => 0x08,
            b'f' => 0x0c,
            b'v' => 0x0b,
            b'0'..=b'7' => {
                let mut v = u32::from(e.saturating_sub(b'0'));
                for _ in 0..2 {
                    match b.get(i) {
                        Some(&d @ b'0'..=b'7') => {
                            v = v
                                .saturating_mul(8)
                                .saturating_add(u32::from(d.saturating_sub(b'0')));
                            i = i.saturating_add(1);
                        }
                        _ => break,
                    }
                }
                u8::try_from(v & 0xff).unwrap_or(0)
            }
            other => other,
        };
        out.push(v);
    }
    out
}

/// Finds the table row of a zk-proto site. The best match has the same
/// place, line and format. A weaker match has the same place and either
/// the line or the format, so the check can name the difference.
fn find_row<'a>(table: &'a [Site], p: &ProtoSite) -> Option<(usize, &'a Site)> {
    let same_place = |s: &&Site| s.file.ends_with(&p.file) && s.func == p.func;
    let rows = || table.iter().enumerate();
    rows()
        .find(|(_, s)| same_place(s) && s.line == p.line && c_unescape(&s.format) == p.format)
        .or_else(|| rows().find(|(_, s)| same_place(s) && s.line == p.line))
        .or_else(|| rows().find(|(_, s)| same_place(s) && c_unescape(&s.format) == p.format))
}

/// Writes bytes as the body of a C string literal. Other bytes than
/// printable ASCII get a three-digit octal escape, so no later character
/// can extend the escape.
fn c_escape(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\r' => s.push_str("\\r"),
            0x20..=0x7e => s.push(char::from(c)),
            _ => {
                let _ = write!(s, "\\{c:03o}");
            }
        }
    }
    s
}

/// The sites that the C shim emits itself, as pairs of the `enum zks_c_site`
/// key and the tsv `site_id`. The order is the order of the enum. The shim
/// gets the level, func, lines and format of each key from its tsv row.
const C_SITES: &[(&str, &str)] = &[
    ("ZKS_SITE_INIT_INITIATING", "zookeeper_init_internal#2"),
    ("ZKS_SITE_STARTING_THREADS", "start_threads#1"),
    // The POSIX site. do_io#2 is the Windows site.
    ("ZKS_SITE_IO_THREAD_STARTED", "do_io#1"),
    ("ZKS_SITE_IO_THREAD_TERMINATED", "do_io#4"),
    ("ZKS_SITE_COMPLETION_THREAD_STARTED", "do_completion#1"),
    ("ZKS_SITE_COMPLETION_THREAD_TERMINATED", "do_completion#2"),
    ("ZKS_SITE_SERVERS_EMPTY", "zoo_set_servers#1"),
    (
        "ZKS_SITE_RESOLUTION_DELAY",
        "zoo_set_servers_resolution_delay#1",
    ),
    ("ZKS_SITE_ENV_VERSION", "log_env#1"),
    ("ZKS_SITE_ENV_HOST_NAME", "log_env#2"),
    ("ZKS_SITE_ENV_OS_NAME", "log_env#4"),
    ("ZKS_SITE_ENV_OS_ARCH", "log_env#5"),
    ("ZKS_SITE_ENV_OS_VERSION", "log_env#6"),
    ("ZKS_SITE_ENV_USER_NAME", "log_env#10"),
    ("ZKS_SITE_ENV_USER_HOME", "log_env#12"),
    ("ZKS_SITE_ENV_USER_HOME_NA", "log_env#13"),
    ("ZKS_SITE_ENV_USER_DIR_TOOLONG", "log_env#15"),
    ("ZKS_SITE_ENV_USER_DIR", "log_env#16"),
    // The SASL glue sites. Only the SASL builds emit them.
    ("ZKS_SITE_SASL_GETNAMEINFO", "_zsasl_getipport#1"),
    ("ZKS_SITE_SASL_HOST", "zoo_sasl_connect#3"),
    ("ZKS_SITE_SASL_NEW", "zoo_sasl_connect#4"),
    ("ZKS_SITE_SASL_START_ERR", "zoo_sasl_client_start#1"),
    ("ZKS_SITE_SASL_START", "zoo_sasl_client_start#2"),
    ("ZKS_SITE_SASL_STEP_OUT", "zoo_sasl_client_step#2"),
    ("ZKS_SITE_SASL_STEP_ERR", "zoo_sasl_client_step#3"),
];

/// Writes the `ZKS_C_SITES(X)` rows. Each key must name a table row
/// whose format is one plain C literal.
fn render_c_sites(table: &[Site], s: &mut String) -> Result<(), Error> {
    s.push_str("#define ZKS_C_SITES(X)");
    for (key, id) in C_SITES {
        let Some(row) = table.iter().find(|r| r.id == *id) else {
            return Err(Error::msg(format!(
                "log-sites header: the C site {key} names {id}, which the table does not have"
            )));
        };
        if row.format.contains('{') {
            return Err(Error::msg(format!(
                "log-sites header: the format of the C site {id} has a macro"
            )));
        }
        let _ = write!(
            s,
            " \\\n    X({key}, ZOO_LOG_LEVEL_{}, \"{}\", {}, {}, \"{}\")",
            row.level,
            c_escape(row.func.as_bytes()),
            row.line,
            row.line_end,
            c_escape(&c_unescape(&row.format))
        );
    }
    s.push_str("\n\n");
    Ok(())
}

/// Renders `shim/zks_log_sites.h`. `ZKS_CORE_SITES` has one `X(...)` row
/// per zk-proto site, in the order of `LogSite::ALL`, so the row index is
/// the site id of a LOG item. Each site must match its pinned row exactly.
/// `ZKS_C_SITES` has one row per entry of `C_SITES`.
pub(crate) fn render_header(table: &[Site], proto: &[ProtoSite]) -> Result<String, Error> {
    let r = check(table, proto);
    if let Some(m) = r.mismatches.first() {
        return Err(Error::msg(format!(
            "log-sites header: {} zk-proto sites do not match the table; first: {m}",
            r.mismatches.len()
        )));
    }
    let mut s = String::new();
    s.push_str(
        crate::util::comment_license(" *")
            .replacen(" *", "/*\n *", 1)
            .trim_end(),
    );
    s.push_str("\n */\n\n");
    s.push_str(
        "/*\n * The log sites of the drop-in library. Generated by\n * `cargo xtask log-sites header` from tests/abi/log-sites.tsv and the\n * zk-proto LogSite table. Do not edit.\n *\n * Each row is X(name, level, func, line, line_end, fmt). line is the line\n * of the macro name. line_end is the line of the closing parenthesis,\n * which clang prints.\n *\n * ZKS_CORE_SITES has the core sites in the order of zk_proto::LogSite::ALL,\n * so the row index is the site id of a LOG item. ZKS_C_SITES has the sites\n * that the shim emits itself, in the order of enum zks_c_site.\n */\n\n",
    );
    s.push_str("#ifndef ZKS_LOG_SITES_H\n#define ZKS_LOG_SITES_H\n\n");
    let _ = writeln!(s, "#define ZKS_CORE_SITE_TOTAL {}\n", proto.len());
    s.push_str("#define ZKS_CORE_SITES(X)");
    for p in proto {
        let row = find_row(table, p).map(|(_, r)| r);
        let line_end = row.map_or(p.line, |r| r.line_end);
        let _ = write!(
            s,
            " \\\n    X({}, ZOO_LOG_LEVEL_{}, \"{}\", {}, {}, \"{}\")",
            p.name,
            p.level,
            c_escape(p.func.as_bytes()),
            p.line,
            line_end,
            c_escape(&p.format)
        );
    }
    s.push_str("\n\n");
    render_c_sites(table, &mut s)?;
    s.push_str("#endif /* ZKS_LOG_SITES_H */\n");
    Ok(s)
}

/// Runs `cargo xtask log-sites header [--check]`.
fn run_header(args: &[String], default_table: &Path, proto: &Path) -> Result<(), Error> {
    let mut check_mode = false;
    let mut out: Option<PathBuf> = None;
    let mut table: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--check" => check_mode = true,
            "--out" => out = Some(PathBuf::from(crate::util::value(&mut it, a)?)),
            "--table" => table = Some(PathBuf::from(crate::util::value(&mut it, a)?)),
            _ => {
                return Err(Error::usage(format!(
                    "log-sites header: unknown argument {a}"
                )));
            }
        }
    }
    let table = table.unwrap_or_else(|| default_table.to_path_buf());
    let path = out.unwrap_or_else(|| crate::util::rust_c_dir().join("shim/zks_log_sites.h"));
    let text = render_header(&parse(&read(&table)?)?, &parse_proto(&read(proto)?)?)?;
    if check_mode {
        let old = read(&path)?;
        if old != text {
            return Err(Error::msg(format!(
                "log-sites header: {} is out of date; run `cargo xtask log-sites header`",
                rel(&path)
            )));
        }
        crate::util::out(&format!("log-sites header: {} is up to date\n", rel(&path)));
    } else {
        crate::util::write(&path, &text)?;
        crate::util::out(&format!("log-sites header: wrote {}\n", rel(&path)));
    }
    Ok(())
}

/// The result of a check.
#[derive(Debug, Default)]
pub(crate) struct CheckReport {
    /// One line per zk-proto site that does not match the table.
    pub(crate) mismatches: Vec<String>,
    /// One line per zk-proto site whose clang line differs from its pinned line.
    pub(crate) clang_lines: Vec<String>,
    /// The number of zk-proto sites.
    pub(crate) proto_sites: usize,
    /// The number of table rows.
    pub(crate) table_rows: usize,
    /// The number of table rows that no zk-proto site uses.
    pub(crate) unused_rows: usize,
}

/// Compares the zk-proto table with the pinned table.
pub(crate) fn check(table: &[Site], proto: &[ProtoSite]) -> CheckReport {
    let mut r = CheckReport {
        proto_sites: proto.len(),
        table_rows: table.len(),
        ..CheckReport::default()
    };
    let mut used = vec![false; table.len()];
    for p in proto {
        let Some((idx, s)) = find_row(table, p) else {
            r.mismatches.push(format!(
                "{}: no table row for {}@{}:{} \"{}\"",
                p.name,
                p.func,
                p.file,
                p.line,
                String::from_utf8_lossy(&p.format).escape_debug()
            ));
            continue;
        };
        if let Some(u) = used.get_mut(idx) {
            *u = true;
        }
        let mut diffs = Vec::new();
        if s.line != p.line {
            diffs.push(format!("line {} (table {})", p.line, s.line));
        }
        if s.level != p.level {
            diffs.push(format!("level {} (table {})", p.level, s.level));
        }
        if c_unescape(&s.format) != p.format {
            diffs.push(format!(
                "format \"{}\" (table \"{}\")",
                String::from_utf8_lossy(&p.format).escape_debug(),
                s.format
            ));
        }
        if !diffs.is_empty() {
            r.mismatches
                .push(format!("{} [{}]: {}", p.name, s.id, diffs.join("; ")));
        }
        if s.line_end != s.line {
            r.clang_lines.push(format!(
                "{} [{}]: pinned {}, clang prints {}",
                p.name, s.id, s.line, s.line_end
            ));
        }
    }
    r.unused_rows = used.iter().filter(|u| !**u).count();
    r
}

/// Runs `cargo xtask log-sites`.
pub(crate) fn run(args: &[String]) -> Result<(), Error> {
    let ws = crate::util::workspace_dir();
    let mut c_dir = crate::util::c_client_dir();
    let mut out: Option<PathBuf> = None;
    let mut table: Option<PathBuf> = None;
    let mut proto = ws.join("crates/zk-proto/src/log.rs");
    let mut check_mode = false;
    let mut verbose = false;
    let mut header: Option<&[String]> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "header" => {
                header = Some(it.as_slice());
                break;
            }
            "--check" => check_mode = true,
            "--verbose" | "-v" => verbose = true,
            "--c-dir" => c_dir = PathBuf::from(crate::util::value(&mut it, a)?),
            "--out" => out = Some(PathBuf::from(crate::util::value(&mut it, a)?)),
            "--table" => table = Some(PathBuf::from(crate::util::value(&mut it, a)?)),
            "--proto" => proto = PathBuf::from(crate::util::value(&mut it, a)?),
            _ => return Err(Error::usage(format!("log-sites: unknown argument {a}"))),
        }
    }
    // The table is a test input in the Rust C tree. The legacy C tree only
    // gives the sources to scan and the commit pin.
    let default_table = crate::util::rust_c_dir().join("tests/abi/log-sites.tsv");
    if let Some(rest) = header {
        return run_header(rest, &default_table, &proto);
    }
    if check_mode {
        let path = table.unwrap_or(default_table);
        let rows = parse(&read(&path)?)?;
        let sites = parse_proto(&read(&proto)?)?;
        let r = check(&rows, &sites);
        let mut o = String::new();
        let _ = writeln!(
            o,
            "log-sites: {} table rows, {} zk-proto sites, {} rows unused by zk-proto",
            r.table_rows, r.proto_sites, r.unused_rows
        );
        for m in &r.mismatches {
            let _ = writeln!(o, "MISMATCH {m}");
        }
        let _ = writeln!(
            o,
            "log-sites: {} zk-proto sites have a clang line that differs from the pinned line",
            r.clang_lines.len()
        );
        if verbose {
            for m in &r.clang_lines {
                let _ = writeln!(o, "CLANG-LINE {m}");
            }
        }
        crate::util::out(&o);
        if r.mismatches.is_empty() {
            Ok(())
        } else {
            Err(Error::msg(format!(
                "log-sites: {} zk-proto sites do not match {}",
                r.mismatches.len(),
                rel(&path)
            )))
        }
    } else {
        let sites = extract(&c_dir)?;
        let pin = crate::util::git_head(&c_dir);
        let text = render(&sites, &pin);
        let path = out.unwrap_or(default_table);
        std::fs::write(&path, text).map_err(|e| Error::io(&path, &e))?;
        crate::util::out(&format!(
            "log-sites: wrote {} sites to {}\n",
            sites.len(),
            rel(&path)
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "static int handle_socket_error_msg(zhandle_t *zh, int line, const char *func, int rc,\n        const char* format, ...);\nint f(zhandle_t *zh)\n{\n    LOG_DEBUG(LOGCALLBACK(zh),\n        \"a %s %#llx\\n\", x,\n        y);\n    return handle_socket_error_msg(zh, __LINE__, __func__, 1,\n        \"b \" \"%\" PRId64, z);\n}\n";

    #[test]
    fn extracts_sites() {
        let mut v = Vec::new();
        assert!(extract_file("src/x.c", SRC, &mut v).is_ok());
        assert_eq!(v.len(), 2);
        let a = v.first();
        assert_eq!(
            a.map(|s| (s.line, s.line_end, s.level.as_str())),
            Some((5, 7, "DEBUG"))
        );
        assert_eq!(a.map(|s| s.format.as_str()), Some("a %s %#llx\\n"));
        assert_eq!(a.map(|s| s.convs.as_str()), Some("%s,%#llx"));
        let b = v.get(1);
        assert_eq!(
            b.map(|s| (s.id.as_str(), s.line, s.level.as_str())),
            Some(("f#2", 8, "ERROR"))
        );
        assert_eq!(
            b.map(|s| s.format.as_str()),
            Some("Socket %s zk retcode=%d, errno=%d(%s): b %{PRId64}")
        );
    }

    #[test]
    fn round_trip_and_check() {
        let mut v = Vec::new();
        assert!(extract_file("src/x.c", SRC, &mut v).is_ok());
        let parsed = parse(&render(&v, "abc"));
        assert_eq!(parsed.as_ref().ok(), Some(&v));
        let proto = parse_proto(
            "log_sites! {\n    A => (Debug, \"x.c\", \"f\", 5, \"a %s %#llx\\n\");\n    B => (Warn, \"x.c\", \"f\", 9, \"nope\");\n}\n",
        );
        let proto = proto.unwrap_or_default();
        assert_eq!(proto.len(), 2);
        let r = check(&v, &proto);
        assert_eq!(r.mismatches.len(), 1);
        assert_eq!(r.clang_lines.len(), 1);
    }

    #[test]
    fn c_sites_need_a_plain_table_row() {
        let mut v = Vec::new();
        assert!(extract_file("src/x.c", SRC, &mut v).is_ok());
        let mut s = String::new();
        assert!(render_c_sites(&v, &mut s).is_err());
        let mut keys: Vec<&str> = C_SITES.iter().map(|(k, _)| *k).collect();
        let mut ids: Vec<&str> = C_SITES.iter().map(|(_, i)| *i).collect();
        keys.sort_unstable();
        keys.dedup();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!((keys.len(), ids.len()), (C_SITES.len(), C_SITES.len()));
    }

    #[test]
    fn unescape() {
        assert_eq!(c_unescape("a\\n\\\"\\101"), b"a\n\"A".to_vec());
        assert_eq!(
            rust_str("\"a\\n\\x41\" rest").map(|(v, r)| (v, r.to_owned())),
            Some((b"a\nA".to_vec(), " rest".to_owned()))
        );
    }
}
