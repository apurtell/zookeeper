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

//! Connect string parsers: the legacy C syntax and the Java syntax.
//!
//! The legacy C parser (`zookeeper_init` and `resolve_hosts` in
//! `zookeeper.c`) has these rules:
//!
//! - The chroot starts at the first `/` anywhere in the string. Thus
//!   `"h1:2181/app,h2:2181"` gives the host `h1:2181` and the chroot
//!   `/app,h2:2181`. A chroot of `/` means no chroot.
//! - The host list splits on `,`. Empty entries are skipped.
//! - The port starts after the last `:` of an entry. Brackets have no special
//!   meaning, so `[::1]:2181` gives the host `[::1]`, which does not resolve,
//!   and `::1:2181` gives the host `::1`.
//! - The port text must pass `strtol(text, &end, 0)` with no text after the
//!   number and a value that is not 0 after the conversion to `int`. The raw
//!   port text goes to the resolver as the service.
//! - Leading white space of the host is skipped. Trailing white space stays.
//!
//! The Java parser (`ConnectStringParser`) also takes the chroot at the first
//! `/`, but it trims each entry, accepts `[v6]:port`, and gives port 2181 when
//! an entry has no port.

use std::fmt;

use super::path::{PathError, is_valid_path, validate_path_strict};

/// The C `errno` value `EINVAL`. It is 22 on all supported platforms.
pub const EINVAL: i32 = 22;
/// The C return code `ZSYSTEMERROR`.
pub const ZSYSTEMERROR: i32 = -1;
/// The C return code `ZBADARGUMENTS`.
pub const ZBADARGUMENTS: i32 = -8;

/// The default port of the Java syntax.
pub const DEFAULT_PORT: u16 = 2181;

/// The C `long` type of the target.
#[cfg(windows)]
pub type CLong = i32;
/// The C `long` type of the target.
#[cfg(not(windows))]
pub type CLong = i64;

/// Returns true for the white space of `isspace` in the C locale.
///
/// The C `strtol` uses `isspace`, which depends on `LC_CTYPE`. This port
/// follows the C locale only. Thus the port parse matches C only when the
/// process uses the C locale, which is the default until a `setlocale` call.
/// In some other locales C can also skip bytes such as 0xA0 before the port.
pub fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Gives the value of an ASCII digit in base 36, or `None`.
fn digit_value(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some(u32::from(b.wrapping_sub(b'0'))),
        b'a'..=b'z' => Some(u32::from(b.wrapping_sub(b'a')).saturating_add(10)),
        b'A'..=b'Z' => Some(u32::from(b.wrapping_sub(b'A')).saturating_add(10)),
        _ => None,
    }
}

/// Emulates C `strtol(text, &end, 0)` in the C locale.
///
/// The white space rule is that of [`is_c_space`], so other locales can give
/// a different result.
///
/// The function gives the value and the number of bytes that the number uses
/// (the offset of `end`). When there is no number, the value is 0 and the
/// offset is 0, as C sets `end` to the start. An overflow clamps the value to
/// the range of C `long`, and the number still uses all its digits.
pub fn strtol_base0(text: &[u8]) -> (CLong, usize) {
    let mut i = 0_usize;
    while text.get(i).copied().is_some_and(is_c_space) {
        i = i.saturating_add(1);
    }
    let mut negative = false;
    match text.get(i) {
        Some(b'+') => i = i.saturating_add(1),
        Some(b'-') => {
            negative = true;
            i = i.saturating_add(1);
        }
        _ => {}
    }
    let mut base = 10_u32;
    if text.get(i) == Some(&b'0') {
        let is_x = matches!(text.get(i.saturating_add(1)), Some(b'x' | b'X'));
        let hex_follows = text
            .get(i.saturating_add(2))
            .copied()
            .and_then(digit_value)
            .is_some_and(|d| d < 16);
        if is_x && hex_follows {
            base = 16;
            i = i.saturating_add(2);
        } else {
            base = 8;
        }
    }
    let start_digits = i;
    // Accumulate the magnitude as a negative number, so that the minimum fits.
    let mut acc: CLong = 0;
    let mut overflow = false;
    while let Some(d) = text.get(i).copied().and_then(digit_value) {
        if d >= base {
            break;
        }
        if !overflow {
            let next = acc
                .checked_mul(CLong::from(u8::try_from(base).unwrap_or(10)))
                .and_then(|v| v.checked_sub(CLong::from(u8::try_from(d).unwrap_or(0))));
            match next {
                Some(v) => acc = v,
                None => overflow = true,
            }
        }
        i = i.saturating_add(1);
    }
    if i == start_digits {
        // A "0x" prefix with no hex digit is the number 0, with the end after
        // the '0'. The base-8 branch already gives that case. No digit at all
        // means no number.
        return (0, 0);
    }
    let value = if overflow {
        if negative { CLong::MIN } else { CLong::MAX }
    } else if negative {
        acc
    } else {
        acc.checked_neg().unwrap_or(CLong::MAX)
    };
    (value, i)
}

/// Converts a C `long` to C `int` with modulo wrap, as the C client's
/// assignment `int port = strtol(...)` does on all supported compilers.
#[allow(clippy::useless_conversion)]
pub fn long_to_int(v: CLong) -> i32 {
    let bytes = i64::from(v).to_le_bytes();
    let mut low = [0_u8; 4];
    for (dst, src) in low.iter_mut().zip(bytes.iter()) {
        *dst = *src;
    }
    i32::from_le_bytes(low)
}

/// One host entry of a legacy connect string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostSpec {
    /// The host text for the resolver, after the leading white space.
    pub host: Vec<u8>,
    /// The raw port text for the resolver, as the service argument.
    pub service: Vec<u8>,
    /// The port value as C computes it: `strtol` converted to `int`.
    pub port: i32,
}

/// The kind of a legacy connect string error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostParseErrorKind {
    /// The connect string is empty.
    Empty,
    /// The chroot fails the legacy path check.
    InvalidChroot,
    /// An entry has no `:`.
    NoPort,
    /// The port text of an entry is empty, has trailing text, or gives 0.
    InvalidPort,
    /// The host list has commas but no entries.
    NoHosts,
}

/// A legacy connect string error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostParseError {
    /// The kind of the error.
    pub kind: HostParseErrorKind,
    /// The C return code.
    pub rc: i32,
    /// The C `errno` value, or `None` when C does not set `errno`.
    ///
    /// C sets `EINVAL` for an empty string, a bad chroot and a port error.
    /// For [`HostParseErrorKind::NoHosts`] C does not set `errno`, so a
    /// drop-in shim keeps the `errno` value of the caller.
    pub errno: Option<i32>,
    /// For a port error, the index of the first bad entry.
    pub entry: Option<usize>,
    /// For a port error, the entries before the bad entry. C resolves them
    /// before it finds the error.
    pub prefix: Vec<HostSpec>,
    /// The text for the `%s` of the C log line.
    pub subject: Vec<u8>,
}

impl HostParseError {
    /// Gives the C log format of the error, if C logs one.
    pub fn log_format(&self) -> Option<&'static str> {
        match self.kind {
            HostParseErrorKind::NoPort => Some("no port in %s"),
            HostParseErrorKind::InvalidPort => Some("invalid port in %s"),
            _ => None,
        }
    }

    fn new(kind: HostParseErrorKind, rc: i32) -> Self {
        // The address count check of `resolve_hosts` is the only failure
        // without an `errno` assignment.
        let errno = match kind {
            HostParseErrorKind::NoHosts => None,
            _ => Some(EINVAL),
        };
        Self {
            kind,
            rc,
            errno,
            entry: None,
            prefix: Vec::new(),
            subject: Vec::new(),
        }
    }
}

impl fmt::Display for HostParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subject = String::from_utf8_lossy(&self.subject);
        match self.kind {
            HostParseErrorKind::Empty => f.write_str("empty connect string"),
            HostParseErrorKind::InvalidChroot => write!(f, "invalid chroot {subject}"),
            HostParseErrorKind::NoPort => write!(f, "no port in {subject}"),
            HostParseErrorKind::InvalidPort => write!(f, "invalid port in {subject}"),
            HostParseErrorKind::NoHosts => f.write_str("no host in connect string"),
        }
    }
}

impl std::error::Error for HostParseError {}

/// A parsed legacy connect string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectString {
    /// The host list text, before the chroot (`zh->hostname`).
    pub host_text: Vec<u8>,
    /// The host entries.
    pub hosts: Vec<HostSpec>,
    /// The chroot, or `None` when there is none or it is `/`.
    pub chroot: Option<Vec<u8>>,
}

/// Parses one host entry as the `resolve_hosts` loop does.
fn parse_entry(token: &[u8]) -> Result<HostSpec, (HostParseErrorKind, Vec<u8>)> {
    let Some(colon) = token.iter().rposition(|&b| b == b':') else {
        return Err((HostParseErrorKind::NoPort, token.to_vec()));
    };
    let host_raw = token.get(..colon).unwrap_or_default();
    let service = token.get(colon.saturating_add(1)..).unwrap_or_default();
    let (value, used) = strtol_base0(service);
    let port = long_to_int(value);
    if service.is_empty() || used != service.len() || port == 0 {
        return Err((HostParseErrorKind::InvalidPort, host_raw.to_vec()));
    }
    let skip = host_raw.iter().take_while(|&&b| is_c_space(b)).count();
    Ok(HostSpec {
        host: host_raw.get(skip..).unwrap_or_default().to_vec(),
        service: service.to_vec(),
        port,
    })
}

/// Parses a legacy host list, as `zoo_set_servers` and `resolve_hosts` do.
///
/// The input is the bytes of the C string, and parsing stops at the first
/// NUL. An empty list gives no entries and no error. A list of commas only
/// gives [`HostParseErrorKind::NoHosts`]: C finds no address and fails with
/// `ZSYSTEMERROR`. A port error names the first bad entry and gives the
/// entries before it.
pub fn parse_servers(s: &[u8]) -> Result<Vec<HostSpec>, HostParseError> {
    let s = super::hashtable::c_str(s);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let mut hosts = Vec::new();
    for (k, token) in s
        .split(|&b| b == b',')
        .filter(|t| !t.is_empty())
        .enumerate()
    {
        match parse_entry(token) {
            Ok(h) => hosts.push(h),
            Err((kind, subject)) => {
                let mut e = HostParseError::new(kind, ZBADARGUMENTS);
                e.entry = Some(k);
                e.prefix = hosts;
                e.subject = subject;
                return Err(e);
            }
        }
    }
    if hosts.is_empty() {
        return Err(HostParseError::new(
            HostParseErrorKind::NoHosts,
            ZSYSTEMERROR,
        ));
    }
    Ok(hosts)
}

/// Parses a legacy connect string, as `zookeeper_init` does.
///
/// The chroot check runs before the host list parse, as in C. The input is
/// the bytes of the C string, and parsing stops at the first NUL.
pub fn parse_init(s: &[u8]) -> Result<ConnectString, HostParseError> {
    let s = super::hashtable::c_str(s);
    if s.is_empty() {
        return Err(HostParseError::new(
            HostParseErrorKind::Empty,
            ZBADARGUMENTS,
        ));
    }
    let (host_text, chroot) = match s.iter().position(|&b| b == b'/') {
        Some(i) => {
            let root = s.get(i..).unwrap_or_default();
            let host = s.get(..i).unwrap_or_default();
            let root = if root.len() == 1 { None } else { Some(root) };
            (host, root)
        }
        None => (s, None),
    };
    if let Some(root) = chroot {
        if !is_valid_path(root, 0) {
            let mut e = HostParseError::new(HostParseErrorKind::InvalidChroot, ZBADARGUMENTS);
            e.subject = root.to_vec();
            return Err(e);
        }
    }
    let hosts = parse_servers(host_text)?;
    Ok(ConnectString {
        host_text: host_text.to_vec(),
        hosts,
        chroot: chroot.map(<[u8]>::to_vec),
    })
}

/// One host entry of a Java syntax connect string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NativeHost {
    /// The host name or IP literal, without IPv6 brackets.
    pub host: String,
    /// The port.
    pub port: u16,
}

/// A parsed Java syntax connect string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeConnectString {
    /// The host entries, in the order of the string.
    pub hosts: Vec<NativeHost>,
    /// The chroot, or `None` when there is none or it is `/`.
    pub chroot: Option<String>,
}

/// A Java syntax connect string error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeParseError {
    /// The connect string is empty or white space.
    Empty,
    /// The `dns-srv://` form, which this client does not support.
    DnsSrvUnsupported,
    /// The chroot fails the strict path check.
    InvalidChroot(PathError),
    /// The string has no host entry.
    NoHosts,
    /// An entry is not valid. The text is the entry.
    InvalidEntry(String),
    /// The port of an entry is not a number in 0 to 65535. The text is the
    /// entry.
    InvalidPort(String),
}

impl fmt::Display for NativeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NativeParseError::Empty => f.write_str("Connect string cannot be null or empty"),
            NativeParseError::DnsSrvUnsupported => {
                f.write_str("dns-srv:// connect strings are not supported")
            }
            NativeParseError::InvalidChroot(e) => write!(f, "invalid chroot: {e}"),
            NativeParseError::NoHosts => f.write_str("connect string has no host"),
            NativeParseError::InvalidEntry(s) => write!(f, "invalid host entry {s}"),
            NativeParseError::InvalidPort(s) => write!(f, "invalid port in {s}"),
        }
    }
}

impl std::error::Error for NativeParseError {}

/// Trims as Java `String.trim` does: all characters up to U+0020.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// Parses a port as Java `Integer.parseInt` and a port range check do. Only
/// ASCII digits are accepted.
fn java_port(text: &str, entry: &str) -> Result<u16, NativeParseError> {
    let bad = || NativeParseError::InvalidPort(entry.to_owned());
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        // A negative number is a valid int but not a valid port.
        return Err(bad());
    }
    digits.parse::<u16>().map_err(|_| bad())
}

/// Parses one Java syntax entry.
fn parse_native_entry(entry: &str) -> Result<NativeHost, NativeParseError> {
    if let Some(inner) = entry.strip_prefix('[') {
        // NetUtils.getIPV6HostAndPort: the last ']' closes the literal.
        let Some(close) = inner.rfind(']') else {
            return Err(NativeParseError::InvalidEntry(entry.to_owned()));
        };
        let host = inner.get(..close).unwrap_or_default();
        if host.is_empty() {
            return Err(NativeParseError::InvalidEntry(entry.to_owned()));
        }
        let rest = inner.get(close.saturating_add(1)..).unwrap_or_default();
        if rest.is_empty() {
            return Ok(NativeHost {
                host: host.to_owned(),
                port: DEFAULT_PORT,
            });
        }
        let Some(port_text) = rest.strip_prefix(':') else {
            return Err(NativeParseError::InvalidEntry(entry.to_owned()));
        };
        if port_text.is_empty() {
            return Err(NativeParseError::InvalidEntry(entry.to_owned()));
        }
        return Ok(NativeHost {
            host: host.to_owned(),
            port: java_port(port_text, entry)?,
        });
    }
    match entry.rfind(':') {
        None => Ok(NativeHost {
            host: entry.to_owned(),
            port: DEFAULT_PORT,
        }),
        Some(colon) => {
            let host = entry.get(..colon).unwrap_or_default();
            let port_text = entry.get(colon.saturating_add(1)..).unwrap_or_default();
            let port = if port_text.is_empty() {
                DEFAULT_PORT
            } else {
                java_port(port_text, entry)?
            };
            Ok(NativeHost {
                host: host.to_owned(),
                port,
            })
        }
    }
}

/// Parses a connect string with the Java syntax, for the native client.
///
/// Examples: `"h1:2181,h2:2181/chroot"`, `"h1,[::1]:2182"`. The chroot starts
/// at the first `/` and must pass the strict path check. Entries split on
/// `,`, are trimmed, and empty entries are skipped. An entry with no port gets
/// port 2181. An empty host list is an error, because the native client needs
/// at least one server.
pub fn parse_connect_string_native(s: &str) -> Result<NativeConnectString, NativeParseError> {
    if java_trim(s).is_empty() {
        return Err(NativeParseError::Empty);
    }
    if s.starts_with("dns-srv://") {
        return Err(NativeParseError::DnsSrvUnsupported);
    }
    let (server_part, chroot) = match s.find('/') {
        Some(i) => {
            let root = s.get(i..).unwrap_or_default();
            let server = s.get(..i).unwrap_or_default();
            if root.len() == 1 {
                (server, None)
            } else {
                validate_path_strict(root, false).map_err(NativeParseError::InvalidChroot)?;
                (server, Some(root.to_owned()))
            }
        }
        None => (s, None),
    };
    let mut hosts = Vec::new();
    for entry in server_part
        .split(',')
        .map(java_trim)
        .filter(|e| !e.is_empty())
    {
        hosts.push(parse_native_entry(entry)?);
    }
    if hosts.is_empty() {
        return Err(NativeParseError::NoHosts);
    }
    Ok(NativeConnectString { hosts, chroot })
}
