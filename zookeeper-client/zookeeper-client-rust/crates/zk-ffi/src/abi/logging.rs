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

//! Log views and the log time.
//!
//! The core emits `LogRecord` values with a `LogSite` and typed
//! arguments. zk-ffi gives C a `zkrs_log_view` with the site id, the
//! level, the time stamp and the arguments. C renders the pinned format
//! of the site (`zks_log_sites.h`) and calls the log callback or writes
//! the log stream.
//!
//! The site id is the index of the site in `zk_proto::LogSite::ALL`. The
//! xtask generator writes `zks_log_sites.h` in the same order.

use std::time::{SystemTime, UNIX_EPOCH};

use zk_proto::{LogArg, LogLevel, LogRecord, LogSite};

use super::raw;
use super::types::{
    ZKRS_ARG_ENDPOINT, ZKRS_ARG_ERRNO_STR, ZKRS_ARG_GAI_STR, ZKRS_ARG_I64, ZKRS_ARG_PTR,
    ZKRS_ARG_STR, ZKRS_ARG_U64, zkrs_log_arg, zkrs_log_view, zkrs_sockaddr_view, zkrs_str,
};

/// The wall-clock time as `gettimeofday` gives it: seconds and
/// microseconds. A clock before 1970 gives `(0, 0)`.
pub(crate) fn now() -> (i64, i32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (
            i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            i32::try_from(d.subsec_micros()).unwrap_or(0),
        ),
        Err(_) => (0, 0),
    }
}

/// `ZOO_LOG_LEVEL_*` of a level.
pub(crate) fn level_code(level: LogLevel) -> u32 {
    u32::try_from(level.code()).unwrap_or(0)
}

/// The site id of `site`: its index in `LogSite::ALL`.
pub(crate) fn site_id(site: LogSite) -> u32 {
    // A site that is not in the table cannot exist, because `ALL` lists
    // every variant. `u32::MAX` is outside the C table in that case.
    LogSite::ALL
        .iter()
        .position(|s| *s == site)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(u32::MAX)
}

/// A string argument before the views exist: the index of its copy in
/// `LogViews::strs`, or `None` for a jute null string.
type StrSlot = Option<usize>;

/// The argument of a view with every member zero, except `kind`.
fn blank_arg(kind: u32) -> zkrs_log_arg {
    zkrs_log_arg {
        kind,
        i: 0,
        u: 0,
        p: 0,
        s: zkrs_str::null(),
        ep: zkrs_sockaddr_view::none(),
        gai_rc: 0,
        err: 0,
    }
}

/// The view of a NUL-terminated copy from `raw::c_bytes`. The length
/// does not include the NUL. The caller keeps the copy while C reads it.
pub(crate) fn str_view(copy: &[u8]) -> zkrs_str {
    let len = copy.len().saturating_sub(1);
    zkrs_str {
        ptr: copy.as_ptr().cast(),
        len: i32::try_from(len).unwrap_or(i32::MAX),
    }
}

/// The storage of the log views of one outbox item.
///
/// Every pointer in a view points into this struct. The struct keeps
/// the arguments, the NUL-terminated copies of the string arguments
/// (`raw::c_bytes`) and the views. [`LogViews::clear`] frees them before
/// the next item.
#[derive(Default)]
pub(crate) struct LogViews {
    views: Vec<zkrs_log_view>,
    args: Vec<zkrs_log_arg>,
    strs: Vec<Box<[u8]>>,
}

impl LogViews {
    /// Frees the views of the last item.
    pub(crate) fn clear(&mut self) {
        self.views.clear();
        self.args.clear();
        self.strs.clear();
    }

    /// Stages the views of `recs` with the time `stamp`.
    ///
    /// It returns the pointer and the count for `zkrs_item.log` or
    /// `delivery_logs`. The function builds every argument first and then
    /// the views, so no vector grows after a pointer into it exists.
    ///
    /// The outbox stages one slice per item, after [`LogViews::clear`].
    /// An empty slice gives a NULL pointer and the count 0.
    pub(crate) fn stage(
        &mut self,
        recs: &[LogRecord],
        stamp: (i64, i32),
    ) -> (*const zkrs_log_view, u32) {
        if recs.is_empty() {
            return (std::ptr::null(), 0);
        }
        // Step 1: the string copies. A boxed copy does not move when the
        // vector grows. The code takes no pointer until every copy exists.
        let mut slots: Vec<StrSlot> = Vec::new();
        for rec in recs {
            for a in &rec.args {
                if let LogArg::Str(js) = a {
                    let slot = js.as_bytes().map(|b| {
                        self.strs.push(raw::c_bytes(b));
                        self.strs.len().saturating_sub(1)
                    });
                    slots.push(slot);
                }
            }
        }
        // Step 2: the arguments of every record, in record order.
        let mut next_str = slots.into_iter();
        let args_start = self.args.len();
        let mut counts: Vec<usize> = Vec::with_capacity(recs.len());
        for rec in recs {
            for a in &rec.args {
                let arg = match a {
                    LogArg::Str(_) => {
                        let s = next_str
                            .next()
                            .flatten()
                            .and_then(|n| self.strs.get(n))
                            .map_or(zkrs_str::null(), |c| str_view(c));
                        zkrs_log_arg {
                            s,
                            ..blank_arg(ZKRS_ARG_STR)
                        }
                    }
                    other => scalar_arg(other),
                };
                self.args.push(arg);
            }
            counts.push(rec.args.len());
        }
        // Step 3: the views. The argument vector is complete, so its
        // element pointers stay valid.
        let mut start = args_start;
        let first = self.views.len();
        for (rec, n) in recs.iter().zip(counts) {
            let end = start.saturating_add(n);
            let args = self
                .args
                .get(start..end)
                .map_or(std::ptr::null(), <[zkrs_log_arg]>::as_ptr);
            self.views.push(zkrs_log_view {
                level: level_code(rec.level),
                site: site_id(rec.site),
                tv_sec: stamp.0,
                tv_usec: stamp.1,
                args,
                nargs: u32::try_from(n).unwrap_or(0),
            });
            start = end;
        }
        let staged = self.views.get(first..).unwrap_or_default();
        let n = u32::try_from(staged.len()).unwrap_or(0);
        (staged.as_ptr(), n)
    }
}

/// The view of an argument that holds no string copy.
fn scalar_arg(a: &LogArg) -> zkrs_log_arg {
    match a {
        LogArg::I64(i) => zkrs_log_arg {
            i: *i,
            ..blank_arg(ZKRS_ARG_I64)
        },
        LogArg::U64(u) => zkrs_log_arg {
            u: *u,
            ..blank_arg(ZKRS_ARG_U64)
        },
        // `p` is `uintptr_t`. `u` keeps all 64 bits for a target where
        // `uintptr_t` is narrower than the session id.
        LogArg::Ptr(u) => zkrs_log_arg {
            p: usize::try_from(*u).unwrap_or(usize::MAX),
            u: *u,
            ..blank_arg(ZKRS_ARG_PTR)
        },
        LogArg::Endpoint(a) => zkrs_log_arg {
            ep: zkrs_sockaddr_view::from_addr(*a),
            ..blank_arg(ZKRS_ARG_ENDPOINT)
        },
        LogArg::ErrnoStr(e) => zkrs_log_arg {
            err: *e,
            ..blank_arg(ZKRS_ARG_ERRNO_STR)
        },
        LogArg::GaiStr { gai_rc, errno } => zkrs_log_arg {
            gai_rc: *gai_rc,
            err: *errno,
            ..blank_arg(ZKRS_ARG_GAI_STR)
        },
        // The caller handles strings. A null string is the safe view.
        LogArg::Str(_) => blank_arg(ZKRS_ARG_STR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_codes_are_the_c_values() {
        assert_eq!(level_code(LogLevel::Error), 1);
        assert_eq!(level_code(LogLevel::Debug), 4);
        let (s, us) = now();
        assert!(s > 0 && (0..1_000_000).contains(&us));
    }

    /// The bytes of a string view with its NUL, or `None` for NULL.
    fn view_bytes(s: zkrs_str) -> Option<Vec<u8>> {
        if s.ptr.is_null() {
            return None;
        }
        let n = usize::try_from(s.len).ok()?.checked_add(1)?;
        raw::bytes(s.ptr.cast(), n).ok().map(<[u8]>::to_vec)
    }

    fn rec(args: Vec<LogArg>) -> LogRecord {
        let site = LogSite::SetServersEmpty;
        LogRecord {
            site,
            level: site.level(),
            args,
        }
    }

    #[test]
    fn site_id_is_the_index_in_all() {
        let first = LogSite::ALL.first().copied();
        let last = LogSite::ALL.last().copied();
        assert_eq!(first.map(site_id), Some(0));
        let n = u32::try_from(LogSite::ALL.len()).unwrap_or(0);
        assert_eq!(last.map(site_id), n.checked_sub(1));
    }

    /// The C shim indexes its core site table by `site_id`, so the core
    /// rows of the generated header must have the order of `LogSite::ALL`.
    #[test]
    fn the_c_site_header_has_the_order_of_all() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../c/shim/zks_log_sites.h");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let core = text
            .split_once("#define ZKS_CORE_SITES(X)")
            .and_then(|(_, rest)| rest.split_once("\n\n"))
            .map_or("", |(block, _)| block);
        let rows: Vec<&str> = core
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("X("))
            .filter_map(|l| l.split(',').next())
            .collect();
        let names: Vec<&str> = LogSite::ALL.iter().map(|s| s.info().name).collect();
        assert_eq!(rows, names);
        for s in LogSite::ALL {
            let at = rows.iter().position(|r| *r == s.info().name);
            assert_eq!(at.and_then(|i| u32::try_from(i).ok()), Some(site_id(*s)));
        }
    }

    #[test]
    fn an_empty_slice_stages_nothing() {
        let mut lv = LogViews::default();
        let (p, n) = lv.stage(&[], (1, 2));
        assert!(p.is_null());
        assert_eq!(n, 0);
    }

    #[test]
    fn stage_gives_a_view_for_each_argument_type() {
        let ep: std::net::SocketAddr = ([10, 0, 0, 1], 2181).into();
        let first = rec(vec![
            LogArg::I64(-5),
            LogArg::U64(7),
            LogArg::Ptr(0x1234),
            LogArg::Str(zk_jute::JString::Bytes(b"/a".to_vec())),
            LogArg::Str(zk_jute::JString::Null),
        ]);
        let second = rec(vec![
            LogArg::Endpoint(Some(ep)),
            LogArg::Endpoint(None),
            LogArg::ErrnoStr(61),
            LogArg::GaiStr {
                gai_rc: -2,
                errno: 4,
            },
        ]);
        let mut lv = LogViews::default();
        let (p, n) = lv.stage(&[first, second], (11, 22));
        let views = raw::array(p, i32::try_from(n).unwrap_or(0)).unwrap_or_default();
        assert_eq!(views.len(), 2);
        let (Some(v0), Some(v1)) = (views.first(), views.get(1)) else {
            return;
        };
        let site = site_id(LogSite::SetServersEmpty);
        for v in [v0, v1] {
            assert_eq!((v.site, v.tv_sec, v.tv_usec), (site, 11, 22));
            assert_eq!(v.level, level_code(LogSite::SetServersEmpty.level()));
        }
        let a0 = raw::array(v0.args, i32::try_from(v0.nargs).unwrap_or(0)).unwrap_or_default();
        let a1 = raw::array(v1.args, i32::try_from(v1.nargs).unwrap_or(0)).unwrap_or_default();
        let kinds: Vec<u32> = a0.iter().chain(a1).map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            vec![
                ZKRS_ARG_I64,
                ZKRS_ARG_U64,
                ZKRS_ARG_PTR,
                ZKRS_ARG_STR,
                ZKRS_ARG_STR,
                ZKRS_ARG_ENDPOINT,
                ZKRS_ARG_ENDPOINT,
                ZKRS_ARG_ERRNO_STR,
                ZKRS_ARG_GAI_STR,
            ]
        );
        assert_eq!(a0.first().map(|a| a.i), Some(-5));
        assert_eq!(a0.get(1).map(|a| a.u), Some(7));
        assert_eq!(a0.get(2).map(|a| (a.p, a.u)), Some((0x1234, 0x1234)));
        assert_eq!(
            a0.get(3).and_then(|a| view_bytes(a.s)),
            Some(b"/a\0".to_vec())
        );
        assert_eq!(a0.get(3).map(|a| a.s.len), Some(2));
        assert_eq!(a0.get(4).map(|a| a.s.ptr.is_null()), Some(true));
        assert_eq!(
            a1.first().map(|a| a.ep),
            Some(zkrs_sockaddr_view::from_addr(Some(ep)))
        );
        assert_eq!(a1.get(1).map(|a| a.ep.family), Some(0));
        assert_eq!(a1.get(2).map(|a| a.err), Some(61));
        assert_eq!(a1.get(3).map(|a| (a.gai_rc, a.err)), Some((-2, 4)));
    }

    #[test]
    fn clear_frees_the_last_views() {
        let mut lv = LogViews::default();
        let _ = lv.stage(&[rec(vec![LogArg::I64(1)])], (0, 0));
        lv.clear();
        let (p, n) = lv.stage(&[rec(vec![])], (0, 0));
        let views = raw::array(p, i32::try_from(n).unwrap_or(0)).unwrap_or_default();
        assert_eq!(views.len(), 1);
        assert_eq!(views.first().map(|v| v.nargs), Some(0));
    }
}
