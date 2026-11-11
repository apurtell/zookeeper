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

//! Observability: the `Metrics` hook, `OpKind` and the log rendering.
//!
//! zk-proto emits structured `LogRecord` values and never formats text.
//! The `Observer` renders them as `tracing` events (feature `tracing`),
//! as `log` records (feature `log` without `tracing`), or not at all.
//! It also runs the user `Metrics` hook inside `catch_unwind`, with no
//! internal lock held. A hook that panics is logged once and then
//! disabled for this client.

use std::any::Any;
use std::fmt::{self, Write as _};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zk_proto::{LogArg, LogLevel, LogRecord, LogSite};

use crate::error::Error;
use crate::watch::{EventKind, SessionState};

/// The kind of a request, for metrics and retry rules.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OpKind {
    /// `create`.
    Create,
    /// `delete`.
    Delete,
    /// `exists`.
    Exists,
    /// `get_data`.
    GetData,
    /// `set_data`.
    SetData,
    /// `get_acl`.
    GetAcl,
    /// `set_acl`.
    SetAcl,
    /// `get_children`.
    GetChildren,
    /// `get_all_children_number`.
    GetAllChildrenNumber,
    /// `get_ephemerals`.
    GetEphemerals,
    /// `sync`.
    Sync,
    /// `multi`.
    Multi,
    /// `multi_read`.
    MultiRead,
    /// `add_watch`.
    AddWatch,
    /// `remove_watches`, explicit or from a watcher drop.
    RemoveWatches,
    /// `get_config`.
    GetConfig,
    /// `reconfig`.
    Reconfig,
    /// `add_auth`.
    AddAuth,
    /// `who_am_i`.
    WhoAmI,
    /// `close`.
    Close,
}

/// The metrics hook.
///
/// Every method has an empty default. The IO side calls the hook after
/// it routes an item, with no internal lock held and inside
/// `catch_unwind`. A hook must not block. A hook that panics is
/// disabled for this client.
pub trait Metrics: Send + Sync + 'static {
    /// A request completed. `result` is `Ok` or the error of the reply.
    fn request_completed(&self, op: OpKind, result: Result<(), &Error>, latency: Duration) {
        let _ = (op, result, latency);
    }
    /// The session state changed.
    fn state_changed(&self, state: SessionState) {
        let _ = state;
    }
    /// Bytes went out or came in. The drivers do not report byte counts,
    /// so the client does not call it (IMPLEMENTATION_GUIDE.md, "Known
    /// differences and open issues").
    fn bytes(&self, sent: usize, received: usize) {
        let _ = (sent, received);
    }
    /// A watch event was delivered.
    fn watch_event(&self, kind: EventKind) {
        let _ = kind;
    }
    /// A persistent watcher dropped events because its queue was full.
    fn watch_lagged(&self, missed: u64) {
        let _ = missed;
    }
    /// The number of pending requests after a change.
    fn pending_requests(&self, n: usize) {
        let _ = n;
    }
}

/// The per-client renderer and metrics runner.
pub(crate) struct Observer {
    /// The `ClientBuilder::name` label. Every record carries it.
    pub(crate) name: Option<Arc<str>>,
    /// The user hook, if any.
    metrics: Option<Arc<dyn Metrics>>,
    /// True after the hook panicked once.
    disabled: AtomicBool,
}

impl std::fmt::Debug for Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observer")
            .field("name", &self.name)
            .field("metrics", &self.metrics.is_some())
            .finish_non_exhaustive()
    }
}

impl Observer {
    /// Makes the observer of one client.
    pub(crate) fn new(name: Option<String>, metrics: Option<Arc<dyn Metrics>>) -> Self {
        Self {
            name: name.map(Arc::from),
            metrics,
            disabled: AtomicBool::new(false),
        }
    }

    /// True when the client has a metrics hook. The router skips the
    /// work of a hook call when it is false.
    pub(crate) fn has_metrics(&self) -> bool {
        self.metrics.is_some()
    }

    /// The `zk_proto::LogFilter` answer: true when the active backend
    /// wants records of `level` (the `tracing` max level, or the `log`
    /// max level). False when no backend feature is on.
    ///
    /// It runs under the core lock, so it must be cheap and must not
    /// call user code.
    pub(crate) fn log_enabled(&self, level: LogLevel) -> bool {
        backend::enabled(level)
    }

    /// Renders one record. The target follows the site:
    /// `apache_zookeeper::session`, `::request`, `::watch` or `::proto`.
    /// The record carries the client name. Secrets never reach a record,
    /// because zk-proto never puts them in one.
    ///
    /// It runs on the IO side with no lock held.
    pub(crate) fn log(&self, rec: &LogRecord) {
        if !backend::enabled(rec.level) {
            return;
        }
        let site = rec.site.info().name;
        backend::emit(
            Target::of(rec.site),
            rec.level,
            self.name.as_deref(),
            site,
            &Rendered(rec),
        );
    }

    /// Runs `Metrics::request_completed` for a reply code. The code
    /// maps through `Error::from_code`. The hook sees the result of the
    /// API call, so `exists` on a missing node is a success.
    pub(crate) fn request_completed(&self, op: OpKind, rc: i32, latency: Duration) {
        let ok = rc == 0 || (op == OpKind::Exists && rc == Error::NoNode.code());
        self.run(|m| {
            // A success gets `Ok` with no error lookup.
            let err = if ok { None } else { Error::from_code(rc) };
            match &err {
                None => m.request_completed(op, Ok(()), latency),
                Some(e) => m.request_completed(op, Err(e), latency),
            }
        });
    }

    /// Runs `Metrics::state_changed`.
    pub(crate) fn state_changed(&self, state: SessionState) {
        self.run(|m| m.state_changed(state));
    }

    /// Runs `Metrics::watch_event`.
    pub(crate) fn watch_event(&self, kind: EventKind) {
        self.run(|m| m.watch_event(kind));
    }

    /// Runs `Metrics::watch_lagged`.
    pub(crate) fn watch_lagged(&self, missed: u64) {
        self.run(|m| m.watch_lagged(missed));
    }

    /// Runs `Metrics::pending_requests`.
    pub(crate) fn pending_requests(&self, n: usize) {
        self.run(|m| m.pending_requests(n));
    }

    /// Runs `f` on the hook inside `catch_unwind`, unless the hook is
    /// absent or disabled. A panic disables the hook and logs one error
    /// record.
    fn run(&self, f: impl FnOnce(&dyn Metrics)) {
        let Some(hook) = self.metrics.as_deref() else {
            return;
        };
        if self.disabled.load(Ordering::Acquire) {
            return;
        }
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| f(hook))) {
            // Only the first panic logs. A concurrent second panic only
            // drops its payload.
            if self.disabled.swap(true, Ordering::AcqRel) {
                discard(payload);
            } else {
                self.hook_panicked(
                    "the metrics hook panicked and is disabled for this client",
                    payload,
                );
            }
        }
    }

    /// Logs one error record for a user hook that panicked, then drops
    /// the panic payload. The resolver and the metrics hook use it.
    ///
    /// It runs with no lock held. The drop of the payload runs inside
    /// `catch_unwind`, so a payload with a bad `Drop` cannot unwind
    /// into the IO side.
    pub(crate) fn hook_panicked(&self, what: &str, payload: Box<dyn Any + Send>) {
        if backend::enabled(LogLevel::Error) {
            let msg = PanicText {
                what,
                payload: &*payload,
            };
            backend::emit(
                Target::Client,
                LogLevel::Error,
                self.name.as_deref(),
                "HookPanicked",
                &msg,
            );
        }
        discard(payload);
    }
}

/// Drops a panic payload. A second panic from its `Drop` is caught, and
/// its payload is leaked, so the drop never unwinds.
fn discard(payload: Box<dyn Any + Send>) {
    if let Err(again) = catch_unwind(AssertUnwindSafe(move || drop(payload))) {
        std::mem::forget(again);
    }
}

/// The text of a hook panic: the event, then the panic message when it
/// is a string.
struct PanicText<'a> {
    what: &'a str,
    payload: &'a (dyn Any + Send),
}

impl fmt::Display for PanicText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.what)?;
        if let Some(s) = self.payload.downcast_ref::<&'static str>() {
            write!(f, ": {s}")
        } else if let Some(s) = self.payload.downcast_ref::<String>() {
            write!(f, ": {s}")
        } else {
            Ok(())
        }
    }
}

/// The log target of a record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Target {
    /// `apache_zookeeper`: lines of the client itself, such as a hook
    /// panic.
    Client,
    /// `apache_zookeeper::session`: connections, authentication and the
    /// session lifecycle.
    Session,
    /// `apache_zookeeper::request`: the send and the completion of
    /// requests.
    Request,
    /// `apache_zookeeper::watch`: watch delivery and restore.
    Watch,
    /// `apache_zookeeper::proto`: protocol violations of the server.
    Proto,
}

impl Target {
    /// Returns the target of a site. A site that is not in a request,
    /// watch or protocol group belongs to the session group.
    fn of(site: LogSite) -> Self {
        use LogSite as S;
        match site {
            S::SendGetData
            | S::SendGetConfig
            | S::SendReconfig
            | S::SendSetData
            | S::SendCreate
            | S::SendCreate2
            | S::SendDelete
            | S::SendExists
            | S::SendGetChildren
            | S::SendGetChildren2
            | S::SendSync
            | S::SendGetAcl
            | S::SendSetAcl
            | S::SendMulti
            | S::SendRemoveWatches
            | S::MultiUnimplemented
            | S::CompletionData
            | S::CompletionStat
            | S::CompletionStringList
            | S::CompletionStringListStat
            | S::CompletionString
            | S::CompletionStringStat
            | S::CompletionAclList
            | S::CompletionVoid
            | S::CompletionMulti
            | S::CompletionUnsupported
            | S::ResponseLatency
            | S::ClearedByClose
            | S::QueueingAsync
            | S::SyncCompletion
            | S::SyncUnsupported => Self::Request,
            S::CleanupSessionState
            | S::CleanupSessionConnecting
            | S::FinalizeSessionEvent
            | S::SendSetWatches
            | S::CallingWatcher
            | S::ProcessingWatcherEvent
            | S::ProcessingSetWatches
            | S::WatcherOom => Self::Watch,
            S::ChrootMismatch | S::UnexpectedResponse | S::SockUnexpectedXid => Self::Proto,
            _ => Self::Session,
        }
    }

    /// Returns the target text.
    #[cfg(all(feature = "log", not(feature = "tracing")))]
    const fn name(self) -> &'static str {
        match self {
            Self::Client => "apache_zookeeper",
            Self::Session => "apache_zookeeper::session",
            Self::Request => "apache_zookeeper::request",
            Self::Watch => "apache_zookeeper::watch",
            Self::Proto => "apache_zookeeper::proto",
        }
    }
}

/// The text of one record: the C format of the site with the typed
/// arguments in place of its conversions.
///
/// It formats only when a backend writes the record, so a filtered
/// record costs no allocation.
struct Rendered<'a>(&'a LogRecord);

impl fmt::Display for Rendered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_format(f, self.0.site.info().format, &self.0.args)
    }
}

/// Writes a C format with the arguments of a record.
///
/// The writer reads the flags, the width, the precision and the length
/// of each conversion, and keeps only the `#` flag and the conversion
/// letter. A missing argument prints `?`. An extra argument follows the
/// text, so no argument is lost. A trailing newline is removed, because
/// the backend ends the line.
fn write_format(f: &mut fmt::Formatter<'_>, format: &str, args: &[LogArg]) -> fmt::Result {
    let mut args = args.iter();
    let mut chars = format.trim_end_matches('\n').chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            f.write_char(c)?;
            continue;
        }
        let mut alt = false;
        while let Some(&n) = chars.peek() {
            match n {
                '#' => alt = true,
                '-' | '+' | ' ' | '0' => {}
                _ => break,
            }
            chars.next();
        }
        while chars
            .peek()
            .is_some_and(|n| n.is_ascii_digit() || *n == '.' || *n == '*')
        {
            chars.next();
        }
        while chars
            .peek()
            .is_some_and(|n| matches!(n, 'l' | 'h' | 'z' | 'j' | 't' | 'q' | 'L'))
        {
            chars.next();
        }
        let Some(conv) = chars.next() else {
            return f.write_char('%');
        };
        if conv == '%' {
            f.write_char('%')?;
            continue;
        }
        match args.next() {
            Some(arg) => write_arg(f, arg, conv, alt)?,
            None => f.write_char('?')?,
        }
    }
    for arg in args {
        f.write_char(' ')?;
        write_arg(f, arg, 's', false)?;
    }
    Ok(())
}

/// Writes one argument. The conversion letter selects hex or decimal for
/// an integer. Other arguments ignore it.
fn write_arg(f: &mut fmt::Formatter<'_>, arg: &LogArg, conv: char, alt: bool) -> fmt::Result {
    let hex = matches!(conv, 'x' | 'X');
    match arg {
        LogArg::I64(v) if hex => write_hex(f, int_bits(*v), alt),
        LogArg::U64(v) if hex => write_hex(f, *v, alt),
        LogArg::I64(v) => write!(f, "{v}"),
        LogArg::U64(v) => write!(f, "{v}"),
        LogArg::Ptr(v) => write_hex(f, *v, true),
        LogArg::Str(s) => match s.as_bytes() {
            Some(b) => write!(f, "{}", String::from_utf8_lossy(b)),
            None => f.write_str("(null)"),
        },
        LogArg::Endpoint(Some(addr)) => write!(f, "{addr}"),
        LogArg::Endpoint(None) => f.write_str("(none)"),
        LogArg::GaiStr { gai_rc, errno: 0 } => {
            write!(f, "name resolution failed (getaddrinfo rc {gai_rc})")
        }
        LogArg::ErrnoStr(errno) | LogArg::GaiStr { errno, .. } => {
            write!(f, "{}", std::io::Error::from_raw_os_error(*errno))
        }
    }
}

/// Gives the bits of a signed value for a hex conversion. C narrows the
/// value to the type of the conversion. An `int` value gives the 32-bit
/// pattern.
fn int_bits(v: i64) -> u64 {
    match i32::try_from(v) {
        Ok(n) => u64::from(u32::from_ne_bytes(n.to_ne_bytes())),
        Err(_) => u64::from_ne_bytes(v.to_ne_bytes()),
    }
}

/// Writes a hex value. The `#` flag adds `0x`, except for zero, as C
/// does.
fn write_hex(f: &mut fmt::Formatter<'_>, v: u64, alt: bool) -> fmt::Result {
    if alt && v != 0 {
        write!(f, "{v:#x}")
    } else {
        write!(f, "{v:x}")
    }
}

/// The `tracing` backend (feature `tracing`).
#[cfg(feature = "tracing")]
mod backend {
    use std::fmt::Display;

    use tracing::Level;
    use tracing::level_filters::{LevelFilter, STATIC_MAX_LEVEL};
    use zk_proto::LogLevel;

    use super::Target;

    /// Maps a record level to a `tracing` level.
    fn level_of(level: LogLevel) -> Level {
        match level {
            LogLevel::Error => Level::ERROR,
            LogLevel::Warn => Level::WARN,
            LogLevel::Info => Level::INFO,
            LogLevel::Debug => Level::DEBUG,
        }
    }

    /// True when the compile-time and the current max level of
    /// `tracing` let `level` through. The subscriber filters each event
    /// again by its target.
    pub(super) fn enabled(level: LogLevel) -> bool {
        let level = level_of(level);
        level <= STATIC_MAX_LEVEL && level <= LevelFilter::current()
    }

    /// Makes one emit function for a constant target. `tracing` needs
    /// the target and the level as constants, so each pair has its own
    /// call site. One function for each target keeps the stack frames
    /// small.
    macro_rules! target_fn {
        ($fn_name:ident, $target:literal) => {
            fn $fn_name(level: LogLevel, client: Option<&str>, site: &str, msg: &dyn Display) {
                match level {
                    LogLevel::Error => tracing::error!(target: $target, client, site, "{}", msg),
                    LogLevel::Warn => tracing::warn!(target: $target, client, site, "{}", msg),
                    LogLevel::Info => tracing::info!(target: $target, client, site, "{}", msg),
                    LogLevel::Debug => tracing::debug!(target: $target, client, site, "{}", msg),
                }
            }
        };
    }

    target_fn!(emit_client, "apache_zookeeper");
    target_fn!(emit_session, "apache_zookeeper::session");
    target_fn!(emit_request, "apache_zookeeper::request");
    target_fn!(emit_watch, "apache_zookeeper::watch");
    target_fn!(emit_proto, "apache_zookeeper::proto");

    /// Emits one event with the fields `client` (when the client has a
    /// name) and `site`.
    pub(super) fn emit(
        target: Target,
        level: LogLevel,
        client: Option<&str>,
        site: &str,
        msg: &dyn Display,
    ) {
        let f = match target {
            Target::Client => emit_client,
            Target::Session => emit_session,
            Target::Request => emit_request,
            Target::Watch => emit_watch,
            Target::Proto => emit_proto,
        };
        f(level, client, site, msg);
    }
}

/// The `log` backend (feature `log` without `tracing`).
#[cfg(all(feature = "log", not(feature = "tracing")))]
mod backend {
    use std::fmt::{self, Display};

    use zk_proto::LogLevel;

    use super::Target;

    /// Maps a record level to a `log` level.
    fn level_of(level: LogLevel) -> log::Level {
        match level {
            LogLevel::Error => log::Level::Error,
            LogLevel::Warn => log::Level::Warn,
            LogLevel::Info => log::Level::Info,
            LogLevel::Debug => log::Level::Debug,
        }
    }

    /// True when the compile-time and the current max level of `log`
    /// let `level` through.
    pub(super) fn enabled(level: LogLevel) -> bool {
        let level = level_of(level);
        level <= log::STATIC_MAX_LEVEL && level <= log::max_level()
    }

    /// The `[name] ` prefix of a named client. `log` has no structured
    /// fields here, so the name goes into the text.
    struct Prefix<'a>(Option<&'a str>);

    impl Display for Prefix<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                Some(name) => write!(f, "[{name}] "),
                None => Ok(()),
            }
        }
    }

    /// Emits one record. The text has the client name first and the
    /// site name last.
    pub(super) fn emit(
        target: Target,
        level: LogLevel,
        client: Option<&str>,
        site: &str,
        msg: &dyn Display,
    ) {
        log::log!(
            target: target.name(),
            level_of(level),
            "{}{} (site {})",
            Prefix(client),
            msg,
            site
        );
    }
}

/// No backend: records go nowhere.
#[cfg(not(any(feature = "tracing", feature = "log")))]
mod backend {
    use std::fmt::Display;

    use zk_proto::LogLevel;

    use super::Target;

    /// No backend wants a record.
    pub(super) fn enabled(_level: LogLevel) -> bool {
        false
    }

    /// Does nothing.
    pub(super) fn emit(
        _target: Target,
        _level: LogLevel,
        _client: Option<&str>,
        _site: &str,
        _msg: &dyn Display,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use zk_jute::JString;

    use super::*;
    use crate::sync::LockExt;

    /// A hook that counts calls and panics on chosen calls.
    #[derive(Default)]
    struct Counting {
        calls: AtomicUsize,
        panic_on_state: bool,
        seen: Mutex<Vec<String>>,
    }

    impl Metrics for Counting {
        fn request_completed(&self, op: OpKind, result: Result<(), &Error>, _latency: Duration) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen
                .lock_unpoisoned()
                .push(format!("req {op:?} {}", result.is_ok()));
        }
        fn state_changed(&self, state: SessionState) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.panic_on_state {
                std::panic::panic_any(String::from("hook bug"));
            }
            self.seen.lock_unpoisoned().push(format!("state {state:?}"));
        }
        fn watch_event(&self, kind: EventKind) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock_unpoisoned().push(format!("watch {kind:?}"));
        }
        fn watch_lagged(&self, missed: u64) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock_unpoisoned().push(format!("lagged {missed}"));
        }
        fn pending_requests(&self, n: usize) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock_unpoisoned().push(format!("pending {n}"));
        }
    }

    fn observer(hook: &Arc<Counting>) -> Observer {
        let m: Arc<dyn Metrics> = Arc::clone(hook) as Arc<dyn Metrics>;
        Observer::new(Some("c1".into()), Some(m))
    }

    fn text(site: LogSite, args: Vec<LogArg>) -> String {
        let rec = LogRecord {
            site,
            level: site.level(),
            args,
        };
        Rendered(&rec).to_string()
    }

    #[test]
    fn every_hook_method_runs() {
        let hook = Arc::new(Counting::default());
        let o = observer(&hook);
        assert!(o.has_metrics());
        o.request_completed(OpKind::GetData, 0, Duration::from_millis(3));
        o.state_changed(SessionState::Connected);
        o.watch_event(EventKind::NodeCreated);
        o.watch_lagged(4);
        o.pending_requests(2);
        assert_eq!(
            *hook.seen.lock_unpoisoned(),
            vec![
                "req GetData true",
                "state Connected",
                "watch NodeCreated",
                "lagged 4",
                "pending 2"
            ]
        );
    }

    #[test]
    fn an_error_code_reaches_the_hook_as_an_error() {
        let hook = Arc::new(Counting::default());
        let o = observer(&hook);
        o.request_completed(OpKind::Delete, -101, Duration::ZERO);
        assert_eq!(*hook.seen.lock_unpoisoned(), vec!["req Delete false"]);
    }

    #[test]
    fn a_panicking_hook_is_disabled_for_this_client() {
        let hook = Arc::new(Counting {
            panic_on_state: true,
            ..Counting::default()
        });
        let o = observer(&hook);
        o.state_changed(SessionState::Connecting);
        assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
        // Every later call skips the hook, for every method.
        o.state_changed(SessionState::Connected);
        o.watch_event(EventKind::NodeDeleted);
        o.pending_requests(1);
        o.request_completed(OpKind::Create, 0, Duration::ZERO);
        assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
        assert!(hook.seen.lock_unpoisoned().is_empty());

        // Another client with the same hook still runs it.
        let other = observer(&hook);
        other.watch_lagged(9);
        assert_eq!(hook.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn no_hook_is_a_no_op() {
        let o = Observer::new(None, None);
        assert!(!o.has_metrics());
        o.state_changed(SessionState::Closed);
        o.request_completed(OpKind::Close, 0, Duration::ZERO);
        o.pending_requests(0);
    }

    #[test]
    fn sites_map_to_the_four_targets() {
        assert_eq!(Target::of(LogSite::SendGetData), Target::Request);
        assert_eq!(Target::of(LogSite::CompletionVoid), Target::Request);
        assert_eq!(Target::of(LogSite::CallingWatcher), Target::Watch);
        assert_eq!(Target::of(LogSite::SendSetWatches), Target::Watch);
        assert_eq!(Target::of(LogSite::SockUnexpectedXid), Target::Proto);
        assert_eq!(Target::of(LogSite::ChrootMismatch), Target::Proto);
        assert_eq!(Target::of(LogSite::SessionEstablished), Target::Session);
        assert_eq!(Target::of(LogSite::SockConnectFailed), Target::Session);
        assert_eq!(Target::of(LogSite::AuthSchemeFailed), Target::Session);
    }

    #[test]
    fn a_record_renders_its_site_format() {
        let addr: SocketAddr = "127.0.0.1:2181".parse().unwrap();
        assert_eq!(
            text(
                LogSite::SessionEstablished,
                vec![
                    LogArg::Endpoint(Some(addr)),
                    LogArg::Ptr(0x1234),
                    LogArg::I64(4000),
                    LogArg::Str(JString::from("")),
                ]
            ),
            "session establishment complete on server 127.0.0.1:2181, \
             sessionId=0x1234, negotiated timeout=4000 "
        );
        // The trailing newline of the C format goes away.
        assert_eq!(
            text(
                LogSite::Closing,
                vec![LogArg::Ptr(0), LogArg::Endpoint(None)]
            ),
            "Closing zookeeper sessionId=0 to (none)"
        );
        // `%#x` of a negative `int` prints the 32-bit pattern.
        assert_eq!(
            text(
                LogSite::CompletionVoid,
                vec![LogArg::I64(-2), LogArg::I64(0), LogArg::I64(-101)]
            ),
            "Calling COMPLETION_VOID for xid=0xfffffffe failed=0 rc=-101"
        );
        assert_eq!(
            text(
                LogSite::SendGetData,
                vec![
                    LogArg::I64(5),
                    LogArg::Str(JString::Null),
                    LogArg::Endpoint(Some(addr))
                ]
            ),
            "Sending request xid=0x5 for path [(null)] to 127.0.0.1:2181"
        );
    }

    #[test]
    fn a_missing_or_extra_argument_is_not_lost() {
        assert_eq!(
            text(LogSite::AuthSchemeSucceeded, Vec::new()),
            "Authentication scheme ? succeeded"
        );
        assert_eq!(
            text(LogSite::PingResponse, vec![LogArg::I64(3), LogArg::U64(9)]),
            "Got ping response in 3 ms 9"
        );
        assert_eq!(
            text(
                LogSite::ResolveGai,
                vec![LogArg::GaiStr {
                    gai_rc: 8,
                    errno: 0
                }]
            ),
            "getaddrinfo: name resolution failed (getaddrinfo rc 8)"
        );
    }

    #[test]
    fn a_socket_site_renders_the_errno_text() {
        let s = text(
            LogSite::SockConnectFailed,
            vec![
                LogArg::Endpoint(None),
                LogArg::I64(-4),
                LogArg::I64(111),
                LogArg::ErrnoStr(111),
            ],
        );
        let errno = std::io::Error::from_raw_os_error(111).to_string();
        assert_eq!(
            s,
            format!("Socket (none) zk retcode=-4, errno=111({errno}): connect() call failed")
        );
    }

    #[test]
    fn a_panic_text_names_the_message() {
        let p: Box<dyn Any + Send> = Box::new("boom");
        let t = PanicText {
            what: "hook",
            payload: &*p,
        };
        assert_eq!(t.to_string(), "hook: boom");
        let p: Box<dyn Any + Send> = Box::new(7_u8);
        let t = PanicText {
            what: "hook",
            payload: &*p,
        };
        assert_eq!(t.to_string(), "hook");
    }

    /// The `tracing` backend: the level filter, the targets and the
    /// fields. It is the only test of this binary that installs a
    /// subscriber, because the max level of `tracing` is global.
    #[cfg(feature = "tracing")]
    #[test]
    fn tracing_filters_by_level_and_carries_the_fields() {
        use tracing::field::{Field, Visit};
        use tracing::span::{Attributes, Id, Record};
        use tracing::{Event, Metadata, Subscriber};

        #[derive(Default)]
        struct Fields {
            client: Option<String>,
            site: Option<String>,
            message: Option<String>,
        }

        impl Visit for Fields {
            fn record_str(&mut self, field: &Field, value: &str) {
                match field.name() {
                    "client" => self.client = Some(value.to_owned()),
                    "site" => self.site = Some(value.to_owned()),
                    _ => {}
                }
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.message = Some(format!("{value:?}"));
                }
            }
        }

        type Seen = Arc<Mutex<Vec<(String, tracing::Level, Fields)>>>;

        struct Capture {
            seen: Seen,
        }

        impl Subscriber for Capture {
            fn enabled(&self, m: &Metadata<'_>) -> bool {
                *m.level() <= tracing::Level::INFO
            }
            fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
                Some(tracing::level_filters::LevelFilter::INFO)
            }
            fn new_span(&self, _: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }
            fn record(&self, _: &Id, _: &Record<'_>) {}
            fn record_follows_from(&self, _: &Id, _: &Id) {}
            fn event(&self, e: &Event<'_>) {
                let mut f = Fields::default();
                e.record(&mut f);
                self.seen.lock_unpoisoned().push((
                    e.metadata().target().to_owned(),
                    *e.metadata().level(),
                    f,
                ));
            }
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
        }

        let seen: Seen = Arc::default();
        let sub = Capture {
            seen: Arc::clone(&seen),
        };
        let named = Observer::new(Some("c1".into()), None);
        let anon = Observer::new(None, None);
        let addr: SocketAddr = "127.0.0.1:2181".parse().unwrap();
        let emit_all = || {
            named.log(&LogRecord {
                site: LogSite::InitiatedConnection,
                level: LogLevel::Info,
                args: vec![LogArg::Endpoint(Some(addr))],
            });
            // A debug record is below the filter.
            named.log(&LogRecord {
                site: LogSite::PingResponse,
                level: LogLevel::Debug,
                args: vec![LogArg::I64(1)],
            });
            anon.log(&LogRecord {
                site: LogSite::UnexpectedResponse,
                level: LogLevel::Error,
                args: Vec::new(),
            });

            // A metrics panic gives one error record.
            let hook = Arc::new(Counting {
                panic_on_state: true,
                ..Counting::default()
            });
            let o = observer(&hook);
            o.state_changed(SessionState::Connecting);
            o.state_changed(SessionState::Connecting);
        };
        tracing::subscriber::with_default(sub, || {
            assert!(named.log_enabled(LogLevel::Error));
            assert!(named.log_enabled(LogLevel::Info));
            assert!(!named.log_enabled(LogLevel::Debug));
            // Tracing caches the interest of a callsite when the callsite
            // registers. Another test thread can register a callsite at
            // the same time with no subscriber, and then the cache says
            // "never". The first pass registers every callsite, the
            // rebuild corrects the cache, and only the second pass counts.
            emit_all();
            tracing::callsite::rebuild_interest_cache();
            seen.lock_unpoisoned().clear();
            emit_all();
        });
        let seen = seen.lock_unpoisoned();
        assert_eq!(
            seen.len(),
            3,
            "{:?}",
            seen.iter().map(|s| &s.0).collect::<Vec<_>>()
        );
        let (target, level, f) = &seen[0];
        assert_eq!(target, "apache_zookeeper::session");
        assert_eq!(*level, tracing::Level::INFO);
        assert_eq!(f.client.as_deref(), Some("c1"));
        assert_eq!(f.site.as_deref(), Some("InitiatedConnection"));
        assert_eq!(
            f.message.as_deref(),
            Some("Initiated connection to server 127.0.0.1:2181")
        );
        let (target, level, f) = &seen[1];
        assert_eq!(target, "apache_zookeeper::proto");
        assert_eq!(*level, tracing::Level::ERROR);
        assert_eq!(f.client, None);
        let (target, level, f) = &seen[2];
        assert_eq!(target, "apache_zookeeper");
        assert_eq!(*level, tracing::Level::ERROR);
        assert_eq!(f.client.as_deref(), Some("c1"));
        assert_eq!(
            f.message.as_deref(),
            Some("the metrics hook panicked and is disabled for this client: hook bug")
        );
    }

    /// The `log` backend (feature `log` without `tracing`). It is the
    /// only test of this binary that installs a logger. Other tests can
    /// log at the same time, so the test keeps only the lines of its own
    /// client name.
    #[cfg(all(feature = "log", not(feature = "tracing")))]
    #[test]
    fn log_filters_by_level_and_names_the_client() {
        struct Capture;
        static SEEN: Mutex<Vec<(String, log::Level, String)>> = Mutex::new(Vec::new());
        impl log::Log for Capture {
            fn enabled(&self, m: &log::Metadata<'_>) -> bool {
                m.level() <= log::Level::Info
            }
            fn log(&self, r: &log::Record<'_>) {
                if self.enabled(r.metadata()) {
                    SEEN.lock_unpoisoned().push((
                        r.target().to_owned(),
                        r.level(),
                        r.args().to_string(),
                    ));
                }
            }
            fn flush(&self) {}
        }
        static LOGGER: Capture = Capture;
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);

        let o = Observer::new(Some("log-test".into()), None);
        assert!(o.log_enabled(LogLevel::Warn));
        assert!(!o.log_enabled(LogLevel::Debug));
        o.log(&LogRecord {
            site: LogSite::SendGetData,
            level: LogLevel::Debug,
            args: Vec::new(),
        });
        o.log(&LogRecord {
            site: LogSite::DelayingConnection,
            level: LogLevel::Warn,
            args: vec![LogArg::Str(JString::from("a:1"))],
        });
        let seen: Vec<_> = SEEN
            .lock_unpoisoned()
            .iter()
            .filter(|s| s.2.starts_with("[log-test]"))
            .cloned()
            .collect();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "apache_zookeeper::session");
        assert_eq!(seen[0].1, log::Level::Warn);
        assert_eq!(
            seen[0].2,
            "[log-test] Delaying connection after exhaustively trying all servers [a:1] \
             (site DelayingConnection)"
        );
    }

    /// With no backend, nothing is enabled.
    #[cfg(not(any(feature = "tracing", feature = "log")))]
    #[test]
    fn no_backend_enables_nothing() {
        let o = Observer::new(Some("c1".into()), None);
        assert!(!o.log_enabled(LogLevel::Error));
        o.log(&LogRecord {
            site: LogSite::Closing,
            level: LogLevel::Info,
            args: Vec::new(),
        });
    }
}
