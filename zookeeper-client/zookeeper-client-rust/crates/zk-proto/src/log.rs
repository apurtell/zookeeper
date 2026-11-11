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

//! Structured log records and the pinned table of legacy log sites.
//!
//! The core never formats a line. It gives a [`LogSite`] and typed
//! arguments. The shim formats the line with the C format of the site, and
//! the native client gives the record to `tracing`.
//!
//! Each site has the C file, function, line and format of the legacy line.
//! The line of a `LOG_*` site is the line of the macro call. The line of a
//! `handle_socket_error_msg` site is the line of its `__LINE__` token. Its
//! format is the full `"Socket %s zk retcode=%d, errno=%d(%s): "` text with
//! the site text after it. A generated table from `tests/abi/log-sites.tsv`
//! replaces this hand-written table later. The variant names stay.

use std::net::SocketAddr;

use zk_jute::JString;

use crate::hooks::LogFilter;

/// The log levels of the C client (`ZOO_LOG_LEVEL_*`).
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// `ZOO_LOG_LEVEL_ERROR`.
    Error = 1,
    /// `ZOO_LOG_LEVEL_WARN`.
    Warn = 2,
    /// `ZOO_LOG_LEVEL_INFO`.
    Info = 3,
    /// `ZOO_LOG_LEVEL_DEBUG`.
    Debug = 4,
}

impl LogLevel {
    /// Returns the C integer value.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Error => 1,
            Self::Warn => 2,
            Self::Info => 3,
            Self::Debug => 4,
        }
    }
}

/// One typed argument of a log record. The shim maps each variant to one
/// C conversion of the site format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogArg {
    /// A signed integer for `%d`, `%x` or `%#x`. The shim narrows it to the
    /// C type of the conversion.
    I64(i64),
    /// An unsigned integer.
    U64(u64),
    /// A 64-bit value for `%#llx`, such as a session id.
    Ptr(u64),
    /// A string for `%s`. `JString::Null` prints `(null)`.
    Str(JString),
    /// A server address for `%s`, as `zoo_get_current_server` formats it.
    /// `None` prints the zeroed address.
    Endpoint(Option<SocketAddr>),
    /// The `strerror` text of an errno value, for `%s`.
    ErrnoStr(i32),
    /// The `gai_strerror` text, or the `strerror` text, as the resolver
    /// site of the platform prints it.
    GaiStr {
        /// The `getaddrinfo` return value.
        gai_rc: i32,
        /// The errno value of the failure.
        errno: i32,
    },
}

/// The static facts of one log site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SiteInfo {
    /// The variant name.
    pub name: &'static str,
    /// The level of the C line.
    pub level: LogLevel,
    /// The C source file.
    pub file: &'static str,
    /// The C function, as `__func__` gives it.
    pub func: &'static str,
    /// The C line number.
    pub line: u32,
    /// The C format.
    pub format: &'static str,
}

macro_rules! log_sites {
    ($( $name:ident => ($level:ident, $file:literal, $func:literal, $line:literal, $fmt:literal); )*) => {
        /// A pinned legacy log site. Each variant documents its C format.
        /// The format is a code span, so rustdoc does not read its square
        /// brackets as links.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum LogSite {
            $(
                #[doc = concat!("`", $fmt, "`")]
                $name,
            )*
        }

        impl LogSite {
            /// Every site, in table order.
            pub const ALL: &'static [Self] = &[$(Self::$name,)*];

            /// Returns the static facts of the site.
            #[must_use]
            pub const fn info(self) -> SiteInfo {
                match self {
                    $(
                        Self::$name => SiteInfo {
                            name: stringify!($name),
                            level: LogLevel::$level,
                            file: $file,
                            func: $func,
                            line: $line,
                            format: $fmt,
                        },
                    )*
                }
            }
        }
    };
}

log_sites! {
    ResolveNoPort => (Error, "zookeeper.c", "resolve_hosts", 876, "no port in %s");
    ResolveBadPort => (Error, "zookeeper.c", "resolve_hosts", 885, "invalid port in %s");
    ResolveWin32 => (Error, "zookeeper.c", "resolve_hosts", 983, "Win32 message: %s\n");
    ResolveGai => (Error, "zookeeper.c", "resolve_hosts", 985, "getaddrinfo: %s\n");
    ResolveGaiErrno => (Error, "zookeeper.c", "resolve_hosts", 987, "getaddrinfo: %s\n");
    ResolveSkipFamily => (Warn, "zookeeper.c", "resolve_hosts", 1016, "skipping unknown address family %x for %s");
    SetServersEmpty => (Error, "zookeeper.c", "zoo_set_servers", 1555, "New server list cannot be empty");
    ResolveDelayInvalid => (Error, "zookeeper.c", "zoo_set_servers_resolution_delay", 1580, "Resolution delay cannot be %d");
    ReconfigOld => (Debug, "zookeeper.c", "get_next_server_in_reconfig", 1614, "[OLD] count=%d capacity=%d next=%d hasnext=%d");
    ReconfigNew => (Debug, "zookeeper.c", "get_next_server_in_reconfig", 1617, "[NEW] count=%d capacity=%d next=%d hasnext=%d");
    ReconfigUseNew => (Debug, "zookeeper.c", "get_next_server_in_reconfig", 1628, "Using next from NEW=%s");
    ReconfigUseOld => (Debug, "zookeeper.c", "get_next_server_in_reconfig", 1635, "Using next from OLD=%s");
    ReconfigNone => (Debug, "zookeeper.c", "get_next_server_in_reconfig", 1639, "Failed to find either new or old");
    ChrootMismatch => (Error, "zookeeper.c", "sub_string", 1733, "server path %s does not include chroot path %s");
    CleanupSessionState => (Debug, "zookeeper.c", "cleanup", 2105, "Calling a watcher for a ZOO_SESSION_EVENT and the state=%s");
    CleanupSessionConnecting => (Debug, "zookeeper.c", "cleanup", 2109, "Calling a watcher for a ZOO_SESSION_EVENT and the state=CONNECTING_STATE");
    CleanupPrevious => (Debug, "zookeeper.c", "cleanup", 2114, "Previous connection=%s delay=%d");
    AuthSchemeFailed => (Error, "zookeeper.c", "auth_completion_func", 2173, "Authentication scheme %s failed. Connection closed.");
    AuthSchemeSucceeded => (Info, "zookeeper.c", "auth_completion_func", 2177, "Authentication scheme %s succeeded");
    SendAllAuth => (Debug, "zookeeper.c", "send_auth_info", 2227, "Sending all auth info request to %s");
    SendLastAuth => (Debug, "zookeeper.c", "send_last_auth_info", 2244, "Sending auth info request to %s");
    SendSetWatches => (Debug, "zookeeper.c", "send_set_watches", 2293, "Sending set watches request to %s");
    SockHandshakeSend => (Error, "zookeeper.c", "prime_connection", 2388, "Socket %s zk retcode=%d, errno=%d(%s): failed to send a handshake packet: %s");
    TcpNoDelay => (Warn, "zookeeper.c", "zookeeper_set_sock_nodelay", 2567, "Unable to set TCP_NODELAY, latency may be effected");
    ZkConnect => (Debug, "zookeeper.c", "zookeeper_connect", 2589, "[zk] connect()\n");
    DeadlineExceeded => (Warn, "zookeeper.c", "zookeeper_interest", 2641, "Exceeded deadline by %dms");
    DelayingConnection => (Warn, "zookeeper.c", "zookeeper_interest", 2671, "Delaying connection after exhaustively trying all servers [%s]");
    SockSocketFailed => (Error, "zookeeper.c", "zookeeper_interest", 2684, "Socket %s zk retcode=%d, errno=%d(%s): socket() call failed");
    SockConnectFailed => (Error, "zookeeper.c", "zookeeper_interest", 2708, "Socket %s zk retcode=%d, errno=%d(%s): connect() call failed");
    InitiatedConnection => (Info, "zookeeper.c", "zookeeper_interest", 2729, "Initiated connection to server %s");
    SockTimedOut => (Error, "zookeeper.c", "zookeeper_interest", 2759, "Socket %s zk retcode=%d, errno=%d(%s): connection to %s timed out (exceeded timeout by %dms)");
    PingSendFailed => (Error, "zookeeper.c", "zookeeper_interest", 2774, "failed to send PING request (zk retcode=%d)");
    RwServerFound => (Info, "zookeeper.c", "zookeeper_interest", 2794, "r/w server found at %s");
    TlsContextNew => (Error, "zookeeper.c", "init_ssl_for_socket", 2867, "error creating ssl context");
    SockTlsContextNew => (Error, "zookeeper.c", "init_ssl_for_socket", 2869, "Socket %s zk retcode=%d, errno=%d(%s): error creating ssl context");
    TlsCaFile => (Error, "zookeeper.c", "init_ssl_for_socket", 2881, "Failed to load CA file %s");
    TlsDefaultVerifyPaths => (Error, "zookeeper.c", "init_ssl_for_socket", 2888, "Call to SSL_CTX_set_default_verify_paths failed");
    TlsClientCertChain => (Error, "zookeeper.c", "init_ssl_for_socket", 2898, "Failed to load client certificate chain from %s");
    TlsClientKey => (Error, "zookeeper.c", "init_ssl_for_socket", 2907, "Failed to load client private key from %s");
    TlsCheckPrivateKey => (Error, "zookeeper.c", "init_ssl_for_socket", 2915, "SSL_CTX_check_private_key failed");
    SockTlsConnectionNew => (Error, "zookeeper.c", "init_ssl_for_socket", 2928, "Socket %s zk retcode=%d, errno=%d(%s): error creating ssl context");
    TlsConnectionNew => (Error, "zookeeper.c", "init_ssl_for_socket", 2930, "error creating ssl context");
    SockTlsConnect => (Error, "zookeeper.c", "init_ssl_for_socket", 2959, "Socket %s zk retcode=%d, errno=%d(%s): error in ssl connect");
    TlsConnect => (Error, "zookeeper.c", "init_ssl_for_socket", 2961, "error in ssl connect");
    SockTlsConnectSelect => (Error, "zookeeper.c", "init_ssl_for_socket", 2968, "Socket %s zk retcode=%d, errno=%d(%s): error in ssl connect (after select)");
    TlsConnectSelect => (Error, "zookeeper.c", "init_ssl_for_socket", 2970, "error in ssl connect (after select)");
    SessionEstablished => (Info, "zookeeper.c", "finalize_session_establishment", 2990, "session establishment complete on server %s, sessionId=%#llx, negotiated timeout=%d %s");
    FinalizeSessionEvent => (Debug, "zookeeper.c", "finalize_session_establishment", 3000, "Calling a watcher for a ZOO_SESSION_EVENT and the state=ZOO_CONNECTED_STATE");
    SaslQueued => (Debug, "zookeeper.c", "queue_sasl_request", 3037, "SASL: Queued request len=%d rc=%d");
    SaslProcessed => (Debug, "zookeeper.c", "process_sasl_response", 3065, "SASL: Processed response len=%d rc=%d");
    SockRefusedTls => (Error, "zookeeper.c", "check_events", 3089, "Socket %s zk retcode=%d, errno=%d(%s): server refused to accept the client");
    SockRefused => (Error, "zookeeper.c", "check_events", 3109, "Socket %s zk retcode=%d, errno=%d(%s): server refused to accept the client");
    InitiatedConnectionLate => (Info, "zookeeper.c", "check_events", 3116, "initiated connection to server %s");
    SockFlushFailed => (Error, "zookeeper.c", "check_events", 3124, "Socket %s zk retcode=%d, errno=%d(%s): failed while flushing send queue");
    SockRecvFailed => (Error, "zookeeper.c", "check_events", 3135, "Socket %s zk retcode=%d, errno=%d(%s): failed while receiving a server response");
    SockSessionExpired => (Error, "zookeeper.c", "check_events", 3172, "Socket %s zk retcode=%d, errno=%d(%s): sessionId=%#llx has expired.");
    CompletionData => (Debug, "zookeeper.c", "deserialize_response", 3343, "Calling COMPLETION_DATA for xid=%#x failed=%d rc=%d");
    CompletionStat => (Debug, "zookeeper.c", "deserialize_response", 3356, "Calling COMPLETION_STAT for xid=%#x failed=%d rc=%d");
    CompletionStringList => (Debug, "zookeeper.c", "deserialize_response", 3368, "Calling COMPLETION_STRINGLIST for xid=%#x failed=%d rc=%d");
    CompletionStringListStat => (Debug, "zookeeper.c", "deserialize_response", 3380, "Calling COMPLETION_STRINGLIST_STAT for xid=%#x failed=%d rc=%d");
    CompletionString => (Debug, "zookeeper.c", "deserialize_response", 3392, "Calling COMPLETION_STRING for xid=%#x failed=%d, rc=%d");
    CompletionStringStat => (Debug, "zookeeper.c", "deserialize_response", 3408, "Calling COMPLETION_STRING_STAT for xid=%#x failed=%d, rc=%d");
    CompletionAclList => (Debug, "zookeeper.c", "deserialize_response", 3423, "Calling COMPLETION_ACLLIST for xid=%#x failed=%d rc=%d");
    CompletionVoid => (Debug, "zookeeper.c", "deserialize_response", 3435, "Calling COMPLETION_VOID for xid=%#x failed=%d rc=%d");
    CompletionMulti => (Debug, "zookeeper.c", "deserialize_response", 3441, "Calling COMPLETION_MULTI for xid=%#x failed=%d rc=%d");
    CompletionUnsupported => (Debug, "zookeeper.c", "deserialize_response", 3452, "Unsupported completion type=%d");
    CallingWatcher => (Debug, "zookeeper.c", "process_completions", 3476, "Calling a watcher for node [%s], type = %d event=%s");
    ResponseLatency => (Debug, "zookeeper.c", "checkResponseLatency", 3525, "The following server response has spent at least %dms sitting in the client socket recv buffer");
    PingResponse => (Debug, "zookeeper.c", "zookeeper_process", 3559, "Got ping response in %d ms");
    ProcessingWatcherEvent => (Debug, "zookeeper.c", "zookeeper_process", 3567, "Processing WATCHER_EVENT");
    ProcessingSetWatches => (Debug, "zookeeper.c", "zookeeper_process", 3583, "Processing SET_WATCHES");
    ProcessingAuth => (Debug, "zookeeper.c", "zookeeper_process", 3586, "Processing AUTH_XID");
    ClearedByClose => (Debug, "zookeeper.c", "zookeeper_process", 3606, "Completion queue has been cleared by zookeeper_close()");
    UnexpectedResponse => (Debug, "zookeeper.c", "zookeeper_process", 3614, "Processing unexpected or out-of-order response!");
    SockUnexpectedXid => (Error, "zookeeper.c", "zookeeper_process", 3623, "Socket %s zk retcode=%d, errno=%d(%s): unexpected server response: expected %#x, but received %#x");
    QueueingAsync => (Debug, "zookeeper.c", "zookeeper_process", 3638, "Queueing asynchronous response");
    CloseWaitTimeout => (Warn, "zookeeper.c", "wait_for_session_to_be_closed", 3984, "Timed out (%dms) during waiting for server's reply after sending a close request, sessionId=%#llx\n");
    CloseWaitError => (Warn, "zookeeper.c", "wait_for_session_to_be_closed", 3987, "System error (%d) happened while waiting for server's reply, sessionId=%#llx\n");
    Closing => (Info, "zookeeper.c", "zookeeper_close", 4030, "Closing zookeeper sessionId=%#llx to %s\n");
    CloseError => (Debug, "zookeeper.c", "zookeeper_close", 4038, "Error during closing zookeeper session, sessionId=%#llx to %s (error: %d)\n");
    Freeing => (Info, "zookeeper.c", "zookeeper_close", 4053, "Freeing zookeeper resources for sessionId=%#llx\n");
    SendGetData => (Debug, "zookeeper.c", "zoo_awget", 4202, "Sending request xid=%#x for path [%s] to %s");
    SendGetConfig => (Debug, "zookeeper.c", "zoo_awgetconfig", 4246, "Sending request xid=%#x for path [%s] to %s");
    SendReconfig => (Debug, "zookeeper.c", "zoo_areconfig", 4283, "Sending Reconfig request xid=%#x to %s");
    SendSetData => (Debug, "zookeeper.c", "zoo_aset", 4327, "Sending request xid=%#x for path [%s] to %s");
    SendCreate => (Debug, "zookeeper.c", "zoo_acreate_ttl", 4454, "Sending request xid=%#x for path [%s] to %s");
    SendCreate2 => (Debug, "zookeeper.c", "zoo_acreate2_ttl", 4521, "Sending request xid=%#x for path [%s] to %s");
    SendDelete => (Debug, "zookeeper.c", "zoo_adelete", 4561, "Sending request xid=%#x for path [%s] to %s");
    SendExists => (Debug, "zookeeper.c", "zoo_awexists", 4600, "Sending request xid=%#x for path [%s] to %s");
    SendGetChildren => (Debug, "zookeeper.c", "zoo_awget_children_", 4633, "Sending request xid=%#x for path [%s] to %s");
    SendGetChildren2 => (Debug, "zookeeper.c", "zoo_awget_children2_", 4681, "Sending request xid=%#x for path [%s] to %s");
    SendSync => (Debug, "zookeeper.c", "zoo_async", 4724, "Sending request xid=%#x for path [%s] to %s");
    SendGetAcl => (Debug, "zookeeper.c", "zoo_aget_acl", 4754, "Sending request xid=%#x for path [%s] to %s");
    SendSetAcl => (Debug, "zookeeper.c", "zoo_aset_acl", 4785, "Sending request xid=%#x for path [%s] to %s");
    MultiUnimplemented => (Error, "zookeeper.c", "zoo_amulti", 4939, "Unimplemented sub-op type=%d in multi-op");
    SendMulti => (Debug, "zookeeper.c", "zoo_amulti", 4972, "Sending multi request xid=%#x with %d subrequests to %s");
    SendRemoveWatches => (Debug, "zookeeper.c", "aremove_watches", 5073, "Sending request xid=%#x for path [%s] to %s");
    SyncCompletion => (Debug, "zookeeper.c", "process_sync_completion", 5425, "Processing sync_completion with type=%d xid=%#x rc=%d");
    SyncUnsupported => (Debug, "zookeeper.c", "process_sync_completion", 5533, "Unsupported completion type=%d");
    SaslFailed => (Error, "zk_sasl.c", "_zsasl_fail", 151, "SASL authentication failed. rc=%d");
    SaslGetsockname => (Error, "zk_sasl.c", "zoo_sasl_connect", 224, "getsockname");
    SaslGetpeername => (Error, "zk_sasl.c", "zoo_sasl_connect", 236, "getpeername");
    SaslStartError => (Error, "zk_sasl.c", "zoo_sasl_client_start", 287, "Starting SASL negotiation: %s %s");
    SaslStart => (Debug, "zk_sasl.c", "zoo_sasl_client_start", 294, "SASL start sr:%d mech:%s client_data_len:%d");
    SaslRefuseReauth => (Debug, "zk_sasl.c", "zoo_sasl_client_start", 316, "SASL start %s: refusing reauthenticate");
    SaslServerData => (Debug, "zk_sasl.c", "zoo_sasl_client_step", 358, "SASL intermediate server_data_len:%d");
    SaslIntermediate => (Debug, "zk_sasl.c", "zoo_sasl_client_step", 371, "SASL intermediate sr:%d client_data_len:%d");
    SaslStepError => (Error, "zk_sasl.c", "zoo_sasl_client_step", 376, "During SASL negotiation: %s %s");
    WatcherOom => (Error, "zk_hashtable.c", "do_insert_watcher_object", 198, "Out of memory: dropped the watcher for path %s");
    PipeFailed => (Error, "mt_adaptor.c", "adaptor_init", 245, "Can't make a pipe %d");
}

impl LogSite {
    /// Returns the level of the site.
    #[must_use]
    pub const fn level(self) -> LogLevel {
        self.info().level
    }
}

/// One structured log record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    /// The site.
    pub site: LogSite,
    /// The level. It is the level of the site.
    pub level: LogLevel,
    /// The arguments, in the order of the site format.
    pub args: Vec<LogArg>,
}

/// The log record factory of one connection.
///
/// It owns the filter. Callers give the arguments as a closure, so a
/// disabled level costs no allocation.
pub(crate) struct Logger {
    filter: Box<dyn LogFilter>,
}

impl Logger {
    /// Makes a logger with the filter.
    pub(crate) fn new(filter: Box<dyn LogFilter>) -> Self {
        Self { filter }
    }

    /// Returns true when the filter enables the level of the site.
    pub(crate) fn enabled(&self, site: LogSite) -> bool {
        self.filter.enabled(site.level())
    }

    /// Returns a record for the site when the filter enables its level.
    /// The closure runs only in that case.
    pub(crate) fn record<F>(&self, site: LogSite, args: F) -> Option<LogRecord>
    where
        F: FnOnce() -> Vec<LogArg>,
    {
        if self.enabled(site) {
            Some(LogRecord {
                site,
                level: site.level(),
                args: args(),
            })
        } else {
            None
        }
    }
}

impl core::fmt::Debug for Logger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Logger")
    }
}

/// Returns a `Str` argument for a byte path.
#[must_use]
pub fn str_arg(bytes: &[u8]) -> LogArg {
    LogArg::Str(JString::Bytes(bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::{AllLevels, NoLevels};

    #[test]
    fn filter_skips_closure() {
        let off = Logger::new(Box::new(NoLevels));
        assert!(
            off.record(LogSite::PingResponse, || -> Vec<LogArg> {
                unreachable!("args must not be built")
            })
            .is_none()
        );
        let on = Logger::new(Box::new(AllLevels));
        let r = on.record(LogSite::PingResponse, || vec![LogArg::I64(3)]);
        assert_eq!(r.map(|r| r.level), Some(LogLevel::Debug));
    }
}
