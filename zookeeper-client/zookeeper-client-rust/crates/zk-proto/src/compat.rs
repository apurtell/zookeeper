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

//! The behavior profile of the core.
//!
//! [`Compat`] holds every behavior knob in one table. The C shim always uses
//! [`Compat::LEGACY_C`]. The native client starts from [`Compat::NATIVE`]
//! and can change some fields from its builder. The compatibility ledger
//! owns the values. This module owns the field names.
//!
//! An enum with one variant marks a registered fix (DV-FIX). Both profiles
//! use that variant, so the fix is on in every configuration.

pub use crate::legacy::addrvec::AddrEq;

/// The result code of pending work on a read-only to read-write switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RwSwitchRc {
    /// Every pending result gets `ZCONNECTIONLOSS`. C fakes a `ZOK` reply
    /// for each pending request instead.
    ConnectionLoss,
}

/// The behavior of a forced close.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ForcedClose {
    /// A snapshot teardown over the work of the closed connection. C keeps
    /// that work and replays it on the next connection.
    Teardown,
}

/// The cursor rule of the address list after a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CursorPolicy {
    /// The cursor advances once per failure. C can advance twice, and then
    /// it can retry one server for ever.
    SingleAdvance,
}

/// The behavior of a SASL failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SaslFailure {
    /// The digest-auth failure path: an AUTH_FAILED event and a teardown.
    Teardown,
}

/// The completion rule of `add_auth` tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthCompletion {
    /// Each AUTH reply completes only the token of its own auth packet,
    /// and its log line names the scheme of that packet. The
    /// core matches the replies to the packets in wire order.
    PerRequest,
}

/// The position of the auth packet that a live `add_auth` call queues.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthInsert {
    /// The priority boundary, as the front insert of C. The packet goes
    /// before the queued requests that are not started.
    Priority,
    /// The tail of the send queue, in call order.
    Tail,
}

/// The order of the auth packets that finalize sends again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthResend {
    /// The wire order is auth_n..auth_1, as C gives it.
    LegacyReverseFront,
    /// The wire order is auth_1..auth_n.
    Forward,
}

/// The watcher table implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WatchTable {
    /// The port of the C hash table, with its iteration order.
    LegacyHashtable,
    /// Path-keyed ordered tables with registration order.
    Ordered,
}

/// The session expiry rule of the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExpiryRule {
    /// Expired when a seen session id changes.
    Legacy,
    /// Also expired when the negotiated timeout is 0 or less.
    Java,
}

/// The behavior when the whole host list fails to resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsFailure {
    /// The resolver rc returns from the interest call, and no connect runs
    /// in that iteration.
    LegacyRcPreserved,
    /// The failure changes nothing, and the last good list stays.
    UseLastGood,
}

/// When the core resolves the host list while no transport is open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolveCadence {
    /// On every interest iteration.
    EveryIterationWhileDisconnected,
    /// Once per full host-list pass.
    EachPass,
    /// When more than `ms` milliseconds passed since the last good
    /// resolution.
    Throttled {
        /// The interval in milliseconds.
        ms: u32,
    },
    /// Only at init and in `set_servers`.
    Never,
}

/// The pause after a full host-list pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backoff {
    /// One iteration with a timeout of T/60, then a connect.
    OneShotSkip,
    /// A pause with jitter until `not_before`. The pause starts at
    /// `reconnect_delay_ms` and doubles after each failed pass, up to a cap.
    Deadline,
}

/// The `timeOut` value of the `ConnectRequest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HandshakeTimeout {
    /// The negotiated timeout after the first session.
    Negotiated,
    /// `Config::timeout_ms` on every handshake.
    Requested,
}

/// The close behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseMode {
    /// `begin_close` fails the pending work with `ZCLOSING` at once.
    LegacyFailPending,
    /// `begin_close` keeps the pending work until the close reply or the
    /// deadline.
    Drain,
}

/// The behavior on a negative frame length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NegativeLen {
    /// The decoder stalls until the receive timeout fires.
    StallUntilTimeout,
    /// The core tears down the connection at once.
    Disconnect,
}

/// The chroot join and strip rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChrootPolicy {
    /// C concatenation with escape checks. A path must start with "/", and a
    /// sequential create must not escape the chroot.
    LegacyConcatNoEscape,
    /// A join and a strip on path component boundaries.
    Component,
}

/// The rc of pending work at a disconnect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DisconnectRc {
    /// Each teardown cause has its own rc.
    PerCause,
    /// The recoverable causes give `ZCONNECTIONLOSS`. The terminal causes
    /// keep their codes.
    ConnectionLoss,
}

/// The TLS verifier policy. The driver builds the verifier from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsVerify {
    /// The OpenSSL trust decision of the C client, with no name check and
    /// no SNI.
    LegacyChainOnly,
    /// A name check against the host token, and SNI for DNS names.
    WebPki,
}

/// The behavior profile of one connection.
///
/// The type is `non_exhaustive`, so code outside the crate starts from a
/// profile constant and changes fields of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Compat {
    /// The rc of pending work on a read-only to read-write switch.
    pub rw_switch_rc: RwSwitchRc,
    /// The forced close behavior.
    pub forced_close: ForcedClose,
    /// The cursor rule after a failure.
    pub server_cursor: CursorPolicy,
    /// The endpoint equality rule.
    pub addr_eq: AddrEq,
    /// The SASL failure behavior.
    pub sasl_failure: SaslFailure,
    /// The completion rule of auth tokens.
    pub auth_completion: AuthCompletion,
    /// The position of the packet of a live `add_auth` call.
    pub auth_insert: AuthInsert,
    /// True when `add_auth` in the closed state (0) gives `ZINVALIDSTATE`,
    /// as C does since ZOOKEEPER-800.
    pub auth_reject_closed: bool,
    /// True when the core emits the auth lock points of C. The AUTH reply
    /// and the auth stage of a teardown then also stop at their `Auth`
    /// barriers.
    pub auth_lockpoints: bool,
    /// The resend order of auth packets.
    pub auth_resend: AuthResend,
    /// True when `add_auth` in the associating state sends the packet, and
    /// finalize sends it again.
    pub auth_dup_while_associating: bool,
    /// The watcher table implementation.
    pub watch_table: WatchTable,
    /// True when session events go to every path watcher.
    pub session_fanout_to_path_watchers: bool,
    /// True when session expiry clears the watcher tables.
    pub clear_watches_on_expiry: bool,
    /// The largest size of one SetWatches packet, or `None` for no limit.
    pub set_watches_batch: Option<u32>,
    /// True when the native-only operations are enabled.
    pub native_ops: bool,
    /// The largest frame body length, or `None` for no limit.
    pub max_frame_len: Option<u32>,
    /// The session expiry rule.
    pub expiry: ExpiryRule,
    /// The behavior on a whole-list resolution failure.
    pub dns_failure: DnsFailure,
    /// The resolution cadence while no transport is open.
    pub resolve_cadence: ResolveCadence,
    /// The pause after a full host-list pass.
    pub reconnect_backoff: Backoff,
    /// The `timeOut` value of the handshake.
    pub handshake_timeout: HandshakeTimeout,
    /// True when pings go out while requests are outstanding.
    pub ping_when_outstanding: bool,
    /// The close behavior.
    pub close_mode: CloseMode,
    /// The behavior on a negative frame length.
    pub negative_frame_len: NegativeLen,
    /// The chroot rule.
    pub chroot: ChrootPolicy,
    /// The rc of pending work at a disconnect.
    pub disconnect_rc: DisconnectRc,
    /// The TLS verifier policy.
    pub tls_verify: TlsVerify,
}

/// The SetWatches packet limit of both profiles: 128 KiB.
pub const SET_WATCHES_BATCH: u32 = 128 * 1024;

/// The native frame length limit: 4 MiB.
pub const NATIVE_MAX_FRAME_LEN: u32 = 4 * 1024 * 1024;

impl Compat {
    /// The profile of the C drop-in libraries. It keeps the C behavior,
    /// except for the registered fixes.
    pub const LEGACY_C: Self = Self {
        rw_switch_rc: RwSwitchRc::ConnectionLoss,
        forced_close: ForcedClose::Teardown,
        server_cursor: CursorPolicy::SingleAdvance,
        addr_eq: AddrEq::IpAndPort,
        sasl_failure: SaslFailure::Teardown,
        auth_completion: AuthCompletion::PerRequest,
        auth_insert: AuthInsert::Priority,
        auth_reject_closed: true,
        auth_lockpoints: true,
        auth_resend: AuthResend::LegacyReverseFront,
        auth_dup_while_associating: true,
        watch_table: WatchTable::LegacyHashtable,
        session_fanout_to_path_watchers: true,
        clear_watches_on_expiry: false,
        set_watches_batch: Some(SET_WATCHES_BATCH),
        native_ops: false,
        max_frame_len: None,
        expiry: ExpiryRule::Legacy,
        dns_failure: DnsFailure::LegacyRcPreserved,
        resolve_cadence: ResolveCadence::EveryIterationWhileDisconnected,
        reconnect_backoff: Backoff::OneShotSkip,
        handshake_timeout: HandshakeTimeout::Negotiated,
        ping_when_outstanding: false,
        close_mode: CloseMode::LegacyFailPending,
        negative_frame_len: NegativeLen::StallUntilTimeout,
        chroot: ChrootPolicy::LegacyConcatNoEscape,
        disconnect_rc: DisconnectRc::PerCause,
        tls_verify: TlsVerify::LegacyChainOnly,
    };

    /// The profile of the native Rust client.
    pub const NATIVE: Self = Self {
        rw_switch_rc: RwSwitchRc::ConnectionLoss,
        forced_close: ForcedClose::Teardown,
        server_cursor: CursorPolicy::SingleAdvance,
        addr_eq: AddrEq::IpAndPort,
        sasl_failure: SaslFailure::Teardown,
        auth_completion: AuthCompletion::PerRequest,
        auth_insert: AuthInsert::Tail,
        auth_reject_closed: false,
        auth_lockpoints: false,
        auth_resend: AuthResend::Forward,
        auth_dup_while_associating: false,
        watch_table: WatchTable::Ordered,
        session_fanout_to_path_watchers: false,
        clear_watches_on_expiry: true,
        set_watches_batch: Some(SET_WATCHES_BATCH),
        native_ops: true,
        max_frame_len: Some(NATIVE_MAX_FRAME_LEN),
        expiry: ExpiryRule::Java,
        dns_failure: DnsFailure::UseLastGood,
        resolve_cadence: ResolveCadence::EachPass,
        reconnect_backoff: Backoff::Deadline,
        handshake_timeout: HandshakeTimeout::Requested,
        ping_when_outstanding: true,
        close_mode: CloseMode::Drain,
        negative_frame_len: NegativeLen::Disconnect,
        chroot: ChrootPolicy::Component,
        disconnect_rc: DisconnectRc::ConnectionLoss,
        tls_verify: TlsVerify::WebPki,
    };

    /// Returns true when the auth lock points are emitted.
    #[must_use]
    pub const fn emits_lockpoints(&self) -> bool {
        self.auth_lockpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_differ_where_the_ledger_says() {
        let l = Compat::LEGACY_C;
        let n = Compat::NATIVE;
        assert_eq!(l.set_watches_batch, n.set_watches_batch);
        assert_eq!(l.addr_eq, AddrEq::IpAndPort);
        assert!(l.emits_lockpoints());
        assert!(!n.emits_lockpoints());
        // Both profiles complete each auth token on its own
        // reply. The other auth knobs keep the C behavior in LEGACY_C.
        assert_eq!(l.auth_completion, n.auth_completion);
        assert_eq!(l.auth_insert, AuthInsert::Priority);
        assert_eq!(n.auth_insert, AuthInsert::Tail);
        assert!(l.auth_reject_closed && !n.auth_reject_closed);
        assert_ne!(l, n);
    }
}
