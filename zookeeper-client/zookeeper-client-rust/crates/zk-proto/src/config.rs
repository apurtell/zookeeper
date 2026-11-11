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

//! The configuration of one connection and the mode of its driver.
//!
//! [`Config`] holds the per-handle inputs. [`DriverMode`] holds the two
//! choices that depend on the driver and not on the profile.

use std::net::SocketAddr;

use zk_jute::JString;
use zk_jute::handshake::PASSWD_LEN;

use crate::legacy::addrvec::EndpointAddr;
use crate::legacy::connect::{HostSpec as LegacyHostSpec, NativeHost};

/// A session identity: the session id and the session password.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ClientId {
    /// The session id. 0 asks the server for a new session.
    pub session_id: i64,
    /// The session password.
    pub passwd: [u8; PASSWD_LEN],
}

impl core::fmt::Debug for ClientId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientId")
            .field("session_id", &format_args!("{:#x}", self.session_id))
            .field("passwd", &"<redacted>")
            .finish()
    }
}

/// One host entry of the connect string, in the form of its parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HostSpec {
    /// An entry from the legacy parser. The driver gives the raw host and
    /// service text to `getaddrinfo`.
    Legacy(LegacyHostSpec),
    /// An entry from the Java syntax parser of the native client.
    Native(NativeHost),
}

impl HostSpec {
    /// Returns the host text of the entry, without the port.
    #[must_use]
    pub fn host_bytes(&self) -> &[u8] {
        match self {
            Self::Legacy(h) => &h.host,
            Self::Native(h) => h.host.as_bytes(),
        }
    }
}

/// The connect-string host that an address came from.
///
/// The token travels with its address. The `WebPki` verifier checks the
/// server name against it. Equality of endpoints never reads it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct HostToken {
    /// The index of the host entry in the committed host list.
    pub index: usize,
    /// The host text of the entry, without the port.
    pub name: Vec<u8>,
}

/// A resolved server address and the host token it came from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// The socket address.
    pub addr: SocketAddr,
    /// The connect-string host of the address.
    pub host: HostToken,
}

impl EndpointAddr for Endpoint {
    fn socket_addr(&self) -> SocketAddr {
        self.addr
    }
}

/// The per-handle configuration.
///
/// The drop-in driver fills the legacy values of the native-only fields,
/// so the `LEGACY_C` behavior does not depend on them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The requested session timeout in milliseconds. It is not validated.
    pub timeout_ms: i32,
    /// The session to resume. A non-zero id counts as seen on a read-write
    /// server.
    pub client_id: ClientId,
    /// True when the client accepts read-only servers.
    pub allow_read_only: bool,
    /// True when the connection runs a SASL negotiation.
    pub sasl: bool,
    /// True when the connection uses TLS. The verifier policy is
    /// `Compat::tls_verify`.
    pub tls: bool,
    /// The host entries, in connect-string order.
    pub hosts: Vec<HostSpec>,
    /// The host list text as the connect string gives it, before the
    /// chroot. The "Delaying connection" log line prints it.
    pub host_text: JString,
    /// The chroot, or `None`. The caller validates it.
    pub chroot: Option<JString>,
    /// The resolution delay while a transport is open: -1 never, 0 always,
    /// `d > 0` after `d` milliseconds.
    pub resolve_delay_ms: i32,
    /// The first xid. Values of 0 or less give 1.
    pub xid_seed: i32,
    /// True when the C `char` type of the platform is signed. The default
    /// is [`TARGET_C_CHAR_SIGNED`], so the watcher table keeps the bucket
    /// order of the C client on the same target.
    ///
    /// [`TARGET_C_CHAR_SIGNED`]: crate::legacy::hashtable::TARGET_C_CHAR_SIGNED
    pub c_char_signed: bool,
    /// True when watches are restored after a reconnect (a native hook).
    pub restore_watches: bool,
    /// The limit of pending requests, or `None` for no limit (a native
    /// hook).
    pub max_pending: Option<usize>,
    /// The bound of the TCP connect phase (a native hook).
    pub connect_timeout_ms: Option<u32>,
    /// The first pause after a full host-list pass under
    /// `Backoff::Deadline` (a native hook). Later pauses grow from it.
    pub reconnect_delay_ms: u32,
    /// The jitter of the pause, in percent of `reconnect_delay_ms`.
    pub reconnect_jitter_pct: u8,
    /// The deadline of a `Drain` close (a native hook).
    pub close_timeout_ms: u32,
}

impl Config {
    /// Returns a configuration with the legacy values of the native-only
    /// fields and no host.
    #[must_use]
    pub fn legacy(timeout_ms: i32) -> Self {
        Self {
            timeout_ms,
            client_id: ClientId::default(),
            allow_read_only: false,
            sasl: false,
            tls: false,
            hosts: Vec::new(),
            host_text: JString::Bytes(Vec::new()),
            chroot: None,
            resolve_delay_ms: 0,
            xid_seed: 1,
            c_char_signed: crate::legacy::hashtable::TARGET_C_CHAR_SIGNED,
            restore_watches: true,
            max_pending: None,
            connect_timeout_ms: None,
            reconnect_delay_ms: 0,
            reconnect_jitter_pct: 0,
            close_timeout_ms: 0,
        }
    }
}

/// How the driver computes the write interest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InterestBits {
    /// The C rule of the single-threaded library.
    LegacyExact,
    /// Write interest only when `poll_transmit` has bytes.
    Precise,
}

/// How the driver delivers session events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionDelivery {
    /// Session outputs are barriers. The single-threaded driver runs the
    /// callbacks inline.
    Inline,
    /// Session outputs go to a dispatch queue.
    Dispatch,
}

/// The choices that depend on the driver, not on the profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DriverMode {
    /// The write interest rule.
    pub interest: InterestBits,
    /// The session event delivery rule.
    pub session_delivery: SessionDelivery,
}

impl DriverMode {
    /// The mode of the single-threaded C library.
    pub const ST: Self = Self {
        interest: InterestBits::LegacyExact,
        session_delivery: SessionDelivery::Inline,
    };
    /// The mode of the multi-threaded C library.
    pub const MT: Self = Self {
        interest: InterestBits::Precise,
        session_delivery: SessionDelivery::Dispatch,
    };
    /// The mode of the native Rust client.
    pub const NATIVE: Self = Self::MT;
}
