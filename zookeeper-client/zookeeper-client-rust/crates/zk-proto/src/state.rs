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

//! The visible session state, the internal phase and the teardown causes.
//!
//! [`State`] is the value that C applications read. The internal
//! `Phase` drives the logic. The two differ where C shows a stale value.

use crate::compat::DisconnectRc;
use crate::rc;
use crate::time::Millis;

/// The session state as C reports it (`zoo_state`).
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// `ZOO_CLOSED_STATE`, and the state after a recoverable teardown.
    Closed = 0,
    /// `ZOO_CONNECTING_STATE`.
    Connecting = 1,
    /// `ZOO_ASSOCIATING_STATE`.
    Associating = 2,
    /// `ZOO_CONNECTED_STATE`.
    Connected = 3,
    /// `ZOO_READONLY_STATE`.
    ReadOnly = 5,
    /// `ZOO_SSL_CONNECTING_STATE`.
    SslConnecting = 7,
    /// `ZOO_NOTCONNECTED_STATE`: the first state, and the state after a
    /// forced close.
    NotConnected = 999,
    /// `ZOO_EXPIRED_SESSION_STATE`. It is terminal.
    ExpiredSession = -112,
    /// `ZOO_AUTH_FAILED_STATE`. It is terminal.
    AuthFailed = -113,
}

impl State {
    /// Returns the C integer value.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Closed => 0,
            Self::Connecting => 1,
            Self::Associating => 2,
            Self::Connected => 3,
            Self::ReadOnly => 5,
            Self::SslConnecting => 7,
            Self::NotConnected => 999,
            Self::ExpiredSession => -112,
            Self::AuthFailed => -113,
        }
    }

    /// Returns the state of a C integer value, or `None` for other values.
    #[must_use]
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Closed),
            1 => Some(Self::Connecting),
            2 => Some(Self::Associating),
            3 => Some(Self::Connected),
            5 => Some(Self::ReadOnly),
            7 => Some(Self::SslConnecting),
            999 => Some(Self::NotConnected),
            -112 => Some(Self::ExpiredSession),
            -113 => Some(Self::AuthFailed),
            _ => None,
        }
    }

    /// Returns true for the connected states 3 and 5.
    #[must_use]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected | Self::ReadOnly)
    }

    /// Returns true for the negative states, as C `is_unrecoverable` does.
    #[must_use]
    pub const fn is_unrecoverable(self) -> bool {
        self.code() < 0
    }

    /// Returns the name that C `state2String` gives.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        state_name(self.code())
    }
}

/// Returns the name that C `state2String` gives for any integer.
#[must_use]
pub const fn state_name(code: i32) -> &'static str {
    match code {
        0 => "ZOO_CLOSED_STATE",
        1 => "ZOO_CONNECTING_STATE",
        7 => "ZOO_SSL_CONNECTING_STATE",
        2 => "ZOO_ASSOCIATING_STATE",
        3 => "ZOO_CONNECTED_STATE",
        5 => "ZOO_READONLY_STATE",
        -112 => "ZOO_EXPIRED_SESSION_STATE",
        -113 => "ZOO_AUTH_FAILED_STATE",
        _ => "INVALID_STATE",
    }
}

/// Returns the name that C `watcherEvent2String` gives for an event type.
#[must_use]
pub const fn event_name(event_type: i32) -> &'static str {
    match event_type {
        0 => "ZOO_ERROR_EVENT",
        1 => "ZOO_CREATED_EVENT",
        2 => "ZOO_DELETED_EVENT",
        3 => "ZOO_CHANGED_EVENT",
        4 => "ZOO_CHILD_EVENT",
        -1 => "ZOO_SESSION_EVENT",
        -2 => "ZOO_NOTWATCHING_EVENT",
        _ => "INVALID_EVENT",
    }
}

/// The per-connection SASL negotiation flags.
///
/// The core makes a new value at each prime response, so no flag survives
/// into the next connection. C keeps `is_gssapi` across sessions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct SaslNegotiation {
    /// True when the mechanism is GSSAPI.
    pub(crate) is_gssapi: bool,
    /// True when GSSAPI finished and the next server packet is the last.
    pub(crate) gssapi_last_packet: bool,
    /// True when the last token went out and the core waits for the final
    /// server reply.
    pub(crate) awaiting_final: bool,
}

/// The internal connection phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum Phase {
    /// No transport.
    #[default]
    Idle,
    /// The TCP connect runs.
    TcpConnecting,
    /// The TLS handshake runs. It must end before the deadline.
    TlsHandshaking {
        /// TCP completion plus 2/3 of the session timeout.
        deadline: Millis,
    },
    /// The TLS configuration failed. The transport stays, with no write
    /// interest, until the receive deadline. C retries on every write event
    /// and spins.
    TlsConfigFailed,
    /// The `ConnectRequest` is queued or sent. The core waits for the
    /// `ConnectResponse`.
    Associating,
    /// The SASL negotiation runs.
    Sasl(SaslNegotiation),
    /// The session is established.
    Established,
}

/// The cause of a teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Cause {
    /// The TCP connect failed.
    ConnectFailed,
    /// A socket read or write failed.
    Io,
    /// The server closed the stream.
    Eof,
    /// The socket could not be made, or the address list is empty.
    SocketCreate,
    /// A TLS resource or handshake failure.
    Tls,
    /// The TLS handshake did not end before its deadline.
    TlsHandshakeTimeout,
    /// No frame arrived for 2/3 of the session timeout, or the native TCP
    /// connect bound expired.
    RecvTimeout,
    /// A reply did not match the head of the pending queue.
    XidMismatch,
    /// A frame could not be decoded.
    ProtocolError,
    /// The server expired the session.
    SessionExpired,
    /// The server rejected an `add_auth` credential.
    AuthFailed,
    /// The read-only probe found a read-write server.
    RwServerFound,
    /// A SASL negotiation failed.
    SaslTeardown,
    /// The remaining stages of a forced close.
    ForcedClose,
}

impl Cause {
    /// Returns true when the cause ends the session: `SessionExpired`,
    /// `AuthFailed` and `SaslTeardown`.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::SessionExpired | Self::AuthFailed | Self::SaslTeardown
        )
    }

    /// Returns true when the teardown runs stage T5 (`handle_error`).
    /// `RwServerFound` and `ForcedClose` do not run it.
    #[must_use]
    pub const fn runs_handle_error(self) -> bool {
        !matches!(self, Self::RwServerFound | Self::ForcedClose)
    }

    /// Returns the rc that the teardown gives to pending work, under the
    /// rule of `Compat::disconnect_rc`.
    #[must_use]
    pub const fn rc_for(self, rule: DisconnectRc) -> i32 {
        let per_cause = match self {
            Self::ConnectFailed
            | Self::Io
            | Self::Eof
            | Self::ProtocolError
            | Self::RwServerFound
            | Self::ForcedClose => rc::ZCONNECTIONLOSS,
            Self::SocketCreate => rc::ZSYSTEMERROR,
            Self::Tls => rc::ZSSLCONNECTIONERROR,
            Self::RecvTimeout | Self::TlsHandshakeTimeout => rc::ZOPERATIONTIMEOUT,
            Self::XidMismatch => rc::ZRUNTIMEINCONSISTENCY,
            Self::SessionExpired => rc::ZSESSIONEXPIRED,
            Self::AuthFailed | Self::SaslTeardown => rc::ZAUTHFAILED,
        };
        match rule {
            DisconnectRc::PerCause => per_cause,
            DisconnectRc::ConnectionLoss => {
                if self.is_terminal() {
                    per_cause
                } else {
                    rc::ZCONNECTIONLOSS
                }
            }
        }
    }
}
