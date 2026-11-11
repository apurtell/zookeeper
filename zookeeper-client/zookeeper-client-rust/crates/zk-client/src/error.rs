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

//! Errors.
//!
//! The module holds the code tables, the predicates, the
//! `Display` texts, `map_submit_error` and `last_error_for`.

use std::borrow::Cow;
use std::sync::Arc;

use zk_proto::{Cause, Stage};

use crate::observe::OpKind;
use crate::path::PathError;

/// The error of a request.
///
/// The type is flat, `Clone` and `Eq`, because one teardown fails many
/// requests with the same value. The server codes map 1:1 to the C
/// `ZOO_ERRORS` values. A recoverable teardown always gives
/// [`Error::ConnectionLoss`]; the cause is in
/// [`SessionInfo::last_error`](crate::SessionInfo::last_error).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// -1: a system error.
    SystemError,
    /// -2: a runtime inconsistency.
    RuntimeInconsistency,
    /// -3: a data inconsistency.
    DataInconsistency,
    /// -4: the connection to the server was lost. Natively every
    /// recoverable teardown gives it.
    ConnectionLoss,
    /// -5: a reply could not be decoded.
    MarshallingError,
    /// -6: the server does not implement the operation.
    Unimplemented,
    /// -7: the operation timed out. Natively only `close` gives it.
    OperationTimeout,
    /// -8: invalid arguments.
    BadArguments,
    /// -9: invalid state. A blocking wait on the IO side of the client
    /// gives it too.
    InvalidState,
    /// -13: the new configuration has no quorum.
    NewConfigNoQuorum,
    /// -14: a reconfiguration is in progress.
    ReconfigInProgress,
    /// -15: a TLS connection error.
    SslConnectionError,
    /// -100: an API error.
    ApiError,
    /// -101: the node does not exist.
    NoNode,
    /// -102: not authorized.
    NoAuth,
    /// -103: the version does not match.
    BadVersion,
    /// -108: ephemeral nodes cannot have children.
    NoChildrenForEphemerals,
    /// -110: the node exists.
    NodeExists,
    /// -111: the node has children.
    NotEmpty,
    /// -112: the session expired. It is terminal.
    SessionExpired,
    /// -113: an invalid callback.
    InvalidCallback,
    /// -114: an invalid ACL.
    InvalidAcl,
    /// -115: authentication failed. It is terminal.
    AuthFailed,
    /// -116: the client is closed, closing or detached. It is terminal.
    Closing,
    /// -117: nothing.
    Nothing,
    /// -118: the session moved to another server.
    SessionMoved,
    /// -119: a write on a read-only server.
    NotReadOnly,
    /// -120: an ephemeral node on a local session.
    EphemeralOnLocalSession,
    /// -121: no such watcher.
    NoWatcher,
    /// -123: reconfiguration is disabled.
    ReconfigDisabled,
    /// -124: the session needs SASL authentication.
    SessionClosedRequireSaslAuth,
    /// -127: the server throttled the operation.
    ThrottledOp,
    /// -12: the session is unknown to the server (Java only).
    UnknownSession,
    /// -122: the request timed out on the server (Java only).
    RequestTimeout,
    /// -125: a quota was exceeded (Java only).
    QuotaExceeded,
    /// Any other non-zero wire code, unchanged.
    Unknown(i32),
    /// A path is not valid. Nothing went to the server. `code()` is -8.
    InvalidPath(PathError),
    /// An argument is not valid. Nothing went to the server. `code()` is
    /// -8.
    InvalidArgument(Cow<'static, str>),
    /// The `max_pending_requests` limit refused the request. `code()` is
    /// -127.
    TooManyPendingRequests,
}

/// Makes `code`, `from_code` and the Java text from one table. Each row
/// is a server code: the variant, the C code and the Java text. One table
/// keeps the three mappings the same. The client-side variants have their
/// own arms here. Each match stays exhaustive, so the compiler finds a
/// variant that has no code or no text.
macro_rules! server_codes {
    ($($variant:ident = $code:literal => $text:literal,)+) => {
        /// Returns the C code of the error, or the nearest legacy code for a
        /// client-side error.
        #[must_use]
        pub fn code(&self) -> i32 {
            match self {
                $(Self::$variant => $code,)+
                Self::Unknown(rc) => *rc,
                Self::InvalidPath(_) | Self::InvalidArgument(_) => -8,
                Self::TooManyPendingRequests => -127,
            }
        }

        /// Maps a wire code to an error. 0 gives `None`, and an unknown code
        /// gives [`Error::Unknown`].
        #[must_use]
        pub fn from_code(code: i32) -> Option<Error> {
            let e = match code {
                0 => return None,
                $($code => Self::$variant,)+
                other => Self::Unknown(other),
            };
            Some(e)
        }

        /// Writes the text of `Display`.
        fn write_text(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let text = match self {
                $(Self::$variant => $text,)+
                Self::Unknown(rc) => return write!(f, "KeeperErrorCode = Unknown error {rc}"),
                // The client-side errors have no Java code. Their text names
                // the local cause.
                Self::InvalidPath(e) => return write!(f, "{e}"),
                Self::InvalidArgument(why) => return write!(f, "invalid argument: {why}"),
                Self::TooManyPendingRequests => {
                    return f.write_str("too many pending requests (max_pending_requests)");
                }
            };
            write!(f, "KeeperErrorCode = {text}")
        }
    };
}

impl Error {
    server_codes! {
        SystemError = -1 => "SystemError",
        RuntimeInconsistency = -2 => "RuntimeInconsistency",
        DataInconsistency = -3 => "DataInconsistency",
        ConnectionLoss = -4 => "ConnectionLoss",
        MarshallingError = -5 => "MarshallingError",
        Unimplemented = -6 => "Unimplemented",
        OperationTimeout = -7 => "OperationTimeout",
        BadArguments = -8 => "BadArguments",
        InvalidState = -9 => "InvalidState",
        UnknownSession = -12 => "Unknown session",
        NewConfigNoQuorum = -13 => "NewConfigNoQuorum",
        ReconfigInProgress = -14 => "ReconfigInProgress",
        SslConnectionError = -15 => "SSL connection error",
        ApiError = -100 => "APIError",
        NoNode = -101 => "NoNode",
        NoAuth = -102 => "NoAuth",
        BadVersion = -103 => "BadVersion",
        NoChildrenForEphemerals = -108 => "NoChildrenForEphemerals",
        NodeExists = -110 => "NodeExists",
        NotEmpty = -111 => "Directory not empty",
        SessionExpired = -112 => "Session expired",
        InvalidCallback = -113 => "Invalid callback",
        InvalidAcl = -114 => "InvalidACL",
        AuthFailed = -115 => "AuthFailed",
        Closing = -116 => "Closing",
        Nothing = -117 => "Nothing",
        SessionMoved = -118 => "Session moved",
        NotReadOnly = -119 => "Not a read-only call",
        EphemeralOnLocalSession = -120 => "Ephemeral node on local session",
        NoWatcher = -121 => "No such watcher",
        RequestTimeout = -122 => "Request timeout",
        ReconfigDisabled = -123 => "Reconfig is disabled",
        SessionClosedRequireSaslAuth = -124 => "Session closed because client failed to authenticate",
        QuotaExceeded = -125 => "Quota has exceeded",
        ThrottledOp = -127 => "Op throttled due to high load",
    }

    /// True for `ConnectionLoss`, `OperationTimeout`,
    /// `SslConnectionError` and `RuntimeInconsistency`.
    #[must_use]
    pub fn is_connection_loss(&self) -> bool {
        matches!(
            self,
            Self::ConnectionLoss
                | Self::OperationTimeout
                | Self::SslConnectionError
                | Self::RuntimeInconsistency
        )
    }

    /// True for the terminal errors `SessionExpired`, `AuthFailed` and
    /// `Closing`.
    #[must_use]
    pub fn is_session_terminal(&self) -> bool {
        matches!(
            self,
            Self::SessionExpired | Self::AuthFailed | Self::Closing
        )
    }

    /// True when a retry of `op` after this error cannot apply a change
    /// twice. After a connection-loss-class error it is false for
    /// operations that are not idempotent: create, sequential create,
    /// multi, reconfig and add_auth.
    ///
    /// The writes `delete`, `set_data` and `set_acl` count as not
    /// idempotent too. A lost reply hides whether the server applied them,
    /// and a retry can change a node that another client changed in the
    /// meantime. After every other error the server did not apply the
    /// request, or a retry fails at once, so a retry is safe.
    #[must_use]
    pub fn is_retry_safe(&self, op: OpKind) -> bool {
        if !self.is_connection_loss() {
            return true;
        }
        !matches!(
            op,
            OpKind::Create
                | OpKind::Delete
                | OpKind::SetData
                | OpKind::SetAcl
                | OpKind::Multi
                | OpKind::Reconfig
                | OpKind::AddAuth
        )
    }
}

impl std::fmt::Display for Error {
    /// Gives the Java `KeeperException` text. `SslConnectionError` has a
    /// real text, which C does not have.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.write_text(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPath(e) => Some(e),
            _ => None,
        }
    }
}

impl From<PathError> for Error {
    fn from(e: PathError) -> Self {
        Self::InvalidPath(e)
    }
}

/// The result type of the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A shared connection-level error: an `io::Error`, a TLS error or a
/// [`DisconnectCause`].
pub(crate) type LastError = Arc<dyn std::error::Error + Send + Sync>;

/// The failure of `connect` or `build`. It has the request error and,
/// when one exists, the underlying cause.
#[derive(Debug, Clone)]
pub struct ConnectError {
    error: Error,
    cause: Option<LastError>,
}

impl ConnectError {
    /// Makes a connect error.
    pub(crate) fn new(error: Error, cause: Option<LastError>) -> Self {
        Self { error, cause }
    }

    /// Returns the request error.
    #[must_use]
    pub fn error(&self) -> &Error {
        &self.error
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            Some(c) => write!(f, "{}: {}", self.error, c),
            None => write!(f, "{}", self.error),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(c) => Some(&**c),
            None => None,
        }
    }
}

impl From<ConnectError> for Error {
    fn from(e: ConnectError) -> Self {
        e.error
    }
}

impl From<Error> for ConnectError {
    fn from(e: Error) -> Self {
        Self::new(e, None)
    }
}

/// Why the last connection ended, when no richer error exists. Requests
/// that the teardown failed see `ConnectionLoss`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DisconnectCause {
    /// No frame arrived within 2/3 of the session timeout.
    ReceiveTimeout,
    /// The TLS handshake did not end before its deadline.
    TlsHandshakeTimeout,
    /// A reply did not match the head of the pending queue.
    XidMismatch,
    /// A frame could not be decoded, or it was too large.
    MalformedFrame,
    /// The server closed the connection.
    ServerClosed,
}

impl std::fmt::Display for DisconnectCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReceiveTimeout => "no frame arrived within 2/3 of the session timeout",
            Self::TlsHandshakeTimeout => "the TLS handshake did not end before its deadline",
            Self::XidMismatch => "a reply did not match the oldest pending request",
            Self::MalformedFrame => "a frame from the server was malformed or too large",
            Self::ServerClosed => "the server closed the connection",
        })
    }
}

impl std::error::Error for DisconnectCause {}

/// The failure of a multi.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MultiError {
    /// The server rolled the transaction back.
    Aborted {
        /// The index of the first failed operation.
        index: usize,
        /// The error of that operation.
        error: Error,
        /// The code of each operation: `None` before `index`, `error` at
        /// `index`, and `RuntimeInconsistency` after it, as the server
        /// reports them.
        per_op: Vec<Option<Error>>,
    },
    /// The request as a whole failed: connection loss, a terminal
    /// state, `NotReadOnly`, or a local refusal.
    Request(Error),
}

impl From<MultiError> for Error {
    fn from(e: MultiError) -> Self {
        match e {
            MultiError::Aborted { error, .. } => error,
            MultiError::Request(error) => error,
        }
    }
}

impl From<Error> for MultiError {
    fn from(e: Error) -> Self {
        Self::Request(e)
    }
}

impl std::fmt::Display for MultiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aborted { index, error, .. } => {
                write!(
                    f,
                    "transaction rolled back: operation {index} failed: {error}"
                )
            }
            Self::Request(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MultiError {}

/// Why a watcher ended or skipped events.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WatchError {
    /// `remove_watches` removed the watcher.
    Removed,
    /// The watch was not restored after a reconnect. Only with
    /// `restore_watches(false)`.
    ConnectionLost,
    /// The session expired.
    SessionExpired,
    /// Authentication failed.
    AuthFailed,
    /// `close`, `detach` or the drop of the last `Client` ended the
    /// session.
    Closed,
    /// A persistent watcher dropped `missed` events because its buffer
    /// was full. The watcher stays active.
    Lagged {
        /// The number of dropped events.
        missed: u64,
    },
    /// A blocking wait on the IO side of the client. The watcher stays
    /// active.
    InvalidState,
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Removed => f.write_str("the watcher was removed"),
            Self::ConnectionLost => {
                f.write_str("the watch was not restored after the connection was lost")
            }
            Self::SessionExpired => f.write_str("the session expired"),
            Self::AuthFailed => f.write_str("authentication failed"),
            Self::Closed => f.write_str("the client is closed"),
            Self::Lagged { missed } => {
                write!(
                    f,
                    "the watcher dropped {missed} events because its buffer was full"
                )
            }
            Self::InvalidState => {
                f.write_str("a blocking wait is not allowed on the IO side of the client")
            }
        }
    }
}

impl std::error::Error for WatchError {}

/// Maps a proto submit refusal to an error.
///
/// `Stage::TooManyPending` gives `TooManyPendingRequests`. Every other
/// stage gives `Error::from_code(code)`, and a code of 0 gives
/// `SystemError`, because proto never refuses with 0.
pub(crate) fn map_submit_error(stage: Stage, code: i32) -> Error {
    match stage {
        Stage::TooManyPending => Error::TooManyPendingRequests,
        _ => Error::from_code(code).unwrap_or(Error::SystemError),
    }
}

/// Converts a result code to a result. 0 is `Ok`.
pub(crate) fn rc_result(rc: i32) -> Result<(), Error> {
    match Error::from_code(rc) {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

/// The change of `SessionInfo::last_error` after a teardown.
#[derive(Clone)]
pub(crate) enum LastErrorUpdate {
    /// Keep the value.
    Keep,
    /// Clear the value.
    Clear,
    /// Store this value.
    Set(LastError),
}

/// Maps a proto teardown cause to the `last_error` change.
///
/// `errno` is the OS error of the teardown, from the driver. The
/// connect, socket and IO causes give the OS error when it is known, so
/// `raw_os_error` names the real failure. With no errno they give a
/// synthetic `io::Error` with a text that names the cause.
///
/// `tls` is the error of the TLS options or of the native SASL
/// mechanism. A TLS configuration error replaces `ReceiveTimeout` for
/// `RecvTimeout`. A [`SaslError`](crate::SaslError) counts only for
/// `SaslTeardown`.
pub(crate) fn last_error_for(
    cause: Cause,
    errno: Option<i32>,
    tls: Option<LastError>,
) -> LastErrorUpdate {
    let disconnect = |c: DisconnectCause| -> LastErrorUpdate { LastErrorUpdate::Set(Arc::new(c)) };
    let io = |kind: std::io::ErrorKind, text: &'static str| -> LastErrorUpdate {
        LastErrorUpdate::Set(Arc::new(std::io::Error::new(kind, text)))
    };
    let os = |kind: std::io::ErrorKind, text: &'static str| -> LastErrorUpdate {
        match errno {
            Some(e) => LastErrorUpdate::Set(Arc::new(std::io::Error::from_raw_os_error(e))),
            None => io(kind, text),
        }
    };
    // Tls and RecvTimeout take the probed error, but never a SASL error.
    let tls_error = tls
        .as_ref()
        .filter(|e| !is_sasl(e))
        .map(|e| LastErrorUpdate::Set(Arc::clone(e)));
    match cause {
        Cause::ConnectFailed => os(
            std::io::ErrorKind::ConnectionRefused,
            "the TCP connect to the server failed",
        ),
        Cause::Io => os(
            std::io::ErrorKind::ConnectionReset,
            "a socket read or write failed",
        ),
        Cause::SocketCreate => os(
            std::io::ErrorKind::AddrNotAvailable,
            "no socket could be made, or no server address is known",
        ),
        Cause::Eof => disconnect(DisconnectCause::ServerClosed),
        Cause::Tls => tls_error.unwrap_or_else(|| {
            io(
                std::io::ErrorKind::InvalidData,
                "the TLS handshake or a TLS record failed",
            )
        }),
        Cause::TlsHandshakeTimeout => disconnect(DisconnectCause::TlsHandshakeTimeout),
        Cause::RecvTimeout => {
            tls_error.unwrap_or_else(|| disconnect(DisconnectCause::ReceiveTimeout))
        }
        Cause::XidMismatch => disconnect(DisconnectCause::XidMismatch),
        Cause::ProtocolError => disconnect(DisconnectCause::MalformedFrame),
        // A switch to a read-write server and a forced move are not
        // errors. The last error stays as it is.
        Cause::RwServerFound | Cause::ForcedClose => LastErrorUpdate::Keep,
        // The terminal state names the cause, so no last error is kept.
        Cause::SessionExpired | Cause::AuthFailed => LastErrorUpdate::Clear,
        Cause::SaslTeardown => sasl_teardown(tls),
        _ => LastErrorUpdate::Keep,
    }
}

/// Returns true when `e` is the error of the native SASL mechanism.
#[cfg(feature = "sasl")]
fn is_sasl(e: &LastError) -> bool {
    e.is::<crate::sasl::SaslError>()
}

/// A build without native SASL has no SASL error.
#[cfg(not(feature = "sasl"))]
fn is_sasl(_e: &LastError) -> bool {
    false
}

/// Gives the last error of a SASL teardown.
///
/// The error of the mechanism comes first. With no mechanism error, the
/// server refused the client, for example with a failed SASL reply.
#[cfg(feature = "sasl")]
fn sasl_teardown(probed: Option<LastError>) -> LastErrorUpdate {
    use crate::sasl::{SaslError, SaslErrorKind};
    match probed {
        Some(e) if is_sasl(&e) => LastErrorUpdate::Set(e),
        _ => LastErrorUpdate::Set(Arc::new(SaslError::new(
            SaslErrorKind::ServerRejected,
            "the server refused the SASL authentication",
        ))),
    }
}

/// A build without native SASL gives a synthetic `io::Error`. Only a
/// driver with a SASL session can start this teardown.
#[cfg(not(feature = "sasl"))]
fn sasl_teardown(_probed: Option<LastError>) -> LastErrorUpdate {
    LastErrorUpdate::Set(Arc::new(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "the SASL negotiation failed",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_errors() {
        assert_eq!(
            map_submit_error(Stage::TooManyPending, -127),
            Error::TooManyPendingRequests
        );
        assert_eq!(
            map_submit_error(Stage::NotEnabled, -6),
            Error::Unimplemented
        );
        assert_eq!(map_submit_error(Stage::Validate, -8), Error::BadArguments);
        assert_eq!(map_submit_error(Stage::Enqueue, -116), Error::Closing);
        assert_eq!(map_submit_error(Stage::Validate, 0), Error::SystemError);
    }

    /// The text of a `Set` update, or a marker for the other kinds.
    fn describe(u: &LastErrorUpdate) -> String {
        match u {
            LastErrorUpdate::Keep => "keep".to_owned(),
            LastErrorUpdate::Clear => "clear".to_owned(),
            LastErrorUpdate::Set(e) => format!("set: {e}"),
        }
    }

    fn set_cause(u: &LastErrorUpdate) -> Option<DisconnectCause> {
        match u {
            LastErrorUpdate::Set(e) => e.downcast_ref::<DisconnectCause>().copied(),
            _ => None,
        }
    }

    fn set_io(u: &LastErrorUpdate) -> Option<std::io::ErrorKind> {
        match u {
            LastErrorUpdate::Set(e) => e.downcast_ref::<std::io::Error>().map(|e| e.kind()),
            _ => None,
        }
    }

    #[test]
    fn last_error_table() {
        use DisconnectCause as D;
        let cases = [
            (Cause::Eof, D::ServerClosed),
            (Cause::TlsHandshakeTimeout, D::TlsHandshakeTimeout),
            (Cause::RecvTimeout, D::ReceiveTimeout),
            (Cause::XidMismatch, D::XidMismatch),
            (Cause::ProtocolError, D::MalformedFrame),
        ];
        for (cause, want) in cases {
            assert_eq!(
                set_cause(&last_error_for(cause, None, None)),
                Some(want),
                "{cause:?}"
            );
        }
        for cause in [
            Cause::ConnectFailed,
            Cause::Io,
            Cause::SocketCreate,
            Cause::Tls,
        ] {
            let u = last_error_for(cause, None, None);
            assert!(set_io(&u).is_some(), "{cause:?}: {}", describe(&u));
        }
        assert_eq!(
            set_io(&last_error_for(Cause::ConnectFailed, None, None)),
            Some(std::io::ErrorKind::ConnectionRefused)
        );
        for cause in [Cause::RwServerFound, Cause::ForcedClose] {
            assert_eq!(describe(&last_error_for(cause, None, None)), "keep");
        }
        for cause in [Cause::SessionExpired, Cause::AuthFailed] {
            assert_eq!(describe(&last_error_for(cause, None, None)), "clear");
        }
        #[cfg(not(feature = "sasl"))]
        assert!(set_io(&last_error_for(Cause::SaslTeardown, None, None)).is_some());
    }

    /// A SASL teardown keeps the mechanism error. With no mechanism
    /// error, the server refused the client. A TLS error does not count
    /// for this cause.
    #[cfg(feature = "sasl")]
    #[test]
    fn a_sasl_teardown_gives_a_sasl_error() {
        use crate::sasl::{CredentialError, SaslError, SaslErrorKind};
        let kind_of = |u: &LastErrorUpdate| match u {
            LastErrorUpdate::Set(e) => e.downcast_ref::<SaslError>().map(|e| e.kind.clone()),
            _ => None,
        };
        let mech: LastError = Arc::new(SaslError::new(
            SaslErrorKind::Credential(CredentialError::Permanent),
            "no password",
        ));
        let u = last_error_for(Cause::SaslTeardown, None, Some(Arc::clone(&mech)));
        assert_eq!(
            kind_of(&u),
            Some(SaslErrorKind::Credential(CredentialError::Permanent))
        );
        let tls: LastError = Arc::new(std::io::Error::other("bad CA file"));
        for probed in [None, Some(tls)] {
            let u = last_error_for(Cause::SaslTeardown, None, probed);
            assert_eq!(kind_of(&u), Some(SaslErrorKind::ServerRejected));
        }
        // A SASL error does not replace the error of a TLS cause.
        for cause in [Cause::Tls, Cause::RecvTimeout] {
            let u = last_error_for(cause, None, Some(Arc::clone(&mech)));
            assert_eq!(kind_of(&u), None, "{cause:?}");
        }
    }

    #[test]
    fn the_os_errno_wins_for_the_io_causes() {
        let timed_out = std::io::Error::from_raw_os_error(60);
        for cause in [Cause::ConnectFailed, Cause::Io, Cause::SocketCreate] {
            let (raw, text) = match last_error_for(cause, Some(60), None) {
                LastErrorUpdate::Set(e) => (
                    e.downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::raw_os_error),
                    e.to_string(),
                ),
                LastErrorUpdate::Keep | LastErrorUpdate::Clear => (None, String::new()),
            };
            assert_eq!(raw, Some(60), "{cause:?}");
            assert_eq!(text, timed_out.to_string(), "{cause:?}");
        }
        // Other causes ignore the errno.
        let u = last_error_for(Cause::Eof, Some(60), None);
        assert_eq!(set_cause(&u), Some(DisconnectCause::ServerClosed));
    }

    #[test]
    fn tls_probe_error_wins() {
        let tls: LastError = Arc::new(std::io::Error::other("bad CA file"));
        for cause in [Cause::RecvTimeout, Cause::Tls] {
            let u = last_error_for(cause, None, Some(Arc::clone(&tls)));
            assert_eq!(describe(&u), "set: bad CA file", "{cause:?}");
        }
        // Other causes keep their own error.
        let u = last_error_for(Cause::Eof, None, Some(tls));
        assert_eq!(set_cause(&u), Some(DisconnectCause::ServerClosed));
    }
}
