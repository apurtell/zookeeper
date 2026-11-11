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

//! The driver actions and the results that come back from them.
//!
//! The core asks the driver for I/O through [`Action`] values. The driver
//! does the work with no core lock held. It then gives the result back
//! through a `handle_*` method of the connection.

use std::net::SocketAddr;

use zk_jute::JString;

use crate::compat::TlsVerify;
use crate::config::{Endpoint, HostSpec};
use crate::secret::SecretBytes;

/// One unit of I/O work for the driver.
#[derive(Debug)]
pub enum Action {
    /// Resolve the host list. The driver gives one
    /// `handle_host_resolved` call per host, then one `handle_resolved`.
    Resolve {
        /// The resolver generation. A result with another value is stale.
        generation: u64,
        /// The host entries, in connect-string order.
        hosts: Vec<HostSpec>,
        /// True for the first resolution of the connection.
        initial: bool,
    },
    /// Open a transport to the endpoint.
    Connect {
        /// The server.
        endpoint: Endpoint,
        /// The verifier policy, or `None` without TLS.
        tls: Option<TlsVerify>,
    },
    /// Close the transport. It always comes before a later `Connect`.
    CloseTransport,
    /// Probe the endpoint for a read-write server.
    ProbeRw {
        /// The server to probe.
        endpoint: Endpoint,
        /// The verifier policy, or `None` without TLS.
        tls: Option<TlsVerify>,
    },
    /// Call the SASL mechanism.
    Sasl(SaslCall),
}

/// One call to the SASL mechanism.
#[derive(Debug)]
pub struct SaslCall {
    /// The generation. `Start` takes a new value. `Step` carries the live
    /// value. `Dispose` carries the value of the `Start` that made the
    /// session. It is never 0.
    pub generation: u32,
    /// The call.
    pub kind: SaslCallKind,
}

/// The kind of a SASL call.
#[derive(Debug)]
pub enum SaslCallKind {
    /// Start a new mechanism session.
    Start,
    /// Give a server token to the mechanism. `None` stands for the server
    /// token of length -1.
    Step(Option<SecretBytes>),
    /// End the mechanism session.
    Dispose,
}

/// One result of the mechanism.
#[derive(Debug)]
pub struct SaslStep {
    /// The token to send, or `None`.
    pub token: Option<SecretBytes>,
    /// False while the mechanism continues (`SASL_CONTINUE`).
    pub done: bool,
}

/// A mechanism error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaslError {
    /// The rc. It is `ZSYSTEMERROR` for mechanism errors.
    pub rc: i32,
    /// The `sasl_errstring` text. The drop-in driver gives it empty.
    pub errstring: Vec<u8>,
    /// The `sasl_errdetail` text. The drop-in driver gives it empty.
    pub errdetail: Vec<u8>,
}

/// The socket address read that failed before the SASL start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SaslAddr {
    /// `getsockname`.
    Local,
    /// `getpeername`.
    Peer,
}

/// The result of one host entry of a resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostResolution {
    /// The index of the entry in the committed host list.
    pub host: usize,
    /// The addresses in resolver order, duplicates included, or the error.
    pub result: Result<Vec<SocketAddr>, ResolveError>,
    /// The address families that the resolver skipped, for the WARN line.
    pub skipped_families: Vec<i32>,
}

/// A resolver error of one host entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResolveError {
    /// The `getaddrinfo` return value.
    pub gai_rc: i32,
    /// The errno value, as C `getaddrinfo_errno` maps it.
    pub errno: i32,
}

/// The TLS object that could not be made. It selects the log site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsResourceAt {
    /// The client configuration: the `SSL_CTX_new` site.
    ContextNew,
    /// The client connection: the `SSL_new` site.
    ConnectionNew,
}

/// The TLS configuration step that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsConfigStep {
    /// The CA file.
    CaFile,
    /// The default verify paths.
    DefaultVerifyPaths,
    /// The client certificate chain.
    ClientCertChain,
    /// The client private key.
    ClientKey,
    /// The key and certificate match.
    CheckPrivateKey,
}

/// A transport failure. The `errno` of each variant is the value that the
/// legacy log line prints: the errno of the last failed socket call, or 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportFailure {
    /// `socket()` failed. Teardown with `ZSYSTEMERROR`.
    SocketCreate {
        /// The errno value.
        errno: i32,
    },
    /// The TCP connect failed. Teardown with `ZCONNECTIONLOSS`.
    TcpRefused {
        /// The errno value.
        errno: i32,
    },
    /// A read or write failed. Teardown with `ZCONNECTIONLOSS`.
    Io {
        /// The errno value.
        errno: i32,
    },
    /// The server closed the stream. Teardown with `ZCONNECTIONLOSS`.
    Eof,
    /// A TLS object could not be made. Teardown with
    /// `ZSSLCONNECTIONERROR`.
    TlsResource {
        /// The object.
        at: TlsResourceAt,
        /// The errno value.
        errno: i32,
    },
    /// The TLS handshake failed. Teardown with `ZSSLCONNECTIONERROR`.
    TlsHandshake {
        /// The errno value.
        errno: i32,
    },
    /// A TLS configuration step failed. The rc is `ZSSLCONNECTIONERROR`
    /// with the errno hint `EINVAL`. No teardown runs.
    TlsConfig {
        /// The step.
        step: TlsConfigStep,
        /// The file of the step, or `JString::Null`.
        file: JString,
    },
    /// The poll of the close flush failed. The rc is `ZSYSTEMERROR`.
    Poll {
        /// The errno value.
        errno: i32,
    },
}

/// A TLS failure of the read-only probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeTlsFailure {
    /// A configuration step failed.
    Config {
        /// The step.
        step: TlsConfigStep,
        /// The file of the step, or `JString::Null`.
        file: JString,
    },
    /// A TLS object could not be made.
    Resource {
        /// The object.
        at: TlsResourceAt,
    },
    /// The handshake failed.
    Handshake,
}

/// The result of one read-only probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The server answered `rw`.
    ReadWrite,
    /// The read completed, but the server did not answer `rw`.
    NotReadWrite,
    /// The probe failed. `Some` holds a TLS failure.
    Failed(Option<ProbeTlsFailure>),
}

/// How the TCP connect started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectStart {
    /// `connect()` returned `EINPROGRESS`.
    InProgress,
    /// `connect()` completed at once.
    Immediate,
}

/// The result of `finish_interest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterestOutcome {
    /// The rc of the interest call.
    pub rc: i32,
    /// The interest, or `None` where C returns before it writes its
    /// outputs.
    pub outputs: Option<Interest>,
}

/// The interest of one iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Interest {
    /// True when a transport is open after this call.
    pub has_socket: bool,
    /// True for read interest.
    pub read: bool,
    /// True for write interest.
    pub write: bool,
    /// The time to the next timer, in milliseconds.
    pub timeout_ms: u32,
}

/// The result of `handle_read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReadOutcome {
    /// The number of complete frames that the call processed.
    pub frames: usize,
    /// The number of input bytes that the call took.
    pub consumed: usize,
    /// The rc.
    pub rc: i32,
}

/// The result of `close_step`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseProgress {
    /// The close waits for the close reply or the deadline.
    Pending,
    /// The close is complete. The driver calls `destroy`.
    Complete,
}

/// A server watch that the native client must remove.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RemoveHint {
    /// The client path, with the chroot removed. The native client gives
    /// it to `submit` as a removeWatches path, and `submit` adds the
    /// chroot again.
    pub path: JString,
    /// The watch type for the `RemoveWatches` request.
    pub wtype: i32,
}
