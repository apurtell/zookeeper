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

//! `IoCore`: the step functions that every driver shares.
//!
//! [`IoCore`] holds the transport and the staging buffers of one handle.
//! Its owner is the IO owner: the mt IO thread, the st caller, the native
//! IO side, or the final closer after the IO thread is gone.
//! The `io` lock of the flavor holds it. The `core` lock holds the proto
//! `Connection` (`crate::state::Core`). The lock order is `io`, then
//! `core`. No lock is held across a blocking call: each blocking call
//! takes the [`Unlocked`] proof.
//!
//! The two steps:
//!
//! - `IoCore::interest_step` is the body of `zookeeper_interest`
//!   (zookeeper.c:2618-2824). It runs the proto actions and
//!   writes the interest outputs.
//! - `IoCore::process_step` is the body of `zookeeper_process` and
//!   `check_events` (zookeeper.c:3530-3667, 3073-3212).
//!
//! A step returns [`Progress::More`] at a barrier. C drains the outbox,
//! then calls `IoCore::resume`, which continues the step from the
//! stored continuation. The TLS parts of the I/O path are in
//! `crate::iocore_tls`.

use std::net::SocketAddr;

use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;
use zk_proto::compat::TlsVerify;
use zk_proto::rc::{
    ZCONNECTIONLOSS, ZINVALIDSTATE, ZNOTHING, ZOK, ZOPERATIONTIMEOUT, ZSYSTEMERROR,
};
use zk_proto::{
    Action, ConnectStart, Connection, Endpoint, HostResolution, HostSpec, LogArg, LogSite, Millis,
    ReadOutcome, SaslCallKind, State, TlsResourceAt, Tokens, TransportFailure,
};

use crate::clock::Clock;
use crate::dispatch::ReadGate;
use crate::host::{HostLeaves, log_record};
use crate::iocore_tls;
use crate::iocore_tls::WriteBursts;
use crate::net::poll::{Poll, PollEvents, ZOOKEEPER_READ, ZOOKEEPER_WRITE};
use crate::net::probe::{ProbeCtx, ProbeEnd, probe};
use crate::net::sock::{TcpSock, errno_value};
use crate::net::tls::{TlsConn, TlsConnector, TlsPurpose, TlsSetupError, TlsTransport};
use crate::net::waker::{WakeRx, Waker};
use crate::outbox::{Flavor, Item, Outbox, SaslItem};
use crate::resolve::{ResolveCtx, ResolveEnd, ResolveRun, apply_results, shuffle_on};
use crate::state::{Core, SaslAnswer};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::{Mutex, Unlocked};

/// The OS socket handle that the shim writes to `*fd`. It is
/// `int` on Unix.
#[cfg(unix)]
pub type RawSock = std::os::fd::RawFd;

/// The size of the heap read buffer.
pub const READ_BUFFER_LEN: usize = 64 * 1024;

/// The largest frame that one plaintext flush step takes from proto with
/// no copy. Proto lends such a frame as the buffer of
/// `tx_copy`, so one send can take all of it. Proto still copies at most
/// 64 KiB of other bytes in one step.
pub(crate) const TX_LEND_MAX: usize = 4 * 1024 * 1024;

/// The fixed driver parameters of one handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverConfig {
    /// The close flush budget (`CLOSE_FLUSH_MS`).
    pub close_flush_ms: u32,
    /// The close wait budget (`CLOSE_WAIT_MS`).
    pub close_wait_ms: u32,
    /// The deadline of each RW probe phase.
    pub probe_phase_ms: u64,
    /// The native read-gate capacity.
    pub dispatch_queue_capacity: usize,
    /// The largest read of mt and native plaintext.
    pub max_read: usize,
    /// True when sockets and pipes get `CLOEXEC`. Native drivers always
    /// set it. The drop-in uses the shim's `sock_cloexec` flag.
    pub cloexec: bool,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            close_flush_ms: zk_proto::CLOSE_FLUSH_MS,
            close_wait_ms: zk_proto::CLOSE_WAIT_MS,
            probe_phase_ms: crate::net::probe::PROBE_PHASE_MS,
            dispatch_queue_capacity: 4096,
            max_read: READ_BUFFER_LEN,
            cloexec: false,
        }
    }
}

/// The outputs of `zookeeper_interest` (`zkrs_interest_out`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterestOut {
    /// The rc of the call.
    pub rc: i32,
    /// True when the call wrote the outputs. False keeps the caller's
    /// values, as C does.
    pub written: bool,
    /// The socket, or -1 when there is none or this call closed it.
    pub fd: RawSock,
    /// `ZOOKEEPER_READ` and `ZOOKEEPER_WRITE` bits.
    pub bits: u32,
    /// The timeout in milliseconds.
    pub timeout_ms: i64,
}

impl InterestOut {
    /// The value before a call: rc `ZOK`, nothing written.
    pub const UNWRITTEN: Self = Self {
        rc: 0,
        written: false,
        fd: -1,
        bits: 0,
        timeout_ms: 0,
    };
}

/// The transport of one attempt.
pub(crate) enum Transport {
    /// No socket.
    None,
    /// The TCP connect is in progress (state 1, or 7 with TLS).
    Connecting {
        /// The socket.
        sock: TcpSock,
        /// The endpoint. A TLS session needs it for the server name.
        ep: Endpoint,
        /// The verifier profile when the attempt uses TLS.
        tls: Option<TlsVerify>,
    },
    /// A plaintext connection.
    Plain(TcpSock),
    /// A TLS session, in the handshake or the data phase.
    Tls(TlsTransport),
    /// The TLS configuration failed. The socket stays, with no session
    /// and no WRITE interest, so the receive timeout ends the attempt.
    Parked(TcpSock),
}

impl Transport {
    /// Returns the socket, if any.
    pub(crate) fn sock(&self) -> Option<&TcpSock> {
        match self {
            Self::None => None,
            Self::Connecting { sock, .. } | Self::Plain(sock) | Self::Parked(sock) => Some(sock),
            Self::Tls(t) => Some(t.sock()),
        }
    }
}

/// Where a suspended step continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cont {
    /// No step is suspended.
    None,
    /// `interest_step` stopped in its action loop or before
    /// `finish_interest`.
    Interest,
    /// `process_step` stopped in its frame loop.
    Process {
        /// The events of the call.
        events: PollEvents,
    },
    /// `interest_step` stopped before `begin_interest`.
    InterestBegin,
    /// `interest_step` stopped after `finish_interest`. The resume writes
    /// these outputs again and ends the call.
    InterestEnd {
        /// The outputs of the call.
        out: InterestOut,
    },
    /// The handshake start stopped before `new_conn`, so LOG items can
    /// drain. The socket waits in `Transport::Connecting`.
    Handshake,
    /// The handshake start is complete with this rc. The step of the
    /// handshake origin continues.
    AfterHandshake {
        /// The rc of the handshake start.
        rc: i32,
    },
    /// `process_step` stopped before its first check.
    ProcessBegin {
        /// The events of the call.
        events: PollEvents,
    },
    /// `process_step` stopped after its flush. The read comes next.
    ProcessRead {
        /// The events of the call.
        events: PollEvents,
    },
    /// `process_step` stopped after the TCP connect completed. One flush
    /// comes next, then `ZOK`.
    ProcessFlush,
    /// The TLS frame loop stopped (`iocore_tls::tls_frames`).
    TlsFrames {
        /// True when the frames came with the last handshake flight.
        handshake: bool,
    },
    /// The handshake completed and `handle_transport_ready` stopped at a
    /// barrier. The flush and the frame loop come next.
    HandshakeReady,
    /// The step is complete. The resume returns this rc.
    End {
        /// The rc of the step.
        rc: i32,
    },
    /// The step waits for a deferred job (`IoCore::complete_job`).
    Job,
}

/// The step that started a TLS handshake. The handshake result goes back
/// to this step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StepKind {
    /// `interest_step`, on the immediate connect path.
    Interest,
    /// `process_step`, on the EINPROGRESS connect path.
    Process,
}

/// The kind of the deferred job that a step waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JobKind {
    /// A `Job::Resolve`.
    Resolve,
    /// A `Job::NewConn`.
    NewConn,
    /// A `Job::Probe`.
    Probe,
}

/// One deferred resolution and the newest resolve action for its host
/// list.
///
/// Proto starts a new generation for each resolve action. A result is
/// valid only for the newest generation. A new action for the same host
/// list joins the job that runs, so the result of that job applies to
/// the newest generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DnsRun {
    /// The newest resolver generation for these hosts.
    pub(crate) generation: u64,
    /// The host entries.
    pub(crate) hosts: Vec<HostSpec>,
    /// True when the shuffle is on.
    pub(crate) shuffle: bool,
}

impl DnsRun {
    /// Makes the job that resolves these hosts.
    fn job(&self) -> Job {
        Job::Resolve {
            generation: self.generation,
            hosts: self.hosts.clone(),
            shuffle: self.shuffle,
        }
    }
}

/// A failure of a flush pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlushError {
    /// A send failed. Proto hears it as `Io`. The close rc is
    /// `ZCONNECTIONLOSS`.
    Send(Errno),
    /// The poll of a blocking send failed or reported `POLLERR`. The
    /// close rc is `ZSYSTEMERROR`.
    Poll(Errno),
    /// The deadline of a blocking send passed. The close rc is
    /// `ZOPERATIONTIMEOUT`.
    Timeout,
    /// The TLS session refused a chunk or holds a latched failure. The
    /// close rc is `ZCONNECTIONLOSS`.
    Session,
}

/// The result of one plaintext read.
enum Part {
    /// The read gave this many bytes. Zero means that the read blocked.
    Got(usize),
    /// The read completed a frame, and the pump stopped at a barrier.
    Barrier,
    /// The read failed.
    Failed(TransportFailure),
}

/// How the frame loop ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameEnd {
    /// The loop stopped at a barrier.
    More,
    /// No complete frame is left, or the decoder stalled.
    Done,
    /// The loop stopped for the SASL mechanism or for the read gate. The
    /// bytes stay in `rx_pending`.
    Held,
}

/// How one action of the interest loop ended.
enum Flow {
    /// The action loop goes on.
    Continue,
    /// The step returns this result.
    Return(Progress),
}

/// The result of one step call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The step is complete with this rc (`ZKRS_DONE`).
    Done(i32),
    /// The step stopped at a barrier, or LOG items wait before a blocking
    /// call, as in C. C drains, then calls `resume` (`ZKRS_MORE`).
    More,
    /// The tokio driver only: the step waits for deferred jobs
    /// (`IoCore::take_jobs`). It gives the results to
    /// `IoCore::complete_job`.
    Wait,
}

/// The blocking calls that a driver runs off the IO side.
///
/// The drop-in runs every call inline ([`DeferPolicy::NONE`]). The native
/// threaded driver defers resolution to a short-lived DNS thread. The
/// tokio driver defers all three to `spawn_blocking`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferPolicy {
    /// Defer `resolve` and `rng_reseed`.
    pub resolve: bool,
    /// Defer `TlsConnector::new_conn`.
    pub new_conn: bool,
    /// Defer the RW probe.
    pub probe: bool,
}

impl DeferPolicy {
    /// Run every blocking call inline (drop-in).
    pub const NONE: Self = Self {
        resolve: false,
        new_conn: false,
        probe: false,
    };
    /// The native threaded driver: resolution on a DNS thread.
    pub const DNS_THREAD: Self = Self {
        resolve: true,
        new_conn: false,
        probe: false,
    };
    /// The tokio driver: every blocking call on `spawn_blocking`.
    pub const ALL: Self = Self {
        resolve: true,
        new_conn: true,
        probe: true,
    };
}

/// A blocking call that the step deferred.
#[derive(Debug)]
pub(crate) enum Job {
    /// Resolve every host entry of one resolver generation, in order.
    Resolve {
        /// The resolver generation.
        generation: u64,
        /// The host entries.
        hosts: Vec<HostSpec>,
        /// True when the shuffle is on, so a reseed follows.
        shuffle: bool,
    },
    /// Make a TLS session.
    NewConn {
        /// The use of the session.
        purpose: TlsPurpose,
        /// The peer.
        endpoint: Endpoint,
    },
    /// Run the RW probe.
    Probe {
        /// The probe target.
        endpoint: Endpoint,
        /// The verifier profile when the probe uses TLS.
        tls: Option<TlsVerify>,
    },
}

/// The result of a deferred [`Job`].
pub(crate) enum JobDone {
    /// The results of every host entry, in order.
    Resolved {
        /// The resolver generation of the job.
        generation: u64,
        /// One result per host entry.
        results: Vec<HostResolution>,
    },
    /// The TLS session, or the setup failure.
    NewConn(Result<Box<dyn TlsConn>, TlsSetupError>),
    /// The probe result.
    Probe {
        /// The probe target.
        endpoint: Endpoint,
        /// The result.
        end: ProbeEnd,
    },
}

/// The services that a deferred job uses. Every field is owned by the
/// job thread or the tokio blocking task.
pub(crate) struct JobCtx<'a, T: Tokens> {
    /// The host leaves.
    pub(crate) host: &'a dyn HostLeaves<T>,
    /// The probe services.
    pub(crate) probe: ProbeCtx<'a>,
}

/// Runs one deferred job with no driver lock held.
///
/// - `Resolve`: one `resolve` leaf call per entry in order, then
///   `rng_reseed` when `shuffle` is on and an address resolved.
/// - `NewConn`: `TlsConnector::new_conn`. With no connector it fails as
///   `Resource{at: ContextNew}`.
/// - `Probe`: `net::probe::probe`.
pub(crate) fn run_job<T: Tokens>(cx: &JobCtx<'_, T>, proof: &Unlocked, job: Job) -> JobDone {
    match job {
        Job::Resolve {
            generation,
            hosts,
            shuffle,
        } => {
            let mut results = Vec::with_capacity(hosts.len());
            let mut any = false;
            for (i, spec) in hosts.iter().enumerate() {
                let r = cx.host.resolve(proof, i, spec);
                any = any || r.result.as_ref().is_ok_and(|a| !a.is_empty());
                results.push(r);
            }
            if shuffle && any {
                cx.host.rng_reseed(proof);
            }
            JobDone::Resolved {
                generation,
                results,
            }
        }
        Job::NewConn { purpose, endpoint } => JobDone::NewConn(match cx.probe.tls {
            Some(c) => c.new_conn(proof, purpose, &endpoint),
            None => Err(TlsSetupError::Resource {
                at: TlsResourceAt::ContextNew,
            }),
        }),
        Job::Probe { endpoint, tls } => {
            let end = probe(&cx.probe, proof, &endpoint, tls);
            JobDone::Probe { endpoint, end }
        }
    }
}

/// Returns true when the native read gate lets the step read frames. The
/// gate applies only to an established session.
pub(crate) fn gate_open<T: Tokens>(cx: &StepCtx<'_, T>, state: State) -> bool {
    !state.is_connected() || cx.gate.is_none_or(ReadGate::is_open)
}

/// Waits until `sock` is writable or `deadline` passes.
///
/// # Errors
///
/// Returns `Timeout` when the deadline passes, and `Poll` when the poll
/// call fails. A ready socket with `POLLERR` or `POLLNVAL` gives `Ok`, as
/// in zookeeper.c `flush_send_queue`. The next send then reports the
/// socket error as a connection loss.
pub(crate) fn wait_writable(
    clock: &dyn Clock,
    poll: &dyn Poll,
    sock: &TcpSock,
    deadline: Millis,
) -> Result<(), FlushError> {
    loop {
        let left = zk_proto::time::until(clock.now(), deadline);
        if left < 0 {
            return Err(FlushError::Timeout);
        }
        let ms = i32::try_from(left).unwrap_or(i32::MAX);
        let mut fds = [PollFd::new(sock, PollFlags::OUT)];
        match poll.poll(&mut fds, ms) {
            Err(Errno::INTR) => {}
            Err(e) => return Err(FlushError::Poll(e)),
            Ok(0) => return Err(FlushError::Timeout),
            Ok(_) => return Ok(()),
        }
    }
}

/// Sends a prefix of `buf` before `deadline`, with a poll for WRITE
/// before each send (zookeeper.c `flush_send_queue`).
fn send_until<T: Tokens>(
    cx: &StepCtx<'_, T>,
    sock: &TcpSock,
    buf: &[u8],
    deadline: Millis,
) -> Result<usize, FlushError> {
    loop {
        wait_writable(cx.clock, cx.poll, sock, deadline)?;
        match sock.send(buf) {
            Ok(n) if n > 0 => return Ok(n),
            Ok(_) | Err(Errno::INTR | Errno::WOULDBLOCK) => {}
            Err(e) => return Err(FlushError::Send(e)),
        }
    }
}

/// Gives the errno that C has after the failed socket call of `f`.
///
/// An end of stream gives `EHOSTDOWN`, as `recv_buffer` sets it. A TLS
/// configuration failure has no socket errno. Proto gives its `EINVAL`
/// hint instead.
fn failure_errno(f: &TransportFailure) -> Option<i32> {
    match *f {
        TransportFailure::SocketCreate { errno }
        | TransportFailure::TcpRefused { errno }
        | TransportFailure::Io { errno }
        | TransportFailure::TlsResource { errno, .. }
        | TransportFailure::TlsHandshake { errno }
        | TransportFailure::Poll { errno } => Some(errno).filter(|&e| e != 0),
        TransportFailure::Eof => Some(zk_proto::errno::EHOSTDOWN),
        TransportFailure::TlsConfig { .. } => None,
    }
}

/// The services of one step call.
pub(crate) struct StepCtx<'a, T: Tokens> {
    /// The `core` lock.
    pub(crate) core: &'a Mutex<Core<T>>,
    /// The host leaves.
    pub(crate) host: &'a dyn HostLeaves<T>,
    /// The TLS connector of a `zookeeper_init_ssl` handle or a native TLS
    /// client.
    pub(crate) tls: Option<&'a dyn TlsConnector>,
    /// The clock.
    pub(crate) clock: &'a dyn Clock,
    /// The poll call of the probe and the close flush.
    pub(crate) poll: &'a dyn Poll,
    /// The waker that interrupts the probe (mt and native threaded).
    pub(crate) wake: Option<(&'a Waker, &'a WakeRx)>,
    /// `close_requested`: it skips `Connect` and aborts the probe.
    pub(crate) abort: Option<&'a AtomicBool>,
    /// The driver parameters.
    pub(crate) cfg: &'a DriverConfig,
    /// The flavor. It selects the FIFO rule and the st exact reads.
    pub(crate) flavor: Flavor,
    /// The blocking calls that the step defers.
    pub(crate) defer: DeferPolicy,
    /// The native read gate. `None` in the drop-in.
    pub(crate) gate: Option<&'a ReadGate>,
}

impl<T: Tokens> StepCtx<'_, T> {
    /// Returns the probe services of this call.
    pub(crate) fn probe_ctx(&self) -> ProbeCtx<'_> {
        ProbeCtx {
            poll: self.poll,
            clock: self.clock,
            wake: self.wake,
            abort: self.abort,
            tls: self.tls,
            cloexec: self.cfg.cloexec,
            phase_ms: self.cfg.probe_phase_ms,
        }
    }
}

/// The transport and the staging buffers of one handle.
pub struct IoCore {
    /// The transport.
    pub(crate) conn: Transport,
    /// The heap read buffer. st plaintext reads `read_hint()` bytes.
    pub(crate) rx: Box<[u8]>,
    /// The count of plaintext bytes at the start of `rx` that proto has
    /// not taken yet. The frame loop gives them to proto in place, so a
    /// plaintext read needs no copy. The value is 0 except between a
    /// plaintext read and the end of the next frame loop.
    rx_fresh: usize,
    /// Received plaintext that proto has not taken yet (barrier, SASL).
    pub(crate) rx_pending: Vec<u8>,
    /// The heap copy of the pinned head bytes. It can hold secret
    /// frames, so its drop erases the whole buffer. The next
    /// `poll_transmit` erases the old secret copies that a clear leaves.
    pub(crate) tx_copy: Zeroizing<Vec<u8>>,
    /// The count of bytes at the start of `tx_copy` that the plaintext
    /// path sent. The bytes stay in place until all are sent, so a
    /// partial send moves no bytes. The field is a `u32`, so it fits in
    /// the free space of the struct and the session does not grow.
    pub(crate) tx_sent: u32,
    /// The record of the recent writes. It tells when the large write
    /// buffers go back to the allocator.
    pub(crate) write_bursts: WriteBursts,
    /// A read that continues the current frame found no bytes. The later
    /// calls for that frame make no such read. A complete frame clears it.
    pub(crate) rx_more_blocked: bool,
    /// A negative frame length was seen. READ stays off, as in C.
    pub(crate) rx_stalled: bool,
    /// Where a suspended step continues.
    pub(crate) cont: Cont,
    /// The per-host resolution loop in progress.
    pub(crate) resolve: Option<ResolveRun>,
    /// Jobs that the step deferred, for [`IoCore::take_jobs`].
    pub(crate) deferred: Vec<Job>,
    /// The rc of the last complete step.
    pub(crate) last_rc: i32,
    /// The rc of a connect failure in this interest call. The call then
    /// writes the outputs of the C early return.
    pub(crate) early: Option<i32>,
    /// An action that waits for the drain of the outbox.
    pub(crate) held: Option<Action>,
    /// True when this process call read the socket.
    pub(crate) read_attempted: bool,
    /// True when this process call gave a complete frame to proto.
    pub(crate) frames_seen: bool,
    /// The first teardown or SASL rc of this process call.
    pub(crate) stop_rc: Option<i32>,
    /// The time origin of the handshake start. It stays across a resume.
    pub(crate) hs_now: Option<Millis>,
    /// The step that started the handshake.
    pub(crate) hs_origin: StepKind,
    /// The deferred job that the step waits for.
    pub(crate) job: Option<JobKind>,
    /// The deferred resolution that runs now, in the foreground or in
    /// the background.
    pub(crate) dns: Option<DnsRun>,
    /// A newer resolution with a different host list. It starts when
    /// the job of `dns` ends.
    pub(crate) dns_next: Option<DnsRun>,
    /// A background resolve job that the driver must start
    /// ([`IoCore::take_bg_job`]).
    pub(crate) bg_start: Option<Job>,
    /// The OS errno of the last transport failure that ended the
    /// transport. The st driver gives it to C as `errno`.
    pub(crate) errno: Option<i32>,
}

impl std::fmt::Debug for IoCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoCore")
            .field("fd", &self.fd())
            .field("rx_pending", &self.rx_pending.len())
            .field("rx_stalled", &self.rx_stalled)
            .field("cont", &self.cont)
            .finish_non_exhaustive()
    }
}

impl IoCore {
    /// Makes an idle core with no transport and a 64 KiB heap buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            conn: Transport::None,
            rx: vec![0u8; READ_BUFFER_LEN].into_boxed_slice(),
            rx_fresh: 0,
            rx_pending: Vec::new(),
            tx_copy: Zeroizing::new(Vec::new()),
            tx_sent: 0,
            write_bursts: WriteBursts::default(),
            rx_more_blocked: false,
            rx_stalled: false,
            cont: Cont::None,
            resolve: None,
            deferred: Vec::new(),
            last_rc: ZOK,
            early: None,
            held: None,
            read_attempted: false,
            frames_seen: false,
            stop_rc: None,
            hs_now: None,
            hs_origin: StepKind::Interest,
            job: None,
            dns: None,
            dns_next: None,
            bg_start: None,
            errno: None,
        }
    }

    /// Returns the socket fd, or -1 when there is none.
    #[must_use]
    pub fn fd(&self) -> RawSock {
        self.conn.sock().map_or(-1, TcpSock::raw)
    }

    /// Returns true while a step waits for its resume.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        self.cont != Cont::None
    }

    /// Returns true when a socket is open.
    #[must_use]
    pub fn has_socket(&self) -> bool {
        self.conn.sock().is_some()
    }

    /// Returns true when the transport is a TLS session. Only such a
    /// transport sends close_notify at a graceful native close.
    #[must_use]
    pub fn has_tls_session(&self) -> bool {
        matches!(self.conn, Transport::Tls(_))
    }

    /// Returns true when received plaintext can make progress with no
    /// socket read. The interest call then gives a timeout of 0.
    ///
    /// `suspended` is `Connection::is_suspended()`. `gate_open` is the
    /// native read gate, true in the drop-in.
    #[must_use]
    pub fn buffered_ready(&self, suspended: bool, gate_open: bool) -> bool {
        !self.rx_pending.is_empty() && !self.rx_stalled && !suspended && gate_open
    }

    /// Drops the transport at once, with no close_notify. It
    /// clears the receive state and the staging copy. Proto pins clear in
    /// `handle_transport_failed` and the teardown, not here.
    pub(crate) fn drop_transport(&mut self) {
        self.conn = Transport::None;
        self.rx_fresh = 0;
        self.rx_pending.clear();
        self.tx_copy.clear();
        self.tx_sent = 0;
        self.rx_more_blocked = false;
        self.rx_stalled = false;
    }

    /// The forked-child close: closes the socket and leaks
    /// the TLS session object, so no TLS code runs in the child.
    pub(crate) fn forked_close(&mut self) {
        match std::mem::replace(&mut self.conn, Transport::None) {
            Transport::Tls(t) => {
                let TlsTransport { sock, tls, .. } = t;
                std::mem::forget(tls);
                drop(sock);
            }
            other => drop(other),
        }
    }

    /// Takes the jobs that the last step deferred (tokio and the native
    /// DNS thread).
    pub(crate) fn take_jobs(&mut self) -> Vec<Job> {
        std::mem::take(&mut self.deferred)
    }

    /// Takes the background resolve job that the last step or result
    /// made. The driver runs it while the socket I/O goes on, and gives
    /// its result to [`IoCore::complete_resolve`].
    pub(crate) fn take_bg_job(&mut self) -> Option<Job> {
        self.bg_start.take()
    }

    /// Gives the result of a deferred resolution to the step that waits
    /// for it, or applies it with no step when it ran in the background.
    ///
    /// A background result that makes a barrier stores `Cont::End`. The
    /// driver drains, then calls `resume` as for any other step.
    pub(crate) fn complete_resolve<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        done: JobDone,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        if self.job.is_some() {
            return self.complete_job(cx, proof, done, ob, out);
        }
        let JobDone::Resolved {
            generation,
            results,
        } = done
        else {
            return Progress::Done(self.last_rc);
        };
        let Some((generation, shuffle)) = self.dns_target(cx, generation) else {
            return Progress::Done(self.last_rc);
        };
        let now = cx.clock.now();
        let barrier = {
            let mut g = cx.core.lock(proof);
            // A close needs no new addresses. A changed list must not
            // force a close of the transport that drains the close.
            match g.conn.as_deref_mut() {
                Some(conn) if !conn.is_closing() => {
                    let _rc = apply_results(conn, generation, results, shuffle, now);
                }
                _ => {}
            }
            self.settle(&mut g, cx, ob)
        };
        if self.cont != Cont::None {
            // A suspended step resumes the stopped stage in its prelude.
            return Progress::More;
        }
        if barrier {
            self.cont = Cont::End { rc: self.last_rc };
            return Progress::More;
        }
        Progress::Done(self.last_rc)
    }

    /// Ends the deferred resolution that runs now.
    ///
    /// It returns the generation and the shuffle flag that the result
    /// applies to. When a newer action changed the host list, the result
    /// is stale. The job of the new list then starts and it returns
    /// `None`. A job in the foreground goes to `deferred`, a job in the
    /// background to `bg_start`.
    fn dns_target<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        generation: u64,
    ) -> Option<(u64, bool)> {
        let Some(run) = self.dns.take() else {
            return Some((generation, shuffle_on(cx.host)));
        };
        let Some(next) = self.dns_next.take() else {
            return Some((run.generation, run.shuffle));
        };
        let job = next.job();
        self.dns = Some(next);
        if self.job.is_some() {
            self.deferred.push(job);
        } else {
            self.bg_start = Some(job);
        }
        None
    }

    /// The body of `zookeeper_interest`.
    ///
    /// 1. Restore the requeued items and resume a stopped stage.
    /// 2. `begin_interest`. On `Err(rc)` set `out.rc` and return
    ///    `Done(rc)` with `written = false`. Then
    ///    `run_pending_teardown`. Drop a condemned socket before the pump.
    /// 3. The action loop (`poll_action` until `None`), in C order:
    ///    - `Resolve`: the per-host loop of `crate::resolve::ResolveRun`
    ///      (a LOG flush before each `resolve` leaf and before the
    ///      reseed). Then `run_pending_teardown`.
    ///    - `Connect`: skipped when `abort` is set. `TcpSock::open` with
    ///      `cfg.cloexec`, `handle_connect_started`. A NODELAY failure
    ///      logs `LogSite::TcpNoDelay`. A socket failure gives
    ///      `TransportFailure::SocketCreate`, a connect failure
    ///      `TcpRefused`. TLS on an immediate connect starts the
    ///      handshake (`iocore_tls::handshake_start`). Set `Core::peer`.
    ///    - `CloseTransport`: `drop_transport`. Clear `Core::peer`.
    ///    - `Sasl(Dispose)`: a `Sasl` item; go on.
    ///    - `ProbeRw`: `More` first when the outbox has items. Then the
    ///      probe with no lock, then `handle_rw_probe`.
    ///    - `Sasl(Start | Step)`: a `Sasl` item (START with the socket
    ///      addresses, or `handle_sasl_addr_failed`), then `More`.
    /// 4. `finish_interest`, then the driver adjustments
    ///    (WRITE while bytes wait or the connect runs; no READ
    ///    while stalled or the read gate is closed; timeout 0 while
    ///    `buffered_ready`; `fd` read after any close in this call).
    ///
    /// Pump the outputs after each proto call. A barrier stores
    /// `Cont::Interest` and returns `More`. `out` is written only by the
    /// call that reaches `finish_interest`.
    pub(crate) fn interest_step<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        if self.job.is_some() {
            return Progress::Wait;
        }
        if self.cont != Cont::None {
            return Progress::Done(ZINVALIDSTATE);
        }
        self.early = None;
        self.held = None;
        if self.prelude(cx, proof, ob) {
            self.cont = Cont::InterestBegin;
            return Progress::More;
        }
        self.interest_begin(cx, proof, ob, out)
    }

    /// The body of `zookeeper_process`.
    ///
    /// 1. Restore the requeued items and resume a stopped stage.
    /// 2. Unrecoverable gives `ZINVALIDSTATE`. `run_pending_teardown`.
    ///    No transport gives `ZINVALIDSTATE`. Check `has_transport` after
    ///    every relock.
    /// 3. Connecting with WRITE (HUP maps to WRITE): `SO_ERROR`. An error
    ///    gives `TcpRefused`. Success with no TLS gives
    ///    `handle_tcp_connected`, `handle_transport_ready`, one flush and
    ///    `Done(ZOK)` with no read. Success with TLS starts the handshake.
    ///    Connecting with READ and no WRITE: one read of at most 4 bytes,
    ///    as C `recv_buffer` does. EOF or an error starts a teardown. A
    ///    read that blocks or gets bytes gives `ZNOTHING`. No event gives
    ///    `ZOK`.
    /// 4. TLS handshake: `iocore_tls::handshake_step`.
    /// 5. Parked: READ only. EOF or an error is a teardown. Bytes are
    ///    discarded.
    /// 6. WRITE: one flush pass (plaintext here, TLS in `iocore_tls`).
    /// 7. READ, or `buffered_ready`: st plaintext reads `read_hint()`
    ///    bytes. mt and native read up to `cfg.max_read`. When a read fills
    ///    its request and leaves the frame open, the call reads the rest of
    ///    that frame, as C `recv_buffer` does. TLS reads in
    ///    `iocore_tls::tls_read`. A partial frame gives `ZNOTHING`. A
    ///    stall sets `rx_stalled`. A barrier stores `Cont::Process` and
    ///    returns `More`. The read gate is checked before each read and
    ///    each `handle_read`.
    /// 8. The rc rule of `process_rc`.
    pub(crate) fn process_step<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        events: PollEvents,
        ob: &mut Outbox<T>,
    ) -> Progress {
        if self.job.is_some() {
            return Progress::Wait;
        }
        if self.cont != Cont::None {
            return Progress::Done(ZINVALIDSTATE);
        }
        self.read_attempted = false;
        self.frames_seen = false;
        self.stop_rc = None;
        if self.prelude(cx, proof, ob) {
            self.cont = Cont::ProcessBegin { events };
            return Progress::More;
        }
        self.process_begin(cx, proof, events, ob)
    }

    /// Continues the suspended step after C drained (`zkrs_resume`,
    /// `zkrs_interest_resume`).
    ///
    /// It gives a SASL answer (`Core::sasl`) to `handle_sasl_started` or
    /// `handle_sasl_stepped` first, then the stopped stage to
    /// `Connection::resume`, then continues from `cont`. With no
    /// suspended step it returns `Done` with the last rc. `out` is the
    /// interest output of an interest continuation.
    pub(crate) fn resume<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        if self.job.is_some() {
            return Progress::Wait;
        }
        let cont = std::mem::replace(&mut self.cont, Cont::None);
        if cont == Cont::None {
            return Progress::Done(self.last_rc);
        }
        if self.prelude(cx, proof, ob) {
            self.cont = cont;
            return Progress::More;
        }
        match cont {
            Cont::None | Cont::Job => Progress::Done(self.last_rc),
            Cont::InterestBegin => self.interest_begin(cx, proof, ob, out),
            Cont::Interest => self.interest_actions(cx, proof, ob, out),
            Cont::InterestEnd { out: saved } => {
                *out = saved;
                self.done(saved.rc)
            }
            Cont::Handshake => match std::mem::replace(&mut self.conn, Transport::None) {
                Transport::Connecting {
                    sock,
                    ep,
                    tls: Some(verify),
                } => {
                    let p = iocore_tls::handshake_start(self, cx, proof, sock, ep, verify, ob);
                    self.after_handshake_progress(cx, proof, ob, out, p)
                }
                other => {
                    self.conn = other;
                    self.after_handshake(cx, proof, ob, out, ZOK)
                }
            },
            Cont::AfterHandshake { rc } => self.after_handshake(cx, proof, ob, out, rc),
            Cont::ProcessBegin { events } => self.process_begin(cx, proof, events, ob),
            Cont::ProcessRead { events } => self.process_read(cx, proof, events, ob),
            Cont::ProcessFlush => self.connected_flush(cx, proof, ob),
            Cont::Process { .. } => self.plain_frames(cx, proof, ob),
            Cont::TlsFrames { handshake } => {
                let p = iocore_tls::tls_frames(self, cx, proof, ob, handshake);
                self.track(p)
            }
            Cont::HandshakeReady => {
                let p = iocore_tls::handshake_ready(self, cx, proof, ob);
                self.track(p)
            }
            Cont::End { rc } => self.done(rc),
        }
    }

    /// Gives a deferred job result to proto and continues the step.
    ///
    /// - `Resolved`: `crate::resolve::apply_results`.
    /// - `NewConn`: the handshake start with this session.
    /// - `Probe`: `handle_rw_probe`. `Aborted` drops the result.
    pub(crate) fn complete_job<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        done: JobDone,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        self.job = None;
        if self.cont == Cont::Job {
            self.cont = Cont::None;
        }
        match done {
            JobDone::Resolved {
                generation,
                results,
            } => {
                self.job = Some(JobKind::Resolve);
                let Some((generation, shuffle)) = self.dns_target(cx, generation) else {
                    // The job of a newer host list runs next.
                    self.cont = Cont::Job;
                    return Progress::Wait;
                };
                self.job = None;
                let now = cx.clock.now();
                let barrier = {
                    let mut g = cx.core.lock(proof);
                    if let Some(conn) = g.conn.as_deref_mut() {
                        let _rc = apply_results(conn, generation, results, shuffle, now);
                    }
                    self.settle(&mut g, cx, ob)
                };
                if barrier {
                    self.cont = Cont::Interest;
                    return Progress::More;
                }
                self.interest_actions(cx, proof, ob, out)
            }
            JobDone::NewConn(result) => match std::mem::replace(&mut self.conn, Transport::None) {
                Transport::Connecting {
                    sock, tls: Some(_), ..
                } => {
                    let p = iocore_tls::handshake_with(self, cx, proof, ob, sock, result);
                    self.after_handshake_progress(cx, proof, ob, out, p)
                }
                other => {
                    // The attempt ended while the job ran. The session is
                    // dropped with no handshake.
                    self.conn = other;
                    self.after_handshake(cx, proof, ob, out, ZOK)
                }
            },
            JobDone::Probe { endpoint, end } => {
                if self.apply_probe(cx, proof, ob, endpoint, end) {
                    self.cont = Cont::Interest;
                    return Progress::More;
                }
                self.interest_actions(cx, proof, ob, out)
            }
        }
    }

    /// One non-blocking flush pass for an st submit.
    ///
    /// It sends only what proto releases. It returns false when a send
    /// failed. The caller then calls `handle_forced_close` and
    /// drops the transport.
    pub(crate) fn flush_once<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
    ) -> bool {
        match &self.conn {
            Transport::Plain(_) => self.plain_flush(cx, proof, None).is_ok(),
            Transport::Tls(t) if !t.tls.is_handshaking() => {
                iocore_tls::tls_flush(self, cx, proof, None).is_ok()
            }
            _ => true,
        }
    }

    /// The flush and wait of the final close.
    ///
    /// Flush `tx` for at most `cfg.close_flush_ms` with blocking sends
    /// through `poll`, then wait for POLLIN for at most
    /// `cfg.close_wait_ms` with no read. Under TLS, when every byte went
    /// out, send close_notify within the rest of the budget. It returns
    /// `ZOK`, `ZOPERATIONTIMEOUT`, `ZCONNECTIONLOSS` or `ZSYSTEMERROR`,
    /// as C does. No lock is held while it blocks.
    ///
    /// A wait that times out or fails pushes the `CloseWaitTimeout` or
    /// `CloseWaitError` line into `ob`, as `wait_for_session_to_be_closed`
    /// logs it. The wait result does not change the rc.
    pub(crate) fn close_flush<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> i32 {
        let start = cx.clock.now();
        let session = {
            let g = cx.core.lock(proof);
            g.conn
                .as_deref()
                .filter(|c| c.state().is_connected() && c.has_transport())
                .map(|c| c.client_id().session_id)
        };
        let data_phase = match &self.conn {
            Transport::Plain(_) => true,
            Transport::Tls(t) => !t.tls.is_handshaking(),
            _ => false,
        };
        let Some(session) = session.filter(|_| data_phase) else {
            return ZOK;
        };
        let flush_deadline = start.saturating_add_ms(u64::from(cx.cfg.close_flush_ms));
        let flushed = if matches!(self.conn, Transport::Tls(_)) {
            iocore_tls::tls_flush_with(self, cx, proof, Some(flush_deadline))
        } else {
            self.plain_flush(cx, proof, Some(flush_deadline))
        };
        let rc = match flushed {
            Ok(()) => ZOK,
            Err(FlushError::Timeout) => ZOPERATIONTIMEOUT,
            Err(FlushError::Poll(_)) => ZSYSTEMERROR,
            Err(FlushError::Send(_) | FlushError::Session) => ZCONNECTIONLOSS,
        };
        if rc != ZOK {
            return rc;
        }
        // The wait ends at the first POLLIN, at an error or at the
        // timeout (zookeeper.c `wait_for_session_to_be_closed`).
        let wait_deadline = cx
            .clock
            .now()
            .saturating_add_ms(u64::from(cx.cfg.close_wait_ms));
        let mut waited = None;
        if let Some(sock) = self.conn.sock() {
            loop {
                let left = zk_proto::time::until(cx.clock.now(), wait_deadline);
                if left < 0 {
                    break;
                }
                let ms = i32::try_from(left).unwrap_or(i32::MAX);
                let mut fds = [PollFd::new(sock, PollFlags::IN)];
                let r = cx.poll.poll(&mut fds, ms);
                if r != Err(Errno::INTR) {
                    waited = Some(r);
                    break;
                }
            }
        }
        let id = LogArg::Ptr(u64::from_ne_bytes(session.to_ne_bytes()));
        let line = match waited {
            Some(Ok(0)) => Some((
                LogSite::CloseWaitTimeout,
                LogArg::I64(i64::from(cx.cfg.close_wait_ms)),
            )),
            Some(Err(_)) => Some((LogSite::CloseWaitError, LogArg::I64(-1))),
            Some(Ok(_)) | None => None,
        };
        if let Some((site, arg)) = line {
            if let Some(rec) = log_record(cx.host, site, vec![arg, id]) {
                ob.push(Item::Log(rec));
            }
        }
        if let Transport::Tls(t) = &mut self.conn {
            let all_out = t.pending.is_none()
                && t.ct_out.is_empty()
                && t.unacked == 0
                && !t.tls.has_ciphertext();
            if all_out {
                let budget = u64::from(cx.cfg.close_flush_ms)
                    .saturating_add(u64::from(cx.cfg.close_wait_ms));
                iocore_tls::close_notify(t, cx, start.saturating_add_ms(budget));
            }
        }
        rc
    }

    /// Returns the (local, peer) addresses of the socket for a SASL
    /// START item. `Err` names the failed call.
    pub(crate) fn sasl_addrs(&self) -> Result<(SocketAddr, SocketAddr), zk_proto::SaslAddr> {
        let Some(sock) = self.conn.sock() else {
            return Err(zk_proto::SaslAddr::Local);
        };
        let local = sock.local_addr().map_err(|_| zk_proto::SaslAddr::Local)?;
        let peer = sock.peer_addr().map_err(|_| zk_proto::SaslAddr::Peer)?;
        Ok((local, peer))
    }
}

/// The shared parts of the steps: the prelude, the pump rule, the
/// interest action loop, the process stages and the plaintext flush.
impl IoCore {
    /// Ends the step with `rc`. The resume with no step returns it.
    pub(crate) fn done(&mut self, rc: i32) -> Progress {
        self.cont = Cont::None;
        self.last_rc = rc;
        Progress::Done(rc)
    }

    /// Records the rc of a step result that another function made.
    pub(crate) fn track(&mut self, p: Progress) -> Progress {
        match p {
            Progress::Done(rc) => self.done(rc),
            other => other,
        }
    }

    /// The pump rule of every proto call.
    ///
    /// When proto has no transport, the driver drops its socket before
    /// the pump, so no callback runs while a condemned socket is open.
    /// It returns true at a barrier.
    pub(crate) fn settle<T: Tokens>(
        &mut self,
        g: &mut Core<T>,
        cx: &StepCtx<'_, T>,
        ob: &mut Outbox<T>,
    ) -> bool {
        let has = g.conn.as_deref().is_some_and(Connection::has_transport);
        if !has {
            if self.has_socket() {
                self.drop_transport();
            }
            g.peer = None;
        }
        g.pump(cx.flavor, ob, cx.host)
    }

    /// Gives a transport failure to proto and pumps. It returns the rc
    /// and true at a barrier.
    pub(crate) fn fail<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        f: TransportFailure,
    ) -> (i32, bool) {
        let now = cx.clock.now();
        let mut g = cx.core.lock(proof);
        let errno = failure_errno(&f);
        let rc = g
            .conn
            .as_deref_mut()
            .map_or(ZOK, |c| c.handle_transport_failed(f, now));
        if rc != ZOK {
            self.errno = errno;
        }
        let barrier = self.settle(&mut g, cx, ob);
        (rc, barrier)
    }

    /// Takes the errno of the last transport failure.
    pub(crate) fn take_errno(&mut self) -> Option<i32> {
        self.errno.take()
    }

    /// Gives a transport failure to proto and ends the step with its rc.
    pub(crate) fn fail_end<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        f: TransportFailure,
    ) -> Progress {
        let (rc, barrier) = self.fail(cx, proof, ob, f);
        self.stop_rc.get_or_insert(rc);
        self.end_after(barrier, rc)
    }

    /// Ends the step with `rc`, or stops first at a barrier.
    pub(crate) fn end_after(&mut self, barrier: bool, rc: i32) -> Progress {
        if barrier {
            self.cont = Cont::End { rc };
            return Progress::More;
        }
        self.done(rc)
    }

    /// The rc rule of a process call. A stop rc wins. Else a read with
    /// no frame gives `ZNOTHING`, and all other cases give `ZOK`.
    pub(crate) fn process_rc(&self) -> i32 {
        self.stop_rc.unwrap_or(if self.frames_seen {
            ZOK
        } else if self.read_attempted {
            ZNOTHING
        } else {
            ZOK
        })
    }

    /// The start of each step and of each resume.
    ///
    /// It restores the requeued items, gives a SASL answer to proto,
    /// resumes the stopped stage and pumps. It returns true when the
    /// step must return `More` first. A failed SASL answer gives the rc
    /// of the process call.
    fn prelude<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> bool {
        let now = cx.clock.now();
        let mut g = cx.core.lock(proof);
        if g.restore_requeued(ob) {
            return true;
        }
        if let Some(answer) = g.sasl.take() {
            if let Some(conn) = g.conn.as_deref_mut() {
                let rc = match answer {
                    SaslAnswer::Started { generation, result } => {
                        conn.handle_sasl_started(generation, result, now)
                    }
                    SaslAnswer::Stepped { generation, result } => {
                        conn.handle_sasl_stepped(generation, result, now)
                    }
                };
                if rc != ZOK {
                    self.stop_rc.get_or_insert(rc);
                }
            }
        }
        g.resume_stopped(now);
        self.settle(&mut g, cx, ob)
    }

    /// Steps 2 and 3 of the interest call: `begin_interest`, the pending
    /// teardown, then the action loop.
    fn interest_begin<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        let now = cx.clock.now();
        let barrier = {
            let mut g = cx.core.lock(proof);
            let Some(conn) = g.conn.as_deref_mut() else {
                out.rc = ZINVALIDSTATE;
                out.written = false;
                return self.done(ZINVALIDSTATE);
            };
            if let Err(rc) = conn.begin_interest(now) {
                out.rc = rc;
                out.written = false;
                return self.done(rc);
            }
            conn.run_pending_teardown(now);
            self.settle(&mut g, cx, ob)
        };
        if barrier {
            self.cont = Cont::Interest;
            return Progress::More;
        }
        self.interest_actions(cx, proof, ob, out)
    }

    /// The action loop of the interest call, then the
    /// outputs.
    fn interest_actions<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        loop {
            if let Some(run) = self.resolve.as_mut() {
                let rcx = ResolveCtx {
                    core: cx.core,
                    host: cx.host,
                    clock: cx.clock,
                    flavor: cx.flavor,
                };
                match run.run(&rcx, proof, ob) {
                    ResolveEnd::More => {
                        self.cont = Cont::Interest;
                        return Progress::More;
                    }
                    ResolveEnd::Done { .. } => {
                        self.resolve = None;
                        let barrier = {
                            let mut g = cx.core.lock(proof);
                            let stopped = g.stopped.is_some();
                            self.settle(&mut g, cx, ob) || stopped
                        };
                        if barrier {
                            self.cont = Cont::Interest;
                            return Progress::More;
                        }
                    }
                }
            }
            if self.early.is_some() {
                break;
            }
            let action = match self.held.take() {
                Some(a) => a,
                None => {
                    let now = cx.clock.now();
                    let (action, barrier) = {
                        let mut g = cx.core.lock(proof);
                        // A set_servers list from the handle runs as a
                        // resolve action before the next proto action.
                        let action = match g.set_servers.take() {
                            Some((generation, hosts)) => Some(Action::Resolve {
                                generation,
                                hosts,
                                initial: false,
                            }),
                            None => g.conn.as_deref_mut().and_then(|c| c.poll_action(now)),
                        };
                        (action, self.settle(&mut g, cx, ob))
                    };
                    let Some(action) = action else {
                        if barrier {
                            self.cont = Cont::Interest;
                            return Progress::More;
                        }
                        break;
                    };
                    if barrier {
                        self.held = Some(action);
                        self.cont = Cont::Interest;
                        return Progress::More;
                    }
                    action
                }
            };
            match self.run_action(cx, proof, ob, action) {
                Flow::Continue => {}
                Flow::Return(p) => return p,
            }
        }
        self.interest_finish(cx, proof, ob, out)
    }

    /// Runs one action of the interest loop.
    fn run_action<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        action: Action,
    ) -> Flow {
        let more = |io: &mut Self| {
            io.cont = Cont::Interest;
            Flow::Return(Progress::More)
        };
        match action {
            Action::Resolve {
                generation, hosts, ..
            } => {
                // A close needs no new addresses. A slow resolver must not
                // delay the close drain past the close timeout.
                let closing = {
                    let g = cx.core.lock(proof);
                    g.conn.as_deref().is_some_and(Connection::is_closing)
                };
                if closing {
                    return Flow::Continue;
                }
                if cx.defer.resolve {
                    return self.defer_resolve(cx, generation, hosts);
                }
                self.resolve = Some(ResolveRun::new(generation, hosts));
                Flow::Continue
            }
            Action::Connect { endpoint, tls } => self.connect(cx, proof, ob, endpoint, tls),
            Action::CloseTransport => {
                self.drop_transport();
                cx.core.lock(proof).peer = None;
                Flow::Continue
            }
            Action::Sasl(call) => match call.kind {
                SaslCallKind::Dispose => {
                    ob.push(Item::Sasl(SaslItem { call, addrs: None }));
                    Flow::Continue
                }
                SaslCallKind::Start => match self.sasl_addrs() {
                    Ok(addrs) => {
                        ob.push(Item::Sasl(SaslItem {
                            call,
                            addrs: Some(addrs),
                        }));
                        more(self)
                    }
                    Err(which) => {
                        let now = cx.clock.now();
                        let barrier = {
                            let mut g = cx.core.lock(proof);
                            if let Some(conn) = g.conn.as_deref_mut() {
                                let _rc = conn.handle_sasl_addr_failed(call.generation, which, now);
                            }
                            self.settle(&mut g, cx, ob)
                        };
                        if barrier { more(self) } else { Flow::Continue }
                    }
                },
                SaslCallKind::Step(_) => {
                    ob.push(Item::Sasl(SaslItem { call, addrs: None }));
                    more(self)
                }
            },
            Action::ProbeRw { endpoint, tls } => {
                if !ob.is_empty() {
                    self.held = Some(Action::ProbeRw { endpoint, tls });
                    return more(self);
                }
                if cx.defer.probe {
                    self.deferred.push(Job::Probe { endpoint, tls });
                    self.job = Some(JobKind::Probe);
                    self.cont = Cont::Job;
                    return Flow::Return(Progress::Wait);
                }
                let end = probe(&cx.probe_ctx(), proof, &endpoint, tls);
                if self.apply_probe(cx, proof, ob, endpoint, end) {
                    more(self)
                } else {
                    Flow::Continue
                }
            }
        }
    }

    /// Defers a `Resolve` action.
    ///
    /// With an open socket the resolution runs in the background. The
    /// step goes on, so pings, reads, request flushes and the close drain
    /// do not wait for a slow resolver. With no socket the step waits for
    /// the result, because the next connect needs the new addresses.
    ///
    /// Only one resolve job runs at a time. A new action for the same
    /// host list joins the job that runs. A new action for a different
    /// list waits in `dns_next` until that job ends.
    fn defer_resolve<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        generation: u64,
        hosts: Vec<HostSpec>,
    ) -> Flow {
        let run = DnsRun {
            generation,
            hosts,
            shuffle: shuffle_on(cx.host),
        };
        let job = match self.dns.as_mut() {
            Some(cur) if cur.hosts == run.hosts => {
                cur.generation = run.generation;
                cur.shuffle = run.shuffle;
                self.dns_next = None;
                None
            }
            Some(_) => {
                self.dns_next = Some(run);
                None
            }
            None => {
                let job = run.job();
                self.dns = Some(run);
                Some(job)
            }
        };
        if self.has_socket() {
            if let Some(job) = job {
                self.bg_start = Some(job);
            }
            return Flow::Continue;
        }
        if let Some(job) = job {
            self.deferred.push(job);
        }
        self.job = Some(JobKind::Resolve);
        self.cont = Cont::Job;
        Flow::Return(Progress::Wait)
    }

    /// The `Connect` action (zookeeper.c:2672-2730).
    fn connect<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        endpoint: Endpoint,
        tls: Option<TlsVerify>,
    ) -> Flow {
        if cx.abort.is_some_and(|a| a.load(Ordering::Acquire)) {
            return Flow::Continue;
        }
        let addr = endpoint.addr;
        let opened = match TcpSock::open(&addr, cx.cfg.cloexec) {
            Ok(o) => o,
            Err(e) => {
                let f = TransportFailure::SocketCreate {
                    errno: errno_value(e),
                };
                return self.early_failure(cx, proof, ob, f);
            }
        };
        if !opened.nodelay_ok {
            if let Some(rec) = log_record(cx.host, LogSite::TcpNoDelay, Vec::new()) {
                ob.push(Item::Log(rec));
            }
        }
        let sock = opened.sock;
        // Legacy logs this line in zookeeper_connect, just before connect().
        if let Some(rec) = log_record(cx.host, LogSite::ZkConnect, Vec::new()) {
            ob.push(Item::Log(rec));
        }
        let start = match sock.start_connect(&addr) {
            Ok(s) => s,
            Err(e) => {
                drop(sock);
                let f = TransportFailure::TcpRefused {
                    errno: errno_value(e),
                };
                return self.early_failure(cx, proof, ob, f);
            }
        };
        let immediate = start == ConnectStart::Immediate;
        let now = cx.clock.now();
        let (installed, barrier) = {
            let mut g = cx.core.lock(proof);
            let mut installed = false;
            if let Some(conn) = g.conn.as_deref_mut() {
                conn.handle_connect_started(start, now);
                if conn.has_transport() {
                    installed = true;
                    if immediate && tls.is_none() {
                        conn.handle_tcp_connected(now);
                        conn.handle_transport_ready(now);
                    }
                }
            }
            if installed {
                g.peer = Some(addr);
            }
            let barrier = self.settle(&mut g, cx, ob);
            (installed.then_some(sock), barrier)
        };
        let Some(sock) = installed else {
            return if barrier {
                self.cont = Cont::Interest;
                Flow::Return(Progress::More)
            } else {
                Flow::Continue
            };
        };
        match (immediate, tls) {
            (true, None) => self.conn = Transport::Plain(sock),
            (true, Some(verify)) => {
                self.hs_origin = StepKind::Interest;
                self.hs_now = None;
                if barrier {
                    self.conn = Transport::Connecting {
                        sock,
                        ep: endpoint,
                        tls,
                    };
                    self.cont = Cont::Handshake;
                    return Flow::Return(Progress::More);
                }
                return match iocore_tls::handshake_start(
                    self, cx, proof, sock, endpoint, verify, ob,
                ) {
                    Progress::Done(rc) => {
                        if rc != ZOK {
                            self.early = Some(rc);
                        }
                        Flow::Continue
                    }
                    other => Flow::Return(other),
                };
            }
            (false, _) => {
                self.conn = Transport::Connecting {
                    sock,
                    ep: endpoint,
                    tls,
                }
            }
        }
        if barrier {
            self.cont = Cont::Interest;
            return Flow::Return(Progress::More);
        }
        Flow::Continue
    }

    /// A connect failure of the interest call. C returns before its
    /// outputs change again, so the call writes `fd = -1`, no interest
    /// and `tv = 0` with this rc.
    fn early_failure<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        f: TransportFailure,
    ) -> Flow {
        let (rc, barrier) = self.fail(cx, proof, ob, f);
        self.early = Some(rc);
        if barrier {
            self.cont = Cont::Interest;
            return Flow::Return(Progress::More);
        }
        Flow::Continue
    }

    /// Gives a probe result to proto. It returns true at a barrier.
    fn apply_probe<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        endpoint: Endpoint,
        end: ProbeEnd,
    ) -> bool {
        let ProbeEnd::Done(outcome) = end else {
            return false;
        };
        let now = cx.clock.now();
        let mut g = cx.core.lock(proof);
        if let Some(conn) = g.conn.as_deref_mut() {
            conn.handle_rw_probe(endpoint, outcome, now);
        }
        self.settle(&mut g, cx, ob)
    }

    /// Step 4 of the interest call: `finish_interest` and the driver
    /// adjustments of the outputs.
    fn interest_finish<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
    ) -> Progress {
        // In st, C `send_ping` flushes the send queue with no wait inside
        // the interest call. The bits and the timeout then see the sent
        // ping, as in C. A send error gives the C rc and log line.
        let mut ping_failed = false;
        if cx.flavor == Flavor::St && self.early.is_none() {
            let ping = cx
                .core
                .lock(proof)
                .conn
                .as_deref()
                .is_some_and(Connection::interest_queued_ping);
            ping_failed = ping && !self.flush_once(cx, proof);
        }
        let now = cx.clock.now();
        let (outcome, suspended, gate, barrier) = {
            let mut g = cx.core.lock(proof);
            let Some(conn) = g.conn.as_deref_mut() else {
                out.rc = ZINVALIDSTATE;
                out.written = false;
                return self.done(ZINVALIDSTATE);
            };
            let outcome = conn.finish_interest(now);
            let suspended = conn.is_suspended();
            let gate = gate_open(cx, conn.state());
            (outcome, suspended, gate, self.settle(&mut g, cx, ob))
        };
        if let Some(rc) = self.early.take() {
            *out = InterestOut {
                rc,
                written: true,
                fd: -1,
                bits: 0,
                timeout_ms: 0,
            };
        } else if let Some(i) = outcome.outputs {
            let fd = if i.has_socket { self.fd() } else { -1 };
            let unsent = match &self.conn {
                Transport::Connecting { .. } => true,
                Transport::Plain(_) => !self.tx_copy.is_empty(),
                Transport::Tls(t) => t.has_unsent() || !self.tx_copy.is_empty(),
                Transport::None | Transport::Parked(_) => false,
            };
            let mut bits = 0;
            if i.read && !self.rx_stalled && gate {
                bits |= ZOOKEEPER_READ;
            }
            if i.write || (fd >= 0 && unsent) {
                bits |= ZOOKEEPER_WRITE;
            }
            let timeout_ms = if self.buffered_ready(suspended, gate) {
                0
            } else {
                i64::from(i.timeout_ms)
            };
            *out = InterestOut {
                rc: outcome.rc,
                written: true,
                fd,
                bits,
                timeout_ms,
            };
        } else {
            out.rc = outcome.rc;
            out.written = false;
        }
        if ping_failed {
            // C returns with fd written. The bits and the timeout stay 0.
            let arg = LogArg::I64(i64::from(ZCONNECTIONLOSS));
            if let Some(rec) = log_record(cx.host, LogSite::PingSendFailed, vec![arg]) {
                ob.push(Item::Log(rec));
            }
            *out = InterestOut {
                rc: ZCONNECTIONLOSS,
                written: true,
                fd: self.fd(),
                bits: 0,
                timeout_ms: 0,
            };
        }
        if barrier {
            self.cont = Cont::InterestEnd { out: *out };
            return Progress::More;
        }
        self.done(out.rc)
    }

    /// Gives a handshake start result back to its origin step.
    fn after_handshake_progress<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
        p: Progress,
    ) -> Progress {
        match p {
            Progress::Done(rc) => self.after_handshake(cx, proof, ob, out, rc),
            other => other,
        }
    }

    /// Continues the origin step after the handshake start gave `rc`.
    fn after_handshake<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        out: &mut InterestOut,
        rc: i32,
    ) -> Progress {
        match self.hs_origin {
            StepKind::Interest => {
                if rc != ZOK {
                    self.early = Some(rc);
                }
                self.interest_actions(cx, proof, ob, out)
            }
            StepKind::Process => self.done(rc),
        }
    }

    /// Step 2 of the process call: the state checks and the pending
    /// teardown, then the stage of the transport.
    fn process_begin<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        events: PollEvents,
        ob: &mut Outbox<T>,
    ) -> Progress {
        let now = cx.clock.now();
        let (has, barrier) = {
            let mut g = cx.core.lock(proof);
            let Some(conn) = g.conn.as_deref_mut() else {
                return self.done(ZINVALIDSTATE);
            };
            if conn.state().is_unrecoverable() {
                return self.done(ZINVALIDSTATE);
            }
            conn.run_pending_teardown(now);
            let has = conn.has_transport();
            (has, self.settle(&mut g, cx, ob))
        };
        if barrier {
            self.cont = Cont::ProcessBegin { events };
            return Progress::More;
        }
        if !has {
            return self.done(ZINVALIDSTATE);
        }
        match &self.conn {
            Transport::None => self.done(ZINVALIDSTATE),
            Transport::Connecting { .. } => self.process_connecting(cx, proof, events, ob),
            Transport::Tls(t) if t.tls.is_handshaking() => {
                let p = iocore_tls::handshake_step(self, cx, proof, events, ob);
                self.track(p)
            }
            Transport::Parked(_) => self.process_parked(cx, proof, events, ob),
            Transport::Plain(_) | Transport::Tls(_) => self.process_data(cx, proof, events, ob),
        }
    }

    /// Step 3 of the process call: the TCP connect completes or fails.
    fn process_connecting<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        events: PollEvents,
        ob: &mut Outbox<T>,
    ) -> Progress {
        if !events.write {
            if events.read {
                return self.connecting_read(cx, proof, ob);
            }
            return self.done(ZOK);
        }
        let status = self.conn.sock().map_or(Ok(()), TcpSock::socket_error);
        if let Err(e) = status {
            let f = TransportFailure::TcpRefused {
                errno: errno_value(e),
            };
            return self.fail_end(cx, proof, ob, f);
        }
        match std::mem::replace(&mut self.conn, Transport::None) {
            Transport::Connecting {
                sock,
                ep,
                tls: Some(verify),
            } => {
                self.hs_origin = StepKind::Process;
                self.hs_now = None;
                let p = iocore_tls::handshake_start(self, cx, proof, sock, ep, verify, ob);
                self.track(p)
            }
            Transport::Connecting { sock, .. } => {
                let now = cx.clock.now();
                self.conn = Transport::Plain(sock);
                let barrier = {
                    let mut g = cx.core.lock(proof);
                    if let Some(conn) = g.conn.as_deref_mut() {
                        conn.handle_tcp_connected(now);
                        conn.handle_transport_ready(now);
                    }
                    self.settle(&mut g, cx, ob)
                };
                if barrier {
                    self.cont = Cont::ProcessFlush;
                    return Progress::More;
                }
                self.connected_flush(cx, proof, ob)
            }
            other => {
                self.conn = other;
                self.done(ZOK)
            }
        }
    }

    /// Step 3 with READ and no WRITE.
    ///
    /// An st program that maps POLLHUP to READ gives these events when a
    /// connect fails. C reads the frame length here (zookeeper.c:3126-3136,
    /// 1932-1952). A failed connect makes this read fail, so the attempt
    /// ends in this call. With TLS the read also uses the TCP socket,
    /// because the TLS session does not exist yet. A server sends nothing
    /// before the `ConnectRequest`, so the step discards the bytes it gets.
    fn connecting_read<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> Progress {
        let Some(sock) = self.conn.sock() else {
            return self.done(ZOK);
        };
        let mut len = [0u8; 4];
        match sock.recv(&mut len) {
            Ok(0) => self.fail_end(cx, proof, ob, TransportFailure::Eof),
            Ok(_) | Err(Errno::WOULDBLOCK) => self.done(ZNOTHING),
            Err(e) => {
                let f = TransportFailure::Io {
                    errno: errno_value(e),
                };
                self.fail_end(cx, proof, ob, f)
            }
        }
    }

    /// The one flush after the TCP connect completes. The call returns
    /// `ZOK` with no read (zookeeper.c:3099-3115).
    fn connected_flush<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> Progress {
        match self.plain_flush(cx, proof, None) {
            Err(FlushError::Send(e)) => {
                let f = TransportFailure::Io {
                    errno: errno_value(e),
                };
                self.fail_end(cx, proof, ob, f)
            }
            _ => {
                let barrier = {
                    let mut g = cx.core.lock(proof);
                    self.settle(&mut g, cx, ob)
                };
                self.end_after(barrier, ZOK)
            }
        }
    }

    /// Step 5 of the process call: a parked socket reads only to see
    /// EOF or an error. The bytes are discarded.
    fn process_parked<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        events: PollEvents,
        ob: &mut Outbox<T>,
    ) -> Progress {
        if !events.read {
            return self.done(ZOK);
        }
        let Transport::Parked(sock) = &self.conn else {
            return self.done(ZOK);
        };
        match sock.recv(&mut self.rx) {
            Ok(0) => self.fail_end(cx, proof, ob, TransportFailure::Eof),
            Ok(_) | Err(Errno::WOULDBLOCK) => self.done(ZNOTHING),
            Err(e) => {
                let f = TransportFailure::Io {
                    errno: errno_value(e),
                };
                self.fail_end(cx, proof, ob, f)
            }
        }
    }

    /// Step 6 of the process call: the flush pass on WRITE.
    fn process_data<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        events: PollEvents,
        ob: &mut Outbox<T>,
    ) -> Progress {
        if events.write {
            let sent = if matches!(self.conn, Transport::Tls(_)) {
                iocore_tls::tls_flush(self, cx, proof, None)
            } else {
                match self.plain_flush(cx, proof, None) {
                    Err(FlushError::Send(e)) => Err(e),
                    _ => Ok(()),
                }
            };
            if let Err(e) = sent {
                let f = TransportFailure::Io {
                    errno: errno_value(e),
                };
                return self.fail_end(cx, proof, ob, f);
            }
            let (has, barrier) = {
                let mut g = cx.core.lock(proof);
                let has = g.conn.as_deref().is_some_and(Connection::has_transport);
                (has, self.settle(&mut g, cx, ob))
            };
            if barrier {
                self.cont = if has {
                    Cont::ProcessRead { events }
                } else {
                    Cont::End { rc: ZINVALIDSTATE }
                };
                return Progress::More;
            }
            if !has {
                return self.done(ZINVALIDSTATE);
            }
        }
        self.process_read(cx, proof, events, ob)
    }

    /// Step 7 of the process call: the read and the frame loop.
    fn process_read<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        events: PollEvents,
        ob: &mut Outbox<T>,
    ) -> Progress {
        let (suspended, gate, hint) = {
            let g = cx.core.lock(proof);
            match g.conn.as_deref() {
                Some(c) => (c.is_suspended(), gate_open(cx, c.state()), c.read_hint()),
                None => return self.done(ZINVALIDSTATE),
            }
        };
        let ready = events.read || self.buffered_ready(suspended, gate);
        if !ready || self.rx_stalled {
            return self.done(self.process_rc());
        }
        match &self.conn {
            Transport::Tls(_) => {
                let p = iocore_tls::tls_read(self, cx, proof, events, ob);
                return self.track(p);
            }
            Transport::Plain(_) => {}
            _ => return self.done(self.process_rc()),
        }
        if self.rx_pending.is_empty() && events.read && gate {
            if let Some(p) = self.plain_read(cx, proof, ob, hint) {
                return p;
            }
        }
        self.plain_frames(cx, proof, ob)
    }

    /// The plaintext reads of one process call. It returns the end of the
    /// call, or `None` when the frame loop takes the received bytes.
    ///
    /// st reads `read_hint()` bytes. mt and native read up to
    /// `cfg.max_read`. A read that fills its request can leave the current
    /// frame open. Then the call reads the rest of that frame, as C
    /// `recv_buffer` does (zookeeper.c 1938-1966).
    fn plain_read<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        hint: usize,
    ) -> Option<Progress> {
        let st = cx.flavor == Flavor::St;
        let cap = if st {
            self.rx.len()
        } else {
            cx.cfg.max_read.min(self.rx.len())
        };
        let want = if st { hint.min(cap) } else { cap };
        if want == 0 {
            return None;
        }
        match self.read_part(cx, proof, ob, want) {
            Part::Got(n) if n == want => self.read_rest(cx, proof, ob, cap, st),
            Part::Got(_) => None,
            Part::Barrier => Some(self.frames_more()),
            Part::Failed(f) => Some(self.fail_end(cx, proof, ob, f)),
        }
    }

    /// Ends the call at a barrier of the frame loop. The resume enters the
    /// frame loop again.
    fn frames_more(&mut self) -> Progress {
        self.cont = Cont::Process {
            events: PollEvents::NONE,
        };
        Progress::More
    }

    /// Reads the rest of the current frame after a full read, in parts
    /// of at most `cap` bytes. It returns as [`IoCore::plain_read`] does.
    ///
    /// The reads continue while each read fills its request. No read goes
    /// past the current frame, so st still completes at most one frame in
    /// each call. st always makes its first body read, as C does. A read
    /// that blocks sets `rx_more_blocked`. Then the later calls for that
    /// frame make no more of these reads, so a slow peer does not cost an
    /// empty read in each call.
    fn read_rest<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        cap: usize,
        st: bool,
    ) -> Option<Progress> {
        let mut free = st;
        loop {
            match self.frame_loop(cx, proof, ob) {
                FrameEnd::More => return Some(self.frames_more()),
                FrameEnd::Held => return Some(self.done(self.process_rc())),
                FrameEnd::Done => {}
            }
            if !free && self.rx_more_blocked {
                return None;
            }
            free = false;
            let rest = self.body_hint(cx, proof).min(cap);
            if rest == 0 {
                return None;
            }
            match self.read_part(cx, proof, ob, rest) {
                Part::Got(0) => {
                    self.rx_more_blocked = true;
                    return None;
                }
                Part::Got(n) if n == rest => {}
                Part::Got(_) => return None,
                Part::Barrier => return Some(self.frames_more()),
                Part::Failed(f) => return Some(self.fail_end(cx, proof, ob, f)),
            }
        }
    }

    /// One plaintext read of at most `want` bytes.
    ///
    /// When the current frame body takes all `want` bytes, the read goes
    /// straight into the body, and no copy follows. Otherwise it goes to
    /// `rx`, as [`IoCore::plain_recv`] does. Received bytes that proto has
    /// not taken come first, so the direct read occurs only when there
    /// are none.
    fn read_part<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        want: usize,
    ) -> Part {
        if self.rx_fresh == 0 && self.rx_pending.is_empty() {
            if let Some(part) = self.body_part(cx, proof, ob, want) {
                return part;
            }
        }
        match self.plain_recv(want) {
            Ok(n) => Part::Got(n),
            Err(f) => Part::Failed(f),
        }
    }

    /// Reads `want` bytes straight into the current frame body. It returns
    /// `None` when the body cannot take them now. Then the caller reads
    /// into `rx`.
    ///
    /// The read, the commit and the pump use one core lock, so proto sees
    /// the bytes in the same state that gave the room. The recv does not
    /// block, so the lock rule holds. The read gate is checked first, as
    /// the frame loop does before each `handle_read`.
    fn body_part<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
        want: usize,
    ) -> Option<Part> {
        let Transport::Plain(sock) = &self.conn else {
            return None;
        };
        let now = cx.clock.now();
        let mut g = cx.core.lock(proof);
        let conn = g.conn.as_deref_mut()?;
        if !gate_open(cx, conn.state()) || conn.read_hint() < want {
            return None;
        }
        let room = conn.body_room(want);
        if room.len() != want {
            return None;
        }
        let got = sock.recv(room);
        self.read_attempted = true;
        let n = match got {
            Ok(0) => return Some(Part::Failed(TransportFailure::Eof)),
            Ok(n) => n,
            Err(Errno::WOULDBLOCK) => return Some(Part::Got(0)),
            Err(e) => {
                let errno = errno_value(e);
                return Some(Part::Failed(TransportFailure::Io { errno }));
            }
        };
        let r = conn.handle_body_read(n, now);
        self.note_outcome(r);
        if self.settle(&mut g, cx, ob) {
            return Some(Part::Barrier);
        }
        Some(Part::Got(n))
    }

    /// One plaintext `recv` of at most `want` bytes into `rx`.
    ///
    /// It gives the byte count, 0 when the read blocks, or the transport
    /// failure. EOF is a failure.
    ///
    /// When `rx_pending` is empty, the new bytes stay in `rx` as fresh
    /// bytes, and the frame loop reads them in place. Otherwise they go to
    /// the end of `rx_pending`, so the byte order does not change.
    fn plain_recv(&mut self, want: usize) -> Result<usize, TransportFailure> {
        self.read_attempted = true;
        // The recv writes over `rx`, so fresh bytes move out first.
        self.spill_fresh();
        let Transport::Plain(sock) = &self.conn else {
            return Ok(0);
        };
        let want = want.min(self.rx.len());
        let got = match self.rx.get_mut(..want) {
            Some(buf) => sock.recv(buf),
            None => Ok(0),
        };
        match got {
            Ok(0) => Err(TransportFailure::Eof),
            Ok(n) => {
                if self.rx_pending.is_empty() {
                    self.rx_fresh = n;
                } else {
                    let data = self.rx.get(..n).unwrap_or_default();
                    self.rx_pending.extend_from_slice(data);
                }
                Ok(n)
            }
            Err(Errno::WOULDBLOCK) => Ok(0),
            Err(e) => Err(TransportFailure::Io {
                errno: errno_value(e),
            }),
        }
    }

    /// The received plaintext that proto has not taken: the fresh bytes
    /// in `rx`, or else `rx_pending`. Only one of them holds bytes.
    fn rx_input(&self) -> &[u8] {
        if self.rx_fresh > 0 {
            self.rx.get(..self.rx_fresh).unwrap_or_default()
        } else {
            self.rx_pending.as_slice()
        }
    }

    /// Removes the first `n` bytes of [`IoCore::rx_input`]. The fresh
    /// bytes after them move to `rx_pending`, so `rx` is free again.
    fn rx_consume(&mut self, n: usize) {
        if self.rx_fresh > 0 {
            let rest = self.rx.get(n..self.rx_fresh).unwrap_or_default();
            self.rx_pending.extend_from_slice(rest);
            self.rx_fresh = 0;
        } else {
            self.rx_pending.drain(..n);
        }
    }

    /// Moves any fresh bytes in `rx` to `rx_pending`.
    fn spill_fresh(&mut self) {
        if self.rx_fresh > 0 {
            self.rx_consume(0);
        }
    }

    /// The size of the read that continues the current frame, or 0 when
    /// no read follows.
    ///
    /// The read follows only when proto took every byte, no frame
    /// completed in this call, and the decoder waits for more of the
    /// frame. The size never goes past the current frame part.
    fn body_hint<T: Tokens>(&self, cx: &StepCtx<'_, T>, proof: &mut Unlocked) -> usize {
        if self.frames_seen || self.rx_stalled || !self.rx_pending.is_empty() {
            return 0;
        }
        let g = cx.core.lock(proof);
        match g.conn.as_deref() {
            Some(c) if c.has_transport() && !c.is_suspended() && gate_open(cx, c.state()) => {
                c.read_hint()
            }
            _ => 0,
        }
    }

    /// The plaintext frame loop and the rc of the call.
    fn plain_frames<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> Progress {
        match self.frame_loop(cx, proof, ob) {
            FrameEnd::More => {
                self.cont = Cont::Process {
                    events: PollEvents::NONE,
                };
                Progress::More
            }
            FrameEnd::Done | FrameEnd::Held => self.done(self.process_rc()),
        }
    }

    /// Gives the received bytes to `handle_read`, one call at a time,
    /// with the pump rule after each call.
    ///
    /// The read gate is checked before each call. A decoder stall sets
    /// `rx_stalled`. When proto takes no byte of a non-empty buffer and
    /// does not stall, it waits for the SASL mechanism, so the bytes stay.
    ///
    /// Fresh bytes in `rx` that proto does not take move to `rx_pending`
    /// before the function returns.
    pub(crate) fn frame_loop<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> FrameEnd {
        let end = self.frame_steps(cx, proof, ob);
        self.spill_fresh();
        end
    }

    /// The steps of [`IoCore::frame_loop`]. The first call of
    /// `handle_read` can read fresh bytes in place.
    ///
    /// Each turn holds one core lock across the gate, the read and the
    /// pump. The turn samples `stalled` before it consumes bytes. It
    /// computes `waits` after it consumes bytes and before the pump.
    fn frame_steps<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> FrameEnd {
        loop {
            if self.process_sasl(cx, proof, ob) {
                return FrameEnd::More;
            }
            if self.rx_input().is_empty() || self.rx_stalled {
                return FrameEnd::Done;
            }
            let now = cx.clock.now();
            let mut g = cx.core.lock(proof);
            if let Some(end) = self.frame_gate(&mut g, cx, ob) {
                return end;
            }
            // The gate ends the turn when no connection is present.
            let Some(conn) = g.conn.as_deref_mut() else {
                return FrameEnd::Done;
            };
            let r = conn.handle_read(self.rx_input(), now);
            let has = conn.has_transport();
            let stalled = has && conn.read_hint() == 0;
            let (n, waits) = self.apply_read(r, has, stalled);
            if self.settle(&mut g, cx, ob) {
                return FrameEnd::More;
            }
            if waits {
                return FrameEnd::Held;
            }
            if n == 0 {
                return FrameEnd::Done;
            }
        }
    }

    /// The admission test of one frame turn. It returns `None` when the
    /// turn can read.
    ///
    /// With no connection the loop is done. With no transport or a
    /// suspended connection the loop pumps and ends. A closed read gate
    /// holds the bytes.
    #[inline]
    fn frame_gate<T: Tokens>(
        &mut self,
        g: &mut Core<T>,
        cx: &StepCtx<'_, T>,
        ob: &mut Outbox<T>,
    ) -> Option<FrameEnd> {
        let Some(conn) = g.conn.as_deref() else {
            return Some(FrameEnd::Done);
        };
        if !conn.has_transport() || conn.is_suspended() {
            return Some(if self.settle(g, cx, ob) {
                FrameEnd::More
            } else {
                FrameEnd::Done
            });
        }
        if !gate_open(cx, conn.state()) {
            return Some(FrameEnd::Held);
        }
        None
    }

    /// Records the result of one `handle_read` call. It returns the
    /// number of bytes that proto takes, and true when proto waits for
    /// the SASL mechanism.
    ///
    /// It removes the taken bytes, notes a complete frame and keeps the
    /// first stop rc. A decoder stall sets `rx_stalled`. The wait test
    /// reads `rx_pending` after the bytes move.
    #[inline]
    fn apply_read(&mut self, r: ReadOutcome, has: bool, stalled: bool) -> (usize, bool) {
        let n = r.consumed.min(self.rx_input().len());
        self.rx_consume(n);
        self.note_outcome(r);
        if stalled {
            self.rx_stalled = true;
        }
        let waits = n == 0 && has && !stalled && !self.rx_pending.is_empty();
        (n, waits)
    }

    /// Notes a complete frame and keeps the first stop rc of a read.
    #[inline]
    fn note_outcome(&mut self, r: ReadOutcome) {
        if r.frames > 0 {
            self.frames_seen = true;
            self.rx_more_blocked = false;
        }
        if r.rc != ZOK && r.rc != ZNOTHING {
            self.stop_rc.get_or_insert(r.rc);
        }
    }

    /// Emits the SASL calls that `handle_read` made.
    ///
    /// C reads a SASL reply and runs the next mechanism call in the same
    /// `zookeeper_process` call (zookeeper.c:3141-3193). Thus the read
    /// loop emits these items at once and does not wait for the next
    /// interest step. The SASL rc of a failed address read becomes the rc
    /// of the call. The function returns true at a barrier: after a START
    /// or STEP item, or when the pump stops.
    fn process_sasl<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        ob: &mut Outbox<T>,
    ) -> bool {
        loop {
            let now = cx.clock.now();
            let mut g = cx.core.lock(proof);
            let Some(conn) = g.conn.as_deref_mut() else {
                return false;
            };
            if !conn.has_transport() {
                return false;
            }
            let Some(call) = conn.poll_sasl_call() else {
                return false;
            };
            match call.kind {
                SaslCallKind::Dispose => ob.push(Item::Sasl(SaslItem { call, addrs: None })),
                SaslCallKind::Step(_) => {
                    ob.push(Item::Sasl(SaslItem { call, addrs: None }));
                    return true;
                }
                SaslCallKind::Start => match self.sasl_addrs() {
                    Ok(addrs) => {
                        ob.push(Item::Sasl(SaslItem {
                            call,
                            addrs: Some(addrs),
                        }));
                        return true;
                    }
                    Err(which) => {
                        let rc = conn.handle_sasl_addr_failed(call.generation, which, now);
                        if rc != ZOK {
                            self.stop_rc.get_or_insert(rc);
                        }
                        if self.settle(&mut g, cx, ob) {
                            return true;
                        }
                    }
                },
            }
        }
    }

    /// The plaintext flush pass.
    ///
    /// It copies what proto releases into `tx_copy`, sends with no lock
    /// held, then acknowledges the sent bytes. With no deadline the sends
    /// stop at WouldBlock. With a deadline each send waits for WRITE
    /// through `poll` until the deadline.
    pub(crate) fn plain_flush<T: Tokens>(
        &mut self,
        cx: &StepCtx<'_, T>,
        proof: &mut Unlocked,
        deadline: Option<Millis>,
    ) -> Result<(), FlushError> {
        loop {
            if self.tx_copy.is_empty() && !self.stage_plain(cx, proof) {
                return Ok(());
            }
            let Transport::Plain(sock) = &self.conn else {
                return Ok(());
            };
            let rest = self.tx_copy.get(self.sent_len()..).unwrap_or_default();
            let n = match deadline {
                None => match sock.send(rest) {
                    Ok(n) => n,
                    Err(Errno::INTR) => continue,
                    Err(Errno::WOULDBLOCK) => return Ok(()),
                    Err(e) => return Err(FlushError::Send(e)),
                },
                Some(d) => send_until(cx, sock, rest, d)?,
            };
            if n == 0 {
                return Ok(());
            }
            let n = self.plain_sent(n);
            let now = cx.clock.now();
            let mut g = cx.core.lock(proof);
            let Some(conn) = g.conn.as_deref_mut() else {
                return Ok(());
            };
            if !conn.has_transport() {
                return Ok(());
            }
            conn.handle_transmitted(n, now);
        }
    }

    /// Copies the next plaintext bytes from proto into the empty
    /// `tx_copy` under the lock. It returns false when no transport
    /// exists or proto has no more bytes to release.
    ///
    /// After the lock, it frees a large `tx_copy` after a run of small
    /// writes, with the rule of the TLS path.
    fn stage_plain<T: Tokens>(&mut self, cx: &StepCtx<'_, T>, proof: &mut Unlocked) -> bool {
        let n = {
            let mut g = cx.core.lock(proof);
            match g.conn.as_deref_mut() {
                Some(conn) if conn.has_transport() => {
                    conn.poll_transmit(&mut self.tx_copy, TX_LEND_MAX)
                }
                _ => return false,
            }
        };
        let cap = self.tx_copy.capacity();
        if self.write_bursts.release(n, cap) && cap > READ_BUFFER_LEN {
            // The buffer is empty here. Its drop erases all of it once,
            // because it can hold old copies of secret frames.
            self.tx_copy = Zeroizing::new(Vec::new());
        }
        n > 0
    }

    /// Records `n` sent bytes of `tx_copy` and returns the count that
    /// proto must acknowledge. When every byte is sent, `tx_copy` clears
    /// and the next flush step copies new bytes.
    fn plain_sent(&mut self, n: usize) -> usize {
        let sent = self.sent_len();
        let n = n.min(self.tx_copy.len().saturating_sub(sent));
        let sent = sent.saturating_add(n);
        if sent >= self.tx_copy.len() {
            self.tx_copy.clear();
            self.tx_sent = 0;
        } else {
            // `tx_copy` holds one lent frame of at most `TX_LEND_MAX`
            // bytes or 64 KiB of copies, so the count fits in a `u32`.
            self.tx_sent = u32::try_from(sent).unwrap_or(u32::MAX);
        }
        n
    }

    /// Returns the count of sent bytes at the start of `tx_copy`.
    pub(crate) fn sent_len(&self) -> usize {
        usize::try_from(self.tx_sent).unwrap_or(usize::MAX)
    }
}

impl Default for IoCore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::socket_pair;

    #[test]
    fn drop_transport_clears_the_receive_state() {
        let (a, _b) = socket_pair();
        let mut io = IoCore::new();
        io.conn = Transport::Plain(a);
        io.rx_pending.extend_from_slice(b"x");
        io.rx_fresh = 3;
        io.rx_stalled = true;
        assert!(io.fd() >= 0);
        io.drop_transport();
        assert_eq!(io.fd(), -1);
        assert_eq!(io.rx_fresh, 0);
        assert!(io.rx_pending.is_empty() && !io.rx_stalled);
    }

    /// Proto reads fresh bytes in place. The bytes that it does not take
    /// move to `rx_pending` in order, and `rx` is then free.
    #[test]
    fn the_rest_of_a_fresh_read_moves_to_rx_pending() {
        let mut io = IoCore::new();
        if let Some(b) = io.rx.get_mut(..3) {
            b.copy_from_slice(b"abc");
        }
        io.rx_fresh = 3;
        assert_eq!(io.rx_input(), b"abc");
        io.rx_consume(1);
        assert_eq!(
            (io.rx_fresh, io.rx_pending.as_slice()),
            (0, b"bc".as_slice())
        );
        assert_eq!(io.rx_input(), b"bc");
        io.rx_consume(1);
        assert_eq!(io.rx_input(), b"c");
        io.spill_fresh();
        assert_eq!(io.rx_pending, b"c");
    }
}
