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

//! The bounded read-only-server probe.
//!
//! The probe runs with no driver lock held, against the endpoint that
//! proto names in `Action::ProbeRw`. It opens its own socket and, with
//! TLS, its own session. It closes both on every path and sends no
//! `close_notify`. Its result goes to proto as `handle_rw_probe`. A probe
//! failure never tears down the main connection.
//!
//! The caller returns `ZKRS_MORE` first when its outbox holds items. The
//! probe itself never touches an outbox.

use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use zk_proto::compat::TlsVerify;
use zk_proto::{ConnectStart, Endpoint, ProbeOutcome, ProbeTlsFailure};

use crate::clock::Clock;
use crate::net::poll::{Poll, PollEvents, clamp_timeout_ms, request_flags};
use crate::net::sock::TcpSock;
use crate::net::tls::{
    TlsConn, TlsConnector, TlsFailure, TlsPurpose, TlsResourceAt, TlsSetupError, alert_attempt,
    jstring,
};
use crate::net::waker::{WakeRx, Waker};
use crate::sync::Unlocked;
use crate::sync::atomic::{AtomicBool, Ordering};

/// The budget of each probe phase: TCP connect, TLS handshake, and the
/// `isro` exchange (`DriverConfig::probe_phase_ms`).
pub const PROBE_PHASE_MS: u64 = 1000;

/// The services of one probe.
pub struct ProbeCtx<'a> {
    /// The poll call of the handle.
    pub poll: &'a dyn Poll,
    /// The clock of the handle. The phase deadlines use it.
    pub clock: &'a dyn Clock,
    /// The waker of the handle (mt and native threaded). It is in every
    /// probe poll set. The probe resets it when it fires.
    pub wake: Option<(&'a Waker, &'a WakeRx)>,
    /// The close flag. The probe checks it after each poll. When it is
    /// set, the probe ends with [`ProbeEnd::Aborted`].
    pub abort: Option<&'a AtomicBool>,
    /// The TLS connector, or `None` for a plaintext handle.
    pub tls: Option<&'a dyn TlsConnector>,
    /// The CLOEXEC rule of the handle.
    pub cloexec: bool,
    /// The budget of each phase, in milliseconds.
    pub phase_ms: u64,
}

/// The end of a probe.
#[derive(Debug, PartialEq, Eq)]
pub enum ProbeEnd {
    /// The probe ran. The caller passes the outcome to `handle_rw_probe`.
    Done(ProbeOutcome),
    /// The close flag was set. The caller does not call
    /// `handle_rw_probe`, and the close goes on.
    Aborted,
}

/// Runs one probe (zookeeper.c:2461-2522).
///
/// Contract:
/// 1. Open a non-blocking socket with [`crate::net::TcpSock::open`]. A
///    failure gives `Failed(None)`.
/// 2. `connect`, poll for WRITE for at most `phase_ms`, then `SO_ERROR`.
///    A failure or the deadline gives `Failed(None)`.
/// 3. With `verify = Some(_)` and a connector: `new_conn(proof,
///    TlsPurpose::Probe, ep)`. `Config{step}` gives
///    `Failed(Some(ProbeTlsFailure::Config{step, file}))`, with `file`
///    from `path_for(step)`. `Resource{at}` gives
///    `Failed(Some(Resource{at}))`. Then a non-blocking handshake for at
///    most `phase_ms`. A failure or the deadline gives
///    `Failed(Some(Handshake))`. A verify failure or a bad record makes
///    one `alert_attempt`.
/// 4. Send `"isro"` (plaintext, or one `write_frame` and its ciphertext),
///    then read. Send and read share one `phase_ms` budget. Plaintext:
///    one successful `recv` of at most 10 bytes. TLS: feed ciphertext
///    until the first plaintext bytes, EOF or the deadline, then take at
///    most 10 plaintext bytes.
/// 5. `ReadWrite` exactly when the first three bytes of a zero-filled
///    10-byte buffer are `'r'`, `'w'`, 0 ([`is_rw_reply`]). Otherwise
///    `NotReadWrite`. A send or read failure, or the deadline, gives
///    `Failed(None)`.
/// 6. Drop the session with no `close_notify`, and close the socket.
#[must_use]
pub fn probe(
    cx: &ProbeCtx<'_>,
    proof: &Unlocked,
    ep: &Endpoint,
    verify: Option<TlsVerify>,
) -> ProbeEnd {
    match run(cx, proof, ep, verify) {
        Ok(outcome) => ProbeEnd::Done(outcome),
        Err(Stop::Failed(f)) => ProbeEnd::Done(ProbeOutcome::Failed(f)),
        Err(Stop::Aborted) => ProbeEnd::Aborted,
    }
}

/// The C `strcmp(buf, "rw") == 0` rule over a zero-filled 10-byte
/// buffer. It never reads past byte 3.
#[must_use]
pub fn is_rw_reply(reply: &[u8]) -> bool {
    // A missing byte is a zero of the zero-filled buffer.
    let byte = |i: usize| reply.get(i).copied().unwrap_or(0);
    byte(0) == b'r' && byte(1) == b'w' && byte(2) == 0
}

/// The size of the C reply buffer. The probe reads at most this many
/// reply bytes.
const REPLY_LEN: usize = 10;

/// The size of the heap buffer for TLS ciphertext. It holds one full
/// TLS record, so one recv call can complete a record.
const CIPHERTEXT_BUF: usize = 17 * 1024;

/// The reason that a probe stops before it has an outcome.
#[derive(Debug)]
enum Stop {
    /// The probe failed. The value is the TLS cause, if there is one.
    Failed(Option<ProbeTlsFailure>),
    /// The close flag was set.
    Aborted,
}

/// The result of one bounded wait for readiness.
#[derive(Debug, PartialEq, Eq)]
enum Wait {
    /// The socket is ready, or it has an error or a hang-up.
    Ready,
    /// The phase deadline passed.
    Timeout,
    /// The poll call failed.
    Failed,
    /// The close flag was set.
    Aborted,
}

/// Runs the probe phases. The socket and the session drop on every
/// return path, and the probe sends no close_notify.
fn run(
    cx: &ProbeCtx<'_>,
    proof: &Unlocked,
    ep: &Endpoint,
    verify: Option<TlsVerify>,
) -> Result<ProbeOutcome, Stop> {
    if aborted(cx) {
        return Err(Stop::Aborted);
    }
    let sock = connect(cx, ep)?;
    match verify {
        None => exchange_plain(cx, &sock),
        Some(_) => {
            let mut tls = new_session(cx, proof, ep)?;
            let mut ct_out = Vec::new();
            let mut buf = vec![0u8; CIPHERTEXT_BUF];
            handshake(cx, &sock, &mut *tls, &mut ct_out, &mut buf)?;
            exchange_tls(cx, &sock, &mut *tls, &mut ct_out, &mut buf)
        }
    }
}

/// Opens the probe socket and connects it within one phase budget.
fn connect(cx: &ProbeCtx<'_>, ep: &Endpoint) -> Result<TcpSock, Stop> {
    let fail = Stop::Failed(None);
    let sock = TcpSock::open(&ep.addr, cx.cloexec).map_err(|_| Stop::Failed(None))?;
    let sock = sock.sock;
    match sock.start_connect(&ep.addr) {
        Ok(ConnectStart::Immediate) => Ok(sock),
        Ok(ConnectStart::InProgress) => {
            let deadline = deadline(cx);
            match wait(cx, &sock, WRITE, deadline) {
                Wait::Ready => match sock.socket_error() {
                    Ok(()) => Ok(sock),
                    Err(_) => Err(fail),
                },
                Wait::Aborted => Err(Stop::Aborted),
                Wait::Timeout | Wait::Failed => Err(fail),
            }
        }
        Err(_) => Err(fail),
    }
}

/// Makes the probe session. A probe that needs TLS but has no connector
/// fails as the context site, as a failed `SSL_CTX_new` does.
fn new_session(
    cx: &ProbeCtx<'_>,
    proof: &Unlocked,
    ep: &Endpoint,
) -> Result<Box<dyn TlsConn>, Stop> {
    let Some(connector) = cx.tls else {
        return Err(Stop::Failed(Some(ProbeTlsFailure::Resource {
            at: TlsResourceAt::ContextNew,
        })));
    };
    connector
        .new_conn(proof, TlsPurpose::Probe, ep)
        .map_err(|e| match e {
            TlsSetupError::Config { step } => Stop::Failed(Some(ProbeTlsFailure::Config {
                step,
                file: jstring(connector.path_for(step)),
            })),
            TlsSetupError::Resource { at } => Stop::Failed(Some(ProbeTlsFailure::Resource { at })),
        })
}

/// Runs the non-blocking handshake within one phase budget.
///
/// Ciphertext that is not sent when the handshake ends stays in
/// `ct_out`. The exchange phase sends it before the request.
fn handshake(
    cx: &ProbeCtx<'_>,
    sock: &TcpSock,
    tls: &mut dyn TlsConn,
    ct_out: &mut Vec<u8>,
    buf: &mut [u8],
) -> Result<(), Stop> {
    let fail = || Stop::Failed(Some(ProbeTlsFailure::Handshake));
    let deadline = deadline(cx);
    loop {
        tls.take_ciphertext(ct_out);
        flush(sock, ct_out).map_err(|_| fail())?;
        if !tls.is_handshaking() {
            return Ok(());
        }
        let want = PollEvents {
            read: true,
            write: !ct_out.is_empty(),
        };
        match wait(cx, sock, want, deadline) {
            Wait::Ready => {}
            Wait::Aborted => return Err(Stop::Aborted),
            Wait::Timeout | Wait::Failed => return Err(fail()),
        }
        match sock.recv(buf) {
            Ok(0) => {
                let _ = tls.feed_eof();
                return Err(fail());
            }
            Ok(n) => {
                if tls.feed(buf.get(..n).unwrap_or_default()).is_err() {
                    // A verify failure or a bad record queues an alert.
                    alert_attempt(sock, tls, ct_out);
                    return Err(fail());
                }
            }
            Err(e) if in_progress(e) => {}
            Err(_) => return Err(fail()),
        }
    }
}

/// Sends `isro` and reads one reply over plaintext within one phase
/// budget. The first recv that succeeds decides the outcome, as in C.
/// So an EOF gives `NotReadWrite`.
fn exchange_plain(cx: &ProbeCtx<'_>, sock: &TcpSock) -> Result<ProbeOutcome, Stop> {
    let deadline = deadline(cx);
    let mut rest: &[u8] = b"isro";
    while !rest.is_empty() {
        match sock.send(rest) {
            Ok(n) => rest = rest.get(n..).unwrap_or_default(),
            Err(e) if in_progress(e) => wait_or_stop(cx, sock, WRITE, deadline)?,
            Err(_) => return Err(Stop::Failed(None)),
        }
    }
    let mut reply = [0u8; REPLY_LEN];
    loop {
        wait_or_stop(cx, sock, READ, deadline)?;
        match sock.recv(&mut reply) {
            Ok(_) => return Ok(outcome(&reply)),
            Err(e) if in_progress(e) => {}
            Err(_) => return Err(Stop::Failed(None)),
        }
    }
}

/// Sends `isro` as one frame and reads the first plaintext within one
/// phase budget. A clean close before any plaintext gives
/// `NotReadWrite`, as an `SSL_read` of 0 does in C.
fn exchange_tls(
    cx: &ProbeCtx<'_>,
    sock: &TcpSock,
    tls: &mut dyn TlsConn,
    ct_out: &mut Vec<u8>,
    buf: &mut [u8],
) -> Result<ProbeOutcome, Stop> {
    let deadline = deadline(cx);
    if tls.write_frame(b"isro").is_err() {
        alert_attempt(sock, tls, ct_out);
        return Err(Stop::Failed(None));
    }
    let mut plain = Vec::new();
    loop {
        tls.take_ciphertext(ct_out);
        flush(sock, ct_out).map_err(|_| Stop::Failed(None))?;
        match tls.read_plaintext(&mut plain) {
            Ok(0) => {}
            Ok(_) => {
                let reply = plain.get(..REPLY_LEN).unwrap_or(&plain);
                return Ok(outcome(reply));
            }
            Err(TlsFailure::Closed) => return Ok(ProbeOutcome::NotReadWrite),
            Err(_) => {
                alert_attempt(sock, tls, ct_out);
                return Err(Stop::Failed(None));
            }
        }
        let want = PollEvents {
            read: true,
            write: !ct_out.is_empty(),
        };
        wait_or_stop(cx, sock, want, deadline)?;
        match sock.recv(buf) {
            // The session latches the end or the failure. The next
            // read_plaintext call reports it after any plaintext.
            Ok(0) => {
                let _ = tls.feed_eof();
            }
            Ok(n) => {
                let _ = tls.feed(buf.get(..n).unwrap_or_default());
            }
            Err(e) if in_progress(e) => {}
            Err(_) => return Err(Stop::Failed(None)),
        }
    }
}

/// Maps a reply to the outcome.
fn outcome(reply: &[u8]) -> ProbeOutcome {
    if is_rw_reply(reply) {
        ProbeOutcome::ReadWrite
    } else {
        ProbeOutcome::NotReadWrite
    }
}

/// The interest of a probe that waits to read.
const READ: PollEvents = PollEvents {
    read: true,
    write: false,
};

/// The interest of a probe that waits to write.
const WRITE: PollEvents = PollEvents {
    read: false,
    write: true,
};

/// Returns true for the errors that mean "try again later".
fn in_progress(e: Errno) -> bool {
    e == Errno::WOULDBLOCK || e == Errno::INTR
}

/// Returns true when the close flag is set.
fn aborted(cx: &ProbeCtx<'_>) -> bool {
    cx.abort.is_some_and(|f| f.load(Ordering::Acquire))
}

/// Returns the deadline of a phase that starts now.
fn deadline(cx: &ProbeCtx<'_>) -> u64 {
    cx.clock.now().0.saturating_add(cx.phase_ms)
}

/// Sends queued ciphertext until the kernel takes no more. The bytes
/// that stay wait for the next writable socket.
fn flush(sock: &TcpSock, ct_out: &mut Vec<u8>) -> Result<(), Errno> {
    while !ct_out.is_empty() {
        match sock.send(ct_out) {
            Ok(0) => break,
            Ok(n) => {
                ct_out.drain(..n.min(ct_out.len()));
            }
            Err(e) if in_progress(e) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Waits for readiness. A timeout or a poll failure is a plain probe
/// failure.
fn wait_or_stop(
    cx: &ProbeCtx<'_>,
    sock: &TcpSock,
    want: PollEvents,
    deadline: u64,
) -> Result<(), Stop> {
    match wait(cx, sock, want, deadline) {
        Wait::Ready => Ok(()),
        Wait::Aborted => Err(Stop::Aborted),
        Wait::Timeout | Wait::Failed => Err(Stop::Failed(None)),
    }
}

/// Waits until the socket is ready, the deadline passes, or the close
/// flag is set.
///
/// The waker is in the poll set, so a close wakes the poll at once. A
/// wake with no close flag only resets the waker, and the wait goes on
/// to the same deadline. The IO owner reads the core state again after
/// the probe, so the reset loses no work. Any returned socket event
/// counts as ready. An error or a hang-up then shows in the next call,
/// so the loop does not spin.
fn wait(cx: &ProbeCtx<'_>, sock: &TcpSock, want: PollEvents, deadline: u64) -> Wait {
    let flags = request_flags(want);
    loop {
        if aborted(cx) {
            return Wait::Aborted;
        }
        let left = deadline.saturating_sub(cx.clock.now().0);
        let timeout = clamp_timeout_ms(i64::try_from(left).unwrap_or(i64::MAX));
        let polled = match cx.wake {
            Some((_, rx)) => {
                let mut fds = [PollFd::new(sock, flags), PollFd::new(rx, PollFlags::IN)];
                let r = cx.poll.poll(&mut fds, timeout);
                let [s, w] = &fds;
                r.map(|n| (n, s.revents(), w.revents()))
            }
            None => {
                let mut fds = [PollFd::new(sock, flags)];
                let r = cx.poll.poll(&mut fds, timeout);
                let [s] = &fds;
                r.map(|n| (n, s.revents(), PollFlags::empty()))
            }
        };
        let (n, sock_ev, wake_ev) = match polled {
            Ok(v) => v,
            Err(Errno::INTR) => continue,
            Err(_) => return Wait::Failed,
        };
        if !wake_ev.is_empty() {
            if let Some((waker, rx)) = cx.wake {
                rx.reset(waker);
            }
        }
        if aborted(cx) {
            return Wait::Aborted;
        }
        if !sock_ev.is_empty() {
            return Wait::Ready;
        }
        if n == 0 || cx.clock.now().0 >= deadline {
            return Wait::Timeout;
        }
    }
}
