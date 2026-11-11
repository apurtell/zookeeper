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

//! The TLS parts of the I/O path.
//!
//! TLS uses the sockets, the poll loop and the proto phases of plaintext.
//! Bytes pass through a [`TlsConn`] between the socket and proto. The
//! driver owns the socket. The session never sees it.
//!
//! These functions are always compiled. They use only the [`TlsConn`]
//! and [`TlsConnector`] traits, so the tests run them over the
//! `testutil::NullTls` session without the `tls` feature.

use rustix::io::Errno;
use zeroize::Zeroizing;
use zk_proto::compat::TlsVerify;
use zk_proto::rc::ZOK;
use zk_proto::{Endpoint, Millis, TlsResourceAt, Tokens, TransportFailure};

use crate::iocore::{
    Cont, FlushError, FrameEnd, IoCore, Job, JobKind, Progress, READ_BUFFER_LEN, StepCtx,
    Transport, gate_open, wait_writable,
};
use crate::net::poll::PollEvents;
use crate::net::sock::{TcpSock, errno_value};
use crate::net::tls::{
    ReadFailure, TlsConn, TlsPurpose, TlsSetupError, TlsTransport, alert_attempt, jstring,
};
use crate::outbox::Outbox;
use crate::sync::Unlocked;

/// The largest `poll_transmit` chunk that one `write_frame` call takes.
/// At most one chunk is inside the session at a time.
///
/// rustls cuts a chunk into records of at most 16 KiB. A chunk of many
/// records gives fewer lock passes and fewer `send` calls for a large
/// frame.
pub(crate) const MAX_CHUNK: usize = 256 * 1024;

/// Starts the handshake on an established TCP socket.
///
/// - Return `More` first when LOG items wait. The deadline
///   origin is the `now` of the first call. Keep it across the resume.
/// - Call `new_conn(Main)` with no lock. With
///   `DeferPolicy::new_conn` push a `Job::NewConn` and return `Wait`.
/// - `Ok`: `handle_tcp_connected(now)`, the TLS transport, the
///   ClientHello into `ct_out`, one send. WouldBlock keeps WRITE.
/// - `Err(Config{step})`: `handle_transport_failed(TlsConfig{step, file:
///   jstring(path_for(step))})`, then park the socket. A parked socket
///   has no teardown and no WRITE interest. The receive timeout then
///   ends the attempt, as in C.
/// - `Err(Resource{at})`: `handle_transport_failed(TlsResource{at,
///   errno})`. This is a teardown.
///
/// It returns `Done(rc)`, with `ZOK` when the session exists.
pub(crate) fn handshake_start<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    sock: TcpSock,
    ep: Endpoint,
    verify: TlsVerify,
    ob: &mut Outbox<T>,
) -> Progress {
    let _origin = *io.hs_now.get_or_insert_with(|| cx.clock.now());
    if ob.has_pending_logs() {
        io.conn = Transport::Connecting {
            sock,
            ep,
            tls: Some(verify),
        };
        io.cont = Cont::Handshake;
        return Progress::More;
    }
    if cx.defer.new_conn {
        io.deferred.push(Job::NewConn {
            purpose: TlsPurpose::Main,
            endpoint: ep.clone(),
        });
        io.conn = Transport::Connecting {
            sock,
            ep,
            tls: Some(verify),
        };
        io.job = Some(JobKind::NewConn);
        io.cont = Cont::Job;
        return Progress::Wait;
    }
    let result = match cx.tls {
        Some(c) => c.new_conn(proof, TlsPurpose::Main, &ep),
        None => Err(TlsSetupError::Resource {
            at: TlsResourceAt::ContextNew,
        }),
    };
    handshake_with(io, cx, proof, ob, sock, result)
}

/// The part of the handshake start after `new_conn`. The
/// deferred `NewConn` job enters here with its result.
pub(crate) fn handshake_with<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    ob: &mut Outbox<T>,
    sock: TcpSock,
    result: Result<Box<dyn TlsConn>, TlsSetupError>,
) -> Progress {
    let now = io.hs_now.take().unwrap_or_else(|| cx.clock.now());
    match result {
        Ok(tls) => {
            let barrier = {
                let mut g = cx.core.lock(proof);
                let has = match g.conn.as_deref_mut() {
                    Some(c) => {
                        c.handle_tcp_connected(now);
                        c.has_transport()
                    }
                    None => false,
                };
                if has {
                    let mut t = TlsTransport::new(sock, tls);
                    let _hello = t.tls.take_ciphertext(&mut t.ct_out);
                    io.conn = Transport::Tls(t);
                }
                io.settle(&mut g, cx, ob)
            };
            if barrier {
                // The ClientHello waits in `ct_out`. WRITE interest sends it.
                return handshake_end(io, true, ZOK);
            }
            let sent = match &mut io.conn {
                Transport::Tls(t) => pump_out(t),
                _ => Ok(true),
            };
            match sent {
                Ok(_) => Progress::Done(ZOK),
                Err(e) => {
                    let f = TransportFailure::TlsHandshake {
                        errno: errno_value(e),
                    };
                    let (rc, barrier) = io.fail(cx, proof, ob, f);
                    handshake_end(io, barrier, rc)
                }
            }
        }
        Err(TlsSetupError::Config { step }) => {
            let file = jstring(cx.tls.and_then(|c| c.path_for(step)));
            io.conn = Transport::Parked(sock);
            let (rc, barrier) = io.fail(cx, proof, ob, TransportFailure::TlsConfig { step, file });
            handshake_end(io, barrier, rc)
        }
        Err(TlsSetupError::Resource { at }) => {
            drop(sock);
            let f = TransportFailure::TlsResource { at, errno: 0 };
            let (rc, barrier) = io.fail(cx, proof, ob, f);
            handshake_end(io, barrier, rc)
        }
    }
}

/// Ends the handshake start with `rc`, or stops first at a barrier.
fn handshake_end(io: &mut IoCore, barrier: bool, rc: i32) -> Progress {
    if barrier {
        io.cont = Cont::AfterHandshake { rc };
        return Progress::More;
    }
    Progress::Done(rc)
}

/// One handshake step of a process call.
///
/// On READ or HUP: one recv, then `feed` (`feed_eof` on EOF). A failure
/// gives `alert_attempt`, then `TlsHandshake{errno}`. Then `pump_out`.
/// When the handshake is complete: `handle_transport_ready`, one flush
/// and the frame steps of [`tls_read`] for bytes of the last flight.
/// It returns `Done(ZOK)` for every handshake step (st parity).
pub(crate) fn handshake_step<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    events: PollEvents,
    ob: &mut Outbox<T>,
) -> Progress {
    let Transport::Tls(t) = &mut io.conn else {
        return Progress::Done(ZOK);
    };
    let mut failed: Option<i32> = None;
    if events.read {
        match t.sock.recv(&mut io.rx) {
            Ok(0) => {
                let _latched = t.tls.feed_eof();
                failed = Some(0);
            }
            Ok(n) => {
                let data = io.rx.get(..n).unwrap_or_default();
                if t.tls.feed(data).is_err() {
                    alert_attempt(&t.sock, &mut *t.tls, &t.ct_out);
                    // A failure after the last flight is a data-phase
                    // latch. The frame loop acts on it after the frames.
                    if t.tls.is_handshaking() {
                        failed = Some(0);
                    }
                }
            }
            Err(Errno::WOULDBLOCK) => {}
            Err(e) => failed = Some(errno_value(e)),
        }
    }
    if failed.is_none() {
        if let Err(e) = pump_out(t) {
            failed = Some(errno_value(e));
        }
    }
    if let Some(errno) = failed {
        return io.fail_end(cx, proof, ob, TransportFailure::TlsHandshake { errno });
    }
    if t.tls.is_handshaking() {
        return Progress::Done(ZOK);
    }
    let now = cx.clock.now();
    let barrier = {
        let mut g = cx.core.lock(proof);
        if let Some(conn) = g.conn.as_deref_mut() {
            conn.handle_transport_ready(now);
        }
        io.settle(&mut g, cx, ob)
    };
    if barrier {
        io.cont = Cont::HandshakeReady;
        return Progress::More;
    }
    handshake_ready(io, cx, proof, ob)
}

/// The end of a complete handshake: one flush for the ConnectRequest,
/// then the frames that came with the last flight.
pub(crate) fn handshake_ready<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    ob: &mut Outbox<T>,
) -> Progress {
    if let Err(e) = tls_flush(io, cx, proof, None) {
        let f = TransportFailure::Io {
            errno: errno_value(e),
        };
        return io.fail_end(cx, proof, ob, f);
    }
    if let Transport::Tls(t) = &mut io.conn {
        if t.pending.is_none() {
            t.pending = take_plaintext(&mut *t.tls, &mut io.rx_pending);
        }
    }
    tls_frames(io, cx, proof, ob, true)
}

/// A data-phase read and the frame loop.
///
/// One recv of up to 64 KiB of ciphertext in every flavor. A failure is
/// latched in `TlsTransport::pending`. The frame loop gives every
/// complete frame of the decrypted plaintext to `handle_read`, with
/// barriers. The resume enters at the frame loop. The latched failure
/// acts only after the loop, and only while proto has the transport.
/// `Closed` gives `Eof`. `Data` and `Io` give `Io`. No complete frame
/// gives `ZNOTHING`.
pub(crate) fn tls_read<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    events: PollEvents,
    ob: &mut Outbox<T>,
) -> Progress {
    let gate = {
        let g = cx.core.lock(proof);
        g.conn.as_deref().is_some_and(|c| gate_open(cx, c.state()))
    };
    let Transport::Tls(t) = &mut io.conn else {
        let rc = io.process_rc();
        return io.done(rc);
    };
    if events.read && t.pending.is_none() && gate {
        io.read_attempted = true;
        match t.sock.recv(&mut io.rx) {
            Ok(0) => {
                // The session latches `Closed`. `take_plaintext` gives it.
                let _latched = t.tls.feed_eof();
            }
            Ok(n) => {
                let data = io.rx.get(..n).unwrap_or_default();
                if t.tls.feed(data).is_err() {
                    alert_attempt(&t.sock, &mut *t.tls, &t.ct_out);
                }
            }
            Err(Errno::WOULDBLOCK) => {}
            Err(e) => t.pending = Some(ReadFailure::Io(errno_value(e))),
        }
    }
    if t.pending.is_none() {
        t.pending = take_plaintext(&mut *t.tls, &mut io.rx_pending);
    }
    tls_frames(io, cx, proof, ob, false)
}

/// The TLS frame loop and the action on a latched failure.
///
/// The resume enters here. The rc of a handshake step is `ZOK` unless a
/// teardown occurs. A data-phase step uses the rc rule of the process
/// call.
pub(crate) fn tls_frames<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    ob: &mut Outbox<T>,
    handshake: bool,
) -> Progress {
    let rc_of = |io: &IoCore| {
        if handshake {
            io.stop_rc.unwrap_or(ZOK)
        } else {
            io.process_rc()
        }
    };
    match io.frame_loop(cx, proof, ob) {
        FrameEnd::More => {
            io.cont = Cont::TlsFrames { handshake };
            return Progress::More;
        }
        FrameEnd::Held => {
            let rc = rc_of(io);
            return io.done(rc);
        }
        FrameEnd::Done => {}
    }
    let pending = match &io.conn {
        Transport::Tls(t) => t.pending,
        _ => None,
    };
    if let Some(p) = pending {
        let now = cx.clock.now();
        let (failed, barrier) = {
            let mut g = cx.core.lock(proof);
            let mut failed = None;
            if let Some(conn) = g.conn.as_deref_mut() {
                if conn.has_transport() {
                    if let Transport::Tls(t) = &mut io.conn {
                        t.pending = None;
                    }
                    let f = match p {
                        ReadFailure::Closed => TransportFailure::Eof,
                        ReadFailure::Data => TransportFailure::Io { errno: 0 },
                        ReadFailure::Io(errno) => TransportFailure::Io { errno },
                    };
                    failed = Some(conn.handle_transport_failed(f, now));
                }
            }
            (failed, io.settle(&mut g, cx, ob))
        };
        if let Some(rc) = failed {
            io.stop_rc.get_or_insert(rc);
        }
        let rc = rc_of(io);
        return io.end_after(barrier, rc);
    }
    if let Transport::Tls(t) = &mut io.conn {
        if t.tls.has_ciphertext() {
            if let Err(e) = pump_out(t) {
                let f = TransportFailure::Io {
                    errno: errno_value(e),
                };
                return io.fail_end(cx, proof, ob, f);
            }
        }
    }
    let rc = rc_of(io);
    io.done(rc)
}

/// Moves the decrypted plaintext into `rx_pending` and returns the
/// latched failure, if any.
///
/// The first `read_plaintext` gives the plaintext. The next call gives
/// the latch. So plaintext before a failure is always delivered.
// The body appends to the buffer, so it takes the `Vec`.
#[allow(clippy::ptr_arg)]
pub(crate) fn take_plaintext(
    tls: &mut dyn TlsConn,
    rx_pending: &mut Vec<u8>,
) -> Option<crate::net::tls::ReadFailure> {
    loop {
        match tls.read_plaintext(rx_pending) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(f) => return Some(f.into()),
        }
    }
}

/// The data-phase flush with the acknowledgment rule.
///
/// Proto hears `handle_transmitted(unacked)` only after the kernel took
/// all ciphertext of the chunk. One `write_frame` per `poll_transmit`
/// chunk of at most [`MAX_CHUNK`]. A latched failure stops the flush.
/// `deadline` is `None` for non-blocking sends, or the close-flush
/// deadline for blocking sends through `poll`.
///
/// # Errors
///
/// Returns the send errno. The caller gives it to proto as `Io`.
pub(crate) fn tls_flush<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    deadline: Option<Millis>,
) -> Result<(), Errno> {
    match tls_flush_with(io, cx, proof, deadline) {
        Ok(()) | Err(FlushError::Timeout | FlushError::Session) => Ok(()),
        Err(FlushError::Send(e) | FlushError::Poll(e)) => Err(e),
    }
}

/// The body of [`tls_flush`] with the failure kinds of the close flush.
///
/// With a deadline, a latched failure and a refused chunk give
/// `Session`. With no deadline they end the pass with no error.
pub(crate) fn tls_flush_with<T: Tokens>(
    io: &mut IoCore,
    cx: &StepCtx<'_, T>,
    proof: &mut Unlocked,
    deadline: Option<Millis>,
) -> Result<(), FlushError> {
    let stop = if deadline.is_some() {
        Err(FlushError::Session)
    } else {
        Ok(())
    };
    loop {
        let Transport::Tls(t) = &mut io.conn else {
            return Ok(());
        };
        if t.pending.is_some() {
            return stop;
        }
        if t.has_unsent() {
            let all_sent = match deadline {
                None => pump_out(t).map_err(FlushError::Send)?,
                Some(d) => pump_until(cx, t, d)?,
            };
            if !all_sent {
                return Ok(());
            }
        }
        if t.unacked > 0 {
            let n = std::mem::take(&mut t.unacked);
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
        let n = stage_chunk(io, cx, proof);
        if n == 0 {
            return Ok(());
        }
        let Transport::Tls(t) = &mut io.conn else {
            io.tx_copy.clear();
            return Ok(());
        };
        let taken = t.tls.write_frame(&io.tx_copy);
        io.tx_copy.clear();
        if taken.is_err() {
            // The frames stay unsent in proto.
            return stop;
        }
        let _n = t.tls.take_ciphertext(&mut t.ct_out);
        t.unacked = n;
    }
}

/// Sends `ct_out` with a poll for WRITE between sends until `deadline`.
/// It returns true when every byte went out.
fn pump_until<T: Tokens>(
    cx: &StepCtx<'_, T>,
    t: &mut TlsTransport,
    deadline: Millis,
) -> Result<bool, FlushError> {
    loop {
        if pump_out(t).map_err(FlushError::Send)? {
            return Ok(true);
        }
        wait_writable(cx.clock, cx.poll, &t.sock, deadline)?;
    }
}

/// Sends `ct_out` with non-blocking sends until WouldBlock.
///
/// It first moves the session ciphertext into `ct_out`. It returns true
/// when `ct_out` is empty after the call.
///
/// # Errors
///
/// Returns the send errno.
pub(crate) fn pump_out(t: &mut TlsTransport) -> Result<bool, Errno> {
    let _n = t.tls.take_ciphertext(&mut t.ct_out);
    while !t.ct_out.is_empty() {
        match t.sock.send(t.unsent()) {
            Ok(0) | Err(Errno::WOULDBLOCK) => return Ok(false),
            Ok(n) => t.mark_sent(n),
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Copies the next plaintext chunk from proto into `tx_copy` under the
/// lock, and returns its size. A size of 0 means that no transport
/// exists or proto has no more bytes to release.
///
/// After the lock, it updates the write record of the large buffers.
fn stage_chunk<T: Tokens>(io: &mut IoCore, cx: &StepCtx<'_, T>, proof: &mut Unlocked) -> usize {
    io.tx_copy.clear();
    let n = {
        let mut g = cx.core.lock(proof);
        match g.conn.as_deref_mut() {
            Some(conn) if conn.has_transport() => conn.poll_transmit(&mut io.tx_copy, MAX_CHUNK),
            _ => return 0,
        }
    };
    release_large_buffers(io, n);
    n
}

/// Frees the large TLS write buffers after a run of small writes. One
/// large write gives `tx_copy`, `ct_out` and the session buffer a
/// capacity of about [`MAX_CHUNK`]. Small writes do not need it, so an
/// idle session keeps little memory.
///
/// `n` is the size of the chunk that `poll_transmit` just staged. The
/// buffers are empty when `n` is 0.
pub(crate) fn release_large_buffers(io: &mut IoCore, n: usize) {
    let Transport::Tls(t) = &mut io.conn else {
        return;
    };
    // A large write grows `tx_copy` and one ciphertext buffer at least.
    // Small capacities mean that the last release freed them all.
    let cap = io.tx_copy.capacity().max(t.ct_out.capacity());
    if !io.write_bursts.release(n, cap) || cap <= READ_BUFFER_LEN {
        return;
    }
    if io.tx_copy.capacity() > READ_BUFFER_LEN {
        // The drop of the old buffer erases all of it, because it can
        // hold old copies of secret frames.
        io.tx_copy = Zeroizing::new(Vec::new());
    }
    free_ciphertext_buffers(t);
}

/// Frees `ct_out` and the buffer that the session holds, when the kernel
/// has taken every ciphertext byte.
///
/// The swap in `take_ciphertext` moves two buffers between `ct_out` and
/// the session. Either one can be the large one, so both go back. A
/// swap with a new empty buffer takes the session buffer.
fn free_ciphertext_buffers(t: &mut TlsTransport) {
    if !t.ct_out.is_empty() || t.tls.has_ciphertext() {
        return;
    }
    t.ct_out = Vec::new();
    let mut held = Vec::new();
    let _n = t.tls.take_ciphertext(&mut held);
}

/// The record of the recent writes that tells when the large write
/// buffers go back to the allocator. The TLS path and the plaintext path
/// use the same rule.
///
/// A burst is the set of chunks between two points where proto has no
/// more bytes to release. A burst is small when its largest chunk fills
/// less than half of the largest buffer. A run of [`SMALL_BURSTS`] small
/// bursts frees the buffers. The burst holds all chunks of a frame, so
/// the small tail chunk of a large frame frees nothing. The run length
/// keeps a mix of large and small requests from a free per request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WriteBursts {
    /// The largest chunk of the current burst.
    peak: usize,
    /// The count of small bursts in a row, at most [`SMALL_BURSTS`].
    small: u8,
}

/// The count of small bursts in a row that frees the large buffers.
pub(crate) const SMALL_BURSTS: u8 = 8;

impl WriteBursts {
    /// Records a staged chunk of `n` bytes. A size of 0 ends the burst.
    /// `cap` is the largest capacity of the buffers. It returns true when
    /// the caller must free the buffers.
    pub(crate) fn release(&mut self, n: usize, cap: usize) -> bool {
        if n > 0 {
            self.peak = self.peak.max(n);
            return false;
        }
        let peak = std::mem::take(&mut self.peak);
        if peak == 0 {
            // No chunk since the last end. This is not a burst.
            return false;
        }
        if peak.saturating_mul(2) >= cap {
            self.small = 0;
            return false;
        }
        self.small = self.small.saturating_add(1).min(SMALL_BURSTS);
        self.small >= SMALL_BURSTS
    }
}

/// The graceful close_notify of the final close.
///
/// Only when the close flush put every byte on the wire. It queues the
/// alert and sends it with non-blocking sends until `deadline`, with at
/// least one attempt. A failure is ignored. It never waits for the peer.
pub(crate) fn close_notify<T: Tokens>(t: &mut TlsTransport, cx: &StepCtx<'_, T>, deadline: Millis) {
    t.tls.send_close_notify();
    loop {
        match pump_out(t) {
            Ok(true) | Err(_) => return,
            Ok(false) => {}
        }
        if wait_writable(cx.clock, cx.poll, &t.sock, deadline).is_err() {
            return;
        }
    }
}
