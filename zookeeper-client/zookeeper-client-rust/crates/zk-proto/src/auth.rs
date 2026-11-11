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

//! The auth list.
//!
//! The module owns [`AuthState`]. `add_auth` appends entries and sends
//! their packets. Each AUTH reply completes the token of its own packet.
//! Finalize sends every entry again after a reconnect.
//!
//! The server answers the auth packets of one connection in receive
//! order. The send queue can put a packet before older packets, so the
//! enqueue order is not the wire order. Each auth frame therefore holds
//! the index of its entry, and `poll_transmit` records that index when it
//! copies the first byte of the frame. The AUTH replies then take the
//! recorded indexes in order. Legacy C completes every pending token on
//! one reply, so a rejected credential can report `ZOK`.

use std::collections::VecDeque;

use zk_jute::proto::RequestHeader;
use zk_jute::{JString, Record, begin_frame, finish_frame, opcode, rc, xid};

use crate::compat::{AuthInsert, AuthResend, CloseMode};
use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::log::{LogArg, LogSite};
use crate::output::{Output, Work};
use crate::recv::Flow;
use crate::request::AddAuthError;
use crate::requests::{FrameKind, OutFrame};
use crate::secret::SecretBytes;
use crate::state::{Cause, State};
use crate::time::Millis;

/// One `add_auth` entry. The list is append-only and never deduplicated.
pub(crate) struct AuthEntry<A> {
    /// The scheme.
    pub(crate) scheme: JString,
    /// The credential.
    pub(crate) cred: SecretBytes,
    /// The completion token, until a reply, a teardown or a close takes
    /// it.
    pub(crate) done: Option<A>,
}

/// The auth list of one connection.
pub(crate) struct AuthState<T: Tokens> {
    /// The entries, in call order.
    pub(crate) list: Vec<AuthEntry<T::Auth>>,
    /// The list indexes of the auth packets that the live transport sent
    /// and that wait for a reply, in wire order. A packet sent twice has
    /// two indexes.
    pub(crate) in_flight: VecDeque<usize>,
    /// The transport epoch of `in_flight`. A transport change drops every
    /// packet in flight, so an old epoch makes `in_flight` empty.
    in_flight_epoch: u64,
}

impl<T: Tokens> AuthState<T> {
    /// Makes an empty list.
    pub(crate) fn new() -> Self {
        Self {
            list: Vec::new(),
            in_flight: VecDeque::new(),
            in_flight_epoch: 0,
        }
    }

    /// Takes every pending token in list order. The entries stay, so a
    /// reconnect sends them again.
    pub(crate) fn take_tokens(&mut self) -> Vec<T::Auth> {
        self.list.iter_mut().filter_map(|e| e.done.take()).collect()
    }

    /// Returns the scheme of the first entry, for the AUTH reply log.
    pub(crate) fn first_scheme(&self) -> Option<&JString> {
        self.list.first().map(|e| &e.scheme)
    }

    /// Takes the token and the scheme of the entry that a reply answers.
    ///
    /// The token is `None` when a reply, a teardown or a close already
    /// took it. The scheme is the scheme of the entry. With no entry, it
    /// is the scheme of the first entry, or `JString::Null` for an empty
    /// list. C dereferences NULL for an empty list.
    fn take_reply(&mut self, entry: Option<usize>) -> (Option<T::Auth>, JString) {
        match entry.and_then(|i| self.list.get_mut(i)) {
            Some(e) => (e.done.take(), e.scheme.clone()),
            None => (None, self.first_scheme().cloned().unwrap_or_default()),
        }
    }
}

/// The step at which an AUTH reply stopped.
///
/// An AUTH reply has seven steps: the packet index, the lock point, the
/// state, the token, the log line, the `Auth` output and the teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthReplyStep {
    /// After the `AuthLockpoint` of step 2. Steps 3-7 remain.
    AfterLockpoint,
    /// After the `Auth{barrier: true}` output (step 6). Step 7 remains.
    AfterAuth,
}

/// The remaining steps of an AUTH reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthReplyJob {
    /// The step to continue at.
    pub(crate) step: AuthReplyStep,
    /// The `err` of the reply header.
    pub(crate) err: i32,
    /// The transport epoch of the reply. A forced close during the lock
    /// point changes the epoch, and then steps 4-7 do not run.
    pub(crate) epoch: u64,
    /// The list index of the packet that the reply answers, or `None`
    /// when no sent packet waits for a reply.
    pub(crate) entry: Option<usize>,
}

impl<T: Tokens> Connection<T> {
    /// Adds an auth entry and sends its packet when the state allows.
    ///
    /// Contract:
    /// - After `destroy` it gives `ZINVALIDSTATE`. No later stage can
    ///   complete the token.
    /// - Under the `Drain` close mode, a running close gives `ZCLOSING`, as
    ///   `submit` does.
    /// - `state < 0` gives `ZINVALIDSTATE`. With `auth_reject_closed`,
    ///   `state == 0` also gives `ZINVALIDSTATE`.
    /// - Otherwise the entry is appended with its token.
    /// - Connected, or Associating with no SASL: one `AuthPacket` frame
    ///   (xid -4, op 100) that holds the entry index. `auth_insert` selects
    ///   the priority boundary or the tail. The send records the index.
    /// - The state check runs before any change. The token stays in the
    ///   core if and only if the result is `Ok`.
    ///
    /// # Errors
    ///
    /// Returns the legacy code and gives the token back.
    pub fn add_auth(
        &mut self,
        scheme: JString,
        cred: SecretBytes,
        done: Option<T::Auth>,
        _now: Millis,
    ) -> Result<(), AddAuthError<T>> {
        let state = self.core.state;
        let closed = self.compat.auth_reject_closed && state == State::Closed;
        if self.close.destroyed || state.code() < 0 || closed {
            return Err(AddAuthError {
                code: rc::ZINVALIDSTATE,
                done,
            });
        }
        if self.compat.close_mode == CloseMode::Drain && self.close.closing {
            return Err(AddAuthError {
                code: rc::ZCLOSING,
                done,
            });
        }
        // In the associating state, C sends the packet when no SASL
        // negotiation follows. Finalize then sends it a second time.
        // `auth_dup_while_associating` selects this C behavior.
        let send = state.is_connected()
            || (state == State::Associating
                && !self.cfg.sasl
                && self.compat.auth_dup_while_associating);
        let entry = self.auth.list.len();
        let frame = send.then(|| auth_out_frame(entry, &scheme, &cred));
        self.auth.list.push(AuthEntry { scheme, cred, done });
        if let Some(frame) = frame {
            match self.compat.auth_insert {
                AuthInsert::Priority => self.requests.push_priority(frame),
                AuthInsert::Tail => self.requests.push_tail(frame),
            }
            let server = self.current_server();
            self.emit_log(LogSite::SendLastAuth, || vec![LogArg::Endpoint(server)]);
        }
        Ok(())
    }

    /// Processes an AUTH reply (xid -4).
    ///
    /// Contract: the reply first takes the oldest index
    /// of `in_flight`, the packet that it answers.
    /// - With the lock points: push `AuthLockpoint`, park
    ///   `AuthReplyJob{AfterLockpoint, err, epoch, entry}` and return
    ///   `Flow::Stop`.
    /// - Without them: push `Auth{[token of the entry], err, barrier:
    ///   false}`. A non-zero `err` then follows the same failure path as
    ///   steps 3 and 7.
    pub(crate) fn on_auth_reply(&mut self, err: i32, now: Millis) -> Flow {
        let entry = self.auth_in_flight().pop_front();
        if self.compat.emits_lockpoints() {
            self.out.push(Output::AuthLockpoint);
            self.out.park(Work::AuthReply(AuthReplyJob {
                step: AuthReplyStep::AfterLockpoint,
                err,
                epoch: self.core.epoch,
                entry,
            }));
            return Flow::Stop;
        }
        self.auth_reply_inline(err, entry, now)
    }

    /// Continues an AUTH reply after a barrier.
    ///
    /// Contract:
    /// - `AfterLockpoint`: when `job.epoch` is not the live transport
    ///   epoch, stop. Otherwise a non-zero `err` sets state -113. Take the
    ///   token of `job.entry`, log the scheme line of that entry, and push
    ///   `Auth{[token], err, barrier: state < 0}` if the token was still
    ///   pending. With a barrier, park `AfterAuth`. Without one, continue
    ///   at step 7.
    /// - Step 7: when the state is still -113, start a
    ///   `Cause::AuthFailed` teardown. A forced close during the `Auth`
    ///   barrier set state 999, so no teardown starts.
    pub(crate) fn continue_auth_reply(&mut self, job: AuthReplyJob, now: Millis) {
        // A forced close or a teardown during a barrier changes the epoch.
        // The reply then belongs to a closed transport.
        if job.epoch != self.core.epoch {
            return;
        }
        if job.step == AuthReplyStep::AfterAuth {
            self.auth_finish_reply(now);
            return;
        }
        if self.auth_apply_reply(job.err, job.entry, true) {
            self.out.park(Work::AuthReply(AuthReplyJob {
                step: AuthReplyStep::AfterAuth,
                ..job
            }));
            return;
        }
        self.auth_finish_reply(now);
    }

    /// Queues the auth packets of every entry for a new session.
    ///
    /// Contract: finalize calls it after its lock point.
    /// Under `LegacyReverseFront` each entry goes to the priority boundary
    /// in list order, so the wire order is auth_n..auth_1. Under `Forward`
    /// the entries go last to first, so the wire order is auth_1..auth_n.
    /// Each frame holds its entry index, and the send records it. With a
    /// non-empty list it logs DEBUG "Sending all auth info request to %s".
    pub(crate) fn queue_auth_resend(&mut self) {
        let mut frames: Vec<OutFrame> = self
            .auth
            .list
            .iter()
            .enumerate()
            .map(|(i, e)| auth_out_frame(i, &e.scheme, &e.cred))
            .collect();
        // Each priority insert goes before the earlier inserts. Inserts in
        // list order thus give the reverse order on the wire.
        if matches!(self.compat.auth_resend, AuthResend::Forward) {
            frames.reverse();
        }
        let count = frames.len();
        for f in frames {
            self.requests.push_priority(f);
        }
        if count > 0 {
            let server = self.current_server();
            self.emit_log(LogSite::SendAllAuth, || vec![LogArg::Endpoint(server)]);
        }
    }

    /// Records that the live transport sent the packet of `entry`. Its
    /// reply comes after the replies of the packets sent before it.
    pub(crate) fn auth_record_sent(&mut self, entry: usize) {
        self.auth_in_flight().push_back(entry);
    }

    /// Returns the `in_flight` queue of the live transport. It first drops
    /// the indexes of an older transport, because their packets are gone.
    fn auth_in_flight(&mut self) -> &mut VecDeque<usize> {
        if self.auth.in_flight_epoch != self.core.epoch {
            self.auth.in_flight.clear();
            self.auth.in_flight_epoch = self.core.epoch;
        }
        &mut self.auth.in_flight
    }

    /// Runs an AUTH reply with no lock point and no barrier. A failed
    /// reply starts the `AuthFailed` teardown in the same call.
    fn auth_reply_inline(&mut self, err: i32, entry: Option<usize>, now: Millis) -> Flow {
        self.auth_apply_reply(err, entry, false);
        if self.core.state.code() < 0 {
            return Flow::Done(self.teardown(Cause::AuthFailed, 0, now));
        }
        Flow::Continue
    }

    /// Applies an AUTH reply to its entry.
    ///
    /// A failed reply sets state -113. The result line names the scheme.
    /// The `Auth` output then gives the token of the entry. When
    /// `barriers` is true and the state is below 0, the output is a
    /// barrier. The function returns true when it pushed a barrier.
    fn auth_apply_reply(&mut self, err: i32, entry: Option<usize>, barriers: bool) -> bool {
        if err != 0 {
            self.set_state(State::AuthFailed);
        }
        let (token, scheme) = self.auth.take_reply(entry);
        self.auth_log_result(err, scheme);
        let Some(token) = token else {
            return false;
        };
        let barrier = barriers && self.core.state.code() < 0;
        self.out.push(Output::Auth {
            tokens: vec![token],
            rc: err,
            barrier,
        });
        barrier
    }

    /// Runs the last step of an AUTH reply. A failed reply leaves the
    /// state below 0, and then the `AuthFailed` teardown starts. A forced
    /// close during the barrier set state 999, so nothing happens.
    fn auth_finish_reply(&mut self, now: Millis) {
        if self.core.state.code() < 0 {
            // The read call that took the reply already returned. The
            // teardown rc therefore goes to no caller.
            let _ = self.teardown(Cause::AuthFailed, 0, now);
        }
    }

    /// Logs the result line of an AUTH reply with the scheme.
    fn auth_log_result(&mut self, err: i32, scheme: JString) {
        let site = if err != 0 {
            LogSite::AuthSchemeFailed
        } else {
            LogSite::AuthSchemeSucceeded
        };
        self.emit_log(site, move || vec![LogArg::Str(scheme)]);
    }
}

/// Builds a request frame that ends with a secret buffer field.
///
/// The frame is the length prefix, the `RequestHeader`, the `plain` bytes,
/// and then `secret` as a jute buffer. The vector has the exact capacity.
/// It thus never grows, and freed memory keeps no copy of the secret. The
/// function cuts a secret longer than `i32::MAX` bytes, as
/// `Record::encode` does.
pub(crate) fn secret_frame(xid: i32, op_type: i32, plain: &[u8], secret: &[u8]) -> Vec<u8> {
    let secret_len = i32::try_from(secret.len()).unwrap_or(i32::MAX);
    let secret = usize::try_from(secret_len)
        .ok()
        .and_then(|n| secret.get(..n))
        .unwrap_or(secret);
    let header = RequestHeader {
        xid,
        r#type: op_type,
    };
    let capacity = 4_usize
        .saturating_add(header.encoded_len())
        .saturating_add(plain.len())
        .saturating_add(4)
        .saturating_add(secret.len());
    let mut out = Vec::with_capacity(capacity);
    let start = begin_frame(&mut out);
    header.encode(&mut out);
    out.extend_from_slice(plain);
    out.extend_from_slice(&secret_len.to_be_bytes());
    out.extend_from_slice(secret);
    finish_frame(&mut out, start);
    out
}

/// Builds the `AuthPacket{0, scheme, cred}` frame (xid -4, op 100).
///
/// C writes a credential of length 0 as an empty buffer, never as -1.
fn auth_frame(scheme: &JString, cred: &SecretBytes) -> Vec<u8> {
    let mut plain = Vec::with_capacity(4_usize.saturating_add(scheme.encoded_len()));
    plain.extend_from_slice(&0_i32.to_be_bytes());
    scheme.encode(&mut plain);
    secret_frame(xid::AUTH, opcode::SET_AUTH, &plain, cred.expose())
}

/// Builds the secret send-queue frame of the auth packet of `entry`.
fn auth_out_frame(entry: usize, scheme: &JString, cred: &SecretBytes) -> OutFrame {
    OutFrame::secret(FrameKind::Auth { entry }, auth_frame(scheme, cred))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::action::ConnectStart;
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::hooks::{AllLevels, NoDefaultWatcher, Rng};
    use crate::state::Phase;
    use crate::teardown::test_support::response;
    use zk_jute::proto::AuthPacket;

    struct Tk;
    impl Tokens for Tk {
        type Completion = u32;
        type Watcher = u32;
        type Auth = u32;
    }

    struct FixedRng;
    impl Rng for FixedRng {
        fn on_resolution(&mut self) {}
        fn random(&mut self) -> i64 {
            0
        }
        fn drand48(&mut self) -> f64 {
            0.0
        }
    }

    const ALL_STATES: [State; 9] = [
        State::Closed,
        State::Connecting,
        State::Associating,
        State::Connected,
        State::ReadOnly,
        State::SslConnecting,
        State::NotConnected,
        State::ExpiredSession,
        State::AuthFailed,
    ];

    fn conn(compat: Compat, sasl: bool) -> Connection<Tk> {
        let mut cfg = Config::legacy(30_000);
        cfg.sasl = sasl;
        Connection::new(
            cfg,
            compat,
            DriverMode::ST,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(NoDefaultWatcher),
            Millis(0),
        )
    }

    fn drain(c: &mut Connection<Tk>) -> Vec<Output<Tk>> {
        let mut v = Vec::new();
        while let Some(o) = c.poll_output() {
            v.push(o);
        }
        v
    }

    fn sites(outs: &[Output<Tk>]) -> Vec<LogSite> {
        outs.iter()
            .filter_map(|o| match o {
                Output::Log(r) => Some(r.site),
                _ => None,
            })
            .collect()
    }

    /// Decodes an auth frame into its xid, op and scheme. It also checks
    /// the length prefix and the credential bytes.
    fn decode_auth(bytes: &[u8], cred: &[u8]) -> (i32, i32, JString) {
        let mut r = zk_jute::Reader::new(bytes);
        let len = r.read_i32().unwrap();
        assert_eq!(usize::try_from(len).unwrap(), bytes.len() - 4);
        let hdr = RequestHeader::decode(&mut r).unwrap();
        let pkt = AuthPacket::decode(&mut r).unwrap();
        assert_eq!(pkt.r#type, 0);
        assert_eq!(pkt.auth.as_bytes(), Some(cred));
        assert_eq!(r.remaining(), 0);
        (hdr.xid, hdr.r#type, pkt.scheme)
    }

    /// Returns the schemes of the auth frames in `tx` order. Other frames
    /// give `None`.
    fn tx_schemes(c: &Connection<Tk>) -> Vec<Option<Vec<u8>>> {
        c.requests
            .tx
            .iter()
            .map(|f| match f.kind {
                FrameKind::Auth { .. } => {
                    assert!(matches!(f.bytes, crate::requests::FrameBytes::Secret(_)));
                    let (x, op, scheme) = decode_auth(f.bytes.as_slice(), b"pw");
                    assert_eq!((x, op), (xid::AUTH, opcode::SET_AUTH));
                    scheme.into_bytes()
                }
                _ => None,
            })
            .collect()
    }

    fn add(c: &mut Connection<Tk>, scheme: &str, tok: u32) -> Result<(), AddAuthError<Tk>> {
        c.add_auth(
            JString::from(scheme),
            SecretBytes::from_slice(b"pw"),
            Some(tok),
            Millis(0),
        )
    }

    fn plain_request(c: &mut Connection<Tk>) {
        c.requests
            .push_tail(OutFrame::plain(FrameKind::Request { xid: 7 }, vec![0; 8]));
    }

    // The helpers below drive the core as a driver does. The tests then
    // see the wire order that the server sees.

    /// One output of interest for the reply tests.
    #[derive(Debug, PartialEq, Eq)]
    enum Ev {
        /// An auth result line with its scheme.
        Scheme(LogSite, JString),
        /// An auth completion: tokens, rc, barrier.
        Auth(Vec<u32>, i32, bool),
        /// `AuthLockpoint`.
        Lockpoint,
        /// A session event with its state.
        Session(i32),
    }

    /// Pops every output and resumes at each stop. It keeps the outputs
    /// of interest.
    fn run(c: &mut Connection<Tk>) -> Vec<Ev> {
        let mut evs = Vec::new();
        loop {
            if let Some(o) = c.poll_output() {
                match o {
                    Output::Log(r)
                        if matches!(
                            r.site,
                            LogSite::AuthSchemeSucceeded | LogSite::AuthSchemeFailed
                        ) =>
                    {
                        let scheme = match r.args.as_slice() {
                            [LogArg::Str(s)] => s.clone(),
                            a => panic!("unexpected args {a:?}"),
                        };
                        evs.push(Ev::Scheme(r.site, scheme));
                    }
                    Output::Auth {
                        tokens,
                        rc,
                        barrier,
                    } => evs.push(Ev::Auth(tokens, rc, barrier)),
                    Output::AuthLockpoint => evs.push(Ev::Lockpoint),
                    Output::Session { state, .. } => evs.push(Ev::Session(state.code())),
                    _ => {}
                }
                continue;
            }
            match c.take_stopped() {
                Some(s) => c.resume(s, Millis(0)),
                None => break,
            }
        }
        evs
    }

    fn ok(scheme: &str) -> Ev {
        Ev::Scheme(LogSite::AuthSchemeSucceeded, JString::from(scheme))
    }

    /// Sends up to `max` bytes and acknowledges them. It returns the
    /// copied bytes.
    fn send_some(c: &mut Connection<Tk>, max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let n = c.poll_transmit(&mut out, max);
        c.handle_transmitted(n, Millis(0));
        out
    }

    /// Splits sent bytes into frames. An auth frame gives its scheme, and
    /// any other frame gives `None`.
    fn wire(bytes: &[u8]) -> Vec<Option<Vec<u8>>> {
        let mut frames = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let len = i32::from_be_bytes(rest[..4].try_into().unwrap());
            let (frame, tail) = rest.split_at(4 + usize::try_from(len).unwrap());
            let auth = frame[4..8] == xid::AUTH.to_be_bytes();
            frames.push(auth.then(|| decode_auth(frame, b"pw").2.into_bytes().unwrap()));
            rest = tail;
        }
        frames
    }

    /// Sends every sendable byte and returns the frames on the wire.
    fn send(c: &mut Connection<Tk>) -> Vec<Option<Vec<u8>>> {
        wire(&send_some(c, usize::MAX))
    }

    fn schemes(names: &[&str]) -> Vec<Option<Vec<u8>>> {
        names.iter().map(|n| Some(n.as_bytes().to_vec())).collect()
    }

    /// Opens a transport and sends the `Connect` frame.
    fn connect(c: &mut Connection<Tk>) {
        c.handle_connect_started(ConnectStart::InProgress, Millis(0));
        c.handle_tcp_connected(Millis(0));
        c.handle_transport_ready(Millis(0));
        assert_eq!(send(c), vec![None]);
    }

    /// Reads the `ConnectResponse` of session 0x55. Under SASL the core
    /// then waits in the Sasl phase. Otherwise finalize runs.
    fn respond(c: &mut Connection<Tk>, read_only: bool) -> Vec<Ev> {
        let body = response(30_000, 0x55, read_only);
        let mut frame = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        assert_eq!(c.handle_read(&frame, Millis(0)).frames, 1);
        run(c)
    }

    /// Connects and finishes finalize.
    fn establish(c: &mut Connection<Tk>, read_only: bool) -> Vec<Ev> {
        connect(c);
        respond(c, read_only)
    }

    /// Reads one AUTH reply with `err` and runs it to the end.
    fn reply(c: &mut Connection<Tk>, err: i32) -> Vec<Ev> {
        let mut frame = 16_i32.to_be_bytes().to_vec();
        frame.extend_from_slice(&xid::AUTH.to_be_bytes());
        frame.extend_from_slice(&0_i64.to_be_bytes());
        frame.extend_from_slice(&err.to_be_bytes());
        assert_eq!(c.handle_read(&frame, Millis(0)).frames, 1);
        run(c)
    }

    #[test]
    fn take_tokens_keeps_entries() {
        let mut a: AuthState<Tk> = AuthState::new();
        for (i, tok) in [Some(1_u32), None, Some(3)].into_iter().enumerate() {
            a.list.push(AuthEntry {
                scheme: JString::Bytes(vec![b'a'; i]),
                cred: SecretBytes::empty(),
                done: tok,
            });
        }
        assert_eq!(a.take_tokens(), vec![1, 3]);
        assert_eq!(a.list.len(), 3);
        assert!(a.take_tokens().is_empty());
    }

    #[test]
    fn add_auth_each_state_legacy() {
        for sasl in [false, true] {
            for state in ALL_STATES {
                let mut c = conn(Compat::LEGACY_C, sasl);
                c.set_state(state);
                plain_request(&mut c);
                let r = add(&mut c, "digest", 5);
                let rejected = state.code() <= 0;
                if rejected {
                    let e = r.unwrap_err();
                    assert_eq!(e.code, rc::ZINVALIDSTATE, "{state:?}");
                    assert_eq!(e.done, Some(5));
                    assert!(c.auth.list.is_empty());
                    assert_eq!(c.requests.tx.len(), 1);
                    assert!(sites(&drain(&mut c)).is_empty());
                    continue;
                }
                assert!(r.is_ok(), "{state:?}");
                assert_eq!(c.auth.list.len(), 1);
                assert_eq!(c.auth.list[0].done, Some(5));
                // The send records the packet, not the enqueue.
                assert!(c.auth.in_flight.is_empty());
                let sends = state.is_connected() || (state == State::Associating && !sasl);
                let logs = sites(&drain(&mut c));
                if sends {
                    // The priority boundary puts the packet before the
                    // queued request.
                    assert_eq!(tx_schemes(&c), vec![Some(b"digest".to_vec()), None]);
                    assert_eq!(logs, vec![LogSite::SendLastAuth], "{state:?}");
                } else {
                    assert_eq!(c.requests.tx.len(), 1, "{state:?} sasl={sasl}");
                    assert!(logs.is_empty());
                }
            }
        }
    }

    #[test]
    fn add_auth_each_state_native() {
        for sasl in [false, true] {
            for state in ALL_STATES {
                let mut c = conn(Compat::NATIVE, sasl);
                c.set_state(state);
                plain_request(&mut c);
                let r = add(&mut c, "digest", 5);
                if state.code() < 0 {
                    let e = r.unwrap_err();
                    assert_eq!((e.code, e.done), (rc::ZINVALIDSTATE, Some(5)));
                    assert!(c.auth.list.is_empty());
                    continue;
                }
                // NATIVE records the entry in state 0.
                assert!(r.is_ok(), "{state:?}");
                assert_eq!(c.auth.list.len(), 1);
                assert!(c.auth.in_flight.is_empty());
                // NATIVE sends no packet while associating: finalize sends it.
                if state.is_connected() {
                    assert_eq!(tx_schemes(&c), vec![None, Some(b"digest".to_vec())]);
                } else {
                    assert_eq!(c.requests.tx.len(), 1, "{state:?}");
                }
            }
        }
    }

    #[test]
    fn add_auth_associating_with_dup_under_native() {
        let mut compat = Compat::NATIVE;
        compat.auth_dup_while_associating = true;
        let mut c = conn(compat, false);
        c.set_state(State::Associating);
        add(&mut c, "a", 1).unwrap();
        assert_eq!(tx_schemes(&c), vec![Some(b"a".to_vec())]);
        assert!(c.auth.in_flight.is_empty());
    }

    #[test]
    fn auth_frame_writes_empty_credential_as_length_zero() {
        let bytes = auth_frame(&JString::from("x"), &SecretBytes::empty());
        assert_eq!(bytes.capacity(), bytes.len());
        let (x, op, scheme) = decode_auth(&bytes, b"");
        assert_eq!((x, op, scheme), (-4, 100, JString::from("x")));
        let null = auth_frame(&JString::Null, &SecretBytes::from_slice(b"pw"));
        assert_eq!(decode_auth(&null, b"pw").2, JString::Null);
    }

    fn three_entries(c: &mut Connection<Tk>) {
        for (s, t) in [("a", 1), ("b", 2), ("c", 3)] {
            c.auth.list.push(AuthEntry {
                scheme: JString::from(s),
                cred: SecretBytes::from_slice(b"pw"),
                done: Some(t),
            });
        }
    }

    #[test]
    fn resend_order_legacy_reverse_front() {
        let mut c = conn(Compat::LEGACY_C, false);
        three_entries(&mut c);
        plain_request(&mut c);
        c.queue_auth_resend();
        let want: Vec<Option<Vec<u8>>> = vec![
            Some(b"c".to_vec()),
            Some(b"b".to_vec()),
            Some(b"a".to_vec()),
            None,
        ];
        assert_eq!(tx_schemes(&c), want);
        assert!(c.auth.in_flight.is_empty());
        assert_eq!(sites(&drain(&mut c)), vec![LogSite::SendAllAuth]);
    }

    #[test]
    fn resend_order_forward() {
        let mut c = conn(Compat::NATIVE, false);
        three_entries(&mut c);
        plain_request(&mut c);
        c.queue_auth_resend();
        let want: Vec<Option<Vec<u8>>> = vec![
            Some(b"a".to_vec()),
            Some(b"b".to_vec()),
            Some(b"c".to_vec()),
            None,
        ];
        assert_eq!(tx_schemes(&c), want);
        assert!(c.auth.in_flight.is_empty());
        assert_eq!(sites(&drain(&mut c)), vec![LogSite::SendAllAuth]);
    }

    #[test]
    fn resend_frames_hold_their_entry_index() {
        let mut c = conn(Compat::LEGACY_C, false);
        three_entries(&mut c);
        c.queue_auth_resend();
        let entries: Vec<FrameKind> = c.requests.tx.iter().map(|f| f.kind).collect();
        assert_eq!(
            entries,
            vec![
                FrameKind::Auth { entry: 2 },
                FrameKind::Auth { entry: 1 },
                FrameKind::Auth { entry: 0 },
            ]
        );
    }

    #[test]
    fn record_drops_the_indexes_of_an_old_transport() {
        let mut c = conn(Compat::LEGACY_C, false);
        let _ = c.open_transport();
        c.auth_record_sent(1);
        c.auth_record_sent(0);
        assert_eq!(c.auth.in_flight, VecDeque::from(vec![1, 0]));
        c.lose_transport();
        let _ = c.open_transport();
        c.auth_record_sent(2);
        assert_eq!(c.auth.in_flight, VecDeque::from(vec![2]));
    }

    #[test]
    fn resend_empty_list_logs_nothing() {
        let mut c = conn(Compat::LEGACY_C, false);
        c.queue_auth_resend();
        assert!(c.requests.tx.is_empty());
        assert!(drain(&mut c).is_empty());
    }

    /// Rule: a successful reply completes only the token of its own packet.
    #[test]
    fn legacy_reply_success_completes_its_own_token() {
        let mut c = conn(Compat::LEGACY_C, false);
        c.set_state(State::Connected);
        three_entries(&mut c);
        c.auth_record_sent(1);
        assert_eq!(c.on_auth_reply(0, Millis(5)), Flow::Stop);
        let outs = drain(&mut c);
        assert!(matches!(outs.as_slice(), [Output::AuthLockpoint]));
        let stopped = c.take_stopped().unwrap();
        c.resume(stopped, Millis(5));
        let outs = drain(&mut c);
        assert_eq!(outs.len(), 2);
        match &outs[0] {
            Output::Log(r) => {
                assert_eq!(r.site, LogSite::AuthSchemeSucceeded);
                assert_eq!(r.args, vec![LogArg::Str(JString::from("b"))]);
            }
            o => panic!("unexpected {o:?}"),
        }
        match &outs[1] {
            Output::Auth {
                tokens,
                rc,
                barrier,
            } => {
                assert_eq!(tokens, &vec![2]);
                assert_eq!((*rc, *barrier), (0, false));
            }
            o => panic!("unexpected {o:?}"),
        }
        assert_eq!(c.state(), State::Connected);
        assert!(c.take_stopped().is_none());
        assert!(!c.is_suspended());
        assert_eq!(c.auth.list[0].done, Some(1));
        assert_eq!(c.auth.list[2].done, Some(3));
    }

    #[test]
    fn legacy_reply_failure_sets_auth_failed_before_the_teardown() {
        let mut c = conn(Compat::LEGACY_C, false);
        c.set_state(State::Connected);
        three_entries(&mut c);
        c.auth_record_sent(0);
        assert_eq!(c.on_auth_reply(rc::ZAUTHFAILED, Millis(5)), Flow::Stop);
        assert!(matches!(drain(&mut c).as_slice(), [Output::AuthLockpoint]));
        // The state changes after the lock point, not before.
        assert_eq!(c.state(), State::Connected);
        let stopped = c.take_stopped().unwrap();
        c.resume(stopped, Millis(5));
        assert_eq!(c.state(), State::AuthFailed);
        let outs = drain(&mut c);
        assert_eq!(sites(&outs), vec![LogSite::AuthSchemeFailed]);
        assert!(matches!(
            outs.last(),
            Some(Output::Auth { tokens, rc: -115, barrier: true }) if tokens == &vec![1]
        ));
        // The `Auth` barrier parks step 6, the `AuthFailed` teardown.
        let stopped = c.take_stopped().unwrap();
        assert!(c.is_suspended());
        // A forced close during the barrier sets state 999 and a new
        // epoch, so step 6 starts no teardown.
        c.set_state(State::NotConnected);
        c.lose_transport();
        c.resume(stopped, Millis(6));
        assert!(drain(&mut c).is_empty());
        assert!(!c.is_suspended());
        assert_eq!(c.state(), State::NotConnected);
    }

    #[test]
    fn legacy_reply_after_forced_close_is_dropped() {
        let mut c = conn(Compat::LEGACY_C, false);
        c.set_state(State::Connected);
        three_entries(&mut c);
        c.auth_record_sent(0);
        assert_eq!(c.on_auth_reply(rc::ZAUTHFAILED, Millis(5)), Flow::Stop);
        drain(&mut c);
        let stopped = c.take_stopped().unwrap();
        c.set_state(State::NotConnected);
        c.lose_transport();
        c.resume(stopped, Millis(5));
        assert_eq!(c.state(), State::NotConnected);
        assert!(drain(&mut c).is_empty());
        assert_eq!(c.auth.list.iter().filter(|e| e.done.is_some()).count(), 3);
    }

    /// Rule: a reply with an empty list logs the scheme as `(null)`.
    #[test]
    fn legacy_reply_with_empty_list_logs_null_scheme() {
        let mut c = conn(Compat::LEGACY_C, false);
        c.set_state(State::Connected);
        assert_eq!(c.on_auth_reply(0, Millis(0)), Flow::Stop);
        drain(&mut c);
        let stopped = c.take_stopped().unwrap();
        c.resume(stopped, Millis(0));
        let outs = drain(&mut c);
        assert_eq!(outs.len(), 1);
        match &outs[0] {
            Output::Log(r) => {
                assert_eq!(r.site, LogSite::AuthSchemeSucceeded);
                assert_eq!(r.args, vec![LogArg::Str(JString::Null)]);
            }
            o => panic!("unexpected {o:?}"),
        }
    }

    #[test]
    fn native_reply_completes_oldest_entry() {
        let mut c = conn(Compat::NATIVE, false);
        c.set_state(State::Connected);
        add(&mut c, "a", 1).unwrap();
        add(&mut c, "b", 2).unwrap();
        drain(&mut c);
        c.auth_record_sent(0);
        c.auth_record_sent(1);
        assert_eq!(c.on_auth_reply(0, Millis(0)), Flow::Continue);
        let outs = drain(&mut c);
        assert_eq!(outs.len(), 2);
        assert!(matches!(&outs[0], Output::Log(r)
            if r.site == LogSite::AuthSchemeSucceeded
                && r.args == vec![LogArg::Str(JString::from("a"))]));
        assert!(matches!(&outs[1],
            Output::Auth { tokens, rc: 0, barrier: false } if tokens == &vec![1]));
        assert_eq!(c.auth.list[1].done, Some(2));
        assert_eq!(c.on_auth_reply(0, Millis(0)), Flow::Continue);
        let outs = drain(&mut c);
        assert!(matches!(outs.last(),
            Some(Output::Auth { tokens, .. }) if tokens == &vec![2]));
        // A reply with nothing in flight completes nothing.
        assert_eq!(c.on_auth_reply(0, Millis(0)), Flow::Continue);
        assert_eq!(sites(&drain(&mut c)), vec![LogSite::AuthSchemeSucceeded]);
        assert!(c.auth.in_flight.is_empty());
        assert!(!c.is_suspended());
    }

    #[test]
    fn priority_inserts_reply_in_wire_order() {
        let mut c = conn(Compat::LEGACY_C, false);
        let _ = establish(&mut c, false);
        add(&mut c, "a", 1).unwrap();
        add(&mut c, "b", 2).unwrap();
        // The second priority insert goes before the first one.
        assert_eq!(send(&mut c), schemes(&["b", "a"]));
        assert_eq!(c.auth.in_flight, VecDeque::from(vec![1, 0]));
        let first = reply(&mut c, 0);
        assert_eq!(
            first,
            vec![Ev::Lockpoint, ok("b"), Ev::Auth(vec![2], 0, false)]
        );
        let second = reply(&mut c, 0);
        assert_eq!(
            second,
            vec![Ev::Lockpoint, ok("a"), Ev::Auth(vec![1], 0, false)]
        );
        // A reply with nothing in flight logs the first scheme only.
        assert_eq!(reply(&mut c, 0), vec![Ev::Lockpoint, ok("a")]);
    }

    /// Rule: a priority insert never splits a partly sent packet.
    #[test]
    fn a_partly_sent_packet_keeps_its_place() {
        let mut c = conn(Compat::LEGACY_C, false);
        let _ = establish(&mut c, false);
        add(&mut c, "a", 1).unwrap();
        // The first byte fixes the position of the packet on the wire.
        let head = send_some(&mut c, 3);
        assert_eq!(head.len(), 3);
        assert_eq!(c.auth.in_flight, VecDeque::from(vec![0]));
        add(&mut c, "b", 2).unwrap();
        let mut bytes = head;
        bytes.extend(send_some(&mut c, usize::MAX));
        assert_eq!(wire(&bytes), schemes(&["a", "b"]));
        assert_eq!(c.auth.in_flight, VecDeque::from(vec![0, 1]));
        assert_eq!(reply(&mut c, 0)[2], Ev::Auth(vec![1], 0, false));
        assert_eq!(reply(&mut c, 0)[2], Ev::Auth(vec![2], 0, false));
    }

    /// Rule: a packet that goes out twice completes its token once.
    #[test]
    fn a_duplicate_packet_completes_its_token_once() {
        let mut c = conn(Compat::LEGACY_C, false);
        connect(&mut c);
        // C sends the packet while associating, and finalize sends it
        // again before it.
        add(&mut c, "a", 1).unwrap();
        let _ = respond(&mut c, false);
        assert_eq!(send(&mut c), schemes(&["a", "a"]));
        assert_eq!(c.auth.in_flight, VecDeque::from(vec![0, 0]));
        assert_eq!(
            reply(&mut c, 0),
            vec![Ev::Lockpoint, ok("a"), Ev::Auth(vec![1], 0, false)]
        );
        // The reply to the duplicate only logs.
        assert_eq!(reply(&mut c, 0), vec![Ev::Lockpoint, ok("a")]);
    }

    #[test]
    fn a_new_transport_drops_the_old_indexes_and_never_reports_twice() {
        let mut c = conn(Compat::LEGACY_C, false);
        let _ = establish(&mut c, false);
        add(&mut c, "a", 1).unwrap();
        add(&mut c, "b", 2).unwrap();
        assert_eq!(send(&mut c), schemes(&["b", "a"]));
        assert_eq!(reply(&mut c, 0)[2], Ev::Auth(vec![2], 0, false));
        // The reply for "a" never comes. The teardown completes its token.
        let _ = c.teardown(Cause::Eof, 0, Millis(0));
        let evs = run(&mut c);
        assert!(evs.contains(&Ev::Auth(vec![1], rc::ZCONNECTIONLOSS, true)));
        // The new transport sends both entries again, and their replies
        // complete nothing.
        let _ = establish(&mut c, false);
        assert_eq!(send(&mut c), schemes(&["b", "a"]));
        assert_eq!(c.auth.in_flight, VecDeque::from(vec![1, 0]));
        assert_eq!(reply(&mut c, 0), vec![Ev::Lockpoint, ok("b")]);
        assert_eq!(reply(&mut c, 0), vec![Ev::Lockpoint, ok("a")]);
    }

    #[test]
    fn forced_close_then_an_add_completes_on_its_resend() {
        let mut c = conn(Compat::LEGACY_C, false);
        let _ = establish(&mut c, false);
        add(&mut c, "a", 1).unwrap();
        assert_eq!(send(&mut c), schemes(&["a"]));
        c.handle_forced_close(Millis(0));
        assert_eq!(c.state(), State::NotConnected);
        // The add after the trigger only records its entry.
        add(&mut c, "b", 2).unwrap();
        assert!(c.requests.tx.is_empty());
        assert!(c.run_pending_teardown(Millis(0)));
        let evs = run(&mut c);
        assert!(evs.contains(&Ev::Auth(vec![1], rc::ZCONNECTIONLOSS, true)));
        assert_eq!(c.auth.list[1].done, Some(2));
        let _ = establish(&mut c, false);
        assert_eq!(send(&mut c), schemes(&["b", "a"]));
        assert_eq!(
            reply(&mut c, 0),
            vec![Ev::Lockpoint, ok("b"), Ev::Auth(vec![2], 0, false)]
        );
        assert_eq!(reply(&mut c, 0), vec![Ev::Lockpoint, ok("a")]);
    }

    #[test]
    fn rw_switch_completes_the_pending_token_once() {
        let mut c = conn(Compat::LEGACY_C, false);
        let _ = establish(&mut c, true);
        assert_eq!(c.state(), State::ReadOnly);
        add(&mut c, "a", 1).unwrap();
        assert_eq!(send(&mut c), schemes(&["a"]));
        let _ = c.teardown(Cause::RwServerFound, 0, Millis(0));
        let evs = run(&mut c);
        let auths: Vec<&Ev> = evs.iter().filter(|e| matches!(e, Ev::Auth(..))).collect();
        assert_eq!(auths, vec![&Ev::Auth(vec![1], rc::ZCONNECTIONLOSS, true)]);
        let _ = establish(&mut c, false);
        assert_eq!(c.state(), State::Connected);
        assert_eq!(send(&mut c), schemes(&["a"]));
        assert_eq!(reply(&mut c, 0), vec![Ev::Lockpoint, ok("a")]);
    }

    #[test]
    fn sasl_holds_auth_packets_until_finalize() {
        let mut c = conn(Compat::LEGACY_C, true);
        connect(&mut c);
        // Under SASL an add while associating only records its entry.
        add(&mut c, "a", 1).unwrap();
        let _ = respond(&mut c, false);
        assert!(matches!(c.core.phase, Phase::Sasl(_)));
        add(&mut c, "b", 2).unwrap();
        assert!(c.requests.tx.is_empty());
        // The Sasl phase holds auth frames, and a held frame records
        // nothing.
        c.queue_auth_resend();
        assert!(send(&mut c).is_empty());
        assert!(c.auth.in_flight.is_empty());
        c.requests
            .tx
            .retain(|f| !matches!(f.kind, FrameKind::Auth { .. }));
        // The end of the negotiation runs finalize, which sends the list.
        let _ = c.start_finalize(Millis(0));
        let _ = run(&mut c);
        assert_eq!(send(&mut c), schemes(&["b", "a"]));
        assert_eq!(reply(&mut c, 0)[2], Ev::Auth(vec![2], 0, false));
        assert_eq!(reply(&mut c, 0)[2], Ev::Auth(vec![1], 0, false));
    }
}
