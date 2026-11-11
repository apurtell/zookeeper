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

//! The SASL sequencing.
//!
//! The module owns [`SaslState`]. The core does not run the mechanism. It
//! asks for mechanism work with `Action::Sasl`, sends the tokens, and
//! takes the results back.

use std::collections::VecDeque;

use zk_jute::proto::ReplyHeader;
use zk_jute::{DecodeError, JString, Reader, Record, opcode, rc};

use crate::action::{Action, SaslAddr, SaslCall, SaslCallKind, SaslError, SaslStep};
use crate::auth::secret_frame;
use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::log::{LogArg, LogSite};
use crate::recv::Flow;
use crate::requests::{FrameKind, OutFrame};
use crate::secret::SecretBytes;
use crate::state::{Cause, Phase, SaslNegotiation, State};
use crate::time::Millis;

/// The kind of a mechanism call that waits for its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitKind {
    /// A `Start` call.
    Start,
    /// A `Step` call.
    Step,
}

/// The mechanism call that waits for its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Waiting {
    /// The kind of the call.
    kind: WaitKind,
    /// The generation of the call.
    generation: u32,
}

/// The SASL state of one connection.
pub(crate) struct SaslState {
    /// The live generation. It is never 0 and wraps from `u32::MAX` to 1.
    pub(crate) generation: u32,
    /// The generation of the last `Start` that the mechanism got, while
    /// its session exists. `Dispose` ends that session and clears it.
    pub(crate) mech_gen: Option<u32>,
    /// True while a `Start` or `Step` result is outstanding.
    pub(crate) outstanding: bool,
    /// The calls to yield, in order.
    pub(crate) calls: VecDeque<SaslCall>,
    /// The mechanism name of the last `Start` result.
    pub(crate) mechanism: Option<String>,
    /// The call that `outstanding` waits for.
    waiting: Option<Waiting>,
    /// The length of the server reply that queued the outstanding `Step`.
    /// C logs "SASL: Processed response" after the step, so the line waits
    /// for the `Step` result.
    processed_len: Option<i64>,
}

impl SaslState {
    /// Makes a state with no session. The first `Start` takes generation 1.
    pub(crate) fn new() -> Self {
        Self {
            generation: 0,
            mech_gen: None,
            outstanding: false,
            calls: VecDeque::new(),
            mechanism: None,
            waiting: None,
            processed_len: None,
        }
    }

    /// Advances `generation`, wrapping from `u32::MAX` to 1, and returns the new
    /// value.
    pub(crate) fn advance_gen(&mut self) -> u32 {
        self.generation = self.generation.checked_add(1).unwrap_or(1);
        self.generation
    }

    /// Returns true when a result with this generation is live.
    pub(crate) fn is_live(&self, generation: u32) -> bool {
        generation != 0 && generation == self.generation
    }

    /// Ends the wait for the outstanding call and returns that call.
    fn end_wait(&mut self) -> Option<Waiting> {
        self.outstanding = false;
        self.waiting.take()
    }

    /// Ends the wait when a result has the generation of the outstanding
    /// call, also when that generation is stale. A result with another
    /// generation belongs to no outstanding call, so the wait stays.
    fn end_wait_for(&mut self, generation: u32) -> Option<Waiting> {
        if self.waiting.is_some_and(|w| w.generation == generation) {
            self.end_wait()
        } else {
            None
        }
    }

    /// Ends the negotiation. It advances the generation, so a late result
    /// becomes stale. It removes the queued `Start` and `Step` calls. It
    /// keeps a queued `Dispose`, because the mechanism session still
    /// exists.
    fn end_negotiation(&mut self) {
        self.advance_gen();
        self.calls
            .retain(|c| matches!(c.kind, SaslCallKind::Dispose));
        self.processed_len = None;
    }
}

/// Decodes the token of a `SetSASLResponse` and reads no byte past it.
///
/// The length -1 gives `None`. A length below -1 is an error, as in C.
fn read_token<'a>(r: &mut Reader<'a>) -> Result<Option<&'a [u8]>, DecodeError> {
    let len = r.read_i32()?;
    if len == -1 {
        return Ok(None);
    }
    let n = usize::try_from(len).map_err(|_| DecodeError::NegativeBuffer(len))?;
    r.read_bytes(n).map(Some)
}

/// Returns the length of a byte count as a log value.
fn log_len(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl<T: Tokens> Connection<T> {
    /// Takes the result of a `Start` call.
    ///
    /// Contract: any result ends the outstanding wait. A
    /// stale `generation` is then ignored and returns `ZOK`. A live `Err` is a
    /// SASL failure with rc `ZSYSTEMERROR` (`sasl_fail`). A live `Ok`
    /// records the mechanism, sets `is_gssapi`, applies the DIGEST-MD5
    /// refusal, and queues a priority Sasl frame when `!done` or the token
    /// is not empty. It returns the rc of the call.
    pub fn handle_sasl_started(
        &mut self,
        generation: u32,
        r: Result<(String, SaslStep), SaslError>,
        now: Millis,
    ) -> i32 {
        let waiting = self.sasl.end_wait_for(generation);
        if !self.sasl_result_live(waiting, WaitKind::Start, generation) {
            return rc::ZOK;
        }
        match r {
            Err(e) => {
                self.sasl_log_mech_error(LogSite::SaslStartError, e);
                self.sasl_fail(rc::ZSYSTEMERROR, now)
            }
            Ok((mechanism, step)) => {
                let mut token = step.token;
                // C empties the initial response of DIGEST-MD5, so the
                // server starts a fresh authentication (JDK-6682540).
                if mechanism == "DIGEST-MD5" && token.as_ref().is_some_and(|t| !t.is_empty()) {
                    let name = JString::from(mechanism.as_str());
                    self.emit_log(LogSite::SaslRefuseReauth, || vec![LogArg::Str(name)]);
                    token = None;
                }
                let is_gssapi = mechanism == "GSSAPI";
                if let Some(n) = self.sasl_negotiation() {
                    n.is_gssapi = is_gssapi;
                }
                self.sasl.mechanism = Some(mechanism);
                if !step.done || token.as_ref().is_some_and(|t| !t.is_empty()) {
                    self.sasl_send(token.as_ref());
                }
                rc::ZOK
            }
        }
    }

    /// Takes the result of a `Step` call.
    ///
    /// Contract: a stale `generation` is ignored. A live `Err` is
    /// a SASL failure with `ZSYSTEMERROR`. A done step sets
    /// `awaiting_final` (non-GSSAPI with a token) or `gssapi_last_packet`
    /// (GSSAPI). A step with a token, or not done, queues a Sasl frame. A
    /// done step with no frame to send completes and calls
    /// `start_finalize`. It returns the rc of the call.
    pub fn handle_sasl_stepped(
        &mut self,
        generation: u32,
        r: Result<SaslStep, SaslError>,
        now: Millis,
    ) -> i32 {
        let waiting = self.sasl.end_wait_for(generation);
        if !self.sasl_result_live(waiting, WaitKind::Step, generation) {
            return rc::ZOK;
        }
        let step = match r {
            Err(e) => {
                self.sasl_log_mech_error(LogSite::SaslStepError, e);
                return self.sasl_fail(rc::ZSYSTEMERROR, now);
            }
            Ok(step) => step,
        };
        let has_token = step.token.as_ref().is_some_and(|t| !t.is_empty());
        if !step.done || has_token {
            self.sasl_send(step.token.as_ref());
        }
        let mut complete = false;
        if step.done {
            if let Some(n) = self.sasl_negotiation() {
                if n.is_gssapi {
                    // GSSAPI: the server sends one more packet.
                    n.gssapi_last_packet = true;
                } else if has_token {
                    // The server must accept the last token first. Its reply
                    // must not reach the FIFO match.
                    n.awaiting_final = true;
                } else {
                    complete = true;
                }
            }
        }
        self.sasl_log_processed(rc::ZOK);
        if !complete {
            return rc::ZOK;
        }
        match self.start_finalize(now) {
            Flow::Done(rc) => rc,
            Flow::Continue | Flow::Stop => rc::ZOK,
        }
    }

    /// Takes a failed socket-address read before `Start`.
    ///
    /// Contract: it logs the getsockname or
    /// getpeername ERROR, clears `mech_gen`, drops the queued `Start`, and
    /// runs `sasl_fail(ZSYSTEMERROR)`. It returns `ZSYSTEMERROR`. A stale
    /// `generation` returns `ZOK` and changes nothing.
    pub fn handle_sasl_addr_failed(
        &mut self,
        generation: u32,
        which: SaslAddr,
        now: Millis,
    ) -> i32 {
        // The failure is the result of the `Start` call, so it ends the
        // wait also when the generation is stale.
        let start_waits = self
            .sasl
            .end_wait_for(generation)
            .is_some_and(|w| w.kind == WaitKind::Start);
        let start_queued = self
            .sasl
            .calls
            .iter()
            .any(|c| c.generation == generation && matches!(c.kind, SaslCallKind::Start));
        let live = self.sasl.is_live(generation)
            && matches!(self.core.phase, Phase::Sasl(_))
            && (start_waits || start_queued);
        if !live {
            return rc::ZOK;
        }
        let site = match which {
            SaslAddr::Local => LogSite::SaslGetsockname,
            SaslAddr::Peer => LogSite::SaslGetpeername,
        };
        self.emit_log(site, Vec::new);
        // The mechanism made no session, so no `Dispose` follows.
        self.sasl.mech_gen = None;
        self.sasl
            .calls
            .retain(|c| !(c.generation == generation && matches!(c.kind, SaslCallKind::Start)));
        self.sasl_fail(rc::ZSYSTEMERROR, now)
    }

    /// Marks the SASL negotiation failed, as `zoo_sasl_mark_failed`.
    ///
    /// Contract: state -113 and the negotiation ends. No log, no
    /// rc and no teardown.
    pub fn mark_sasl_failed(&mut self) {
        self.set_state(State::AuthFailed);
        self.sasl.end_negotiation();
    }

    /// Starts a negotiation after the prime response.
    ///
    /// Contract: the phase becomes `Sasl` with a fresh
    /// `SaslNegotiation`. When `mech_gen` is set, a `Dispose{mech_gen}`
    /// call is queued first and `mech_gen` is cleared. Then `generation`
    /// advances and a `Start{generation}` call is queued.
    pub(crate) fn begin_sasl(&mut self, _now: Millis) {
        self.core.phase = Phase::Sasl(SaslNegotiation::default());
        self.sasl.mechanism = None;
        self.sasl.processed_len = None;
        // A teardown already removed these calls. The retain keeps the
        // call order correct when no teardown ran.
        self.sasl
            .calls
            .retain(|c| matches!(c.kind, SaslCallKind::Dispose));
        // C disposes the old mechanism session before it starts a new one.
        self.sasl_on_destroy();
        let generation = self.sasl.advance_gen();
        self.sasl.calls.push_back(SaslCall {
            generation,
            kind: SaslCallKind::Start,
        });
    }

    /// Processes a server reply in the Sasl phase.
    ///
    /// Contract: it logs "SASL: Processed response". An
    /// `err < 0` fails with rc `err`. A decode failure fails with the
    /// `DecodeError::c_rc()` value. Under `awaiting_final` or
    /// `gssapi_last_packet` it completes and calls `start_finalize`.
    /// Otherwise it logs "SASL intermediate server_data_len" and queues a
    /// `Step` call. It returns `Flow::Stop` while mechanism work is
    /// outstanding.
    pub(crate) fn on_sasl_reply(&mut self, body: &[u8], now: Millis) -> Flow {
        // C logs the length of its input buffer, which includes the 4-byte
        // length prefix of the frame.
        let len = log_len(body.len()).saturating_add(4);
        let mut r = Reader::new(body);
        let hdr = match ReplyHeader::decode(&mut r) {
            Ok(h) => h,
            Err(e) => return self.sasl_reply_failed(len, e.c_rc(), now),
        };
        if hdr.err < 0 {
            return self.sasl_reply_failed(len, hdr.err, now);
        }
        let token = match read_token(&mut r) {
            Ok(t) => t,
            Err(e) => return self.sasl_reply_failed(len, e.c_rc(), now),
        };
        let neg = match self.core.phase {
            Phase::Sasl(n) => n,
            _ => SaslNegotiation::default(),
        };
        if neg.awaiting_final {
            // The server accepted the last token.
            if let Some(n) = self.sasl_negotiation() {
                n.awaiting_final = false;
            }
            self.sasl_log_processed_now(len, rc::ZOK);
            return self.start_finalize(now);
        }
        let server_len = token.map_or(-1, |t| log_len(t.len()));
        self.emit_log(LogSite::SaslServerData, || vec![LogArg::I64(server_len)]);
        if neg.is_gssapi && neg.gssapi_last_packet {
            // The last GSSAPI packet completes with no mechanism call.
            if let Some(n) = self.sasl_negotiation() {
                n.gssapi_last_packet = false;
            }
            self.sasl_log_processed_now(len, rc::ZOK);
            return self.start_finalize(now);
        }
        let generation = self.sasl.generation;
        self.sasl.calls.push_back(SaslCall {
            generation,
            kind: SaslCallKind::Step(token.map(SecretBytes::from_slice)),
        });
        self.sasl.processed_len = Some(len);
        Flow::Stop
    }

    /// Runs a SASL failure under `sasl_failure = Teardown`.
    ///
    /// Contract: it logs "SASL authentication failed. rc=%d", sets state
    /// -113 and starts a `Cause::SaslTeardown` teardown. It returns `rc`,
    /// which stays the rc of the call.
    pub(crate) fn sasl_fail(&mut self, rc: i32, now: Millis) -> i32 {
        self.emit_log(LogSite::SaslFailed, || vec![LogArg::I64(i64::from(rc))]);
        self.sasl_log_processed(rc);
        self.sasl_abort(now);
        rc
    }

    /// Returns the next SASL call to yield, if no result is outstanding.
    ///
    /// Contract: a `Dispose` goes out at once. A `Start` or
    /// `Step` sets `outstanding`, and no later call goes out until its
    /// result arrives. A `Start` records `mech_gen`.
    pub(crate) fn poll_sasl_action(&mut self) -> Option<Action> {
        // Every call waits behind an outstanding result, a `Dispose`
        // included. Then no call runs at the same time as another.
        if self.sasl.outstanding {
            return None;
        }
        let call = self.sasl.calls.pop_front()?;
        let kind = match call.kind {
            SaslCallKind::Start => Some(WaitKind::Start),
            SaslCallKind::Step(_) => Some(WaitKind::Step),
            SaslCallKind::Dispose => None,
        };
        if let Some(kind) = kind {
            self.sasl.outstanding = true;
            self.sasl.waiting = Some(Waiting {
                kind,
                generation: call.generation,
            });
        }
        if kind == Some(WaitKind::Start) {
            self.sasl.mech_gen = Some(call.generation);
        }
        Some(Action::Sasl(call))
    }

    /// Returns the next SASL call of a process step, or `None`.
    ///
    /// Contract: a driver calls it after `handle_read`.
    /// C runs the next mechanism call in the `check_events` call that
    /// reads the reply (zookeeper.c:3141-3193). This method gives the
    /// driver the same timing. It gives only `Sasl` calls, with the rules
    /// of `poll_sasl_action`. A suspended stage gives `None`.
    pub fn poll_sasl_call(&mut self) -> Option<SaslCall> {
        if self.out.is_suspended() || self.sasl.calls.is_empty() {
            return None;
        }
        match self.poll_sasl_action() {
            Some(Action::Sasl(call)) => Some(call),
            _ => None,
        }
    }

    /// Returns true while the read loop must wait for mechanism work.
    pub(crate) fn sasl_awaiting_mechanism(&self) -> bool {
        self.sasl.outstanding || !self.sasl.calls.is_empty()
    }

    /// Drops the negotiation at teardown stage T1.
    ///
    /// Contract: `generation` advances, so late results are stale. The queued
    /// `Start` and `Step` calls are dropped. A queued `Dispose` stays.
    /// `mech_gen` stays, so the next `Start` or `destroy` disposes it.
    pub(crate) fn sasl_on_teardown(&mut self) {
        // The outstanding wait stays. Its result arrives stale and ends it.
        self.sasl.end_negotiation();
    }

    /// Queues the `Dispose` of `destroy`.
    ///
    /// Contract: when `mech_gen` is set, queue `Dispose{mech_gen}` and
    /// clear it. `poll_action` yields it after `CloseTransport`.
    /// A new negotiation uses the same step. It disposes the old mechanism
    /// before the new `Start`.
    pub(crate) fn sasl_on_destroy(&mut self) {
        if let Some(generation) = self.sasl.mech_gen.take() {
            self.sasl.calls.push_back(SaslCall {
                generation,
                kind: SaslCallKind::Dispose,
            });
        }
    }

    /// Returns true when a result belongs to the live negotiation and to
    /// the call that waited for it.
    fn sasl_result_live(&self, waiting: Option<Waiting>, kind: WaitKind, generation: u32) -> bool {
        self.sasl.is_live(generation)
            && matches!(self.core.phase, Phase::Sasl(_))
            && waiting.is_some_and(|w| w.kind == kind && w.generation == generation)
    }

    /// Returns the flags of the live negotiation.
    fn sasl_negotiation(&mut self) -> Option<&mut SaslNegotiation> {
        match &mut self.core.phase {
            Phase::Sasl(n) => Some(n),
            _ => None,
        }
    }

    /// Queues a SASL frame at the priority boundary.
    ///
    /// The frame is op 102 with a fresh xid, as in C. A missing token gets
    /// the length 0, never -1.
    fn sasl_send(&mut self, token: Option<&SecretBytes>) {
        let bytes = token.map_or(&[][..], SecretBytes::expose);
        let xid = self.requests.next_xid();
        let frame = secret_frame(xid, opcode::SASL, &[], bytes);
        self.requests
            .push_priority(OutFrame::secret(FrameKind::Sasl, frame));
        let len = log_len(bytes.len());
        self.emit_log(LogSite::SaslQueued, || {
            vec![LogArg::I64(len), LogArg::I64(i64::from(rc::ZOK))]
        });
    }

    /// Logs the mechanism error line when the error carries text. The
    /// drop-in driver passes empty text, because the C glue logs the line.
    fn sasl_log_mech_error(&mut self, site: LogSite, e: SaslError) {
        if e.errstring.is_empty() && e.errdetail.is_empty() {
            return;
        }
        self.emit_log(site, || {
            vec![
                LogArg::Str(JString::Bytes(e.errstring)),
                LogArg::Str(JString::Bytes(e.errdetail)),
            ]
        });
    }

    /// Logs the deferred "SASL: Processed response" line of the server
    /// reply that queued the outstanding `Step`, if one exists.
    fn sasl_log_processed(&mut self, rc: i32) {
        if let Some(len) = self.sasl.processed_len.take() {
            self.sasl_log_processed_now(len, rc);
        }
    }

    /// Logs the "SASL: Processed response" line.
    fn sasl_log_processed_now(&mut self, len: i64, rc: i32) {
        self.emit_log(LogSite::SaslProcessed, || {
            vec![LogArg::I64(len), LogArg::I64(i64::from(rc))]
        });
    }

    /// Fails a server reply. C calls `zoo_sasl_mark_failed` here, so the
    /// "SASL authentication failed" line does not occur.
    fn sasl_reply_failed(&mut self, len: i64, rc: i32, now: Millis) -> Flow {
        self.sasl_log_processed_now(len, rc);
        self.sasl_abort(now);
        Flow::Done(rc)
    }

    /// Sets state -113 and starts the `SaslTeardown` teardown. The SASL rc
    /// stays the rc of the call, so the teardown rc is not used.
    fn sasl_abort(&mut self, now: Millis) {
        self.set_state(State::AuthFailed);
        let _ = self.teardown(Cause::SaslTeardown, 0, now);
    }
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
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::hooks::{AllLevels, NoDefaultWatcher, Rng};
    use crate::output::Output;
    use zk_jute::proto::{GetSASLRequest, RequestHeader};

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

    fn conn() -> Connection<Tk> {
        let mut cfg = Config::legacy(30_000);
        cfg.sasl = true;
        let mut c = Connection::new(
            cfg,
            Compat::LEGACY_C,
            DriverMode::ST,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(NoDefaultWatcher),
            Millis(0),
        );
        c.set_state(State::Associating);
        c
    }

    fn logs(c: &mut Connection<Tk>) -> Vec<(LogSite, Vec<LogArg>)> {
        let mut v = Vec::new();
        while let Some(o) = c.poll_output() {
            if let Output::Log(r) = o {
                v.push((r.site, r.args));
            }
        }
        v
    }

    /// Returns (generation, kind name, step token) of the next call.
    fn next_call(c: &mut Connection<Tk>) -> Option<(u32, &'static str, Option<Vec<u8>>)> {
        match c.poll_sasl_action()? {
            Action::Sasl(SaslCall { generation, kind }) => Some(match kind {
                SaslCallKind::Start => (generation, "start", None),
                SaslCallKind::Step(t) => (generation, "step", t.map(|t| t.expose().to_vec())),
                SaslCallKind::Dispose => (generation, "dispose", None),
            }),
            _ => panic!("not a SASL action"),
        }
    }

    /// Decodes the SASL frames in `tx` order and returns their tokens.
    fn tx_tokens(c: &Connection<Tk>) -> Vec<Vec<u8>> {
        c.requests
            .tx
            .iter()
            .map(|f| {
                assert_eq!(f.kind, FrameKind::Sasl);
                assert!(matches!(f.bytes, crate::requests::FrameBytes::Secret(_)));
                let bytes = f.bytes.as_slice();
                let mut r = Reader::new(bytes);
                let len = r.read_i32().unwrap();
                assert_eq!(usize::try_from(len).unwrap(), bytes.len() - 4);
                let hdr = RequestHeader::decode(&mut r).unwrap();
                assert!(hdr.xid > 0);
                assert_eq!(hdr.r#type, opcode::SASL);
                let req = GetSASLRequest::decode(&mut r).unwrap();
                assert_eq!(r.remaining(), 0);
                // The token is never null on the wire.
                req.token.into_bytes().unwrap()
            })
            .collect()
    }

    fn step(token: Option<&[u8]>, done: bool) -> SaslStep {
        SaslStep {
            token: token.map(SecretBytes::from_slice),
            done,
        }
    }

    fn mech_err() -> SaslError {
        SaslError {
            rc: rc::ZSYSTEMERROR,
            errstring: Vec::new(),
            errdetail: Vec::new(),
        }
    }

    fn reply(err: i32, token: Option<&[u8]>) -> Vec<u8> {
        let mut b = Vec::new();
        ReplyHeader {
            xid: 1,
            zxid: 9,
            err,
        }
        .encode(&mut b);
        match token {
            None => b.extend_from_slice(&(-1_i32).to_be_bytes()),
            Some(t) => {
                b.extend_from_slice(&i32::try_from(t.len()).unwrap().to_be_bytes());
                b.extend_from_slice(t);
            }
        }
        b
    }

    fn started(c: &mut Connection<Tk>, mech: &str, token: Option<&[u8]>, done: bool) -> i32 {
        let generation = c.sasl.generation;
        c.handle_sasl_started(
            generation,
            Ok((mech.to_owned(), step(token, done))),
            Millis(0),
        )
    }

    #[test]
    fn gen_wraps_to_one() {
        let mut s = SaslState::new();
        assert_eq!(s.advance_gen(), 1);
        s.generation = u32::MAX;
        assert_eq!(s.advance_gen(), 1);
        assert!(s.is_live(1));
        assert!(!s.is_live(0));
    }

    /// Rule: the core gives the mechanism one call at a time.
    #[test]
    fn negotiation_runs_one_call_at_a_time() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        assert!(matches!(c.core.phase, Phase::Sasl(n) if n == SaslNegotiation::default()));
        assert!(c.sasl_awaiting_mechanism());
        assert_eq!(next_call(&mut c), Some((1, "start", None)));
        assert_eq!(c.sasl.mech_gen, Some(1));
        assert!(c.sasl.outstanding);
        // No other call goes out while the `Start` result is outstanding.
        assert_eq!(next_call(&mut c), None);
        assert_eq!(started(&mut c, "PLAIN", Some(b"init"), false), rc::ZOK);
        assert!(!c.sasl_awaiting_mechanism());
        assert_eq!(c.sasl.mechanism.as_deref(), Some("PLAIN"));
        assert_eq!(tx_tokens(&c), vec![b"init".to_vec()]);
        assert_eq!(
            logs(&mut c),
            vec![(LogSite::SaslQueued, vec![LogArg::I64(4), LogArg::I64(0)])]
        );

        // A server challenge queues a `Step` and stops the read loop.
        let body = reply(0, Some(b"chal"));
        assert_eq!(c.on_sasl_reply(&body, Millis(1)), Flow::Stop);
        assert!(c.sasl_awaiting_mechanism());
        assert_eq!(
            logs(&mut c),
            vec![(LogSite::SaslServerData, vec![LogArg::I64(4)])]
        );
        assert_eq!(next_call(&mut c), Some((1, "step", Some(b"chal".to_vec()))));
        assert_eq!(next_call(&mut c), None);
        let r = c.handle_sasl_stepped(1, Ok(step(Some(b"resp"), false)), Millis(2));
        assert_eq!(r, rc::ZOK);
        assert_eq!(tx_tokens(&c), vec![b"resp".to_vec(), b"init".to_vec()]);
        // C logs the processed line after the step, with the frame length.
        let len = i64::try_from(body.len() + 4).unwrap();
        assert_eq!(
            logs(&mut c),
            vec![
                (LogSite::SaslQueued, vec![LogArg::I64(4), LogArg::I64(0)]),
                (
                    LogSite::SaslProcessed,
                    vec![LogArg::I64(len), LogArg::I64(0)]
                ),
            ]
        );
        assert!(!c.sasl_awaiting_mechanism());
    }

    #[test]
    fn digest_md5_initial_response_is_refused() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        assert_eq!(
            started(&mut c, "DIGEST-MD5", Some(b"reauth"), false),
            rc::ZOK
        );
        assert_eq!(tx_tokens(&c), vec![Vec::<u8>::new()]);
        assert_eq!(
            logs(&mut c),
            vec![
                (
                    LogSite::SaslRefuseReauth,
                    vec![LogArg::Str(JString::from("DIGEST-MD5"))]
                ),
                (LogSite::SaslQueued, vec![LogArg::I64(0), LogArg::I64(0)]),
            ]
        );
    }

    #[test]
    fn start_done_with_no_token_sends_nothing() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        assert_eq!(started(&mut c, "EXTERNAL", None, true), rc::ZOK);
        assert!(c.requests.tx.is_empty());
        assert!(logs(&mut c).is_empty());
        // `done` with an empty token also sends nothing.
        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        assert_eq!(started(&mut c, "EXTERNAL", Some(b""), true), rc::ZOK);
        assert!(c.requests.tx.is_empty());
    }

    #[test]
    fn gssapi_and_final_token_flags() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        started(&mut c, "GSSAPI", Some(b"t0"), false);
        assert!(matches!(c.core.phase, Phase::Sasl(n) if n.is_gssapi));
        c.on_sasl_reply(&reply(0, Some(b"c1")), Millis(0));
        next_call(&mut c);
        assert_eq!(
            c.handle_sasl_stepped(1, Ok(step(None, true)), Millis(0)),
            rc::ZOK
        );
        assert!(
            matches!(c.core.phase, Phase::Sasl(n) if n.gssapi_last_packet && !n.awaiting_final)
        );
        assert_eq!(c.requests.tx.len(), 1);

        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        started(&mut c, "SCRAM", Some(b"t0"), false);
        c.on_sasl_reply(&reply(0, Some(b"c1")), Millis(0));
        next_call(&mut c);
        assert_eq!(
            c.handle_sasl_stepped(1, Ok(step(Some(b"t1"), true)), Millis(0)),
            rc::ZOK
        );
        assert!(matches!(c.core.phase, Phase::Sasl(n) if n.awaiting_final && !n.is_gssapi));
        assert_eq!(tx_tokens(&c), vec![b"t1".to_vec(), b"t0".to_vec()]);
    }

    #[test]
    fn null_server_token_gives_step_none() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        started(&mut c, "PLAIN", None, false);
        logs(&mut c);
        assert_eq!(c.on_sasl_reply(&reply(0, None), Millis(0)), Flow::Stop);
        assert_eq!(
            logs(&mut c),
            vec![(LogSite::SaslServerData, vec![LogArg::I64(-1)])]
        );
        assert_eq!(next_call(&mut c), Some((1, "step", None)));
    }

    /// Rule: the token reader rejects a bad token length.
    #[test]
    fn token_reader_rejects_bad_lengths() {
        let mut short = Vec::new();
        short.extend_from_slice(&5_i32.to_be_bytes());
        short.extend_from_slice(b"ab");
        let e = read_token(&mut Reader::new(&short)).unwrap_err();
        assert!(matches!(e, DecodeError::Truncated { .. }));
        let neg = (-2_i32).to_be_bytes();
        let e = read_token(&mut Reader::new(&neg)).unwrap_err();
        assert_eq!(e, DecodeError::NegativeBuffer(-2));
        assert_eq!(e.c_rc(), -12);
        let e = read_token(&mut Reader::new(&[0, 0])).unwrap_err();
        assert!(matches!(e, DecodeError::Truncated { .. }));
        let mut r = Reader::new(&[0, 0, 0, 0, 7]);
        assert_eq!(read_token(&mut r).unwrap(), Some(&[][..]));
        assert_eq!(r.remaining(), 1);
    }

    /// Rule: a result of an old negotiation changes nothing.
    #[test]
    fn stale_result_after_teardown_changes_nothing() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        assert_eq!(next_call(&mut c), Some((1, "start", None)));
        c.sasl_on_teardown();
        assert_eq!(c.sasl.generation, 2);
        assert!(c.sasl.calls.is_empty());
        // The wait stays until the stale result arrives.
        assert!(c.sasl_awaiting_mechanism());
        let r = c.handle_sasl_started(1, Err(mech_err()), Millis(0));
        assert_eq!(r, rc::ZOK);
        assert!(!c.sasl.outstanding);
        assert_eq!(c.state(), State::Associating);
        assert!(c.requests.tx.is_empty());
        assert!(logs(&mut c).is_empty());
        // A stale `Ok` result and a stale step result also do nothing.
        let r = c.handle_sasl_started(
            1,
            Ok(("PLAIN".to_owned(), step(Some(b"x"), false))),
            Millis(0),
        );
        assert_eq!(r, rc::ZOK);
        let r = c.handle_sasl_stepped(1, Ok(step(Some(b"x"), false)), Millis(0));
        assert_eq!(r, rc::ZOK);
        assert_eq!(
            c.handle_sasl_addr_failed(1, SaslAddr::Local, Millis(0)),
            rc::ZOK
        );
        assert!(c.requests.tx.is_empty());
        assert!(c.sasl.mechanism.is_none());
        assert_eq!(c.sasl.mech_gen, Some(1));
        assert!(logs(&mut c).is_empty());
    }

    #[test]
    fn stale_step_after_teardown_drops_the_processed_line() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        started(&mut c, "PLAIN", Some(b"a"), false);
        c.on_sasl_reply(&reply(0, Some(b"b")), Millis(0));
        // A teardown drops the queued `Step` and the queued frames.
        c.sasl_on_teardown();
        c.requests.tx.clear();
        assert!(c.sasl.calls.is_empty());
        assert!(c.sasl.processed_len.is_none());
        assert_eq!(next_call(&mut c), None);
        logs(&mut c);
        // The second negotiation starts with the `Dispose` of the first.
        c.begin_sasl(Millis(0));
        assert_eq!(next_call(&mut c), Some((1, "dispose", None)));
        assert_eq!(next_call(&mut c), Some((3, "start", None)));
        let r = c.handle_sasl_stepped(1, Ok(step(Some(b"x"), false)), Millis(0));
        assert_eq!(r, rc::ZOK);
        // A stray result of another generation does not end the wait of
        // the live `Start`, so its result still counts.
        assert!(c.sasl.outstanding);
        assert!(c.requests.tx.is_empty());
        assert_eq!(
            c.handle_sasl_started(
                3,
                Ok(("PLAIN".to_owned(), step(Some(b"n"), false))),
                Millis(0)
            ),
            rc::ZOK
        );
        assert_eq!(tx_tokens(&c), vec![b"n".to_vec()]);
    }

    #[test]
    fn second_negotiation_disposes_then_starts() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        assert_eq!(next_call(&mut c), Some((1, "start", None)));
        started(&mut c, "PLAIN", Some(b"a"), false);
        c.sasl_on_teardown();
        // A teardown alone yields no `Dispose`.
        assert_eq!(next_call(&mut c), None);
        assert_eq!(c.sasl.mech_gen, Some(1));
        c.begin_sasl(Millis(0));
        assert_eq!(c.sasl.mech_gen, None);
        assert_eq!(next_call(&mut c), Some((1, "dispose", None)));
        // `Dispose` sets no wait, so the `Start` follows at once.
        assert_eq!(next_call(&mut c), Some((3, "start", None)));
        assert_eq!(c.sasl.mech_gen, Some(3));
        assert_eq!(next_call(&mut c), None);
    }

    /// Rule: a `Dispose` waits until the outstanding call gives its result.
    #[test]
    fn dispose_waits_behind_an_outstanding_result() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        assert_eq!(next_call(&mut c), Some((1, "start", None)));
        c.sasl_on_teardown();
        c.begin_sasl(Millis(0));
        assert_eq!(next_call(&mut c), None);
        assert_eq!(
            c.handle_sasl_started(1, Err(mech_err()), Millis(0)),
            rc::ZOK
        );
        assert_eq!(c.state(), State::Associating);
        assert_eq!(next_call(&mut c), Some((1, "dispose", None)));
        assert_eq!(next_call(&mut c), Some((3, "start", None)));
    }

    #[test]
    fn destroy_queues_the_final_dispose_once() {
        let mut c = conn();
        c.sasl_on_destroy();
        assert_eq!(next_call(&mut c), None);
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        started(&mut c, "PLAIN", Some(b"a"), false);
        c.sasl_on_teardown();
        c.sasl_on_destroy();
        c.sasl_on_destroy();
        assert_eq!(next_call(&mut c), Some((1, "dispose", None)));
        assert_eq!(next_call(&mut c), None);
        assert_eq!(c.sasl.mech_gen, None);
    }

    #[test]
    fn mark_failed_sets_state_and_ends_the_negotiation() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        c.mark_sasl_failed();
        assert_eq!(c.state(), State::AuthFailed);
        assert!(c.sasl.calls.is_empty());
        assert_eq!(c.sasl.generation, 2);
        assert!(logs(&mut c).is_empty());
        assert!(!c.is_suspended());
        // A `Dispose` that waits stays queued.
        let mut c = conn();
        c.begin_sasl(Millis(0));
        next_call(&mut c);
        started(&mut c, "PLAIN", Some(b"a"), false);
        c.sasl_on_teardown();
        c.begin_sasl(Millis(0));
        c.mark_sasl_failed();
        assert_eq!(next_call(&mut c), Some((1, "dispose", None)));
        assert_eq!(next_call(&mut c), None);
    }

    #[test]
    fn addr_failure_for_a_stale_or_unknown_start_is_ignored() {
        let mut c = conn();
        c.begin_sasl(Millis(0));
        assert_eq!(
            c.handle_sasl_addr_failed(7, SaslAddr::Peer, Millis(0)),
            rc::ZOK
        );
        assert_eq!(c.sasl.calls.len(), 1);
        next_call(&mut c);
        // A wrong generation does not end the wait of the live `Start`.
        assert_eq!(
            c.handle_sasl_addr_failed(7, SaslAddr::Peer, Millis(0)),
            rc::ZOK
        );
        assert!(c.sasl.outstanding);
        // After a teardown the failure of the old `Start` ends its wait.
        c.sasl_on_teardown();
        assert_eq!(
            c.handle_sasl_addr_failed(1, SaslAddr::Local, Millis(0)),
            rc::ZOK
        );
        assert!(!c.sasl.outstanding);
        assert_eq!(c.state(), State::Associating);
        assert!(logs(&mut c).is_empty());
    }
}
