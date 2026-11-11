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

//! SASL scenarios of the Rust core: a request that waits in the Start
//! window, a stale flag at a reconnect, a final reply with a token, a token
//! of length -1 and a malformed reply.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use common::{Profile, reply, sasl_calls, sasl_harness, token};
use zk_jute::{opcode, rc};
use zk_proto::{LogArg, LogSite, State};
use zk_testkit::server::{InboundKind, Rule, RuleAction, SaslReply};
use zk_testkit::{Harness, SaslKind, SaslScript};

fn kinds(h: &Harness) -> Vec<SaslKind> {
    sasl_calls(h).into_iter().map(|(_, k)| k).collect()
}

fn log_args(h: &Harness, site: LogSite) -> Vec<Vec<LogArg>> {
    h.recorder()
        .logs()
        .iter()
        .filter(|l| l.site == site)
        .map(|l| l.args.clone())
        .collect()
}

fn digest_script() -> SaslScript {
    SaslScript {
        mechanism: "DIGEST-MD5".to_owned(),
        start: token(b"t1", false),
        steps: vec![token(b"t2", true)],
        ..SaslScript::default()
    }
}

fn all_ops(h: &Harness) -> Vec<i32> {
    h.server()
        .inbound()
        .iter()
        .filter_map(|f| match f.kind {
            InboundKind::Request { op, .. } => Some(op),
            _ => None,
        })
        .collect()
}

// Source: the phase gate of the send queue. The application submits a
// request while the Start result is outstanding. The SASL frames still go
// out first, the request follows, and the session completes. The mt drop-in
// showed this window in tests/conformance/cases/sasl_fail.c.
#[test]
fn request_in_start_window_waits_behind_sasl() {
    for p in Profile::ALL {
        let script = SaslScript {
            mechanism: "DIGEST-MD5".to_owned(),
            start: token(b"t1", false),
            steps: vec![token(b"t2", true)],
            defer_ms: Some(50),
            ..SaslScript::default()
        };
        let mut h = sasl_harness(p, 201, script, vec![reply(b"c1"), reply(b"")]);
        h.run_until(|h| !sasl_calls(h).is_empty(), 5_000).unwrap();
        let ops = h.ops();
        let t = h.submit(ops.exists("/", None)).unwrap();
        h.wait_for(t).unwrap();
        h.expect_completion(t, rc::ZOK).unwrap();
        assert_eq!(
            all_ops(&h)[..3],
            [opcode::SASL, opcode::SASL, opcode::EXISTS],
            "{p:?}"
        );
        assert_eq!(h.state(), State::Connected, "{p:?}");
        h.close().unwrap();
    }
}

// Source: ledger row SAS-04. The negotiation state is new at every prime
// response. A reset while the final reply is due does not carry
// awaiting_final into the next connection, so the first reply of the new
// connection goes to Step and does not complete the session.
/// Ledger: SAS-04
#[test]
fn awaiting_final_does_not_survive_a_reconnect() {
    for p in Profile::ALL {
        let mut h = sasl_harness(p, 202, digest_script(), vec![reply(b"c1"), reply(b"")]);
        // The final token of the first link gets no reply.
        h.server_mut().add_rule(
            Rule::on_request()
                .op(opcode::SASL)
                .conn(0)
                .skip(1)
                .once()
                .then(RuleAction::Ignore),
        );
        h.run_until(|h| h.server().request_count(opcode::SASL) == 2, 5_000)
            .unwrap();
        assert_eq!(h.state(), State::Associating, "{p:?}");
        h.reset_current();
        h.run_until(|h| h.state() == State::Connected, 10_000)
            .unwrap();
        let c1 = SaslKind::Step(Some(b"c1".to_vec()));
        assert_eq!(
            kinds(&h),
            [
                SaslKind::Start,
                c1.clone(),
                SaslKind::Dispose,
                SaslKind::Start,
                c1
            ],
            "{p:?}"
        );
        h.close().unwrap();
    }
}

// Source: ledger row SAS-05. After a done step with a token, the next reply
// completes the session, also when that reply has a token. The mechanism
// gets no Step for it, and no server_data_len line comes.
/// Ledger: SAS-05
#[test]
fn final_reply_with_a_token_completes_without_a_step() {
    for p in Profile::ALL {
        let mut h = sasl_harness(
            p,
            203,
            digest_script(),
            vec![reply(b"c1"), reply(b"rspauth=1")],
        );
        h.connect().unwrap();
        h.run_until(|h| h.state() == State::Connected, 10_000)
            .unwrap();
        assert_eq!(
            kinds(&h),
            [SaslKind::Start, SaslKind::Step(Some(b"c1".to_vec()))],
            "{p:?}"
        );
        assert_eq!(h.server().request_count(opcode::SASL), 2, "{p:?}");
        assert_eq!(
            log_args(&h, LogSite::SaslServerData),
            [vec![LogArg::I64(2)]],
            "{p:?}"
        );
        h.close().unwrap();
    }
}

// Source: ledger row SAS-10. A server token of length -1 gives Step(None),
// and the server_data_len line prints -1.
/// Ledger: SAS-10
#[test]
fn null_server_token_steps_with_none() {
    for p in Profile::ALL {
        let null = SaslReply {
            token: None,
            err: rc::ZOK,
        };
        let mut h = sasl_harness(p, 204, digest_script(), vec![null, reply(b"")]);
        h.connect().unwrap();
        h.run_until(|h| h.state() == State::Connected, 10_000)
            .unwrap();
        assert_eq!(kinds(&h), [SaslKind::Start, SaslKind::Step(None)], "{p:?}");
        assert_eq!(
            log_args(&h, LogSite::SaslServerData),
            [vec![LogArg::I64(-1)]],
            "{p:?}"
        );
        h.close().unwrap();
    }
}

// Source: ledger rows SAS-08 and SAS-11. A reply whose token runs past the
// frame fails the negotiation with DecodeError::c_rc(), which is -E2BIG for
// a truncated input. The "SASL: Processed response" line logs that rc, the
// state becomes -113 and the mechanism gets no Step.
/// Ledger: SAS-08, SAS-11
#[test]
fn malformed_reply_fails_with_the_decode_rc() {
    // A reply header (xid 1, zxid 0, err 0), then a token length of 100
    // with no token bytes.
    let mut frame = 20_i32.to_be_bytes().to_vec();
    frame.extend_from_slice(&1_i32.to_be_bytes());
    frame.extend_from_slice(&0_i64.to_be_bytes());
    frame.extend_from_slice(&0_i32.to_be_bytes());
    frame.extend_from_slice(&100_i32.to_be_bytes());
    for p in Profile::ALL {
        let mut h = sasl_harness(p, 205, digest_script(), Vec::new());
        h.server_mut().add_rule(
            Rule::on_request()
                .op(opcode::SASL)
                .once()
                .then(RuleAction::Garbage(frame.clone())),
        );
        h.run_until(|h| h.state() == State::AuthFailed, 10_000)
            .unwrap();
        assert_eq!(kinds(&h), [SaslKind::Start], "{p:?}");
        // The processed line has the frame length and the rc. A reply
        // failure has no failure line, as zoo_sasl_mark_failed logs none.
        assert_eq!(
            log_args(&h, LogSite::SaslProcessed).last(),
            Some(&vec![LogArg::I64(24), LogArg::I64(-7)]),
            "{p:?}"
        );
        assert!(log_args(&h, LogSite::SaslFailed).is_empty(), "{p:?}");
        assert!(!h.conn().has_transport(), "{p:?}");
    }
}
