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

//! SASL scenarios: a scripted mechanism that starts, steps and fails, a
//! server failure reply, and a late result of an old generation.

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

use common::{Profile, cause, reply, run_to_state, sasl_calls, sasl_harness, token};
use zk_jute::{opcode, rc};
use zk_proto::{Cause, Output, State};
use zk_testkit::server::{InboundKind, SaslReply};
use zk_testkit::{Event, Harness, SaslKind, SaslScript, ScriptStep};

/// Returns the request ops of all links, in arrival order.
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

// Start gives the first token. Each server challenge goes to Step. A done
// step with a token waits for the final server reply, and then the session
// completes. The SASL frames go out before the queued requests.
#[test]
fn sasl_start_and_step_complete_the_session() {
    for p in Profile::ALL {
        let script = SaslScript {
            mechanism: "DIGEST-MD5".to_owned(),
            start: token(b"t1", false),
            steps: vec![token(b"t2", true)],
            ..SaslScript::default()
        };
        let mut h = sasl_harness(p, 90, script, vec![reply(b"c1"), reply(b"")]);
        let ops = h.ops();
        let t = h.submit(ops.exists("/", None)).unwrap();
        h.connect().unwrap();
        h.wait_for(t).unwrap();
        h.expect_completion(t, rc::ZOK).unwrap();
        assert_eq!(
            sasl_calls(&h),
            vec![
                (1, SaslKind::Start),
                (1, SaslKind::Step(Some(b"c1".to_vec())))
            ],
            "{p:?}"
        );
        assert_eq!(
            all_ops(&h)[..3],
            [opcode::SASL, opcode::SASL, opcode::EXISTS],
            "{p:?}"
        );
        assert_eq!(h.state(), State::Connected);
        // Dispose comes only from destroy.
        h.close().unwrap();
        assert_eq!(
            sasl_calls(&h).last(),
            Some(&(1, SaslKind::Dispose)),
            "{p:?}"
        );
    }
}

// Source: zk-proto sasl_fail. A mechanism error is a SASL failure with
// ZSYSTEMERROR. The state becomes -113, the teardown closes the transport
// and emits Session{-113}, and pending work fails with ZAUTHFAILED. The
// session ends: no new connect follows. Dispose waits for destroy.
#[test]
fn mechanism_failure_is_a_terminal_teardown() {
    for p in Profile::ALL {
        let script = SaslScript {
            start: token(b"t1", false),
            steps: vec![ScriptStep::Fail { rc: -1 }],
            ..SaslScript::default()
        };
        let mut h = sasl_harness(p, 91, script, vec![reply(b"c1")]);
        let ops = h.ops();
        let t = h.submit(ops.exists("/", None)).unwrap();
        run_to_state(&mut h, State::AuthFailed, 10_000);
        h.run_for(100).unwrap();
        assert_eq!(cause(&h), Some(Cause::SaslTeardown), "{p:?}");
        h.expect_completion(t, rc::ZAUTHFAILED).unwrap();
        let rcs: Vec<i32> = h
            .recorder()
            .all()
            .iter()
            .filter_map(|r| match r.event {
                Event::SaslResult { rc, .. } => Some(rc),
                _ => None,
            })
            .collect();
        assert_eq!(rcs.last(), Some(&rc::ZSYSTEMERROR), "{p:?}");
        assert!(
            h.recorder().outputs().any(|o| matches!(
                o,
                Output::Session {
                    state: State::AuthFailed,
                    ..
                }
            )),
            "{p:?}"
        );
        assert!(!h.conn().has_transport());
        let n = h.server().connect_requests().len();
        h.run_for(5_000).unwrap();
        assert_eq!(h.server().connect_requests().len(), n, "{p:?}");
        assert!(!sasl_calls(&h).iter().any(|(_, k)| *k == SaslKind::Dispose));
        let now = h.now();
        h.conn_mut().destroy(now);
        h.pump(now);
        assert_eq!(
            sasl_calls(&h).last(),
            Some(&(1, SaslKind::Dispose)),
            "{p:?}"
        );
        h.expect_exactly_once().unwrap();
    }
}

// Source: zk-proto on_sasl_reply. A server reply with err < 0 fails the
// negotiation with that err. The state becomes -113.
#[test]
fn server_failure_reply_fails_the_negotiation() {
    for p in Profile::ALL {
        let script = SaslScript {
            start: token(b"t1", false),
            ..SaslScript::default()
        };
        let bad = SaslReply {
            token: None,
            err: rc::ZAUTHFAILED,
        };
        let mut h = sasl_harness(p, 92, script, vec![bad]);
        run_to_state(&mut h, State::AuthFailed, 10_000);
        h.run_for(100).unwrap();
        assert_eq!(sasl_calls(&h), vec![(1, SaslKind::Start)], "{p:?}");
        assert!(!h.recorder().session_states().contains(&State::Connected));
        assert!(!h.conn().has_transport());
    }
}

// Source: the stale generation rule, and teardown stage T1. A teardown
// advances the generation. A late result of the old generation returns ZOK
// and sends nothing. The next connect disposes the old session and starts a
// new one with the next generation.
#[test]
fn stale_generation_result_is_ignored() {
    for p in Profile::ALL {
        let script = SaslScript {
            defer_ms: Some(500),
            ..SaslScript::default()
        };
        let mut h = sasl_harness(p, 93, script, Vec::new());
        // Wait for the first Start, then reset before its result.
        h.run_until(|h| !sasl_calls(h).is_empty(), 5_000).unwrap();
        let sasl_frames = h.server().request_count(opcode::SASL);
        assert_eq!(sasl_frames, 0);
        h.reset_current();
        h.run_until(|h| h.state() == State::Connected, 10_000)
            .unwrap();
        let results: Vec<(u32, i32)> = h
            .recorder()
            .all()
            .iter()
            .filter_map(|r| match r.event {
                Event::SaslResult { generation, rc } => Some((generation, rc)),
                _ => None,
            })
            .collect();
        assert_eq!(results.first(), Some(&(1, rc::ZOK)), "{p:?}");
        // The teardown and the new Start each advance the generation, so
        // the second Start has generation 3.
        let calls = sasl_calls(&h);
        assert_eq!(
            calls[..3],
            [
                (1, SaslKind::Start),
                (1, SaslKind::Dispose),
                (3, SaslKind::Start)
            ],
            "{p:?}"
        );
        // Only the live generation sent a token.
        assert_eq!(h.server().request_count(opcode::SASL), 1, "{p:?}");
    }
}
