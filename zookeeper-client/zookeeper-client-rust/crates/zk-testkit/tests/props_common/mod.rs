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

//! Shared parts of the property tests: the seeded runner config, the
//! driver profiles, the random request scripts and the exactly-once
//! checks.

#![allow(
    dead_code,
    missing_docs,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

#[path = "../common/mod.rs"]
mod scenario;

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use proptest::test_runner::{Config as PtConfig, RngSeed};
use zk_proto::{Op, OpResult, Origin, Output, Route, State};
use zk_testkit::server::{Rule, RuleAction, ServerOptions};
use zk_testkit::{
    AuthTicket, Event, Finished, Harness, HarnessBuilder, HarnessError, Ops, TestTokens, Ticket,
    WatcherId,
};

/// The three driver profiles of the scenario tests.
pub(crate) use scenario::Profile;

/// The number of cases of each property.
pub const CASES: u32 = 256;

/// Returns a runner config with a fixed seed, so each run is the same.
pub fn config(seed: u64) -> PtConfig {
    config_cases(CASES, seed)
}

/// Returns a runner config with a fixed seed and `cases` cases.
pub fn config_cases(cases: u32, seed: u64) -> PtConfig {
    PtConfig {
        cases,
        rng_seed: RngSeed::Fixed(seed),
        failure_persistence: None,
        max_shrink_iters: 512,
        ..PtConfig::default()
    }
}

pub fn profile() -> impl Strategy<Value = Profile> {
    prop_oneof![Just(Profile::St), Just(Profile::Mt), Just(Profile::Native)]
}

/// The paths of the scripts. The server answers each one.
pub const PATHS: [&str; 4] = ["/a", "/b", "/a/c", "/zk"];

/// The auth scheme that the server refuses.
pub const BAD_SCHEME: &str = "bad";

/// The operation kinds of the scripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Create,
    Exists,
    GetData,
    SetData,
    Delete,
    GetChildren,
    GetChildren2,
    GetAcl,
    Sync,
    Multi,
}

pub fn op_kind() -> impl Strategy<Value = OpKind> {
    prop_oneof![
        Just(OpKind::Create),
        Just(OpKind::Exists),
        Just(OpKind::GetData),
        Just(OpKind::SetData),
        Just(OpKind::Delete),
        Just(OpKind::GetChildren),
        Just(OpKind::GetChildren2),
        Just(OpKind::GetAcl),
        Just(OpKind::Sync),
        Just(OpKind::Multi),
    ]
}

/// Builds the operation of a script step.
pub fn make_op(ops: &Ops, kind: OpKind, path: usize, watch: bool) -> Op<WatcherId> {
    let p = PATHS[path % PATHS.len()];
    let w = watch.then(|| WatcherId::new(1, u32::try_from(path).unwrap_or(0)));
    match kind {
        OpKind::Create => ops.create(p, b"v", 0),
        OpKind::Exists => ops.exists(p, w),
        OpKind::GetData => ops.get_data(p, w),
        OpKind::SetData => ops.set_data(p, b"w", -1),
        OpKind::Delete => ops.delete(p, -1),
        OpKind::GetChildren => ops.get_children(p, w),
        OpKind::GetChildren2 => ops.get_children2(p, w),
        OpKind::GetAcl => ops.get_acl(p),
        OpKind::Sync => ops.sync(p),
        OpKind::Multi => ops.multi(vec![ops.m_create(p, b"m", 0), ops.m_check(p, -1)]),
    }
}

/// The transport failures that a script can inject. The harness drops
/// the link after each one, so a failure that the core ignores is not in
/// this list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailKind {
    Io,
    Eof,
    Refused,
    SocketCreate,
    TlsHandshake,
}

pub fn fail_kind() -> impl Strategy<Value = FailKind> {
    prop_oneof![
        Just(FailKind::Io),
        Just(FailKind::Eof),
        Just(FailKind::Refused),
        Just(FailKind::SocketCreate),
        Just(FailKind::TlsHandshake),
    ]
}

impl FailKind {
    pub fn failure(self) -> zk_proto::TransportFailure {
        use zk_proto::TransportFailure as F;
        match self {
            Self::Io => F::Io { errno: 104 },
            Self::Eof => F::Eof,
            Self::Refused => F::TcpRefused { errno: 111 },
            Self::SocketCreate => F::SocketCreate { errno: 24 },
            Self::TlsHandshake => F::TlsHandshake { errno: 0 },
        }
    }
}

/// One step of a random script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Submits one request. `direct` applies only under MT.
    Submit {
        kind: OpKind,
        path: usize,
        watch: bool,
        direct: bool,
    },
    /// Adds an auth entry. The server refuses the bad scheme.
    AddAuth { bad: bool },
    /// Runs the steps for this many milliseconds.
    Run(u32),
    /// Runs until connected, or until 30 s pass.
    Connect,
    /// The server resets the link.
    Reset,
    /// The server closes the link.
    CloseLink,
    /// The driver reports a transport failure.
    Fail(FailKind),
    /// The server expires the session.
    Expire,
    /// The server gives no reply to the next request.
    DropNext,
    /// The server answers the next request with garbage bytes.
    GarbageNext(Vec<u8>),
    /// The driver forces a close of the transport, as a reconfig does.
    ForcedClose,
    /// The application closes the handle. The script ends.
    Close,
}

pub fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        8 => (op_kind(), 0..PATHS.len(), any::<bool>(), any::<bool>()).prop_map(
            |(kind, path, watch, direct)| Step::Submit {
                kind,
                path,
                watch,
                direct
            }
        ),
        1 => any::<bool>().prop_map(|bad| Step::AddAuth { bad }),
        4 => (0u32..3_000).prop_map(Step::Run),
        3 => Just(Step::Connect),
        1 => Just(Step::Reset),
        1 => Just(Step::CloseLink),
        1 => fail_kind().prop_map(Step::Fail),
        1 => Just(Step::Expire),
        1 => Just(Step::DropNext),
        1 => proptest::collection::vec(any::<u8>(), 0..12).prop_map(Step::GarbageNext),
        1 => Just(Step::ForcedClose),
        1 => Just(Step::Close),
    ]
}

pub fn script(max: usize) -> impl Strategy<Value = Vec<Step>> {
    proptest::collection::vec(step(), 1..max)
}

/// Builds the harness of a script run. The server refuses the bad
/// scheme with an auth failure.
pub fn script_harness(p: Profile, seed: u64) -> Harness {
    script_builder(p, seed).build()
}

/// Returns the builder of `script_harness`, for tests that change it.
pub fn script_builder(p: Profile, seed: u64) -> HarnessBuilder {
    let mut opts = ServerOptions::default();
    opts.reject_auth_schemes
        .insert(BAD_SCHEME.as_bytes().to_vec());
    p.builder(seed).server_options(opts)
}

/// Runs one step. It returns true when the script must end.
///
/// A timeout of the harness is a normal outcome of a random script. A
/// runaway is a livelock and fails the case.
pub fn apply(h: &mut Harness, p: Profile, s: &Step) -> Result<bool, TestCaseError> {
    let ok = |r: Result<(), HarnessError>| match r {
        Err(HarnessError::Runaway { steps }) => {
            Err(TestCaseError::fail(format!("runaway after {steps} steps")))
        }
        _ => Ok(()),
    };
    match s {
        Step::Submit {
            kind,
            path,
            watch,
            direct,
        } => {
            let ops = h.ops();
            let op = make_op(&ops, *kind, *path, *watch);
            let route = if *direct && p == Profile::Mt {
                Route::Direct
            } else {
                Route::Queued
            };
            // A refusal is recorded and counts as the one delivery.
            let _ = h.submit_with(op, route, zk_proto::InputDefect::default());
        }
        Step::AddAuth { bad } => {
            let scheme = if *bad { BAD_SCHEME } else { "digest" };
            let _ = h.add_auth(scheme, b"user:pw");
        }
        Step::Run(ms) => ok(h.run_for(u64::from(*ms)))?,
        Step::Connect => ok(h.run_until(|h| h.state().is_connected(), 30_000))?,
        Step::Reset => h.reset_current(),
        Step::CloseLink => h.close_current(),
        Step::Fail(f) => {
            if h.conn().has_transport() {
                let _ = h.inject_failure(f.failure());
            }
        }
        Step::Expire => {
            let sid = h.conn().client_id().session_id;
            if sid != 0 {
                h.server_mut().expire_session(sid);
            }
        }
        Step::DropNext => {
            h.server_mut()
                .add_rule(Rule::on_request().once().then(RuleAction::Drop));
        }
        Step::GarbageNext(b) => {
            h.server_mut().add_rule(
                Rule::on_request()
                    .once()
                    .then(RuleAction::Garbage(b.clone())),
            );
        }
        Step::ForcedClose => {
            let now = h.now();
            h.conn_mut().handle_forced_close(now);
            h.pump(now);
        }
        Step::Close => {
            ok(h.close())?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Checks the result invariant of each `OpResult` completion: a
/// teardown result has no reply, and rc is never 0 with no reply.
pub fn check_results(f: &Finished) -> Result<(), TestCaseError> {
    for r in f.recorder.all() {
        if let Event::Output(Output::Completion { token, result, .. }) = &r.event {
            check_result(token.ticket(), result)?;
        }
    }
    Ok(())
}

pub fn check_result(t: Ticket, r: &OpResult) -> Result<(), TestCaseError> {
    if r.origin == Origin::Teardown {
        prop_assert!(r.reply.is_none(), "ticket {}: teardown reply", t.0);
        prop_assert!(r.rc != 0, "ticket {}: teardown rc 0", t.0);
    }
    prop_assert!(
        !(r.rc == 0 && r.reply.is_none()),
        "ticket {}: rc 0 with no reply",
        t.0
    );
    Ok(())
}

/// Checks that each auth token leaves the core exactly once: in an
/// `Auth` output, as a refused `add_auth`, or in the leftovers.
pub fn check_auth_once(f: &Finished) -> Result<(), TestCaseError> {
    let mut issued: BTreeSet<AuthTicket> = BTreeSet::new();
    let mut seen: BTreeMap<AuthTicket, usize> = BTreeMap::new();
    let mut bump = |t: AuthTicket| *seen.entry(t).or_insert(0) += 1;
    for r in f.recorder.all() {
        match &r.event {
            Event::AuthAdded(Some(t)) => {
                issued.insert(*t);
            }
            Event::AuthRejected { ticket, code } => {
                let Some(t) = ticket else {
                    return Err(TestCaseError::fail(format!(
                        "add_auth rejected with {code} and lost the token"
                    )));
                };
                issued.insert(*t);
                bump(*t);
            }
            Event::Output(Output::Auth { tokens, .. }) => {
                for a in tokens {
                    bump(a.ticket());
                }
            }
            _ => {}
        }
    }
    for a in &f.leftovers.auth {
        bump(a.ticket());
    }
    for o in &f.leftovers.outputs {
        if let Output::Auth { tokens, .. } = o {
            for a in tokens {
                bump(a.ticket());
            }
        }
    }
    for t in &issued {
        let n = seen.get(t).copied().unwrap_or(0);
        prop_assert_eq!(n, 1, "auth ticket {} delivered {} times", t.0, n);
    }
    for t in seen.keys() {
        prop_assert!(issued.contains(t), "auth ticket {} never issued", t.0);
    }
    Ok(())
}

/// Checks every exactly-once rule of a finished run.
pub fn check_once(f: &Finished) -> Result<(), TestCaseError> {
    f.recorder
        .check_exactly_once()
        .map_err(TestCaseError::fail)?;
    check_auth_once(f)?;
    check_results(f)
}

/// Returns the tickets of the queued submits, in submit order, with
/// their xids.
pub fn submitted(f: &zk_testkit::Recorder) -> Vec<(Ticket, i32)> {
    f.all()
        .iter()
        .filter_map(|r| match r.event {
            Event::Submitted { ticket, xid } => Some((ticket, xid)),
            _ => None,
        })
        .collect()
}

/// Returns the completion outputs of a record slice as ticket and result.
pub fn completions(rs: &[zk_testkit::Recorded]) -> Vec<(Ticket, OpResult)> {
    rs.iter()
        .filter_map(|r| match &r.event {
            Event::Output(Output::Completion { token, result, .. }) => {
                Some((token.ticket(), result.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Returns true for a connected or read-only state.
pub fn connected(s: State) -> bool {
    s.is_connected()
}

/// Names the output kind, for messages.
pub fn kind(o: &Output<TestTokens>) -> &'static str {
    match o {
        Output::Completion { .. } => "Completion",
        Output::Watch { .. } => "Watch",
        Output::Session { .. } => "Session",
        Output::Auth { .. } => "Auth",
        Output::AuthLockpoint => "AuthLockpoint",
        Output::ClientId(_) => "ClientId",
        Output::WatchTerminated { .. } => "WatchTerminated",
        Output::Log(_) => "Log",
        Output::DrainPoint => "DrainPoint",
    }
}
