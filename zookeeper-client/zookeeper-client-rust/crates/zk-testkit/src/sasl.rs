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

//! A scripted SASL mechanism.
//!
//! The script gives the result of the start call and of each step call.
//! A shared log records the calls, so a test can check the challenge
//! bytes that the core passes to the mechanism.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use zk_proto::{SaslAddr, SaslError, SaslSession, SaslStep, SecretBytes};

/// One scripted mechanism result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptStep {
    /// The call succeeds with this token and this done flag.
    Token {
        /// The token for the server, or `None` for no token.
        token: Option<Vec<u8>>,
        /// True when the mechanism is complete.
        done: bool,
    },
    /// The call fails with this rc.
    Fail {
        /// The SASL rc.
        rc: i32,
    },
}

impl ScriptStep {
    fn to_step(&self) -> Result<SaslStep, SaslError> {
        match self {
            Self::Token { token, done } => Ok(SaslStep {
                token: token.as_deref().map(SecretBytes::from_slice),
                done: *done,
            }),
            Self::Fail { rc } => Err(SaslError {
                rc: *rc,
                errstring: b"scripted failure".to_vec(),
                errdetail: Vec::new(),
            }),
        }
    }
}

/// The script of one mechanism session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaslScript {
    /// The mechanism name that `start` reports.
    pub mechanism: String,
    /// The result of `start`.
    pub start: ScriptStep,
    /// The results of the `step` calls, in order. When the list ends,
    /// each further step succeeds with no token and `done`.
    pub steps: Vec<ScriptStep>,
    /// When set, the harness reports this address read failure instead of
    /// calling `start`.
    pub addr_failure: Option<SaslAddr>,
    /// When set, the harness gives each mechanism result to the core after
    /// this delay, in a later step.
    pub defer_ms: Option<u64>,
}

impl Default for SaslScript {
    /// A one-round `PLAIN` mechanism.
    fn default() -> Self {
        Self {
            mechanism: "PLAIN".to_owned(),
            start: ScriptStep::Token {
                token: Some(b"\0user\0secret".to_vec()),
                done: true,
            },
            steps: Vec::new(),
            addr_failure: None,
            defer_ms: None,
        }
    }
}

/// One call to a [`ScriptedSasl`] session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaslCallRecord {
    /// A `start` call.
    Start,
    /// A `step` call with the challenge bytes.
    Step(Option<Vec<u8>>),
}

/// A shared log of mechanism calls.
#[derive(Clone, Debug, Default)]
pub struct SaslLog {
    calls: Arc<Mutex<Vec<SaslCallRecord>>>,
}

impl SaslLog {
    /// Makes an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&self, c: SaslCallRecord) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(c);
    }

    /// Returns a copy of the calls, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<SaslCallRecord> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A [`SaslSession`] that follows a [`SaslScript`].
#[derive(Debug)]
pub struct ScriptedSasl {
    mechanism: String,
    start: ScriptStep,
    steps: VecDeque<ScriptStep>,
    log: SaslLog,
}

impl ScriptedSasl {
    /// Makes a session for this script. The calls go to `log`.
    #[must_use]
    pub fn new(script: &SaslScript, log: SaslLog) -> Self {
        Self {
            mechanism: script.mechanism.clone(),
            start: script.start.clone(),
            steps: script.steps.iter().cloned().collect(),
            log,
        }
    }
}

impl SaslSession for ScriptedSasl {
    fn start(&mut self) -> Result<(String, SaslStep), SaslError> {
        self.log.push(SaslCallRecord::Start);
        self.start.to_step().map(|s| (self.mechanism.clone(), s))
    }

    fn step(&mut self, challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
        self.log
            .push(SaslCallRecord::Step(challenge.map(<[u8]>::to_vec)));
        match self.steps.pop_front() {
            Some(s) => s.to_step(),
            None => Ok(SaslStep {
                token: None,
                done: true,
            }),
        }
    }
}
