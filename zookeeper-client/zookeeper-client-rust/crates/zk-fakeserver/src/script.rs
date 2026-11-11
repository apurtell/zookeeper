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

//! Fault rules.
//!
//! A [`Script`] is an ordered list of [`Rule`]s. For each client frame the
//! server takes the first rule that matches and runs its actions. When no
//! rule matches, the model handles the frame. A rule that has no action
//! that answers the frame also lets the model handle it after its other
//! actions, so `Rule::on_request().op(GET_DATA).then(Action::Delay(..))`
//! delays the normal reply.

use std::time::Duration;

use crate::config::{Chunking, HandshakeStyle};
use crate::rng::SplitMix64;

/// The kind of frame that a rule looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trigger {
    /// The connect request, the first frame of a connection.
    Connect,
    /// A request after the handshake.
    Request,
    /// Both kinds.
    Any,
}

/// A frame that breaks the length-prefix framing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Malformed {
    /// A length prefix of zero.
    ZeroLength,
    /// A negative length prefix.
    NegativeLength(i32),
    /// A length prefix with fewer body bytes after it. The client then
    /// waits for the rest.
    Truncated {
        /// The length in the prefix.
        declared: i32,
        /// The body bytes that follow the prefix.
        body: Vec<u8>,
    },
    /// A frame with a body that is too short for a reply header.
    ShortHeader(Vec<u8>),
}

impl Malformed {
    /// Returns the bytes on the wire.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::ZeroLength => 0i32.to_be_bytes().to_vec(),
            Self::NegativeLength(n) => n.to_be_bytes().to_vec(),
            Self::Truncated { declared, body } => {
                let mut out = declared.to_be_bytes().to_vec();
                out.extend_from_slice(body);
                out
            }
            Self::ShortHeader(body) => {
                let mut out = Vec::new();
                zk_jute::encode_frame(body, &mut out);
                out
            }
        }
    }
}

/// One step of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The model handles the frame and sends its reply.
    Model,
    /// Wait before the next output of this connection. Later output also
    /// waits, so replies keep their order.
    Delay(Duration),
    /// The model handles the frame, and its reply is not sent. Watch events
    /// are still sent.
    DropReply,
    /// The frame is not handled and nothing is sent.
    Ignore,
    /// Send a reply header with this error and no body. The model does not
    /// handle the frame.
    Reply {
        /// The error code.
        err: i32,
    },
    /// Send a reply header with this error and this body. The model does
    /// not handle the frame.
    ReplyWith {
        /// The error code.
        err: i32,
        /// The body after the header.
        body: Vec<u8>,
    },
    /// The model handles the frame, and only the header of its reply is
    /// sent.
    HeaderOnly,
    /// The model handles the frame, and its reply has this xid.
    RewriteXid(i32),
    /// The model handles the frame, and its reply has this error. The body
    /// stays.
    RewriteErr(i32),
    /// The model handles the frame, and only the first bytes of the framed
    /// reply are sent. The length prefix counts.
    TruncateReply(usize),
    /// Send a reply that the client did not ask for, before the normal
    /// handling.
    Unsolicited {
        /// The xid.
        xid: i32,
        /// The zxid.
        zxid: i64,
        /// The error code.
        err: i32,
        /// The body after the header.
        body: Vec<u8>,
    },
    /// Send a watch event to this connection.
    Notify {
        /// The event type, for example 3 for NodeDataChanged.
        event_type: i32,
        /// The keeper state, 3 for SyncConnected.
        state: i32,
        /// The path.
        path: String,
    },
    /// Send a frame with this body.
    SendFrame(Vec<u8>),
    /// Send these bytes with no framing.
    SendRaw(Vec<u8>),
    /// Send a bad frame.
    Malformed(Malformed),
    /// Close the connection after the output before this action. The model
    /// does not handle the frame unless an earlier action did.
    Close,
    /// Stop all output and input processing. The socket stays open.
    Stall,
    /// Expire the session of this connection and close the connection.
    ExpireSession,
    /// Answer an auth request with `ZAUTHFAILED` and close the connection.
    RejectAuth,
    /// Change the write chunking of this connection.
    Chunking(Chunking),
    /// Connect only: answer the handshake in this form. `split_at` cuts the
    /// response into two writes at that byte, the length prefix included.
    Handshake {
        /// The body form.
        style: HandshakeStyle,
        /// The cut point.
        split_at: Option<usize>,
    },
    /// Connect only: answer as for an expired session, then close.
    ExpiredHandshake,
}

impl Action {
    /// Returns true when the action answers the frame, so the model does
    /// not run after the rule.
    pub(crate) const fn answers(&self) -> bool {
        !matches!(
            self,
            Self::Delay(_)
                | Self::Unsolicited { .. }
                | Self::Notify { .. }
                | Self::SendFrame(_)
                | Self::SendRaw(_)
                | Self::Malformed(_)
                | Self::Chunking(_)
        )
    }
}

/// A fault rule: a frame pattern and the actions for a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The frame kind.
    pub trigger: Trigger,
    /// The 1-based connection number on this listener.
    pub conn: Option<u64>,
    /// The 1-based request number on the connection. The connect request
    /// is number 0.
    pub frame: Option<u64>,
    /// The opcode.
    pub op: Option<i32>,
    /// The exact path.
    pub path: Option<String>,
    /// A path prefix.
    pub path_prefix: Option<String>,
    /// The xid.
    pub xid: Option<i32>,
    /// The number of matches to let pass before the rule fires.
    pub skip: u32,
    /// The number of times the rule fires. `None` means no limit.
    pub times: Option<u32>,
    /// The chance that a match fires, as `numerator / denominator`.
    pub chance: Option<(u32, u32)>,
    /// The actions.
    pub actions: Vec<Action>,
    seen: u32,
    fired: u32,
}

impl Rule {
    fn new(trigger: Trigger) -> Self {
        Self {
            trigger,
            conn: None,
            frame: None,
            op: None,
            path: None,
            path_prefix: None,
            xid: None,
            skip: 0,
            times: None,
            chance: None,
            actions: Vec::new(),
            seen: 0,
            fired: 0,
        }
    }

    /// A rule for connect requests.
    #[must_use]
    pub fn on_connect() -> Self {
        Self::new(Trigger::Connect)
    }

    /// A rule for requests after the handshake.
    #[must_use]
    pub fn on_request() -> Self {
        Self::new(Trigger::Request)
    }

    /// A rule for every frame.
    #[must_use]
    pub fn on_any() -> Self {
        Self::new(Trigger::Any)
    }

    /// Matches only the n-th connection, from 1.
    #[must_use]
    pub const fn conn(mut self, n: u64) -> Self {
        self.conn = Some(n);
        self
    }

    /// Matches only the n-th request of a connection, from 1.
    #[must_use]
    pub const fn frame(mut self, n: u64) -> Self {
        self.frame = Some(n);
        self
    }

    /// Matches only this opcode.
    #[must_use]
    pub const fn op(mut self, op: i32) -> Self {
        self.op = Some(op);
        self
    }

    /// Matches only this path.
    #[must_use]
    pub fn path(mut self, path: &str) -> Self {
        self.path = Some(path.to_owned());
        self
    }

    /// Matches only paths with this prefix.
    #[must_use]
    pub fn path_prefix(mut self, prefix: &str) -> Self {
        self.path_prefix = Some(prefix.to_owned());
        self
    }

    /// Matches only this xid.
    #[must_use]
    pub const fn xid(mut self, xid: i32) -> Self {
        self.xid = Some(xid);
        self
    }

    /// Lets the first `n` matches pass.
    #[must_use]
    pub const fn skip(mut self, n: u32) -> Self {
        self.skip = n;
        self
    }

    /// Fires at most `n` times.
    #[must_use]
    pub const fn times(mut self, n: u32) -> Self {
        self.times = Some(n);
        self
    }

    /// Fires once.
    #[must_use]
    pub const fn once(self) -> Self {
        self.times(1)
    }

    /// Fires on a match with the chance `num / den`, from the seeded
    /// generator.
    #[must_use]
    pub const fn chance(mut self, num: u32, den: u32) -> Self {
        self.chance = Some((num, den));
        self
    }

    /// Adds an action.
    #[must_use]
    pub fn then(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Returns the number of times the rule fired.
    #[must_use]
    pub const fn fired(&self) -> u32 {
        self.fired
    }

    fn matches(&self, f: &FrameView<'_>) -> bool {
        let kind_ok = match self.trigger {
            Trigger::Any => true,
            Trigger::Connect => f.connect,
            Trigger::Request => !f.connect,
        };
        kind_ok
            && self.conn.is_none_or(|c| c == f.conn)
            && self.frame.is_none_or(|n| n == f.frame)
            && self.op.is_none_or(|op| Some(op) == f.op)
            && self.xid.is_none_or(|x| Some(x) == f.xid)
            && self.path.as_deref().is_none_or(|p| Some(p) == f.path)
            && self
                .path_prefix
                .as_deref()
                .is_none_or(|p| f.path.is_some_and(|fp| fp.starts_with(p)))
    }
}

/// The facts about a frame that rules match on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameView<'a> {
    pub(crate) connect: bool,
    pub(crate) conn: u64,
    pub(crate) frame: u64,
    pub(crate) op: Option<i32>,
    pub(crate) xid: Option<i32>,
    pub(crate) path: Option<&'a str>,
}

/// An ordered list of rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    rules: Vec<Rule>,
}

impl Script {
    /// Creates an empty script.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds a rule at the end.
    #[must_use]
    pub fn rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Adds a rule at the end.
    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Removes every rule.
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Returns the rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Finds the rule for a frame and counts the match. It returns the
    /// rule index and a copy of its actions.
    pub(crate) fn decide(
        &mut self,
        f: &FrameView<'_>,
        rng: &mut SplitMix64,
    ) -> Option<(usize, Vec<Action>)> {
        for (i, rule) in self.rules.iter_mut().enumerate() {
            if rule.times.is_some_and(|t| rule.fired >= t) || !rule.matches(f) {
                continue;
            }
            rule.seen = rule.seen.saturating_add(1);
            if rule.seen <= rule.skip {
                continue;
            }
            if let Some((num, den)) = rule.chance {
                if rng.below(u64::from(den)) >= u64::from(num) {
                    continue;
                }
            }
            rule.fired = rule.fired.saturating_add(1);
            return Some((i, rule.actions.clone()));
        }
        None
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
    use super::{Action, FrameView, Rule, Script};
    use crate::rng::SplitMix64;

    fn view(frame: u64, op: i32) -> FrameView<'static> {
        FrameView {
            connect: false,
            conn: 1,
            frame,
            op: Some(op),
            xid: Some(1),
            path: Some("/a/b"),
        }
    }

    #[test]
    fn skip_times_and_order() {
        let mut s = Script::new()
            .rule(Rule::on_request().op(4).skip(1).once().then(Action::Close))
            .rule(Rule::on_request().path_prefix("/a").then(Action::Ignore));
        let mut rng = SplitMix64::new(1);
        assert_eq!(s.decide(&view(1, 4), &mut rng).map(|d| d.0), Some(1));
        assert_eq!(s.decide(&view(2, 4), &mut rng).map(|d| d.0), Some(0));
        assert_eq!(s.decide(&view(3, 4), &mut rng).map(|d| d.0), Some(1));
        assert_eq!(s.rules()[0].fired(), 1);
    }

    #[test]
    fn connect_rules_do_not_match_requests() {
        let mut s = Script::new().rule(Rule::on_connect().then(Action::Close));
        let mut rng = SplitMix64::new(1);
        assert!(s.decide(&view(1, 4), &mut rng).is_none());
    }

    #[test]
    fn chance_is_seeded() {
        let run = |seed| {
            let mut s = Script::new().rule(Rule::on_any().chance(1, 2).then(Action::Ignore));
            let mut rng = SplitMix64::new(seed);
            (0..32)
                .map(|i| s.decide(&view(i, 4), &mut rng).is_some())
                .collect::<Vec<_>>()
        };
        assert_eq!(run(9), run(9));
    }
}
