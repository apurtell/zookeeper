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

//! Scripted overrides of the server behavior.
//!
//! A [`Rule`] matches inbound frames and replaces the normal answer with
//! a [`RuleAction`]. The server checks the rules in order, and the first
//! rule that matches and has budget left wins.

/// The frames that a rule can match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchKind {
    /// Only the `ConnectRequest` of a link.
    Connect,
    /// Only the request frames after the handshake.
    Request,
    /// Every frame.
    Any,
}

/// How the server answers a `ConnectRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeStyle {
    /// The normal answer: a new session, a resumed session or an expired
    /// session.
    Normal,
    /// The session-expired answer: session id 0 and timeout 0, then the
    /// server closes the link.
    Expired,
    /// The normal answer with this `read_only` flag.
    ReadOnly(bool),
    /// The normal answer without the `read_only` byte (36 bytes).
    Short,
    /// The normal answer with this negotiated timeout.
    Timeout(i32),
    /// An answer with these exact fields.
    Exact {
        /// The negotiated timeout.
        timeout: i32,
        /// The session id.
        session_id: i64,
        /// The password.
        passwd: Vec<u8>,
        /// The `read_only` flag.
        read_only: bool,
    },
}

/// The action of a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleAction {
    /// Handle the frame normally, and hold every reply bytes of it for
    /// this many milliseconds. Later replies on the link wait too, so the
    /// order stays the same.
    Delay(u64),
    /// Handle the frame normally, and send no reply.
    Drop,
    /// Do not handle the frame and send no reply.
    Ignore,
    /// Do not handle the frame. Send a reply header with this error code
    /// and no body.
    Error(i32),
    /// Do not handle the frame. Close the link after the bytes that are
    /// already queued.
    Close,
    /// Handle the frame normally, then close the link after the reply.
    CloseAfterReply,
    /// Do not handle the frame. Reset the link at once and drop the queued
    /// bytes.
    Reset,
    /// Do not handle the frame. Send these raw bytes, with no frame header.
    Garbage(Vec<u8>),
    /// Expire the session of the link, then close the link.
    ExpireSession,
    /// Answer a `ConnectRequest` in this style.
    Handshake(HandshakeStyle),
}

/// A rule: a frame matcher, a budget and an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub(crate) kind: MatchKind,
    pub(crate) op: Option<i32>,
    pub(crate) path: Option<Vec<u8>>,
    pub(crate) xid: Option<i32>,
    pub(crate) frame: Option<u64>,
    pub(crate) conn: Option<u64>,
    pub(crate) skip: u32,
    pub(crate) times: Option<u32>,
    pub(crate) action: RuleAction,
}

impl Rule {
    fn of(kind: MatchKind) -> Self {
        Self {
            kind,
            op: None,
            path: None,
            xid: None,
            frame: None,
            conn: None,
            skip: 0,
            times: None,
            action: RuleAction::Drop,
        }
    }

    /// Matches the request frames after the handshake.
    #[must_use]
    pub fn on_request() -> Self {
        Self::of(MatchKind::Request)
    }

    /// Matches the `ConnectRequest` frames.
    #[must_use]
    pub fn on_connect() -> Self {
        Self::of(MatchKind::Connect)
    }

    /// Matches every frame.
    #[must_use]
    pub fn on_any() -> Self {
        Self::of(MatchKind::Any)
    }

    /// Closes each link right after the server answers its `n`-th frame.
    /// The `ConnectRequest` is frame 1. The value 0 acts as 1.
    #[must_use]
    pub fn close_after(n: u64) -> Self {
        Self::on_any()
            .frame(n.saturating_sub(1))
            .then(RuleAction::CloseAfterReply)
    }

    /// Matches only this request type.
    #[must_use]
    pub const fn op(mut self, op: i32) -> Self {
        self.op = Some(op);
        self
    }

    /// Matches only requests whose first field is this path, as the server
    /// receives it.
    #[must_use]
    pub fn path(mut self, path: &str) -> Self {
        self.path = Some(path.as_bytes().to_vec());
        self
    }

    /// Matches only this xid.
    #[must_use]
    pub const fn xid(mut self, xid: i32) -> Self {
        self.xid = Some(xid);
        self
    }

    /// Matches only the frame with this index on its link. The
    /// `ConnectRequest` has index 0.
    #[must_use]
    pub const fn frame(mut self, index: u64) -> Self {
        self.frame = Some(index);
        self
    }

    /// Matches only the link with this ordinal. The first link of the
    /// server has ordinal 0.
    #[must_use]
    pub const fn conn(mut self, ordinal: u64) -> Self {
        self.conn = Some(ordinal);
        self
    }

    /// Lets this many matches pass before the rule acts.
    #[must_use]
    pub const fn skip(mut self, n: u32) -> Self {
        self.skip = n;
        self
    }

    /// Limits the rule to this many actions.
    #[must_use]
    pub const fn times(mut self, n: u32) -> Self {
        self.times = Some(n);
        self
    }

    /// Limits the rule to one action.
    #[must_use]
    pub const fn once(self) -> Self {
        self.times(1)
    }

    /// Sets the action.
    #[must_use]
    pub fn then(mut self, action: RuleAction) -> Self {
        self.action = action;
        self
    }

    /// Returns the action.
    #[must_use]
    pub const fn action(&self) -> &RuleAction {
        &self.action
    }
}

/// The facts of one inbound frame that a rule can match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameFacts<'a> {
    pub(crate) connect: bool,
    pub(crate) op: i32,
    pub(crate) xid: i32,
    pub(crate) path: Option<&'a [u8]>,
    pub(crate) frame: u64,
    pub(crate) conn: u64,
}

/// A rule and its use count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuleState {
    pub(crate) rule: Rule,
    pub(crate) matched: u32,
    pub(crate) fired: u32,
}

impl RuleState {
    pub(crate) const fn new(rule: Rule) -> Self {
        Self {
            rule,
            matched: 0,
            fired: 0,
        }
    }

    fn matches(&self, f: &FrameFacts<'_>) -> bool {
        let r = &self.rule;
        let kind_ok = match r.kind {
            MatchKind::Connect => f.connect,
            MatchKind::Request => !f.connect,
            MatchKind::Any => true,
        };
        kind_ok
            && r.op.is_none_or(|o| !f.connect && o == f.op)
            && r.xid.is_none_or(|x| !f.connect && x == f.xid)
            && r.path
                .as_deref()
                .is_none_or(|p| f.path.is_some_and(|fp| fp == p))
            && r.frame.is_none_or(|n| n == f.frame)
            && r.conn.is_none_or(|c| c == f.conn)
    }

    /// Counts a match and returns the action when the rule acts.
    pub(crate) fn consider(&mut self, f: &FrameFacts<'_>) -> Option<RuleAction> {
        if !self.matches(f) {
            return None;
        }
        if self.rule.times.is_some_and(|t| self.fired >= t) {
            return None;
        }
        self.matched = self.matched.saturating_add(1);
        if self.matched <= self.rule.skip {
            return None;
        }
        self.fired = self.fired.saturating_add(1);
        Some(self.rule.action.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(connect: bool, op: i32, frame: u64) -> FrameFacts<'static> {
        FrameFacts {
            connect,
            op,
            xid: 1,
            path: Some(b"/a"),
            frame,
            conn: 0,
        }
    }

    #[test]
    fn skip_and_times() {
        let mut s = RuleState::new(
            Rule::on_request()
                .op(4)
                .skip(1)
                .once()
                .then(RuleAction::Drop),
        );
        assert_eq!(s.consider(&facts(false, 4, 1)), None);
        assert_eq!(s.consider(&facts(false, 4, 2)), Some(RuleAction::Drop));
        assert_eq!(s.consider(&facts(false, 4, 3)), None);
        assert_eq!(s.consider(&facts(false, 5, 3)), None);
    }

    #[test]
    fn kinds_and_close_after() {
        let mut c = RuleState::new(Rule::on_connect().then(RuleAction::Reset));
        assert_eq!(c.consider(&facts(false, 4, 0)), None);
        assert_eq!(c.consider(&facts(true, 0, 0)), Some(RuleAction::Reset));
        let mut a = RuleState::new(Rule::close_after(2));
        assert_eq!(a.consider(&facts(true, 0, 0)), None);
        assert_eq!(
            a.consider(&facts(false, 4, 1)),
            Some(RuleAction::CloseAfterReply)
        );
        let mut p = RuleState::new(Rule::on_request().path("/b"));
        assert_eq!(p.consider(&facts(false, 4, 1)), None);
    }
}
