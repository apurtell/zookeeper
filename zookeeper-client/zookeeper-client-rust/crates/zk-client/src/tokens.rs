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

//! `NativeTokens`: the `zk_proto::Tokens` implementation.
//!
//! A completion token owns the result slot of one request. A watcher
//! token is a `WatchId`, unique per client, so proto never merges two
//! native watchers. An auth token owns the slot of one `add_auth` call.
//!
//! A token that drops with no fill closes its slot. The receiver then
//! sees the terminal error of the client. Thus no future waits forever
//! when the core drops a token.

use std::sync::Arc;
use std::time::Instant;

use crate::observe::OpKind;
use crate::slot::Slot;

/// The raw result of a request, as the core gives it.
pub(crate) use zk_proto::OpResult as RawResult;

/// The token types of the native client.
#[derive(Debug)]
pub(crate) struct NativeTokens;

impl zk_proto::Tokens for NativeTokens {
    type Completion = NativeCompletion;
    type Watcher = WatchId;
    type Auth = AuthToken;
}

/// The identity of one native watcher. It is unique per client and is
/// never reused.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct WatchId(pub(crate) u64);

/// The completion of one request.
#[derive(Debug)]
pub(crate) enum NativeCompletion {
    /// A result that a receiver waits for.
    Reply(ReplyToken),
    /// A result that nobody waits for: the `RemoveWatches` request that
    /// a watcher drop sends.
    Discard,
    /// A config read of the follower of `update_servers_from_config`.
    /// The router gives the result to the follower.
    Follow,
}

/// The completion of a request with a receiver.
#[derive(Debug)]
pub(crate) struct ReplyToken {
    /// The slot. `None` after `complete`.
    slot: Option<Arc<Slot<RawResult>>>,
    /// The watcher that this request arms, if any. The router removes
    /// its sink when the receiver is gone.
    pub(crate) watch: Option<WatchId>,
    /// The operation, for `Metrics::request_completed`.
    pub(crate) kind: OpKind,
    /// The submit time, for the request latency.
    pub(crate) started: Instant,
}

impl ReplyToken {
    /// Makes a token over `slot`.
    pub(crate) fn new(slot: Arc<Slot<RawResult>>, watch: Option<WatchId>, kind: OpKind) -> Self {
        Self {
            slot: Some(slot),
            watch,
            kind,
            started: Instant::now(),
        }
    }

    /// Fills the slot with `r`. It returns the result of `Slot::fill`:
    /// `Ok(counted)`, or `Err(r)` when the receiver is gone.
    pub(crate) fn complete(mut self, r: RawResult, count: bool) -> Result<bool, RawResult> {
        match self.slot.take() {
            Some(slot) => slot.fill(r, count),
            None => Err(r),
        }
    }
}

impl Drop for ReplyToken {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            slot.close();
        }
    }
}

/// The completion of one `add_auth` call. The result code goes into a
/// `RawResult` slot, so `add_auth` uses the same future as every other
/// request.
#[derive(Debug)]
pub(crate) struct AuthToken {
    /// The slot of the result. `None` after `complete`.
    slot: Option<Arc<Slot<RawResult>>>,
    /// The call time, for the request latency.
    pub(crate) started: Instant,
}

impl AuthToken {
    /// Makes a token over `slot`.
    pub(crate) fn new(slot: Arc<Slot<RawResult>>) -> Self {
        Self {
            slot: Some(slot),
            started: Instant::now(),
        }
    }

    /// Fills the slot with the result of `rc`: `Reply::Void` for 0, else
    /// no reply. The return value is as for [`ReplyToken::complete`].
    pub(crate) fn complete(mut self, rc: i32, count: bool) -> Result<bool, RawResult> {
        let r = RawResult {
            rc,
            zxid: 0,
            origin: zk_proto::Origin::Reply,
            reply: (rc == 0).then_some(zk_proto::Reply::Void),
        };
        match self.slot.take() {
            Some(slot) => slot.fill(r, count),
            None => Err(r),
        }
    }
}

impl Drop for AuthToken {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            slot.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot::Taken;

    fn void() -> RawResult {
        RawResult {
            rc: 0,
            zxid: 0,
            origin: zk_proto::Origin::Reply,
            reply: None,
        }
    }

    #[test]
    fn a_dropped_token_closes_its_slot() {
        let slot = Slot::new();
        drop(ReplyToken::new(Arc::clone(&slot), None, OpKind::Sync));
        assert!(matches!(slot.try_take(), Some(Taken::Closed)));
        let slot = Slot::new();
        drop(AuthToken::new(Arc::clone(&slot)));
        assert!(matches!(slot.try_take(), Some(Taken::Closed)));
    }

    #[test]
    fn complete_fills_the_slot() {
        let slot = Slot::new();
        let t = ReplyToken::new(Arc::clone(&slot), None, OpKind::GetData);
        assert!(matches!(t.complete(void(), true), Ok(true)));
        assert!(matches!(
            slot.try_take(),
            Some(Taken::Value { counted: true, .. })
        ));
        let slot = Slot::new();
        assert!(matches!(
            AuthToken::new(Arc::clone(&slot)).complete(-115, false),
            Ok(false)
        ));
        assert!(
            matches!(slot.try_take(), Some(Taken::Value { v, .. }) if v.rc == -115 && v.reply.is_none())
        );
    }
}
