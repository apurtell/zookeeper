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

//! The token types of the test kit.
//!
//! The completion and auth tokens have no `Clone`, so the type system
//! keeps them linear: each token enters the core once and leaves it once.
//! The test keeps a [`Ticket`] or an [`AuthTicket`], which is a copyable
//! name of the same identity. The recorder uses the ticket to check
//! exactly-once delivery.

use zk_proto::Tokens;

/// The [`Tokens`] implementation of the test kit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TestTokens {}

impl Tokens for TestTokens {
    type Completion = CompletionId;
    type Watcher = WatcherId;
    type Auth = AuthId;
}

/// The completion token of one request. It has no `Clone`.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct CompletionId(u64);

impl CompletionId {
    /// Makes a token with this identity.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the identity.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.0
    }

    /// Returns the ticket of the token.
    #[must_use]
    pub const fn ticket(&self) -> Ticket {
        Ticket(self.0)
    }
}

/// The copyable name of a completion token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ticket(pub u64);

/// The completion token of one `add_auth` call. It has no `Clone`.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AuthId(u64);

impl AuthId {
    /// Makes a token with this identity.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the identity.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.0
    }

    /// Returns the ticket of the token.
    #[must_use]
    pub const fn ticket(&self) -> AuthTicket {
        AuthTicket(self.0)
    }
}

/// The copyable name of an auth token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthTicket(pub u64);

/// A watcher identity, as the C `(watcher_fn, context)` pair.
///
/// Equality is the deduplication relation of the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WatcherId {
    /// The identity of the callback function.
    pub fn_id: u32,
    /// The identity of the callback context.
    pub ctx_id: u32,
}

impl WatcherId {
    /// Makes a watcher identity.
    #[must_use]
    pub const fn new(fn_id: u32, ctx_id: u32) -> Self {
        Self { fn_id, ctx_id }
    }
}

/// Makes tokens with unique identities, in increasing order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TokenMint {
    next: u64,
}

impl Default for TokenMint {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenMint {
    /// Makes a mint whose first identity is 1.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    fn take(&mut self) -> u64 {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        id
    }

    /// Makes a completion token and its ticket.
    pub fn completion(&mut self) -> (CompletionId, Ticket) {
        let id = self.take();
        (CompletionId(id), Ticket(id))
    }

    /// Makes an auth token and its ticket.
    pub fn auth(&mut self) -> (AuthId, AuthTicket) {
        let id = self.take();
        (AuthId(id), AuthTicket(id))
    }
}
