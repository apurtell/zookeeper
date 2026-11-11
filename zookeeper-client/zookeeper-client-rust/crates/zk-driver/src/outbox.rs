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

//! The driver outbox: the ordered items of one driving call.
//!
//! The drop-in drivers never call application code. Each driving call
//! returns an [`Outbox`], and C runs the items after the Rust frames are
//! gone. The native drivers route the same items into zk-client.
//!
//! - [`pump`] moves the outputs of one proto call into the outbox, in
//!   proto order, and stops at a barrier.
//! - FIFO-bound outputs (`Completion{route: Queued}`, `Watch`, `Session`)
//!   go where the flavor puts them: mt stores them as publish entries,
//!   st puts them in the handle-local FIFO, and the native drivers keep
//!   them inline.
//! - Publish-on-take: when [`Outbox::next`] reaches a publish entry, it
//!   appends the item to the dispatch FIFO and goes on. C never sees a
//!   publish entry. So a log line that comes before the output in proto
//!   order is already out when the dispatch thread can see the output.
//!   A publish entry with no entry ahead goes to the FIFO in the pump.
//!   A pump on another thread thus cannot put a later result before it.
//! - The close mark: an mt close puts it after its last publish entry.
//!   When [`Outbox::next`] reaches it, the FIFO records that the close
//!   published all its results.
//! - [`Outbox::requeue`] gives back the untaken entries after a callback
//!   throws.
//! - mt: no publish entry follows an item in one outbox. An item can run
//!   a callback that closes the handle. The close then publishes the
//!   later results itself, before its close mark.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use zk_proto::{
    Connection, LogRecord, OpResult, Output, Route, SaslCall, State, Stopped, TerminateReason,
    Tokens, WatchedEvent,
};

use crate::host::{Discarded, HostLeaves};

/// Work that only C may do. zk-ffi turns each item into one `zkrs_item`.
pub enum Item<T: Tokens> {
    /// A log line. C emits it now, on this thread.
    Log(LogRecord),
    /// An operation result: async (st, native) or sync (`Direct`).
    Result {
        /// The completion token.
        token: T::Completion,
        /// The result.
        result: OpResult,
        /// The lines that C emits before the callback.
        delivery_logs: Vec<LogRecord>,
    },
    /// One `zoo_add_auth` completion.
    AuthResult {
        /// The auth token.
        token: T::Auth,
        /// The result code.
        rc: i32,
    },
    /// A node event.
    Watch {
        /// The event.
        event: WatchedEvent,
        /// The watchers, in delivery order.
        watchers: Vec<T::Watcher>,
        /// The lines that C emits before the callbacks.
        delivery_logs: Vec<LogRecord>,
    },
    /// A session event. C adds the path "".
    Session {
        /// The new state.
        state: State,
        /// The watchers, in delivery order.
        watchers: Vec<T::Watcher>,
        /// The lines that C emits before the callbacks.
        delivery_logs: Vec<LogRecord>,
    },
    /// Native only. It never reaches zk-ffi.
    WatchTerminated {
        /// The watchers.
        watchers: Vec<T::Watcher>,
        /// The reason.
        reason: TerminateReason,
    },
    /// C locks and unlocks `zh->auth_lock`. Always a barrier.
    AuthLockpoint,
    /// Cyrus work. C answers START and STEP with `zkrs_sasl_result`.
    Sasl(SaslItem),
    /// A thread join or detach (mt only). Always a barrier.
    Thread {
        /// Join or detach.
        op: ThreadOp,
        /// The thread.
        role: ThreadRole,
    },
}

impl<T: Tokens> std::fmt::Debug for Item<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Log(_) => "Log",
            Self::Result { .. } => "Result",
            Self::AuthResult { .. } => "AuthResult",
            Self::Watch { .. } => "Watch",
            Self::Session { .. } => "Session",
            Self::WatchTerminated { .. } => "WatchTerminated",
            Self::AuthLockpoint => "AuthLockpoint",
            Self::Sasl(_) => "Sasl",
            Self::Thread { .. } => "Thread",
        };
        f.write_str(kind)
    }
}

/// One proto SASL call, plus the addresses that START needs.
#[derive(Debug)]
pub struct SaslItem {
    /// The call.
    pub call: SaslCall,
    /// START only: (local, peer) from `getsockname` and `getpeername`.
    pub addrs: Option<(SocketAddr, SocketAddr)>,
}

/// The result of one driving step (`zkrs_step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// `ZKRS_DONE` with the legacy rc.
    Done(i32),
    /// `ZKRS_MORE`: C drains, then calls the resume entry.
    More,
    /// `ZKRS_RELEASE` (the final close ran): C frees `zhandle_t`.
    Release,
    /// `ZKRS_EXIT`: the library thread leaves its loop.
    Exit,
}

/// A thread operation of a `Thread` item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThreadOp {
    /// `pthread_join`.
    Join,
    /// `pthread_detach`.
    Detach,
}

/// A library thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThreadRole {
    /// The IO thread.
    Io,
    /// The dispatch (completion) thread.
    Dispatch,
}

/// The driver flavor. It decides where FIFO-bound outputs go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flavor {
    /// The mt drop-in: publish entries for the dispatch FIFO.
    Mt,
    /// The st drop-in: the handle-local FIFO.
    St,
    /// The native drivers: inline, routed in order by the IO side.
    Native,
}

/// The step that the next resume continues.
///
/// A step that returns `ZKRS_MORE` stores it in the outbox of the call.
/// `zkrs_resume` takes no role, so the flavor reads it to find the
/// suspended step. A nested call, such as `zookeeper_close` in a
/// callback, uses its own outbox, so each outbox names one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResumeAt {
    /// `zkrs_handle_new`: the init.
    Init,
    /// st `zookeeper_interest` (`zkrs_interest_resume`).
    Interest,
    /// st `zookeeper_process`.
    Process,
    /// The mt IO step (`zkrs_io_step`).
    IoStep,
    /// `zkrs_close` before the final close.
    Close,
    /// The final close.
    FinalClose,
    /// A drop-in `zoo_set_servers` call. The value names the run.
    SetServers(u64),
}

/// The dispatch FIFO of an mt handle, as the outbox sees it.
pub trait Publish<T: Tokens>: Send + Sync {
    /// Appends the item to the FIFO and notifies the dispatch thread.
    fn publish(&self, item: Item<T>);

    /// Records that a close published all its results, and notifies the
    /// dispatch thread. The dispatch thread can then exit. A
    /// FIFO with no dispatch thread ignores the mark.
    fn close_published(&self) {}
}

enum Entry<T: Tokens> {
    Item(Item<T>),
    Publish(Item<T>),
    ClosePublished,
}

/// The ordered items of one driving call.
pub struct Outbox<T: Tokens> {
    entries: VecDeque<Entry<T>>,
    /// The number of entries that C sees.
    items: usize,
    publish: Option<Arc<dyn Publish<T>>>,
    resume: Option<ResumeAt>,
    frame: Option<u64>,
}

/// The untaken entries of an outbox after a callback threw.
pub struct Requeued<T: Tokens> {
    entries: VecDeque<Entry<T>>,
    resume: Option<ResumeAt>,
    frame: Option<u64>,
}

impl<T: Tokens> Requeued<T> {
    /// Returns true when nothing was left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the step that the abandoned outbox was to resume.
    #[must_use]
    pub fn resume_at(&self) -> Option<ResumeAt> {
        self.resume
    }

    /// Returns the st driving call that the abandoned outbox belongs to.
    #[must_use]
    pub fn frame(&self) -> Option<u64> {
        self.frame
    }
}

impl<T: Tokens> Default for Outbox<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Tokens> Outbox<T> {
    /// Makes an empty outbox with no FIFO. Publish entries then stay
    /// ordinary items.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            items: 0,
            publish: None,
            resume: None,
            frame: None,
        }
    }

    /// Makes an empty outbox that publishes into the mt FIFO.
    #[must_use]
    pub fn with_publish(publish: Arc<dyn Publish<T>>) -> Self {
        Self {
            entries: VecDeque::new(),
            items: 0,
            publish: Some(publish),
            resume: None,
            frame: None,
        }
    }

    /// Stops the use of the FIFO for this outbox. Each FIFO-bound item
    /// becomes an ordinary item and keeps its place. The dispatch thread
    /// uses this after its loop, because no thread reads the FIFO then.
    pub(crate) fn deliver_here(&mut self) {
        self.publish = None;
        let mut moved = 0usize;
        self.entries = std::mem::take(&mut self.entries)
            .into_iter()
            .map(|entry| match entry {
                Entry::Publish(item) => {
                    moved = moved.saturating_add(1);
                    Entry::Item(item)
                }
                other => other,
            })
            .collect();
        self.items = self.items.saturating_add(moved);
    }

    /// Appends an item that C sees.
    pub fn push(&mut self, item: Item<T>) {
        self.entries.push_back(Entry::Item(item));
        self.items = self.items.saturating_add(1);
    }

    /// Appends a FIFO-bound item. With no FIFO it is an ordinary item.
    ///
    /// With a FIFO and no entry ahead, the item goes to the FIFO at once.
    /// C then sees no difference, because its first take would publish
    /// the item first. A later pump of another thread cannot then pass
    /// it. The caller holds the core lock, and the FIFO lock is a leaf.
    pub fn push_publish(&mut self, item: Item<T>) {
        match &self.publish {
            Some(p) if self.entries.is_empty() => p.publish(item),
            Some(_) => self.entries.push_back(Entry::Publish(item)),
            None => self.push(item),
        }
    }

    /// Appends the close mark. The mark goes to the FIFO when
    /// the drain reaches it, so every earlier publish entry is in the FIFO
    /// first. C never sees the mark. With no FIFO it adds nothing.
    pub(crate) fn push_close_published(&mut self) {
        if self.publish.is_some() {
            self.entries.push_back(Entry::ClosePublished);
        }
    }

    /// Appends items in order (the dispatch batch, the st local FIFO).
    pub fn extend_items<I: IntoIterator<Item = Item<T>>>(&mut self, items: I) {
        for item in items {
            self.push(item);
        }
    }

    /// Returns true when the outbox holds no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when an entry that C sees waits.
    #[must_use]
    pub(crate) fn holds_items(&self) -> bool {
        self.items > 0
    }

    /// Returns true when a LOG item waits. The before-blocking barrier
    /// uses it, so each line reaches the log before a wait.
    #[must_use]
    pub fn has_pending_logs(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e, Entry::Item(Item::Log(_))))
    }

    /// Takes the next item for C, with publish-on-take.
    ///
    /// Each publish entry and close mark before the next item goes to
    /// the FIFO first.
    pub fn pop(&mut self) -> Option<Item<T>> {
        while let Some(entry) = self.entries.pop_front() {
            match entry {
                Entry::Item(item) => {
                    self.items = self.items.saturating_sub(1);
                    return Some(item);
                }
                Entry::Publish(item) => match &self.publish {
                    Some(p) => p.publish(item),
                    None => {
                        self.items = self.items.saturating_sub(1);
                        return Some(item);
                    }
                },
                Entry::ClosePublished => self.mark_close_published(),
            }
        }
        None
    }

    /// Gives the close mark to the FIFO. A mark in an outbox with no FIFO
    /// has no effect.
    fn mark_close_published(&self) {
        if let Some(p) = &self.publish {
            p.close_published();
        }
    }

    /// Stores the step that the next resume continues.
    pub fn set_resume(&mut self, at: ResumeAt) {
        self.resume = Some(at);
    }

    /// Returns the stored resume step.
    #[must_use]
    pub fn resume_at(&self) -> Option<ResumeAt> {
        self.resume
    }

    /// Takes the stored resume step. The resume entry calls it first.
    pub fn take_resume(&mut self) -> Option<ResumeAt> {
        self.resume.take()
    }

    /// Records the st driving call that owns this outbox. The resume and
    /// the requeue of the outbox then find the state of that call.
    pub fn set_frame(&mut self, id: u64) {
        self.frame = Some(id);
    }

    /// Returns the st driving call that owns this outbox, if any.
    #[must_use]
    pub fn frame(&self) -> Option<u64> {
        self.frame
    }

    /// Gives back the untaken entries and the resume step, in order
    /// (`zkrs_outbox_requeue`).
    pub fn requeue(&mut self) -> Requeued<T> {
        self.items = 0;
        Requeued {
            entries: std::mem::take(&mut self.entries),
            resume: self.resume.take(),
            frame: self.frame.take(),
        }
    }

    /// Puts requeued entries in front of the current entries. The next
    /// driving call delivers them first. The driving call keeps its own
    /// resume step. The flavor `requeue` reads the step of the requeued
    /// outbox first, and gives a stopped close or `zoo_set_servers` call
    /// to a new owner.
    pub fn restore(&mut self, mut requeued: Requeued<T>) {
        // With no FIFO a publish entry is an item that C sees.
        let local = self.publish.is_none();
        let restored = requeued
            .entries
            .iter()
            .filter(|e| match e {
                Entry::Item(_) => true,
                Entry::Publish(_) => local,
                Entry::ClosePublished => false,
            })
            .count();
        self.items = self.items.saturating_add(restored);
        requeued.entries.append(&mut self.entries);
        self.entries = requeued.entries;
    }

    /// Ends the outbox (`zkrs_outbox_finish`). Publish entries and the
    /// close mark go to the FIFO. Items that C did not take go to
    /// `discard_token`.
    pub fn finish(&mut self, host: &dyn HostLeaves<T>) {
        self.items = 0;
        while let Some(entry) = self.entries.pop_front() {
            match entry {
                Entry::Publish(item) => match &self.publish {
                    Some(p) => p.publish(item),
                    None => discard_item(host, item),
                },
                Entry::Item(item) => discard_item(host, item),
                Entry::ClosePublished => self.mark_close_published(),
            }
        }
    }
}

impl<T: Tokens> Iterator for Outbox<T> {
    type Item = Item<T>;

    /// The same as [`Outbox::pop`]. The native drivers route with it.
    fn next(&mut self) -> Option<Item<T>> {
        self.pop()
    }
}

/// Gives every token of an item to `discard_token`.
pub fn discard_item<T: Tokens>(host: &dyn HostLeaves<T>, item: Item<T>) {
    match item {
        Item::Result { token, .. } => host.discard_token(Discarded::Completion(token)),
        Item::AuthResult { token, .. } => host.discard_token(Discarded::Auth(token)),
        Item::Watch { watchers, .. }
        | Item::Session { watchers, .. }
        | Item::WatchTerminated { watchers, .. } => {
            for w in watchers {
                host.discard_token(Discarded::Watcher(w));
            }
        }
        Item::Log(_) | Item::AuthLockpoint | Item::Sasl(_) | Item::Thread { .. } => {}
    }
}

/// Where [`pump`] puts FIFO-bound outputs.
pub enum FifoBound<'a, T: Tokens> {
    /// mt: publish entries of the outbox.
    Publish,
    /// st: the handle-local FIFO. A `Session` or `DrainPoint` barrier
    /// moves the whole FIFO into the outbox.
    Local(&'a mut VecDeque<Item<T>>),
    /// Native: inline items.
    Inline,
}

/// The end of one [`pump`].
#[derive(Debug, PartialEq, Eq)]
pub enum Pumped {
    /// Proto has no more outputs.
    Drained,
    /// Proto stopped at a barrier. The step returns `ZKRS_MORE`. The
    /// driver keeps the handle and calls `Connection::resume` with it in
    /// the next resume. `None` is a barrier with no stopped stage.
    Barrier(Option<Stopped>),
}

/// Moves the outputs of proto into the outbox, in order.
///
/// - `Completion{Direct}` becomes a `Result` item (a barrier).
/// - `Completion{Queued}`, `Watch` and `Session` go to `bound`.
/// - `Auth` becomes one `AuthResult` item per token. With
///   [`FifoBound::Publish`] the pump then stops, so the later outputs
///   stay in proto until the next pump. C runs the auth callback before
///   it decodes the next reply.
/// - `ClientId` goes to the `store_client_id` leaf. It makes no item.
/// - `Log`, `AuthLockpoint` and `WatchTerminated` become items.
/// - `DrainPoint` and a barrier `Session` move the st local FIFO into the
///   outbox.
///
/// It stops when `poll_output` gives `None`, or after the mt auth items.
/// With [`FifoBound::Publish`] it also stops when the outbox holds an
/// item and proto has more outputs. C runs that item before the dispatch
/// thread can see a later result. A callback of the item can close the
/// handle on the IO thread. The dispatch thread then exits at the close
/// mark. So each later result must stay in proto, and the close
/// publishes it before the mark.
///
/// The result is [`Pumped::Barrier`] after a stopped stage, a barrier
/// output, or an mt stop. The next pump continues after an mt stop.
pub fn pump<T: Tokens>(
    conn: &mut Connection<T>,
    ob: &mut Outbox<T>,
    mut bound: FifoBound<'_, T>,
    host: &dyn HostLeaves<T>,
) -> Pumped {
    let mut barrier = false;
    let mut drain_local = false;
    let publish = matches!(bound, FifoBound::Publish);
    loop {
        if publish && ob.holds_items() && conn.has_output() {
            barrier = true;
            break;
        }
        let Some(out) = conn.poll_output() else {
            break;
        };
        barrier = out.is_barrier();
        drain_local = false;
        match out {
            Output::Completion {
                token,
                route,
                result,
                delivery_logs,
            } => {
                let item = Item::Result {
                    token,
                    result,
                    delivery_logs,
                };
                match route {
                    Route::Direct => ob.push(item),
                    Route::Queued => to_bound(ob, &mut bound, item),
                }
            }
            Output::Watch {
                event,
                watchers,
                delivery_logs,
            } => to_bound(
                ob,
                &mut bound,
                Item::Watch {
                    event,
                    watchers,
                    delivery_logs,
                },
            ),
            Output::Session {
                state,
                watchers,
                barrier: is_barrier,
                delivery_logs,
            } => {
                to_bound(
                    ob,
                    &mut bound,
                    Item::Session {
                        state,
                        watchers,
                        delivery_logs,
                    },
                );
                drain_local = is_barrier;
            }
            Output::Auth { tokens, rc, .. } => {
                let stop = !tokens.is_empty() && publish;
                for token in tokens {
                    ob.push(Item::AuthResult { token, rc });
                }
                // mt: the auth callback runs on the calling thread and can
                // close the handle. The later outputs stay in proto, so
                // that close publishes them before the close mark.
                if stop {
                    barrier = true;
                    break;
                }
            }
            Output::AuthLockpoint => ob.push(Item::AuthLockpoint),
            Output::ClientId(id) => host.store_client_id(&id),
            Output::WatchTerminated { watchers, reason } => {
                ob.push(Item::WatchTerminated { watchers, reason });
            }
            Output::Log(rec) => ob.push(Item::Log(rec)),
            Output::DrainPoint => {
                barrier = true;
                drain_local = true;
            }
        }
    }
    if drain_local {
        if let FifoBound::Local(fifo) = &mut bound {
            ob.extend_items(fifo.drain(..));
        }
    }
    match conn.take_stopped() {
        Some(stopped) => Pumped::Barrier(Some(stopped)),
        None if barrier => Pumped::Barrier(None),
        None => Pumped::Drained,
    }
}

fn to_bound<T: Tokens>(ob: &mut Outbox<T>, bound: &mut FifoBound<'_, T>, item: Item<T>) {
    match bound {
        FifoBound::Publish => ob.push_publish(item),
        FifoBound::Local(fifo) => fifo.push_back(item),
        FifoBound::Inline => ob.push(item),
    }
}

// The close mark is internal to the crate, so its tests stay here.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::sync::Arc;

    use zk_proto::{LogRecord, LogSite};
    use zk_testkit::tokens::TestTokens;

    use super::*;
    use crate::sync::Mutex;
    use crate::testutil::TestHost;

    #[derive(Default)]
    struct Fifo(Mutex<Vec<Item<TestTokens>>>);

    impl Publish<TestTokens> for Fifo {
        fn publish(&self, item: Item<TestTokens>) {
            self.0.lock_owner().push(item);
        }
    }

    /// Records the FIFO length at each close mark.
    #[derive(Default)]
    struct MarkFifo {
        items: Mutex<Vec<Item<TestTokens>>>,
        marks: Mutex<Vec<usize>>,
    }

    impl Publish<TestTokens> for MarkFifo {
        fn publish(&self, item: Item<TestTokens>) {
            self.items.lock_owner().push(item);
        }

        fn close_published(&self) {
            let n = self.items.lock_owner().len();
            self.marks.lock_owner().push(n);
        }
    }

    fn join_io() -> Item<TestTokens> {
        Item::Thread {
            op: ThreadOp::Join,
            role: ThreadRole::Io,
        }
    }

    fn log() -> Item<TestTokens> {
        Item::Log(LogRecord {
            site: LogSite::TcpNoDelay,
            level: LogSite::TcpNoDelay.level(),
            args: Vec::new(),
        })
    }

    #[test]
    fn the_close_mark_follows_the_earlier_publish_entries() {
        let fifo = Arc::new(MarkFifo::default());
        let mut ob = Outbox::with_publish(Arc::clone(&fifo) as Arc<dyn Publish<TestTokens>>);
        ob.push_publish(Item::AuthLockpoint);
        ob.push_publish(Item::AuthLockpoint);
        ob.push_close_published();
        ob.push(join_io());
        // C never sees the mark. The mark comes after both publish
        // entries and before the thread item.
        assert!(matches!(ob.pop(), Some(Item::Thread { .. })));
        assert_eq!(*fifo.marks.lock_owner(), [2]);
        assert!(ob.pop().is_none());
    }

    #[test]
    fn finish_gives_the_close_mark_to_the_fifo() {
        let host = TestHost::new();
        let fifo = Arc::new(MarkFifo::default());
        let mut ob = Outbox::with_publish(Arc::clone(&fifo) as Arc<dyn Publish<TestTokens>>);
        ob.push_publish(Item::AuthLockpoint);
        ob.push_close_published();
        ob.finish(&host);
        assert_eq!(*fifo.marks.lock_owner(), [1]);
        assert!(ob.is_empty());
    }

    #[test]
    fn a_requeued_close_mark_keeps_its_place() {
        let fifo = Arc::new(MarkFifo::default());
        let mut ob = Outbox::with_publish(Arc::clone(&fifo) as Arc<dyn Publish<TestTokens>>);
        ob.push_publish(Item::AuthLockpoint);
        ob.push_close_published();
        ob.push(join_io());
        let rest = ob.requeue();
        assert!(fifo.marks.lock_owner().is_empty());
        let mut next = Outbox::with_publish(Arc::clone(&fifo) as Arc<dyn Publish<TestTokens>>);
        next.push(log());
        next.restore(rest);
        assert!(matches!(next.pop(), Some(Item::Thread { .. })));
        assert_eq!(*fifo.marks.lock_owner(), [1]);
        assert!(matches!(next.pop(), Some(Item::Log(_))));
    }

    #[test]
    fn a_publish_entry_with_no_entry_ahead_goes_to_the_fifo_at_once() {
        let fifo = Arc::new(Fifo::default());
        let mut ob = Outbox::with_publish(Arc::clone(&fifo) as Arc<dyn Publish<TestTokens>>);
        ob.push_publish(Item::AuthLockpoint);
        assert!(ob.is_empty());
        assert_eq!(fifo.0.lock_owner().len(), 1);
        // An entry ahead keeps the next one in the outbox until C takes
        // the entry ahead.
        ob.push(log());
        ob.push_publish(Item::AuthLockpoint);
        assert_eq!(ob.len(), 2);
        assert_eq!(fifo.0.lock_owner().len(), 1);
        assert!(matches!(ob.pop(), Some(Item::Log(_))));
        assert_eq!(fifo.0.lock_owner().len(), 1);
        assert!(ob.pop().is_none());
        assert_eq!(fifo.0.lock_owner().len(), 2);
    }

    #[test]
    fn holds_items_counts_only_the_entries_that_c_sees() {
        let host = TestHost::new();
        let fifo = Arc::new(Fifo::default());
        let mut ob = Outbox::with_publish(Arc::clone(&fifo) as Arc<dyn Publish<TestTokens>>);
        ob.push_publish(Item::AuthLockpoint);
        assert!(!ob.holds_items());
        ob.push(log());
        assert!(ob.holds_items());
        ob.push_publish(Item::AuthLockpoint);
        ob.push_close_published();
        assert!(matches!(ob.pop(), Some(Item::Log(_))));
        // A queued publish entry and the close mark are not items.
        assert_eq!(ob.len(), 2);
        assert!(!ob.holds_items());
        ob.extend_items([join_io()]);
        assert!(ob.holds_items());
        let rest = ob.requeue();
        assert!(!ob.holds_items());
        ob.restore(rest);
        assert!(ob.holds_items());
        assert!(matches!(ob.pop(), Some(Item::Thread { .. })));
        assert!(!ob.holds_items());
        assert_eq!(fifo.0.lock_owner().len(), 2);
        ob.push(log());
        ob.finish(&host);
        assert!(!ob.holds_items());
        // With no FIFO a publish entry is an item.
        let mut plain: Outbox<TestTokens> = Outbox::new();
        plain.push_publish(Item::AuthLockpoint);
        assert!(plain.holds_items());
        plain.restore(requeue_with_a_publish_entry(&fifo));
        for _ in 0..2 {
            assert!(plain.pop().is_some());
            assert!(plain.holds_items());
        }
        assert!(plain.pop().is_some());
        assert!(!plain.holds_items());
    }

    /// Gives back an item and a queued publish entry of an outbox with a
    /// FIFO.
    fn requeue_with_a_publish_entry(fifo: &Arc<Fifo>) -> Requeued<TestTokens> {
        let mut ob = Outbox::with_publish(Arc::clone(fifo) as Arc<dyn Publish<TestTokens>>);
        ob.push(log());
        ob.push_publish(Item::AuthLockpoint);
        ob.requeue()
    }

    #[test]
    fn an_outbox_with_no_fifo_takes_no_close_mark() {
        let mut ob: Outbox<TestTokens> = Outbox::new();
        ob.push_close_published();
        assert!(ob.is_empty());
        // The default `close_published` method of `Publish` does nothing.
        let fifo = Arc::new(Fifo::default());
        let mut ob = Outbox::with_publish(Arc::clone(&fifo) as Arc<dyn Publish<TestTokens>>);
        ob.push_close_published();
        assert_eq!(ob.len(), 1);
        assert!(ob.pop().is_none());
        assert!(fifo.0.lock_owner().is_empty());
    }
}
