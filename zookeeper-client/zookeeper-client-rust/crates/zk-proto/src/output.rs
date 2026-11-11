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

//! The outputs of the core and the barrier machinery.
//!
//! The core never calls application code. It puts every notification in an
//! ordered queue, and the driver pops them with `poll_output`.
//! A barrier output stops the stage that made it. The
//! stage continues only when the driver calls `resume`.

use core::fmt;
use std::collections::VecDeque;

use zk_jute::data::{ACL, ClientInfo, Stat};
use zk_jute::multi::MultiItem;
use zk_jute::{JString, JVec};

use crate::auth::AuthReplyJob;
use crate::close::CloseJob;
use crate::config::ClientId;
use crate::hooks::Tokens;
use crate::log::LogRecord;
use crate::request::Route;
use crate::responses::ReplyData;
use crate::session::FinalizeJob;
use crate::state::State;
use crate::teardown::TeardownJob;

/// One notification for the application or the driver.
pub enum Output<T: Tokens> {
    /// The result of one request.
    ///
    /// A `Queued` route goes to the dispatch queue of the handle. A
    /// `Direct` route is a barrier: the popping thread delivers it at once.
    Completion {
        /// The completion token of the request.
        token: T::Completion,
        /// The delivery route.
        route: Route,
        /// The result.
        result: OpResult,
        /// The log lines that the delivering thread emits before the
        /// callback.
        delivery_logs: Vec<LogRecord>,
    },
    /// A node event. The core collected the watchers at receipt, in
    /// delivery order. Under `LEGACY_C` the list can be empty.
    Watch {
        /// The event.
        event: WatchedEvent,
        /// The watchers to call, in order.
        watchers: Vec<T::Watcher>,
        /// The log lines that come before the callbacks.
        delivery_logs: Vec<LogRecord>,
    },
    /// A session event. The default watcher is last in the legacy profile.
    Session {
        /// The new state.
        state: State,
        /// The watchers to call, in order.
        watchers: Vec<T::Watcher>,
        /// True when the output is a barrier (`SessionDelivery::Inline`).
        barrier: bool,
        /// The log lines that come before the callbacks.
        delivery_logs: Vec<LogRecord>,
    },
    /// The completions of `add_auth` calls, in list order, with one rc.
    Auth {
        /// The completion tokens.
        tokens: Vec<T::Auth>,
        /// The result code.
        rc: i32,
        /// True when a stage continues after the output.
        barrier: bool,
    },
    /// A barrier. The C driver locks and unlocks its auth mutex, then
    /// resumes.
    AuthLockpoint,
    /// The handshake adopted this session identity. It comes before the
    /// connected `Session` output.
    ClientId(ClientId),
    /// The watchers ended (a native hook).
    WatchTerminated {
        /// The watchers, in order.
        watchers: Vec<T::Watcher>,
        /// The reason.
        reason: TerminateReason,
    },
    /// A log line, in order with the outputs around it.
    Log(LogRecord),
    /// The single-threaded driver drains its dispatch queue now.
    DrainPoint,
}

impl<T: Tokens> Output<T> {
    /// Returns true when popping the output stops the stage that made it.
    #[must_use]
    pub fn is_barrier(&self) -> bool {
        match self {
            Self::Completion { route, .. } => *route == Route::Direct,
            Self::Session { barrier, .. } | Self::Auth { barrier, .. } => *barrier,
            Self::AuthLockpoint => true,
            Self::Watch { .. }
            | Self::ClientId(_)
            | Self::WatchTerminated { .. }
            | Self::Log(_)
            | Self::DrainPoint => false,
        }
    }
}

impl<T: Tokens> fmt::Debug for Output<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completion {
                route,
                result,
                delivery_logs,
                ..
            } => f
                .debug_struct("Completion")
                .field("route", route)
                .field("result", result)
                .field("delivery_logs", delivery_logs)
                .finish_non_exhaustive(),
            Self::Watch {
                event,
                watchers,
                delivery_logs,
            } => f
                .debug_struct("Watch")
                .field("event", event)
                .field("watchers", &watchers.len())
                .field("delivery_logs", delivery_logs)
                .finish(),
            Self::Session {
                state,
                watchers,
                barrier,
                delivery_logs,
            } => f
                .debug_struct("Session")
                .field("state", state)
                .field("watchers", &watchers.len())
                .field("barrier", barrier)
                .field("delivery_logs", delivery_logs)
                .finish(),
            Self::Auth {
                tokens,
                rc,
                barrier,
            } => f
                .debug_struct("Auth")
                .field("tokens", &tokens.len())
                .field("rc", rc)
                .field("barrier", barrier)
                .finish(),
            Self::AuthLockpoint => f.write_str("AuthLockpoint"),
            Self::ClientId(id) => f.debug_tuple("ClientId").field(id).finish(),
            Self::WatchTerminated { watchers, reason } => f
                .debug_struct("WatchTerminated")
                .field("watchers", &watchers.len())
                .field("reason", reason)
                .finish(),
            Self::Log(r) => f.debug_tuple("Log").field(r).finish(),
            Self::DrainPoint => f.write_str("DrainPoint"),
        }
    }
}

/// The reason of a `WatchTerminated` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TerminateReason {
    /// The application removed the watch.
    Removed,
    /// The connection was lost and the watch is not restored.
    ConnectionLost,
    /// The session expired.
    SessionExpired,
    /// Authentication failed.
    AuthFailed,
    /// The handle closed.
    Closed,
}

/// Where a result comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A server reply.
    Reply,
    /// A teardown or a close made the result. No reply exists.
    Teardown,
}

/// The result of one request.
///
/// `reply` is `None` when `origin` is `Teardown`, or when `rc != 0` on a
/// reply that is not a decoded multi. `rc` is never 0 with no reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpResult {
    /// The result code. For a multi it is the first sub-result error other
    /// than 0 and `ZRUNTIMEINCONSISTENCY`.
    pub rc: i32,
    /// The zxid of the reply header, or 0.
    pub zxid: i64,
    /// The origin.
    pub origin: Origin,
    /// The decoded reply.
    pub reply: Option<Reply>,
}

impl OpResult {
    /// Returns a teardown result with this rc and no reply.
    #[must_use]
    pub const fn teardown(rc: i32) -> Self {
        Self {
            rc,
            zxid: 0,
            origin: Origin::Teardown,
            reply: None,
        }
    }
}

/// A decoded reply. Every path in it has the chroot stripped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// No body: delete, setACL with no stat, check, removeWatches,
    /// addWatch.
    Void,
    /// A `Stat`: exists, setData, setACL.
    Stat(Stat),
    /// getData.
    Data {
        /// The data. A large value is a range of the frame body.
        data: ReplyData,
        /// The stat.
        stat: Stat,
    },
    /// create and sync.
    Path(JString),
    /// create2.
    PathStat(JString, Stat),
    /// getChildren.
    Children(JVec<JString>),
    /// getChildren2.
    Children2(JVec<JString>, Stat),
    /// getACL.
    Acl(JVec<ACL>, Stat),
    /// multi.
    Multi(Vec<MultiItem>),
    /// getEphemerals (a native hook).
    Ephemerals(JVec<JString>),
    /// getAllChildrenNumber (a native hook).
    ChildrenCount(i32),
    /// whoAmI (a native hook).
    WhoAmI(JVec<ClientInfo>),
    /// multiRead (a native hook).
    MultiRead(Vec<MultiItem>),
}

/// A node event as the application sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchedEvent {
    /// The event type: 1 created, 2 deleted, 3 changed, 4 child, and the
    /// native types.
    pub event_type: i32,
    /// The state code of the event.
    pub state: i32,
    /// The path, with the chroot stripped.
    pub path: JString,
    /// The zxid of the reply header (a native hook).
    pub zxid: i64,
}

/// The handle of one stopped stage. The driver gives it to `resume`.
///
/// The type has no `Clone`, so each stop resumes at most once.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Stopped {
    id: u64,
}

impl Stopped {
    /// Returns the identity of the stop. It is unique per connection.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }
}

/// The remaining work of a stopped stage.
pub(crate) enum Work<T: Tokens> {
    /// `handle_read` stopped after a direct reply. Nothing remains: the
    /// next `handle_read` continues with the buffered bytes.
    Hold,
    /// A staged teardown.
    Teardown(TeardownJob<T>),
    /// A close stage.
    Close(CloseJob<T>),
    /// The steps of an AUTH reply after its lock point.
    AuthReply(AuthReplyJob),
    /// The steps of finalize after its lock point.
    Finalize(FinalizeJob),
}

impl<T: Tokens> Work<T> {
    /// Moves every token out of the work, in order: completions, then auth
    /// tokens.
    pub(crate) fn into_tokens(self) -> (Vec<T::Completion>, Vec<T::Auth>) {
        match self {
            Self::Hold | Self::AuthReply(_) | Self::Finalize(_) => (Vec::new(), Vec::new()),
            Self::Teardown(job) => job.into_tokens(),
            Self::Close(job) => job.into_tokens(),
        }
    }
}

/// One entry of the output queue.
enum Entry<T: Tokens> {
    /// An output for the driver.
    Out(Output<T>),
    /// The stage that made the outputs before it stopped here.
    Park(Work<T>),
}

/// The output queue and the stopped stages of one connection.
///
/// A stage pushes its outputs and, after a barrier, parks its remaining
/// work. `poll` pops outputs. When the popped output comes just before a
/// parked work, the work becomes suspended. Then `poll` returns `None`
/// until the driver takes the stop handle.
pub(crate) struct Outputs<T: Tokens> {
    queue: VecDeque<Entry<T>>,
    suspended: Vec<(u64, Work<T>)>,
    next_id: u64,
    pending_stop: Option<Stopped>,
    destroyed: bool,
}

impl<T: Tokens> Outputs<T> {
    /// Makes an empty queue.
    pub(crate) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            suspended: Vec::new(),
            next_id: 1,
            pending_stop: None,
            destroyed: false,
        }
    }

    /// Appends an output.
    pub(crate) fn push(&mut self, out: Output<T>) {
        self.queue.push_back(Entry::Out(out));
    }

    /// Appends a log output when the record exists.
    pub(crate) fn push_log(&mut self, record: Option<LogRecord>) {
        if let Some(r) = record {
            self.push(Output::Log(r));
        }
    }

    /// Parks the remaining work of a stage behind the outputs it made.
    /// The stage must stop at once and make no further output.
    pub(crate) fn park(&mut self, work: Work<T>) {
        self.queue.push_back(Entry::Park(work));
    }

    /// Pops the next output.
    ///
    /// It returns `None` when the queue is empty, or when a stage stopped
    /// and the driver did not take its handle yet.
    pub(crate) fn poll(&mut self) -> Option<Output<T>> {
        if self.pending_stop.is_some() {
            return None;
        }
        match self.queue.pop_front() {
            None => None,
            Some(Entry::Park(work)) => {
                self.stop(work);
                None
            }
            Some(Entry::Out(out)) => {
                if matches!(self.queue.front(), Some(Entry::Park(_))) {
                    if let Some(Entry::Park(work)) = self.queue.pop_front() {
                        self.stop(work);
                    }
                }
                Some(out)
            }
        }
    }

    /// Returns true when the next `poll` gives an output or stops a
    /// stage. A stopped stage whose handle the driver did not take
    /// blocks the queue, so the result is then false.
    pub(crate) fn has_output(&self) -> bool {
        self.pending_stop.is_none() && !self.queue.is_empty()
    }

    fn stop(&mut self, work: Work<T>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.suspended.push((id, work));
        self.pending_stop = Some(Stopped { id });
    }

    /// Takes the handle of the stage that stopped at the last popped
    /// output. Then `poll` continues.
    pub(crate) fn take_stopped(&mut self) -> Option<Stopped> {
        self.pending_stop.take()
    }

    /// Takes the work of a stopped stage. It returns `None` for an unknown
    /// handle and after `mark_destroyed`.
    pub(crate) fn take_suspended(&mut self, stopped: Stopped) -> Option<Work<T>> {
        if self.destroyed {
            return None;
        }
        let pos = self
            .suspended
            .iter()
            .position(|(id, _)| *id == stopped.id)?;
        Some(self.suspended.remove(pos).1)
    }

    /// Returns true while any stage is stopped or parked.
    pub(crate) fn is_suspended(&self) -> bool {
        !self.suspended.is_empty()
            || self.pending_stop.is_some()
            || self.queue.iter().any(|e| matches!(e, Entry::Park(_)))
    }

    /// Takes every parked and suspended work, in order of age, and forgets
    /// the pending stop. The outputs stay queued.
    pub(crate) fn take_all_work(&mut self) -> Vec<Work<T>> {
        self.pending_stop = None;
        let mut works: Vec<Work<T>> = self.suspended.drain(..).map(|(_, w)| w).collect();
        let mut kept = VecDeque::with_capacity(self.queue.len());
        for entry in self.queue.drain(..) {
            match entry {
                Entry::Park(w) => works.push(w),
                Entry::Out(o) => kept.push_back(Entry::Out(o)),
            }
        }
        self.queue = kept;
        works
    }

    /// Marks the connection destroyed. Every later `take_suspended` call
    /// returns `None`.
    pub(crate) fn mark_destroyed(&mut self) {
        self.destroyed = true;
    }

    /// Returns true after `mark_destroyed`.
    #[cfg(test)]
    pub(crate) fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    /// Splits the queue into its outputs and every work, for
    /// `into_leftovers`.
    pub(crate) fn into_parts(mut self) -> (Vec<Output<T>>, Vec<Work<T>>) {
        let works = self.take_all_work();
        let outs = self
            .queue
            .into_iter()
            .filter_map(|e| match e {
                Entry::Out(o) => Some(o),
                Entry::Park(_) => None,
            })
            .collect();
        (outs, works)
    }
}

impl<T: Tokens> fmt::Debug for Outputs<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outputs")
            .field("queued", &self.queue.len())
            .field("suspended", &self.suspended.len())
            .field("pending_stop", &self.pending_stop)
            .field("destroyed", &self.destroyed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tk;
    impl Tokens for Tk {
        type Completion = u32;
        type Watcher = u32;
        type Auth = u32;
    }

    fn lockpoint() -> Output<Tk> {
        Output::AuthLockpoint
    }

    #[test]
    fn barrier_stops_until_handle_taken() {
        let mut q: Outputs<Tk> = Outputs::new();
        q.push(Output::DrainPoint);
        q.push(lockpoint());
        q.park(Work::Hold);
        assert!(q.is_suspended());
        assert!(matches!(q.poll(), Some(Output::DrainPoint)));
        assert!(matches!(q.poll(), Some(Output::AuthLockpoint)));
        q.push(Output::DrainPoint);
        assert!(q.poll().is_none());
        let stop = q.take_stopped();
        assert!(stop.is_some());
        assert!(matches!(q.poll(), Some(Output::DrainPoint)));
        assert!(q.is_suspended());
        let work = stop.and_then(|s| q.take_suspended(s));
        assert!(matches!(work, Some(Work::Hold)));
        assert!(!q.is_suspended());
    }

    #[test]
    fn has_output_follows_the_queue_and_the_pending_stop() {
        let mut q: Outputs<Tk> = Outputs::new();
        assert!(!q.has_output());
        q.push(lockpoint());
        q.park(Work::Hold);
        q.push(Output::DrainPoint);
        assert!(q.has_output());
        assert!(matches!(q.poll(), Some(Output::AuthLockpoint)));
        // The stop blocks the queue until the driver takes its handle.
        assert!(!q.has_output());
        assert!(q.take_stopped().is_some());
        assert!(q.has_output());
        assert!(matches!(q.poll(), Some(Output::DrainPoint)));
        assert!(!q.has_output());
    }

    #[test]
    fn leading_park_and_destroy() {
        let mut q: Outputs<Tk> = Outputs::new();
        q.park(Work::Hold);
        assert!(q.poll().is_none());
        let stop = q.take_stopped();
        q.mark_destroyed();
        assert!(stop.and_then(|s| q.take_suspended(s)).is_none());
        assert_eq!(q.take_all_work().len(), 1);
        assert!(!q.is_suspended());
    }
}
