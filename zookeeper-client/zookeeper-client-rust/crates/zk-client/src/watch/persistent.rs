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

//! `PersistentWatcher` and its event queue.
//!
//! The IO side pushes events and never blocks. With no bound the queue
//! grows. With `persistent_watch_buffer(n)` a full queue drops the event
//! and counts it. The next take then gives `WatchError::Lagged` before
//! any later event. A terminal error never takes a queue slot. After
//! the terminal error, the watcher gives `None` for ever.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::task::{Context, Poll, Waker};
#[cfg(any(test, feature = "blocking"))]
use std::time::Instant;

use crate::decode;
use crate::error::{Error, WatchError};
use crate::future::ResponseFuture;
use crate::path::{ZPath, ZPathBuf};
use crate::shared::Shared;
use crate::sync::LockExt;
#[cfg(feature = "blocking")]
use crate::sync::blocking_refused;
#[cfg(any(test, feature = "blocking"))]
use crate::sync::{wait, wait_until};
use crate::tokens::WatchId;

use super::{AddWatchMode, WatchOutcome, WatchedEvent, wake_quietly};

/// The state behind the queue lock.
#[derive(Debug, Default)]
struct QueueState {
    events: VecDeque<WatchedEvent>,
    /// Events dropped since the last `Lagged` report.
    missed: u64,
    /// The terminal error, once it arrives.
    terminal: Option<WatchError>,
    /// True after the terminal error was taken.
    finished: bool,
    waker: Option<Waker>,
    receiver_gone: bool,
}

/// The event queue of one persistent watcher. The queue lock is a leaf
/// lock.
#[derive(Debug)]
pub(crate) struct EventQueue {
    st: Mutex<QueueState>,
    cv: Condvar,
    /// The `persistent_watch_buffer` bound, or `None` for no bound.
    bound: Option<usize>,
}

impl EventQueue {
    /// Makes an empty queue.
    pub(crate) fn new(bound: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            st: Mutex::new(QueueState::default()),
            cv: Condvar::new(),
            bound,
        })
    }

    /// Adds an event and wakes the receiver after the lock is released.
    /// It returns the missed count when the full queue dropped the event.
    /// It does nothing after a terminal error or with no receiver.
    pub(crate) fn push(&self, ev: WatchedEvent) -> Option<u64> {
        let (waker, lagged) = {
            let mut s = self.st.lock_unpoisoned();
            if s.receiver_gone || s.terminal.is_some() || s.finished {
                return None;
            }
            let full = self.bound.is_some_and(|b| s.events.len() >= b);
            let lagged = if full {
                s.missed = s.missed.saturating_add(1);
                Some(s.missed)
            } else {
                s.events.push_back(ev);
                None
            };
            // A drop wakes the receiver too: with a bound of 0 the
            // queue stays empty, and only the wake reports the lag.
            (s.waker.take(), lagged)
        };
        self.wake(waker);
        lagged
    }

    /// Notifies a blocked receiver and calls the stored waker. The
    /// caller released the queue lock.
    fn wake(&self, waker: Option<Waker>) {
        self.cv.notify_all();
        if let Some(w) = waker {
            wake_quietly(w);
        }
    }

    /// Takes the next outcome under the lock. The outer `None` means
    /// that nothing is ready yet.
    fn take_locked(s: &mut QueueState) -> Option<Option<WatchOutcome>> {
        if s.missed > 0 {
            let missed = std::mem::take(&mut s.missed);
            return Some(Some(Err(WatchError::Lagged { missed })));
        }
        if let Some(ev) = s.events.pop_front() {
            return Some(Some(Ok(ev)));
        }
        if let Some(err) = s.terminal.take() {
            s.finished = true;
            return Some(Some(Err(err)));
        }
        if s.finished {
            return Some(None);
        }
        None
    }

    /// Stores the terminal error and wakes the receiver. A second error
    /// is ignored.
    pub(crate) fn terminate(&self, err: WatchError) {
        let waker = {
            let mut s = self.st.lock_unpoisoned();
            if s.receiver_gone || s.terminal.is_some() || s.finished {
                return;
            }
            s.terminal = Some(err);
            s.waker.take()
        };
        self.wake(waker);
    }

    /// Takes the next outcome: `Lagged` first when events were dropped,
    /// then the events in order, then the terminal error once, then
    /// `None`. It stores the waker while the queue is empty.
    pub(crate) fn poll_next(&self, cx: &mut Context<'_>) -> Poll<Option<WatchOutcome>> {
        let mut s = self.st.lock_unpoisoned();
        if let Some(o) = Self::take_locked(&mut s) {
            return Poll::Ready(o);
        }
        match &s.waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => s.waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }

    /// Blocks for the next outcome, as `poll_next` orders them. It
    /// returns `Err(())` when the deadline passes first.
    #[cfg(any(test, feature = "blocking"))]
    pub(crate) fn wait_next(&self, deadline: Option<Instant>) -> Result<Option<WatchOutcome>, ()> {
        let mut s = self.st.lock_unpoisoned();
        loop {
            if let Some(o) = Self::take_locked(&mut s) {
                return Ok(o);
            }
            match deadline {
                None => s = wait(&self.cv, s),
                Some(d) => {
                    let (g, timed_out) = wait_until(&self.cv, s, d);
                    s = g;
                    if timed_out {
                        return Self::take_locked(&mut s).ok_or(());
                    }
                }
            }
        }
    }

    /// Marks the receiver gone and drops the queued events.
    pub(crate) fn drop_receiver(&self) {
        let (events, waker) = {
            let mut s = self.st.lock_unpoisoned();
            s.receiver_gone = true;
            s.missed = 0;
            s.terminal = None;
            (std::mem::take(&mut s.events), s.waker.take())
        };
        // The events and the waker drop after the lock is released.
        drop(events);
        drop(waker);
    }
}

/// A persistent watcher. It gives many events and ends after one
/// terminal [`WatchError`]. `Lagged` is not terminal.
///
/// It does not keep the session open. Dropping it detaches the watcher,
/// and the last local user of the server watch sends `RemoveWatches`.
#[must_use = "dropping the watcher removes the watch"]
pub struct PersistentWatcher {
    id: WatchId,
    queue: Arc<EventQueue>,
    shared: Weak<Shared>,
    /// True when the tokio driver runs the client. Only a blocking wait
    /// reads it.
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    tokio: bool,
    path: ZPathBuf,
    mode: AddWatchMode,
    /// True after `remove`.
    removed: bool,
}

impl std::fmt::Debug for PersistentWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentWatcher")
            .field("path", &self.path)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl PersistentWatcher {
    /// Makes the handle of an armed watcher. Only `PersistentReg::arm`
    /// calls it.
    pub(crate) fn new(
        id: WatchId,
        queue: Arc<EventQueue>,
        shared: Weak<Shared>,
        tokio: bool,
        path: ZPathBuf,
        mode: AddWatchMode,
    ) -> Self {
        Self {
            id,
            queue,
            shared,
            tokio,
            path,
            mode,
            removed: false,
        }
    }

    /// The next outcome, or `None` after the terminal error. The future
    /// is cancel-safe: an outcome leaves the queue only when it is
    /// returned. It is not `Iterator::next`, because the result is a
    /// future.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Next<'_> {
        Next { w: self }
    }

    /// The watched path, as the caller gave it.
    #[must_use]
    pub fn path(&self) -> ZPath<'_> {
        self.path.as_path()
    }

    /// The watch mode.
    #[must_use]
    pub fn mode(&self) -> AddWatchMode {
        self.mode
    }

    /// Removes the watcher and returns the server result. With other local
    /// users of the server watch, it resolves to `Ok(())` with no request.
    pub fn remove(mut self) -> ResponseFuture<()> {
        self.removed = true;
        self.queue.drop_receiver();
        let Some(shared) = self.shared.upgrade() else {
            return ResponseFuture::ready(Err(Error::Closing));
        };
        match shared.remove_watch(self.id) {
            Ok(None) => ResponseFuture::ready(Ok(())),
            Ok(Some(slot)) => {
                ResponseFuture::waiting(slot, decode::boxed(decode::void), Arc::downgrade(&shared))
            }
            Err(e) => ResponseFuture::ready(Err(e)),
        }
    }

    /// Blocks for the next outcome. It gives
    /// `Some(Err(WatchError::InvalidState))` at once on the IO side of a
    /// client, and in a tokio runtime context when the tokio driver runs
    /// the client.
    #[cfg(feature = "blocking")]
    pub fn recv(&mut self) -> Option<Result<WatchedEvent, WatchError>> {
        if blocking_refused(self.tokio) {
            return Some(Err(WatchError::InvalidState));
        }
        loop {
            // With no deadline the wait returns only with an outcome.
            if let Ok(o) = self.queue.wait_next(None) {
                return o;
            }
        }
    }
}

impl Drop for PersistentWatcher {
    /// Drops the receiver of the queue and calls
    /// `Shared::drop_watch_sink`, unless `remove` ran.
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        self.queue.drop_receiver();
        if let Some(shared) = self.shared.upgrade() {
            shared.drop_watch_sink(self.id);
        }
    }
}

/// The future of [`PersistentWatcher::next`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Next<'a> {
    w: &'a mut PersistentWatcher,
}

impl Future for Next<'_> {
    type Output = Option<Result<WatchedEvent, WatchError>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.w.queue.poll_next(cx)
    }
}

#[cfg(feature = "stream")]
impl futures_core::Stream for PersistentWatcher {
    type Item = Result<WatchedEvent, WatchError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.queue.poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;
    use std::time::Duration;

    use super::*;
    use crate::watch::EventKind;

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Arc<CountWake>, Waker) {
        let c = Arc::new(CountWake(AtomicUsize::new(0)));
        (Arc::clone(&c), Waker::from(Arc::clone(&c)))
    }

    fn event(path: &str) -> WatchedEvent {
        WatchedEvent {
            kind: EventKind::NodeCreated,
            path: ZPathBuf::new(path.to_owned()).unwrap(),
            zxid: None,
        }
    }

    fn next(q: &EventQueue) -> Poll<Option<WatchOutcome>> {
        q.poll_next(&mut Context::from_waker(Waker::noop()))
    }

    fn soon() -> Instant {
        Instant::now()
            .checked_add(Duration::from_millis(10))
            .unwrap()
    }

    #[test]
    fn an_unbounded_queue_never_drops() {
        let q = EventQueue::new(None);
        // Miri interprets slowly, so it pushes fewer events.
        let n = if cfg!(miri) { 500 } else { 10_000 };
        for i in 0..n {
            assert_eq!(q.push(event(&format!("/n{i}"))), None);
        }
        for i in 0..n {
            assert_eq!(next(&q), Poll::Ready(Some(Ok(event(&format!("/n{i}"))))));
        }
        assert_eq!(next(&q), Poll::Pending);
    }

    #[test]
    fn a_full_queue_gives_lagged_first_and_stays_active() {
        let q = EventQueue::new(Some(2));
        assert_eq!(q.push(event("/a")), None);
        assert_eq!(q.push(event("/b")), None);
        assert_eq!(q.push(event("/c")), Some(1));
        assert_eq!(q.push(event("/d")), Some(2));
        assert_eq!(
            next(&q),
            Poll::Ready(Some(Err(WatchError::Lagged { missed: 2 })))
        );
        assert_eq!(next(&q), Poll::Ready(Some(Ok(event("/a")))));
        // One slot is free again.
        assert_eq!(q.push(event("/e")), None);
        assert_eq!(q.push(event("/f")), Some(1));
        assert_eq!(
            next(&q),
            Poll::Ready(Some(Err(WatchError::Lagged { missed: 1 })))
        );
        assert_eq!(next(&q), Poll::Ready(Some(Ok(event("/b")))));
        assert_eq!(next(&q), Poll::Ready(Some(Ok(event("/e")))));
        assert_eq!(next(&q), Poll::Pending);
    }

    #[test]
    fn a_zero_bound_drops_every_event_and_wakes() {
        let q = EventQueue::new(Some(0));
        let (count, w) = counting_waker();
        assert!(q.poll_next(&mut Context::from_waker(&w)).is_pending());
        assert_eq!(q.push(event("/a")), Some(1));
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            next(&q),
            Poll::Ready(Some(Err(WatchError::Lagged { missed: 1 })))
        );
    }

    #[test]
    fn the_terminal_error_never_takes_a_slot() {
        let q = EventQueue::new(Some(1));
        assert_eq!(q.push(event("/a")), None);
        assert_eq!(q.push(event("/b")), Some(1));
        q.terminate(WatchError::SessionExpired);
        q.terminate(WatchError::Closed);
        assert_eq!(q.push(event("/c")), None);
        assert_eq!(
            next(&q),
            Poll::Ready(Some(Err(WatchError::Lagged { missed: 1 })))
        );
        assert_eq!(next(&q), Poll::Ready(Some(Ok(event("/a")))));
        assert_eq!(next(&q), Poll::Ready(Some(Err(WatchError::SessionExpired))));
        for _ in 0..3 {
            assert_eq!(next(&q), Poll::Ready(None));
        }
        assert_eq!(q.push(event("/d")), None);
        q.terminate(WatchError::Closed);
        assert_eq!(next(&q), Poll::Ready(None));
    }

    #[test]
    fn push_and_terminate_wake_once_per_stored_waker() {
        let q = EventQueue::new(None);
        let (count, w) = counting_waker();
        let mut cx = Context::from_waker(&w);
        assert!(q.poll_next(&mut cx).is_pending());
        assert!(q.poll_next(&mut cx).is_pending());
        q.push(event("/a"));
        q.push(event("/b"));
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(q.poll_next(&mut cx).is_ready());
        assert!(q.poll_next(&mut cx).is_ready());
        assert!(q.poll_next(&mut cx).is_pending());
        q.terminate(WatchError::Removed);
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_gone_receiver_drops_events_and_refuses_new_ones() {
        let q = EventQueue::new(Some(1));
        q.push(event("/a"));
        q.push(event("/b"));
        q.drop_receiver();
        assert_eq!(q.push(event("/c")), None);
        q.terminate(WatchError::Closed);
        let s = q.st.lock_unpoisoned();
        assert!(s.events.is_empty());
        assert_eq!(s.missed, 0);
        assert!(s.terminal.is_none());
        assert!(s.waker.is_none());
    }

    #[test]
    fn wait_next_times_out_then_gets_the_outcome() {
        let q = EventQueue::new(None);
        assert_eq!(q.wait_next(Some(soon())), Err(()));
        let pusher = Arc::clone(&q);
        let t = std::thread::spawn(move || {
            pusher.push(event("/a"));
            pusher.terminate(WatchError::Closed);
        });
        assert_eq!(q.wait_next(None), Ok(Some(Ok(event("/a")))));
        t.join().unwrap();
        assert_eq!(q.wait_next(None), Ok(Some(Err(WatchError::Closed))));
        assert_eq!(q.wait_next(Some(soon())), Ok(None));
    }

    #[test]
    fn a_watcher_drop_with_no_client_drops_the_receiver() {
        let q = EventQueue::new(None);
        let w = PersistentWatcher::new(
            WatchId(1),
            Arc::clone(&q),
            Weak::new(),
            false,
            ZPathBuf::new("/a".to_owned()).unwrap(),
            AddWatchMode::PersistentRecursive,
        );
        assert_eq!(w.path().as_str(), "/a");
        assert_eq!(w.mode(), AddWatchMode::PersistentRecursive);
        q.push(event("/a"));
        drop(w);
        assert!(q.st.lock_unpoisoned().receiver_gone);
        assert_eq!(q.push(event("/a")), None);
    }

    #[test]
    fn next_gives_the_queue_order() {
        let q = EventQueue::new(None);
        let mut w = PersistentWatcher::new(
            WatchId(1),
            Arc::clone(&q),
            Weak::new(),
            false,
            ZPathBuf::new("/a".to_owned()).unwrap(),
            AddWatchMode::Persistent,
        );
        q.push(event("/a"));
        q.terminate(WatchError::Removed);
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = w.next();
        assert_eq!(
            Pin::new(&mut f).poll(&mut cx),
            Poll::Ready(Some(Ok(event("/a"))))
        );
        let mut f = w.next();
        assert_eq!(
            Pin::new(&mut f).poll(&mut cx),
            Poll::Ready(Some(Err(WatchError::Removed)))
        );
        let mut f = w.next();
        assert_eq!(Pin::new(&mut f).poll(&mut cx), Poll::Ready(None));
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn recv_is_refused_on_the_io_side() {
        let q = EventQueue::new(None);
        let mut w = PersistentWatcher::new(
            WatchId(1),
            Arc::clone(&q),
            Weak::new(),
            false,
            ZPathBuf::new("/a".to_owned()).unwrap(),
            AddWatchMode::Persistent,
        );
        q.push(event("/a"));
        {
            let _io = crate::sync::enter_io_side(42);
            assert_eq!(w.recv(), Some(Err(WatchError::InvalidState)));
        }
        assert_eq!(w.recv(), Some(Ok(event("/a"))));
        q.terminate(WatchError::Closed);
        assert_eq!(w.recv(), Some(Err(WatchError::Closed)));
        assert_eq!(w.recv(), None);
    }
}
