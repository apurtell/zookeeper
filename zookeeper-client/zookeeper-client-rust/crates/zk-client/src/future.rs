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

//! The named futures: `ResponseFuture`, `CloseFuture` and
//! `ReadyFuture`.
//!
//! A future never borrows the `Client`. It holds a slot, a
//! `Weak<Shared>` and a read-gate reporter, so it does not keep the
//! session open. A value leaves
//! its slot only when `poll` or `wait` returns it, so every future is
//! cancel-safe.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::task::{Context, Poll, Waker};
#[cfg(feature = "blocking")]
use std::time::Duration;
#[cfg(any(test, feature = "blocking"))]
use std::time::Instant;

use crate::decode::Decoder;
use crate::driver::{CloseWait, Gate};
use crate::error::{Error, rc_result};
use crate::shared::Shared;
use crate::slot::{Slot, Taken};
#[cfg(feature = "blocking")]
use crate::sync::blocking_refused;
use crate::sync::{LockExt, wake_quietly};
#[cfg(any(test, feature = "blocking"))]
use crate::sync::{wait, wait_until};
use crate::tokens::RawResult;

/// The state of a `ResponseFuture`.
enum Inner<T, E> {
    /// The result is known at call time: a local refusal, or a local
    /// result. `None` after `poll` returned it.
    Ready(Option<Result<T, E>>),
    /// The request is on the wire.
    Waiting {
        slot: Arc<Slot<RawResult>>,
        decode: Decoder<T, E>,
        shared: Weak<Shared>,
        /// The read gate of the driver. It stays valid after the drop
        /// of the last clone, while the driver drains the queue.
        gate: Option<Gate>,
    },
    /// The result was returned.
    Done,
}

/// The result of one request.
///
/// The request went out when the method returned. Dropping the future
/// only discards the result. It never cancels the server operation.
/// The future is `Unpin`, and it is `Send` and `Sync` when `T` and `E`
/// are.
#[must_use = "the request was already sent; dropping this future only discards the result"]
pub struct ResponseFuture<T, E = Error> {
    inner: Inner<T, E>,
}

impl<T, E> std::fmt::Debug for ResponseFuture<T, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &self.inner {
            Inner::Ready(_) => "Ready",
            Inner::Waiting { .. } => "Waiting",
            Inner::Done => "Done",
        };
        f.debug_struct("ResponseFuture")
            .field("state", &state)
            .finish()
    }
}

impl<T, E> Unpin for ResponseFuture<T, E> {}

impl<T, E> ResponseFuture<T, E> {
    /// A future with a result that is known now.
    pub(crate) fn ready(r: Result<T, E>) -> Self {
        Self {
            inner: Inner::Ready(Some(r)),
        }
    }

    /// A future that waits for `slot` and converts the raw result with
    /// `decode`.
    pub(crate) fn waiting(
        slot: Arc<Slot<RawResult>>,
        decode: Decoder<T, E>,
        shared: Weak<Shared>,
    ) -> Self {
        let gate = shared.upgrade().map(|s| s.driver.gate());
        Self {
            inner: Inner::Waiting {
                slot,
                decode,
                shared,
                gate,
            },
        }
    }

    /// True when a blocking wait on this future must fail at once. A
    /// known result needs no driver, so only the IO side refuses it.
    #[cfg(feature = "blocking")]
    fn wait_refused(&self) -> bool {
        let tokio = match &self.inner {
            Inner::Waiting { gate, .. } => gate.as_ref().is_some_and(Gate::is_tokio),
            Inner::Ready(_) | Inner::Done => false,
        };
        blocking_refused(tokio)
    }
}

impl<T, E: From<Error>> ResponseFuture<T, E> {
    /// True when `poll` would return `Ready` now.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        match &self.inner {
            Inner::Waiting { slot, .. } => slot.is_ready(),
            Inner::Ready(_) | Inner::Done => true,
        }
    }

    /// Blocks until the result is there.
    ///
    /// # Errors
    ///
    /// The error of the request. It returns `Error::InvalidState` at
    /// once on the IO side of a client, and in a tokio runtime context
    /// when the tokio driver runs the client. The result is then
    /// discarded. A client on the thread driver accepts a wait in a
    /// tokio worker or in `spawn_blocking`.
    #[cfg(feature = "blocking")]
    pub fn wait(mut self) -> Result<T, E> {
        if self.wait_refused() {
            // The drop of `self` releases the slot and the read gate.
            return Err(E::from(Error::InvalidState));
        }
        // With no deadline, the wait ends only with a result. The
        // `Closing` fallback cannot occur.
        self.wait_deadline(None)
            .unwrap_or_else(|| Err(E::from(Error::Closing)))
    }

    /// Blocks at most `d`. It gives the future back when the time passes
    /// first.
    ///
    /// # Errors
    ///
    /// The outer `Err` is the future after the timeout. The inner result
    /// is as for [`wait`](Self::wait).
    #[cfg(feature = "blocking")]
    pub fn wait_timeout(mut self, d: Duration) -> Result<Result<T, E>, Self> {
        if self.wait_refused() {
            return Ok(Err(E::from(Error::InvalidState)));
        }
        // A duration past the range of `Instant` means no deadline.
        let deadline = Instant::now().checked_add(d);
        match self.wait_deadline(deadline) {
            Some(r) => Ok(r),
            None => Err(self),
        }
    }

    /// Blocks until the result is there or `deadline` passes. It gives
    /// `None` at the deadline, and the future then stays unchanged.
    #[cfg(feature = "blocking")]
    fn wait_deadline(&mut self, deadline: Option<Instant>) -> Option<Result<T, E>> {
        let taken = match &mut self.inner {
            Inner::Ready(r) => {
                return Some(r.take().unwrap_or_else(|| Err(E::from(Error::Closing))));
            }
            Inner::Done => return Some(Err(E::from(Error::Closing))),
            Inner::Waiting { slot, .. } => slot.wait_take(deadline)?,
        };
        Some(self.finish(taken))
    }

    /// Converts what the receiver took into the result, and moves the
    /// future to `Done`.
    ///
    /// A counted value reports to the read gate before the decoder runs.
    /// A closed slot drops the decoder, so a watch registration in it
    /// removes its sink.
    fn finish(&mut self, taken: Taken<RawResult>) -> Result<T, E> {
        let Inner::Waiting {
            slot,
            decode,
            shared,
            gate,
        } = std::mem::replace(&mut self.inner, Inner::Done)
        else {
            return Err(E::from(Error::Closing));
        };
        drop(slot);
        match taken {
            Taken::Value { v, counted } => {
                if counted {
                    report_taken(gate.as_ref());
                }
                decode(v)
            }
            Taken::Closed => {
                drop(decode);
                Err(E::from(closed_error(&shared)))
            }
        }
    }
}

impl<T, E: From<Error>> Future for ResponseFuture<T, E> {
    type Output = Result<T, E>;

    /// Takes the result.
    ///
    /// - `Ready` gives its value once.
    /// - `Waiting` takes from the slot. A counted value calls
    ///   `Shared::taken`, then runs the decoder.
    /// - A closed slot gives `Shared::terminal_error`, or `Closing` when
    ///   the client is gone.
    /// - A poll after the result gives `Err(Closing)`.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let taken = match &mut this.inner {
            Inner::Ready(r) => {
                return Poll::Ready(r.take().unwrap_or_else(|| Err(E::from(Error::Closing))));
            }
            Inner::Done => return Poll::Ready(Err(E::from(Error::Closing))),
            Inner::Waiting { slot, .. } => match slot.poll_take(cx) {
                Poll::Ready(t) => t,
                Poll::Pending => return Poll::Pending,
            },
        };
        Poll::Ready(this.finish(taken))
    }
}

impl<T, E> Drop for ResponseFuture<T, E> {
    /// In `Waiting`, it drops the receiver of the slot. A counted value
    /// calls `Shared::taken`, so the read gate opens again. The decoder
    /// drops after that. A watch registration in it removes its sink.
    fn drop(&mut self) {
        if let Inner::Waiting {
            slot, decode, gate, ..
        } = std::mem::replace(&mut self.inner, Inner::Done)
        {
            if slot.drop_receiver() {
                report_taken(gate.as_ref());
            }
            drop(slot);
            drop(decode);
        }
    }
}

/// Tells the driver that a receiver took or dropped a counted value.
/// The reporter works after the drop of the last clone too, so the
/// driver can drain the queue of the background close.
pub(crate) fn report_taken(gate: Option<&Gate>) {
    if let Some(g) = gate {
        g.taken();
    }
}

/// The error of a slot that closed with no value: the terminal error of
/// the client, or `Closing`.
fn closed_error(shared: &Weak<Shared>) -> Error {
    shared
        .upgrade()
        .and_then(|s| s.terminal_error())
        .unwrap_or(Error::Closing)
}

/// The state of a `CloseFuture`.
enum CloseInner {
    /// The driver close wait.
    Waiting(CloseWait),
    /// A known result. `None` after `poll` returned it.
    Ready(Option<Result<(), Error>>),
}

/// The result of [`Client::close`](crate::Client::close).
///
/// It resolves when the driver exits: `Ok(())`, `Err(OperationTimeout)`
/// or a connection-loss-class error. The close was requested at call
/// time, so a drop of the future does not stop it.
#[must_use = "the close was already requested; dropping this future only discards the result"]
pub struct CloseFuture {
    inner: CloseInner,
}

impl std::fmt::Debug for CloseFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CloseFuture(..)")
    }
}

impl CloseFuture {
    /// A future over the close wait of the driver.
    pub(crate) fn new(wait: CloseWait) -> Self {
        Self {
            inner: CloseInner::Waiting(wait),
        }
    }

    /// A future with a known result.
    #[cfg(test)]
    pub(crate) fn ready(r: Result<(), Error>) -> Self {
        Self {
            inner: CloseInner::Ready(Some(r)),
        }
    }

    /// Blocks until the close ends.
    ///
    /// # Errors
    ///
    /// As for the future. It returns `Error::InvalidState` at once on the
    /// IO side of a client, and in a tokio runtime context when the tokio
    /// driver runs the client.
    #[cfg(feature = "blocking")]
    pub fn wait(mut self) -> Result<(), Error> {
        let tokio = match &self.inner {
            CloseInner::Waiting(w) => w.is_tokio(),
            CloseInner::Ready(_) => false,
        };
        if blocking_refused(tokio) {
            return Err(Error::InvalidState);
        }
        match &mut self.inner {
            // With no deadline, the wait ends only at the driver exit.
            // The `Closing` fallback cannot occur.
            CloseInner::Waiting(w) => w.wait(None).map_or(Err(Error::Closing), rc_result),
            CloseInner::Ready(r) => r.take().unwrap_or(Ok(())),
        }
    }
}

impl Future for CloseFuture {
    type Output = Result<(), Error>;

    /// Polls the close wait and maps the close rc with `rc_result`. A
    /// poll after the result gives `Ok(())`.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let rc = match &mut this.inner {
            CloseInner::Ready(r) => return Poll::Ready(r.take().unwrap_or(Ok(()))),
            CloseInner::Waiting(w) => match w.poll(cx) {
                Poll::Ready(rc) => rc,
                Poll::Pending => return Poll::Pending,
            },
        };
        // The wait is done. A later poll gives `Ok(())`.
        this.inner = CloseInner::Ready(None);
        Poll::Ready(rc_result(rc))
    }
}

/// The result of [`Client::ready`](crate::Client::ready).
///
/// It resolves when the pending count is below half of
/// `max_pending_requests`, and at once when no limit is set. A terminal
/// client gives its terminal error, so a wait never hangs.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ReadyFuture {
    shared: Weak<Shared>,
}

impl ReadyFuture {
    /// A future for the client of `shared`.
    pub(crate) fn new(shared: Weak<Shared>) -> Self {
        Self { shared }
    }

    /// Blocks until the future would resolve.
    ///
    /// # Errors
    ///
    /// As for the future. It returns `Error::InvalidState` on the IO side
    /// of a client, and in a tokio runtime context when the tokio driver
    /// runs the client.
    #[cfg(feature = "blocking")]
    pub fn wait(self) -> Result<(), Error> {
        let tokio = self.shared.upgrade().is_some_and(|s| s.driver.is_tokio());
        if blocking_refused(tokio) {
            return Err(Error::InvalidState);
        }
        // The wait holds the router only, so it does not keep the
        // client state alive. Each check upgrades the weak reference
        // again.
        let Some(router) = self.shared.upgrade().map(|s| Arc::clone(&s.router)) else {
            return Err(Error::Closing);
        };
        wait_ready(&router.ready, || match self.shared.upgrade() {
            Some(s) => ready_check(&s),
            None => Some(Err(Error::Closing)),
        })
    }
}

impl Future for ReadyFuture {
    type Output = Result<(), Error>;

    /// Checks the limit. Below it, or with no limit, it resolves. Else it
    /// registers the waker with `Router::ready` and checks again, so a
    /// wake between the check and the registration is not lost. A gone
    /// client gives `Err(Closing)`.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(shared) = self.shared.upgrade() else {
            return Poll::Ready(Err(Error::Closing));
        };
        poll_ready(&shared.router.ready, cx, || ready_check(&shared))
    }
}

/// The ready condition of a client. `None` means "not yet".
///
/// - No limit gives `Ok` at once.
/// - A terminal client gives its terminal error.
/// - A driver that exited gives `Closing`.
/// - Else the pending count decides.
fn ready_check(shared: &Shared) -> Option<Result<(), Error>> {
    let Some(max) = shared.config.max_pending else {
        return Some(Ok(()));
    };
    if let Some(e) = shared.terminal_error() {
        return Some(Err(e));
    }
    match shared.pending_len() {
        None => Some(Err(Error::Closing)),
        Some(n) if below_half(n, max) => Some(Ok(())),
        Some(_) => None,
    }
}

/// True when `pending` is below half of `max`.
///
/// No pending request also counts. With a limit of 0 or 1 no request
/// can complete to free more room, so a wait would never end.
fn below_half(pending: usize, max: usize) -> bool {
    pending == 0 || pending.saturating_mul(2) < max
}

/// Polls a ready condition. It checks, registers the waker, and checks
/// again. Thus a `wake_all` between the first check and the
/// registration does not cause a lost wake.
fn poll_ready(
    waiters: &ReadyWaiters,
    cx: &mut Context<'_>,
    check: impl Fn() -> Option<Result<(), Error>>,
) -> Poll<Result<(), Error>> {
    if let Some(r) = check() {
        return Poll::Ready(r);
    }
    waiters.register(cx.waker());
    match check() {
        Some(r) => Poll::Ready(r),
        None => Poll::Pending,
    }
}

/// Blocks until a ready condition holds. The generation is read before
/// each check, so a `wake_all` after the check ends the wait at once.
#[cfg(feature = "blocking")]
fn wait_ready(
    waiters: &ReadyWaiters,
    check: impl Fn() -> Option<Result<(), Error>>,
) -> Result<(), Error> {
    loop {
        let seen = waiters.generation();
        if let Some(r) = check() {
            return r;
        }
        waiters.wait_past(seen, None);
    }
}

/// The state behind the `ReadyWaiters` lock.
#[derive(Debug, Default)]
struct ReadyState {
    wakers: Vec<Waker>,
    /// Grows by one at each `wake_all`.
    generation: u64,
}

/// The waiters of `ReadyFuture`.
///
/// The router calls `wake_all` after each result and at each terminal
/// state. A waiter checks its condition again after each wake. The
/// lock is a leaf lock, and wakers run after it is released.
#[derive(Debug, Default)]
pub(crate) struct ReadyWaiters {
    st: Mutex<ReadyState>,
    cv: Condvar,
}

impl ReadyWaiters {
    /// Makes an empty set.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Adds a waker, unless an equal one is there.
    pub(crate) fn register(&self, w: &Waker) {
        let mut s = self.st.lock_unpoisoned();
        if !s.wakers.iter().any(|x| x.will_wake(w)) {
            s.wakers.push(w.clone());
        }
    }

    /// The current generation, for `wait_past`.
    #[cfg(any(test, feature = "blocking"))]
    pub(crate) fn generation(&self) -> u64 {
        self.st.lock_unpoisoned().generation
    }

    /// Wakes every waiter and starts a new generation.
    pub(crate) fn wake_all(&self) {
        let wakers = {
            let mut s = self.st.lock_unpoisoned();
            s.generation = s.generation.wrapping_add(1);
            std::mem::take(&mut s.wakers)
        };
        self.cv.notify_all();
        for w in wakers {
            wake_quietly(w);
        }
    }

    /// Blocks until the generation is not `seen`, or until `deadline`.
    /// It returns false at the deadline.
    #[cfg(any(test, feature = "blocking"))]
    pub(crate) fn wait_past(&self, seen: u64, deadline: Option<Instant>) -> bool {
        let mut s = self.st.lock_unpoisoned();
        loop {
            if s.generation != seen {
                return true;
            }
            match deadline {
                None => s = wait(&self.cv, s),
                Some(d) => {
                    let (g, timed_out) = wait_until(&self.cv, s, d);
                    s = g;
                    if timed_out {
                        return s.generation != seen;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Wake;

    use zk_proto::Origin;

    /// The close rc of a clean close.
    const ZOK: i32 = 0;

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Checks the wake count after two registrations of one waker.
    ///
    /// The second registration finds the first through `Waker::will_wake`.
    /// That check compares vtable addresses and is best effort. Miri gives
    /// a vtable a random address at each use, so there it can miss. Then
    /// the waker wakes twice, which is a spurious wake only.
    fn assert_wakes_of_two_registrations(count: &CountWake) {
        let n = count.0.load(Ordering::SeqCst);
        if cfg!(miri) {
            assert!(n == 1 || n == 2, "{n}");
        } else {
            assert_eq!(n, 1);
        }
    }

    fn counter() -> (Arc<CountWake>, Waker) {
        let c = Arc::new(CountWake(AtomicUsize::new(0)));
        (Arc::clone(&c), Waker::from(Arc::clone(&c)))
    }

    fn raw(rc: i32) -> RawResult {
        RawResult {
            rc,
            zxid: 7,
            origin: Origin::Reply,
            reply: None,
        }
    }

    /// Sets a flag when the decoder drops, and records whether the
    /// receiver of the slot was gone at that time.
    struct DropProbe {
        dropped: Arc<AtomicBool>,
        receiver_gone_first: Arc<AtomicBool>,
        slot: Arc<Slot<RawResult>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.receiver_gone_first
                .store(!self.slot.receiver_alive(), Ordering::SeqCst);
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    /// A future over a new slot. The decoder gives the rc of the raw
    /// result.
    fn waiting() -> (Arc<Slot<RawResult>>, ResponseFuture<i32>) {
        let slot = Slot::new();
        let decode: Decoder<i32> = Box::new(|r: RawResult| Ok(r.rc));
        let fut = ResponseFuture::waiting(Arc::clone(&slot), decode, Weak::new());
        (slot, fut)
    }

    /// A future with a decoder that holds a drop probe.
    fn probed() -> (
        Arc<Slot<RawResult>>,
        ResponseFuture<i32>,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    ) {
        let slot = Slot::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let first = Arc::new(AtomicBool::new(false));
        let probe = DropProbe {
            dropped: Arc::clone(&dropped),
            receiver_gone_first: Arc::clone(&first),
            slot: Arc::clone(&slot),
        };
        let decode: Decoder<i32> = Box::new(move |r: RawResult| {
            let _keep = &probe;
            Ok(r.rc)
        });
        let fut = ResponseFuture::waiting(Arc::clone(&slot), decode, Weak::new());
        (slot, fut, dropped, first)
    }

    fn poll_once<F: Future + Unpin>(f: &mut F, w: &Waker) -> Poll<F::Output> {
        let mut cx = Context::from_waker(w);
        Pin::new(f).poll(&mut cx)
    }

    #[test]
    fn a_ready_future_gives_its_value_once() {
        let (_c, w) = counter();
        let mut f: ResponseFuture<u8> = ResponseFuture::ready(Ok(3));
        assert!(f.is_ready());
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(3)));
        assert!(f.is_ready());
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Err(Error::Closing)));
    }

    #[test]
    fn a_filled_slot_gives_the_decoded_value_then_closing() {
        let (_c, w) = counter();
        let (slot, mut f) = waiting();
        assert_eq!(slot.fill(raw(-101), false), Ok(false));
        assert!(f.is_ready());
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(-101)));
        assert!(f.is_ready());
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Err(Error::Closing)));
    }

    #[test]
    fn an_empty_slot_is_pending_until_the_fill_wakes_it() {
        let (count, w) = counter();
        let (slot, mut f) = waiting();
        assert!(!f.is_ready());
        assert!(poll_once(&mut f, &w).is_pending());
        assert!(poll_once(&mut f, &w).is_pending());
        assert_eq!(slot.fill(raw(0), true), Ok(true));
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(f.is_ready());
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(0)));
    }

    #[test]
    fn a_closed_slot_gives_closing_and_drops_the_decoder() {
        let (_c, w) = counter();
        let (slot, mut f, dropped, _first) = probed();
        assert!(poll_once(&mut f, &w).is_pending());
        slot.close();
        assert!(f.is_ready());
        assert!(!dropped.load(Ordering::SeqCst));
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Err(Error::Closing)));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn a_pending_poll_leaves_the_value_in_the_slot() {
        // Cancel safety: a poll that returns `Pending` takes nothing, and
        // a value stays in the slot until a poll returns it.
        let (_c, w) = counter();
        let (slot, mut f) = waiting();
        assert!(poll_once(&mut f, &w).is_pending());
        assert_eq!(slot.fill(raw(5), false), Ok(false));
        assert!(slot.is_ready());
        assert!(slot.receiver_alive());
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(5)));
        assert!(matches!(slot.try_take(), Some(Taken::Closed)));
    }

    #[test]
    fn drop_with_a_counted_value_drops_the_receiver_before_the_decoder() {
        let (slot, f, dropped, first) = probed();
        assert_eq!(slot.fill(raw(0), true), Ok(true));
        drop(f);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(first.load(Ordering::SeqCst));
        assert!(!slot.receiver_alive());
        // The counted value is gone, so a second drop reports nothing.
        assert!(!slot.drop_receiver());
        assert!(!slot.is_ready());
    }

    #[test]
    fn drop_of_an_empty_future_refuses_a_later_fill() {
        let (slot, f, dropped, first) = probed();
        drop(f);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(first.load(Ordering::SeqCst));
        assert_eq!(slot.fill(raw(0), true), Err(raw(0)));
    }

    #[test]
    fn drop_after_the_result_does_not_touch_the_slot() {
        let (_c, w) = counter();
        let (slot, mut f) = waiting();
        assert_eq!(slot.fill(raw(1), true), Ok(true));
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(1)));
        drop(f);
        // `finish` took the value, so the receiver was never dropped.
        assert!(slot.receiver_alive());
    }

    #[test]
    fn the_close_rc_of_a_clean_close_is_ok() {
        assert_eq!(rc_result(ZOK), Ok(()));
    }

    #[test]
    fn the_close_rc_maps_through_rc_result() {
        assert_eq!(rc_result(-7), Err(Error::OperationTimeout));
        assert_eq!(rc_result(-4), Err(Error::ConnectionLoss));
    }

    #[test]
    fn a_ready_close_future_gives_its_value_then_ok() {
        let (_c, w) = counter();
        let mut f = CloseFuture::ready(Err(Error::OperationTimeout));
        assert_eq!(
            poll_once(&mut f, &w),
            Poll::Ready(Err(Error::OperationTimeout))
        );
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(())));
    }

    #[cfg(all(unix, feature = "tokio"))]
    #[test]
    fn a_close_future_maps_the_driver_rc_once() {
        let (_c, w) = counter();
        let wait = CloseWait::Tokio(Box::pin(std::future::ready(ZOK)));
        let mut f = CloseFuture::new(wait);
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(())));
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(())));
    }

    #[cfg(all(unix, feature = "tokio"))]
    #[test]
    fn a_close_future_is_pending_until_the_driver_exits() {
        let (count, w) = counter();
        let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
        let wait = CloseWait::Tokio(Box::pin(async move { rx.await.unwrap_or(-4) }));
        let mut f = CloseFuture::new(wait);
        assert!(poll_once(&mut f, &w).is_pending());
        tx.send(ZOK).unwrap();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Ok(())));
    }

    #[test]
    fn a_gone_client_gives_closing_to_ready() {
        let (_c, w) = counter();
        let mut f = ReadyFuture::new(Weak::new());
        assert_eq!(poll_once(&mut f, &w), Poll::Ready(Err(Error::Closing)));
    }

    #[test]
    fn below_half_follows_04_section_14() {
        assert!(below_half(0, 0));
        assert!(below_half(0, 1));
        assert!(!below_half(1, 1));
        assert!(below_half(1, 4));
        assert!(!below_half(2, 4));
        assert!(below_half(2, 5));
        assert!(!below_half(3, 5));
        assert!(!below_half(usize::MAX, usize::MAX));
    }

    #[test]
    fn poll_ready_checks_again_after_the_registration() {
        // The state changes and `wake_all` runs between the first check
        // and the registration. The second check sees the change, so
        // the wake is not lost.
        let waiters = ReadyWaiters::new();
        let (count, w) = counter();
        let mut cx = Context::from_waker(&w);
        let calls = AtomicUsize::new(0);
        let r = poll_ready(&waiters, &mut cx, || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                waiters.wake_all();
                None
            } else {
                Some(Ok(()))
            }
        });
        assert_eq!(r, Poll::Ready(Ok(())));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn poll_ready_registers_the_waker_while_pending() {
        let waiters = ReadyWaiters::new();
        let (count, w) = counter();
        let mut cx = Context::from_waker(&w);
        let open = AtomicBool::new(false);
        let check = || open.load(Ordering::SeqCst).then_some(Ok(()));
        assert!(poll_ready(&waiters, &mut cx, check).is_pending());
        assert!(poll_ready(&waiters, &mut cx, check).is_pending());
        open.store(true, Ordering::SeqCst);
        waiters.wake_all();
        assert_wakes_of_two_registrations(&count);
        assert_eq!(poll_ready(&waiters, &mut cx, check), Poll::Ready(Ok(())));
    }

    #[test]
    fn poll_ready_gives_the_terminal_error() {
        let waiters = ReadyWaiters::new();
        let (_c, w) = counter();
        let mut cx = Context::from_waker(&w);
        let r = poll_ready(&waiters, &mut cx, || Some(Err(Error::SessionExpired)));
        assert_eq!(r, Poll::Ready(Err(Error::SessionExpired)));
    }

    #[cfg(feature = "blocking")]
    mod blocking {
        use super::*;
        use crate::sync::enter_io_side;
        use std::time::Duration;

        #[test]
        fn wait_gives_a_ready_value() {
            let f: ResponseFuture<u8> = ResponseFuture::ready(Ok(4));
            assert_eq!(f.wait(), Ok(4));
        }

        #[test]
        fn wait_gives_a_filled_value() {
            let (slot, f) = waiting();
            assert_eq!(slot.fill(raw(-110), true), Ok(true));
            assert_eq!(f.wait(), Ok(-110));
        }

        #[test]
        fn wait_blocks_until_another_thread_fills_the_slot() {
            let (slot, f) = waiting();
            let filler = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                slot.fill(raw(-112), false)
            });
            assert_eq!(f.wait(), Ok(-112));
            assert_eq!(filler.join().unwrap(), Ok(false));
        }

        #[test]
        fn wait_on_a_closed_slot_gives_closing_and_drops_the_decoder() {
            let (slot, f, dropped, _first) = probed();
            slot.close();
            assert_eq!(f.wait(), Err(Error::Closing));
            assert!(dropped.load(Ordering::SeqCst));
        }

        #[test]
        fn wait_timeout_gives_the_future_back_unchanged() {
            let (slot, f) = waiting();
            let f = match f.wait_timeout(Duration::from_millis(10)) {
                Err(f) => f,
                Ok(r) => panic!("no timeout: {r:?}"),
            };
            assert!(!f.is_ready());
            assert!(slot.receiver_alive());
            assert_eq!(slot.fill(raw(2), true), Ok(true));
            assert!(f.is_ready());
            assert_eq!(f.wait_timeout(Duration::ZERO).ok(), Some(Ok(2)));
        }

        #[test]
        fn wait_timeout_gives_a_value_that_comes_in_time() {
            let (slot, f) = waiting();
            let filler = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                slot.fill(raw(9), false)
            });
            assert_eq!(f.wait_timeout(Duration::from_secs(5)).ok(), Some(Ok(9)));
            assert_eq!(filler.join().unwrap(), Ok(false));
        }

        #[test]
        fn wait_timeout_with_a_huge_duration_does_not_overflow() {
            let f: ResponseFuture<u8> = ResponseFuture::ready(Ok(1));
            assert_eq!(f.wait_timeout(Duration::MAX).ok(), Some(Ok(1)));
        }

        #[test]
        fn the_io_side_refuses_every_wait_and_releases_the_slot() {
            let _io = enter_io_side(42);
            let (slot, f) = waiting();
            assert_eq!(slot.fill(raw(0), true), Ok(true));
            assert_eq!(f.wait(), Err(Error::InvalidState));
            assert!(!slot.receiver_alive());
            let (slot, f) = waiting();
            assert_eq!(
                f.wait_timeout(Duration::from_secs(1)).ok(),
                Some(Err(Error::InvalidState))
            );
            assert!(!slot.receiver_alive());
            let f: ResponseFuture<u8> = ResponseFuture::ready(Ok(1));
            assert_eq!(f.wait(), Err(Error::InvalidState));
            assert_eq!(CloseFuture::ready(Ok(())).wait(), Err(Error::InvalidState));
            assert_eq!(
                ReadyFuture::new(Weak::new()).wait(),
                Err(Error::InvalidState)
            );
        }

        #[cfg(all(unix, feature = "tokio"))]
        #[test]
        fn a_tokio_runtime_lets_a_thread_driver_future_wait() {
            // A future with no tokio driver does not need the runtime.
            // Thus a wait in the runtime context gives the normal result.
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                let (slot, f) = waiting();
                assert_eq!(slot.fill(raw(5), true), Ok(true));
                assert_eq!(f.wait(), Ok(5));
                assert_eq!(CloseFuture::ready(Ok(())).wait(), Ok(()));
                assert_eq!(ReadyFuture::new(Weak::new()).wait(), Err(Error::Closing));
            });
        }

        #[test]
        fn close_wait_gives_a_ready_value() {
            assert_eq!(
                CloseFuture::ready(Err(Error::OperationTimeout)).wait(),
                Err(Error::OperationTimeout)
            );
        }

        #[cfg(all(unix, feature = "tokio"))]
        #[test]
        fn close_wait_blocks_until_the_driver_exits() {
            let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
            let wait = CloseWait::Tokio(Box::pin(async move { rx.await.unwrap_or(-4) }));
            let t = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                tx.send(ZOK)
            });
            assert_eq!(CloseFuture::new(wait).wait(), Ok(()));
            assert!(t.join().unwrap().is_ok());
        }

        #[test]
        fn a_gone_client_gives_closing_to_ready_wait() {
            assert_eq!(ReadyFuture::new(Weak::new()).wait(), Err(Error::Closing));
        }

        #[test]
        fn wait_ready_ends_after_a_wake_all_of_another_thread() {
            let waiters = Arc::new(ReadyWaiters::new());
            let open = Arc::new(AtomicBool::new(false));
            let t = {
                let waiters = Arc::clone(&waiters);
                let open = Arc::clone(&open);
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    open.store(true, Ordering::SeqCst);
                    waiters.wake_all();
                })
            };
            let r = wait_ready(&waiters, || open.load(Ordering::SeqCst).then_some(Ok(())));
            assert_eq!(r, Ok(()));
            t.join().unwrap();
        }

        #[test]
        fn wait_ready_does_not_lose_a_wake_after_the_check() {
            // The wake comes after the check and before the block. The
            // generation was read before the check, so the wait ends.
            let waiters = ReadyWaiters::new();
            let calls = AtomicUsize::new(0);
            let r = wait_ready(&waiters, || {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    waiters.wake_all();
                    None
                } else {
                    Some(Err(Error::Closing))
                }
            });
            assert_eq!(r, Err(Error::Closing));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn wake_all_wakes_each_waker_once_and_bumps_the_generation() {
        let w = ReadyWaiters::new();
        let count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        w.register(&waker);
        w.register(&waker);
        let g = w.generation();
        w.wake_all();
        assert_wakes_of_two_registrations(&count);
        assert!(w.wait_past(g, Some(Instant::now())));
        assert!(!w.wait_past(w.generation(), Some(Instant::now())));
    }
}
