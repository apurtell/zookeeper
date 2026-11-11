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

//! Session state: `SessionState`, `SessionInfo`, `StateWatcher` and the
//! private `StateCell`.
//!
//! The cell keeps only the latest value and a change version, as
//! `tokio::sync::watch` does. Thus it needs no backpressure. The cell
//! lock is a leaf lock. Wakers run after the lock is released.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

#[cfg(test)]
use crate::error::LastError;
use crate::error::{Error, LastErrorUpdate};
use crate::sync::LockExt;
#[cfg(feature = "blocking")]
use crate::sync::blocking_refused;
#[cfg(any(test, feature = "blocking"))]
use crate::sync::{wait, wait_until};

use super::wake_quietly;

/// The public session state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionState {
    /// Before the first connection, or during a reconnect (Java
    /// "Disconnected").
    Connecting,
    /// Connected, after SASL when SASL is on.
    Connected,
    /// Connected to a read-only server.
    ConnectedReadOnly,
    /// The session expired. Terminal.
    Expired,
    /// Authentication failed. Terminal.
    AuthFailed,
    /// `close`, `detach` or the drop of the last clone. Terminal.
    Closed,
}

impl SessionState {
    /// True for `Connected` and `ConnectedReadOnly`.
    #[must_use]
    pub fn is_connected(self) -> bool {
        matches!(self, Self::Connected | Self::ConnectedReadOnly)
    }

    /// True for `Expired`, `AuthFailed` and `Closed`.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::AuthFailed | Self::Closed)
    }
}

/// A snapshot of the session.
#[derive(Clone)]
pub struct SessionInfo {
    /// The state.
    pub state: SessionState,
    /// The count of established connections. It grows by one at each
    /// `Connected` or `ConnectedReadOnly` after a state that is not
    /// connected.
    pub epoch: u64,
    /// When the last established connection ended, while the client is
    /// not connected.
    pub disconnected_since: Option<Instant>,
    /// The cause of the last teardown: an `io::Error`, a
    /// `TlsConfigError`, or a [`DisconnectCause`](crate::DisconnectCause).
    pub last_error: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInfo")
            .field("state", &self.state)
            .field("epoch", &self.epoch)
            .field("disconnected_since", &self.disconnected_since)
            .field(
                "last_error",
                &self.last_error.as_ref().map(|e| e.to_string()),
            )
            .finish()
    }
}

/// The state behind the cell lock.
struct CellState {
    info: SessionInfo,
    /// Grows by one at each change of `info`.
    version: u64,
    /// The wakers of the pending `Changed` futures, by key. A future
    /// removes its entry when it drops, so the map holds only live
    /// waiters.
    wakers: BTreeMap<u64, Waker>,
    /// The key of the next waiter.
    next_key: u64,
}

/// The latest session value and its waiters.
pub(crate) struct StateCell {
    st: Mutex<CellState>,
    cv: Condvar,
    /// True when the tokio driver runs the client. A blocking wait uses
    /// it to choose the refusal rule.
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    tokio_driver: bool,
}

impl std::fmt::Debug for StateCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StateCell(..)")
    }
}

impl StateCell {
    /// Makes a cell in `Connecting` at epoch 0, for a client on the
    /// thread driver.
    pub(crate) fn new() -> Arc<Self> {
        Self::for_driver(false)
    }

    /// Makes a cell in `Connecting` at epoch 0. `tokio_driver` is true
    /// when the tokio driver runs the client.
    pub(crate) fn for_driver(tokio_driver: bool) -> Arc<Self> {
        Arc::new(Self {
            st: Mutex::new(CellState {
                info: SessionInfo {
                    state: SessionState::Connecting,
                    epoch: 0,
                    disconnected_since: None,
                    last_error: None,
                },
                version: 0,
                wakers: BTreeMap::new(),
                next_key: 0,
            }),
            cv: Condvar::new(),
            tokio_driver,
        })
    }

    /// The current value.
    pub(crate) fn snapshot(&self) -> SessionInfo {
        self.st.lock_unpoisoned().info.clone()
    }

    /// The current change version.
    pub(crate) fn version(&self) -> u64 {
        self.st.lock_unpoisoned().version
    }

    /// Applies a proto session state.
    ///
    /// The mapping:
    /// - `Connected` gives `Connected`; `ReadOnly` gives
    ///   `ConnectedReadOnly`. Both bump `epoch` when the old state was not
    ///   connected, and clear `disconnected_since`.
    /// - `ExpiredSession` gives `Expired`; `AuthFailed` gives
    ///   `AuthFailed`.
    /// - `Closed` gives `Closed` when `closing` is true. Otherwise it is
    ///   a recoverable teardown and gives `Connecting`.
    /// - Every other state gives `Connecting`.
    ///
    /// A move out of a connected state sets `disconnected_since`. A
    /// state that is not connected applies `update` to `last_error`. A
    /// terminal state never changes again. It returns the new public
    /// state when the state changed, and it wakes every waiter after the
    /// lock is released.
    pub(crate) fn on_session(
        &self,
        state: zk_proto::State,
        closing: bool,
        update: LastErrorUpdate,
    ) -> Option<SessionState> {
        let new = public_state(state, closing);
        let mut s = self.st.lock_unpoisoned();
        let old = s.info.state;
        if old.is_terminal() {
            return None;
        }
        let mut changed = new != old;
        if new.is_connected() {
            if !old.is_connected() {
                s.info.epoch = s.info.epoch.saturating_add(1);
                changed = true;
            }
            s.info.disconnected_since = None;
        } else {
            if old.is_connected() {
                s.info.disconnected_since = Some(Instant::now());
            }
            match update {
                LastErrorUpdate::Keep => {}
                LastErrorUpdate::Clear => {
                    changed |= s.info.last_error.take().is_some();
                }
                LastErrorUpdate::Set(e) => {
                    s.info.last_error = Some(e);
                    changed = true;
                }
            }
        }
        if !changed {
            return None;
        }
        s.info.state = new;
        let wakers = Self::bump(&mut s);
        drop(s);
        self.wake(wakers);
        (new != old).then_some(new)
    }

    /// Counts one change of the value and takes the wakers out. The
    /// caller wakes them after it releases the lock.
    fn bump(s: &mut CellState) -> BTreeMap<u64, Waker> {
        s.version = s.version.saturating_add(1);
        std::mem::take(&mut s.wakers)
    }

    /// Notifies the blocked waiters and calls the wakers. The caller
    /// released the cell lock.
    fn wake(&self, wakers: BTreeMap<u64, Waker>) {
        self.cv.notify_all();
        for w in wakers.into_values() {
            wake_quietly(w);
        }
    }

    /// Returns the value when it is newer than `*seen`, or when the
    /// state is terminal. It then moves `*seen` to the version.
    fn changed_locked(s: &CellState, seen: &mut u64) -> Option<SessionInfo> {
        if s.version > *seen || s.info.state.is_terminal() {
            *seen = s.version;
            return Some(s.info.clone());
        }
        None
    }

    /// Moves the cell to `Closed` when the driver exits. It returns true
    /// when the state changed. A terminal state stays as it is.
    pub(crate) fn set_closed(&self) -> bool {
        let mut s = self.st.lock_unpoisoned();
        if s.info.state.is_terminal() {
            return false;
        }
        if s.info.state.is_connected() {
            s.info.disconnected_since = Some(Instant::now());
        }
        s.info.state = SessionState::Closed;
        let wakers = Self::bump(&mut s);
        drop(s);
        self.wake(wakers);
        true
    }

    /// Stores a last error with no state change, for example a TLS
    /// configuration error of `connect`.
    #[cfg(test)]
    pub(crate) fn set_last_error(&self, e: LastError) {
        let mut s = self.st.lock_unpoisoned();
        s.info.last_error = Some(e);
        let wakers = Self::bump(&mut s);
        drop(s);
        self.wake(wakers);
    }

    /// The request error of a terminal state: `SessionExpired`,
    /// `AuthFailed` or `Closing`. `None` while not terminal.
    pub(crate) fn terminal_error(&self) -> Option<Error> {
        match self.st.lock_unpoisoned().info.state {
            SessionState::Expired => Some(Error::SessionExpired),
            SessionState::AuthFailed => Some(Error::AuthFailed),
            SessionState::Closed => Some(Error::Closing),
            SessionState::Connecting
            | SessionState::Connected
            | SessionState::ConnectedReadOnly => None,
        }
    }

    /// Resolves when the version is above `*seen`, and then sets `*seen` to
    /// it. A terminal state resolves at once, always.
    ///
    /// `key` identifies the waker entry of one `Changed` future. A poll
    /// replaces the entry of its key, so one future holds one entry.
    /// A ready poll removes the entry.
    pub(crate) fn poll_changed(
        &self,
        seen: &mut u64,
        key: &mut Option<u64>,
        cx: &mut Context<'_>,
    ) -> Poll<SessionInfo> {
        let mut s = self.st.lock_unpoisoned();
        if let Some(info) = Self::changed_locked(&s, seen) {
            if let Some(k) = key.take() {
                s.wakers.remove(&k);
            }
            return Poll::Ready(info);
        }
        let k = match *key {
            Some(k) => k,
            None => {
                let k = s.next_key;
                s.next_key = s.next_key.wrapping_add(1);
                *key = Some(k);
                k
            }
        };
        match s.wakers.get_mut(&k) {
            Some(w) if w.will_wake(cx.waker()) => {}
            Some(w) => w.clone_from(cx.waker()),
            None => {
                s.wakers.insert(k, cx.waker().clone());
            }
        }
        Poll::Pending
    }

    /// Removes the waker entry of a `Changed` future that drops.
    fn forget(&self, key: u64) {
        let removed = self.st.lock_unpoisoned().wakers.remove(&key);
        // The waker drops after the lock is released.
        drop(removed);
    }

    /// The count of stored wakers, for the tests.
    #[cfg(test)]
    fn waker_count(&self) -> usize {
        self.st.lock_unpoisoned().wakers.len()
    }

    /// Blocks as `poll_changed` waits. It returns `None` when the
    /// deadline passes first.
    #[cfg(any(test, feature = "blocking"))]
    pub(crate) fn wait_changed(
        &self,
        seen: &mut u64,
        deadline: Option<Instant>,
    ) -> Option<SessionInfo> {
        let mut s = self.st.lock_unpoisoned();
        loop {
            if let Some(info) = Self::changed_locked(&s, seen) {
                return Some(info);
            }
            match deadline {
                None => s = wait(&self.cv, s),
                Some(d) => {
                    let (g, timed_out) = wait_until(&self.cv, s, d);
                    s = g;
                    if timed_out {
                        return Self::changed_locked(&s, seen);
                    }
                }
            }
        }
    }
}

/// Maps a proto state to the public state. A proto `Closed` is terminal
/// only while the client closes. Otherwise it is a recoverable
/// teardown.
fn public_state(state: zk_proto::State, closing: bool) -> SessionState {
    match state {
        zk_proto::State::Connected => SessionState::Connected,
        zk_proto::State::ReadOnly => SessionState::ConnectedReadOnly,
        zk_proto::State::ExpiredSession => SessionState::Expired,
        zk_proto::State::AuthFailed => SessionState::AuthFailed,
        zk_proto::State::Closed if closing => SessionState::Closed,
        zk_proto::State::Closed
        | zk_proto::State::Connecting
        | zk_proto::State::Associating
        | zk_proto::State::SslConnecting
        | zk_proto::State::NotConnected => SessionState::Connecting,
    }
}

/// Watches the session state.
///
/// It keeps the last version that it saw. Intermediate states can
/// merge, and `epoch` shows that a reconnect happened. A terminal state
/// never merges away. It does not keep the session open.
#[derive(Clone, Debug)]
pub struct StateWatcher {
    cell: Arc<StateCell>,
    seen: u64,
}

impl StateWatcher {
    /// Makes a watcher that has seen the current value.
    pub(crate) fn new(cell: Arc<StateCell>) -> Self {
        let seen = cell.version();
        Self { cell, seen }
    }

    /// The current value.
    #[must_use]
    pub fn current(&self) -> SessionInfo {
        self.cell.snapshot()
    }

    /// True when the tokio driver runs the client.
    #[cfg(feature = "blocking")]
    pub(crate) fn tokio_driver(&self) -> bool {
        self.cell.tokio_driver
    }

    /// The cause of the last teardown (specification "Operations,
    /// Result Types, and Error Handling"). It is `current().last_error`.
    #[must_use]
    pub fn last_error(&self) -> Option<Arc<dyn std::error::Error + Send + Sync>> {
        self.cell.snapshot().last_error
    }

    /// Resolves at the next change after the last one that this watcher
    /// saw. After a terminal state it resolves at once, always.
    pub fn changed(&mut self) -> Changed<'_> {
        Changed { w: self, key: None }
    }

    /// Polls for the next change with a waker entry that the caller
    /// keeps across polls. A caller that stores the future state in its
    /// own fields uses it, and calls [`forget`](Self::forget) at the end.
    pub(crate) fn poll_keyed(
        &mut self,
        key: &mut Option<u64>,
        cx: &mut Context<'_>,
    ) -> Poll<SessionInfo> {
        self.cell.poll_changed(&mut self.seen, key, cx)
    }

    /// Removes the waker entry of [`poll_keyed`](Self::poll_keyed).
    pub(crate) fn forget(&self, key: &mut Option<u64>) {
        if let Some(k) = key.take() {
            self.cell.forget(k);
        }
    }

    /// Blocks until the next change, as [`changed`](Self::changed) waits.
    ///
    /// # Errors
    ///
    /// `Error::InvalidState` on the IO side of a client, and in a tokio
    /// runtime context when the tokio driver runs the client.
    #[cfg(feature = "blocking")]
    pub fn wait_changed(&mut self) -> Result<SessionInfo, Error> {
        if blocking_refused(self.cell.tokio_driver) {
            return Err(Error::InvalidState);
        }
        loop {
            // With no deadline the wait returns only with a value.
            if let Some(info) = self.cell.wait_changed(&mut self.seen, None) {
                return Ok(info);
            }
        }
    }
}

/// The future of [`StateWatcher::changed`].
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Changed<'a> {
    w: &'a mut StateWatcher,
    /// The key of the waker entry in the cell, after the first pending
    /// poll.
    key: Option<u64>,
}

impl Future for Changed<'_> {
    type Output = SessionInfo;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<SessionInfo> {
        let this = self.get_mut();
        let w = &mut *this.w;
        w.cell.poll_changed(&mut w.seen, &mut this.key, cx)
    }
}

impl Drop for Changed<'_> {
    /// Removes the waker entry, so a dropped future leaves no waker in
    /// the cell.
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.w.cell.forget(k);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;
    use std::time::Duration;

    use zk_proto::State;

    use super::*;

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A teardown cause. An `io::Error` keeps the tests free of the
    /// `Display` of other modules.
    fn cause(text: &str) -> LastErrorUpdate {
        LastErrorUpdate::Set(Arc::new(std::io::Error::other(text.to_owned())))
    }

    fn poll(w: &mut StateWatcher, waker: &Waker) -> Poll<SessionInfo> {
        let mut f = w.changed();
        Pin::new(&mut f).poll(&mut Context::from_waker(waker))
    }

    fn soon() -> Instant {
        Instant::now()
            .checked_add(Duration::from_millis(10))
            .unwrap()
    }

    #[test]
    fn a_dropped_changed_future_leaves_no_waker() {
        let cell = StateCell::new();
        let mut w = StateWatcher::new(Arc::clone(&cell));
        let c = Arc::new(CountWake(AtomicUsize::new(0)));
        for _ in 0..1000 {
            let waker = Waker::from(Arc::new(CountWake(AtomicUsize::new(0))));
            assert!(poll(&mut w, &waker).is_pending());
        }
        assert_eq!(cell.waker_count(), 0, "each drop removes its entry");
        // A future that polls twice keeps one entry, with the last waker.
        {
            let mut f = w.changed();
            let first = Waker::from(Arc::new(CountWake(AtomicUsize::new(0))));
            let last = Waker::from(Arc::clone(&c));
            let mut pf = Pin::new(&mut f);
            assert!(
                pf.as_mut()
                    .poll(&mut Context::from_waker(&first))
                    .is_pending()
            );
            assert!(
                pf.as_mut()
                    .poll(&mut Context::from_waker(&last))
                    .is_pending()
            );
            assert_eq!(cell.waker_count(), 1);
            cell.on_session(State::Connected, false, LastErrorUpdate::Keep);
            assert_eq!(c.0.load(Ordering::SeqCst), 1, "the last waker runs");
            assert!(pf.poll(&mut Context::from_waker(Waker::noop())).is_ready());
        }
        assert_eq!(cell.waker_count(), 0);
    }

    #[test]
    fn a_keyed_poll_keeps_its_waker_until_forget() {
        // The connect future keeps its waker entry across polls. Thus a
        // state change wakes it, also when the change comes later.
        let cell = StateCell::new();
        let mut w = StateWatcher::new(Arc::clone(&cell));
        let c = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&c));
        let mut key = None;
        for _ in 0..3 {
            assert!(
                w.poll_keyed(&mut key, &mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        assert_eq!(cell.waker_count(), 1);
        cell.on_session(State::Connected, false, LastErrorUpdate::Keep);
        assert_eq!(c.0.load(Ordering::SeqCst), 1);
        assert!(
            w.poll_keyed(&mut key, &mut Context::from_waker(&waker))
                .is_ready()
        );
        assert!(
            w.poll_keyed(&mut key, &mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(cell.waker_count(), 1);
        w.forget(&mut key);
        assert_eq!((cell.waker_count(), key), (0, None));
    }

    #[test]
    fn the_mapping_table() {
        use SessionState as S;
        let rows = [
            (State::Connected, false, S::Connected),
            (State::ReadOnly, false, S::ConnectedReadOnly),
            (State::ExpiredSession, false, S::Expired),
            (State::AuthFailed, false, S::AuthFailed),
            (State::Closed, true, S::Closed),
            (State::Closed, false, S::Connecting),
            (State::Connecting, false, S::Connecting),
            (State::Associating, true, S::Connecting),
            (State::SslConnecting, false, S::Connecting),
            (State::NotConnected, false, S::Connecting),
        ];
        for (proto, closing, public) in rows {
            assert_eq!(public_state(proto, closing), public, "{proto:?} {closing}");
        }
    }

    #[test]
    fn epoch_grows_at_each_connect_only() {
        let cell = StateCell::new();
        assert_eq!(
            cell.on_session(State::Connected, false, LastErrorUpdate::Keep),
            Some(SessionState::Connected)
        );
        assert_eq!(cell.snapshot().epoch, 1);
        // A move from Connected to read-only is not a new connection.
        assert_eq!(
            cell.on_session(State::ReadOnly, false, LastErrorUpdate::Keep),
            Some(SessionState::ConnectedReadOnly)
        );
        assert_eq!(cell.snapshot().epoch, 1);
        assert_eq!(
            cell.on_session(State::Connected, false, LastErrorUpdate::Keep),
            Some(SessionState::Connected)
        );
        assert_eq!(
            cell.on_session(State::Connected, false, LastErrorUpdate::Keep),
            None
        );
        assert_eq!(cell.snapshot().epoch, 1);
        let v = cell.version();
        assert_eq!(
            cell.on_session(State::Closed, false, cause("server closed")),
            Some(SessionState::Connecting)
        );
        let info = cell.snapshot();
        assert!(info.disconnected_since.is_some());
        assert_eq!(info.last_error.unwrap().to_string(), "server closed");
        assert!(cell.version() > v);
        assert_eq!(
            cell.on_session(State::Connecting, false, LastErrorUpdate::Keep),
            None
        );
        assert_eq!(
            cell.on_session(State::ReadOnly, false, LastErrorUpdate::Keep),
            Some(SessionState::ConnectedReadOnly)
        );
        let info = cell.snapshot();
        assert_eq!(info.epoch, 2);
        assert!(info.disconnected_since.is_none());
        assert!(info.last_error.is_some(), "a connect keeps the last error");
    }

    #[test]
    fn a_new_last_error_changes_the_value_but_not_the_state() {
        let cell = StateCell::new();
        let v = cell.version();
        assert_eq!(
            cell.on_session(State::Connecting, false, cause("receive timeout")),
            None
        );
        assert_eq!(cell.version(), v.saturating_add(1));
        assert!(cell.snapshot().disconnected_since.is_none());
        assert_eq!(
            cell.on_session(State::Connecting, false, LastErrorUpdate::Clear),
            None
        );
        assert!(cell.snapshot().last_error.is_none());
        assert_eq!(cell.version(), v.saturating_add(2));
        // A second clear changes nothing.
        cell.on_session(State::Connecting, false, LastErrorUpdate::Clear);
        assert_eq!(cell.version(), v.saturating_add(2));
        cell.set_last_error(Arc::new(std::io::Error::other("tls")));
        assert_eq!(cell.version(), v.saturating_add(3));
        assert!(cell.snapshot().last_error.is_some());
        assert_eq!(cell.snapshot().state, SessionState::Connecting);
    }

    #[test]
    fn a_terminal_state_never_changes() {
        for (proto, closing, public, err) in [
            (
                State::ExpiredSession,
                false,
                SessionState::Expired,
                Error::SessionExpired,
            ),
            (
                State::AuthFailed,
                false,
                SessionState::AuthFailed,
                Error::AuthFailed,
            ),
            (State::Closed, true, SessionState::Closed, Error::Closing),
        ] {
            let cell = StateCell::new();
            cell.on_session(State::Connected, false, LastErrorUpdate::Keep);
            assert!(cell.terminal_error().is_none());
            assert_eq!(
                cell.on_session(proto, closing, LastErrorUpdate::Keep),
                Some(public)
            );
            assert!(cell.snapshot().disconnected_since.is_some());
            assert_eq!(cell.terminal_error(), Some(err.clone()));
            let v = cell.version();
            assert_eq!(
                cell.on_session(State::Connected, false, LastErrorUpdate::Keep),
                None
            );
            assert_eq!(
                cell.on_session(State::Closed, true, LastErrorUpdate::Clear),
                None
            );
            assert!(!cell.set_closed());
            assert_eq!(cell.version(), v);
            assert_eq!(cell.snapshot().state, public);
            assert_eq!(cell.terminal_error(), Some(err));
        }
    }

    #[test]
    fn set_closed_moves_to_closed_once() {
        let cell = StateCell::new();
        assert!(cell.terminal_error().is_none());
        assert!(cell.set_closed());
        assert!(!cell.set_closed());
        assert_eq!(cell.snapshot().state, SessionState::Closed);
        assert_eq!(cell.terminal_error(), Some(Error::Closing));
        // It never connected, so it has no disconnect time.
        assert!(cell.snapshot().disconnected_since.is_none());
    }

    #[test]
    fn changed_resolves_at_the_next_change_and_wakes_every_watcher() {
        let cell = StateCell::new();
        let mut a = StateWatcher::new(Arc::clone(&cell));
        let mut b = a.clone();
        let ca = Arc::new(CountWake(AtomicUsize::new(0)));
        let cb = Arc::new(CountWake(AtomicUsize::new(0)));
        let wa = Waker::from(Arc::clone(&ca));
        let wb = Waker::from(Arc::clone(&cb));
        // A live future keeps one waker entry, also after a second poll.
        let mut fa = a.changed();
        let mut fb = b.changed();
        let pa = |f: &mut Changed<'_>| Pin::new(f).poll(&mut Context::from_waker(&wa));
        assert!(pa(&mut fa).is_pending());
        assert!(pa(&mut fa).is_pending());
        assert!(
            Pin::new(&mut fb)
                .poll(&mut Context::from_waker(&wb))
                .is_pending()
        );
        assert_eq!(cell.st.lock_unpoisoned().wakers.len(), 2);
        cell.on_session(State::Connected, false, LastErrorUpdate::Keep);
        assert_eq!(ca.0.load(Ordering::SeqCst), 1);
        assert_eq!(cb.0.load(Ordering::SeqCst), 1);
        match pa(&mut fa) {
            Poll::Ready(info) => assert_eq!(info.state, SessionState::Connected),
            Poll::Pending => panic!("no change"),
        }
        drop(fa);
        assert!(poll(&mut a, &wa).is_pending());
        // Two changes merge into one, and epoch shows the reconnect.
        cell.on_session(State::Closed, false, LastErrorUpdate::Keep);
        cell.on_session(State::Connected, false, LastErrorUpdate::Keep);
        match Pin::new(&mut fb).poll(&mut Context::from_waker(&wb)) {
            Poll::Ready(info) => {
                assert_eq!(info.state, SessionState::Connected);
                assert_eq!(info.epoch, 2);
            }
            Poll::Pending => panic!("no change"),
        }
        drop(fb);
        assert!(poll(&mut b, &wb).is_pending());
    }

    #[test]
    fn changed_resolves_at_once_after_a_terminal_state() {
        let cell = StateCell::new();
        let mut w = StateWatcher::new(Arc::clone(&cell));
        cell.on_session(State::ExpiredSession, false, LastErrorUpdate::Keep);
        for _ in 0..3 {
            match poll(&mut w, Waker::noop()) {
                Poll::Ready(info) => assert_eq!(info.state, SessionState::Expired),
                Poll::Pending => panic!("a terminal state must resolve at once"),
            }
        }
        // A watcher made after the terminal state resolves at once too.
        let mut late = StateWatcher::new(Arc::clone(&cell));
        assert!(poll(&mut late, Waker::noop()).is_ready());
        let mut seen = cell.version();
        assert!(cell.wait_changed(&mut seen, Some(soon())).is_some());
    }

    #[test]
    fn a_panicking_waker_does_not_stop_the_change() {
        struct Boom;
        impl Wake for Boom {
            fn wake(self: Arc<Self>) {
                std::panic::panic_any("waker panic");
            }
        }
        let cell = StateCell::new();
        let mut w = StateWatcher::new(Arc::clone(&cell));
        assert!(poll(&mut w, &Waker::from(Arc::new(Boom))).is_pending());
        assert_eq!(
            cell.on_session(State::Connected, false, LastErrorUpdate::Keep),
            Some(SessionState::Connected)
        );
        assert!(poll(&mut w, Waker::noop()).is_ready());
    }

    #[test]
    fn wait_changed_times_out_and_wakes() {
        let cell = StateCell::new();
        let mut seen = cell.version();
        assert!(cell.wait_changed(&mut seen, Some(soon())).is_none());
        let other = Arc::clone(&cell);
        let t = std::thread::spawn(move || {
            other.on_session(State::Connected, false, LastErrorUpdate::Keep)
        });
        let info = cell.wait_changed(&mut seen, None).unwrap();
        assert!(info.state == SessionState::Connected);
        assert_eq!(seen, cell.version());
        assert_eq!(t.join().unwrap(), Some(SessionState::Connected));
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn the_watcher_wait_is_refused_on_the_io_side() {
        let cell = StateCell::new();
        let mut w = StateWatcher::new(Arc::clone(&cell));
        {
            let _io = crate::sync::enter_io_side(3);
            assert_eq!(w.wait_changed().unwrap_err(), Error::InvalidState);
        }
        cell.set_closed();
        assert_eq!(w.wait_changed().unwrap().state, SessionState::Closed);
    }

    #[test]
    fn a_new_cell_is_connecting() {
        let cell = StateCell::new();
        let w = StateWatcher::new(Arc::clone(&cell));
        assert_eq!(w.current().state, SessionState::Connecting);
        assert_eq!(w.current().epoch, 0);
        assert!(w.last_error().is_none());
    }
}
