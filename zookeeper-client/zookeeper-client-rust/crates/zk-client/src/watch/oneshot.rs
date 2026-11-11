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

//! `OneshotWatcher`: exactly one outcome.
//!
//! The watcher exists only after its request succeeds, because the
//! decoder of the watched request makes it. Its sink exists from the
//! submit on, so an event right after the reply is never lost.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use crate::decode;
use crate::driver::Gate;
use crate::error::{Error, WatchError};
use crate::future::{ResponseFuture, report_taken};
use crate::path::{ZPath, ZPathBuf};
use crate::shared::Shared;
use crate::slot::{Slot, Taken};
#[cfg(feature = "blocking")]
use crate::sync::blocking_refused;
use crate::tokens::WatchId;

use super::{WatchOutcome, WatchedEvent, WatcherKind};

/// A one-shot watcher. It resolves once: to the event, or to the
/// terminal [`WatchError`].
///
/// It does not keep the session open. Dropping it before the outcome
/// detaches the watcher. When it was the last local user of the server
/// watch, the client sends `RemoveWatches`.
#[must_use = "dropping the watcher removes the watch"]
pub struct OneshotWatcher {
    id: WatchId,
    slot: Arc<Slot<WatchOutcome>>,
    shared: Weak<Shared>,
    /// The read gate. It stays valid after the drop of the last clone,
    /// while the driver drains the queue.
    gate: Option<Gate>,
    path: ZPathBuf,
    kind: WatcherKind,
    /// True after the outcome was taken, or after `remove`.
    done: bool,
}

impl std::fmt::Debug for OneshotWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneshotWatcher")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl OneshotWatcher {
    /// Makes the handle of an armed watcher. Only `OneshotReg::arm`
    /// calls it.
    pub(crate) fn new(
        id: WatchId,
        slot: Arc<Slot<WatchOutcome>>,
        shared: Weak<Shared>,
        gate: Option<Gate>,
        path: ZPathBuf,
        kind: WatcherKind,
    ) -> Self {
        Self {
            id,
            slot,
            shared,
            gate,
            path,
            kind,
            done: false,
        }
    }

    /// The watched path, as the caller gave it.
    #[must_use]
    pub fn path(&self) -> ZPath<'_> {
        self.path.as_path()
    }

    /// `Data` for a data or exist watch, `Children` for a child watch.
    #[must_use]
    pub fn kind(&self) -> WatcherKind {
        self.kind
    }

    /// Removes the watcher and returns the server result.
    ///
    /// When other local users of the server watch remain, it resolves to
    /// `Ok(())` with no request.
    pub fn remove(mut self) -> ResponseFuture<()> {
        self.done = true;
        if self.slot.drop_receiver() {
            report_taken(self.gate.as_ref());
        }
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

    /// Takes one outcome from the slot and keeps the read-gate rule.
    fn finish(&mut self, t: Taken<WatchOutcome>) -> WatchOutcome {
        self.done = true;
        match t {
            Taken::Value { v, counted } => {
                if counted {
                    report_taken(self.gate.as_ref());
                }
                v
            }
            Taken::Closed => {
                // The slot closed with no outcome. The sink can still be
                // in the table, so the watcher detaches here.
                let shared = self.shared.upgrade();
                let err = shared
                    .as_ref()
                    .and_then(|s| s.terminal_error())
                    .map_or(WatchError::Closed, |e| watch_error_of(&e));
                if let Some(s) = shared {
                    s.drop_watch_sink(self.id);
                }
                Err(err)
            }
        }
    }

    /// Blocks until the outcome.
    ///
    /// # Errors
    ///
    /// The terminal [`WatchError`]. It returns `WatchError::InvalidState`
    /// at once on the IO side of a client, and in a tokio runtime context
    /// when the tokio driver runs the client.
    #[cfg(feature = "blocking")]
    pub fn wait(mut self) -> Result<WatchedEvent, WatchError> {
        if blocking_refused(self.gate.as_ref().is_some_and(Gate::is_tokio)) {
            return Err(WatchError::InvalidState);
        }
        loop {
            // With no deadline the wait returns only with an outcome.
            if let Some(t) = self.slot.wait_take(None) {
                return self.finish(t);
            }
        }
    }
}

impl Future for OneshotWatcher {
    type Output = Result<WatchedEvent, WatchError>;

    /// Takes the outcome from the slot. A counted value calls
    /// `Shared::taken`. A closed slot gives the terminal error of the
    /// client as a `WatchError`, or `WatchError::Closed`. A poll after the
    /// outcome gives `WatchError::Closed`.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(WatchError::Closed));
        }
        match this.slot.poll_take(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(t) => Poll::Ready(this.finish(t)),
        }
    }
}

impl Drop for OneshotWatcher {
    /// Before the outcome: drops the receiver (a counted value calls
    /// `Shared::taken`) and calls `Shared::drop_watch_sink`. After the
    /// outcome it does nothing.
    fn drop(&mut self) {
        if self.done {
            return;
        }
        if self.slot.drop_receiver() {
            report_taken(self.gate.as_ref());
        }
        if let Some(shared) = self.shared.upgrade() {
            shared.drop_watch_sink(self.id);
        }
    }
}

/// The watch error of a terminal request error.
fn watch_error_of(e: &Error) -> WatchError {
    match e {
        Error::SessionExpired => WatchError::SessionExpired,
        Error::AuthFailed => WatchError::AuthFailed,
        _ => WatchError::Closed,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    use super::*;
    use crate::watch::EventKind;

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn event() -> WatchedEvent {
        WatchedEvent {
            kind: EventKind::NodeDeleted,
            path: ZPathBuf::new("/a".to_owned()).unwrap(),
            zxid: None,
        }
    }

    fn watcher(slot: &Arc<Slot<WatchOutcome>>) -> OneshotWatcher {
        OneshotWatcher::new(
            WatchId(1),
            Arc::clone(slot),
            Weak::new(),
            None,
            ZPathBuf::new("/a".to_owned()).unwrap(),
            WatcherKind::Data,
        )
    }

    fn poll(w: &mut OneshotWatcher, waker: &Waker) -> Poll<WatchOutcome> {
        Pin::new(w).poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn poll_gives_one_outcome_then_closed() {
        let slot = Slot::new();
        let mut w = watcher(&slot);
        assert_eq!(w.path().as_str(), "/a");
        assert_eq!(w.kind(), WatcherKind::Data);
        let c = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&c));
        assert!(poll(&mut w, &waker).is_pending());
        assert_eq!(slot.fill(Ok(event()), true), Ok(true));
        assert_eq!(c.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll(&mut w, &waker), Poll::Ready(Ok(event())));
        assert_eq!(poll(&mut w, &waker), Poll::Ready(Err(WatchError::Closed)));
        drop(w);
        // The handle took the outcome, so the drop leaves the slot alone.
        assert!(slot.receiver_alive());
    }

    #[test]
    fn a_terminal_error_is_the_outcome() {
        let slot = Slot::new();
        let mut w = watcher(&slot);
        assert_eq!(slot.fill(Err(WatchError::SessionExpired), false), Ok(false));
        assert_eq!(
            poll(&mut w, Waker::noop()),
            Poll::Ready(Err(WatchError::SessionExpired))
        );
    }

    #[test]
    fn a_closed_slot_with_no_client_gives_closed() {
        let slot = Slot::new();
        let mut w = watcher(&slot);
        slot.close();
        assert_eq!(
            poll(&mut w, Waker::noop()),
            Poll::Ready(Err(WatchError::Closed))
        );
    }

    #[test]
    fn a_drop_before_the_outcome_drops_the_receiver() {
        let slot = Slot::new();
        let w = watcher(&slot);
        drop(w);
        assert!(!slot.receiver_alive());
        assert!(slot.fill(Ok(event()), true).is_err());
    }

    #[test]
    fn a_drop_with_a_pending_outcome_drops_it() {
        let slot = Slot::new();
        let w = watcher(&slot);
        assert_eq!(slot.fill(Ok(event()), true), Ok(true));
        drop(w);
        assert!(!slot.receiver_alive());
        assert!(slot.try_take().is_none());
    }

    #[test]
    fn terminal_errors_map_to_watch_errors() {
        assert_eq!(
            watch_error_of(&Error::SessionExpired),
            WatchError::SessionExpired
        );
        assert_eq!(watch_error_of(&Error::AuthFailed), WatchError::AuthFailed);
        assert_eq!(watch_error_of(&Error::Closing), WatchError::Closed);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn wait_is_refused_on_the_io_side_and_blocks_elsewhere() {
        let slot = Slot::new();
        {
            let w = watcher(&slot);
            let _io = crate::sync::enter_io_side(7);
            assert_eq!(w.wait(), Err(WatchError::InvalidState));
        }
        let slot = Slot::new();
        let w = watcher(&slot);
        let filler = Arc::clone(&slot);
        let t = std::thread::spawn(move || filler.fill(Ok(event()), false));
        assert_eq!(w.wait(), Ok(event()));
        assert_eq!(t.join().unwrap(), Ok(false));
    }
}
