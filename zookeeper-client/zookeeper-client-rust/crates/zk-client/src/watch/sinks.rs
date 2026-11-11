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

//! The watch sink table.
//!
//! The table maps each `WatchId` to its sink. The router plans the
//! deliveries of one item under the `sinks` lock, a leaf lock. It then
//! releases the lock and applies each delivery. The slot and queue locks
//! wake their receivers only after their own lock is released.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::WatchError;
use crate::slot::Slot;
use crate::tokens::WatchId;

use super::{EventQueue, WatchedEvent};

/// What a watcher receives: one event or one error.
pub(crate) type WatchOutcome = Result<WatchedEvent, WatchError>;

/// The sink of one watcher.
#[derive(Clone, Debug)]
pub(crate) enum Sink {
    /// A one-shot watcher: one outcome, then the sink leaves the table.
    Oneshot(Arc<Slot<WatchOutcome>>),
    /// A persistent watcher: many events, then one terminal error.
    Persistent(Arc<EventQueue>),
}

/// The sinks of one client, keyed by watcher.
#[derive(Debug, Default)]
pub(crate) struct WatchSinks {
    map: HashMap<WatchId, Sink>,
}

impl WatchSinks {
    /// Makes an empty table.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Adds the sink of a new watcher. The sink exists before the
    /// request that arms it is submitted.
    pub(crate) fn insert(&mut self, id: WatchId, sink: Sink) {
        self.map.insert(id, sink);
    }

    /// Removes a sink. The caller drops it after the lock is released.
    pub(crate) fn remove(&mut self, id: WatchId) -> Option<Sink> {
        self.map.remove(&id)
    }

    /// The number of sinks.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Plans the delivery of one node event to `watchers`, in the given
    /// order.
    ///
    /// A one-shot sink leaves the table. A persistent sink stays. An id
    /// with no sink is skipped: its handle is gone. Only the first one-shot
    /// delivery has `count` set, so one `Watch` item counts once against
    /// the read gate. Persistent events never count.
    pub(crate) fn deliver_event(
        &mut self,
        watchers: Vec<WatchId>,
        ev: &WatchedEvent,
    ) -> Vec<Delivery> {
        let mut out = Vec::with_capacity(watchers.len());
        let mut counted = false;
        for id in watchers {
            let persistent = match self.map.get(&id) {
                None => continue,
                Some(Sink::Persistent(q)) => Some(Arc::clone(q)),
                Some(Sink::Oneshot(_)) => None,
            };
            match persistent {
                Some(q) => out.push(Delivery::new(Sink::Persistent(q), Ok(ev.clone()), false)),
                None => {
                    if let Some(sink) = self.map.remove(&id) {
                        let count = !counted;
                        counted = true;
                        out.push(Delivery::new(sink, Ok(ev.clone()), count));
                    }
                }
            }
        }
        out
    }

    /// Plans the terminal error `err` for `watchers`. Each sink leaves the
    /// table. No delivery counts.
    pub(crate) fn terminate(&mut self, watchers: Vec<WatchId>, err: &WatchError) -> Vec<Delivery> {
        watchers
            .into_iter()
            .filter_map(|id| self.map.remove(&id))
            .map(|sink| Delivery::new(sink, Err(err.clone()), false))
            .collect()
    }

    /// Plans `err` for every sink and empties the table. The router uses
    /// it when the client reaches a terminal state or the driver exits.
    pub(crate) fn terminate_all(&mut self, err: &WatchError) -> Vec<Delivery> {
        // Ids grow with each registration, so the sort gives the
        // registration order. That makes the order of the wakes stable.
        let mut all: Vec<(WatchId, Sink)> = self.map.drain().collect();
        all.sort_by_key(|(id, _)| *id);
        all.into_iter()
            .map(|(_, sink)| Delivery::new(sink, Err(err.clone()), false))
            .collect()
    }
}

/// One planned delivery.
#[derive(Debug)]
pub(crate) struct Delivery {
    sink: Sink,
    outcome: WatchOutcome,
    count: bool,
}

/// The effect of one applied delivery.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Applied {
    /// True when the value counts against the read gate.
    pub(crate) counted: bool,
    /// The missed count when a full persistent queue dropped the event,
    /// for `Metrics::watch_lagged`.
    pub(crate) lagged: Option<u64>,
}

impl Delivery {
    /// Makes a delivery.
    pub(crate) fn new(sink: Sink, outcome: WatchOutcome, count: bool) -> Self {
        Self {
            sink,
            outcome,
            count,
        }
    }

    /// Applies the delivery with no `sinks` lock held.
    ///
    /// A one-shot sink takes the outcome through `Slot::fill`. A dead
    /// receiver drops it. A persistent sink pushes an event, or ends with
    /// an error. A terminal error never takes a queue slot.
    pub(crate) fn apply(self) -> Applied {
        match self.sink {
            Sink::Oneshot(slot) => match slot.fill(self.outcome, self.count) {
                Ok(counted) => Applied {
                    counted,
                    lagged: None,
                },
                // The receiver is gone or the slot has its outcome. The
                // rejected outcome drops here, after the slot lock.
                Err(_) => Applied::default(),
            },
            Sink::Persistent(queue) => match self.outcome {
                Ok(ev) => Applied {
                    counted: false,
                    lagged: queue.push(ev),
                },
                Err(err) => {
                    queue.terminate(err);
                    Applied::default()
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use std::task::{Context, Poll, Waker};

    use super::*;
    use crate::path::ZPathBuf;
    use crate::slot::Taken;
    use crate::watch::EventKind;

    fn event(path: &str) -> WatchedEvent {
        WatchedEvent {
            kind: EventKind::NodeDataChanged,
            path: ZPathBuf::new(path.to_owned()).unwrap(),
            zxid: None,
        }
    }

    fn oneshot(t: &mut WatchSinks, id: u64) -> Arc<Slot<WatchOutcome>> {
        let slot = Slot::new();
        t.insert(WatchId(id), Sink::Oneshot(Arc::clone(&slot)));
        slot
    }

    fn persistent(t: &mut WatchSinks, id: u64, bound: Option<usize>) -> Arc<EventQueue> {
        let q = EventQueue::new(bound);
        t.insert(WatchId(id), Sink::Persistent(Arc::clone(&q)));
        q
    }

    fn next(q: &EventQueue) -> Poll<Option<WatchOutcome>> {
        q.poll_next(&mut Context::from_waker(Waker::noop()))
    }

    fn taken(slot: &Slot<WatchOutcome>) -> (WatchOutcome, bool) {
        match slot.try_take() {
            Some(Taken::Value { v, counted }) => (v, counted),
            _ => panic!("no value"),
        }
    }

    #[test]
    fn an_event_counts_once_and_keeps_the_order() {
        let mut t = WatchSinks::new();
        let a = oneshot(&mut t, 1);
        let p = persistent(&mut t, 2, None);
        let b = oneshot(&mut t, 3);
        let ev = event("/x");
        let plan = t.deliver_event(vec![WatchId(2), WatchId(1), WatchId(9), WatchId(3)], &ev);
        assert_eq!(plan.len(), 3);
        assert!(matches!(plan[0].sink, Sink::Persistent(_)));
        assert!(!plan[0].count);
        assert!(plan[1].count);
        assert!(!plan[2].count);
        // The one-shot sinks leave the table. The persistent sink stays.
        assert_eq!(t.len(), 1);
        let applied: Vec<Applied> = plan.into_iter().map(Delivery::apply).collect();
        assert_eq!(
            applied.iter().filter(|a| a.counted).count(),
            1,
            "one Watch item counts once"
        );
        assert_eq!(taken(&a), (Ok(ev.clone()), true));
        assert_eq!(taken(&b), (Ok(ev.clone()), false));
        assert_eq!(next(&p), Poll::Ready(Some(Ok(ev))));
    }

    #[test]
    fn a_persistent_sink_gets_every_event() {
        let mut t = WatchSinks::new();
        let p = persistent(&mut t, 1, None);
        for path in ["/a", "/b"] {
            for d in t.deliver_event(vec![WatchId(1)], &event(path)) {
                assert_eq!(d.apply(), Applied::default());
            }
        }
        assert_eq!(next(&p), Poll::Ready(Some(Ok(event("/a")))));
        assert_eq!(next(&p), Poll::Ready(Some(Ok(event("/b")))));
        assert_eq!(next(&p), Poll::Pending);
    }

    #[test]
    fn a_oneshot_sink_fires_once() {
        let mut t = WatchSinks::new();
        let a = oneshot(&mut t, 1);
        assert_eq!(t.deliver_event(vec![WatchId(1)], &event("/a")).len(), 1);
        assert!(t.deliver_event(vec![WatchId(1)], &event("/a")).is_empty());
        assert!(
            t.terminate(vec![WatchId(1)], &WatchError::Removed)
                .is_empty()
        );
        drop(a);
    }

    #[test]
    fn a_dead_receiver_drops_the_outcome() {
        let mut t = WatchSinks::new();
        let a = oneshot(&mut t, 1);
        assert!(!a.drop_receiver());
        let plan = t.deliver_event(vec![WatchId(1)], &event("/a"));
        assert_eq!(plan.len(), 1);
        for d in plan {
            assert_eq!(d.apply(), Applied::default());
        }
    }

    #[test]
    fn terminate_ends_the_given_sinks_only() {
        let mut t = WatchSinks::new();
        let a = oneshot(&mut t, 1);
        let p = persistent(&mut t, 2, None);
        let other = oneshot(&mut t, 3);
        let plan = t.terminate(
            vec![WatchId(1), WatchId(2), WatchId(7)],
            &WatchError::Removed,
        );
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|d| !d.count));
        assert_eq!(t.len(), 1);
        for d in plan {
            assert!(!d.apply().counted);
        }
        assert_eq!(taken(&a), (Err(WatchError::Removed), false));
        assert_eq!(next(&p), Poll::Ready(Some(Err(WatchError::Removed))));
        assert_eq!(next(&p), Poll::Ready(None));
        assert!(other.try_take().is_none());
    }

    #[test]
    fn terminate_all_empties_the_table_in_id_order() {
        let mut t = WatchSinks::new();
        let mut slots = Vec::new();
        for id in [5, 1, 4, 2, 3] {
            slots.push((id, oneshot(&mut t, id)));
        }
        let p = persistent(&mut t, 6, Some(1));
        let plan = t.terminate_all(&WatchError::SessionExpired);
        assert_eq!(t.len(), 0);
        assert_eq!(plan.len(), 6);
        assert!(matches!(plan[5].sink, Sink::Persistent(_)));
        let order: Vec<bool> = plan.iter().map(|d| d.count).collect();
        assert_eq!(order, vec![false; 6]);
        for d in plan {
            assert_eq!(d.apply(), Applied::default());
        }
        for (_, s) in &slots {
            assert_eq!(taken(s), (Err(WatchError::SessionExpired), false));
        }
        assert_eq!(next(&p), Poll::Ready(Some(Err(WatchError::SessionExpired))));
        assert!(t.terminate_all(&WatchError::Closed).is_empty());
    }

    #[test]
    fn a_full_bounded_queue_reports_the_lag() {
        let mut t = WatchSinks::new();
        let p = persistent(&mut t, 1, Some(1));
        let mut lagged = Vec::new();
        for path in ["/a", "/b", "/c"] {
            for d in t.deliver_event(vec![WatchId(1)], &event(path)) {
                lagged.push(d.apply().lagged);
            }
        }
        assert_eq!(lagged, vec![None, Some(1), Some(2)]);
        assert_eq!(
            next(&p),
            Poll::Ready(Some(Err(WatchError::Lagged { missed: 2 })))
        );
        assert_eq!(next(&p), Poll::Ready(Some(Ok(event("/a")))));
    }
}
