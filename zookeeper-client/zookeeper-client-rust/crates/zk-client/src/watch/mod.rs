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

//! Watches and session state.
//!
//! The IO side pushes each event into the sink of each watcher: a slot
//! for a one-shot watcher, a queue for a persistent watcher. The handles
//! take events on the caller's task. Session state goes only to
//! `StateWatcher` (`session_fanout_to_path_watchers = false`).

mod oneshot;
mod persistent;
mod sinks;
mod state;

pub use oneshot::OneshotWatcher;
pub(crate) use persistent::EventQueue;
pub use persistent::{Next, PersistentWatcher};
pub(crate) use sinks::{Applied, Delivery, Sink, WatchOutcome, WatchSinks};
pub(crate) use state::StateCell;
pub use state::{Changed, SessionInfo, SessionState, StateWatcher};

use zk_proto::TerminateReason;

use crate::error::WatchError;
use crate::path::ZPathBuf;
use crate::types::Zxid;

/// One node event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchedEvent {
    /// What happened.
    pub kind: EventKind,
    /// The node path. zk-proto strips the chroot on a component boundary.
    pub path: ZPathBuf,
    /// The zxid of the notification, or `None` when the server sent a
    /// value of 0 or less (servers before 3.9).
    pub zxid: Option<Zxid>,
}

/// The kind of a node event.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventKind {
    /// The node was created.
    NodeCreated,
    /// The node was deleted.
    NodeDeleted,
    /// The data of the node changed.
    NodeDataChanged,
    /// The children of the node changed.
    NodeChildrenChanged,
}

/// The mode of a persistent watch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddWatchMode {
    /// Every event on the path itself.
    Persistent,
    /// Created, changed and deleted events on the path and every
    /// descendant.
    PersistentRecursive,
}

impl AddWatchMode {
    /// The `AddWatchRequest.mode` value: 0 or 1.
    pub(crate) const fn wire(self) -> i32 {
        match self {
            Self::Persistent => 0,
            Self::PersistentRecursive => 1,
        }
    }

    /// The watcher kind of the mode, for `remove_watches`.
    #[cfg(test)]
    pub(crate) const fn kind(self) -> WatcherKind {
        match self {
            Self::Persistent => WatcherKind::Persistent,
            Self::PersistentRecursive => WatcherKind::PersistentRecursive,
        }
    }
}

/// The class of watchers that `remove_watches` removes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WatcherKind {
    /// Child watchers.
    Children,
    /// Data and exist watchers.
    Data,
    /// Every class.
    Any,
    /// Persistent watchers.
    Persistent,
    /// Persistent recursive watchers.
    PersistentRecursive,
}

impl WatcherKind {
    /// The `RemoveWatchesRequest.type` value: 1 to 5.
    pub(crate) const fn wire(self) -> i32 {
        match self {
            Self::Children => 1,
            Self::Data => 2,
            Self::Any => 3,
            Self::Persistent => 4,
            Self::PersistentRecursive => 5,
        }
    }
}

/// Converts a proto node event.
///
/// Event types 1 to 4 map to [`EventKind`]. Every other type gives
/// `None`: session events, which never reach a path watcher natively,
/// and the `*WatchRemoved` types, which come as `WatchTerminated`. A
/// path that is null or not UTF-8 also gives `None`. A zxid of 0 or
/// less gives `zxid: None`.
pub(crate) fn event_from_proto(ev: &zk_proto::WatchedEvent) -> Option<WatchedEvent> {
    let kind = match ev.event_type {
        1 => EventKind::NodeCreated,
        2 => EventKind::NodeDeleted,
        3 => EventKind::NodeDataChanged,
        4 => EventKind::NodeChildrenChanged,
        _ => return None,
    };
    let bytes = ev.path.as_bytes()?;
    let path = ZPathBuf::from_server(bytes.to_vec()).ok()?;
    let zxid = (ev.zxid > 0).then_some(Zxid(ev.zxid));
    Some(WatchedEvent { kind, path, zxid })
}

pub(super) use crate::sync::wake_quietly;

/// The terminal watch error of a proto termination reason.
pub(crate) fn watch_error_for(reason: TerminateReason) -> WatchError {
    match reason {
        TerminateReason::Removed => WatchError::Removed,
        TerminateReason::ConnectionLost => WatchError::ConnectionLost,
        TerminateReason::SessionExpired => WatchError::SessionExpired,
        TerminateReason::AuthFailed => WatchError::AuthFailed,
        TerminateReason::Closed => WatchError::Closed,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn proto_event(event_type: i32, path: zk_jute::JString, zxid: i64) -> zk_proto::WatchedEvent {
        zk_proto::WatchedEvent {
            event_type,
            state: 3,
            path,
            zxid,
        }
    }

    #[test]
    fn node_event_types_convert() {
        let cases = [
            (1, EventKind::NodeCreated),
            (2, EventKind::NodeDeleted),
            (3, EventKind::NodeDataChanged),
            (4, EventKind::NodeChildrenChanged),
        ];
        for (t, kind) in cases {
            let ev = event_from_proto(&proto_event(t, "/a/b".into(), 7)).unwrap();
            assert_eq!(ev.kind, kind);
            assert_eq!(ev.path.as_str(), "/a/b");
            assert_eq!(ev.zxid, Some(Zxid(7)));
        }
    }

    #[test]
    fn other_event_types_give_none() {
        // Type -1 is a session event. Types 5 to 7 are the removal types.
        for t in [-1, 0, 5, 6, 7, 8, i32::MAX, i32::MIN] {
            assert!(event_from_proto(&proto_event(t, "/a".into(), 1)).is_none());
        }
    }

    #[test]
    fn a_zxid_of_zero_or_less_gives_none() {
        for z in [0, -1, i64::MIN] {
            let ev = event_from_proto(&proto_event(3, "/a".into(), z)).unwrap();
            assert_eq!(ev.zxid, None);
        }
    }

    #[test]
    fn a_null_or_bad_path_gives_none() {
        assert!(event_from_proto(&proto_event(1, zk_jute::JString::Null, 1)).is_none());
        let bad = zk_jute::JString::from(vec![b'/', 0xff, 0xfe]);
        assert!(event_from_proto(&proto_event(1, bad, 1)).is_none());
    }

    #[test]
    fn a_panicking_waker_is_contained() {
        struct Boom;
        impl std::task::Wake for Boom {
            fn wake(self: std::sync::Arc<Self>) {
                std::panic::panic_any("waker panic");
            }
        }
        wake_quietly(std::task::Waker::from(std::sync::Arc::new(Boom)));
    }

    #[test]
    fn wire_values() {
        assert_eq!(AddWatchMode::Persistent.wire(), 0);
        assert_eq!(AddWatchMode::PersistentRecursive.wire(), 1);
        assert_eq!(WatcherKind::Children.wire(), 1);
        assert_eq!(WatcherKind::PersistentRecursive.wire(), 5);
        assert_eq!(
            AddWatchMode::PersistentRecursive.kind(),
            WatcherKind::PersistentRecursive
        );
        assert_eq!(watch_error_for(TerminateReason::Closed), WatchError::Closed);
    }
}
