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
//! The config follower of `update_servers_from_config`.
//!
//! The follower keeps one watch armed on `/zookeeper/config`. It starts
//! no thread and no task. It runs on the IO side, inside the router.
//!
//! Each config read gives the client addresses of the ensemble. When
//! they differ from the last list that the follower applied, it calls
//! `set_servers`. Each watch event reads the config again, and that read
//! arms the next watch. A connection loss also reads the config again.
//! A terminal error or any other error stops the follower.
//!
//! The results of the follower have no receiver, so they never count
//! against the read gate.

use std::sync::Mutex;

use zk_proto::TerminateReason;

use crate::connect_string;
use crate::decode;
use crate::error::Error;
use crate::ops;
use crate::shared::Shared;
use crate::sync::LockExt;
use crate::tokens::{RawResult, WatchId};

/// The state of the config follower of one client.
#[derive(Debug, Default)]
pub(crate) struct ConfigFollow {
    inner: Mutex<Inner>,
}

/// The fields of [`ConfigFollow`].
#[derive(Debug, Default)]
struct Inner {
    /// The watcher of the read in flight, or of the armed watch.
    watch: Option<WatchId>,
    /// The connect string that the follower applied last.
    applied: Option<String>,
    /// True after a stop. A stopped follower does nothing more.
    stopped: bool,
}

impl ConfigFollow {
    /// Records `id` as the current watcher. It returns false when the
    /// follower is stopped.
    fn arm(&self, id: WatchId) -> bool {
        let mut s = self.inner.lock_unpoisoned();
        if s.stopped {
            return false;
        }
        s.watch = Some(id);
        true
    }

    /// Stops the follower and gives the current watcher, if any.
    fn stop(&self) -> Option<WatchId> {
        let mut s = self.inner.lock_unpoisoned();
        s.stopped = true;
        s.watch.take()
    }

    /// True when `watchers` contains the current watcher.
    fn owns_any(&self, watchers: &[WatchId]) -> bool {
        let s = self.inner.lock_unpoisoned();
        s.watch.is_some_and(|w| watchers.contains(&w))
    }

    /// Records `next` as the applied string. It returns true when the
    /// string is new, so the caller applies it.
    fn take_change(&self, next: &str) -> bool {
        let mut s = self.inner.lock_unpoisoned();
        if s.stopped || s.applied.as_deref() == Some(next) {
            return false;
        }
        s.applied = Some(next.to_owned());
        true
    }
}

/// Reads the config and arms the next watch. A refusal stops the
/// follower.
pub(crate) fn read(shared: &Shared) {
    let id = shared.new_watch_id();
    if !shared.router.follow.arm(id) {
        return;
    }
    if !shared.submit_follow(ops::get_config(Some(id))) {
        stop(shared);
    }
}

/// Stops the follower and detaches its watcher from proto.
fn stop(shared: &Shared) {
    if let Some(id) = shared.router.follow.stop() {
        shared.detach_watch(id);
    }
}

/// Handles the result of one config read.
///
/// A config that does not parse, a config with no client address, or a
/// list that does not parse changes nothing. The watch of the read stays
/// armed.
pub(crate) fn on_result(shared: &Shared, r: RawResult) {
    match decode::config(r) {
        Ok((cfg, _stat)) => {
            let Some(next) = cfg.client_connect_string() else {
                return;
            };
            if !shared.router.follow.take_change(&next) {
                return;
            }
            if let Ok(hosts) = connect_string::parse_update(&next) {
                // A result of 0 means that the driver exited. The next
                // read then fails, and that failure stops the follower.
                let _generation = shared.driver.set_servers(hosts);
            }
        }
        Err(Error::ConnectionLoss | Error::OperationTimeout | Error::RequestTimeout) => {
            read(shared);
        }
        // The read succeeded and armed its watch, but the text does not
        // parse. A standalone server has an empty config, for example.
        // The next change of the node reads it again.
        Err(Error::MarshallingError) => {}
        Err(_) => stop(shared),
    }
}

/// Handles a node event. It reads the config again when the event is
/// for the follower watch. It returns true in that case.
pub(crate) fn on_watch(shared: &Shared, watchers: &[WatchId]) -> bool {
    if !shared.router.follow.owns_any(watchers) {
        return false;
    }
    read(shared);
    true
}

/// Handles the end of watches. A lost connection reads the config
/// again. Any other reason stops the follower.
pub(crate) fn on_terminated(shared: &Shared, watchers: &[WatchId], reason: TerminateReason) {
    if !shared.router.follow.owns_any(watchers) {
        return;
    }
    match reason {
        TerminateReason::ConnectionLost => read(shared),
        TerminateReason::Removed
        | TerminateReason::SessionExpired
        | TerminateReason::AuthFailed
        | TerminateReason::Closed => stop(shared),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stopped_follower_arms_nothing() {
        let f = ConfigFollow::default();
        assert!(f.arm(WatchId(1)));
        assert!(f.owns_any(&[WatchId(2), WatchId(1)]));
        assert!(!f.owns_any(&[WatchId(2)]));
        assert_eq!(f.stop(), Some(WatchId(1)));
        assert!(!f.arm(WatchId(3)));
        assert!(!f.owns_any(&[WatchId(3)]));
        assert!(!f.take_change("a:1"));
    }

    #[test]
    fn only_a_new_string_applies() {
        let f = ConfigFollow::default();
        assert!(f.take_change("a:1"));
        assert!(!f.take_change("a:1"));
        assert!(f.take_change("a:1,b:2"));
    }
}
