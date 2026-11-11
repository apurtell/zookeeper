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

//! The router: the `RouteSink` of the native client.
//!
//! The router calls the sinks, the state cell and the observer.
//!
//! The driver calls `route` on the IO side, in outbox order, with the
//! core unlocked. The router never blocks. It fills result slots, plans
//! watch deliveries under the `sinks` lock and applies them after the
//! lock is released, and updates the state cell. Decoding runs later, on
//! the task of the caller.
//!
//! The return value of `route` tells the driver that the item counts
//! against the read gate. Only a value that a live receiver still has
//! to take counts.

use std::sync::{Arc, Mutex, OnceLock, Weak};

use zk_driver::{Item, RouteSink};
use zk_proto::{LogRecord, State};

use crate::error::{LastError, LastErrorUpdate, WatchError, last_error_for};
use crate::follow::{self, ConfigFollow};
use crate::future::ReadyWaiters;
use crate::observe::{Observer, OpKind};
use crate::shared::Shared;
use crate::sync::{LockExt, enter_io_side};
use crate::tokens::{NativeCompletion, NativeTokens, RawResult, WatchId};
use crate::watch::{
    Applied, Delivery, SessionState, StateCell, WatchSinks, event_from_proto, watch_error_for,
};

/// Gives the TLS configuration error of the current connection attempt.
/// The TLS options make it. The type keeps the router free of the `tls`
/// feature.
pub(crate) type TlsErrorSource = Arc<dyn Fn() -> Option<LastError> + Send + Sync>;

/// The router of one client.
pub(crate) struct Router {
    /// The watch sinks. A leaf lock.
    pub(crate) sinks: Mutex<WatchSinks>,
    /// The session state.
    pub(crate) state: Arc<StateCell>,
    /// The log renderer and the metrics hook.
    pub(crate) observe: Arc<Observer>,
    /// The waiters of `Client::ready`.
    pub(crate) ready: ReadyWaiters,
    /// The client state, set once after the driver starts. The router
    /// holds it weakly, so the driver never keeps the client alive.
    shared: OnceLock<Weak<Shared>>,
    /// The TLS error source, when TLS is on.
    tls_error: Option<TlsErrorSource>,
    /// The follower of `/zookeeper/config`. It does nothing until
    /// `follow::read` starts it.
    pub(crate) follow: ConfigFollow,
    /// The client id of the IO-side marker.
    client: u64,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl Router {
    /// Makes the router of client `client`.
    pub(crate) fn new(
        state: Arc<StateCell>,
        observe: Arc<Observer>,
        tls_error: Option<TlsErrorSource>,
        client: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            sinks: Mutex::new(WatchSinks::new()),
            state,
            observe,
            ready: ReadyWaiters::new(),
            shared: OnceLock::new(),
            tls_error,
            follow: ConfigFollow::default(),
            client,
        })
    }

    /// Binds the router to its client after the driver starts. A second
    /// call does nothing.
    pub(crate) fn bind(&self, shared: &Arc<Shared>) {
        let _ = self.shared.set(Arc::downgrade(shared));
    }

    /// The client state, while the client exists.
    fn shared(&self) -> Option<Arc<Shared>> {
        self.shared.get().and_then(Weak::upgrade)
    }

    /// Renders the delivery lines of one item.
    fn log_all(&self, logs: &[LogRecord]) {
        for rec in logs {
            self.observe.log(rec);
        }
    }

    /// Applies planned deliveries with no lock held. It returns true when
    /// one of them counts, and reports dropped persistent events.
    fn apply(&self, deliveries: Vec<Delivery>) -> bool {
        let mut counted = false;
        for d in deliveries {
            let Applied { counted: c, lagged } = d.apply();
            counted |= c;
            if let Some(missed) = lagged {
                self.observe.watch_lagged(missed);
            }
        }
        counted
    }

    /// Ends every sink with `err`.
    fn terminate_all(&self, err: &WatchError) {
        let deliveries = self.sinks.lock_unpoisoned().terminate_all(err);
        self.apply(deliveries);
    }

    /// Routes one result. A receiver that is gone leaves a watch with no
    /// handle, so the router detaches it now. Proto then sends the
    /// server removal when the watch has no other user.
    fn on_result(&self, token: NativeCompletion, result: RawResult) -> bool {
        let t = match token {
            NativeCompletion::Discard => return false,
            NativeCompletion::Follow => {
                if let Some(shared) = self.shared() {
                    follow::on_result(&shared, result);
                }
                self.ready.wake_all();
                return false;
            }
            NativeCompletion::Reply(t) => t,
        };
        let kind = t.kind;
        let started = t.started;
        let watch = t.watch;
        let rc = result.rc;
        let counted = match t.complete(result, true) {
            Ok(counted) => counted,
            Err(_dropped) => {
                if let Some(id) = watch {
                    self.detach_orphan(id);
                }
                false
            }
        };
        self.after_request(kind, rc, started);
        counted
    }

    /// Detaches a watch whose request has no receiver.
    fn detach_orphan(&self, id: WatchId) {
        if let Some(shared) = self.shared() {
            shared.drop_watch_sink(id);
        }
    }

    /// Runs the metrics of one completed request and wakes the
    /// `ready` waiters.
    fn after_request(&self, kind: OpKind, rc: i32, started: std::time::Instant) {
        self.observe.request_completed(kind, rc, started.elapsed());
        if self.observe.has_metrics() {
            if let Some(n) = self.shared().and_then(|s| s.pending_len()) {
                self.observe.pending_requests(n);
            }
        }
        self.ready.wake_all();
    }

    /// Routes one session state.
    fn on_session(&self, state: State) {
        let (closing, cause, errno) = self
            .shared()
            .and_then(|s| {
                s.read_conn(|c| {
                    (
                        c.is_closing(),
                        c.last_teardown_cause(),
                        c.last_teardown_errno(),
                    )
                })
            })
            .unwrap_or((true, None, None));
        let update = match (state, cause) {
            (State::Connected | State::ReadOnly, _) | (_, None) => LastErrorUpdate::Keep,
            (_, Some(cause)) => {
                let tls = self.tls_error.as_ref().and_then(|f| f());
                last_error_for(cause, errno, tls)
            }
        };
        let Some(new) = self.state.on_session(state, closing, update) else {
            return;
        };
        self.observe.state_changed(new);
        if let Some(err) = terminal_watch_error(new) {
            self.terminate_all(&err);
            self.ready.wake_all();
        }
    }

    /// Runs when the IO thread of the thread driver exits. It moves the
    /// state to `Closed`, ends every sink and wakes every `ready` waiter. A
    /// second call finds nothing to do.
    pub(crate) fn on_exit(&self) {
        if self.state.set_closed() {
            self.observe.state_changed(SessionState::Closed);
        }
        self.terminate_all(&WatchError::Closed);
        self.ready.wake_all();
    }
}

/// The watch error of a terminal state.
fn terminal_watch_error(state: SessionState) -> Option<WatchError> {
    match state {
        SessionState::Expired => Some(WatchError::SessionExpired),
        SessionState::AuthFailed => Some(WatchError::AuthFailed),
        SessionState::Closed => Some(WatchError::Closed),
        _ => None,
    }
}

impl RouteSink<NativeTokens> for Router {
    /// Routes one item. Each item runs inside the IO-side marker, so a
    /// blocking wait in a hook fails with `InvalidState`.
    fn route(&self, item: Item<NativeTokens>) -> bool {
        let _io = enter_io_side(self.client);
        match item {
            Item::Log(rec) => {
                self.observe.log(&rec);
                false
            }
            Item::Result {
                token,
                result,
                delivery_logs,
            } => {
                self.log_all(&delivery_logs);
                self.on_result(token, result)
            }
            Item::AuthResult { token, rc } => {
                let started = token.started;
                let counted = token.complete(rc, true).unwrap_or(false);
                self.after_request(OpKind::AddAuth, rc, started);
                counted
            }
            Item::Watch {
                event,
                watchers,
                delivery_logs,
            } => {
                self.log_all(&delivery_logs);
                // An event that does not convert has no receiver. Its
                // one-shot sinks stay until their handles drop.
                let Some(ev) = event_from_proto(&event) else {
                    return false;
                };
                let kind = ev.kind;
                if let Some(shared) = self.shared() {
                    follow::on_watch(&shared, &watchers);
                }
                let deliveries = self.sinks.lock_unpoisoned().deliver_event(watchers, &ev);
                let counted = self.apply(deliveries);
                self.observe.watch_event(kind);
                counted
            }
            Item::Session {
                state,
                watchers: _,
                delivery_logs,
            } => {
                self.log_all(&delivery_logs);
                self.on_session(state);
                false
            }
            Item::WatchTerminated { watchers, reason } => {
                if let Some(shared) = self.shared() {
                    follow::on_terminated(&shared, &watchers, reason);
                }
                let err = watch_error_for(reason);
                let deliveries = self.sinks.lock_unpoisoned().terminate(watchers, &err);
                self.apply(deliveries);
                false
            }
            Item::AuthLockpoint | Item::Sasl(_) | Item::Thread { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states_map_to_watch_errors() {
        assert_eq!(
            terminal_watch_error(SessionState::Expired),
            Some(WatchError::SessionExpired)
        );
        assert_eq!(terminal_watch_error(SessionState::Connected), None);
    }

    #[test]
    fn a_discarded_result_does_not_count() {
        let r = Router::new(
            StateCell::new(),
            Arc::new(Observer::new(None, None)),
            None,
            1,
        );
        let res = RawResult {
            rc: 0,
            zxid: 0,
            origin: zk_proto::Origin::Reply,
            reply: None,
        };
        assert!(!r.on_result(NativeCompletion::Discard, res));
    }
}
