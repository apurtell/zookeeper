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

//! Session helpers of the recipes.
//!
//! A terminal session state ends each recipe with the error of that
//! state: `SessionExpired`, `AuthFailed` or `Closing`. The same mapping
//! applies to the terminal errors of a watcher.

use apache_zookeeper::{
    Error, ResponseFuture, SessionInfo, SessionState, StateWatcher, WatchError,
};

/// The error of a terminal session state, or `None` for a state that
/// is not terminal.
pub(crate) fn terminal_error(state: SessionState) -> Option<Error> {
    match state {
        SessionState::Expired => Some(Error::SessionExpired),
        SessionState::AuthFailed => Some(Error::AuthFailed),
        SessionState::Closed => Some(Error::Closing),
        _ => None,
    }
}

/// The session error of a terminal watch error, or `None` for a watch
/// error that does not end the session (`Removed`, `ConnectionLost`,
/// `Lagged`, `InvalidState`). The caller decides what those mean.
pub(crate) fn watch_terminal_error(e: &WatchError) -> Option<Error> {
    match e {
        WatchError::SessionExpired => Some(Error::SessionExpired),
        WatchError::AuthFailed => Some(Error::AuthFailed),
        WatchError::Closed => Some(Error::Closing),
        _ => None,
    }
}

/// Waits until the session is connected with an epoch above `after`.
/// A read-only connection counts as connected.
///
/// # Errors
///
/// The error of a terminal state (see [`terminal_error`]).
pub(crate) async fn connected_after(
    state: &mut StateWatcher,
    after: u64,
) -> Result<SessionInfo, Error> {
    wait_for(state, |info| {
        info.state.is_connected() && info.epoch > after
    })
    .await
}

/// Waits until the session is `Connected` with an epoch above `after`,
/// and gives that epoch. A read-only connection does not count, because
/// a read-only server applies no write. It gives `None` when the session
/// ends.
pub(crate) async fn writable_after(state: &mut StateWatcher, after: u64) -> Option<u64> {
    let ready = |info: &SessionInfo| info.state == SessionState::Connected && info.epoch > after;
    wait_for(state, ready).await.ok().map(|info| info.epoch)
}

/// Waits until `ready` accepts the session state. A terminal state ends
/// the wait with its error.
async fn wait_for(
    state: &mut StateWatcher,
    ready: impl Fn(&SessionInfo) -> bool,
) -> Result<SessionInfo, Error> {
    loop {
        let info = state.current();
        if let Some(e) = terminal_error(info.state) {
            return Err(e);
        }
        if ready(&info) {
            return Ok(info);
        }
        // A terminal state never merges away, so the loop sees it.
        let _ = state.changed().await;
    }
}

/// Gives the value of `result`, or `None` after a connection loss. After
/// a loss it first waits until the session is connected with an epoch
/// above `epoch`, so that the caller can try again.
///
/// # Errors
///
/// Each error of `result` other than a connection loss, or the error of
/// a terminal state during the wait.
pub(crate) async fn after_loss<T>(
    result: Result<T, Error>,
    state: &mut StateWatcher,
    epoch: u64,
) -> Result<Option<T>, Error> {
    match result {
        Err(e) if e.is_connection_loss() => connected_after(state, epoch).await.map(|_| None),
        other => other.map(Some),
    }
}

/// True for an error after which a new connection can succeed: a
/// connection loss, or `NotReadOnly` from a read-only server.
pub(crate) fn is_retryable(e: &Error) -> bool {
    e.is_connection_loss() || matches!(e, Error::NotReadOnly)
}

/// Awaits a `sync`, then the list that went out after it. The list
/// gives its own `NoNode`, so that error of the `sync` does not count.
///
/// The caller owns the list. Thus the caller controls when an unread
/// list drops.
pub(crate) async fn synced_list(
    sync: ResponseFuture<()>,
    list: &mut ResponseFuture<Vec<String>>,
) -> Result<Vec<String>, Error> {
    match sync.await {
        Ok(()) | Err(Error::NoNode) => list.await,
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states_map_to_errors() {
        assert_eq!(
            terminal_error(SessionState::Expired),
            Some(Error::SessionExpired)
        );
        assert_eq!(
            terminal_error(SessionState::AuthFailed),
            Some(Error::AuthFailed)
        );
        assert_eq!(terminal_error(SessionState::Closed), Some(Error::Closing));
        assert_eq!(terminal_error(SessionState::Connecting), None);
        assert_eq!(terminal_error(SessionState::Connected), None);
        assert_eq!(terminal_error(SessionState::ConnectedReadOnly), None);
    }

    #[test]
    fn terminal_watch_errors_map_to_errors() {
        assert_eq!(
            watch_terminal_error(&WatchError::SessionExpired),
            Some(Error::SessionExpired)
        );
        assert_eq!(
            watch_terminal_error(&WatchError::AuthFailed),
            Some(Error::AuthFailed)
        );
        assert_eq!(
            watch_terminal_error(&WatchError::Closed),
            Some(Error::Closing)
        );
        assert_eq!(watch_terminal_error(&WatchError::Removed), None);
        assert_eq!(watch_terminal_error(&WatchError::ConnectionLost), None);
        assert_eq!(
            watch_terminal_error(&WatchError::Lagged { missed: 1 }),
            None
        );
    }
}
