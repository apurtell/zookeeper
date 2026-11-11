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

//! The blocking facade (feature `blocking`).
//!
//! Each method is `self.inner.op(..).wait()`. Thus this file has no
//! logic of its own, and it is complete when the async methods are
//! complete. `wait()` blocks on the slot condvar and needs no executor.
//! On the IO side of a client it fails with `InvalidState`.

use std::net::SocketAddr;
use std::time::Duration;

use crate::acl::Acl;
use crate::auth::ClientInfo;
use crate::builder::{ClientBuilder, Runtime, ThreadOptions};
use crate::client::ClientStats;
use crate::config::{EnsembleConfig, Reconfig};
use crate::error::{ConnectError, MultiError, Result};
use crate::multi::{MultiReader, MultiResults, MultiWriter, ReadResult};
use crate::path::{PathArg, ZPathBuf};
use crate::types::{CreateMode, SessionId, SessionPassword, Stat, VersionArg, Zxid};
use crate::watch::{
    AddWatchMode, OneshotWatcher, PersistentWatcher, SessionInfo, StateWatcher, WatcherKind,
};

/// Makes each forwarding method of the facade. A method with `=> wait`
/// blocks on the future of the async method. A method without it gives
/// the value of the async method as it is.
macro_rules! wait_forward {
    ($(
        $(#[$attr:meta])*
        fn $name:ident(&self $(, $arg:ident: $ty:ty)* $(,)?) -> $ret:ty $(=> $wait:ident)?;
    )+) => {
        $(
            $(#[$attr])*
            pub fn $name(&self $(, $arg: $ty)*) -> $ret {
                self.inner.$name($($arg),*)$(.$wait())?
            }
        )+
    };
}

/// A blocking ZooKeeper client.
///
/// It always uses `Runtime::Thread`, so the client has its own IO
/// thread. Thus a call works in a plain thread, in a tokio
/// `spawn_blocking` thread and in a tokio worker, and it cannot
/// deadlock the driver. A call in a tokio worker blocks that worker,
/// which is misuse. A call on the IO side of a client fails at once
/// with `Error::InvalidState`. Each method has the name and the
/// arguments of the async method.
#[derive(Clone, Debug)]
pub struct Client {
    inner: crate::Client,
}

impl Client {
    /// Connects and waits for the session.
    ///
    /// A `Runtime::Thread` value of the builder stays. Any other runtime
    /// changes to `Runtime::Thread` with the default options.
    ///
    /// # Errors
    ///
    /// As for [`ConnectFuture`](crate::ConnectFuture).
    pub fn connect(builder: ClientBuilder) -> std::result::Result<Client, ConnectError> {
        let builder = match builder.runtime {
            Some(Runtime::Thread(_)) => builder,
            _ => builder.runtime(Runtime::Thread(ThreadOptions::default())),
        };
        builder.connect().wait().map(|inner| Client { inner })
    }

    /// The async client of this session. Use it to pipeline: issue
    /// several requests, then wait for each.
    #[must_use]
    pub fn as_async(&self) -> &crate::Client {
        &self.inner
    }

    wait_forward! {
        /// See [`crate::Client::create`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn create(
            &self,
            path: impl PathArg,
            data: &[u8],
            mode: CreateMode,
            acl: &[Acl],
        ) -> Result<(ZPathBuf, Stat)> => wait;

        /// See [`crate::Client::delete`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn delete(&self, path: impl PathArg, version: impl VersionArg) -> Result<()> => wait;

        /// See [`crate::Client::exists`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn exists(&self, path: impl PathArg) -> Result<Option<Stat>> => wait;

        /// See [`crate::Client::get_data`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_data(&self, path: impl PathArg) -> Result<(Vec<u8>, Stat)> => wait;

        /// See [`crate::Client::get_data_opt`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_data_opt(&self, path: impl PathArg) -> Result<(Option<Vec<u8>>, Stat)> => wait;

        /// See [`crate::Client::set_data`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn set_data(
            &self,
            path: impl PathArg,
            data: &[u8],
            version: impl VersionArg,
        ) -> Result<Stat> => wait;

        /// See [`crate::Client::get_children`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_children(&self, path: impl PathArg) -> Result<Vec<String>> => wait;

        /// See [`crate::Client::get_children_with_stat`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_children_with_stat(&self, path: impl PathArg) -> Result<(Vec<String>, Stat)> => wait;

        /// See [`crate::Client::get_all_children_number`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_all_children_number(&self, path: impl PathArg) -> Result<u32> => wait;

        /// See [`crate::Client::get_ephemerals`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_ephemerals(&self, prefix: impl PathArg) -> Result<Vec<ZPathBuf>> => wait;

        /// See [`crate::Client::get_ephemerals_all`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_ephemerals_all(&self) -> Result<Vec<ZPathBuf>> => wait;

        /// See [`crate::Client::exists_watched`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn exists_watched(
            &self,
            path: impl PathArg,
        ) -> Result<(Option<Stat>, OneshotWatcher)> => wait;

        /// See [`crate::Client::get_data_watched`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_data_watched(
            &self,
            path: impl PathArg,
        ) -> Result<(Vec<u8>, Stat, OneshotWatcher)> => wait;

        /// See [`crate::Client::get_children_watched`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_children_watched(
            &self,
            path: impl PathArg,
        ) -> Result<(Vec<String>, Stat, OneshotWatcher)> => wait;

        /// See [`crate::Client::add_watch`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn add_watch(
            &self,
            path: impl PathArg,
            mode: AddWatchMode,
        ) -> Result<PersistentWatcher> => wait;

        /// See [`crate::Client::remove_watches`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn remove_watches(
            &self,
            path: impl PathArg,
            kind: WatcherKind,
            local_only: bool,
        ) -> Result<()> => wait;

        /// See [`crate::Client::get_acl`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_acl(&self, path: impl PathArg) -> Result<(Vec<Acl>, Stat)> => wait;

        /// See [`crate::Client::set_acl`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn set_acl(
            &self,
            path: impl PathArg,
            acl: &[Acl],
            aversion: impl VersionArg,
        ) -> Result<Stat> => wait;

        /// See [`crate::Client::sync`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn sync(&self, path: impl PathArg) -> Result<()> => wait;

        /// See [`crate::Client::multi`].
        ///
        /// # Errors
        ///
        /// The error of the transaction.
        fn multi(
            &self,
            txn: &MultiWriter<'_>,
        ) -> std::result::Result<MultiResults, MultiError> => wait;

        /// See [`crate::Client::multi_read`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn multi_read(&self, ops: &MultiReader<'_>) -> Result<Vec<Result<ReadResult>>> => wait;

        /// See [`crate::Client::get_config`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_config(&self) -> Result<(EnsembleConfig, Stat)> => wait;

        /// See [`crate::Client::get_config_watched`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn get_config_watched(&self) -> Result<(EnsembleConfig, Stat, OneshotWatcher)> => wait;

        /// See [`crate::Client::reconfig`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn reconfig(
            &self,
            change: &Reconfig,
            expected: Option<i64>,
        ) -> Result<(EnsembleConfig, Stat)> => wait;

        /// See [`crate::Client::update_servers`]. It does not block.
        ///
        /// # Errors
        ///
        /// As for the async method.
        fn update_servers(&self, connect_string: &str) -> Result<()>;

        /// See [`crate::Client::add_auth`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn add_auth(&self, scheme: &str, data: impl Into<Vec<u8>>) -> Result<()> => wait;

        /// See [`crate::Client::who_am_i`].
        ///
        /// # Errors
        ///
        /// The error of the request.
        fn who_am_i(&self) -> Result<Vec<ClientInfo>> => wait;

        /// See [`crate::Client::state`].
        #[must_use]
        fn state(&self) -> SessionInfo;

        /// See [`crate::Client::state_watcher`].
        #[must_use]
        fn state_watcher(&self) -> StateWatcher;

        /// See [`crate::Client::session`].
        #[must_use]
        fn session(&self) -> (SessionId, SessionPassword);

        /// See [`crate::Client::negotiated_timeout`].
        #[must_use]
        fn negotiated_timeout(&self) -> Option<Duration>;

        /// See [`crate::Client::last_zxid`].
        #[must_use]
        fn last_zxid(&self) -> Zxid;

        /// See [`crate::Client::connected_server`].
        #[must_use]
        fn connected_server(&self) -> Option<SocketAddr>;

        /// See [`crate::Client::stats`].
        #[must_use]
        fn stats(&self) -> ClientStats;

        /// Waits as [`crate::Client::ready`] waits.
        ///
        /// # Errors
        ///
        /// A terminal session gives its error.
        fn ready(&self) -> Result<()> => wait;

        /// Closes the session and waits for the end of the close.
        ///
        /// # Errors
        ///
        /// As for [`CloseFuture`](crate::CloseFuture).
        fn close(&self) -> Result<()> => wait;
    }

    /// See [`crate::Client::detach`].
    #[must_use = "the session lives on; use the credentials or close it"]
    pub fn detach(self) -> (SessionId, SessionPassword) {
        self.inner.detach()
    }
}
