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

//! Settings of a cluster model and of each listener.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::script::Script;
use crate::transport::Acceptor;

/// How the server answers digest `addAuth` requests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthPolicy {
    /// Accept every digest credential, as the Java server does.
    #[default]
    AcceptAll,
    /// Reject every credential with `ZAUTHFAILED` and close the connection.
    RejectAll,
    /// Accept only the listed `user:password` credentials.
    Only(Vec<String>),
}

/// The form of the handshake response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeStyle {
    /// The 37-byte body with the read-only flag, as servers since 3.4 send.
    #[default]
    Modern,
    /// The 36-byte body without the read-only flag, as pre-3.4 servers send.
    Legacy36,
}

/// How the server cuts its writes into socket writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Chunking {
    /// Each frame goes out in one write.
    #[default]
    Whole,
    /// Each frame goes out in writes of this many bytes. Zero means whole.
    Fixed(usize),
    /// Each frame goes out in writes of 1 to `max` bytes. The seeded
    /// generator picks the sizes.
    Random {
        /// The largest write.
        max: usize,
    },
}

/// The state of the shared model: the data tree, the sessions and the
/// rules for the session timeout.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// The seed for session ids, passwords, rule chances and chunk sizes.
    pub seed: u64,
    /// The server id. It is the high byte of each session id. Keep it at
    /// 254 or below, as the Java server does.
    pub server_id: u8,
    /// The lowest negotiated session timeout. The Java default is two ticks.
    pub min_session_timeout_ms: i32,
    /// The highest negotiated session timeout. The Java default is twenty
    /// ticks.
    pub max_session_timeout_ms: i32,
    /// When true, a session with no traffic for its timeout expires.
    pub session_expiry: bool,
    /// The interval of the session and reaper check.
    pub check_interval: Duration,
    /// The digest `addAuth` policy.
    pub auth: AuthPolicy,
    /// A digest identity, for example from
    /// [`digest_id`](crate::digest_id), that gives super-user rights.
    pub super_digest: Option<String>,
    /// When true, TTL nodes are allowed. The Java server needs
    /// `zookeeper.extendedTypesEnabled` for this.
    pub ttl_enabled: bool,
    /// When true, `reconfig` is allowed. The Java default is false.
    pub reconfig_enabled: bool,
    /// When set, empty containers and expired TTL nodes are removed at this
    /// interval. When not set, only [`Cluster::reap`](crate::Cluster::reap)
    /// removes them.
    pub reap_interval: Option<Duration>,
    /// The largest request body that the server reads. A larger frame
    /// closes the connection.
    pub max_frame_len: u32,
    /// The base of the logical clock for `ctime` and `mtime`. Each stat
    /// time is this value plus the zxid, so stats are the same in each run.
    pub epoch_ms: i64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            seed: 0x5EED_2181,
            server_id: 1,
            min_session_timeout_ms: 4_000,
            max_session_timeout_ms: 40_000,
            session_expiry: true,
            check_interval: Duration::from_millis(10),
            auth: AuthPolicy::AcceptAll,
            super_digest: None,
            ttl_enabled: true,
            reconfig_enabled: false,
            reap_interval: None,
            max_frame_len: 0x000F_FFFF_u32.saturating_add(1024),
            epoch_ms: 1_700_000_000_000,
        }
    }
}

/// The settings of one listener.
#[derive(Clone, Default)]
pub struct ServerOptions {
    /// When true, the listener acts as a read-only server.
    pub read_only: bool,
    /// The answer to the `isro` probe. `None` gives `ro` or `rw` from
    /// `read_only`.
    pub isro_answer: Option<String>,
    /// The handshake response form.
    pub handshake: HandshakeStyle,
    /// How writes are cut.
    pub chunking: Chunking,
    /// The pause between two chunks of one frame.
    pub chunk_gap: Duration,
    /// The fault rules.
    pub script: Script,
    /// The stream wrapper. `None` gives plain TCP.
    pub acceptor: Option<Arc<dyn Acceptor>>,
}

impl fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerOptions")
            .field("read_only", &self.read_only)
            .field("isro_answer", &self.isro_answer)
            .field("handshake", &self.handshake)
            .field("chunking", &self.chunking)
            .field("chunk_gap", &self.chunk_gap)
            .field("script", &self.script)
            .field("acceptor", &self.acceptor.is_some())
            .finish()
    }
}

impl ServerOptions {
    /// Sets the stream wrapper, for example a TLS acceptor.
    #[must_use]
    pub fn with_acceptor(mut self, acceptor: Arc<dyn Acceptor>) -> Self {
        self.acceptor = Some(acceptor);
        self
    }
}
