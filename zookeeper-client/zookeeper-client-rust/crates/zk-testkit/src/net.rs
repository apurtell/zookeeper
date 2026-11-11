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

//! The in-memory network: name resolution, connect plans and read-only
//! probe results.
//!
//! The network has no sockets. It only decides the result of each
//! resolver call, connect attempt and probe. The harness gives these
//! results to the core.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use zk_proto::{HostResolution, HostSpec, ProbeOutcome, ResolveError};

/// The Linux `ECONNRESET` errno value.
pub const ECONNRESET: i32 = 104;
/// The Linux `ECONNREFUSED` errno value.
pub const ECONNREFUSED: i32 = 111;
/// The Linux `ETIMEDOUT` errno value.
pub const ETIMEDOUT: i32 = 110;
/// The Linux `EMFILE` errno value.
pub const EMFILE: i32 = 24;
/// The glibc `EAI_NONAME` value.
pub const EAI_NONAME: i32 = -2;
/// The glibc `EAI_AGAIN` value.
pub const EAI_AGAIN: i32 = -3;

/// The result of a connect attempt to one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectPlan {
    /// The connect reaches the server listener at the address.
    Accept,
    /// The connect starts and then fails with `TcpRefused{errno}`.
    Refuse {
        /// The errno value of the failure.
        errno: i32,
    },
    /// The connect starts and then fails with `SocketCreate{errno}`.
    SocketFail {
        /// The errno value of the failure.
        errno: i32,
    },
    /// The connect starts and never ends.
    Hang,
}

/// How a successful connect completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectStyle {
    /// The connect completes in the same call (`ConnectStart::Immediate`).
    Immediate,
    /// The connect returns `InProgress` and completes after a delay.
    InProgress {
        /// The delay in milliseconds. The value 0 completes in the same
        /// step.
        delay_ms: u64,
    },
}

/// A scripted resolver failure for one host name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Failure {
    err: ResolveError,
    remaining: Option<u32>,
}

/// The in-memory network.
#[derive(Clone, Debug)]
pub struct Network {
    names: BTreeMap<Vec<u8>, Vec<IpAddr>>,
    failures: BTreeMap<Vec<u8>, Failure>,
    skipped: BTreeMap<Vec<u8>, Vec<i32>>,
    plans: BTreeMap<SocketAddr, ConnectPlan>,
    probes: BTreeMap<SocketAddr, ProbeOutcome>,
    style: ConnectStyle,
    resolve_calls: usize,
    connects: Vec<SocketAddr>,
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

impl Network {
    /// Makes a network with no names, no overrides and immediate
    /// connects.
    #[must_use]
    pub fn new() -> Self {
        let mut names = BTreeMap::new();
        names.insert(b"localhost".to_vec(), vec![IpAddr::from([127_u8, 0, 0, 1])]);
        Self {
            names,
            failures: BTreeMap::new(),
            skipped: BTreeMap::new(),
            plans: BTreeMap::new(),
            probes: BTreeMap::new(),
            style: ConnectStyle::Immediate,
            resolve_calls: 0,
            connects: Vec::new(),
        }
    }

    /// Maps a host name to addresses. It replaces an earlier entry.
    pub fn add_name(&mut self, name: &str, addrs: Vec<IpAddr>) {
        self.names.insert(name.as_bytes().to_vec(), addrs);
    }

    /// Removes a host name.
    pub fn remove_name(&mut self, name: &str) {
        self.names.remove(name.as_bytes());
    }

    /// Makes the resolution of `name` fail. `times` limits the number of
    /// failures, and `None` fails every time.
    pub fn fail_name(&mut self, name: &str, err: ResolveError, times: Option<u32>) {
        self.failures.insert(
            name.as_bytes().to_vec(),
            Failure {
                err,
                remaining: times,
            },
        );
    }

    /// Removes a scripted resolver failure.
    pub fn clear_failure(&mut self, name: &str) {
        self.failures.remove(name.as_bytes());
    }

    /// Sets the address families that the resolver skips for `name`.
    pub fn set_skipped_families(&mut self, name: &str, families: Vec<i32>) {
        self.skipped.insert(name.as_bytes().to_vec(), families);
    }

    /// Sets the connect result for one address.
    pub fn set_plan(&mut self, addr: SocketAddr, plan: ConnectPlan) {
        self.plans.insert(addr, plan);
    }

    /// Removes the connect override of one address.
    pub fn clear_plan(&mut self, addr: SocketAddr) {
        self.plans.remove(&addr);
    }

    /// Returns the connect override of one address.
    #[must_use]
    pub fn plan(&self, addr: SocketAddr) -> Option<ConnectPlan> {
        self.plans.get(&addr).copied()
    }

    /// Sets the read-only probe result for one address.
    pub fn set_probe(&mut self, addr: SocketAddr, outcome: ProbeOutcome) {
        self.probes.insert(addr, outcome);
    }

    /// Removes the probe override of one address.
    pub fn clear_probe(&mut self, addr: SocketAddr) {
        self.probes.remove(&addr);
    }

    /// Returns the probe override of one address.
    #[must_use]
    pub fn probe(&self, addr: SocketAddr) -> Option<ProbeOutcome> {
        self.probes.get(&addr).cloned()
    }

    /// Sets how a successful connect completes.
    pub fn set_connect_style(&mut self, style: ConnectStyle) {
        self.style = style;
    }

    /// Returns how a successful connect completes.
    #[must_use]
    pub const fn connect_style(&self) -> ConnectStyle {
        self.style
    }

    /// Returns the number of host resolutions so far.
    #[must_use]
    pub const fn resolve_calls(&self) -> usize {
        self.resolve_calls
    }

    /// Returns the addresses of every connect attempt, oldest first.
    #[must_use]
    pub fn connects(&self) -> &[SocketAddr] {
        &self.connects
    }

    pub(crate) fn note_connect(&mut self, addr: SocketAddr) {
        self.connects.push(addr);
    }

    /// Resolves one host entry, as `getaddrinfo` does.
    ///
    /// An IP literal resolves to itself. A name uses the name table. A
    /// scripted failure applies before both. An unknown name fails with
    /// `EAI_NONAME`.
    pub fn resolve(&mut self, index: usize, host: &HostSpec) -> HostResolution {
        self.resolve_calls = self.resolve_calls.saturating_add(1);
        let name = host.host_bytes().to_vec();
        let port = match host {
            HostSpec::Legacy(h) => u16::try_from(h.port).unwrap_or(0),
            HostSpec::Native(h) => h.port,
        };
        let skipped_families = self.skipped.get(&name).cloned().unwrap_or_default();
        if let Some(f) = self.failures.get_mut(&name) {
            let active = f.remaining.is_none_or(|n| n > 0);
            if active {
                f.remaining = f.remaining.map(|n| n.saturating_sub(1));
                return HostResolution {
                    host: index,
                    result: Err(f.err),
                    skipped_families,
                };
            }
        }
        let literal = core::str::from_utf8(&name)
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok());
        let result = match literal {
            Some(ip) => Ok(vec![SocketAddr::new(ip, port)]),
            None => match self.names.get(&name) {
                Some(ips) => Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect()),
                None => Err(ResolveError {
                    gai_rc: EAI_NONAME,
                    errno: 0,
                }),
            },
        };
        HostResolution {
            host: index,
            result,
            skipped_families,
        }
    }
}
