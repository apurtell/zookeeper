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

//! Safe port of the legacy server list rebalance and server selection
//! (`update_addrs`, `get_next_server_in_reconfig` and `zoo_cycle_next_server`
//! in `zookeeper.c`).
//!
//! The rebalance is the ZOOKEEPER-1355 protocol. When the server list
//! changes, a client can move to a new server with a computed probability, so
//! that the load spreads over the new list. The port uses the same unsigned
//! 32-bit counts, the same `double` arithmetic and the same order of
//! `drand48()` draws as C. The draws come from a function that the caller
//! supplies.

use std::net::SocketAddr;

use super::addrvec::{AddrEq, AddrVec, EndpointAddr, ListEq, contains, lists_equal};

/// The result of [`ServerSet::update`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UpdateOutcome {
    /// The new list compares equal to the current list. Nothing changed and
    /// no value was drawn.
    Unchanged,
    /// The new list is now the current list.
    Changed {
        /// True when the client must change its server. The caller then
        /// closes an open connection.
        reconfig: bool,
    },
}

/// The server list state of a legacy C client handle.
///
/// The fields match the handle fields `addrs`, `addrs_old`, `addrs_new`,
/// `addr_cur`, `reconfig`, `pNew` and `pOld`.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerSet<T> {
    /// The current server list (`addrs`).
    pub addrs: AddrVec<T>,
    /// The servers of the new list that were also in the old list
    /// (`addrs_old`).
    pub old: AddrVec<T>,
    /// The servers of the new list that were not in the old list
    /// (`addrs_new`).
    pub new: AddrVec<T>,
    /// The server of the current connection attempt (`addr_cur`). `None`
    /// stands for the zeroed C address.
    pub current: Option<T>,
    /// True while the client looks for a server after a list change.
    pub reconfig: bool,
    /// The probability to take a server from `new` (`pNew`).
    pub p_new: f64,
    /// The probability to take a server from `old` (`pOld`).
    pub p_old: f64,
}

impl<T> Default for ServerSet<T> {
    fn default() -> Self {
        Self {
            addrs: AddrVec::new(),
            old: AddrVec::new(),
            new: AddrVec::new(),
            current: None,
            reconfig: false,
            p_new: 0.0,
            p_old: 0.0,
        }
    }
}

/// Converts a list length to the C `unsigned int` count.
fn count_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl<T: EndpointAddr + Clone> ServerSet<T> {
    /// Creates an empty state, as a new C handle has it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs a resolved list, as `update_addrs` does after a successful
    /// resolution.
    ///
    /// The list rule `list_eq` and the address rule `addr_eq` decide if the
    /// list changed. C uses [`ListEq::LegacyOneWay`] with [`AddrEq::IpOnly`].
    /// The address rule also decides which servers count as old and if the
    /// current server is in the new list.
    ///
    /// The function `drand48` stands for C `drand48()`. The function calls it
    /// at most once: only when the list grows and the current server is in
    /// the new list.
    pub fn update<F: FnMut() -> f64>(
        &mut self,
        resolved: Vec<T>,
        list_eq: ListEq,
        addr_eq: AddrEq,
        mut drand48: F,
    ) -> UpdateOutcome {
        if lists_equal(self.addrs.as_slice(), &resolved, list_eq, addr_eq) {
            return UpdateOutcome::Unchanged;
        }
        let found_current = self
            .current
            .as_ref()
            .is_some_and(|cur| contains(&resolved, &cur.socket_addr(), addr_eq));

        self.reconfig = true;
        self.old.clear();
        self.new.clear();
        for item in &resolved {
            if self.addrs.contains(&item.socket_addr(), addr_eq) {
                self.old.push(item.clone());
            } else {
                self.new.push(item.clone());
            }
        }

        // C does this arithmetic in unsigned int, with modulo wrap.
        let num_old = count_u32(self.old.len());
        let num_new = count_u32(self.new.len());
        let count = count_u32(self.addrs.len());
        let total = num_old.wrapping_add(num_new);

        if total > count {
            // The number of servers grew.
            if found_current {
                let threshold = 1.0 - f64::from(count) / f64::from(total);
                if drand48() <= threshold {
                    self.p_new = 1.0;
                    self.p_old = 0.0;
                } else {
                    self.reconfig = false;
                }
            } else {
                self.p_new = 1.0;
                self.p_old = 0.0;
            }
        } else if found_current {
            // The number of servers stayed the same or fell, and the current
            // server stays.
            self.reconfig = false;
        } else {
            let numerator = num_old.wrapping_mul(count.wrapping_sub(total));
            let denominator = total.wrapping_mul(count.wrapping_sub(num_old));
            // 0/0 gives NaN, as in C.
            self.p_old = f64::from(numerator) / f64::from(denominator);
            self.p_new = 1.0 - self.p_old;
        }

        self.addrs = AddrVec::from(resolved);
        UpdateOutcome::Changed {
            reconfig: self.reconfig,
        }
    }

    /// Installs a resolved list as [`Self::update`] does, but keeps an
    /// unchanged list with the caller.
    ///
    /// An unchanged list stays in `resolved`, so the caller can use its
    /// storage again. A changed list moves into the set and leaves
    /// `resolved` empty.
    pub(crate) fn update_from<F: FnMut() -> f64>(
        &mut self,
        resolved: &mut Vec<T>,
        list_eq: ListEq,
        addr_eq: AddrEq,
        drand48: F,
    ) -> UpdateOutcome {
        if lists_equal(self.addrs.as_slice(), resolved, list_eq, addr_eq) {
            return UpdateOutcome::Unchanged;
        }
        self.update(core::mem::take(resolved), list_eq, addr_eq, drand48)
    }

    /// Selects a server from `new` or `old` while `reconfig` is set
    /// (`get_next_server_in_reconfig`). It gives false when both lists are
    /// used up, and then clears `current`.
    fn next_in_reconfig<F: FnMut() -> f64>(&mut self, drand48: &mut F) -> bool {
        let take_new = drand48() <= self.p_new;
        if self.new.has_next() && (take_new || !self.old.has_next()) {
            self.current = self.new.next_item().cloned();
            return true;
        }
        if self.old.has_next() {
            self.current = self.old.next_item().cloned();
            return true;
        }
        self.current = None;
        false
    }

    /// Selects the next server, as `zoo_cycle_next_server` does, and gives it.
    ///
    /// While `reconfig` is set, each call draws one value with `drand48`, as C
    /// does. When the reconfig lists are used up, `reconfig` goes off and the
    /// cursor of `addrs` selects the server.
    pub fn cycle_next<F: FnMut() -> f64>(&mut self, mut drand48: F) -> Option<&T> {
        self.current = None;
        if self.reconfig {
            if self.next_in_reconfig(&mut drand48) {
                return self.current.as_ref();
            }
            self.reconfig = false;
        }
        self.current = self.addrs.next_item().cloned();
        self.current.as_ref()
    }

    /// Returns the address of the current server, if any.
    pub fn current_addr(&self) -> Option<SocketAddr> {
        self.current.as_ref().map(EndpointAddr::socket_addr)
    }
}
