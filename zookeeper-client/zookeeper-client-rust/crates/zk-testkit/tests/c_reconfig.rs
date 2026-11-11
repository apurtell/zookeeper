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

//! Parity with the C suite `TestReconfig.cc` (`Zookeeper_reconfig`).
//!
//! The C suite drives the server-list logic of the legacy C client
//! (ZOOKEEPER-1355) through `zoo_set_servers` and
//! `zoo_cycle_next_server`. It uses fake `10.10.10.x` hosts and never
//! connects. These tests drive the same logic through the public port
//! in `zk_proto::legacy`: the host parser, the shuffle, `addrvec` and
//! `ServerSet`. The C random sources `random()` and `drand48()` come
//! from the clones in `zk_testkit::rng`, with the seeds of the C suite.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use zk_proto::legacy::addrvec::{AddrEq, AddrVec, ListEq, contains, shuffle};
use zk_proto::legacy::connect::parse_servers;
use zk_proto::legacy::servers::{ServerSet, UpdateOutcome};
use zk_testkit::rng::{Drand48, GlibcRandom, SplitMix};

/// The C suite adds this value to the octet of a host to get its port.
const PORT_OFFSET: u16 = 2000;

/// The number of simulated clients of the load tests.
const NUM_CLIENTS: usize = 10_000;

/// The slack of the load bounds, in percent.
const SLACK_PERCENT: f64 = 10.0;

/// The host list of the C helper `createHostList(start, stop, octet)`.
///
/// The list runs from `octet` down, one entry for each value from
/// `start` down to `stop`. Each entry is `10.10.10.<o>:<2000 + o>`, and
/// the entries are joined with `", "`.
fn host_list(start: u16, stop: u16, octet: u16) -> String {
    let octet = if octet == 0 { start } else { octet };
    (stop..=start)
        .rev()
        .zip((0..=octet).rev())
        .map(|(_, o)| format!("10.10.10.{o}:{}", PORT_OFFSET + o))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `createHostList(start)`: the hosts `start` down to 1.
fn hosts(start: u16) -> String {
    host_list(start, 1, 0)
}

/// One simulated C client handle.
///
/// The C suite seeds `srandom` and `srand48` for each client with
/// `seed * seed + 0xAFAFAFAF`. When the connect order is not
/// deterministic, C seeds both again from `/dev/urandom` in each
/// resolution (`setup_random`). Here a fixed `SplitMix` stream stands
/// for `/dev/urandom`, so each run gives the same result.
struct Client {
    set: ServerSet<SocketAddr>,
    seed: u32,
    random: GlibcRandom,
    drand: Drand48,
    deterministic: bool,
    urandom: SplitMix,
}

impl Client {
    /// Makes client number `index`, as the C `Client` constructor does:
    /// it resolves the list, seeds the generators again and cycles once.
    fn new(index: u32, list: &str, deterministic: bool) -> Self {
        let seed = index.wrapping_mul(index).wrapping_add(0xAFAF_AFAF);
        let mut c = Self {
            set: ServerSet::new(),
            seed,
            random: GlibcRandom::new(seed),
            drand: Drand48::new(seed),
            deterministic,
            urandom: SplitMix::new(u64::from(seed)),
        };
        c.set_servers(list);
        c.re_seed();
        c.cycle_next_server();
        c
    }

    /// Makes a client and cycles until its server has the IP `ip`
    /// (C `createClient(hosts, host)`).
    fn on(index: u32, list: &str, ip: &str) -> Self {
        assert!(list.contains(ip), "{ip} is not in {list}");
        let mut c = Self::new(index, list, true);
        c.cycle_until_server(ip);
        c
    }

    /// Seeds both generators with the seed of this client (C `reSeed`).
    fn re_seed(&mut self) {
        self.random.seed(self.seed);
        self.drand.seed(self.seed);
    }

    /// Resolves `list` and installs it, as `zoo_set_servers` calls
    /// `update_addrs`. It gives the outcome of the update.
    fn set_servers(&mut self, list: &str) -> UpdateOutcome {
        let mut resolved: Vec<SocketAddr> = parse_servers(list.as_bytes())
            .unwrap()
            .iter()
            .map(|h| {
                let ip: Ipv4Addr = std::str::from_utf8(&h.host).unwrap().parse().unwrap();
                SocketAddr::from((ip, u16::try_from(h.port).unwrap()))
            })
            .collect();
        if !self.deterministic {
            // C `setup_random`, then `addrvec_shuffle`.
            let s = u32::try_from(self.urandom.next_u64() >> 32).unwrap();
            self.random.seed(s);
            self.drand.seed(s);
            let random = &mut self.random;
            shuffle(&mut resolved, || i64::from(random.next_u32()));
        }
        let drand = &mut self.drand;
        self.set
            .update(resolved, ListEq::LegacyOneWay, AddrEq::IpOnly, || {
                drand.next_f64()
            })
    }

    /// Sets the list and checks the `reconfig` flag after it (C
    /// `setServersAndVerifyReconfig`).
    fn set_servers_and_verify_reconfig(&mut self, list: &str, want: bool) {
        self.set_servers(list);
        assert_eq!(self.set.reconfig, want, "reconfig after {list}");
    }

    /// Sets the list and cycles when the client must move (C
    /// `setServersAndCycleIfNeeded`).
    fn set_servers_and_cycle_if_needed(&mut self, list: &str) {
        self.set_servers(list);
        if self.set.reconfig {
            self.cycle_next_server();
        }
    }

    /// Selects the next server (`zoo_cycle_next_server`) and gives it.
    fn cycle_next_server(&mut self) -> SocketAddr {
        let drand = &mut self.drand;
        self.set.cycle_next(|| drand.next_f64());
        self.server()
    }

    /// Cycles until the server has the IP `ip`. A full loop without a
    /// match is a failure, as in C `cycleUntilServer`.
    fn cycle_until_server(&mut self, ip: &str) {
        let want: IpAddr = ip.parse().unwrap();
        let mut first = None;
        loop {
            let next = self.cycle_next_server();
            match first {
                None => first = Some(next),
                Some(f) => assert_ne!(f, next, "{ip} not found in one loop"),
            }
            if next.ip() == want {
                return;
            }
        }
    }

    /// The current server (`zoo_get_current_server`).
    fn server(&self) -> SocketAddr {
        self.set.current_addr().expect("a current server")
    }

    /// The index of the current server in the C count table: the
    /// octet minus 1.
    fn host_index(&self) -> usize {
        usize::from(self.server().port() - PORT_OFFSET - 1)
    }
}

/// The addresses of a host list, for membership checks.
fn addr_set(list: &str) -> BTreeSet<SocketAddr> {
    list.split(", ").map(|s| s.parse().unwrap()).collect()
}

fn upper_bound(clients: usize, servers: usize) -> f64 {
    (1.0 + SLACK_PERCENT / 100.0) * clients as f64 / servers as f64
}

fn lower_bound(clients: usize, servers: usize) -> f64 {
    (1.0 - SLACK_PERCENT / 100.0) * clients as f64 / servers as f64
}

/// Checks that each listed host has a fair share of the clients, then
/// clears the counts of these hosts (the check loop of C
/// `updateAllClientsAndServers`).
fn check_balance(counts: &mut [u32], offset: usize, servers: usize) {
    for (index, n) in counts.iter_mut().enumerate().take(servers).skip(offset) {
        let n_f = f64::from(*n);
        assert!(
            n_f <= upper_bound(NUM_CLIENTS, servers),
            "host {index}: {n} clients"
        );
        assert!(
            n_f >= lower_bound(NUM_CLIENTS, servers),
            "host {index}: {n} clients"
        );
        *n = 0;
    }
}

/// Moves every client to the list `start` down to `stop` and checks
/// the new load (C `updateAllClientsAndServers`).
fn update_all(clients: &mut [Client], counts: &mut [u32], start: u16, stop: u16) {
    let list = host_list(start, stop, 0);
    for c in clients.iter_mut() {
        c.re_seed();
        c.set_servers_and_cycle_if_needed(&list);
        counts[c.host_index()] += 1;
    }
    let servers = usize::from(start - stop + 1);
    check_balance(counts, usize::from(stop - 1), servers);
}

/// `Zookeeper_reconfig::testcycleNextServer`: a smaller list that does
/// not hold the current server sets `reconfig`. Each later cycle gives
/// a server of the new list, first the old servers that stay and then
/// the plain round robin.
#[test]
fn cycle_next_server() {
    let initial = hosts(10);
    let new = hosts(4);
    let mut c = Client::new(0, &initial, true);
    assert_eq!(c.server(), "10.10.10.10:2010".parse().unwrap());
    c.set_servers_and_verify_reconfig(&new, true);
    let allowed = addr_set(&new);
    let got: Vec<SocketAddr> = (0..10).map(|_| c.cycle_next_server()).collect();
    assert!(got.iter().all(|a| allowed.contains(a)), "{got:?}");
    // The four staying servers come first, each one time.
    assert_eq!(got[..4].iter().collect::<BTreeSet<_>>().len(), 4, "{got:?}");
    assert!(!c.set.reconfig);
    // Then the cursor of the list goes round.
    assert_eq!(got[4], got[8], "{got:?}");
}

/// `Zookeeper_reconfig::testMigrateOrNot`: the corner cases of the
/// move rule. A smaller list that holds the server gives no move. A
/// smaller list without it gives a move. The same list again changes
/// nothing, so the flag stays set. A larger list without the server
/// gives a move.
#[test]
fn migrate_or_not() {
    let mut c = Client::on(0, &hosts(4), "10.10.10.3");
    // The ensemble gets smaller. The current server is in the new list.
    c.set_servers_and_verify_reconfig(&hosts(3), false);
    // The ensemble gets smaller. The current server is not in the new list.
    c.set_servers_and_verify_reconfig(&hosts(2), true);
    // The ensemble size stays the same. The current server is not in the
    // new list. The lists are equal, so the update changes nothing.
    assert_eq!(c.set_servers(&hosts(2)), UpdateOutcome::Unchanged);
    assert!(c.set.reconfig);
    // The ensemble gets larger. The current server is not in the new list.
    c.set_servers(&hosts(4));
    c.cycle_until_server("10.10.10.1");
    c.set_servers_and_verify_reconfig(&host_list(7, 2, 0), true);
}

/// `Zookeeper_reconfig::testMigrationCycle`: in reconfig mode the client
/// tries all new servers first, then the old servers that stay, and
/// then goes back to the round robin over the full list.
#[test]
fn migration_cycle() {
    let new_hosts = host_list(12, 3, 0);
    let old_staying = addr_set(&host_list(4, 3, 0));
    let new_coming = addr_set(&host_list(12, 5, 0));
    let mut c = Client::on(0, &hosts(4), "10.10.10.1");
    c.set_servers_and_verify_reconfig(&new_hosts, true);

    let mut seen = BTreeSet::new();
    for _ in 0..new_coming.len() {
        let next = c.cycle_next_server();
        assert!(new_coming.contains(&next), "{next} not in the new list");
        assert!(seen.insert(next), "{next} seen twice");
    }
    seen.clear();
    for _ in 0..old_staying.len() {
        let next = c.cycle_next_server();
        assert!(old_staying.contains(&next), "{next} not in the old list");
        assert!(seen.insert(next), "{next} seen twice");
    }
    // Back to the round robin over the ten servers.
    let first = c.cycle_next_server();
    for _ in 0..9 {
        c.cycle_next_server();
    }
    assert_eq!(c.cycle_next_server(), first);
}

/// `Zookeeper_reconfig::testAddrVecContainsIPv4`: the address compare
/// sees a change of any one bit of an IPv4 address, and an IPv6
/// address with the same bytes is a different address.
#[test]
fn addr_vec_contains_ipv4() {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1234));
    let mut vec: AddrVec<SocketAddr> = AddrVec::new();
    for i in 0..32 {
        let ip = Ipv4Addr::from(u32::from(Ipv4Addr::UNSPECIFIED) ^ (1 << i));
        vec.push(SocketAddr::from((ip, 1234)));
    }
    // The same bytes as IPv6, plain and IPv4-mapped.
    vec.push(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1234)));
    vec.push(SocketAddr::from((
        Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
        1234,
    )));
    assert!(!vec.contains(&addr, AddrEq::IpOnly));
    assert!(!contains(vec.as_slice(), &addr, AddrEq::IpAndPort));
    vec.push(addr);
    assert!(vec.contains(&addr, AddrEq::IpOnly));
    assert!(contains(vec.as_slice(), &addr, AddrEq::IpAndPort));
}

/// `Zookeeper_reconfig::testAddrVecContainsIPv6`: the address compare
/// sees a change of any one of the 128 bits of an IPv6 address, and an
/// IPv4 address is a different address.
#[test]
fn addr_vec_contains_ipv6() {
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1234));
    let mut vec: AddrVec<SocketAddr> = AddrVec::new();
    for i in 0..128 {
        let ip = Ipv6Addr::from(u128::from(Ipv6Addr::UNSPECIFIED) ^ (1 << i));
        vec.push(SocketAddr::from((ip, 1234)));
    }
    vec.push(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1234)));
    assert!(!vec.contains(&addr, AddrEq::IpOnly));
    assert!(!contains(vec.as_slice(), &addr, AddrEq::IpAndPort));
    vec.push(addr);
    assert!(vec.contains(&addr, AddrEq::IpOnly));
    assert!(contains(vec.as_slice(), &addr, AddrEq::IpAndPort));
}

/// `Zookeeper_reconfig::testMigrateProbability`: when the list grows
/// from 9 to 10 servers and holds the current server, a client moves
/// with the probability 1 - 9/10. Of 10000 clients, fewer than 1100
/// move. The C case checks only the upper bound. This test also checks
/// the lower bound, because the seeds are fixed.
#[test]
fn migrate_probability() {
    let initial = hosts(9);
    let new = hosts(10);
    let mut moves = 0_usize;
    for i in 0..NUM_CLIENTS {
        let mut c = Client::on(u32::try_from(i).unwrap(), &initial, "10.10.10.3");
        c.set_servers(&new);
        if c.set.reconfig {
            moves += 1;
        }
    }
    let m = moves as f64;
    assert!(m < upper_bound(NUM_CLIENTS, 10), "{moves} moves");
    assert!(m > lower_bound(NUM_CLIENTS, 10), "{moves} moves");
}

/// `Zookeeper_reconfig::testLoadBalancing`: 10000 clients with a random
/// connect order spread evenly over 9 servers. After each list change
/// (8, 6, 8 and 9 servers) the load stays within 10 % on each server,
/// and a removed server has no clients.
///
/// The C step `updateAllClientsAndServers(8, 1)` builds the same list
/// as the step to 8 servers. Its check of host 0 runs after the count
/// is cleared, so it always holds. This test keeps both, as in C.
#[test]
fn load_balancing() {
    let initial = hosts(9);
    let mut counts = vec![0_u32; NUM_CLIENTS];
    let mut clients: Vec<Client> = (0..NUM_CLIENTS)
        .map(|i| Client::new(u32::try_from(i).unwrap(), &initial, false))
        .collect();
    for c in &clients {
        counts[c.host_index()] += 1;
    }
    check_balance(&mut counts, 0, 9);

    // Remove the last server.
    update_all(&mut clients, &mut counts, 8, 1);
    assert_eq!(counts[8], 0);

    // Remove two more servers.
    update_all(&mut clients, &mut counts, 6, 1);
    assert_eq!(counts[6..9], [0, 0, 0]);

    // The C step "remove host 0 and add back 6, 7 and 8".
    update_all(&mut clients, &mut counts, 8, 1);
    assert_eq!(counts[0], 0);

    // Add host 0 back.
    update_all(&mut clients, &mut counts, 9, 1);
}
