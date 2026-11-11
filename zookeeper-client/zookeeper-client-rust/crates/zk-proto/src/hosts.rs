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

//! The host list, DNS resolution, server selection and the read-only
//! probe.
//!
//! The module owns [`Hosts`]. The driver resolves host names when the core
//! asks with `Action::Resolve`. The core commits the results, rebalances,
//! and selects the next endpoint.

use std::net::SocketAddr;

use zk_jute::JString;
use zk_jute::rc;

use crate::action::{Action, HostResolution, ProbeOutcome, ProbeTlsFailure, TlsResourceAt};
use crate::compat::{Backoff, DnsFailure, ResolveCadence};
use crate::config::{Endpoint, HostSpec, HostToken};
use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::interest::IterStep;
use crate::legacy::addrvec::{AddrVec, ListEq, shuffle as shuffle_list};
use crate::legacy::servers::{ServerSet, UpdateOutcome};
use crate::log::{LogArg, LogSite};
use crate::state::{Cause, State};
use crate::time::{Millis, elapsed};
use crate::timers::RW_PROBE_MIN_MS;

/// The C growth step of an address vector (`ADDRVEC_DEFAULT_GROW_AMOUNT`).
const ADDRVEC_GROW: usize = 16;

/// The largest exponent of the `Deadline` pause growth. The pause is at
/// most `2^16` times the configured delay before the cap applies.
const BACKOFF_MAX_SHIFT: u32 = 16;

/// The cap of the `Deadline` pause before jitter. A configured delay
/// above the cap is not shortened.
pub(crate) const BACKOFF_CAP_MS: i64 = 30_000;

/// The result of the connect decision of one interest iteration.
#[derive(Debug)]
pub(crate) enum ConnectDecision {
    /// Yield this `Connect` action.
    Connect(Action),
    /// A backoff runs. `finish_interest` writes the backoff timeout.
    Wait,
    /// A resolution failure blocks the connect in this iteration.
    Blocked,
    /// The host list is empty. A `SocketCreate` teardown ran.
    Failed,
}

/// The source of the resolution that waits for `handle_resolved`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
enum ResolveOrigin {
    /// The first resolution of the handle.
    #[default]
    Init,
    /// Step 1 of an interest iteration.
    Iteration,
    /// `set_servers`.
    SetServers,
}

/// The host list state of one connection.
pub(crate) struct Hosts {
    /// The committed host entries, in connect-string order.
    pub(crate) specs: Vec<HostSpec>,
    /// The resolved address lists and the cursor.
    pub(crate) servers: ServerSet<Endpoint>,
    /// The generation of the last `Resolve` action. Results of another
    /// generation are ignored.
    pub(crate) generation: u64,
    /// True when a resolution is due.
    pub(crate) resolve_due: bool,
    /// True until the first `Resolve` action goes out. It sets `initial`.
    pub(crate) initial: bool,
    /// The generation that waits for `handle_resolved`, if any.
    pub(crate) in_flight: Option<u64>,
    /// The addresses that the per-host results collected for `in_flight`.
    pub(crate) collected: Vec<Endpoint>,
    /// The entries of the last unchanged list, in reverse list order. The
    /// next resolution writes its addresses and names into them. When the
    /// name capacities settle, a repeated resolution copies no name into
    /// new storage. A changed list frees this storage, so the kept memory
    /// follows the current list.
    spare: Vec<Endpoint>,
    /// True when at least one host of `in_flight` resolved.
    pub(crate) any_resolved: bool,
    /// The resolution delay while a transport is open: -1 never, 0 always,
    /// `d > 0` after `d` milliseconds.
    pub(crate) resolve_delay_ms: i32,
    /// The time of the last good resolution.
    pub(crate) last_resolved_at: Option<Millis>,
    /// True when a resolution failure blocks the connect of this
    /// iteration (`LegacyRcPreserved`).
    pub(crate) block_connect: bool,
    /// The legacy `delay` flag: a full host-list pass ended.
    pub(crate) delay: bool,
    /// The end of a `Backoff::Deadline` pause.
    pub(crate) not_before: Option<Millis>,
    /// The count of full host-list passes that failed since the last
    /// established session or `set_servers`. The `Deadline` pause grows
    /// with it.
    pub(crate) failed_passes: u32,
    /// The read-write server that a probe found. The next connect uses it.
    pub(crate) rw_target: Option<Endpoint>,
    /// True when a host-list pass ended, or a lost session started a new
    /// pass, and no resolution followed. The `EachPass` cadence reads it.
    pass_ended: bool,
    /// The failures left in a counted pass. A lost session starts a
    /// counted pass. `None` means that the end of the address list ends
    /// the pass. Only `Backoff::Deadline` uses it.
    pass_left: Option<usize>,
    /// The source of the resolution in `in_flight`.
    origin: ResolveOrigin,
    /// The errno of the last failed host of `in_flight`.
    last_errno: Option<i32>,
    /// The host text after `set_servers`. Before it, `Config::host_text`
    /// applies.
    host_text: Option<JString>,
}

impl Hosts {
    /// Makes the host state. The first `poll_action` yields
    /// `Resolve{initial: true}`.
    pub(crate) fn new(specs: Vec<HostSpec>, resolve_delay_ms: i32) -> Self {
        Self {
            specs,
            servers: ServerSet::new(),
            generation: 0,
            resolve_due: true,
            initial: true,
            in_flight: None,
            collected: Vec::new(),
            spare: Vec::new(),
            any_resolved: false,
            resolve_delay_ms,
            last_resolved_at: None,
            block_connect: false,
            delay: false,
            not_before: None,
            failed_passes: 0,
            rw_target: None,
            pass_ended: false,
            pass_left: None,
            origin: ResolveOrigin::Init,
            last_errno: None,
            host_text: None,
        }
    }
}

/// Returns the C capacity of an address vector that grew to `count`
/// entries in steps of 16.
fn addrvec_capacity(count: usize) -> usize {
    count
        .checked_add(ADDRVEC_GROW.saturating_sub(1))
        .and_then(|n| n.checked_div(ADDRVEC_GROW))
        .map_or(usize::MAX, |n| n.saturating_mul(ADDRVEC_GROW))
}

/// Returns the DEBUG arguments that describe one reconfig list.
fn reconfig_list_args(list: &AddrVec<Endpoint>) -> Vec<LogArg> {
    let as_i64 = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    vec![
        LogArg::I64(as_i64(list.len())),
        LogArg::I64(as_i64(addrvec_capacity(list.len()))),
        LogArg::I64(as_i64(list.cursor())),
        LogArg::I64(i64::from(list.has_next())),
    ]
}

/// Builds the host text of a host list: `host:port` entries joined with
/// commas, as a connect string has them.
fn join_host_text(specs: &[HostSpec]) -> JString {
    let mut out = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        match spec {
            HostSpec::Legacy(h) => {
                out.extend_from_slice(&h.host);
                out.push(b':');
                out.extend_from_slice(&h.service);
            }
            HostSpec::Native(h) => {
                out.extend_from_slice(h.host.as_bytes());
                out.push(b':');
                out.extend_from_slice(h.port.to_string().as_bytes());
            }
        }
    }
    JString::Bytes(out)
}

/// Returns the endpoint of one resolved address of host entry `index`.
///
/// A spare entry keeps the storage of its name. The function writes the
/// address and the name into it. The spare entries come back in list order,
/// so without a shuffle each host gets the entry of its own name. Without a
/// spare entry the function copies the name into new storage.
fn spare_endpoint(
    spare: &mut Vec<Endpoint>,
    addr: SocketAddr,
    index: usize,
    name: &[u8],
) -> Endpoint {
    match spare.pop() {
        Some(mut ep) => {
            ep.addr = addr;
            ep.host.index = index;
            ep.host.name.clear();
            ep.host.name.extend_from_slice(name);
            ep
        }
        None => Endpoint {
            addr,
            host: HostToken {
                index,
                name: name.to_vec(),
            },
        },
    }
}

/// Returns the log site of a failed `getaddrinfo` on this platform.
const fn gai_site() -> LogSite {
    if cfg!(windows) {
        LogSite::ResolveWin32
    } else if cfg!(target_os = "linux") {
        LogSite::ResolveGai
    } else {
        LogSite::ResolveGaiErrno
    }
}

impl<T: Tokens> Connection<T> {
    /// Takes the resolution result of one host, in host order.
    ///
    /// Contract: a result whose `generation` is not `in_flight` is
    /// ignored. A failure logs the getaddrinfo ERROR site of the platform
    /// at once (DR5). Each skipped family logs its WARN. The addresses go
    /// to `collected` with their host token.
    pub fn handle_host_resolved(&mut self, generation: u64, r: HostResolution, _now: Millis) {
        if self.hosts.in_flight != Some(generation) {
            return;
        }
        let HostResolution {
            host,
            result,
            skipped_families,
        } = r;
        if !skipped_families.is_empty() {
            let text = self.hosts_text();
            for family in skipped_families {
                let text = text.clone();
                self.emit_log(LogSite::ResolveSkipFamily, || {
                    vec![LogArg::I64(i64::from(family)), LogArg::Str(text)]
                });
            }
        }
        match result {
            Err(e) => {
                self.hosts.last_errno = Some(e.errno);
                self.emit_log(gai_site(), || {
                    vec![LogArg::GaiStr {
                        gai_rc: e.gai_rc,
                        errno: e.errno,
                    }]
                });
            }
            Ok(addrs) => {
                if !addrs.is_empty() {
                    self.hosts.any_resolved = true;
                }
                let h = &mut self.hosts;
                let name = h.specs.get(host).map_or(&[][..], HostSpec::host_bytes);
                for addr in addrs {
                    let ep = spare_endpoint(&mut h.spare, addr, host, name);
                    h.collected.push(ep);
                }
            }
        }
    }

    /// Commits the collected resolution after the last host.
    ///
    /// Contract:
    /// - A stale `generation` returns `ZOK` and changes nothing.
    /// - With no address at all it returns `ZSYSTEMERROR`. The
    ///   `dns_failure` knob decides the effect: `LegacyRcPreserved` keeps
    ///   the rc for `finish_interest` and sets `block_connect` with no
    ///   transport. `UseLastGood` changes nothing.
    /// - Otherwise `hosts_commit` calls `Rng::on_resolution`, shuffles when
    ///   `shuffle` is true, and runs `ServerSet::update_from` (the rules of
    ///   `ServerSet::update`) with `Compat::addr_eq`.
    ///   The result `UpdateOutcome::Changed { reconfig: true }` with an
    ///   open transport is a forced close trigger (`forced_close_trigger`).
    ///   It returns `ZOK`.
    pub fn handle_resolved(&mut self, generation: u64, shuffle: bool, now: Millis) -> i32 {
        if self.hosts.in_flight != Some(generation) {
            return rc::ZOK;
        }
        self.hosts.in_flight = None;
        let origin = self.hosts.origin;
        if origin == ResolveOrigin::SetServers {
            // A set_servers resolution is also the `EachPass` resolution
            // of the current pass.
            self.hosts.resolve_due = false;
            self.hosts.pass_ended = false;
        }
        let list = core::mem::take(&mut self.hosts.collected);
        self.hosts.any_resolved = false;
        let last_errno = self.hosts.last_errno.take();

        // C resolves an empty host list to an empty list with ZOK.
        if list.is_empty() && !self.hosts.specs.is_empty() {
            if let Some(e) = last_errno {
                self.set_errno_hint(e);
            }
            // Only a resolution of a running iteration feeds its rc.
            let in_iteration =
                origin == ResolveOrigin::Iteration && self.interest.step != IterStep::Idle;
            if self.compat.dns_failure == DnsFailure::LegacyRcPreserved && in_iteration {
                self.interest.rc = rc::ZSYSTEMERROR;
                if !self.core.has_transport {
                    self.hosts.block_connect = true;
                }
            }
            return rc::ZSYSTEMERROR;
        }
        self.hosts_commit(list, shuffle, now);
        rc::ZOK
    }

    /// Commits a good resolution: the list of `handle_resolved` that has an
    /// address, or the empty list of an empty host list.
    fn hosts_commit(&mut self, mut list: Vec<Endpoint>, shuffle: bool, now: Millis) {
        self.hosts.last_resolved_at = Some(now);
        if shuffle && !list.is_empty() {
            self.rng.on_resolution();
            shuffle_list(&mut list, || self.rng.random());
        }
        let addr_eq = self.compat.addr_eq;
        let outcome =
            self.hosts
                .servers
                .update_from(&mut list, ListEq::LegacyOneWay, addr_eq, || {
                    self.rng.drand48()
                });
        // An unchanged list stays with the caller. Its entries become the
        // spare entries, and the old spare storage holds the next list.
        // Thus a repeated resolution needs no new list and no name copy.
        // The reverse order lets the next resolution pop them in list order.
        core::mem::swap(&mut self.hosts.spare, &mut list);
        self.hosts.spare.reverse();
        list.clear();
        self.hosts.collected = list;
        if matches!(outcome, UpdateOutcome::Changed { .. }) {
            // A changed list starts again at its first address. The end of
            // the list then ends the pass.
            self.hosts.pass_left = None;
            // A changed list leaves no spare entries. The old storage goes,
            // so a shrunk list keeps no memory of the longer list.
            self.hosts.collected = Vec::new();
        }
        if outcome == (UpdateOutcome::Changed { reconfig: true }) && self.core.has_transport {
            self.forced_close_trigger(now);
        }
    }

    /// Replaces the host list. The caller already parsed it.
    ///
    /// Contract: it commits `hosts`, advances `generation`, marks a
    /// resolution due and returns the new `generation`. The driver then resolves
    /// each host and calls `handle_host_resolved` and `handle_resolved`
    /// with that `generation`. An empty list logs the `SetServersEmpty` site.
    pub fn set_servers(&mut self, hosts: Vec<HostSpec>, _now: Millis) -> u64 {
        // The C shim logs SetServersEmpty for a NULL list. C accepts an
        // empty string as an empty list with no log, so the core logs
        // nothing here.
        self.hosts.host_text = Some(join_host_text(&hosts));
        self.hosts.specs = hosts;
        // A new list starts the backoff growth again.
        self.hosts.failed_passes = 0;
        self.hosts.resolve_due = true;
        self.hosts_start_generation(ResolveOrigin::SetServers)
    }

    /// Sets the resolution delay.
    ///
    /// Contract: `ms < -1` logs the `ResolveDelayInvalid` site
    /// and returns `ZBADARGUMENTS` with no change. Otherwise it stores
    /// `ms` and returns `ZOK`.
    pub fn set_resolve_delay(&mut self, ms: i32) -> i32 {
        if ms < -1 {
            self.emit_log(LogSite::ResolveDelayInvalid, || {
                vec![LogArg::I64(i64::from(ms))]
            });
            return rc::ZBADARGUMENTS;
        }
        self.hosts.resolve_delay_ms = ms;
        rc::ZOK
    }

    /// Moves the server cursor to the next endpoint (`zoo_cycle_next_server`).
    ///
    /// Contract: `ServerSet::cycle_next` with `Rng::drand48`.
    pub fn cycle_next_server(&mut self) {
        let reconfig = self.hosts.servers.reconfig;
        let new_cursor = self.hosts.servers.new.cursor();
        let old_cursor = self.hosts.servers.old.cursor();
        if reconfig {
            let old_args = reconfig_list_args(&self.hosts.servers.old);
            let new_args = reconfig_list_args(&self.hosts.servers.new);
            self.emit_log(LogSite::ReconfigOld, || old_args);
            self.emit_log(LogSite::ReconfigNew, || new_args);
        }
        let _ = self.hosts.servers.cycle_next(|| self.rng.drand48());
        if !reconfig {
            return;
        }
        // The moved reconfig cursor tells which list gave the server.
        let current = self.hosts.servers.current_addr();
        let still = self.hosts.servers.reconfig;
        if still && self.hosts.servers.new.cursor() != new_cursor {
            self.emit_log(LogSite::ReconfigUseNew, || vec![LogArg::Endpoint(current)]);
        } else if still && self.hosts.servers.old.cursor() != old_cursor {
            self.emit_log(LogSite::ReconfigUseOld, || vec![LogArg::Endpoint(current)]);
        } else {
            self.emit_log(LogSite::ReconfigNone, Vec::new);
        }
    }

    /// Returns the current server address (`zoo_get_current_server`).
    ///
    /// After a failure it is the address at the cursor.
    #[must_use]
    pub fn current_server(&self) -> Option<SocketAddr> {
        self.hosts.servers.current_addr()
    }

    /// Takes the result of a read-only probe.
    ///
    /// Contract: `ReadWrite` sets `rw_target`, resets the probe
    /// interval to 200 ms, logs "r/w server found at %s" and starts a
    /// `Cause::RwServerFound` teardown. Any other outcome logs the TLS
    /// probe line when one applies and advances the cursor without setting
    /// `cur`. A result outside the ReadOnly state is ignored.
    pub fn handle_rw_probe(&mut self, ep: Endpoint, outcome: ProbeOutcome, now: Millis) {
        if self.core.state != State::ReadOnly {
            return;
        }
        match outcome {
            ProbeOutcome::ReadWrite => {
                let addr = ep.addr;
                self.hosts.rw_target = Some(ep);
                self.timers.rw_timeout_ms = RW_PROBE_MIN_MS;
                self.emit_log(LogSite::RwServerFound, || {
                    vec![LogArg::Endpoint(Some(addr))]
                });
                let _ = self.teardown(Cause::RwServerFound, 0, now);
            }
            ProbeOutcome::NotReadWrite => {
                let _ = self.hosts.servers.addrs.next_item();
            }
            ProbeOutcome::Failed(failure) => {
                if let Some(f) = failure {
                    self.hosts_probe_tls_log(f);
                }
                let _ = self.hosts.servers.addrs.next_item();
            }
        }
    }

    /// Emits the probe-side TLS line of a failed probe.
    fn hosts_probe_tls_log(&mut self, failure: ProbeTlsFailure) {
        match failure {
            ProbeTlsFailure::Resource {
                at: TlsResourceAt::ContextNew,
            } => self.emit_log(LogSite::TlsContextNew, Vec::new),
            ProbeTlsFailure::Resource {
                at: TlsResourceAt::ConnectionNew,
            } => self.emit_log(LogSite::TlsConnectionNew, Vec::new),
            ProbeTlsFailure::Handshake => self.emit_log(LogSite::TlsConnect, Vec::new),
            ProbeTlsFailure::Config { step, file } => self.tls_config_failed(step, file),
        }
    }

    /// Returns the `Resolve` action of step 1 of an interest iteration.
    ///
    /// Contract: it yields when `resolve_due` is
    /// set, or when `Compat::resolve_cadence` and `resolve_delay_ms` make
    /// one due. It advances `generation`, records `in_flight`, clears
    /// `collected`, and sets `initial` only on the first call.
    pub(crate) fn resolve_action(&mut self, now: Millis) -> Option<Action> {
        // The driver resolves a set_servers list itself. A new generation
        // here would make that result stale.
        if self.hosts.in_flight.is_some() && self.hosts.origin == ResolveOrigin::SetServers {
            return None;
        }
        if !self.hosts.resolve_due && !self.hosts_resolve_by_cadence(now) {
            return None;
        }
        let initial = self.hosts.initial;
        self.hosts.initial = false;
        let origin = if initial {
            ResolveOrigin::Init
        } else {
            ResolveOrigin::Iteration
        };
        let generation = self.hosts_start_generation(origin);
        self.hosts.resolve_due = false;
        self.hosts.pass_ended = false;
        Some(Action::Resolve {
            generation,
            hosts: self.hosts.specs.clone(),
            initial,
        })
    }

    /// Starts a new resolution generation from `origin` and returns it.
    /// The results of the earlier generations become stale.
    fn hosts_start_generation(&mut self, origin: ResolveOrigin) -> u64 {
        let generation = self.hosts.generation.wrapping_add(1);
        self.hosts.generation = generation;
        self.hosts.in_flight = Some(generation);
        self.hosts.origin = origin;
        self.hosts.collected.clear();
        self.hosts.any_resolved = false;
        self.hosts.last_errno = None;
        generation
    }

    /// Returns true when the cadence rules make a resolution due.
    fn hosts_resolve_by_cadence(&self, now: Millis) -> bool {
        let since_last_over = |ms: i64| {
            self.hosts
                .last_resolved_at
                .is_none_or(|t| elapsed(now, t) > ms)
        };
        if self.core.has_transport {
            return match self.hosts.resolve_delay_ms {
                -1 => false,
                d if d <= 0 => true,
                d => since_last_over(i64::from(d)),
            };
        }
        match self.compat.resolve_cadence {
            ResolveCadence::EveryIterationWhileDisconnected => true,
            ResolveCadence::EachPass => {
                self.hosts.pass_ended
                    && !self.hosts.delay
                    && self.hosts.not_before.is_none_or(|nb| now >= nb)
            }
            ResolveCadence::Throttled { ms } => since_last_over(i64::from(ms)),
            ResolveCadence::Never => false,
        }
    }

    /// Runs the connect decision of step 2 of an interest iteration.
    ///
    /// Contract: it applies the backoff of `Compat::reconnect_backoff`
    /// (`delay` with `OneShotSkip`, `not_before` with `Deadline`), then
    /// `block_connect`, then takes `rw_target` or selects the next server.
    /// An empty list starts a `Cause::SocketCreate` teardown and sets
    /// `delay`. A selected endpoint gives `Connect{endpoint, tls}` with
    /// `tls = cfg.tls.then_some(compat.tls_verify)`.
    pub(crate) fn connect_decision(&mut self, now: Millis) -> ConnectDecision {
        match self.compat.reconnect_backoff {
            Backoff::OneShotSkip => {
                if self.hosts.delay {
                    self.hosts.delay = false;
                    let text = self.hosts_text();
                    self.emit_log(LogSite::DelayingConnection, || vec![LogArg::Str(text)]);
                    self.timers.reset_for_connect(now);
                    return ConnectDecision::Wait;
                }
            }
            Backoff::Deadline => {
                if let Some(nb) = self.hosts.not_before {
                    if now < nb {
                        return ConnectDecision::Wait;
                    }
                    self.hosts.not_before = None;
                }
            }
        }
        if self.hosts.block_connect {
            return ConnectDecision::Blocked;
        }
        let endpoint = if let Some(ep) = self.hosts.rw_target.take() {
            self.hosts.servers.current = Some(ep.clone());
            Some(ep)
        } else {
            self.cycle_next_server();
            self.hosts.servers.current.clone()
        };
        let Some(endpoint) = endpoint else {
            // T5 of this teardown sets `delay` again. Under `Deadline` it
            // turns the flag into a pause.
            self.hosts.delay = true;
            self.hosts.pass_ended = true;
            self.interest.rc = self.teardown(Cause::SocketCreate, 0, now);
            return ConnectDecision::Failed;
        };
        let tls = self.cfg.tls.then_some(self.compat.tls_verify);
        ConnectDecision::Connect(Action::Connect { endpoint, tls })
    }

    /// Runs teardown stage T5 for the causes that run `handle_error`.
    ///
    /// Contract: `delay = at_end(addrs) || addrs.is_empty()`.
    /// `cur = addrs.peek()`. The cursor does not move. Under
    /// `Backoff::Deadline`, the end of a pass sets `not_before` with one
    /// `Rng::random` draw, and counts one more failed pass. A counted
    /// pass ends after one failure per address. Any other pass ends when
    /// `delay` is set.
    pub(crate) fn hosts_on_handle_error(&mut self, now: Millis) {
        let addrs = &self.hosts.servers.addrs;
        let delay = addrs.at_end() || addrs.is_empty();
        let len = addrs.len();
        let current = addrs.peek().cloned();
        self.hosts.servers.current = current;
        match self.compat.reconnect_backoff {
            Backoff::OneShotSkip => {
                if delay {
                    self.hosts.pass_ended = true;
                }
                self.hosts.delay = delay;
            }
            Backoff::Deadline => {
                self.hosts.delay = false;
                let pass_end = match self.hosts.pass_left {
                    Some(left) => {
                        let left = left.saturating_sub(1);
                        self.hosts.pass_left = Some(left);
                        left == 0
                    }
                    None => delay,
                };
                if pass_end {
                    self.hosts.pass_ended = true;
                    self.hosts.not_before = self.hosts_pause_end(now);
                    self.hosts.failed_passes = self.hosts.failed_passes.saturating_add(1);
                    if self.hosts.pass_left.is_some() {
                        // The next counted pass also has one attempt per
                        // address.
                        self.hosts.pass_left = Some(len);
                    }
                }
            }
        }
    }

    /// Runs teardown stage T5 when the teardown ends an established
    /// session.
    ///
    /// A lost session is not a failed address. Under
    /// `Backoff::Deadline`, the loss sets no pause. It
    /// starts a counted pass at the cursor. That pass ends after one
    /// failure per address. The loss also makes an `EachPass` resolution
    /// due before the next connect. `cur` follows the rule of
    /// `hosts_on_handle_error`. `OneShotSkip` keeps the legacy rule, so
    /// the drop-in delays as C does.
    pub(crate) fn hosts_on_session_lost(&mut self, now: Millis) {
        match self.compat.reconnect_backoff {
            Backoff::OneShotSkip => self.hosts_on_handle_error(now),
            Backoff::Deadline => {
                let addrs = &self.hosts.servers.addrs;
                let len = addrs.len();
                let current = addrs.peek().cloned();
                self.hosts.servers.current = current;
                self.hosts.delay = false;
                self.hosts.pass_left = Some(len);
                self.hosts.pass_ended = true;
            }
        }
    }

    /// Returns the end of a `Deadline` pause: `now + b + offset`.
    ///
    /// The base `b` grows exponentially with the failed passes (spec
    /// "Reconnection Backoff"): `min(d * 2^k, max(d, cap))`. One
    /// `Rng::random` draw puts the offset in `[-j, j]`, where `j` is a
    /// percentage of `b`. A zero delay gives no pause
    /// and no draw.
    fn hosts_pause_end(&mut self, now: Millis) -> Option<Millis> {
        let base = i64::from(self.cfg.reconnect_delay_ms);
        if base == 0 {
            return None;
        }
        let shift = self.hosts.failed_passes.min(BACKOFF_MAX_SHIFT);
        let grown = 1i64
            .checked_shl(shift)
            .map_or(i64::MAX, |factor| base.saturating_mul(factor));
        let d = grown.min(base.max(BACKOFF_CAP_MS));
        let j = d
            .saturating_mul(i64::from(self.cfg.reconnect_jitter_pct))
            .checked_div(100)
            .unwrap_or(0);
        let span = j.saturating_mul(2).saturating_add(1);
        let draw = self.rng.random().checked_rem_euclid(span).unwrap_or(0);
        let offset = draw.saturating_sub(j);
        Some(now.offset_ms(d.saturating_add(offset)))
    }

    /// Records an established session. The next failed pass starts the
    /// `Deadline` pause at the configured delay again. The session also
    /// ends the counted passes that an earlier loss started.
    pub(crate) fn hosts_on_established(&mut self) {
        self.hosts.failed_passes = 0;
        self.hosts.pass_left = None;
    }

    /// Returns the endpoint of the next read-only probe: `addrs.peek()`.
    pub(crate) fn probe_endpoint(&self) -> Option<Endpoint> {
        self.hosts.servers.addrs.peek().cloned()
    }

    /// Returns the host text for the log lines. It is the `set_servers`
    /// text, or the configured text before any `set_servers`.
    fn hosts_text(&self) -> JString {
        self.hosts
            .host_text
            .clone()
            .unwrap_or_else(|| self.cfg.host_text.clone())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::action::{ResolveError, TlsConfigStep};
    use crate::compat::Compat;
    use crate::config::DriverMode;
    use crate::errno;
    use crate::interest::test_support::{
        Tk, answer, conn, conn_with, ep, host, init_two, logs, sa, sites,
    };

    #[test]
    fn stale_results_change_nothing() {
        let mut c = conn();
        let Some(Action::Resolve { generation, .. }) = c.poll_action(Millis(0)) else {
            panic!("expected Resolve");
        };
        c.handle_host_resolved(
            generation + 1,
            HostResolution {
                host: 0,
                result: Ok(vec![sa("10.0.0.1:2181")]),
                skipped_families: vec![99],
            },
            Millis(0),
        );
        assert!(c.hosts.collected.is_empty());
        assert!(sites(&mut c).is_empty());
        assert_eq!(c.handle_resolved(generation + 1, true, Millis(0)), rc::ZOK);
        assert_eq!(c.hosts.in_flight, Some(generation));
        assert!(c.hosts.servers.addrs.is_empty());
    }

    #[test]
    fn unchanged_resolution_keeps_the_list_storage() {
        let mut c = conn();
        init_two(&mut c);
        let two = [Some("10.0.0.1:2181"), Some("10.0.0.2:2181")];
        let want = [ep("10.0.0.1:2181", 0, "a"), ep("10.0.0.2:2181", 1, "b")];
        assert_eq!(c.hosts.servers.addrs.as_slice(), &want[..]);
        let specs = vec![host("a", 2181), host("b", 2181)];
        let generation = c.set_servers(specs.clone(), Millis(1));
        assert_eq!(answer(&mut c, generation, &two, Millis(1)), rc::ZOK);
        assert_eq!(c.hosts.servers.addrs.as_slice(), &want[..]);
        assert!(c.hosts.collected.is_empty());
        assert_eq!(c.hosts.spare.len(), 2);
        // The next resolution writes into the spare entries in list order,
        // and the list storage swaps between `collected` and `spare`.
        let generation = c.set_servers(specs.clone(), Millis(2));
        assert_eq!(answer(&mut c, generation, &two, Millis(2)), rc::ZOK);
        let names: Vec<*const u8> = c.hosts.spare.iter().rev().map(name_ptr).collect();
        let spare_list = c.hosts.spare.as_ptr();
        let collected_list = c.hosts.collected.as_ptr();
        assert!(c.hosts.collected.capacity() >= 2);
        let generation = c.set_servers(specs.clone(), Millis(3));
        feed_host(&mut c, generation, 0, &["10.0.0.1:2181"]);
        feed_host(&mut c, generation, 1, &["10.0.0.2:2181"]);
        assert_eq!(c.hosts.collected.as_ptr(), collected_list);
        let reused: Vec<*const u8> = c.hosts.collected.iter().map(name_ptr).collect();
        assert_eq!(reused, names);
        assert_eq!(c.handle_resolved(generation, false, Millis(3)), rc::ZOK);
        assert_eq!(c.hosts.servers.addrs.as_slice(), &want[..]);
        assert_eq!(c.hosts.spare.as_ptr(), collected_list);
        assert_eq!(c.hosts.collected.as_ptr(), spare_list);
        // A changed list moves into the set and frees the spare storage.
        let generation = c.set_servers(specs, Millis(4));
        let one = [Some("10.0.0.3:2181"), None];
        assert_eq!(answer(&mut c, generation, &one, Millis(4)), rc::ZOK);
        let want = [ep("10.0.0.3:2181", 0, "a")];
        assert_eq!(c.hosts.servers.addrs.as_slice(), &want[..]);
        assert!(c.hosts.collected.is_empty());
        assert_eq!(c.hosts.collected.capacity(), 0);
        assert!(c.hosts.spare.is_empty());
        assert_eq!(c.hosts.spare.capacity(), 0);
    }

    /// Gives the address of the name storage of an entry.
    fn name_ptr(e: &Endpoint) -> *const u8 {
        e.host.name.as_ptr()
    }

    /// Gives each host entry its addresses and returns the collected list.
    fn feed(c: &mut Connection<Tk>, generation: u64, per_host: &[&[&str]]) -> Vec<Endpoint> {
        for (i, addrs) in per_host.iter().enumerate() {
            feed_host(c, generation, i, addrs);
        }
        c.hosts.collected.clone()
    }

    /// Gives host entry `host` its addresses.
    fn feed_host(c: &mut Connection<Tk>, generation: u64, host: usize, addrs: &[&str]) {
        c.handle_host_resolved(
            generation,
            HostResolution {
                host,
                result: Ok(addrs.iter().map(|a| sa(a)).collect()),
                skipped_families: Vec::new(),
            },
            Millis(0),
        );
    }

    /// Resolves `specs` on `c` and on a fresh connection, and checks that
    /// both give the same lists.
    fn resolve_like_fresh(c: &mut Connection<Tk>, specs: &[HostSpec], per_host: &[&[&str]]) {
        let mut fresh = conn();
        let fg = fresh.set_servers(specs.to_vec(), Millis(0));
        let want = feed(&mut fresh, fg, per_host);
        assert_eq!(fresh.handle_resolved(fg, false, Millis(0)), rc::ZOK);
        let generation = c.set_servers(specs.to_vec(), Millis(0));
        assert_eq!(feed(c, generation, per_host), want);
        assert_eq!(c.handle_resolved(generation, false, Millis(0)), rc::ZOK);
        assert_eq!(
            c.hosts.servers.addrs.as_slice(),
            fresh.hosts.servers.addrs.as_slice()
        );
    }

    #[test]
    fn spare_entries_give_the_list_of_a_fresh_build() {
        let mut c = conn();
        let two = [host("alpha", 2181), host("b", 2181)];
        let addrs: [&[&str]; 2] = [&["10.0.0.1:2181"], &["10.0.0.2:2181"]];
        resolve_like_fresh(&mut c, &two, &addrs);
        assert!(c.hosts.spare.is_empty());
        // An unchanged list gives its entries to the next resolution.
        resolve_like_fresh(&mut c, &two, &addrs);
        assert_eq!(c.hosts.spare.len(), 2);
        let generation = c.set_servers(two.to_vec(), Millis(0));
        feed_host(&mut c, generation, 0, addrs[0]);
        assert_eq!(c.hosts.spare.len(), 1);
        feed_host(&mut c, generation, 1, addrs[1]);
        assert!(c.hosts.spare.is_empty());
        assert_eq!(c.handle_resolved(generation, false, Millis(0)), rc::ZOK);
        assert_eq!(c.hosts.spare.len(), 2);
        // A shorter list with a shorter name writes over a spare entry.
        let one = [host("c", 2182)];
        resolve_like_fresh(&mut c, &one, &[&["10.0.0.3:2182"]]);
        assert!(c.hosts.spare.is_empty());
        resolve_like_fresh(&mut c, &one, &[&["10.0.0.3:2182"]]);
        assert_eq!(c.hosts.spare.len(), 1);
        // A longer list uses the spare entry and then new storage.
        let three = [host("x", 2181), host("yy", 2181), host("zzz", 2181)];
        let more: [&[&str]; 3] = [
            &["10.0.1.1:2181", "10.0.1.2:2181"],
            &["10.0.1.3:2181"],
            &["10.0.1.4:2181", "10.0.1.5:2181"],
        ];
        resolve_like_fresh(&mut c, &three, &more);
        assert!(c.hosts.spare.is_empty());
        resolve_like_fresh(&mut c, &three, &more);
        assert_eq!(c.hosts.spare.len(), 5);
        resolve_like_fresh(&mut c, &three, &more);
        assert_eq!(c.hosts.spare.len(), 5);
    }

    #[test]
    fn host_results_log_at_once_and_carry_the_token() {
        let mut c = conn();
        let Some(Action::Resolve { generation, .. }) = c.poll_action(Millis(0)) else {
            panic!("expected Resolve");
        };
        c.handle_host_resolved(
            generation,
            HostResolution {
                host: 0,
                result: Err(ResolveError {
                    gai_rc: -2,
                    errno: 5,
                }),
                skipped_families: Vec::new(),
            },
            Millis(0),
        );
        let l = logs(&mut c);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].site, gai_site());
        assert_eq!(
            l[0].args,
            vec![LogArg::GaiStr {
                gai_rc: -2,
                errno: 5
            }]
        );
        c.handle_host_resolved(
            generation,
            HostResolution {
                host: 1,
                result: Ok(vec![sa("10.0.0.2:2181")]),
                skipped_families: vec![0x1e],
            },
            Millis(0),
        );
        let l = logs(&mut c);
        assert_eq!(l[0].site, LogSite::ResolveSkipFamily);
        assert_eq!(
            l[0].args,
            vec![
                LogArg::I64(0x1e),
                LogArg::Str(JString::Bytes(b"a:2181,b:2181".to_vec()))
            ]
        );
        assert_eq!(c.hosts.collected, vec![ep("10.0.0.2:2181", 1, "b")]);
        assert_eq!(c.handle_resolved(generation, false, Millis(3)), rc::ZOK);
        assert_eq!(c.hosts.last_resolved_at, Some(Millis(3)));
        assert_eq!(c.hosts.servers.addrs.len(), 1);
    }

    /// Rule: each resolution reseeds once and shuffles with `random()`.
    #[test]
    fn shuffle_reseeds_and_draws() {
        let (mut c, draws) = conn_with(Compat::LEGACY_C, DriverMode::ST, |_| {});
        let Some(Action::Resolve { generation, .. }) = c.poll_action(Millis(0)) else {
            panic!("expected Resolve");
        };
        for (i, a) in ["10.0.0.1:2181", "10.0.0.2:2181"].iter().enumerate() {
            c.handle_host_resolved(
                generation,
                HostResolution {
                    host: i,
                    result: Ok(vec![sa(a)]),
                    skipped_families: Vec::new(),
                },
                Millis(0),
            );
        }
        // random() % 2 == 0 swaps the two entries.
        draws.lock().unwrap().random.push_back(0);
        assert_eq!(c.handle_resolved(generation, true, Millis(0)), rc::ZOK);
        let d = draws.lock().unwrap();
        assert_eq!(d.resolutions, 1);
        assert_eq!(d.random_calls, 1);
        drop(d);
        assert_eq!(
            c.hosts.servers.addrs.as_slice()[0].addr,
            sa("10.0.0.2:2181")
        );
    }

    #[test]
    fn set_servers_commits_and_resolves_with_its_generation() {
        let mut c = conn();
        init_two(&mut c);
        let generation = c.set_servers(vec![host("c", 2182)], Millis(10));
        assert_eq!(c.hosts.generation, generation);
        assert!(c.hosts.resolve_due);
        // No iteration resolution goes out while the driver resolves.
        c.begin_interest(Millis(10)).unwrap();
        c.interest.step = IterStep::Resolve;
        assert!(c.resolve_action(Millis(10)).is_none());
        c.handle_host_resolved(
            generation,
            HostResolution {
                host: 0,
                result: Ok(vec![sa("10.0.0.3:2182")]),
                skipped_families: Vec::new(),
            },
            Millis(10),
        );
        assert_eq!(c.handle_resolved(generation, false, Millis(10)), rc::ZOK);
        assert!(!c.hosts.resolve_due);
        assert_eq!(
            c.hosts.servers.addrs.as_slice()[0],
            ep("10.0.0.3:2182", 0, "c")
        );
        assert_eq!(c.hosts_text(), JString::Bytes(b"c:2182".to_vec()));
    }

    #[test]
    fn set_servers_failure_keeps_the_old_addresses() {
        let mut c = conn();
        init_two(&mut c);
        let generation = c.set_servers(vec![host("c", 2182)], Millis(10));
        let rc = answer(&mut c, generation, &[None], Millis(10));
        assert_eq!(rc, rc::ZSYSTEMERROR);
        // A set_servers failure does not feed an iteration.
        assert_eq!(c.interest.rc, rc::ZOK);
        assert!(!c.hosts.block_connect);
        assert_eq!(c.hosts.servers.addrs.len(), 2);
        assert_eq!(c.hosts.specs, vec![host("c", 2182)]);
    }

    #[test]
    fn empty_host_list_resolves_to_an_empty_list() {
        let mut c = conn();
        init_two(&mut c);
        let generation = c.set_servers(Vec::new(), Millis(10));
        assert!(sites(&mut c).is_empty());
        assert_eq!(c.handle_resolved(generation, true, Millis(10)), rc::ZOK);
        assert!(c.hosts.servers.addrs.is_empty());
    }

    #[test]
    fn resolve_delay_validation() {
        let mut c = conn();
        assert_eq!(c.set_resolve_delay(-2), rc::ZBADARGUMENTS);
        let l = logs(&mut c);
        assert_eq!(l[0].site, LogSite::ResolveDelayInvalid);
        assert_eq!(l[0].args, vec![LogArg::I64(-2)]);
        assert_eq!(c.hosts.resolve_delay_ms, 0);
        assert_eq!(c.set_resolve_delay(-1), rc::ZOK);
        assert_eq!(c.hosts.resolve_delay_ms, -1);
    }

    #[test]
    fn resolve_with_transport_follows_the_delay() {
        let mut c = conn();
        init_two(&mut c);
        c.core.has_transport = true;
        c.hosts.resolve_delay_ms = -1;
        assert!(c.resolve_action(Millis(1_000_000)).is_none());
        c.hosts.resolve_delay_ms = 0;
        assert!(c.resolve_action(Millis(1)).is_some());
        c.hosts.in_flight = None;
        c.hosts.last_resolved_at = Some(Millis(1000));
        c.hosts.resolve_delay_ms = 500;
        assert!(c.resolve_action(Millis(1500)).is_none());
        assert!(c.resolve_action(Millis(1501)).is_some());
    }

    #[test]
    fn resolve_cadence_without_transport() {
        let with = |cadence| {
            let compat = Compat {
                resolve_cadence: cadence,
                ..Compat::LEGACY_C
            };
            let (mut c, _) = conn_with(compat, DriverMode::ST, |_| {});
            init_two(&mut c);
            c
        };
        let mut c = with(ResolveCadence::Never);
        assert!(c.resolve_action(Millis(1_000_000)).is_none());

        let mut c = with(ResolveCadence::Throttled { ms: 100 });
        assert!(c.resolve_action(Millis(100)).is_none());
        assert!(c.resolve_action(Millis(101)).is_some());

        let mut c = with(ResolveCadence::EachPass);
        assert!(c.resolve_action(Millis(5)).is_none());
        c.hosts.servers.reconfig = false;
        let _ = c.hosts.servers.addrs.next_item();
        let _ = c.hosts.servers.addrs.next_item();
        c.hosts_on_handle_error(Millis(5));
        // OneShotSkip: the pass resolves after its delay iteration.
        assert!(c.resolve_action(Millis(5)).is_none());
        c.hosts.delay = false;
        let Some(Action::Resolve { initial, .. }) = c.resolve_action(Millis(6)) else {
            panic!("expected Resolve");
        };
        assert!(!initial);
        assert!(c.resolve_action(Millis(7)).is_none());
    }

    #[test]
    fn reconfig_selection_logs() {
        let mut c = conn();
        init_two(&mut c);
        assert!(c.hosts.servers.reconfig);
        c.cycle_next_server();
        let l = logs(&mut c);
        let s: Vec<LogSite> = l.iter().map(|r| r.site).collect();
        assert_eq!(
            s,
            vec![
                LogSite::ReconfigOld,
                LogSite::ReconfigNew,
                LogSite::ReconfigUseNew
            ]
        );
        assert_eq!(
            l[1].args,
            vec![
                LogArg::I64(2),
                LogArg::I64(16),
                LogArg::I64(0),
                LogArg::I64(1)
            ]
        );
        assert_eq!(l[0].args, vec![LogArg::I64(0); 4]);
        assert_eq!(l[2].args, vec![LogArg::Endpoint(Some(sa("10.0.0.1:2181")))]);
        c.cycle_next_server();
        let _ = logs(&mut c);
        c.cycle_next_server();
        assert_eq!(
            sites(&mut c),
            vec![
                LogSite::ReconfigOld,
                LogSite::ReconfigNew,
                LogSite::ReconfigNone
            ]
        );
        assert!(!c.hosts.servers.reconfig);
        assert_eq!(c.current_server(), Some(sa("10.0.0.1:2181")));
        c.cycle_next_server();
        assert!(sites(&mut c).is_empty());
    }

    #[test]
    fn reconfig_old_list_logs_use_old() {
        let mut c = conn();
        init_two(&mut c);
        // Same list size, current server gone: p_old decides.
        c.hosts.servers.new = AddrVec::new();
        c.hosts.servers.old = AddrVec::from(vec![ep("10.0.0.2:2181", 1, "b")]);
        c.cycle_next_server();
        let s = sites(&mut c);
        assert_eq!(s[2], LogSite::ReconfigUseOld);
        assert_eq!(c.current_server(), Some(sa("10.0.0.2:2181")));
    }

    #[test]
    fn capacity_rounds_up_to_the_growth_step() {
        assert_eq!(addrvec_capacity(0), 0);
        assert_eq!(addrvec_capacity(1), 16);
        assert_eq!(addrvec_capacity(16), 16);
        assert_eq!(addrvec_capacity(17), 32);
    }

    #[test]
    fn probe_failures_advance_the_cursor_without_cur() {
        let mut c = conn();
        init_two(&mut c);
        c.hosts.servers.reconfig = false;
        c.cycle_next_server();
        let cur = c.current_server();
        c.core.state = State::ReadOnly;
        assert_eq!(c.probe_endpoint(), Some(ep("10.0.0.2:2181", 1, "b")));
        c.handle_rw_probe(
            ep("10.0.0.2:2181", 1, "b"),
            ProbeOutcome::NotReadWrite,
            Millis(0),
        );
        assert_eq!(c.current_server(), cur);
        assert_eq!(c.probe_endpoint(), Some(ep("10.0.0.1:2181", 0, "a")));
        assert!(sites(&mut c).is_empty());

        c.handle_rw_probe(
            ep("10.0.0.1:2181", 0, "a"),
            ProbeOutcome::Failed(Some(ProbeTlsFailure::Config {
                step: TlsConfigStep::CaFile,
                file: JString::Null,
            })),
            Millis(0),
        );
        let l = logs(&mut c);
        assert_eq!(l[0].site, LogSite::TlsCaFile);
        assert_eq!(l[0].args, vec![LogArg::Str(JString::Null)]);
        assert_eq!(c.take_errno_hint(), Some(errno::EINVAL));
        assert_eq!(c.probe_endpoint(), Some(ep("10.0.0.2:2181", 1, "b")));

        c.handle_rw_probe(
            ep("10.0.0.2:2181", 1, "b"),
            ProbeOutcome::Failed(Some(ProbeTlsFailure::Handshake)),
            Millis(0),
        );
        assert_eq!(sites(&mut c), vec![LogSite::TlsConnect]);
        assert_eq!(c.take_errno_hint(), None);
        c.handle_rw_probe(
            ep("10.0.0.1:2181", 0, "a"),
            ProbeOutcome::Failed(None),
            Millis(0),
        );
        assert!(sites(&mut c).is_empty());
    }

    #[test]
    fn probe_results_outside_read_only_are_ignored() {
        let mut c = conn();
        init_two(&mut c);
        c.core.state = State::Connected;
        let before = c.hosts.servers.addrs.cursor();
        c.handle_rw_probe(
            ep("10.0.0.1:2181", 0, "a"),
            ProbeOutcome::ReadWrite,
            Millis(0),
        );
        assert_eq!(c.hosts.rw_target, None);
        assert_eq!(c.hosts.servers.addrs.cursor(), before);
        assert!(sites(&mut c).is_empty());
    }

    /// Rule: the read-write target of a probe is the next connect.
    #[test]
    fn rw_target_is_the_next_connect() {
        let mut c = conn();
        init_two(&mut c);
        c.hosts.rw_target = Some(ep("10.0.0.2:2181", 1, "b"));
        let ConnectDecision::Connect(Action::Connect { endpoint, .. }) =
            c.connect_decision(Millis(0))
        else {
            panic!("expected Connect");
        };
        assert_eq!(endpoint.addr, sa("10.0.0.2:2181"));
        assert_eq!(c.current_server(), Some(sa("10.0.0.2:2181")));
        assert_eq!(c.hosts.rw_target, None);
        // The reconfig cursor did not move.
        assert_eq!(c.hosts.servers.new.cursor(), 0);
    }

    #[test]
    fn block_connect_gives_blocked() {
        let mut c = conn();
        init_two(&mut c);
        c.hosts.block_connect = true;
        assert!(matches!(
            c.connect_decision(Millis(0)),
            ConnectDecision::Blocked
        ));
    }

    #[test]
    fn one_shot_wait_resets_the_timers() {
        let mut c = conn();
        init_two(&mut c);
        c.hosts.delay = true;
        c.timers.rw_timeout_ms = 800;
        assert!(matches!(
            c.connect_decision(Millis(42)),
            ConnectDecision::Wait
        ));
        assert!(!c.hosts.delay);
        assert_eq!(c.timers.last_recv, Millis(42));
        assert_eq!(c.timers.rw_timeout_ms, RW_PROBE_MIN_MS);
        let l = logs(&mut c);
        assert_eq!(l[0].site, LogSite::DelayingConnection);
        assert_eq!(
            l[0].args,
            vec![LogArg::Str(JString::Bytes(b"a:2181,b:2181".to_vec()))]
        );
    }

    #[test]
    fn handle_error_on_an_empty_list() {
        let mut c = conn();
        c.hosts_on_handle_error(Millis(0));
        assert!(c.hosts.delay);
        assert_eq!(c.current_server(), None);
    }

    #[test]
    fn deadline_pause_grows_exponentially_and_resets() {
        let compat = Compat {
            reconnect_backoff: Backoff::Deadline,
            ..Compat::LEGACY_C
        };
        let (mut c, _) = conn_with(compat, DriverMode::ST, |cfg| {
            cfg.reconnect_delay_ms = 1_000;
            cfg.reconnect_jitter_pct = 0;
        });
        // The address list is empty, so each failure ends a full pass.
        let mut pauses = Vec::new();
        for _ in 0..7 {
            c.hosts_on_handle_error(Millis(0));
            pauses.push(c.hosts.not_before.unwrap().0);
        }
        assert_eq!(
            pauses,
            vec![1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]
        );
        // An established session starts the growth again.
        c.hosts_on_established();
        c.hosts_on_handle_error(Millis(0));
        assert_eq!(c.hosts.not_before, Some(Millis(1_000)));
        c.hosts_on_handle_error(Millis(0));
        assert_eq!(c.hosts.not_before, Some(Millis(2_000)));
        // So does a new host list.
        let _ = c.set_servers(vec![host("a", 2181)], Millis(0));
        c.hosts_on_handle_error(Millis(0));
        assert_eq!(c.hosts.not_before, Some(Millis(1_000)));
        // Many failures saturate and stay at the cap.
        c.hosts.failed_passes = u32::MAX;
        c.hosts_on_handle_error(Millis(0));
        assert_eq!(c.hosts.not_before, Some(Millis(30_000)));
        // A delay above the cap is not shortened.
        let (mut big, _) = conn_with(compat, DriverMode::ST, |cfg| {
            cfg.reconnect_delay_ms = 45_000;
        });
        big.hosts_on_handle_error(Millis(0));
        big.hosts_on_handle_error(Millis(0));
        assert_eq!(big.hosts.not_before, Some(Millis(45_000)));
    }

    #[test]
    fn deadline_jitter_scales_with_the_grown_pause() {
        let compat = Compat {
            reconnect_backoff: Backoff::Deadline,
            ..Compat::LEGACY_C
        };
        let (mut c, draws) = conn_with(compat, DriverMode::ST, |cfg| {
            cfg.reconnect_delay_ms = 1_000;
            cfg.reconnect_jitter_pct = 25;
        });
        c.hosts.failed_passes = 2;
        // b = 4000 and j = 1000. The draw 0 gives the offset -1000.
        draws.lock().unwrap().random.push_back(0);
        c.hosts_on_handle_error(Millis(0));
        assert_eq!(c.hosts.not_before, Some(Millis(3_000)));
    }

    #[test]
    fn deadline_lost_session_starts_a_counted_pass() {
        let compat = Compat {
            reconnect_backoff: Backoff::Deadline,
            ..Compat::LEGACY_C
        };
        let (mut c, _) = conn_with(compat, DriverMode::ST, |cfg| {
            cfg.reconnect_delay_ms = 1_000;
            cfg.reconnect_jitter_pct = 0;
        });
        init_two(&mut c);
        c.hosts.servers.reconfig = false;
        // The session was on the last address. The loss sets no pause,
        // and it makes a resolution due.
        let _ = c.hosts.servers.addrs.next_item();
        let _ = c.hosts.servers.addrs.next_item();
        c.hosts_on_session_lost(Millis(0));
        assert_eq!(c.hosts.not_before, None);
        assert!(c.hosts.pass_ended);
        assert_eq!(c.hosts.pass_left, Some(2));
        assert_eq!(c.current_server(), Some(sa("10.0.0.1:2181")));
        // The pass ends at its second failure. The next pass has the
        // same length.
        c.cycle_next_server();
        c.hosts_on_handle_error(Millis(10));
        assert_eq!(c.hosts.not_before, None);
        c.cycle_next_server();
        c.hosts_on_handle_error(Millis(20));
        assert_eq!(c.hosts.not_before, Some(Millis(1_020)));
        assert_eq!(c.hosts.failed_passes, 1);
        assert_eq!(c.hosts.pass_left, Some(2));
        // A changed list ends the counted passes.
        let generation = c.set_servers(vec![host("c", 23700)], Millis(30));
        let got = answer(&mut c, generation, &[Some("10.0.0.3:23700")], Millis(30));
        assert_eq!(got, rc::ZOK);
        assert_eq!(c.hosts.pass_left, None);
        // The set_servers resolution is the resolution of the pass.
        assert!(!c.hosts.pass_ended);
        // So does an established session.
        c.hosts_on_session_lost(Millis(40));
        assert_eq!(c.hosts.pass_left, Some(1));
        c.hosts_on_established();
        assert_eq!(c.hosts.pass_left, None);
    }

    #[test]
    fn each_pass_counts_a_set_servers_resolution_after_a_loss() {
        let compat = Compat {
            resolve_cadence: ResolveCadence::EachPass,
            reconnect_backoff: Backoff::Deadline,
            ..Compat::LEGACY_C
        };
        let (mut c, _) = conn_with(compat, DriverMode::ST, |_| {});
        init_two(&mut c);
        c.hosts.servers.reconfig = false;
        c.hosts_on_session_lost(Millis(0));
        assert!(c.hosts.pass_ended);
        // A failed set_servers resolution also counts for the pass. The
        // next iteration does not resolve the same list again.
        let generation = c.set_servers(vec![host("c", 2182)], Millis(10));
        let got = answer(&mut c, generation, &[None], Millis(10));
        assert_eq!(got, rc::ZSYSTEMERROR);
        assert!(!c.hosts.pass_ended);
        assert!(c.resolve_action(Millis(20)).is_none());
    }

    #[test]
    fn one_shot_skip_lost_session_keeps_the_legacy_delay() {
        let mut c = conn();
        init_two(&mut c);
        c.hosts.servers.reconfig = false;
        let _ = c.hosts.servers.addrs.next_item();
        let _ = c.hosts.servers.addrs.next_item();
        c.hosts_on_session_lost(Millis(0));
        assert!(c.hosts.delay);
        assert!(c.hosts.pass_ended);
        assert_eq!(c.hosts.pass_left, None);
        assert_eq!(c.hosts.not_before, None);
        assert_eq!(c.current_server(), Some(sa("10.0.0.1:2181")));
    }
}
