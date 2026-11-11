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

//! The deterministic driver loop.
//!
//! A [`Harness`] owns one [`Connection`], one [`ServerSim`], one
//! [`Network`] and one [`ManualClock`]. It acts as the driver of the core:
//! it runs the interest cycle, executes the actions, moves bytes in both
//! directions and drains the outputs. No real I/O occurs, and the same
//! seed gives the same run.

use core::fmt;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use zk_jute::data::ACL;
use zk_jute::{JBuffer, JString, JVec, opcode};
use zk_proto::compat::CloseMode;
use zk_proto::legacy::connect::{HostSpec as LegacyHostSpec, NativeHost};
use zk_proto::{
    Action, CloseProgress, Compat, Config, ConnectStart, Connection, DriverMode, Endpoint,
    HostSpec, InputDefect, InterestOutcome, Leftovers, LogLevel, Millis, MultiOp, Op, OpResult,
    Origin, Output, PathIn, ProbeOutcome, Request, Route, SaslAddr, SaslCall, SaslCallKind,
    SaslError, SaslSession, SaslStep, SecretBytes, Stage, State, Submitted, TransportFailure, rc,
};

use crate::chunk::{Chunker, Chunking};
use crate::clock::ManualClock;
use crate::hooks::{SharedDefaultWatcher, SharedLogFilter};
use crate::net::{ConnectPlan, ConnectStyle, ECONNREFUSED, ECONNRESET, Network};
use crate::recorder::{ActionRecord, Event, Recorder, SaslKind};
use crate::rng::{LibcRandomClone, RngLog, ScriptedRng, SeededRng};
use crate::sasl::{SaslLog, SaslScript, ScriptedSasl};
use crate::server::{LinkId, LinkStatus, ServerOptions, ServerSim, open_acl};
use crate::tokens::{AuthTicket, TestTokens, Ticket, TokenMint, WatcherId};

/// The budget of one `poll_transmit` call. It matches the plaintext
/// drivers: proto copies at most 64 KiB in one call, and only a lent large
/// frame uses the rest.
pub const TRANSMIT_MAX: usize = 4 * 1024 * 1024;
/// The default limit of [`Harness::connect`] and [`Harness::wait_for`], in
/// milliseconds of harness time.
pub const DEFAULT_LIMIT_MS: u64 = 120_000;
/// The first client port of the server listeners.
pub const BASE_PORT: u16 = 2181;

/// The largest number of loop rounds in one pump or one I/O loop.
const LOOP_LIMIT: usize = 100_000;
/// The largest number of steps in one run.
const STEP_LIMIT: u64 = 2_000_000;
/// The number of busy steps at one time stamp before the clock moves.
const BUSY_LIMIT: u32 = 256;

/// Returns the host spec of `addr`: the native form when `native` is
/// true, else the legacy form.
fn host_spec_for(native: bool, addr: SocketAddr) -> HostSpec {
    let host = addr.ip().to_string();
    if native {
        HostSpec::Native(NativeHost {
            host,
            port: addr.port(),
        })
    } else {
        HostSpec::Legacy(LegacyHostSpec {
            host: host.into_bytes(),
            service: addr.port().to_string().into_bytes(),
            port: i32::from(addr.port()),
        })
    }
}

/// Returns the address of server `index`: `127.0.0.1:2181+index`.
#[must_use]
pub fn server_addr(index: usize) -> SocketAddr {
    let off = u16::try_from(index).unwrap_or(u16::MAX);
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        BASE_PORT.saturating_add(off),
    )
}

/// How the harness gives received bytes to `handle_read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    /// Chunks from the receive [`Chunking`] plan.
    Chunked,
    /// At most `read_hint()` bytes per call, as the single-threaded C
    /// driver reads. The receive plan can make the calls smaller.
    Hint,
}

/// When the harness writes to the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteGate {
    /// Only when the last interest asked for write.
    Interest,
    /// In every step.
    Always,
}

/// The random source of the connection.
#[derive(Clone, Debug, PartialEq)]
pub enum RngChoice {
    /// A [`SeededRng`] with the harness seed.
    Seeded,
    /// A [`LibcRandomClone`] with these seeds.
    Libc(Vec<u32>),
    /// A [`ScriptedRng`] with these values.
    Scripted {
        /// The values of `random()`.
        randoms: Vec<i64>,
        /// The values of `drand48()`.
        drands: Vec<f64>,
    },
}

/// The error of a harness run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HarnessError {
    /// The condition did not become true before the limit.
    Timeout {
        /// The harness time at the end.
        at: Millis,
    },
    /// The run used too many steps.
    Runaway {
        /// The number of steps.
        steps: u64,
    },
    /// The core refused a submit.
    Rejected {
        /// The ticket of the request.
        ticket: Ticket,
        /// The stage of the failure.
        stage: Stage,
        /// The legacy code.
        code: i32,
    },
    /// The core refused an `add_auth`.
    AuthRejected {
        /// The legacy code.
        code: i32,
    },
    /// An assert helper failed.
    Assert(String),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout { at } => write!(f, "timeout at {} ms", at.0),
            Self::Runaway { steps } => write!(f, "runaway after {steps} steps"),
            Self::Rejected {
                ticket,
                stage,
                code,
            } => write!(f, "ticket {} rejected at {stage:?} with {code}", ticket.0),
            Self::AuthRejected { code } => write!(f, "add_auth rejected with {code}"),
            Self::Assert(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for HarnessError {}

/// A refused submit. The core gave the token back at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitRejected {
    /// The ticket of the request.
    pub ticket: Ticket,
    /// The stage of the failure.
    pub stage: Stage,
    /// The legacy code.
    pub code: i32,
}

impl From<SubmitRejected> for HarnessError {
    fn from(r: SubmitRejected) -> Self {
        Self::Rejected {
            ticket: r.ticket,
            stage: r.stage,
            code: r.code,
        }
    }
}

/// The state that an output hook can use.
pub struct HookCtx<'a> {
    /// The connection. A hook can submit, as a C completion can call the
    /// API again.
    pub conn: &'a mut Connection<TestTokens>,
    /// The harness time.
    pub now: Millis,
    /// The token source.
    pub mint: &'a mut TokenMint,
    /// The record. The output itself is recorded after the hook returns.
    pub recorder: &'a mut Recorder,
}

impl HookCtx<'_> {
    /// Submits a queued request from inside a hook.
    ///
    /// # Errors
    ///
    /// Returns the refusal of the core.
    pub fn submit(&mut self, op: Op<WatcherId>) -> Result<Ticket, SubmitRejected> {
        submit_on(
            self.conn,
            self.mint,
            self.recorder,
            self.now,
            op,
            Route::Queued,
            InputDefect::default(),
        )
    }
}

/// A function that sees each output before the harness records it.
pub type OutputHook = Box<dyn FnMut(&mut HookCtx<'_>, &Output<TestTokens>)>;

/// Everything that is left at the end of a run.
#[derive(Debug)]
pub struct Finished {
    /// The tokens and outputs that the connection still held.
    pub leftovers: Leftovers<TestTokens>,
    /// The record. The leftover tickets count as delivered.
    pub recorder: Recorder,
    /// The server model.
    pub server: ServerSim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkState {
    None,
    Connecting {
        addr: SocketAddr,
        plan: ConnectPlan,
        ready_at: Option<Millis>,
    },
    Open {
        link: LinkId,
    },
}

#[derive(Debug)]
enum SaslResult {
    Started(Result<(String, SaslStep), SaslError>),
    Stepped(Result<SaslStep, SaslError>),
}

#[derive(Debug)]
struct Deferred {
    at: Millis,
    generation: u32,
    result: SaslResult,
}

/// Builds a [`Harness`].
pub struct HarnessBuilder {
    config: Config,
    compat: Compat,
    mode: Option<DriverMode>,
    seed: u64,
    servers: usize,
    server_options: ServerOptions,
    tx_chunking: Chunking,
    rx_chunking: Chunking,
    read_mode: Option<ReadMode>,
    write_gate: WriteGate,
    connect_style: ConnectStyle,
    rng: RngChoice,
    log_level: Option<LogLevel>,
    default_watcher: Option<WatcherId>,
    sasl: SaslScript,
    shuffle: bool,
    start: Millis,
}

impl fmt::Debug for HarnessBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarnessBuilder")
            .field("mode", &self.mode)
            .field("seed", &self.seed)
            .field("servers", &self.servers)
            .finish_non_exhaustive()
    }
}

impl HarnessBuilder {
    /// Starts a builder with one server, seed 0 and whole chunks.
    #[must_use]
    pub fn new(config: Config, compat: Compat) -> Self {
        Self {
            config,
            compat,
            mode: None,
            seed: 0,
            servers: 1,
            server_options: ServerOptions::default(),
            tx_chunking: Chunking::Whole,
            rx_chunking: Chunking::Whole,
            read_mode: None,
            write_gate: WriteGate::Interest,
            connect_style: ConnectStyle::Immediate,
            rng: RngChoice::Seeded,
            log_level: Some(LogLevel::Debug),
            default_watcher: None,
            sasl: SaslScript::default(),
            shuffle: true,
            start: Millis(1_000),
        }
    }

    /// Sets the driver mode. The default is `ST` for a legacy profile and
    /// `NATIVE` for a native profile.
    #[must_use]
    pub const fn mode(mut self, mode: DriverMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Sets the seed of every random choice of the run.
    #[must_use]
    pub const fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Sets the number of server listeners. The addresses come from
    /// [`server_addr`]. An empty host list in the config gets these
    /// addresses.
    #[must_use]
    pub const fn servers(mut self, n: usize) -> Self {
        self.servers = n;
        self
    }

    /// Sets the requested session timeout of the config.
    #[must_use]
    pub const fn timeout(mut self, ms: i32) -> Self {
        self.config.timeout_ms = ms;
        self
    }

    /// Sets the deadline of a `Drain` close in the config.
    #[must_use]
    pub const fn close_timeout(mut self, ms: u32) -> Self {
        self.config.close_timeout_ms = ms;
        self
    }

    /// Sets the server options.
    #[must_use]
    pub fn server_options(mut self, opts: ServerOptions) -> Self {
        self.server_options = opts;
        self
    }

    /// Sets the chunk plan of both directions.
    #[must_use]
    pub fn chunking(mut self, plan: Chunking) -> Self {
        self.tx_chunking = plan.clone();
        self.rx_chunking = plan;
        self
    }

    /// Sets the chunk plan of the writes to the server.
    #[must_use]
    pub fn tx_chunking(mut self, plan: Chunking) -> Self {
        self.tx_chunking = plan;
        self
    }

    /// Sets the chunk plan of the reads from the server.
    #[must_use]
    pub fn rx_chunking(mut self, plan: Chunking) -> Self {
        self.rx_chunking = plan;
        self
    }

    /// Sets the read mode. The default is `Hint` for `ST` and `Chunked`
    /// for the other modes.
    #[must_use]
    pub const fn read_mode(mut self, mode: ReadMode) -> Self {
        self.read_mode = Some(mode);
        self
    }

    /// Sets the write gate.
    #[must_use]
    pub const fn write_gate(mut self, gate: WriteGate) -> Self {
        self.write_gate = gate;
        self
    }

    /// Sets how a successful connect completes.
    #[must_use]
    pub const fn connect_style(mut self, style: ConnectStyle) -> Self {
        self.connect_style = style;
        self
    }

    /// Sets the random source of the connection.
    #[must_use]
    pub fn rng(mut self, rng: RngChoice) -> Self {
        self.rng = rng;
        self
    }

    /// Sets the most verbose enabled log level, or `None` for no logs. The
    /// default is `Debug`.
    #[must_use]
    pub const fn log_level(mut self, level: Option<LogLevel>) -> Self {
        self.log_level = level;
        self
    }

    /// Sets the default watcher.
    #[must_use]
    pub const fn default_watcher(mut self, w: Option<WatcherId>) -> Self {
        self.default_watcher = w;
        self
    }

    /// Sets the script of each SASL mechanism session.
    #[must_use]
    pub fn sasl(mut self, script: SaslScript) -> Self {
        self.sasl = script;
        self
    }

    /// Sets the `shuffle` argument of `handle_resolved`. The default is
    /// true.
    #[must_use]
    pub const fn shuffle(mut self, shuffle: bool) -> Self {
        self.shuffle = shuffle;
        self
    }

    /// Sets the start time. The default is 1000 ms.
    #[must_use]
    pub const fn start_at(mut self, t: Millis) -> Self {
        self.start = t;
        self
    }

    /// Makes the harness. The connection exists, but no step ran.
    #[must_use]
    pub fn build(self) -> Harness {
        let mode = self.mode.unwrap_or(if self.compat.native_ops {
            DriverMode::NATIVE
        } else {
            DriverMode::ST
        });
        let read_mode = self.read_mode.unwrap_or(if mode == DriverMode::ST {
            ReadMode::Hint
        } else {
            ReadMode::Chunked
        });
        let mut config = self.config;
        let n = self.servers.max(1);
        if config.hosts.is_empty() {
            let mut text = Vec::new();
            for i in 0..n {
                let a = server_addr(i);
                let host = a.ip().to_string();
                if i > 0 {
                    text.push(b',');
                }
                text.extend_from_slice(format!("{host}:{}", a.port()).as_bytes());
                config.hosts.push(host_spec_for(self.compat.native_ops, a));
            }
            config.host_text = JString::Bytes(text);
        }
        let mut server = ServerSim::new(self.server_options, self.seed);
        for i in 0..n {
            server.add_listener(server_addr(i), false);
        }
        let mut net = Network::new();
        net.set_connect_style(self.connect_style);
        let rng_log = RngLog::new();
        let rng: Box<dyn zk_proto::Rng> = match self.rng {
            RngChoice::Seeded => Box::new(SeededRng::new(self.seed).with_log(rng_log.clone())),
            RngChoice::Libc(seeds) => {
                Box::new(LibcRandomClone::new(seeds).with_log(rng_log.clone()))
            }
            RngChoice::Scripted { randoms, drands } => {
                Box::new(ScriptedRng::new(randoms, drands, self.seed).with_log(rng_log.clone()))
            }
        };
        let log_filter = SharedLogFilter::new(self.log_level);
        let default_watcher = SharedDefaultWatcher::new(self.default_watcher);
        let clock = ManualClock::new(self.start);
        let conn = Box::new(Connection::new(
            config,
            self.compat,
            mode,
            rng,
            Box::new(log_filter.clone()),
            Box::new(default_watcher.clone()),
            clock.now(),
        ));
        Harness {
            conn,
            clock,
            server,
            net,
            recorder: Recorder::new(),
            mint: TokenMint::new(),
            compat: self.compat,
            mode,
            link: LinkState::None,
            tx_buf: Vec::new(),
            rx_buf: Vec::new(),
            tx_chunker: Chunker::new(self.tx_chunking),
            rx_chunker: Chunker::new(self.rx_chunking),
            read_mode,
            write_gate: self.write_gate,
            sasl_script: self.sasl,
            sasl_log: SaslLog::new(),
            sasl: None,
            deferred: VecDeque::new(),
            scheduled: VecDeque::new(),
            last_interest: None,
            hook: None,
            reset_after: None,
            write_budget: None,
            shuffle: self.shuffle,
            log_filter,
            default_watcher,
            rng_log,
            progress: false,
            reads_paused: false,
        }
    }
}

/// The deterministic driver of one connection.
pub struct Harness {
    conn: Box<Connection<TestTokens>>,
    clock: ManualClock,
    server: ServerSim,
    net: Network,
    recorder: Recorder,
    mint: TokenMint,
    compat: Compat,
    mode: DriverMode,
    link: LinkState,
    tx_buf: Vec<u8>,
    rx_buf: Vec<u8>,
    tx_chunker: Chunker,
    rx_chunker: Chunker,
    read_mode: ReadMode,
    write_gate: WriteGate,
    sasl_script: SaslScript,
    sasl_log: SaslLog,
    sasl: Option<ScriptedSasl>,
    deferred: VecDeque<Deferred>,
    scheduled: VecDeque<(Millis, TransportFailure)>,
    last_interest: Option<InterestOutcome>,
    hook: Option<OutputHook>,
    reset_after: Option<usize>,
    write_budget: Option<usize>,
    shuffle: bool,
    log_filter: SharedLogFilter,
    default_watcher: SharedDefaultWatcher,
    rng_log: RngLog,
    progress: bool,
    reads_paused: bool,
}

impl fmt::Debug for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Harness")
            .field("now", &self.clock.now())
            .field("conn", &self.conn)
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

fn submit_on(
    conn: &mut Connection<TestTokens>,
    mint: &mut TokenMint,
    recorder: &mut Recorder,
    now: Millis,
    op: Op<WatcherId>,
    route: Route,
    defect: InputDefect,
) -> Result<Ticket, SubmitRejected> {
    let (token, ticket) = mint.completion();
    recorder.issue(ticket);
    let req = Request {
        op,
        token,
        route,
        defect,
    };
    match conn.submit(req, now) {
        Ok(Submitted::Queued { xid }) => {
            recorder.push(now, Event::Submitted { ticket, xid });
            Ok(ticket)
        }
        Ok(Submitted::Local(_)) => {
            recorder.push(now, Event::SubmitLocal(ticket));
            Ok(ticket)
        }
        Err(e) => {
            recorder.push(
                now,
                Event::SubmitRejected {
                    ticket,
                    stage: e.stage,
                    code: e.code,
                },
            );
            Err(SubmitRejected {
                ticket,
                stage: e.stage,
                code: e.code,
            })
        }
    }
}

impl Harness {
    /// Makes a harness with one server. The mode is `ST` for a legacy
    /// profile and `NATIVE` for a native profile.
    #[must_use]
    pub fn new(config: Config, compat: Compat, seed: u64) -> Self {
        HarnessBuilder::new(config, compat).seed(seed).build()
    }

    /// Starts a builder.
    #[must_use]
    pub fn builder(config: Config, compat: Compat) -> HarnessBuilder {
        HarnessBuilder::new(config, compat)
    }

    /// Makes a legacy C harness in `ST` mode with a 10 s timeout.
    #[must_use]
    pub fn st(seed: u64) -> Self {
        HarnessBuilder::new(Config::legacy(10_000), Compat::LEGACY_C)
            .mode(DriverMode::ST)
            .seed(seed)
            .build()
    }

    /// Makes a legacy C harness in `MT` mode with a 10 s timeout.
    #[must_use]
    pub fn mt(seed: u64) -> Self {
        HarnessBuilder::new(Config::legacy(10_000), Compat::LEGACY_C)
            .mode(DriverMode::MT)
            .seed(seed)
            .build()
    }

    /// Makes a native harness with a 10 s timeout and a 2 s close drain.
    #[must_use]
    pub fn native(seed: u64) -> Self {
        let mut config = Config::legacy(10_000);
        config.close_timeout_ms = 2_000;
        HarnessBuilder::new(config, Compat::NATIVE)
            .mode(DriverMode::NATIVE)
            .seed(seed)
            .build()
    }

    // ----- accessors -----

    /// Returns the connection.
    #[must_use]
    pub const fn conn(&self) -> &Connection<TestTokens> {
        &self.conn
    }

    /// Returns the connection for a direct call. The harness does not see
    /// the outputs of the call until the next pump.
    pub fn conn_mut(&mut self) -> &mut Connection<TestTokens> {
        &mut self.conn
    }

    /// Returns the server model.
    #[must_use]
    pub const fn server(&self) -> &ServerSim {
        &self.server
    }

    /// Returns the server model for a change.
    pub fn server_mut(&mut self) -> &mut ServerSim {
        &mut self.server
    }

    /// Returns the network model.
    #[must_use]
    pub const fn net(&self) -> &Network {
        &self.net
    }

    /// Returns the network model for a change.
    pub fn net_mut(&mut self) -> &mut Network {
        &mut self.net
    }

    /// Returns the record.
    #[must_use]
    pub const fn recorder(&self) -> &Recorder {
        &self.recorder
    }

    /// Returns the record for a note.
    pub fn recorder_mut(&mut self) -> &mut Recorder {
        &mut self.recorder
    }

    /// Returns the token source.
    pub fn mint(&mut self) -> &mut TokenMint {
        &mut self.mint
    }

    /// Returns the harness time.
    #[must_use]
    pub const fn now(&self) -> Millis {
        self.clock.now()
    }

    /// Returns the compat profile.
    #[must_use]
    pub const fn compat(&self) -> &Compat {
        &self.compat
    }

    /// Returns the driver mode.
    #[must_use]
    pub const fn mode(&self) -> DriverMode {
        self.mode
    }

    /// Returns the visible state of the connection.
    #[must_use]
    pub fn state(&self) -> State {
        self.conn.state()
    }

    /// Returns the result of the last `finish_interest`.
    #[must_use]
    pub const fn last_interest(&self) -> Option<InterestOutcome> {
        self.last_interest
    }

    /// Returns the open server link, if any.
    #[must_use]
    pub const fn link(&self) -> Option<LinkId> {
        match self.link {
            LinkState::Open { link } => Some(link),
            LinkState::None | LinkState::Connecting { .. } => None,
        }
    }

    /// Returns the log of the random calls of the connection.
    #[must_use]
    pub const fn rng_log(&self) -> &RngLog {
        &self.rng_log
    }

    /// Returns the log of the mechanism calls.
    #[must_use]
    pub const fn sasl_log(&self) -> &SaslLog {
        &self.sasl_log
    }

    /// Returns the shared log filter. A change applies at once.
    #[must_use]
    pub const fn log_filter(&self) -> &SharedLogFilter {
        &self.log_filter
    }

    /// Returns the shared default watcher. A change applies at once.
    #[must_use]
    pub const fn default_watcher(&self) -> &SharedDefaultWatcher {
        &self.default_watcher
    }

    /// Returns a request builder for the profile of the harness.
    #[must_use]
    pub const fn ops(&self) -> Ops {
        Ops {
            native: self.compat.native_ops,
        }
    }

    // ----- settings -----

    /// Sets the output hook. The hook sees each output before the record
    /// gets it, and before the harness resumes a barrier.
    pub fn set_hook(&mut self, hook: OutputHook) {
        self.hook = Some(hook);
    }

    /// Removes the output hook.
    pub fn clear_hook(&mut self) {
        self.hook = None;
    }

    /// Sets the SASL script of the next mechanism session.
    pub fn set_sasl(&mut self, script: SaslScript) {
        self.sasl_script = script;
    }

    /// Sets the write gate.
    pub fn set_write_gate(&mut self, gate: WriteGate) {
        self.write_gate = gate;
    }

    /// Sets the read mode.
    pub fn set_read_mode(&mut self, mode: ReadMode) {
        self.read_mode = mode;
    }

    /// Sets the chunk plans of both directions.
    pub fn set_chunking(&mut self, plan: Chunking) {
        self.tx_chunker = Chunker::new(plan.clone());
        self.rx_chunker = Chunker::new(plan);
    }

    /// Limits the bytes that the server takes from now on, or removes the
    /// limit. A limit of 0 blocks every write, as a full socket buffer
    /// does.
    pub fn set_write_budget(&mut self, budget: Option<usize>) {
        self.write_budget = budget;
    }

    /// Stops or restarts the reads from the server. The bytes stay queued
    /// at the server.
    pub fn pause_reads(&mut self, paused: bool) {
        self.reads_paused = paused;
    }

    /// Resets the open link after the client writes `n` more bytes.
    pub fn reset_after_bytes(&mut self, n: usize) {
        self.reset_after = Some(n);
    }

    /// Sets the `shuffle` argument of `handle_resolved`.
    pub fn set_shuffle(&mut self, shuffle: bool) {
        self.shuffle = shuffle;
    }

    /// Replaces the host list, as `zoo_set_servers` does.
    ///
    /// The core yields no `Resolve` action for a `set_servers` list, so
    /// the harness resolves each host through the network at once. It
    /// records the resolution as an action and returns the generation and
    /// the rc of `handle_resolved`.
    pub fn set_servers(&mut self, hosts: Vec<HostSpec>) -> (u64, i32) {
        let now = self.now();
        let generation = self.conn.set_servers(hosts.clone(), now);
        for (i, h) in hosts.iter().enumerate() {
            let r = self.net.resolve(i, h);
            self.conn.handle_host_resolved(generation, r, now);
        }
        let rc = self.conn.handle_resolved(generation, self.shuffle, now);
        self.recorder.push(
            now,
            Event::Action(ActionRecord::Resolve {
                generation,
                hosts: hosts.len(),
                initial: false,
                rc,
            }),
        );
        self.pump(now);
        (generation, rc)
    }

    /// Returns the host spec of server `index` in the form of the profile.
    #[must_use]
    pub fn host_spec(&self, index: usize) -> HostSpec {
        host_spec_for(self.compat.native_ops, server_addr(index))
    }

    // ----- faults -----

    /// Resets the open link at the server. The next step reports
    /// `Io{ECONNRESET}` to the core.
    pub fn reset_current(&mut self) {
        if let LinkState::Open { link } = self.link {
            self.server.reset_link(link);
        }
    }

    /// Closes the open link at the server. The next step reports `Eof`
    /// after the queued bytes.
    pub fn close_current(&mut self) {
        if let LinkState::Open { link } = self.link {
            self.server.close_link(link);
        }
    }

    /// Reports a transport failure to the core now, and drops the link.
    /// It returns the rc of `handle_transport_failed`.
    pub fn inject_failure(&mut self, f: TransportFailure) -> i32 {
        let now = self.now();
        let rc = self.report_failure(f, now);
        self.pump(now);
        rc
    }

    /// Reports a transport failure to the core in the first step at or
    /// after `at`.
    pub fn schedule_failure(&mut self, at: Millis, f: TransportFailure) {
        self.scheduled.push_back((at, f));
    }

    // ----- requests -----

    /// Submits a queued request.
    ///
    /// # Errors
    ///
    /// Returns the refusal of the core.
    pub fn submit(&mut self, op: Op<WatcherId>) -> Result<Ticket, SubmitRejected> {
        self.submit_with(op, Route::Queued, InputDefect::default())
    }

    /// Submits a request with this route and these input defects.
    ///
    /// # Errors
    ///
    /// Returns the refusal of the core.
    pub fn submit_with(
        &mut self,
        op: Op<WatcherId>,
        route: Route,
        defect: InputDefect,
    ) -> Result<Ticket, SubmitRejected> {
        let now = self.now();
        let r = submit_on(
            &mut self.conn,
            &mut self.mint,
            &mut self.recorder,
            now,
            op,
            route,
            defect,
        );
        self.pump(now);
        r
    }

    /// Runs until the completion of `ticket` is in the record, and returns
    /// it. A local completion gives `rc = ZOK` with no reply.
    ///
    /// # Errors
    ///
    /// Returns a timeout after [`DEFAULT_LIMIT_MS`], a runaway, or the
    /// refusal of the core when the submit failed.
    pub fn wait_for(&mut self, ticket: Ticket) -> Result<OpResult, HarnessError> {
        self.wait_for_within(ticket, DEFAULT_LIMIT_MS)
    }

    /// Runs until the completion of `ticket` is in the record, with a
    /// limit in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns a timeout, a runaway, or the refusal of the core when the
    /// submit failed.
    pub fn wait_for_within(
        &mut self,
        ticket: Ticket,
        limit_ms: u64,
    ) -> Result<OpResult, HarnessError> {
        self.run_until(|h| h.recorder.delivery(ticket).is_some(), limit_ms)?;
        match self.recorder.delivery(ticket) {
            Some(crate::recorder::Delivery::Completion(r)) => Ok(r.clone()),
            Some(crate::recorder::Delivery::Local) => Ok(OpResult {
                rc: rc::ZOK,
                zxid: 0,
                origin: Origin::Reply,
                reply: None,
            }),
            Some(crate::recorder::Delivery::Rejected(code)) => {
                let stage = self
                    .recorder
                    .all()
                    .iter()
                    .find_map(|r| match &r.event {
                        Event::SubmitRejected {
                            ticket: t, stage, ..
                        } if *t == ticket => Some(*stage),
                        _ => None,
                    })
                    .unwrap_or(Stage::Validate);
                Err(HarnessError::Rejected {
                    ticket,
                    stage,
                    code,
                })
            }
            None => Err(HarnessError::Timeout { at: self.now() }),
        }
    }

    /// Submits a queued request and waits for its completion.
    ///
    /// # Errors
    ///
    /// Returns the refusal of the core, a timeout or a runaway.
    pub fn call(&mut self, op: Op<WatcherId>) -> Result<OpResult, HarnessError> {
        let t = self.submit(op)?;
        self.wait_for(t)
    }

    /// Adds an auth entry with a fresh auth token.
    ///
    /// # Errors
    ///
    /// Returns the refusal of the core.
    pub fn add_auth(&mut self, scheme: &str, cred: &[u8]) -> Result<AuthTicket, HarnessError> {
        let now = self.now();
        let (id, ticket) = self.mint.auth();
        let r = self.conn.add_auth(
            JString::from(scheme),
            SecretBytes::from_slice(cred),
            Some(id),
            now,
        );
        let out = match r {
            Ok(()) => {
                self.recorder.push(now, Event::AuthAdded(Some(ticket)));
                Ok(ticket)
            }
            Err(e) => {
                self.recorder.push(
                    now,
                    Event::AuthRejected {
                        ticket: e.done.map(|a| a.ticket()),
                        code: e.code,
                    },
                );
                Err(HarnessError::AuthRejected { code: e.code })
            }
        };
        self.pump(now);
        out
    }

    // ----- the run -----

    /// Runs until the state is connected (3 or 5).
    ///
    /// # Errors
    ///
    /// Returns a timeout after [`DEFAULT_LIMIT_MS`], or a runaway.
    pub fn connect(&mut self) -> Result<(), HarnessError> {
        self.run_until(|h| h.conn.state().is_connected(), DEFAULT_LIMIT_MS)
    }

    /// Runs the steps for `ms` milliseconds of harness time.
    ///
    /// # Errors
    ///
    /// Returns a runaway.
    pub fn run_for(&mut self, ms: u64) -> Result<(), HarnessError> {
        let end = self.now().saturating_add_ms(ms);
        match self.run_until(|h| h.now() >= end, ms.saturating_add(1)) {
            Err(HarnessError::Timeout { .. }) | Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Runs steps until `pred` is true. When a step makes no progress, the
    /// clock moves to the next wake time.
    ///
    /// # Errors
    ///
    /// Returns a timeout when `limit_ms` of harness time pass, or a
    /// runaway after too many steps.
    pub fn run_until<F>(&mut self, mut pred: F, limit_ms: u64) -> Result<(), HarnessError>
    where
        F: FnMut(&mut Self) -> bool,
    {
        let deadline = self.now().saturating_add_ms(limit_ms);
        let mut steps: u64 = 0;
        let mut busy: u32 = 0;
        loop {
            if pred(self) {
                return Ok(());
            }
            if self.now() > deadline {
                return Err(HarnessError::Timeout { at: self.now() });
            }
            steps = steps.saturating_add(1);
            if steps > STEP_LIMIT {
                return Err(HarnessError::Runaway { steps });
            }
            let now = self.now();
            let progressed = self.step(now);
            if pred(self) {
                return Ok(());
            }
            if progressed && busy < BUSY_LIMIT {
                busy = busy.saturating_add(1);
                continue;
            }
            busy = 0;
            let next = self
                .next_wake(now)
                .min(deadline.saturating_add_ms(1))
                .max(now.saturating_add_ms(1));
            self.clock.advance_to(next);
        }
    }

    /// Returns the next time when something can change by itself: the
    /// interest timeout, a server event, a connect completion, a deferred
    /// SASL result or a scheduled failure. It is always after `now`.
    #[must_use]
    pub fn next_wake(&self, now: Millis) -> Millis {
        let mut best = Millis(u64::MAX);
        let t_ms = u64::try_from(self.conn.recv_timeout().max(0)).unwrap_or(0);
        let interest = match self.last_interest.and_then(|o| o.outputs) {
            Some(i) => u64::from(i.timeout_ms),
            None => t_ms.checked_div(60).unwrap_or(0),
        };
        best = best.min(now.saturating_add_ms(interest));
        if let Some(t) = self.server.next_wake(now) {
            best = best.min(t);
        }
        if let LinkState::Connecting {
            ready_at: Some(t), ..
        } = self.link
        {
            best = best.min(t);
        }
        if let Some(d) = self.deferred.iter().map(|d| d.at).min() {
            best = best.min(d);
        }
        if let Some(s) = self.scheduled.iter().map(|s| s.0).min() {
            best = best.min(s);
        }
        best.max(now.saturating_add_ms(1))
    }

    /// Runs one driver step at `now`. It returns true when the step made
    /// progress: an output, an action other than a resolution, a byte
    /// moved or a failure.
    ///
    /// The order is: the server clock, a forced-close teardown, scheduled
    /// faults, deferred SASL results, the interest cycle, a connect
    /// completion, the writes, the reads and the link state.
    pub fn step(&mut self, now: Millis) -> bool {
        let now = self.clock.advance_to(now);
        self.progress = false;
        self.server.tick(now);
        if self.conn.run_pending_teardown(now) {
            self.progress = true;
        }
        self.pump(now);
        self.run_scheduled(now);
        self.run_deferred(now);
        self.pump(now);
        self.interest_cycle(now);
        self.pump(now);
        self.finish_connect(now);
        self.pump(now);
        let write = match self.write_gate {
            WriteGate::Always => true,
            WriteGate::Interest => self
                .last_interest
                .and_then(|o| o.outputs)
                .is_some_and(|i| i.write),
        };
        if write {
            self.write_loop(now);
        }
        let read = self
            .last_interest
            .and_then(|o| o.outputs)
            .is_some_and(|i| i.read);
        let stalled = if read && !self.reads_paused {
            self.read_loop(now)
        } else {
            false
        };
        self.check_link(now, stalled || !read || self.reads_paused);
        self.pump(now);
        self.progress
    }

    /// Pops every output, resumes every barrier and runs every queued
    /// action.
    pub fn pump(&mut self, now: Millis) {
        for _ in 0..LOOP_LIMIT {
            if let Some(o) = self.conn.poll_output() {
                self.progress = true;
                let barrier = o.is_barrier();
                let stopped = if barrier {
                    self.conn.take_stopped()
                } else {
                    None
                };
                self.run_hook(now, &o);
                self.recorder.push(now, Event::Output(o));
                if let Some(s) = stopped {
                    self.resume(s, now);
                }
                continue;
            }
            if let Some(s) = self.conn.take_stopped() {
                self.progress = true;
                self.resume(s, now);
                continue;
            }
            if let Some(a) = self.conn.poll_action(now) {
                self.execute(a, now);
                continue;
            }
            break;
        }
    }

    /// Closes the connection as the profile does.
    ///
    /// Under `LegacyFailPending` it runs `begin_close`, `queue_close_op`, a
    /// flush of up to [`zk_proto::CLOSE_FLUSH_MS`], a readability wait of
    /// up to [`zk_proto::CLOSE_WAIT_MS`] with no read, then `destroy`.
    /// Under `Drain` it runs `begin_close` and `queue_close_op`, then the
    /// normal steps until `close_step` gives `Complete`, then `destroy`.
    ///
    /// # Errors
    ///
    /// Returns a runaway of the drain loop.
    pub fn close(&mut self) -> Result<(), HarnessError> {
        let now = self.now();
        self.conn.begin_close(now);
        self.pump(now);
        match self.compat.close_mode {
            CloseMode::LegacyFailPending => {
                if self.conn.queue_close_op() {
                    self.close_flush();
                    self.close_wait();
                }
            }
            CloseMode::Drain => {
                // A false return makes `close_step` complete at once.
                let _ = self.conn.queue_close_op();
                self.pump(now);
                let r = self.run_until(
                    |h| {
                        let t = h.now();
                        h.conn.close_step(t) == CloseProgress::Complete
                    },
                    DEFAULT_LIMIT_MS,
                );
                if let Err(HarnessError::Runaway { steps }) = r {
                    return Err(HarnessError::Runaway { steps });
                }
            }
        }
        let now = self.now();
        self.conn.destroy(now);
        self.pump(now);
        Ok(())
    }

    /// Ends the run. The leftover tickets go to the record.
    #[must_use]
    pub fn finish(self) -> Finished {
        let mut recorder = self.recorder;
        let leftovers = self.conn.into_leftovers();
        for c in &leftovers.completions {
            recorder.leftover(c.ticket());
        }
        for o in &leftovers.outputs {
            if let Output::Completion { token, .. } = o {
                recorder.leftover(token.ticket());
            }
        }
        Finished {
            leftovers,
            recorder,
            server: self.server,
        }
    }

    // ----- assert helpers -----

    /// Checks the visible state.
    ///
    /// # Errors
    ///
    /// Returns an assert error with both states.
    pub fn expect_state(&self, want: State) -> Result<(), HarnessError> {
        let got = self.conn.state();
        if got == want {
            Ok(())
        } else {
            Err(HarnessError::Assert(format!(
                "state is {got:?}, want {want:?}"
            )))
        }
    }

    /// Checks that `ticket` completed once with `rc`, and returns the
    /// result.
    ///
    /// # Errors
    ///
    /// Returns an assert error when the ticket has no completion, more
    /// than one, or another rc.
    pub fn expect_completion(&self, ticket: Ticket, want: i32) -> Result<&OpResult, HarnessError> {
        let n = self.recorder.completion_count(ticket);
        if n != 1 {
            return Err(HarnessError::Assert(format!(
                "ticket {} has {n} completions",
                ticket.0
            )));
        }
        match self.recorder.completion(ticket) {
            Some(r) if r.rc == want => Ok(r),
            Some(r) => Err(HarnessError::Assert(format!(
                "ticket {} completed with {}, want {want}",
                ticket.0, r.rc
            ))),
            None => Err(HarnessError::Assert(format!(
                "ticket {} has no completion",
                ticket.0
            ))),
        }
    }

    /// Checks that each issued ticket so far completed exactly once.
    ///
    /// # Errors
    ///
    /// Returns an assert error that names the bad tickets.
    pub fn expect_exactly_once(&self) -> Result<(), HarnessError> {
        self.recorder
            .check_exactly_once()
            .map_err(HarnessError::Assert)
    }

    // ----- internals -----

    fn resume(&mut self, s: zk_proto::Stopped, now: Millis) {
        let id = s.id();
        self.recorder.push(now, Event::Stopped(id));
        self.conn.resume(s, now);
        self.recorder.push(now, Event::Resumed(id));
    }

    fn run_hook(&mut self, now: Millis, o: &Output<TestTokens>) {
        if let Some(mut hook) = self.hook.take() {
            let mut ctx = HookCtx {
                conn: &mut self.conn,
                now,
                mint: &mut self.mint,
                recorder: &mut self.recorder,
            };
            hook(&mut ctx, o);
            self.hook = Some(hook);
        }
    }

    fn run_scheduled(&mut self, now: Millis) {
        let mut keep = VecDeque::new();
        while let Some((at, f)) = self.scheduled.pop_front() {
            if at <= now {
                let _ = self.report_failure(f, now);
                self.pump(now);
            } else {
                keep.push_back((at, f));
            }
        }
        self.scheduled = keep;
    }

    fn run_deferred(&mut self, now: Millis) {
        let mut keep = VecDeque::new();
        while let Some(d) = self.deferred.pop_front() {
            if d.at <= now {
                self.give_sasl(d.generation, d.result, now);
                self.pump(now);
            } else {
                keep.push_back(d);
            }
        }
        self.deferred = keep;
    }

    fn interest_cycle(&mut self, now: Millis) {
        match self.conn.begin_interest(now) {
            Err(code) => {
                self.recorder.push(now, Event::InterestRefused(code));
                self.last_interest = None;
            }
            Ok(()) => {
                for _ in 0..LOOP_LIMIT {
                    match self.conn.poll_action(now) {
                        Some(a) => self.execute(a, now),
                        None => break,
                    }
                }
                let out = self.conn.finish_interest(now);
                self.recorder.push(now, Event::Interest(out));
                self.last_interest = Some(out);
            }
        }
    }

    fn execute(&mut self, a: Action, now: Millis) {
        match a {
            Action::Resolve {
                generation,
                hosts,
                initial,
            } => {
                for (i, h) in hosts.iter().enumerate() {
                    let r = self.net.resolve(i, h);
                    self.conn.handle_host_resolved(generation, r, now);
                }
                let rc = self.conn.handle_resolved(generation, self.shuffle, now);
                self.recorder.push(
                    now,
                    Event::Action(ActionRecord::Resolve {
                        generation,
                        hosts: hosts.len(),
                        initial,
                        rc,
                    }),
                );
            }
            Action::Connect { endpoint, tls } => {
                self.progress = true;
                self.start_connect(&endpoint, tls.is_some(), now);
            }
            Action::CloseTransport => {
                self.progress = true;
                self.recorder
                    .push(now, Event::Action(ActionRecord::CloseTransport));
                self.drop_link();
            }
            Action::ProbeRw { endpoint, .. } => {
                self.progress = true;
                let addr = endpoint.addr;
                let outcome =
                    self.net
                        .probe(addr)
                        .unwrap_or_else(|| match self.server.listener(addr) {
                            Some(l) if l.accepting && !l.read_only => ProbeOutcome::ReadWrite,
                            Some(l) if l.accepting => ProbeOutcome::NotReadWrite,
                            _ => ProbeOutcome::Failed(None),
                        });
                self.recorder.push(
                    now,
                    Event::Action(ActionRecord::ProbeRw {
                        addr,
                        outcome: outcome.clone(),
                    }),
                );
                self.conn.handle_rw_probe(endpoint, outcome, now);
            }
            Action::Sasl(call) => {
                self.progress = true;
                self.sasl_call(call, now);
            }
        }
    }

    fn start_connect(&mut self, endpoint: &Endpoint, tls: bool, now: Millis) {
        let addr = endpoint.addr;
        self.net.note_connect(addr);
        let plan = self.net.plan(addr).unwrap_or(if self.server.accepts(addr) {
            ConnectPlan::Accept
        } else {
            ConnectPlan::Refuse {
                errno: ECONNREFUSED,
            }
        });
        self.recorder.push(
            now,
            Event::Action(ActionRecord::Connect { addr, tls, plan }),
        );
        self.tx_buf.clear();
        self.rx_buf.clear();
        match plan {
            ConnectPlan::Accept => match self.net.connect_style() {
                ConnectStyle::Immediate => match self.server.accept(addr, now) {
                    Some(link) => {
                        self.conn
                            .handle_connect_started(ConnectStart::Immediate, now);
                        self.link = LinkState::Open { link };
                        self.conn.handle_tcp_connected(now);
                        self.conn.handle_transport_ready(now);
                    }
                    None => {
                        self.conn
                            .handle_connect_started(ConnectStart::InProgress, now);
                        self.link = LinkState::Connecting {
                            addr,
                            plan: ConnectPlan::Refuse {
                                errno: ECONNREFUSED,
                            },
                            ready_at: Some(now),
                        };
                    }
                },
                ConnectStyle::InProgress { delay_ms } => {
                    self.conn
                        .handle_connect_started(ConnectStart::InProgress, now);
                    self.link = LinkState::Connecting {
                        addr,
                        plan,
                        ready_at: Some(now.saturating_add_ms(delay_ms)),
                    };
                }
            },
            ConnectPlan::Refuse { .. } => {
                self.conn
                    .handle_connect_started(ConnectStart::InProgress, now);
                self.link = LinkState::Connecting {
                    addr,
                    plan,
                    ready_at: Some(now),
                };
            }
            ConnectPlan::SocketFail { errno } => {
                // The core ignores a failure when no transport exists. Thus
                // the transport opens before the failure.
                self.conn
                    .handle_connect_started(ConnectStart::InProgress, now);
                self.link = LinkState::Connecting {
                    addr,
                    plan,
                    ready_at: None,
                };
                let _ = self.report_failure(TransportFailure::SocketCreate { errno }, now);
            }
            ConnectPlan::Hang => {
                self.conn
                    .handle_connect_started(ConnectStart::InProgress, now);
                self.link = LinkState::Connecting {
                    addr,
                    plan,
                    ready_at: None,
                };
            }
        }
    }

    fn finish_connect(&mut self, now: Millis) {
        let LinkState::Connecting {
            addr,
            plan,
            ready_at: Some(at),
        } = self.link
        else {
            return;
        };
        if at > now {
            return;
        }
        self.progress = true;
        match plan {
            ConnectPlan::Accept => match self.server.accept(addr, now) {
                Some(link) => {
                    self.link = LinkState::Open { link };
                    self.conn.handle_tcp_connected(now);
                    self.conn.handle_transport_ready(now);
                }
                None => {
                    let _ = self.report_failure(
                        TransportFailure::TcpRefused {
                            errno: ECONNREFUSED,
                        },
                        now,
                    );
                }
            },
            ConnectPlan::Refuse { errno } => {
                let _ = self.report_failure(TransportFailure::TcpRefused { errno }, now);
            }
            ConnectPlan::SocketFail { errno } => {
                let _ = self.report_failure(TransportFailure::SocketCreate { errno }, now);
            }
            ConnectPlan::Hang => {}
        }
    }

    fn drop_link(&mut self) {
        if let LinkState::Open { link } = self.link {
            self.server.client_close(link);
        }
        self.link = LinkState::None;
        self.tx_buf.clear();
        self.rx_buf.clear();
    }

    fn report_failure(&mut self, f: TransportFailure, now: Millis) -> i32 {
        self.progress = true;
        let rc = self.conn.handle_transport_failed(f.clone(), now);
        self.recorder.push(now, Event::Failure { failure: f, rc });
        // The core always ends the transport on a failure, so the link
        // ends here too.
        self.drop_link();
        rc
    }

    /// Moves bytes from the core to the server. It returns the number of
    /// bytes that the server took.
    fn write_loop(&mut self, now: Millis) -> usize {
        let LinkState::Open { link } = self.link else {
            return 0;
        };
        let mut total = 0usize;
        for _ in 0..LOOP_LIMIT {
            if self.server.status(link) != LinkStatus::Open {
                break;
            }
            if self.tx_buf.is_empty()
                && self.conn.poll_transmit(&mut self.tx_buf, TRANSMIT_MAX) == 0
            {
                break;
            }
            let mut n = self.tx_chunker.next_len(self.tx_buf.len());
            if let Some(b) = self.write_budget {
                n = n.min(b);
                self.write_budget = Some(b.saturating_sub(n));
            }
            let mut reset = false;
            if let Some(r) = self.reset_after {
                if r <= n {
                    n = r;
                    reset = true;
                    self.reset_after = None;
                } else {
                    self.reset_after = Some(r.saturating_sub(n));
                }
            }
            if n > 0 {
                let chunk: Vec<u8> = self.tx_buf.drain(..n).collect();
                self.server.client_write(link, &chunk, now);
                self.conn.handle_transmitted(n, now);
                self.recorder.push(now, Event::Transmit { bytes: n });
                self.progress = true;
                total = total.saturating_add(n);
            }
            if reset {
                self.server.reset_link(link);
                break;
            }
            if n == 0 {
                break;
            }
        }
        total
    }

    /// Moves bytes from the server to the core. It returns true when the
    /// core left bytes that it did not take.
    fn read_loop(&mut self, now: Millis) -> bool {
        let LinkState::Open { link } = self.link else {
            return false;
        };
        for _ in 0..LOOP_LIMIT {
            if self.link != (LinkState::Open { link }) {
                return false;
            }
            let more = self.server.take_available(link, now);
            self.rx_buf.extend_from_slice(&more);
            if self.rx_buf.is_empty() {
                return false;
            }
            let avail = self.rx_buf.len();
            let n = match self.read_mode {
                ReadMode::Chunked => self.rx_chunker.next_len(avail),
                ReadMode::Hint => {
                    let h = self.conn.read_hint();
                    if h == 0 {
                        return true;
                    }
                    self.rx_chunker.next_len(avail).min(h)
                }
            };
            let Some(bytes) = self.rx_buf.get(..n) else {
                return true;
            };
            let out = self.conn.handle_read(bytes, now);
            self.recorder.push(
                now,
                Event::Read {
                    len: n,
                    outcome: out,
                },
            );
            let used = out.consumed.min(self.rx_buf.len());
            self.rx_buf.drain(..used);
            if used > 0 {
                self.progress = true;
            }
            self.pump(now);
            if used == 0 {
                return true;
            }
        }
        true
    }

    fn check_link(&mut self, now: Millis, stalled: bool) {
        let LinkState::Open { link } = self.link else {
            return;
        };
        // A native driver stops reading when the drain is complete. After
        // that, the state of the server end does not matter.
        if self.compat.close_mode == CloseMode::Drain
            && self.conn.is_closing()
            && self.conn.close_step(now) == CloseProgress::Complete
        {
            return;
        }
        match self.server.status(link) {
            LinkStatus::Open => {}
            LinkStatus::Eof => {
                if self.rx_buf.is_empty() || stalled {
                    let _ = self.report_failure(TransportFailure::Eof, now);
                }
            }
            LinkStatus::Reset | LinkStatus::Gone => {
                self.rx_buf.clear();
                let _ = self.report_failure(TransportFailure::Io { errno: ECONNRESET }, now);
            }
        }
    }

    fn close_flush(&mut self) {
        let start = self.now();
        let end = start.saturating_add_ms(u64::from(zk_proto::CLOSE_FLUSH_MS));
        loop {
            let now = self.now();
            let _ = self.write_loop(now);
            if self.tx_buf.is_empty() || self.link().is_none() || now >= end {
                break;
            }
            self.clock.advance(1);
        }
    }

    fn close_wait(&mut self) {
        let start = self.now();
        let end = start.saturating_add_ms(u64::from(zk_proto::CLOSE_WAIT_MS));
        loop {
            let now = self.now();
            self.server.tick(now);
            let ready = match self.link {
                LinkState::Open { link } => {
                    self.server.has_available(link, now)
                        || self.server.status(link) != LinkStatus::Open
                }
                LinkState::None | LinkState::Connecting { .. } => true,
            };
            if ready || now >= end {
                break;
            }
            let next = self
                .server
                .next_wake(now)
                .unwrap_or(end)
                .min(end)
                .max(now.saturating_add_ms(1));
            self.clock.advance_to(next);
        }
    }

    fn sasl_call(&mut self, call: SaslCall, now: Millis) {
        let generation = call.generation;
        let kind = match &call.kind {
            SaslCallKind::Start => SaslKind::Start,
            SaslCallKind::Step(t) => SaslKind::Step(t.as_ref().map(|s| s.expose().to_vec())),
            SaslCallKind::Dispose => SaslKind::Dispose,
        };
        self.recorder
            .push(now, Event::Action(ActionRecord::Sasl { generation, kind }));
        let result = match call.kind {
            SaslCallKind::Dispose => {
                self.sasl = None;
                return;
            }
            SaslCallKind::Start => {
                if let Some(which) = self.sasl_script.addr_failure {
                    self.give_addr_failure(generation, which, now);
                    return;
                }
                let mut s = ScriptedSasl::new(&self.sasl_script, self.sasl_log.clone());
                let r = s.start();
                self.sasl = Some(s);
                SaslResult::Started(r)
            }
            SaslCallKind::Step(tok) => {
                let script = &self.sasl_script;
                let log = &self.sasl_log;
                let s = self
                    .sasl
                    .get_or_insert_with(|| ScriptedSasl::new(script, log.clone()));
                SaslResult::Stepped(s.step(tok.as_ref().map(SecretBytes::expose)))
            }
        };
        match self.sasl_script.defer_ms {
            Some(d) => self.deferred.push_back(Deferred {
                at: now.saturating_add_ms(d),
                generation,
                result,
            }),
            None => self.give_sasl(generation, result, now),
        }
    }

    fn give_addr_failure(&mut self, generation: u32, which: SaslAddr, now: Millis) {
        let rc = self.conn.handle_sasl_addr_failed(generation, which, now);
        self.recorder
            .push(now, Event::SaslResult { generation, rc });
    }

    fn give_sasl(&mut self, generation: u32, result: SaslResult, now: Millis) {
        self.progress = true;
        let rc = match result {
            SaslResult::Started(r) => self.conn.handle_sasl_started(generation, r, now),
            SaslResult::Stepped(r) => self.conn.handle_sasl_stepped(generation, r, now),
        };
        self.recorder
            .push(now, Event::SaslResult { generation, rc });
    }
}

/// Builds requests in the path style of one profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ops {
    /// True for native paths (`PathIn::Native`).
    pub native: bool,
}

impl Ops {
    /// Returns a builder for legacy paths.
    #[must_use]
    pub const fn legacy() -> Self {
        Self { native: false }
    }

    /// Returns a builder for native paths.
    #[must_use]
    pub const fn native() -> Self {
        Self { native: true }
    }

    /// Returns a path in the style of the builder.
    #[must_use]
    pub fn path(&self, p: &str) -> PathIn {
        if self.native {
            PathIn::Native(JString::from(p))
        } else {
            PathIn::Legacy(Some(p.as_bytes().to_vec()))
        }
    }

    /// Returns the open ACL list.
    #[must_use]
    pub fn open_acl() -> JVec<ACL> {
        JVec::Items(open_acl())
    }

    /// Returns a `create` with the open ACL.
    #[must_use]
    pub fn create(&self, p: &str, data: &[u8], mode: i32) -> Op<WatcherId> {
        Op::Create {
            path: self.path(p),
            data: JBuffer::from(data),
            acl: Self::open_acl(),
            mode,
            ttl: -1,
            create2: false,
        }
    }

    /// Returns a `create2` with the open ACL.
    #[must_use]
    pub fn create2(&self, p: &str, data: &[u8], mode: i32) -> Op<WatcherId> {
        Op::Create {
            path: self.path(p),
            data: JBuffer::from(data),
            acl: Self::open_acl(),
            mode,
            ttl: -1,
            create2: true,
        }
    }

    /// Returns a `create2` with a TTL.
    #[must_use]
    pub fn create_ttl(&self, p: &str, data: &[u8], mode: i32, ttl: i64) -> Op<WatcherId> {
        Op::Create {
            path: self.path(p),
            data: JBuffer::from(data),
            acl: Self::open_acl(),
            mode,
            ttl,
            create2: true,
        }
    }

    /// Returns a `delete`.
    #[must_use]
    pub fn delete(&self, p: &str, version: i32) -> Op<WatcherId> {
        Op::Delete {
            path: self.path(p),
            version,
        }
    }

    /// Returns an `exists`.
    #[must_use]
    pub fn exists(&self, p: &str, watch: Option<WatcherId>) -> Op<WatcherId> {
        Op::Exists {
            path: self.path(p),
            watch,
        }
    }

    /// Returns a `getData`.
    #[must_use]
    pub fn get_data(&self, p: &str, watch: Option<WatcherId>) -> Op<WatcherId> {
        Op::GetData {
            path: self.path(p),
            watch,
        }
    }

    /// Returns a `setData`.
    #[must_use]
    pub fn set_data(&self, p: &str, data: &[u8], version: i32) -> Op<WatcherId> {
        Op::SetData {
            path: self.path(p),
            data: JBuffer::from(data),
            version,
        }
    }

    /// Returns a `getChildren`.
    #[must_use]
    pub fn get_children(&self, p: &str, watch: Option<WatcherId>) -> Op<WatcherId> {
        Op::GetChildren {
            path: self.path(p),
            watch,
            with_stat: false,
        }
    }

    /// Returns a `getChildren2`.
    #[must_use]
    pub fn get_children2(&self, p: &str, watch: Option<WatcherId>) -> Op<WatcherId> {
        Op::GetChildren {
            path: self.path(p),
            watch,
            with_stat: true,
        }
    }

    /// Returns a `getACL`.
    #[must_use]
    pub fn get_acl(&self, p: &str) -> Op<WatcherId> {
        Op::GetAcl { path: self.path(p) }
    }

    /// Returns a `setACL`.
    #[must_use]
    pub fn set_acl(&self, p: &str, acl: Vec<ACL>, version: i32) -> Op<WatcherId> {
        Op::SetAcl {
            path: self.path(p),
            acl: JVec::Items(acl),
            version,
        }
    }

    /// Returns a `sync`.
    #[must_use]
    pub fn sync(&self, p: &str) -> Op<WatcherId> {
        Op::Sync { path: self.path(p) }
    }

    /// Returns a `multi`.
    #[must_use]
    pub fn multi(&self, ops: Vec<MultiOp>) -> Op<WatcherId> {
        Op::Multi { ops }
    }

    /// Returns a `multiRead`.
    #[must_use]
    pub fn multi_read(&self, ops: Vec<MultiOp>) -> Op<WatcherId> {
        Op::MultiRead { ops }
    }

    /// Returns a multi `create` with the open ACL.
    #[must_use]
    pub fn m_create(&self, p: &str, data: &[u8], mode: i32) -> MultiOp {
        MultiOp::Create {
            op_type: opcode::CREATE,
            path: self.path(p),
            data: JBuffer::from(data),
            acl: Self::open_acl(),
            mode,
            ttl: -1,
            defect: InputDefect::default(),
        }
    }

    /// Returns a multi `delete`.
    #[must_use]
    pub fn m_delete(&self, p: &str, version: i32) -> MultiOp {
        MultiOp::Delete {
            path: self.path(p),
            version,
            defect: InputDefect::default(),
        }
    }

    /// Returns a multi `setData`.
    #[must_use]
    pub fn m_set_data(&self, p: &str, data: &[u8], version: i32) -> MultiOp {
        MultiOp::SetData {
            path: self.path(p),
            data: JBuffer::from(data),
            version,
            defect: InputDefect::default(),
        }
    }

    /// Returns a multi `check`.
    #[must_use]
    pub fn m_check(&self, p: &str, version: i32) -> MultiOp {
        MultiOp::Check {
            path: self.path(p),
            version,
            defect: InputDefect::default(),
        }
    }

    /// Returns a multi-read `getData`.
    #[must_use]
    pub fn m_get_data(&self, p: &str) -> MultiOp {
        MultiOp::GetData { path: self.path(p) }
    }

    /// Returns a multi-read `getChildren`.
    #[must_use]
    pub fn m_get_children(&self, p: &str) -> MultiOp {
        MultiOp::GetChildren { path: self.path(p) }
    }

    /// Returns an `addWatch`. Mode 0 is persistent and mode 1 is
    /// recursive.
    #[must_use]
    pub fn add_watch(&self, p: &str, mode: i32, watch: WatcherId) -> Op<WatcherId> {
        Op::AddWatch {
            path: self.path(p),
            mode,
            watch,
        }
    }

    /// Returns a `removeWatches`.
    #[must_use]
    pub fn remove_watches(
        &self,
        p: &str,
        wtype: i32,
        watcher: Option<WatcherId>,
        local: bool,
    ) -> Op<WatcherId> {
        Op::RemoveWatches {
            path: self.path(p),
            wtype,
            all: watcher.is_none(),
            watcher,
            local,
        }
    }

    /// Returns a `getEphemerals`.
    #[must_use]
    pub fn get_ephemerals(&self, prefix: &str) -> Op<WatcherId> {
        Op::GetEphemerals {
            prefix: self.path(prefix),
        }
    }

    /// Returns a `getAllChildrenNumber`.
    #[must_use]
    pub fn get_all_children_number(&self, p: &str) -> Op<WatcherId> {
        Op::GetAllChildrenNumber { path: self.path(p) }
    }

    /// Returns a `whoAmI`.
    #[must_use]
    pub const fn who_am_i(&self) -> Op<WatcherId> {
        Op::WhoAmI
    }
}
