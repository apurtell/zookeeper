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

//! A fuzz driver of `zk_proto::Connection`.
//!
//! [`Sim`] acts as the driver and as the server. The fuzz input selects
//! the profile, the server bytes, the requests, the time steps and the
//! results of the driver work. The driver follows the rules of the core
//! API. It runs the interest cycle and resumes each barrier. It keeps one
//! transmit buffer and reads only while the core asks for reads.
//!
//! The sim checks these properties:
//!
//! - No call panics, and no loop of the core runs without end.
//! - Each completion token and each auth token leaves the core exactly
//!   once, as an output, as a refusal or as a leftover.
//! - The core never gives a token that the sim did not issue.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use zk_jute::data::{ACL, Id};
use zk_jute::proto::{ReplyHeader, WatcherEvent};
use zk_jute::{FrameDecoder, JBuffer, JString, JVec, Pushed, Record, xid};
use zk_proto::hooks::{AllLevels, NoDefaultWatcher, NoLevels};
use zk_proto::legacy::connect::{HostSpec as LegacyHost, NativeHost, parse_servers};
use zk_proto::{
    Action, AddAuthError, ClientId, CloseProgress, Compat, Config, ConnectStart, Connection,
    DriverMode, HostResolution, HostSpec, InputDefect, Interest, Millis, MultiOp, Op, Output,
    PathIn, ProbeOutcome, Request, ResolveError, Rng, Route, SaslAddr, SaslCallKind, SaslError,
    SaslStep, SecretBytes, SubmitError, Submitted, Tokens, TransportFailure, rc,
};

use crate::{Cursor, Enc, framed};

/// The first port of the fuzz servers. No socket opens on it.
pub const BASE_PORT: u16 = 23700;
/// The budget of one `poll_transmit` call.
const TRANSMIT_MAX: usize = 1024 * 1024;
/// The largest number of rounds of one loop. More rounds mean a busy loop.
const LOOP_LIMIT: usize = 100_000;
/// The largest number of commands of one input.
const COMMAND_LIMIT: usize = 512;
/// The largest number of received bytes that the sim keeps.
const RX_LIMIT: usize = 1024 * 1024;
/// The number of request ids that the sim remembers for replies.
const XID_MEMORY: usize = 64;

/// The token types of the sim: plain integers.
#[derive(Debug)]
pub struct Tk;

impl Tokens for Tk {
    type Completion = u32;
    type Watcher = u32;
    type Auth = u32;
}

/// A small random source with a fixed seed.
struct XorRng(u64);

impl XorRng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

impl Rng for XorRng {
    fn on_resolution(&mut self) {}

    fn random(&mut self) -> i64 {
        i64::try_from(self.next() >> 33).unwrap_or(0)
    }

    fn drand48(&mut self) -> f64 {
        // 53 random bits give a value in [0, 1).
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The profile of the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The single-threaded drop-in.
    LegacySt,
    /// The multi-threaded drop-in.
    LegacyMt,
    /// The native client.
    Native,
}

/// The choices that the input makes before the first command.
#[derive(Clone, Debug)]
pub struct Options {
    /// The profile.
    pub profile: Profile,
    /// The read-only flag of the config.
    pub allow_read_only: bool,
    /// SASL negotiation after the handshake.
    pub sasl: bool,
    /// A TLS transport.
    pub tls: bool,
    /// The sim moves bytes to the server only on a `TRANSMIT` command.
    pub manual_tx: bool,
    /// The sim keeps all log outputs.
    pub all_logs: bool,
    /// The requested session timeout.
    pub timeout_ms: i32,
    /// The first xid.
    pub xid_seed: i32,
    /// The chroot of the config.
    pub chroot: Option<Vec<u8>>,
    /// The limit of pending requests.
    pub max_pending: Option<usize>,
    /// The stored session id. Zero asks for a new session.
    pub session_id: i64,
    /// The number of server addresses.
    pub servers: u8,
    /// The seed of the random source.
    pub seed: u64,
}

impl Options {
    /// Reads the options from the head of the input.
    pub fn read(c: &mut Cursor<'_>) -> Self {
        let profile = match c.u8() % 3 {
            0 => Profile::LegacySt,
            1 => Profile::LegacyMt,
            _ => Profile::Native,
        };
        let flags = c.u8();
        let timeout_ms = i32::from(c.u16());
        let xid_seed = c.i32();
        let chroot = (flags & 0x40 != 0).then(|| c.lp().to_vec());
        let max_pending = (flags & 0x80 != 0).then(|| usize::from(c.u8()));
        let session_id = if flags & 0x20 != 0 { c.i64() } else { 0 };
        let servers = c.u8() % 3 + 1;
        Self {
            profile,
            allow_read_only: flags & 0x01 != 0,
            sasl: flags & 0x02 != 0,
            tls: flags & 0x04 != 0,
            manual_tx: flags & 0x08 != 0,
            all_logs: flags & 0x10 != 0,
            timeout_ms,
            xid_seed,
            chroot,
            max_pending,
            session_id,
            servers,
            seed: u64::from(c.u32()) | 1,
        }
    }

    /// Writes options that [`Options::read`] reads back.
    pub fn write(&self, e: &mut Enc) {
        e.u8(match self.profile {
            Profile::LegacySt => 0,
            Profile::LegacyMt => 1,
            Profile::Native => 2,
        });
        let mut flags = 0u8;
        for (on, bit) in [
            (self.allow_read_only, 0x01),
            (self.sasl, 0x02),
            (self.tls, 0x04),
            (self.manual_tx, 0x08),
            (self.all_logs, 0x10),
            (self.session_id != 0, 0x20),
            (self.chroot.is_some(), 0x40),
            (self.max_pending.is_some(), 0x80),
        ] {
            if on {
                flags |= bit;
            }
        }
        e.u8(flags);
        e.u16(u16::try_from(self.timeout_ms).unwrap_or(u16::MAX));
        e.i32(self.xid_seed);
        if let Some(c) = &self.chroot {
            e.lp(c);
        }
        if let Some(m) = self.max_pending {
            e.u8(u8::try_from(m).unwrap_or(u8::MAX));
        }
        if self.session_id != 0 {
            e.i64(self.session_id);
        }
        e.u8(self.servers.saturating_sub(1));
        e.u32(u32::try_from(self.seed & 0xffff_ffff).unwrap_or(1));
    }

    /// Returns plain options: a single-threaded drop-in with no extras.
    pub fn plain(profile: Profile) -> Self {
        Self {
            profile,
            allow_read_only: false,
            sasl: false,
            tls: false,
            manual_tx: false,
            all_logs: false,
            timeout_ms: 30_000,
            xid_seed: 1,
            chroot: None,
            max_pending: None,
            session_id: 0,
            servers: 1,
            seed: 1,
        }
    }

    fn native(&self) -> bool {
        self.profile == Profile::Native
    }
}

/// The commands of a fuzz program. The input selects one with a byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    /// Raw server bytes.
    Raw = 0,
    /// One server frame with a fuzz body.
    Frame,
    /// A reply to a request that the server saw.
    Reply,
    /// A frame with a special xid.
    Special,
    /// A connect response with fuzz fields.
    ConnectResp,
    /// A request.
    Submit,
    /// A multi request.
    Multi,
    /// A time step.
    Tick,
    /// A time step to the deadline of the last interest.
    TickInterest,
    /// A transmit of some bytes in manual mode.
    Transmit,
    /// A transport failure.
    Fail,
    /// A read through `body_room`.
    BodyRead,
    /// An `add_auth` call.
    AddAuth,
    /// A start of the close.
    Close,
    /// A forced close.
    ForcedClose,
    /// A new server list or a cycle to the next server.
    Servers,
    /// The result of the next connect.
    PlanConnect,
    /// The result of the next SASL call.
    PlanSasl,
    /// The result of the next resolution.
    PlanResolve,
    /// The result of the next read-write probe.
    PlanProbe,
    /// A watch event with a valid body.
    WatchEvent,
    /// A change of the read chunk size.
    Chunk,
}

/// The number of commands.
pub const CMD_COUNT: u8 = Cmd::Chunk as u8 + 1;

impl Cmd {
    fn from_byte(b: u8) -> Self {
        match b % CMD_COUNT {
            0 => Self::Raw,
            1 => Self::Frame,
            2 => Self::Reply,
            3 => Self::Special,
            4 => Self::ConnectResp,
            5 => Self::Submit,
            6 => Self::Multi,
            7 => Self::Tick,
            8 => Self::TickInterest,
            9 => Self::Transmit,
            10 => Self::Fail,
            11 => Self::BodyRead,
            12 => Self::AddAuth,
            13 => Self::Close,
            14 => Self::ForcedClose,
            15 => Self::Servers,
            16 => Self::PlanConnect,
            17 => Self::PlanSasl,
            18 => Self::PlanResolve,
            19 => Self::PlanProbe,
            20 => Self::WatchEvent,
            _ => Self::Chunk,
        }
    }
}

/// The planned result of a connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectPlan {
    Immediate,
    Deferred,
    Refuse,
    SocketFail,
    Hang,
}

/// The planned result of a SASL call.
#[derive(Debug)]
enum SaslPlan {
    Ok { token: Option<Vec<u8>>, done: bool },
    Err(i32),
    AddrFail,
}

/// The state of the transport as the driver sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    None,
    Connecting,
    Hanging,
    Open,
}

/// The fuzz driver and server.
pub struct Sim {
    conn: Option<Connection<Tk>>,
    opts: Options,
    now: Millis,
    link: Link,
    tx: Vec<u8>,
    rx: Vec<u8>,
    chunk: usize,
    interest: Option<Interest>,
    server: FrameDecoder,
    server_saw_connect: bool,
    xids: VecDeque<i32>,
    next_token: u32,
    completions: BTreeMap<u32, u32>,
    auths: BTreeMap<u32, u32>,
    connect_plans: VecDeque<ConnectPlan>,
    sasl_plans: VecDeque<SaslPlan>,
    resolve_plans: VecDeque<u8>,
    probe_plans: VecDeque<u8>,
}

impl Sim {
    /// Makes a sim with `opts`.
    pub fn new(opts: Options) -> Self {
        let native = opts.native();
        let mut cfg = Config::legacy(opts.timeout_ms);
        cfg.client_id = ClientId {
            session_id: opts.session_id,
            passwd: [7u8; 16],
        };
        cfg.allow_read_only = opts.allow_read_only;
        cfg.sasl = opts.sasl;
        cfg.tls = opts.tls;
        cfg.xid_seed = opts.xid_seed;
        cfg.max_pending = opts.max_pending;
        cfg.hosts = hosts(native, 0, opts.servers);
        cfg.host_text = JString::Bytes(host_text(0, opts.servers));
        cfg.chroot = opts.chroot.clone().map(JString::Bytes);
        if native {
            cfg.connect_timeout_ms = Some(5_000);
            cfg.reconnect_delay_ms = 100;
            cfg.reconnect_jitter_pct = 10;
            cfg.close_timeout_ms = 2_000;
        }
        let (compat, mode) = match opts.profile {
            Profile::LegacySt => (Compat::LEGACY_C, DriverMode::ST),
            Profile::LegacyMt => (Compat::LEGACY_C, DriverMode::MT),
            Profile::Native => (Compat::NATIVE, DriverMode::NATIVE),
        };
        let filter: Box<dyn zk_proto::LogFilter> = if opts.all_logs {
            Box::new(AllLevels)
        } else {
            Box::new(NoLevels)
        };
        let now = Millis(1_000);
        let conn = Connection::new(
            cfg,
            compat,
            mode,
            Box::new(XorRng(opts.seed)),
            filter,
            Box::new(NoDefaultWatcher),
            now,
        );
        Self {
            conn: Some(conn),
            opts,
            now,
            link: Link::None,
            tx: Vec::new(),
            rx: Vec::new(),
            chunk: usize::MAX,
            interest: None,
            server: FrameDecoder::new(None),
            server_saw_connect: false,
            xids: VecDeque::new(),
            next_token: 1,
            completions: BTreeMap::new(),
            auths: BTreeMap::new(),
            connect_plans: VecDeque::new(),
            sasl_plans: VecDeque::new(),
            resolve_plans: VecDeque::new(),
            probe_plans: VecDeque::new(),
        }
    }

    /// Reads the options and runs every command of the input.
    pub fn run(data: &[u8]) {
        let mut c = Cursor::new(data);
        let opts = Options::read(&mut c);
        let mut sim = Self::new(opts);
        sim.run_commands(&mut c);
        sim.finish();
    }

    /// Runs commands until the input ends.
    pub fn run_commands(&mut self, c: &mut Cursor<'_>) {
        self.settle();
        for _ in 0..COMMAND_LIMIT {
            if c.is_empty() {
                break;
            }
            let cmd = Cmd::from_byte(c.u8());
            self.command(cmd, c);
            self.settle();
        }
    }

    fn conn(&mut self) -> &mut Connection<Tk> {
        // The connection exists until `finish` takes it.
        match self.conn.as_mut() {
            Some(c) => c,
            None => panic!("the sim has no connection"),
        }
    }

    /// Gives the server bytes of one frame with `body`.
    pub fn push_frame(&mut self, body: &[u8]) {
        let f = framed(body);
        self.push_rx(&f);
    }

    /// Gives raw server bytes.
    pub fn push_rx(&mut self, bytes: &[u8]) {
        if self.rx.len() < RX_LIMIT {
            self.rx.extend_from_slice(bytes);
        }
    }

    /// Gives a reply frame to the request with `xid`.
    pub fn push_reply(&mut self, xid: i32, zxid: i64, err: i32, body: &[u8]) {
        let mut b = ReplyHeader { xid, zxid, err }.to_bytes();
        b.extend_from_slice(body);
        self.push_frame(&b);
    }

    /// Gives a valid connect response for a new session.
    pub fn push_connect_response(&mut self, timeout_ms: i32, session_id: i64, ro: bool) {
        self.push_frame(&connect_response(
            0,
            timeout_ms,
            session_id,
            16,
            &[9u8; 16],
            Some(ro),
        ));
    }

    /// Returns the xids that the server saw, oldest first.
    pub fn seen_xids(&self) -> impl Iterator<Item = i32> + '_ {
        self.xids.iter().copied()
    }

    /// Submits `op` and records the token.
    pub fn submit(&mut self, op: Op<u32>, route: Route, defect: InputDefect) {
        let token = self.issue();
        let now = self.now;
        let r = self.conn().submit(
            Request {
                op,
                token,
                route,
                defect,
            },
            now,
        );
        match r {
            Ok(Submitted::Queued { .. }) => {}
            Ok(Submitted::Local(t)) => self.complete(t),
            Err(SubmitError { token: t, .. }) => self.complete(t),
        }
    }

    fn issue(&mut self) -> u32 {
        let t = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.completions.insert(t, 0);
        t
    }

    fn complete(&mut self, t: u32) {
        match self.completions.get_mut(&t) {
            Some(n) => *n += 1,
            None => panic!("completion token {t} was never issued"),
        }
    }

    fn auth_done(&mut self, t: u32) {
        match self.auths.get_mut(&t) {
            Some(n) => *n += 1,
            None => panic!("auth token {t} was never issued"),
        }
    }

    /// Runs one command.
    pub fn command(&mut self, cmd: Cmd, c: &mut Cursor<'_>) {
        let native = self.opts.native();
        let now = self.now;
        match cmd {
            Cmd::Raw => {
                let n = usize::from(c.u16() % 2048);
                let b = c.bytes(n);
                self.push_rx(b);
            }
            Cmd::Frame => {
                let b = c.lp();
                self.push_frame(b);
            }
            Cmd::Reply => {
                let sel = c.u8();
                let xid = if sel == 255 || self.xids.is_empty() {
                    c.i32()
                } else {
                    let i = usize::from(sel) % self.xids.len();
                    self.xids.get(i).copied().unwrap_or(0)
                };
                let zxid = c.i64();
                let err = reply_err(c.u8());
                let body = c.lp();
                self.push_reply(xid, zxid, err, body);
            }
            Cmd::Special => {
                let xid = [xid::WATCHER_EVENT, xid::PING, xid::AUTH, xid::SET_WATCHES]
                    .get(usize::from(c.u8() % 4))
                    .copied()
                    .unwrap_or(xid::PING);
                let zxid = c.i64();
                let err = reply_err(c.u8());
                let body = c.lp();
                self.push_reply(xid, zxid, err, body);
            }
            Cmd::ConnectResp => {
                let proto = c.i32();
                let timeout = i32::from(c.u16());
                let session = c.i64();
                let plen_sel = c.u8();
                let plen = if plen_sel >= 128 {
                    16
                } else {
                    i32::from(plen_sel) - 8
                };
                let passwd = c.array::<16>();
                let ro = match c.u8() % 3 {
                    0 => None,
                    1 => Some(false),
                    _ => Some(true),
                };
                let body = connect_response(proto, timeout, session, plen, &passwd, ro);
                self.push_frame(&body);
            }
            Cmd::Submit => {
                let op = read_op(c, native);
                let route = if c.bool() && self.opts.profile == Profile::LegacyMt {
                    Route::Direct
                } else {
                    Route::Queued
                };
                let defect = read_defect(c);
                self.submit(op, route, defect);
            }
            Cmd::Multi => {
                let n = c.u8() % 8;
                let ops = (0..n).map(|_| read_multi_op(c, native)).collect();
                let op = if c.bool() {
                    Op::MultiRead { ops }
                } else {
                    Op::Multi { ops }
                };
                self.submit(op, Route::Queued, InputDefect::default());
            }
            Cmd::Tick => {
                let ms = u64::from(c.u16());
                self.now = self.now.saturating_add_ms(ms);
            }
            Cmd::TickInterest => {
                let ms = self
                    .interest
                    .map_or(1, |i| u64::from(i.timeout_ms).clamp(1, 600_000));
                self.now = self.now.saturating_add_ms(ms);
            }
            Cmd::Transmit => {
                let n = usize::from(c.u16());
                self.transmit(n);
            }
            Cmd::Fail => {
                let f = match c.u8() % 6 {
                    0 => TransportFailure::Eof,
                    1 => TransportFailure::Io { errno: 104 },
                    2 => TransportFailure::TlsHandshake { errno: 0 },
                    3 => TransportFailure::Poll { errno: 4 },
                    4 => TransportFailure::TcpRefused { errno: 61 },
                    _ => TransportFailure::SocketCreate { errno: 24 },
                };
                if self.link != Link::None {
                    let _ = self.conn().handle_transport_failed(f, now);
                    self.drop_link();
                }
            }
            Cmd::BodyRead => {
                let max = usize::from(c.u16()).max(1);
                self.body_read(max);
            }
            Cmd::AddAuth => {
                let scheme = c.lp().to_vec();
                let cred = c.lp().to_vec();
                let done = c.bool().then(|| self.issue_auth());
                let r =
                    self.conn()
                        .add_auth(JString::Bytes(scheme), SecretBytes::new(cred), done, now);
                if let Err(AddAuthError { done: Some(t), .. }) = r {
                    self.auth_done(t);
                }
            }
            Cmd::Close => {
                self.conn().begin_close(now);
                self.pump();
                let _ = self.conn().queue_close_op();
            }
            Cmd::ForcedClose => {
                self.conn().handle_forced_close(now);
            }
            Cmd::Servers => {
                if c.bool() {
                    self.conn().cycle_next_server();
                } else {
                    let first = c.u8() % 4;
                    let n = c.u8() % 4;
                    let list = if c.bool() && !native {
                        parse_servers(c.lp())
                            .unwrap_or_default()
                            .into_iter()
                            .map(HostSpec::Legacy)
                            .collect()
                    } else {
                        hosts(native, first, n)
                    };
                    let _ = self.conn().set_servers(list, now);
                }
            }
            Cmd::PlanConnect => {
                let p = match c.u8() % 5 {
                    0 => ConnectPlan::Immediate,
                    1 => ConnectPlan::Deferred,
                    2 => ConnectPlan::Refuse,
                    3 => ConnectPlan::SocketFail,
                    _ => ConnectPlan::Hang,
                };
                self.connect_plans.push_back(p);
            }
            Cmd::PlanSasl => {
                let p = match c.u8() % 4 {
                    0 => SaslPlan::Err(-1 - i32::from(c.u8() % 8)),
                    1 => SaslPlan::AddrFail,
                    _ => {
                        let token = c.bool().then(|| c.lp().to_vec());
                        SaslPlan::Ok {
                            token,
                            done: c.bool(),
                        }
                    }
                };
                self.sasl_plans.push_back(p);
            }
            Cmd::PlanResolve => {
                let b = c.u8();
                self.resolve_plans.push_back(b);
            }
            Cmd::PlanProbe => {
                let b = c.u8();
                self.probe_plans.push_back(b);
            }
            Cmd::WatchEvent => {
                let ev = WatcherEvent {
                    r#type: i32::from(c.u8() % 9) - 2,
                    state: i32::from(c.u8() % 8) - 2,
                    path: read_jstring(c),
                };
                let zxid = c.i64();
                self.push_reply(xid::WATCHER_EVENT, zxid, 0, &ev.to_bytes());
            }
            Cmd::Chunk => {
                let n = usize::from(c.u8());
                self.chunk = if n == 0 { usize::MAX } else { n };
            }
        }
    }

    fn issue_auth(&mut self) -> u32 {
        let t = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.auths.insert(t, 0);
        t
    }

    /// Pops every output, resumes every barrier and runs every action.
    pub fn pump(&mut self) {
        let now = self.now;
        for _ in 0..LOOP_LIMIT {
            if let Some(o) = self.conn().poll_output() {
                let stopped = if o.is_barrier() {
                    self.conn().take_stopped()
                } else {
                    None
                };
                self.observe(o);
                if let Some(s) = stopped {
                    self.conn().resume(s, now);
                }
                continue;
            }
            if let Some(s) = self.conn().take_stopped() {
                self.conn().resume(s, now);
                continue;
            }
            if let Some(a) = self.conn().poll_action(now) {
                self.execute(a);
                continue;
            }
            return;
        }
        panic!("the output and action loop did not end");
    }

    fn observe(&mut self, o: Output<Tk>) {
        match o {
            Output::Completion { token, .. } => self.complete(token),
            Output::Auth { tokens, .. } => {
                for t in tokens {
                    self.auth_done(t);
                }
            }
            Output::Watch { .. }
            | Output::Session { .. }
            | Output::AuthLockpoint
            | Output::ClientId(_)
            | Output::WatchTerminated { .. }
            | Output::Log(_)
            | Output::DrainPoint => {}
        }
    }

    fn execute(&mut self, a: Action) {
        let now = self.now;
        match a {
            Action::Resolve {
                generation, hosts, ..
            } => {
                let plan = self.resolve_plans.pop_front().unwrap_or(0);
                for (i, h) in hosts.iter().enumerate() {
                    let result = if plan % 4 == 1 && i == 0 {
                        Err(ResolveError {
                            gai_rc: -2,
                            errno: 0,
                        })
                    } else if plan % 4 == 2 {
                        Ok(Vec::new())
                    } else {
                        let port = match h {
                            HostSpec::Legacy(l) => u16::try_from(l.port).unwrap_or(BASE_PORT),
                            HostSpec::Native(n) => n.port,
                        };
                        let mut v = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)];
                        if plan % 4 == 3 {
                            v.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
                        }
                        Ok(v)
                    };
                    let r = HostResolution {
                        host: i,
                        result,
                        skipped_families: Vec::new(),
                    };
                    self.conn().handle_host_resolved(generation, r, now);
                }
                let _ = self
                    .conn()
                    .handle_resolved(generation, plan & 0x10 != 0, now);
            }
            Action::Connect { .. } => self.connect(),
            Action::CloseTransport => self.drop_link(),
            Action::ProbeRw { endpoint, .. } => {
                let outcome = match self.probe_plans.pop_front().unwrap_or(2) % 3 {
                    0 => ProbeOutcome::ReadWrite,
                    1 => ProbeOutcome::NotReadWrite,
                    _ => ProbeOutcome::Failed(None),
                };
                self.conn().handle_rw_probe(endpoint, outcome, now);
            }
            Action::Sasl(call) => {
                let generation = call.generation;
                match call.kind {
                    SaslCallKind::Dispose => {}
                    SaslCallKind::Start => {
                        let r = match self.sasl_plans.pop_front() {
                            Some(SaslPlan::AddrFail) => {
                                let _ = self.conn().handle_sasl_addr_failed(
                                    generation,
                                    SaslAddr::Peer,
                                    now,
                                );
                                return;
                            }
                            Some(SaslPlan::Err(rc)) => Err(sasl_error(rc)),
                            Some(SaslPlan::Ok { token, done }) => Ok((
                                "DIGEST-MD5".to_owned(),
                                SaslStep {
                                    token: token.map(SecretBytes::new),
                                    done,
                                },
                            )),
                            None => Ok((
                                "DIGEST-MD5".to_owned(),
                                SaslStep {
                                    token: None,
                                    done: false,
                                },
                            )),
                        };
                        let _ = self.conn().handle_sasl_started(generation, r, now);
                    }
                    SaslCallKind::Step(_) => {
                        let r = match self.sasl_plans.pop_front() {
                            Some(SaslPlan::Err(rc)) => Err(sasl_error(rc)),
                            Some(SaslPlan::Ok { token, done }) => Ok(SaslStep {
                                token: token.map(SecretBytes::new),
                                done,
                            }),
                            Some(SaslPlan::AddrFail) | None => Ok(SaslStep {
                                token: None,
                                done: true,
                            }),
                        };
                        let _ = self.conn().handle_sasl_stepped(generation, r, now);
                    }
                }
            }
        }
    }

    fn connect(&mut self) {
        let now = self.now;
        self.tx.clear();
        self.rx.clear();
        self.server.reset();
        self.server_saw_connect = false;
        let plan = self
            .connect_plans
            .pop_front()
            .unwrap_or(ConnectPlan::Immediate);
        match plan {
            ConnectPlan::Immediate => {
                self.conn()
                    .handle_connect_started(ConnectStart::Immediate, now);
                self.link = Link::Open;
                self.conn().handle_tcp_connected(now);
                self.conn().handle_transport_ready(now);
            }
            ConnectPlan::Deferred => {
                self.conn()
                    .handle_connect_started(ConnectStart::InProgress, now);
                self.link = Link::Connecting;
            }
            ConnectPlan::Refuse => {
                self.conn()
                    .handle_connect_started(ConnectStart::InProgress, now);
                self.link = Link::Connecting;
                let _ = self
                    .conn()
                    .handle_transport_failed(TransportFailure::TcpRefused { errno: 61 }, now);
                self.drop_link();
            }
            ConnectPlan::SocketFail => {
                self.conn()
                    .handle_connect_started(ConnectStart::InProgress, now);
                self.link = Link::Connecting;
                let _ = self
                    .conn()
                    .handle_transport_failed(TransportFailure::SocketCreate { errno: 24 }, now);
                self.drop_link();
            }
            ConnectPlan::Hang => {
                self.conn()
                    .handle_connect_started(ConnectStart::InProgress, now);
                self.link = Link::Hanging;
            }
        }
    }

    fn drop_link(&mut self) {
        self.link = Link::None;
        self.tx.clear();
        self.rx.clear();
        self.server.reset();
        self.server_saw_connect = false;
    }

    fn interest_cycle(&mut self) {
        let now = self.now;
        if self.conn().begin_interest(now).is_err() {
            self.interest = None;
            return;
        }
        for _ in 0..LOOP_LIMIT {
            match self.conn().poll_action(now) {
                Some(a) => self.execute(a),
                None => {
                    let out = self.conn().finish_interest(now);
                    self.interest = out.outputs;
                    return;
                }
            }
        }
        panic!("the interest cycle did not end");
    }

    /// Runs the driver until it has no more work at the current time.
    pub fn settle(&mut self) {
        let now = self.now;
        let _ = self.conn().run_pending_teardown(now);
        self.pump();
        self.interest_cycle();
        self.pump();
        if self.link == Link::Connecting {
            self.link = Link::Open;
            self.conn().handle_tcp_connected(now);
            self.conn().handle_transport_ready(now);
            self.pump();
        }
        let want_write = self.interest.is_some_and(|i| i.write);
        if !self.opts.manual_tx && want_write {
            self.transmit(usize::MAX);
        }
        if self.interest.is_some_and(|i| i.read) {
            self.read_loop();
        }
        self.pump();
    }

    /// Moves up to `n` bytes from the core to the server.
    fn transmit(&mut self, n: usize) {
        let now = self.now;
        let mut left = n;
        for _ in 0..LOOP_LIMIT {
            if self.link != Link::Open || left == 0 {
                return;
            }
            if self.tx.is_empty() {
                let mut tx = std::mem::take(&mut self.tx);
                let got = self.conn().poll_transmit(&mut tx, TRANSMIT_MAX);
                self.tx = tx;
                if got == 0 {
                    return;
                }
            }
            let k = left.min(self.tx.len());
            let sent: Vec<u8> = self.tx.drain(..k).collect();
            self.server_read(&sent);
            self.conn().handle_transmitted(k, now);
            left = left.saturating_sub(k);
            self.pump();
        }
        panic!("the transmit loop did not end");
    }

    /// Splits the bytes that the server got into frames, and keeps the
    /// xid of each request.
    fn server_read(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let (used, p) = self.server.push(bytes);
            bytes = bytes.get(used..).unwrap_or_default();
            match p {
                Pushed::NeedMore => {
                    if used == 0 {
                        return;
                    }
                }
                Pushed::Frame(f) => {
                    if self.server_saw_connect {
                        if let Some(x) = f.get(..4) {
                            let x = i32::from_be_bytes([x[0], x[1], x[2], x[3]]);
                            if self.xids.len() == XID_MEMORY {
                                self.xids.pop_front();
                            }
                            self.xids.push_back(x);
                        }
                    } else {
                        // The first frame of each transport is the connect
                        // request, which has no xid.
                        self.server_saw_connect = true;
                    }
                }
                Pushed::Error(_) => {
                    self.server.reset();
                    return;
                }
            }
        }
    }

    fn read_loop(&mut self) {
        let now = self.now;
        let st = self.opts.profile == Profile::LegacySt;
        for _ in 0..LOOP_LIMIT {
            if self.link != Link::Open || self.rx.is_empty() {
                return;
            }
            let mut n = self.rx.len().min(self.chunk);
            if st {
                let h = self.conn().read_hint();
                if h == 0 {
                    return;
                }
                n = n.min(h);
            }
            let bytes: Vec<u8> = self.rx.get(..n).unwrap_or_default().to_vec();
            let out = self.conn().handle_read(&bytes, now);
            assert!(out.consumed <= n, "handle_read used more bytes than it got");
            if self.link == Link::Open {
                let used = out.consumed.min(self.rx.len());
                self.rx.drain(..used);
            }
            self.pump();
            if out.consumed == 0 {
                return;
            }
        }
        panic!("the read loop did not end");
    }

    fn body_read(&mut self, max: usize) {
        let now = self.now;
        if self.link != Link::Open {
            return;
        }
        let mut rx = std::mem::take(&mut self.rx);
        let room = self.conn().body_room(max);
        assert!(room.len() <= max, "body_room gave more room than asked");
        let n = room.len().min(rx.len());
        if let (Some(dst), Some(src)) = (room.get_mut(..n), rx.get(..n)) {
            dst.copy_from_slice(src);
        }
        if n > 0 {
            rx.drain(..n);
            let _ = self.conn().handle_body_read(n, now);
        }
        if self.link == Link::Open {
            self.rx = rx;
        }
        self.pump();
    }

    /// Closes the connection, destroys it and checks the token counts.
    pub fn finish(mut self) {
        let now = self.now;
        self.conn().begin_close(now);
        self.pump();
        let queued = self.conn().queue_close_op();
        self.pump();
        let drain = self.opts.native();
        if drain || queued {
            for _ in 0..64 {
                self.settle();
                self.transmit(usize::MAX);
                let t = self.now;
                if self.conn().close_step(t) == CloseProgress::Complete {
                    break;
                }
                if !drain {
                    break;
                }
                self.now = self.now.saturating_add_ms(250);
            }
        }
        let now = self.now;
        self.conn().destroy(now);
        self.pump();
        let Some(conn) = self.conn.take() else {
            return;
        };
        let left = conn.into_leftovers();
        for t in left.completions {
            self.complete(t);
        }
        for t in left.auth {
            self.auth_done(t);
        }
        for o in left.outputs {
            self.observe(o);
        }
        for (t, n) in &self.completions {
            assert_eq!(*n, 1, "completion token {t} left the core {n} times");
        }
        for (t, n) in &self.auths {
            assert_eq!(*n, 1, "auth token {t} left the core {n} times");
        }
    }
}

/// Makes `n` host specs from server `first` on.
fn hosts(native: bool, first: u8, n: u8) -> Vec<HostSpec> {
    (first..first.saturating_add(n))
        .map(|i| {
            let port = BASE_PORT.saturating_add(u16::from(i));
            if native {
                HostSpec::Native(NativeHost {
                    host: "127.0.0.1".to_owned(),
                    port,
                })
            } else {
                HostSpec::Legacy(LegacyHost {
                    host: b"127.0.0.1".to_vec(),
                    service: port.to_string().into_bytes(),
                    port: i32::from(port),
                })
            }
        })
        .collect()
}

/// Makes the connect string of `n` servers from server `first` on.
fn host_text(first: u8, n: u8) -> Vec<u8> {
    (first..first.saturating_add(n))
        .map(|i| format!("127.0.0.1:{}", BASE_PORT.saturating_add(u16::from(i))))
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes()
}

/// Encodes a connect response. `ro` of `None` gives the old 36-byte form.
pub fn connect_response(
    proto: i32,
    timeout_ms: i32,
    session_id: i64,
    passwd_len: i32,
    passwd: &[u8],
    ro: Option<bool>,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(37);
    b.extend_from_slice(&proto.to_be_bytes());
    b.extend_from_slice(&timeout_ms.to_be_bytes());
    b.extend_from_slice(&session_id.to_be_bytes());
    b.extend_from_slice(&passwd_len.to_be_bytes());
    b.extend_from_slice(passwd);
    if let Some(ro) = ro {
        b.push(u8::from(ro));
    }
    b
}

/// Maps a byte to a reply error code. Most bytes give success.
fn reply_err(b: u8) -> i32 {
    match b % 8 {
        0..=3 => rc::ZOK,
        4 => rc::ZNONODE,
        5 => rc::ZNODEEXISTS,
        6 => i32::from(b) - 256,
        _ => rc::ZRUNTIMEINCONSISTENCY,
    }
}

fn sasl_error(rc: i32) -> SaslError {
    SaslError {
        rc,
        errstring: b"fuzz".to_vec(),
        errdetail: Vec::new(),
    }
}

/// Reads a path. Most choices give a valid path.
pub fn read_path(c: &mut Cursor<'_>, native: bool) -> PathIn {
    let bytes: Option<Vec<u8>> = match c.u8() % 8 {
        0 => Some(b"/".to_vec()),
        1 => Some(b"/a".to_vec()),
        2 => Some(b"/a/b".to_vec()),
        3 => Some(b"/zookeeper/config".to_vec()),
        4 => None,
        _ => Some(c.lp().to_vec()),
    };
    if native {
        PathIn::Native(bytes.map_or(JString::Null, JString::Bytes))
    } else {
        PathIn::Legacy(bytes)
    }
}

fn read_jstring(c: &mut Cursor<'_>) -> JString {
    if c.u8().is_multiple_of(8) {
        JString::Null
    } else {
        JString::Bytes(c.lp().to_vec())
    }
}

fn read_jbuffer(c: &mut Cursor<'_>) -> JBuffer {
    if c.u8().is_multiple_of(8) {
        JBuffer::Null
    } else {
        JBuffer::Bytes(c.lp().to_vec())
    }
}

fn read_acl(c: &mut Cursor<'_>) -> JVec<ACL> {
    match c.u8() % 4 {
        0 => JVec::Null,
        1 => JVec::Items(Vec::new()),
        _ => JVec::Items(vec![ACL {
            perms: i32::from(c.u8() & 0x1f),
            id: Id {
                scheme: JString::Bytes(b"world".to_vec()),
                id: JString::Bytes(b"anyone".to_vec()),
            },
        }]),
    }
}

fn read_defect(c: &mut Cursor<'_>) -> InputDefect {
    let b = c.u8();
    // Most requests have no defect.
    if b < 224 {
        return InputDefect::default();
    }
    InputDefect {
        bad_value_buffer: b & 1 != 0,
        bad_acl: b & 2 != 0,
        marshal_oom: b & 4 != 0,
    }
}

/// Reads one request.
pub fn read_op(c: &mut Cursor<'_>, native: bool) -> Op<u32> {
    let watch = |c: &mut Cursor<'_>| c.bool().then(|| u32::from(c.u8()));
    match c.u8() % 20 {
        0 => Op::Create {
            path: read_path(c, native),
            data: read_jbuffer(c),
            acl: read_acl(c),
            mode: i32::from(c.u8() % 8),
            ttl: i64::from(c.i32()),
            create2: c.bool(),
        },
        1 => Op::Delete {
            path: read_path(c, native),
            version: c.i32(),
        },
        2 => Op::Exists {
            path: read_path(c, native),
            watch: watch(c),
        },
        3 => Op::GetData {
            path: read_path(c, native),
            watch: watch(c),
        },
        4 => Op::GetConfig { watch: watch(c) },
        5 => Op::SetData {
            path: read_path(c, native),
            data: read_jbuffer(c),
            version: c.i32(),
        },
        6 => Op::GetAcl {
            path: read_path(c, native),
        },
        7 => Op::SetAcl {
            path: read_path(c, native),
            acl: read_acl(c),
            version: c.i32(),
        },
        8 => Op::GetChildren {
            path: read_path(c, native),
            watch: watch(c),
            with_stat: c.bool(),
        },
        9 => Op::Sync {
            path: read_path(c, native),
        },
        10 => Op::Reconfig {
            joining: read_jstring(c),
            leaving: read_jstring(c),
            members: read_jstring(c),
            version: c.i64(),
        },
        11 => Op::RemoveWatches {
            path: read_path(c, native),
            wtype: i32::from(c.u8() % 4),
            watcher: watch(c),
            local: c.bool(),
            all: c.bool(),
        },
        12 => Op::AddWatch {
            path: read_path(c, native),
            mode: i32::from(c.u8() % 3),
            watch: u32::from(c.u8()),
        },
        13 => Op::GetEphemerals {
            prefix: read_path(c, native),
        },
        14 => Op::GetAllChildrenNumber {
            path: read_path(c, native),
        },
        15 => Op::WhoAmI,
        16 => Op::SetAclStat {
            path: read_path(c, native),
            acl: read_acl(c),
            version: c.i32(),
        },
        _ => Op::GetData {
            path: read_path(c, native),
            watch: None,
        },
    }
}

/// Reads one operation of a multi request.
pub fn read_multi_op(c: &mut Cursor<'_>, native: bool) -> MultiOp {
    match c.u8() % 8 {
        0 => MultiOp::Create {
            op_type: [1, 15, 19, 21]
                .get(usize::from(c.u8() % 4))
                .copied()
                .unwrap_or(1),
            path: read_path(c, native),
            data: read_jbuffer(c),
            acl: read_acl(c),
            mode: i32::from(c.u8() % 8),
            ttl: i64::from(c.i32()),
            defect: InputDefect::default(),
        },
        1 => MultiOp::Delete {
            path: read_path(c, native),
            version: c.i32(),
            defect: InputDefect::default(),
        },
        2 => MultiOp::SetData {
            path: read_path(c, native),
            data: read_jbuffer(c),
            version: c.i32(),
            defect: InputDefect::default(),
        },
        3 => MultiOp::Check {
            path: read_path(c, native),
            version: c.i32(),
            defect: InputDefect::default(),
        },
        4 => MultiOp::GetData {
            path: read_path(c, native),
        },
        5 => MultiOp::GetChildren {
            path: read_path(c, native),
        },
        6 => MultiOp::Other {
            op_type: i32::from(c.u8()) - 8,
        },
        _ => MultiOp::Delete {
            path: read_path(c, native),
            version: -1,
            defect: InputDefect::default(),
        },
    }
}

/// Writes a program that connects, takes a session and runs `body`.
///
/// The seed generator uses it to give each target a session in the
/// connected state.
pub fn connected_prefix(opts: &Options, e: &mut Enc) {
    opts.write(e);
    e.u8(Cmd::ConnectResp as u8)
        .i32(0)
        .u16(u16::try_from(opts.timeout_ms).unwrap_or(30_000))
        .i64(0x1234)
        .u8(200)
        .raw(&[9u8; 16])
        .u8(1);
}
