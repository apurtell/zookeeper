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

//! The scripted in-memory server model.
//!
//! [`ServerSim`] is an independent model of a ZooKeeper ensemble. It has
//! no sockets. Each listener is an address, and each accepted connection
//! is a link with a byte pipe in both directions. The model decodes
//! frames with `zk_jute` and answers them with the Java server rules for
//! sessions, znodes, watches, multi and auth. [`Rule`] overrides change
//! the answer of chosen frames.
//!
//! All the listeners share one tree and one session table, as the members
//! of one healthy ensemble do.

pub mod codec;
pub mod rules;
pub mod tree;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;

use zk_jute::data::{ACL, ClientInfo, Id};
use zk_jute::handshake::PASSWD_LEN;
use zk_jute::proto::{
    AddWatchRequest, AuthPacket, CheckVersionRequest, ConnectRequest, ConnectResponse,
    Create2Response, CreateRequest, CreateResponse, CreateTTLRequest, DeleteRequest, ErrorResponse,
    ExistsRequest, ExistsResponse, GetACLRequest, GetACLResponse, GetAllChildrenNumberRequest,
    GetAllChildrenNumberResponse, GetChildren2Request, GetChildren2Response, GetChildrenRequest,
    GetChildrenResponse, GetDataRequest, GetDataResponse, GetEphemeralsRequest,
    GetEphemeralsResponse, GetSASLRequest, MultiHeader, RemoveWatchesRequest, SetACLRequest,
    SetACLResponse, SetDataRequest, SetDataResponse, SetSASLResponse, SetWatches, SetWatches2,
    SyncRequest, SyncResponse, WatcherEvent, WhoAmIResponse,
};
use zk_jute::{
    DecodeError, FrameDecoder, JBuffer, JString, JVec, Pushed, Reader, Record, opcode, rc, xid,
};
use zk_proto::Millis;

use crate::rng::SplitMix;

pub use rules::{HandshakeStyle, MatchKind, Rule, RuleAction};
pub use tree::{CreateArgs, DataTree, Node, Trigger};

use rules::{FrameFacts, RuleState};
use tree::{EVENT_CHILDREN_CHANGED, EVENT_CREATED, EVENT_DATA_CHANGED, EVENT_DELETED, is_below};

/// The Java `KeeperState.SyncConnected` value.
pub const STATE_SYNC_CONNECTED: i32 = 3;
/// The Java `WatcherType.Children` value.
pub const WATCHER_CHILDREN: i32 = 1;
/// The Java `WatcherType.Data` value.
pub const WATCHER_DATA: i32 = 2;
/// The Java `WatcherType.Any` value.
pub const WATCHER_ANY: i32 = 3;
/// The Java `WatcherType.Persistent` value.
pub const WATCHER_PERSISTENT: i32 = 4;
/// The Java `WatcherType.PersistentRecursive` value.
pub const WATCHER_PERSISTENT_RECURSIVE: i32 = 5;
/// The `AddWatchMode.PERSISTENT` value.
pub const ADD_WATCH_PERSISTENT: i32 = 0;
/// The `AddWatchMode.PERSISTENT_RECURSIVE` value.
pub const ADD_WATCH_PERSISTENT_RECURSIVE: i32 = 1;

/// The name of one link. Links are never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkId(pub u64);

/// The state of a link as the client sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkStatus {
    /// The link is open. Some bytes can still be on the way.
    Open,
    /// The server closed the link, and the client read every byte.
    Eof,
    /// The server reset the link. Unread bytes are lost.
    Reset,
    /// The client closed the link, or the link does not exist.
    Gone,
}

/// One scripted answer to a SASL request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaslReply {
    /// The challenge token, or `None` for a null token.
    pub token: Option<Vec<u8>>,
    /// The reply error code. A non-zero code closes the link after the
    /// reply.
    pub err: i32,
}

/// The options of the server model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerOptions {
    /// The smallest negotiated session timeout (Java `2 * tickTime`).
    pub min_session_timeout: i32,
    /// The largest negotiated session timeout (Java `20 * tickTime`).
    pub max_session_timeout: i32,
    /// When true, a session with no traffic for its timeout expires.
    pub expire_sessions: bool,
    /// When true, each `ConnectResponse` has no `read_only` byte.
    pub short_handshake: bool,
    /// The largest frame that the server accepts. A larger frame closes
    /// the link.
    pub max_frame_len: Option<u32>,
    /// The auth schemes that the server rejects. A rejected auth packet
    /// gets `ZAUTHFAILED` and the link closes.
    pub reject_auth_schemes: BTreeSet<Vec<u8>>,
    /// The answers to SASL requests, in order. When the list ends, each
    /// SASL request gets an empty token.
    pub sasl_replies: Vec<SaslReply>,
    /// The zxid before the first transaction.
    pub initial_zxid: i64,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            min_session_timeout: 4_000,
            max_session_timeout: 40_000,
            expire_sessions: true,
            short_handshake: false,
            max_frame_len: None,
            reject_auth_schemes: BTreeSet::new(),
            sasl_replies: Vec::new(),
            initial_zxid: 0,
        }
    }
}

/// One listener of the ensemble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listener {
    /// The address of the listener.
    pub addr: SocketAddr,
    /// True for a read-only server.
    pub read_only: bool,
    /// False when the listener refuses connects.
    pub accepting: bool,
}

/// What the server received in one inbound frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundKind {
    /// A `ConnectRequest`.
    Connect(ConnectRequest),
    /// A request after the handshake.
    Request {
        /// The xid of the request.
        xid: i32,
        /// The type of the request.
        op: i32,
        /// The first path field of the request, when it has one.
        path: Option<Vec<u8>>,
    },
    /// A frame that did not decode.
    Undecodable,
}

/// One inbound frame of the transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    /// The link of the frame.
    pub link: LinkId,
    /// The arrival time.
    pub at: Millis,
    /// The index of the frame on its link. The `ConnectRequest` has
    /// index 0.
    pub index: u64,
    /// The content.
    pub kind: InboundKind,
    /// The rule action that applied, if any.
    pub rule: Option<RuleAction>,
}

/// What the server sent in one outbound item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundKind {
    /// A `ConnectResponse`.
    Handshake {
        /// The session id.
        session_id: i64,
        /// The negotiated timeout.
        timeout: i32,
        /// The `read_only` flag.
        read_only: bool,
    },
    /// A reply.
    Reply {
        /// The xid of the reply.
        xid: i32,
        /// The zxid of the reply.
        zxid: i64,
        /// The error code of the reply.
        err: i32,
    },
    /// A watch event.
    Event {
        /// The Java event type.
        event_type: i32,
        /// The server path.
        path: Vec<u8>,
        /// The zxid of the event.
        zxid: i64,
    },
    /// Raw bytes with no frame structure.
    Raw(usize),
}

/// One outbound item of the transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound {
    /// The link of the item.
    pub link: LinkId,
    /// The time when the server queued the item.
    pub at: Millis,
    /// The time when the client can read the item.
    pub deliver_at: Millis,
    /// The content.
    pub kind: OutboundKind,
}

#[derive(Clone, Debug)]
struct Session {
    passwd: [u8; PASSWD_LEN],
    timeout: i32,
    last_touch: Millis,
}

#[derive(Clone, Debug, Default)]
struct LinkWatches {
    data: BTreeSet<Vec<u8>>,
    child: BTreeSet<Vec<u8>>,
    persistent: BTreeSet<Vec<u8>>,
    recursive: BTreeSet<Vec<u8>>,
}

impl LinkWatches {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn wants(&mut self, t: &Trigger) -> bool {
        let p = t.path.as_slice();
        let mut fire = match t.event_type {
            EVENT_CREATED | EVENT_DATA_CHANGED => self.data.remove(p),
            EVENT_DELETED => {
                let d = self.data.remove(p);
                let c = self.child.remove(p);
                d || c
            }
            EVENT_CHILDREN_CHANGED => self.child.remove(p),
            _ => false,
        };
        if self.persistent.contains(p) {
            fire = true;
        }
        if t.event_type != EVENT_CHILDREN_CHANGED && self.recursive.iter().any(|r| is_below(p, r)) {
            fire = true;
        }
        fire
    }
}

#[derive(Debug)]
struct Item {
    deliver_at: Millis,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct Link {
    ordinal: u64,
    addr: SocketAddr,
    read_only: bool,
    decoder: FrameDecoder,
    frames: u64,
    handshaken: bool,
    session: Option<i64>,
    out: VecDeque<Item>,
    last_at: Millis,
    closing: bool,
    reset: bool,
    gone: bool,
    watches: LinkWatches,
    auth: Vec<Id>,
    sasl_round: usize,
}

impl Link {
    const fn open(&self) -> bool {
        !self.closing && !self.reset && !self.gone
    }
}

/// The result of one request handler.
enum Answer {
    /// Send a header with this zxid, then this body.
    Body(i64, Vec<u8>),
    /// Send only a header with this error code.
    Err(i32, i64),
    /// Send nothing.
    None,
}

/// One decoded multi op.
enum MOp {
    Create(i32, CreateRequest, i64),
    Delete(DeleteRequest),
    SetData(SetDataRequest),
    Check(CheckVersionRequest),
    GetData(GetDataRequest),
    GetChildren(GetChildrenRequest),
}

/// The in-memory server model.
#[derive(Debug)]
pub struct ServerSim {
    opts: ServerOptions,
    listeners: Vec<Listener>,
    tree: DataTree,
    sessions: BTreeMap<i64, Session>,
    links: BTreeMap<LinkId, Link>,
    next_link: u64,
    rng: SplitMix,
    zxid: i64,
    rules: Vec<RuleState>,
    inbound: Vec<Inbound>,
    outbound: Vec<Outbound>,
    delay: u64,
    now: Millis,
}

fn jstr_bytes(s: &JString) -> Vec<u8> {
    s.as_bytes().map(<[u8]>::to_vec).unwrap_or_default()
}

fn jbuf_bytes(b: &JBuffer) -> &[u8] {
    b.as_bytes().unwrap_or_default()
}

fn acl_items(a: &JVec<ACL>) -> &[ACL] {
    a.as_slice().unwrap_or_default()
}

fn time_of(now: Millis) -> i64 {
    i64::try_from(now.0).unwrap_or(i64::MAX)
}

fn children_jvec(names: Vec<Vec<u8>>) -> JVec<JString> {
    JVec::Items(names.into_iter().map(JString::Bytes).collect())
}

const fn is_write_op(op: i32) -> bool {
    matches!(
        op,
        opcode::CREATE
            | opcode::CREATE2
            | opcode::CREATE_CONTAINER
            | opcode::CREATE_TTL
            | opcode::DELETE
            | opcode::SET_DATA
            | opcode::SET_ACL
            | opcode::MULTI
            | opcode::RECONFIG
    )
}

const fn has_path(op: i32) -> bool {
    matches!(
        op,
        opcode::CREATE
            | opcode::CREATE2
            | opcode::CREATE_CONTAINER
            | opcode::CREATE_TTL
            | opcode::DELETE
            | opcode::EXISTS
            | opcode::GET_DATA
            | opcode::SET_DATA
            | opcode::GET_ACL
            | opcode::SET_ACL
            | opcode::GET_CHILDREN
            | opcode::GET_CHILDREN2
            | opcode::SYNC
            | opcode::CHECK
            | opcode::CHECK_WATCHES
            | opcode::REMOVE_WATCHES
            | opcode::ADD_WATCH
            | opcode::GET_EPHEMERALS
            | opcode::GET_ALL_CHILDREN_NUMBER
    )
}

impl ServerSim {
    /// Makes a server with no listener.
    #[must_use]
    pub fn new(opts: ServerOptions, seed: u64) -> Self {
        let zxid = opts.initial_zxid;
        Self {
            opts,
            listeners: Vec::new(),
            tree: DataTree::new(),
            sessions: BTreeMap::new(),
            links: BTreeMap::new(),
            next_link: 0,
            rng: SplitMix::new(seed ^ 0x5EED_5E7E_0000_0001),
            zxid,
            rules: Vec::new(),
            inbound: Vec::new(),
            outbound: Vec::new(),
            delay: 0,
            now: Millis(0),
        }
    }

    /// Returns the options.
    #[must_use]
    pub const fn options(&self) -> &ServerOptions {
        &self.opts
    }

    /// Returns the options for a change.
    pub fn options_mut(&mut self) -> &mut ServerOptions {
        &mut self.opts
    }

    // ----- listeners -----

    /// Adds a listener. An earlier listener at the same address is
    /// replaced.
    pub fn add_listener(&mut self, addr: SocketAddr, read_only: bool) {
        self.listeners.retain(|l| l.addr != addr);
        self.listeners.push(Listener {
            addr,
            read_only,
            accepting: true,
        });
    }

    /// Returns the listeners.
    #[must_use]
    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }

    /// Returns the listener at `addr`.
    #[must_use]
    pub fn listener(&self, addr: SocketAddr) -> Option<Listener> {
        self.listeners.iter().find(|l| l.addr == addr).copied()
    }

    /// Makes a listener accept or refuse new connects. Open links stay.
    pub fn set_accepting(&mut self, addr: SocketAddr, accepting: bool) {
        for l in &mut self.listeners {
            if l.addr == addr {
                l.accepting = accepting;
            }
        }
    }

    /// Makes a listener read-only or read-write. Open links stay as they
    /// are.
    pub fn set_read_only(&mut self, addr: SocketAddr, read_only: bool) {
        for l in &mut self.listeners {
            if l.addr == addr {
                l.read_only = read_only;
            }
        }
    }

    /// Stops a listener as a server crash does: it refuses connects and
    /// resets every link to it.
    pub fn crash(&mut self, addr: SocketAddr) {
        self.set_accepting(addr, false);
        let ids: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, l)| l.addr == addr && l.open())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.reset_link(id);
        }
    }

    /// Returns true when a listener at `addr` accepts connects.
    #[must_use]
    pub fn accepts(&self, addr: SocketAddr) -> bool {
        self.listener(addr).is_some_and(|l| l.accepting)
    }

    // ----- rules -----

    /// Adds a rule after the existing rules.
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(RuleState::new(rule));
    }

    /// Removes every rule.
    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    /// Returns the number of times each rule acted, in rule order.
    #[must_use]
    pub fn rule_hits(&self) -> Vec<u32> {
        self.rules.iter().map(|r| r.fired).collect()
    }

    // ----- state -----

    /// Returns the tree.
    #[must_use]
    pub const fn tree(&self) -> &DataTree {
        &self.tree
    }

    /// Returns the zxid of the last transaction.
    #[must_use]
    pub const fn zxid(&self) -> i64 {
        self.zxid
    }

    /// Sets the zxid of the last transaction, as a new leader epoch does.
    pub fn set_zxid(&mut self, zxid: i64) {
        self.zxid = zxid;
    }

    /// Returns the ids of the live sessions, in order.
    #[must_use]
    pub fn sessions(&self) -> Vec<i64> {
        self.sessions.keys().copied().collect()
    }

    /// Returns the negotiated timeout of a live session.
    #[must_use]
    pub fn session_timeout(&self, id: i64) -> Option<i32> {
        self.sessions.get(&id).map(|s| s.timeout)
    }

    /// Returns the password of a live session.
    #[must_use]
    pub fn session_passwd(&self, id: i64) -> Option<[u8; PASSWD_LEN]> {
        self.sessions.get(&id).map(|s| s.passwd)
    }

    /// Returns the links that are still open, in order.
    #[must_use]
    pub fn open_links(&self) -> Vec<LinkId> {
        self.links
            .iter()
            .filter(|(_, l)| l.open())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns the session of a link.
    #[must_use]
    pub fn link_session(&self, link: LinkId) -> Option<i64> {
        self.links.get(&link).and_then(|l| l.session)
    }

    /// Returns the auth ids that a link added, in arrival order. Each
    /// item is the scheme and the user part of the credential.
    #[must_use]
    pub fn link_auth(&self, link: LinkId) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.links.get(&link).map_or_else(Vec::new, |l| {
            l.auth
                .iter()
                .map(|id| (jstr_bytes(&id.scheme), jstr_bytes(&id.id)))
                .collect()
        })
    }

    /// Returns the listener address of a link.
    #[must_use]
    pub fn link_addr(&self, link: LinkId) -> Option<SocketAddr> {
        self.links.get(&link).map(|l| l.addr)
    }

    /// Returns the inbound transcript, oldest first.
    #[must_use]
    pub fn inbound(&self) -> &[Inbound] {
        &self.inbound
    }

    /// Returns the outbound transcript, oldest first.
    #[must_use]
    pub fn outbound(&self) -> &[Outbound] {
        &self.outbound
    }

    /// Returns the number of received requests of type `op`.
    #[must_use]
    pub fn request_count(&self, op: i32) -> usize {
        self.inbound
            .iter()
            .filter(|f| matches!(f.kind, InboundKind::Request { op: o, .. } if o == op))
            .count()
    }

    /// Returns the received `ConnectRequest` records, oldest first.
    #[must_use]
    pub fn connect_requests(&self) -> Vec<&ConnectRequest> {
        self.inbound
            .iter()
            .filter_map(|f| match &f.kind {
                InboundKind::Connect(c) => Some(c),
                InboundKind::Request { .. } | InboundKind::Undecodable => None,
            })
            .collect()
    }

    /// Returns true when `link` has a watch of this Java watcher type at
    /// `path`.
    #[must_use]
    pub fn has_watch(&self, link: LinkId, path: &str, wtype: i32) -> bool {
        let p = path.as_bytes();
        self.links.get(&link).is_some_and(|l| {
            let w = &l.watches;
            match wtype {
                WATCHER_CHILDREN => w.child.contains(p),
                WATCHER_DATA => w.data.contains(p),
                WATCHER_PERSISTENT => w.persistent.contains(p),
                WATCHER_PERSISTENT_RECURSIVE => w.recursive.contains(p),
                _ => {
                    w.child.contains(p)
                        || w.data.contains(p)
                        || w.persistent.contains(p)
                        || w.recursive.contains(p)
                }
            }
        })
    }

    // ----- the client side of the pipe -----

    /// Accepts a connect at `addr`. It returns `None` when no listener
    /// accepts there.
    pub fn accept(&mut self, addr: SocketAddr, now: Millis) -> Option<LinkId> {
        self.now = now.max(self.now);
        let l = self.listener(addr).filter(|l| l.accepting)?;
        let id = LinkId(self.next_link);
        self.next_link = self.next_link.saturating_add(1);
        self.links.insert(
            id,
            Link {
                ordinal: id.0,
                addr,
                read_only: l.read_only,
                decoder: FrameDecoder::new(self.opts.max_frame_len),
                frames: 0,
                handshaken: false,
                session: None,
                out: VecDeque::new(),
                last_at: now,
                closing: false,
                reset: false,
                gone: false,
                watches: LinkWatches::default(),
                auth: Vec::new(),
                sasl_round: 0,
            },
        );
        Some(id)
    }

    /// Takes bytes that the client wrote on `link`, and answers every
    /// complete frame.
    pub fn client_write(&mut self, link: LinkId, bytes: &[u8], now: Millis) {
        self.now = now.max(self.now);
        let mut frames = Vec::new();
        let mut bad = false;
        {
            let Some(l) = self.links.get_mut(&link) else {
                return;
            };
            if !l.open() {
                return;
            }
            let mut rest = bytes;
            while !rest.is_empty() {
                let (n, p) = l.decoder.push(rest);
                rest = rest.get(n..).unwrap_or_default();
                match p {
                    Pushed::Frame(f) => frames.push(f),
                    Pushed::Error(_) => {
                        bad = true;
                        break;
                    }
                    Pushed::NeedMore => {
                        if n == 0 {
                            break;
                        }
                    }
                }
            }
        }
        for f in frames {
            if !self.links.get(&link).is_some_and(Link::open) {
                return;
            }
            self.on_frame(link, &f, now);
        }
        if bad {
            self.close_link(link);
        }
    }

    /// Takes every byte that the client can read on `link` at `now`.
    pub fn take_available(&mut self, link: LinkId, now: Millis) -> Vec<u8> {
        let mut out = Vec::new();
        let Some(l) = self.links.get_mut(&link) else {
            return out;
        };
        if l.reset || l.gone {
            return out;
        }
        while l.out.front().is_some_and(|i| i.deliver_at <= now) {
            if let Some(i) = l.out.pop_front() {
                out.extend_from_slice(&i.bytes);
            }
        }
        out
    }

    /// Returns true when the client can read bytes on `link` at `now`.
    #[must_use]
    pub fn has_available(&self, link: LinkId, now: Millis) -> bool {
        self.links.get(&link).is_some_and(|l| {
            !l.reset && !l.gone && l.out.front().is_some_and(|i| i.deliver_at <= now)
        })
    }

    /// Returns the state of `link` as the client sees it.
    #[must_use]
    pub fn status(&self, link: LinkId) -> LinkStatus {
        match self.links.get(&link) {
            None => LinkStatus::Gone,
            Some(l) if l.gone => LinkStatus::Gone,
            Some(l) if l.reset => LinkStatus::Reset,
            Some(l) if l.closing && l.out.is_empty() => LinkStatus::Eof,
            Some(_) => LinkStatus::Open,
        }
    }

    /// Takes a close of `link` by the client. The session stays until it
    /// expires or the client resumes it.
    pub fn client_close(&mut self, link: LinkId) {
        if let Some(l) = self.links.get_mut(&link) {
            l.gone = true;
            l.out.clear();
            l.watches.clear();
        }
    }

    /// Closes `link` from the server side. The client reads the bytes that
    /// are already queued, then it reads the end of stream.
    pub fn close_link(&mut self, link: LinkId) {
        if let Some(l) = self.links.get_mut(&link) {
            l.closing = true;
            l.watches.clear();
        }
    }

    /// Resets `link` from the server side. The queued bytes are lost.
    pub fn reset_link(&mut self, link: LinkId) {
        if let Some(l) = self.links.get_mut(&link) {
            l.reset = true;
            l.out.clear();
            l.watches.clear();
        }
    }

    /// Queues raw bytes for the client on `link`, with no frame structure.
    pub fn push_raw(&mut self, link: LinkId, bytes: Vec<u8>) {
        let n = bytes.len();
        self.push_item(link, bytes, OutboundKind::Raw(n));
    }

    /// Queues a watch event for the client on `link`, as a real change
    /// does. It changes no watch and no node.
    pub fn push_event(&mut self, link: LinkId, event_type: i32, path: &str, zxid: i64) {
        self.push_event_bytes(link, event_type, path.as_bytes(), zxid);
    }

    /// Advances the clock of the server and expires idle sessions.
    pub fn tick(&mut self, now: Millis) {
        self.now = now.max(self.now);
        if !self.opts.expire_sessions {
            return;
        }
        let expired: Vec<i64> = self
            .sessions
            .iter()
            .filter(|(_, s)| now > s.last_touch.saturating_add_ms(timeout_ms(s.timeout)))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.expire_session(id);
        }
    }

    /// Returns the next time when the server state changes by itself: a
    /// held reply becomes readable or a session expires.
    #[must_use]
    pub fn next_wake(&self, now: Millis) -> Option<Millis> {
        let mut best: Option<Millis> = None;
        let mut offer = |t: Millis| {
            if t > now {
                best = Some(best.map_or(t, |b| b.min(t)));
            }
        };
        for l in self.links.values() {
            if l.reset || l.gone {
                continue;
            }
            if let Some(i) = l.out.front() {
                offer(i.deliver_at);
            }
        }
        if self.opts.expire_sessions {
            for s in self.sessions.values() {
                offer(
                    s.last_touch
                        .saturating_add_ms(timeout_ms(s.timeout))
                        .saturating_add_ms(1),
                );
            }
        }
        best
    }

    // ----- out-of-band changes -----

    /// Expires a session as the leader does: it deletes the ephemeral
    /// nodes, fires their watches and closes every link of the session.
    pub fn expire_session(&mut self, id: i64) {
        if self.sessions.remove(&id).is_none() {
            return;
        }
        let z = self.next_zxid();
        let mut trig = Vec::new();
        self.tree.kill_session(id, z, &mut trig);
        self.fire(&trig, z);
        let ids: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, l)| l.session == Some(id) && l.open())
            .map(|(lid, _)| *lid)
            .collect();
        for lid in ids {
            self.close_link(lid);
        }
    }

    /// Creates a node as another client does, and fires its watches.
    ///
    /// # Errors
    ///
    /// Returns the Java error code of the create.
    pub fn create(&mut self, path: &str, data: &[u8], mode: i32) -> Result<String, i32> {
        let acl = open_acl();
        let z = self.next_zxid();
        let mut trig = Vec::new();
        let args = CreateArgs {
            path: path.as_bytes(),
            data,
            acl: &acl,
            mode,
            ttl: -1,
            session: 0,
        };
        let (p, _) = self.tree.create(&args, z, time_of(self.now), &mut trig)?;
        self.fire(&trig, z);
        Ok(String::from_utf8_lossy(&p).into_owned())
    }

    /// Sets the data of a node as another client does, and fires its
    /// watches.
    ///
    /// # Errors
    ///
    /// Returns the Java error code of the write.
    pub fn set_data(&mut self, path: &str, data: &[u8]) -> Result<(), i32> {
        let z = self.next_zxid();
        let mut trig = Vec::new();
        self.tree
            .set_data(path.as_bytes(), data, -1, z, time_of(self.now), &mut trig)?;
        self.fire(&trig, z);
        Ok(())
    }

    /// Deletes a node as another client does, and fires its watches.
    ///
    /// # Errors
    ///
    /// Returns the Java error code of the delete.
    pub fn delete(&mut self, path: &str) -> Result<(), i32> {
        let z = self.next_zxid();
        let mut trig = Vec::new();
        self.tree.delete(path.as_bytes(), -1, z, &mut trig)?;
        self.fire(&trig, z);
        Ok(())
    }

    // ----- internals -----

    fn next_zxid(&mut self) -> i64 {
        self.zxid = self.zxid.wrapping_add(1);
        self.zxid
    }

    fn push_item(&mut self, link: LinkId, bytes: Vec<u8>, kind: OutboundKind) {
        let now = self.now;
        let delay = self.delay;
        let Some(l) = self.links.get_mut(&link) else {
            return;
        };
        if !l.open() {
            return;
        }
        let at = now.saturating_add_ms(delay).max(l.last_at);
        l.last_at = at;
        l.out.push_back(Item {
            deliver_at: at,
            bytes,
        });
        self.outbound.push(Outbound {
            link,
            at: now,
            deliver_at: at,
            kind,
        });
    }

    fn push_event_bytes(&mut self, link: LinkId, event_type: i32, path: &[u8], zxid: i64) {
        let ev = WatcherEvent {
            r#type: event_type,
            state: STATE_SYNC_CONNECTED,
            path: JString::Bytes(path.to_vec()),
        };
        let bytes = codec::encode_record_reply(xid::WATCHER_EVENT, zxid, rc::ZOK, Some(&ev));
        self.push_item(
            link,
            bytes,
            OutboundKind::Event {
                event_type,
                path: path.to_vec(),
                zxid,
            },
        );
    }

    fn reply(&mut self, link: LinkId, x: i32, zxid: i64, err: i32, body: &[u8]) {
        let bytes = codec::encode_reply(x, zxid, err, body);
        self.push_item(link, bytes, OutboundKind::Reply { xid: x, zxid, err });
    }

    /// Sends one event to each link whose watches match each trigger.
    fn fire(&mut self, triggers: &[Trigger], zxid: i64) {
        for t in triggers {
            let targets: Vec<LinkId> = self
                .links
                .iter_mut()
                .filter(|(_, l)| l.open() && l.handshaken)
                .filter_map(|(id, l)| l.watches.wants(t).then_some(*id))
                .collect();
            for id in targets {
                self.push_event_bytes(id, t.event_type, &t.path, zxid);
            }
        }
    }

    fn rule_for(&mut self, facts: &FrameFacts<'_>) -> Option<RuleAction> {
        self.rules.iter_mut().find_map(|r| r.consider(facts))
    }

    fn on_frame(&mut self, link: LinkId, body: &[u8], now: Millis) {
        let Some(l) = self.links.get_mut(&link) else {
            return;
        };
        let index = l.frames;
        l.frames = l.frames.saturating_add(1);
        let ordinal = l.ordinal;
        if !l.handshaken {
            let req = codec::decode_connect_request(body);
            let facts = FrameFacts {
                connect: true,
                op: 0,
                xid: 0,
                path: None,
                frame: index,
                conn: ordinal,
            };
            let action = self.rule_for(&facts);
            self.inbound.push(Inbound {
                link,
                at: now,
                index,
                kind: req.as_ref().map_or(InboundKind::Undecodable, |r| {
                    InboundKind::Connect(r.clone())
                }),
                rule: action.clone(),
            });
            match req {
                Ok(r) => self.on_connect(link, &r, action),
                Err(_) => self.close_link(link),
            }
            return;
        }
        let Ok((h, rest)) = codec::decode_client_frame(body) else {
            self.inbound.push(Inbound {
                link,
                at: now,
                index,
                kind: InboundKind::Undecodable,
                rule: None,
            });
            self.close_link(link);
            return;
        };
        let path = if has_path(h.r#type) {
            JString::from_bytes(rest).ok().map(|p| jstr_bytes(&p))
        } else {
            None
        };
        let facts = FrameFacts {
            connect: false,
            op: h.r#type,
            xid: h.xid,
            path: path.as_deref(),
            frame: index,
            conn: ordinal,
        };
        let action = self.rule_for(&facts);
        self.inbound.push(Inbound {
            link,
            at: now,
            index,
            kind: InboundKind::Request {
                xid: h.xid,
                op: h.r#type,
                path,
            },
            rule: action.clone(),
        });
        if let Some(sid) = self.links.get(&link).and_then(|l| l.session) {
            if let Some(s) = self.sessions.get_mut(&sid) {
                s.last_touch = now;
            }
        }
        match action {
            None | Some(RuleAction::Handshake(_)) => {
                self.on_request(link, h.xid, h.r#type, rest, true);
            }
            Some(RuleAction::Delay(ms)) => {
                self.delay = ms;
                self.on_request(link, h.xid, h.r#type, rest, true);
                self.delay = 0;
            }
            Some(RuleAction::Drop) => self.on_request(link, h.xid, h.r#type, rest, false),
            Some(RuleAction::Ignore) => {}
            Some(RuleAction::Error(code)) => self.reply(link, h.xid, self.zxid, code, &[]),
            Some(RuleAction::Close) => self.close_link(link),
            Some(RuleAction::CloseAfterReply) => {
                self.on_request(link, h.xid, h.r#type, rest, true);
                self.close_link(link);
            }
            Some(RuleAction::Reset) => self.reset_link(link),
            Some(RuleAction::Garbage(g)) => self.push_raw(link, g),
            Some(RuleAction::ExpireSession) => {
                if let Some(sid) = self.links.get(&link).and_then(|l| l.session) {
                    self.expire_session(sid);
                }
                self.close_link(link);
            }
        }
    }

    fn negotiate(&self, requested: i32) -> i32 {
        requested.clamp(
            self.opts.min_session_timeout,
            self.opts
                .max_session_timeout
                .max(self.opts.min_session_timeout),
        )
    }

    fn new_session(&mut self, timeout: i32, now: Millis) -> (i64, [u8; PASSWD_LEN]) {
        let mut id = 0_i64;
        while id == 0 || self.sessions.contains_key(&id) {
            id = i64::try_from(self.rng.next_u64() >> 2).unwrap_or(1);
        }
        let mut passwd = [0_u8; PASSWD_LEN];
        let a = self.rng.next_u64().to_be_bytes();
        let b = self.rng.next_u64().to_be_bytes();
        for (dst, src) in passwd.iter_mut().zip(a.iter().chain(b.iter())) {
            *dst = *src;
        }
        let _ = self.next_zxid();
        self.sessions.insert(
            id,
            Session {
                passwd,
                timeout,
                last_touch: now,
            },
        );
        (id, passwd)
    }

    fn send_handshake(&mut self, link: LinkId, resp: &ConnectResponse, short: bool) {
        let bytes = codec::connect_response_frame(resp, short);
        self.push_item(
            link,
            bytes,
            OutboundKind::Handshake {
                session_id: resp.session_id,
                timeout: resp.time_out,
                read_only: resp.read_only,
            },
        );
    }

    fn send_expired(&mut self, link: LinkId, read_only: bool, short: bool) {
        let resp = ConnectResponse {
            protocol_version: 0,
            time_out: 0,
            session_id: 0,
            passwd: JBuffer::Bytes(vec![0; PASSWD_LEN]),
            read_only,
        };
        self.send_handshake(link, &resp, short);
        self.close_link(link);
    }

    fn on_connect(&mut self, link: LinkId, req: &ConnectRequest, action: Option<RuleAction>) {
        let now = self.now;
        let Some(l) = self.links.get(&link) else {
            return;
        };
        let listener_ro = l.read_only;
        let close_after = matches!(action, Some(RuleAction::CloseAfterReply));
        let mut style = HandshakeStyle::Normal;
        match action {
            None | Some(RuleAction::CloseAfterReply) => {}
            Some(RuleAction::Handshake(s)) => style = s,
            Some(RuleAction::Delay(ms)) => self.delay = ms,
            Some(RuleAction::Drop | RuleAction::Ignore) => return,
            Some(RuleAction::Error(_) | RuleAction::Close | RuleAction::ExpireSession) => {
                self.close_link(link);
                return;
            }
            Some(RuleAction::Reset) => {
                self.reset_link(link);
                return;
            }
            Some(RuleAction::Garbage(g)) => {
                self.push_raw(link, g);
                return;
            }
        }
        let short = self.opts.short_handshake || style == HandshakeStyle::Short;
        if let HandshakeStyle::Exact {
            timeout,
            session_id,
            passwd,
            read_only,
        } = &style
        {
            let resp = ConnectResponse {
                protocol_version: 0,
                time_out: *timeout,
                session_id: *session_id,
                passwd: JBuffer::Bytes(passwd.clone()),
                read_only: *read_only,
            };
            if let Some(l) = self.links.get_mut(&link) {
                l.handshaken = true;
                l.session = self
                    .sessions
                    .contains_key(session_id)
                    .then_some(*session_id);
            }
            self.send_handshake(link, &resp, short);
        } else if style == HandshakeStyle::Expired {
            self.send_expired(link, listener_ro, short);
        } else if (listener_ro && !req.read_only) || req.last_zxid_seen > self.zxid {
            // The Java server closes the socket with no answer.
            self.close_link(link);
        } else {
            let mut timeout = self.negotiate(req.time_out);
            if let HandshakeStyle::Timeout(t) = style {
                timeout = t;
            }
            let read_only = match style {
                HandshakeStyle::ReadOnly(b) => b,
                _ => listener_ro,
            };
            let session = if req.session_id == 0 {
                Some(self.new_session(timeout, now))
            } else {
                let ok = self
                    .sessions
                    .get(&req.session_id)
                    .is_some_and(|s| jbuf_bytes(&req.passwd) == s.passwd.as_slice());
                if ok {
                    self.resume_session(link, req.session_id, timeout, now)
                } else {
                    None
                }
            };
            match session {
                Some((id, passwd)) => {
                    if let Some(l) = self.links.get_mut(&link) {
                        l.handshaken = true;
                        l.session = Some(id);
                    }
                    let resp = ConnectResponse {
                        protocol_version: 0,
                        time_out: timeout,
                        session_id: id,
                        passwd: JBuffer::Bytes(passwd.to_vec()),
                        read_only,
                    };
                    self.send_handshake(link, &resp, short);
                }
                None => self.send_expired(link, listener_ro, short),
            }
        }
        self.delay = 0;
        if close_after {
            self.close_link(link);
        }
    }

    fn resume_session(
        &mut self,
        link: LinkId,
        id: i64,
        timeout: i32,
        now: Millis,
    ) -> Option<(i64, [u8; PASSWD_LEN])> {
        let passwd = {
            let s = self.sessions.get_mut(&id)?;
            s.timeout = timeout;
            s.last_touch = now;
            s.passwd
        };
        // The Java server closes the older connection of a moved session.
        let older: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(lid, l)| **lid != link && l.session == Some(id) && l.open())
            .map(|(lid, _)| *lid)
            .collect();
        for lid in older {
            self.close_link(lid);
        }
        Some((id, passwd))
    }

    fn link_read_only(&self, link: LinkId) -> bool {
        self.links.get(&link).is_some_and(|l| l.read_only)
    }

    fn on_request(&mut self, link: LinkId, x: i32, op: i32, body: &[u8], send: bool) {
        if self.link_read_only(link) && is_write_op(op) {
            if send {
                self.reply(link, x, self.zxid, rc::ZNOTREADONLY, &[]);
            }
            return;
        }
        let answer = match op {
            opcode::PING => Answer::Body(self.zxid, Vec::new()),
            opcode::CLOSE => self.op_close(link),
            opcode::SET_AUTH => self.op_auth(link, x, body),
            opcode::SASL => self.op_sasl(link, x, body),
            opcode::SET_WATCHES | opcode::SET_WATCHES2 => self.op_set_watches(link, op, body),
            opcode::MULTI | opcode::MULTI_READ => self.op_multi(link, x, op, body),
            opcode::RECONFIG => Answer::Err(rc::ZRECONFIGDISABLED, self.zxid),
            opcode::WHO_AM_I => self.op_who_am_i(link),
            _ => match self.op_simple(link, op, body) {
                Ok(a) => a,
                Err(_) => Answer::Err(rc::ZMARSHALLINGERROR, self.zxid),
            },
        };
        if send {
            match answer {
                Answer::Body(z, b) => self.reply(link, x, z, rc::ZOK, &b),
                Answer::Err(code, z) => self.reply(link, x, z, code, &[]),
                Answer::None => {}
            }
        }
        if op == opcode::CLOSE {
            self.close_link(link);
        }
    }

    fn op_close(&mut self, link: LinkId) -> Answer {
        let sid = self.links.get(&link).and_then(|l| l.session);
        let z = self.next_zxid();
        if let Some(id) = sid {
            self.sessions.remove(&id);
            let mut trig = Vec::new();
            self.tree.kill_session(id, z, &mut trig);
            self.fire(&trig, z);
        }
        Answer::Body(z, Vec::new())
    }

    fn op_auth(&mut self, link: LinkId, x: i32, body: &[u8]) -> Answer {
        let Ok(p) = AuthPacket::from_bytes(body) else {
            return Answer::Err(rc::ZMARSHALLINGERROR, 0);
        };
        let scheme = jstr_bytes(&p.scheme);
        if self.opts.reject_auth_schemes.contains(&scheme) {
            self.reply(link, x, 0, rc::ZAUTHFAILED, &[]);
            self.close_link(link);
            return Answer::None;
        }
        let auth = jbuf_bytes(&p.auth);
        let user = auth
            .split(|b| *b == b':')
            .next()
            .unwrap_or_default()
            .to_vec();
        if let Some(l) = self.links.get_mut(&link) {
            l.auth.push(Id {
                scheme: p.scheme.clone(),
                id: JString::Bytes(user),
            });
        }
        Answer::Body(0, Vec::new())
    }

    fn op_sasl(&mut self, link: LinkId, x: i32, body: &[u8]) -> Answer {
        if GetSASLRequest::from_bytes(body).is_err() {
            return Answer::Err(rc::ZMARSHALLINGERROR, self.zxid);
        }
        let round = match self.links.get_mut(&link) {
            Some(l) => {
                let r = l.sasl_round;
                l.sasl_round = r.saturating_add(1);
                r
            }
            None => 0,
        };
        let reply = self
            .opts
            .sasl_replies
            .get(round)
            .cloned()
            .unwrap_or(SaslReply {
                token: Some(Vec::new()),
                err: rc::ZOK,
            });
        if reply.err != rc::ZOK {
            self.reply(link, x, self.zxid, reply.err, &[]);
            self.close_link(link);
            return Answer::None;
        }
        let resp = SetSASLResponse {
            token: JBuffer::from(reply.token),
        };
        Answer::Body(self.zxid, resp.to_bytes())
    }

    fn op_set_watches(&mut self, link: LinkId, op: i32, body: &[u8]) -> Answer {
        let parsed = if op == opcode::SET_WATCHES2 {
            SetWatches2::from_bytes(body)
        } else {
            SetWatches::from_bytes(body).map(|s| SetWatches2 {
                relative_zxid: s.relative_zxid,
                data_watches: s.data_watches,
                exist_watches: s.exist_watches,
                child_watches: s.child_watches,
                persistent_watches: JVec::Items(Vec::new()),
                persistent_recursive_watches: JVec::Items(Vec::new()),
            })
        };
        let Ok(sw) = parsed else {
            return Answer::Err(rc::ZMARSHALLINGERROR, self.zxid);
        };
        let rel = sw.relative_zxid;
        let mut events: Vec<(i32, Vec<u8>)> = Vec::new();
        let mut add_data = Vec::new();
        let mut add_child = Vec::new();
        for p in sw.data_watches.iter().map(jstr_bytes) {
            match self.tree.get(&p) {
                None => events.push((EVENT_DELETED, p)),
                Some(n) if n.stat.mzxid > rel => events.push((EVENT_DATA_CHANGED, p)),
                Some(_) => add_data.push(p),
            }
        }
        for p in sw.exist_watches.iter().map(jstr_bytes) {
            if self.tree.contains(&p) {
                events.push((EVENT_CREATED, p));
            } else {
                add_data.push(p);
            }
        }
        for p in sw.child_watches.iter().map(jstr_bytes) {
            match self.tree.get(&p) {
                None => events.push((EVENT_DELETED, p)),
                Some(n) if n.stat.pzxid > rel => events.push((EVENT_CHILDREN_CHANGED, p)),
                Some(_) => add_child.push(p),
            }
        }
        if let Some(l) = self.links.get_mut(&link) {
            l.watches.data.extend(add_data);
            l.watches.child.extend(add_child);
            l.watches
                .persistent
                .extend(sw.persistent_watches.iter().map(jstr_bytes));
            l.watches
                .recursive
                .extend(sw.persistent_recursive_watches.iter().map(jstr_bytes));
        }
        for (t, p) in events {
            self.push_event_bytes(link, t, &p, -1);
        }
        Answer::Body(self.zxid, Vec::new())
    }

    fn op_who_am_i(&self, link: LinkId) -> Answer {
        let mut infos = vec![ClientInfo {
            auth_scheme: "ip".into(),
            user: "127.0.0.1".into(),
        }];
        if let Some(l) = self.links.get(&link) {
            for id in &l.auth {
                infos.push(ClientInfo {
                    auth_scheme: id.scheme.clone(),
                    user: id.id.clone(),
                });
            }
        }
        let resp = WhoAmIResponse {
            client_info: JVec::Items(infos),
        };
        Answer::Body(self.zxid, resp.to_bytes())
    }

    fn register(&mut self, link: LinkId, set: i32, path: &[u8]) {
        if let Some(l) = self.links.get_mut(&link) {
            let target = match set {
                WATCHER_CHILDREN => &mut l.watches.child,
                WATCHER_PERSISTENT => &mut l.watches.persistent,
                WATCHER_PERSISTENT_RECURSIVE => &mut l.watches.recursive,
                _ => &mut l.watches.data,
            };
            target.insert(path.to_vec());
        }
    }

    fn session_of(&self, link: LinkId) -> i64 {
        self.links.get(&link).and_then(|l| l.session).unwrap_or(0)
    }

    /// Handles the requests that have one record body and one answer.
    fn op_simple(&mut self, link: LinkId, op: i32, body: &[u8]) -> Result<Answer, DecodeError> {
        Ok(match op {
            opcode::CREATE | opcode::CREATE2 | opcode::CREATE_CONTAINER => {
                self.do_create(link, op, &CreateRequest::from_bytes(body)?, -1)
            }
            opcode::CREATE_TTL => {
                let r = CreateTTLRequest::from_bytes(body)?;
                let c = CreateRequest {
                    path: r.path,
                    data: r.data,
                    acl: r.acl,
                    flags: r.flags,
                };
                self.do_create(link, op, &c, r.ttl)
            }
            opcode::DELETE => self.arm_delete(&DeleteRequest::from_bytes(body)?),
            opcode::EXISTS => self.arm_exists(link, &ExistsRequest::from_bytes(body)?),
            opcode::GET_DATA => self.arm_get_data(link, &GetDataRequest::from_bytes(body)?),
            opcode::SET_DATA => self.arm_set_data(&SetDataRequest::from_bytes(body)?),
            opcode::GET_ACL => self.arm_get_acl(&GetACLRequest::from_bytes(body)?),
            opcode::SET_ACL => self.arm_set_acl(&SetACLRequest::from_bytes(body)?),
            opcode::GET_CHILDREN => {
                self.arm_get_children(link, &GetChildrenRequest::from_bytes(body)?)
            }
            opcode::GET_CHILDREN2 => {
                self.arm_get_children2(link, &GetChildren2Request::from_bytes(body)?)
            }
            opcode::SYNC => self.arm_sync(&SyncRequest::from_bytes(body)?),
            opcode::CHECK_WATCHES | opcode::REMOVE_WATCHES => {
                self.arm_check_watches(link, op, &RemoveWatchesRequest::from_bytes(body)?)
            }
            opcode::ADD_WATCH => self.arm_add_watch(link, &AddWatchRequest::from_bytes(body)?),
            opcode::GET_EPHEMERALS => {
                self.arm_get_ephemerals(link, &GetEphemeralsRequest::from_bytes(body)?)
            }
            opcode::GET_ALL_CHILDREN_NUMBER => {
                self.arm_get_all_children_number(&GetAllChildrenNumberRequest::from_bytes(body)?)
            }
            _ => Answer::Err(rc::ZUNIMPLEMENTED, self.zxid),
        })
    }

    fn arm_delete(&mut self, r: &DeleteRequest) -> Answer {
        let z = self.next_zxid();
        let mut trig = Vec::new();
        match self
            .tree
            .delete(&jstr_bytes(&r.path), r.version, z, &mut trig)
        {
            Ok(()) => {
                self.fire(&trig, z);
                Answer::Body(z, Vec::new())
            }
            Err(e) => Answer::Err(e, z),
        }
    }

    fn arm_exists(&mut self, link: LinkId, r: &ExistsRequest) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        if tree::validate_path(&p, false).is_err() {
            return Answer::Err(rc::ZBADARGUMENTS, cur);
        }
        if r.watch {
            self.register(link, WATCHER_DATA, &p);
        }
        match self.tree.get(&p) {
            Some(n) => Answer::Body(
                cur,
                ExistsResponse {
                    stat: n.stat.clone(),
                }
                .to_bytes(),
            ),
            None => Answer::Err(rc::ZNONODE, cur),
        }
    }

    fn arm_get_data(&mut self, link: LinkId, r: &GetDataRequest) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        match self.tree.get(&p) {
            Some(n) => {
                let resp = GetDataResponse {
                    data: JBuffer::Bytes(n.data.clone()),
                    stat: n.stat.clone(),
                };
                if r.watch {
                    self.register(link, WATCHER_DATA, &p);
                }
                Answer::Body(cur, resp.to_bytes())
            }
            None => Answer::Err(path_err(&p), cur),
        }
    }

    fn arm_set_data(&mut self, r: &SetDataRequest) -> Answer {
        let now = self.now;
        let z = self.next_zxid();
        let mut trig = Vec::new();
        let res = self.tree.set_data(
            &jstr_bytes(&r.path),
            jbuf_bytes(&r.data),
            r.version,
            z,
            time_of(now),
            &mut trig,
        );
        match res {
            Ok(stat) => {
                self.fire(&trig, z);
                Answer::Body(z, SetDataResponse { stat }.to_bytes())
            }
            Err(e) => Answer::Err(e, z),
        }
    }

    fn arm_get_acl(&self, r: &GetACLRequest) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        match self.tree.get(&p) {
            Some(n) => Answer::Body(
                cur,
                GetACLResponse {
                    acl: JVec::Items(n.acl.clone()),
                    stat: n.stat.clone(),
                }
                .to_bytes(),
            ),
            None => Answer::Err(path_err(&p), cur),
        }
    }

    fn arm_set_acl(&mut self, r: &SetACLRequest) -> Answer {
        let z = self.next_zxid();
        match self
            .tree
            .set_acl(&jstr_bytes(&r.path), acl_items(&r.acl), r.version)
        {
            Ok(stat) => Answer::Body(z, SetACLResponse { stat }.to_bytes()),
            Err(e) => Answer::Err(e, z),
        }
    }

    fn arm_get_children(&mut self, link: LinkId, r: &GetChildrenRequest) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        match self.tree.children(&p) {
            Ok(names) => {
                if r.watch {
                    self.register(link, WATCHER_CHILDREN, &p);
                }
                let resp = GetChildrenResponse {
                    children: children_jvec(names),
                };
                Answer::Body(cur, resp.to_bytes())
            }
            Err(_) => Answer::Err(path_err(&p), cur),
        }
    }

    fn arm_get_children2(&mut self, link: LinkId, r: &GetChildren2Request) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        match (self.tree.children(&p), self.tree.get(&p)) {
            (Ok(names), Some(n)) => {
                let resp = GetChildren2Response {
                    children: children_jvec(names),
                    stat: n.stat.clone(),
                };
                if r.watch {
                    self.register(link, WATCHER_CHILDREN, &p);
                }
                Answer::Body(cur, resp.to_bytes())
            }
            _ => Answer::Err(path_err(&p), cur),
        }
    }

    fn arm_sync(&self, r: &SyncRequest) -> Answer {
        let cur = self.zxid;
        Answer::Body(
            cur,
            SyncResponse {
                path: r.path.clone(),
            }
            .to_bytes(),
        )
    }

    fn arm_check_watches(&mut self, link: LinkId, op: i32, r: &RemoveWatchesRequest) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        let remove = op == opcode::REMOVE_WATCHES;
        if self.remove_watches(link, &p, r.r#type, remove) {
            Answer::Body(cur, Vec::new())
        } else {
            Answer::Err(rc::ZNOWATCHER, cur)
        }
    }

    fn arm_add_watch(&mut self, link: LinkId, r: &AddWatchRequest) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        let set = if r.mode == ADD_WATCH_PERSISTENT_RECURSIVE {
            WATCHER_PERSISTENT_RECURSIVE
        } else {
            WATCHER_PERSISTENT
        };
        self.register(link, set, &p);
        Answer::Body(cur, ErrorResponse { err: 0 }.to_bytes())
    }

    fn arm_get_ephemerals(&mut self, link: LinkId, r: &GetEphemeralsRequest) -> Answer {
        let cur = self.zxid;
        let list = self
            .tree
            .ephemerals(self.session_of(link), &jstr_bytes(&r.prefix_path));
        let resp = GetEphemeralsResponse {
            ephemerals: children_jvec(list),
        };
        Answer::Body(cur, resp.to_bytes())
    }

    fn arm_get_all_children_number(&self, r: &GetAllChildrenNumberRequest) -> Answer {
        let cur = self.zxid;
        let p = jstr_bytes(&r.path);
        match self.tree.all_children_number(&p) {
            Ok(n) => Answer::Body(
                cur,
                GetAllChildrenNumberResponse { total_number: n }.to_bytes(),
            ),
            Err(e) => Answer::Err(e, cur),
        }
    }

    fn do_create(&mut self, link: LinkId, op: i32, r: &CreateRequest, ttl: i64) -> Answer {
        let z = self.next_zxid();
        if op == opcode::CREATE_CONTAINER && r.flags != tree::MODE_CONTAINER {
            return Answer::Err(rc::ZBADARGUMENTS, z);
        }
        let path = jstr_bytes(&r.path);
        let args = CreateArgs {
            path: &path,
            data: jbuf_bytes(&r.data),
            acl: acl_items(&r.acl),
            mode: r.flags,
            ttl,
            session: self.session_of(link),
        };
        let mut trig = Vec::new();
        match self.tree.create(&args, z, time_of(self.now), &mut trig) {
            Ok((actual, stat)) => {
                self.fire(&trig, z);
                let body = if op == opcode::CREATE {
                    CreateResponse {
                        path: JString::Bytes(actual),
                    }
                    .to_bytes()
                } else {
                    Create2Response {
                        path: JString::Bytes(actual),
                        stat,
                    }
                    .to_bytes()
                };
                Answer::Body(z, body)
            }
            Err(e) => Answer::Err(e, z),
        }
    }

    fn remove_watches(&mut self, link: LinkId, path: &[u8], wtype: i32, remove: bool) -> bool {
        let Some(l) = self.links.get_mut(&link) else {
            return false;
        };
        let w = &mut l.watches;
        let sets: Vec<&mut BTreeSet<Vec<u8>>> = match wtype {
            WATCHER_CHILDREN => vec![&mut w.child],
            WATCHER_DATA => vec![&mut w.data],
            WATCHER_PERSISTENT => vec![&mut w.persistent],
            WATCHER_PERSISTENT_RECURSIVE => vec![&mut w.recursive],
            _ => vec![
                &mut w.data,
                &mut w.child,
                &mut w.persistent,
                &mut w.recursive,
            ],
        };
        let mut found = false;
        for s in sets {
            if remove {
                found |= s.remove(path);
            } else {
                found |= s.contains(path);
            }
        }
        found
    }

    fn decode_mops(body: &[u8]) -> Option<Vec<MOp>> {
        let mut r = Reader::new(body);
        let mut out = Vec::new();
        loop {
            let h = MultiHeader::decode(&mut r).ok()?;
            if h.done {
                break;
            }
            let op = match h.r#type {
                opcode::CREATE | opcode::CREATE2 | opcode::CREATE_CONTAINER => {
                    MOp::Create(h.r#type, CreateRequest::decode(&mut r).ok()?, -1)
                }
                opcode::CREATE_TTL => {
                    let t = CreateTTLRequest::decode(&mut r).ok()?;
                    MOp::Create(
                        h.r#type,
                        CreateRequest {
                            path: t.path,
                            data: t.data,
                            acl: t.acl,
                            flags: t.flags,
                        },
                        t.ttl,
                    )
                }
                opcode::DELETE => MOp::Delete(DeleteRequest::decode(&mut r).ok()?),
                opcode::SET_DATA => MOp::SetData(SetDataRequest::decode(&mut r).ok()?),
                opcode::CHECK => MOp::Check(CheckVersionRequest::decode(&mut r).ok()?),
                opcode::GET_DATA => MOp::GetData(GetDataRequest::decode(&mut r).ok()?),
                opcode::GET_CHILDREN => MOp::GetChildren(GetChildrenRequest::decode(&mut r).ok()?),
                _ => return None,
            };
            out.push(op);
        }
        Some(out)
    }

    fn op_multi(&mut self, link: LinkId, x: i32, op: i32, body: &[u8]) -> Answer {
        let Some(ops) = Self::decode_mops(body) else {
            return Answer::Err(rc::ZMARSHALLINGERROR, self.zxid);
        };
        if op == opcode::MULTI_READ {
            return self.multi_read(&ops);
        }
        let z = self.next_zxid();
        let mut scratch = self.tree.clone();
        let mut trig = Vec::new();
        let mut results: Vec<(i32, Vec<u8>)> = Vec::new();
        let mut failed: Option<(usize, i32)> = None;
        let session = self.session_of(link);
        let time = time_of(self.now);
        for (i, mop) in ops.iter().enumerate() {
            let r: Result<(i32, Vec<u8>), i32> = match mop {
                MOp::Create(ct, req, ttl) => {
                    let path = jstr_bytes(&req.path);
                    let args = CreateArgs {
                        path: &path,
                        data: jbuf_bytes(&req.data),
                        acl: acl_items(&req.acl),
                        mode: req.flags,
                        ttl: *ttl,
                        session,
                    };
                    scratch
                        .create(&args, z, time, &mut trig)
                        .map(|(actual, stat)| {
                            if *ct == opcode::CREATE {
                                (
                                    opcode::CREATE,
                                    CreateResponse {
                                        path: JString::Bytes(actual),
                                    }
                                    .to_bytes(),
                                )
                            } else {
                                (
                                    opcode::CREATE2,
                                    Create2Response {
                                        path: JString::Bytes(actual),
                                        stat,
                                    }
                                    .to_bytes(),
                                )
                            }
                        })
                }
                MOp::Delete(d) => scratch
                    .delete(&jstr_bytes(&d.path), d.version, z, &mut trig)
                    .map(|()| (opcode::DELETE, Vec::new())),
                MOp::SetData(s) => scratch
                    .set_data(
                        &jstr_bytes(&s.path),
                        jbuf_bytes(&s.data),
                        s.version,
                        z,
                        time,
                        &mut trig,
                    )
                    .map(|stat| (opcode::SET_DATA, SetDataResponse { stat }.to_bytes())),
                MOp::Check(c) => scratch
                    .check(&jstr_bytes(&c.path), c.version)
                    .map(|()| (opcode::CHECK, Vec::new())),
                MOp::GetData(_) | MOp::GetChildren(_) => Err(rc::ZBADARGUMENTS),
            };
            match r {
                Ok(v) => results.push(v),
                Err(e) => {
                    failed = Some((i, e));
                    break;
                }
            }
        }
        let mut out = Vec::new();
        let header_err = match failed {
            Some((fi, frc)) => {
                for i in 0..ops.len() {
                    let err = match i.cmp(&fi) {
                        core::cmp::Ordering::Less => rc::ZOK,
                        core::cmp::Ordering::Equal => frc,
                        core::cmp::Ordering::Greater => rc::ZRUNTIMEINCONSISTENCY,
                    };
                    MultiHeader {
                        r#type: opcode::ERROR,
                        done: false,
                        err,
                    }
                    .encode(&mut out);
                    ErrorResponse { err }.encode(&mut out);
                }
                frc
            }
            None => {
                self.tree = scratch;
                self.fire(&trig, z);
                for (t, b) in results {
                    MultiHeader {
                        r#type: t,
                        done: false,
                        err: 0,
                    }
                    .encode(&mut out);
                    out.extend_from_slice(&b);
                }
                rc::ZOK
            }
        };
        zk_jute::multi::encode_end(&mut out);
        self.reply(link, x, z, header_err, &out);
        Answer::None
    }

    fn multi_read(&self, ops: &[MOp]) -> Answer {
        let mut out = Vec::new();
        for mop in ops {
            let (t, err, body) = match mop {
                MOp::GetData(g) => {
                    let p = jstr_bytes(&g.path);
                    match self.tree.get(&p) {
                        Some(n) => (
                            opcode::GET_DATA,
                            0,
                            GetDataResponse {
                                data: JBuffer::Bytes(n.data.clone()),
                                stat: n.stat.clone(),
                            }
                            .to_bytes(),
                        ),
                        None => (opcode::ERROR, path_err(&p), Vec::new()),
                    }
                }
                MOp::GetChildren(g) => {
                    let p = jstr_bytes(&g.path);
                    match self.tree.children(&p) {
                        Ok(names) => (
                            opcode::GET_CHILDREN,
                            0,
                            GetChildrenResponse {
                                children: children_jvec(names),
                            }
                            .to_bytes(),
                        ),
                        Err(_) => (opcode::ERROR, path_err(&p), Vec::new()),
                    }
                }
                MOp::Create(..) | MOp::Delete(_) | MOp::SetData(_) | MOp::Check(_) => {
                    (opcode::ERROR, rc::ZBADARGUMENTS, Vec::new())
                }
            };
            MultiHeader {
                r#type: t,
                done: false,
                err,
            }
            .encode(&mut out);
            if t == opcode::ERROR {
                ErrorResponse { err }.encode(&mut out);
            } else {
                out.extend_from_slice(&body);
            }
        }
        zk_jute::multi::encode_end(&mut out);
        Answer::Body(self.zxid, out)
    }
}

fn path_err(p: &[u8]) -> i32 {
    if tree::validate_path(p, false).is_err() {
        rc::ZBADARGUMENTS
    } else {
        rc::ZNONODE
    }
}

fn timeout_ms(t: i32) -> u64 {
    u64::try_from(t.max(0)).unwrap_or(0)
}

/// Returns the open ACL: `world:anyone` with every permission.
#[must_use]
pub fn open_acl() -> Vec<ACL> {
    vec![ACL {
        perms: 31,
        id: Id {
            scheme: "world".into(),
            id: "anyone".into(),
        },
    }]
}
