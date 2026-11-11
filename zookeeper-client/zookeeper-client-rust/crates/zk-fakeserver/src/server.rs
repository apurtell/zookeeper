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

//! The listeners, the connection threads and the public control API.
//!
//! Each listener has an accept thread. Each connection has one thread that
//! reads, runs the rules and the model, and writes. The thread owns the
//! stream and does not split it, so a TLS stream fits the same loop. All
//! listeners of a [`Cluster`] share one model under one lock. This gives
//! one total order for every frame and makes each run repeatable.

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zk_jute::data::Stat;
use zk_jute::proto::{GetSASLRequest, RequestHeader, SetSASLResponse};
use zk_jute::{FrameDecoder, JBuffer, Pushed, Reader, Record, encode_frame, opcode};

use crate::config::{Chunking, ClusterConfig, HandshakeStyle, ServerOptions};
use crate::link::{ConnLink, Out};
use crate::model::{ConnectOutcome, Handled, Model, NodeInfo, Reply, SessionInfo, answer};
use crate::script::{Action, FrameView, Rule, Script};
use crate::transcript::{ConnectInfo, Detail, FrameKind, FrameRecord, describe};
use crate::transport::Transport;

#[path = "sasl.rs"]
mod sasl;

/// The read timeout of a connection thread. It sets how fast the thread
/// sees new output, a stop request and a release.
const POLL: Duration = Duration::from_millis(2);
/// The write timeout of a connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// The four-letter words of the Java server.
const FOUR_LETTER: [&[u8; 4]; 18] = [
    b"conf", b"cons", b"crst", b"dump", b"envi", b"gtmk", b"ruok", b"stmk", b"srst", b"srvr",
    b"stat", b"wchc", b"wchp", b"wchs", b"mntr", b"isro", b"hash", b"dirs",
];

/// The state of one listener.
#[derive(Debug)]
struct Slot {
    opts: ServerOptions,
    conn_count: u64,
    held: bool,
    /// The DIGEST-MD5 user and password. `None` refuses SASL.
    sasl: Option<(String, String)>,
}

/// Everything that the threads share.
#[derive(Debug)]
struct State {
    model: Model,
    slots: Vec<Slot>,
    transcript: Vec<FrameRecord>,
    seq: u64,
    next_conn: u64,
}

impl State {
    fn record(&mut self, mut rec: FrameRecord) {
        rec.seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        self.transcript.push(rec);
    }
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A shared server model with any number of listeners.
///
/// The listeners act as the servers of one ensemble: they share the data
/// tree, the sessions and the zxid. A client can move its session from one
/// listener to another. The model also runs session expiry and the
/// container and TTL reaper on a timer thread.
#[derive(Debug, Clone)]
pub struct Cluster {
    shared: Arc<Shared>,
}

impl Default for Cluster {
    fn default() -> Self {
        Self::new(ClusterConfig::default())
    }
}

impl Cluster {
    /// Creates a cluster with no listeners.
    #[must_use]
    pub fn new(cfg: ClusterConfig) -> Self {
        let every = cfg.check_interval.max(Duration::from_millis(1));
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                model: Model::new(cfg),
                slots: Vec::new(),
                transcript: Vec::new(),
                seq: 0,
                next_conn: 0,
            }),
            changed: Condvar::new(),
        });
        spawn_ticker(Arc::downgrade(&shared), every);
        Self { shared }
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let out = f(&mut self.shared.lock());
        self.shared.changed.notify_all();
        out
    }

    /// Starts a new listener on `127.0.0.1` with a free port.
    ///
    /// # Errors
    ///
    /// Returns the bind error.
    pub fn start_server(&self, opts: ServerOptions) -> io::Result<FakeServer> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let index = self.with(|st| {
            st.slots.push(Slot {
                opts,
                conn_count: 0,
                held: false,
                sasl: None,
            });
            st.slots.len().saturating_sub(1)
        });
        let ctl = spawn_listener(&self.shared, index, listener)?;
        Ok(FakeServer {
            cluster: self.clone(),
            index,
            addr,
            ctl: Some(ctl),
        })
    }

    /// Returns the last zxid.
    #[must_use]
    pub fn zxid(&self) -> i64 {
        self.with(|st| st.model.zxid())
    }

    /// Sets the last zxid. A client that has seen a higher zxid than the
    /// server gets no handshake response.
    pub fn set_zxid(&self, zxid: i64) {
        self.with(|st| st.model.set_zxid(zxid));
    }

    /// Returns a copy of a node.
    #[must_use]
    pub fn node(&self, path: &str) -> Option<NodeInfo> {
        self.with(|st| st.model.node(path))
    }

    /// Returns the data of a node. The outer `None` is a missing node.
    #[must_use]
    pub fn data(&self, path: &str) -> Option<Option<Vec<u8>>> {
        self.node(path).map(|n| n.data)
    }

    /// Returns the sorted child names of a node.
    #[must_use]
    pub fn children(&self, path: &str) -> Option<Vec<String>> {
        self.node(path).map(|n| n.children)
    }

    /// Creates a node with the open ACL as a client with full rights. The
    /// watches fire. It returns the final path.
    ///
    /// # Errors
    ///
    /// Returns the ZooKeeper error code.
    pub fn create(&self, path: &str, data: &[u8], flags: i32) -> Result<String, i32> {
        self.with(|st| st.model.admin_create(path, data, flags))
    }

    /// Sets the data of a node. The watches fire.
    ///
    /// # Errors
    ///
    /// Returns the ZooKeeper error code.
    pub fn set_data(&self, path: &str, data: &[u8]) -> Result<Stat, i32> {
        self.with(|st| st.model.admin_set_data(path, data))
    }

    /// Deletes a node. The watches fire.
    ///
    /// # Errors
    ///
    /// Returns the ZooKeeper error code.
    pub fn delete(&self, path: &str) -> Result<(), i32> {
        self.with(|st| st.model.admin_delete(path))
    }

    /// Sets the text of `/zookeeper/config` with no watch event.
    pub fn set_config_data(&self, text: &str) {
        self.with(|st| st.model.set_config(text));
    }

    /// Returns the facts about every session.
    #[must_use]
    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.with(|st| st.model.sessions())
    }

    /// Expires a session now. Its connection closes with no reply, its
    /// ephemeral nodes go away and their watches fire. It returns false
    /// for an unknown session.
    pub fn expire_session(&self, session_id: i64) -> bool {
        self.with(|st| st.model.expire_session(session_id))
    }

    /// Expires every session.
    pub fn expire_all(&self) {
        self.with(|st| st.model.expire_all());
    }

    /// Runs the container and TTL reaper now. It returns the removed paths.
    pub fn reap(&self) -> Vec<String> {
        self.with(|st| st.model.reap(Instant::now()))
    }

    /// Returns the number of registered watches.
    #[must_use]
    pub fn watch_count(&self) -> usize {
        self.with(|st| st.model.watch_count())
    }

    /// Sends a watch event to the connection of a session. It returns
    /// false when the session has no connection.
    pub fn notify_session(&self, session_id: i64, event_type: i32, state: i32, path: &str) -> bool {
        self.with(|st| {
            let conn = st
                .model
                .conns
                .iter()
                .find(|(_, c)| c.session == Some(session_id))
                .map(|(id, _)| *id);
            let zxid = st.model.zxid();
            conn.is_some_and(|c| {
                st.model.notify(c, event_type, state, path, zxid);
                true
            })
        })
    }

    /// Clears the tree, the sessions and the watches, and closes every
    /// connection. The transcript stays.
    pub fn reset(&self) {
        self.with(|st| st.model.reset());
    }

    /// Returns a copy of every recorded frame.
    #[must_use]
    pub fn transcript(&self) -> Vec<FrameRecord> {
        self.with(|st| st.transcript.clone())
    }

    /// Removes every recorded frame.
    pub fn clear_transcript(&self) {
        self.with(|st| st.transcript.clear());
    }

    /// Waits for a recorded frame that matches `pred`. It returns `None`
    /// after the timeout.
    pub fn wait_for_frame(
        &self,
        timeout: Duration,
        mut pred: impl FnMut(&FrameRecord) -> bool,
    ) -> Option<FrameRecord> {
        let deadline = Instant::now().checked_add(timeout);
        let mut st = self.shared.lock();
        loop {
            if let Some(r) = st.transcript.iter().find(|r| pred(r)) {
                return Some(r.clone());
            }
            let left = deadline?.checked_duration_since(Instant::now())?;
            if left.is_zero() {
                return None;
            }
            st = match self.shared.changed.wait_timeout(st, left) {
                Ok((g, _)) => g,
                Err(e) => e.into_inner().0,
            };
        }
    }

    /// Waits until `pred` is true for the cluster. It checks after each
    /// change and at least every 5 ms. It returns false after the timeout.
    pub fn wait_until(&self, timeout: Duration, mut pred: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now().checked_add(timeout);
        loop {
            if pred(self) {
                return true;
            }
            let Some(left) = deadline.and_then(|d| d.checked_duration_since(Instant::now())) else {
                return false;
            };
            let st = self.shared.lock();
            let wait = left.min(Duration::from_millis(5));
            drop(self.shared.changed.wait_timeout(st, wait));
        }
    }
}

/// Starts the timer thread for session expiry and reaping. The thread holds
/// a weak reference, so it ends when the cluster goes away.
fn spawn_ticker(weak: Weak<Shared>, every: Duration) {
    let spawned = thread::Builder::new()
        .name("zk-fake-ticker".into())
        .spawn(move || {
            loop {
                thread::sleep(every);
                let Some(shared) = weak.upgrade() else {
                    break;
                };
                shared.lock().model.tick(Instant::now());
                shared.changed.notify_all();
            }
        });
    drop(spawned);
}

/// The control of a running accept thread.
#[derive(Debug)]
struct ListenerCtl {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ListenerCtl {
    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            drop(t.join());
        }
    }
}

fn spawn_listener(
    shared: &Arc<Shared>,
    index: usize,
    listener: TcpListener,
) -> io::Result<ListenerCtl> {
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let shared = Arc::clone(shared);
        let stop = Arc::clone(&stop);
        thread::Builder::new()
            .name(format!("zk-fake-accept-{index}"))
            .spawn(move || accept_loop(&shared, index, listener, &stop))?
    };
    Ok(ListenerCtl {
        stop,
        thread: Some(thread),
    })
}

fn accept_loop(shared: &Arc<Shared>, index: usize, listener: TcpListener, stop: &Arc<AtomicBool>) {
    let mut conns: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((tcp, peer)) => {
                if let Some(h) = start_conn(shared, index, tcp, peer, stop) {
                    conns.push(h);
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(1)),
        }
        conns.retain(|h| !h.is_finished());
    }
    drop(listener);
    for h in conns {
        drop(h.join());
    }
}

fn start_conn(
    shared: &Arc<Shared>,
    index: usize,
    tcp: TcpStream,
    peer: SocketAddr,
    stop: &Arc<AtomicBool>,
) -> Option<JoinHandle<()>> {
    // Socket options are best effort. A failure shows up as an I/O error
    // in the loop.
    drop(tcp.set_nonblocking(false));
    drop(tcp.set_nodelay(true));
    drop(tcp.set_read_timeout(Some(POLL)));
    drop(tcp.set_write_timeout(Some(WRITE_TIMEOUT)));
    let link = Arc::new(ConnLink::default());
    let (id, ordinal, acceptor, gap, max) = {
        let mut st = shared.lock();
        st.next_conn = st.next_conn.wrapping_add(1);
        let id = st.next_conn;
        let slot = st.slots.get_mut(index)?;
        slot.conn_count = slot.conn_count.wrapping_add(1);
        let ordinal = slot.conn_count;
        let chunking = slot.opts.chunking;
        let acceptor = slot.opts.acceptor.clone();
        let gap = slot.opts.chunk_gap;
        st.model.conn_opened(
            id,
            index,
            Arc::clone(&link),
            peer.ip().to_string(),
            chunking,
        );
        let max = st.model.cfg.max_frame_len;
        (id, ordinal, acceptor, gap, max)
    };
    let closer = Arc::clone(shared);
    let shared = Arc::clone(shared);
    let stop = Arc::clone(stop);
    let spawned = thread::Builder::new()
        .name(format!("zk-fake-conn-{id}"))
        .spawn(move || {
            let io = match acceptor {
                Some(a) => a.accept(tcp),
                None => Ok(Box::new(tcp) as Box<dyn Transport>),
            };
            match io {
                Ok(io) => Conn {
                    shared,
                    index,
                    id,
                    ordinal,
                    link,
                    stop,
                    io,
                    gap,
                    head: Vec::new(),
                    head_done: false,
                    dec: FrameDecoder::new(Some(max)),
                    pending: VecDeque::new(),
                    frames: 0,
                    handshaken: false,
                    stalled: false,
                    out_stalled: false,
                    closing: false,
                    pause_until: None,
                    sasl: None,
                }
                .run(),
                Err(_) => {
                    shared.lock().model.conn_closed(id);
                    shared.changed.notify_all();
                }
            }
        });
    match spawned {
        Ok(h) => Some(h),
        Err(_) => {
            closer.lock().model.conn_closed(id);
            None
        }
    }
}

/// The modifiers of the model reply that a rule asks for.
#[derive(Debug, Clone, Copy, Default)]
struct Mods {
    drop: bool,
    header_only: bool,
    xid: Option<i32>,
    err: Option<i32>,
    truncate: Option<usize>,
    style: Option<HandshakeStyle>,
    split: Option<usize>,
    invalid: bool,
}

impl Mods {
    fn of(actions: &[Action]) -> Self {
        let mut m = Self::default();
        for a in actions {
            match a {
                Action::DropReply => m.drop = true,
                Action::HeaderOnly => m.header_only = true,
                Action::RewriteXid(x) => m.xid = Some(*x),
                Action::RewriteErr(e) => m.err = Some(*e),
                Action::TruncateReply(n) => m.truncate = Some(*n),
                Action::Handshake { style, split_at } => {
                    m.style = Some(*style);
                    m.split = *split_at;
                }
                Action::ExpiredHandshake => m.invalid = true,
                _ => {}
            }
        }
        m
    }
}

/// True for an action that runs the model.
const fn runs_model(a: &Action) -> bool {
    matches!(
        a,
        Action::Model
            | Action::DropReply
            | Action::HeaderOnly
            | Action::RewriteXid(_)
            | Action::RewriteErr(_)
            | Action::TruncateReply(_)
            | Action::Handshake { .. }
            | Action::ExpiredHandshake
    )
}

/// The frame that a rule runs on.
enum Ctx<'a> {
    Connect(&'a ConnectInfo),
    Request { xid: i32, op: i32, body: &'a [u8] },
}

impl Ctx<'_> {
    const fn xid(&self) -> i32 {
        match self {
            Self::Connect(_) => 0,
            Self::Request { xid, .. } => *xid,
        }
    }
}

/// One connection thread.
struct Conn {
    shared: Arc<Shared>,
    index: usize,
    id: u64,
    ordinal: u64,
    link: Arc<ConnLink>,
    stop: Arc<AtomicBool>,
    io: Box<dyn Transport>,
    gap: Duration,
    head: Vec<u8>,
    head_done: bool,
    dec: FrameDecoder,
    pending: VecDeque<Vec<u8>>,
    frames: u64,
    handshaken: bool,
    stalled: bool,
    out_stalled: bool,
    closing: bool,
    pause_until: Option<Instant>,
    /// The DIGEST-MD5 exchange of this connection.
    sasl: Option<sasl::DigestServer>,
}

impl Conn {
    fn run(mut self) {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if self.stop.load(Ordering::SeqCst) || self.link.killed() {
                break;
            }
            if !self.flush() {
                break;
            }
            match self.io.read(&mut buf) {
                Ok(0) => {
                    // The peer closed its side. Handle what arrived, send
                    // what can go out, then close.
                    self.process_pending();
                    let _sent = self.flush();
                    break;
                }
                Ok(n) => self.on_bytes(buf.get(..n).unwrap_or_default()),
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
            self.process_pending();
        }
        let graceful = !self.stop.load(Ordering::SeqCst) && !self.link.killed();
        self.io.finish(graceful);
        drop(self.io.tcp().shutdown(Shutdown::Both));
        self.shared.lock().model.conn_closed(self.id);
        self.shared.changed.notify_all();
    }

    /// Writes queued output until the queue is empty, a pause holds it, or
    /// the connection must close. It returns false to close.
    fn flush(&mut self) -> bool {
        loop {
            if self.out_stalled {
                return true;
            }
            if let Some(t) = self.pause_until {
                if Instant::now() < t {
                    return true;
                }
                self.pause_until = None;
            }
            if self.link.killed() || self.stop.load(Ordering::SeqCst) {
                return false;
            }
            let Some(item) = self.link.pop() else {
                return true;
            };
            match item {
                Out::Pause(d) => match Instant::now().checked_add(d) {
                    Some(t) => self.pause_until = Some(t),
                    None => self.out_stalled = true,
                },
                Out::Bytes { data, chunks } => {
                    if self.write_chunks(&data, &chunks).is_err() {
                        return false;
                    }
                }
                Out::Close => return false,
                Out::Stall => self.out_stalled = true,
            }
        }
    }

    fn write_chunks(&mut self, data: &[u8], chunks: &[usize]) -> io::Result<()> {
        let mut at = 0usize;
        for c in chunks {
            if at > 0 && !self.gap.is_zero() {
                thread::sleep(self.gap);
            }
            let end = at.saturating_add(*c).min(data.len());
            self.io.write_all(data.get(at..end).unwrap_or_default())?;
            self.io.flush()?;
            at = end;
        }
        if at < data.len() {
            self.io.write_all(data.get(at..).unwrap_or_default())?;
            self.io.flush()?;
        }
        Ok(())
    }

    fn on_bytes(&mut self, data: &[u8]) {
        if self.closing {
            return;
        }
        let mut data = data;
        if !self.head_done {
            let take = 4usize.saturating_sub(self.head.len()).min(data.len());
            let (a, b) = data.split_at_checked(take).unwrap_or((data, &[]));
            self.head.extend_from_slice(a);
            data = b;
            if self.head.len() < 4 {
                return;
            }
            self.head_done = true;
            let head = core::mem::take(&mut self.head);
            if FOUR_LETTER.iter().any(|w| w.as_slice() == head.as_slice()) {
                self.four_letter(head);
                return;
            }
            if !self.feed(&head) {
                return;
            }
        }
        self.feed(data);
    }

    /// Pushes bytes into the frame decoder. It returns false after a bad
    /// length prefix, which closes the connection.
    fn feed(&mut self, data: &[u8]) -> bool {
        let mut data = data;
        loop {
            let (n, p) = self.dec.push(data);
            data = data.get(n..).unwrap_or_default();
            match p {
                Pushed::Frame(f) => self.pending.push_back(f),
                Pushed::NeedMore => return true,
                Pushed::Error(e) => {
                    self.process_pending();
                    let shared = Arc::clone(&self.shared);
                    let mut st = shared.lock();
                    self.record_error(&mut st, self.frames, Vec::new(), e.to_string());
                    drop(st);
                    shared.changed.notify_all();
                    self.close();
                    return false;
                }
            }
            if data.is_empty() {
                return true;
            }
        }
    }

    fn close(&mut self) {
        self.closing = true;
        self.link.push(Out::Close);
    }

    fn rec(&self, st: &State, frame: u64, kind: FrameKind, body: Vec<u8>) -> FrameRecord {
        FrameRecord {
            seq: 0,
            server: self.index,
            conn: self.id,
            conn_ordinal: self.ordinal,
            frame,
            kind,
            session_id: st.model.session_of(self.id),
            xid: None,
            op: None,
            path: None,
            detail: Detail::None,
            body,
            rule: None,
            handled: true,
        }
    }

    /// Records a frame that the server cannot parse.
    fn record_error(&self, st: &mut State, frame: u64, body: Vec<u8>, error: String) {
        let rec = self.rec(st, frame, FrameKind::Unparsable, body);
        st.record(FrameRecord {
            detail: Detail::Error(error),
            ..rec
        });
    }

    /// Answers a four-letter word and closes, as the Java server does.
    fn four_letter(&mut self, word: Vec<u8>) {
        let shared = Arc::clone(&self.shared);
        let mut st = shared.lock();
        let rec = self.rec(&st, 0, FrameKind::FourLetter, word.clone());
        st.record(rec);
        let text = String::from_utf8_lossy(&word).into_owned();
        let slot = st.slots.get(self.index);
        let read_only = slot.is_some_and(|s| s.opts.read_only);
        let answer = match text.as_str() {
            "isro" => slot
                .and_then(|s| s.opts.isro_answer.clone())
                .unwrap_or_else(|| if read_only { "ro" } else { "rw" }.to_owned()),
            "ruok" => "imok".to_owned(),
            "srvr" => {
                let conns = st
                    .model
                    .conns
                    .values()
                    .filter(|c| c.server == self.index)
                    .count();
                format!(
                    "Zookeeper version: 3.10.0-fake\nLatency min/avg/max: 0/0.0/0\n\
                     Received: {}\nSent: {}\nConnections: {conns}\nOutstanding: 0\n\
                     Zxid: 0x{:x}\nMode: {}\nNode count: {}\n",
                    st.transcript.len(),
                    st.transcript.len(),
                    st.model.zxid(),
                    if read_only { "read-only" } else { "standalone" },
                    st.model.node_count(),
                )
            }
            _ => format!("{text} is not executed because it is not in the whitelist.\n"),
        };
        st.model.send(self.id, answer.into_bytes());
        drop(st);
        shared.changed.notify_all();
        self.close();
    }

    fn process_pending(&mut self) {
        while let Some(f) = self.pending.pop_front() {
            let shared = Arc::clone(&self.shared);
            let mut st = shared.lock();
            let held = st.slots.get(self.index).is_some_and(|s| s.held);
            if held && !self.stalled && !self.closing {
                self.pending.push_front(f);
                break;
            }
            self.handle_frame(&mut st, f);
            drop(st);
            shared.changed.notify_all();
        }
    }

    fn handle_frame(&mut self, st: &mut State, body: Vec<u8>) {
        if self.closing {
            return;
        }
        let n = self.frames;
        self.frames = self.frames.wrapping_add(1);
        if self.handshaken {
            self.on_request(st, n, body);
        } else {
            self.on_connect(st, body);
        }
    }

    /// Runs the script on a frame, then records the frame with the rule
    /// that fired. It returns the actions, or `None` on a stalled
    /// connection, which does not handle the frame.
    fn decide_and_record(&self, st: &mut State, mut rec: FrameRecord) -> Option<Vec<Action>> {
        let decision = if self.stalled {
            None
        } else {
            let view = FrameView {
                connect: rec.kind == FrameKind::Connect,
                conn: self.ordinal,
                frame: rec.frame,
                op: rec.op,
                xid: rec.xid,
                path: rec.path.as_deref(),
            };
            let State { slots, model, .. } = st;
            slots
                .get_mut(self.index)
                .and_then(|s| s.opts.script.decide(&view, &mut model.rng))
        };
        rec.rule = decision.as_ref().map(|d| d.0);
        rec.handled = !self.stalled;
        st.record(rec);
        if self.stalled {
            return None;
        }
        Some(decision.map(|d| d.1).unwrap_or_default())
    }

    fn on_connect(&mut self, st: &mut State, body: Vec<u8>) {
        let info = match ConnectInfo::decode(&body) {
            Ok(i) => i,
            Err(e) => {
                self.record_error(st, 0, body, e.to_string());
                self.close();
                return;
            }
        };
        self.handshaken = true;
        let rec = FrameRecord {
            session_id: info.session_id,
            detail: Detail::Connect(info.clone()),
            ..self.rec(st, 0, FrameKind::Connect, body)
        };
        let Some(actions) = self.decide_and_record(st, rec) else {
            return;
        };
        self.execute(st, &actions, &Ctx::Connect(&info));
    }

    fn on_request(&mut self, st: &mut State, n: u64, body: Vec<u8>) {
        let mut r = Reader::new(&body);
        let Ok(hdr) = RequestHeader::decode(&mut r) else {
            self.record_error(st, n, body, "short request header".into());
            self.close();
            return;
        };
        let rest = r.rest().to_vec();
        let (path, detail) = describe(hdr.r#type, &rest);
        let rec = FrameRecord {
            xid: Some(hdr.xid),
            op: Some(hdr.r#type),
            path,
            detail,
            ..self.rec(st, n, FrameKind::Request, body)
        };
        let Some(actions) = self.decide_and_record(st, rec) else {
            return;
        };
        self.execute(
            st,
            &actions,
            &Ctx::Request {
                xid: hdr.xid,
                op: hdr.r#type,
                body: &rest,
            },
        );
    }

    /// Runs the actions of a rule in order. The model runs at most once,
    /// with every reply modifier of the rule.
    fn execute(&mut self, st: &mut State, actions: &[Action], ctx: &Ctx<'_>) {
        let mods = Mods::of(actions);
        let mut ran = false;
        let conn = self.id;
        for a in actions {
            if runs_model(a) {
                if !ran {
                    ran = true;
                    self.run_model(st, ctx, mods);
                }
                continue;
            }
            match a {
                Action::Delay(d) => st.model.push(conn, Out::Pause(*d)),
                Action::Reply { err } => {
                    st.model
                        .send(conn, header(ctx.xid(), st.model.zxid(), *err, None));
                }
                Action::ReplyWith { err, body } => {
                    let r = header(ctx.xid(), st.model.zxid(), *err, Some(body.clone()));
                    st.model.send(conn, r);
                }
                Action::Unsolicited {
                    xid,
                    zxid,
                    err,
                    body,
                } => st
                    .model
                    .send(conn, header(*xid, *zxid, *err, Some(body.clone()))),
                Action::Notify {
                    event_type,
                    state,
                    path,
                } => {
                    let z = st.model.zxid();
                    st.model.notify(conn, *event_type, *state, path, z);
                }
                Action::SendFrame(body) => {
                    let mut out = Vec::new();
                    encode_frame(body, &mut out);
                    st.model.send(conn, out);
                }
                Action::SendRaw(bytes) => st.model.send(conn, bytes.clone()),
                Action::Malformed(m) => st.model.send(conn, m.to_bytes()),
                Action::Close => {
                    self.close();
                    return;
                }
                Action::Stall => {
                    self.stalled = true;
                    self.link.push(Out::Stall);
                    return;
                }
                Action::ExpireSession => {
                    let s = st.model.session_of(conn);
                    if s != 0 {
                        st.model.expire_session(s);
                    }
                    self.close();
                    return;
                }
                Action::RejectAuth => {
                    let r = header(ctx.xid(), 0, zk_jute::rc::ZAUTHFAILED, None);
                    st.model.send(conn, r);
                    self.close();
                    return;
                }
                Action::Chunking(c) => {
                    if let Some(e) = st.model.conns.get_mut(&conn) {
                        e.chunking = *c;
                    }
                }
                _ => {}
            }
        }
        if !ran && !actions.iter().any(Action::answers) {
            self.run_model(st, ctx, mods);
        }
    }

    fn run_model(&mut self, st: &mut State, ctx: &Ctx<'_>, mods: Mods) {
        let slot = st.slots.get(self.index);
        let read_only = slot.is_some_and(|s| s.opts.read_only);
        let style = mods
            .style
            .or_else(|| slot.map(|s| s.opts.handshake))
            .unwrap_or_default();
        match ctx {
            Ctx::Connect(info) => self.connect_reply(st, info, read_only, style, mods),
            Ctx::Request { xid, op, body } => {
                let h = match self.sasl_request(st, *xid, *op, body) {
                    Some(h) => h,
                    None => st.model.handle_request(self.id, *xid, *op, body, read_only),
                };
                self.request_reply(st, h, mods);
            }
        }
    }

    /// Answers a connect request in the handshake form, with the reply
    /// modifiers of the rule.
    fn connect_reply(
        &mut self,
        st: &mut State,
        info: &ConnectInfo,
        read_only: bool,
        style: HandshakeStyle,
        mods: Mods,
    ) {
        let conn = self.id;
        let (resp, close) = match st.model.handle_connect(conn, info, read_only, mods.invalid) {
            ConnectOutcome::Close => {
                self.close();
                return;
            }
            ConnectOutcome::Respond { resp, close } => (resp, close),
        };
        let mut body = resp.to_bytes();
        if style == HandshakeStyle::Legacy36 {
            body.truncate(zk_jute::handshake::CONNECT_RESPONSE_OLD_LEN);
        }
        let mut frame = Vec::new();
        encode_frame(&body, &mut frame);
        if let Some(n) = mods.truncate {
            frame.truncate(n);
        }
        if !mods.drop {
            let len = frame.len();
            match mods.split.filter(|at| *at > 0 && *at < len) {
                Some(at) => st
                    .model
                    .send_chunks(conn, frame, vec![at, len.saturating_sub(at)]),
                None => st.model.send(conn, frame),
            }
        }
        if close {
            self.close();
        }
    }

    /// Sends the result of a request with the reply modifiers of the rule.
    fn request_reply(&mut self, st: &mut State, h: Handled, mods: Mods) {
        if let Some(mut r) = h.reply {
            if let Some(x) = mods.xid {
                r.xid = x;
            }
            if let Some(e) = mods.err {
                r.err = e;
            }
            if mods.header_only {
                r.body = None;
            }
            let mut bytes = r.encode();
            if let Some(n) = mods.truncate {
                bytes.truncate(n);
            }
            if !mods.drop {
                st.model.send(self.id, bytes);
            }
        }
        if h.close {
            self.close();
        }
    }
}

impl Conn {
    /// Answers a SASL request when the listener has a DIGEST-MD5 user.
    /// A failure gets `ZAUTHFAILED` and a close, as in the Java server.
    /// With no user it gives `None`, and the model refuses SASL.
    fn sasl_request(&mut self, st: &State, xid: i32, op: i32, body: &[u8]) -> Option<Handled> {
        if op != opcode::SASL {
            return None;
        }
        let (user, password) = st.slots.get(self.index)?.sasl.clone()?;
        let id = self.id;
        let server = self
            .sasl
            .get_or_insert_with(|| sasl::DigestServer::new(user, password, id));
        let token = GetSASLRequest::from_bytes(body)
            .ok()
            .and_then(|q| q.token.into_bytes())
            .unwrap_or_default();
        Some(match server.step(&token) {
            Some(out) => {
                let resp = SetSASLResponse {
                    token: JBuffer::Bytes(out),
                };
                answer(xid, st.model.zxid(), Ok(Some(resp.to_bytes())), false)
            }
            None => answer(xid, 0, Err(zk_jute::rc::ZAUTHFAILED), true),
        })
    }
}

fn header(xid: i32, zxid: i64, err: i32, body: Option<Vec<u8>>) -> Vec<u8> {
    Reply {
        xid,
        zxid,
        err,
        body,
    }
    .encode()
}

/// One listener of a [`Cluster`].
///
/// The listener binds `127.0.0.1` with a free port. [`FakeServer::stop`]
/// closes the port and every connection, so a new connect gets a refusal.
/// [`FakeServer::restart`] binds the same port again. Drop stops the
/// listener.
#[derive(Debug)]
pub struct FakeServer {
    cluster: Cluster,
    index: usize,
    addr: SocketAddr,
    ctl: Option<ListenerCtl>,
}

impl FakeServer {
    /// Starts a listener on a new cluster with the default settings.
    ///
    /// # Errors
    ///
    /// Returns the bind error.
    pub fn start() -> io::Result<Self> {
        Self::start_with(ClusterConfig::default(), ServerOptions::default())
    }

    /// Starts a listener on a new cluster.
    ///
    /// # Errors
    ///
    /// Returns the bind error.
    pub fn start_with(cfg: ClusterConfig, opts: ServerOptions) -> io::Result<Self> {
        Cluster::new(cfg).start_server(opts)
    }

    /// Returns the socket address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Returns `127.0.0.1:<port>`.
    #[must_use]
    pub fn connect_string(&self) -> String {
        self.addr.to_string()
    }

    /// Returns the listener index in the cluster.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Returns the cluster.
    #[must_use]
    pub const fn cluster(&self) -> &Cluster {
        &self.cluster
    }

    /// Returns true while the listener accepts connections.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.ctl.is_some()
    }

    fn slot<T>(&self, f: impl FnOnce(&mut Slot) -> T) -> Option<T> {
        self.cluster.with(|st| st.slots.get_mut(self.index).map(f))
    }

    /// Stops the listener and closes its connections. The sessions stay
    /// in the model and expire on their timeout.
    pub fn stop(&mut self) {
        if let Some(mut c) = self.ctl.take() {
            c.stop();
        }
    }

    /// Stops the listener, then binds the same port again. With
    /// `keep_sessions` the sessions stay valid and their expiry clocks
    /// restart, as on a Java server that loads its sessions. Without it
    /// every session expires.
    ///
    /// # Errors
    ///
    /// Returns the bind error after two seconds of retries.
    pub fn restart(&mut self, keep_sessions: bool) -> io::Result<()> {
        self.stop();
        self.cluster.with(|st| {
            if keep_sessions {
                st.model.touch_all();
            } else {
                st.model.expire_all();
            }
        });
        self.resume()
    }

    /// Binds the port again after [`FakeServer::stop`]. The model does not
    /// change.
    ///
    /// # Errors
    ///
    /// Returns the bind error after two seconds of retries.
    pub fn resume(&mut self) -> io::Result<()> {
        if self.ctl.is_some() {
            return Ok(());
        }
        let deadline = Instant::now().checked_add(Duration::from_secs(2));
        let listener = loop {
            match TcpListener::bind(self.addr) {
                Ok(l) => break l,
                Err(e) => {
                    if deadline.is_none_or(|d| Instant::now() >= d) {
                        return Err(e);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        };
        self.ctl = Some(spawn_listener(&self.cluster.shared, self.index, listener)?);
        Ok(())
    }

    /// Adds a fault rule at the end of the script.
    pub fn add_rule(&self, rule: Rule) {
        self.slot(|s| s.opts.script.push(rule));
    }

    /// Replaces the script.
    pub fn set_script(&self, script: Script) {
        self.slot(|s| s.opts.script = script);
    }

    /// Removes every rule.
    pub fn clear_rules(&self) {
        self.slot(|s| s.opts.script.clear());
    }

    /// Returns a copy of the script, with the fire counts.
    #[must_use]
    pub fn script(&self) -> Script {
        self.slot(|s| s.opts.script.clone()).unwrap_or_default()
    }

    /// Switches read-only mode. It applies to new connections and to new
    /// requests on open connections.
    pub fn set_read_only(&self, read_only: bool) {
        self.slot(|s| s.opts.read_only = read_only);
    }

    /// Sets the answer to `isro`. `None` gives `ro` or `rw` from the mode.
    pub fn set_isro_answer(&self, answer: Option<&str>) {
        self.slot(|s| s.opts.isro_answer = answer.map(str::to_owned));
    }

    /// Sets the handshake form for new connections.
    pub fn set_handshake(&self, style: HandshakeStyle) {
        self.slot(|s| s.opts.handshake = style);
    }

    /// Sets the write chunking of new and open connections.
    pub fn set_chunking(&self, chunking: Chunking) {
        self.cluster.with(|st| {
            if let Some(s) = st.slots.get_mut(self.index) {
                s.opts.chunking = chunking;
            }
            for c in st.model.conns.values_mut() {
                if c.server == self.index {
                    c.chunking = chunking;
                }
            }
        });
    }

    /// Sets the pause between chunks for new connections.
    pub fn set_chunk_gap(&self, gap: Duration) {
        self.slot(|s| s.opts.chunk_gap = gap);
    }

    /// Stops the handling of new requests. The connections keep reading
    /// and keep the frames in arrival order. Recording happens when the
    /// server handles a frame.
    pub fn hold(&self) {
        self.slot(|s| s.held = true);
    }

    /// Handles the held requests in order and continues.
    pub fn release(&self) {
        self.slot(|s| s.held = false);
    }

    /// Returns the ids of the open connections of this listener.
    #[must_use]
    pub fn connections(&self) -> Vec<u64> {
        self.cluster.with(|st| {
            st.model
                .conns
                .iter()
                .filter(|(_, c)| c.server == self.index)
                .map(|(id, _)| *id)
                .collect()
        })
    }

    /// Returns the number of connections that the listener accepted.
    #[must_use]
    pub fn accepted(&self) -> u64 {
        self.slot(|s| s.conn_count).unwrap_or(0)
    }

    /// Closes every open connection of this listener at once, with no
    /// further output. The sessions stay.
    pub fn drop_connections(&self) {
        self.cluster.with(|st| {
            for c in st.model.conns.values() {
                if c.server == self.index {
                    c.link.kill();
                }
            }
        });
    }

    /// Accepts DIGEST-MD5 SASL for `user` with `password` on new SASL
    /// exchanges. The realm and the server name are `zk-sasl-md5`, and
    /// the service is `zookeeper`, as the client defaults give. Without
    /// this call, a SASL request gets `ZAUTHFAILED`.
    pub fn set_sasl_digest(&self, user: &str, password: &str) {
        self.slot(|s| s.sasl = Some((user.to_owned(), password.to_owned())));
    }

    /// Writes bytes to every open connection of this listener.
    pub fn send_raw(&self, bytes: &[u8]) {
        for id in self.connections() {
            self.cluster.with(|st| st.model.send(id, bytes.to_vec()));
        }
    }

    /// Returns the frames that this listener recorded.
    #[must_use]
    pub fn transcript(&self) -> Vec<FrameRecord> {
        self.cluster
            .transcript()
            .into_iter()
            .filter(|r| r.server == self.index)
            .collect()
    }

    /// Waits for a frame of this listener that matches `pred`.
    pub fn wait_for(
        &self,
        timeout: Duration,
        mut pred: impl FnMut(&FrameRecord) -> bool,
    ) -> Option<FrameRecord> {
        let index = self.index;
        self.cluster
            .wait_for_frame(timeout, |r| r.server == index && pred(r))
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A set of listeners on one cluster, for failover tests.
#[derive(Debug)]
pub struct Ensemble {
    cluster: Cluster,
    servers: Vec<FakeServer>,
}

impl Ensemble {
    /// Starts `n` listeners with the default options.
    ///
    /// # Errors
    ///
    /// Returns the first bind error.
    pub fn start(n: usize, cfg: ClusterConfig) -> io::Result<Self> {
        let cluster = Cluster::new(cfg);
        let servers = (0..n)
            .map(|_| cluster.start_server(ServerOptions::default()))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { cluster, servers })
    }

    /// Returns the comma-separated addresses.
    #[must_use]
    pub fn connect_string(&self) -> String {
        self.servers
            .iter()
            .map(FakeServer::connect_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Returns the cluster.
    #[must_use]
    pub const fn cluster(&self) -> &Cluster {
        &self.cluster
    }

    /// Returns the listeners.
    #[must_use]
    pub fn servers(&self) -> &[FakeServer] {
        &self.servers
    }

    /// Returns one listener.
    #[must_use]
    pub fn server(&self, i: usize) -> Option<&FakeServer> {
        self.servers.get(i)
    }

    /// Returns one listener for stop and restart.
    pub fn server_mut(&mut self, i: usize) -> Option<&mut FakeServer> {
        self.servers.get_mut(i)
    }
}
