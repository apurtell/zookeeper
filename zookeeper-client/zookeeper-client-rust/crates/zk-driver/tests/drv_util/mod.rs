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

//! The flavor harness of the `drv_*` driver tests.
//!
//! One trait, [`Drv`], covers the four driver flavors:
//!
//! - [`NativeDrv`]: the native threaded driver (`native::start`).
//! - [`TokioDrv`]: the tokio task driver on a current-thread runtime.
//! - [`MtDrv`]: `threaded::Shared`. Two test threads stand in for the C
//!   IO and dispatch loops (`do_io`, `do_completion`).
//! - [`StDrv`]: `polled::Polled`. The test thread is the application
//!   event loop of `libzookeeper_st`.
//!
//! Each flavor records the items that it delivers as [`Ev`] values. A
//! [`Hook`] runs on each delivered item, with the handle API, so a test
//! can call back into the driver from an item handler.

#![allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use zk_driver::native::{Spawn, ThreadBody};
use zk_driver::net::tls::TlsConnector;
use zk_driver::outbox::{Flavor, Item};
use zk_driver::{
    Discarded, DriverConfig, Env, HostLeaves, Init, InitArgs, InitStep, InterestOut, NativeHandle,
    Outbox, Polled, ResumeAt, Role, RouteSink, Shared, Step, ThreadOp, ThreadRole, Unlocked,
};
use zk_fakeserver::{Cluster, ClusterConfig, FrameKind, FrameRecord};
use zk_jute::data::{ACL, Id};
use zk_jute::{JBuffer, JString, JVec};
use zk_proto::legacy::connect::parse_init;
use zk_proto::{
    ClientId, Compat, Config, Connection, DriverMode, HostResolution, HostSpec, InputDefect,
    LogLevel, LogSite, Millis, MultiOp, Op, PathIn, Reply, Request, ResolveError, Route,
    WatchedEvent,
};
use zk_testkit::tokens::{CompletionId, TestTokens, WatcherId};

/// The wait budget of one test step.
///
/// Miri runs the driver and the fake server many times slower, and more
/// slowly again on a loaded host. So under Miri the budget is 60 s. A
/// budget only limits a wait for a condition, so a longer budget does
/// not change what a test checks. One exception applies: under Miri,
/// `close_with_outstanding` also uses the budget as its time bound.
pub const WAIT: Duration = if cfg!(miri) {
    Duration::from_secs(60)
} else {
    Duration::from_secs(5)
};

/// The session timeout of the tests. The ping interval is T/3 = 500 ms
/// and the receive timeout is 2T/3 = 1000 ms.
pub const SESSION_MS: i32 = 1_500;

/// The `getaddrinfo` rc of [`DrvHost`] for a host that is not an IP
/// literal (`EAI_NONAME` on Linux).
pub const EAI_NONAME: i32 = -2;

/// The default watcher of every handle. Session events then reach the
/// outbox (zookeeper.c `queue_session_event`).
pub const DEFAULT_WATCHER: WatcherId = WatcherId {
    fn_id: 0,
    ctx_id: 0,
};

/// Returns a cluster that accepts the short session and never expires
/// it, so receive-timeout and reconnect tests resume the same session.
/// Under Miri the cluster also accepts sessions up to 300 s. The tests
/// with no rule about time then get a long receive timeout.
pub fn cluster_config() -> ClusterConfig {
    let base = ClusterConfig::default();
    let max = if cfg!(miri) {
        300_000
    } else {
        base.max_session_timeout_ms
    };
    ClusterConfig {
        min_session_timeout_ms: 1_000,
        max_session_timeout_ms: max,
        session_expiry: false,
        ..base
    }
}

/// Returns a new cluster with [`cluster_config`].
pub fn cluster() -> Cluster {
    Cluster::new(cluster_config())
}

/// Host leaves with no DNS. They resolve IP literals only and record
/// each resolved name and each discarded token.
#[derive(Debug, Default)]
pub struct DrvHost {
    pub discarded: Mutex<Vec<&'static str>>,
    pub resolved: Mutex<Vec<String>>,
}

impl DrvHost {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn discarded(&self) -> Vec<&'static str> {
        self.discarded.lock().unwrap().clone()
    }

    pub fn resolved(&self) -> Vec<String> {
        self.resolved.lock().unwrap().clone()
    }
}

impl HostLeaves<TestTokens> for DrvHost {
    fn discard_token(&self, token: Discarded<TestTokens>) {
        let kind = match token {
            Discarded::Completion(_) => "completion",
            Discarded::Watcher(_) => "watcher",
            Discarded::Auth(_) => "auth",
        };
        self.discarded.lock().unwrap().push(kind);
    }

    fn snapshot_default_watcher(&self) -> Option<WatcherId> {
        Some(DEFAULT_WATCHER)
    }

    fn store_client_id(&self, _id: &ClientId) {}

    fn log_enabled(&self, level: LogLevel) -> bool {
        level.code() <= LogLevel::Debug.code()
    }

    fn conn_permute_disabled(&self) -> bool {
        true
    }

    fn rng_random(&self) -> i64 {
        7
    }

    fn rng_drand48(&self) -> f64 {
        0.5
    }

    fn rng_reseed(&self, _proof: &Unlocked) {}

    fn resolve(&self, _proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution {
        let name = String::from_utf8_lossy(spec.host_bytes()).into_owned();
        self.resolved.lock().unwrap().push(name.clone());
        let port = match spec {
            HostSpec::Legacy(h) => u16::try_from(h.port).ok(),
            HostSpec::Native(h) => Some(h.port),
        };
        let result = match (name.parse::<IpAddr>().ok(), port) {
            (Some(ip), Some(port)) => Ok(vec![SocketAddr::new(ip, port)]),
            _ => Err(ResolveError {
                gai_rc: EAI_NONAME,
                errno: 0,
            }),
        };
        HostResolution {
            host,
            result,
            skipped_families: Vec::new(),
        }
    }
}

/// One delivered item, in a form that tests compare.
#[derive(Clone, Debug)]
pub enum Ev {
    Log(LogSite),
    Result {
        id: u64,
        rc: i32,
        reply: Option<Reply>,
    },
    Watch {
        event: WatchedEvent,
        watchers: Vec<WatcherId>,
    },
    Session(i32),
    Auth(i32),
    Thread(ThreadOp, ThreadRole),
    Other(&'static str),
    /// A broken outbox rule, found by the harness.
    Violation(String),
}

/// Maps one item. The delivery logs come first, as C emits them before
/// the callback.
pub fn evs_of(item: &Item<TestTokens>) -> Vec<Ev> {
    let logs = |l: &[zk_proto::LogRecord]| l.iter().map(|r| Ev::Log(r.site)).collect::<Vec<_>>();
    match item {
        Item::Log(r) => vec![Ev::Log(r.site)],
        Item::Result {
            token,
            result,
            delivery_logs,
        } => {
            let mut v = logs(delivery_logs);
            v.push(Ev::Result {
                id: token.id(),
                rc: result.rc,
                reply: result.reply.clone(),
            });
            v
        }
        Item::AuthResult { rc, .. } => vec![Ev::Auth(*rc)],
        Item::Watch {
            event,
            watchers,
            delivery_logs,
        } => {
            let mut v = logs(delivery_logs);
            v.push(Ev::Watch {
                event: event.clone(),
                watchers: watchers.clone(),
            });
            v
        }
        Item::Session {
            state,
            delivery_logs,
            ..
        } => {
            let mut v = logs(delivery_logs);
            v.push(Ev::Session(state.code()));
            v
        }
        Item::WatchTerminated { .. } => vec![Ev::Other("terminated")],
        Item::AuthLockpoint => vec![Ev::Other("lockpoint")],
        Item::Sasl(_) => vec![Ev::Other("sasl")],
        Item::Thread { op, role } => vec![Ev::Thread(*op, *role)],
    }
}

/// The handle API that an item handler can call (object safe).
pub trait Api {
    /// Submits a request and returns the submit rc (0 for queued).
    fn api_submit(&self, req: Request<TestTokens>) -> i32;
    fn api_state(&self) -> i32;
    fn api_client_id(&self) -> ClientId;
}

/// An item handler. It runs on the delivering thread, after the item
/// leaves the outbox and before the driving call resumes.
pub type Hook = Arc<dyn Fn(&Ev, &dyn Api) + Send + Sync>;

/// The delivered events of one handle, in delivery order.
#[derive(Default)]
pub struct Rec {
    evs: Mutex<Vec<(Instant, Ev)>>,
    hook: Option<Hook>,
}

impl Rec {
    pub fn new(hook: Option<Hook>) -> Arc<Self> {
        Arc::new(Self {
            evs: Mutex::new(Vec::new()),
            hook,
        })
    }

    /// Records the item and runs the hook on each event.
    pub fn deliver(&self, item: &Item<TestTokens>, api: Option<&dyn Api>) {
        for ev in evs_of(item) {
            self.evs.lock().unwrap().push((Instant::now(), ev.clone()));
            if let (Some(hook), Some(api)) = (&self.hook, api) {
                hook(&ev, api);
            }
        }
    }

    pub fn push(&self, ev: Ev) {
        self.evs.lock().unwrap().push((Instant::now(), ev));
    }

    pub fn all(&self) -> Vec<Ev> {
        self.evs
            .lock()
            .unwrap()
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }

    pub fn timed(&self) -> Vec<(Instant, Ev)> {
        self.evs.lock().unwrap().clone()
    }

    /// Returns `(token id, rc)` of each result, in delivery order.
    pub fn results(&self) -> Vec<(u64, i32)> {
        self.all()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Result { id, rc, .. } => Some((id, rc)),
                _ => None,
            })
            .collect()
    }

    pub fn result(&self, want: u64) -> Option<(i32, Option<Reply>)> {
        self.all().into_iter().find_map(|e| match e {
            Ev::Result { id, rc, reply } if id == want => Some((rc, reply)),
            _ => None,
        })
    }

    pub fn has_log(&self, site: LogSite) -> bool {
        self.all()
            .iter()
            .any(|e| matches!(e, Ev::Log(s) if *s == site))
    }

    pub fn violations(&self) -> Vec<String> {
        self.all()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Violation(v) => Some(v),
                _ => None,
            })
            .collect()
    }
}

/// The start options of one handle.
pub struct Opts {
    pub hosts: String,
    pub session_ms: i32,
    pub read_only: bool,
    pub tls: Option<Arc<dyn TlsConnector>>,
    pub hook: Option<Hook>,
    pub host: Arc<DrvHost>,
    /// The `Drain` close deadline of the native flavors.
    pub close_timeout_ms: u32,
}

impl Opts {
    pub fn new(hosts: &str) -> Self {
        Self {
            hosts: hosts.to_owned(),
            session_ms: SESSION_MS,
            read_only: false,
            tls: None,
            hook: None,
            host: DrvHost::new(),
            close_timeout_ms: 2_000,
        }
    }

    fn env(&self, native: bool) -> Env<TestTokens> {
        let leaves: Arc<dyn HostLeaves<TestTokens>> = self.host.clone();
        let mut env = Env::new(leaves);
        env.tls.clone_from(&self.tls);
        env.cfg = DriverConfig {
            close_flush_ms: 1_000,
            close_wait_ms: 1_000,
            cloexec: native,
            ..DriverConfig::default()
        };
        env
    }

    fn legacy_cfg(&self) -> Config {
        let mut cfg = Config::legacy(self.session_ms);
        cfg.allow_read_only = self.read_only;
        cfg.tls = self.tls.is_some();
        cfg
    }

    /// Makes a native connection (`Compat::NATIVE`).
    fn native_connection(&self) -> Box<Connection<TestTokens>> {
        let mut cfg = self.legacy_cfg();
        let cs = parse_init(self.hosts.as_bytes()).expect("valid connect string");
        cfg.hosts = cs.hosts.into_iter().map(HostSpec::Legacy).collect();
        cfg.host_text = JString::Bytes(cs.host_text);
        cfg.chroot = cs.chroot.map(JString::Bytes);
        cfg.close_timeout_ms = self.close_timeout_ms;
        let leaves: Arc<dyn HostLeaves<TestTokens>> = self.host.clone();
        let (rng, filter, watcher) = zk_driver::host::connection_hooks(&leaves);
        Box::new(Connection::new(
            cfg,
            Compat::NATIVE,
            DriverMode::NATIVE,
            rng,
            filter,
            watcher,
            Millis(0),
        ))
    }

    /// Runs the drop-in init to `Ready`. Its items go to `rec`.
    fn init(
        &self,
        mode: DriverMode,
        flavor: Flavor,
        rec: &Rec,
    ) -> (Init<TestTokens>, Outbox<TestTokens>) {
        let args = InitArgs {
            cfg: self.legacy_cfg(),
            host_string: self.hosts.clone().into_bytes(),
            compat: Compat::LEGACY_C,
            mode,
            flavor,
        };
        let mut ob = Outbox::new();
        let mut init = Init::new(args, self.env(false), &mut ob).unwrap();
        let mut proof = Unlocked::new_at_entry();
        loop {
            let step = init.step(&mut proof, &mut ob);
            while let Some(item) = ob.pop() {
                rec.deliver(&item, None);
            }
            match step {
                InitStep::More | InitStep::SaslPoint => {}
                InitStep::Ready => break,
                InitStep::Failed(e) => panic!("init failed: {e:?}"),
            }
        }
        (init, ob)
    }
}

/// Parses a host list into specs for the native `set_servers`.
pub fn specs(hosts: &str) -> Vec<HostSpec> {
    parse_init(hosts.as_bytes())
        .expect("valid host list")
        .hosts
        .into_iter()
        .map(HostSpec::Legacy)
        .collect()
}

/// One driver flavor under test.
pub trait Drv: Sized {
    const NAME: &'static str;
    /// True for the native flavors: `Compat::NATIVE`, native paths and
    /// the `Drain` close.
    const NATIVE: bool;
    fn start(o: Opts) -> Self;
    fn rec(&self) -> &Rec;
    /// Lets the driver run for a short time. st runs one round of the
    /// application loop. The threaded flavors sleep.
    fn tick(&self);
    fn submit(&self, req: Request<TestTokens>) -> i32;
    fn state(&self) -> i32;
    fn client_id(&self) -> ClientId;
    /// `zoo_set_servers` or the native `set_servers`. It returns true on
    /// success.
    fn set_servers(&self, hosts: &str) -> bool;
    /// Closes the handle and returns the close rc. The records stay.
    fn close(&self) -> i32;
}

/// Ticks `d` until `pred` is true or [`WAIT`] passes.
pub fn wait<D: Drv>(d: &D, mut pred: impl FnMut(&D) -> bool) -> bool {
    wait_for(d, WAIT, &mut pred)
}

/// Ticks `d` until `pred` is true or `timeout` passes.
pub fn wait_for<D: Drv>(d: &D, timeout: Duration, pred: &mut dyn FnMut(&D) -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if pred(d) {
            return true;
        }
        d.tick();
    }
    pred(d)
}

/// Ticks `d` for `dur`.
pub fn run_for<D: Drv>(d: &D, dur: Duration) {
    let end = Instant::now() + dur;
    while Instant::now() < end {
        d.tick();
    }
}

/// Waits for the connected state (3).
pub fn connected<D: Drv>(d: &D) {
    assert!(
        wait(d, |d| d.state() == zk_proto::State::Connected.code()),
        "{}: no session, state {}",
        D::NAME,
        d.state()
    );
}

/// Returns the connect frames of the cluster, in order.
pub fn connects(c: &Cluster) -> Vec<FrameRecord> {
    c.transcript()
        .into_iter()
        .filter(|r| r.kind == FrameKind::Connect)
        .collect()
}

// Request builders. The native flavors take native paths.

pub fn path(native: bool, p: &str) -> PathIn {
    if native {
        PathIn::Native(p.into())
    } else {
        PathIn::Legacy(Some(p.as_bytes().to_vec()))
    }
}

pub fn acl() -> JVec<ACL> {
    JVec::from(vec![ACL {
        perms: 31,
        id: Id {
            scheme: "world".into(),
            id: "anyone".into(),
        },
    }])
}

pub fn req(id: u64, op: Op<WatcherId>) -> Request<TestTokens> {
    Request {
        op,
        token: CompletionId::new(id),
        route: Route::Queued,
        defect: InputDefect::default(),
    }
}

pub fn exists(native: bool, id: u64, p: &str) -> Request<TestTokens> {
    req(
        id,
        Op::Exists {
            path: path(native, p),
            watch: None,
        },
    )
}

pub fn get_data(native: bool, id: u64, p: &str, watch: Option<WatcherId>) -> Request<TestTokens> {
    req(
        id,
        Op::GetData {
            path: path(native, p),
            watch,
        },
    )
}

pub fn create(native: bool, id: u64, p: &str, data: &[u8]) -> Request<TestTokens> {
    req(
        id,
        Op::Create {
            path: path(native, p),
            data: JBuffer::Bytes(data.to_vec()),
            acl: acl(),
            mode: 0,
            ttl: -1,
            create2: false,
        },
    )
}

pub fn multi(id: u64, ops: Vec<MultiOp>) -> Request<TestTokens> {
    req(id, Op::Multi { ops })
}

// The st flavor.

/// `polled::Polled` driven by the test thread.
pub struct StDrv {
    h: Polled<TestTokens>,
    rec: Arc<Rec>,
    /// True after the first close, by the test or by the drop.
    closed: AtomicBool,
}

struct StApi<'a>(&'a StDrv);

impl Api for StApi<'_> {
    fn api_submit(&self, req: Request<TestTokens>) -> i32 {
        let mut ob = self.0.h.outbox();
        let rc = submit_rc(self.0.h.submit(req, &mut ob));
        while let Some(item) = ob.pop() {
            self.0.rec.deliver(&item, None);
        }
        rc
    }

    fn api_state(&self) -> i32 {
        self.0.h.state()
    }

    fn api_client_id(&self) -> ClientId {
        self.0.h.client_id()
    }
}

fn submit_rc(r: Result<zk_proto::Submitted<TestTokens>, zk_proto::SubmitError<TestTokens>>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(e) => e.code,
    }
}

impl StDrv {
    /// Runs one driving call to its end. On each `More`, the outbox must
    /// name the step to resume.
    fn finish(
        &self,
        mut step: Step,
        ob: &mut Outbox<TestTokens>,
        out: &mut InterestOut,
        rc: &mut i32,
        want: &[ResumeAt],
    ) -> Step {
        loop {
            if step == Step::More && !ob.resume_at().is_some_and(|at| want.contains(&at)) {
                self.rec.push(Ev::Violation(format!(
                    "st More with resume {:?}, want one of {want:?}",
                    ob.resume_at()
                )));
            }
            while let Some(item) = ob.pop() {
                self.rec.deliver(&item, Some(&StApi(self)));
            }
            if step != Step::More {
                return step;
            }
            step = self.h.resume(ob, out, rc);
        }
    }
}

impl Drv for StDrv {
    const NAME: &'static str = "st";
    const NATIVE: bool = false;

    fn start(o: Opts) -> Self {
        let rec = Rec::new(o.hook.clone());
        let (init, _ob) = o.init(DriverMode::ST, Flavor::St, &rec);
        Self {
            h: Polled::from_init(init),
            rec,
            closed: AtomicBool::new(false),
        }
    }

    fn rec(&self) -> &Rec {
        &self.rec
    }

    fn tick(&self) {
        let mut ob = self.h.outbox();
        let mut out = InterestOut::UNWRITTEN;
        let mut rc = 0;
        let first = self.h.interest(&mut ob, &mut out, &mut rc);
        let step = self.finish(first, &mut ob, &mut out, &mut rc, &[ResumeAt::Interest]);
        if step == Step::Release {
            return;
        }
        // The application polls with the interest timeout, bounded so
        // that the test loop checks its condition often.
        let ms = i32::try_from(out.timeout_ms.clamp(0, 20)).unwrap_or(20);
        if out.fd < 0 {
            std::thread::sleep(Duration::from_millis(u64::try_from(ms.max(1)).unwrap_or(1)));
            return;
        }
        let events = self.h.wait_events(&out, ms);
        let mut ob = self.h.outbox();
        let first = self.h.process(events, &mut ob, &mut rc);
        self.finish(first, &mut ob, &mut out, &mut rc, &[ResumeAt::Process]);
    }

    fn submit(&self, req: Request<TestTokens>) -> i32 {
        StApi(self).api_submit(req)
    }

    fn state(&self) -> i32 {
        self.h.state()
    }

    fn client_id(&self) -> ClientId {
        self.h.client_id()
    }

    fn set_servers(&self, hosts: &str) -> bool {
        let mut ob = self.h.outbox();
        let mut out = InterestOut::UNWRITTEN;
        let mut rc = -1;
        let mut step = self.h.set_servers(hosts.as_bytes(), &mut ob, &mut rc);
        loop {
            while let Some(item) = ob.pop() {
                self.rec.deliver(&item, None);
            }
            if step != Step::More {
                break;
            }
            step = self.h.resume(&mut ob, &mut out, &mut rc);
        }
        rc == zk_proto::rc::ZOK
    }

    fn close(&self) -> i32 {
        self.closed.store(true, Ordering::Release);
        let mut ob = self.h.outbox();
        let mut out = InterestOut::UNWRITTEN;
        let mut rc = -1;
        let first = self.h.close(&mut ob, &mut rc);
        let step = self.finish(
            first,
            &mut ob,
            &mut out,
            &mut rc,
            &[ResumeAt::Close, ResumeAt::FinalClose],
        );
        assert_eq!(step, Step::Release, "st close must release");
        rc
    }
}

/// Closes a handle that the test did not close, for example after a
/// failed assertion. The close sends the close request, so the fake
/// server sees a clean end. This path runs no hook and checks nothing,
/// so it cannot panic during an unwind.
impl Drop for StDrv {
    fn drop(&mut self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut ob = self.h.outbox();
        let mut out = InterestOut::UNWRITTEN;
        let mut rc = -1;
        let mut step = self.h.close(&mut ob, &mut rc);
        loop {
            while ob.pop().is_some() {}
            if step != Step::More {
                return;
            }
            step = self.h.resume(&mut ob, &mut out, &mut rc);
        }
    }
}

// The mt flavor.

/// `threaded::Shared` with an IO thread and a dispatch thread.
pub struct MtDrv {
    s: Arc<Shared<TestTokens>>,
    rec: Arc<Rec>,
    io: Mutex<Option<JoinHandle<()>>>,
    dispatch: Mutex<Option<JoinHandle<()>>>,
    released: Arc<Mutex<Option<i32>>>,
    /// True after the first close, by the test or by the drop.
    closed: AtomicBool,
}

struct MtApi(Arc<Shared<TestTokens>>);

impl Api for MtApi {
    fn api_submit(&self, req: Request<TestTokens>) -> i32 {
        submit_rc(self.0.submit(req))
    }

    fn api_state(&self) -> i32 {
        self.0.state()
    }

    fn api_client_id(&self) -> ClientId {
        self.0.client_id()
    }
}

/// Runs one mt driving call to its end, as the C loops do. `on_item`
/// takes each item before the next resume. It returns the last step and
/// the rc.
fn mt_drive(
    s: &Shared<TestTokens>,
    rec: &Rec,
    first: impl FnOnce(&mut Outbox<TestTokens>, &mut i32) -> Step,
    on_item: &mut dyn FnMut(Item<TestTokens>),
) -> (Step, i32) {
    let mut ob = s.outbox();
    let mut rc = 0;
    let mut step = first(&mut ob, &mut rc);
    loop {
        if step == Step::More && ob.resume_at().is_none() {
            rec.push(Ev::Violation("mt More with no resume step".to_owned()));
        }
        while let Some(item) = ob.pop() {
            on_item(item);
        }
        if step != Step::More {
            return (step, rc);
        }
        step = s.resume(&mut ob, &mut rc);
    }
}

impl MtDrv {
    fn spawn_threads(&self) {
        self.s.thread_enter(Role::Io);
        self.s.thread_enter(Role::Dispatch);
        let io = {
            let s = Arc::clone(&self.s);
            let rec = Arc::clone(&self.rec);
            let released = Arc::clone(&self.released);
            std::thread::spawn(move || {
                let api = MtApi(Arc::clone(&s));
                let mut deliver = |item: Item<TestTokens>| rec.deliver(&item, Some(&api));
                loop {
                    let (step, _) = mt_drive(&s, &rec, |ob, rc| s.io_step(ob, rc), &mut deliver);
                    if step == Step::Exit {
                        break;
                    }
                }
                let (step, rc) = mt_drive(
                    &s,
                    &rec,
                    |ob, rc| s.thread_exit(Role::Io, ob, rc),
                    &mut deliver,
                );
                if step == Step::Release {
                    *released.lock().unwrap() = Some(rc);
                }
            })
        };
        let dispatch = {
            let s = Arc::clone(&self.s);
            let rec = Arc::clone(&self.rec);
            let released = Arc::clone(&self.released);
            std::thread::spawn(move || {
                let api = MtApi(Arc::clone(&s));
                loop {
                    let mut ob = s.outbox();
                    if s.wait_dispatch(&mut ob) == Step::Exit {
                        break;
                    }
                    while let Some(item) = ob.pop() {
                        rec.deliver(&item, Some(&api));
                    }
                }
                let mut deliver = |item: Item<TestTokens>| rec.deliver(&item, Some(&api));
                let (step, rc) = mt_drive(
                    &s,
                    &rec,
                    |ob, rc| s.thread_exit(Role::Dispatch, ob, rc),
                    &mut deliver,
                );
                if step == Step::Release {
                    *released.lock().unwrap() = Some(rc);
                }
            })
        };
        *self.io.lock().unwrap() = Some(io);
        *self.dispatch.lock().unwrap() = Some(dispatch);
    }

    fn join(slot: &Mutex<Option<JoinHandle<()>>>) {
        let h = slot.lock().unwrap().take();
        if let Some(h) = h {
            h.join().unwrap();
        }
    }

    /// Joins the thread in `slot` if it ends within [`WAIT`]. A thread
    /// that does not end stays detached, so a hung driver cannot hang
    /// the drop. A panic of the thread is ignored.
    fn join_quiet(slot: &Mutex<Option<JoinHandle<()>>>) {
        let h = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
        let Some(h) = h else {
            return;
        };
        let end = Instant::now() + WAIT;
        while !h.is_finished() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        if h.is_finished() {
            let _ = h.join();
        }
    }
}

impl Drv for MtDrv {
    const NAME: &'static str = "mt";
    const NATIVE: bool = false;

    fn start(o: Opts) -> Self {
        let rec = Rec::new(o.hook.clone());
        let (init, mut ob) = o.init(DriverMode::MT, Flavor::Mt, &rec);
        let s = Shared::from_init(init, &mut ob).unwrap();
        while let Some(item) = ob.pop() {
            rec.deliver(&item, None);
        }
        let d = Self {
            s,
            rec,
            io: Mutex::new(None),
            dispatch: Mutex::new(None),
            released: Arc::new(Mutex::new(None)),
            closed: AtomicBool::new(false),
        };
        d.spawn_threads();
        d
    }

    fn rec(&self) -> &Rec {
        &self.rec
    }

    fn tick(&self) {
        std::thread::sleep(Duration::from_millis(5));
    }

    fn submit(&self, req: Request<TestTokens>) -> i32 {
        submit_rc(self.s.submit(req))
    }

    fn state(&self) -> i32 {
        self.s.state()
    }

    fn client_id(&self) -> ClientId {
        self.s.client_id()
    }

    fn set_servers(&self, hosts: &str) -> bool {
        let mut ob = self.s.outbox();
        let mut rc = -1;
        let mut step = self.s.set_servers(hosts.as_bytes(), &mut ob, &mut rc);
        loop {
            while let Some(item) = ob.pop() {
                self.rec.deliver(&item, None);
            }
            if step != Step::More {
                break;
            }
            step = self.s.resume(&mut ob, &mut rc);
        }
        rc == zk_proto::rc::ZOK
    }

    /// Closes from a foreign thread. The thread items are barriers: the
    /// closer joins the named thread before it resumes, as
    /// `zookeeper_close` does with `pthread_join`.
    fn close(&self) -> i32 {
        self.closed.store(true, Ordering::Release);
        let rec = Arc::clone(&self.rec);
        let mut on_item = |item: Item<TestTokens>| {
            if let Item::Thread { op, role } = &item {
                if *op == ThreadOp::Join {
                    match role {
                        ThreadRole::Io => Self::join(&self.io),
                        ThreadRole::Dispatch => Self::join(&self.dispatch),
                    }
                }
            }
            rec.deliver(&item, None);
        };
        let (step, rc) = mt_drive(
            &self.s,
            &self.rec,
            |ob, rc| self.s.close(Role::Foreign, ob, rc),
            &mut on_item,
        );
        Self::join(&self.io);
        Self::join(&self.dispatch);
        if step == Step::Release {
            return rc;
        }
        let rc = *self.released.lock().unwrap();
        rc.expect("mt close: no thread released the handle")
    }
}

/// Closes a handle that the test did not close and joins its threads.
///
/// A failed assertion unwinds the test with the IO and dispatch threads
/// still live. Without this drop they run on into the next tests. Under
/// Miri all threads share one interpreter, so the live threads slow the
/// next tests and fail them too. After a close that panicked, the drop
/// joins the threads that the close did not join. The drop runs no hook
/// and checks nothing, so it cannot panic during an unwind. The IO and
/// dispatch threads can still run hooks until they end.
impl Drop for MtDrv {
    fn drop(&mut self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            // A close that panicked can leave a thread unjoined. After a
            // clean close both slots are empty, so these joins do nothing.
            Self::join_quiet(&self.io);
            Self::join_quiet(&self.dispatch);
            return;
        }
        let mut on_item = |item: Item<TestTokens>| {
            if let Item::Thread {
                op: ThreadOp::Join,
                role,
            } = item
            {
                match role {
                    ThreadRole::Io => Self::join_quiet(&self.io),
                    ThreadRole::Dispatch => Self::join_quiet(&self.dispatch),
                }
            }
        };
        let _ = mt_drive(
            &self.s,
            &self.rec,
            |ob, rc| self.s.close(Role::Foreign, ob, rc),
            &mut on_item,
        );
        Self::join_quiet(&self.io);
        Self::join_quiet(&self.dispatch);
    }
}

// The native flavors.

/// A route sink that records each item. It returns false, so the read
/// gate never closes.
struct Sink<H> {
    rec: Arc<Rec>,
    h: OnceLock<Arc<H>>,
}

impl<H: Api + Send + Sync> RouteSink<TestTokens> for Sink<H> {
    fn route(&self, item: Item<TestTokens>) -> bool {
        let api = self.h.get().map(|h| &**h as &dyn Api);
        self.rec.deliver(&item, api);
        false
    }
}

/// A spawner with named std threads.
struct TestSpawner;

impl Spawn for TestSpawner {
    fn spawn(&self, name: &'static str, body: ThreadBody) -> std::io::Result<()> {
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(body)
            .map(drop)
    }
}

impl Api for NativeHandle<TestTokens> {
    fn api_submit(&self, req: Request<TestTokens>) -> i32 {
        submit_rc(self.submit(req))
    }

    fn api_state(&self) -> i32 {
        self.state()
    }

    fn api_client_id(&self) -> ClientId {
        self.client_id()
    }
}

/// The native threaded driver.
pub struct NativeDrv {
    h: Arc<NativeHandle<TestTokens>>,
    rec: Arc<Rec>,
    /// True after the first close, by the test or by the drop.
    closed: AtomicBool,
}

impl Drv for NativeDrv {
    const NAME: &'static str = "native";
    const NATIVE: bool = true;

    fn start(o: Opts) -> Self {
        let rec = Rec::new(o.hook.clone());
        let sink = Arc::new(Sink {
            rec: Arc::clone(&rec),
            h: OnceLock::new(),
        });
        let h = zk_driver::native::start(
            o.native_connection(),
            o.env(true),
            sink.clone(),
            None,
            Arc::new(TestSpawner),
        )
        .unwrap();
        let h = Arc::new(h);
        let _ = sink.h.set(Arc::clone(&h));
        Self {
            h,
            rec,
            closed: AtomicBool::new(false),
        }
    }

    fn rec(&self) -> &Rec {
        &self.rec
    }

    fn tick(&self) {
        std::thread::sleep(Duration::from_millis(5));
    }

    fn submit(&self, req: Request<TestTokens>) -> i32 {
        self.h.api_submit(req)
    }

    fn state(&self) -> i32 {
        self.h.state()
    }

    fn client_id(&self) -> ClientId {
        self.h.client_id()
    }

    fn set_servers(&self, hosts: &str) -> bool {
        self.h.set_servers(specs(hosts)) != 0
    }

    fn close(&self) -> i32 {
        self.closed.store(true, Ordering::Release);
        self.h.close();
        self.h.wait_closed(WAIT).expect("native close timed out")
    }
}

/// Closes a handle that the test did not close. The sink keeps a clone
/// of the handle, so the last drop never comes and the close on drop of
/// the driver never starts. The wait is bounded and checks nothing.
impl Drop for NativeDrv {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.h.close();
            let _ = self.h.wait_closed(WAIT);
        }
    }
}

#[cfg(all(unix, feature = "tokio"))]
pub use tokio_flavor::TokioDrv;

#[cfg(all(unix, feature = "tokio"))]
mod tokio_flavor {
    use super::*;
    use zk_driver::tokio::TaskHandle;

    impl Api for TaskHandle<TestTokens> {
        fn api_submit(&self, req: Request<TestTokens>) -> i32 {
            submit_rc(self.submit(req))
        }

        fn api_state(&self) -> i32 {
            self.state()
        }

        fn api_client_id(&self) -> ClientId {
            self.client_id()
        }
    }

    /// The tokio task driver. A dedicated thread runs the current-thread
    /// runtime, so the test thread stays free to wait.
    pub struct TokioDrv {
        h: Arc<TaskHandle<TestTokens>>,
        rec: Arc<Rec>,
        rt: tokio::runtime::Handle,
        /// True after the first close, by the test or by the drop.
        closed: AtomicBool,
        // Dropping the sender ends the runtime thread.
        _stop: tokio::sync::oneshot::Sender<()>,
    }

    impl Drv for TokioDrv {
        const NAME: &'static str = "tokio";
        const NATIVE: bool = true;

        fn start(o: Opts) -> Self {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let rt = runtime.handle().clone();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            std::thread::spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            });
            let rec = Rec::new(o.hook.clone());
            let sink = Arc::new(Sink {
                rec: Arc::clone(&rec),
                h: OnceLock::new(),
            });
            let h = Arc::new(zk_driver::tokio::spawn(
                o.native_connection(),
                o.env(true),
                sink.clone(),
                None,
                &rt,
            ));
            let _ = sink.h.set(Arc::clone(&h));
            Self {
                h,
                rec,
                rt,
                closed: AtomicBool::new(false),
                _stop: stop,
            }
        }

        fn rec(&self) -> &Rec {
            &self.rec
        }

        fn tick(&self) {
            std::thread::sleep(Duration::from_millis(5));
        }

        fn submit(&self, req: Request<TestTokens>) -> i32 {
            self.h.api_submit(req)
        }

        fn state(&self) -> i32 {
            self.h.state()
        }

        fn client_id(&self) -> ClientId {
            self.h.client_id()
        }

        fn set_servers(&self, hosts: &str) -> bool {
            self.h.set_servers(specs(hosts)) != 0
        }

        fn close(&self) -> i32 {
            self.closed.store(true, Ordering::Release);
            self.h.close();
            let (tx, rx) = mpsc::channel();
            let h = Arc::clone(&self.h);
            self.rt.spawn(async move {
                let _ = tx.send(h.closed().await);
            });
            rx.recv_timeout(WAIT).expect("tokio close timed out")
        }
    }

    /// Starts the close of a handle that the test did not close. The
    /// sink keeps a clone of the handle, so the drop alone starts no
    /// close. The stop sender drops next and ends the runtime thread.
    impl Drop for TokioDrv {
        fn drop(&mut self) {
            if !self.closed.swap(true, Ordering::AcqRel) {
                self.h.close();
            }
        }
    }
}

// Fault helpers.

/// Runs `body` on its own thread and fails when it does not end within
/// `limit`. A deadlock in the driver then fails the test, not the run.
pub fn with_deadline(limit: Duration, body: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    let t = std::thread::spawn(move || {
        body();
        let _ = tx.send(());
    });
    match rx.recv_timeout(limit) {
        Ok(()) => t.join().unwrap(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // The body panicked: give its panic to the test.
            if let Err(p) = t.join() {
                std::panic::resume_unwind(p);
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("deadlock: the body did not end in {limit:?}")
        }
    }
}

/// A TCP proxy that can end every connection with a reset (SO_LINGER
/// 0). The fake server itself only shuts a connection down.
pub struct RstProxy {
    pub addr: SocketAddr,
    kills: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
    stop: Arc<AtomicBool>,
}

impl RstProxy {
    pub fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let kills: Arc<Mutex<Vec<Arc<AtomicBool>>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (k, s) = (Arc::clone(&kills), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !s.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        // Each connection has its own flag, so a reset
                        // ends only the connections open at that time.
                        let kill = Arc::new(AtomicBool::new(false));
                        k.lock().unwrap().push(Arc::clone(&kill));
                        Self::pipe(client, upstream, kill);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
        });
        Self { addr, kills, stop }
    }

    fn pipe(client: TcpStream, upstream: SocketAddr, kill: Arc<AtomicBool>) {
        let Ok(server) = TcpStream::connect(upstream) else {
            return;
        };
        client.set_nonblocking(false).unwrap();
        // With linger 0 the last close of the socket sends RST.
        rustix::net::sockopt::set_socket_linger(&client, Some(Duration::ZERO)).unwrap();
        for s in [&client, &server] {
            s.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
            s.set_nodelay(true).unwrap();
        }
        let pump = |mut from: TcpStream, mut to: TcpStream, kill: Arc<AtomicBool>| {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !kill.load(Ordering::Acquire) {
                    match from.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if to.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
                // Both pumps drop their clones. The last drop of the
                // client socket sends the reset.
            })
        };
        let c2 = client.try_clone().unwrap();
        let s2 = server.try_clone().unwrap();
        pump(client, s2, Arc::clone(&kill));
        pump(server, c2, kill);
    }

    /// Resets every open connection.
    pub fn reset(&self) {
        for k in self.kills.lock().unwrap().drain(..) {
            k.store(true, Ordering::Release);
        }
    }
}

impl Drop for RstProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.reset();
    }
}
