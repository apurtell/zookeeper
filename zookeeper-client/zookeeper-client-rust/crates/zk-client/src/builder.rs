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

//! `ClientBuilder`, `ConnectFuture` and the runtime types.
//!
//! The builder only records values. `build` checks them, makes the
//! proto `Connection` with `Compat::NATIVE`, starts the driver and gives
//! the client. Requests queue until the first connection.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(not(feature = "tls-rustls"))]
use zk_driver::net::tls::TlsConnector;
use zk_driver::{Env, HostLeaves};
use zk_jute::JString;
use zk_proto::compat::ResolveCadence;
use zk_proto::{ClientId, Compat, Config, Connection, DriverMode, SecretBytes};

use crate::client::Client;
use crate::connect_string;
use crate::driver;
use crate::error::{ConnectError, Error};
use crate::follow;
use crate::future::ResponseFuture;
use crate::host::{NativeHost, StdResolve};
use crate::observe::{Metrics, Observer};
use crate::path::{PathArg, PathError, ZPathBuf};
use crate::route::Router;
#[cfg(any(not(feature = "tls-rustls"), feature = "sasl"))]
use crate::route::TlsErrorSource;
#[cfg(feature = "sasl")]
use crate::sasl::{LastSaslError, NativeSasl, SaslConfig};
use crate::shared::{self, ClientConfig, Shared};
#[cfg(feature = "sasl")]
use crate::sync::LockExt;
#[cfg(feature = "blocking")]
use crate::sync::blocking_refused;
#[cfg(feature = "tls-rustls")]
use crate::tls::TlsOptions;
use crate::tokens::NativeTokens;
use crate::types::{SessionId, SessionPassword};
use crate::watch::{SessionInfo, SessionState, StateCell, StateWatcher};

/// The default session timeout.
pub(crate) const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
/// The default reconnect pause.
pub(crate) const DEFAULT_RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// The reconnect jitter in percent.
pub(crate) const RECONNECT_JITTER_PCT: u8 = 25;
/// The default close timeout.
pub(crate) const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_secs(3);
/// The default frame cap: 4 MiB.
pub(crate) const DEFAULT_MAX_FRAME_SIZE: u32 = zk_proto::compat::NATIVE_MAX_FRAME_LEN;
/// The default read-gate capacity.
pub(crate) const DEFAULT_DISPATCH_QUEUE_CAPACITY: usize = 4096;

/// The order of the host list.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ServerOrder {
    /// A random order, made again for each new list.
    #[default]
    Shuffled,
    /// The order of the connect string.
    AsGiven,
}

/// When the client resolves the host names again.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum DnsRefresh {
    /// Once per pass over the host list, when the reconnect pause ends.
    #[default]
    EachPass,
    /// When more than this time has passed since the last good
    /// resolution, while connected or not.
    Interval(Duration),
    /// Only at `build` and in `update_servers`.
    Never,
}

impl DnsRefresh {
    /// Gives the proto resolve cadence and the legacy resolve delay in
    /// ms. The delay is -1 when no interval applies.
    fn proto(self) -> (ResolveCadence, i32) {
        match self {
            Self::EachPass => (ResolveCadence::EachPass, -1),
            Self::Interval(d) => (
                ResolveCadence::Throttled { ms: millis_u32(d) },
                i32::try_from(d.as_millis()).unwrap_or(i32::MAX),
            ),
            Self::Never => (ResolveCadence::Never, -1),
        }
    }
}

/// A host name resolver.
///
/// It is synchronous and can block. The thread driver calls it on its
/// IO thread with no lock held. The tokio driver calls it through
/// `spawn_blocking`. A panic counts as a resolve failure.
pub trait Resolve: Send + Sync + 'static {
    /// Resolves `host` and `port` to addresses, in the order to try.
    ///
    /// # Errors
    ///
    /// Any error makes the host fail this resolution.
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

/// The runtime of the driver.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Runtime {
    /// One IO thread for this client. It works with any executor, or
    /// with none.
    Thread(ThreadOptions),
    /// One task on this tokio runtime. Unix targets only.
    #[cfg(all(unix, feature = "tokio"))]
    Tokio(tokio::runtime::Handle),
}

/// The options of the IO thread.
#[derive(Clone, Debug, Default)]
pub struct ThreadOptions {
    /// The thread name. The default is `zk-io`. A name with a NUL byte
    /// fails `build`.
    pub name: Option<String>,
    /// The stack size in bytes. The default is the std default.
    pub stack_size: Option<usize>,
}

/// The builder of a [`Client`].
#[must_use = "a builder does nothing until connect() or build() is called"]
pub struct ClientBuilder {
    pub(crate) connect_string: String,
    pub(crate) session_timeout: Duration,
    /// The `chroot` override. A bad path fails `build`.
    pub(crate) chroot: Option<Result<ZPathBuf, PathError>>,
    pub(crate) allow_read_only: bool,
    pub(crate) session: Option<(SessionId, SessionPassword)>,
    /// The `auth` entries, in call order.
    pub(crate) auth: Vec<(String, SecretBytes)>,
    pub(crate) restore_watches: bool,
    /// `None` gives `session_timeout / 3`.
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) reconnect_delay: Duration,
    pub(crate) server_order: ServerOrder,
    pub(crate) dns_refresh: DnsRefresh,
    /// `None` gives the std resolver.
    pub(crate) resolver: Option<Arc<dyn Resolve>>,
    /// `None` gives the default runtime of `driver::default_runtime`.
    pub(crate) runtime: Option<Runtime>,
    pub(crate) update_servers_from_config: bool,
    pub(crate) max_pending: Option<usize>,
    pub(crate) max_frame_size: u32,
    pub(crate) persistent_watch_buffer: Option<usize>,
    pub(crate) dispatch_queue_capacity: usize,
    pub(crate) close_timeout: Duration,
    #[cfg(feature = "tls-rustls")]
    pub(crate) tls: Option<TlsOptions>,
    /// The native SASL configuration.
    #[cfg(feature = "sasl")]
    pub(crate) sasl: Option<SaslConfig>,
    pub(crate) metrics: Option<Arc<dyn Metrics>>,
    pub(crate) name: Option<String>,
}

impl std::fmt::Debug for ClientBuilder {
    /// Shows the settings. Credentials and the session password never
    /// show.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("ClientBuilder");
        d.field("connect_string", &self.connect_string)
            .field("session_timeout", &self.session_timeout)
            .field("auth_entries", &self.auth.len())
            .field("runtime", &self.runtime)
            .field("name", &self.name);
        // The `SaslConfig` text redacts the password.
        #[cfg(feature = "sasl")]
        d.field("sasl", &self.sasl);
        d.finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// Makes a builder with the default settings. The connect string is
    /// parsed in `connect` or `build`.
    pub(crate) fn new(connect_string: String) -> Self {
        Self {
            connect_string,
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            chroot: None,
            allow_read_only: false,
            session: None,
            auth: Vec::new(),
            restore_watches: true,
            connect_timeout: None,
            reconnect_delay: DEFAULT_RECONNECT_DELAY,
            server_order: ServerOrder::Shuffled,
            dns_refresh: DnsRefresh::EachPass,
            resolver: None,
            runtime: None,
            update_servers_from_config: false,
            max_pending: None,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            persistent_watch_buffer: None,
            dispatch_queue_capacity: DEFAULT_DISPATCH_QUEUE_CAPACITY,
            close_timeout: DEFAULT_CLOSE_TIMEOUT,
            #[cfg(feature = "tls-rustls")]
            tls: None,
            #[cfg(feature = "sasl")]
            sasl: None,
            metrics: None,
            name: None,
        }
    }

    /// Sets the requested session timeout. The default is 30 s. The
    /// server negotiates the final value. The value must be at least
    /// 1 ms, else `build` and `connect` fail with
    /// `Error::InvalidArgument`.
    pub fn session_timeout(mut self, t: Duration) -> Self {
        self.session_timeout = t;
        self
    }

    /// Sets the chroot. It overrides a chroot suffix of the connect
    /// string. `/` means no chroot.
    pub fn chroot(mut self, chroot: impl PathArg) -> Self {
        self.chroot = Some(chroot.to_zpath().map(|p| p.to_buf()));
        self
    }

    /// Allows read-only servers. The default is false.
    pub fn allow_read_only(mut self, yes: bool) -> Self {
        self.allow_read_only = yes;
        self
    }

    /// Resumes a session.
    pub fn session(mut self, id: SessionId, password: SessionPassword) -> Self {
        self.session = Some((id, password));
        self
    }

    /// Adds an auth entry. Entries go out first on every connection, in
    /// call order. The data is wiped when the client drops.
    pub fn auth(mut self, scheme: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        self.auth
            .push((scheme.into(), SecretBytes::new(data.into())));
        self
    }

    /// Restores watches after a reconnect. The default is true.
    pub fn restore_watches(mut self, yes: bool) -> Self {
        self.restore_watches = yes;
        self
    }

    /// Bounds each TCP connect attempt. The default is a third of the
    /// session timeout. The value, or the default, must be at least
    /// 1 ms, else `build` and `connect` fail with
    /// `Error::InvalidArgument`.
    pub fn connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = Some(t);
        self
    }

    /// Sets the base pause after a full pass over the host list. The
    /// default is 1 s. The first pass has no pause. After each later
    /// failed pass, the pause doubles up to 30 s, or up to this value
    /// when it is larger. Each pause has 25% jitter. An established
    /// session resets the pause to the base value.
    pub fn reconnect_delay(mut self, t: Duration) -> Self {
        self.reconnect_delay = t;
        self
    }

    /// Sets the host order. The default is `Shuffled`.
    pub fn server_order(mut self, o: ServerOrder) -> Self {
        self.server_order = o;
        self
    }

    /// Sets the DNS refresh rule. The default is `EachPass`.
    pub fn dns_refresh(mut self, p: DnsRefresh) -> Self {
        self.dns_refresh = p;
        self
    }

    /// Sets the resolver. The default uses `std::net::ToSocketAddrs`.
    pub fn resolver(mut self, r: impl Resolve) -> Self {
        self.resolver = Some(Arc::new(r));
        self
    }

    /// Sets the runtime. With no value, the client uses the current tokio
    /// runtime when it is a multi-thread runtime, and the thread driver in
    /// all other cases.
    pub fn runtime(mut self, rt: Runtime) -> Self {
        self.runtime = Some(rt);
        self
    }

    /// Follows `/zookeeper/config` and updates the host list. The default
    /// is false.
    pub fn update_servers_from_config(mut self, yes: bool) -> Self {
        self.update_servers_from_config = yes;
        self
    }

    /// Bounds the queued and in-flight requests. The default is no bound.
    pub fn max_pending_requests(mut self, n: usize) -> Self {
        self.max_pending = Some(n);
        self
    }

    /// Caps an inbound frame. The default is 4 MiB.
    pub fn max_frame_size(mut self, bytes: u32) -> Self {
        self.max_frame_size = bytes;
        self
    }

    /// Bounds the queue of each persistent watcher. The default is no
    /// bound.
    pub fn persistent_watch_buffer(mut self, events: usize) -> Self {
        self.persistent_watch_buffer = Some(events);
        self
    }

    /// Sets the read-gate capacity. The default is 4096.
    pub fn dispatch_queue_capacity(mut self, items: usize) -> Self {
        self.dispatch_queue_capacity = items;
        self
    }

    /// Bounds the wait for the `CloseSession` reply. The default is 3 s.
    pub fn close_timeout(mut self, t: Duration) -> Self {
        self.close_timeout = t;
        self
    }

    /// Uses TLS with these options.
    #[cfg(feature = "tls-rustls")]
    pub fn tls(mut self, opts: TlsOptions) -> Self {
        self.tls = Some(opts);
        self
    }

    /// Authenticates each connection with native SASL.
    ///
    /// The client runs the mechanism after the session handshake and
    /// before `CONNECTED`. Every SASL failure is terminal: the session
    /// goes to `AuthFailed`, and `SessionInfo::last_error` carries the
    /// [`SaslError`](crate::SaslError) when the client has one.
    #[cfg(feature = "sasl")]
    pub fn sasl(mut self, cfg: SaslConfig) -> Self {
        self.sasl = Some(cfg);
        self
    }

    /// Sets the metrics hook.
    pub fn metrics(mut self, m: impl Metrics) -> Self {
        self.metrics = Some(Arc::new(m));
        self
    }

    /// Sets the label of every log record of this client.
    pub fn name(mut self, label: impl Into<String>) -> Self {
        self.name = Some(label.into());
        self
    }

    /// Builds the client and gives a future that resolves when the session
    /// is established.
    ///
    /// The future resolves after `Connected`, or `ConnectedReadOnly`
    /// when allowed, and after every builder `auth` entry is
    /// acknowledged. An expired resumed session gives
    /// `Error::SessionExpired`. A refused entry gives `AuthFailed`.
    /// Against an unreachable ensemble it stays pending, and
    /// [`ConnectFuture::state_watcher`] shows the last failure.
    ///
    /// The client starts in this call, so the state watcher is valid at
    /// once (IMPLEMENTATION_GUIDE.md, "Known differences and open
    /// issues").
    pub fn connect(self) -> ConnectFuture {
        match self.start() {
            Ok((client, auth)) => {
                let watcher = client.state_watcher();
                ConnectFuture {
                    client: Some(client),
                    error: None,
                    watcher,
                    auth,
                    state_key: None,
                }
            }
            Err(e) => ConnectFuture {
                client: None,
                error: Some(e),
                watcher: StateWatcher::new(StateCell::new()),
                auth: Vec::new(),
                state_key: None,
            },
        }
    }

    /// Builds the client and returns at once.
    ///
    /// The steps:
    /// 1. Parse the connect string (`connect_string::parse`) and apply
    ///    the `chroot` override.
    /// 2. Check the values: the session timeout fits an `i32` of ms,
    ///    and the TLS options pass `TlsOptions::check`.
    /// 3. Make the `Observer`, the `StateCell`, the `Router` (with the
    ///    TLS error probe) and the `NativeHost`.
    /// 4. Make the proto `Config` and `Compat::NATIVE` with
    ///    `max_frame_len` and `tls_verify` set, then the `Connection`
    ///    with `DriverMode::NATIVE` and `zk_driver::host::connection_hooks`.
    /// 5. Start the driver with `driver::start`, make `Shared`, and
    ///    record each `auth` entry with `Shared::add_auth`.
    ///
    /// # Errors
    ///
    /// `Error::InvalidArgument` or `Error::InvalidPath` for a bad value,
    /// with the cause when one exists. `Error::SystemError` when the
    /// driver cannot start.
    pub fn build(self) -> Result<Client, ConnectError> {
        // The auth results are not needed here. The entries stay
        // recorded in proto, and a refusal ends the session.
        self.start().map(|(client, _auth)| client)
    }

    /// Makes the client and gives the futures of the builder `auth`
    /// entries, in call order. `build` and `connect` share it.
    fn start(self) -> Result<(Client, Vec<ResponseFuture<()>>), ConnectError> {
        let parsed = connect_string::parse(&self.connect_string)?;
        let chroot = match self.chroot {
            None => parsed.chroot,
            Some(Err(e)) => return Err(Error::InvalidPath(e).into()),
            Some(Ok(p)) if p.as_path().is_root() => None,
            Some(Ok(p)) => Some(p.into_string()),
        };
        let (timeout_ms, connect_timeout) =
            checked_timeouts(self.session_timeout, self.connect_timeout)?;

        let mut compat = Compat::NATIVE;
        compat.max_frame_len = Some(self.max_frame_size);
        let (cadence, resolve_delay_ms) = self.dns_refresh.proto();
        compat.resolve_cadence = cadence;

        let id = shared::next_client_id();
        let observe = Arc::new(Observer::new(self.name, self.metrics));
        // The runtime is known before the cell exists, because the cell
        // keeps the refusal rule of blocking waits.
        let runtime = self.runtime.unwrap_or_else(driver::default_runtime);
        #[cfg(all(unix, feature = "tokio"))]
        let follow_on = match &runtime {
            Runtime::Tokio(h) => Some(h.clone()),
            Runtime::Thread(_) => None,
        };
        #[cfg(all(unix, feature = "tokio"))]
        let state = StateCell::for_driver(follow_on.is_some());
        #[cfg(not(all(unix, feature = "tokio")))]
        let state = StateCell::new();

        #[cfg(feature = "tls-rustls")]
        let tls = match &self.tls {
            Some(opts) => {
                opts.check().map_err(|e| {
                    ConnectError::new(
                        Error::InvalidArgument("the TLS options are not valid".into()),
                        Some(Arc::new(e)),
                    )
                })?;
                compat.tls_verify = opts.tls_verify();
                Some((opts.connector(), opts.error_probe()))
            }
            None => None,
        };
        #[cfg(not(feature = "tls-rustls"))]
        let tls: Option<(Arc<dyn TlsConnector>, TlsErrorSource)> = None;
        let (connector, probe) = tls.unzip();

        #[cfg(feature = "sasl")]
        let (sasl, probe) = match self.sasl {
            Some(config) => {
                let last = LastSaslError::default();
                let session: Box<dyn zk_proto::SaslSession> =
                    Box::new(NativeSasl::new(config, Arc::clone(&last)));
                (Some(session), Some(with_sasl_error(probe, last)))
            }
            None => (None, probe),
        };
        #[cfg(not(feature = "sasl"))]
        let sasl: Option<Box<dyn zk_proto::SaslSession>> = None;

        let router = Router::new(Arc::clone(&state), Arc::clone(&observe), probe, id);
        let resolver = self.resolver.unwrap_or_else(|| Arc::new(StdResolve));
        let host: Arc<dyn HostLeaves<NativeTokens>> = Arc::new(NativeHost::new(
            resolver,
            self.server_order,
            Arc::clone(&observe),
            id,
        ));

        let mut cfg = Config::legacy(timeout_ms);
        cfg.client_id = self
            .session
            .as_ref()
            .map_or_else(ClientId::default, |(sid, pw)| ClientId {
                session_id: sid.0,
                passwd: *pw.as_bytes(),
            });
        cfg.allow_read_only = self.allow_read_only;
        cfg.tls = connector.is_some();
        cfg.sasl = sasl.is_some();
        cfg.hosts = parsed.hosts;
        cfg.host_text = JString::from(parsed.host_text);
        cfg.chroot = chroot.map(JString::from);
        cfg.resolve_delay_ms = resolve_delay_ms;
        cfg.restore_watches = self.restore_watches;
        cfg.max_pending = self.max_pending;
        cfg.connect_timeout_ms = Some(millis_u32(connect_timeout));
        cfg.reconnect_delay_ms = millis_u32(self.reconnect_delay);
        cfg.reconnect_jitter_pct = RECONNECT_JITTER_PCT;
        cfg.close_timeout_ms = millis_u32(self.close_timeout);

        let mut env = Env::new(Arc::clone(&host));
        env.tls = connector;
        env.cfg.dispatch_queue_capacity = self.dispatch_queue_capacity;
        env.cfg.cloexec = true;
        let now = env.clock.now();
        let (rng, log, default_watcher) = zk_driver::host::connection_hooks(&host);
        let conn = Box::new(Connection::new(
            cfg,
            compat,
            DriverMode::NATIVE,
            rng,
            log,
            default_watcher,
            now,
        ));

        let driver = driver::start(conn, env, Arc::clone(&router), Some(runtime), sasl, id)?;
        // The tokio driver has no exit hook. A follower task gives the
        // exit to the router, as the thread driver does.
        #[cfg(all(unix, feature = "tokio"))]
        if let (Some(rt), driver::DriverHandle::Tokio(task)) = (follow_on, &driver) {
            follow_exit(&rt, task.clone(), Arc::clone(&router));
        }
        let config = Arc::new(ClientConfig {
            max_pending: self.max_pending,
            persistent_watch_buffer: self.persistent_watch_buffer,
        });
        let shared = Shared::new(driver, router, config);
        let auth = self
            .auth
            .into_iter()
            .map(|(scheme, cred)| shared.add_auth(JString::from(scheme), cred))
            .collect();
        // The follower read goes after the credentials, so the server
        // checks it with them.
        if self.update_servers_from_config {
            follow::read(&shared);
        }
        Ok((Client::from_shared(shared), auth))
    }
}

/// Runs `Router::on_exit` when the tokio driver task ends. Thus the
/// state becomes `Closed` and the sinks end after a close, a detach or
/// the drop of the last clone.
///
/// A guard in the follower task runs `on_exit`. The guard also runs
/// when the runtime shuts down and drops the task before the driver
/// exit. Thus no watcher on another runtime or thread waits forever.
/// `on_exit` does nothing the second time.
#[cfg(all(unix, feature = "tokio"))]
fn follow_exit(
    rt: &tokio::runtime::Handle,
    task: zk_driver::tokio::TaskHandle<NativeTokens>,
    router: Arc<Router>,
) {
    let guard = ExitOnDrop(router);
    drop(rt.spawn(async move {
        let _guard = guard;
        let _rc = task.closed().await;
    }));
}

/// Runs `Router::on_exit` when it drops.
#[cfg(all(unix, feature = "tokio"))]
struct ExitOnDrop(Arc<Router>);

#[cfg(all(unix, feature = "tokio"))]
impl Drop for ExitOnDrop {
    fn drop(&mut self) {
        self.0.on_exit();
    }
}

/// Checks the session timeout and the connect timeout. It gives the
/// session timeout in ms and the connect timeout. With no connect timeout,
/// the connect timeout is a third of the session timeout.
fn checked_timeouts(
    session_timeout: Duration,
    connect_timeout: Option<Duration>,
) -> Result<(i32, Duration), Error> {
    let timeout_ms = i32::try_from(session_timeout.as_millis()).map_err(|_| {
        Error::InvalidArgument("the session timeout does not fit an i32 of milliseconds".into())
    })?;
    // A zero bound expires at once, so every connect attempt would
    // fail and the client would never connect.
    if timeout_ms == 0 {
        return Err(Error::InvalidArgument(
            "the session timeout is below 1 ms".into(),
        ));
    }
    let connect_timeout =
        connect_timeout.unwrap_or_else(|| session_timeout.checked_div(3).unwrap_or_default());
    if connect_timeout.as_millis() == 0 {
        return Err(Error::InvalidArgument(
            "the connect timeout is below 1 ms (the default is a third of the session timeout)"
                .into(),
        ));
    }
    Ok((timeout_ms, connect_timeout))
}

/// Adds the native SASL error to the error probe of the router.
///
/// The TLS error comes first. It exists only after a failed reload, and
/// then no connection reaches SASL. `last_error_for` takes a
/// [`SaslError`](crate::SaslError) only for a SASL teardown.
#[cfg(feature = "sasl")]
fn with_sasl_error(tls: Option<TlsErrorSource>, sasl: LastSaslError) -> TlsErrorSource {
    Arc::new(move || {
        if let Some(e) = tls.as_ref().and_then(|f| f()) {
            return Some(e);
        }
        let e = sasl.lock_unpoisoned().clone()?;
        let e: crate::error::LastError = Arc::new(e);
        Some(e)
    })
}

/// Converts a duration to whole milliseconds, capped at `u32::MAX`.
fn millis_u32(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// The future of [`ClientBuilder::connect`].
///
/// It owns the client until it resolves. A drop before that closes the
/// client.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    /// The client, or `None` after `build` failed or after the future
    /// resolved.
    pub(crate) client: Option<Client>,
    /// The `build` error, given at the first poll.
    pub(crate) error: Option<ConnectError>,
    /// The session state of the client.
    pub(crate) watcher: StateWatcher,
    /// The results of the builder `auth` entries.
    pub(crate) auth: Vec<ResponseFuture<()>>,
    /// The waker entry of the state wait. It stays across polls, so a
    /// state change wakes the task.
    pub(crate) state_key: Option<u64>,
}

impl Drop for ConnectFuture {
    /// Removes the waker entry from the state cell.
    fn drop(&mut self) {
        self.watcher.forget(&mut self.state_key);
    }
}

impl std::fmt::Debug for ConnectFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectFuture")
            .field("state", &self.watcher.current().state)
            .finish_non_exhaustive()
    }
}

impl ConnectFuture {
    /// The session state of the client that this future builds. While
    /// the future is pending, `last_error` names the last failure.
    #[must_use]
    pub fn state_watcher(&self) -> StateWatcher {
        self.watcher.clone()
    }

    /// Blocks until the future resolves.
    ///
    /// # Errors
    ///
    /// As for the future. It fails at once with `Error::InvalidState` on
    /// the IO side of a client, and in a tokio runtime context when the
    /// tokio driver runs the client.
    #[cfg(feature = "blocking")]
    pub fn wait(mut self) -> Result<Client, ConnectError> {
        if blocking_refused(self.watcher.tokio_driver()) {
            return Err(Error::InvalidState.into());
        }
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        'connect: loop {
            loop {
                let info = self.watcher.current();
                if info.state.is_terminal() {
                    return Err(self.terminal(info));
                }
                if info.state.is_connected() {
                    break;
                }
                self.watcher.wait_changed()?;
            }
            while !self.auth.is_empty() {
                let f = self.auth.remove(0);
                match f.wait() {
                    Ok(()) => {}
                    Err(e) if e.is_connection_loss() => {
                        self.after_auth_loss();
                        continue 'connect;
                    }
                    Err(e) => return Err(ConnectError::new(e, self.watcher.last_error())),
                }
            }
            return self.client.take().ok_or_else(|| Error::Closing.into());
        }
    }

    /// Replaces the auth results after a connection loss.
    ///
    /// The loss fails every auth result that is not answered, but proto
    /// keeps the credentials and sends them again on the next
    /// connection. A server that refuses one ends the session with
    /// `AuthFailed`. The server answers in order, so the reply to a
    /// `sync` after the new auth packets shows that it accepted them.
    /// Thus one `sync` replaces the remaining results.
    fn after_auth_loss(&mut self) {
        self.auth.clear();
        if let Some(c) = &self.client {
            self.auth.push(c.sync("/"));
        }
    }
}

impl Future for ConnectFuture {
    type Output = Result<Client, ConnectError>;

    /// Gives the `build` error, or waits for an established state and
    /// then for each auth result. A terminal state gives its error, with
    /// `last_error` as the cause. A connection loss before an auth reply
    /// is not a result, so the wait starts again.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(e) = this.error.take() {
            return Poll::Ready(Err(e));
        }
        if this.client.is_none() {
            // The future gave its result already.
            return Poll::Ready(Err(Error::Closing.into()));
        }
        'connect: loop {
            // Wait for an established state. Each change wakes the task.
            loop {
                let info = this.watcher.current();
                if info.state.is_terminal() {
                    return Poll::Ready(Err(this.terminal(info)));
                }
                if info.state.is_connected() {
                    break;
                }
                match this.watcher.poll_keyed(&mut this.state_key, cx) {
                    Poll::Ready(_) => continue,
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.watcher.forget(&mut this.state_key);
            // Proto answers the auth entries in call order.
            while let Some(f) = this.auth.first_mut() {
                match Pin::new(f).poll(cx) {
                    Poll::Ready(Ok(())) => {
                        drop(this.auth.remove(0));
                    }
                    Poll::Ready(Err(e)) if e.is_connection_loss() => {
                        this.after_auth_loss();
                        continue 'connect;
                    }
                    Poll::Ready(Err(e)) => {
                        let cause = this.watcher.last_error();
                        this.client = None;
                        return Poll::Ready(Err(ConnectError::new(e, cause)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            return Poll::Ready(this.client.take().ok_or_else(|| Error::Closing.into()));
        }
    }
}

impl ConnectFuture {
    /// The error of a terminal state, with the last error as the cause.
    /// It drops the client, so the driver ends.
    fn terminal(&mut self, info: SessionInfo) -> ConnectError {
        let error = self
            .client
            .as_ref()
            .and_then(|c| c.shared().terminal_error())
            .unwrap_or(match info.state {
                SessionState::Expired => Error::SessionExpired,
                SessionState::AuthFailed => Error::AuthFailed,
                _ => Error::Closing,
            });
        self.client = None;
        ConnectError::new(error, info.last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_follow_04() {
        let b = ClientBuilder::new("h:2181".into());
        assert_eq!(b.session_timeout, Duration::from_secs(30));
        assert!(b.restore_watches);
        assert_eq!(b.max_frame_size, 4 * 1024 * 1024);
        assert_eq!(b.dispatch_queue_capacity, 4096);
        assert_eq!(b.server_order, ServerOrder::Shuffled);
        assert!(b.chroot.is_none());
    }

    #[test]
    fn millis_saturate_at_u32_max() {
        assert_eq!(millis_u32(Duration::from_millis(1500)), 1500);
        assert_eq!(millis_u32(Duration::from_secs(u64::MAX)), u32::MAX);
    }

    #[test]
    fn a_build_error_comes_at_the_first_poll() {
        let mut f = ConnectFuture {
            client: None,
            error: Some(Error::BadArguments.into()),
            watcher: StateWatcher::new(StateCell::new()),
            auth: Vec::new(),
            state_key: None,
        };
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match Pin::new(&mut f).poll(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.error(), &Error::BadArguments),
            other => panic!("unexpected poll result: {other:?}"),
        }
        // A poll after the result gives an error and touches no client.
        match Pin::new(&mut f).poll(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.error(), &Error::Closing),
            other => panic!("unexpected poll result: {other:?}"),
        }
    }

    #[test]
    fn a_bad_chroot_is_kept_for_build() {
        let b = ClientBuilder::new("h".into()).chroot("no-slash");
        assert!(matches!(b.chroot, Some(Err(_))));
    }

    #[test]
    fn debug_hides_credentials() {
        let b = ClientBuilder::new("h".into()).auth("digest", "u:secret");
        assert!(!format!("{b:?}").contains("secret"));
    }
}
