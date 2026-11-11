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

//! The driver selection and `DriverHandle`.
//!
//! The module hides the two zk-driver handles behind one enum, so no
//! other module names a driver type.
//!
//! The thread driver runs the IO loop on one thread per client. The
//! `ClientSpawner` wraps each thread body: it sets the IO-side marker,
//! and the IO body tells the router and the close waiters when it
//! exits. The tokio driver has no exit hook, so the router also ends
//! the sinks at a terminal session state.

#[cfg(any(test, all(unix, feature = "tokio")))]
use std::future::Future;
#[cfg(any(test, all(unix, feature = "tokio")))]
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
#[cfg(any(test, all(feature = "blocking", unix, feature = "tokio")))]
use std::task::Wake;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
#[cfg(any(test, feature = "blocking"))]
use std::time::Instant;

use zk_driver::native::{IO_THREAD_NAME, ThreadBody};
use zk_driver::{Env, NativeHandle, RouteSink, Spawn, StartError, StdSpawner};
use zk_jute::JString;
use zk_proto::{
    AddAuthError, ClientId, Connection, HostSpec, MultiOpRef, Request, SaslSession, SecretBytes,
    SubmitError, Submitted,
};

use crate::builder::{Runtime, ThreadOptions};
use crate::error::{ConnectError, Error};
use crate::route::Router;
use crate::sync::{LockExt, enter_io_side, wake_quietly};
#[cfg(any(test, feature = "blocking"))]
use crate::sync::{wait, wait_until};
use crate::tokens::{AuthToken, NativeTokens};

/// The close rc when the driver exits with no rc.
const ZSYSTEMERROR: i32 = -1;

/// The handle of the driver of one client.
pub(crate) enum DriverHandle {
    /// The thread driver.
    Thread {
        /// The driver handle.
        handle: NativeHandle<NativeTokens>,
        /// Set when the IO thread exits.
        exit: Arc<ExitSignal>,
    },
    /// The tokio driver.
    #[cfg(all(unix, feature = "tokio"))]
    Tokio(zk_driver::tokio::TaskHandle<NativeTokens>),
}

impl std::fmt::Debug for DriverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Thread { .. } => f.write_str("DriverHandle::Thread"),
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(_) => f.write_str("DriverHandle::Tokio"),
        }
    }
}

/// Calls the same method on either handle.
macro_rules! forward {
    ($self:ident, $h:ident => $e:expr) => {
        match $self {
            DriverHandle::Thread { handle: $h, .. } => $e,
            #[cfg(all(unix, feature = "tokio"))]
            DriverHandle::Tokio($h) => $e,
        }
    };
}

impl DriverHandle {
    /// Submits a request under the core lock and wakes the driver.
    pub(crate) fn submit(
        &self,
        req: Request<NativeTokens>,
    ) -> Result<Submitted<NativeTokens>, SubmitError<NativeTokens>> {
        forward!(self, h => h.submit(req))
    }

    /// Submits a request whose data is borrowed, as
    /// `Connection::submit_with_data` tells, and wakes the driver.
    pub(crate) fn submit_with_data(
        &self,
        req: Request<NativeTokens>,
        data: Option<&[u8]>,
    ) -> Result<Submitted<NativeTokens>, SubmitError<NativeTokens>> {
        forward!(self, h => h.submit_with_data(req, data))
    }

    /// Submits a multi request whose sub-ops are borrowed, as
    /// `Connection::submit_multi_ref` tells, and wakes the driver.
    pub(crate) fn submit_multi_ref(
        &self,
        req: Request<NativeTokens>,
        ops: &[MultiOpRef<'_>],
    ) -> Result<Submitted<NativeTokens>, SubmitError<NativeTokens>> {
        forward!(self, h => h.submit_multi_ref(req, ops))
    }

    /// Records an `add_auth` call and wakes the driver.
    pub(crate) fn add_auth(
        &self,
        scheme: JString,
        cred: SecretBytes,
        done: Option<AuthToken>,
    ) -> Result<(), AddAuthError<NativeTokens>> {
        forward!(self, h => h.add_auth(scheme, cred, done))
    }

    /// Gives proto a new host list. It returns the resolver generation,
    /// or 0 after the driver exits.
    pub(crate) fn set_servers(&self, hosts: Vec<HostSpec>) -> u64 {
        forward!(self, h => h.set_servers(hosts))
    }

    /// Starts the graceful close. A second call does nothing.
    pub(crate) fn close(&self) {
        forward!(self, h => h.close())
    }

    /// Ends the client with no close request.
    pub(crate) fn detach(&self) {
        forward!(self, h => h.detach())
    }

    /// Makes a read-gate reporter that does not keep the session open.
    pub(crate) fn gate(&self) -> Gate {
        match self {
            Self::Thread { handle, .. } => Gate::Thread(handle.gate_reporter()),
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(h) => Gate::Tokio(h.gate_reporter()),
        }
    }

    /// True when the tokio driver runs the client.
    pub(crate) fn is_tokio(&self) -> bool {
        match self {
            Self::Thread { .. } => false,
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(_) => true,
        }
    }

    /// The session identity.
    pub(crate) fn client_id(&self) -> ClientId {
        forward!(self, h => h.client_id())
    }

    /// Runs `f` on the connection under the core lock. `None` after the
    /// driver exits.
    pub(crate) fn read_conn<R>(&self, f: impl FnOnce(&Connection<NativeTokens>) -> R) -> Option<R> {
        forward!(self, h => h.read_conn(f))
    }

    /// Runs `f` on the connection under the core lock, then wakes the
    /// driver. `None` after the driver exits.
    pub(crate) fn with_conn<R>(
        &self,
        f: impl FnOnce(&mut Connection<NativeTokens>, zk_proto::Millis) -> R,
    ) -> Option<R> {
        forward!(self, h => h.with_conn(f))
    }

    /// Makes a wait for the exit of the driver.
    ///
    /// The tokio driver has no exit hook, and the exit follower task can
    /// run after the close waiter. Thus the tokio wait runs
    /// `Router::on_exit` itself before it resolves. The client is then
    /// `Closed` when the close future is ready, as with the IO thread.
    /// A second call of `on_exit` does nothing.
    pub(crate) fn close_wait(&self, router: &Arc<Router>) -> CloseWait {
        match self {
            Self::Thread { handle, exit } => {
                // The IO thread runs `on_exit` before it sets the signal.
                let _ = router;
                CloseWait::Thread {
                    exit: Arc::clone(exit),
                    handle: handle.clone(),
                }
            }
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(h) => {
                let h = h.clone();
                let router = Arc::clone(router);
                CloseWait::Tokio(Box::pin(async move {
                    let rc = h.closed().await;
                    router.on_exit();
                    rc
                }))
            }
        }
    }
}

/// Reports taken items to the read gate of one driver.
///
/// Futures and watchers hold it next to their weak client reference.
/// The driver drains the queue after the drop of the last clone, and
/// the gate must stay correct until it exits. The reporter does not
/// keep the session open.
#[derive(Clone)]
pub(crate) enum Gate {
    /// The thread driver.
    Thread(zk_driver::NativeGate<NativeTokens>),
    /// The tokio driver.
    #[cfg(all(unix, feature = "tokio"))]
    Tokio(zk_driver::tokio::TaskGate<NativeTokens>),
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gate(..)")
    }
}

impl Gate {
    /// A receiver took or dropped a counted item.
    pub(crate) fn taken(&self) {
        match self {
            Self::Thread(g) => g.taken(),
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(g) => g.taken(),
        }
    }

    /// True when the tokio driver runs the client.
    #[cfg(feature = "blocking")]
    pub(crate) fn is_tokio(&self) -> bool {
        match self {
            Self::Thread(_) => false,
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(_) => true,
        }
    }
}

/// The state behind the `ExitSignal` lock.
#[derive(Debug, Default)]
struct ExitState {
    done: bool,
    wakers: Vec<Waker>,
}

/// Set once when the IO thread exits.
#[derive(Debug, Default)]
pub(crate) struct ExitSignal {
    st: Mutex<ExitState>,
    cv: Condvar,
}

impl ExitSignal {
    /// Makes an unset signal.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Sets the signal and wakes every waiter after the lock is
    /// released.
    pub(crate) fn signal(&self) {
        let wakers = {
            let mut s = self.st.lock_unpoisoned();
            s.done = true;
            std::mem::take(&mut s.wakers)
        };
        self.cv.notify_all();
        for w in wakers {
            wake_quietly(w);
        }
    }

    /// Ready when the signal is set. Else it stores the waker.
    pub(crate) fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut s = self.st.lock_unpoisoned();
        if s.done {
            return Poll::Ready(());
        }
        if !s.wakers.iter().any(|w| w.will_wake(cx.waker())) {
            s.wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }

    /// Blocks until the signal is set. It returns false when `deadline`
    /// passes first.
    #[cfg(any(test, feature = "blocking"))]
    pub(crate) fn wait(&self, deadline: Option<Instant>) -> bool {
        let mut s = self.st.lock_unpoisoned();
        loop {
            if s.done {
                return true;
            }
            match deadline {
                None => s = wait(&self.cv, s),
                Some(d) => {
                    let (g, timed_out) = wait_until(&self.cv, s, d);
                    s = g;
                    if timed_out {
                        return s.done;
                    }
                }
            }
        }
    }
}

/// A wait for the exit of a driver and its close rc.
pub(crate) enum CloseWait {
    /// The thread driver: the exit signal, then the rc of the handle.
    Thread {
        /// The exit signal.
        exit: Arc<ExitSignal>,
        /// A clone of the handle. The close was requested already.
        handle: NativeHandle<NativeTokens>,
    },
    /// The tokio driver: `TaskHandle::closed`.
    #[cfg(all(unix, feature = "tokio"))]
    Tokio(Pin<Box<dyn Future<Output = i32> + Send>>),
}

impl CloseWait {
    /// Ready with the close rc when the driver exits.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<i32> {
        match self {
            Self::Thread { exit, handle } => match exit.poll(cx) {
                Poll::Ready(()) => Poll::Ready(exit_rc(handle)),
                Poll::Pending => Poll::Pending,
            },
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(f) => f.as_mut().poll(cx),
        }
    }

    /// True when the tokio driver runs the client.
    #[cfg(feature = "blocking")]
    pub(crate) fn is_tokio(&self) -> bool {
        match self {
            Self::Thread { .. } => false,
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(_) => true,
        }
    }

    /// Blocks until the driver exits. It returns `None` when `deadline`
    /// passes first. The caller checks `blocking_refused` first.
    #[cfg(feature = "blocking")]
    pub(crate) fn wait(&mut self, deadline: Option<Instant>) -> Option<i32> {
        match self {
            Self::Thread { exit, handle } => {
                if exit.wait(deadline) {
                    Some(exit_rc(handle))
                } else {
                    None
                }
            }
            #[cfg(all(unix, feature = "tokio"))]
            Self::Tokio(f) => block_on(f.as_mut(), deadline),
        }
    }
}

/// The close rc of an exited IO thread.
fn exit_rc(handle: &NativeHandle<NativeTokens>) -> i32 {
    handle.wait_closed(Duration::ZERO).unwrap_or(ZSYSTEMERROR)
}

/// Unparks a thread.
#[cfg(any(test, all(feature = "blocking", unix, feature = "tokio")))]
struct ThreadWaker(std::thread::Thread);

#[cfg(any(test, all(feature = "blocking", unix, feature = "tokio")))]
impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Polls `f` on this thread and parks between polls. It returns `None`
/// when `deadline` passes first.
#[cfg(any(test, all(feature = "blocking", unix, feature = "tokio")))]
fn block_on<T>(
    mut f: Pin<&mut (dyn Future<Output = T> + Send)>,
    deadline: Option<Instant>,
) -> Option<T> {
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
        match deadline {
            None => std::thread::park(),
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return None;
                }
                std::thread::park_timeout(left);
            }
        }
    }
}

/// Runs the router exit and sets the exit signal when the IO body ends.
struct OnIoExit {
    router: Arc<Router>,
    exit: Arc<ExitSignal>,
}

impl Drop for OnIoExit {
    fn drop(&mut self) {
        self.router.on_exit();
        self.exit.signal();
    }
}

/// The `Spawn` of the thread driver of one client.
struct ClientSpawner {
    std: StdSpawner,
    /// The IO thread name of `ThreadOptions`, or `None` for `zk-io`.
    io_name: Option<String>,
    router: Arc<Router>,
    exit: Arc<ExitSignal>,
    client: u64,
}

impl Spawn for ClientSpawner {
    /// Starts the IO thread or a DNS thread. Each body runs with the
    /// IO-side marker of the client. The IO body ends with
    /// `Router::on_exit` and the exit signal.
    fn spawn(&self, name: &'static str, body: ThreadBody) -> std::io::Result<()> {
        let client = self.client;
        if name == IO_THREAD_NAME {
            let on_exit = OnIoExit {
                router: Arc::clone(&self.router),
                exit: Arc::clone(&self.exit),
            };
            let wrapped: ThreadBody = Box::new(move || {
                let _io = enter_io_side(client);
                let _on_exit = on_exit;
                body();
            });
            let thread_name = self
                .io_name
                .clone()
                .unwrap_or_else(|| IO_THREAD_NAME.to_owned());
            self.std.spawn_owned(thread_name, wrapped)
        } else {
            let wrapped: ThreadBody = Box::new(move || {
                let _io = enter_io_side(client);
                body();
            });
            self.std.spawn(name, wrapped)
        }
    }
}

/// Picks the runtime when the builder has none (specification
/// "Execution Runtimes").
///
/// The client uses the current tokio runtime only when it is a
/// multi-thread runtime. A current-thread runtime runs the driver task
/// only when the application yields, so busy user code can stop the
/// pings. Thus every other case uses the thread driver. An explicit
/// `Runtime::Tokio` can still name a current-thread runtime.
pub(crate) fn default_runtime() -> Runtime {
    #[cfg(all(unix, feature = "tokio"))]
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return Runtime::Tokio(h);
        }
    }
    Runtime::Thread(ThreadOptions::default())
}

/// Starts the driver of one client.
///
/// `runtime` is the builder value, or `None` for the default. A thread
/// name with a NUL byte is refused before any thread starts, because
/// `std::thread::Builder` panics on it. `sasl` is the native SASL
/// session. The driver owns it for the life of the client.
///
/// # Errors
///
/// `Error::BadArguments` for a thread name with a NUL byte. A failed
/// start gives `Error::SystemError` with the OS error as the cause.
pub(crate) fn start(
    conn: Box<Connection<NativeTokens>>,
    env: Env<NativeTokens>,
    router: Arc<Router>,
    runtime: Option<Runtime>,
    sasl: Option<Box<dyn SaslSession>>,
    client: u64,
) -> Result<DriverHandle, ConnectError> {
    match runtime.unwrap_or_else(default_runtime) {
        Runtime::Thread(opts) => {
            if opts.name.as_deref().is_some_and(|n| n.contains('\0')) {
                return Err(ConnectError::new(
                    Error::InvalidArgument("the thread name has a NUL byte".into()),
                    None,
                ));
            }
            let exit = ExitSignal::new();
            let spawner = Arc::new(ClientSpawner {
                std: StdSpawner {
                    stack_size: opts.stack_size,
                },
                io_name: opts.name,
                router: Arc::clone(&router),
                exit: Arc::clone(&exit),
                client,
            });
            let sink: Arc<dyn RouteSink<NativeTokens>> = router;
            match zk_driver::native::start(conn, env, sink, sasl, spawner) {
                Ok(handle) => Ok(DriverHandle::Thread { handle, exit }),
                Err(e) => Err(start_error(e)),
            }
        }
        #[cfg(all(unix, feature = "tokio"))]
        Runtime::Tokio(h) => {
            let sink: Arc<dyn RouteSink<NativeTokens>> = router;
            Ok(DriverHandle::Tokio(zk_driver::tokio::spawn(
                conn, env, sink, sasl, &h,
            )))
        }
    }
}

/// Maps a driver start failure to a `ConnectError`.
fn start_error(e: StartError) -> ConnectError {
    let io = match e {
        StartError::Waker(errno) => std::io::Error::from_raw_os_error(errno.raw_os_error()),
        StartError::Spawn(io) => io,
    };
    ConnectError::new(Error::SystemError, Some(Arc::new(io)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_signal_wakes_blocked_waiters() {
        let s = ExitSignal::new();
        assert!(!s.wait(Some(Instant::now())));
        let s2 = Arc::clone(&s);
        let t = std::thread::spawn(move || s2.wait(None));
        s.signal();
        assert!(t.join().unwrap());
    }

    #[test]
    fn block_on_returns_a_ready_value() {
        let mut f = std::future::ready(7);
        let p: Pin<&mut std::future::Ready<i32>> = Pin::new(&mut f);
        assert_eq!(block_on(p, None), Some(7));
    }

    #[test]
    fn the_default_runtime_follows_the_flavor() {
        assert!(matches!(default_runtime(), Runtime::Thread(_)));
        #[cfg(all(unix, feature = "tokio"))]
        {
            let ct = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            assert!(ct.block_on(async { matches!(default_runtime(), Runtime::Thread(_)) }));
            let mt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .build()
                .unwrap();
            assert!(mt.block_on(async { matches!(default_runtime(), Runtime::Tokio(_)) }));
        }
    }
}
