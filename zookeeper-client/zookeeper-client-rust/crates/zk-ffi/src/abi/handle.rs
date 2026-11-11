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

//! The handle, its lifecycle and the driving calls.
//!
//! `zkrs_handle_new` makes one `Arc<Inner>` and gives a strong reference
//! to C as the `zkrs_handle` pointer. Each library thread holds one more
//! reference (`zkrs_handle_retain`). Every export makes its own reference
//! for the call through `with_handle`, so the final close can run inside
//! any call.
//!
//! [`Inner`] holds the init state until the init finishes, then the
//! driver. [`Driver`] has one variant per flavor: `Mt` holds a `Shared`
//! driver for `libzookeeper_mt`, and `St` holds a `Polled` driver for
//! `libzookeeper_st`. One staticlib serves both libraries.
//! `zkrs_init_args.flavor` selects the variant at run time.
//!
//! The [`Driver`] methods give one interface to the two drivers. The
//! other files use only these methods, so they do not match on the
//! flavor.

use std::ffi::c_int;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use zeroize::{Zeroize, Zeroizing};

use zk_driver::net::tls::TlsConnector;
use zk_driver::outbox::Flavor;
use zk_driver::sync::Mutex;
use zk_driver::{
    Env, HostLeaves, Init, InitArgs, InitError, InitStep, InterestOut, Outbox, Polled, RawSock,
    Requeued, Role, Shared, Step, Unlocked,
};
use zk_jute::JString;
use zk_proto::{
    AddAuthError, ClientId, Compat, Config, Connection, DriverMode, Millis, MultiOpRef, Request,
    SecretBytes, SubmitError, Submitted,
};

use super::entry::{abort_with, ffi_guard, with_handle};
use super::host::FfiHost;
use super::outbox::{take_driver_outbox, with_outbox};
use super::raw;
use super::tokens::CTokens;
use super::types::{
    ZKRS_FLAVOR_MT, ZKRS_FLAVOR_ST, ZKRS_INIT_SASL_POINT, ZKRS_ROLE_DISPATCH, ZKRS_ROLE_INIT,
    ZKRS_ROLE_IO, zkrs_handle, zkrs_host_vtable, zkrs_init_args, zkrs_interest_out, zkrs_outbox,
    zkrs_step,
};

/// The driver of one handle, by flavor.
pub(crate) enum Driver {
    /// The mt driver: an IO thread and a dispatch thread.
    Mt(Arc<Shared<CTokens>>),
    /// The st driver: the application polls, and the callbacks run on
    /// its thread inside `zookeeper_process`.
    St(Arc<Polled<CTokens>>),
}

impl Driver {
    /// Makes the outbox of one call. The mt outbox publishes to the
    /// dispatch FIFO. The st outbox never publishes.
    pub(crate) fn outbox(&self) -> Outbox<CTokens> {
        match self {
            Self::Mt(s) => s.outbox(),
            Self::St(p) => p.outbox(),
        }
    }

    /// Stores the items that C did not take.
    pub(crate) fn requeue(&self, rest: Requeued<CTokens>) {
        match self {
            Self::Mt(s) => s.requeue(rest),
            Self::St(p) => p.requeue(rest),
        }
    }

    /// `zoo_state`. 0 after the final close.
    pub(crate) fn state(&self) -> i32 {
        match self {
            Self::Mt(s) => s.state(),
            Self::St(p) => p.state(),
        }
    }

    /// The errno of the st driving call that ended last, or 0. mt
    /// drives no connection in a C call, so it gives 0.
    pub(crate) fn last_errno(&self) -> i32 {
        match self {
            Self::Mt(_) => 0,
            Self::St(p) => p.last_errno(),
        }
    }

    /// `zoo_recv_timeout`.
    pub(crate) fn recv_timeout(&self) -> i32 {
        match self {
            Self::Mt(s) => s.recv_timeout(),
            Self::St(p) => p.recv_timeout(),
        }
    }

    /// Submits one request. `data` is the borrowed data of a create or
    /// a set data, as `Connection::submit_with_data` tells.
    ///
    /// mt wakes the IO thread and does not use `ob`. st runs one
    /// non-blocking flush pass. A failed flush is a forced close, and its
    /// log lines go into `ob`.
    pub(crate) fn submit_with_data(
        &self,
        req: Request<CTokens>,
        data: Option<&[u8]>,
        ob: &mut Outbox<CTokens>,
    ) -> Result<Submitted<CTokens>, SubmitError<CTokens>> {
        match self {
            Self::Mt(s) => s.submit_with_data(req, data),
            Self::St(p) => p.submit_with_data(req, data, ob),
        }
    }

    /// Submits one multi request whose sub-ops are borrowed, as
    /// `Connection::submit_multi_ref` tells. The flush rules are those of
    /// [`Self::submit_with_data`].
    pub(crate) fn submit_multi_ref(
        &self,
        req: Request<CTokens>,
        ops: &[MultiOpRef<'_>],
        ob: &mut Outbox<CTokens>,
    ) -> Result<Submitted<CTokens>, SubmitError<CTokens>> {
        match self {
            Self::Mt(s) => s.submit_multi_ref(req, ops),
            Self::St(p) => p.submit_multi_ref(req, ops, ob),
        }
    }

    /// `zoo_add_auth`: records the entry for the next send.
    pub(crate) fn add_auth(
        &self,
        scheme: JString,
        cred: SecretBytes,
        done: Option<<CTokens as zk_proto::Tokens>::Auth>,
    ) -> Result<(), AddAuthError<CTokens>> {
        match self {
            Self::Mt(s) => s.add_auth(scheme, cred, done),
            Self::St(p) => p.add_auth(scheme, cred, done),
        }
    }

    /// `zoo_set_servers`. A barrier gives `More`, and `zkrs_resume`
    /// continues it.
    pub(crate) fn set_servers(&self, hosts: &[u8], ob: &mut Outbox<CTokens>, rc: &mut i32) -> Step {
        match self {
            Self::Mt(s) => s.set_servers(hosts, ob, rc),
            Self::St(p) => p.set_servers(hosts, ob, rc),
        }
    }

    /// The peer of the current transport.
    pub(crate) fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Mt(s) => s.peer_addr(),
            Self::St(p) => p.peer_addr(),
        }
    }

    /// Reads the connection under the core lock. `None` after the final
    /// close.
    pub(crate) fn read_conn<R>(&self, f: impl FnOnce(&Connection<CTokens>) -> R) -> Option<R> {
        match self {
            Self::Mt(s) => s.read_conn(f),
            Self::St(p) => p.read_conn(f),
        }
    }

    /// Changes the connection under the core lock. mt then wakes the IO
    /// thread. st routes the outputs in the next driving call. `None`
    /// after the final close.
    pub(crate) fn with_conn<R>(
        &self,
        f: impl FnOnce(&mut Connection<CTokens>, Millis) -> R,
    ) -> Option<R> {
        match self {
            Self::Mt(s) => s.with_conn(f),
            Self::St(p) => p.with_conn(f),
        }
    }
}

/// The Rust state behind one `zkrs_handle` pointer.
pub(crate) struct Inner {
    host: Arc<FfiHost>,
    flavor: u32,
    init: Mutex<Option<Init<CTokens>>>,
    driver: OnceLock<Driver>,
}

impl Inner {
    /// Makes the state of a new handle. The init is stored with
    /// [`Inner::put_init`] when it exists.
    pub(crate) fn new(host: Arc<FfiHost>, flavor: u32) -> Self {
        Self {
            host,
            flavor,
            init: Mutex::new(None),
            driver: OnceLock::new(),
        }
    }

    /// The host of the handle.
    pub(crate) fn host(&self) -> &Arc<FfiHost> {
        &self.host
    }

    /// `ZKRS_FLAVOR_*` of the handle.
    #[cfg(test)]
    pub(crate) fn flavor(&self) -> u32 {
        self.flavor
    }

    /// Takes the init state out for one step. `Init::step` needs the
    /// lock proof, so the init lock is not held during the step.
    pub(crate) fn take_init(&self, u: &mut Unlocked) -> Option<Init<CTokens>> {
        self.init.lock(u).take()
    }

    /// Stores the init state after a step that did not finish.
    pub(crate) fn put_init(&self, u: &mut Unlocked, init: Init<CTokens>) {
        *self.init.lock(u) = Some(init);
    }

    /// Stores the driver when the init is ready. A second call gives the
    /// driver back.
    pub(crate) fn install(&self, d: Driver) -> Result<(), Driver> {
        self.driver.set(d)
    }

    /// The driver, or `None` while the init runs.
    pub(crate) fn driver(&self) -> Option<&Driver> {
        self.driver.get()
    }
}

/// Maps a C role (`ZKRS_ROLE_*`) to the driver role. An unknown value is
/// a foreign thread.
pub(crate) fn role_of(role: u32) -> Role {
    match role {
        ZKRS_ROLE_INIT => Role::Init,
        ZKRS_ROLE_IO => Role::Io,
        ZKRS_ROLE_DISPATCH => Role::Dispatch,
        _ => Role::Foreign,
    }
}

/// Maps a driver step to `zkrs_step` and writes `*rc` for `Done`.
///
/// Every driving export ends with it. It writes `*rc` only for
/// `ZKRS_DONE`. For `ZKRS_RELEASE`, [`finish_step`] writes the close rc.
pub(crate) fn step_out(s: Step, rc: *mut c_int) -> zkrs_step {
    match s {
        Step::Done(r) => {
            raw::write_out(rc, r);
            zkrs_step::ZKRS_DONE
        }
        Step::More => zkrs_step::ZKRS_MORE,
        Step::Release => zkrs_step::ZKRS_RELEASE,
        Step::Exit => zkrs_step::ZKRS_EXIT,
    }
}

/// Aborts when a call needs the driver and the init has not finished.
/// C makes no such call: `zookeeper_init` returns only a ready handle.
pub(crate) fn require_driver(h: &Inner) -> &Driver {
    match h.driver() {
        Some(d) => d,
        None => abort_with("zk-ffi: driving call before the init finished"),
    }
}

/// The mt driver for a call that only `libzookeeper_mt` makes. st has
/// no library threads, so the st shim never makes the call. A call on
/// an st handle is a defect, and the process aborts.
fn require_mt(h: &Inner) -> &Arc<Shared<CTokens>> {
    match require_driver(h) {
        Driver::Mt(s) => s,
        Driver::St(_) => abort_with("zk-ffi: an mt-only call on an st handle"),
    }
}

/// Gives a failure errno that is never 0.
///
/// C reads `*rc == 0` as success. Thus an unknown errno becomes EINVAL.
/// The legacy client also gives EINVAL for an empty host list.
fn failure_errno(errno: Option<i32>) -> i32 {
    match errno {
        Some(e) if e != 0 => e,
        _ => libc::EINVAL,
    }
}

/// Ends one driving call.
///
/// `ZKRS_RELEASE` also writes `*rc`, because C returns it after
/// `zks_release`. The driver already took every leftover token. Thus
/// the host goes to 0 here, and no leaf call follows.
fn finish_step(i: &Inner, s: Step, close_rc: i32, rc: *mut c_int) -> zkrs_step {
    if s == Step::Release {
        i.host().zero();
        raw::write_out(rc, close_rc);
        return zkrs_step::ZKRS_RELEASE;
    }
    step_out(s, rc)
}

/// Runs one driver step with the outbox of the call. [`finish_step`]
/// ends the step.
fn drive(
    i: &Arc<Inner>,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
    f: impl FnOnce(&Driver, &mut Outbox<CTokens>, &mut i32) -> Step,
) -> zkrs_step {
    let d = require_driver(i);
    let mut close_rc: i32 = 0;
    let step = with_outbox(ob, i, |o| f(d, o, &mut close_rc));
    finish_step(i, step, close_rc, rc)
}

/// Runs one mt-only driver step. See [`require_mt`].
fn drive_mt(
    i: &Arc<Inner>,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
    f: impl FnOnce(&Shared<CTokens>, &mut Outbox<CTokens>, &mut i32) -> Step,
) -> zkrs_step {
    let s = require_mt(i);
    drive(i, ob, rc, |_, o, r| f(s, o, r))
}

/// Runs the init until it stops, and installs the driver when the init
/// is ready.
///
/// The init goes back into the handle after a barrier and after a
/// failure. Then `zkrs_resume` continues it, or `zkrs_handle_abandon`
/// discards it. The handle state selects the init, not the resume tag.
/// Thus the function removes the tag from the box first.
fn init_step(
    i: &Arc<Inner>,
    mut init: Init<CTokens>,
    u: &mut Unlocked,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    let step = with_outbox(ob, i, |o| {
        let _tag = o.take_resume();
        match init.step(u, o) {
            InitStep::More => {
                i.put_init(u, init);
                None
            }
            InitStep::SaslPoint => {
                i.put_init(u, init);
                Some(ZKRS_INIT_SASL_POINT)
            }
            InitStep::Ready => match make_driver(i.flavor, init, o) {
                Ok(d) => {
                    if i.install(d).is_err() {
                        abort_with("zk-ffi: the handle has a driver already");
                    }
                    Some(0)
                }
                Err(e) => Some(failure_errno(Some(e))),
            },
            InitStep::Failed(InitError { errno }) => {
                i.put_init(u, init);
                Some(failure_errno(errno))
            }
        }
    });
    match step {
        None => zkrs_step::ZKRS_MORE,
        Some(ZKRS_INIT_SASL_POINT) => {
            raw::write_out(rc, ZKRS_INIT_SASL_POINT);
            zkrs_step::ZKRS_MORE
        }
        Some(r) => step_out(Step::Done(r), rc),
    }
}

/// Makes the driver of the flavor from a ready init.
///
/// mt makes the waker and can fail with an errno. st has no waker and
/// no threads, so it cannot fail.
fn make_driver(flavor: u32, init: Init<CTokens>, o: &mut Outbox<CTokens>) -> Result<Driver, i32> {
    if flavor == ZKRS_FLAVOR_ST {
        return Ok(Driver::St(Arc::new(Polled::from_init(init))));
    }
    Shared::from_init(init, o).map(Driver::Mt)
}

/// Makes a handle and runs the init up to the first barrier.
///
/// The function copies `*a` and `*vt` with `raw::read_struct` and every
/// string with the `raw` readers. It builds the `zk_driver::InitArgs`
/// with `Compat::LEGACY_C` and the mode of `a->flavor`, and calls
/// `Init::new`. A parse error of the chroot leaves `*out` NULL and
/// writes `*rc`. Otherwise `*out` is set before the first barrier. Each
/// barrier returns `ZKRS_MORE`, and `zkrs_resume` continues the init. On
/// `InitStep::Ready` the function installs the driver of `a->flavor`:
/// `Shared` for `ZKRS_FLAVOR_MT`, `Polled` for `ZKRS_FLAVOR_ST`. `*rc`
/// is 0 or the init errno. A failure after `*out` is set needs
/// `zkrs_handle_abandon`. A build without TLS rejects `a->tls == 1`,
/// and a build without SASL rejects `a->sasl == 1`, with `EINVAL`. An
/// unknown flavor aborts.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_handle_new(
    a: *const zkrs_init_args,
    vt: *const zkrs_host_vtable,
    host: usize,
    out: *mut *mut zkrs_handle,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    ffi_guard(|| {
        raw::write_out(out, std::ptr::null_mut());
        let mut args = raw::read_struct(a);
        // Only a wiped copy of the password stays on the stack, on all
        // paths. The connection wipes its own copies when it ends.
        let passwd = Zeroizing::new(args.client_passwd);
        args.client_passwd.zeroize();
        let table = raw::read_struct(vt);
        // One staticlib serves both flavors. Another value is a build
        // error of the shim.
        let (mode, flavor) = match args.flavor {
            ZKRS_FLAVOR_MT => (DriverMode::MT, Flavor::Mt),
            ZKRS_FLAVOR_ST => (DriverMode::ST, Flavor::St),
            _ => abort_with("zk-ffi: no driver for the flavor"),
        };
        // The `ZOO_READONLY` bit of the `zookeeper_init` flags.
        const ZOO_READONLY: i32 = 1;
        let mut cfg = Config::legacy(args.recv_timeout);
        if args.have_client_id != 0 {
            cfg.client_id = ClientId {
                session_id: args.client_id,
                passwd: *passwd,
            };
        }
        cfg.allow_read_only = args.flags & ZOO_READONLY != 0;
        cfg.xid_seed = args.xid_seed;
        cfg.c_char_signed = args.c_char_signed != 0;
        // A setup error ends the init before the Rust handle exists. C
        // then frees its handle and returns NULL with this errno.
        let tls = match tls_setup(&args, &mut cfg) {
            Ok(t) => t,
            Err(e) => return step_out(Step::Done(e), rc),
        };
        if let Err(e) = super::sasl::setup(&args, &mut cfg) {
            return step_out(Step::Done(e), rc);
        }
        let init_args = InitArgs {
            cfg,
            host_string: raw::cstr_opt(args.hosts).unwrap_or_default(),
            compat: Compat::LEGACY_C,
            mode,
            flavor,
        };
        let ffi_host = Arc::new(FfiHost::new(table, host));
        let leaves: Arc<dyn HostLeaves<CTokens>> = ffi_host.clone();
        let mut env = Env::new(leaves);
        env.tls = tls;
        env.cfg.cloexec = args.sock_cloexec != 0;
        let inner = Arc::new(Inner::new(ffi_host, args.flavor));
        let mut u = Unlocked::new_at_entry();
        match with_outbox(ob, &inner, |o| Init::new(init_args, env, o)) {
            // The chroot error comes before the handle exists.
            Err(InitError { errno }) => step_out(Step::Done(failure_errno(errno)), rc),
            Ok(init) => {
                let p = raw::handle_into_raw(Arc::clone(&inner));
                raw::write_out(out, p.cast_mut());
                init_step(&inner, init, &mut u, ob, rc)
            }
        }
    })
}

/// Sets up TLS when `a->tls` is 1.
///
/// The result is the connector of `Env::tls`, or `None` for a plaintext
/// handle. `abi::tls` owns the setup. An error is the init errno.
#[cfg(feature = "tls")]
fn tls_setup(a: &zkrs_init_args, cfg: &mut Config) -> Result<Option<Arc<dyn TlsConnector>>, c_int> {
    if a.tls == 0 {
        return Ok(None);
    }
    super::tls::setup(a, cfg, Compat::LEGACY_C.tls_verify).map(Some)
}

/// Rejects `a->tls == 1`, because this build has no TLS.
#[cfg(not(feature = "tls"))]
fn tls_setup(a: &zkrs_init_args, cfg: &mut Config) -> Result<Option<Arc<dyn TlsConnector>>, c_int> {
    let _ = cfg;
    if a.tls == 0 {
        Ok(None)
    } else {
        Err(libc::EINVAL)
    }
}

/// Adds one strong reference. Each library thread holds one.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_handle_retain(h: *const zkrs_handle) {
    ffi_guard(|| std::mem::forget(raw::handle_arc(h)));
}

/// Gives back one strong reference.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_handle_release(h: *const zkrs_handle) {
    ffi_guard(|| raw::handle_release(h));
}

/// Ends a failed init.
///
/// The function abandons the `Init` (it closes the waker and drops
/// every token), sets the host to 0 and gives back the C reference.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_handle_abandon(h: *const zkrs_handle) {
    ffi_guard(|| {
        let i = raw::handle_arc(h);
        let mut u = Unlocked::new_at_entry();
        if let Some(init) = i.take_init(&mut u) {
            init.abandon();
        }
        // A driver from a ready init holds no C token yet. The driver drops
        // with the last reference.
        i.host().zero();
        drop(i);
        raw::handle_release(h);
    })
}

/// `api_prolog` of a library thread or the init thread.
/// mt only: a call on an st handle aborts.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_thread_enter(h: *const zkrs_handle, role: u32) {
    with_handle(h, |i, _| require_mt(i).thread_enter(role_of(role)));
}

/// `api_epilog`. It can run the final close on this
/// thread, so it returns a step. mt only.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_thread_exit(
    h: *const zkrs_handle,
    role: u32,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| {
        drive_mt(i, ob, rc, |s, o, r| s.thread_exit(role_of(role), o, r))
    })
}

/// The cleanup handler of the dispatch thread. A callback ended that
/// thread, for example with `pthread_exit`.
///
/// The function frees the box of `ob`, and its untaken items get no
/// callback. It then marks the thread as ended and wakes a close that
/// waits for the queued callbacks (`Shared::dispatch_ended`). NULL
/// `impl` is an empty outbox. mt only.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_dispatch_ended(h: *const zkrs_handle, ob: *mut zkrs_outbox) {
    with_handle(h, |i, _| {
        let s = require_mt(i);
        let mut left = take_driver_outbox(ob).unwrap_or_default();
        s.dispatch_ended(&mut left);
    });
}

/// One IO-thread step: interest, poll and process. It returns
/// `ZKRS_MORE` at each barrier and `ZKRS_EXIT` when the IO loop ends. mt
/// only.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_io_step(
    h: *const zkrs_handle,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| drive_mt(i, ob, rc, |s, o, r| s.io_step(o, r)))
}

/// The dispatch-thread wait. It blocks until the FIFO has
/// a batch (`ZKRS_DONE`) or the dispatch loop ends (`ZKRS_EXIT`). mt
/// only.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_wait_dispatch(
    h: *const zkrs_handle,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| drive_mt(i, ob, rc, |s, o, _| s.wait_dispatch(o)))
}

/// `zookeeper_interest`.
///
/// mt: the function writes `{fd = -1, interest = 0, timeout_ms =
/// recv_timeout / 3}` and `*written = 1` from `Shared::interest_exported`,
/// and returns `ZKRS_DONE` with its rc.
///
/// st: the function drives the connection with `Polled::interest`. Each
/// barrier returns `ZKRS_MORE`, and `zkrs_interest_resume`
/// continues the step. The call that finishes writes `*out` and
/// `*written` from the `InterestOut`. A deferred close returns
/// `ZKRS_RELEASE` with the close rc.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_interest(
    h: *const zkrs_handle,
    out: *mut zkrs_interest_out,
    written: *mut c_int,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| match i.driver() {
        // mt reports "no socket" and does not drive the connection.
        Some(Driver::Mt(s)) => {
            let io = s.interest_exported();
            let step = step_out(Step::Done(io.rc), rc);
            write_interest(step, &io, out, written);
            step
        }
        Some(Driver::St(p)) => st_interest(i, p, out, written, ob, rc),
        None => abort_with("zk-ffi: driving call before the init finished"),
    })
}

/// `zookeeper_process`. mt: `ZKRS_DONE` with
/// `Shared::process_exported` (ZINVALIDSTATE).
///
/// st: the function reads and writes the socket with `Polled::process`.
/// `events` has the `ZOOKEEPER_READ` and `ZOOKEEPER_WRITE`
/// bits. Each barrier returns `ZKRS_MORE`, and C runs the callbacks of
/// the outbox inline before `zkrs_resume`. A close from a callback ends
/// with `ZKRS_RELEASE` and the close rc.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_process(
    h: *const zkrs_handle,
    events: i32,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| match i.driver() {
        Some(Driver::Mt(s)) => step_out(Step::Done(s.process_exported()), rc),
        Some(Driver::St(p)) => {
            let events = u32::try_from(events).unwrap_or(0);
            drive(i, ob, rc, |_, o, r| p.process(events, o, r))
        }
        None => abort_with("zk-ffi: driving call before the init finished"),
    })
}

/// `zookeeper_close`.
///
/// The caller role decides the close path: an application thread runs
/// the full close, the IO thread or the dispatch thread runs the
/// deferred close. Each THREAD item is a barrier. The final close sets
/// the host to 0 and returns `ZKRS_RELEASE`.
///
/// st ignores the role. A close from a callback defers to the epilog of
/// the driving call. Otherwise this call runs the final close.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_close(
    h: *const zkrs_handle,
    caller_role: u32,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| {
        drive(i, ob, rc, |d, o, r| match d {
            Driver::Mt(s) => s.close(role_of(caller_role), o, r),
            Driver::St(p) => p.close(o, r),
        })
    })
}

/// Continues the step that stopped at a barrier.
///
/// During the init it steps the `Init`. After the init it calls
/// `Shared::resume` or `Polled::resume`, which read the resume tag of
/// the outbox. A tag of `ResumeAt::Interest` belongs to
/// `zkrs_interest_resume`.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_resume(
    h: *const zkrs_handle,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, u| match i.take_init(u) {
        Some(init) => init_step(i, init, u, ob, rc),
        None => drive(i, ob, rc, |d, o, r| match d {
            Driver::Mt(s) => s.resume(o, r),
            Driver::St(p) => st_resume(p, o, r),
        }),
    })
}

/// `zkrs_resume` for a suspended `zkrs_interest`.
///
/// st only. mt never suspends `zkrs_interest`, so a call on an mt handle
/// aborts. st continues with `Polled::resume` and writes `*out` and
/// `*written` as `zkrs_interest` does.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_interest_resume(
    h: *const zkrs_handle,
    out: *mut zkrs_interest_out,
    written: *mut c_int,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| match i.driver() {
        Some(Driver::Mt(_)) => abort_with("zk-ffi: zkrs_interest_resume on an mt handle"),
        Some(Driver::St(p)) => st_interest_resume(i, p, out, written, ob, rc),
        None => abort_with("zk-ffi: driving call before the init finished"),
    })
}

/// The errno of the last `zookeeper_interest` or `zookeeper_process`
/// call.
///
/// The value is the cause of a failed step: for example ECONNREFUSED,
/// ETIMEDOUT or ESTALE. It is 0 after a step with no cause, and on an mt
/// handle. C reads it after the last step of the call and before a
/// release, and sets `errno` when the value is not 0.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_last_errno(h: *const zkrs_handle) -> c_int {
    with_handle(h, |i, _| i.driver().map_or(0, Driver::last_errno))
}

// The st driving paths.
//
// Each path runs one `Polled` step with the outbox of the call. The step
// returns at each barrier. Thus no Rust frame is on the stack while C
// runs a callback, and no foreign unwind can reach a Rust frame. C
// drains the outbox, then calls `zkrs_resume` or `zkrs_interest_resume`.
// `Polled` keeps the stage, so these paths keep no state across calls.

/// One `zkrs_interest` step of an st handle.
///
/// The function calls `Polled::interest` with a new `InterestOut`
/// through `drive`. A step with a true `InterestOut::written` writes
/// `*out` (fd, bits, timeout) and `*written = 1`. A `Done` or `Release`
/// step with a false `written` writes `*written = 0`. C then keeps the
/// caller values, as legacy C does on an early return. A `More` step
/// with a false `written` writes nothing. A `More` step can have true
/// `written`, because `Polled` stops after `finish_interest` to drain
/// the items of the step (see [`write_interest`]). C writes the outputs
/// also after a release. `Release` goes through `finish_step` with the
/// close rc.
fn st_interest(
    i: &Arc<Inner>,
    p: &Polled<CTokens>,
    out: *mut zkrs_interest_out,
    written: *mut c_int,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    let mut io = InterestOut::UNWRITTEN;
    let step = drive(i, ob, rc, |_, o, r| p.interest(o, &mut io, r));
    write_interest(step, &io, out, written);
    step
}

/// One `zkrs_interest_resume` step of an st handle. The output rules of
/// [`st_interest`] apply, with `Polled::resume` in place of
/// `Polled::interest`.
fn st_interest_resume(
    i: &Arc<Inner>,
    p: &Polled<CTokens>,
    out: *mut zkrs_interest_out,
    written: *mut c_int,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    let mut io = read_interest(out.cast_const(), written.cast_const());
    let step = drive(i, ob, rc, |_, o, r| p.resume(o, &mut io, r));
    write_interest(step, &io, out, written);
    step
}

/// One `zkrs_resume` step of an st handle after the init.
///
/// `Polled::resume` needs an `InterestOut`. C never continues an
/// interest step with `zkrs_resume`. Thus the function gives a scratch
/// value and drops it.
fn st_resume(p: &Polled<CTokens>, o: &mut Outbox<CTokens>, r: &mut i32) -> Step {
    let mut scratch = InterestOut::UNWRITTEN;
    p.resume(o, &mut scratch, r)
}

/// Converts the driver outputs of an interest call to the C view.
///
/// A value that does not fit the C type gives the "no socket" value
/// (fd -1, interest 0), so no conversion can panic.
fn interest_view(io: &InterestOut) -> zkrs_interest_out {
    zkrs_interest_out {
        fd: isize::try_from(io.fd).unwrap_or(-1),
        interest: i32::try_from(io.bits).unwrap_or(0),
        timeout_ms: io.timeout_ms,
    }
}

/// Writes the outputs of one interest call to C.
///
/// When the driver wrote its outputs, the function writes `*out` and
/// `*written = 1`. This also applies to a `ZKRS_MORE` step: `Polled`
/// can reach `finish_interest` and then stop to drain the items of the
/// step. The next resume gets a new `InterestOut`, so the C locals are
/// the only copy of these outputs. A step that ends with no outputs
/// writes `*written = 0`. A `ZKRS_MORE` step with no outputs writes
/// nothing.
fn write_interest(
    step: zkrs_step,
    io: &InterestOut,
    out: *mut zkrs_interest_out,
    written: *mut c_int,
) {
    if io.written {
        raw::write_out(out, interest_view(io));
        raw::write_out(written, 1);
    } else if step != zkrs_step::ZKRS_MORE {
        raw::write_out(written, 0);
    }
}

/// Reads the outputs that an earlier step of the same interest call
/// wrote to the C locals of `zookeeper_interest`.
///
/// `Polled` keeps one `InterestOut` across the steps of an interest
/// call. zk-ffi keeps no state across calls, so the C locals carry the
/// value. The release stage then sees the outputs and sets the fd to -1
/// after it closes the socket, so C keeps no stale fd. With
/// `*written == 0` the value is `InterestOut::UNWRITTEN`.
fn read_interest(out: *const zkrs_interest_out, written: *const c_int) -> InterestOut {
    if raw::read_struct(written) != 1 {
        return InterestOut::UNWRITTEN;
    }
    let v = raw::read_struct(out);
    InterestOut {
        rc: 0,
        written: true,
        fd: RawSock::try_from(v.fd).unwrap_or(-1),
        bits: u32::try_from(v.interest).unwrap_or(0),
        timeout_ms: v.timeout_ms,
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared fixtures of the unit tests: a handle with the stand-in
    //! vtable and no init, init arguments and an empty outbox.

    use std::ffi::CStr;

    use super::*;
    use crate::abi::standin;
    use crate::abi::types::ZKRS_FLAVOR_MT;

    /// Makes a handle pointer. The caller gives it back with
    /// `zkrs_handle_release`.
    pub(crate) fn new_handle() -> *const zkrs_handle {
        let host = Arc::new(FfiHost::new(standin::vtable(), 0x55));
        raw::handle_into_raw(Arc::new(Inner::new(host, ZKRS_FLAVOR_MT)))
    }

    /// The init arguments of a plain mt handle for `hosts`. A test sets
    /// the fields that it needs with the struct update syntax.
    pub(crate) fn init_args(hosts: &CStr) -> zkrs_init_args {
        zkrs_init_args {
            flavor: ZKRS_FLAVOR_MT,
            hosts: hosts.as_ptr(),
            recv_timeout: 30_000,
            have_client_id: 0,
            client_id: 0,
            client_passwd: [0; 16],
            flags: 0,
            tls: 0,
            tls_ca: std::ptr::null(),
            tls_cert: std::ptr::null(),
            tls_key: std::ptr::null(),
            tls_passwd: std::ptr::null(),
            tls_env_allowed: 0,
            sasl: 0,
            xid_seed: 1,
            sock_cloexec: 1,
            c_char_signed: 1,
        }
    }

    /// An outbox with no box.
    pub(crate) fn empty_outbox() -> zkrs_outbox {
        zkrs_outbox {
            r#impl: std::ptr::null_mut(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{empty_outbox, init_args, new_handle};
    use super::*;

    #[test]
    fn retain_and_release_balance() {
        let _rec = crate::abi::standin::recorder();
        let h = new_handle();
        zkrs_handle_retain(h);
        let count = with_handle(h, |i, _| Arc::strong_count(i));
        assert_eq!(count, 3);
        zkrs_handle_release(h);
        let (count, flavor, ready) = with_handle(h, |i, _| {
            (Arc::strong_count(i), i.flavor(), i.driver().is_some())
        });
        assert_eq!(
            (count, flavor, ready),
            (2, crate::abi::types::ZKRS_FLAVOR_MT, false)
        );
        zkrs_handle_release(h);
    }

    #[test]
    fn steps_map_to_the_c_enum() {
        let mut rc: c_int = 0;
        assert_eq!(step_out(Step::Done(-4), &raw mut rc), zkrs_step::ZKRS_DONE);
        assert_eq!(rc, -4);
        assert_eq!(step_out(Step::More, &raw mut rc), zkrs_step::ZKRS_MORE);
        assert_eq!(role_of(ZKRS_ROLE_IO), Role::Io);
        assert_eq!(role_of(99), Role::Foreign);
    }

    use std::ffi::CString;

    use crate::abi::standin;
    use crate::abi::types::{
        ZKRS_FLAVOR_MT, ZKRS_FLAVOR_ST, ZKRS_ROLE_FOREIGN, zkrs_item, zkrs_sockaddr_view,
    };

    /// The legacy `ZINVALIDSTATE`.
    const ZINVALIDSTATE: c_int = -9;

    /// Calls `zkrs_handle_new` and gives `(step, handle, rc)`.
    fn handle_new(
        a: &zkrs_init_args,
        ob: &mut zkrs_outbox,
    ) -> (zkrs_step, *mut zkrs_handle, c_int) {
        let vt = standin::vtable();
        let mut out: *mut zkrs_handle = std::ptr::dangling_mut();
        let mut rc: c_int = 12_345;
        let s = zkrs_handle_new(a, &raw const vt, 0x55, &raw mut out, ob, &raw mut rc);
        (s, out, rc)
    }

    /// Drops the box of `ob`. Its items and its resume tag go with it.
    fn drop_box(ob: &mut zkrs_outbox) {
        drop(raw::outbox_take(ob));
    }

    /// Runs the init to its end. Each barrier drops the box. The init
    /// does not read the resume tag.
    fn ready(hosts: &str) -> *mut zkrs_handle {
        let hosts = CString::new(hosts).unwrap_or_default();
        let a = init_args(&hosts);
        let mut ob = empty_outbox();
        let (mut s, h, mut rc) = handle_new(&a, &mut ob);
        assert!(!h.is_null());
        while s == zkrs_step::ZKRS_MORE {
            drop_box(&mut ob);
            s = zkrs_resume(h, &raw mut ob, &raw mut rc);
        }
        drop_box(&mut ob);
        assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, 0));
        h
    }

    fn loopback() -> zkrs_sockaddr_view {
        zkrs_sockaddr_view::from_addr("127.0.0.1:2181".parse().ok())
    }

    #[test]
    fn handle_new_installs_the_mt_driver() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let h = ready("127.0.0.1:2181,localhost:2182");
        let (ready, flavor) = with_handle(h, |i, _| (i.driver().is_some(), i.flavor()));
        assert_eq!((ready, flavor), (true, ZKRS_FLAVOR_MT));
        assert_eq!(
            standin::resolved(),
            vec![
                (b"127.0.0.1".to_vec(), b"2181".to_vec()),
                (b"localhost".to_vec(), b"2182".to_vec()),
            ]
        );
        zkrs_handle_release(h);
    }

    #[test]
    fn handle_new_installs_the_st_driver() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let hosts = CString::new("127.0.0.1:2181").unwrap_or_default();
        let mut a = init_args(&hosts);
        a.flavor = ZKRS_FLAVOR_ST;
        let mut ob = empty_outbox();
        let (mut s, h, mut rc) = handle_new(&a, &mut ob);
        assert!(!h.is_null());
        while s == zkrs_step::ZKRS_MORE {
            drop_box(&mut ob);
            s = zkrs_resume(h, &raw mut ob, &raw mut rc);
        }
        drop_box(&mut ob);
        assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, 0));
        let (st, flavor, state) = with_handle(h, |i, _| {
            let st = matches!(i.driver(), Some(Driver::St(_)));
            (st, i.flavor(), i.driver().map_or(-1, Driver::state))
        });
        // ZOO_NOTCONNECTED_STATE until the first `zookeeper_interest`.
        assert_eq!((st, flavor, state), (true, ZKRS_FLAVOR_ST, 999));
        // The init holds no C token, and the driver has no socket yet.
        // Abandon ends the handle with no final close.
        zkrs_handle_retain(h);
        zkrs_handle_abandon(h);
        zkrs_handle_release(h);
    }

    /// The thread start fails after the init installed the driver and
    /// entered the init prolog. Abandon then ends the handle with no abort.
    #[test]
    fn abandon_after_a_ready_init_ends_the_handle() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let h = ready("127.0.0.1:2181");
        zkrs_thread_enter(h, ZKRS_ROLE_INIT);
        zkrs_handle_retain(h);
        zkrs_handle_release(h);
        zkrs_handle_abandon(h);
    }

    #[test]
    fn handle_new_rejects_an_empty_host_list() {
        let _rec = standin::recorder();
        for text in [",", ",,"] {
            let hosts = CString::new(text).unwrap_or_default();
            let mut ob = empty_outbox();
            let (s, h, rc) = handle_new(&init_args(&hosts), &mut ob);
            drop_box(&mut ob);
            assert_eq!(
                (s, h.is_null(), rc),
                (zkrs_step::ZKRS_DONE, true, libc::EINVAL)
            );
        }
        assert!(standin::resolved().is_empty());
    }

    #[test]
    fn handle_new_leaves_out_null_on_a_bad_chroot() {
        let _rec = standin::recorder();
        let hosts = CString::new("127.0.0.1:2181/bad/").unwrap_or_default();
        let mut ob = empty_outbox();
        let (s, h, rc) = handle_new(&init_args(&hosts), &mut ob);
        drop_box(&mut ob);
        assert_eq!(
            (s, h.is_null(), rc),
            (zkrs_step::ZKRS_DONE, true, libc::EINVAL)
        );
        assert!(standin::resolved().is_empty());
    }

    #[test]
    fn handle_new_takes_tls_and_sasl_only_in_their_builds() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let hosts = CString::new("127.0.0.1:2181").unwrap_or_default();
        let mut tls = init_args(&hosts);
        tls.tls = 1;
        let mut sasl = init_args(&hosts);
        sasl.sasl = 1;
        for (a, built) in [(tls, cfg!(feature = "tls")), (sasl, cfg!(feature = "sasl"))] {
            let mut ob = empty_outbox();
            let (mut s, h, mut rc) = handle_new(&a, &mut ob);
            if !built {
                // A build without the feature rejects the flag.
                assert_eq!(
                    (s, h.is_null(), rc),
                    (zkrs_step::ZKRS_DONE, true, libc::EINVAL)
                );
                assert!(ob.r#impl.is_null());
                continue;
            }
            // A build with the feature makes the handle. The SASL init
            // stops once at the SASL point, and then it completes.
            assert!(!h.is_null());
            let mut sasl_points = 0u32;
            while s == zkrs_step::ZKRS_MORE {
                if rc == ZKRS_INIT_SASL_POINT {
                    sasl_points = sasl_points.saturating_add(1);
                }
                drop_box(&mut ob);
                s = zkrs_resume(h, &raw mut ob, &raw mut rc);
            }
            drop_box(&mut ob);
            assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, 0));
            assert_eq!(sasl_points, u32::from(a.sasl == 1));
            zkrs_handle_release(h);
        }
    }

    #[test]
    fn a_failed_resolution_gives_the_errno_and_abandon_ends_it() {
        let _rec = standin::recorder();
        standin::set_resolve(Vec::new(), Vec::new(), libc::ENOENT, -2);
        let hosts = CString::new("nohost1:2181,nohost2:2181").unwrap_or_default();
        let mut ob = empty_outbox();
        let (mut s, h, mut rc) = handle_new(&init_args(&hosts), &mut ob);
        assert!(!h.is_null());
        // The error line of the first host is a barrier before the second.
        let mut barriers = 0u32;
        while s == zkrs_step::ZKRS_MORE {
            barriers = barriers.saturating_add(1);
            drop_box(&mut ob);
            s = zkrs_resume(h, &raw mut ob, &raw mut rc);
        }
        drop_box(&mut ob);
        assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, libc::ENOENT));
        assert!(barriers >= 1);
        assert_eq!(standin::resolved().len(), 2);
        zkrs_handle_retain(h);
        zkrs_handle_abandon(h);
        let (count, zero, init, ready) = with_handle(h, |i, u| {
            (
                Arc::strong_count(i),
                i.host().is_zero(),
                i.take_init(u).is_some(),
                i.driver().is_some(),
            )
        });
        assert_eq!((count, zero, init, ready), (2, true, false, false));
        // The init holds no C token. Thus discard_token gets no call.
        assert!(standin::discarded().is_empty());
        zkrs_handle_release(h);
    }

    #[test]
    fn abandon_at_a_barrier_discards_the_init() {
        let _rec = standin::recorder();
        standin::set_resolve(Vec::new(), Vec::new(), libc::ENOENT, -2);
        let hosts = CString::new("nohost1:2181,nohost2:2181").unwrap_or_default();
        let mut ob = empty_outbox();
        let (s, h, _) = handle_new(&init_args(&hosts), &mut ob);
        assert_eq!(s, zkrs_step::ZKRS_MORE);
        assert!(!ob.r#impl.is_null());
        drop_box(&mut ob);
        zkrs_handle_retain(h);
        zkrs_handle_abandon(h);
        let (count, zero, init) = with_handle(h, |i, u| {
            (
                Arc::strong_count(i),
                i.host().is_zero(),
                i.take_init(u).is_some(),
            )
        });
        assert_eq!((count, zero, init), (2, true, false));
        assert!(standin::discarded().is_empty());
        zkrs_handle_release(h);
    }

    #[test]
    fn mt_interest_and_process_give_the_exported_values() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let h = ready("127.0.0.1:2181");
        let mut ob = empty_outbox();
        let mut out = zkrs_interest_out {
            fd: 7,
            interest: 7,
            timeout_ms: 7,
        };
        let mut written: c_int = 0;
        let mut rc: c_int = 1;
        let s = zkrs_interest(h, &raw mut out, &raw mut written, &raw mut ob, &raw mut rc);
        assert_eq!((s, rc, written), (zkrs_step::ZKRS_DONE, 0, 1));
        assert_eq!(
            out,
            zkrs_interest_out {
                fd: -1,
                interest: 0,
                timeout_ms: 10_000,
            }
        );
        let s = zkrs_process(h, 3, &raw mut ob, &raw mut rc);
        assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, ZINVALIDSTATE));
        assert!(ob.r#impl.is_null());
        zkrs_handle_release(h);
    }

    #[test]
    fn the_init_thread_enters_and_leaves() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let h = ready("127.0.0.1:2181");
        let mut ob = empty_outbox();
        let mut rc: c_int = 1;
        zkrs_thread_enter(h, ZKRS_ROLE_INIT);
        let s = zkrs_thread_exit(h, ZKRS_ROLE_INIT, &raw mut ob, &raw mut rc);
        drop_box(&mut ob);
        assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, 0));
        zkrs_handle_release(h);
    }

    /// Drains `ob` and ends the drain, as `zks_drain` does.
    fn drain(ob: &mut zkrs_outbox) {
        let mut it = zkrs_item::empty();
        while crate::abi::outbox::zkrs_outbox_next(ob, &raw mut it) == 1 {}
        crate::abi::outbox::zkrs_outbox_finish(ob);
    }

    #[test]
    fn an_app_close_with_no_threads_releases_the_handle() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let h = ready("127.0.0.1:2181");
        zkrs_handle_retain(h);
        let mut ob = empty_outbox();
        let mut rc: c_int = 1;
        let mut s = zkrs_close(h, ZKRS_ROLE_FOREIGN, &raw mut ob, &raw mut rc);
        while s == zkrs_step::ZKRS_MORE {
            drain(&mut ob);
            s = zkrs_resume(h, &raw mut ob, &raw mut rc);
        }
        drain(&mut ob);
        assert_eq!((s, rc), (zkrs_step::ZKRS_RELEASE, 0));
        let zero = with_handle(h, |i, _| i.host().is_zero());
        assert!(zero);
        zkrs_handle_release(h);
        zkrs_handle_release(h);
    }

    /// A callback ends the dispatch thread before it delivers its batch.
    /// The batch holds the ZCLOSING result of the close pump. The cleanup
    /// handler discards the batch, so the close does not wait for it. The
    /// joining close gives back the ref of that thread and releases the
    /// handle.
    #[test]
    fn a_dispatch_end_gives_its_ref_to_the_joining_close() {
        let _rec = standin::recorder();
        standin::set_resolve(vec![loopback()], Vec::new(), 0, 0);
        let h = ready("127.0.0.1:2181");
        zkrs_handle_retain(h);
        zkrs_thread_enter(h, ZKRS_ROLE_DISPATCH);
        submit_exists(h, 41);
        let mut ob = empty_outbox();
        let mut rc: c_int = 1;
        let mut joined = false;
        let mut s = zkrs_close(h, ZKRS_ROLE_FOREIGN, &raw mut ob, &raw mut rc);
        loop {
            let mut it = zkrs_item::empty();
            while crate::abi::outbox::zkrs_outbox_next(&raw mut ob, &raw mut it) == 1 {
                let join = it.r#type == crate::abi::types::zkrs_item_type::ZKRS_ITEM_THREAD as u32
                    && it.thread_op == crate::abi::types::zkrs_thread_op::ZKRS_THREAD_JOIN as u32;
                if join && it.thread_role == ZKRS_ROLE_IO {
                    // The dispatch thread takes the ZCLOSING result, and
                    // a callback ends it before the delivery.
                    let mut dob = empty_outbox();
                    let mut drc: c_int = -1;
                    let first = zkrs_wait_dispatch(h, &raw mut dob, &raw mut drc);
                    assert_eq!(first, zkrs_step::ZKRS_DONE);
                    assert!(!dob.r#impl.is_null());
                    zkrs_dispatch_ended(h, &raw mut dob);
                    zkrs_handle_release(h);
                    joined = true;
                }
            }
            crate::abi::outbox::zkrs_outbox_finish(&raw mut ob);
            if s != zkrs_step::ZKRS_MORE {
                break;
            }
            s = zkrs_resume(h, &raw mut ob, &raw mut rc);
        }
        assert!(joined);
        assert_eq!((s, rc), (zkrs_step::ZKRS_RELEASE, 0));
        assert_eq!(standin::discarded(), [41]);
        let zero = with_handle(h, |i, _| i.host().is_zero());
        assert!(zero);
        zkrs_handle_release(h);
    }

    // The st driving paths. The calls follow `zookeeper_interest`,
    // `zookeeper_process` and `zookeeper_close` of the shim.

    /// The legacy `ZOK`.
    const ZOK: c_int = 0;
    /// The C values of `zkrs_item_type`.
    const ITEM_RESULT: u32 = 2;
    const ITEM_WATCH: u32 = 3;
    /// `ZOO_CONNECTED_STATE`.
    const CONNECTED: i32 = 3;
    /// The port of the no-server tests. These tests need no server on
    /// the port. The server tests take their port from
    /// [`PORT_BASE_ENV`].
    const ST_PORT: u16 = 23_000;
    /// A value that no interest step writes.
    const SENTINEL: zkrs_interest_out = zkrs_interest_out {
        fd: 77,
        interest: 77,
        timeout_ms: 77,
    };

    /// One drained item, as the tests see it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Seen {
        Result { token: usize, rc: i32 },
        Watch { kind: i32, state: i32 },
        Other(u32),
    }

    fn seen(it: &zkrs_item) -> Seen {
        match it.r#type {
            ITEM_RESULT => Seen::Result {
                token: it.token,
                rc: raw::read_struct(it.result).rc,
            },
            ITEM_WATCH => {
                let w = raw::read_struct(it.watch);
                Seen::Watch {
                    kind: w.r#type,
                    state: w.state,
                }
            }
            t => Seen::Other(t),
        }
    }

    /// Drains `ob` as `zks_drain` does. `f` is the callback of each item.
    fn drain_with(ob: &mut zkrs_outbox, f: &mut dyn FnMut(Seen)) -> Vec<Seen> {
        let mut it = zkrs_item::empty();
        let mut batch = Vec::new();
        while crate::abi::outbox::zkrs_outbox_next(ob, &raw mut it) == 1 {
            let s = seen(&it);
            f(s);
            batch.push(s);
        }
        crate::abi::outbox::zkrs_outbox_finish(ob);
        batch
    }

    /// Makes an st handle for `127.0.0.1:port` with a finished init.
    fn st_ready(port: u16) -> *mut zkrs_handle {
        let text = format!("127.0.0.1:{port}");
        let addr = zkrs_sockaddr_view::from_addr(text.parse().ok());
        standin::set_resolve(vec![addr], Vec::new(), 0, 0);
        let hosts = CString::new(text).unwrap_or_default();
        let mut a = init_args(&hosts);
        a.flavor = ZKRS_FLAVOR_ST;
        a.recv_timeout = 10_000;
        let mut ob = empty_outbox();
        let (mut s, h, mut rc) = handle_new(&a, &mut ob);
        assert!(!h.is_null());
        while s == zkrs_step::ZKRS_MORE {
            drop_box(&mut ob);
            s = zkrs_resume(h, &raw mut ob, &raw mut rc);
        }
        drop_box(&mut ob);
        assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, ZOK));
        h
    }

    /// The result of one C-style driving call.
    struct Call {
        step: zkrs_step,
        rc: c_int,
        batches: Vec<Vec<Seen>>,
    }

    /// Runs `zookeeper_interest` as the shim does. The C locals `out` and
    /// `written` stay across the steps. A `More` step with `*written ==
    /// 0` must leave `out` as the caller gave it.
    fn c_interest(
        h: *const zkrs_handle,
        out: &mut zkrs_interest_out,
        written: &mut c_int,
        f: &mut dyn FnMut(Seen),
    ) -> Call {
        let before = *out;
        let mut ob = empty_outbox();
        let mut rc: c_int = ZOK;
        let mut step = zkrs_interest(h, out, written, &raw mut ob, &raw mut rc);
        let mut batches = Vec::new();
        loop {
            batches.push(drain_with(&mut ob, f));
            if step != zkrs_step::ZKRS_MORE {
                break;
            }
            if *written == 0 {
                assert_eq!(*out, before, "a More step wrote the outputs");
            }
            step = zkrs_interest_resume(h, out, written, &raw mut ob, &raw mut rc);
        }
        Call { step, rc, batches }
    }

    /// Runs `zookeeper_process` or `zookeeper_close` as the shim does.
    fn c_call(
        h: *const zkrs_handle,
        first: impl FnOnce(&mut zkrs_outbox, &mut c_int) -> zkrs_step,
        f: &mut dyn FnMut(Seen),
    ) -> Call {
        let mut ob = empty_outbox();
        let mut rc: c_int = ZOK;
        let mut step = first(&mut ob, &mut rc);
        let mut batches = Vec::new();
        loop {
            batches.push(drain_with(&mut ob, f));
            if step != zkrs_step::ZKRS_MORE {
                break;
            }
            step = zkrs_resume(h, &raw mut ob, &raw mut rc);
        }
        Call { step, rc, batches }
    }

    fn c_process(h: *const zkrs_handle, events: i32, f: &mut dyn FnMut(Seen)) -> Call {
        c_call(h, |ob, rc| zkrs_process(h, events, ob, rc), f)
    }

    fn c_close(h: *const zkrs_handle, f: &mut dyn FnMut(Seen)) -> Call {
        c_call(h, |ob, rc| zkrs_close(h, ZKRS_ROLE_FOREIGN, ob, rc), f)
    }

    fn ignore(_: Seen) {}

    #[test]
    fn st_process_before_the_first_interest_is_invalid() {
        let _rec = standin::recorder();
        let h = st_ready(ST_PORT);
        let c = c_process(h, 3, &mut ignore);
        assert_eq!((c.step, c.rc), (zkrs_step::ZKRS_DONE, ZINVALIDSTATE));
        assert!(c.batches.iter().all(Vec::is_empty));
        // The handle stays usable: a close ends it.
        zkrs_handle_retain(h);
        let c = c_close(h, &mut ignore);
        assert_eq!((c.step, c.rc), (zkrs_step::ZKRS_RELEASE, ZOK));
        zkrs_handle_release(h);
        zkrs_handle_release(h);
    }

    #[test]
    fn st_close_before_the_first_interest_releases_the_handle() {
        let _rec = standin::recorder();
        let h = st_ready(ST_PORT);
        zkrs_handle_retain(h);
        let c = c_close(h, &mut ignore);
        assert_eq!((c.step, c.rc), (zkrs_step::ZKRS_RELEASE, ZOK));
        let zero = with_handle(h, |i, _| i.host().is_zero());
        assert!(zero);
        // No request was open, so no token went back.
        assert!(standin::discarded().is_empty());
        // `zks_release` gives back the C reference.
        zkrs_handle_release(h);
        zkrs_handle_release(h);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri has no fcntl(F_SETFD), which sets CLOEXEC on the socket"
    )]
    fn st_interest_with_no_server_follows_the_output_rules() {
        let _rec = standin::recorder();
        let h = st_ready(ST_PORT);
        let mut out = SENTINEL;
        let mut written: c_int = 0;
        let c = c_interest(h, &mut out, &mut written, &mut ignore);
        assert_eq!(c.step, zkrs_step::ZKRS_DONE);
        // The connect is in progress or failed. C sees ZOK in both cases
        // and polls again after the timeout.
        assert_eq!((c.rc, written), (ZOK, 1));
        assert_ne!(out, SENTINEL);
        assert!(out.timeout_ms >= 0 && out.timeout_ms <= 10_000, "{out:?}");
        if out.fd >= 0 {
            // ZOOKEEPER_WRITE (1) waits for the connect.
            assert_eq!(out.interest & 1, 1, "{out:?}");
        }
        zkrs_handle_retain(h);
        let c = c_close(h, &mut ignore);
        assert_eq!((c.step, c.rc), (zkrs_step::ZKRS_RELEASE, ZOK));
        zkrs_handle_release(h);
        zkrs_handle_release(h);
    }

    #[test]
    fn st_interest_after_the_close_keeps_the_caller_values() {
        let _rec = standin::recorder();
        let h = st_ready(ST_PORT);
        zkrs_handle_retain(h);
        let c = c_close(h, &mut ignore);
        assert_eq!(c.step, zkrs_step::ZKRS_RELEASE);
        zkrs_handle_release(h);
        // Only this test keeps a reference after the release. The driver
        // ended, so the call gives ZINVALIDSTATE with no outputs. C then
        // keeps the values of the caller.
        let mut out = SENTINEL;
        let mut written: c_int = 1;
        let c = c_interest(h, &mut out, &mut written, &mut ignore);
        assert_eq!((c.step, c.rc), (zkrs_step::ZKRS_DONE, ZINVALIDSTATE));
        assert_eq!((written, out), (0, SENTINEL));
        zkrs_handle_release(h);
    }

    #[test]
    fn interest_views_fall_back_to_no_socket() {
        let io = InterestOut {
            rc: 0,
            written: true,
            fd: 5,
            bits: u32::MAX,
            timeout_ms: 9,
        };
        assert_eq!(
            interest_view(&io),
            zkrs_interest_out {
                fd: 5,
                interest: 0,
                timeout_ms: 9,
            }
        );
        let bad = zkrs_interest_out {
            fd: isize::MAX,
            interest: -1,
            timeout_ms: 4,
        };
        let one: c_int = 1;
        let got = read_interest(&raw const bad, &raw const one);
        assert_eq!(
            (got.written, got.fd, got.bits, got.timeout_ms),
            (true, -1, 0, 4)
        );
        let zero: c_int = 0;
        let got = read_interest(&raw const bad, &raw const zero);
        assert!(!got.written);
    }

    #[test]
    fn write_interest_writes_only_real_outputs() {
        let io = InterestOut {
            rc: 0,
            written: true,
            fd: 6,
            bits: 3,
            timeout_ms: 1_000,
        };
        let want = zkrs_interest_out {
            fd: 6,
            interest: 3,
            timeout_ms: 1_000,
        };
        for step in [zkrs_step::ZKRS_MORE, zkrs_step::ZKRS_DONE] {
            let (mut out, mut written) = (SENTINEL, 0);
            write_interest(step, &io, &raw mut out, &raw mut written);
            assert_eq!((out, written), (want, 1), "{step:?}");
        }
        let none = InterestOut::UNWRITTEN;
        let (mut out, mut written) = (SENTINEL, 7);
        write_interest(zkrs_step::ZKRS_MORE, &none, &raw mut out, &raw mut written);
        assert_eq!((out, written), (SENTINEL, 7));
        for step in [zkrs_step::ZKRS_DONE, zkrs_step::ZKRS_RELEASE] {
            let (mut out, mut written) = (SENTINEL, 7);
            write_interest(step, &none, &raw mut out, &raw mut written);
            assert_eq!((out, written), (SENTINEL, 0), "{step:?}");
        }
    }

    // The server tests. They follow the workspace convention for
    // real-server tests. `ZK_TEST_PORT_BASE` gives the port range of the
    // run, and the tests start and stop their server with
    // `dev/test-server.sh`. With no base, or when the server cannot
    // start, a test skips. For example:
    // `ZK_TEST_PORT_BASE=<base> cargo test -p zk-ffi -- --ignored st_`.

    /// The environment variable that holds the first port of the range.
    const PORT_BASE_ENV: &str = "ZK_TEST_PORT_BASE";
    /// The offset of the shared st server in the port range.
    const SERVER_OFFSET: u16 = 0;

    /// The port of the shared server, or `None` when the base is not set
    /// or not valid.
    fn server_port() -> Option<u16> {
        let base: u16 = std::env::var(PORT_BASE_ENV).ok()?.trim().parse().ok()?;
        base.checked_add(SERVER_OFFSET)
    }

    /// Runs `dev/test-server.sh CMD PORT` and tells if it succeeded.
    fn test_server(cmd: &str, port: u16) -> bool {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dev/test-server.sh");
        std::process::Command::new("bash")
            .arg(script)
            .arg(cmd)
            .arg(port.to_string())
            .stdout(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// The use count and the port of the shared server. The server runs
    /// while the count is not 0.
    static SERVER: std::sync::Mutex<(usize, Option<u16>)> = std::sync::Mutex::new((0, None));

    /// A use of the shared server. The drop of the last guard stops the
    /// server.
    struct ServerGuard {
        port: u16,
    }

    impl Drop for ServerGuard {
        fn drop(&mut self) {
            let mut st = SERVER
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.0 = st.0.saturating_sub(1);
            if st.0 == 0 {
                if let Some(port) = st.1.take() {
                    test_server("stop", port);
                }
            }
        }
    }

    /// Writes the reason for a skipped test.
    #[allow(clippy::print_stderr, reason = "the test harness shows the skip note")]
    fn skip(why: &str) {
        eprintln!("skip: {why}");
    }

    /// Starts the shared server if it does not run, or gives `None` to
    /// skip the test.
    fn server_or_skip() -> Option<ServerGuard> {
        let Some(port) = server_port() else {
            skip(&format!("{PORT_BASE_ENV} is not set"));
            return None;
        };
        let mut st = SERVER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.1.is_none() {
            if !test_server("start", port) {
                // A failed start can leave a server process.
                test_server("stop", port);
                skip(&format!("no ZooKeeper server can start on port {port}"));
                return None;
            }
            st.1 = Some(port);
        }
        st.0 = st.0.saturating_add(1);
        Some(ServerGuard { port })
    }

    /// Waits for the events of the last interest call, as the poll of
    /// the application does.
    fn wait(h: *const zkrs_handle, out: &zkrs_interest_out, written: c_int) -> i32 {
        let io = read_interest(out, &raw const written);
        let wait_ms = i32::try_from(out.timeout_ms.clamp(0, 200)).unwrap_or(200);
        let events = with_handle(h, |i, _| match i.driver() {
            Some(Driver::St(p)) => p.wait_events(&io, wait_ms),
            _ => 0,
        });
        i32::try_from(events).unwrap_or(0)
    }

    /// Runs the event loop of the application once: interest, poll and
    /// process. Each step must end with `ZKRS_DONE`.
    fn turn(h: *const zkrs_handle, f: &mut dyn FnMut(Seen)) -> Vec<Seen> {
        let mut out = SENTINEL;
        let mut written: c_int = 0;
        let c = c_interest(h, &mut out, &mut written, f);
        assert_eq!(c.step, zkrs_step::ZKRS_DONE, "rc {}", c.rc);
        let mut all: Vec<Seen> = c.batches.concat();
        let events = wait(h, &out, written);
        if events != 0 {
            let c = c_process(h, events, f);
            assert_eq!(c.step, zkrs_step::ZKRS_DONE, "rc {}", c.rc);
            all.extend(c.batches.concat());
        }
        all
    }

    fn state(h: *const zkrs_handle) -> i32 {
        with_handle(h, |i, _| i.driver().map_or(-1, Driver::state))
    }

    /// Turns the loop until the handle is connected. It gives the items
    /// of every call.
    fn connect(h: *const zkrs_handle) -> Vec<Seen> {
        let mut all = Vec::new();
        for _ in 0..100 {
            all.extend(turn(h, &mut ignore));
            if state(h) == CONNECTED {
                break;
            }
        }
        assert_eq!(state(h), CONNECTED, "the st handle did not connect");
        all
    }

    /// Submits `exists /` with `token` (QUEUED delivery, as `zoo_aexists`).
    fn submit_exists(h: *const zkrs_handle, token: usize) {
        let rq = crate::abi::types::zkrs_request {
            op: crate::abi::types::ZKRS_OP_EXISTS,
            flags: 0,
            path: c"/".as_ptr(),
            data: std::ptr::null(),
            datalen: -1,
            acl: std::ptr::null(),
            mode: 0,
            ttl: -1,
            version: -1,
            reconfig_version: -1,
            joining: std::ptr::null(),
            leaving: std::ptr::null(),
            members: std::ptr::null(),
            watch_fn: 0,
            watch_ctx: 0,
            wtype: 0,
            ops: std::ptr::null(),
            ops_len: 0,
            count: 0,
        };
        let mut ob = empty_outbox();
        let st = crate::abi::submit::zkrs_submit(
            h,
            &raw const rq,
            token,
            crate::abi::types::ZKRS_DELIVER_QUEUED,
            &raw mut ob,
        );
        drain(&mut ob);
        assert_eq!(st, crate::abi::types::zkrs_status::ZKRS_OK);
    }

    #[test]
    #[ignore = "real-server"]
    fn st_connects_through_interest_and_process() {
        let Some(server) = server_or_skip() else {
            return;
        };
        let _rec = standin::recorder();
        let h = st_ready(server.port);
        let seen = connect(h);
        // The connect event reaches C as a session event.
        let want = Seen::Watch {
            kind: -1,
            state: CONNECTED,
        };
        assert!(seen.contains(&want), "{seen:?}");
        let mut out = SENTINEL;
        let mut written: c_int = 0;
        let c = c_interest(h, &mut out, &mut written, &mut ignore);
        assert_eq!((c.step, c.rc, written), (zkrs_step::ZKRS_DONE, ZOK, 1));
        assert!(out.fd >= 0, "{out:?}");
        zkrs_handle_retain(h);
        let c = c_close(h, &mut ignore);
        assert_eq!((c.step, c.rc), (zkrs_step::ZKRS_RELEASE, ZOK));
        zkrs_handle_release(h);
        zkrs_handle_release(h);
    }

    #[test]
    #[ignore = "real-server"]
    fn st_session_event_ends_a_batch() {
        let Some(server) = server_or_skip() else {
            return;
        };
        let _rec = standin::recorder();
        let h = st_ready(server.port);
        let mut batches = Vec::new();
        for _ in 0..100 {
            let mut out = SENTINEL;
            let mut written: c_int = 0;
            let c = c_interest(h, &mut out, &mut written, &mut ignore);
            batches.extend(c.batches);
            let events = wait(h, &out, written);
            if events != 0 {
                batches.extend(c_process(h, events, &mut ignore).batches);
            }
            if state(h) == CONNECTED {
                break;
            }
        }
        // A WATCH item is a barrier: C runs its callbacks with no Rust
        // frame on the stack, so the watch is the last item of its batch.
        let session = batches
            .iter()
            .find(|b| b.iter().any(|s| matches!(s, Seen::Watch { kind: -1, .. })));
        let last = session.and_then(|b| b.last().copied());
        assert_eq!(
            last,
            Some(Seen::Watch {
                kind: -1,
                state: CONNECTED,
            }),
            "{batches:?}"
        );
        zkrs_handle_retain(h);
        let c = c_close(h, &mut ignore);
        assert_eq!(c.step, zkrs_step::ZKRS_RELEASE);
        zkrs_handle_release(h);
        zkrs_handle_release(h);
    }

    #[test]
    #[ignore = "real-server"]
    fn st_submit_gives_its_result() {
        let Some(server) = server_or_skip() else {
            return;
        };
        let _rec = standin::recorder();
        let h = st_ready(server.port);
        connect(h);
        submit_exists(h, 0x7000);
        let want = Seen::Result {
            token: 0x7000,
            rc: ZOK,
        };
        let mut got = false;
        for _ in 0..100 {
            if turn(h, &mut ignore).contains(&want) {
                got = true;
                break;
            }
        }
        assert!(got);
        zkrs_handle_retain(h);
        let c = c_close(h, &mut ignore);
        assert_eq!((c.step, c.rc), (zkrs_step::ZKRS_RELEASE, ZOK));
        zkrs_handle_release(h);
        zkrs_handle_release(h);
        assert!(standin::discarded().is_empty());
    }

    #[test]
    #[ignore = "real-server"]
    fn st_close_from_a_callback_releases_at_the_end_of_the_call() {
        let Some(server) = server_or_skip() else {
            return;
        };
        let _rec = standin::recorder();
        let h = st_ready(server.port);
        connect(h);
        submit_exists(h, 0x7001);
        zkrs_handle_retain(h);
        let mut nested: Option<(zkrs_step, c_int)> = None;
        let mut end: Option<(zkrs_step, c_int)> = None;
        for _ in 0..100 {
            let mut on_item = |s: Seen| {
                if let Seen::Result { token: 0x7001, .. } = s {
                    // The completion closes the handle. The close defers
                    // to the epilog of the enclosing call.
                    let c = c_close(h, &mut ignore);
                    nested = Some((c.step, c.rc));
                }
            };
            let mut out = SENTINEL;
            let mut written: c_int = 0;
            let c = c_interest(h, &mut out, &mut written, &mut on_item);
            if c.step == zkrs_step::ZKRS_RELEASE {
                end = Some((c.step, c.rc));
                break;
            }
            let events = wait(h, &out, written);
            if events != 0 {
                let c = c_process(h, events, &mut on_item);
                if c.step == zkrs_step::ZKRS_RELEASE {
                    end = Some((c.step, c.rc));
                    break;
                }
            }
        }
        assert_eq!(nested, Some((zkrs_step::ZKRS_DONE, ZOK)));
        // The enclosing call ends with its own rc.
        assert_eq!(end, Some((zkrs_step::ZKRS_RELEASE, ZOK)));
        let zero = with_handle(h, |i, _| i.host().is_zero());
        assert!(zero);
        zkrs_handle_release(h);
        zkrs_handle_release(h);
    }
}
