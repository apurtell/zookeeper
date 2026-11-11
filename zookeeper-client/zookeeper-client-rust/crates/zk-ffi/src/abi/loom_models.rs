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

//! The loom models of the close mark at the C ABI.
//!
//! loom threads play the IO thread, the dispatch thread and the
//! application of the shim. They call the C exports in the order of
//! `zks_threads.c`. The models check that each completion token has
//! exactly one end. Either the dispatch thread delivers it, or the
//! submit gives it back to C. A discard of an accepted token is a lost
//! completion for the application, so the models reject it. The models
//! also check that the dispatch thread leaves only after the close mark.
//! When a callback ends the dispatch thread, the cleanup handler of the
//! shim discards the tokens that no callback can take.
//!
//! The models need the stand-in vtable and the handle fixtures, so they
//! are unit tests. Run them with `cargo xtask loom`.
//!
//! loom runs every thread on one OS thread. So the thread-local record
//! of the stand-in sees the discards of all threads. The IO thread does
//! not poll, because a blocking poll stops the whole model.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_macros,
    reason = "test code may panic and assert"
)]

use std::collections::BTreeMap;
use std::ffi::{CString, c_int};
use std::sync::Arc;

use loom::thread::{self, JoinHandle};
use zk_driver::sync::Mutex;
use zk_jute::rc::ZCLOSING;

use super::handle::test_support::{empty_outbox, init_args};
use super::handle::{
    zkrs_close, zkrs_dispatch_ended, zkrs_handle_new, zkrs_handle_release, zkrs_handle_retain,
    zkrs_resume, zkrs_thread_enter, zkrs_thread_exit, zkrs_wait_dispatch,
};
use super::outbox::{zkrs_outbox_finish, zkrs_outbox_next};
use super::raw;
use super::standin;
use super::submit::zkrs_submit;
use super::types::{
    ZKRS_DELIVER_QUEUED, ZKRS_OP_EXISTS, ZKRS_ROLE_DISPATCH, ZKRS_ROLE_FOREIGN, ZKRS_ROLE_IO,
    zkrs_handle, zkrs_item, zkrs_item_type, zkrs_outbox, zkrs_request, zkrs_sockaddr_view,
    zkrs_status, zkrs_step, zkrs_thread_op,
};

/// The default preemption bound. `LOOM_MAX_PREEMPTIONS` overrides it.
const DEFAULT_PREEMPTIONS: usize = 3;

/// The server address of the handle. No model opens a socket.
const HOSTS: &str = "127.0.0.1:23751";

fn model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    if b.preemption_bound.is_none() {
        b.preemption_bound = Some(DEFAULT_PREEMPTIONS);
    }
    b.check(f);
}

/// A handle pointer that a loom thread can take. The address keeps its
/// provenance, so the pointer is valid again on the other thread.
#[derive(Clone, Copy)]
struct H(usize);

impl H {
    fn of(h: *const zkrs_handle) -> Self {
        Self(h.expose_provenance())
    }

    fn get(self) -> *const zkrs_handle {
        std::ptr::with_exposed_provenance(self.0)
    }
}

/// The token ends that one thread saw: token to the result codes.
type Delivered = BTreeMap<usize, Vec<i32>>;

/// Makes an mt handle with a finished init, as `zookeeper_init` does
/// before it starts the threads.
fn ready() -> H {
    let addr = zkrs_sockaddr_view::from_addr(HOSTS.parse().ok());
    standin::set_resolve(vec![addr], Vec::new(), 0, 0);
    let hosts = CString::new(HOSTS).unwrap();
    let a = init_args(&hosts);
    let vt = standin::vtable();
    let mut out: *mut zkrs_handle = std::ptr::null_mut();
    let mut ob = empty_outbox();
    let mut rc: c_int = -1;
    let mut s = zkrs_handle_new(&a, &vt, 0x55, &mut out, &mut ob, &mut rc);
    assert!(!out.is_null());
    while s == zkrs_step::ZKRS_MORE {
        drop(raw::outbox_take(&mut ob));
        s = zkrs_resume(out, &mut ob, &mut rc);
    }
    drop(raw::outbox_take(&mut ob));
    assert_eq!((s, rc), (zkrs_step::ZKRS_DONE, 0));
    H::of(out)
}

/// The exists request of "/a".
fn exists() -> zkrs_request {
    zkrs_request {
        op: ZKRS_OP_EXISTS,
        flags: 0,
        path: c"/a".as_ptr(),
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
    }
}

/// Submits the exists request with `token`, as `zoo_aexists` does.
fn submit(h: H, token: usize) -> zkrs_status {
    let rq = exists();
    let mut ob = empty_outbox();
    let st = zkrs_submit(h.get(), &rq, token, ZKRS_DELIVER_QUEUED, &mut ob);
    zkrs_outbox_finish(&mut ob);
    st
}

/// One item that C takes from an outbox.
enum Seen {
    Result { token: usize, rc: i32 },
    Thread { op: u32, role: u32 },
    Other,
}

fn seen(it: &zkrs_item) -> Seen {
    if it.r#type == zkrs_item_type::ZKRS_ITEM_RESULT as u32 {
        Seen::Result {
            token: it.token,
            rc: raw::read_struct(it.result).rc,
        }
    } else if it.r#type == zkrs_item_type::ZKRS_ITEM_THREAD as u32 {
        Seen::Thread {
            op: it.thread_op,
            role: it.thread_role,
        }
    } else {
        Seen::Other
    }
}

const JOIN: u32 = zkrs_thread_op::ZKRS_THREAD_JOIN as u32;
const DETACH: u32 = zkrs_thread_op::ZKRS_THREAD_DETACH as u32;

/// Drains `ob` and ends the drain, as `zks_drain` does. `on` sees each
/// item. It notes each result in `got`.
fn drain(ob: &mut zkrs_outbox, got: &mut Delivered, on: &mut dyn FnMut(&Seen)) {
    let mut it = zkrs_item::empty();
    while zkrs_outbox_next(ob, &mut it) == 1 {
        let s = seen(&it);
        if let Seen::Result { token, rc } = s {
            got.entry(token).or_default().push(rc);
        }
        on(&s);
    }
    zkrs_outbox_finish(ob);
}

/// Drives one call to its end, as `zks_drive` does.
fn drive(
    h: H,
    first: zkrs_step,
    ob: &mut zkrs_outbox,
    rc: &mut c_int,
    got: &mut Delivered,
    on: &mut dyn FnMut(&Seen),
) -> zkrs_step {
    let mut s = first;
    loop {
        drain(ob, got, on);
        if s != zkrs_step::ZKRS_MORE {
            return s;
        }
        s = zkrs_resume(h.get(), ob, rc);
    }
}

/// Ends a library thread as the shim does. A `ZKRS_RELEASE` means that
/// this thread ran the final close, so it also drops the reference of
/// `zh`. The thread then drops its own reference.
fn leave(h: H, role: u32, got: &mut Delivered) -> zkrs_step {
    let mut ob = empty_outbox();
    let mut rc: c_int = -1;
    let first = zkrs_thread_exit(h.get(), role, &mut ob, &mut rc);
    let end = drive(h, first, &mut ob, &mut rc, got, &mut |_| {});
    if end == zkrs_step::ZKRS_RELEASE {
        zkrs_handle_release(h.get());
    }
    zkrs_handle_release(h.get());
    end
}

/// The dispatch thread of `zks_dispatch_main`. It returns what it
/// delivered.
fn spawn_dispatch(h: H) -> JoinHandle<Delivered> {
    zkrs_handle_retain(h.get());
    zkrs_thread_enter(h.get(), ZKRS_ROLE_DISPATCH);
    thread::spawn(move || {
        let mut got = Delivered::new();
        loop {
            let mut ob = empty_outbox();
            let mut rc: c_int = -1;
            let first = zkrs_wait_dispatch(h.get(), &mut ob, &mut rc);
            if drive(h, first, &mut ob, &mut rc, &mut got, &mut |_| {}) == zkrs_step::ZKRS_EXIT {
                break;
            }
        }
        // The closer joins this thread, so it never runs the final close.
        assert_eq!(leave(h, ZKRS_ROLE_DISPATCH, &mut got), zkrs_step::ZKRS_DONE);
        got
    })
}

/// The IO thread of `zks_io_main` with no poll. It leaves its loop at
/// once, as after a session expiry. The leave can come at any point of
/// the close.
fn spawn_io(h: H) -> JoinHandle<Delivered> {
    zkrs_handle_retain(h.get());
    zkrs_thread_enter(h.get(), ZKRS_ROLE_IO);
    thread::spawn(move || {
        let mut got = Delivered::new();
        let _ = leave(h, ZKRS_ROLE_IO, &mut got);
        got
    })
}

/// Checks that each token in `tokens` has exactly one end. A token in
/// `refused` went back to C at the submit. Each other token reaches the
/// application once. The final close discards no token, because the
/// close gives each accepted request its ZCLOSING completion.
fn check_once(tokens: &[usize], refused: &[usize], got: &Delivered) {
    let discarded = standin::discarded();
    assert!(discarded.is_empty(), "discarded {discarded:?}, got {got:?}");
    for t in tokens {
        let delivered = got.get(t).map_or(0, Vec::len);
        let back = usize::from(refused.contains(t));
        assert_eq!(
            delivered + back,
            1,
            "token {t}: got {got:?}, refused {refused:?}"
        );
    }
}

/// A foreign close with both library threads. The IO thread can leave
/// before, during or after the close. The dispatch thread delivers each
/// pending request once with ZCLOSING, and nothing goes to
/// `discard_token`.
#[test]
fn loom_abi_foreign_close_delivers_each_token_once() {
    model(|| {
        let _rec = standin::recorder();
        let h = ready();
        assert_eq!(submit(h, 41), zkrs_status::ZKRS_OK);
        assert_eq!(submit(h, 42), zkrs_status::ZKRS_OK);
        let mut dispatch = Some(spawn_dispatch(h));
        let mut io = Some(spawn_io(h));
        let mut got = Delivered::new();
        let mut on_threads = Vec::new();
        let mut ob = empty_outbox();
        let mut rc: c_int = -1;
        let first = zkrs_close(h.get(), ZKRS_ROLE_FOREIGN, &mut ob, &mut rc);
        let end = drive(h, first, &mut ob, &mut rc, &mut got, &mut |s| match s {
            Seen::Thread {
                op: JOIN,
                role: ZKRS_ROLE_IO,
            } => {
                on_threads.push(io.take().unwrap().join().unwrap());
            }
            Seen::Thread {
                op: JOIN,
                role: ZKRS_ROLE_DISPATCH,
            } => on_threads.push(dispatch.take().unwrap().join().unwrap()),
            Seen::Thread { .. } => panic!("a foreign close detaches no thread"),
            _ => {}
        });
        assert_eq!((end, rc), (zkrs_step::ZKRS_RELEASE, 0));
        zkrs_handle_release(h.get());
        assert!(io.is_none() && dispatch.is_none());
        assert!(got.is_empty(), "the closer delivered {got:?}");
        let [on_io, on_dispatch] = <[Delivered; 2]>::try_from(on_threads).unwrap();
        assert!(on_io.is_empty(), "{on_io:?}");
        let want: Delivered = [(41, vec![ZCLOSING]), (42, vec![ZCLOSING])].into();
        assert_eq!(on_dispatch, want);
        check_once(&[41, 42], &[], &on_dispatch);
    });
}

/// The dispatch thread of `zks_dispatch_main`, with a callback that ends
/// the thread. C takes the first item of the first batch, and its
/// callback calls `pthread_exit`. The cleanup handler then runs. It
/// returns the token of the taken item.
fn spawn_ending_dispatch(h: H) -> JoinHandle<Option<usize>> {
    zkrs_handle_retain(h.get());
    zkrs_thread_enter(h.get(), ZKRS_ROLE_DISPATCH);
    thread::spawn(move || {
        let mut ob = empty_outbox();
        let mut rc: c_int = -1;
        let first = zkrs_wait_dispatch(h.get(), &mut ob, &mut rc);
        assert_eq!(first, zkrs_step::ZKRS_DONE);
        let mut it = zkrs_item::empty();
        let taken = match zkrs_outbox_next(&mut ob, &mut it) {
            1 => match seen(&it) {
                Seen::Result { token, .. } => Some(token),
                _ => None,
            },
            _ => None,
        };
        zkrs_dispatch_ended(h.get(), &mut ob);
        zkrs_handle_release(h.get());
        taken
    })
}

/// A callback ends the dispatch thread while a foreign close runs. The
/// cleanup handler wakes the close, so the close returns. The close
/// gives back the ref of the ended thread and runs the final close. The
/// taken token has its callback, and `discard_token` gets the other.
#[test]
fn loom_abi_dispatch_end_wakes_a_foreign_close() {
    model(|| {
        let _rec = standin::recorder();
        let h = ready();
        assert_eq!(submit(h, 41), zkrs_status::ZKRS_OK);
        assert_eq!(submit(h, 42), zkrs_status::ZKRS_OK);
        let mut dispatch = Some(spawn_ending_dispatch(h));
        let mut io = Some(spawn_io(h));
        let mut taken = None;
        let mut got = Delivered::new();
        let mut ob = empty_outbox();
        let mut rc: c_int = -1;
        let first = zkrs_close(h.get(), ZKRS_ROLE_FOREIGN, &mut ob, &mut rc);
        let end = drive(h, first, &mut ob, &mut rc, &mut got, &mut |s| match s {
            Seen::Thread {
                op: JOIN,
                role: ZKRS_ROLE_IO,
            } => {
                let _ = io.take().unwrap().join().unwrap();
            }
            Seen::Thread {
                op: JOIN,
                role: ZKRS_ROLE_DISPATCH,
            } => taken = dispatch.take().unwrap().join().unwrap(),
            Seen::Thread { .. } => panic!("a foreign close detaches no thread"),
            _ => {}
        });
        assert_eq!((end, rc), (zkrs_step::ZKRS_RELEASE, 0));
        zkrs_handle_release(h.get());
        assert!(io.is_none() && dispatch.is_none());
        assert!(got.is_empty(), "the closer delivered {got:?}");
        let taken = taken.expect("the dispatch thread took a result");
        let other = if taken == 41 { 42 } else { 41 };
        assert_eq!(standin::discarded(), [other]);
    });
}

/// A close from a callback on the IO thread, while the dispatch thread
/// runs and the application submits. The close detaches the IO thread
/// and joins the dispatch thread. The IO thread then runs the final
/// close. Each token has exactly one end.
#[test]
fn loom_abi_io_callback_close_racing_a_submit_ends_each_token_once() {
    model(|| {
        let _rec = standin::recorder();
        let h = ready();
        assert_eq!(submit(h, 41), zkrs_status::ZKRS_OK);
        // This thread is the IO thread. It holds the reference of `zh`
        // and its own reference.
        zkrs_handle_retain(h.get());
        zkrs_thread_enter(h.get(), ZKRS_ROLE_IO);
        let dispatch = Arc::new(Mutex::new(Some(spawn_dispatch(h))));
        let submitter = thread::spawn(move || submit(h, 43));
        let mut got = Delivered::new();
        let mut on_dispatch = None;
        let mut items = Vec::new();
        let mut ob = empty_outbox();
        let mut rc: c_int = -1;
        let first = zkrs_close(h.get(), ZKRS_ROLE_IO, &mut ob, &mut rc);
        let end = drive(h, first, &mut ob, &mut rc, &mut got, &mut |s| match s {
            Seen::Thread {
                op: JOIN,
                role: ZKRS_ROLE_DISPATCH,
            } => {
                let d = dispatch.lock_owner().take().unwrap();
                on_dispatch = Some(d.join().unwrap());
                items.push("join dispatch");
            }
            Seen::Thread {
                op: DETACH,
                role: ZKRS_ROLE_IO,
            } => items.push("detach io"),
            Seen::Thread { .. } => panic!("an unexpected thread item"),
            _ => {}
        });
        assert_eq!((end, rc), (zkrs_step::ZKRS_DONE, 0));
        assert_eq!(items, ["detach io", "join dispatch"]);
        // The application call ends before the handle can go away.
        let st = submitter.join().unwrap();
        // The IO thread leaves its loop and runs the final close.
        assert_eq!(leave(h, ZKRS_ROLE_IO, &mut got), zkrs_step::ZKRS_RELEASE);
        let on_dispatch = on_dispatch.expect("the close joined the dispatch thread");
        for (t, rcs) in &on_dispatch {
            got.entry(*t).or_default().extend_from_slice(rcs);
        }
        let refused: &[usize] = if st == zkrs_status::ZKRS_OK {
            &[]
        } else {
            &[43]
        };
        check_once(&[41, 43], refused, &got);
        assert_eq!(on_dispatch.get(&41), Some(&vec![ZCLOSING]));
    });
}
