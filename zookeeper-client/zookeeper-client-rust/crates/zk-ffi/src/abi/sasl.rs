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

//! The SASL exports of the drop-in.
//!
//! Cyrus SASL runs in the C glue, never in Rust. Rust gives the glue
//! `ZKRS_ITEM_SASL` items, and the drain gives each Cyrus output back
//! with `zkrs_sasl_result`. The export copies the views, maps the status
//! and gives the answer to the driver with `sasl_result`. It ignores a
//! stale generation. The next driving call returns the legacy rc.
//!
//! `zkrs_sasl_mark_failed` is the leaked `zoo_sasl_mark_failed`: it
//! marks the negotiation failed, with no event and no teardown
//! (zk_sasl.c:135-141).
//!
//! The exports exist in every build, so `zkrs.h` is the same for each
//! configuration. A build without SASL emits no SASL item, so C never
//! calls `zkrs_sasl_result` there.
//!
//! `zkrs_handle_new` calls `setup` for each handle. A handle with
//! `a->sasl == 1` stops its init at the SASL point.
//!
//! The table of taken items records each START or STEP item that C
//! takes from an outbox. The result of C removes the record, and the
//! record gives the kind of the answer. C can take an item and give no
//! result: a C++ exception from a Cyrus callback unwinds the drain, or
//! the glue finds the generation stale. The core then waits, and the
//! receive timeout tears the connection down. When a driving call sees
//! that teardown, it gives the core an `Err` result for the old
//! generation. The core ignores that result as stale, and the wait ends.
//! Thus the next connection gets its DISPOSE and START.

use std::ffi::c_int;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use zk_driver::SaslAnswer;
use zk_proto::{Cause, Config, SaslError, SaslStep, State, rc};

use super::entry::with_handle;
use super::handle::{Driver, Inner};
use super::raw;
use super::types::{zkrs_handle, zkrs_init_args, zkrs_sasl_out, zkrs_sasl_status};

/// Sets up the SASL of a `zookeeper_init_sasl` handle.
///
/// A handle with `a->sasl == 0` needs nothing. Otherwise the function
/// sets `cfg.sasl`, so that the init stops at the SASL point. A build
/// without SASL rejects the handle with `EINVAL`. An error is the init
/// errno.
pub(crate) fn setup(a: &zkrs_init_args, cfg: &mut Config) -> Result<(), c_int> {
    if a.sasl == 0 {
        return Ok(());
    }
    enable(cfg)
}

/// Turns on the SASL negotiation of the handle.
#[cfg(feature = "sasl")]
#[allow(clippy::unnecessary_wraps, reason = "the build without SASL fails")]
fn enable(cfg: &mut Config) -> Result<(), c_int> {
    cfg.sasl = true;
    Ok(())
}

/// A build without SASL has no Cyrus glue, so it rejects the handle.
#[cfg(not(feature = "sasl"))]
fn enable(_cfg: &mut Config) -> Result<(), c_int> {
    Err(libc::EINVAL)
}

/// The kind of a SASL item that waits for the result of C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Taken {
    /// A START item.
    Start,
    /// A STEP item.
    Step,
}

/// The connection facts that a teardown changes.
///
/// A teardown closes the transport, sets a new state and records its
/// cause. During a SASL wait, the core changes none of these facts
/// without a teardown or an end of the negotiation. Both of these make
/// the generation of the wait stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mark {
    /// The core has a transport.
    transport: bool,
    /// The session state.
    state: State,
    /// The cause of the last teardown.
    cause: Option<Cause>,
    /// The errno of the last teardown.
    errno: Option<i32>,
}

/// One START or STEP item that C took and did not answer yet.
struct Record {
    /// The handle of the item. The weak reference keeps the allocation,
    /// so no new handle can get the same address.
    handle: Weak<Inner>,
    /// The kind of the item.
    kind: Taken,
    /// The generation of the item.
    generation: u32,
    /// The connection facts when C took the item.
    mark: Option<Mark>,
}

impl Record {
    /// True when the record belongs to the handle `h`.
    fn is_for(&self, h: &Arc<Inner>) -> bool {
        std::ptr::eq(self.handle.as_ptr(), Arc::as_ptr(h))
    }
}

/// The records of all handles. Each handle has at most one record,
/// because the core yields no SASL call while a result is outstanding.
static TAKEN: Mutex<Vec<Record>> = Mutex::new(Vec::new());

/// The number of records. A driving call reads it first, so a handle
/// with no record does not take the lock.
static N_TAKEN: AtomicUsize = AtomicUsize::new(0);

/// Locks the table. A panic cannot leave the table half written, so the
/// function ignores the poison flag.
fn table() -> MutexGuard<'static, Vec<Record>> {
    TAKEN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Removes the records of released handles and stores the count.
fn prune(t: &mut Vec<Record>) {
    t.retain(|r| r.handle.strong_count() > 0);
    N_TAKEN.store(t.len(), Ordering::Release);
}

/// Reads the connection facts. `None` means that no connection exists.
fn mark_of(d: &Driver) -> Option<Mark> {
    d.read_conn(|c| Mark {
        transport: c.has_transport(),
        state: c.state(),
        cause: c.last_teardown_cause(),
        errno: c.last_teardown_errno(),
    })
}

/// Records a START or STEP item that C takes from an outbox.
///
/// The outbox calls it when it gives the item to C. A new record
/// replaces the old record of the handle: the core yields a new call
/// only after the old wait ended.
pub(crate) fn note_taken(h: &Arc<Inner>, kind: Taken, generation: u32) {
    // The connection facts come first, so the table lock is not held
    // around the core lock here.
    let mark = h.driver().and_then(mark_of);
    let mut t = table();
    t.retain(|r| !r.is_for(h));
    t.push(Record {
        handle: Arc::downgrade(h),
        kind,
        generation,
        mark,
    });
    prune(&mut t);
}

/// Removes the record of the item that a result answers and returns
/// its kind. A result with no record changes nothing.
fn take_answered(h: &Arc<Inner>, generation: u32) -> Option<Taken> {
    let mut t = table();
    let at = t
        .iter()
        .position(|r| r.is_for(h) && r.generation == generation);
    let kind = at.map(|n| t.swap_remove(n).kind);
    prune(&mut t);
    kind
}

/// True when the connection facts show a teardown after C took the
/// item. A record with no facts never matches, so it stays.
fn torn_down(then: Option<Mark>, now: Option<Mark>) -> bool {
    match (then, now) {
        (Some(a), Some(b)) => a != b,
        // The final close took the connection, so no wait remains.
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Ends the wait of an item that C took and did not answer.
///
/// Every driving call runs it before and after its core work. When the
/// connection facts show a teardown, the function removes the record
/// and gives the core an `Err` result for the old generation. The core
/// ignores that result as stale, and it ends the wait at the start of
/// the next core call. A live result must never come from here, because
/// it fails the live negotiation.
pub(crate) fn settle_unanswered(h: &Arc<Inner>) {
    if N_TAKEN.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(d) = h.driver() else {
        return;
    };
    let stale = {
        // The table lock is taken before the core lock. No code takes
        // them in the other order.
        let mut t = table();
        let found = t.iter().position(|r| r.is_for(h));
        let gone = found.and_then(|n| {
            let then = t.get(n).and_then(|r| r.mark);
            torn_down(then, mark_of(d)).then(|| t.swap_remove(n))
        });
        prune(&mut t);
        gone
    };
    if let Some(r) = stale {
        give(d, unanswered(r.kind, r.generation));
    }
}

/// The `Err` result of an item that C did not answer.
fn unanswered(kind: Taken, generation: u32) -> SaslAnswer {
    let e = SaslError {
        rc: rc::ZSYSTEMERROR,
        errstring: Vec::new(),
        errdetail: Vec::new(),
    };
    match kind {
        Taken::Start => SaslAnswer::Started {
            generation,
            result: Err(e),
        },
        Taken::Step => SaslAnswer::Stepped {
            generation,
            result: Err(e),
        },
    }
}

/// Gives an answer to the driver. The next core call gives it to proto.
fn give(d: &Driver, answer: SaslAnswer) {
    match d {
        Driver::Mt(s) => s.sasl_result(answer),
        Driver::St(p) => p.sasl_result(answer),
    }
}

/// Maps the Cyrus output of one item to its answer.
///
/// A status other than CONTINUE or DONE, a bad view, or a START with no
/// valid mechanism name is a FAIL result. A FAIL result is `ZSYSTEMERROR`
/// with empty texts, because the glue logged the Cyrus texts.
fn answer_of(kind: Taken, generation: u32, v: &zkrs_sasl_out) -> SaslAnswer {
    let fail = || SaslError {
        rc: rc::ZSYSTEMERROR,
        errstring: Vec::new(),
        errdetail: Vec::new(),
    };
    let done = if v.status == zkrs_sasl_status::ZKRS_SASL_DONE as i32 {
        Some(true)
    } else if v.status == zkrs_sasl_status::ZKRS_SASL_CONTINUE as i32 {
        Some(false)
    } else {
        None
    };
    let step = done.and_then(|done| {
        raw::view_bytes(&v.token)
            .ok()
            .map(|token| SaslStep { token, done })
    });
    match kind {
        Taken::Start => {
            let mech = raw::view_bytes(&v.mech)
                .ok()
                .flatten()
                .and_then(|m| String::from_utf8(m.expose().to_vec()).ok())
                .filter(|m| !m.is_empty());
            let result = match (mech, step) {
                (Some(m), Some(s)) => Ok((m, s)),
                _ => Err(fail()),
            };
            SaslAnswer::Started { generation, result }
        }
        Taken::Step => SaslAnswer::Stepped {
            generation,
            result: step.ok_or_else(fail),
        },
    }
}

/// Gives the Cyrus output of one START or STEP item to the core.
///
/// C calls it at most once per START or STEP item, inside the drain of
/// that item. The export copies `*v` and its views with `abi::raw`
/// before it returns. A bad view is a FAIL result. A status other than
/// `ZKRS_SASL_CONTINUE` or `ZKRS_SASL_DONE` is a FAIL result with
/// `ZSYSTEMERROR` and empty texts. A `gen` that names no item that C
/// took changes nothing, and the core ignores a stale `gen`.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_sasl_result(h: *const zkrs_handle, r#gen: u32, v: *const zkrs_sasl_out) {
    with_handle(h, |i, _| {
        let out = raw::read_struct(v);
        let Some(d) = i.driver() else {
            return;
        };
        let Some(kind) = take_answered(i, r#gen) else {
            return;
        };
        give(d, answer_of(kind, r#gen, &out));
    });
}

/// `zoo_sasl_mark_failed`: marks the negotiation failed and
/// sets `AUTH_FAILED`. It emits no event and starts no teardown. After
/// the final close it does nothing.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_sasl_mark_failed(h: *const zkrs_handle) {
    with_handle(h, |i, _| {
        if let Some(d) = i.driver() {
            let _ = d.with_conn(|c, _| c.mark_sasl_failed());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::super::handle::test_support::{init_args, new_handle};
    use super::super::handle::zkrs_handle_release;
    use super::super::standin;
    use super::super::types::zkrs_bytes;
    use super::*;

    fn args(sasl: u32) -> zkrs_init_args {
        zkrs_init_args {
            flavor: 0,
            hosts: std::ptr::null(),
            sasl,
            ..init_args(c"")
        }
    }

    fn view(b: &[u8]) -> zkrs_bytes {
        zkrs_bytes {
            p: b.as_ptr(),
            len: u32::try_from(b.len()).unwrap_or(u32::MAX),
            is_null: 0,
        }
    }

    fn out(status: i32, mech: zkrs_bytes, token: zkrs_bytes) -> zkrs_sasl_out {
        zkrs_sasl_out {
            status,
            mech,
            token,
        }
    }

    const CONTINUE: i32 = zkrs_sasl_status::ZKRS_SASL_CONTINUE as i32;
    const DONE: i32 = zkrs_sasl_status::ZKRS_SASL_DONE as i32;
    const FAIL: i32 = zkrs_sasl_status::ZKRS_SASL_FAIL as i32;
    const STALE: i32 = zkrs_sasl_status::ZKRS_SASL_STALE as i32;

    /// A token copy and the done flag.
    type Step = (Option<Vec<u8>>, bool);

    /// The parts of a START answer: gen, then the mechanism, the token
    /// and the done flag, or the error rc.
    fn started(a: SaslAnswer) -> (u32, Result<(String, Step), i32>) {
        match a {
            SaslAnswer::Started { generation, result } => (
                generation,
                result
                    .map(|(m, s)| (m, (s.token.map(|t| t.expose().to_vec()), s.done)))
                    .map_err(|e| e.rc),
            ),
            SaslAnswer::Stepped { .. } => (0, Err(0)),
        }
    }

    /// The parts of a STEP answer.
    fn stepped(a: SaslAnswer) -> (u32, Result<Step, i32>) {
        match a {
            SaslAnswer::Stepped { generation, result } => (
                generation,
                result
                    .map(|s| (s.token.map(|t| t.expose().to_vec()), s.done))
                    .map_err(|e| e.rc),
            ),
            SaslAnswer::Started { .. } => (0, Err(0)),
        }
    }

    #[test]
    fn setup_follows_the_sasl_flag_and_the_feature() {
        let mut cfg = Config::legacy(30_000);
        assert_eq!(setup(&args(0), &mut cfg), Ok(()));
        assert!(!cfg.sasl);
        let r = setup(&args(1), &mut cfg);
        if cfg!(feature = "sasl") {
            assert_eq!(r, Ok(()));
            assert!(cfg.sasl);
        } else {
            assert_eq!(r, Err(libc::EINVAL));
            assert!(!cfg.sasl);
        }
    }

    #[test]
    fn a_start_answer_has_the_mechanism_and_the_token() {
        let o = out(CONTINUE, view(b"DIGEST-MD5"), view(b"tok"));
        assert_eq!(
            started(answer_of(Taken::Start, 7, &o)),
            (
                7,
                Ok(("DIGEST-MD5".to_owned(), (Some(b"tok".to_vec()), false)))
            )
        );
        let o = out(DONE, view(b"PLAIN"), zkrs_bytes::null());
        assert_eq!(
            started(answer_of(Taken::Start, 8, &o)),
            (8, Ok(("PLAIN".to_owned(), (None, true))))
        );
        // An empty token is not the null token.
        let o = out(CONTINUE, view(b"X"), view(b""));
        assert_eq!(
            started(answer_of(Taken::Start, 9, &o)),
            (9, Ok(("X".to_owned(), (Some(Vec::new()), false))))
        );
    }

    /// Rule: a failed status and a bad Cyrus output view give
    /// ZSYSTEMERROR.
    #[test]
    fn a_failed_status_or_a_bad_view_is_zsystemerror() {
        let sys = Err(rc::ZSYSTEMERROR);
        for status in [FAIL, STALE, 2, -3, i32::MIN] {
            let o = out(status, view(b"PLAIN"), view(b"t"));
            assert_eq!(started(answer_of(Taken::Start, 3, &o)), (3, sys.clone()));
            assert_eq!(
                stepped(answer_of(Taken::Step, 3, &o)).1,
                Err(rc::ZSYSTEMERROR)
            );
        }
        let bad = [
            // is_null with a length or a pointer.
            zkrs_bytes {
                p: std::ptr::null(),
                len: 1,
                is_null: 1,
            },
            zkrs_bytes {
                p: b"x".as_ptr(),
                len: 0,
                is_null: 1,
            },
            // NULL with a length, and a length above the cap.
            zkrs_bytes {
                p: std::ptr::null(),
                len: 4,
                is_null: 0,
            },
            zkrs_bytes {
                p: b"x".as_ptr(),
                len: 0x8000_0000,
                is_null: 0,
            },
        ];
        for b in bad {
            let o = out(DONE, view(b"PLAIN"), b);
            assert_eq!(started(answer_of(Taken::Start, 4, &o)), (4, sys.clone()));
            assert_eq!(
                stepped(answer_of(Taken::Step, 4, &o)).1,
                Err(rc::ZSYSTEMERROR)
            );
            let o = out(DONE, b, view(b"t"));
            assert_eq!(started(answer_of(Taken::Start, 4, &o)), (4, sys.clone()));
        }
        // A START needs a mechanism name that is valid UTF-8.
        for mech in [zkrs_bytes::null(), view(b""), view(&[0xff, 0xfe])] {
            let o = out(CONTINUE, mech, view(b"t"));
            assert_eq!(started(answer_of(Taken::Start, 5, &o)), (5, sys.clone()));
        }
    }

    #[test]
    fn a_step_answer_ignores_the_mechanism() {
        let o = out(CONTINUE, zkrs_bytes::null(), view(b"resp"));
        assert_eq!(
            stepped(answer_of(Taken::Step, 2, &o)),
            (2, Ok((Some(b"resp".to_vec()), false)))
        );
        let o = out(DONE, view(b"junk"), zkrs_bytes::null());
        assert_eq!(
            stepped(answer_of(Taken::Step, 2, &o)),
            (2, Ok((None, true)))
        );
    }

    #[test]
    fn an_unanswered_item_gets_an_empty_zsystemerror() {
        let start = match unanswered(Taken::Start, 11) {
            SaslAnswer::Started {
                generation,
                result: Err(e),
            } => Some((generation, e)),
            SaslAnswer::Started { .. } | SaslAnswer::Stepped { .. } => None,
        };
        assert_eq!(
            start,
            Some((
                11,
                SaslError {
                    rc: rc::ZSYSTEMERROR,
                    errstring: Vec::new(),
                    errdetail: Vec::new(),
                }
            ))
        );
        assert_eq!(
            stepped(unanswered(Taken::Step, 12)),
            (12, Err(rc::ZSYSTEMERROR))
        );
    }

    #[test]
    fn only_a_changed_mark_is_a_teardown() {
        let m = Mark {
            transport: true,
            state: State::Associating,
            cause: None,
            errno: None,
        };
        assert!(!torn_down(Some(m), Some(m)));
        assert!(!torn_down(None, Some(m)));
        assert!(!torn_down(None, None));
        assert!(torn_down(Some(m), None));
        for other in [
            Mark {
                transport: false,
                ..m
            },
            Mark {
                state: State::Connecting,
                ..m
            },
            Mark {
                cause: Some(Cause::SaslTeardown),
                ..m
            },
            Mark {
                errno: Some(libc::ETIMEDOUT),
                ..m
            },
        ] {
            assert!(torn_down(Some(m), Some(other)));
        }
    }

    #[test]
    fn the_table_answers_each_taken_item_once() {
        let _rec = standin::recorder();
        let h1 = new_handle();
        let h2 = new_handle();
        let (k1, k2, again, other) = with_handle(h1, |a, _| {
            with_handle(h2, |b, _| {
                note_taken(a, Taken::Start, 5);
                note_taken(b, Taken::Step, 5);
                // A new item replaces the record of the same handle.
                note_taken(a, Taken::Step, 6);
                let stale = take_answered(a, 5);
                let k1 = take_answered(a, 6);
                let again = take_answered(a, 6);
                let k2 = take_answered(b, 5);
                (k1, k2, again, stale)
            })
        });
        assert_eq!(
            (k1, k2, again, other),
            (Some(Taken::Step), Some(Taken::Step), None, None)
        );
        zkrs_handle_release(h1);
        zkrs_handle_release(h2);
    }

    #[test]
    fn a_released_handle_leaves_no_record() {
        let _rec = standin::recorder();
        let h = new_handle();
        with_handle(h, |i, _| note_taken(i, Taken::Start, 1));
        zkrs_handle_release(h);
        let h2 = new_handle();
        // The prune runs at the next table write.
        let n = with_handle(h2, |i, _| {
            note_taken(i, Taken::Start, 1);
            let n = table()
                .iter()
                .filter(|r| r.handle.strong_count() > 0)
                .count();
            let _ = take_answered(i, 1);
            n
        });
        assert!(n >= 1);
        assert!(table().iter().all(|r| r.handle.strong_count() > 0));
        zkrs_handle_release(h2);
    }

    #[test]
    fn a_result_without_a_driver_or_a_record_changes_nothing() {
        let _rec = standin::recorder();
        let h = new_handle();
        let o = out(DONE, view(b"PLAIN"), zkrs_bytes::null());
        zkrs_sasl_result(h, 3, &raw const o);
        with_handle(h, |i, _| {
            note_taken(i, Taken::Start, 3);
            // A handle with no driver keeps its record; nothing can wait.
            settle_unanswered(i);
            assert_eq!(take_answered(i, 3), Some(Taken::Start));
        });
        zkrs_handle_release(h);
    }
}
