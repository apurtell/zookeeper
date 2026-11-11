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

//! State, server list and endpoint accessors.
//!
//! The accessors read the driver with the `Driver` methods `state`,
//! `recv_timeout`, `peer_addr` and `read_conn`. They change the
//! connection with `Driver::with_conn` and `Driver::set_servers`. The
//! methods serve the mt and the st driver. None of them delivers a
//! callback.

use std::ffi::{c_char, c_int};

use zk_driver::host::log_record;
use zk_driver::{Item, Step};
use zk_proto::rc::{ZBADARGUMENTS, ZOK};
use zk_proto::{LogSite, State};

use super::entry::with_handle;
use super::handle::{require_driver, step_out};
use super::outbox::with_outbox;
use super::raw;
use super::types::{zkrs_handle, zkrs_outbox, zkrs_sockaddr_view, zkrs_step};

/// `zoo_state`: the legacy state int, including 0, 7, 999,
/// -112 and -113.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_state(h: *const zkrs_handle) -> i32 {
    with_handle(h, |i, _| i.driver().map_or(0, |d| d.state()))
}

/// `zoo_recv_timeout`: the negotiated session timeout, or the
/// requested timeout before the first session.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_recv_timeout(h: *const zkrs_handle) -> i32 {
    with_handle(h, |i, _| i.driver().map_or(0, |d| d.recv_timeout()))
}

/// `zoo_set_servers`. `*rc` is the legacy rc.
///
/// A NULL or empty `hosts` gives ZBADARGUMENTS with the
/// `SetServersEmpty` line. An empty string does not change the server
/// list or the connection (spec "Rejection of Empty Server Lists in
/// `zoo_set_servers`"). Legacy C accepts it. The resolution of a new list
/// can reach the Blocking `resolve` entry, so the call returns
/// `ZKRS_MORE` at the log-flush barrier.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_set_servers(
    h: *const zkrs_handle,
    hosts: *const c_char,
    ob: *mut zkrs_outbox,
    rc: *mut c_int,
) -> zkrs_step {
    with_handle(h, |i, _| {
        // Legacy accepts an empty list and strands the handle, so the
        // core treats it as a NULL list.
        let hosts = raw::cstr_opt(hosts).filter(|l| !l.is_empty());
        let host = i.host();
        let mut code: i32 = ZOK;
        let step = with_outbox(ob, i, |o| match hosts {
            // The NULL check comes first, as in legacy.
            None => {
                if let Some(rec) = log_record(&**host, LogSite::SetServersEmpty, Vec::new()) {
                    o.push(Item::Log(rec));
                }
                Step::Done(ZBADARGUMENTS)
            }
            Some(list) => require_driver(i).set_servers(&list, o, &mut code),
        });
        step_out(step, rc)
    })
}

/// `zoo_set_servers_resolution_delay`.
///
/// The function calls `Connection::set_resolve_delay` through the
/// `with_conn` method of the driver. A delay below -1 gives
/// ZBADARGUMENTS and the `ResolveDelayInvalid` line. The mt IO thread or
/// the next st driving call routes the line.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_set_resolution_delay(h: *const zkrs_handle, delay_ms: i32) -> i32 {
    with_handle(h, |i, _| {
        // After the final close no connection exists. The function then
        // checks the argument only.
        let fallback = if delay_ms < -1 { ZBADARGUMENTS } else { ZOK };
        i.driver()
            .and_then(|d| d.with_conn(|c, _| c.set_resolve_delay(delay_ms)))
            .unwrap_or(fallback)
    })
}

/// `zoo_cycle_next_server`.
///
/// The function calls `Connection::cycle_next_server` through the
/// `with_conn` method of the driver. The reconfig lines go out through
/// the mt IO thread after the wake, or in the next st driving call. They
/// do not go through `ob` (open issue: the legacy lines come from the
/// calling thread).
#[allow(
    unused_variables,
    reason = "ob is for the reconfig log lines; see the open issue"
)]
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_cycle_next_server(h: *const zkrs_handle, ob: *mut zkrs_outbox) {
    with_handle(h, |i, _| {
        if let Some(d) = i.driver() {
            let _ = d.with_conn(|c, _| c.cycle_next_server());
        }
    })
}

/// `zoo_get_current_server`: writes the `cur` address,
/// or family 0 when none exists.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_current_server(h: *const zkrs_handle, out: *mut zkrs_sockaddr_view) {
    with_handle(h, |i, _| {
        let cur = i
            .driver()
            .and_then(|d| d.read_conn(|c| c.current_server()))
            .flatten();
        raw::write_out(out, zkrs_sockaddr_view::from_addr(cur));
    })
}

/// `zookeeper_get_connected_host`. It returns 0 and writes
/// `*out` only when the state is CONNECTED (3) and `getpeername`
/// succeeds; otherwise it returns -1.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_peer_addr(h: *const zkrs_handle, out: *mut zkrs_sockaddr_view) -> i32 {
    with_handle(h, |i, _| {
        let peer = i
            .driver()
            .filter(|d| d.state() == State::Connected.code())
            .and_then(|d| d.peer_addr());
        match peer {
            Some(a) => {
                raw::write_out(out, zkrs_sockaddr_view::from_addr(Some(a)));
                0
            }
            None => -1,
        }
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::super::handle::test_support::{empty_outbox, init_args};
    use super::super::handle::{zkrs_handle_new, zkrs_handle_release, zkrs_resume};
    use super::super::outbox::{zkrs_outbox_finish, zkrs_outbox_next};
    use super::super::standin;
    use super::super::types::{
        ZKRS_AF_INET, ZKRS_FLAVOR_MT, ZKRS_FLAVOR_ST, zkrs_init_args, zkrs_item, zkrs_item_type,
    };
    use super::*;

    /// The port of the first server. No server listens there.
    const PORT: u16 = 22650;

    /// Takes every item and ends the drain. It returns the item types.
    fn drain(ob: &mut zkrs_outbox) -> Vec<u32> {
        let mut types = Vec::new();
        let mut it = zkrs_item::empty();
        while zkrs_outbox_next(ob, &raw mut it) == 1 {
            types.push(it.r#type);
        }
        zkrs_outbox_finish(ob);
        types
    }

    /// Drains and resumes until the step is not `ZKRS_MORE`.
    fn drive(
        h: *const zkrs_handle,
        ob: &mut zkrs_outbox,
        mut step: zkrs_step,
        rc: &mut c_int,
    ) -> (zkrs_step, Vec<u32>) {
        let mut types = drain(ob);
        while step == zkrs_step::ZKRS_MORE {
            step = zkrs_resume(h, ob, rc);
            types.extend(drain(ob));
        }
        (step, types)
    }

    fn resolve_to(port: u16) {
        let a: SocketAddr = ([127, 0, 0, 1], port).into();
        standin::set_resolve(vec![zkrs_sockaddr_view::from_addr(Some(a))], vec![], 0, 0);
    }

    /// Makes an mt handle with the stand-in vtable and runs the init to
    /// the end. No library thread runs.
    fn ready_handle() -> *const zkrs_handle {
        ready_flavor(ZKRS_FLAVOR_MT)
    }

    /// Makes a handle of `flavor` with the stand-in vtable and runs the
    /// init to the end.
    fn ready_flavor(flavor: u32) -> *const zkrs_handle {
        resolve_to(PORT);
        let a = zkrs_init_args {
            flavor,
            recv_timeout: 10_000,
            ..init_args(c"127.0.0.1:22650")
        };
        let vt = standin::vtable();
        let mut out: *mut zkrs_handle = std::ptr::null_mut();
        let mut ob = empty_outbox();
        let mut rc: c_int = -1;
        let step = zkrs_handle_new(
            &raw const a,
            &raw const vt,
            0x55,
            &raw mut out,
            &raw mut ob,
            &raw mut rc,
        );
        let (step, _) = drive(out, &mut ob, step, &mut rc);
        assert_eq!((step, rc), (zkrs_step::ZKRS_DONE, 0));
        assert!(!out.is_null());
        out
    }

    #[test]
    fn a_ready_handle_reports_state_timeout_and_endpoints() {
        let _rec = crate::abi::standin::recorder();
        let h = ready_handle();
        let st = zkrs_state(h);
        assert!(st == 999 || st == 1, "state {st}");
        assert_eq!(zkrs_recv_timeout(h), 10_000);
        let mut v = zkrs_sockaddr_view::none();
        zkrs_current_server(h, &raw mut v);
        // No IO thread runs, so no connect chose a server yet. The view
        // is empty, or it names the only server.
        assert!(
            v.family == 0 || (v.family, v.port) == (ZKRS_AF_INET, PORT),
            "{v:?}"
        );
        let mut p = zkrs_sockaddr_view::none();
        assert_eq!(zkrs_peer_addr(h, &raw mut p), -1);
        assert_eq!(p.family, 0);
        zkrs_handle_release(h);
    }

    #[test]
    fn resolution_delay_and_cycle_follow_the_legacy_rules() {
        let _rec = crate::abi::standin::recorder();
        let h = ready_handle();
        assert_eq!(zkrs_set_resolution_delay(h, -2), ZBADARGUMENTS);
        assert_eq!(zkrs_set_resolution_delay(h, -1), ZOK);
        assert_eq!(zkrs_set_resolution_delay(h, 0), ZOK);
        let mut ob = empty_outbox();
        zkrs_cycle_next_server(h, &raw mut ob);
        assert!(ob.r#impl.is_null());
        zkrs_handle_release(h);
    }

    /// Rule: a NULL list and an empty list give ZBADARGUMENTS and one log
    /// line.
    #[test]
    fn set_servers_checks_null_and_bad_lists() {
        let _rec = crate::abi::standin::recorder();
        let h = ready_handle();
        let mut ob = empty_outbox();
        let mut rc: c_int = 0;

        let step = zkrs_set_servers(h, std::ptr::null(), &raw mut ob, &raw mut rc);
        let (step, types) = drive(h, &mut ob, step, &mut rc);
        assert_eq!((step, rc), (zkrs_step::ZKRS_DONE, ZBADARGUMENTS));
        assert_eq!(types, vec![zkrs_item_type::ZKRS_ITEM_LOG as u32]);

        // An empty list keeps the state and the list.
        let before = zkrs_state(h);
        let step = zkrs_set_servers(h, c"".as_ptr(), &raw mut ob, &raw mut rc);
        let (step, types) = drive(h, &mut ob, step, &mut rc);
        assert_eq!((step, rc), (zkrs_step::ZKRS_DONE, ZBADARGUMENTS));
        assert_eq!(types, vec![zkrs_item_type::ZKRS_ITEM_LOG as u32]);
        assert_eq!(zkrs_state(h), before);

        let step = zkrs_set_servers(h, c"127.0.0.1".as_ptr(), &raw mut ob, &raw mut rc);
        let (step, _) = drive(h, &mut ob, step, &mut rc);
        assert_eq!((step, rc), (zkrs_step::ZKRS_DONE, ZBADARGUMENTS));

        resolve_to(22651);
        let step = zkrs_set_servers(h, c"127.0.0.1:22651".as_ptr(), &raw mut ob, &raw mut rc);
        let (step, _) = drive(h, &mut ob, step, &mut rc);
        assert_eq!((step, rc), (zkrs_step::ZKRS_DONE, ZOK));
        assert!(ob.r#impl.is_null());
        zkrs_handle_release(h);
    }

    #[test]
    fn an_st_handle_reports_state_timeout_and_endpoints() {
        let _rec = crate::abi::standin::recorder();
        let h = ready_flavor(ZKRS_FLAVOR_ST);
        // ZOO_NOTCONNECTED_STATE until the first `zookeeper_interest`.
        assert_eq!(zkrs_state(h), 999);
        assert_eq!(zkrs_recv_timeout(h), 10_000);
        let mut p = zkrs_sockaddr_view::none();
        assert_eq!(zkrs_peer_addr(h, &raw mut p), -1);
        assert_eq!(p.family, 0);
        assert_eq!(zkrs_set_resolution_delay(h, -2), ZBADARGUMENTS);
        assert_eq!(zkrs_set_resolution_delay(h, 0), ZOK);
        zkrs_handle_release(h);
    }

    #[test]
    fn st_set_servers_checks_the_list_and_resumes_its_stage() {
        let _rec = crate::abi::standin::recorder();
        let h = ready_flavor(ZKRS_FLAVOR_ST);
        let mut ob = empty_outbox();
        let mut rc: c_int = 0;

        let step = zkrs_set_servers(h, std::ptr::null(), &raw mut ob, &raw mut rc);
        let (step, types) = drive(h, &mut ob, step, &mut rc);
        assert_eq!((step, rc), (zkrs_step::ZKRS_DONE, ZBADARGUMENTS));
        assert_eq!(types, vec![zkrs_item_type::ZKRS_ITEM_LOG as u32]);

        // Each barrier of the set-servers stage continues with
        // `zkrs_resume`.
        resolve_to(22651);
        let step = zkrs_set_servers(h, c"127.0.0.1:22651".as_ptr(), &raw mut ob, &raw mut rc);
        let (step, _) = drive(h, &mut ob, step, &mut rc);
        assert_eq!((step, rc), (zkrs_step::ZKRS_DONE, ZOK));
        assert!(ob.r#impl.is_null());
        assert_eq!(zkrs_state(h), 999);
        zkrs_handle_release(h);
    }
}
