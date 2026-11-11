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

//! The submission funnel.
//!
//! `zkrs_submit` turns one `zkrs_request` into a `zk_proto::Request` and
//! gives it to the driver. The call never delivers a callback. It can
//! queue log items in the outbox of the caller. The `zkrs_status` result
//! tells C the stage of a failure, and C maps it to the legacy rc with
//! `zks_funnel`.
//!
//! C gives the legacy `struct ACL_vector` of a create or a set ACL as it
//! is. Rust reads it through the `CAclVector` mirror and copies the
//! entries once.
//!
//! Input defects (a bad value buffer, a bad ACL vector, a NULL op array,
//! token 0) become `InputDefect` flags. zk-proto reports them at the
//! serialization stage, so they never reorder the return codes.

use std::ffi::c_char;
use std::sync::Arc;

use zk_jute::data::{ACL, Id};
use zk_jute::{JBuffer, JString, JVec, rc};
use zk_proto::{
    InputDefect, Op, PathIn, Request, Route, SecretBytes, SubmitError, Submitted, check_ttl,
};

use zk_driver::Outbox;

use super::entry::{abort_with, ffi_guard, with_handle};
use super::handle::{Driver, Inner, require_driver};
use super::legacy::{CAcl, CAclVector, CZooOp};
use super::multi::multi_ops;
use super::outbox::with_outbox;
use super::raw;
use super::tokens::{CReq, CTokens, CWatcher};
use super::types::{
    ZKRS_AUTH_F_ALLOC_FAILED, ZKRS_DELIVER_DIRECT, ZKRS_F_CREATE2, ZKRS_F_LOCAL, ZKRS_F_REMOVE_ALL,
    ZKRS_K_ACLLIST, ZKRS_K_DATA, ZKRS_K_MULTI, ZKRS_K_STAT, ZKRS_K_STRING, ZKRS_K_STRING_STAT,
    ZKRS_K_STRINGLIST, ZKRS_K_STRINGLIST_STAT, ZKRS_K_VOID, ZKRS_OP_CREATE, ZKRS_OP_DELETE,
    ZKRS_OP_EXISTS, ZKRS_OP_GETACL, ZKRS_OP_GETCHILDREN, ZKRS_OP_GETCHILDREN2, ZKRS_OP_GETCONFIG,
    ZKRS_OP_GETDATA, ZKRS_OP_MULTI, ZKRS_OP_RECONFIG, ZKRS_OP_REMOVE_WATCHES, ZKRS_OP_SETACL,
    ZKRS_OP_SETDATA, ZKRS_OP_SYNC, zkrs_handle, zkrs_outbox, zkrs_request, zkrs_status,
};

/// The completion kind (`ZKRS_K_*`) of a request, as the legacy
/// `zoo_a*` function chooses it. 0 is an unknown operation.
///
/// `zks_req.kind` in C uses the same table. The kind travels in the
/// `CReq` token, so the result view can carry it.
pub(crate) fn kind_of(op: u32, flags: u32) -> u32 {
    match op {
        ZKRS_OP_CREATE if flags & ZKRS_F_CREATE2 != 0 => ZKRS_K_STRING_STAT,
        ZKRS_OP_CREATE | ZKRS_OP_SYNC => ZKRS_K_STRING,
        ZKRS_OP_EXISTS | ZKRS_OP_SETDATA => ZKRS_K_STAT,
        ZKRS_OP_GETDATA | ZKRS_OP_GETCONFIG | ZKRS_OP_RECONFIG => ZKRS_K_DATA,
        ZKRS_OP_GETACL => ZKRS_K_ACLLIST,
        ZKRS_OP_GETCHILDREN => ZKRS_K_STRINGLIST,
        ZKRS_OP_GETCHILDREN2 => ZKRS_K_STRINGLIST_STAT,
        ZKRS_OP_MULTI => ZKRS_K_MULTI,
        // DELETE, SETACL, REMOVE_WATCHES and an unknown operation.
        _ => ZKRS_K_VOID,
    }
}

/// Builds the `zk_proto::Request` of one C request.
///
/// The function copies every input with the `raw` readers: the path as
/// `PathIn::Legacy`, the ACL vector with [`acl_of_vec`], the reconfig
/// strings and the watcher pair. The value of a create or a set data is
/// not copied here. [`data_of`] borrows it, and zk-proto encodes it
/// straight into the owned request frame. The sub-ops of a multi are not
/// copied here either. [`super::multi::multi_ops`] borrows them in the
/// same way, and the op holds no sub-op. It sets
/// `Route::Direct` for `ZKRS_DELIVER_DIRECT`. It records each input
/// defect in the `InputDefect` flags.
pub(crate) fn build_request(
    h: &Arc<Inner>,
    rq: &zkrs_request,
    token: usize,
    delivery: u32,
) -> Request<CTokens> {
    // Only a create and a set ACL read the ACL vector. The function copies
    // it once and gives its defect to `defects_of`. The copy of an
    // unusable input is a null or empty value. zk-proto never encodes
    // that value, because the request fails at the serialization stage.
    let (acl, bad_acl) = match rq.op {
        ZKRS_OP_CREATE => acl_of_vec(rq.acl.cast(), false),
        ZKRS_OP_SETACL => acl_of_vec(rq.acl.cast(), true),
        _ => (JVec::Items(Vec::new()), false),
    };
    let defect = defects_of(rq, token, bad_acl);
    let token = CReq::new(token, kind_of(rq.op, rq.flags), h.host().discard_fn());
    let route = if delivery == ZKRS_DELIVER_DIRECT {
        Route::Direct
    } else {
        Route::Queued
    };
    let op = op_of(rq, acl);
    Request {
        op,
        token,
        route,
        defect,
    }
}

/// Builds the operation of one request. `acl` is the copy of the ACL
/// vector. An operation code that is not in the `ZKRS_OP_*` table is a
/// broken shim contract.
fn op_of(rq: &zkrs_request, acl: JVec<ACL>) -> Op<CWatcher> {
    let watch = CWatcher::from_request(rq.watch_fn, rq.watch_ctx);
    match rq.op {
        ZKRS_OP_CREATE => Op::Create {
            path: path_of(rq.path),
            data: JBuffer::Null,
            acl,
            mode: rq.mode,
            ttl: rq.ttl,
            create2: rq.flags & ZKRS_F_CREATE2 != 0,
        },
        ZKRS_OP_DELETE => Op::Delete {
            path: path_of(rq.path),
            version: rq.version,
        },
        ZKRS_OP_EXISTS => Op::Exists {
            path: path_of(rq.path),
            watch,
        },
        ZKRS_OP_GETDATA => Op::GetData {
            path: path_of(rq.path),
            watch,
        },
        // The operation has no path. zk-proto sends the config node with
        // no chroot, so `ZKRS_F_RAW_PATH` needs no action here.
        ZKRS_OP_GETCONFIG => Op::GetConfig { watch },
        ZKRS_OP_SETDATA => Op::SetData {
            path: path_of(rq.path),
            data: JBuffer::Null,
            version: rq.version,
        },
        ZKRS_OP_GETACL => Op::GetAcl {
            path: path_of(rq.path),
        },
        ZKRS_OP_SETACL => Op::SetAcl {
            path: path_of(rq.path),
            acl,
            version: rq.version,
        },
        ZKRS_OP_GETCHILDREN | ZKRS_OP_GETCHILDREN2 => Op::GetChildren {
            path: path_of(rq.path),
            watch,
            with_stat: rq.op == ZKRS_OP_GETCHILDREN2,
        },
        ZKRS_OP_SYNC => Op::Sync {
            path: path_of(rq.path),
        },
        ZKRS_OP_RECONFIG => Op::Reconfig {
            joining: JString::from(raw::cstr_opt(rq.joining)),
            leaving: JString::from(raw::cstr_opt(rq.leaving)),
            members: JString::from(raw::cstr_opt(rq.members)),
            version: rq.reconfig_version,
        },
        // `zkrs_submit` gives the borrowed sub-ops of `multi_ops`.
        ZKRS_OP_MULTI => Op::Multi { ops: Vec::new() },
        ZKRS_OP_REMOVE_WATCHES => Op::RemoveWatches {
            path: path_of(rq.path),
            wtype: rq.wtype,
            watcher: watch,
            local: rq.flags & ZKRS_F_LOCAL != 0,
            all: rq.flags & ZKRS_F_REMOVE_ALL != 0,
        },
        _ => abort_with("zk-ffi: unknown zkrs_request operation"),
    }
}

/// Copies a request path. NULL gives `PathIn::Legacy(None)`, which
/// zk-proto rejects at the path stage.
pub(crate) fn path_of(p: *const c_char) -> PathIn {
    PathIn::Legacy(raw::cstr_opt(p))
}

/// Borrows the value buffer of a create or a set data.
///
/// The result goes to `Connection::submit_with_data` inside the FFI
/// call. A null buffer, an unusable buffer and another op give `None`.
/// Then zk-proto uses the null data of the op. An unusable buffer is
/// also an input defect, so zk-proto never encodes it.
pub(crate) fn data_of(rq: &zkrs_request) -> Option<&[u8]> {
    if !matches!(rq.op, ZKRS_OP_CREATE | ZKRS_OP_SETDATA) {
        return None;
    }
    raw::value_ref(rq.data, rq.datalen).ok().flatten()
}

/// Submits one request with its borrowed C inputs.
///
/// A multi borrows its sub-ops through [`multi_ops`]. Another request
/// borrows the value of a create or a set data through [`data_of`]. Both
/// views come from `rq`, which lives in the FFI call. zk-proto encodes
/// them into the owned request frame before this function returns.
fn submit_borrowed(
    d: &Driver,
    req: Request<CTokens>,
    rq: &zkrs_request,
    ob: &mut Outbox<CTokens>,
) -> Result<Submitted<CTokens>, SubmitError<CTokens>> {
    if rq.op == ZKRS_OP_MULTI {
        d.submit_multi_ref(req, &multi_ops(rq), ob)
    } else {
        d.submit_with_data(req, data_of(rq), ob)
    }
}

/// Copies a legacy `struct ACL_vector` and reports an input defect.
///
/// A NULL vector gives an empty vector, as the legacy create sends. It is
/// a defect only when `null_is_bad` is true, as for a set ACL. The
/// function reads the count and the data pointer once. A negative count
/// gives the null vector, because a jute vector holds no other negative
/// count. A NULL array with a positive count is a defect.
pub(crate) fn acl_of_vec(v: *const CAclVector, null_is_bad: bool) -> (JVec<ACL>, bool) {
    if v.is_null() {
        return (JVec::Items(Vec::new()), null_is_bad);
    }
    let v = raw::read_struct(v);
    if v.count < 0 {
        return (JVec::Null, false);
    }
    match raw::array(v.data.cast_const(), v.count) {
        Ok(a) => (JVec::Items(a.iter().map(acl_entry).collect()), false),
        Err(_) => (JVec::Items(Vec::new()), true),
    }
}

/// Copies one legacy ACL entry. A NULL string is a jute null string.
fn acl_entry(e: &CAcl) -> ACL {
    ACL {
        perms: e.perms,
        id: Id {
            scheme: JString::from(raw::cstr_opt(e.id.scheme)),
            id: JString::from(raw::cstr_opt(e.id.id)),
        },
    }
}

/// True when a value buffer breaks the rule of `raw::value_ref`. The
/// check borrows the bytes and makes no copy.
fn value_defect(p: *const c_char, len: i32) -> bool {
    if len < -1 {
        return true;
    }
    match usize::try_from(len) {
        Ok(n) if n > 0 => raw::bytes(p.cast::<u8>(), n).is_err(),
        _ => false,
    }
}

/// Maps a legacy return code of zk-proto to `zkrs_status`.
///
/// A code with no stage of its own maps to `ZKRS_LATE`, the
/// serialization stage. This includes `ZCLOSING` and `ZTHROTTLEDOP`,
/// which the legacy profile cannot give. A failure never has `ZOK`, so
/// `ZOK` also maps to `ZKRS_LATE`.
fn status_of_code(code: i32) -> zkrs_status {
    match code {
        rc::ZBADARGUMENTS => zkrs_status::ZKRS_EARLY_BADARGS,
        rc::ZINVALIDSTATE => zkrs_status::ZKRS_EARLY_STATE,
        rc::ZUNIMPLEMENTED => zkrs_status::ZKRS_UNIMPLEMENTED,
        rc::ZNOWATCHER => zkrs_status::ZKRS_NOWATCHER,
        rc::ZSYSTEMERROR => zkrs_status::ZKRS_SYSTEM,
        _ => zkrs_status::ZKRS_LATE,
    }
}

/// Maps a submit failure to `zkrs_status`.
///
/// C frees the request for every status other than `ZKRS_OK`
/// (`zks_submit_raw`). Thus this function gives back the token of the
/// error with `CReq::into_raw` and never drops it. A drop calls
/// `discard_token`, and C would then free the request twice.
pub(crate) fn status_of(e: SubmitError<CTokens>) -> zkrs_status {
    let SubmitError { code, token, .. } = e;
    // C still owns the request. Rust keeps no copy of the address.
    let _ = token.into_raw();
    status_of_code(code)
}

/// The defect flags of a request, from `rq.flags`, the value buffer, the
/// ACL defect of [`acl_of_vec`] and the token.
pub(crate) fn defects_of(rq: &zkrs_request, token: usize, bad_acl: bool) -> InputDefect {
    let reads_value = matches!(rq.op, ZKRS_OP_CREATE | ZKRS_OP_SETDATA);
    // A NULL multi array with a positive length breaks the shim contract.
    // The sub-op defects travel in each `MultiOpRef`.
    let ops_missing =
        rq.op == ZKRS_OP_MULTI && raw::array_len(rq.ops.cast::<CZooOp>(), rq.ops_len).is_err();
    InputDefect {
        bad_value_buffer: reads_value && value_defect(rq.data, rq.datalen),
        bad_acl,
        marshal_oom: token == 0 || ops_missing,
    }
}

/// The early stages of `zoo_add_auth` that need no lock
/// (zookeeper.c:5309-5328).
///
/// `state < 0` and `state == 0` give `ZKRS_EARLY_STATE`. The credential
/// stage runs only when `cert != NULL && cert_len != 0`, as legacy: a
/// negative length gives `ZKRS_SYSTEM` (the legacy `calloc` fails). Any
/// other input is an empty credential.
fn auth_early(state: i32, cert: *const c_char, cert_len: i32) -> Result<(), zkrs_status> {
    if state <= 0 {
        return Err(zkrs_status::ZKRS_EARLY_STATE);
    }
    if !cert.is_null() && cert_len < 0 {
        return Err(zkrs_status::ZKRS_SYSTEM);
    }
    Ok(())
}

/// Copies the credential of `zoo_add_auth` into `SecretBytes`. The copy
/// reserves the exact size first, so no other copy of the secret stays
/// in memory. A failed reservation gives
/// `ZKRS_SYSTEM`, as the checked legacy `calloc`.
fn auth_credential(cert: *const c_char, cert_len: i32) -> Result<SecretBytes, zkrs_status> {
    let n = match usize::try_from(cert_len) {
        Ok(n) if n > 0 && !cert.is_null() => n,
        Ok(_) => return Ok(SecretBytes::empty()),
        Err(_) if cert.is_null() => return Ok(SecretBytes::empty()),
        Err(_) => return Err(zkrs_status::ZKRS_SYSTEM),
    };
    let src = raw::bytes(cert.cast::<u8>(), n).map_err(|_| zkrs_status::ZKRS_SYSTEM)?;
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| zkrs_status::ZKRS_SYSTEM)?;
    v.extend_from_slice(src);
    Ok(SecretBytes::new(v))
}

/// Submits one request.
///
/// `ZKRS_OK` retains the token, and the driver delivers it exactly once.
/// `ZKRS_OK_LOCAL` is a local remove-watches call that finished; the
/// token is not retained. Every other status gives the token
/// back to C. `delivery` is `ZKRS_DELIVER_QUEUED` or
/// `ZKRS_DELIVER_DIRECT`.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_submit(
    h: *const zkrs_handle,
    rq: *const zkrs_request,
    token: usize,
    delivery: u32,
    ob: *mut zkrs_outbox,
) -> zkrs_status {
    with_handle(h, |i, _| {
        let d = require_driver(i);
        let rq: zkrs_request = raw::read_struct(rq);
        let req = build_request(i, &rq, token, delivery);
        with_outbox(ob, i, |o| match submit_borrowed(d, req, &rq, o) {
            Ok(Submitted::Queued { .. }) => zkrs_status::ZKRS_OK,
            // A local completion is a C-side record. C
            // completes and frees it, so the token goes back to C.
            Ok(Submitted::Local(t)) => {
                let _ = t.into_raw();
                zkrs_status::ZKRS_OK_LOCAL
            }
            Err(e) => status_of(e),
        })
    })
}

/// `zoo_add_auth`.
///
/// zk-ffi checks the `cert_len` stage (a negative value with a non-NULL
/// `cert` gives `ZKRS_SYSTEM`) and
/// `ZKRS_AUTH_F_ALLOC_FAILED` (`ZKRS_SYSTEM`). zk-proto `add_auth`
/// checks the state, the close and the send stages. `cert == NULL` with
/// `cert_len > 0` is an empty credential. The credential is
/// copied into `SecretBytes`. Token 0 means no completion.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_add_auth(
    h: *const zkrs_handle,
    scheme: *const c_char,
    cert: *const c_char,
    cert_len: i32,
    token: usize,
    flags: u32,
    ob: *mut zkrs_outbox,
) -> zkrs_status {
    with_handle(h, |i, _| {
        let d = require_driver(i);
        let Some(scheme) = raw::cstr_opt(scheme) else {
            abort_with("zk-ffi: zkrs_add_auth with a NULL scheme");
        };
        // Stages 1 to 3 run again under the auth lock, because the state
        // can change after `zkrs_add_auth_check`.
        if let Err(st) = auth_early(d.state(), cert, cert_len) {
            return st;
        }
        let cred = match auth_credential(cert, cert_len) {
            Ok(c) => c,
            Err(st) => return st,
        };
        // Stage 4. The shim could not allocate the completion record.
        if flags & ZKRS_AUTH_F_ALLOC_FAILED != 0 {
            return zkrs_status::ZKRS_SYSTEM;
        }
        let done = (token != 0).then(|| CReq::new(token, ZKRS_K_VOID, i.host().discard_fn()));
        with_outbox(ob, i, |_| {
            match d.add_auth(JString::Bytes(scheme), cred, done) {
                Ok(()) => zkrs_status::ZKRS_OK,
                Err(e) => {
                    // C frees the record for every status other than
                    // ZKRS_OK, so the token goes back with no discard.
                    let _ = e.done.map(CReq::into_raw);
                    status_of_code(e.code)
                }
            }
        })
    })
}

/// Stages 1 to 3 of `zoo_add_auth` only. No lock is held
/// and no outbox is used.
///
/// A driver state `< 0` or `== 0` gives `ZKRS_EARLY_STATE`. A negative
/// `cert_len` with a non-NULL `cert` gives `ZKRS_SYSTEM`.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_add_auth_check(
    h: *const zkrs_handle,
    cert: *const c_char,
    cert_len: i32,
) -> zkrs_status {
    with_handle(h, |i, _| {
        let d = require_driver(i);
        match auth_early(d.state(), cert, cert_len) {
            Ok(()) => zkrs_status::ZKRS_OK,
            Err(st) => st,
        }
    })
}

/// The TTL stage of a create, with no handle.
///
/// C calls it when `zh == NULL`, so the TTL stage still wins over the
/// NULL-handle check.
#[allow(unsafe_code, reason = "a C export")]
#[unsafe(no_mangle)]
pub extern "C" fn zkrs_validate_ttl(mode: i32, ttl: i64) -> zkrs_status {
    ffi_guard(|| match check_ttl(mode, ttl) {
        Ok(()) => zkrs_status::ZKRS_OK,
        Err(_) => zkrs_status::ZKRS_EARLY_BADARGS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::handle::test_support::{empty_outbox, new_handle};
    use crate::abi::handle::zkrs_handle_release;
    use crate::abi::host::FfiHost;
    use crate::abi::legacy::CId;
    use crate::abi::multi::test_support::{TestOp, ops_ptr};
    use crate::abi::standin;
    use crate::abi::types::{
        ZKRS_DELIVER_QUEUED, ZKRS_F_RAW_PATH, ZKRS_FLAVOR_MT, ZKRS_FLAVOR_ST, zkrs_item,
    };
    use zk_driver::outbox::Flavor;
    use zk_driver::{
        Env, HostLeaves, Init, InitArgs, InitStep, Outbox, Polled, Shared, StdHostLeaves,
    };
    use zk_proto::{Compat, Config, DriverMode, MultiOpRef, Stage};

    /// A request with no inputs. The numbers are the legacy defaults.
    fn req(op: u32) -> zkrs_request {
        zkrs_request {
            op,
            flags: 0,
            path: std::ptr::null(),
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

    /// The `zkrs_request.acl` value of a legacy ACL vector.
    fn vec_ptr(v: &CAclVector) -> *const std::ffi::c_void {
        std::ptr::from_ref(v).cast()
    }

    /// One legacy ACL entry.
    fn c_acl(perms: i32, scheme: *const c_char, id: *const c_char) -> CAcl {
        CAcl {
            perms,
            id: CId {
                scheme: scheme.cast_mut(),
                id: id.cast_mut(),
            },
        }
    }

    /// Builds the request on a handle with no driver. The token goes back
    /// with no discard.
    fn built(rq: &zkrs_request, delivery: u32) -> (Op<CWatcher>, Route, InputDefect, u32) {
        let h = new_handle();
        let r = with_handle(h, |i, _| {
            let req = build_request(i, rq, 7, delivery);
            let kind = req.token.kind();
            assert_eq!(req.token.into_raw(), 7);
            (req.op, req.route, req.defect, kind)
        });
        zkrs_handle_release(h);
        r
    }

    fn legacy(p: &std::ffi::CStr) -> PathIn {
        PathIn::Legacy(Some(p.to_bytes().to_vec()))
    }

    /// Makes a handle with a ready mt driver, as `zkrs_handle_new` makes
    /// it. The init resolves a numeric address, so it needs no server.
    fn ready_handle() -> *const zkrs_handle {
        ready_flavor(ZKRS_FLAVOR_MT)
    }

    /// Makes a handle with a ready driver of `flavor`. The st driver has
    /// no socket until the first interest call.
    #[allow(clippy::expect_used, reason = "a failed setup ends the test")]
    fn ready_flavor(flavor: u32) -> *const zkrs_handle {
        let host = Arc::new(FfiHost::new(standin::vtable(), 0x55));
        let inner = Arc::new(Inner::new(host, flavor));
        let leaves: Arc<dyn HostLeaves<CTokens>> = Arc::new(StdHostLeaves::new());
        let (mode, fl) = if flavor == ZKRS_FLAVOR_ST {
            (DriverMode::ST, Flavor::St)
        } else {
            (DriverMode::MT, Flavor::Mt)
        };
        let args = InitArgs {
            cfg: Config::legacy(10_000),
            host_string: b"127.0.0.1:22640".to_vec(),
            compat: Compat::LEGACY_C,
            mode,
            flavor: fl,
        };
        let mut ob = Outbox::new();
        let mut init = Init::new(args, Env::new(leaves), &mut ob).expect("init");
        let mut proof = zk_driver::Unlocked::new_at_entry();
        loop {
            let mut ob = Outbox::new();
            match init.step(&mut proof, &mut ob) {
                InitStep::Ready => break,
                InitStep::More => {}
                _ => return std::ptr::null(),
            }
        }
        let driver = if flavor == ZKRS_FLAVOR_ST {
            Driver::St(Arc::new(Polled::from_init(init)))
        } else {
            let mut ob = Outbox::new();
            Driver::Mt(Shared::from_init(init, &mut ob).expect("shared"))
        };
        assert!(inner.install(driver).is_ok());
        raw::handle_into_raw(inner)
    }

    /// Submits one request on `h` with an empty outbox.
    fn submit(h: *const zkrs_handle, rq: &zkrs_request, token: usize) -> zkrs_status {
        let mut ob = empty_outbox();
        let st = zkrs_submit(h, rq, token, ZKRS_DELIVER_QUEUED, &mut ob);
        assert!(ob.r#impl.is_null(), "the mt submit fills no outbox");
        st
    }

    fn add_auth(
        h: *const zkrs_handle,
        cert: *const c_char,
        len: i32,
        token: usize,
        flags: u32,
    ) -> zkrs_status {
        let mut ob = empty_outbox();
        let st = zkrs_add_auth(h, c"digest".as_ptr(), cert, len, token, flags, &mut ob);
        assert!(ob.r#impl.is_null(), "the mt add_auth fills no outbox");
        st
    }

    #[test]
    fn ttl_stage_follows_the_mode() {
        // ZOO_PERSISTENT (0) needs ttl < 0. ZOO_PERSISTENT_WITH_TTL (5)
        // needs 0 < ttl <= 0xFFFFFFFFFF.
        assert_eq!(zkrs_validate_ttl(0, -1), zkrs_status::ZKRS_OK);
        assert_eq!(zkrs_validate_ttl(0, 5), zkrs_status::ZKRS_EARLY_BADARGS);
        assert_eq!(zkrs_validate_ttl(5, 5), zkrs_status::ZKRS_OK);
        assert_eq!(zkrs_validate_ttl(5, 0), zkrs_status::ZKRS_EARLY_BADARGS);
    }

    #[test]
    fn kinds_follow_the_legacy_completions() {
        assert_eq!(kind_of(ZKRS_OP_CREATE, 0), ZKRS_K_STRING);
        assert_eq!(kind_of(ZKRS_OP_CREATE, ZKRS_F_CREATE2), ZKRS_K_STRING_STAT);
        assert_eq!(kind_of(ZKRS_OP_GETCHILDREN2, 0), ZKRS_K_STRINGLIST_STAT);
        assert_eq!(kind_of(ZKRS_OP_MULTI, 0), ZKRS_K_MULTI);
    }

    #[test]
    fn create_copies_every_input() {
        let _rec = standin::recorder();
        let mut acl = [c_acl(31, c"world".as_ptr(), std::ptr::null())];
        let v = CAclVector {
            count: 1,
            data: acl.as_mut_ptr(),
        };
        let mut rq = req(ZKRS_OP_CREATE);
        rq.path = c"/a".as_ptr();
        rq.data = c"xyz".as_ptr();
        rq.datalen = 2;
        rq.acl = vec_ptr(&v);
        rq.mode = 5;
        rq.ttl = 100;
        rq.flags = ZKRS_F_CREATE2;
        let (op, route, defect, kind) = built(&rq, ZKRS_DELIVER_DIRECT);
        // The value is borrowed for the submit, so the op holds no copy.
        assert_eq!(data_of(&rq), Some(&b"xy"[..]));
        let want = Op::Create {
            path: legacy(c"/a"),
            data: JBuffer::Null,
            acl: JVec::Items(vec![ACL {
                perms: 31,
                id: Id {
                    scheme: JString::from("world"),
                    id: JString::Null,
                },
            }]),
            mode: 5,
            ttl: 100,
            create2: true,
        };
        assert_eq!(op, want);
        assert_eq!(route, Route::Direct);
        assert_eq!(defect, InputDefect::default());
        assert_eq!(kind, ZKRS_K_STRING_STAT);
        assert!(standin::discarded().is_empty());
    }

    #[test]
    fn value_buffers_follow_the_legacy_lengths() {
        let _rec = standin::recorder();
        let mut rq = req(ZKRS_OP_SETDATA);
        rq.path = c"/a".as_ptr();
        rq.version = 3;
        // A length of -1 gives the null buffer. A length of 0 gives an empty buffer.
        let (op, _, defect, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::SetData {
            path: legacy(c"/a"),
            data: JBuffer::Null,
            version: 3,
        };
        assert_eq!(
            (op, defect, kind),
            (want.clone(), InputDefect::default(), ZKRS_K_STAT)
        );
        assert_eq!(data_of(&rq), None);
        rq.datalen = 0;
        let (op, _, _, _) = built(&rq, ZKRS_DELIVER_QUEUED);
        assert_eq!(op, want);
        assert_eq!(data_of(&rq), Some(&b""[..]));
        rq.data = c"abc".as_ptr();
        rq.datalen = 3;
        assert_eq!(data_of(&rq), Some(&b"abc"[..]));
        // Only a create and a set data have a value.
        rq.op = ZKRS_OP_SETACL;
        assert_eq!(data_of(&rq), None);
        rq.op = ZKRS_OP_SETDATA;
        rq.data = std::ptr::null();
        // NULL with a positive length, and a length below -1, are defects.
        for len in [4, -2] {
            rq.datalen = len;
            let (op, _, defect, _) = built(&rq, ZKRS_DELIVER_QUEUED);
            assert!(defect.bad_value_buffer, "{len}");
            assert!(!defect.bad_acl && !defect.marshal_oom, "{len}");
            assert_eq!(data_of(&rq), None, "{len}");
            let want = Op::SetData {
                path: legacy(c"/a"),
                data: JBuffer::Null,
                version: 3,
            };
            assert_eq!(op, want);
        }
    }

    #[test]
    fn reads_copy_the_watcher() {
        let _rec = standin::recorder();
        let mut rq = req(ZKRS_OP_GETDATA);
        rq.path = c"/w".as_ptr();
        rq.watch_fn = 0x100;
        rq.watch_ctx = 0x200;
        let w = Some(CWatcher {
            f: 0x100,
            ctx: 0x200,
        });
        let cases = [
            (
                ZKRS_OP_GETDATA,
                Op::GetData {
                    path: legacy(c"/w"),
                    watch: w,
                },
                ZKRS_K_DATA,
            ),
            (
                ZKRS_OP_EXISTS,
                Op::Exists {
                    path: legacy(c"/w"),
                    watch: w,
                },
                ZKRS_K_STAT,
            ),
            (
                ZKRS_OP_GETCHILDREN,
                Op::GetChildren {
                    path: legacy(c"/w"),
                    watch: w,
                    with_stat: false,
                },
                ZKRS_K_STRINGLIST,
            ),
            (
                ZKRS_OP_GETCHILDREN2,
                Op::GetChildren {
                    path: legacy(c"/w"),
                    watch: w,
                    with_stat: true,
                },
                ZKRS_K_STRINGLIST_STAT,
            ),
            (ZKRS_OP_GETCONFIG, Op::GetConfig { watch: w }, ZKRS_K_DATA),
        ];
        for (code, want, want_kind) in cases {
            rq.op = code;
            if code == ZKRS_OP_GETCONFIG {
                rq.flags = ZKRS_F_RAW_PATH;
            }
            let (op, _, _, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
            assert_eq!((op, kind), (want, want_kind), "{code}");
        }
        // A zero function sets no watch.
        rq.op = ZKRS_OP_EXISTS;
        rq.watch_fn = 0;
        let (op, _, _, _) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::Exists {
            path: legacy(c"/w"),
            watch: None,
        };
        assert_eq!(op, want);
    }

    #[test]
    fn writes_and_admin_ops_copy_their_fields() {
        let _rec = standin::recorder();
        let mut rq = req(ZKRS_OP_DELETE);
        rq.path = c"/d".as_ptr();
        rq.version = 9;
        let (op, _, _, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::Delete {
            path: legacy(c"/d"),
            version: 9,
        };
        assert_eq!((op, kind), (want, ZKRS_K_VOID));

        rq.op = ZKRS_OP_GETACL;
        let (op, _, _, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::GetAcl {
            path: legacy(c"/d"),
        };
        assert_eq!((op, kind), (want, ZKRS_K_ACLLIST));

        // A negative count is the null vector.
        let neg = CAclVector {
            count: -1,
            data: std::ptr::null_mut(),
        };
        rq.op = ZKRS_OP_SETACL;
        rq.acl = vec_ptr(&neg);
        let (op, _, defect, _) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::SetAcl {
            path: legacy(c"/d"),
            acl: JVec::Null,
            version: 9,
        };
        assert_eq!((op, defect), (want, InputDefect::default()));
        rq.acl = std::ptr::null();

        rq.op = ZKRS_OP_SYNC;
        let (op, _, _, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::Sync {
            path: legacy(c"/d"),
        };
        assert_eq!((op, kind), (want, ZKRS_K_STRING));

        let mut rq = req(ZKRS_OP_RECONFIG);
        rq.joining = c"server.1=a:1:2".as_ptr();
        rq.members = c"".as_ptr();
        rq.reconfig_version = 0x1_0000_0001;
        let (op, _, _, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::Reconfig {
            joining: JString::from("server.1=a:1:2"),
            leaving: JString::Null,
            members: JString::from(""),
            version: 0x1_0000_0001,
        };
        assert_eq!((op, kind), (want, ZKRS_K_DATA));
    }

    #[test]
    fn remove_watches_and_multi_copy_their_flags() {
        let _rec = standin::recorder();
        let mut rq = req(ZKRS_OP_REMOVE_WATCHES);
        rq.path = c"/r".as_ptr();
        rq.wtype = 2;
        rq.flags = ZKRS_F_LOCAL | ZKRS_F_REMOVE_ALL;
        let (op, _, _, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
        let want = Op::RemoveWatches {
            path: legacy(c"/r"),
            wtype: 2,
            watcher: None,
            local: true,
            all: true,
        };
        assert_eq!((op, kind), (want, ZKRS_K_VOID));

        let ops = [TestOp::check(c"/m", 4)];
        let mut rq = req(ZKRS_OP_MULTI);
        rq.ops = ops_ptr(&ops);
        rq.ops_len = 1;
        rq.count = 1;
        let (op, _, defect, kind) = built(&rq, ZKRS_DELIVER_QUEUED);
        // The op holds no sub-op. `zkrs_submit` borrows them from `rq`.
        let want = Op::Multi { ops: Vec::new() };
        assert_eq!(
            (op, defect, kind),
            (want, InputDefect::default(), ZKRS_K_MULTI)
        );
        let sub = [MultiOpRef::Check {
            path: Some(b"/m".as_slice()),
            version: 4,
            defect: InputDefect::default(),
        }];
        assert_eq!(multi_ops(&rq), sub);
    }

    #[test]
    fn acl_vectors_follow_the_legacy_rules() {
        let empty = (JVec::Items(Vec::new()), false);
        // A NULL vector is empty. Only a set ACL makes it a defect.
        assert_eq!(acl_of_vec(std::ptr::null(), false), empty);
        assert_eq!(
            acl_of_vec(std::ptr::null(), true),
            (JVec::Items(Vec::new()), true)
        );
        // A negative count is the null vector, and 0 is an empty vector.
        let mut v = CAclVector {
            count: -1,
            data: std::ptr::null_mut(),
        };
        assert_eq!(acl_of_vec(&v, true), (JVec::Null, false));
        v.count = 0;
        assert_eq!(acl_of_vec(&v, true), empty);
        // NULL data with a positive count is a defect.
        v.count = 2;
        assert_eq!(acl_of_vec(&v, false), (JVec::Items(Vec::new()), true));

        // 20 entries keep their order. A NULL scheme or id is a jute null
        // string.
        let null = std::ptr::null();
        let mut many: Vec<CAcl> = (0..20)
            .map(|i| {
                let scheme = if i == 3 { null } else { c"digest".as_ptr() };
                let id = if i == 4 { null } else { c"u:p".as_ptr() };
                c_acl(i, scheme, id)
            })
            .collect();
        let v = CAclVector {
            count: 20,
            data: many.as_mut_ptr(),
        };
        let want: Vec<ACL> = (0..20)
            .map(|i| ACL {
                perms: i,
                id: Id {
                    scheme: if i == 3 {
                        JString::Null
                    } else {
                        JString::from("digest")
                    },
                    id: if i == 4 {
                        JString::Null
                    } else {
                        JString::from("u:p")
                    },
                },
            })
            .collect();
        assert_eq!(acl_of_vec(&v, true), (JVec::Items(want), false));
    }

    #[test]
    fn only_create_and_set_acl_read_the_acl_vector() {
        let _rec = standin::recorder();
        let bad = CAclVector {
            count: 2,
            data: std::ptr::null_mut(),
        };
        for (code, null_bad) in [(ZKRS_OP_CREATE, false), (ZKRS_OP_SETACL, true)] {
            let mut rq = req(code);
            rq.path = c"/a".as_ptr();
            let (_, _, defect, _) = built(&rq, ZKRS_DELIVER_QUEUED);
            assert_eq!(defect.bad_acl, null_bad, "{code}");
            rq.acl = vec_ptr(&bad);
            let (_, _, defect, _) = built(&rq, ZKRS_DELIVER_QUEUED);
            assert!(defect.bad_acl, "{code}");
        }
        // Another op never reads the vector.
        let mut rq = req(ZKRS_OP_GETACL);
        rq.path = c"/a".as_ptr();
        rq.acl = vec_ptr(&bad);
        let (_, _, defect, _) = built(&rq, ZKRS_DELIVER_QUEUED);
        assert_eq!(defect, InputDefect::default());
    }

    #[test]
    fn defects_come_from_the_buffers_the_acl_and_the_token() {
        let rq = req(ZKRS_OP_CREATE);
        assert_eq!(defects_of(&rq, 1, false), InputDefect::default());
        assert!(defects_of(&rq, 0, false).marshal_oom);
        assert!(defects_of(&rq, 1, true).bad_acl);

        // A bad value buffer. Only create and set_data read the buffer.
        let mut v = req(ZKRS_OP_CREATE);
        v.datalen = 3;
        assert!(defects_of(&v, 1, false).bad_value_buffer);
        v.datalen = -5;
        assert!(defects_of(&v, 1, false).bad_value_buffer);
        v.op = ZKRS_OP_DELETE;
        assert!(!defects_of(&v, 1, false).bad_value_buffer);

        // A multi with a NULL array and a positive length.
        let mut m = req(ZKRS_OP_MULTI);
        m.ops_len = 1;
        assert!(defects_of(&m, 1, false).marshal_oom);
        m.ops_len = 0;
        assert_eq!(defects_of(&m, 1, false), InputDefect::default());
    }

    #[test]
    fn status_of_gives_the_token_back() {
        let _rec = standin::recorder();
        let cases = [
            (rc::ZBADARGUMENTS, zkrs_status::ZKRS_EARLY_BADARGS),
            (rc::ZINVALIDSTATE, zkrs_status::ZKRS_EARLY_STATE),
            (rc::ZUNIMPLEMENTED, zkrs_status::ZKRS_UNIMPLEMENTED),
            (rc::ZNOWATCHER, zkrs_status::ZKRS_NOWATCHER),
            (rc::ZSYSTEMERROR, zkrs_status::ZKRS_SYSTEM),
            (rc::ZMARSHALLINGERROR, zkrs_status::ZKRS_LATE),
            (rc::ZCLOSING, zkrs_status::ZKRS_LATE),
            (rc::ZTHROTTLEDOP, zkrs_status::ZKRS_LATE),
            (rc::ZOK, zkrs_status::ZKRS_LATE),
        ];
        for (code, want) in cases {
            let e = SubmitError {
                stage: Stage::Validate,
                code,
                token: CReq::new(9, ZKRS_K_VOID, standin::discard_token),
            };
            assert_eq!(status_of(e), want, "{code}");
        }
        assert!(standin::discarded().is_empty());
    }

    #[test]
    fn auth_stages_follow_the_legacy_order() {
        let cert = c"pw".as_ptr();
        let null = std::ptr::null();
        assert_eq!(
            auth_early(-112, cert, -1),
            Err(zkrs_status::ZKRS_EARLY_STATE)
        );
        assert_eq!(auth_early(0, cert, 2), Err(zkrs_status::ZKRS_EARLY_STATE));
        assert_eq!(auth_early(3, cert, -1), Err(zkrs_status::ZKRS_SYSTEM));
        assert_eq!(auth_early(3, null, -1), Ok(()));
        assert_eq!(auth_early(3, cert, 0), Ok(()));
        assert_eq!(auth_early(3, null, 5), Ok(()));

        // The tests compare the exposed bytes, because a secret has no `==`.
        let bytes = |c, n| auth_credential(c, n).map(|s| s.expose().to_vec());
        assert_eq!(bytes(null, 5), Ok(Vec::new()));
        assert_eq!(bytes(null, -1), Ok(Vec::new()));
        assert_eq!(bytes(cert, 0), Ok(Vec::new()));
        assert_eq!(bytes(cert, -1), Err(zkrs_status::ZKRS_SYSTEM));
        assert_eq!(bytes(cert, 2), Ok(b"pw".to_vec()));
    }

    #[test]
    fn submit_retains_only_on_ok() {
        let _rec = standin::recorder();
        let h = ready_handle();
        assert!(!h.is_null());
        let mut rq = req(ZKRS_OP_CREATE);
        rq.path = c"/a".as_ptr();
        assert_eq!(submit(h, &rq, 11,), zkrs_status::ZKRS_OK);
        // A bad path fails early.
        rq.path = c"a".as_ptr();
        assert_eq!(submit(h, &rq, 12), zkrs_status::ZKRS_EARLY_BADARGS);
        // The input defects fail at the serialization stage.
        rq.path = c"/a".as_ptr();
        rq.datalen = 4;
        assert_eq!(submit(h, &rq, 13), zkrs_status::ZKRS_LATE);
        rq.datalen = -1;
        let bad = CAclVector {
            count: 2,
            data: std::ptr::null_mut(),
        };
        rq.acl = vec_ptr(&bad);
        assert_eq!(submit(h, &rq, 14), zkrs_status::ZKRS_LATE);
        rq.acl = std::ptr::null();
        assert_eq!(submit(h, &rq, 0), zkrs_status::ZKRS_LATE);
        // The TTL stage comes first.
        rq.path = c"a".as_ptr();
        rq.ttl = 7;
        assert_eq!(submit(h, &rq, 16), zkrs_status::ZKRS_EARLY_BADARGS);
        assert!(standin::discarded().is_empty());
        // The release drops the driver, which discards the kept token.
        zkrs_handle_release(h);
        assert_eq!(standin::discarded(), vec![11]);
    }

    #[test]
    fn submit_maps_the_multi_and_watch_stages() {
        let _rec = standin::recorder();
        let h = ready_handle();
        assert!(!h.is_null());
        let ops = [TestOp::unset(99)];
        let mut rq = req(ZKRS_OP_MULTI);
        rq.ops = ops_ptr(&ops);
        rq.ops_len = 1;
        rq.count = 1;
        assert_eq!(submit(h, &rq, 21), zkrs_status::ZKRS_UNIMPLEMENTED);
        // A NULL array that C did not fill.
        rq.ops = std::ptr::null();
        assert_eq!(submit(h, &rq, 22), zkrs_status::ZKRS_LATE);
        // An empty multi is legal.
        rq.ops_len = 0;
        rq.count = 0;
        assert_eq!(submit(h, &rq, 23), zkrs_status::ZKRS_OK);
        // The sub-ops borrow C memory for the call only. The frame keeps
        // no view, so the caller frees its buffers after the call.
        let path = c"/s".to_owned();
        let data = vec![7u8; 8];
        let ops = [TestOp::set(&path, data.as_ptr().cast(), 8, -1)];
        rq.ops = ops_ptr(&ops);
        rq.ops_len = 1;
        rq.count = 1;
        assert_eq!(submit(h, &rq, 27), zkrs_status::ZKRS_OK);
        // A bad sub-op value buffer fails at the serialization stage.
        let bad = [TestOp::set(&path, data.as_ptr().cast(), -2, -1)];
        rq.ops = ops_ptr(&bad);
        assert_eq!(submit(h, &rq, 28), zkrs_status::ZKRS_LATE);
        drop((path, data));

        // A watcher with no registration fails the local check.
        let mut rw = req(ZKRS_OP_REMOVE_WATCHES);
        rw.path = c"/w".as_ptr();
        rw.wtype = 1;
        rw.watch_fn = 0x300;
        assert_eq!(submit(h, &rw, 24), zkrs_status::ZKRS_NOWATCHER);
        // A NULL watcher matches every valid type, as in legacy C. A local
        // removal completes on the C side, so C keeps the token.
        rw.watch_fn = 0;
        rw.flags = ZKRS_F_LOCAL;
        assert_eq!(submit(h, &rw, 25), zkrs_status::ZKRS_OK_LOCAL);
        rw.flags = ZKRS_F_REMOVE_ALL;
        assert_eq!(submit(h, &rw, 26), zkrs_status::ZKRS_OK);
        assert!(standin::discarded().is_empty());
        zkrs_handle_release(h);
        let mut d = standin::discarded();
        d.sort_unstable();
        assert_eq!(d, vec![23, 26, 27]);
    }

    /// Rule: a negative `cert_len` and a failed allocation give
    /// `ZKRS_SYSTEM`, as in legacy C.
    #[test]
    fn add_auth_checks_and_retains() {
        let _rec = standin::recorder();
        let h = ready_handle();
        assert!(!h.is_null());
        let cert = c"pw".as_ptr();
        assert_eq!(zkrs_add_auth_check(h, cert, 2), zkrs_status::ZKRS_OK);
        assert_eq!(zkrs_add_auth_check(h, cert, -1), zkrs_status::ZKRS_SYSTEM);
        assert_eq!(
            zkrs_add_auth_check(h, std::ptr::null(), -1),
            zkrs_status::ZKRS_OK
        );
        assert_eq!(add_auth(h, cert, -1, 31, 0), zkrs_status::ZKRS_SYSTEM);
        assert_eq!(
            add_auth(h, cert, 2, 0, ZKRS_AUTH_F_ALLOC_FAILED),
            zkrs_status::ZKRS_SYSTEM
        );
        assert_eq!(add_auth(h, cert, 2, 32, 0), zkrs_status::ZKRS_OK);
        // NULL with a positive length is an empty credential.
        assert_eq!(
            add_auth(h, std::ptr::null(), 5, 33, 0),
            zkrs_status::ZKRS_OK
        );
        // Token 0 means no completion.
        assert_eq!(add_auth(h, cert, 2, 0, 0), zkrs_status::ZKRS_OK);
        assert!(standin::discarded().is_empty());
        zkrs_handle_release(h);
        let mut d = standin::discarded();
        d.sort_unstable();
        assert_eq!(d, vec![32, 33]);
    }

    /// Submits one request on an st handle as `zks_submit_req` does. It
    /// drains the outbox and gives the status and the item types.
    fn st_submit(
        h: *const zkrs_handle,
        rq: &zkrs_request,
        token: usize,
    ) -> (zkrs_status, Vec<u32>) {
        let mut ob = empty_outbox();
        let st = zkrs_submit(h, rq, token, ZKRS_DELIVER_QUEUED, &mut ob);
        let mut types = Vec::new();
        let mut it = zkrs_item::empty();
        while crate::abi::outbox::zkrs_outbox_next(&mut ob, &raw mut it) == 1 {
            types.push(it.r#type);
        }
        crate::abi::outbox::zkrs_outbox_finish(&mut ob);
        assert!(ob.r#impl.is_null());
        (st, types)
    }

    #[test]
    fn st_submit_queues_with_no_socket() {
        let _rec = standin::recorder();
        let h = ready_flavor(ZKRS_FLAVOR_ST);
        assert!(!h.is_null());
        let st = with_handle(h, |i, _| matches!(i.driver(), Some(Driver::St(_))));
        assert!(st);
        let mut rq = req(ZKRS_OP_EXISTS);
        rq.path = c"/a".as_ptr();
        // No socket exists, so the flush pass sends nothing and gives no
        // item.
        assert_eq!(st_submit(h, &rq, 41), (zkrs_status::ZKRS_OK, vec![]));
        rq.path = c"a".as_ptr();
        assert_eq!(
            st_submit(h, &rq, 42),
            (zkrs_status::ZKRS_EARLY_BADARGS, vec![])
        );
        rq.path = c"/a".as_ptr();
        assert_eq!(st_submit(h, &rq, 0).0, zkrs_status::ZKRS_LATE);
        assert!(standin::discarded().is_empty());
        // The release drops the driver, which discards the kept token.
        zkrs_handle_release(h);
        assert_eq!(standin::discarded(), vec![41]);
    }

    #[test]
    fn st_add_auth_checks_and_retains() {
        let _rec = standin::recorder();
        let h = ready_flavor(ZKRS_FLAVOR_ST);
        assert!(!h.is_null());
        let cert = c"pw".as_ptr();
        assert_eq!(zkrs_add_auth_check(h, cert, 2), zkrs_status::ZKRS_OK);
        let mut ob = empty_outbox();
        let st = zkrs_add_auth(h, c"digest".as_ptr(), cert, 2, 51, 0, &mut ob);
        crate::abi::outbox::zkrs_outbox_finish(&mut ob);
        assert_eq!(st, zkrs_status::ZKRS_OK);
        assert!(standin::discarded().is_empty());
        zkrs_handle_release(h);
        assert_eq!(standin::discarded(), vec![51]);
    }
}
