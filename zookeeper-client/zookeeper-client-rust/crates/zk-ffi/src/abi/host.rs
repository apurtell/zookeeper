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

//! The host vtable as zk-driver [`HostLeaves`].
//!
//! [`FfiHost`] keeps a copy of the vtable and the `host` value of the
//! handle (the `zhandle_t *`). zk-driver calls the leaves through
//! `Env`. The Pure leaves never block. The Blocking leaves take the
//! [`Unlocked`] proof, so they run with no Rust lock held.
//!
//! The final close sets `host` to 0 just before `ZKRS_RELEASE`. A later
//! leaf call that reads 0 aborts, because the `zhandle_t` is then gone.

use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use zk_driver::{Discarded, HostLeaves, Unlocked};
use zk_proto::{ClientId, HostResolution, HostSpec, LogLevel, ResolveError};

use super::entry::abort_with;
use super::raw;
use super::tokens::{CTokens, CWatcher};
use super::types::zkrs_host_vtable;

/// The host side of one handle.
#[derive(Debug)]
pub(crate) struct FfiHost {
    vt: zkrs_host_vtable,
    host: AtomicUsize,
}

impl FfiHost {
    /// Makes the host from the vtable copy and the `host` value of
    /// `zkrs_handle_new`.
    pub(crate) fn new(vt: zkrs_host_vtable, host: usize) -> Self {
        Self {
            vt,
            host: AtomicUsize::new(host),
        }
    }

    /// The `host` value. 0 (after release) aborts.
    pub(crate) fn host(&self) -> usize {
        let h = self.host.load(Ordering::Acquire);
        if h == 0 {
            abort_with("zk-ffi: host vtable used after release");
        }
        h
    }

    /// Sets `host` to 0. The final close calls it after it took every
    /// leftover token out of the driver, just before `ZKRS_RELEASE`.
    pub(crate) fn zero(&self) {
        self.host.store(0, Ordering::Release);
    }

    /// True after [`FfiHost::zero`]. Tests read it, because
    /// [`FfiHost::host`] aborts on 0.
    #[cfg(test)]
    pub(crate) fn is_zero(&self) -> bool {
        self.host.load(Ordering::Acquire) == 0
    }

    /// The `discard_token` entry, for [`super::tokens::CReq`].
    pub(crate) fn discard_fn(&self) -> unsafe extern "C" fn(usize) {
        match self.vt.discard_token {
            Some(f) => f,
            None => abort_with("zk-ffi: missing host vtable entry discard_token"),
        }
    }
}

impl HostLeaves<CTokens> for FfiHost {
    /// Pure. A completion or auth token drops, and its `Drop` calls
    /// `discard_token`. A watcher holds no C resource.
    fn discard_token(&self, token: Discarded<CTokens>) {
        match token {
            Discarded::Completion(r) | Discarded::Auth(r) => drop(r),
            Discarded::Watcher(_) => {}
        }
    }

    /// Pure. The pair cell is never NULL (`zks_null_watcher`), so a 0
    /// function means no default watcher.
    fn snapshot_default_watcher(&self) -> Option<CWatcher> {
        let w = raw::vt_snapshot_default_watcher(&self.vt, self.host());
        CWatcher::from_request(w.r#fn, w.ctx)
    }

    /// Pure.
    fn store_client_id(&self, id: &ClientId) {
        raw::vt_store_client_id(&self.vt, self.host(), id.session_id, &id.passwd);
    }

    /// Pure.
    fn log_enabled(&self, level: LogLevel) -> bool {
        let code = u32::try_from(level.code()).unwrap_or(0);
        raw::vt_log_enabled(&self.vt, code)
    }

    /// Pure.
    fn conn_permute_disabled(&self) -> bool {
        raw::vt_conn_permute_disabled(&self.vt)
    }

    /// Pure.
    fn rng_random(&self) -> i64 {
        raw::vt_rng_random(&self.vt)
    }

    /// Pure.
    fn rng_drand48(&self) -> f64 {
        raw::vt_rng_drand48(&self.vt)
    }

    /// Blocking.
    fn rng_reseed(&self, proof: &Unlocked) {
        raw::vt_rng_reseed(&self.vt, proof);
    }

    /// Blocking. Resolves one host entry.
    ///
    /// The function makes NUL-terminated copies of `spec.host` and
    /// `spec.service` in a [`CText`] and calls [`raw::vt_resolve`].
    /// It maps `(errno, gai_rc)` to the zk-proto `ResolveError` and gives
    /// the skipped families in `HostResolution.skipped_families`. The
    /// core queues the platform log site; this leaf logs nothing.
    fn resolve(&self, proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution {
        let (name, port) = resolve_args(spec);
        let mut out = raw::HostAddrs::default();
        // `CText` ends each copy with a NUL. Thus the conversion always
        // succeeds. An inner NUL ends the C string early, as in C.
        let (errno, gai_rc) = match (
            CStr::from_bytes_until_nul(name.as_bytes()),
            CStr::from_bytes_until_nul(port.as_bytes()),
        ) {
            (Ok(n), Ok(p)) => raw::vt_resolve(&self.vt, proof, n, p, &mut out),
            _ => (libc::EINVAL, 0),
        };
        let raw::HostAddrs {
            addrs,
            skipped_families,
        } = out;
        // C reads errno 0 as success. Thus a failure with errno 0 gets
        // EINVAL, the default of the legacy `getaddrinfo_errno`.
        let result = if errno == 0 && gai_rc == 0 {
            Ok(addrs)
        } else {
            Err(ResolveError {
                gai_rc,
                errno: if errno == 0 { libc::EINVAL } else { errno },
            })
        };
        HostResolution {
            host,
            result,
            skipped_families,
        }
    }
}

/// The inline capacity of [`CText`]. A DNS name has at most 253 bytes.
/// Thus a usual host or service text needs no heap copy.
const CTEXT_INLINE: usize = 256;

/// Holds one NUL-terminated text for `getaddrinfo`.
///
/// The client can resolve on each interest turn. A short text stays on
/// the stack. A longer text uses a heap copy from [`raw::c_bytes`].
struct CText {
    inline: [u8; CTEXT_INLINE],
    len: usize,
    heap: Option<Box<[u8]>>,
}

impl CText {
    /// Copies a text and ends it with a NUL.
    fn copy(b: &[u8]) -> Self {
        let mut t = Self {
            inline: [0u8; CTEXT_INLINE],
            len: 0,
            heap: None,
        };
        match t.inline.get_mut(..b.len()) {
            Some(dst) if b.len() < CTEXT_INLINE => {
                dst.copy_from_slice(b);
                t.len = b.len().saturating_add(1);
            }
            _ => t.heap = Some(raw::c_bytes(b)),
        }
        t
    }

    /// Writes a port as decimal text. A `u16` has at most five digits.
    fn port(port: u16) -> Self {
        let mut digits = [0u8; 5];
        let mut at = digits.len();
        let mut v = port;
        while at > 0 {
            at = at.saturating_sub(1);
            if let Some(d) = digits.get_mut(at) {
                *d = b'0'.saturating_add(u8::try_from(v % 10).unwrap_or(0));
            }
            v /= 10;
            if v == 0 {
                break;
            }
        }
        Self::copy(digits.get(at..).unwrap_or(&[]))
    }

    fn as_bytes(&self) -> &[u8] {
        match &self.heap {
            Some(b) => b,
            None => self.inline.get(..self.len).unwrap_or(&[]),
        }
    }
}

/// Gives the NUL-terminated name and port texts of one host entry.
///
/// A legacy entry keeps the raw host and service texts of the parser.
/// Thus `getaddrinfo` gets the same strings as in the legacy client. A
/// native entry gives its port as decimal text.
fn resolve_args(spec: &HostSpec) -> (CText, CText) {
    match spec {
        HostSpec::Legacy(h) => (CText::copy(&h.host), CText::copy(&h.service)),
        HostSpec::Native(h) => (CText::copy(h.host.as_bytes()), CText::port(h.port)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::standin;
    use super::super::types::zkrs_sockaddr_view;
    use super::*;

    #[test]
    fn pure_leaves_reach_the_vtable() {
        let _rec = standin::recorder();
        let h = FfiHost::new(standin::vtable(), 0x55);
        assert_eq!(h.host(), 0x55);
        assert!(h.log_enabled(LogLevel::Error));
        assert!(!h.log_enabled(LogLevel::Debug));
        assert_eq!(h.rng_random(), standin::RANDOM);
        assert_eq!(
            h.snapshot_default_watcher(),
            Some(CWatcher { f: 0x10, ctx: 0x55 })
        );
        h.store_client_id(&ClientId {
            session_id: 7,
            passwd: [1; 16],
        });
        assert_eq!(standin::client_ids(), vec![(0x55, 7, [1; 16])]);
    }

    fn legacy(host: &[u8], service: &[u8]) -> HostSpec {
        HostSpec::Legacy(zk_proto::legacy::connect::HostSpec {
            host: host.to_vec(),
            service: service.to_vec(),
            port: 0,
        })
    }

    fn view(a: &str) -> zkrs_sockaddr_view {
        zkrs_sockaddr_view::from_addr(a.parse().ok())
    }

    #[test]
    fn resolve_keeps_the_order_and_the_skipped_families() {
        let _rec = standin::recorder();
        let h = FfiHost::new(standin::vtable(), 0x55);
        let v4 = view("10.0.0.1:2181");
        let v6 = view("[::1]:2181");
        standin::set_resolve(vec![v4, v6, v4], vec![1, 17], 0, 0);
        let r = h.resolve(&Unlocked::new_at_entry(), 3, &legacy(b"zk1", b"2181"));
        let want: Vec<std::net::SocketAddr> =
            [v4, v6, v4].iter().filter_map(|v| v.to_addr()).collect();
        assert_eq!(r.host, 3);
        assert_eq!(r.result, Ok(want));
        assert_eq!(r.skipped_families, vec![1, 17]);
        assert_eq!(
            standin::resolved(),
            vec![(b"zk1".to_vec(), b"2181".to_vec())]
        );
    }

    #[test]
    fn resolve_gives_each_error() {
        let _rec = standin::recorder();
        let h = FfiHost::new(standin::vtable(), 0x55);
        let u = Unlocked::new_at_entry();
        let spec = legacy(b"nohost", b"2181");
        // A getaddrinfo failure with the errno that C mapped.
        standin::set_resolve(Vec::new(), vec![2], libc::ENOENT, -2);
        let r = h.resolve(&u, 0, &spec);
        let e = ResolveError {
            gai_rc: -2,
            errno: libc::ENOENT,
        };
        assert_eq!((r.result, r.skipped_families), (Err(e), vec![2]));
        // A failure with no errno is still a failure for C.
        standin::set_resolve(Vec::new(), Vec::new(), 0, -8);
        let e = ResolveError {
            gai_rc: -8,
            errno: libc::EINVAL,
        };
        assert_eq!(h.resolve(&u, 0, &spec).result, Err(e));
        // An entry that fails before getaddrinfo gives only the errno.
        standin::set_resolve(Vec::new(), Vec::new(), libc::ENOSYS, 0);
        let e = ResolveError {
            gai_rc: 0,
            errno: libc::ENOSYS,
        };
        assert_eq!(h.resolve(&u, 0, &spec).result, Err(e));
        // No address and no error is an empty success.
        standin::set_resolve(Vec::new(), Vec::new(), 0, 0);
        assert_eq!(h.resolve(&u, 0, &spec).result, Ok(Vec::new()));
    }

    #[test]
    fn resolve_passes_a_native_port_as_text() {
        let _rec = standin::recorder();
        let h = FfiHost::new(standin::vtable(), 0x55);
        let spec = HostSpec::Native(zk_proto::legacy::connect::NativeHost {
            host: "zk2".into(),
            port: 2182,
        });
        let _ = h.resolve(&Unlocked::new_at_entry(), 0, &spec);
        assert_eq!(
            standin::resolved(),
            vec![(b"zk2".to_vec(), b"2182".to_vec())]
        );
        h.zero();
        assert!(h.is_zero());
    }

    #[test]
    fn ctext_ends_short_and_long_texts_with_a_nul() {
        assert_eq!(CText::copy(b"zk1").as_bytes(), b"zk1\0");
        assert_eq!(CText::copy(b"").as_bytes(), b"\0");
        let long = vec![b'a'; CTEXT_INLINE];
        let mut want = long.clone();
        want.push(0);
        assert!(CText::copy(&long).heap.is_some());
        assert_eq!(CText::copy(&long).as_bytes(), &want[..]);
        let fits = vec![b'b'; CTEXT_INLINE - 1];
        assert!(CText::copy(&fits).heap.is_none());
        assert_eq!(CText::copy(&fits).as_bytes().len(), CTEXT_INLINE);
        assert_eq!(CText::port(0).as_bytes(), b"0\0");
        assert_eq!(CText::port(7).as_bytes(), b"7\0");
        assert_eq!(CText::port(65535).as_bytes(), b"65535\0");
    }
}
