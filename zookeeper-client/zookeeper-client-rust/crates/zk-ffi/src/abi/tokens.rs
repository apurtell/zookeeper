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

//! The token types of the drop-in drivers.
//!
//! A completion token is the address of a C `struct zks_req`. Rust owns
//! it from `zkrs_submit` to one of two ends: C takes it from a RESULT
//! item, or the token drops and C frees it through `discard_token`.
//! [`CReq`] is not `Clone` and not `Copy`, so the type system keeps the
//! "exactly once" rule.
//!
//! A watcher token is the `(watcher_fn, void *)` pair of the
//! application. It holds no C resource, so [`CWatcher`] is `Copy`.

use zk_proto::Tokens;

use super::raw;
use super::types::{ZKRS_K_STRING_STAT, zkrs_watcher};

/// The token set of the drop-in drivers.
#[derive(Debug)]
pub(crate) struct CTokens;

impl Tokens for CTokens {
    type Completion = CReq;
    type Watcher = CWatcher;
    type Auth = CReq;
}

/// One C request token (`struct zks_req *`).
///
/// The drop of a `CReq` calls `discard_token`. Thus a token that the core
/// drops frees the C request and ends a sync wait with ZCLOSING.
/// [`CReq::into_raw`] gives the token to C with no call.
///
/// Address 0 means that the shim failed to allocate the request. The
/// submit path reports it as an `InputDefect`, so the core never
/// delivers it. Its drop calls nothing.
#[derive(Debug)]
pub(crate) struct CReq {
    addr: usize,
    kind: u8,
    discard: unsafe extern "C" fn(usize),
}

impl CReq {
    /// Takes a token from C.
    ///
    /// `kind` is the `ZKRS_K_*` value of the request. The result view
    /// needs it, because `OpResult` carries no kind. A value above
    /// `ZKRS_K_STRING_STAT` is stored as `u8::MAX`. `discard` is the
    /// `discard_token` entry of the handle vtable.
    pub(crate) fn new(addr: usize, kind: u32, discard: unsafe extern "C" fn(usize)) -> Self {
        let kind = u8::try_from(kind)
            .ok()
            .filter(|k| u32::from(*k) <= ZKRS_K_STRING_STAT)
            .unwrap_or(u8::MAX);
        Self {
            addr,
            kind,
            discard,
        }
    }

    /// True for the token 0 of a shim allocation failure.
    #[cfg(test)]
    pub(crate) fn is_null(&self) -> bool {
        self.addr == 0
    }

    /// The `ZKRS_K_*` kind of the request.
    pub(crate) fn kind(&self) -> u32 {
        u32::from(self.kind)
    }

    /// Gives the token to C with no `discard_token` call. C then owns
    /// the request (`zkrs_item.token`).
    pub(crate) fn into_raw(self) -> usize {
        let a = self.addr;
        std::mem::forget(self);
        a
    }
}

impl Drop for CReq {
    fn drop(&mut self) {
        if self.addr != 0 {
            raw::vt_discard_token_fn(self.discard, self.addr);
        }
    }
}

/// One watcher pair. `==` is the legacy deduplication relation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct CWatcher {
    /// The `watcher_fn` value.
    pub(crate) f: usize,
    /// The context value.
    pub(crate) ctx: usize,
}

impl CWatcher {
    /// Makes the watcher of a request. `f == 0` gives `None`: the
    /// request sets no watch.
    pub(crate) fn from_request(f: usize, ctx: usize) -> Option<Self> {
        (f != 0).then_some(Self { f, ctx })
    }

    /// The C view of the pair.
    pub(crate) fn view(self) -> zkrs_watcher {
        zkrs_watcher {
            r#fn: self.f,
            ctx: self.ctx,
        }
    }
}

impl From<zkrs_watcher> for CWatcher {
    fn from(w: zkrs_watcher) -> Self {
        Self {
            f: w.r#fn,
            ctx: w.ctx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::standin;
    use super::super::types::ZKRS_K_DATA;
    use super::*;

    #[test]
    fn drop_discards_and_into_raw_does_not() {
        let _rec = standin::recorder();
        let a = CReq::new(0x1000, ZKRS_K_DATA, standin::discard_token);
        let b = CReq::new(0x2000, ZKRS_K_DATA, standin::discard_token);
        let z = CReq::new(0, 99, standin::discard_token);
        assert!(z.is_null());
        assert_eq!(z.kind(), u32::from(u8::MAX));
        drop(z);
        assert_eq!(a.kind(), ZKRS_K_DATA);
        drop(a);
        assert_eq!(b.into_raw(), 0x2000);
        assert_eq!(standin::discarded(), vec![0x1000]);
    }

    #[test]
    fn watcher_zero_sets_no_watch() {
        assert_eq!(CWatcher::from_request(0, 9), None);
        let w = CWatcher::from_request(5, 9);
        assert_eq!(
            w.map(CWatcher::view),
            Some(zkrs_watcher { r#fn: 5, ctx: 9 })
        );
    }
}
