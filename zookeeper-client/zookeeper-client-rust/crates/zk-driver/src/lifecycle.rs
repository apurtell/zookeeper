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

//! The reference-count lifecycle of a drop-in handle.
//!
//! `refs` is the `api_prolog`/`api_epilog` count of C
//! (zookeeper.c:3214-3224). It decides only who runs the final close and
//! when. Rust memory stays alive through `Arc` references.
//!
//! - Holders of a ref: the IO and dispatch threads (from
//!   `zkrs_thread_enter` to `zkrs_thread_exit`), the init thread during
//!   start, `close`, and each st `zookeeper_interest` or
//!   `zookeeper_process` call. Async and sync API calls take no ref.
//! - `epilog`: the call that drops the last ref after a close request
//!   runs the final close, exactly once (`finalizing`).
//!
//! The close-by-role state machine is in `threaded` and `polled`.

use crate::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The lifecycle flags of one handle.
#[derive(Debug)]
pub struct Lifecycle {
    refs: AtomicU32,
    close_requested: AtomicBool,
    finalizing: AtomicBool,
    creator_pid: u32,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// Makes the flags with no ref. It records the pid of the creator for
    /// the forked-child close.
    #[must_use]
    pub fn new() -> Self {
        Self {
            refs: AtomicU32::new(0),
            close_requested: AtomicBool::new(false),
            finalizing: AtomicBool::new(false),
            creator_pid: std::process::id(),
        }
    }

    /// Takes a ref (`api_prolog`) and returns the new count.
    ///
    /// A close reads the count here, before it publishes the request, as
    /// `zookeeper_close` does (zookeeper.c:4007-4009). A later load can
    /// miss the refs of library threads that saw the request and left.
    pub fn prolog(&self) -> u32 {
        self.refs.fetch_add(1, Ordering::AcqRel).saturating_add(1)
    }

    /// Drops a ref (`api_epilog`). It returns true when this call dropped
    /// the last ref after a close request. The caller then runs the final
    /// close.
    pub fn epilog(&self) -> bool {
        let mut prev = self.refs.load(Ordering::Acquire);
        // A compare-exchange loop, because new toolchains deprecate
        // `fetch_update`. A count of 0 stays 0.
        while let Some(next) = prev.checked_sub(1) {
            match self
                .refs
                .compare_exchange_weak(prev, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(seen) => prev = seen,
            }
        }
        prev == 1 && self.close_requested.load(Ordering::Acquire)
    }

    /// Returns the number of refs.
    #[must_use]
    pub fn refs(&self) -> u32 {
        self.refs.load(Ordering::Acquire)
    }

    /// Records the close request. It returns true for the first request.
    /// A nested or second close is a no-op.
    pub fn request_close(&self) -> bool {
        !self.close_requested.swap(true, Ordering::AcqRel)
    }

    /// Returns true after a close request.
    #[must_use]
    pub fn close_requested(&self) -> bool {
        self.close_requested.load(Ordering::Acquire)
    }

    /// Returns the flag itself, for `StepCtx::abort`.
    #[must_use]
    pub fn close_flag(&self) -> &AtomicBool {
        &self.close_requested
    }

    /// Starts the final close. It returns true exactly once.
    pub fn begin_final(&self) -> bool {
        !self.finalizing.swap(true, Ordering::AcqRel)
    }

    /// Returns true when the caller runs in a forked child.
    #[must_use]
    pub fn is_forked_child(&self) -> bool {
        std::process::id() != self.creator_pid
    }
}
