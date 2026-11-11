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

//! The output queue of one connection.
//!
//! The model and the rules put items on the queue under the state lock.
//! The connection thread takes them off in order and writes them. A pause
//! item holds back every later item, so the order on the wire is the
//! order of the queue.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// One item of the output queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Out {
    /// Bytes to write, cut into writes of the given sizes.
    Bytes {
        /// The bytes.
        data: Vec<u8>,
        /// The write sizes. Their sum is the data length.
        chunks: Vec<usize>,
    },
    /// Wait this long before the next item.
    Pause(Duration),
    /// Write nothing more and close the connection.
    Close,
    /// Write nothing more and process no more input. The socket stays open.
    Stall,
}

/// The link between the shared state and one connection thread.
#[derive(Debug, Default)]
pub(crate) struct ConnLink {
    queue: Mutex<VecDeque<Out>>,
    kill: AtomicBool,
}

impl ConnLink {
    /// Appends an item.
    pub(crate) fn push(&self, item: Out) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(item);
    }

    /// Removes the first item.
    pub(crate) fn pop(&self) -> Option<Out> {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    /// Tells the thread to close the socket at once, without a flush.
    pub(crate) fn kill(&self) {
        self.kill.store(true, Ordering::SeqCst);
    }

    /// Returns true after [`ConnLink::kill`].
    pub(crate) fn killed(&self) -> bool {
        self.kill.load(Ordering::SeqCst)
    }
}

/// Returns the write sizes for `len` bytes cut into pieces of `size`.
pub(crate) fn fixed_chunks(len: usize, size: usize) -> Vec<usize> {
    if size == 0 || len <= size {
        return vec![len];
    }
    let mut out = Vec::new();
    let mut left = len;
    while left > 0 {
        let n = left.min(size);
        out.push(n);
        left = left.saturating_sub(n);
    }
    out
}
