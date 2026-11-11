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

//! `StdSpawner`: the only module that calls `std::thread::spawn`. Only the
//! native API uses it, so the drop-in starts no Rust threads. It exists
//! with the `std-thread` feature.

use crate::native::{Spawn, ThreadBody};

/// Starts detached `std::thread`s with a name and an optional stack size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StdSpawner {
    /// The stack size in bytes, or `None` for the std default.
    pub stack_size: Option<usize>,
}

impl StdSpawner {
    /// Makes a spawner with the std default stack size.
    #[must_use]
    pub const fn new() -> Self {
        Self { stack_size: None }
    }

    /// Starts a detached thread with a name that the caller owns.
    ///
    /// zk-client uses it for the thread name of `ThreadOptions`. The
    /// name can come from the user, so it is not `'static`.
    ///
    /// # Errors
    ///
    /// Returns the spawn error of `std::thread::Builder`.
    pub fn spawn_owned(&self, name: String, body: ThreadBody) -> std::io::Result<()> {
        let builder = std::thread::Builder::new().name(name);
        let builder = match self.stack_size {
            Some(size) => builder.stack_size(size),
            None => builder,
        };
        builder.spawn(body).map(drop)
    }
}

impl Spawn for StdSpawner {
    /// Starts the thread through `std::thread::Builder` and drops the
    /// join handle, so the thread is detached.
    fn spawn(&self, name: &'static str, body: ThreadBody) -> std::io::Result<()> {
        self.spawn_owned(name.to_owned(), body)
    }
}
