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

//! The auto traits of the client handles and the futures. The checks
//! compile only when each type has its traits.

// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

use apache_zookeeper::{
    Client, ClientStats, CloseFuture, MultiError, ReadyFuture, ResponseFuture, WeakClient,
};

fn assert_traits<T: Send + Sync + Clone + Unpin + 'static>() {}

#[test]
fn client_is_send_sync_clone_unpin() {
    assert_traits::<Client>();
    assert_traits::<ClientStats>();
    assert_traits::<WeakClient>();
}

fn assert_send_sync_unpin<T: Send + Sync + Unpin + 'static>() {}
fn assert_send_unpin<T: Send + Unpin + 'static>() {}

#[test]
fn the_futures_have_the_traits_of_04_section_14() {
    assert_send_sync_unpin::<ResponseFuture<Vec<u8>>>();
    assert_send_sync_unpin::<ResponseFuture<(), MultiError>>();
    assert_send_sync_unpin::<ReadyFuture>();
    assert_send_unpin::<CloseFuture>();
}
