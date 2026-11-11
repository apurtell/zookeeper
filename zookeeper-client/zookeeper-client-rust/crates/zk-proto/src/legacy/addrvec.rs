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

//! Safe port of the legacy address vector (`addrvec.c`).
//!
//! An address vector is a list of server addresses with a cursor. The cursor
//! goes round the list, and the shuffle gives the same permutation as C for the
//! same `random()` values.
//!
//! The C comparison of two addresses uses the address family and the IP only.
//! The port is not part of it. The Rust core fixes this defect and compares the
//! IP and the port. Both rules are available here through [`AddrEq`].

use std::net::SocketAddr;

/// A list item that carries a socket address.
///
/// The host list of a driver can carry more data with each address, for
/// example the host token of the connect string. Only the address takes part
/// in the comparisons.
pub trait EndpointAddr {
    /// Returns the socket address of the item.
    fn socket_addr(&self) -> SocketAddr;
}

impl EndpointAddr for SocketAddr {
    fn socket_addr(&self) -> SocketAddr {
        *self
    }
}

/// The rule that tells if two addresses are the same server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddrEq {
    /// The C rule (`addrvec_contains`): same family and same IP. The port and
    /// the IPv6 scope are not compared.
    IpOnly,
    /// The Rust rule: same IP and same port. The IPv6 scope and flow
    /// information are not compared.
    IpAndPort,
}

impl AddrEq {
    /// Returns true when the two addresses are the same server under this
    /// rule.
    pub fn same(self, a: &SocketAddr, b: &SocketAddr) -> bool {
        match self {
            AddrEq::IpOnly => a.ip() == b.ip(),
            AddrEq::IpAndPort => a.ip() == b.ip() && a.port() == b.port(),
        }
    }
}

/// The rule that tells if two address lists are the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListEq {
    /// The C rule (`addrvec_eq`): the same count, and each old address is in
    /// the new list. The rule is one-way, so `{A, A}` equals `{A, B}`.
    LegacyOneWay,
    /// The Rust rule: the same count, and each address of each list is in the
    /// other list.
    Bidirectional,
}

/// Returns true when the list holds an address equal to `addr`
/// (`addrvec_contains`).
pub fn contains<T: EndpointAddr>(list: &[T], addr: &SocketAddr, eq: AddrEq) -> bool {
    list.iter().any(|x| eq.same(&x.socket_addr(), addr))
}

/// The C list compare (`addrvec_eq`): the same count, and each address of
/// `old` is in `new`. The order of the arguments matters.
pub fn legacy_eq<A: EndpointAddr, B: EndpointAddr>(old: &[A], new: &[B], eq: AddrEq) -> bool {
    old.len() == new.len() && old.iter().all(|a| contains(new, &a.socket_addr(), eq))
}

/// The Rust list compare: the same count, and containment in both directions.
pub fn bidirectional_eq<A: EndpointAddr, B: EndpointAddr>(a: &[A], b: &[B], eq: AddrEq) -> bool {
    legacy_eq(a, b, eq) && legacy_eq(b, a, eq)
}

/// Compares two lists with the given list and address rules.
pub fn lists_equal<A: EndpointAddr, B: EndpointAddr>(
    old: &[A],
    new: &[B],
    list_eq: ListEq,
    addr_eq: AddrEq,
) -> bool {
    match list_eq {
        ListEq::LegacyOneWay => legacy_eq(old, new, addr_eq),
        ListEq::Bidirectional => bidirectional_eq(old, new, addr_eq),
    }
}

/// Shuffles a list as `addrvec_shuffle` does.
///
/// For each `i` from the last index down to 1, the function draws a value
/// with `random`, takes it modulo `i + 1`, and swaps the two items when the
/// index differs. The function `random` stands for C `random()`, whose values
/// are never negative. A negative value is reduced with a Euclidean modulo, so
/// no input can give an index out of range.
pub fn shuffle<T, F: FnMut() -> i64>(list: &mut [T], mut random: F) {
    let mut i = list.len().saturating_sub(1);
    while i > 0 {
        let modulus = i64::try_from(i).map_or(i64::MAX, |x| x.saturating_add(1));
        let j = usize::try_from(random().rem_euclid(modulus)).unwrap_or(0);
        if i != j && j < list.len() {
            list.swap(i, j);
        }
        i = i.saturating_sub(1);
    }
}

/// An address list with a cursor (`addrvec_t`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrVec<T> {
    data: Vec<T>,
    next: usize,
}

impl<T> Default for AddrVec<T> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            next: 0,
        }
    }
}

impl<T> From<Vec<T>> for AddrVec<T> {
    fn from(data: Vec<T>) -> Self {
        Self { data, next: 0 }
    }
}

impl<T> AddrVec<T> {
    /// Creates an empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the items of the list.
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Returns the number of items.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true when the list is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the cursor: the index of the item that comes next.
    pub fn cursor(&self) -> usize {
        self.next
    }

    /// Adds an item at the end (`addrvec_append`). The cursor stays.
    pub fn push(&mut self, item: T) {
        self.data.push(item);
    }

    /// Removes all items and resets the cursor (`addrvec_free`).
    pub fn clear(&mut self) {
        self.data.clear();
        self.next = 0;
    }

    /// Sets the cursor to the start of the list.
    pub fn reset(&mut self) {
        self.next = 0;
    }

    /// Returns true when the cursor has an item to give (`addrvec_hasnext`).
    pub fn has_next(&self) -> bool {
        !self.data.is_empty() && self.next < self.data.len()
    }

    /// Returns true when the cursor is past the last item of a list that is
    /// not empty (`addrvec_atend`).
    pub fn at_end(&self) -> bool {
        !self.data.is_empty() && self.next >= self.data.len()
    }

    /// Gives the item at the cursor and moves the cursor (`addrvec_next`).
    ///
    /// At the end of the list the cursor first goes back to the start. An
    /// empty list gives `None`, where C gives a zeroed address.
    pub fn next_item(&mut self) -> Option<&T> {
        if self.at_end() {
            self.next = 0;
        }
        if !self.has_next() {
            return None;
        }
        let index = self.next;
        self.next = self.next.saturating_add(1);
        self.data.get(index)
    }

    /// Gives what [`AddrVec::next_item`] would give, without a move of the
    /// cursor (`addrvec_peek`).
    pub fn peek(&self) -> Option<&T> {
        if self.data.is_empty() {
            return None;
        }
        let index = if self.at_end() { 0 } else { self.next };
        self.data.get(index)
    }

    /// Shuffles the items as `addrvec_shuffle` does. The cursor stays.
    pub fn shuffle<F: FnMut() -> i64>(&mut self, random: F) {
        shuffle(&mut self.data, random);
    }

    /// Takes the items out of the list.
    pub fn into_vec(self) -> Vec<T> {
        self.data
    }
}

impl<T: EndpointAddr> AddrVec<T> {
    /// Returns true when the list holds an address equal to `addr`.
    pub fn contains(&self, addr: &SocketAddr, eq: AddrEq) -> bool {
        contains(&self.data, addr, eq)
    }
}
