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

//! Safe port of the legacy chained hash table (`hashtable.c`, `hashtable_itr.c`).
//!
//! The C client keeps its watchers in this table. Applications can observe the
//! iteration order of the table, so this port gives the same order as C for the
//! same history of inserts and removals. The port keeps these C rules:
//!
//! - The key hash is DJB2 over C `unsigned int`. Each byte is read as a C `char`,
//!   so the signedness of `char` on the target changes the hash.
//! - A mixer from the Java 1.4 hash table runs on the key hash.
//! - The bucket index is the mixed hash modulo the bucket count.
//! - The bucket counts come from a fixed table of primes.
//! - The load limit is `ceil(size * 0.65f)`, with the product in `float`.
//! - An insert counts the new entry first. If the count is then above the
//!   load limit, the table grows before the insert.
//! - A new entry goes to the head of its bucket chain.
//! - Growth moves the chains of the old buckets in bucket order, from head to
//!   tail, to the head of the new chains. This reverses the relative order.
//! - Iteration visits the buckets in order and each chain from head to tail.
//!
//! The C table stores C strings as keys. This port stores bytes and uses only
//! the bytes before the first NUL, as the C string functions do.

use std::collections::BTreeMap;

/// The bucket counts of the C table (`hashtable.c`, `primes`).
pub const PRIMES: [u32; 26] = [
    53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, 98317, 196613, 393241, 786433,
    1572869, 3145739, 6291469, 12582917, 25165843, 50331653, 100663319, 201326611, 402653189,
    805306457, 1610612741,
];

/// The maximum load factor of the C table, as a C `float`.
pub const MAX_LOAD_FACTOR: f32 = 0.65;

/// The minimum size that the C client gives to `create_hashtable` for each
/// watcher table (`zk_hashtable.c`, `create_zk_hashtable`).
pub const ZK_TABLE_MIN_SIZE: u32 = 32;

/// The largest minimum size that `create_hashtable` accepts.
pub const MAX_MIN_SIZE: u32 = 1 << 30;

/// True when C `char` is signed on the compile target.
///
/// The value follows the C ABI of the target: for example, `char` is signed
/// on x86-64 and on Apple aarch64, and unsigned on aarch64 Linux. A table
/// with this value gives the bucket order of the C client on the same
/// target. Use it as the default for the drop-in libraries.
pub const TARGET_C_CHAR_SIGNED: bool = std::ffi::c_char::MIN != 0;

/// Returns the bytes of a C string: the bytes before the first NUL.
pub fn c_str(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(end) => bytes.get(..end).unwrap_or(bytes),
        None => bytes,
    }
}

/// Computes `string_hash_djb2` of `zk_hashtable.c` for a key.
///
/// The C function adds each `char` to an `unsigned int` accumulator. When
/// `c_char_signed` is true, a byte at or above 0x80 is sign-extended, as on
/// targets where `char` is signed. The hash stops at the first NUL.
pub fn djb2(key: &[u8], c_char_signed: bool) -> u32 {
    let mut h: u32 = 5381;
    for &b in c_str(key) {
        let c: i32 = if c_char_signed {
            i32::from(i8::from_ne_bytes([b]))
        } else {
            i32::from(b)
        };
        // The int converts to unsigned int with modulo arithmetic, as in C.
        let c = u32::from_ne_bytes(c.to_ne_bytes());
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(c);
    }
    h
}

/// Applies the hash mixer of `hashtable.c` (`hash`) to a key hash.
pub fn mix(h: u32) -> u32 {
    let mut i = h;
    i = i.wrapping_add(!i.wrapping_shl(9));
    i ^= i.wrapping_shr(14) | i.wrapping_shl(18);
    i = i.wrapping_add(i.wrapping_shl(4));
    i ^= i.wrapping_shr(10) | i.wrapping_shl(22);
    i
}

/// Computes the load limit for a bucket count, as `hashtable.c` does.
///
/// C multiplies the size by the `float` load factor in `float` precision and
/// then rounds up with `ceil`. The conversion to `float` rounds to nearest, as
/// the `as` conversion does.
pub fn load_limit_for(size: u32) -> u32 {
    #[allow(clippy::as_conversions, clippy::cast_precision_loss)]
    let product = (size as f32) * MAX_LOAD_FACTOR;
    let limit = f64::from(product).ceil();
    // The value is in range for all sizes in the prime table.
    #[allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let limit = limit as u32;
    limit
}

/// Returns the first prime index whose prime is above `min_size`, as
/// `create_hashtable` selects it.
fn initial_prime_index(min_size: u32) -> usize {
    PRIMES.iter().position(|&p| p > min_size).unwrap_or(0)
}

#[derive(Debug, Clone)]
struct Entry<V> {
    key: Vec<u8>,
    hash: u32,
    value: V,
}

/// A safe port of the legacy C hash table, keyed by byte strings.
///
/// The table allows duplicate keys, as C does. The C client never inserts a
/// duplicate key, because it searches before each insert.
///
/// The buckets are kept in a sparse ordered map. Memory use is thus in
/// proportion to the number of entries, not to the bucket count. Each chain is
/// kept head first.
#[derive(Debug, Clone)]
pub struct LegacyHashTable<V> {
    buckets: BTreeMap<u32, Vec<Entry<V>>>,
    table_length: u32,
    entry_count: u32,
    load_limit: u32,
    prime_index: usize,
    c_char_signed: bool,
}

impl<V> LegacyHashTable<V> {
    /// Creates a table as `create_hashtable(min_size, ...)` does.
    ///
    /// The bucket count is the first prime above `min_size`. The function gives
    /// `None` when `min_size` is above 2^30, where C gives `NULL`.
    pub fn with_min_size(min_size: u32, c_char_signed: bool) -> Option<Self> {
        if min_size > MAX_MIN_SIZE {
            return None;
        }
        let prime_index = initial_prime_index(min_size);
        let table_length = PRIMES.get(prime_index).copied().unwrap_or(53);
        Some(Self {
            buckets: BTreeMap::new(),
            table_length,
            entry_count: 0,
            load_limit: load_limit_for(table_length),
            prime_index,
            c_char_signed,
        })
    }

    /// Creates a table with the size of a C client watcher table (53 buckets).
    pub fn new(c_char_signed: bool) -> Self {
        let prime_index = initial_prime_index(ZK_TABLE_MIN_SIZE);
        let table_length = PRIMES.get(prime_index).copied().unwrap_or(53);
        Self {
            buckets: BTreeMap::new(),
            table_length,
            entry_count: 0,
            load_limit: load_limit_for(table_length),
            prime_index,
            c_char_signed,
        }
    }

    /// Creates a C client watcher table with the C `char` signedness of the
    /// target ([`TARGET_C_CHAR_SIGNED`]).
    pub fn new_native() -> Self {
        Self::new(TARGET_C_CHAR_SIGNED)
    }

    /// Returns true when the table reads key bytes as signed C `char` values.
    pub fn c_char_signed(&self) -> bool {
        self.c_char_signed
    }

    /// Returns the number of entries (`hashtable_count`).
    pub fn len(&self) -> usize {
        usize::try_from(self.entry_count).unwrap_or(usize::MAX)
    }

    /// Returns true when the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Returns the current bucket count (`tablelength`).
    pub fn bucket_count(&self) -> u32 {
        self.table_length
    }

    /// Returns the current load limit (`loadlimit`).
    pub fn load_limit(&self) -> u32 {
        self.load_limit
    }

    /// Returns the mixed hash of a key, as `hash()` in `hashtable.c` gives it.
    pub fn hash_of(&self, key: &[u8]) -> u32 {
        mix(djb2(key, self.c_char_signed))
    }

    /// Returns the bucket index of a key for the current bucket count.
    pub fn bucket_of(&self, key: &[u8]) -> u32 {
        index_for(self.table_length, self.hash_of(key))
    }

    /// Grows the table to the next prime, as `hashtable_expand` does.
    ///
    /// The function does nothing when the table already has the largest prime.
    fn expand(&mut self) {
        let Some(next_index) = self.prime_index.checked_add(1) else {
            return;
        };
        let Some(&new_size) = PRIMES.get(next_index) else {
            return;
        };
        self.prime_index = next_index;
        let old = std::mem::take(&mut self.buckets);
        // C walks the old buckets in order and moves each chain from its head.
        // Each moved entry goes to the head of its new chain.
        for chain in old.into_values() {
            for entry in chain {
                let index = index_for(new_size, entry.hash);
                self.buckets.entry(index).or_default().insert(0, entry);
            }
        }
        self.table_length = new_size;
        self.load_limit = load_limit_for(new_size);
    }

    /// Inserts an entry, as `hashtable_insert` does.
    ///
    /// The table grows first when the new count is above the load limit. The
    /// entry then goes to the head of its chain. A duplicate key is allowed.
    pub fn insert(&mut self, key: &[u8], value: V) {
        self.entry_count = self.entry_count.saturating_add(1);
        if self.entry_count > self.load_limit {
            self.expand();
        }
        let key = c_str(key);
        let hash = self.hash_of(key);
        let index = index_for(self.table_length, hash);
        self.buckets.entry(index).or_default().insert(
            0,
            Entry {
                key: key.to_vec(),
                hash,
                value,
            },
        );
    }

    /// Finds the position of the first entry for a key in its chain.
    fn locate(&self, key: &[u8]) -> Option<(u32, usize)> {
        let key = c_str(key);
        let hash = self.hash_of(key);
        let index = index_for(self.table_length, hash);
        let chain = self.buckets.get(&index)?;
        let pos = chain
            .iter()
            .position(|e| e.hash == hash && e.key.as_slice() == key)?;
        Some((index, pos))
    }

    /// Returns the value of the first entry for a key (`hashtable_search`).
    pub fn get(&self, key: &[u8]) -> Option<&V> {
        let (index, pos) = self.locate(key)?;
        self.buckets
            .get(&index)
            .and_then(|c| c.get(pos))
            .map(|e| &e.value)
    }

    /// Returns the value of the first entry for a key, for change.
    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        let (index, pos) = self.locate(key)?;
        self.buckets
            .get_mut(&index)
            .and_then(|c| c.get_mut(pos))
            .map(|e| &mut e.value)
    }

    /// Returns true when the table has an entry for a key.
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.locate(key).is_some()
    }

    /// Removes the first entry for a key and returns its value
    /// (`hashtable_remove`). The table does not shrink.
    pub fn remove(&mut self, key: &[u8]) -> Option<V> {
        let (index, pos) = self.locate(key)?;
        let chain = self.buckets.get_mut(&index)?;
        if pos >= chain.len() {
            return None;
        }
        let entry = chain.remove(pos);
        if chain.is_empty() {
            self.buckets.remove(&index);
        }
        self.entry_count = self.entry_count.saturating_sub(1);
        Some(entry.value)
    }

    /// Removes all entries. The bucket count stays, as in C, where the table
    /// is emptied through its iterator and never shrinks.
    pub fn clear(&mut self) {
        self.buckets.clear();
        self.entry_count = 0;
    }

    /// Iterates over the entries in C iteration order: buckets in order, and
    /// each chain from head to tail.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &V)> + '_ {
        self.buckets
            .values()
            .flat_map(|chain| chain.iter().map(|e| (e.key.as_slice(), &e.value)))
    }

    /// Iterates over the keys in C iteration order.
    pub fn keys(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.iter().map(|(k, _)| k)
    }

    /// Iterates over the entries in C iteration order, for change.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&[u8], &mut V)> + '_ {
        self.buckets
            .values_mut()
            .flat_map(|chain| chain.iter_mut().map(|e| (e.key.as_slice(), &mut e.value)))
    }
}

/// Computes `indexFor` of `hashtable_private.h`: the hash modulo the length.
fn index_for(table_length: u32, hash: u32) -> u32 {
    hash.checked_rem(table_length).unwrap_or(0)
}
