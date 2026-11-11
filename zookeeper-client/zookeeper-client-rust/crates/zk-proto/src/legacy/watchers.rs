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

//! Safe port of the legacy watcher tables (`zk_hashtable.c`).
//!
//! The C client keeps three tables of watchers: data, exist and child. Each
//! table maps a path to a list of watchers. A watcher is a `(fn, ctx)` pair in
//! C. Here it is any `W: Clone + Eq`, and equality takes the place of the pair
//! compare.
//!
//! The port keeps the C order rules:
//!
//! - A new watcher goes to the head of the list of its path, unless an equal
//!   watcher is already in that list.
//! - Collection for an event visits the tables in a fixed sequence, each list
//!   from head to tail. It keeps the first occurrence of each watcher. Delivery
//!   then runs in the reverse of the collection order.
//! - A node event removes the paths that it collects from. A session event
//!   copies all lists and changes nothing.

use super::hashtable::{LegacyHashTable, TARGET_C_CHAR_SIGNED};

/// The C event type for a created node (`CREATED_EVENT_DEF`).
pub const CREATED_EVENT: i32 = 1;
/// The C event type for a deleted node (`DELETED_EVENT_DEF`).
pub const DELETED_EVENT: i32 = 2;
/// The C event type for changed node data (`CHANGED_EVENT_DEF`).
pub const CHANGED_EVENT: i32 = 3;
/// The C event type for changed children (`CHILD_EVENT_DEF`).
pub const CHILD_EVENT: i32 = 4;
/// The C event type for a session state change (`SESSION_EVENT_DEF`).
pub const SESSION_EVENT: i32 = -1;

/// The C watch type for child watches (`ZWATCHTYPE_CHILD`).
pub const WATCH_TYPE_CHILD: i32 = 1;
/// The C watch type for data and exist watches (`ZWATCHTYPE_DATA`).
pub const WATCH_TYPE_DATA: i32 = 2;
/// The C watch type for all watches (`ZWATCHTYPE_ANY`).
pub const WATCH_TYPE_ANY: i32 = 3;

/// Keeps the first occurrence of each watcher and reverses the result.
///
/// This is the effect of the C delivery list. C builds that list with a
/// prepend after a search for an equal watcher (`add_to_list`). The input is
/// the collection sequence and the output is the delivery order.
pub fn fan_out<W: Eq, I: IntoIterator<Item = W>>(collected: I) -> Vec<W> {
    let mut kept: Vec<W> = Vec::new();
    for w in collected {
        if !kept.contains(&w) {
            kept.push(w);
        }
    }
    kept.reverse();
    kept
}

/// One watcher table of the C client: a path to a list of watchers.
///
/// Each list is kept head first. The table never holds an empty list.
#[derive(Debug, Clone)]
pub struct LegacyWatchTable<W> {
    table: LegacyHashTable<Vec<W>>,
}

impl<W: Clone + Eq> LegacyWatchTable<W> {
    /// Creates an empty table with the C size (53 buckets).
    pub fn new(c_char_signed: bool) -> Self {
        Self {
            table: LegacyHashTable::new(c_char_signed),
        }
    }

    /// Creates an empty table with the C `char` signedness of the target.
    pub fn new_native() -> Self {
        Self::new(TARGET_C_CHAR_SIGNED)
    }

    /// Gives access to the hash table under the watcher lists.
    pub fn table(&self) -> &LegacyHashTable<Vec<W>> {
        &self.table
    }

    /// Returns the number of paths in the table.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns true when the table has no paths.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Adds a watcher for a path, as `activateWatcher` does.
    ///
    /// The watcher goes to the head of the list. The function gives false and
    /// changes nothing when the list already holds an equal watcher.
    pub fn insert(&mut self, path: &[u8], watcher: W) -> bool {
        match self.table.get_mut(path) {
            Some(list) => {
                if list.contains(&watcher) {
                    false
                } else {
                    list.insert(0, watcher);
                    true
                }
            }
            None => {
                self.table.insert(path, vec![watcher]);
                true
            }
        }
    }

    /// Returns true when the list of a path holds the watcher
    /// (`containsWatcher`). A `None` watcher always matches, also for a path
    /// with no list, as in C.
    pub fn contains(&self, path: &[u8], watcher: Option<&W>) -> bool {
        let Some(w) = watcher else {
            return true;
        };
        self.table.get(path).is_some_and(|list| list.contains(w))
    }

    /// Removes a watcher from the list of a path (`removeWatcher`).
    ///
    /// A `None` watcher removes the path with its full list. When the list
    /// becomes empty, the path goes out of the table. The unlink follows
    /// `removeWatcherFromList`: first the first match after the head, then
    /// the head if it matches.
    pub fn remove(&mut self, path: &[u8], watcher: Option<&W>) {
        let Some(w) = watcher else {
            self.table.remove(path);
            return;
        };
        let Some(list) = self.table.get_mut(path) else {
            return;
        };
        if let Some(pos) = list.iter().skip(1).position(|x| x == w) {
            if let Some(index) = pos.checked_add(1) {
                if index < list.len() {
                    list.remove(index);
                }
            }
        }
        if list.first() == Some(w) {
            list.remove(0);
        }
        if list.is_empty() {
            self.table.remove(path);
        }
    }

    /// Removes a path and gives its watchers from head to tail
    /// (`hashtable_remove`, as `add_for_event` uses it).
    pub fn take(&mut self, path: &[u8]) -> Vec<W> {
        self.table.remove(path).unwrap_or_default()
    }

    /// Iterates over the watchers of a path from head to tail.
    pub fn watchers(&self, path: &[u8]) -> impl Iterator<Item = &W> + '_ {
        self.table.get(path).into_iter().flatten()
    }

    /// Iterates over the paths in C iteration order (`collect_keys`).
    pub fn keys(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.table.keys()
    }

    /// Iterates over the paths and their lists in C iteration order. Each list
    /// is head to tail.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[W])> + '_ {
        self.table.iter().map(|(k, v)| (k, v.as_slice()))
    }

    /// Removes all paths. The bucket count stays, as in C.
    pub fn clear(&mut self) {
        self.table.clear();
    }
}

/// The three watcher tables of a legacy C client handle.
#[derive(Debug, Clone)]
pub struct LegacyWatchers<W> {
    /// The data watchers (`active_node_watchers`).
    pub data: LegacyWatchTable<W>,
    /// The exist watchers (`active_exist_watchers`).
    pub exist: LegacyWatchTable<W>,
    /// The child watchers (`active_child_watchers`).
    pub child: LegacyWatchTable<W>,
}

impl<W: Clone + Eq> LegacyWatchers<W> {
    /// Creates three empty tables.
    pub fn new(c_char_signed: bool) -> Self {
        Self {
            data: LegacyWatchTable::new(c_char_signed),
            exist: LegacyWatchTable::new(c_char_signed),
            child: LegacyWatchTable::new(c_char_signed),
        }
    }

    /// Creates three empty tables with the C `char` signedness of the target.
    pub fn new_native() -> Self {
        Self::new(TARGET_C_CHAR_SIGNED)
    }

    /// Collects the watchers for a node event and gives them in delivery order
    /// (`collectWatchers`).
    ///
    /// The paths that the event uses go out of their tables. For CREATED and
    /// CHANGED the sequence is data, then exist. For CHILD it is child. For
    /// DELETED it is data, exist, then child. Other types match no watcher.
    pub fn collect_node_event(&mut self, event_type: i32, path: &[u8]) -> Vec<W> {
        let mut seq: Vec<W> = Vec::new();
        match event_type {
            CREATED_EVENT | CHANGED_EVENT => {
                seq.extend(self.data.take(path));
                seq.extend(self.exist.take(path));
            }
            CHILD_EVENT => {
                seq.extend(self.child.take(path));
            }
            DELETED_EVENT => {
                seq.extend(self.data.take(path));
                seq.extend(self.exist.take(path));
                seq.extend(self.child.take(path));
            }
            _ => {}
        }
        fan_out(seq)
    }

    /// Collects the watchers for a session event and gives them in delivery
    /// order (`collectWatchers` with `ZOO_SESSION_EVENT`).
    ///
    /// The sequence is the default watcher, then every list of the data,
    /// exist and child tables in table iteration order. The tables do not
    /// change. The default watcher is thus delivered last.
    pub fn collect_session_event(&self, default_watcher: &W) -> Vec<W> {
        let mut seq: Vec<&W> = vec![default_watcher];
        for table in [&self.data, &self.exist, &self.child] {
            for (_, list) in table.iter() {
                seq.extend(list.iter());
            }
        }
        fan_out(seq).into_iter().cloned().collect()
    }

    /// Collects the watchers for any event type, as `collectWatchers` does.
    pub fn collect(&mut self, event_type: i32, path: &[u8], default_watcher: &W) -> Vec<W> {
        if event_type == SESSION_EVENT {
            self.collect_session_event(default_watcher)
        } else {
            self.collect_node_event(event_type, path)
        }
    }

    /// Returns true when a path has the watcher for a watch type
    /// (`pathHasWatcher`). Unknown watch types give false.
    pub fn has_watcher(&self, path: &[u8], watch_type: i32, watcher: Option<&W>) -> bool {
        match watch_type {
            WATCH_TYPE_CHILD => self.child.contains(path, watcher),
            WATCH_TYPE_DATA => {
                self.data.contains(path, watcher) || self.exist.contains(path, watcher)
            }
            WATCH_TYPE_ANY => {
                self.child.contains(path, watcher)
                    || self.data.contains(path, watcher)
                    || self.exist.contains(path, watcher)
            }
            _ => false,
        }
    }

    /// Removes a watcher from the tables of a watch type (`removeWatchers`).
    /// Unknown watch types change nothing.
    pub fn remove_watchers(&mut self, path: &[u8], watch_type: i32, watcher: Option<&W>) {
        match watch_type {
            WATCH_TYPE_CHILD => self.child.remove(path, watcher),
            WATCH_TYPE_DATA => {
                self.data.remove(path, watcher);
                self.exist.remove(path, watcher);
            }
            WATCH_TYPE_ANY => {
                self.child.remove(path, watcher);
                self.data.remove(path, watcher);
                self.exist.remove(path, watcher);
            }
            _ => {}
        }
    }
}
