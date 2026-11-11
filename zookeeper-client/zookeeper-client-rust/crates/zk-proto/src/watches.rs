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

//! The watcher registry.
//!
//! The module owns [`Watches`]. It arms watches from replies, collects
//! watchers for events, removes them and builds the SetWatches packets.
//! `Compat::watch_table` selects the table type.
//!
//! Every table is keyed by the server path, with the chroot. The C client
//! does the same, so SetWatches can send the keys as they are. The chroot
//! is stripped only from the paths that go to the application.

use std::collections::{BTreeMap, HashMap};

use zk_jute::proto::{SetWatches, SetWatches2, WatcherEvent};
use zk_jute::{JString, JVec, Record, opcode, rc, xid};

use crate::action::RemoveHint;
use crate::compat::WatchTable;
use crate::connection::Connection;
use crate::hooks::Tokens;
use crate::legacy::chroot::is_config_node;
use crate::legacy::watchers::{
    CHANGED_EVENT, CHILD_EVENT, CREATED_EVENT, DELETED_EVENT, LegacyWatchTable, LegacyWatchers,
    SESSION_EVENT, fan_out,
};
use crate::log::{LogArg, LogRecord, LogSite, str_arg};
use crate::output::{Output, TerminateReason, WatchedEvent};
use crate::recv::Flow;
use crate::requests::{FrameKind, OutFrame, Unwatch, WatchKind, WatchReg, completion};
use crate::state::Cause;
use crate::time::Millis;

/// The watch type for child watches (`ZWATCHTYPE_CHILD`).
const WTYPE_CHILD: i32 = 1;
/// The watch type for data and exist watches (`ZWATCHTYPE_DATA`).
const WTYPE_DATA: i32 = 2;
/// The watch type for every watch (`ZWATCHTYPE_ANY`).
const WTYPE_ANY: i32 = 3;
/// The watch type for persistent watches (native only).
const WTYPE_PERSISTENT: i32 = 4;
/// The watch type for persistent recursive watches (native only).
const WTYPE_RECURSIVE: i32 = 5;

/// Every table kind, in the order of the SetWatches lists.
const ALL_KINDS: [WatchKind; 5] = [
    WatchKind::Data,
    WatchKind::Exist,
    WatchKind::Child,
    WatchKind::Persistent,
    WatchKind::PersistentRecursive,
];

/// Returns the wire watch type of the server watch class of a table.
///
/// The data and exist tables share one server class, as on the server.
const fn class_wtype(kind: WatchKind) -> i32 {
    match kind {
        WatchKind::Data | WatchKind::Exist => WTYPE_DATA,
        WatchKind::Child => WTYPE_CHILD,
        WatchKind::Persistent => WTYPE_PERSISTENT,
        WatchKind::PersistentRecursive => WTYPE_RECURSIVE,
    }
}

/// Returns the ordered tables that a watch type selects, in the removal
/// order of the Java client. An invalid type selects no table.
const fn ordered_kinds(wtype: i32) -> &'static [WatchKind] {
    match wtype {
        WTYPE_CHILD => &[WatchKind::Child],
        WTYPE_DATA => &[WatchKind::Data, WatchKind::Exist],
        WTYPE_ANY => &[
            WatchKind::Child,
            WatchKind::Data,
            WatchKind::Exist,
            WatchKind::Persistent,
            WatchKind::PersistentRecursive,
        ],
        WTYPE_PERSISTENT => &[WatchKind::Persistent],
        WTYPE_RECURSIVE => &[WatchKind::PersistentRecursive],
        _ => &[],
    }
}

/// Returns the legacy tables that a watch type selects, in the order of
/// `removeWatchers`. The legacy tables have no persistent kinds.
const fn legacy_kinds(wtype: i32) -> &'static [WatchKind] {
    match wtype {
        WTYPE_CHILD => &[WatchKind::Child],
        WTYPE_DATA => &[WatchKind::Data, WatchKind::Exist],
        WTYPE_ANY => &[WatchKind::Child, WatchKind::Data, WatchKind::Exist],
        _ => &[],
    }
}

/// Returns the table that a reply arms.
///
/// `Exist` is the registration of an `exists` request. It arms the data
/// table on `ZOK` and the exist table on `ZNONODE`. `Data` is the
/// registration of a `getData` request and arms only on `ZOK`.
const fn armed_table(kind: WatchKind, rc_value: i32) -> Option<WatchKind> {
    match kind {
        WatchKind::Exist if rc_value == rc::ZOK => Some(WatchKind::Data),
        WatchKind::Exist if rc_value == rc::ZNONODE => Some(WatchKind::Exist),
        WatchKind::Exist => None,
        _ if rc_value == rc::ZOK => Some(kind),
        _ => None,
    }
}

/// Keeps the first occurrence of each watcher and keeps the order.
fn dedup_keep_first<W: Eq>(seq: Vec<W>) -> Vec<W> {
    let mut kept: Vec<W> = Vec::with_capacity(seq.len());
    for w in seq {
        if !kept.contains(&w) {
            kept.push(w);
        }
    }
    kept
}

/// Returns a path and each of its ancestors up to `/`, nearest first.
///
/// This is the order of the Java `PathParentIterator`. A path that does
/// not start with `/` gives only itself.
fn path_lineage(path: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = vec![path];
    if path.first() != Some(&b'/') {
        return out;
    }
    let mut cur = path;
    while cur.len() > 1 {
        cur = match cur.iter().rposition(|&b| b == b'/') {
            Some(0) | None => b"/",
            Some(i) => cur.get(..i).unwrap_or(b"/"),
        };
        out.push(cur);
    }
    out
}

/// Returns the `watcherEvent2String` text of an event type.
const fn event_name(event_type: i32) -> &'static [u8] {
    match event_type {
        0 => b"ZOO_ERROR_EVENT",
        CREATED_EVENT => b"ZOO_CREATED_EVENT",
        DELETED_EVENT => b"ZOO_DELETED_EVENT",
        CHANGED_EVENT => b"ZOO_CHANGED_EVENT",
        CHILD_EVENT => b"ZOO_CHILD_EVENT",
        SESSION_EVENT => b"ZOO_SESSION_EVENT",
        -2 => b"ZOO_NOTWATCHING_EVENT",
        _ => b"INVALID_EVENT",
    }
}

/// A map from a path to its watcher list that iterates in insertion
/// order (spec "Watcher Table Implementation").
///
/// Each new path gets the next sequence number. The ordered map holds the
/// entries by that number, and the index finds the number of a path. A
/// path that leaves the map and comes back goes to the end.
pub(crate) struct PathMap<W> {
    /// The entries by sequence number.
    entries: BTreeMap<u64, (Vec<u8>, Vec<W>)>,
    /// The sequence number of each path.
    index: HashMap<Vec<u8>, u64>,
    /// The sequence number of the next new path.
    next_seq: u64,
}

impl<W> PathMap<W> {
    /// Makes an empty map.
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            index: HashMap::new(),
            next_seq: 0,
        }
    }

    /// Returns the list of a path.
    pub(crate) fn get(&self, path: &[u8]) -> Option<&Vec<W>> {
        let seq = self.index.get(path)?;
        self.entries.get(seq).map(|(_, list)| list)
    }

    /// Returns the list of a path for change.
    pub(crate) fn get_mut(&mut self, path: &[u8]) -> Option<&mut Vec<W>> {
        let seq = self.index.get(path)?;
        self.entries.get_mut(seq).map(|(_, list)| list)
    }

    /// Returns the list of a path. A new path gets an empty list at the
    /// end of the order.
    pub(crate) fn entry_or_default(&mut self, path: &[u8]) -> &mut Vec<W> {
        let seq = match self.index.get(path) {
            Some(seq) => *seq,
            None => {
                let seq = self.take_seq();
                self.index.insert(path.to_vec(), seq);
                seq
            }
        };
        &mut self
            .entries
            .entry(seq)
            .or_insert_with(|| (path.to_vec(), Vec::new()))
            .1
    }

    /// Removes a path and gives its list.
    pub(crate) fn remove(&mut self, path: &[u8]) -> Option<Vec<W>> {
        let seq = self.index.remove(path)?;
        self.entries.remove(&seq).map(|(_, list)| list)
    }

    /// Iterates the paths and their lists in insertion order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Vec<W>)> {
        self.entries.values().map(|(path, list)| (path, list))
    }

    /// Iterates the paths in insertion order.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.entries.values().map(|(path, _)| path)
    }

    /// Iterates the lists in insertion order.
    pub(crate) fn values(&self) -> impl Iterator<Item = &Vec<W>> {
        self.entries.values().map(|(_, list)| list)
    }

    /// Gives the next sequence number. When the counter is at its end,
    /// the entries get new numbers from 0 in the same order.
    fn take_seq(&mut self) -> u64 {
        if self.next_seq == u64::MAX {
            let old = core::mem::take(&mut self.entries);
            self.index.clear();
            self.next_seq = 0;
            for (path, list) in old.into_values() {
                let seq = self.next_seq;
                self.next_seq = self.next_seq.saturating_add(1);
                self.index.insert(path.clone(), seq);
                self.entries.insert(seq, (path, list));
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }
}

/// The path-keyed tables of the native profile. Each table iterates its
/// paths in insertion order, and each list keeps the registration order.
pub(crate) struct OrderedWatches<W> {
    /// The data watches.
    pub(crate) data: PathMap<W>,
    /// The exist watches.
    pub(crate) exist: PathMap<W>,
    /// The child watches.
    pub(crate) child: PathMap<W>,
    /// The persistent watches.
    pub(crate) persistent: PathMap<W>,
    /// The persistent recursive watches.
    pub(crate) persistent_recursive: PathMap<W>,
}

impl<W> OrderedWatches<W> {
    /// Makes empty tables.
    pub(crate) fn new() -> Self {
        Self {
            data: PathMap::new(),
            exist: PathMap::new(),
            child: PathMap::new(),
            persistent: PathMap::new(),
            persistent_recursive: PathMap::new(),
        }
    }
}

impl<W: Clone + Eq> OrderedWatches<W> {
    /// Returns the table of a kind.
    fn table(&self, kind: WatchKind) -> &PathMap<W> {
        match kind {
            WatchKind::Data => &self.data,
            WatchKind::Exist => &self.exist,
            WatchKind::Child => &self.child,
            WatchKind::Persistent => &self.persistent,
            WatchKind::PersistentRecursive => &self.persistent_recursive,
        }
    }

    /// Returns the table of a kind, for change.
    fn table_mut(&mut self, kind: WatchKind) -> &mut PathMap<W> {
        match kind {
            WatchKind::Data => &mut self.data,
            WatchKind::Exist => &mut self.exist,
            WatchKind::Child => &mut self.child,
            WatchKind::Persistent => &mut self.persistent,
            WatchKind::PersistentRecursive => &mut self.persistent_recursive,
        }
    }

    /// Appends a watcher to the list of a path. An equal watcher in the
    /// list stops the insert, and the function then gives false.
    fn insert(&mut self, kind: WatchKind, path: &[u8], w: W) -> bool {
        let list = self.table_mut(kind).entry_or_default(path);
        if list.contains(&w) {
            false
        } else {
            list.push(w);
            true
        }
    }

    /// Returns true when the list of a path holds the watcher. `None`
    /// matches when the path has any watcher, as in the Java client.
    fn contains(&self, kind: WatchKind, path: &[u8], w: Option<&W>) -> bool {
        self.table(kind).get(path).is_some_and(|list| match w {
            None => !list.is_empty(),
            Some(w) => list.contains(w),
        })
    }

    /// Removes a watcher, or every watcher with `None`, from the list of
    /// a path, and gives the removed watchers. An empty list leaves the
    /// table.
    fn remove(&mut self, kind: WatchKind, path: &[u8], w: Option<&W>) -> Vec<W> {
        let table = self.table_mut(kind);
        let Some(w) = w else {
            return table.remove(path).unwrap_or_default();
        };
        let Some(list) = table.get_mut(path) else {
            return Vec::new();
        };
        let mut removed = Vec::new();
        list.retain(|x| {
            if x == w {
                removed.push(x.clone());
                false
            } else {
                true
            }
        });
        if list.is_empty() {
            table.remove(path);
        }
        removed
    }

    /// Removes a path and gives its watchers in registration order.
    fn take(&mut self, kind: WatchKind, path: &[u8]) -> Vec<W> {
        self.table_mut(kind).remove(path).unwrap_or_default()
    }

    /// Gives a copy of the watchers of a path in registration order.
    fn copy(&self, kind: WatchKind, path: &[u8]) -> Vec<W> {
        self.table(kind).get(path).cloned().unwrap_or_default()
    }

    /// Collects the watchers of a node event under the `Ordered` table.
    ///
    /// The one-shot tables come first in the delivery-column order and
    /// leave the table. The persistent table follows for every node event
    /// type. The recursive table follows for created, changed and deleted
    /// events, for the path and each ancestor. Persistent entries stay.
    fn collect_node_event(&mut self, event_type: i32, path: &[u8]) -> Vec<W> {
        let mut seq: Vec<W> = Vec::new();
        match event_type {
            CREATED_EVENT | CHANGED_EVENT => {
                seq.extend(self.take(WatchKind::Exist, path));
                seq.extend(self.take(WatchKind::Data, path));
            }
            CHILD_EVENT => {
                seq.extend(self.take(WatchKind::Child, path));
            }
            DELETED_EVENT => {
                seq.extend(self.take(WatchKind::Child, path));
                seq.extend(self.take(WatchKind::Exist, path));
                seq.extend(self.take(WatchKind::Data, path));
            }
            _ => return Vec::new(),
        }
        seq.extend(self.copy(WatchKind::Persistent, path));
        if event_type != CHILD_EVENT {
            for p in path_lineage(path) {
                seq.extend(self.copy(WatchKind::PersistentRecursive, p));
            }
        }
        dedup_keep_first(seq)
    }
}

/// The table type of one connection.
pub(crate) enum Store<W> {
    /// The port of the C hash tables.
    Legacy(LegacyWatchers<W>),
    /// The ordered native tables. They are large, so the store keeps
    /// them on the heap.
    Ordered(Box<OrderedWatches<W>>),
}

/// The watcher registry.
pub(crate) struct Watches<W> {
    /// The tables.
    pub(crate) store: Store<W>,
}

/// The keys of every table, in table iteration order, for SetWatches.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WatchKeys {
    /// The data table keys.
    pub(crate) data: Vec<Vec<u8>>,
    /// The exist table keys.
    pub(crate) exist: Vec<Vec<u8>>,
    /// The child table keys.
    pub(crate) child: Vec<Vec<u8>>,
    /// The persistent table keys.
    pub(crate) persistent: Vec<Vec<u8>>,
    /// The persistent recursive table keys.
    pub(crate) recursive: Vec<Vec<u8>>,
}

impl WatchKeys {
    /// Returns true when no table has a key.
    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
            && self.exist.is_empty()
            && self.child.is_empty()
            && self.persistent.is_empty()
            && self.recursive.is_empty()
    }
}

/// Returns the legacy table of a kind, or `None` for the persistent kinds.
fn legacy_table<W>(l: &LegacyWatchers<W>, kind: WatchKind) -> Option<&LegacyWatchTable<W>> {
    match kind {
        WatchKind::Data => Some(&l.data),
        WatchKind::Exist => Some(&l.exist),
        WatchKind::Child => Some(&l.child),
        WatchKind::Persistent | WatchKind::PersistentRecursive => None,
    }
}

/// Returns the legacy table of a kind for change, or `None` for the
/// persistent kinds.
fn legacy_table_mut<W>(
    l: &mut LegacyWatchers<W>,
    kind: WatchKind,
) -> Option<&mut LegacyWatchTable<W>> {
    match kind {
        WatchKind::Data => Some(&mut l.data),
        WatchKind::Exist => Some(&mut l.exist),
        WatchKind::Child => Some(&mut l.child),
        WatchKind::Persistent | WatchKind::PersistentRecursive => None,
    }
}

/// Removes a watcher from one legacy table, as `removeWatcher` does, and
/// gives the removed watchers.
fn legacy_remove<W: Clone + Eq>(
    table: &mut LegacyWatchTable<W>,
    path: &[u8],
    w: Option<&W>,
) -> Vec<W> {
    match w {
        None => table.take(path),
        Some(w) => {
            if table.contains(path, Some(w)) {
                table.remove(path, Some(w));
                vec![w.clone()]
            } else {
                Vec::new()
            }
        }
    }
}

impl<W: Clone + Eq> Watches<W> {
    /// Makes empty tables of the selected type.
    pub(crate) fn new(table: WatchTable, c_char_signed: bool) -> Self {
        let store = match table {
            WatchTable::LegacyHashtable => Store::Legacy(LegacyWatchers::new(c_char_signed)),
            WatchTable::Ordered => Store::Ordered(Box::new(OrderedWatches::new())),
        };
        Self { store }
    }

    /// Returns true when a watcher of the type is armed on the path.
    ///
    /// The legacy tables follow `pathHasWatcher`: `None` always matches
    /// for a valid type. The ordered tables follow the Java client: `None`
    /// matches when the path has any watcher of the type.
    pub(crate) fn has(&self, path: &[u8], wtype: i32, w: Option<&W>) -> bool {
        match &self.store {
            Store::Legacy(l) => l.has_watcher(path, wtype, w),
            Store::Ordered(o) => ordered_kinds(wtype)
                .iter()
                .any(|kind| o.contains(*kind, path, w)),
        }
    }

    /// Removes the matching registrations of a watch type and gives the
    /// removed watchers in removal order.
    pub(crate) fn remove(&mut self, path: &[u8], wtype: i32, w: Option<&W>) -> Vec<W> {
        let mut removed = Vec::new();
        match &mut self.store {
            Store::Legacy(l) => {
                for kind in legacy_kinds(wtype) {
                    if let Some(table) = legacy_table_mut(l, *kind) {
                        removed.extend(legacy_remove(table, path, w));
                    }
                }
            }
            Store::Ordered(o) => {
                for kind in ordered_kinds(wtype) {
                    removed.extend(o.remove(*kind, path, w));
                }
            }
        }
        dedup_keep_first(removed)
    }

    /// Arms a registration per the checker table. It gives true when the
    /// watcher went into a table.
    pub(crate) fn arm(&mut self, kind: WatchKind, path: &[u8], w: W, rc_value: i32) -> bool {
        let Some(target) = armed_table(kind, rc_value) else {
            return false;
        };
        match &mut self.store {
            Store::Legacy(l) => legacy_table_mut(l, target).is_some_and(|t| t.insert(path, w)),
            Store::Ordered(o) => o.insert(target, path, w),
        }
    }

    /// Collects the watchers of a node event in delivery order. One-shot
    /// registrations leave the tables.
    pub(crate) fn collect_event(&mut self, event_type: i32, path: &[u8]) -> Vec<W> {
        match &mut self.store {
            Store::Legacy(l) => l.collect_node_event(event_type, path),
            Store::Ordered(o) => o.collect_node_event(event_type, path),
        }
    }

    /// Returns the watchers of a session event in delivery order. The
    /// tables do not change.
    ///
    /// With `fanout`, the legacy tables give the C order: the path
    /// watchers in reverse collection order, then the default watcher.
    /// The ordered tables give every path watcher in table order, then the
    /// default watcher. Without `fanout`, only the default watcher comes.
    pub(crate) fn session(&self, default: Option<W>, fanout: bool) -> Vec<W> {
        if !fanout {
            return default.into_iter().collect();
        }
        match (&self.store, default) {
            (Store::Legacy(l), Some(d)) => l.collect_session_event(&d),
            (Store::Legacy(l), None) => {
                let mut seq: Vec<&W> = Vec::new();
                for table in [&l.data, &l.exist, &l.child] {
                    for (_, list) in table.iter() {
                        seq.extend(list.iter());
                    }
                }
                fan_out(seq).into_iter().cloned().collect()
            }
            (Store::Ordered(_), default) => {
                let mut all = self.all_watchers();
                if let Some(d) = default {
                    all.retain(|w| *w != d);
                    all.push(d);
                }
                all
            }
        }
    }

    /// Returns every armed watcher once, in table order: data, exist,
    /// child, persistent, recursive.
    pub(crate) fn all_watchers(&self) -> Vec<W> {
        let mut seq: Vec<W> = Vec::new();
        match &self.store {
            Store::Legacy(l) => {
                for table in [&l.data, &l.exist, &l.child] {
                    for (_, list) in table.iter() {
                        seq.extend(list.iter().cloned());
                    }
                }
            }
            Store::Ordered(o) => {
                for kind in ALL_KINDS {
                    for list in o.table(kind).values() {
                        seq.extend(list.iter().cloned());
                    }
                }
            }
        }
        dedup_keep_first(seq)
    }

    /// Removes every watcher and gives them once, in table order.
    pub(crate) fn clear(&mut self) -> Vec<W> {
        let all = self.all_watchers();
        match &mut self.store {
            Store::Legacy(l) => {
                l.data.clear();
                l.exist.clear();
                l.child.clear();
            }
            Store::Ordered(o) => **o = OrderedWatches::new(),
        }
        all
    }

    /// Returns true when the server watch class of a table has a watcher
    /// on the path.
    fn class_in_use(&self, kind: WatchKind, path: &[u8]) -> bool {
        self.has(path, class_wtype(kind), None) && {
            // The legacy `None` match is true for every path, so the
            // legacy tables check the lists directly.
            match &self.store {
                Store::Legacy(l) => match kind {
                    WatchKind::Data | WatchKind::Exist => {
                        l.data.watchers(path).next().is_some()
                            || l.exist.watchers(path).next().is_some()
                    }
                    _ => legacy_table(l, kind).is_some_and(|t| t.watchers(path).next().is_some()),
                },
                Store::Ordered(_) => true,
            }
        }
    }

    /// Removes a watcher from every table. It gives each table and path
    /// that lost the watcher and now has no watcher of the same server
    /// class, in table order.
    pub(crate) fn detach(&mut self, w: &W) -> Vec<(WatchKind, Vec<u8>)> {
        let mut touched: Vec<(WatchKind, Vec<u8>)> = Vec::new();
        match &mut self.store {
            Store::Legacy(l) => {
                for kind in [WatchKind::Data, WatchKind::Exist, WatchKind::Child] {
                    if let Some(table) = legacy_table_mut(l, kind) {
                        let paths: Vec<Vec<u8>> = table
                            .iter()
                            .filter(|(_, list)| list.contains(w))
                            .map(|(p, _)| p.to_vec())
                            .collect();
                        for p in paths {
                            table.remove(&p, Some(w));
                            touched.push((kind, p));
                        }
                    }
                }
            }
            Store::Ordered(o) => {
                for kind in ALL_KINDS {
                    let paths: Vec<Vec<u8>> = o
                        .table(kind)
                        .iter()
                        .filter(|(_, list)| list.contains(w))
                        .map(|(p, _)| p.clone())
                        .collect();
                    for p in paths {
                        o.remove(kind, &p, Some(w));
                        touched.push((kind, p));
                    }
                }
            }
        }
        touched
            .into_iter()
            .filter(|(kind, p)| !self.class_in_use(*kind, p))
            .collect()
    }

    /// Returns the keys of every table in table iteration order.
    pub(crate) fn keys(&self) -> WatchKeys {
        match &self.store {
            Store::Legacy(l) => WatchKeys {
                data: l.data.keys().map(<[u8]>::to_vec).collect(),
                exist: l.exist.keys().map(<[u8]>::to_vec).collect(),
                child: l.child.keys().map(<[u8]>::to_vec).collect(),
                persistent: Vec::new(),
                recursive: Vec::new(),
            },
            Store::Ordered(o) => WatchKeys {
                data: o.data.keys().cloned().collect(),
                exist: o.exist.keys().cloned().collect(),
                child: o.child.keys().cloned().collect(),
                persistent: o.persistent.keys().cloned().collect(),
                recursive: o.persistent_recursive.keys().cloned().collect(),
            },
        }
    }
}

/// Encodes one SetWatches packet body and gives its opcode.
///
/// A packet with persistent keys uses SetWatches2 (op 105). Any other
/// packet uses SetWatches (op 101), as the Java client chooses per batch.
fn encode_set_watches(batch: [Vec<JString>; 5], relative_zxid: i64) -> (i32, Vec<u8>) {
    let [data, exist, child, persistent, recursive] = batch;
    if persistent.is_empty() && recursive.is_empty() {
        let req = SetWatches {
            relative_zxid,
            data_watches: JVec::from(data),
            exist_watches: JVec::from(exist),
            child_watches: JVec::from(child),
        };
        (opcode::SET_WATCHES, req.to_bytes())
    } else {
        let req = SetWatches2 {
            relative_zxid,
            data_watches: JVec::from(data),
            exist_watches: JVec::from(exist),
            child_watches: JVec::from(child),
            persistent_watches: JVec::from(persistent),
            persistent_recursive_watches: JVec::from(recursive),
        };
        (opcode::SET_WATCHES2, req.to_bytes())
    }
}

/// Splits the keys into SetWatches packets and gives each opcode and body
/// in wire order.
///
/// The keys go into packets in table order. A packet holds at most
/// `limit` bytes of paths. A key that is longer than the limit goes alone
/// into its own packet, so no key is lost. With no key there is no packet.
pub(crate) fn set_watches_packets(
    keys: &WatchKeys,
    relative_zxid: i64,
    limit: Option<u32>,
) -> Vec<(i32, Vec<u8>)> {
    let limit = limit.map_or(usize::MAX, |l| usize::try_from(l).unwrap_or(usize::MAX));
    let mut packets = Vec::new();
    let mut batch: [Vec<JString>; 5] = Default::default();
    let mut batch_bytes: usize = 0;
    let mut batch_keys: usize = 0;
    let sources = [
        &keys.data,
        &keys.exist,
        &keys.child,
        &keys.persistent,
        &keys.recursive,
    ];
    for (slot, list) in sources.iter().enumerate() {
        for key in list.iter() {
            if batch_keys > 0 && batch_bytes.saturating_add(key.len()) > limit {
                packets.push(encode_set_watches(
                    core::mem::take(&mut batch),
                    relative_zxid,
                ));
                batch_bytes = 0;
                batch_keys = 0;
            }
            if let Some(dst) = batch.get_mut(slot) {
                dst.push(JString::Bytes(key.clone()));
            }
            batch_bytes = batch_bytes.saturating_add(key.len());
            batch_keys = batch_keys.saturating_add(1);
        }
    }
    if batch_keys > 0 {
        packets.push(encode_set_watches(batch, relative_zxid));
    }
    packets
}

impl<T: Tokens> Connection<T> {
    /// Returns true when the native watch rules apply: `WatchTerminated`
    /// outputs, and no `Watch` output with an empty list.
    fn watches_native(&self) -> bool {
        !self.compat.session_fanout_to_path_watchers
    }

    /// Pushes `WatchTerminated` under the native rules when the list is
    /// not empty.
    fn watches_push_terminated(&mut self, watchers: Vec<T::Watcher>, reason: TerminateReason) {
        if self.watches_native() && !watchers.is_empty() {
            self.out.push(Output::WatchTerminated { watchers, reason });
        }
    }

    /// Returns true when an unanswered request carries a registration of
    /// this server watch class on the path.
    fn watches_in_flight(&self, server_path: &[u8], wtype: i32) -> bool {
        self.requests.fifo.iter().any(|p| {
            p.watch
                .as_ref()
                .is_some_and(|r| r.path == server_path && class_wtype(r.kind) == wtype)
        })
    }

    /// Returns the client form of a server path. With no chroot the path
    /// does not change. A path outside the chroot stays as it is.
    fn watches_client_path(&self, server_path: &[u8]) -> JString {
        if self.cfg.chroot.is_none() {
            return JString::Bytes(server_path.to_vec());
        }
        let mut logs = Vec::new();
        self.strip_path(server_path, &mut logs)
            .unwrap_or_else(|| JString::Bytes(server_path.to_vec()))
    }

    /// Returns true when a watcher of this type is armed on the server
    /// path.
    ///
    /// Contract: `wtype` 1 child, 2 data (data and exist
    /// tables), 3 any; natively also 4 persistent and 5 recursive. `None`
    /// matches any watcher. An invalid `wtype` gives false.
    #[must_use]
    pub fn has_watcher(&self, server_path: &[u8], wtype: i32, w: Option<&T::Watcher>) -> bool {
        self.watches.has(server_path, wtype, w)
    }

    /// Removes every registration of a watcher and returns a hint for the
    /// server removal.
    ///
    /// Contract: it removes `w` from every table. When the
    /// watcher was the last one of its path and type, it returns the path
    /// (client form) and the type, so the native client can send a
    /// removeWatches. Otherwise it returns `None`.
    ///
    /// The count of users of a server watch class includes the
    /// registrations on unanswered requests. Such a request
    /// sets the same server watch, so no hint goes out for it.
    pub fn detach_watcher(&mut self, w: &T::Watcher) -> Option<RemoveHint> {
        let emptied = self.watches.detach(w);
        for (kind, path) in emptied {
            let wtype = class_wtype(kind);
            if self.watches_in_flight(&path, wtype) {
                continue;
            }
            return Some(RemoveHint {
                path: self.watches_client_path(&path),
                wtype,
            });
        }
        None
    }

    /// Arms a watch from a matched reply.
    ///
    /// Contract: data watches arm on `ZOK`. An
    /// exists watch arms in the data table on `ZOK` and in the exist table
    /// on `ZNONODE`. Child watches arm on `ZOK`. Persistent watches arm on
    /// `ZOK`. Any other rc arms nothing. A duplicate watcher on a path is
    /// not added twice.
    ///
    /// The exists registration is `WatchKind::Exist`. The getData
    /// registration is `WatchKind::Data`, so a getData on a missing node
    /// arms nothing, as in C.
    pub(crate) fn arm_watch(&mut self, reg: WatchReg<T::Watcher>, rc: i32) {
        self.watches.arm(reg.kind, &reg.path, reg.watcher, rc);
    }

    /// Applies the local removal of a successful removeWatches reply.
    ///
    /// Contract: it removes the matching registrations. Under
    /// the native profile it pushes `WatchTerminated{Removed}` for them.
    pub(crate) fn apply_unwatch(&mut self, u: Unwatch<T::Watcher>) {
        let removed = self.watches.remove(&u.path, u.wtype, u.watcher.as_ref());
        self.watches_push_terminated(removed, TerminateReason::Removed);
    }

    /// Runs the local removal of the remove-watches check of `submit`.
    ///
    /// Contract: an invalid `wtype`, or no matching watcher, gives
    /// `Err(ZNOWATCHER)`. With `local`, the watchers are removed now. When
    /// `session_fanout_to_path_watchers` is false it also pushes
    /// `WatchTerminated{Removed}`. Without `local`, it only checks.
    pub(crate) fn check_remove_watches(
        &mut self,
        server_path: &[u8],
        wtype: i32,
        watcher: Option<&T::Watcher>,
        local: bool,
    ) -> Result<(), i32> {
        if !self.watches.has(server_path, wtype, watcher) {
            return Err(rc::ZNOWATCHER);
        }
        if local {
            let removed = self.watches.remove(server_path, wtype, watcher);
            self.watches_push_terminated(removed, TerminateReason::Removed);
        }
        Ok(())
    }

    /// Processes a watcher event frame (xid -1).
    ///
    /// Contract:
    /// - It logs DEBUG "Processing WATCHER_EVENT" and decodes the
    ///   `WatcherEvent` record. A decode failure tears down with
    ///   `Cause::ProtocolError`.
    /// - It strips the path with `strip_path`. The mismatch ERROR goes to
    ///   the delivery logs, after the "Calling a watcher" DEBUG line.
    /// - It collects the watchers now, with one-shot entries removed.
    /// - It pushes `Output::Watch`. Under `LEGACY_C` the output also goes
    ///   out with an empty list. Under `NATIVE` only with watchers.
    ///
    /// `body` is the frame after the `ReplyHeader`. The tables use the
    /// server path as the key, so the collection uses the raw path. Under
    /// `ChrootPolicy::Component` an event outside the chroot is dropped
    /// with its ERROR line, except for the configuration node, which
    /// goes out unstripped.
    pub(crate) fn on_watcher_event(&mut self, zxid: i64, body: &[u8], now: Millis) -> Flow {
        self.emit_log(LogSite::ProcessingWatcherEvent, Vec::new);
        let Ok(evt) = WatcherEvent::from_bytes(body) else {
            let rc_value = self.teardown(Cause::ProtocolError, 0, now);
            return Flow::Done(rc_value);
        };
        let raw: Vec<u8> = evt.path.as_bytes().map(<[u8]>::to_vec).unwrap_or_default();
        let mut logs: Vec<LogRecord> = Vec::new();
        let shown: &[u8] = if evt.path.is_null() { b"NULL" } else { &raw };
        if let Some(r) = self.log.record(LogSite::CallingWatcher, || {
            vec![
                str_arg(shown),
                LogArg::I64(i64::from(completion::WATCH)),
                str_arg(event_name(evt.r#type)),
            ]
        }) {
            logs.push(r);
        }
        let path = if evt.path.is_null() || self.cfg.chroot.is_none() {
            evt.path.clone()
        } else {
            let mark = logs.len();
            match self.strip_path(&raw, &mut logs) {
                Some(p) => p,
                None if is_config_node(&raw) => {
                    logs.truncate(mark);
                    evt.path.clone()
                }
                None => {
                    for r in logs.into_iter().skip(mark) {
                        self.out.push(Output::Log(r));
                    }
                    return Flow::Continue;
                }
            }
        };
        let watchers = self.watches.collect_event(evt.r#type, &raw);
        if watchers.is_empty() && self.watches_native() {
            return Flow::Continue;
        }
        self.out.push(Output::Watch {
            event: WatchedEvent {
                event_type: evt.r#type,
                state: evt.state,
                path,
                zxid,
            },
            watchers,
            delivery_logs: logs,
        });
        Flow::Continue
    }

    /// Returns the watchers of a session event, in delivery order.
    ///
    /// Contract: under `session_fanout_to_path_watchers` every
    /// path watcher comes first, then the default watcher. Otherwise only
    /// the default watcher. The default watcher comes from the
    /// `DefaultWatcher` hook at this call.
    pub(crate) fn session_watchers(&mut self) -> Vec<T::Watcher> {
        let default = self.default_watcher.snapshot();
        self.watches
            .session(default, self.compat.session_fanout_to_path_watchers)
    }

    /// Queues the SetWatches packets of the armed watches.
    ///
    /// Contract: with `cfg.restore_watches` false, or no watch, it does
    /// nothing. Each packet holds at most `Compat::set_watches_batch`
    /// bytes of paths. Paths keep the chroot. The packets carry
    /// `core.last_zxid`. They go to the priority boundary, behind the auth
    /// packets that finalize already queued. SetWatches2 carries the
    /// persistent watches.
    ///
    /// The packets go in last to first, so they reach the wire first to
    /// last. One DEBUG "Sending set watches" line follows, as in C.
    pub(crate) fn queue_set_watches(&mut self) {
        if !self.cfg.restore_watches {
            return;
        }
        let keys = self.watches.keys();
        if keys.is_empty() {
            return;
        }
        let packets =
            set_watches_packets(&keys, self.core.last_zxid, self.compat.set_watches_batch);
        for (op, body) in packets.iter().rev() {
            let frame = Self::request_frame(xid::SET_WATCHES, *op, body);
            self.requests
                .push_priority(OutFrame::plain(FrameKind::SetWatches, frame));
        }
        let server = self.current_server();
        self.emit_log(LogSite::SendSetWatches, || vec![LogArg::Endpoint(server)]);
    }

    /// Clears every table.
    ///
    /// Contract: under `clear_watches_on_expiry`, or on close, it removes
    /// every watcher. Under the native profile it pushes
    /// `WatchTerminated{reason}` with the removed watchers.
    ///
    /// `Closed` and `Removed` always clear. `SessionExpired` and
    /// `AuthFailed` clear under `clear_watches_on_expiry`.
    /// `ConnectionLost` clears when `cfg.restore_watches` is false.
    pub(crate) fn clear_watches(&mut self, reason: TerminateReason) {
        let clear = match reason {
            TerminateReason::Closed | TerminateReason::Removed => true,
            TerminateReason::SessionExpired | TerminateReason::AuthFailed => {
                self.compat.clear_watches_on_expiry
            }
            TerminateReason::ConnectionLost => !self.cfg.restore_watches,
        };
        if !clear {
            return;
        }
        let removed = self.watches.clear();
        self.watches_push_terminated(removed, reason);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::compat::Compat;
    use crate::config::{Config, DriverMode};
    use crate::hooks::{AllLevels, DefaultWatcher, Rng};
    use crate::request::Route;
    use crate::requests::{Pending, Shape};

    struct Tk;
    impl Tokens for Tk {
        type Completion = u32;
        type Watcher = u32;
        type Auth = u32;
    }

    struct FixedRng;
    impl Rng for FixedRng {
        fn on_resolution(&mut self) {}
        fn random(&mut self) -> i64 {
            0
        }
        fn drand48(&mut self) -> f64 {
            0.0
        }
    }

    struct Dw(Option<u32>);
    impl DefaultWatcher<u32> for Dw {
        fn snapshot(&self) -> Option<u32> {
            self.0
        }
    }

    fn conn_with(compat: Compat, default: Option<u32>) -> Connection<Tk> {
        Connection::new(
            Config::legacy(30_000),
            compat,
            DriverMode::MT,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(Dw(default)),
            Millis(0),
        )
    }

    fn legacy() -> Connection<Tk> {
        conn_with(Compat::LEGACY_C, Some(0))
    }

    fn native() -> Connection<Tk> {
        conn_with(Compat::NATIVE, None)
    }

    fn reg(kind: WatchKind, path: &[u8], w: u32) -> WatchReg<u32> {
        WatchReg {
            kind,
            path: path.to_vec(),
            watcher: w,
        }
    }

    fn event_body(t: i32, path: &[u8]) -> Vec<u8> {
        WatcherEvent {
            r#type: t,
            state: 3,
            path: JString::Bytes(path.to_vec()),
        }
        .to_bytes()
    }

    /// Pops every output and gives the `Watch` outputs.
    fn watch_outputs(c: &mut Connection<Tk>) -> Vec<(WatchedEvent, Vec<u32>, Vec<LogRecord>)> {
        let mut got = Vec::new();
        while let Some(o) = c.poll_output() {
            if let Output::Watch {
                event,
                watchers,
                delivery_logs,
            } = o
            {
                got.push((event, watchers, delivery_logs));
            }
        }
        got
    }

    fn terminated(c: &mut Connection<Tk>) -> Vec<(Vec<u32>, TerminateReason)> {
        let mut got = Vec::new();
        while let Some(o) = c.poll_output() {
            if let Output::WatchTerminated { watchers, reason } = o {
                got.push((watchers, reason));
            }
        }
        got
    }

    /// The tables that hold a watcher on a path, by kind.
    fn kinds_holding(c: &Connection<Tk>, path: &[u8], w: u32) -> Vec<WatchKind> {
        match &c.watches.store {
            Store::Legacy(l) => {
                let mut v = Vec::new();
                if l.data.contains(path, Some(&w)) {
                    v.push(WatchKind::Data);
                }
                if l.exist.contains(path, Some(&w)) {
                    v.push(WatchKind::Exist);
                }
                if l.child.contains(path, Some(&w)) {
                    v.push(WatchKind::Child);
                }
                v
            }
            Store::Ordered(o) => ALL_KINDS
                .iter()
                .copied()
                .filter(|k| o.contains(*k, path, Some(&w)))
                .collect(),
        }
    }

    #[test]
    fn checker_table_every_kind_and_rc() {
        let rcs = [rc::ZOK, rc::ZNONODE, rc::ZCONNECTIONLOSS, rc::ZNOAUTH];
        for native_store in [false, true] {
            for kind in ALL_KINDS {
                for rc_value in rcs {
                    let mut c = if native_store { native() } else { legacy() };
                    c.arm_watch(reg(kind, b"/a", 7), rc_value);
                    let got = kinds_holding(&c, b"/a", 7);
                    let want: Vec<WatchKind> = match (kind, rc_value) {
                        (WatchKind::Exist, rc::ZOK) | (WatchKind::Data, rc::ZOK) => {
                            vec![WatchKind::Data]
                        }
                        (WatchKind::Exist, rc::ZNONODE) => vec![WatchKind::Exist],
                        (WatchKind::Child, rc::ZOK) => vec![WatchKind::Child],
                        (WatchKind::Persistent | WatchKind::PersistentRecursive, rc::ZOK)
                            if native_store =>
                        {
                            vec![kind]
                        }
                        _ => vec![],
                    };
                    assert_eq!(
                        got, want,
                        "store native={native_store} {kind:?} rc={rc_value}"
                    );
                }
            }
        }
    }

    #[test]
    fn arm_never_duplicates() {
        for mut c in [legacy(), native()] {
            c.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
            c.arm_watch(reg(WatchKind::Exist, b"/a", 1), rc::ZOK);
            c.arm_watch(reg(WatchKind::Data, b"/a", 2), rc::ZOK);
            c.on_watcher_event(5, &event_body(CHANGED_EVENT, b"/a"), Millis(0));
            let w = watch_outputs(&mut c);
            assert_eq!(w.len(), 1);
            let mut got = w[0].1.clone();
            got.sort_unstable();
            assert_eq!(got, vec![1, 2]);
        }
    }

    #[test]
    fn legacy_collection_order() {
        let mut c = legacy();
        // Registration order: data 1, data 2, exist 3, child 4.
        c.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        c.arm_watch(reg(WatchKind::Data, b"/a", 2), rc::ZOK);
        c.arm_watch(reg(WatchKind::Exist, b"/a", 3), rc::ZNONODE);
        c.arm_watch(reg(WatchKind::Child, b"/a", 4), rc::ZOK);
        c.on_watcher_event(9, &event_body(DELETED_EVENT, b"/a"), Millis(0));
        let w = watch_outputs(&mut c);
        assert_eq!(w.len(), 1);
        // Child, exist, then data oldest first.
        assert_eq!(w[0].1, vec![4, 3, 1, 2]);
        assert_eq!(w[0].0.zxid, 9);
        assert_eq!(w[0].0.event_type, DELETED_EVENT);
        assert_eq!(w[0].0.path, JString::Bytes(b"/a".to_vec()));
        assert!(!c.has_watcher(b"/a", WTYPE_DATA, Some(&1)));
        assert!(!c.has_watcher(b"/a", WTYPE_CHILD, Some(&4)));

        c.arm_watch(reg(WatchKind::Data, b"/b", 1), rc::ZOK);
        c.arm_watch(reg(WatchKind::Exist, b"/b", 2), rc::ZNONODE);
        c.arm_watch(reg(WatchKind::Child, b"/b", 3), rc::ZOK);
        c.on_watcher_event(10, &event_body(CREATED_EVENT, b"/b"), Millis(0));
        let w = watch_outputs(&mut c);
        assert_eq!(w[0].1, vec![2, 1]);
        // The child watch stays for a create event.
        assert!(c.has_watcher(b"/b", WTYPE_CHILD, Some(&3)));
        c.on_watcher_event(11, &event_body(CHILD_EVENT, b"/b"), Millis(0));
        assert_eq!(watch_outputs(&mut c)[0].1, vec![3]);
    }

    #[test]
    fn legacy_empty_event_still_goes_out_with_logs() {
        let mut c = legacy();
        c.on_watcher_event(1, &event_body(CHANGED_EVENT, b"/none"), Millis(0));
        c.on_watcher_event(1, &event_body(99, b"/none"), Millis(0));
        let w = watch_outputs(&mut c);
        assert_eq!(w.len(), 2);
        assert!(w.iter().all(|(_, ws, _)| ws.is_empty()));
        let first = &w[0].2[0];
        assert_eq!(first.site, LogSite::CallingWatcher);
        assert_eq!(
            first.args,
            vec![
                str_arg(b"/none"),
                LogArg::I64(-1),
                str_arg(b"ZOO_CHANGED_EVENT")
            ]
        );
        assert_eq!(w[1].2[0].args[2], str_arg(b"INVALID_EVENT"));
    }

    #[test]
    fn native_empty_event_has_no_output() {
        let mut c = native();
        c.on_watcher_event(1, &event_body(CHANGED_EVENT, b"/none"), Millis(0));
        assert!(watch_outputs(&mut c).is_empty());
    }

    #[test]
    fn processing_line_comes_first() {
        let mut c = legacy();
        c.on_watcher_event(1, &event_body(CHANGED_EVENT, b"/a"), Millis(0));
        match c.poll_output() {
            Some(Output::Log(r)) => assert_eq!(r.site, LogSite::ProcessingWatcherEvent),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ordered_collection_order() {
        let mut c = native();
        c.arm_watch(reg(WatchKind::Data, b"/a/b", 1), rc::ZOK);
        c.arm_watch(reg(WatchKind::Data, b"/a/b", 2), rc::ZOK);
        c.arm_watch(reg(WatchKind::Exist, b"/a/b", 3), rc::ZNONODE);
        c.arm_watch(reg(WatchKind::Exist, b"/a/b", 4), rc::ZNONODE);
        c.arm_watch(reg(WatchKind::Child, b"/a/b", 5), rc::ZOK);
        c.arm_watch(reg(WatchKind::Persistent, b"/a/b", 6), rc::ZOK);
        c.arm_watch(reg(WatchKind::PersistentRecursive, b"/", 7), rc::ZOK);
        c.arm_watch(reg(WatchKind::PersistentRecursive, b"/a", 8), rc::ZOK);
        c.arm_watch(reg(WatchKind::PersistentRecursive, b"/a/b", 9), rc::ZOK);
        c.arm_watch(reg(WatchKind::PersistentRecursive, b"/x", 10), rc::ZOK);

        c.on_watcher_event(1, &event_body(CHANGED_EVENT, b"/a/b"), Millis(0));
        let w = watch_outputs(&mut c);
        // Exist then data, oldest first; persistent; recursive nearest first.
        assert_eq!(w[0].1, vec![3, 4, 1, 2, 6, 9, 8, 7]);

        // Children changed: child, persistent, and no recursive watcher.
        c.on_watcher_event(2, &event_body(CHILD_EVENT, b"/a/b"), Millis(0));
        assert_eq!(watch_outputs(&mut c)[0].1, vec![5, 6]);

        // The persistent watches stay; the one-shot ones are gone.
        c.arm_watch(reg(WatchKind::Data, b"/a/b", 1), rc::ZOK);
        c.arm_watch(reg(WatchKind::Exist, b"/a/b", 3), rc::ZNONODE);
        c.arm_watch(reg(WatchKind::Child, b"/a/b", 5), rc::ZOK);
        c.on_watcher_event(3, &event_body(DELETED_EVENT, b"/a/b"), Millis(0));
        assert_eq!(watch_outputs(&mut c)[0].1, vec![5, 3, 1, 6, 9, 8, 7]);
        assert!(c.has_watcher(b"/a/b", WTYPE_PERSISTENT, Some(&6)));
        assert!(!c.has_watcher(b"/a/b", WTYPE_DATA, None));
    }

    #[test]
    fn lineage_order() {
        assert_eq!(
            path_lineage(b"/a/b/c"),
            vec![&b"/a/b/c"[..], b"/a/b", b"/a", b"/"]
        );
        assert_eq!(path_lineage(b"/"), vec![&b"/"[..]]);
        assert_eq!(path_lineage(b"rel"), vec![&b"rel"[..]]);
        assert_eq!(path_lineage(b""), vec![&b""[..]]);
    }

    #[test]
    fn has_watcher_each_wtype() {
        let mut l = legacy();
        l.arm_watch(reg(WatchKind::Data, b"/d", 1), rc::ZOK);
        l.arm_watch(reg(WatchKind::Exist, b"/e", 2), rc::ZNONODE);
        l.arm_watch(reg(WatchKind::Child, b"/c", 3), rc::ZOK);
        assert!(l.has_watcher(b"/c", WTYPE_CHILD, Some(&3)));
        assert!(!l.has_watcher(b"/d", WTYPE_CHILD, Some(&1)));
        assert!(l.has_watcher(b"/d", WTYPE_DATA, Some(&1)));
        assert!(l.has_watcher(b"/e", WTYPE_DATA, Some(&2)));
        assert!(!l.has_watcher(b"/c", WTYPE_DATA, Some(&3)));
        for (p, w) in [(&b"/d"[..], 1), (b"/e", 2), (b"/c", 3)] {
            assert!(l.has_watcher(p, WTYPE_ANY, Some(&w)));
        }
        // Legacy: `None` always matches a valid type, as in C.
        assert!(l.has_watcher(b"/nothing", WTYPE_CHILD, None));
        for bad in [0, 4, 5, 6, -1] {
            assert!(!l.has_watcher(b"/d", bad, None));
            assert!(!l.has_watcher(b"/d", bad, Some(&1)));
        }

        let mut n = native();
        n.arm_watch(reg(WatchKind::Data, b"/d", 1), rc::ZOK);
        n.arm_watch(reg(WatchKind::Exist, b"/e", 2), rc::ZNONODE);
        n.arm_watch(reg(WatchKind::Child, b"/c", 3), rc::ZOK);
        n.arm_watch(reg(WatchKind::Persistent, b"/p", 4), rc::ZOK);
        n.arm_watch(reg(WatchKind::PersistentRecursive, b"/r", 5), rc::ZOK);
        assert!(n.has_watcher(b"/c", WTYPE_CHILD, Some(&3)));
        assert!(n.has_watcher(b"/d", WTYPE_DATA, Some(&1)));
        assert!(n.has_watcher(b"/e", WTYPE_DATA, None));
        assert!(n.has_watcher(b"/p", WTYPE_PERSISTENT, Some(&4)));
        assert!(!n.has_watcher(b"/p", WTYPE_DATA, Some(&4)));
        assert!(n.has_watcher(b"/r", WTYPE_RECURSIVE, Some(&5)));
        assert!(!n.has_watcher(b"/r", WTYPE_PERSISTENT, None));
        for (p, w) in [
            (&b"/d"[..], 1),
            (b"/e", 2),
            (b"/c", 3),
            (b"/p", 4),
            (b"/r", 5),
        ] {
            assert!(n.has_watcher(p, WTYPE_ANY, Some(&w)));
        }
        // Ordered: `None` needs a watcher on the path.
        assert!(!n.has_watcher(b"/nothing", WTYPE_ANY, None));
        for bad in [0, 6, -1] {
            assert!(!n.has_watcher(b"/d", bad, None));
        }
    }

    #[test]
    fn remove_watches_check_and_local() {
        let mut l = legacy();
        l.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        assert_eq!(
            l.check_remove_watches(b"/a", WTYPE_CHILD, Some(&1), true),
            Err(rc::ZNOWATCHER)
        );
        assert_eq!(
            l.check_remove_watches(b"/a", 9, None, true),
            Err(rc::ZNOWATCHER)
        );
        // Without `local` it only checks.
        assert_eq!(
            l.check_remove_watches(b"/a", WTYPE_DATA, Some(&1), false),
            Ok(())
        );
        assert!(l.has_watcher(b"/a", WTYPE_DATA, Some(&1)));
        assert_eq!(
            l.check_remove_watches(b"/a", WTYPE_ANY, Some(&1), true),
            Ok(())
        );
        assert!(!l.has_watcher(b"/a", WTYPE_ANY, Some(&1)));
        // Legacy: no WatchTerminated output.
        assert!(terminated(&mut l).is_empty());

        let mut n = native();
        n.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        n.arm_watch(reg(WatchKind::Exist, b"/a", 2), rc::ZNONODE);
        n.arm_watch(reg(WatchKind::Child, b"/a", 3), rc::ZOK);
        assert_eq!(
            n.check_remove_watches(b"/b", WTYPE_DATA, None, true),
            Err(rc::ZNOWATCHER)
        );
        assert_eq!(
            n.check_remove_watches(b"/a", WTYPE_DATA, None, true),
            Ok(())
        );
        assert_eq!(
            terminated(&mut n),
            vec![(vec![1, 2], TerminateReason::Removed)]
        );
        assert!(n.has_watcher(b"/a", WTYPE_CHILD, Some(&3)));
    }

    #[test]
    fn unwatch_reply_removes() {
        let mut n = native();
        n.arm_watch(reg(WatchKind::Child, b"/a", 3), rc::ZOK);
        n.arm_watch(reg(WatchKind::Persistent, b"/a", 4), rc::ZOK);
        n.apply_unwatch(Unwatch {
            path: b"/a".to_vec(),
            wtype: WTYPE_ANY,
            watcher: None,
        });
        assert_eq!(
            terminated(&mut n),
            vec![(vec![3, 4], TerminateReason::Removed)]
        );
        assert!(!n.has_watcher(b"/a", WTYPE_ANY, None));

        let mut l = legacy();
        l.arm_watch(reg(WatchKind::Child, b"/a", 3), rc::ZOK);
        l.arm_watch(reg(WatchKind::Child, b"/a", 4), rc::ZOK);
        l.apply_unwatch(Unwatch {
            path: b"/a".to_vec(),
            wtype: WTYPE_CHILD,
            watcher: Some(3),
        });
        assert!(!l.has_watcher(b"/a", WTYPE_CHILD, Some(&3)));
        assert!(l.has_watcher(b"/a", WTYPE_CHILD, Some(&4)));
    }

    #[test]
    fn session_watchers_with_and_without_fanout() {
        // Legacy fan-out: the path watchers in reverse collection order,
        // then the default watcher last; an equal path watcher is dropped.
        let mut l = legacy();
        l.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        l.arm_watch(reg(WatchKind::Child, b"/b", 2), rc::ZOK);
        l.arm_watch(reg(WatchKind::Child, b"/c", 0), rc::ZOK);
        let got = l.session_watchers();
        assert_eq!(got.last(), Some(&0));
        assert_eq!(got.len(), 3);
        let mut path_part = got[..2].to_vec();
        path_part.sort_unstable();
        assert_eq!(path_part, vec![1, 2]);
        // The tables do not change.
        assert!(l.has_watcher(b"/a", WTYPE_DATA, Some(&1)));

        // Legacy fan-out with no default watcher.
        let mut l = conn_with(Compat::LEGACY_C, None);
        l.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        assert_eq!(l.session_watchers(), vec![1]);

        // No fan-out: only the default watcher.
        let mut n = conn_with(Compat::NATIVE, Some(42));
        n.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        assert_eq!(n.session_watchers(), vec![42]);
        let mut n = native();
        n.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        assert!(n.session_watchers().is_empty());

        // Ordered tables with fan-out: table order, default last.
        let mut compat = Compat::NATIVE;
        compat.session_fanout_to_path_watchers = true;
        let mut o = conn_with(compat, Some(9));
        o.arm_watch(reg(WatchKind::Child, b"/a", 3), rc::ZOK);
        o.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        o.arm_watch(reg(WatchKind::Data, b"/b", 9), rc::ZOK);
        assert_eq!(o.session_watchers(), vec![1, 3, 9]);
    }

    fn decode_packet(op: i32, body: &[u8]) -> (i64, Vec<Vec<Vec<u8>>>) {
        let names = |v: &JVec<JString>| -> Vec<Vec<u8>> {
            v.iter()
                .map(|s| s.as_bytes().unwrap_or_default().to_vec())
                .collect()
        };
        if op == opcode::SET_WATCHES {
            let r = SetWatches::from_bytes(body).unwrap();
            (
                r.relative_zxid,
                vec![
                    names(&r.data_watches),
                    names(&r.exist_watches),
                    names(&r.child_watches),
                ],
            )
        } else {
            assert_eq!(op, opcode::SET_WATCHES2);
            let r = SetWatches2::from_bytes(body).unwrap();
            (
                r.relative_zxid,
                vec![
                    names(&r.data_watches),
                    names(&r.exist_watches),
                    names(&r.child_watches),
                    names(&r.persistent_watches),
                    names(&r.persistent_recursive_watches),
                ],
            )
        }
    }

    #[test]
    fn set_watches_batching_at_the_limit() {
        let k = |s: &str| s.as_bytes().to_vec();
        let keys = WatchKeys {
            data: vec![k("/aaaa"), k("/bbbb")],
            exist: vec![k("/cccc")],
            child: vec![k("/dddd"), k("/eeee")],
            persistent: Vec::new(),
            recursive: Vec::new(),
        };
        // Each key is 5 bytes. A limit of 10 holds two keys per packet.
        let packets = set_watches_packets(&keys, 77, Some(10));
        assert_eq!(packets.len(), 3);
        let decoded: Vec<_> = packets
            .iter()
            .map(|(op, b)| decode_packet(*op, b))
            .collect();
        assert!(packets.iter().all(|(op, _)| *op == opcode::SET_WATCHES));
        assert!(decoded.iter().all(|(z, _)| *z == 77));
        assert_eq!(
            decoded[0].1,
            vec![vec![k("/aaaa"), k("/bbbb")], vec![], vec![]]
        );
        assert_eq!(
            decoded[1].1,
            vec![vec![], vec![k("/cccc")], vec![k("/dddd")]]
        );
        assert_eq!(decoded[2].1, vec![vec![], vec![], vec![k("/eeee")]]);

        // One byte under the pair size splits every key.
        assert_eq!(set_watches_packets(&keys, 0, Some(9)).len(), 5);
        // No limit, or a large limit, gives one packet.
        assert_eq!(set_watches_packets(&keys, 0, None).len(), 1);
        assert_eq!(set_watches_packets(&keys, 0, Some(25)).len(), 1);
        assert_eq!(set_watches_packets(&keys, 0, Some(24)).len(), 2);
        // An oversized key goes alone.
        let big = WatchKeys {
            data: vec![k("/x"), vec![b'/'; 40], k("/y")],
            ..WatchKeys::default()
        };
        let p = set_watches_packets(&big, 0, Some(10));
        assert_eq!(p.len(), 3);
        // No key gives no packet.
        assert!(set_watches_packets(&WatchKeys::default(), 0, Some(10)).is_empty());
    }

    /// Rule: SetWatches splits at 128 KiB. A persistent key needs SetWatches2.
    #[test]
    fn set_watches_128k_split_and_setwatches2() {
        let keys = WatchKeys {
            data: (0..3000)
                .map(|i| format!("/node/{i:080}").into_bytes())
                .collect(),
            persistent: vec![b"/p".to_vec()],
            ..WatchKeys::default()
        };
        let packets = set_watches_packets(&keys, 5, Some(crate::compat::SET_WATCHES_BATCH));
        assert!(packets.len() > 1);
        let mut seen = 0usize;
        for (op, body) in &packets {
            let (_, lists) = decode_packet(*op, body);
            let bytes: usize = lists.iter().flatten().map(Vec::len).sum();
            assert!(bytes <= 128 * 1024);
            seen += lists.iter().map(Vec::len).sum::<usize>();
        }
        assert_eq!(seen, 3001);
        // Only the packet with the persistent key is SetWatches2.
        let ops: Vec<i32> = packets.iter().map(|(op, _)| *op).collect();
        assert_eq!(ops.last(), Some(&opcode::SET_WATCHES2));
        assert!(
            ops[..ops.len() - 1]
                .iter()
                .all(|op| *op == opcode::SET_WATCHES)
        );
    }

    #[test]
    fn ordered_tables_keep_insertion_order() {
        let mut n = native();
        for (i, p) in [&b"/b"[..], b"/a", b"/c"].iter().enumerate() {
            n.arm_watch(reg(WatchKind::Data, p, u32::try_from(i).unwrap()), rc::ZOK);
        }
        let keys = n.watches.keys();
        assert_eq!(
            keys.data,
            vec![b"/b".to_vec(), b"/a".to_vec(), b"/c".to_vec()]
        );
        // The fan-out of every watcher follows the same order.
        assert_eq!(n.watches.all_watchers(), vec![0, 1, 2]);
        // A path that leaves and comes back goes to the end.
        n.apply_unwatch(Unwatch {
            path: b"/b".to_vec(),
            wtype: WTYPE_ANY,
            watcher: None,
        });
        n.arm_watch(reg(WatchKind::Data, b"/b", 7), rc::ZOK);
        let keys = n.watches.keys();
        assert_eq!(
            keys.data,
            vec![b"/a".to_vec(), b"/c".to_vec(), b"/b".to_vec()]
        );
    }

    #[test]
    fn path_map_renumbers_at_the_counter_end() {
        let mut m: PathMap<u32> = PathMap::new();
        m.entry_or_default(b"/x").push(1);
        m.next_seq = u64::MAX;
        m.entry_or_default(b"/y").push(2);
        m.entry_or_default(b"/z").push(3);
        let keys: Vec<Vec<u8>> = m.keys().cloned().collect();
        assert_eq!(keys, vec![b"/x".to_vec(), b"/y".to_vec(), b"/z".to_vec()]);
        assert_eq!(m.get(b"/y"), Some(&vec![2]));
        assert_eq!(m.remove(b"/x"), Some(vec![1]));
        assert!(m.get(b"/x").is_none());
    }

    #[test]
    fn set_watches_keys_keep_the_chroot_and_c_order() {
        let mut l = legacy();
        for (i, p) in [&b"/app/a"[..], b"/app/b", b"/app/c"].iter().enumerate() {
            l.arm_watch(reg(WatchKind::Data, p, u32::try_from(i).unwrap()), rc::ZOK);
        }
        let keys = l.watches.keys();
        let Store::Legacy(t) = &l.watches.store else {
            panic!("legacy store expected");
        };
        let c_order: Vec<Vec<u8>> = t.data.keys().map(<[u8]>::to_vec).collect();
        assert_eq!(keys.data, c_order);
        assert!(keys.data.iter().all(|k| k.starts_with(b"/app/")));
    }

    #[test]
    fn queue_set_watches_noops() {
        // No watch: nothing is queued, and request_frame is not reached.
        let mut c = legacy();
        c.queue_set_watches();
        assert!(c.requests.tx.is_empty());
        // restore_watches false: nothing is queued.
        let mut cfg = Config::legacy(30_000);
        cfg.restore_watches = false;
        let mut c: Connection<Tk> = Connection::new(
            cfg,
            Compat::NATIVE,
            DriverMode::NATIVE,
            Box::new(FixedRng),
            Box::new(AllLevels),
            Box::new(Dw(None)),
            Millis(0),
        );
        c.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        c.queue_set_watches();
        assert!(c.requests.tx.is_empty());
    }

    #[test]
    fn clear_watches_by_reason() {
        // Legacy keeps the tables on expiry and clears them on close,
        // with no output.
        let mut l = legacy();
        l.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        l.clear_watches(TerminateReason::SessionExpired);
        l.clear_watches(TerminateReason::ConnectionLost);
        assert!(l.has_watcher(b"/a", WTYPE_DATA, Some(&1)));
        l.clear_watches(TerminateReason::Closed);
        assert!(!l.has_watcher(b"/a", WTYPE_DATA, Some(&1)));
        assert!(terminated(&mut l).is_empty());

        // Native clears on expiry and reports the watchers once.
        let mut n = native();
        n.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        n.arm_watch(reg(WatchKind::Child, b"/a", 1), rc::ZOK);
        n.arm_watch(reg(WatchKind::Persistent, b"/b", 2), rc::ZOK);
        // restore_watches is true, so a lost connection keeps the tables.
        n.clear_watches(TerminateReason::ConnectionLost);
        assert!(terminated(&mut n).is_empty());
        n.clear_watches(TerminateReason::SessionExpired);
        assert_eq!(
            terminated(&mut n),
            vec![(vec![1, 2], TerminateReason::SessionExpired)]
        );
        assert!(!n.has_watcher(b"/a", WTYPE_ANY, None));
        // Nothing left: no output.
        n.clear_watches(TerminateReason::Closed);
        assert!(terminated(&mut n).is_empty());
    }

    fn pending_with(reg: WatchReg<u32>) -> Pending<Tk> {
        Pending {
            xid: 1,
            shape: Shape::Data,
            route: Route::Queued,
            token: 0,
            watch: Some(reg),
            unwatch: None,
            written: false,
        }
    }

    #[test]
    fn detach_gives_hint_for_last_user() {
        let mut n = native();
        n.arm_watch(reg(WatchKind::Data, b"/a", 1), rc::ZOK);
        n.arm_watch(reg(WatchKind::Exist, b"/a", 2), rc::ZNONODE);
        n.arm_watch(reg(WatchKind::PersistentRecursive, b"/r", 3), rc::ZOK);
        // Another user of the data class remains.
        assert_eq!(n.detach_watcher(&1), None);
        assert!(!n.has_watcher(b"/a", WTYPE_DATA, Some(&1)));
        assert_eq!(
            n.detach_watcher(&2),
            Some(RemoveHint {
                path: JString::Bytes(b"/a".to_vec()),
                wtype: WTYPE_DATA
            })
        );
        assert_eq!(
            n.detach_watcher(&3),
            Some(RemoveHint {
                path: JString::Bytes(b"/r".to_vec()),
                wtype: WTYPE_RECURSIVE
            })
        );
        // An unknown watcher gives no hint.
        assert_eq!(n.detach_watcher(&99), None);
    }

    #[test]
    fn detach_counts_in_flight_registrations() {
        let mut n = native();
        n.arm_watch(reg(WatchKind::Child, b"/a", 1), rc::ZOK);
        n.requests
            .push_pending(pending_with(reg(WatchKind::Child, b"/a", 2)));
        assert_eq!(n.detach_watcher(&1), None);
        // An in-flight registration of another class does not count.
        n.arm_watch(reg(WatchKind::Data, b"/b", 4), rc::ZOK);
        n.requests
            .push_pending(pending_with(reg(WatchKind::Child, b"/b", 5)));
        assert_eq!(
            n.detach_watcher(&4),
            Some(RemoveHint {
                path: JString::Bytes(b"/b".to_vec()),
                wtype: WTYPE_DATA
            })
        );
    }

    #[test]
    fn detach_legacy_store() {
        let mut l = legacy();
        l.arm_watch(reg(WatchKind::Child, b"/a", 1), rc::ZOK);
        l.arm_watch(reg(WatchKind::Child, b"/a", 2), rc::ZOK);
        assert_eq!(l.detach_watcher(&1), None);
        assert_eq!(
            l.detach_watcher(&2),
            Some(RemoveHint {
                path: JString::Bytes(b"/a".to_vec()),
                wtype: WTYPE_CHILD
            })
        );
    }

    #[test]
    fn event_name_table() {
        assert_eq!(event_name(0), b"ZOO_ERROR_EVENT");
        assert_eq!(event_name(SESSION_EVENT), b"ZOO_SESSION_EVENT");
        assert_eq!(event_name(-2), b"ZOO_NOTWATCHING_EVENT");
        assert_eq!(event_name(DELETED_EVENT), b"ZOO_DELETED_EVENT");
    }
}
