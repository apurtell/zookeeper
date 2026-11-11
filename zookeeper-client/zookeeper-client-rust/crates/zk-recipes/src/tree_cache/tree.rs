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

//! The cached nodes of a `TreeCache`.
//!
//! A recursive watch never gives `NodeChildrenChanged`, so the tree keeps
//! each child list from the `NodeCreated` and `NodeDeleted` events and
//! from the reads of a sync.
//!
//! The tree applies three rules:
//!
//! - A read replaces a cached node only when it is newer: a different
//!   `czxid` (a new node with the same path) or a greater `mzxid`.
//! - A node enters the tree only below a cached parent. Thus each cached
//!   node has a chain of cached ancestors up to the root.
//! - A removal takes the node and its cached subtree, deepest first.
//!
//! A resync compares the old tree with a new full read by the same
//! rules. Each difference gives one event.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Bound;

use apache_zookeeper::{ZPath, ZPathBuf};

use super::{CachedNode, TreeEvent};

/// One cached node and the names of its cached children.
#[derive(Debug)]
struct Entry {
    /// The full path. The map key holds the same text.
    path: ZPathBuf,
    node: CachedNode,
    children: BTreeSet<String>,
}

/// The cached nodes by full path.
///
/// The map key is the path text. Thus a subtree is the node itself and
/// one key range, from `<path>/` up to `<path>0`. The character `0`
/// comes just after `/`.
#[derive(Debug)]
pub(super) struct Tree {
    root: ZPathBuf,
    nodes: BTreeMap<String, Entry>,
}

/// The depth of `path` below `root`, or `None` when `path` is not in
/// the subtree of `root`. The root has depth 0.
pub(super) fn depth(root: ZPath<'_>, path: ZPath<'_>) -> Option<usize> {
    if !path.starts_with(root) {
        return None;
    }
    path.components()
        .count()
        .checked_sub(root.components().count())
}

/// The absolute level of a path. Only the order of events uses it.
fn level(path: &str) -> usize {
    if path == "/" {
        0
    } else {
        path.matches('/').count()
    }
}

/// Sorts entries parents first: by level, then by path.
fn parents_first(a: &&Entry, b: &&Entry) -> std::cmp::Ordering {
    level(a.path.as_str())
        .cmp(&level(b.path.as_str()))
        .then_with(|| a.path.cmp(&b.path))
}

/// Sorts entries deepest first: by level from the bottom, then by path.
fn deepest_first(a: &&Entry, b: &&Entry) -> std::cmp::Ordering {
    Reverse(level(a.path.as_str()))
        .cmp(&Reverse(level(b.path.as_str())))
        .then_with(|| a.path.cmp(&b.path))
}

impl Tree {
    /// An empty tree for the subtree at `root`.
    pub(super) fn new(root: ZPathBuf) -> Self {
        Self {
            root,
            nodes: BTreeMap::new(),
        }
    }

    /// The root of the cached subtree.
    pub(super) fn root(&self) -> ZPath<'_> {
        self.root.as_path()
    }

    /// A snapshot of one node.
    pub(super) fn get(&self, path: ZPath<'_>) -> Option<CachedNode> {
        self.node(path).cloned()
    }

    /// The cached value of one node.
    pub(super) fn node(&self, path: ZPath<'_>) -> Option<&CachedNode> {
        self.nodes.get(path.as_str()).map(|e| &e.node)
    }

    /// The sorted child names of one node.
    pub(super) fn children(&self, path: ZPath<'_>) -> Option<Vec<String>> {
        self.nodes
            .get(path.as_str())
            .map(|e| e.children.iter().cloned().collect())
    }

    /// Puts `node` at `path`. A node that is there already keeps its
    /// child list. A node other than the root needs a cached parent.
    /// The result is false when the parent is missing, or when `path`
    /// is not in the subtree.
    pub(super) fn insert(&mut self, path: ZPath<'_>, node: CachedNode) -> bool {
        if depth(self.root.as_path(), path).is_none() {
            return false;
        }
        if let Some(e) = self.nodes.get_mut(path.as_str()) {
            e.node = node;
            return true;
        }
        if path != self.root.as_path() {
            let (Some(parent), Some(name)) = (path.parent(), path.name()) else {
                return false;
            };
            let Some(p) = self.nodes.get_mut(parent.as_str()) else {
                return false;
            };
            p.children.insert(name.to_owned());
        }
        self.nodes.insert(
            path.as_str().to_owned(),
            Entry {
                path: path.to_buf(),
                node,
                children: BTreeSet::new(),
            },
        );
        true
    }

    /// The keys of `path` and of its cached subtree.
    fn subtree_keys(&self, path: ZPath<'_>) -> Vec<String> {
        if path.is_root() {
            return self.nodes.keys().cloned().collect();
        }
        let p = path.as_str();
        let lower = format!("{p}/");
        let upper = format!("{p}0");
        let mut keys: Vec<String> = self
            .nodes
            .range::<str, _>((
                Bound::Included(lower.as_str()),
                Bound::Excluded(upper.as_str()),
            ))
            .map(|(k, _)| k.clone())
            .collect();
        if self.nodes.contains_key(p) {
            keys.push(p.to_owned());
        }
        keys
    }

    /// Removes `path` and its cached subtree. It queues one
    /// `NodeRemoved` for each node, deepest first.
    pub(super) fn remove_subtree(&mut self, path: ZPath<'_>, events: &mut VecDeque<TreeEvent>) {
        let keys = self.subtree_keys(path);
        if keys.is_empty() {
            return;
        }
        let mut removed: Vec<Entry> = keys.iter().filter_map(|k| self.nodes.remove(k)).collect();
        removed.sort_by(|a, b| deepest_first(&a, &b));
        for e in removed {
            events.push_back(TreeEvent::NodeRemoved {
                path: e.path,
                node: e.node,
            });
        }
        if let (Some(parent), Some(name)) = (path.parent(), path.name()) {
            if let Some(p) = self.nodes.get_mut(parent.as_str()) {
                p.children.remove(name);
            }
        }
    }

    /// Applies the result of one live read of `path`. A read with a new
    /// `czxid` or a greater `mzxid` replaces the cached node. `None`
    /// means that the node does not exist. The events that result go to
    /// `events`.
    pub(super) fn apply(
        &mut self,
        path: ZPath<'_>,
        read: Option<CachedNode>,
        events: &mut VecDeque<TreeEvent>,
    ) {
        let Some(new) = read else {
            self.remove_subtree(path, events);
            return;
        };
        match self.node(path).map(|n| n.stat) {
            Some(old) if old.czxid != new.stat.czxid => {
                // The node was deleted and created again. The old node
                // and its subtree are gone.
                self.remove_subtree(path, events);
                self.add(path, new, events);
            }
            Some(old) if new.stat.mzxid > old.mzxid => {
                if self.insert(path, new.clone()) {
                    events.push_back(TreeEvent::NodeUpdated {
                        path: path.to_buf(),
                        node: new,
                    });
                }
            }
            Some(_) => {}
            None => self.add(path, new, events),
        }
    }

    /// Inserts a new node and queues its `NodeAdded`.
    fn add(&mut self, path: ZPath<'_>, node: CachedNode, events: &mut VecDeque<TreeEvent>) {
        if self.insert(path, node.clone()) {
            events.push_back(TreeEvent::NodeAdded {
                path: path.to_buf(),
                node,
            });
        }
    }

    /// The entries, parents first.
    fn breadth_first(&self) -> Vec<&Entry> {
        let mut all: Vec<&Entry> = self.nodes.values().collect();
        all.sort_by(parents_first);
        all
    }

    /// Queues one `NodeAdded` for each node, parents first. The initial
    /// sync uses it.
    pub(super) fn added_events(&self, events: &mut VecDeque<TreeEvent>) {
        for e in self.breadth_first() {
            events.push_back(TreeEvent::NodeAdded {
                path: e.path.clone(),
                node: e.node.clone(),
            });
        }
    }

    /// Replaces this tree with `new`, the result of a full read. It
    /// queues one event for each difference:
    ///
    /// - First `NodeRemoved`, deepest first, for each node that is not
    ///   in `new` or has a different `czxid` there.
    /// - Then, parents first, `NodeAdded` for each node that is new or
    ///   has a different `czxid`, and `NodeUpdated` for each node with
    ///   a greater `mzxid`.
    ///
    /// A full read is never older than the cached copy. Thus a node
    /// with the same `czxid` and `mzxid` takes the new stat with no
    /// event. Only fields such as the child count can differ.
    pub(super) fn resync(&mut self, new: Tree, events: &mut VecDeque<TreeEvent>) {
        let mut gone: Vec<&Entry> = self
            .nodes
            .values()
            .filter(|e| {
                new.nodes
                    .get(e.path.as_str())
                    .is_none_or(|n| n.node.stat.czxid != e.node.stat.czxid)
            })
            .collect();
        gone.sort_by(deepest_first);
        for e in gone {
            events.push_back(TreeEvent::NodeRemoved {
                path: e.path.clone(),
                node: e.node.clone(),
            });
        }
        for e in new.breadth_first() {
            match self.node(e.path.as_path()).map(|o| o.stat) {
                Some(o) if o.czxid == e.node.stat.czxid => {
                    if e.node.stat.mzxid > o.mzxid {
                        events.push_back(TreeEvent::NodeUpdated {
                            path: e.path.clone(),
                            node: e.node.clone(),
                        });
                    }
                }
                _ => events.push_back(TreeEvent::NodeAdded {
                    path: e.path.clone(),
                    node: e.node.clone(),
                }),
            }
        }
        *self = new;
    }
}

#[cfg(test)]
mod tests {
    use apache_zookeeper::{Stat, Zxid};

    use super::*;

    fn p(s: &str) -> ZPath<'_> {
        ZPath::new(s).unwrap()
    }

    fn node(czxid: i64, mzxid: i64) -> CachedNode {
        CachedNode {
            stat: Stat {
                czxid: Zxid(czxid),
                mzxid: Zxid(mzxid),
                ..Stat::default()
            },
            data: None,
        }
    }

    fn tree(root: &str, nodes: &[(&str, i64, i64)]) -> Tree {
        let mut t = Tree::new(p(root).to_buf());
        for &(path, c, m) in nodes {
            assert!(t.insert(p(path), node(c, m)), "{path}");
        }
        t
    }

    fn names(events: &VecDeque<TreeEvent>) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                TreeEvent::NodeAdded { path, .. } => format!("+{path}"),
                TreeEvent::NodeUpdated { path, .. } => format!("~{path}"),
                TreeEvent::NodeRemoved { path, .. } => format!("-{path}"),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn depth_counts_components_below_the_root() {
        assert_eq!(depth(p("/"), p("/")), Some(0));
        assert_eq!(depth(p("/"), p("/a/b")), Some(2));
        assert_eq!(depth(p("/r"), p("/r")), Some(0));
        assert_eq!(depth(p("/r"), p("/r/a/b")), Some(2));
        assert_eq!(depth(p("/r"), p("/r2/a")), None);
        assert_eq!(depth(p("/r/a"), p("/r")), None);
    }

    #[test]
    fn insert_needs_a_cached_parent() {
        let mut t = tree("/r", &[("/r", 1, 1)]);
        assert!(!t.insert(p("/r/a/b"), node(3, 3)));
        assert!(!t.insert(p("/other"), node(3, 3)));
        assert!(t.insert(p("/r/a"), node(2, 2)));
        assert!(t.insert(p("/r/a/b"), node(3, 3)));
        assert_eq!(t.children(p("/r")).unwrap(), vec!["a"]);
        assert_eq!(t.children(p("/r/a")).unwrap(), vec!["b"]);
        // A replacement keeps the child list.
        assert!(t.insert(p("/r/a"), node(2, 9)));
        assert_eq!(t.children(p("/r/a")).unwrap(), vec!["b"]);
        assert_eq!(t.nodes.len(), 3);
    }

    #[test]
    fn remove_subtree_goes_deepest_first_and_spares_siblings() {
        let mut t = tree(
            "/r",
            &[
                ("/r", 1, 1),
                ("/r/a", 2, 2),
                ("/r/a/x", 3, 3),
                ("/r/a/y", 4, 4),
                ("/r/a/x/1", 5, 5),
                ("/r/a0", 6, 6),
                ("/r/a-b", 7, 7),
            ],
        );
        let mut ev = VecDeque::new();
        t.remove_subtree(p("/r/a"), &mut ev);
        assert_eq!(names(&ev), ["-/r/a/x/1", "-/r/a/x", "-/r/a/y", "-/r/a"]);
        assert_eq!(t.children(p("/r")).unwrap(), vec!["a-b", "a0"]);
        assert!(t.get(p("/r/a0")).is_some());
        assert!(t.get(p("/r/a-b")).is_some());

        let mut ev = VecDeque::new();
        t.remove_subtree(p("/r/missing"), &mut ev);
        assert!(ev.is_empty());
    }

    #[test]
    fn remove_of_the_slash_root_clears_all() {
        let mut t = tree("/", &[("/", 0, 0), ("/a", 1, 1), ("/a/b", 2, 2)]);
        let mut ev = VecDeque::new();
        t.remove_subtree(p("/"), &mut ev);
        assert_eq!(names(&ev), ["-/a/b", "-/a", "-/"]);
        assert!(t.nodes.is_empty());
    }

    #[test]
    fn apply_follows_the_czxid_and_mzxid_rule() {
        let mut t = tree("/r", &[("/r", 1, 1), ("/r/a", 2, 5), ("/r/a/k", 6, 6)]);
        let mut ev = VecDeque::new();

        // A read that is not newer changes nothing.
        t.apply(p("/r/a"), Some(node(2, 5)), &mut ev);
        t.apply(p("/r/a"), Some(node(2, 4)), &mut ev);
        assert!(ev.is_empty());

        // A greater mzxid updates the node and keeps its children.
        t.apply(p("/r/a"), Some(node(2, 7)), &mut ev);
        assert_eq!(names(&ev), ["~/r/a"]);
        assert_eq!(t.children(p("/r/a")).unwrap(), vec!["k"]);

        // A different czxid is a new node.
        ev.clear();
        t.apply(p("/r/a"), Some(node(8, 8)), &mut ev);
        assert_eq!(names(&ev), ["-/r/a/k", "-/r/a", "+/r/a"]);
        assert!(t.children(p("/r/a")).unwrap().is_empty());

        // A missing node goes away with its subtree.
        ev.clear();
        t.apply(p("/r/a"), None, &mut ev);
        assert_eq!(names(&ev), ["-/r/a"]);
        assert!(t.children(p("/r")).unwrap().is_empty());

        // A node with no cached parent does not enter.
        ev.clear();
        t.apply(p("/r/x/y"), Some(node(9, 9)), &mut ev);
        assert!(ev.is_empty());
    }

    #[test]
    fn resync_gives_one_event_for_each_difference() {
        let mut t = tree(
            "/r",
            &[
                ("/r", 1, 1),
                ("/r/same", 2, 2),
                ("/r/changed", 3, 3),
                ("/r/gone", 4, 4),
                ("/r/gone/kid", 5, 5),
                ("/r/again", 6, 6),
                ("/r/again/old", 7, 7),
            ],
        );
        let new = tree(
            "/r",
            &[
                ("/r", 1, 1),
                ("/r/same", 2, 2),
                ("/r/changed", 3, 10),
                ("/r/again", 11, 11),
                ("/r/new", 12, 12),
                ("/r/new/kid", 13, 13),
            ],
        );
        let mut ev = VecDeque::new();
        t.resync(new, &mut ev);
        assert_eq!(
            names(&ev),
            [
                "-/r/again/old",
                "-/r/gone/kid",
                "-/r/again",
                "-/r/gone",
                "+/r/again",
                "~/r/changed",
                "+/r/new",
                "+/r/new/kid",
            ]
        );
        assert_eq!(
            t.children(p("/r")).unwrap(),
            vec!["again", "changed", "new", "same"]
        );
    }

    #[test]
    fn added_events_are_parents_first() {
        let t = tree(
            "/r",
            &[
                ("/r", 1, 1),
                ("/r/b", 2, 2),
                ("/r/b/c", 3, 3),
                ("/r/z", 4, 4),
            ],
        );
        let mut ev = VecDeque::new();
        t.added_events(&mut ev);
        assert_eq!(names(&ev), ["+/r", "+/r/b", "+/r/z", "+/r/b/c"]);
    }
}
