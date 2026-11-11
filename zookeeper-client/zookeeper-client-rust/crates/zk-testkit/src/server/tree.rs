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

//! The znode tree of the server model.
//!
//! The tree follows the Java `DataTree` rules for paths, versions,
//! sequential names and ephemeral owners. It does not enforce ACLs. Each
//! write returns the watch triggers that it causes, and the server fires
//! them after the write commits.

use std::collections::{BTreeMap, BTreeSet};

use zk_jute::data::{ACL, Stat};
use zk_jute::rc;

/// The Java `EventType.NodeCreated` value.
pub const EVENT_CREATED: i32 = 1;
/// The Java `EventType.NodeDeleted` value.
pub const EVENT_DELETED: i32 = 2;
/// The Java `EventType.NodeDataChanged` value.
pub const EVENT_DATA_CHANGED: i32 = 3;
/// The Java `EventType.NodeChildrenChanged` value.
pub const EVENT_CHILDREN_CHANGED: i32 = 4;

/// The `CreateMode` flag value of a persistent node.
pub const MODE_PERSISTENT: i32 = 0;
/// The `CreateMode` flag value of an ephemeral node.
pub const MODE_EPHEMERAL: i32 = 1;
/// The `CreateMode` flag value of a persistent sequential node.
pub const MODE_PERSISTENT_SEQUENTIAL: i32 = 2;
/// The `CreateMode` flag value of an ephemeral sequential node.
pub const MODE_EPHEMERAL_SEQUENTIAL: i32 = 3;
/// The `CreateMode` flag value of a container node.
pub const MODE_CONTAINER: i32 = 4;
/// The `CreateMode` flag value of a persistent node with a TTL.
pub const MODE_PERSISTENT_WITH_TTL: i32 = 5;
/// The `CreateMode` flag value of a persistent sequential node with a TTL.
pub const MODE_PERSISTENT_SEQUENTIAL_WITH_TTL: i32 = 6;

/// One znode.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Node {
    /// The data of the node.
    pub data: Vec<u8>,
    /// The ACL of the node. The model stores it and does not check it.
    pub acl: Vec<ACL>,
    /// The stat of the node. `data_length` and `num_children` stay
    /// current.
    pub stat: Stat,
    /// The names of the children, in byte order.
    pub children: BTreeSet<Vec<u8>>,
    /// The create flags of the node.
    pub mode: i32,
    /// The TTL of the node, or -1.
    pub ttl: i64,
}

/// A watch trigger that a write causes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trigger {
    /// The path of the event.
    pub path: Vec<u8>,
    /// The Java event type.
    pub event_type: i32,
}

fn trigger(path: &[u8], event_type: i32) -> Trigger {
    Trigger {
        path: path.to_vec(),
        event_type,
    }
}

/// Returns the parent of a valid path. The parent of `/` is `None`.
#[must_use]
pub fn parent_of(path: &[u8]) -> Option<&[u8]> {
    if path == b"/" {
        return None;
    }
    let cut = path.iter().rposition(|b| *b == b'/')?;
    if cut == 0 {
        Some(b"/")
    } else {
        path.get(..cut)
    }
}

/// Returns the last component of a valid path.
#[must_use]
pub fn name_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(cut) => path.get(cut.saturating_add(1)..).unwrap_or_default(),
        None => path,
    }
}

/// Joins a parent path and a child name.
#[must_use]
pub fn join(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = parent.to_vec();
    if p != b"/" {
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

/// Checks a path with the Java `PathUtils.validatePath` rules.
///
/// # Errors
///
/// Returns `ZBADARGUMENTS` for a path that the Java server rejects.
pub fn validate_path(path: &[u8], sequential: bool) -> Result<(), i32> {
    let bad = Err(rc::ZBADARGUMENTS);
    if path.first() != Some(&b'/') {
        return bad;
    }
    if path.len() == 1 {
        return Ok(());
    }
    let body = if sequential && path.last() == Some(&b'/') {
        path.get(..path.len().saturating_sub(1)).unwrap_or_default()
    } else {
        path
    };
    if body.last() == Some(&b'/') || body.contains(&0) {
        return bad;
    }
    for comp in body.split(|b| *b == b'/').skip(1) {
        if comp.is_empty() || comp == b"." || comp == b".." {
            return bad;
        }
    }
    Ok(())
}

/// Returns true for a sequential create mode.
#[must_use]
pub const fn is_sequential(mode: i32) -> bool {
    matches!(
        mode,
        MODE_PERSISTENT_SEQUENTIAL
            | MODE_EPHEMERAL_SEQUENTIAL
            | MODE_PERSISTENT_SEQUENTIAL_WITH_TTL
    )
}

/// Returns true for an ephemeral create mode.
#[must_use]
pub const fn is_ephemeral(mode: i32) -> bool {
    matches!(mode, MODE_EPHEMERAL | MODE_EPHEMERAL_SEQUENTIAL)
}

/// Returns true for a TTL create mode.
#[must_use]
pub const fn is_ttl(mode: i32) -> bool {
    matches!(
        mode,
        MODE_PERSISTENT_WITH_TTL | MODE_PERSISTENT_SEQUENTIAL_WITH_TTL
    )
}

/// The inputs of one create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateArgs<'a> {
    /// The requested path.
    pub path: &'a [u8],
    /// The data.
    pub data: &'a [u8],
    /// The ACL.
    pub acl: &'a [ACL],
    /// The create flags.
    pub mode: i32,
    /// The TTL, or -1.
    pub ttl: i64,
    /// The session that owns an ephemeral node.
    pub session: i64,
}

/// The znode tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataTree {
    nodes: BTreeMap<Vec<u8>, Node>,
}

impl Default for DataTree {
    fn default() -> Self {
        Self::new()
    }
}

impl DataTree {
    /// Makes a tree with `/`, `/zookeeper`, `/zookeeper/config` and
    /// `/zookeeper/quota`.
    #[must_use]
    pub fn new() -> Self {
        let mut t = Self {
            nodes: BTreeMap::new(),
        };
        t.nodes.insert(b"/".to_vec(), Node::default());
        for p in [
            &b"/zookeeper"[..],
            b"/zookeeper/config",
            b"/zookeeper/quota",
        ] {
            t.insert_raw(p);
        }
        t
    }

    fn insert_raw(&mut self, path: &[u8]) {
        if let Some(parent) = parent_of(path) {
            if let Some(pn) = self.nodes.get_mut(parent) {
                pn.children.insert(name_of(path).to_vec());
                pn.stat.num_children = len_i32(pn.children.len());
            }
        }
        self.nodes.insert(
            path.to_vec(),
            Node {
                ttl: -1,
                ..Node::default()
            },
        );
    }

    /// Returns the node at `path`.
    #[must_use]
    pub fn get(&self, path: &[u8]) -> Option<&Node> {
        self.nodes.get(path)
    }

    /// Returns true when a node exists at `path`.
    #[must_use]
    pub fn contains(&self, path: &[u8]) -> bool {
        self.nodes.contains_key(path)
    }

    /// Returns the number of nodes, the root included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns false. A tree always has its root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns every path, in byte order.
    pub fn paths(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.nodes.keys()
    }

    /// Returns the child names of `path`, in byte order.
    ///
    /// # Errors
    ///
    /// Returns `ZNONODE` when the node does not exist.
    pub fn children(&self, path: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
        self.nodes
            .get(path)
            .map(|n| n.children.iter().cloned().collect())
            .ok_or(rc::ZNONODE)
    }

    /// Returns the number of nodes below `path`, as Java
    /// `getAllChildrenNumber` does.
    ///
    /// # Errors
    ///
    /// Returns `ZNONODE` when the node does not exist.
    pub fn all_children_number(&self, path: &[u8]) -> Result<i32, i32> {
        if !self.nodes.contains_key(path) {
            return Err(rc::ZNONODE);
        }
        let n = self
            .nodes
            .keys()
            .filter(|p| p.as_slice() != path && is_below(p, path))
            .count();
        Ok(len_i32(n))
    }

    /// Returns the ephemeral paths of `session` that start with `prefix`,
    /// in byte order.
    #[must_use]
    pub fn ephemerals(&self, session: i64, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.nodes
            .iter()
            .filter(|(p, n)| {
                n.stat.ephemeral_owner == session && is_ephemeral(n.mode) && p.starts_with(prefix)
            })
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// Creates a node.
    ///
    /// The checks run in the Java order: path, ACL, TTL, parent, existing
    /// node, ephemeral parent. It returns the actual path and the stat.
    ///
    /// # Errors
    ///
    /// Returns the Java error code of the first failed check.
    pub fn create(
        &mut self,
        a: &CreateArgs<'_>,
        zxid: i64,
        time: i64,
        out: &mut Vec<Trigger>,
    ) -> Result<(Vec<u8>, Stat), i32> {
        let seq = is_sequential(a.mode);
        validate_path(a.path, seq)?;
        if a.path == b"/" {
            return Err(rc::ZNODEEXISTS);
        }
        if a.acl.is_empty() {
            return Err(rc::ZINVALIDACL);
        }
        if !(0..=MODE_PERSISTENT_SEQUENTIAL_WITH_TTL).contains(&a.mode) {
            return Err(rc::ZBADARGUMENTS);
        }
        if is_ttl(a.mode) && a.ttl <= 0 {
            return Err(rc::ZBADARGUMENTS);
        }
        let parent_path = parent_of(a.path).ok_or(rc::ZBADARGUMENTS)?.to_vec();
        let parent = self.nodes.get(&parent_path).ok_or(rc::ZNONODE)?;
        let mut path = a.path.to_vec();
        if seq {
            path.extend_from_slice(format!("{:010}", parent.stat.cversion).as_bytes());
        }
        validate_path(&path, false)?;
        if self.nodes.contains_key(&path) {
            return Err(rc::ZNODEEXISTS);
        }
        if is_ephemeral(parent.mode) {
            return Err(rc::ZNOCHILDRENFOREPHEMERALS);
        }
        let stat = Stat {
            czxid: zxid,
            mzxid: zxid,
            ctime: time,
            mtime: time,
            version: 0,
            cversion: 0,
            aversion: 0,
            ephemeral_owner: if is_ephemeral(a.mode) { a.session } else { 0 },
            data_length: len_i32(a.data.len()),
            num_children: 0,
            pzxid: zxid,
        };
        self.nodes.insert(
            path.clone(),
            Node {
                data: a.data.to_vec(),
                acl: a.acl.to_vec(),
                stat: stat.clone(),
                children: BTreeSet::new(),
                mode: a.mode,
                ttl: a.ttl,
            },
        );
        if let Some(pn) = self.nodes.get_mut(&parent_path) {
            pn.children.insert(name_of(&path).to_vec());
            pn.stat.cversion = pn.stat.cversion.wrapping_add(1);
            pn.stat.pzxid = zxid;
            pn.stat.num_children = len_i32(pn.children.len());
        }
        out.push(trigger(&path, EVENT_CREATED));
        out.push(trigger(&parent_path, EVENT_CHILDREN_CHANGED));
        Ok((path, stat))
    }

    /// Deletes a node.
    ///
    /// # Errors
    ///
    /// Returns `ZBADARGUMENTS`, `ZNONODE`, `ZBADVERSION` or `ZNOTEMPTY`.
    pub fn delete(
        &mut self,
        path: &[u8],
        version: i32,
        zxid: i64,
        out: &mut Vec<Trigger>,
    ) -> Result<(), i32> {
        validate_path(path, false)?;
        let parent_path = parent_of(path).ok_or(rc::ZBADARGUMENTS)?.to_vec();
        if !self.nodes.contains_key(&parent_path) {
            return Err(rc::ZNONODE);
        }
        let node = self.nodes.get(path).ok_or(rc::ZNONODE)?;
        if version != -1 && version != node.stat.version {
            return Err(rc::ZBADVERSION);
        }
        if !node.children.is_empty() {
            return Err(rc::ZNOTEMPTY);
        }
        self.nodes.remove(path);
        if let Some(pn) = self.nodes.get_mut(&parent_path) {
            pn.children.remove(name_of(path));
            pn.stat.cversion = pn.stat.cversion.wrapping_add(1);
            pn.stat.pzxid = zxid;
            pn.stat.num_children = len_i32(pn.children.len());
        }
        out.push(trigger(path, EVENT_DELETED));
        out.push(trigger(&parent_path, EVENT_CHILDREN_CHANGED));
        Ok(())
    }

    /// Checks the version of a node, as the multi `check` op does.
    ///
    /// # Errors
    ///
    /// Returns `ZBADARGUMENTS`, `ZNONODE` or `ZBADVERSION`.
    pub fn check(&self, path: &[u8], version: i32) -> Result<(), i32> {
        validate_path(path, false)?;
        let node = self.nodes.get(path).ok_or(rc::ZNONODE)?;
        if version != -1 && version != node.stat.version {
            return Err(rc::ZBADVERSION);
        }
        Ok(())
    }

    /// Sets the data of a node and returns its new stat.
    ///
    /// # Errors
    ///
    /// Returns `ZBADARGUMENTS`, `ZNONODE` or `ZBADVERSION`.
    pub fn set_data(
        &mut self,
        path: &[u8],
        data: &[u8],
        version: i32,
        zxid: i64,
        time: i64,
        out: &mut Vec<Trigger>,
    ) -> Result<Stat, i32> {
        validate_path(path, false)?;
        let node = self.nodes.get_mut(path).ok_or(rc::ZNONODE)?;
        if version != -1 && version != node.stat.version {
            return Err(rc::ZBADVERSION);
        }
        node.data = data.to_vec();
        node.stat.version = node.stat.version.wrapping_add(1);
        node.stat.mzxid = zxid;
        node.stat.mtime = time;
        node.stat.data_length = len_i32(data.len());
        out.push(trigger(path, EVENT_DATA_CHANGED));
        Ok(node.stat.clone())
    }

    /// Sets the ACL of a node and returns its new stat.
    ///
    /// # Errors
    ///
    /// Returns `ZBADARGUMENTS`, `ZINVALIDACL`, `ZNONODE` or `ZBADVERSION`.
    pub fn set_acl(&mut self, path: &[u8], acl: &[ACL], version: i32) -> Result<Stat, i32> {
        validate_path(path, false)?;
        if acl.is_empty() {
            return Err(rc::ZINVALIDACL);
        }
        let node = self.nodes.get_mut(path).ok_or(rc::ZNONODE)?;
        if version != -1 && version != node.stat.aversion {
            return Err(rc::ZBADVERSION);
        }
        node.acl = acl.to_vec();
        node.stat.aversion = node.stat.aversion.wrapping_add(1);
        Ok(node.stat.clone())
    }

    /// Deletes every ephemeral node of `session`, deepest first.
    pub fn kill_session(&mut self, session: i64, zxid: i64, out: &mut Vec<Trigger>) {
        let mut paths = self.ephemerals(session, b"/");
        paths.sort_by(|a, b| b.cmp(a));
        for p in paths {
            let _ = self.delete(&p, -1, zxid, out);
        }
    }
}

/// Returns true when `path` is `root` or below it.
#[must_use]
pub fn is_below(path: &[u8], root: &[u8]) -> bool {
    if root == b"/" {
        return path.first() == Some(&b'/');
    }
    match path.strip_prefix(root) {
        Some(rest) => rest.is_empty() || rest.first() == Some(&b'/'),
        None => false,
    }
}

fn len_i32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}
