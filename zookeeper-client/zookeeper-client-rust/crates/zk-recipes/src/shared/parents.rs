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

//! Container parents.
//!
//! The lock path, the latch path and their missing ancestors are made
//! as `CreateMode::Container` nodes, as Curator's
//! `creatingParentContainersIfNeeded` makes them. The server removes a
//! container after its last child goes, so a lock path leaves no node
//! behind.
//!
//! The helper checks each level with `exists` first, so a client
//! without create permission on an existing level does not fail. The
//! server checks the read permission only of a node that exists
//! (ZOOKEEPER-2590). Thus a `NoAuth` reply to `exists` shows that the
//! level is present. This goes past Curator. Curator's `ZKPaths.mkdirs`
//! walks up from the leaf and calls `exists` on each level, up to the
//! first level that exists. It works only when a readable level that
//! exists lies below the unreadable ancestor. When the deepest level
//! that exists is unreadable, its `exists` fails with `NoAuth`, and the
//! Curator recipe fails.

use apache_zookeeper::acl::OPEN_ACL_UNSAFE;
use apache_zookeeper::{Client, CreateMode, Error, ZPath};

/// Makes each missing level of `path` as a container, from the top.
///
/// The `exists` reads go out together, and then the creates go out
/// together. The call order is the wire order, so each level
/// exists before its child is made. `NoAuth` on a read means that the
/// level exists. `NodeExists` counts as success, because another
/// participant can make the same level at the same time.
///
/// # Errors
///
/// The first error of a read other than `NoAuth`, or of a create other
/// than `NodeExists`. A `NoNode` means that the server removed a new
/// container before its child came. The caller then tries again.
pub(crate) async fn ensure_parents(client: &Client, path: ZPath<'_>) -> Result<(), Error> {
    let mut levels = Vec::new();
    let mut at = Some(path);
    while let Some(p) = at {
        if p.is_root() {
            break;
        }
        levels.push(p);
        at = p.parent();
    }
    levels.reverse();

    let checks: Vec<_> = levels.iter().map(|p| client.exists(*p)).collect();
    let mut missing = Vec::new();
    for (p, check) in levels.iter().zip(checks) {
        match check.await {
            Ok(Some(_)) | Err(Error::NoAuth) => {}
            Ok(None) => missing.push(*p),
            Err(e) => return Err(e),
        }
    }

    let creates: Vec<_> = missing
        .iter()
        .map(|p| client.create(*p, &[], CreateMode::Container, OPEN_ACL_UNSAFE))
        .collect();
    for create in creates {
        match create.await {
            Ok(_) | Err(Error::NodeExists) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
