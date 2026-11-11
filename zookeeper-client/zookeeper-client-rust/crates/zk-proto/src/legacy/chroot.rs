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

//! Chroot join and strip.
//!
//! The C client joins a chroot and a path with a byte concatenation
//! (`prepend_string`). It strips the chroot from a server path with a byte
//! prefix test that ignores component boundaries (`sub_string`). This module
//! has exact ports of both functions as a reference.
//!
//! The Rust core applies these rules instead:
//!
//! - Under a chroot, a client path must start with `/`. A relative or empty
//!   path is a bad argument. The path `/` maps to the chroot, except for a
//!   sequential create, which is a bad argument because it escapes the chroot.
//!   Other paths get the chroot as a byte prefix.
//! - A server path loses the chroot only on a `/` boundary. A path such as
//!   `/app2/x` under the chroot `/app` stays as it is, and the caller gets a
//!   mismatch flag for its warning.
//! - The configuration node `/zookeeper/config` never gets the chroot on a
//!   request. The native client also delivers its events without a strip.
//!
//! A chroot of `/` or an empty chroot means no chroot, as the connect string
//! parsers give it.

use std::borrow::Cow;

use super::path::{is_sequence, is_valid_path};

/// The configuration node (`ZOO_CONFIG_NODE`).
pub const CONFIG_NODE: &[u8] = b"/zookeeper/config";

/// The C return code for a bad argument (`ZBADARGUMENTS`).
pub const ZBADARGUMENTS: i32 = -8;

/// The result of a strip of the chroot from a server path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stripped<'a> {
    /// The path for the application.
    pub path: Cow<'a, [u8]>,
    /// True when the server path is not inside the chroot. The path is then
    /// the raw server path, and the caller logs the C error line "server path
    /// %s does not include chroot path %s".
    pub mismatch: bool,
}

/// The reason why a client path cannot be joined with the chroot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JoinError {
    /// Under a chroot, the path does not start with `/`.
    NotAbsolute,
    /// A sequential create on `/` under a chroot. The server would create
    /// the node outside the chroot.
    SequentialOnRoot,
    /// The joined path fails the legacy path check.
    InvalidPath,
}

impl JoinError {
    /// Returns the C return code for the error. All errors are
    /// `ZBADARGUMENTS`.
    pub fn rc(self) -> i32 {
        ZBADARGUMENTS
    }
}

/// Gives the chroot when it is a real chroot: not `None`, not empty and not
/// `/`.
fn effective(chroot: Option<&[u8]>) -> Option<&[u8]> {
    chroot.filter(|c| c.len() > 1)
}

/// Returns true when the path is the configuration node.
pub fn is_config_node(path: &[u8]) -> bool {
    path == CONFIG_NODE
}

/// The exact C join (`prepend_string`).
///
/// Without a chroot the path is unchanged. With a chroot, any path of one
/// byte becomes the chroot, and any other path is appended to the chroot as
/// bytes. This is the reference for the C behavior, not the Rust rule.
pub fn prepend_c<'a>(chroot: Option<&[u8]>, path: &'a [u8]) -> Cow<'a, [u8]> {
    let Some(root) = chroot else {
        return Cow::Borrowed(path);
    };
    if path.len() == 1 {
        return Cow::Owned(root.to_vec());
    }
    let mut out = Vec::with_capacity(root.len().saturating_add(path.len()));
    out.extend_from_slice(root);
    out.extend_from_slice(path);
    Cow::Owned(out)
}

/// The exact C strip (`sub_string`).
///
/// C tests the chroot as a byte prefix with no `/` boundary, so `/app2/x`
/// under `/app` becomes `2/x`. A path equal to the chroot becomes `/`. This
/// is the reference for the C behavior, not the Rust rule.
pub fn strip_c<'a>(chroot: Option<&[u8]>, server: &'a [u8]) -> Stripped<'a> {
    let Some(root) = chroot else {
        return Stripped {
            path: Cow::Borrowed(server),
            mismatch: false,
        };
    };
    match server.strip_prefix(root) {
        None => Stripped {
            path: Cow::Borrowed(server),
            mismatch: true,
        },
        Some([]) => Stripped {
            path: Cow::Borrowed(b"/"),
            mismatch: false,
        },
        Some(rest) => Stripped {
            path: Cow::Borrowed(rest),
            mismatch: false,
        },
    }
}

/// Joins a client path with the chroot under the Rust drop-in rule, and runs
/// the legacy path check on the result.
///
/// Without a chroot the path is checked as it is. The `mode` is the C create
/// mode, or 0 for an operation that is not a create.
pub fn join_legacy<'a>(
    chroot: Option<&[u8]>,
    path: &'a [u8],
    mode: i32,
) -> Result<Cow<'a, [u8]>, JoinError> {
    let joined = match effective(chroot) {
        None => Cow::Borrowed(path),
        Some(root) => {
            if path.first() != Some(&b'/') {
                return Err(JoinError::NotAbsolute);
            }
            if path == b"/" {
                if is_sequence(mode) {
                    return Err(JoinError::SequentialOnRoot);
                }
                Cow::Owned(root.to_vec())
            } else {
                prepend_c(Some(root), path)
            }
        }
    };
    if is_valid_path(&joined, mode) {
        Ok(joined)
    } else {
        Err(JoinError::InvalidPath)
    }
}

/// Joins a validated client path with the chroot on a component boundary,
/// for the native client.
///
/// The path must already pass the strict check, so it starts with `/`. The
/// path `/` maps to the chroot. The caller rejects a sequential create on
/// `/` under a chroot before the join.
pub fn join_component<'a>(chroot: Option<&str>, path: &'a str) -> Cow<'a, str> {
    match chroot.filter(|c| c.len() > 1) {
        None => Cow::Borrowed(path),
        Some(root) if path == "/" => Cow::Owned(root.to_owned()),
        Some(root) => {
            let mut out = String::with_capacity(root.len().saturating_add(path.len()));
            out.push_str(root);
            out.push_str(path);
            Cow::Owned(out)
        }
    }
}

/// Gives the length of the chroot prefix of `server` when `server` is inside
/// the chroot on a `/` boundary.
fn boundary_prefix(root: &[u8], server: &[u8]) -> Option<usize> {
    let rest = server.strip_prefix(root)?;
    if rest.is_empty() || rest.first() == Some(&b'/') {
        Some(root.len())
    } else {
        None
    }
}

/// Strips the chroot from a server path on a `/` boundary, for both clients.
///
/// A path equal to the chroot becomes `/`. A path below the chroot loses the
/// chroot. Any other path stays as it is, with the mismatch flag set.
pub fn strip<'a>(chroot: Option<&[u8]>, server: &'a [u8]) -> Stripped<'a> {
    let Some(root) = effective(chroot) else {
        return Stripped {
            path: Cow::Borrowed(server),
            mismatch: false,
        };
    };
    match boundary_prefix(root, server) {
        None => Stripped {
            path: Cow::Borrowed(server),
            mismatch: true,
        },
        Some(n) => match server.get(n..) {
            Some([]) | None => Stripped {
                path: Cow::Borrowed(b"/"),
                mismatch: false,
            },
            Some(rest) => Stripped {
                path: Cow::Borrowed(rest),
                mismatch: false,
            },
        },
    }
}

/// Strips the chroot from the path of a watch event.
///
/// With `config_bypass` set, as in the native client, the configuration node
/// outside the chroot comes back as it is, with no mismatch. Otherwise the
/// function is [`strip`].
pub fn strip_event<'a>(
    chroot: Option<&[u8]>,
    server: &'a [u8],
    config_bypass: bool,
) -> Stripped<'a> {
    let s = strip(chroot, server);
    if config_bypass && s.mismatch && is_config_node(server) {
        return Stripped {
            path: Cow::Borrowed(server),
            mismatch: false,
        };
    }
    s
}

/// The text form of [`strip`], for the native client.
///
/// The function gives the path for the application and the mismatch flag.
pub fn strip_str<'a>(chroot: Option<&str>, server: &'a str) -> (&'a str, bool) {
    let Some(root) = chroot.filter(|c| c.len() > 1) else {
        return (server, false);
    };
    match boundary_prefix(root.as_bytes(), server.as_bytes()) {
        None => (server, true),
        // The prefix ends before a '/' byte or at the end, which is always a
        // character boundary.
        Some(n) => match server.get(n..) {
            Some("") | None => ("/", false),
            Some(rest) => (rest, false),
        },
    }
}
