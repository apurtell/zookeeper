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

//! Checks the path rules of the native client and the legacy core.
//!
//! `ZPath::new` must accept a path exactly when the strict check of the
//! core accepts it. For a valid path, the parent, the name and the
//! components must give the path back. The legacy chroot helpers must
//! give back a path that they prefixed.

#![no_main]
#![forbid(unsafe_code)]

use apache_zookeeper::ZPath;
use libfuzzer_sys::fuzz_target;
use zk_fuzz::Cursor;
use zk_proto::legacy::chroot::{join_legacy, prepend_c, strip, strip_c, strip_event};
use zk_proto::legacy::path::is_valid_path;
use zk_proto::native::{join_component, strip_str, validate_path_strict};

fn check_zpath(s: &str) {
    let z = ZPath::new(s);
    assert_eq!(
        z.is_ok(),
        validate_path_strict(s, false).is_ok(),
        "ZPath and the core disagree"
    );
    let Ok(p) = z else {
        return;
    };
    assert_eq!(p.as_str(), s);
    let parts: Vec<&str> = p.components().collect();
    if p.is_root() {
        assert!(parts.is_empty());
        assert!(p.parent().is_none() && p.name().is_none());
        return;
    }
    assert_eq!(
        format!("/{}", parts.join("/")),
        s,
        "the components do not give the path"
    );
    let parent = p.parent().expect("a path below the root has a parent");
    let name = p.name().expect("a path below the root has a name");
    assert_eq!(parts.last().copied(), Some(name));
    assert!(p.starts_with(parent) && p.starts_with(ZPath::ROOT) && p.starts_with(p));
    let joined = parent.join(name).expect("the parent and the name join");
    assert_eq!(
        joined.as_str(),
        s,
        "the parent and the name do not give the path"
    );
    assert_eq!(
        validate_path_strict(s, true).is_ok(),
        ZPath::new(&format!("{s}1")).is_ok()
    );
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let mode = i32::from(c.u8() % 8);
    let root = c.lp();
    let path = c.rest();

    if let Ok(s) = std::str::from_utf8(path) {
        check_zpath(s);
        if let Ok(r) = std::str::from_utf8(root) {
            let full = join_component(Some(r), s);
            let (back, mismatch) = strip_str(Some(r), &full);
            if r.len() > 1 && ZPath::new(r).is_ok() && ZPath::new(s).is_ok() {
                assert!(!mismatch, "a joined path is inside the chroot");
                assert_eq!(back, s, "strip_str does not undo join_component");
            }
        }
    }

    let _ = is_valid_path(path, mode);
    let chroot = (!root.is_empty()).then_some(root);
    // The C reference: a path of one byte becomes the chroot itself.
    let full = prepend_c(chroot, path);
    let back = strip_c(chroot, &full);
    if path.len() > 1 {
        assert_eq!(back.path.as_ref(), path, "strip_c does not undo prepend_c");
    }
    // The Rust rule: a joined path strips back on a component boundary.
    if let Ok(joined) = join_legacy(chroot, path, mode) {
        assert!(
            is_valid_path(&joined, mode),
            "join_legacy gives a path that fails the check"
        );
        let s = strip(chroot, &joined);
        if chroot.is_some_and(|r| r.len() > 1) {
            assert!(!s.mismatch, "a joined path is inside the chroot");
            assert_eq!(s.path.as_ref(), path, "strip does not undo join_legacy");
        }
    }
    let _ = strip_event(chroot, path, mode & 1 == 1);
});
