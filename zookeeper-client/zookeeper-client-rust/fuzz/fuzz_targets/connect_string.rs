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

//! Parses connect strings with the legacy and the native parsers.
//!
//! A legacy host list must parse to the same entries after the sim
//! joins the entries again. `parse_init` must agree with
//! `parse_servers` on its host text. A native chroot must pass the
//! strict path check.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use zk_proto::legacy::connect::{HostSpec, parse_init, parse_servers};
use zk_proto::native::{parse_connect_string_native, validate_path_strict};

fn join(hosts: &[HostSpec]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&h.host);
        out.push(b':');
        out.extend_from_slice(&h.service);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if let Ok(hosts) = parse_servers(data) {
        let again = parse_servers(&join(&hosts)).expect("a joined list parses again");
        assert_eq!(hosts, again, "the host list changed in a round trip");
        for h in &hosts {
            assert_ne!(h.port, 0, "a parsed entry has a port");
        }
    }
    match parse_init(data) {
        Ok(cs) => {
            // A string that starts with the chroot has no hosts. The
            // resolution step then fails, as C does.
            assert_eq!(cs.hosts.is_empty(), cs.host_text.is_empty());
            let hosts = parse_servers(&cs.host_text).expect("the host text parses alone");
            assert_eq!(hosts, cs.hosts);
            if let Some(root) = &cs.chroot {
                assert!(root.len() > 1 && root.first() == Some(&b'/'));
            }
        }
        Err(e) => assert_ne!(e.rc, 0, "a parse error has a nonzero rc"),
    }
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(cs) = parse_connect_string_native(s)
    {
        assert!(
            !cs.hosts.is_empty(),
            "the native parser gives at least one host"
        );
        if let Some(root) = &cs.chroot {
            assert!(validate_path_strict(root, false).is_ok());
            assert!(s.contains(root.as_str()));
        }
    }
});
