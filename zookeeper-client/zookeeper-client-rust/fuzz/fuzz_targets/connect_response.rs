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

//! Decodes connect responses, alone and in a session.
//!
//! The direct check decodes the body with `decode_connect_response` and
//! encodes the fields again. The session check gives the body to a
//! connection as the first server frame, then runs the fuzz program.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use zk_fuzz::Cursor;
use zk_fuzz::sim::{Options, Sim, connect_response};
use zk_jute::handshake::{CONNECT_RESPONSE_LEN, CONNECT_RESPONSE_OLD_LEN, decode_connect_response};

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let opts = Options::read(&mut c);
    let body = c.lp();
    match decode_connect_response(body) {
        Ok(r) => {
            let long = body.len() == CONNECT_RESPONSE_LEN;
            assert!(long || body.len() == CONNECT_RESPONSE_OLD_LEN);
            let ro = long.then_some(r.read_only);
            let again = connect_response(
                r.protocol_version,
                r.time_out,
                r.session_id,
                r.passwd_len,
                &r.passwd,
                ro,
            );
            // Any nonzero read-only byte reads as true.
            let n = CONNECT_RESPONSE_OLD_LEN;
            assert_eq!(
                again[..n],
                body[..n],
                "the fields do not encode to the input"
            );
            if long {
                assert_eq!(again[n] != 0, body[n] != 0);
            }
        }
        Err(e) => {
            assert_eq!(e.len, body.len());
            assert!(body.len() != CONNECT_RESPONSE_LEN && body.len() != CONNECT_RESPONSE_OLD_LEN);
        }
    }
    let mut sim = Sim::new(opts);
    sim.settle();
    sim.push_frame(body);
    sim.run_commands(&mut c);
    sim.finish();
});
