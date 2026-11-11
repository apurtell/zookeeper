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

//! Decodes each jute record of the client from arbitrary bytes.
//!
//! The first byte selects the record. A decoded value must encode to the
//! bytes that the decoder used. The encoding must have the length that
//! `encoded_len` gives, and it must decode again to the same value.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use zk_jute::{Reader, Record};

fn check<R: Record + PartialEq + core::fmt::Debug>(data: &[u8]) {
    let mut r = Reader::new(data);
    let Ok(x) = R::decode(&mut r) else {
        return;
    };
    let used = data.len() - r.remaining();
    let y = x.to_bytes();
    assert_eq!(
        y.len(),
        x.encoded_len(),
        "encoded_len differs from the encoding"
    );
    assert_eq!(
        y.len(),
        used,
        "the encoding differs in length from the input"
    );
    let z = R::from_bytes(&y).expect("an encoding decodes again");
    assert_eq!(x, z, "the record changed in a round trip");
    assert_eq!(z.to_bytes(), y, "the encoding is not stable");
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let mut checks: Vec<fn(&[u8])> = Vec::new();
    macro_rules! add {
        ($m:ident, $r:ident) => {
            checks.push(check::<zk_jute::$m::$r>);
        };
    }
    zk_fuzz::for_each_record!(add);
    let f = checks[usize::from(sel) % checks.len()];
    f(rest);
});
