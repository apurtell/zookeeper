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

//! Gives fuzz challenges to the DIGEST-MD5 mechanism of the native client.
//!
//! The first challenge goes through the challenge parser and the response
//! builder. A response must name the user and the `auth` quality of
//! protection. The second challenge goes through the `rspauth` check. A
//! mode byte selects fuzz bytes, no challenge, or the correct `rspauth`
//! with fuzz bytes after it. The harness computes the correct value from
//! the response, so the success path also runs. A good `rspauth` ends the
//! exchange, and the mechanism refuses each challenge after the end.
//!
//! The mechanism is private. The target reaches it through the
//! `apache_zookeeper::sasl::fuzzing` module, which only a fuzz build has.

#![no_main]
#![forbid(unsafe_code)]

use apache_zookeeper::SecretString;
use apache_zookeeper::sasl::fuzzing::digest_md5;
use libfuzzer_sys::fuzz_target;
use md5::{Digest, Md5};
use zk_fuzz::Cursor;

/// The client nonce of each run.
const CNONCE: &str = "0123456789abcdef0123456789abcdef";

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Splits a digest response into its directives. A quoted value loses its
/// quotes and its escapes.
fn directives(token: &[u8]) -> Vec<(&[u8], Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = token;
    while let Some(eq) = rest.iter().position(|&b| b == b'=') {
        let key = &rest[..eq];
        rest = &rest[eq + 1..];
        let mut value = Vec::new();
        if let Some((&b'"', tail)) = rest.split_first() {
            rest = tail;
            while let Some((&b, tail)) = rest.split_first() {
                rest = tail;
                match b {
                    b'"' => break,
                    b'\\' => {
                        if let Some((&n, tail)) = rest.split_first() {
                            value.push(n);
                            rest = tail;
                        }
                    }
                    _ => value.push(b),
                }
            }
        } else {
            let end = rest.iter().position(|&b| b == b',').unwrap_or(rest.len());
            value.extend_from_slice(&rest[..end]);
            rest = &rest[end..];
        }
        if let Some((&b',', tail)) = rest.split_first() {
            rest = tail;
        }
        out.push((key, value));
    }
    out
}

/// Gives the value of the directive `key`, or an empty value.
fn field<'a>(d: &'a [(&[u8], Vec<u8>)], key: &str) -> &'a [u8] {
    d.iter()
        .find(|(k, _)| *k == key.as_bytes())
        .map_or(&[][..], |(_, v)| v.as_slice())
}

/// Encodes a text for the hash as RFC 2831 asks: ISO 8859-1 when each
/// character fits, else UTF-8.
fn hash_text(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| u8::try_from(u32::from(c)).ok())
        .collect::<Option<Vec<u8>>>()
        .unwrap_or_else(|| s.as_bytes().to_vec())
}

/// Encodes a response value for the hash. Without the `utf-8` charset,
/// the response bytes are ISO 8859-1 already.
fn hash_wire(wire: &[u8], utf8: bool) -> Vec<u8> {
    if utf8 {
        hash_text(&String::from_utf8_lossy(wire))
    } else {
        wire.to_vec()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn md5(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// Computes the `rspauth` value of RFC 2831, section 2.1.3, from the
/// response of the client and the password. The values have no authzid.
fn rspauth(token: &[u8], password: &str) -> String {
    let d = directives(token);
    let utf8 = field(&d, "charset") == b"utf-8";
    let user = hash_wire(field(&d, "username"), utf8);
    let realm = hash_wire(field(&d, "realm"), utf8);
    let nonce = field(&d, "nonce");
    let cnonce = field(&d, "cnonce");
    let nc = field(&d, "nc");
    let qop = field(&d, "qop");
    let uri = field(&d, "digest-uri");
    let inner = md5(&[&user, b":", &realm, b":", &hash_text(password)]);
    let ha1 = hex(&md5(&[&inner, b":", nonce, b":", cnonce]));
    let ha2 = hex(&md5(&[b":", uri]));
    hex(&md5(&[
        ha1.as_bytes(),
        b":",
        nonce,
        b":",
        nc,
        b":",
        cnonce,
        b":",
        qop,
        b":",
        ha2.as_bytes(),
    ]))
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let user = text(c.lp());
    let pass = text(c.lp());
    let uri = if c.bool() {
        text(c.lp())
    } else {
        "zookeeper/zk-sasl-md5".to_owned()
    };
    let mut m = digest_md5(
        user,
        SecretString::new(pass.clone()),
        uri,
        CNONCE.to_owned(),
    );
    assert_eq!(m.name(), "DIGEST-MD5");
    let first = m.start().expect("DIGEST-MD5 starts");
    assert!(first.token.is_none() && !first.done);
    let ch1 = c.lp();
    let Ok(step) = m.step(Some(ch1)) else {
        return;
    };
    assert!(!step.done, "the first challenge does not end the exchange");
    let token = step.token.expect("a response goes to the server");
    let t = String::from_utf8_lossy(&token);
    assert!(t.contains("username=\""), "the response names the user");
    assert!(t.ends_with(",qop=auth"), "the response names qop=auth");
    let (ch2, good) = match c.u8() % 3 {
        0 => (Some(c.rest().to_vec()), false),
        1 => (None, false),
        _ => {
            let extra = c.rest();
            let mut ch = format!("rspauth={}", rspauth(&token, &pass)).into_bytes();
            ch.extend_from_slice(extra);
            (Some(ch), extra.is_empty())
        }
    };
    match m.step(ch2.as_deref()) {
        Ok(s) => {
            assert!(
                s.done && s.token.is_none(),
                "a good rspauth ends the exchange"
            );
            assert!(
                m.step(Some(b"rspauth=0")).is_err(),
                "no challenge follows the end"
            );
            assert!(m.step(None).is_err(), "no step follows the end");
        }
        Err(e) => assert!(!good, "the correct rspauth must pass: {e}"),
    }
});
