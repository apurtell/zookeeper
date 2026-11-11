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

//! The built-in DIGEST-MD5 client (RFC 2831).
//!
//! The mechanism supports `qop=auth` only, as the Java server and the C
//! client do. It makes a random client nonce for each connection with
//! `getrandom`, and computes the digests with the `md-5` crate. It reads
//! the password from the [`CredentialSource`] once per connection. The
//! password and the derived secrets stay in zeroizing buffers.
//!
//! zk-proto sends the empty initial response. The mechanism answers the
//! first challenge with the digest response, and it checks `rspauth` in
//! the second challenge.

use std::sync::Arc;

use md5::{Digest, Md5};
use zeroize::Zeroizing;

use crate::secret::SecretString;

use super::{
    CredentialSource, SaslContext, SaslError, SaslErrorKind, SaslMechanism, SaslMechanismFactory,
    SaslStep,
};

/// The mechanism name.
pub(crate) const NAME: &str = "DIGEST-MD5";

/// The largest challenge that the parser reads (RFC 2831, section
/// 2.1.1). A larger challenge is a mechanism error.
pub(crate) const MAX_CHALLENGE: usize = 2048;

/// The largest number of directives in one challenge. A challenge with
/// more directives is a mechanism error.
pub(crate) const MAX_DIRECTIVES: usize = 32;

/// The length of the client nonce before the encoding, in bytes.
pub(crate) const CNONCE_BYTES: usize = 16;

/// The nonce count of the only response (RFC 2831, section 2.1.2).
const NONCE_COUNT: &str = "00000001";

/// The quality of protection. Only authentication is supported.
const QOP: &str = "auth";

/// The `maxbuf` value of the response. It is the RFC default.
const MAXBUF: &str = "65536";

/// The factory of [`DigestMd5`] sessions.
pub(crate) struct DigestMd5Factory {
    /// The authentication identity.
    username: String,
    /// The source of the password.
    password: Arc<dyn CredentialSource>,
    /// The service of the `digest-uri`.
    service: String,
    /// The host of the `digest-uri`.
    server_name: String,
}

impl DigestMd5Factory {
    /// Makes the factory.
    pub(crate) fn new(
        username: String,
        password: Arc<dyn CredentialSource>,
        service: String,
        server_name: String,
    ) -> Self {
        Self {
            username,
            password,
            service,
            server_name,
        }
    }
}

impl SaslMechanismFactory for DigestMd5Factory {
    /// Reads the password and makes a session with a new client nonce. A
    /// credential error gives a [`super::SaslErrorKind::Credential`]
    /// error of the same kind.
    fn create(&self, _ctx: &SaslContext) -> Result<Box<dyn SaslMechanism>, SaslError> {
        let password = self.password.password().map_err(|kind| {
            SaslError::new(
                SaslErrorKind::Credential(kind),
                "the password source failed",
            )
        })?;
        let mut nonce = Zeroizing::new([0u8; CNONCE_BYTES]);
        getrandom::getrandom(nonce.as_mut_slice())
            .map_err(|_| mechanism_error("the system random source failed"))?;
        Ok(Box::new(DigestMd5::new(
            self.username.clone(),
            password,
            format!("{}/{}", self.service, self.server_name),
            hex(nonce.as_slice()).to_string(),
        )))
    }
}

/// The state of one DIGEST-MD5 session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// No challenge yet.
    Initial,
    /// The response went out. The next challenge carries `rspauth`.
    SentResponse,
    /// The server proved that it knows the password.
    Complete,
}

/// One DIGEST-MD5 session.
pub(crate) struct DigestMd5 {
    /// The authentication identity.
    username: String,
    /// The password of this connection. It is wiped on drop.
    password: SecretString,
    /// `service/server_name`.
    digest_uri: String,
    /// The client nonce, as lower-case hex text.
    cnonce: String,
    /// The `rspauth` value that the server must send, as lower-case hex
    /// text. It exists after the response.
    rspauth: Option<Zeroizing<String>>,
    /// The state.
    phase: Phase,
}

impl DigestMd5 {
    /// Makes a session with a known client nonce.
    pub(crate) fn new(
        username: String,
        password: SecretString,
        digest_uri: String,
        cnonce: String,
    ) -> Self {
        Self {
            username,
            password,
            digest_uri,
            cnonce,
            rspauth: None,
            phase: Phase::Initial,
        }
    }
}

impl SaslMechanism for DigestMd5 {
    fn name(&self) -> &str {
        NAME
    }

    /// Gives no token, because DIGEST-MD5 has no initial response.
    fn start(&mut self) -> Result<SaslStep, SaslError> {
        Ok(SaslStep {
            token: None,
            done: false,
        })
    }

    /// Answers the digest challenge, then checks `rspauth`.
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
        let Some(challenge) = challenge else {
            return Err(mechanism_error("the server sent no challenge"));
        };
        match self.phase {
            Phase::Initial => {
                let c = parse_challenge(challenge)?;
                let token = response(self, &c)?;
                self.phase = Phase::SentResponse;
                Ok(SaslStep {
                    token: Some(token),
                    done: false,
                })
            }
            Phase::SentResponse => {
                verify_rspauth(self, challenge)?;
                self.phase = Phase::Complete;
                Ok(SaslStep {
                    token: None,
                    done: true,
                })
            }
            Phase::Complete => Err(mechanism_error(
                "the server sent a challenge after the authentication",
            )),
        }
    }
}

/// The fields of a digest challenge that the client uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Challenge {
    /// The first realm, or `None` when the server gives no realm.
    pub(crate) realm: Option<String>,
    /// The server nonce, as the bytes of the challenge.
    pub(crate) nonce: Vec<u8>,
    /// True when `qop` names `auth`, or when `qop` is absent.
    pub(crate) qop_auth: bool,
    /// True when the charset is `utf-8`.
    pub(crate) utf8: bool,
    /// True when the algorithm is `md5-sess`.
    pub(crate) md5_sess: bool,
}

/// Parses a challenge (RFC 2831, sections 2.1.1 and 7.1).
///
/// The parser is bounded by [`MAX_CHALLENGE`]. It refuses a duplicate
/// directive, a missing `nonce` or `algorithm`, and a quoted string that
/// does not end. A challenge can name more than one realm. The client
/// then uses the first realm. The parser ignores unknown directives.
pub(crate) fn parse_challenge(challenge: &[u8]) -> Result<Challenge, SaslError> {
    let mut realm: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut qop: Option<Vec<u8>> = None;
    let mut charset: Option<Vec<u8>> = None;
    let mut algorithm: Option<Vec<u8>> = None;
    for (name, value) in directives(challenge)? {
        let slot = match name.as_str() {
            "realm" => {
                if realm.is_none() {
                    realm = Some(value);
                }
                continue;
            }
            "nonce" => &mut nonce,
            "qop" => &mut qop,
            "charset" => &mut charset,
            "algorithm" => &mut algorithm,
            _ => continue,
        };
        if slot.is_some() {
            return Err(mechanism_error("the challenge repeats a directive"));
        }
        *slot = Some(value);
    }
    let nonce = nonce.ok_or_else(|| mechanism_error("the challenge has no nonce"))?;
    let algorithm = algorithm.ok_or_else(|| mechanism_error("the challenge has no algorithm"))?;
    let utf8 = match charset {
        None => false,
        Some(v) if v.eq_ignore_ascii_case(b"utf-8") => true,
        Some(_) => return Err(mechanism_error("the challenge has an unknown charset")),
    };
    let qop_auth = qop.as_deref().is_none_or(|list| {
        list.split(|&b| b == b',')
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(QOP.as_bytes()))
    });
    let realm = match realm {
        Some(r) => Some(decode(&r, utf8)?),
        None => None,
    };
    Ok(Challenge {
        realm,
        nonce,
        qop_auth,
        utf8,
        md5_sess: algorithm.eq_ignore_ascii_case(b"md5-sess"),
    })
}

/// Makes the digest response for `c` (RFC 2831, section 2.1.2).
///
/// The function also keeps the `rspauth` value that the server must
/// send. The password and the derived secrets stay in zeroizing buffers.
pub(crate) fn response(session: &mut DigestMd5, c: &Challenge) -> Result<Vec<u8>, SaslError> {
    if !c.md5_sess {
        return Err(mechanism_error("the server does not offer md5-sess"));
    }
    if !c.qop_auth {
        return Err(mechanism_error("the server does not offer qop=auth"));
    }
    let realm = c.realm.as_deref().unwrap_or("");
    // RFC 2831, section 2.1.2.1:
    // A1 = H(user ":" realm ":" passwd) ":" nonce ":" cnonce.
    // The three values are ISO 8859-1 when they can be.
    let mut inner = Md5::new();
    inner.update(hash_text(&session.username, c.utf8)?.as_slice());
    inner.update(b":");
    inner.update(hash_text(realm, c.utf8)?.as_slice());
    inner.update(b":");
    inner.update(hash_text(session.password.expose(), c.utf8)?.as_slice());
    // The secret buffers get their exact size first. A buffer that grows
    // frees its old block without zeroizing it.
    let inner = Zeroizing::new(<[u8; 16]>::from(inner.finalize()));
    let a1_parts: [&[u8]; 3] = [inner.as_slice(), &c.nonce, session.cnonce.as_bytes()];
    let ha1 = Zeroizing::new(hex(&md5(&join_secret(&a1_parts)?)));

    let uri = wire_text(&session.digest_uri, c.utf8)?;
    let digest = |a2_prefix: &[u8]| -> Result<Zeroizing<String>, SaslError> {
        let mut a2 = Vec::with_capacity(a2_prefix.len().saturating_add(uri.len()));
        a2.extend_from_slice(a2_prefix);
        a2.extend_from_slice(&uri);
        let ha2 = hex(&md5(&a2));
        let kd = join_secret(&[
            ha1.as_bytes(),
            &c.nonce,
            NONCE_COUNT.as_bytes(),
            session.cnonce.as_bytes(),
            QOP.as_bytes(),
            ha2.as_bytes(),
        ])?;
        Ok(Zeroizing::new(hex(&md5(&kd))))
    };
    let value = digest(b"AUTHENTICATE:")?;
    session.rspauth = Some(digest(b":")?);

    let mut out = Vec::with_capacity(256);
    if c.utf8 {
        out.extend_from_slice(b"charset=utf-8,");
    }
    out.extend_from_slice(b"username=");
    quote(&mut out, &wire_text(&session.username, c.utf8)?);
    if let Some(r) = &c.realm {
        out.extend_from_slice(b",realm=");
        quote(&mut out, &wire_text(r, c.utf8)?);
    }
    out.extend_from_slice(b",nonce=");
    quote(&mut out, &c.nonce);
    out.extend_from_slice(b",nc=");
    out.extend_from_slice(NONCE_COUNT.as_bytes());
    out.extend_from_slice(b",cnonce=");
    quote(&mut out, session.cnonce.as_bytes());
    out.extend_from_slice(b",digest-uri=");
    quote(&mut out, &uri);
    out.extend_from_slice(b",maxbuf=");
    out.extend_from_slice(MAXBUF.as_bytes());
    out.extend_from_slice(b",response=");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b",qop=");
    out.extend_from_slice(QOP.as_bytes());
    Ok(out)
}

/// Checks the `rspauth` value of the last challenge (RFC 2831, section
/// 2.1.3).
///
/// The value must be 32 hex digits. The comparison with the expected
/// value takes the same time for every value of that length.
pub(crate) fn verify_rspauth(session: &DigestMd5, challenge: &[u8]) -> Result<(), SaslError> {
    let expected = session
        .rspauth
        .as_ref()
        .ok_or_else(|| mechanism_error("no response went to the server"))?;
    let mut got: Option<Vec<u8>> = None;
    for (name, value) in directives(challenge)? {
        if name == "rspauth" {
            if got.is_some() {
                return Err(mechanism_error("the challenge repeats a directive"));
            }
            got = Some(value);
        }
    }
    let got = got.ok_or_else(|| mechanism_error("the server sent no rspauth"))?;
    if got.len() != expected.len() || !got.iter().all(u8::is_ascii_hexdigit) {
        return Err(mechanism_error("the server sent a malformed rspauth"));
    }
    if ct_eq_hex(&got, expected.as_bytes()) {
        Ok(())
    } else {
        Err(SaslError::new(
            SaslErrorKind::ServerRejected,
            "the server did not prove that it knows the password",
        ))
    }
}

/// Compares two hex strings of the same length with no early exit. The
/// case of the letters does not count. Both inputs are hex digits, so
/// the bit 0x20 changes only the case of a letter.
fn ct_eq_hex(a: &[u8], b: &[u8]) -> bool {
    let diff = a
        .iter()
        .zip(b)
        .fold(0u8, |acc, (x, y)| acc | ((x | 0x20) ^ (y | 0x20)));
    a.len() == b.len() && diff == 0
}

/// Splits a challenge into its directives (RFC 2831, section 7.1).
///
/// The names are lower case. The values have no quotes and no escape
/// characters. Empty list elements are allowed. The parser reads each
/// byte once, so the work is linear in the bounded input.
fn directives(input: &[u8]) -> Result<Vec<(String, Vec<u8>)>, SaslError> {
    if input.len() > MAX_CHALLENGE {
        return Err(mechanism_error("the challenge is too long"));
    }
    let mut out = Vec::new();
    let mut it = input.iter().copied().peekable();
    loop {
        skip_lws(&mut it);
        match it.peek() {
            None => break,
            Some(b',') => {
                it.next();
                continue;
            }
            Some(_) => {}
        }
        let name = read_token(&mut it)?;
        skip_lws(&mut it);
        if it.next() != Some(b'=') {
            return Err(mechanism_error("a challenge directive has no value"));
        }
        skip_lws(&mut it);
        let value = if it.peek() == Some(&b'"') {
            it.next();
            read_quoted(&mut it)?
        } else {
            read_token(&mut it)?
        };
        if out.len() >= MAX_DIRECTIVES {
            return Err(mechanism_error("the challenge has too many directives"));
        }
        let name = String::from_utf8_lossy(&name).to_ascii_lowercase();
        out.push((name, value));
        skip_lws(&mut it);
        match it.next() {
            None => break,
            Some(b',') => {}
            Some(_) => return Err(mechanism_error("a challenge directive is malformed")),
        }
    }
    Ok(out)
}

/// The byte iterator of the parser.
type Bytes<'a> = std::iter::Peekable<std::iter::Copied<std::slice::Iter<'a, u8>>>;

/// Skips linear white space.
fn skip_lws(it: &mut Bytes<'_>) {
    while it
        .next_if(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .is_some()
    {}
}

/// Returns true for a token character (RFC 2616, section 2.2).
fn is_token(b: u8) -> bool {
    b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b)
}

/// Reads a token of at least one character.
fn read_token(it: &mut Bytes<'_>) -> Result<Vec<u8>, SaslError> {
    let mut out = Vec::new();
    while let Some(b) = it.next_if(|&b| is_token(b)) {
        out.push(b);
    }
    if out.is_empty() {
        return Err(mechanism_error("a challenge directive is malformed"));
    }
    Ok(out)
}

/// Reads the rest of a quoted string after its first quote. A backslash
/// quotes the next byte.
fn read_quoted(it: &mut Bytes<'_>) -> Result<Vec<u8>, SaslError> {
    let mut out = Vec::new();
    loop {
        match it.next() {
            None => return Err(mechanism_error("a quoted string does not end")),
            Some(b'"') => return Ok(out),
            Some(b'\\') => match it.next() {
                Some(b) => out.push(b),
                None => return Err(mechanism_error("a quoted string does not end")),
            },
            Some(b) => out.push(b),
        }
    }
}

/// Writes `value` as a quoted string.
fn quote(out: &mut Vec<u8>, value: &[u8]) {
    out.push(b'"');
    for &b in value {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b'"');
}

/// Decodes a challenge value: UTF-8 with the `utf-8` charset, else
/// ISO 8859-1.
fn decode(value: &[u8], utf8: bool) -> Result<String, SaslError> {
    if utf8 {
        String::from_utf8(value.to_vec())
            .map_err(|_| mechanism_error("the challenge is not valid UTF-8"))
    } else {
        Ok(value.iter().map(|&b| char::from(b)).collect())
    }
}

/// Encodes a value for the hash (RFC 2831, section 2.1.2.1). The value
/// is ISO 8859-1 when every character fits. Otherwise it is UTF-8, which only
/// the `utf-8` charset allows.
fn hash_text(value: &str, utf8: bool) -> Result<Zeroizing<Vec<u8>>, SaslError> {
    match latin1(value) {
        Some(bytes) => Ok(bytes),
        None if utf8 => Ok(Zeroizing::new(value.as_bytes().to_vec())),
        None => Err(mechanism_error(
            "a value needs UTF-8, but the server does not allow it",
        )),
    }
}

/// Encodes a value for the response: UTF-8 with the `utf-8` charset,
/// else ISO 8859-1.
fn wire_text(value: &str, utf8: bool) -> Result<Zeroizing<Vec<u8>>, SaslError> {
    if utf8 {
        return Ok(Zeroizing::new(value.as_bytes().to_vec()));
    }
    latin1(value)
        .ok_or_else(|| mechanism_error("a value needs UTF-8, but the server does not allow it"))
}

/// Gives the ISO 8859-1 bytes of `value`, or `None` when a character
/// does not fit.
fn latin1(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    for ch in value.chars() {
        out.push(u8::try_from(u32::from(ch)).ok()?);
    }
    Some(out)
}

/// Joins `parts` with `:` into a zeroizing buffer of exact capacity.
/// The buffer never grows, so no unzeroized copy of a secret part stays
/// in freed memory.
fn join_secret(parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, SaslError> {
    let len = parts
        .iter()
        .try_fold(0usize, |n, p| n.checked_add(p.len())?.checked_add(1))
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| mechanism_error("the challenge is too long"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b':');
        }
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// Gives the MD5 digest of `data`.
fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// Gives the lower-case hex text of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Makes a mechanism error with `message`.
fn mechanism_error(message: &str) -> SaslError {
    SaslError::new(SaslErrorKind::Mechanism, message)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;

    /// The challenge of the example in RFC 2831, section 4.
    const RFC_CHALLENGE: &[u8] = b"realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",\
qop=\"auth\",algorithm=md5-sess,charset=utf-8";

    /// Makes the session of the example in RFC 2831, section 4.
    fn rfc_session() -> DigestMd5 {
        DigestMd5::new(
            "chris".to_owned(),
            SecretString::from("secret"),
            "imap/elwood.innosoft.com".to_owned(),
            "OA6MHXh6VqTrRk".to_owned(),
        )
    }

    fn text(step: &SaslStep) -> String {
        String::from_utf8(step.token.clone().expect("a token")).expect("UTF-8")
    }

    fn message(r: Result<SaslStep, SaslError>) -> (SaslErrorKind, String) {
        let e = r.expect_err("an error");
        (e.kind.clone(), e.to_string())
    }

    #[test]
    fn the_rfc_2831_example_gives_the_rfc_response() {
        let mut s = rfc_session();
        let first = s.start().expect("start");
        assert!(first.token.is_none() && !first.done);
        let step = s.step(Some(RFC_CHALLENGE)).expect("response");
        assert!(!step.done);
        assert_eq!(
            text(&step),
            "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",\
nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",\
digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,\
response=d388dad90d4bbd760a152321f2143af7,qop=auth"
        );
        let done = s
            .step(Some(b"rspauth=ea40f60335c427b5527b84dbabcdfffd"))
            .expect("rspauth");
        assert!(done.done && done.token.is_none());
        assert_eq!(s.phase, Phase::Complete);
        // A challenge after the end is an error.
        let (kind, _) = message(s.step(Some(b"rspauth=x")));
        assert_eq!(kind, SaslErrorKind::Mechanism);
    }

    /// A challenge with a 100-byte nonce. The A1 and KD texts are longer
    /// than any fixed buffer size.
    fn long_nonce_challenge() -> Vec<u8> {
        let mut c = b"realm=\"elwood.innosoft.com\",nonce=\"".to_vec();
        c.extend_from_slice(&[b'n'; 100]);
        c.extend_from_slice(b"\",qop=\"auth\",algorithm=md5-sess,charset=utf-8");
        c
    }

    /// Rule: a long nonce gives the RFC 2831 digest. The expected value
    /// comes from an independent MD5 computation.
    #[test]
    fn a_long_nonce_gives_the_rfc_digest() {
        let mut s = rfc_session();
        let step = s.step(Some(&long_nonce_challenge())).expect("response");
        assert!(text(&step).contains("response=8dd1f522cc9fe09bab9a6b5b06694875,"));
    }

    /// Rule: no freed heap block holds the session key after a response to
    /// a long nonce. The marker is the hex HA1 of [`long_nonce_challenge`].
    /// `tests/free_scan/free_scan.sh` runs this test with the free scanner.
    /// A heap copy of the marker is the control buffer.
    #[test]
    #[ignore = "free-scan"]
    fn long_nonce_secrets_are_zero_before_free() {
        let Some(out) = std::env::var_os("ZK_FREE_SCAN_OUT") else {
            // Without the scanner the test has nothing to check.
            return;
        };
        let hits = || {
            std::fs::read_to_string(&out)
                .map(|t| t.lines().filter(|l| l.starts_with("hit")).count())
                .unwrap_or(0)
        };
        drop(std::hint::black_box(String::from(
            "66a1b64b6346800663dd35e9c207ad26",
        )));
        let control = hits();
        assert!(control >= 1, "the free scanner does not run");
        let mut s = rfc_session();
        drop(s.step(Some(&long_nonce_challenge())).expect("response"));
        drop(s);
        assert_eq!(hits(), control, "a freed block holds HA1");
    }

    #[test]
    fn the_rspauth_check_ignores_the_case_and_refuses_a_bad_value() {
        let mut s = rfc_session();
        s.step(Some(RFC_CHALLENGE)).expect("response");
        assert!(verify_rspauth(&s, b"rspauth=EA40F60335C427B5527B84DBABCDFFFD").is_ok());
        let wrong = verify_rspauth(&s, b"rspauth=ea40f60335c427b5527b84dbabcdfffe");
        assert_eq!(
            wrong.expect_err("wrong").kind,
            SaslErrorKind::ServerRejected
        );
        for bad in [
            &b"rspauth=ea40"[..],
            b"rspauth=ea40f60335c427b5527b84dbabcdfffz",
            b"rspauth=ea40f60335c427b5527b84dbabcdfffd,rspauth=ea40f60335c427b5527b84dbabcdfffd",
            b"realm=x",
            b"",
        ] {
            let e = verify_rspauth(&s, bad).expect_err("bad rspauth");
            assert_eq!(e.kind, SaslErrorKind::Mechanism, "{bad:?}");
        }
        assert!(!ct_eq_hex(b"ab", b"abc"));
    }

    #[test]
    fn no_challenge_is_a_mechanism_error() {
        let mut s = rfc_session();
        let (kind, _) = message(s.step(None));
        assert_eq!(kind, SaslErrorKind::Mechanism);
        // An rspauth check before a response is an error, too.
        assert!(verify_rspauth(&s, b"rspauth=00").is_err());
    }

    #[test]
    fn the_parser_reads_the_rfc_challenge() {
        let c = parse_challenge(RFC_CHALLENGE).expect("parse");
        assert_eq!(c.realm.as_deref(), Some("elwood.innosoft.com"));
        assert_eq!(c.nonce, b"OA6MG9tEQGm2hh");
        assert!(c.qop_auth && c.utf8 && c.md5_sess);
    }

    #[test]
    fn the_parser_accepts_the_list_rules_of_rfc_2831() {
        let c = parse_challenge(
            b" , realm = \"a\\\"b\" ,, realm=\"second\",\tnonce=\"n\\\\1\" ,\
qop=\"auth-int, auth\", stale=true, maxbuf=1024,algorithm=MD5-SESS ,",
        )
        .expect("parse");
        assert_eq!(c.realm.as_deref(), Some("a\"b"));
        assert_eq!(c.nonce, b"n\\1");
        assert!(c.qop_auth && !c.utf8 && c.md5_sess);
        // Without qop, the RFC default is auth. Without a realm, the
        // response has no realm.
        let c = parse_challenge(b"nonce=n,algorithm=md5-sess").expect("parse");
        assert!(c.qop_auth && c.realm.is_none());
        // Without the utf-8 charset, a value is ISO 8859-1.
        let c = parse_challenge(b"realm=\"\xe9\",nonce=n,algorithm=md5-sess").expect("parse");
        assert_eq!(c.realm.as_deref(), Some("\u{e9}"));
    }

    #[test]
    fn the_parser_refuses_a_bad_challenge() {
        let long = vec![b' '; MAX_CHALLENGE.saturating_add(1)];
        let many = "x=1,".repeat(MAX_DIRECTIVES.saturating_add(1));
        let cases: Vec<&[u8]> = vec![
            &long,
            many.as_bytes(),
            b"nonce=a,nonce=b,algorithm=md5-sess",
            b"nonce=a,algorithm=md5-sess,algorithm=md5-sess",
            b"realm=r,algorithm=md5-sess",
            b"nonce=a",
            b"nonce=\"a,algorithm=md5-sess",
            b"nonce=\"a\\",
            b"nonce=a,algorithm=md5-sess,charset=latin1",
            b"realm=\"\xff\",nonce=a,algorithm=md5-sess,charset=utf-8",
            b"nonce",
            b"nonce=,algorithm=md5-sess",
            b"=a",
            b"nonce=a b,algorithm=md5-sess",
            b"nonce=a;algorithm=md5-sess",
        ];
        for bad in cases {
            let e = parse_challenge(bad).expect_err("bad challenge");
            assert_eq!(e.kind, SaslErrorKind::Mechanism, "{bad:?}");
        }
        // The limit counts the input, so a challenge at the limit parses.
        let mut at_limit = b"nonce=a,algorithm=md5-sess".to_vec();
        at_limit.resize(MAX_CHALLENGE, b' ');
        assert!(parse_challenge(&at_limit).is_ok());
    }

    #[test]
    fn the_response_needs_md5_sess_and_qop_auth() {
        for bad in [
            &b"nonce=a,algorithm=md5"[..],
            b"nonce=a,algorithm=md5-sess,qop=\"auth-int,auth-conf\"",
        ] {
            let mut s = rfc_session();
            let (kind, _) = message(s.step(Some(bad)));
            assert_eq!(kind, SaslErrorKind::Mechanism, "{bad:?}");
            assert_eq!(s.phase, Phase::Initial);
        }
    }

    #[test]
    fn a_name_outside_latin1_needs_the_utf8_charset() {
        let mut s = DigestMd5::new(
            "\u{4e2d}".to_owned(),
            SecretString::from("p"),
            "zookeeper/zk-sasl-md5".to_owned(),
            "c".to_owned(),
        );
        assert!(s.step(Some(b"nonce=a,algorithm=md5-sess")).is_err());
        let step = s
            .step(Some(b"nonce=a,algorithm=md5-sess,charset=utf-8"))
            .expect("UTF-8 response");
        assert!(text(&step).starts_with("charset=utf-8,username=\"\u{4e2d}\","));
    }

    #[test]
    fn the_response_quotes_the_values() {
        let mut s = DigestMd5::new(
            "a\"b\\c".to_owned(),
            SecretString::from("p"),
            "zookeeper/zk-sasl-md5".to_owned(),
            "c".to_owned(),
        );
        let step = s
            .step(Some(b"nonce=a,algorithm=md5-sess"))
            .expect("response");
        assert!(text(&step).starts_with("username=\"a\\\"b\\\\c\",nonce=\"a\""));
    }

    struct Fails(crate::sasl::CredentialError);

    impl CredentialSource for Fails {
        fn password(&self) -> Result<SecretString, crate::sasl::CredentialError> {
            Err(self.0)
        }
    }

    struct Gives;

    impl CredentialSource for Gives {
        fn password(&self) -> Result<SecretString, crate::sasl::CredentialError> {
            Ok(SecretString::from("p"))
        }
    }

    fn ctx() -> SaslContext {
        SaslContext {
            server_host: "zk".to_owned(),
            server_addr: "127.0.0.1:2181".parse().expect("addr"),
            local_addr: "127.0.0.1:40000".parse().expect("addr"),
        }
    }

    #[test]
    fn the_factory_maps_a_credential_error_and_makes_a_new_nonce() {
        use crate::sasl::CredentialError;
        for kind in [CredentialError::Transient, CredentialError::Permanent] {
            let f = DigestMd5Factory::new(
                "u".to_owned(),
                Arc::new(Fails(kind)),
                "zookeeper".to_owned(),
                "zk-sasl-md5".to_owned(),
            );
            let e = f.create(&ctx()).err().expect("credential error");
            assert_eq!(e.kind, SaslErrorKind::Credential(kind));
        }
        let f = DigestMd5Factory::new(
            "u".to_owned(),
            Arc::new(Gives),
            "zookeeper".to_owned(),
            "zk-sasl-md5".to_owned(),
        );
        let mut a = f.create(&ctx()).expect("create");
        let mut b = f.create(&ctx()).expect("create");
        assert_eq!(a.name(), NAME);
        let challenge = Some(&b"nonce=a,algorithm=md5-sess"[..]);
        let ta = text(&a.step(challenge).expect("step"));
        let tb = text(&b.step(challenge).expect("step"));
        assert!(ta.contains("digest-uri=\"zookeeper/zk-sasl-md5\""));
        assert_ne!(ta, tb, "each session has its own client nonce");
    }

    proptest::proptest! {
        #![proptest_config(crate::test_config::proptest())]
        #[test]
        fn no_challenge_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let mut s = rfc_session();
            let _ = parse_challenge(&data);
            if s.step(Some(&data)).is_ok() {
                let _ = s.step(Some(&data));
            }
        }

        #[test]
        fn no_directive_list_panics(s in "[a-z=\",\\\\ ]{0,128}") {
            let _ = parse_challenge(s.as_bytes());
        }
    }
}
