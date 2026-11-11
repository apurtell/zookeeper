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

//! The strict PEM block reader with RFC 1421 headers.
//!
//! The trust loader (`trust.rs`) and the identity loader (`identity.rs`)
//! read every file through this module. The reader keeps the `Proc-Type`
//! and `DEK-Info` headers of traditional encrypted keys, which the
//! `rustls-pki-types` reader drops. It fails on invalid base64 in a block
//! of any label, as OpenSSL `PEM_X509_INFO_read_bio` does. Text outside
//! blocks is ignored.
//!
//! The reader is bounded by the input: it allocates at most the size of
//! the decoded bodies, and it never panics on hostile input. Every body is
//! a [`SecretBytes`], because a key block holds key material.
//!
//! The reader copies `PEM_read_bio_ex` with the `PEM_FLAG_EAY_COMPATIBLE`
//! flag. It reads lines as `BIO_gets` does, at most 254 bytes at a time,
//! and it cleans each line as `sanitize_line` does. The base64 decoder
//! copies `EVP_DecodeUpdate`, so it accepts the non-canonical input that
//! OpenSSL accepts. [`read_blocks`] keeps every header line and does not
//! check the header syntax. The loaders check it.

use der::zeroize::Zeroizing;
use zk_proto::SecretBytes;

use crate::net::tls::x509::{self, Mode, Reader, int_ok, oid_ok};

/// One PEM block.
#[derive(Debug)]
pub struct PemBlock {
    /// The label, for example `CERTIFICATE`.
    pub label: String,
    /// The RFC 1421 headers, in file order. Only key blocks use them.
    pub headers: Vec<(String, String)>,
    /// The decoded body.
    pub body: SecretBytes,
}

/// The use of a PEM label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PemKind {
    /// `CERTIFICATE` or `X509 CERTIFICATE`.
    Certificate,
    /// `TRUSTED CERTIFICATE`: a certificate and an `X509_CERT_AUX`.
    TrustedCertificate,
    /// `X509 CRL`. The trust loader counts it and does not use it.
    Crl,
    /// `PRIVATE KEY` (PKCS#8).
    Pkcs8Key,
    /// `RSA PRIVATE KEY` (PKCS#1).
    RsaKey,
    /// `EC PRIVATE KEY` (SEC1).
    EcKey,
    /// `ENCRYPTED PRIVATE KEY` (PKCS#8 `EncryptedPrivateKeyInfo`).
    EncryptedPkcs8Key,
    /// `DSA PRIVATE KEY`. The key loader rejects it, unlike OpenSSL.
    DsaKey,
    /// Any other label. The loaders skip the block.
    Other,
}

/// A PEM read failure. Each failure fails the whole file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PemError {
    /// A block has invalid base64.
    Base64,
    /// A block has no end line, or the end label differs.
    Unterminated,
    /// A header line is malformed.
    Header,
}

/// `LINESIZE - 1`: the most bytes that one `BIO_gets` call returns.
const CHUNK: usize = 254;
/// The longest base64 line after the header, with its newline.
const LINE_MAX: usize = 65;
const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const TAIL: &[u8] = b"-----";
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Reads a file image the way `BIO_gets` reads a file BIO.
#[derive(Clone, Copy)]
struct Lines<'a> {
    data: &'a [u8],
}

impl<'a> Lines<'a> {
    /// Returns the next chunk up to its first NUL, or `None` at the end.
    /// A chunk that starts with NUL has length 0, which OpenSSL takes as
    /// the end of the file.
    fn next_chunk(&mut self) -> Option<&'a [u8]> {
        self.next_chunk_colon().map(|(chunk, _)| chunk)
    }

    /// Returns [`Lines::next_chunk`] and tells whether the chunk holds a
    /// `:`. One pass over the window finds the newline, the first NUL and
    /// the colon.
    fn next_chunk_colon(&mut self) -> Option<(&'a [u8], bool)> {
        let max = self.data.len().min(CHUNK);
        let window = self.data.get(..max)?;
        let scan = scan_window(window);
        let chunk = window.get(..scan.len)?;
        self.data = self.data.get(scan.len..)?;
        let eff = match scan.nul {
            Some(z) => chunk.get(..z)?,
            None => chunk,
        };
        (!eff.is_empty()).then_some((eff, scan.colon))
    }
}

/// The result of one scan of a line window.
struct Scan {
    /// The chunk length. The chunk ends after the first newline, or at the end of the window.
    len: usize,
    /// The position of the first NUL in the chunk.
    nul: Option<usize>,
    /// The chunk holds a `:` before its first NUL.
    colon: bool,
}

/// Scans a window in words of eight bytes. Only a word that holds a
/// newline, a NUL or a colon gets a scan byte by byte.
fn scan_window(window: &[u8]) -> Scan {
    let mut scan = Scan {
        len: window.len(),
        nul: None,
        colon: false,
    };
    let mut base = 0usize;
    for part in window.chunks(8) {
        if !plain_word(part) {
            for (at, &b) in (base..).zip(part) {
                if b == b'\n' {
                    scan.len = at.saturating_add(1);
                    return scan;
                }
                if scan.nul.is_none() {
                    if b == 0 {
                        scan.nul = Some(at);
                    } else if b == b':' {
                        scan.colon = true;
                    }
                }
            }
        }
        base = base.saturating_add(part.len());
    }
    scan
}

/// The byte `\n` in each lane of a word.
const NL_WORD: u64 = 0x0a0a_0a0a_0a0a_0a0a;
/// The byte `:` in each lane of a word.
const COLON_WORD: u64 = 0x3a3a_3a3a_3a3a_3a3a;

/// Tells whether a part of eight bytes holds no newline, no NUL and no
/// colon. A shorter part gives false, so that it gets a scan byte by
/// byte.
fn plain_word(part: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 8]>::try_from(part) else {
        return false;
    };
    let w = u64::from_ne_bytes(bytes);
    !has_zero_byte(w) && !has_zero_byte(w ^ NL_WORD) && !has_zero_byte(w ^ COLON_WORD)
}

/// Tells whether a word holds a zero byte. The test is exact for the
/// word as a whole.
fn has_zero_byte(w: u64) -> bool {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    w.wrapping_sub(LO) & !w & HI != 0
}

/// `sanitize_line` with `PEM_FLAG_EAY_COMPATIBLE`: strip the trailing bytes
/// that a signed `char` compares as `<= ' '`. The caller appends the
/// newline.
fn sanitize(line: &[u8]) -> &[u8] {
    let keep = line
        .iter()
        .rposition(|b| *b > b' ' && *b < 0x80)
        .and_then(|i| i.checked_add(1))
        .unwrap_or(0);
    line.get(..keep).unwrap_or(&[])
}

/// `get_name`: skips lines up to a BEGIN line and returns its label.
fn find_begin<'a>(lines: &mut Lines<'a>) -> Option<&'a [u8]> {
    let mut first = true;
    loop {
        let mut raw = lines.next_chunk()?;
        if first && raw.len() > 3 && raw.starts_with(BOM) {
            raw = raw.get(3..)?;
        }
        first = false;
        let s = sanitize(raw);
        if s.starts_with(BEGIN) && s.ends_with(TAIL) {
            let end = s.len().checked_sub(TAIL.len())?;
            return s.get(BEGIN.len()..end);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderState {
    Maybe,
    In,
    Post,
}

/// The text of a block part, in a zeroizing buffer.
type Text = Zeroizing<Vec<u8>>;

/// `get_header_and_data` and the base64 decode: returns the header text
/// of one block, with a newline after each line, and the decoded body.
/// The body is `None` when the base64 text does not decode.
///
/// The header and the body can hold key material, so both buffers are
/// zeroized. A first pass measures the block. A second pass copies the
/// header and decodes the base64 lines straight into the body. Each
/// buffer has its final capacity before the second pass. Thus no buffer
/// grows, and no reallocation frees an unzeroized copy. The
/// base64 text gets no buffer of its own.
fn header_and_body(lines: &mut Lines<'_>, label: &[u8]) -> Result<(Text, Option<Text>), PemError> {
    let (mut header_len, mut data_len) = (0usize, 0usize);
    let mut probe = *lines;
    // A block without a header gives all its lines as header lines. Then
    // these lines are the base64 text.
    let swap = scan_block(&mut probe, label, |to_data, s| {
        let slot = if to_data {
            &mut data_len
        } else {
            &mut header_len
        };
        *slot = slot.saturating_add(s.len()).saturating_add(1);
    })?;
    if swap {
        std::mem::swap(&mut header_len, &mut data_len);
    }
    let mut header = Zeroizing::new(Vec::with_capacity(header_len));
    let mut body = Zeroizing::new(Vec::with_capacity(b64_capacity(data_len)));
    let mut b64 = B64::default();
    scan_block(lines, label, |to_data, s| {
        if to_data || swap {
            b64.feed(&mut body, s);
        } else {
            header.extend_from_slice(s);
            header.push(b'\n');
        }
    })?;
    Ok((header, b64.finish().then_some(body)))
}

/// Walks the lines of one block and gives each kept line to `put`, with
/// a flag that is true for base64 text. It returns true when the block
/// has no header, so that the header text is the base64 text.
fn scan_block(
    lines: &mut Lines<'_>,
    label: &[u8],
    mut put: impl FnMut(bool, &[u8]),
) -> Result<bool, PemError> {
    let mut to_data = false;
    let mut state = HeaderState::Maybe;
    let mut end = false;
    let mut partial = false;
    loop {
        let (raw, colon) = lines.next_chunk_colon().ok_or(PemError::Unterminated)?;
        let prev_partial = partial;
        partial = raw.len() == CHUNK && raw.last() != Some(&b'\n');
        if state == HeaderState::Maybe && colon {
            state = HeaderState::In;
        }
        let s = sanitize(raw);
        if s.is_empty() {
            if !prev_partial {
                if state == HeaderState::Post {
                    return Err(PemError::Base64);
                }
                state = HeaderState::Post;
                to_data = true;
            }
            continue;
        }
        if let Some(rest) = s.strip_prefix(END) {
            let name_ok = rest.strip_prefix(label).is_some_and(|tail| tail == TAIL);
            if !name_ok {
                return Err(PemError::Unterminated);
            }
            return Ok(state == HeaderState::Maybe);
        }
        if end {
            return Err(PemError::Base64);
        }
        put(to_data, s);
        if state == HeaderState::Post {
            // Here `end` is false, so the line length alone sets it.
            end = short_line(s)?;
        }
    }
}

/// Checks the length of one base64 line with its newline. A longer line
/// than [`LINE_MAX`] fails. A shorter line must be the last line, so the
/// result tells whether the line is shorter.
fn short_line(s: &[u8]) -> Result<bool, PemError> {
    let len = s.len().saturating_add(1);
    if len > LINE_MAX {
        return Err(PemError::Base64);
    }
    Ok(len < LINE_MAX)
}

/// The base64 digit value of each byte, or `0xff` for a byte that is no
/// digit. A digit value is below 64, so any other entry has a high bit
/// set.
#[rustfmt::skip]
static B64_DIGIT: [u8; 256] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// The table entry of a byte: its digit value, or `0xff`.
fn b64_digit(b: u8) -> u8 {
    B64_DIGIT.get(usize::from(b)).copied().unwrap_or(0xff)
}

fn b64_value(b: u8) -> Option<u8> {
    Some(b64_digit(b)).filter(|v| *v < 64)
}

/// The most bytes that `len` bytes of base64 text can give.
fn b64_capacity(len: usize) -> usize {
    (len / 4).saturating_mul(3)
}

/// `EVP_DecodeUpdate` and `EVP_DecodeFinal` over text that comes in
/// parts. White space is skipped, `-` ends the input, and padding may
/// only end the text. The parts decode as their concatenation does.
///
/// The caller gives an output buffer with the capacity of
/// [`b64_capacity`] for the whole text, so the buffer never grows.
#[derive(Default)]
struct B64 {
    /// The digits of the open group.
    acc: u32,
    /// The count of digits in the open group.
    n: u8,
    /// The count of `=` bytes.
    pad: u8,
    /// A `-` ended the input.
    done: bool,
    /// The text is invalid.
    bad: bool,
}

impl B64 {
    /// Decodes the next part of the text.
    fn feed(&mut self, out: &mut Vec<u8>, text: &[u8]) {
        let mut rest = text;
        while !self.done && !self.bad {
            if self.n == 0 && self.pad == 0 {
                rest = Self::groups(out, rest);
            }
            let Some((&b, tail)) = rest.split_first() else {
                break;
            };
            rest = tail;
            self.step(out, b);
        }
    }

    /// Decodes each run of four digits at the start of a group into three
    /// bytes at once. It stops at the first group that holds another byte
    /// and returns the text from that group on.
    fn groups<'t>(out: &mut Vec<u8>, mut rest: &'t [u8]) -> &'t [u8] {
        while let Some((&[a, b, c, d], tail)) = rest.split_first_chunk::<4>() {
            let (a, b, c, d) = (b64_digit(a), b64_digit(b), b64_digit(c), b64_digit(d));
            if (a | b | c | d) & 0xc0 != 0 {
                break;
            }
            let v = u32::from(a).wrapping_shl(18)
                | u32::from(b).wrapping_shl(12)
                | u32::from(c).wrapping_shl(6)
                | u32::from(d);
            let [_, b1, b2, b3] = v.to_be_bytes();
            out.extend_from_slice(&[b1, b2, b3]);
            rest = tail;
        }
        rest
    }

    /// Decodes one byte with the full rules.
    fn step(&mut self, out: &mut Vec<u8>, b: u8) {
        let v = match b {
            b' ' | b'\t' | b'\n' | b'\r' => return,
            b'-' => {
                self.done = true;
                return;
            }
            b'=' => {
                self.pad = self.pad.saturating_add(1);
                if self.pad > 2 {
                    self.bad = true;
                    return;
                }
                0
            }
            _ => {
                let Some(v) = b64_value(b).filter(|_| self.pad == 0) else {
                    self.bad = true;
                    return;
                };
                v
            }
        };
        self.acc = self.acc.wrapping_shl(6) | u32::from(v);
        self.n = self.n.saturating_add(1);
        if self.n == 4 {
            let [_, b1, b2, b3] = self.acc.to_be_bytes();
            out.push(b1);
            if self.pad < 2 {
                out.push(b2);
            }
            if self.pad < 1 {
                out.push(b3);
            }
            self.acc = 0;
            self.n = 0;
        }
    }

    /// Tells whether the text decodes: it is valid and ends on a group.
    fn finish(&self) -> bool {
        !self.bad && self.n == 0
    }
}

/// Decodes one base64 text in a zeroized buffer.
#[cfg(test)]
fn b64_decode(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(b64_capacity(text.len())));
    let mut b64 = B64::default();
    b64.feed(&mut out, text);
    b64.finish().then_some(out)
}

/// Splits the header text into `(name, value)` pairs. A line with `:`
/// gives the text before the first `:` and the rest without leading
/// blanks. A line that starts with a blank continues the previous value.
/// Any other line gives the line and an empty value.
fn parse_headers(text: &[u8]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let line = String::from_utf8_lossy(line);
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push('\n');
                v.push_str(&line);
                continue;
            }
        }
        match line.split_once(':') {
            Some((k, v)) => out.push((k.to_owned(), v.trim_start_matches([' ', '\t']).to_owned())),
            None => out.push((line.into_owned(), String::new())),
        }
    }
    out
}

/// Reads every PEM block of a file image, in order.
///
/// The rules are those of `PEM_read_bio_ex`: a block starts at a
/// `-----BEGIN <label>-----` line and ends at the matching END line.
/// RFC 1421 headers come before the first empty line of the body. The
/// reader skips text before, between and after the blocks. A NUL byte at
/// the start of a line ends the file, as it does for OpenSSL.
///
/// # Errors
///
/// Returns the first [`PemError`] of the file. A block with an empty
/// body, or a body that decodes to no bytes, is [`PemError::Base64`].
pub fn read_blocks(text: &[u8]) -> Result<Vec<PemBlock>, PemError> {
    match read_blocks_partial(text) {
        (blocks, None) => Ok(blocks),
        (_, Some(e)) => Err(e),
    }
}

/// Reads blocks up to the first failure. It returns the blocks before the
/// failure and the failure. The hash-directory loader needs this form,
/// because `X509_load_cert_file` keeps the certificates that it reads
/// before a bad block.
pub(crate) fn read_blocks_partial(text: &[u8]) -> (Vec<PemBlock>, Option<PemError>) {
    let mut lines = Lines { data: text };
    let mut out = Vec::new();
    while let Some(label) = find_begin(&mut lines) {
        match read_body(&mut lines, label) {
            Ok(block) => out.push(block),
            Err(e) => return (out, Some(e)),
        }
    }
    (out, None)
}

fn read_body(lines: &mut Lines<'_>, label: &[u8]) -> Result<PemBlock, PemError> {
    let (header, body) = header_and_body(lines, label)?;
    let mut body = body.ok_or(PemError::Base64)?;
    if body.is_empty() {
        return Err(PemError::Base64);
    }
    Ok(PemBlock {
        label: String::from_utf8_lossy(label).into_owned(),
        headers: parse_headers(&header),
        body: SecretBytes::new(std::mem::take(&mut *body)),
    })
}

/// Maps a label to its use.
///
/// The match is exact and case-sensitive, as the OpenSSL label tests are.
#[must_use]
pub fn classify_label(label: &str) -> PemKind {
    match label {
        "CERTIFICATE" | "X509 CERTIFICATE" => PemKind::Certificate,
        "TRUSTED CERTIFICATE" => PemKind::TrustedCertificate,
        "X509 CRL" => PemKind::Crl,
        "PRIVATE KEY" => PemKind::Pkcs8Key,
        "RSA PRIVATE KEY" => PemKind::RsaKey,
        "EC PRIVATE KEY" => PemKind::EcKey,
        "ENCRYPTED PRIVATE KEY" => PemKind::EncryptedPkcs8Key,
        "DSA PRIVATE KEY" => PemKind::DsaKey,
        _ => PemKind::Other,
    }
}

/// Tells whether a certificate body passes the OpenSSL `d2i_X509` test.
///
/// The test is a structural decode of the X.509 `Certificate` template:
/// tags, lengths and nesting only. A body that passes this test and that
/// `LegacyCert` does not parse adds no trust input. It still counts as a
/// certificate for the load rule, as in OpenSSL.
/// The test ignores bytes after the certificate, as `d2i_X509` does.
#[must_use]
pub fn der_is_certificate(der: &[u8]) -> bool {
    x509::ber_certificate(der).is_some()
}

/// The `PEM_get_EVP_CIPHER_INFO` test of an encrypted traditional key.
///
/// The first header must be `Proc-Type: 4,ENCRYPTED`. The second header
/// must be `DEK-Info` with a known cipher and a hex IV of the cipher IV
/// length. The check ignores text after the IV. The cipher table is the set of
/// OpenSSL default-provider CBC, CFB, OFB, CTR and ECB names that a
/// traditional key can name. Names compare without case.
#[must_use]
pub fn cipher_info_ok(headers: &[(String, String)]) -> bool {
    cipher_info(headers).is_some()
}

fn cipher_info(headers: &[(String, String)]) -> Option<()> {
    let [(k1, v1), (k2, v2), ..] = headers else {
        return None;
    };
    if k1 != "Proc-Type" || k2 != "DEK-Info" {
        return None;
    }
    let rest = v1.strip_prefix("4,")?.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix("ENCRYPTED")?;
    if !rest.chars().all(|c| matches!(c, ' ' | '\t' | '\r')) {
        return None;
    }
    // OpenSSL takes the cipher name up to a blank or a comma. Without one,
    // the name runs into the next line and the lookup fails.
    let cut = v2.find([' ', '\t', ','])?;
    let (name, rest) = v2.split_at_checked(cut)?;
    let iv_len = cipher_iv_len(name)?;
    let rest = rest.trim_start_matches([' ', '\t']);
    if iv_len == 0 {
        return (!rest.starts_with(',')).then_some(());
    }
    let hex = rest.strip_prefix(',')?.as_bytes();
    let need = iv_len.checked_mul(2)?;
    hex.get(..need)?
        .iter()
        .all(u8::is_ascii_hexdigit)
        .then_some(())
}

fn cipher_iv_len(name: &str) -> Option<usize> {
    const TABLE: &[(&str, usize)] = &[
        ("AES-128-CBC", 16),
        ("AES-192-CBC", 16),
        ("AES-256-CBC", 16),
        ("AES-128-CFB", 16),
        ("AES-192-CFB", 16),
        ("AES-256-CFB", 16),
        ("AES-128-OFB", 16),
        ("AES-192-OFB", 16),
        ("AES-256-OFB", 16),
        ("AES-128-CTR", 16),
        ("AES-192-CTR", 16),
        ("AES-256-CTR", 16),
        ("AES-128-ECB", 0),
        ("AES-192-ECB", 0),
        ("AES-256-ECB", 0),
        ("AES128", 16),
        ("AES192", 16),
        ("AES256", 16),
        ("DES-CBC", 8),
        ("DES", 8),
        ("DES-EDE3-CBC", 8),
        ("DES3", 8),
        ("DES-EDE-CBC", 8),
        ("CAMELLIA-128-CBC", 16),
        ("CAMELLIA-192-CBC", 16),
        ("CAMELLIA-256-CBC", 16),
        ("ARIA-128-CBC", 16),
        ("ARIA-192-CBC", 16),
        ("ARIA-256-CBC", 16),
        ("SEED-CBC", 16),
        ("SM4-CBC", 16),
        ("BF-CBC", 8),
        ("CAST5-CBC", 8),
        ("IDEA-CBC", 8),
        ("RC2-CBC", 8),
    ];
    TABLE
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, l)| *l)
}

// ---------------------------------------------------------------------
// The structural key test of `PEM_X509_INFO_read_bio_ex`.
// ---------------------------------------------------------------------

const RSA_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const RSA_PSS_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
const EC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const DSA_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01];
const DH_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01];
const DHX_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01];
const X25519_KEY: &[u8] = &[0x2B, 0x65, 0x6E];
const X448_KEY: &[u8] = &[0x2B, 0x65, 0x6F];
const ED25519_KEY: &[u8] = &[0x2B, 0x65, 0x70];
const ED448_KEY: &[u8] = &[0x2B, 0x65, 0x71];

/// The key families that the key test tells apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyAlg {
    Rsa,
    RsaPss,
    Ec,
    Dsa,
    Dh,
    X25519,
    X448,
    Ed25519,
    Ed448,
}

fn int_seq(body: &[u8], min: usize, max: usize) -> Option<()> {
    let mut top = Reader::new(body, Mode::Ber);
    let mut r = Reader::new(top.take(0x30)?, Mode::Ber);
    let mut n: usize = 0;
    while r.peek() == Some(0x02) {
        if !int_ok(r.take(0x02)?) {
            return None;
        }
        n = n.checked_add(1)?;
    }
    (min <= n && n <= max).then_some(())
}

/// PKCS#1 `RSAPrivateKey`: a version and eight INTEGERs, and optional
/// other prime infos.
fn pkcs1_ok(body: &[u8]) -> bool {
    int_seq(body, 9, 9).is_some() || multi_prime_ok(body).is_some()
}

fn multi_prime_ok(body: &[u8]) -> Option<()> {
    let mut top = Reader::new(body, Mode::Ber);
    let mut r = Reader::new(top.take(0x30)?, Mode::Ber);
    for _ in 0..9 {
        if !int_ok(r.take(0x02)?) {
            return None;
        }
    }
    r.take(0x30)?;
    r.finish()
}

/// SEC1 `ECPrivateKey`: version 1, the key octets, and optional
/// parameters and public key.
fn sec1_ok(body: &[u8]) -> bool {
    sec1(body).is_some()
}

fn sec1(body: &[u8]) -> Option<()> {
    let mut top = Reader::new(body, Mode::Ber);
    let mut r = Reader::new(top.take(0x30)?, Mode::Ber);
    if r.take(0x02)? != [1] {
        return None;
    }
    r.take(0x04)?;
    r.opt(0xA0)?;
    r.opt(0xA1)?;
    r.finish()
}

/// The OpenSSL DSA private key: six INTEGERs.
fn dsa_ok(body: &[u8]) -> bool {
    int_seq(body, 6, 6).is_some()
}

fn octets_of_len(inner: &[u8], len: usize) -> bool {
    let mut r = Reader::new(inner, Mode::Ber);
    r.take(0x04).is_some_and(|k| k.len() == len) && r.is_empty()
}

/// PKCS#8 `PrivateKeyInfo` with a known algorithm and a plausible key.
fn pkcs8_alg(body: &[u8]) -> Option<KeyAlg> {
    let mut top = Reader::new(body, Mode::Ber);
    let mut r = Reader::new(top.take(0x30)?, Mode::Ber);
    let version = r.take(0x02)?;
    if version != [0] && version != [1] {
        return None;
    }
    let alg = r.take(0x30)?;
    x509::algid_ok(alg, Mode::Ber)?;
    let oid = Reader::new(alg, Mode::Ber).take(0x06)?;
    if !oid_ok(oid) {
        return None;
    }
    let inner = r.take(0x04)?;
    r.opt(0xA0)?;
    r.opt(0x81)?;
    r.opt(0xA1)?;
    r.finish()?;
    let (kind, ok) = if oid == RSA_KEY {
        (KeyAlg::Rsa, pkcs1_ok(inner))
    } else if oid == RSA_PSS_KEY {
        (KeyAlg::RsaPss, pkcs1_ok(inner))
    } else if oid == EC_KEY {
        (KeyAlg::Ec, sec1_ok(inner))
    } else if oid == DSA_KEY {
        (KeyAlg::Dsa, int_seq_bare(inner))
    } else if oid == DH_KEY || oid == DHX_KEY {
        (KeyAlg::Dh, int_seq_bare(inner))
    } else if oid == X25519_KEY {
        (KeyAlg::X25519, octets_of_len(inner, 32))
    } else if oid == X448_KEY {
        (KeyAlg::X448, octets_of_len(inner, 56))
    } else if oid == ED25519_KEY {
        (KeyAlg::Ed25519, octets_of_len(inner, 32))
    } else if oid == ED448_KEY {
        (KeyAlg::Ed448, octets_of_len(inner, 57))
    } else {
        return None;
    };
    ok.then_some(kind)
}

/// One bare INTEGER: the private value of a DSA or DH PKCS#8 key.
fn int_seq_bare(inner: &[u8]) -> bool {
    let mut r = Reader::new(inner, Mode::Ber);
    r.take(0x02).is_some_and(int_ok) && r.is_empty()
}

/// Tells whether an unencrypted key block decodes as the OpenSSL CA-file
/// loader decodes it. The key type comes from the label text before
/// ` PRIVATE KEY`. A label without a known type takes any key form.
pub(crate) fn key_block_ok(label: &str, body: &[u8]) -> bool {
    let Some(pos) = label.find("PRIVATE KEY") else {
        return false;
    };
    let prefix = pos
        .checked_sub(1)
        .and_then(|end| label.get(..end))
        .map(str::to_ascii_uppercase);
    let p8 = pkcs8_alg(body);
    let only = |want: &[KeyAlg]| p8.is_some_and(|k| want.contains(&k));
    match prefix.as_deref() {
        Some("RSA") => pkcs1_ok(body) || only(&[KeyAlg::Rsa]),
        Some("RSA-PSS") => only(&[KeyAlg::RsaPss]),
        Some("EC" | "SM2") => sec1_ok(body) || only(&[KeyAlg::Ec]),
        Some("DSA") => dsa_ok(body) || only(&[KeyAlg::Dsa]),
        Some("DH" | "DHX" | "X9.42 DH") => only(&[KeyAlg::Dh]),
        Some("ED25519") => only(&[KeyAlg::Ed25519]),
        Some("ED448") => only(&[KeyAlg::Ed448]),
        Some("X25519") => only(&[KeyAlg::X25519]),
        Some("X448") => only(&[KeyAlg::X448]),
        _ => p8.is_some() || pkcs1_ok(body) || sec1_ok(body) || dsa_ok(body),
    }
}

#[cfg(test)]
#[path = "pem_diff_tests.rs"]
mod pem_diff_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn b64_decode(text: &[u8]) -> Option<Vec<u8>> {
        super::b64_decode(text).map(|z| z.to_vec())
    }

    #[test]
    fn base64_rules() {
        assert_eq!(b64_decode(b"QUJD"), Some(b"ABC".to_vec()));
        assert_eq!(b64_decode(b"QUI=\n"), Some(b"AB".to_vec()));
        assert_eq!(b64_decode(b"QQ=="), Some(b"A".to_vec()));
        assert_eq!(b64_decode(b"QR=="), Some(b"A".to_vec()));
        assert_eq!(b64_decode(b"Q U\tJ\r\nD"), Some(b"ABC".to_vec()));
        assert_eq!(b64_decode(b"QUJD-garbage"), Some(b"ABC".to_vec()));
        assert_eq!(b64_decode(b"QUJ"), None);
        assert_eq!(b64_decode(b"Q==="), None);
        assert_eq!(b64_decode(b"QQ==QUJD"), None);
        assert_eq!(b64_decode(b"QU*D"), None);
    }

    #[test]
    fn sanitize_strips_high_and_control_bytes() {
        assert_eq!(sanitize(b"abc \t\r\n"), b"abc");
        assert_eq!(sanitize(b"abc\xc3\xa9"), b"abc");
        assert_eq!(sanitize(b"  \n"), b"");
    }

    #[test]
    fn lines_stop_at_nul_and_split_long_lines() {
        let long = [b'A'; 300];
        let mut l = Lines { data: &long };
        assert_eq!(l.next_chunk().map(<[u8]>::len), Some(254));
        assert_eq!(l.next_chunk().map(<[u8]>::len), Some(46));
        assert_eq!(l.next_chunk(), None);
        let mut l = Lines {
            data: b"ab\0cd\n\0x\nyz\n",
        };
        assert_eq!(l.next_chunk(), Some(&b"ab"[..]));
        assert_eq!(l.next_chunk(), None);
    }

    #[test]
    fn headers_and_cipher_info() {
        let h = parse_headers(
            b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n",
        );
        assert!(cipher_info_ok(&h));
        let h = parse_headers(b"Proc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,0011\n");
        assert!(!cipher_info_ok(&h));
        let h = parse_headers(b"Proc-Type: 4,ENCRYPTED\nDEK-Info: NOPE-CBC,0011223344556677\n");
        assert!(!cipher_info_ok(&h));
        let h = parse_headers(b"DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n");
        assert!(!cipher_info_ok(&h));
        let h = parse_headers(b"Comment: a\n b\nOther\n");
        assert_eq!(
            h,
            vec![
                ("Comment".to_owned(), "a\n b".to_owned()),
                ("Other".to_owned(), String::new())
            ]
        );
    }
}
