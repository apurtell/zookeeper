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

//! Traditional OpenSSL PEM decryption.
//!
//! A key block with `Proc-Type: 4,ENCRYPTED` and `DEK-Info` is decrypted
//! with `EVP_BytesToKey` (MD5, count 1, salt `IV[0..8]`), then
//! AES-128/192/256-CBC, DES-EDE3-CBC or DES-CBC, then strict PKCS#7
//! padding removal. The derived key and the plaintext are zeroizing
//! buffers, and each digest goes straight into the key buffer. A wrong
//! passphrase shows as bad padding or bad DER.
//!
//! The header rule is that of OpenSSL `PEM_get_EVP_CIPHER_INFO`: the
//! first header is `Proc-Type`, and the second header is `DEK-Info`.
//! The IV has exactly two hex digits per byte.
//!
//! The CBC helper `cbc_decrypt` also decrypts PBES2 keys
//! (`identity.rs`). The FIPS build does not compile this module.

#![cfg(feature = "_legacy-keys")]

use cipher::block_padding::Pkcs7;
use cipher::{BlockCipher, BlockDecryptMut, KeyInit, KeyIvInit};
use der::zeroize::Zeroizing;
use md5::digest::Output;
use md5::{Digest, Md5};
use zk_proto::SecretBytes;

use crate::net::tls::identity::KeyError;
use crate::net::tls::pem::PemBlock;

/// The ciphers of `DEK-Info`. Any other name is rejected, although
/// OpenSSL accepts more ciphers. This is a known difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DekCipher {
    /// AES-128-CBC: key 16, IV 16.
    Aes128Cbc,
    /// AES-192-CBC: key 24, IV 16.
    Aes192Cbc,
    /// AES-256-CBC: key 32, IV 16.
    Aes256Cbc,
    /// DES-EDE3-CBC: key 24, IV 8.
    DesEde3Cbc,
    /// DES-CBC: key 8, IV 8.
    DesCbc,
}

impl DekCipher {
    /// Finds a cipher by its OpenSSL name. The match ignores case, as
    /// `EVP_get_cipherbyname` does.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            ("AES-128-CBC", Self::Aes128Cbc),
            ("AES-192-CBC", Self::Aes192Cbc),
            ("AES-256-CBC", Self::Aes256Cbc),
            ("DES-EDE3-CBC", Self::DesEde3Cbc),
            ("DES-CBC", Self::DesCbc),
        ]
        .into_iter()
        .find_map(|(n, c)| n.eq_ignore_ascii_case(name).then_some(c))
    }

    /// Returns the key length in bytes.
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes192Cbc | Self::DesEde3Cbc => 24,
            Self::Aes256Cbc => 32,
            Self::DesCbc => 8,
        }
    }

    /// Returns the IV length in bytes, which is the block length.
    #[must_use]
    pub fn iv_len(self) -> usize {
        match self {
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => 16,
            Self::DesEde3Cbc | Self::DesCbc => 8,
        }
    }
}

/// Tells whether a block uses traditional encryption: it has the header
/// `Proc-Type: 4,ENCRYPTED`.
#[must_use]
pub fn is_encrypted(block: &PemBlock) -> bool {
    block
        .headers
        .iter()
        .any(|(k, v)| k == "Proc-Type" && proc_type_encrypted(v))
}

/// Decrypts a traditional encrypted PEM key block into the DER of its
/// label (PKCS#1, SEC1 or PKCS#8).
///
/// # Errors
///
/// Returns [`KeyError::Rejected`] for a bad header or cipher, and
/// [`KeyError::BadPassphrase`] for bad padding.
pub fn decrypt(block: &PemBlock, passwd: &[u8]) -> Result<SecretBytes, KeyError> {
    let (cipher, iv) = dek_info(&block.headers)?;
    let salt = iv.get(..8).ok_or(KeyError::Rejected)?;
    let key = bytes_to_key(passwd, salt, cipher.key_len());
    let mut buf = block.body.expose().to_vec();
    match cbc_decrypt(cipher, &key, &iv, &mut buf) {
        Ok(len) => {
            buf.truncate(len);
            Ok(SecretBytes::new(buf))
        }
        Err(e) => {
            drop(SecretBytes::new(buf));
            Err(e)
        }
    }
}

/// Decrypts `buf` in place with CBC and strict PKCS#7 padding removal.
/// It returns the plaintext length.
///
/// # Errors
///
/// Returns [`KeyError::Rejected`] for a bad key or IV length, and
/// [`KeyError::BadPassphrase`] for a bad length or bad padding.
pub(crate) fn cbc_decrypt(
    cipher: DekCipher,
    key: &[u8],
    iv: &[u8],
    buf: &mut [u8],
) -> Result<usize, KeyError> {
    match cipher {
        DekCipher::Aes128Cbc => cbc_with::<aes::Aes128>(key, iv, buf),
        DekCipher::Aes192Cbc => cbc_with::<aes::Aes192>(key, iv, buf),
        DekCipher::Aes256Cbc => cbc_with::<aes::Aes256>(key, iv, buf),
        DekCipher::DesEde3Cbc => cbc_with::<des::TdesEde3>(key, iv, buf),
        DekCipher::DesCbc => cbc_with::<des::Des>(key, iv, buf),
    }
}

/// The CBC decryption of one block cipher.
fn cbc_with<C>(key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<usize, KeyError>
where
    C: BlockCipher + BlockDecryptMut + KeyInit,
{
    let dec = cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| KeyError::Rejected)?;
    dec.decrypt_padded_mut::<Pkcs7>(buf)
        .map(<[u8]>::len)
        .map_err(|_| KeyError::BadPassphrase)
}

/// Tells whether a `Proc-Type` value is `4,ENCRYPTED`. OpenSSL allows
/// blanks after the comma and at the end, and none before the comma.
fn proc_type_encrypted(value: &str) -> bool {
    value
        .trim()
        .strip_prefix("4,")
        .is_some_and(|v| v.trim_start() == "ENCRYPTED")
}

/// Reads the cipher and the IV from the headers.
fn dek_info(headers: &[(String, String)]) -> Result<(DekCipher, Vec<u8>), KeyError> {
    let mut it = headers.iter();
    match it.next() {
        Some((k, v)) if k == "Proc-Type" && proc_type_encrypted(v) => {}
        _ => return Err(KeyError::Rejected),
    }
    let info = match it.next() {
        Some((k, v)) if k == "DEK-Info" => v.trim(),
        _ => return Err(KeyError::Rejected),
    };
    let (name, iv) = info.split_once(',').ok_or(KeyError::Rejected)?;
    let cipher = DekCipher::from_name(name.trim()).ok_or(KeyError::Rejected)?;
    let iv = hex(iv.trim(), cipher.iv_len()).ok_or(KeyError::Rejected)?;
    Ok((cipher, iv))
}

/// Decodes exactly `len` bytes of hex, in upper or lower case.
fn hex(text: &str, len: usize) -> Option<Vec<u8>> {
    if text.len() != len.checked_mul(2)? {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let mut byte = 0u8;
            for &c in pair {
                let nibble = u8::try_from(char::from(c).to_digit(16)?).ok()?;
                byte = byte.checked_mul(16)?.checked_add(nibble)?;
            }
            Some(byte)
        })
        .collect()
}

/// `EVP_BytesToKey` with MD5 and one iteration. `D1 = MD5(pass || salt)`
/// and `D2 = MD5(D1 || pass || salt)`. The key is the first `key_len`
/// bytes of `D1 || D2`, which covers every cipher of [`DekCipher`].
fn bytes_to_key(pass: &[u8], salt: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; 32]);
    let (d1, d2) = out.split_at_mut(16);
    let mut h = Md5::new();
    h.update(pass);
    h.update(salt);
    h.finalize_into(Output::<Md5>::from_mut_slice(d1));
    if key_len > 16 {
        let mut h = Md5::new();
        h.update(&*d1);
        h.update(pass);
        h.update(salt);
        h.finalize_into(Output::<Md5>::from_mut_slice(d2));
    }
    out.truncate(key_len);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn bytes_to_key_matches_openssl() {
        // `openssl enc -aes-256-cbc -P -md md5 -pass pass:pw
        // -S 0102030405060708` prints this key.
        let want = hex(
            "222776D258E716EFDAA0CF5A7E504B9D21982575418A44BE8D93693294778EEA",
            32,
        )
        .unwrap();
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(&*bytes_to_key(b"pw", &salt, 32), &want[..]);
        assert_eq!(&*bytes_to_key(b"pw", &salt, 24), &want[..24]);
        assert_eq!(&*bytes_to_key(b"pw", &salt, 16), &want[..16]);
        assert_eq!(&*bytes_to_key(b"pw", &salt, 8), &want[..8]);
    }

    #[test]
    fn dek_info_follows_the_openssl_header_rule() {
        let iv16 = "000102030405060708090A0B0C0D0E0F";
        let (c, iv) = dek_info(&headers(&[
            ("Proc-Type", "4,ENCRYPTED"),
            ("DEK-Info", &format!("aes-128-cbc,{}", iv16.to_lowercase())),
        ]))
        .unwrap();
        assert_eq!(c, DekCipher::Aes128Cbc);
        assert_eq!(iv, (0u8..16).collect::<Vec<_>>());
        let ok = dek_info(&headers(&[
            ("Proc-Type", "4, ENCRYPTED "),
            ("DEK-Info", "DES-EDE3-CBC,0001020304050607"),
        ]));
        assert_eq!(ok.unwrap().0, DekCipher::DesEde3Cbc);
        for bad in [
            vec![("DEK-Info", "AES-128-CBC,00")],
            vec![("Proc-Type", "4,ENCRYPTED")],
            vec![
                ("Proc-Type", "4 ,ENCRYPTED"),
                ("DEK-Info", "DES-CBC,0001020304050607"),
            ],
            vec![
                ("Proc-Type", "4,MIC-ONLY"),
                ("DEK-Info", "DES-CBC,0001020304050607"),
            ],
            vec![
                ("Proc-Type", "4,ENCRYPTED"),
                ("X", "y"),
                ("DEK-Info", "DES-CBC,0001020304050607"),
            ],
            vec![("Proc-Type", "4,ENCRYPTED"), ("DEK-Info", "DES-CBC")],
            vec![
                ("Proc-Type", "4,ENCRYPTED"),
                ("DEK-Info", "DES-CBC,00010203040506"),
            ],
            vec![
                ("Proc-Type", "4,ENCRYPTED"),
                ("DEK-Info", "DES-CBC,000102030405060708"),
            ],
            vec![
                ("Proc-Type", "4,ENCRYPTED"),
                ("DEK-Info", "DES-CBC,00010203040506zz"),
            ],
            vec![
                ("Proc-Type", "4,ENCRYPTED"),
                ("DEK-Info", "AES-128-CFB,000102030405060708090A0B0C0D0E0F"),
            ],
            vec![
                ("Proc-Type", "4,ENCRYPTED"),
                ("DEK-Info", "DES-CBC,0001020304050\u{e9}"),
            ],
        ] {
            assert_eq!(dek_info(&headers(&bad)), Err(KeyError::Rejected), "{bad:?}");
        }
    }

    #[test]
    fn cbc_needs_strict_padding_and_whole_blocks() {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        for len in [0usize, 15, 17] {
            let mut buf = vec![0u8; len];
            assert_eq!(
                cbc_decrypt(DekCipher::Aes128Cbc, &key, &iv, &mut buf),
                Err(KeyError::BadPassphrase)
            );
        }
        let mut buf = vec![0u8; 16];
        assert_eq!(
            cbc_decrypt(DekCipher::Aes128Cbc, &key, &iv[..8], &mut buf),
            Err(KeyError::Rejected)
        );
        assert_eq!(
            cbc_decrypt(DekCipher::Aes256Cbc, &key, &iv, &mut buf),
            Err(KeyError::Rejected)
        );
    }
}
