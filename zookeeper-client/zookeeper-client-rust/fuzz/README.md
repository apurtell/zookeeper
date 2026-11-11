<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
//-->

# Fuzz targets of the Rust client

This crate holds the `cargo fuzz` targets of the Rust client. It is not
a member of the main workspace. It needs a nightly toolchain, and it
has its own `Cargo.lock`.

## Targets

| Target | Input |
| --- | --- |
| `jute_records` | One jute record of `zk-jute`, picked by the first byte. |
| `frame_decoder` | A frame stream, given to `FrameDecoder` in fuzz chunks. |
| `connect_response` | A connect response to a new `zk-proto` session. |
| `multi_response` | A multi response, alone and as a session reply. |
| `session_stream` | A program of server frames and driver calls for a session. |
| `sasl_frames` | SASL replies and mechanism results for a session. |
| `connect_string` | A connect string for the legacy and the native parsers. |
| `zpath` | A chroot and a path for the path checks. |
| `sasl_digest_md5` | Challenges for the DIGEST-MD5 mechanism, and the correct `rspauth` on request. |
| `tls_trust` | A PEM CA file for the trust store and the chain check. |
| `tls_keys` | A passphrase and a PEM key file, plain or encrypted. |
| `tls_stream` | TLS records for the client stream of `zk-driver`. |
| `ffi_writers` | Replies and C buffers for the result writers of `zk-ffi`. |

The targets use the public API of the client crates. There are two
exceptions:

- `sasl_digest_md5` calls `apache_zookeeper::sasl::fuzzing`. Only a
  build with `--cfg fuzzing` has this module.
- `ffi_writers` includes the writer source of `zk-ffi` with `#[path]`.
  The writers fill C buffers through raw pointers, so this target uses
  `unsafe`. AddressSanitizer finds each write out of bounds.

## Seeds

The repository holds no seeds. The seed generator writes them to
`corpus/<target>/`, which git ignores:

```sh
cargo +nightly run --example gen_seeds
```

The TLS seeds and the `tls_stream` target use the certificates of
`zk-testkit`. The test kit makes them once with the `openssl` tool, so
`openssl` must be on the `PATH`.

## Runs

Install `cargo-fuzz` once, then run a target from this directory:

```sh
cargo install --locked cargo-fuzz
cargo +nightly fuzz run session_stream -- -max_total_time=60
```

A crash input goes to `artifacts/<target>/`. Use `cargo fuzz tmin` to
make it smaller, and add a regression test to the tests of the product
crate.

The `tls_trust` and `tls_keys` targets write each input to a temporary
file, because the product code reads key and CA files by path. The file
name contains the process ID. Each input removes its file after use.

The `tls_keys` target does not decrypt a key with a costly key
derivation. A PBKDF2 key with more than 2048 iterations or a scrypt key
with more than 8192 units of work only goes through the parameter check.

A plain `cargo check` of this crate fails on `sasl_digest_md5`, because
that target needs the `fuzzing` module. Set the flag for checks:

```sh
RUSTFLAGS="--cfg fuzzing" cargo clippy --all-targets
```
