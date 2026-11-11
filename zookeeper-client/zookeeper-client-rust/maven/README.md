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

# The Maven build of the Rust client

The Maven module `zookeeper-client-rust` builds the Cargo workspace. The
module is optional. A default Maven build does not include it and does
not need Cargo.

`rust-module.sh` does the work for the module. `pom.xml` calls it from
`exec-maven-plugin` and gives it the Maven properties in the environment.

## Selection

The `rust` profile of `zookeeper-client` adds the module. `-Prust`
activates it, and so does each `-Drust-client=...` on the command line.

| Property | Default | Meaning |
|---|---|---|
| `rust-client` | `no` | `yes` builds the Rust core. `no` builds nothing. Each other value stops the build. |
| `rust-tls` | `no` | `yes` builds TLS into the Rust core. |
| `rust-tls-provider` | `ring` | The TLS provider: `ring`, `aws-lc-rs` or `aws-lc-rs-fips`. |
| `rust-cargo-vendor` | empty | An absolute vendor directory. Cargo then runs offline. |
| `rust-system-crates` | empty | An absolute directory of system crates. Cargo then runs offline and writes `Cargo.lock` again. |
| `c-client-openssl` | `yes` | The OpenSSL option of the C client. The TLS probe uses it. |
| `c-client-sasl` | `yes` | The SASL option of the C client. The SASL probe uses it. |

Maven does not support `auto`. Give only one of `rust-cargo-vendor` and
`rust-system-crates`. Cargo writes to `target/cargo` in this module.

The enforcer rule of this module checks `rust-client`. In a full reactor,
the modules before this one build first, so a bad value stops the build
late.

## Lifecycle

| Lifecycle | Execution | Work |
|---|---|---|
| `validate` | `rust-client-value` | The enforcer checks `rust-client`. |
| `process-sources` | `rust-prepare` | Checks the options and the toolchain (1.85 or later). Checks that the `Cargo.toml` version is the project version. Takes the TLS and SASL decisions of `configure`, and runs `cargo fetch`. |
| `compile` | `rust-build` | `cargo build -p zk-ffi --profile capi`, then `cargo build --workspace --release --exclude zk-ffi`. |
| `test` | `rust-test` | `cargo test` for the workspace, for zk-ffi and for the `zk-ffi-layout` check. |
| `integration-test` | `rust-curator-interop` | The Curator interop test (profile `rust-integration` only). |
| `verify` | `rust-lint`, `rust-supply-chain` | The lint checks and the supply chain checks. |

The prepare task writes its decisions to `target/rust-build.env`. The
other tasks read that file, so the staticlib, the tests and the checks
use the same features and the same crate sources.

## Profiles

| Profile | Activation | Work |
|---|---|---|
| `cargo-test` | active, `-DskipCargoTest` skips it | Runs the cargo tests. `-DskipTests` also skips them. |
| `rust-lint` | active, `-DskipRustLint` skips it | `cargo fmt --all --check` and `cargo clippy` with `-D warnings`. |
| `rust-supply-chain` | `-Prust-supply-chain` | `cargo deny check` with `deny.toml` and with `deny-fips.toml`, and `cargo xtask closure check`. `cargo vet` and `cargo audit` run when they are installed. |
| `rust-integration` | `-Prust-integration` | Runs `dev/run-curator-interop.sh`. |
| `rust-test-coverage` | `-Prust-test-coverage` | Runs the tests with `cargo llvm-cov`. The report goes to `target/rust-coverage`. |
| `rust-test-asan` | `-Prust-test-asan` | Runs the tests with AddressSanitizer on a nightly toolchain. |

## Tests with real servers

By default, `cargo test` does not run the real-server tests.
`-Drust-test-port-base=PORT` runs them too. They start their servers with `dev/test-server.sh` and use
the ports PORT to PORT+19. They need the server classes, so build
`zookeeper-server` first. A test that cannot start its server fails.

The Curator interop test uses `-Drust-it-port-base` (default 23400) and
the server versions in `-Drust-it-server-versions` (default `head`).
`-Drust-it-mvn-args` gives extra arguments to the Maven run of the test.

## Examples

```sh
# The Rust core of the C client, with TLS through ring.
mvn -Pfull-build -Drust-client=yes -Drust-tls=yes install

# The Rust module only. Build zookeeper-jute and zookeeper-server first.
mvn -Prust -Drust-client=yes -pl zookeeper-client/zookeeper-client-rust verify

# The real-server tests and the supply chain checks.
mvn -Prust -Prust-supply-chain -Drust-client=yes -Drust-test-port-base=23700 \
  -pl zookeeper-client/zookeeper-client-rust verify

# The Curator interop test.
mvn -Prust -Prust-integration -Drust-client=yes -DskipCargoTest \
  -pl zookeeper-client/zookeeper-client-rust verify
```

## Supply chain checks

Each cargo-deny policy checks the union of its feature sets over the
whole workspace graph. `cargo xtask closure check` compares each shipped
build with its inventory in `supply-chain/closure`. The comparison uses
the crate sources of the prepare task.

With `rust-system-crates`, the closure comparison accepts
semver-compatible versions. cargo-vet certifies exact versions, so its
failure is a note in that mode.

## The C client

With `rust-client` set, `zookeeper-client-c` depends on this module, so
the module builds first. The C module gives `configure` these options:
`--with-rust-client`, `--with-rust-staticlib`, `--with-rust-tls`,
`--with-rust-tls-provider`, `--with-cargo-vendor` and
`--with-system-rust-crates`. `configure` links the prebuilt staticlib and
does not run Cargo. With `rust-client=yes`, the C module runs
`make abi-check` in `verify`.

The two crate options get the values of `rust-cargo-vendor` and
`rust-system-crates`. An empty value gives no crate source. Thus the
cargo calls of `make abi-check` use the crate sources of this module.
The two modules run in different directories, so give absolute
directories. The Curator interop task also gives the crate sources to
the build of its peer binary.

A build of both modules with a vendor directory. The section "Offline
builds" of `c/shim/README.md` shows how to make the directory.

```sh
mvn -Pfull-build -Drust-client=yes -Drust-cargo-vendor=/path/to/vendor \
  -pl zookeeper-client/zookeeper-client-rust,zookeeper-client/zookeeper-client-c verify
```

## Versions

The root `pom.xml` gives the version. The `rust-prepare` execution stops
the build when the `[workspace.package]` version of `Cargo.toml` is not
the project version without `-SNAPSHOT`. The root execution
`replace-rustclient-files-during-release` writes the project version to
the C version files and to `Cargo.toml`. It also writes it to the
workspace entries of the lock files and to the parent version of this
`pom.xml`. The release
goals run it, and they commit the changed files. To run it by hand:

```sh
mvn -N antrun:run@replace-rustclient-files-during-release
```
