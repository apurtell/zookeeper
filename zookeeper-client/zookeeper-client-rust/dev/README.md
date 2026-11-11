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

# Developer scripts of the Rust client

This directory holds the scripts that build the drop-in C libraries for
development and that run ZooKeeper servers for the real-server tests. The
scripts are bash scripts. Each script has a header with its usage and its
environment variables. The header is the full reference. This file gives a
summary.

Tests and other scripts call these scripts by path. Do not rename or move
them.

| Script | Purpose | Called by | Platforms |
|---|---|---|---|
| `build-dropin.sh` | Builds and checks the drop-in `libzookeeper_mt` and `libzookeeper_st` | developers, `c/tests/link` | macOS only |
| `test-server.sh` | Starts or stops one standalone server | Rust tests, `c/tests/conformance`, `c/tests/public`, the runners below | macOS, Linux |
| `test-ensemble.sh` | Starts or stops a three-node ensemble | Rust tests, `run-curator-interop.sh` | macOS, Linux |
| `get-release-server.sh` | Downloads and checks a ZooKeeper binary release | the two runners below, developers | macOS, Linux |
| `run-recipes-real.sh` | Runs the zk-recipes real-server tests against several servers | developers, CI-style jobs | macOS, Linux |
| `run-curator-interop.sh` | Runs the Curator interop test of zk-recipes | developers, CI-style jobs | macOS, Linux |

## The server under test

The real-server scripts use the server of this source tree (HEAD) by
default. Build it first:

```sh
mvn -DskipTests install -pl zookeeper-server -am
```

A release server replaces HEAD when one of these variables is set:

| Variable | Meaning |
|---|---|
| `ZK_TEST_SERVER_HOME` | The directory of an extracted binary release. |
| `ZK_TEST_SERVER_VERSION` | A release version below `ZK_TEST_SERVERS_DIR`. `get-release-server.sh` puts it there. |
| `ZK_TEST_SERVERS_DIR` | The directory of the downloaded releases (default `/tmp/zk-servers`). |
| `ZK_TEST_SOURCE_ROOT` | The source tree of the HEAD server (default: the tree that holds these scripts). |

The server scripts need a JDK (`java` on `PATH`) and `nc`.

## build-dropin.sh

This script builds the Rust-core drop-in libraries without configure or
CMake. It joins the zk-ffi staticlib, the C shim and the jute and recordio
objects into one object per flavor. Only the golden symbols stay global.
It then makes the dylib, the static archive and `cli_mt` or `cli_st`. It
checks the export set against `c/abi/symbols.tsv`, runs smoke programs,
and with `ABI_CHECK=1` runs `cargo xtask abi check` and
`cargo xtask abi static`.

The script supports macOS only. It uses Mach-O linker options and `otool`.
On Linux and on other platforms, use the main build of
`zookeeper-client-c`:

- autotools: `configure --with-rust-client=yes` (hooks in
  `c/m4/zk_rust.m4` and `c/rust.am`);
- CMake: `-DWITH_RUST_CLIENT=ON` (hooks in `c/cmake/ZkRustClient.cmake`).

These hooks build the same libraries on Linux, on other hosts with GNU
`ld` and `objcopy`, and on macOS. They do not build the Rust core on
Cygwin. The CMake hooks also do not build it on Windows.

Usage, from the `zookeeper-client-rust` directory:

```sh
CONFIG=plain FLAVORS="mt st" ABI_CHECK=1 dev/build-dropin.sh .. /tmp/zk-dropin
```

The first argument is the `zookeeper-client` directory. The second
argument is the output directory. Both arguments are optional. The
defaults are the `zookeeper-client` directory of this tree and its
`target-dropin` directory.

Prerequisites: the Xcode command line tools, a Rust toolchain, and the
generated jute sources in `zookeeper-client-c/generated`. The `ssl` and
`full` configurations use `openssl` to find the default trust locations.
The `sasl` and `full` configurations need Cyrus SASL.

Ports: none. With `SMOKE_HOST=HOST:PORT`, the static cli runs `ls /`
against that server.

| Variable | Default | Meaning |
|---|---|---|
| `CONFIG` | `plain` | `plain`, `ssl`, `sasl` or `full`. |
| `FLAVORS` | `mt st` | The flavors to build. |
| `TLS_PROVIDER` | `ring` | The rustls provider: `ring` or `aws-lc-rs`. |
| `TLS_DEFAULT_PATHS` | the OPENSSLDIR of `OPENSSL_PREFIX` | `FILE:DIR`, the default trust locations. |
| `OPENSSL_PREFIX` | the Homebrew `openssl@3` prefix | Gives the headers for `cli_FL` and the `openssl` command. The build never links OpenSSL. |
| `SASL_PREFIX` | the Homebrew `cyrus-sasl` prefix | The Cyrus SASL prefix. |
| `CARGO_TARGET_DIR` | the workspace `target` | The cargo target directory. |
| `ARCH` | `uname -m` | The Mach-O architecture. |
| `CC` | `cc` | The C compiler. |
| `INSTALL_DIR` | the output directory | The directory part of the dylib install names. |
| `ABI_CHECK` | `0` | `1` runs the ABI checks of `cargo xtask abi`. |
| `SMOKE_HOST` | unset | A running server for the static cli test. |

The script finds the Homebrew prefixes with `brew --prefix`. Without
`brew`, it uses `/opt/homebrew`. Set the variables to use another install.

## test-server.sh

This script starts or stops one standalone server on `127.0.0.1`.

```sh
dev/test-server.sh start PORT [DIR]
dev/test-server.sh stop PORT [DIR]
```

The default port is 22181. The default directory is
`${TMPDIR:-/tmp}/zk-rust-test-PORT`. The start waits until the server
serves requests. The stop waits until the server exits, and it kills only a
ZooKeeper process.

`ZK_TEST_SERVER_PROPS` adds `zoo.cfg` lines. `ZK_TEST_SERVER_JVM_OPTS`
adds JVM options. The release variables of the section above also apply.

## test-ensemble.sh

This script starts or stops a three-node ensemble on `127.0.0.1`.

```sh
dev/test-ensemble.sh start BASE [DIR]
dev/test-ensemble.sh stop BASE [DIR]
dev/test-ensemble.sh stop-node BASE N [DIR]
dev/test-ensemble.sh start-node BASE N [DIR]
dev/test-ensemble.sh leader BASE
```

Node N (1 to 3) uses the client port BASE+N-1, the quorum port BASE+N+2
and the election port BASE+N+5. Thus the ensemble uses the ports BASE to
BASE+8. The default directory is `${TMPDIR:-/tmp}/zk-rust-ensemble-BASE`.
The variables are the same as for `test-server.sh`.

## get-release-server.sh

This script downloads an Apache ZooKeeper binary release from
`archive.apache.org`, checks its SHA-512 sum, and extracts it.

```sh
dev/get-release-server.sh 3.9.6
```

The release goes to `$ZK_TEST_SERVERS_DIR/VERSION` (default
`/tmp/zk-servers`). The script runs nothing from the release. A release
that is already there is not downloaded again.

Prerequisites: `curl`, `tar`, and `shasum` or `sha512sum`. Ports: none.

## run-recipes-real.sh

This script runs the zk-recipes real-server tests against each given server
version, on a standalone server and on an ensemble.

```sh
dev/run-recipes-real.sh [VERSION ...]
```

A version is `head` or a release version. The default is `head 3.9.6`.
The script also gets the 3.5.10 release for the TreeCache test.

| Variable | Default | Meaning |
|---|---|---|
| `ZK_TEST_PORT_BASE` | `23400` | The tests use the ports BASE to BASE+9. |
| `ZK_TEST_REQUIRE_SERVER` | `1` | A test that cannot start its server fails and does not skip. |
| `ZK_RECIPES_REPEAT` | `1` | The number of runs for each version. |
| `ZK_RECIPES_CARGO_ARGS` | empty | Extra cargo arguments. |
| `ZK_TEST_SOURCE_ROOT` | this source tree | The source tree of the HEAD server. |

Prerequisites: cargo and the server prerequisites.

## run-curator-interop.sh

This script runs the JUnit project `interop/curator`. The test checks that
the Rust lock and leader latch of zk-recipes work together with the Apache
Curator `InterProcessMutex` and `LeaderLatch`.

```sh
dev/run-curator-interop.sh [VERSION ...]
```

A version is `head` or a release version. The default is `head 3.9.6`.

| Variable | Default | Meaning |
|---|---|---|
| `ZK_TEST_PORT_BASE` | `23400` | The standalone server uses BASE. The ensemble uses BASE+1 to BASE+9. |
| `ZK_INTEROP_PROXY_PORT` | `0` (a free port) | The port of the proxy of the recovery test. |
| `ZK_INTEROP_TOPOLOGIES` | `standalone ensemble` | The topologies to test. |
| `ZK_INTEROP_MVN_ARGS` | empty | Extra Maven arguments, for example `-Dtest=...`. |
| `ZK_INTEROP_REPEAT` | `1` | The number of passes for each version and topology. |
| `ZK_DEV_DIR` | this directory | The directory of the server scripts. |
| `CARGO_TARGET_DIR` | the workspace `target` | The cargo target directory of the peer binary. |

The script and the zk-recipes real-server tests share a port lease, the
directory `${TMPDIR:-/tmp}/zk-recipes-lease-BASE`. Thus they never use one
port range at the same time.

Prerequisites: cargo, Maven and the server prerequisites.
