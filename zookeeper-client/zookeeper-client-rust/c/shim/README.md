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

# The C shim of the Rust client core

This directory holds the C half of the Rust-core drop-in libraries. The
Rust half is the `zk-ffi` crate in `zookeeper-client-rust/crates/zk-ffi`.
For each flavor, the build joins the `zk-ffi` staticlib, the shim of the
flavor and the unchanged `src/recordio.c` and `generated/zookeeper.jute.c`
into one relocatable object (`zookeeper_FL_all.o`). Only the golden
symbols stay global in that object (`abi/prelink.sh`). The shared library
then exports the golden set of its flavor (`abi/gen-exports.awk`). The
static archive has that object as its only member.

Paths in this file such as `shim/`, `abi/` and `tests/public/` are
relative to `zookeeper-client/zookeeper-client-rust/c`, the Rust C tree.
That tree holds the C sources and the build logic of the Rust core.
The legacy C tree `zookeeper-client/zookeeper-client-c` keeps the legacy
sources `include/`, `src/` and `generated/`. It also keeps the legacy
tests `tests/*.cc` and `tests/zkServer.sh`. Its three build files
include the logic of the Rust C tree. The `tests/` directory of the Rust
C tree holds development and conformance material. A release can omit
it. The build then skips the checks that use it.

Scope: the mt flavor (`libzookeeper_mt`) and the st flavor
(`libzookeeper_st`), shared and static, in four configurations. Column 4
of `abi/symbols.tsv` gives the feature of each row (`-`, `ssl` or
`sasl`). Each library exports the rows of its flavor and configuration:

| Configuration | TLS | SASL | mt exports | st exports |
|---|---|---|---|---|
| `plain` | no | no | 201 | 178 |
| `ssl` | yes | no | 202 | 179 |
| `sasl` | no | yes | 210 | 187 |
| `full` | yes | yes | 211 | 188 |

One `zk-ffi` staticlib serves both flavors, because the flavor is a
run-time value. The legacy C core stays the default, and its build does
not change.

The st flavor has no library threads. The application drives the handle
with `zookeeper_interest` and `zookeeper_process`. The st shim omits
`zks_sync.c` and `zks_threads.c`. Both flavors disable thread
cancellation during each call into Rust. In mt, the mask also covers each
scope that runs application callbacks (`ZKS_HOLD_SCOPE`). In st, no Rust
frame is active while a callback runs, so an st callback keeps the
cancel state of legacy st.

## Requirements

- cargo and rustc 1.85 or later. A build with a prebuilt staticlib needs
  only rustc.
- The crate sources: network access, or a full `CARGO_HOME`. configure
  and CMake run `cargo fetch --locked`.
- Autotools (autoconf, automake, GNU libtool) or CMake 3.15 or later. A
  Mach-O shared library from CMake needs CMake 3.17 or later.
- `generated/zookeeper.jute.{c,h}` from the jute compiler, as for the
  legacy build.

## Files

| File | Content |
|---|---|
| `zks_internal.h` | The private header. Every shim unit includes it first. |
| `zkrs.h` | The Rust ABI. cbindgen generates it from `zk-ffi`. |
| `zks_log_sites.h` | The core log sites and the C log sites. `cargo xtask log-sites header` generates it. |
| `zks_*.c` | The shim units. `zks_sync.c` and `zks_threads.c` are mt only. |
| `zks_hashtable_stub.c` | The only member of the CMake `hashtable` archive. It has no global symbols. |
| `zks_tls.c` | `zookeeper_init_ssl` and the parser of the cert string. TLS builds only. |
| `zks_sasl.h` | The private SASL interface of the shim. SASL builds only. |
| `zks_sasl_cb.h` | The private header of the Cyrus glue. Only the two SASL units include it. |
| `zks_sasl_cyrus.c` | The Cyrus session, `zookeeper_init_sasl` and the SASL entry points. SASL builds only. |
| `zks_sasl_cb.c` | The legacy SASL callbacks and `zoo_sasl_make_basic_callbacks`. SASL builds only. |

A TLS build defines `ZKS_WITH_TLS` and `HAVE_OPENSSL_H`. A SASL build
defines `ZKS_WITH_SASL` and `HAVE_CYRUS_SASL_H`, and links `-lsasl2`. No
build links OpenSSL. `zks_internal.h` removes `HAVE_OPENSSL_H` from every
shim unit, and `HAVE_CYRUS_SASL_H` from every unit except the two Cyrus
glue units. Only the glue units get the Cyrus include directory (as
`-isystem`) and the conversion warnings. configure,
CMake and `zookeeper-client-rust/dev/build-dropin.sh` (`CONFIG=ssl`,
`CONFIG=sasl` or `CONFIG=full`) select these builds. The section "TLS
and SASL" below gives the rules.

Do not edit `zkrs.h` or `zks_log_sites.h` by hand.

## Autotools

configure selects the core with `--with-rust-client`:

| Value | Result |
|---|---|
| `no` (default) | The legacy C core. The Rust options are ignored. |
| `yes` | The Rust core in `$(libdir)`, with `cli_st`, `cli_mt` and `load_gen`. A failed check is an error. |
| `auto` | The Rust core when the check passes, else the legacy core with a notice. |

The other options:

- `--with-rust-workspace=DIR`: the Rust workspace. The default is
  `$srcdir/../zookeeper-client-rust`, the workspace that holds this
  `c/` directory.
- `--with-rust-staticlib=PATH`: link this prebuilt `libzk_ffi.a`. make
  does not run cargo.
- `--with-rust-target=TRIPLE`: give `--target TRIPLE` to cargo. A cross
  build needs it.
- `--with-rust-tls=yes|no`: build TLS also when the OpenSSL probe fails
  (default `no`).
- `--with-rust-tls-provider=ring|aws-lc-rs|aws-lc-rs-fips`: the rustls
  crypto provider (default `ring`). `aws-lc-rs-fips` needs a Linux host
  on x86_64 or aarch64, and cmake and go when make runs cargo.
- `--with-rust-tls-default-paths=FILE:DIR`: the default trust file and
  directory. Each part is an absolute path or empty.
- `--with-cargo-vendor=DIR`: cargo runs offline with the crates of a
  `cargo vendor` directory. The section "Offline builds" below gives
  the rules.
- `--with-system-rust-crates[=DIR]`: cargo runs offline with the system
  crates of `DIR` (default `/usr/share/cargo/registry`). Give only one of
  the two crate options.
- `--disable-werror`: do not add `-Werror` to the shim flags.
- `--enable-debug`: the `capi-dev` cargo profile and the handle registry
  (`ZKS_HANDLE_REGISTRY`).

A Rust-only option without `--with-rust-client` is an error. The legacy
options `--with-openssl` and `--with-sasl` keep their meaning, and the
section "TLS and SASL" below gives their effect. The flavors follow
`--without-syncapi` as in legacy: without it, the build makes
`libzookeeper_st` and `libzookeeper_mt`. With it, the build makes only
`libzookeeper_st` and `cli_st`, and it has no `cli_mt` and no `load_gen`.
Each flavor has a shared library and a static archive. `--disable-shared`
and `--disable-static` remove one of the two.

Build out of tree:

```sh
cd zookeeper-client/zookeeper-client-c
autoreconf -if        # on macOS with Homebrew: LIBTOOLIZE=glibtoolize
mkdir -p /tmp/zk-build && cd /tmp/zk-build
/path/to/zookeeper-client-c/configure --prefix=/tmp/zk-install \
    --with-rust-client=yes --without-openssl --without-sasl --without-cppunit
make -j8
make install
```

The full configuration (TLS and SASL) with the Homebrew prefixes:

```sh
/path/to/zookeeper-client-c/configure --with-rust-client=yes --without-cppunit \
    --with-openssl=/opt/homebrew/opt/openssl@3 --with-sasl=/opt/homebrew/opt/cyrus-sasl
make -j8 && make abi-check abi-static
```

autoreconf needs the `CHECK_CPPUNIT` macro. Homebrew cppunit does not
install `cppunit.m4`, so give a copy of it through `ACLOCAL_PATH`.

make runs cargo on each build. cargo does not write the staticlib again
when no Rust source changes, so make does not pre-link or link again. The
cargo output is in `<builddir>/cargo`.

The make targets of the Rust core:

- `make abi-check`: `cargo xtask abi check` on each built shared library.
- `make abi-static`: `cargo xtask abi static` on each built static archive.
- `make check`: `cargo test` on the workspace. The CppUnit tests use the
  internals of the legacy core, so the Rust core does not build them.
- `make check-abi`: the `tests/abi` programs on each installed shared
  library. The runner gets `--config` from configure. It compares the
  exports with the rows of that configuration, and it requires
  `libsasl2` exactly in the SASL configurations.
- `make check-link`: the `tests/link` tests on each installed
  static archive, with the `--config` of
  configure. Run `make install` first. The
  make variables `ZK_ABI_TEST_HOST`, `ZK_ABI_TEST_DEAD_HOST` and
  `ZK_ABI_TEST_REF` have the meaning of the CMake cache variables below.

## CMake

CMake selects the core with `-DWITH_RUST_CLIENT=ON|OFF|AUTO`. Unset
means `OFF`. The rules are the configure rules.

`WANT_SYNCAPI` selects the flavor, as in the legacy build. `ON` (the
default) gives the mt flavor, and `OFF` gives the st flavor. The
programs follow the legacy CMake build: `cli` links the library of the
flavor, and `load_gen` needs `ON`.

```sh
cmake -S zookeeper-client/zookeeper-client-c -B /tmp/zk-cmake \
    -DWITH_RUST_CLIENT=ON -DWITH_OPENSSL=OFF -DWITH_CYRUS_SASL=OFF \
    -DWANT_CPPUNIT=OFF -DZOOKEEPER_BUILD_SHARED=ON -DCMAKE_INSTALL_PREFIX=/tmp/zk-cmake-install
cmake --build /tmp/zk-cmake -j8
cmake --install /tmp/zk-cmake
cmake --build /tmp/zk-cmake --target abi-check abi-static
```

The default `WITH_OPENSSL=ON` and `WITH_CYRUS_SASL=ON` keep the legacy
probes. A probe that fails gives a warning, and the build continues
without that feature. The full configuration with the Homebrew
prefixes:

```sh
cmake -S zookeeper-client/zookeeper-client-c -B /tmp/zk-cmake-full \
    -DWITH_RUST_CLIENT=ON -DWITH_OPENSSL=/opt/homebrew/opt/openssl@3 \
    -DWITH_CYRUS_SASL=/opt/homebrew/opt/cyrus-sasl \
    -DWANT_CPPUNIT=OFF -DZOOKEEPER_BUILD_SHARED=ON
```

The variables of the Rust core:

- `ZKRS_WORKSPACE`: the Rust workspace (default: as configure).
- `ZKRS_STATICLIB`: a prebuilt `libzk_ffi.a`. The build does not run cargo.
- `Rust_TARGET`: give `--target` to cargo.
- `ZOOKEEPER_BUILD_SHARED`: also build the shared library of the flavor,
  `libzookeeper_mt.2.dylib` or `libzookeeper_st.2.dylib` (`.so.2` on
  Linux), with the golden export set of the flavor.
- `WITH_RUST_TLS`: build TLS also when the OpenSSL probe fails (default
  `OFF`). `WITH_OPENSSL=OFF` with `WITH_RUST_TLS=ON` is an error.
- `ZK_RUST_TLS_PROVIDER`: `ring` (default), `aws-lc-rs` or
  `aws-lc-rs-fips` (Linux on x86_64 or aarch64 only).
- `ZK_RUST_TLS_DEFAULT_PATHS`: `FILE:DIR`, the default trust locations.
- `ZOOKEEPER_CARGO_VENDOR`: a `cargo vendor` directory, as
  `--with-cargo-vendor`.
- `ZK_SYSTEM_RUST_CRATES`: a system crate directory, as
  `--with-system-rust-crates`. CMake has no default directory.
- `ZK_WERROR`: add `-Werror` to the shim flags (default `ON`).
- `CMAKE_BUILD_TYPE=Debug`: the `capi-dev` cargo profile and the handle
  registry.

The `zookeeper` target is a static archive with one member, the
pre-linked object. The `hashtable` archive has one member and no globals.
A post-build step checks this. Install puts the six legacy
headers in `include/zookeeper`, and it puts `libzookeeper.a`,
`libhashtable.a` and the shared library in `lib`. Thus a
`-lzookeeper -lhashtable` link line also works against the install
prefix.

The targets of the Rust core:

- `abi-check`: `cargo xtask abi check` on the shared library. It needs
  `ZOOKEEPER_BUILD_SHARED=ON`.
- `abi-static`: `cargo xtask abi static` on `libzookeeper.a`.

The ctest labels of the Rust core:

- `rust`: the Rust workspace tests. They run only when the build runs
  cargo.
- `abi`: the hashtable check, the link checks and the `tests/abi`
  programs. Each configuration registers them with its own
  `--config`. The cache variables
  `ZK_ABI_TEST_HOST` (a running server,
  `host:port`), `ZK_ABI_TEST_DEAD_HOST` (an address with no server) and
  `ZK_ABI_TEST_REF` (the directory of a legacy library of the same
  flavor) control the server tests. An empty `ZK_ABI_TEST_HOST` skips
  them.
- `link`: `tests/link/run-link-tests.sh` on `libzookeeper.a`. It links
  the archive with an unrelated Rust staticlib, with whole-archive
  flags and with application definitions of legacy internal names. It
  also builds `tests/link/cmake-consumer`, an `add_subdirectory()`
  application. `ZK_ABI_TEST_HOST` and `ZK_ABI_TEST_REF` apply.

## Offline builds

By default, the capability check runs `cargo fetch --locked`. That
command needs network access or a full `CARGO_HOME`. A build without
network access uses a vendor directory or system crates instead.

Make the vendor directory on a host with network access. The second
manifest adds the crates of the layout check, which Maven runs:

```sh
cd zookeeper-client/zookeeper-client-rust
cargo vendor --locked -s crates/zk-ffi-layout/Cargo.toml /path/to/vendor
```

Then give the directory to configure or CMake:

```sh
/path/to/zookeeper-client-c/configure --with-rust-client=yes \
    --with-cargo-vendor=/path/to/vendor
make -j8 && make abi-check

cmake -S zookeeper-client/zookeeper-client-c -B /tmp/zk-cmake \
    -DWITH_RUST_CLIENT=ON -DZOOKEEPER_CARGO_VENDOR=/path/to/vendor
```

A distribution build uses its packaged crates:

```sh
/path/to/zookeeper-client-c/configure --with-rust-client=yes \
    --with-system-rust-crates
```

The rules:

- The build writes `cargo-sources.toml` to the build directory. That
  file replaces crates.io with the directory. A system crate directory
  with an `index/` subdirectory is a `local-registry` source. Each other
  directory is a `directory` source.
- Each cargo call of the build gets `--offline` and `--config` with that
  file: the staticlib, `abi-check`, `abi-static`, the Rust tests and the
  link tests (`make check-link` and the ctest test `zk_link_tests`). The
  link test runner gets the file in `ZKRS_CARGO_SOURCE_CONFIG`.
- The link tests build `tests/link/zklinkring` from a copy in their out
  directory. When its `Cargo.lock` does not match the crates, the runner
  writes the lock of the copy again. The tracked lock does not change.
- System crates can have other versions than `Cargo.lock`. Thus the
  check runs `cargo generate-lockfile --offline`, which writes the
  workspace `Cargo.lock` again. Use this mode in an unpacked source
  release or a package build, not in a git working tree.
- Both crate options together are an error. A directory that does not
  exist, or that does not have all crates, stops the build. The message
  gives the reason.
- Give an absolute directory. configure also accepts a directory that
  is relative to the build directory.
- The make recipes do not quote the crate source options. Thus configure
  rejects a build directory or a crate directory with a space, a quote
  or a backslash. CMake rejects only a path with a `'`.
- A failed check removes `cargo-sources.toml`. `make distclean` also
  removes it.

## TLS and SASL

The Rust core takes the TLS and SASL decision of the legacy probes.
configure and CMake use the
same rules, and `abi/tls-probe.sh` gives the TLS decision to the Maven
build.

- TLS is on when the OpenSSL probe finds `openssl/ssl.h` and links
  `SSL_CTX_new`, or when `--with-rust-tls=yes` (`-DWITH_RUST_TLS=ON`) is
  given. The probe decides only the cargo feature `tls-<provider>` and
  the export of `zookeeper_init_ssl`. The build never links `-lssl` or
  `-lcrypto`, and the `-I` and `-L` flags of the probe never reach the
  shim or the Rust link.
- `--with-rust-tls=yes` with `--with-openssl=no` is an error.
- A provider that TLS does not use gives the notice "TLS is not built".
- SASL is on when the Cyrus SASL probe passes. The cargo feature is
  `sasl`, and the libraries link `-lsasl2`. On macOS without a SASL
  directory, the glue uses the SDK headers, which mark the Cyrus API as
  deprecated. The glue units then also get `-Wno-deprecated-declarations`.
- The pkg-config files list `-lsasl2` only with SASL, and never OpenSSL.
  Their `Cflags` define no feature macro.
- With TLS, `zookeeper.h` includes `openssl/ossl_typ.h`. An application
  that defines `HAVE_OPENSSL_H` needs the OpenSSL headers. When configure
  cannot find them, `cli_st`, `cli_mt` and `load_gen` build without the
  TLS option. CMake gives the OpenSSL include directory to the consumers
  of `zookeeper`. When it cannot find the headers, it warns and does not
  build `cli` and `load_gen`.
- The default trust locations go to cargo as `ZK_TLS_DEFAULT_CERT_FILE`
  and `ZK_TLS_DEFAULT_CERT_DIR`. The option comes first. Then the
  `OPENSSLDIR` of `openssl version -d` gives `OPENSSLDIR/cert.pem` and
  `OPENSSLDIR/certs`. The command is `DIR/bin/openssl` for
  `--with-openssl=DIR` (CMake: `OPENSSL_ROOT_DIR/bin/openssl`), else the
  first `openssl` on `PATH`. Then the first directory of this list:
  `/usr/lib/ssl`, `/etc/pki/tls`, `/etc/ssl`, `/usr/local/ssl`,
  `/usr/local/etc/openssl@3`, `/opt/homebrew/etc/openssl@3`. Windows
  records no location.
- A prebuilt staticlib (`--with-rust-staticlib`, `ZKRS_STATICLIB`) must
  have the TLS decision of the build. The check reads the marker symbol
  `zkrs_feature_tls` with `nm`. Only a `tls` build of `zk-ffi` defines
  it. `zks_tls.c` also calls it, so a TLS shim does not link against a
  staticlib without TLS.
- In `zkrs.h`, the TLS items are under `#if defined(ZKS_WITH_TLS)`
  (cbindgen `[defines]`). The SASL items have no guard, because they
  name no type of Cyrus.
- The Rust core uses rustls with the provider `ring` or `aws-lc-rs`. It
  never links OpenSSL. In the drop-in, the trust check is the chain-only
  check of legacy. As in legacy, it does not check the
  host name.
- The SASL mechanisms stay in Cyrus. The shim runs the Cyrus calls, and
  the Rust core runs the SASL state machine and the wire protocol. The
  shim zeroes its secret C buffers with `zks_secure_zero` on every return.
  The Rust core holds the tokens in `SecretBytes`.
- After a SASL failure, the state is `ZOO_AUTH_FAILED_STATE`, and an
  `AUTH_FAILED` session event goes out. All pending work then fails with
  `ZAUTHFAILED`. Legacy only sets the state, so its callers can wait
  forever.
- Each `zoo_add_auth` completion gets the result of the AUTH reply to
  its own request. The auth log line names the scheme of that request.
  Legacy completes every pending auth with the first reply, so a
  rejected credential can get `ZOK`. The insert position,
  the resend order, the lock points and the `AUTH_FAILED` teardown stay
  as in legacy.

## The development script

`zookeeper-client-rust/dev/build-dropin.sh` builds the macOS drop-in
without autotools or CMake. It is for fast tests of shim changes:

```sh
cd zookeeper-client/zookeeper-client-rust
FLAVORS="mt st" ABI_CHECK=1 dev/build-dropin.sh .. /tmp/zk-dropin
```

For each flavor FL, the script writes `libzookeeper_FL.2.dylib`,
`libzookeeper_FL.a` and `cli_FL`. It checks the export set and runs a
smoke test against the shared library and the static archive.
`FLAVORS` selects the flavors (default `mt st`). `ABI_CHECK=1` also runs
`cargo xtask abi check` and `cargo xtask abi static`. `SMOKE_HOST=H:P`
runs `ls /` through the static `cli_FL` against a running server.
`CONFIG` selects `plain`, `ssl`, `sasl` or `full`, with the rules of
configure. `OPENSSL_PREFIX` and `SASL_PREFIX` give the Homebrew
prefixes. The script then compiles each shim unit with
`-std=c99 -Wall -Wextra -Wdeclaration-after-statement -Werror`:

```sh
CONFIG=full FLAVORS="mt st" ABI_CHECK=1 dev/build-dropin.sh .. /tmp/zk-dropin-full
``` `TLS_PROVIDER` is `ring` or `aws-lc-rs`, and
`TLS_DEFAULT_PATHS=FILE:DIR` sets the default trust locations. Else
`abi/tls-probe.sh` computes them from `OPENSSL_PREFIX`. The script also
checks with `otool -L` that no library links OpenSSL, and that only the
SASL configurations link `libsasl2`.

## Checks

The ABI check of a built library. `--config` is `plain`, `ssl`, `sasl`
or `full`, and it must be the configuration of the build:

```sh
cd zookeeper-client/zookeeper-client-rust
cargo xtask abi check /tmp/zk-install/lib/libzookeeper_mt.dylib --flavor mt --config plain \
    --libdir /tmp/zk-install/lib
cargo xtask abi check /tmp/zk-install/lib/libzookeeper_st.dylib --flavor st --config plain \
    --libdir /tmp/zk-install/lib
```

The static check of a built archive:

```sh
cargo xtask abi static /tmp/zk-install/lib/libzookeeper_st.a --flavor st --config plain
```

The generated headers must be up to date:

```sh
(cd crates/zk-ffi && cbindgen --config cbindgen.toml --crate zk-ffi \
    --output ../../c/shim/zkrs.h --verify)
cargo xtask log-sites --check
cargo xtask log-sites header --check
```

The shim must compile without a warning in both flavors:

```sh
cd zookeeper-client/zookeeper-client-c
for t in -DTHREADED ""; do
  for f in ../zookeeper-client-rust/c/shim/*.c; do
    cc -std=c99 -Wall -Wextra -Wdeclaration-after-statement -Werror -D_GNU_SOURCE \
        -fexceptions $t -Iinclude -Igenerated -I../zookeeper-client-rust/c/shim -c "$f" -o /dev/null
  done
done
```

The Rust checks:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
cargo +1.85.0 check --locked --workspace --all-targets
```

Run clippy and the tests of `zk-ffi` also for each feature set of the
drop-in:

```sh
for f in tls,tls-ring sasl tls,tls-ring,sasl tls,tls-aws-lc-rs,sasl; do
  cargo clippy --locked -p zk-ffi --all-targets --features "$f" -- -D warnings
  cargo test --locked -p zk-ffi --features "$f"
done
```

## A session against a real server

`zookeeper-client-rust/dev/test-server.sh` starts a standalone server
from this source tree. Always give the command, the port and the
directory:

```sh
cd zookeeper-client/zookeeper-client-rust
dev/test-server.sh start 22720 /tmp/zk-server
/tmp/zk-install/bin/cli_mt -h 127.0.0.1:22720
/tmp/zk-install/bin/cli_st -h 127.0.0.1:22720
dev/test-server.sh stop 22720 /tmp/zk-server
```

The st `cli_st` reads stdin in its own `select` loop, and it stops at
the end of stdin. Thus a batch script must keep stdin open until the
last result arrives. For example, send the commands with a pause after
each one.

A TLS session needs a server with `secureClientPort`,
`serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory`
and a keystore (give the properties through `ZK_TEST_SERVER_PROPS`).
`ssl/gencerts.sh` makes the certificates and the keystores. The `-s`
option gives the CA file, the client certificate, the client key and the
key password:

```sh
cli_mt -s "server.crt,client.crt,clientkey.pem,password" -h localhost:22721 -c "ls /"
```

Both cores accept only a server certificate that the CA file proves with
the legacy chain-only check. With OpenSSL 3.2 and
later, `ssl/gencerts.sh` makes v3 leaf certificates with an authority
key identifier, and both cores reject them. Certificates from
OpenSSL 3.1 and earlier are v1, and both cores accept them.

A DIGEST-MD5 session needs a JAAS file with a `Server` section and
`-Dzookeeper.authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider`
in `ZK_TEST_SERVER_JVM_OPTS`:

```sh
cli_mt --mechlist DIGEST-MD5 --user myuser --password-file /tmp/pw \
    --server-fqdn zk-sasl-md5 -h localhost:22720 -c "ls /"
```

`tests/conformance/run.sh --sasl` starts such a server for the
conformance cases.

To compare with legacy, run the same command script through the drop-in
`cli_FL` and through a legacy `cli_FL`.
Mask the times, the thread ids, the session ids and the ports, then
compare the output. Run it again with `-d` to compare the debug lines. The
debug lines can be in a different order where two threads write at the
same time. The xid values differ by one.

## The public-API CppUnit suite

`zktest-public-mt` and `zktest-public-st` are the part
of the CppUnit suite that uses only the public API: TestClient,
TestMulti, TestClientRetry, TestLogClientEnv, TestReadOnlyClient,
TestSASLAuth and TestReconfigServer. They compile copies of the legacy
test sources, and each links the shared library of its flavor with no
mocks and no `--wrap`. `tests/public/gen-sources.sh` makes the copies. It
sets the ports of the build, and it removes the registration of the cases
in `tests/public/omit-cases.txt`. These cases use the internals of the
legacy core. The legacy sources do not change. Most cases need
`THREADED`, so the st suite has few cases.

`tests/public/zkServer.sh` replaces the legacy `tests/zkServer.sh`. It starts the
server through `dev/test-server.sh`. `tests/public/run-public.sh` runs the
binary against one library directory, and it stops all servers of the run.
The suite needs a built server (`mvn -DskipTests install -pl zookeeper-server -am`) and CppUnit.

Autotools builds and runs the suites only on `make check-public`. The mt
suite needs the mt library, so `--without-syncapi` builds only the st
suite. Give the ports on the command line. 0 selects the legacy ports:

```sh
make check-public ZKTEST_PORT=22730 ZKTEST_DOWN_PORT=22731 \
    ZKTEST_QUORUM_PORT_BASE=22738 ZKTEST_RO_PORT_BASE=22732
```

CMake has the option `WANT_CPPUNIT_PUBLIC`, the same port cache
variables, the ctest label `public` and the target `check-public`. CMake
builds the suite of its flavor: `zktest-public-mt` with `WANT_SYNCAPI=ON` and
`zktest-public-st` with `WANT_SYNCAPI=OFF`:

```sh
cmake -S zookeeper-client/zookeeper-client-c -B /tmp/zk-cmake -DWITH_RUST_CLIENT=ON -DZOOKEEPER_BUILD_SHARED=ON \
    -DWANT_CPPUNIT_PUBLIC=ON -DZKTEST_PORT=22730 -DZKTEST_DOWN_PORT=22731 \
    -DZKTEST_QUORUM_PORT_BASE=22738 -DZKTEST_RO_PORT_BASE=22732
cmake --build /tmp/zk-cmake --target check-public
```

To run a binary against the legacy library, give its directory:

```sh
ZKTEST_PORT=22730 ZKTEST_RO_PORT_BASE=22732 tests/public/run-public.sh \
    --libdir /tmp/zk-legacy/lib --workdir /tmp/zk-public-legacy /tmp/zk-cmake/zktest-public-mt
```

The port variables of the run must be the values of the build.

### The scripted cli_st session

`tests/public/run-cli-session.sh` runs the session script
`tests/public/cli-session.txt` with `cli_st` on each core and compares
the output. The script sends commands
to the standard input of `cli_st`, and it waits for the output of each
command with a fixed limit. A second client in batch mode fires a watch
while `cli_st` waits in `select`. Each run starts a new server. The
comparison masks the session ids, the zxids and the times. Give the
`cli_st` binary and the library directory of each core:

```sh
ZKTEST_PORT=22730 tests/public/run-cli-session.sh \
    --legacy /tmp/zk-legacy/bin/cli_st --legacy-libdir /tmp/zk-legacy/lib \
    --rust /tmp/zk-install/bin/cli_st --rust-libdir /tmp/zk-install/lib
```

`--expected DIR` also compares each run with the normalized files of an
earlier run in `DIR`.
