#!/bin/sh
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The cargo tasks of the zookeeper-client-rust Maven module.
#
#   sh rust-module.sh prepare|build|test|lint|supply-chain|interop
#
# pom.xml calls this script from exec-maven-plugin. The pom gives the
# Maven properties in the environment:
#   ZKRS_CLIENT          rust-client: no or yes
#   ZKRS_TLS             rust-tls: no or yes
#   ZKRS_TLS_PROVIDER    rust-tls-provider: ring, aws-lc-rs or aws-lc-rs-fips
#   ZKRS_CARGO_VENDOR    rust-cargo-vendor: a vendor directory, or empty
#   ZKRS_SYSTEM_CRATES   rust-system-crates: a system crate directory, or empty
#   ZKRS_OPENSSL         c-client-openssl: yes, no or DIR
#   ZKRS_SASL            c-client-sasl: yes, no or DIR
#   ZKRS_VERSION         the project version of the root pom
#   ZKRS_BUILD_DIR       the build directory of the module
#   ZKRS_SKIP_TESTS      skipTests: the test task does nothing when true
#   ZKRS_TEST_MODE       plain, coverage or asan
#   ZKRS_TEST_PORT_BASE  the first port of the real-server tests, or empty
#   ZKRS_IT_PORT_BASE    the first port of the interop task
#   ZKRS_IT_VERSIONS     the server versions of the interop task
#   ZKRS_IT_MVN_ARGS     extra Maven arguments of the interop task
#   ZKRS_MVN_OFFLINE     offline=true when Maven runs offline
#   ZKRS_MVN_REPO        the local Maven repository
#   CARGO_TARGET_DIR     the cargo target directory
#
# The prepare task makes the build decisions once. It writes them to
# ZKRS_BUILD_DIR/rust-build.env, and the other tasks read that file. So
# the staticlib, the tests and the checks use the same features and
# the same crate sources. With rust-client=no, each task does nothing.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ws=$(cd "$here/.." && pwd)
task=${1:-}
build_dir=${ZKRS_BUILD_DIR:-$ws/target}
state=$build_dir/rust-build.env
src_config=$build_dir/cargo-sources.toml
zoo_version_h=$ws/../zookeeper-client-c/include/zookeeper_version.h

fail() {
  echo "zookeeper-client-rust: $*" >&2
  exit 1
}

note() {
  echo "zookeeper-client-rust: $*"
}

# Gives MAJOR*1000+MINOR of the version that "$1 --version" prints.
tool_version() {
  "$1" --version 2>/dev/null | awk '{ split($2, v, "."); print (v[1] * 1000 + v[2]) }'
}

# The C compiler probe of configure. The arguments are the program
# text, the directory option (yes or DIR) and the link flags.
cc_probe() {
  probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/zkrs-probe.XXXXXX")
  printf '%s\n' "$1" >"$probe_dir/probe.c"
  dir_flags=
  if [ "$2" != yes ]; then
    dir_flags="-I$2/include -L$2/lib"
  fi
  # CC and the flags can hold more than one word, so they are not quoted.
  # shellcheck disable=SC2086
  if ${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:-} $dir_flags ${LDFLAGS:-} -o "$probe_dir/probe" \
      "$probe_dir/probe.c" $3 >/dev/null 2>&1; then
    rm -rf "$probe_dir"
    return 0
  fi
  rm -rf "$probe_dir"
  return 1
}

# Runs cargo with --locked and the crate sources of the prepare task.
# The first argument is the cargo command. A set cargo_toolchain, for
# example +nightly, selects the rustup toolchain.
cargo_toolchain=
run_cargo() {
  sub=$1
  shift
  # An empty toolchain gives no word.
  # shellcheck disable=SC2086
  if [ -f "$src_config" ]; then
    cargo $cargo_toolchain "$sub" --locked --offline --config "$src_config" "$@"
  else
    cargo $cargo_toolchain "$sub" --locked "$@"
  fi
}

# Reads the decisions of the prepare task.
load_state() {
  [ -f "$state" ] || fail "$state is missing: run the process-sources goals of this module first"
  tls=no
  openssl=no
  sasl=no
  features=
  cert_file=
  cert_dir=
  while IFS='=' read -r key value; do
    case "$key" in
      tls) tls=$value ;;
      openssl) openssl=$value ;;
      sasl) sasl=$value ;;
      features) features=$value ;;
      cert_file) cert_file=$value ;;
      cert_dir) cert_dir=$value ;;
    esac
  done <"$state"
  feature_args=
  if [ -n "$features" ]; then
    feature_args="--features=$features"
  fi
  ZK_TLS_DEFAULT_CERT_FILE=$cert_file
  ZK_TLS_DEFAULT_CERT_DIR=$cert_dir
  ZK_VERSION_H=$zoo_version_h
  export ZK_TLS_DEFAULT_CERT_FILE ZK_TLS_DEFAULT_CERT_DIR ZK_VERSION_H
}

# The value checks. The enforcer rule of the pom also checks
# rust-client, but this script can run alone.
case "${ZKRS_CLIENT:-no}" in
  yes) ;;
  no)
    note "rust-client=no: the $task task does nothing"
    exit 0
    ;;
  *) fail "rust-client=${ZKRS_CLIENT}: give no or yes" ;;
esac

# Sets the crate sources. A vendor directory and a system crate
# directory replace crates.io with a local source. The configuration
# file is in the build directory. The source replacement changes no
# tracked file. System crates can have other versions than Cargo.lock,
# so system-crates mode writes the lock files again. The C module
# gives the same directory to configure, so make abi-check uses the same
# crates.
prepare_sources() {
  rm -f "$src_config"
  vendor=${ZKRS_CARGO_VENDOR:-}
  system=${ZKRS_SYSTEM_CRATES:-}
  if [ -n "$vendor" ] && [ -n "$system" ]; then
    fail "give only one of -Drust-cargo-vendor and -Drust-system-crates"
  fi
  dir=$vendor$system
  [ -n "$dir" ] || return 0
  [ -d "$dir" ] || fail "the crate directory $dir does not exist"
  dir=$(cd "$dir" && pwd)
  kind=directory
  if [ -n "$system" ] && [ -d "$dir/index" ]; then
    kind=local-registry
  fi
  mkdir -p "$build_dir"
  {
    echo "# The crate sources of the Maven build. The build writes this file."
    echo "[source.crates-io]"
    echo "replace-with = \"zk-local\""
    echo "[source.zk-local]"
    echo "$kind = \"$dir\""
  } >"$src_config"
  if [ -n "$system" ]; then
    # The system crates can have other versions than the lock file.
    note "system crates from $dir: cargo generate-lockfile writes Cargo.lock again"
    (cd "$ws" && cargo generate-lockfile --offline --config "$src_config")
    (cd "$ws" && cargo generate-lockfile --offline --config "$src_config" \
      --manifest-path crates/zk-ffi-layout/Cargo.toml)
  else
    note "vendored crates from $dir"
  fi
}

prepare() {
  case "${ZKRS_TLS:-no}" in
    yes|no) ;;
    *) fail "rust-tls=${ZKRS_TLS}: give yes or no" ;;
  esac
  provider=${ZKRS_TLS_PROVIDER:-ring}
  case "$provider" in
    ring|aws-lc-rs|aws-lc-rs-fips) ;;
    *) fail "rust-tls-provider=$provider: give ring, aws-lc-rs or aws-lc-rs-fips" ;;
  esac

  # The toolchain must meet the MSRV of the workspace.
  for tool in cargo rustc; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool not found: rust-client=yes needs cargo and rustc 1.85 or later"
    v=$(tool_version "$tool")
    if [ -z "$v" ] || [ "$v" -lt 1085 ]; then
      fail "$tool $("$tool" --version 2>/dev/null) is too old: rust-client=yes needs 1.85 or later"
    fi
  done

  # The root pom gives the version. The release execution
  # replace-rustclient-files-during-release writes it to Cargo.toml.
  want=${ZKRS_VERSION:-}
  want=${want%-SNAPSHOT}
  have=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' "$ws/Cargo.toml")
  if [ "$have" != "$want" ]; then
    fail "the Cargo.toml workspace version $have is not the project version $want: run 'mvn -N antrun:run@replace-rustclient-files-during-release' from the top level directory"
  fi

  # The TLS decision of configure. The C module links the staticlib, and
  # configure checks that the staticlib has the same decision.
  probe_out=$(sh "$ws/c/abi/tls-probe.sh" "--with-openssl=${ZKRS_OPENSSL:-yes}" "--with-rust-tls=${ZKRS_TLS:-no}") ||
    fail "abi/tls-probe.sh failed"
  tls=$(printf '%s\n' "$probe_out" | sed -n 's/^tls=//p')
  openssl=$(printf '%s\n' "$probe_out" | sed -n 's/^openssl=//p')
  cert_file=$(printf '%s\n' "$probe_out" | sed -n 's/^cert_file=//p')
  cert_dir=$(printf '%s\n' "$probe_out" | sed -n 's/^cert_dir=//p')

  # The SASL decision of configure: the Cyrus header and libsasl2.
  sasl=no
  if [ "${ZKRS_SASL:-yes}" != no ] &&
      cc_probe '#include <sasl/sasl.h>
int main(void) { return sasl_client_init(0); }' "${ZKRS_SASL:-yes}" -lsasl2; then
    sasl=yes
  fi

  features=
  if [ "$tls" = yes ]; then
    features=tls-$provider
  elif [ "$provider" != ring ]; then
    note "TLS is not built: rust-tls-provider=$provider is not used"
  fi
  if [ "$sasl" = yes ]; then
    features=${features:+$features,}sasl
  fi

  prepare_sources
  note "cargo fetch"
  (cd "$ws" && run_cargo fetch)

  mkdir -p "$build_dir"
  {
    echo "tls=$tls"
    echo "openssl=$openssl"
    echo "sasl=$sasl"
    echo "features=$features"
    echo "cert_file=$cert_file"
    echo "cert_dir=$cert_dir"
  } >"$state"
  note "tls=$tls provider=$provider sasl=$sasl features=${features:-none}"
}

build() {
  load_state
  cd "$ws"
  # The staticlib builds alone, so that no workspace feature reaches it.
  # shellcheck disable=SC2086
  run_cargo build -p zk-ffi --profile capi $feature_args
  run_cargo build --workspace --release --exclude zk-ffi
  note "staticlib $CARGO_TARGET_DIR/capi/libzk_ffi.a"
}

# The cross-language layout check of the drop-in ABI. The crate is a
# separate workspace, so the workspace test run does not include it. The
# check covers the plain configuration and each configuration that the
# OpenSSL and SASL probes of the prepare task select: ssl, sasl and full.
# The ssl configuration follows the OpenSSL header probe and not the TLS
# decision, because only the headers add the OpenSSL types to zookeeper.h.
layout_check() {
  configs=plain
  if [ "$openssl" = yes ]; then
    configs=$configs,ssl
    case "${ZKRS_OPENSSL:-yes}" in
      yes | '') ;;
      *)
        ZK_LAYOUT_SSL_CFLAGS="-I$ZKRS_OPENSSL/include"
        export ZK_LAYOUT_SSL_CFLAGS
        ;;
    esac
  fi
  if [ "$sasl" = yes ]; then
    configs=$configs,sasl
    if [ "${ZKRS_SASL:-yes}" != yes ]; then
      ZK_LAYOUT_SASL_CFLAGS="-I$ZKRS_SASL/include"
      export ZK_LAYOUT_SASL_CFLAGS
    fi
  fi
  if [ "$openssl" = yes ] && [ "$sasl" = yes ]; then
    configs=$configs,full
  fi
  ZK_LAYOUT_CONFIGS=$configs
  export ZK_LAYOUT_CONFIGS
  note "layout check: $configs"
  run_cargo test --manifest-path crates/zk-ffi-layout/Cargo.toml
}

run_tests() {
  if [ "${ZKRS_SKIP_TESTS:-false}" = true ]; then
    note "skipTests is set: the cargo tests do not run"
    return 0
  fi
  load_state
  cd "$ws"
  # A port base also runs the ignored real-server tests. They start their
  # servers with dev/test-server.sh and use the ports BASE to BASE+19.
  # A test that cannot start its server fails. The resolver test stays
  # ignored, because it depends on the host configuration.
  set --
  if [ -n "${ZKRS_TEST_PORT_BASE:-}" ]; then
    ZK_TEST_PORT_BASE=$ZKRS_TEST_PORT_BASE
    ZK_TEST_REQUIRE_SERVER=${ZK_TEST_REQUIRE_SERVER:-1}
    export ZK_TEST_PORT_BASE ZK_TEST_REQUIRE_SERVER
    set -- -- --include-ignored --skip std_host_leaves_resolve_localhost
    note "real-server tests on the ports $ZK_TEST_PORT_BASE to $((ZK_TEST_PORT_BASE + 19))"
  fi
  case "${ZKRS_TEST_MODE:-plain}" in
    plain)
      run_cargo test --workspace --exclude zk-ffi "$@"
      # shellcheck disable=SC2086
      run_cargo test -p zk-ffi $feature_args "$@"
      layout_check
      ;;
    coverage)
      command -v cargo-llvm-cov >/dev/null 2>&1 ||
        fail "rust-test-coverage needs cargo-llvm-cov: cargo install --locked cargo-llvm-cov"
      run_cargo llvm-cov --no-report --workspace --exclude zk-ffi "$@"
      # shellcheck disable=SC2086
      run_cargo llvm-cov --no-report -p zk-ffi $feature_args "$@"
      cargo llvm-cov report --html --output-dir "$build_dir/rust-coverage"
      cargo llvm-cov report --lcov --output-path "$build_dir/rust-coverage/lcov.info"
      note "coverage report in $build_dir/rust-coverage"
      ;;
    asan)
      # AddressSanitizer needs a nightly toolchain. Only the target crates
      # get the instrumentation, because the build gives --target.
      cargo +nightly --version >/dev/null 2>&1 ||
        fail "rust-test-asan needs a nightly toolchain: rustup toolchain install nightly"
      host=$(rustc -vV | sed -n 's/^host: //p')
      CARGO_TARGET_DIR=$build_dir/cargo-asan
      RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=address"
      export CARGO_TARGET_DIR RUSTFLAGS
      case "$host" in
        # LeakSanitizer does not run on macOS.
        *-apple-darwin) ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0} ;;
        *) ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1} ;;
      esac
      export ASAN_OPTIONS
      cargo_toolchain=+nightly
      # Doctests do not get the target flags, so they do not run here.
      run_cargo test --target "$host" --workspace --exclude zk-ffi --lib --bins --tests "$@"
      # shellcheck disable=SC2086
      run_cargo test --target "$host" -p zk-ffi $feature_args --lib --tests "$@"
      ;;
    *) fail "unknown test mode ${ZKRS_TEST_MODE}" ;;
  esac
}

lint() {
  load_state
  cd "$ws"
  cargo fmt --all --check || fail "cargo fmt --check found unformatted code: run cargo fmt --all"
  run_cargo clippy --workspace --exclude zk-ffi --all-targets -- -D warnings
  # shellcheck disable=SC2086
  run_cargo clippy -p zk-ffi --all-targets $feature_args -- -D warnings
}

supply_chain() {
  load_state
  cd "$ws"
  command -v cargo-deny >/dev/null 2>&1 ||
    fail "rust-supply-chain needs cargo-deny: cargo install --locked cargo-deny"
  offline=
  config_args=
  if [ -f "$src_config" ]; then
    offline=--offline
    config_args="--config $src_config"
  fi
  # Each policy file checks the union of its feature sets over the whole
  # workspace graph. A pass on the union is a pass on each closure.
  note "cargo deny: deny.toml"
  # shellcheck disable=SC2086
  cargo deny --locked $offline check
  note "cargo deny: deny-fips.toml"
  # shellcheck disable=SC2086
  cargo deny --locked $offline --config deny-fips.toml check

  # cargo-vet certifies exact versions. System crates can have other
  # versions, so the differences are a note and not a failure.
  if ! command -v cargo-vet >/dev/null 2>&1; then
    note "cargo vet: skipped, cargo-vet is not installed (cargo install --locked cargo-vet)"
  elif [ ! -f supply-chain/config.toml ]; then
    note "cargo vet: skipped, the workspace has no supply-chain/config.toml"
  elif [ -n "${ZKRS_SYSTEM_CRATES:-}" ]; then
    # shellcheck disable=SC2086
    cargo vet --locked $offline ||
      note "cargo vet: the system crates differ from the audited versions"
  else
    # shellcheck disable=SC2086
    cargo vet --locked $offline
  fi

  if ! command -v cargo-audit >/dev/null 2>&1; then
    note "cargo audit: skipped, cargo-audit is not installed (cargo install --locked cargo-audit)"
  else
    cargo audit
  fi

  # The closure comparison resolves each shipped build with the crate
  # sources of this build. System crates can have other patch versions,
  # so that comparison accepts semver-compatible versions.
  if [ ! -d supply-chain/closure ]; then
    note "closure comparison: skipped, the workspace has no supply-chain/closure inventory"
  else
    semver=
    if [ -n "${ZKRS_SYSTEM_CRATES:-}" ]; then
      semver=--semver-compatible
    fi
    note "closure comparison: supply-chain/closure"
    # shellcheck disable=SC2086
    cargo --locked $config_args $offline xtask closure check $config_args $offline $semver
  fi
}

# The Curator interop test. dev/run-curator-interop.sh starts each
# server, runs the JUnit project interop/curator, and stops the server.
interop() {
  args=-B
  if [ "${ZKRS_MVN_OFFLINE:-}" = offline=true ]; then
    args="$args -o"
  fi
  if [ -n "${ZKRS_MVN_REPO:-}" ]; then
    args="$args -Dmaven.repo.local=$ZKRS_MVN_REPO"
  fi
  ZK_INTEROP_MVN_ARGS="$args ${ZKRS_IT_MVN_ARGS:-}"
  # The peer binary uses the crate sources of the prepare task.
  ZK_INTEROP_CARGO_ARGS=
  if [ -f "$src_config" ]; then
    ZK_INTEROP_CARGO_ARGS="--offline --config $src_config"
  fi
  ZK_TEST_PORT_BASE=${ZKRS_IT_PORT_BASE:-23400}
  export ZK_INTEROP_MVN_ARGS ZK_INTEROP_CARGO_ARGS ZK_TEST_PORT_BASE
  # The versions are separate words.
  # shellcheck disable=SC2086
  bash "$ws/dev/run-curator-interop.sh" ${ZKRS_IT_VERSIONS:-head}
}

case "$task" in
  prepare) prepare ;;
  build) build ;;
  test) run_tests ;;
  lint) lint ;;
  supply-chain) supply_chain ;;
  interop) interop ;;
  *) fail "unknown task '$task': give prepare, build, test, lint, supply-chain or interop" ;;
esac
