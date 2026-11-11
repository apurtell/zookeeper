#!/usr/bin/env bash
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

# Runs the build configuration matrix of the drop-in libraries on macOS:
# the configurations plain, ssl, sasl and full, the flavors mt and st, and
# the build systems (the dev build, autotools yes and no, CMake shared
# and static-only). Sources: spec "Producing the libraries" and
# "Selecting what to build".
#
# Usage: run-build-matrix.sh [options]
#   --stage S     dev, autotools, cmake, provider, paths, gating or legacy.
#                 The option repeats. Default: all stages
#   --config C    plain, ssl, sasl or full. The option repeats. Default: all
#   --work DIR    the work directory (default /tmp/xbuild/matrix)
#   --ref DIR     the legacy reference builds (default /tmp/zk-legacy-ref)
#   --jobs N      the make job count (default 8)
#   --no-runtime  do not run tests/abi and tests/link on the outputs
#
# Environment: OPENSSL_PREFIX (default the Homebrew openssl@3 prefix) and
# SASL_PREFIX (default the Homebrew cyrus-sasl prefix). CARGO_TARGET_DIR
# is the cargo directory of the dev build, the xtask checks and the cargo
# feature checks. The autotools and CMake trees share one cargo directory
# for each configuration, so that a configuration compiles the Rust core
# once for each build system.
#
# The runner starts no server. Each step has a time limit. A KNOWN line is
# a known failure that the runner reports and does not count. ZK_CPU_GATE
# names an optional command that each step runs first. The step waits
# until that command exits with status 0. Hosts that share the CPU use it
# to pause the builds.

set -uo pipefail

# The script uses three roots. RCDIR is the Rust C tree. RDIR is the Rust
# workspace. CDIR is the legacy C tree. ZKRS_C_DIR overrides RCDIR, and
# ZK_C_DIR overrides CDIR. Thus a copy of this script can run from another
# place, so that edits do not change a running script.
HERE="$(cd "$(dirname "$0")" && pwd)"
RCDIR="$(cd "${ZKRS_C_DIR:-$HERE/../..}" && pwd)"
RDIR="$(cd "$RCDIR/.." && pwd)"
CDIR="$(cd "${ZK_C_DIR:-$RDIR/../zookeeper-client-c}" && pwd)"
ABI="$RCDIR/abi"

STAGES=()
CONFIGS=()
WORK=/tmp/xbuild/matrix
REF=/tmp/zk-legacy-ref
JOBS=8
RUNTIME=1
while [ $# -gt 0 ]; do
    case "$1" in
    --stage) STAGES+=("$2"); shift 2 ;;
    --config) CONFIGS+=("$2"); shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --no-runtime) RUNTIME=0; shift ;;
    *) echo "run-build-matrix.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "${#STAGES[@]}" -gt 0 ] || STAGES=(dev autotools cmake provider paths gating legacy)
[ "${#CONFIGS[@]}" -gt 0 ] || CONFIGS=(plain ssl sasl full)
for c in "${CONFIGS[@]}"; do
    case "$c" in
    plain | ssl | sasl | full) ;;
    *) echo "run-build-matrix.sh: unknown config $c" >&2; exit 2 ;;
    esac
done
if [ "$(uname -s)" != Darwin ]; then
    echo "run-build-matrix.sh: this runner supports macOS only" >&2
    exit 2
fi
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}"
SASL_PREFIX="${SASL_PREFIX:-/opt/homebrew/opt/cyrus-sasl}"
XT="${CARGO_TARGET_DIR:-$RDIR/target}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
LOGS="$WORK/logs"
mkdir -p "$LOGS"
RESULTS="$WORK/results.txt"
: >"$RESULTS"
# Every compile of the C units must be free of warnings. The Homebrew
# libraries (libsasl2, and OpenSSL for the legacy core) have a newer
# minimum macOS version than the build. ld warns about it, and the
# warning does not come from this build.
WARN_ALLOW='ld: warning: .*linking with dylib .*/opt/homebrew/.*was built for newer (macOS )?version'
# The time limits of the steps, in seconds.
T_BUILD=2400
T_TEST=1800
T_CONF=600

PASS=0
FAIL=0
SKIP=0
KNOWN=0
pass() { PASS=$((PASS + 1)); echo "PASS $*" | tee -a "$RESULTS"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*" | tee -a "$RESULTS"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP $*" | tee -a "$RESULTS"; }
known() { KNOWN=$((KNOWN + 1)); echo "KNOWN $*" | tee -a "$RESULTS"; }
info() { echo "INFO $*" | tee -a "$RESULTS"; }

has_stage() {
    local s
    for s in "${STAGES[@]}"; do [ "$s" = "$1" ] && return 0; done
    return 1
}
has_config() {
    local c
    for c in "${CONFIGS[@]}"; do [ "$c" = "$1" ] && return 0; done
    return 1
}

# Runs a command with a time limit. The output goes to the log file.
# Usage: run SECS LOG CMD...
run() {
    local secs="$1" log="$2"
    shift 2
    if [ -n "${ZK_CPU_GATE:-}" ]; then
        until "$ZK_CPU_GATE" >&2; do :; done
    fi
    timeout "$secs" "$@" >"$log" 2>&1
}

# The test passes when the command exits with status 0.
check() {
    local name="$1" log="$LOGS/$1.log"
    shift
    if run "$T_TEST" "$log" "$@"; then
        pass "$name"
    else
        fail "$name (see $log)"
        tail -15 "$log"
    fi
}

# The test passes when the command fails and its output matches PATTERN.
# An explicit request that the host cannot satisfy must stop the build
# with a reason (spec "Selecting what to build").
expect_fail() {
    local name="$1" pattern="$2" log="$LOGS/$1.log"
    shift 2
    if run "$T_CONF" "$log" "$@"; then
        fail "$name: the command succeeds (see $log)"
    elif grep -Eq "$pattern" "$log"; then
        pass "$name: $(grep -Eo "$pattern" "$log" | head -1)"
    else
        fail "$name: no '$pattern' in the output (see $log)"
        tail -10 "$log"
    fi
}

# The feature bits of a configuration.
bits() {
    case "$1" in
    plain) SSL01=0 SASL01=0 ;;
    ssl) SSL01=1 SASL01=0 ;;
    sasl) SSL01=0 SASL01=1 ;;
    full) SSL01=1 SASL01=1 ;;
    esac
}

# The golden export names of FLAVOR and CONFIG with the Mach-O prefix
# (abi/symbols.tsv: plain 201/178, ssl 202/179, sasl 210/187, full 211/188).
golden() {
    bits "$2"
    awk -f "$ABI/gen-exports.awk" -v flavor="$1" -v fmt=exp -v ssl="$SSL01" -v sasl="$SASL01" \
        "$ABI/symbols.tsv" | sort -u
}

# The checks below use "grep -c ... >/dev/null" after a pipe, not
# "grep -q". grep -q stops early, and with pipefail the SIGPIPE of the
# first command fails the pipeline.

# The test passes when the nm output of FILE has a line that matches
# PATTERN. Apple nm cannot read the LLVM bitcode members of some
# staticlibs and then exits with an error, but it still lists the other
# members. Thus the exit status of nm is not used.
nm_has() {
    nm "$1" >"$WORK/nm.out" 2>/dev/null
    grep -q "$2" "$WORK/nm.out"
}

# The defined global symbols of an archive.
ar_globals() {
    nm -g "$1" 2>/dev/null | awk 'NF >= 3 && $(NF - 1) ~ /^[A-TV-Z]$/ { print $NF }' | sort -u
}

# The non-system dependencies of a Mach-O file, one basename each line.
macho_deps() {
    otool -L "$1" | awk 'NR > 1 { print $1 }' | grep -v '^/usr/lib/libSystem' |
        sed 's|.*/||' | sort
}

# The legacy SASL source warns with Apple clang 21 and -std=gnu23. The
# legacy sources do not change, so this warning is a known failure of the
# legacy builds (the reference README; spec "Selecting what to build").
LEGACY_WARN='src/zk_sasl\.c:[0-9]+:[0-9]+: warning: .*\[-Wgnu-folding-constant\]'

# The C compile output of a build has no warning. The
# optional third argument is the pattern of the known warnings.
warn_check() {
    local name="$1" log="$2" kw="${3:-}" w
    w="$(grep -E 'warning:' "$log" | grep -Ev "$WARN_ALLOW" || true)"
    if [ -n "$w" ] && [ -n "$kw" ] && [ -z "$(echo "$w" | grep -Ev "$kw" || true)" ]; then
        known "$name: the known legacy warning: $(echo "$w" | head -1)"
    elif [ -z "$w" ]; then
        pass "$name: no compiler warning"
    else
        fail "$name: warnings: $(echo "$w" | head -3)"
    fi
}

# The export set of a shared library is the golden set of its flavor and
# configuration. A Rust-core library never links libssl or
# libcrypto, and it links libsasl2 exactly when SASL is on (spec
# line 1081). A legacy library links OpenSSL exactly with TLS.
dylib_facts() {
    local name="$1" lib="$2" fl="$3" config="$4" core="${5:-rust}" deps n
    if [ ! -f "$lib" ]; then
        fail "$name: no $lib"
        return
    fi
    golden "$fl" "$config" >"$LOGS/$name.golden"
    nm -gU "$lib" | awk '{ print $NF }' | sort -u >"$LOGS/$name.exports"
    n="$(wc -l <"$LOGS/$name.exports" | tr -d ' ')"
    if cmp -s "$LOGS/$name.golden" "$LOGS/$name.exports"; then
        pass "$name: $n exports, the $config $fl golden set"
    else
        fail "$name: the exports differ from the $config $fl golden set ($n exports)"
        diff "$LOGS/$name.golden" "$LOGS/$name.exports" | head -6
    fi
    bits "$config"
    deps="$(macho_deps "$lib" | tr '\n' ' ')"
    local has_ssl=0 has_sasl=0 want_ssl=0
    case " $deps" in *" libssl"* | *" libcrypto"*) has_ssl=1 ;; esac
    case " $deps" in *" libsasl2"*) has_sasl=1 ;; esac
    [ "$core" = legacy ] && want_ssl="$SSL01"
    if [ "$has_ssl" = "$want_ssl" ] && [ "$has_sasl" = "$SASL01" ]; then
        pass "$name: otool -L: ${deps:-libSystem only}"
    else
        fail "$name: otool -L: '$deps' (want OpenSSL=$want_ssl libsasl2=$SASL01)"
    fi
}

# A Rust-core archive has exactly one member.
one_member() {
    local name="$1" a="$2" n
    n="$(ar t "$a" 2>/dev/null | grep -cv '^__.SYMDEF')"
    if [ "$n" = 1 ]; then
        pass "$name: one member"
    else
        fail "$name: $n members"
    fi
}

xtask_check() {
    local name="$1" lib="$2" fl="$3" config="$4"
    shift 4
    check "$name" sh -c "cd \"$RDIR\" && CARGO_TARGET_DIR=\"$XT\" cargo xtask abi check \"$lib\" \
        --flavor $fl --config $config $*"
}
xtask_static() {
    local name="$1" a="$2" fl="$3" config="$4"
    check "$name" sh -c "cd \"$RDIR\" && CARGO_TARGET_DIR=\"$XT\" cargo xtask abi static \"$a\" \
        --flavor $fl --config $config"
}

# The native libraries of a Rust staticlib, as m4/zk_rust.m4 and
# cmake/ZkRust.cmake compute them.
echo 'pub fn f() {}' >"$WORK/native.rs"
NATIVE="$(rustc --crate-type staticlib --print native-static-libs "$WORK/native.rs" \
    -o "$WORK/native.a" 2>&1 | sed -n 's/.*native-static-libs: //p' | tr ' ' '\n' |
    grep -Ev '^(-lc|-lSystem)$' | awk 'NF && !seen[$0]++' | tr '\n' ' ')"
info "native libraries of a Rust staticlib: ${NATIVE:-none}"

# The link metadata rule (spec line 1087): each native
# library, -lsasl2 exactly with SASL, and no OpenSSL library. CMake names
# an imported library by its path, so a path to libNAME counts as -lNAME.
libs_rule() {
    local name="$1" config="$2" libs="$3" l ok=1 has_sasl=0
    bits "$config"
    for l in $NATIVE; do
        case " $libs " in *" $l "*) continue ;; esac
        if printf '%s\n' $libs | grep -Eq "/lib${l#-l}(\.[0-9]+)*\.(a|dylib|tbd)$"; then
            continue
        fi
        fail "$name: no $l in '$libs'"
        ok=0
    done
    if printf '%s\n' $libs | grep -Eq '^-l(ssl|crypto)$|/lib(ssl|crypto)[.0-9]*\.(a|dylib|tbd)$'; then
        fail "$name: an OpenSSL library in '$libs'"
        ok=0
    fi
    if printf '%s\n' $libs | grep -Eq '^-lsasl2$|/libsasl2[.0-9]*\.(dylib|tbd|a)$'; then
        has_sasl=1
    fi
    if [ "$has_sasl" != "$SASL01" ]; then
        fail "$name: libsasl2=$has_sasl in '$libs', want $SASL01"
        ok=0
    fi
    [ "$ok" = 1 ] && pass "$name: '$libs'"
}

# The installed headers are the six legacy headers, unchanged:
# include/zookeeper.h, zookeeper_version.h, zookeeper_log.h, proto.h,
# recordio.h and generated/zookeeper.jute.h.
headers_check() {
    local name="$1" dir="$2" h src bad=""
    if [ "$(ls "$dir" 2>/dev/null | sort | tr '\n' ' ')" != \
        "proto.h recordio.h zookeeper.h zookeeper.jute.h zookeeper_log.h zookeeper_version.h " ]; then
        fail "$name: the header set is '$(ls "$dir" 2>/dev/null | tr '\n' ' ')'"
        return
    fi
    for h in zookeeper.h zookeeper_version.h zookeeper_log.h proto.h recordio.h zookeeper.jute.h; do
        src="$CDIR/include/$h"
        [ "$h" = zookeeper.jute.h ] && src="$CDIR/generated/$h"
        cmp -s "$src" "$dir/$h" || bad="$bad $h"
    done
    if [ -z "$bad" ]; then
        pass "$name: the six headers equal the sources"
    else
        fail "$name: headers differ:$bad"
    fi
}

# The default trust paths are compiled into the library.
paths_in_lib() {
    local name="$1" lib="$2" file="$3" dir="$4"
    if [ -z "$file$dir" ]; then
        skip "$name: no default trust path recorded"
        return
    fi
    # grep -q stops early, and with pipefail the SIGPIPE of strings fails
    # the pipeline. Thus the test reads the strings from a file.
    strings -a "$lib" >"$LOGS/$name.strings" 2>/dev/null
    if grep -qF "$file" "$LOGS/$name.strings" && grep -qF "$dir" "$LOGS/$name.strings"; then
        pass "$name: the library has $file and $dir"
    else
        fail "$name: the library lacks $file or $dir"
    fi
}

###########################################################################
# The dev build (dev/build-dropin.sh): each configuration in
# both flavors with ABI_CHECK=1, then tests/abi and tests/link.
###########################################################################
stage_dev() {
    local config out fl
    for config in "${CONFIGS[@]}"; do
        out="$WORK/dev-$config"
        if run "$T_BUILD" "$LOGS/dev-$config.log" env CONFIG="$config" ABI_CHECK=1 \
            CARGO_TARGET_DIR="$XT" OPENSSL_PREFIX="$OPENSSL_PREFIX" SASL_PREFIX="$SASL_PREFIX" \
            "$RDIR/dev/build-dropin.sh" "$CDIR/.." "$out"; then
            pass "dev-$config: build-dropin.sh with ABI_CHECK=1"
        else
            fail "dev-$config: build-dropin.sh (see $LOGS/dev-$config.log)"
            tail -15 "$LOGS/dev-$config.log"
            continue
        fi
        warn_check "dev-$config" "$LOGS/dev-$config.log"
        for fl in mt st; do
            dylib_facts "dev-$config-$fl" "$out/libzookeeper_$fl.2.dylib" "$fl" "$config"
            one_member "dev-$config-$fl-archive" "$out/libzookeeper_$fl.a"
            if [ "$RUNTIME" = 1 ]; then
                check "dev-$config-$fl-abi-tests" "$RCDIR/tests/abi/run-abi-tests.sh" --flavor "$fl" \
                    --config "$config" --lib "$out" --no-xtask --dead-host 127.0.0.1:23559 \
                    --out "$WORK/dev-$config/abi-tests-$fl"
                check "dev-$config-$fl-link-tests" env LIBRARY_PATH="$SASL_PREFIX/lib" \
                    "$RCDIR/tests/link/run-link-tests.sh" --flavor "$fl" --config "$config" \
                    --archive "$out/libzookeeper_$fl.a" --no-xtask \
                    --out "$WORK/dev-$config/link-tests-$fl"
            fi
        done
    done
}

###########################################################################
# Autotools in a /tmp copy of the C sources.
###########################################################################
# The copy keeps the repository layout. The configure.ac and Makefile.am
# hooks include files from ../zookeeper-client-rust. Thus a symbolic link
# to RDIR stands next to the copy of the legacy C tree.
AT_SRC="$WORK/src/zookeeper-client-c"
at_prepared=0
at_prepare() {
    [ "$at_prepared" = 1 ] && return 0
    mkdir -p "$AT_SRC" && rm -rf "$WORK/src/zookeeper-client-rust" &&
        ln -s "$RDIR" "$WORK/src/zookeeper-client-rust" &&
        rsync -a --delete --exclude .deps --exclude target-dropin "$CDIR/" "$AT_SRC/" &&
        (cd "$AT_SRC" && LIBTOOLIZE=glibtoolize \
            ACLOCAL_PATH="$REF/m4:/opt/homebrew/share/aclocal" \
            run "$T_CONF" "$LOGS/autoreconf.log" autoreconf -fi) || {
        fail "autoreconf -fi (see $LOGS/autoreconf.log)"
        return 1
    }
    pass "autoreconf -fi of the copy $AT_SRC"
    at_prepared=1
}

# The probe options of the four configurations, as for the legacy
# reference builds.
at_args() {
    case "$1" in
    plain) echo --without-openssl --without-sasl ;;
    ssl) echo "--with-openssl=$OPENSSL_PREFIX" --without-sasl ;;
    sasl) echo --without-openssl "--with-sasl=$SASL_PREFIX" ;;
    full) echo "--with-openssl=$OPENSSL_PREFIX" "--with-sasl=$SASL_PREFIX" ;;
    default) ;;
    esac
}

# Configures, builds and installs the tree $WORK/at-ID. The Rust trees
# use the shared cargo directory CARGOKEY. The legacy SASL sources need
# -Wno-gnu-folding-constant with Apple clang 21, as for the reference.
# Usage: at_build ID MODE CARGOKEY LEGACY_SASL CONFIGURE-ARGS...
at_build() {
    local id="$1" mode="$2" key="$3" lsasl="$4" b="$WORK/at-$1"
    shift 4
    at_prepare || return 1
    rm -rf "$b"
    mkdir -p "$b"
    if [ "$mode" != no ]; then
        mkdir -p "$WORK/cargo-at-$key"
        ln -s "$WORK/cargo-at-$key" "$b/cargo"
    fi
    local cfl=()
    [ "$lsasl" = 1 ] && cfl=("CFLAGS=-g -O2 -D_GNU_SOURCE -Wno-gnu-folding-constant")
    if ! (cd "$b" && PKG_CONFIG_PATH=/opt/homebrew/opt/cppunit/lib/pkgconfig run "$T_CONF" \
        "$LOGS/at-$id-configure.log" "$AT_SRC/configure" --prefix="$b/inst" \
        --with-rust-client="$mode" --with-rust-workspace="$RDIR" "$@" ${cfl[@]+"${cfl[@]}"}); then
        fail "at-$id: configure (see $LOGS/at-$id-configure.log)"
        tail -5 "$LOGS/at-$id-configure.log"
        return 1
    fi
    if ! (cd "$b" && run "$T_BUILD" "$LOGS/at-$id-make.log" make -j"$JOBS" &&
        run "$T_CONF" "$LOGS/at-$id-install.log" make install); then
        fail "at-$id: make and make install (see $LOGS/at-$id-make.log)"
        grep -E 'error|Error' "$LOGS/at-$id-make.log" | head -8
        return 1
    fi
    pass "at-$id: configure, make, make install"
    warn_check "at-$id" "$LOGS/at-$id-make.log"
}

# The value of a make variable of a configured tree.
mkvar() {
    sed -n "s|^$2 = ||p" "$WORK/at-$1/Makefile" | head -1
}

# The checks of a Rust-core autotools tree.
at_rust_checks() {
    local id="$1" config="$2" b="$WORK/at-$1" lib fl deps
    lib="$b/inst/lib"
    if [ "$(mkvar "$id" ZKRS_ABI_CONFIG)" = "$config" ]; then
        pass "at-$id: ZKRS_ABI_CONFIG=$config"
    else
        fail "at-$id: ZKRS_ABI_CONFIG=$(mkvar "$id" ZKRS_ABI_CONFIG), want $config"
    fi
    check "at-$id-abi-check-static" make -C "$b" abi-check abi-static
    headers_check "at-$id-headers" "$b/inst/include/zookeeper"
    for fl in mt st; do
        dylib_facts "at-$id-$fl" "$lib/libzookeeper_$fl.2.dylib" "$fl" "$config"
        one_member "at-$id-$fl-archive" "$lib/libzookeeper_$fl.a"
        # shellcheck disable=SC1090
        deps="$(. "$lib/libzookeeper_$fl.la" && echo "${dependency_libs:-}")"
        libs_rule "at-$id-$fl.la dependency_libs" "$config" "$deps"
        bits "$config"
        if [ "$SSL01" = 1 ]; then
            paths_in_lib "at-$id-$fl-trust-paths" "$lib/libzookeeper_$fl.2.dylib" \
                "$(mkvar "$id" ZK_TLS_DEFAULT_CERT_FILE)" "$(mkvar "$id" ZK_TLS_DEFAULT_CERT_DIR)"
        fi
    done
    for fl in mt st; do
        if [ -f "$lib/pkgconfig/zookeeper_$fl.pc" ]; then
            libs_rule "at-$id-$fl.pc Libs.private" "$config" \
                "$(sed -n 's/^Libs.private:[[:space:]]*//p' "$lib/pkgconfig/zookeeper_$fl.pc")"
        else
            fail "at-$id: no zookeeper_$fl.pc"
        fi
        # The programs link the Rust core, so they never link OpenSSL.
        if macho_deps "$b/inst/bin/cli_$fl" | grep -Ec '^lib(ssl|crypto)' >/dev/null; then
            fail "at-$id: cli_$fl links OpenSSL"
        else
            pass "at-$id: cli_$fl: $(macho_deps "$b/inst/bin/cli_$fl" | tr '\n' ' ')"
        fi
    done
    if [ "$RUNTIME" = 1 ]; then
        check "at-$id-check-abi-link" make -C "$b" check-abi check-link \
            ZK_ABI_TEST_DEAD_HOST=127.0.0.1:23559
    fi
}

# The legacy libraries of a tree equal the reference build of the
# configuration: exports, archive globals, Mach-O dependencies, headers
# and the installed files (spec "Selecting what to build": the legacy
# products do not change).
legacy_compare() {
    local id="$1" config="$2" b="$WORK/at-$1" r="$REF/install-$2" lib="$WORK/at-$1/inst/lib" fl
    if [ ! -d "$r" ]; then
        skip "at-$id: no reference $r"
        return
    fi
    for fl in mt st; do
        if cmp -s <(nm -gU "$r/lib/libzookeeper_$fl.2.dylib" | awk '{ print $NF }' | sort -u) \
            <(nm -gU "$lib/libzookeeper_$fl.2.dylib" | awk '{ print $NF }' | sort -u); then
            pass "at-$id-$fl: the legacy exports equal the reference" \
                "($(nm -gU "$lib/libzookeeper_$fl.2.dylib" | wc -l | tr -d ' '))"
        else
            fail "at-$id-$fl: the legacy exports differ from the reference"
        fi
        if cmp -s <(ar_globals "$r/lib/libzookeeper_$fl.a") <(ar_globals "$lib/libzookeeper_$fl.a"); then
            pass "at-$id-$fl: the legacy archive globals equal the reference"
        else
            fail "at-$id-$fl: the legacy archive globals differ from the reference"
        fi
        if [ "$(macho_deps "$r/lib/libzookeeper_$fl.2.dylib" | grep -v "libzookeeper_$fl")" = \
            "$(macho_deps "$lib/libzookeeper_$fl.2.dylib" | grep -v "libzookeeper_$fl")" ]; then
            pass "at-$id-$fl: the legacy dependencies equal the reference"
        else
            fail "at-$id-$fl: legacy dependencies differ:" \
                "$(macho_deps "$lib/libzookeeper_$fl.2.dylib" | tr '\n' ' ')"
        fi
    done
    if diff -r "$r/include" "$b/inst/include" >"$LOGS/at-$id-hdr.diff" 2>&1; then
        pass "at-$id: the installed headers equal the reference"
    else
        fail "at-$id: the installed headers differ (see $LOGS/at-$id-hdr.diff)"
    fi
}

at_one() {
    local mode="$1" config="$2" id="$1-$2" lsasl=0
    bits "$config"
    [ "$mode" = no ] && [ "$SASL01" = 1 ] && lsasl=1
    # shellcheck disable=SC2046
    at_build "$id" "$mode" "$config" "$lsasl" $(at_args "$config") || return
    case "$mode" in
    yes) at_rust_checks "$id" "$config" ;;
    no)
        legacy_compare "$id" "$config"
        if [ "$(ls "$WORK/at-$id/inst/lib" | tr '\n' ' ')" = \
            "$(ls "$REF/install-$config/lib" 2>/dev/null | tr '\n' ' ')" ]; then
            pass "at-$id: the installed library files equal the reference"
        else
            fail "at-$id: the library files are '$(ls "$WORK/at-$id/inst/lib" | tr '\n' ' ')'"
        fi
        ;;
    esac
}

# Each build installs exactly one core. Thus configure accepts only the
# values no, yes and auto. The check gives the removed value side-by-side
# and expects the error.
stage_autotools() {
    local config
    for config in "${CONFIGS[@]}"; do
        at_one yes "$config"
    done
    if at_prepare; then
        mkdir -p "$WORK/at-conf"
        expect_fail at-bad-client-value \
            'with-rust-client must be no, yes or auto, not side-by-side' sh -c \
            "cd \"$WORK/at-conf\" && \"$AT_SRC/configure\" --with-rust-client=side-by-side \
            --with-rust-workspace=\"$RDIR\""
    fi
}

stage_legacy() {
    local config
    for config in "${CONFIGS[@]}"; do
        at_one no "$config"
    done
}

###########################################################################
# CMake: shared and static-only builds of each configuration and
# flavor. ctest -L 'abi|link' runs tests/abi and tests/link.
###########################################################################
cm_args() {
    case "$1" in
    plain) echo -DWITH_OPENSSL=OFF -DWITH_CYRUS_SASL=OFF ;;
    ssl) echo "-DWITH_OPENSSL=$OPENSSL_PREFIX" -DWITH_CYRUS_SASL=OFF ;;
    sasl) echo -DWITH_OPENSSL=OFF "-DWITH_CYRUS_SASL=$SASL_PREFIX" ;;
    full) echo "-DWITH_OPENSSL=$OPENSSL_PREFIX" "-DWITH_CYRUS_SASL=$SASL_PREFIX" ;;
    default) ;;
    esac
}

# Configures, builds and installs $WORK/cm-ID with the shared cargo
# directory CARGOKEY. Usage: cm_build ID CARGOKEY CMAKE-ARGS...
cm_build() {
    local id="$1" key="$2" b="$WORK/cm-$1"
    shift 2
    rm -rf "$b"
    mkdir -p "$b" "$WORK/cargo-cm-$key"
    ln -s "$WORK/cargo-cm-$key" "$b/cargo"
    if ! run "$T_CONF" "$LOGS/cm-$id-configure.log" cmake -S "$CDIR" -B "$b" -DWANT_CPPUNIT=OFF \
        -DCMAKE_INSTALL_PREFIX="$b/inst" -DZK_ABI_TEST_DEAD_HOST=127.0.0.1:23559 "$@"; then
        fail "cm-$id: configure (see $LOGS/cm-$id-configure.log)"
        grep -A3 'CMake Error' "$LOGS/cm-$id-configure.log" | head -8
        return 1
    fi
    if ! run "$T_BUILD" "$LOGS/cm-$id-build.log" cmake --build "$b" -j "$JOBS" ||
        ! run "$T_CONF" "$LOGS/cm-$id-install.log" cmake --install "$b"; then
        fail "cm-$id: build and install (see $LOGS/cm-$id-build.log)"
        grep -E 'error|Error' "$LOGS/cm-$id-build.log" | head -8
        return 1
    fi
    pass "cm-$id: configure, build, install"
    if [ "$key" = legacy ]; then
        warn_check "cm-$id" "$LOGS/cm-$id-build.log" "$LEGACY_WARN"
    else
        warn_check "cm-$id" "$LOGS/cm-$id-build.log"
    fi
}

# The TLS and SASL decision line of the configure step.
cm_decision() {
    sed -n 's/.*The TLS and SASL build of the Rust client: //p' "$LOGS/cm-$1-configure.log" | head -1
}

cm_checks() {
    local id="$1" config="$2" fl="$3" shared="$4" b="$WORK/cm-$1" want lt pc
    bits "$config"
    want="tls=$([ "$SSL01" = 1 ] && echo ON || echo OFF) provider=${5:-ring}"
    want="$want sasl=$([ "$SASL01" = 1 ] && echo ON || echo OFF)"
    if [ "$(cm_decision "$id")" = "$want" ]; then
        pass "cm-$id: $want"
    else
        fail "cm-$id: '$(cm_decision "$id")', want '$want'"
    fi
    one_member "cm-$id-archive" "$b/libzookeeper.a"
    headers_check "cm-$id-headers" "$b/inst/include/zookeeper"
    check "cm-$id-abi-static" cmake --build "$b" --target abi-static
    if [ "$shared" = ON ]; then
        dylib_facts "cm-$id" "$b/libzookeeper_$fl.2.dylib" "$fl" "$config"
        check "cm-$id-abi-check" cmake --build "$b" --target abi-check
    elif ls "$b"/libzookeeper_*.dylib >/dev/null 2>&1; then
        fail "cm-$id: the static-only build makes a shared library"
    else
        pass "cm-$id: static only"
    fi
    # The link interface of the zookeeper target: the program
    # zks_link_check links with target_link_libraries(... zookeeper hashtable).
    lt="$b/CMakeFiles/zks_link_check.dir/link.txt"
    if [ -f "$lt" ]; then
        libs_rule "cm-$id link interface" "$config" \
            "$(tr -s ' ' '\n' <"$lt" | grep -E '^-l|\.(dylib|tbd)$|/lib[^/]*\.a$' |
                grep -Ev '/libzookeeper\.a$|/libhashtable\.a$' | tr '\n' ' ')"
    else
        fail "cm-$id: no $lt"
    fi
    pc="$b/inst/lib/pkgconfig/zookeeper_$fl.pc"
    if [ -f "$pc" ]; then
        libs_rule "cm-$id .pc Libs.private" "$config" \
            "$(sed -n 's/^Libs.private:[[:space:]]*//p' "$pc")"
    else
        fail "cm-$id: no $pc"
    fi
    if [ -f "$b/cli" ] && macho_deps "$b/cli" | grep -Ec '^lib(ssl|crypto)' >/dev/null; then
        fail "cm-$id: cli links OpenSSL"
    fi
    if [ "$RUNTIME" = 1 ]; then
        check "cm-$id-ctest" ctest --test-dir "$b" -L 'abi|link' --output-on-failure \
            --timeout 1200
    fi
}

stage_cmake() {
    local config fl shared sync id
    for config in "${CONFIGS[@]}"; do
        for fl in mt st; do
            for shared in ON OFF; do
                sync=OFF
                [ "$fl" = mt ] && sync=ON
                id="$config-$fl-$([ "$shared" = ON ] && echo shared || echo static)"
                # shellcheck disable=SC2046
                cm_build "$id" "$config" -DWITH_RUST_CLIENT=ON "-DWANT_SYNCAPI=$sync" \
                    "-DZOOKEEPER_BUILD_SHARED=$shared" $(cm_args "$config") || continue
                cm_checks "$id" "$config" "$fl" "$shared"
            done
        done
    done
}

###########################################################################
# Provider builds (spec "Workspace layout and dependency rules" and
# "Selecting what to build"). Ring is the default. Aws-lc-rs builds and
# passes the TLS tests. Two providers or no provider stop the build. The
# FIPS provider stops the build on macOS.
###########################################################################
cargo_fail() {
    local name="$1" pattern="$2"
    shift 2
    expect_fail "$name" "$pattern" sh -c "cd \"$RDIR\" && CARGO_TARGET_DIR=\"$XT\" \
        cargo check --locked $*"
}

stage_provider() {
    local fl
    # The compile_error! guards of zk-driver, zk-ffi and zk-client. The
    # package name of zk-client is apache-zookeeper.
    cargo_fail prov-ffi-none 'needs exactly one provider feature' -p zk-ffi --features tls
    cargo_fail prov-ffi-two 'only one provider feature|only one TLS provider' \
        -p zk-ffi --features tls-ring,tls-aws-lc-rs
    cargo_fail prov-driver-none 'needs exactly one provider feature' -p zk-driver --features tls
    cargo_fail prov-driver-two 'takes only one provider feature' \
        -p zk-driver --features tls-ring,tls-aws-lc-rs
    # zk-client enables the tls feature of zk-driver, so the zk-driver check
    # can stop the build before the zk-client check runs.
    cargo_fail prov-client-none 'needs exactly one (TLS )?provider feature' \
        -p apache-zookeeper --features tls-rustls
    cargo_fail prov-client-two 'only one (TLS )?provider feature' \
        -p apache-zookeeper --features tls-ring,tls-aws-lc-rs

    # The FIPS provider needs Linux. Each build system stops
    # with the reason.
    expect_fail prov-dev-fips 'needs a Linux host' env CONFIG=ssl TLS_PROVIDER=aws-lc-rs-fips \
        CARGO_TARGET_DIR="$XT" "$RDIR/dev/build-dropin.sh" "$CDIR/.." "$WORK/dev-fips"
    expect_fail prov-cm-fips 'aws-lc-rs-fips needs a Linux target' cmake -S "$CDIR" \
        -B "$WORK/cm-fips" -DWITH_RUST_CLIENT=ON -DWANT_CPPUNIT=OFF \
        -DZK_RUST_TLS_PROVIDER=aws-lc-rs-fips
    expect_fail prov-cm-bogus 'give ring, aws-lc-rs or aws-lc-rs-fips' cmake -S "$CDIR" \
        -B "$WORK/cm-bogus" -DWITH_RUST_CLIENT=ON -DWANT_CPPUNIT=OFF -DZK_RUST_TLS_PROVIDER=bogus
    # The build systems take exactly one provider. Two providers or an
    # empty value stop the build, as the compile_error! checks do.
    expect_fail prov-cm-two 'give ring, aws-lc-rs or aws-lc-rs-fips' cmake -S "$CDIR" \
        -B "$WORK/cm-two" -DWITH_RUST_CLIENT=ON -DWANT_CPPUNIT=OFF \
        "-DZK_RUST_TLS_PROVIDER=ring;aws-lc-rs"
    expect_fail prov-cm-empty 'give ring, aws-lc-rs or aws-lc-rs-fips' cmake -S "$CDIR" \
        -B "$WORK/cm-empty" -DWITH_RUST_CLIENT=ON -DWANT_CPPUNIT=OFF -DZK_RUST_TLS_PROVIDER=
    expect_fail prov-dev-two 'unknown TLS_PROVIDER' env CONFIG=ssl "TLS_PROVIDER=ring aws-lc-rs" \
        CARGO_TARGET_DIR="$XT" "$RDIR/dev/build-dropin.sh" "$CDIR/.." "$WORK/dev-two"
    # A provider value is a Rust option. With the default core selection
    # it needs WITH_RUST_CLIENT=ON (spec "Selecting what to build").
    expect_fail prov-cm-default-off 'needs -DWITH_RUST_CLIENT=ON' cmake -S "$CDIR" \
        -B "$WORK/cm-provoff" -DWANT_CPPUNIT=OFF -DZK_RUST_TLS_PROVIDER=ring
    if at_prepare; then
        mkdir -p "$WORK/at-conf"
        expect_fail prov-at-fips 'aws-lc-rs-fips needs a Linux host' sh -c "cd \"$WORK/at-conf\" && \
            \"$AT_SRC/configure\" --with-rust-client=yes --with-rust-workspace=\"$RDIR\" \
            --with-rust-tls-provider=aws-lc-rs-fips"
        expect_fail prov-at-bogus 'give ring, aws-lc-rs or aws-lc-rs-fips' sh -c "cd \"$WORK/at-conf\" && \
            \"$AT_SRC/configure\" --with-rust-client=yes --with-rust-workspace=\"$RDIR\" \
            --with-rust-tls-provider=bogus"
        expect_fail prov-at-two 'give ring, aws-lc-rs or aws-lc-rs-fips' sh -c "cd \"$WORK/at-conf\" && \
            \"$AT_SRC/configure\" --with-rust-client=yes --with-rust-workspace=\"$RDIR\" \
            --with-rust-tls-provider=ring,aws-lc-rs"
        expect_fail prov-at-none 'give ring, aws-lc-rs or aws-lc-rs-fips' sh -c "cd \"$WORK/at-conf\" && \
            \"$AT_SRC/configure\" --with-rust-client=yes --with-rust-workspace=\"$RDIR\" \
            --without-rust-tls-provider"
        expect_fail prov-at-default-no 'needs --with-rust-client=yes' sh -c "cd \"$WORK/at-conf\" && \
            \"$AT_SRC/configure\" --with-rust-tls-provider=ring"
    fi

    # The ring default: a TLS build without a provider option uses ring,
    # and the ring archive has no aws-lc code.
    if [ -f "$WORK/dev-ssl/ffi-ssl/libzk_ffi.a" ]; then
        if nm_has "$WORK/dev-ssl/ffi-ssl/libzk_ffi.a" aws_lc; then
            fail "prov-ring-default: the default ssl staticlib has aws-lc symbols"
        elif nm_has "$WORK/dev-ssl/ffi-ssl/libzk_ffi.a" ring_core; then
            pass "prov-ring-default: the default ssl staticlib uses ring"
        else
            fail "prov-ring-default: the default ssl staticlib has no ring symbols"
        fi
    else
        skip "prov-ring-default (no dev-ssl build; run the dev stage first)"
    fi

    # aws-lc-rs: the dev build of ssl, its ABI checks and the tests of
    # tests/abi, then the Rust TLS tests with this provider.
    local out="$WORK/dev-ssl-awslc"
    if run "$T_BUILD" "$LOGS/prov-dev-awslc.log" env CONFIG=ssl TLS_PROVIDER=aws-lc-rs ABI_CHECK=1 \
        CARGO_TARGET_DIR="$XT" OPENSSL_PREFIX="$OPENSSL_PREFIX" \
        "$RDIR/dev/build-dropin.sh" "$CDIR/.." "$out"; then
        pass "prov-dev-awslc: build-dropin.sh TLS_PROVIDER=aws-lc-rs with ABI_CHECK=1"
        if nm_has "$out/ffi-ssl/libzk_ffi.a" ring_core; then
            fail "prov-dev-awslc: the aws-lc-rs staticlib has ring symbols"
        else
            pass "prov-dev-awslc: the aws-lc-rs staticlib has no ring symbols"
        fi
        for fl in mt st; do
            dylib_facts "prov-dev-awslc-$fl" "$out/libzookeeper_$fl.2.dylib" "$fl" ssl
            [ "$RUNTIME" = 1 ] && check "prov-dev-awslc-$fl-abi-tests" \
                "$RCDIR/tests/abi/run-abi-tests.sh" --flavor "$fl" --config ssl --lib "$out" \
                --no-xtask --dead-host 127.0.0.1:23559 --out "$out/abi-tests-$fl"
        done
    else
        fail "prov-dev-awslc: build-dropin.sh (see $LOGS/prov-dev-awslc.log)"
        tail -10 "$LOGS/prov-dev-awslc.log"
    fi
    check prov-driver-awslc-tests sh -c "cd \"$RDIR\" && CARGO_TARGET_DIR=\"$XT\" \
        cargo test --locked -p zk-driver --features tls-aws-lc-rs"
    check prov-client-awslc-tests sh -c "cd \"$RDIR\" && CARGO_TARGET_DIR=\"$XT\" \
        cargo test --locked -p apache-zookeeper --features tls-aws-lc-rs,sasl --test api_tls \
        --test tls_fake --test tls_keys"
    check prov-ffi-awslc-tests sh -c "cd \"$RDIR\" && CARGO_TARGET_DIR=\"$XT\" \
        cargo test --locked -p zk-ffi --features tls-aws-lc-rs"
    # The autotools build with --with-rust-tls-provider=aws-lc-rs.
    # shellcheck disable=SC2046
    if has_config ssl &&
        at_build awslc-ssl yes ssl-awslc 0 $(at_args ssl) --with-rust-tls-provider=aws-lc-rs; then
        if grep -q 'tls=yes provider=aws-lc-rs sasl=no' "$LOGS/at-awslc-ssl-configure.log"; then
            pass "at-awslc-ssl: configure selects aws-lc-rs"
        else
            fail "at-awslc-ssl: configure does not report provider=aws-lc-rs"
        fi
        at_rust_checks awslc-ssl ssl
    fi
    # The CMake build with ZK_RUST_TLS_PROVIDER=aws-lc-rs. Autotools and
    # CMake share abi/prelink.sh, and the aws-lc C code has common symbols
    # that the pre-link makes private externs.
    # shellcheck disable=SC2046
    if has_config full &&
        cm_build awslc-full-mt awslc-full -DWITH_RUST_CLIENT=ON -DWANT_SYNCAPI=ON \
            -DZOOKEEPER_BUILD_SHARED=ON -DZK_RUST_TLS_PROVIDER=aws-lc-rs $(cm_args full); then
        cm_checks awslc-full-mt full mt ON aws-lc-rs
    fi
}

###########################################################################
# The default trust paths: the option value, else the
# OPENSSLDIR of the probed OpenSSL. A bad value stops the build.
###########################################################################
stage_paths() {
    local p="$RCDIR/abi/tls-probe.sh" out
    out="$(sh "$p" --with-openssl="$OPENSSL_PREFIX" | tr '\n' ' ')"
    if [ "$out" = "tls=yes openssl=yes cert_file=$("$OPENSSL_PREFIX/bin/openssl" version -d |
        sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')/cert.pem cert_dir=$("$OPENSSL_PREFIX/bin/openssl" \
        version -d | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')/certs " ]; then
        pass "paths-probe-auto: $out"
    else
        fail "paths-probe-auto: '$out'"
    fi
    out="$(sh "$p" --without-openssl --with-rust-tls=no | tr '\n' ' ')"
    [ "$out" = "tls=no openssl=no cert_file= cert_dir= " ] && pass "paths-probe-no-tls: $out" ||
        fail "paths-probe-no-tls: '$out'"
    out="$(sh "$p" --with-openssl=/nonexistent --with-rust-tls=yes \
        --with-rust-tls-default-paths=:/x/certs | tr '\n' ' ')"
    [ "$out" = "tls=yes openssl=no cert_file= cert_dir=/x/certs " ] && pass "paths-probe-empty-file: $out" ||
        fail "paths-probe-empty-file: '$out'"
    expect_fail paths-probe-two-colons 'with one colon' sh "$p" \
        --with-rust-tls-default-paths=/a:/b:/c
    expect_fail paths-probe-relative 'give absolute paths' sh "$p" \
        --with-rust-tls-default-paths=a.pem:/b
    expect_fail paths-probe-no-colon 'give FILE:DIR' sh "$p" --with-rust-tls-default-paths=/a
    expect_fail paths-probe-contradiction 'contradicts --with-openssl=no' sh "$p" \
        --without-openssl --with-rust-tls=yes

    expect_fail paths-cm-two-colons 'with one colon' cmake -S "$CDIR" -B "$WORK/cm-badpaths" \
        -DWITH_RUST_CLIENT=ON -DWANT_CPPUNIT=OFF -DZK_RUST_TLS_DEFAULT_PATHS=/a:/b:/c
    expect_fail paths-cm-relative 'give absolute paths' cmake -S "$CDIR" -B "$WORK/cm-badpaths" \
        -DWITH_RUST_CLIENT=ON -DWANT_CPPUNIT=OFF -DZK_RUST_TLS_DEFAULT_PATHS=a.pem:/b
    if at_prepare; then
        mkdir -p "$WORK/at-conf"
        # The option is checked also without TLS.
        expect_fail paths-at-two-colons 'with one colon' sh -c "cd \"$WORK/at-conf\" && \
            \"$AT_SRC/configure\" --with-rust-client=yes --with-rust-workspace=\"$RDIR\" \
            --without-openssl --without-sasl --with-rust-tls-default-paths=/a:/b:/c"
    fi
    # A dev build with TLS_DEFAULT_PATHS records the values.
    local out2="$WORK/dev-ssl-paths"
    if run "$T_BUILD" "$LOGS/paths-dev.log" env CONFIG=ssl FLAVORS=mt CARGO_TARGET_DIR="$XT" \
        TLS_DEFAULT_PATHS=/zkxbuild/etc/cert.pem:/zkxbuild/etc/certs \
        "$RDIR/dev/build-dropin.sh" "$CDIR/.." "$out2"; then
        paths_in_lib paths-dev "$out2/libzookeeper_mt.2.dylib" /zkxbuild/etc/cert.pem \
            /zkxbuild/etc/certs
    else
        fail "paths-dev: build-dropin.sh (see $LOGS/paths-dev.log)"
    fi
}

###########################################################################
# The export-gating rule: the OpenSSL probe decides
# whether zookeeper_init_ssl is exported. The default export set thus
# equals the legacy default set of this host, and --with-rust-tls=yes
# builds TLS without OpenSSL headers.
###########################################################################
stage_gating() {
    local fl
    # Autotools without TLS or SASL options: the legacy core and the Rust
    # core give the same export sets.
    at_build default-no no default 1 &&
        at_build default-yes yes default 0 && {
        info "gating: autotools default config is $(mkvar default-yes ZKRS_ABI_CONFIG)"
        for fl in mt st; do
            if cmp -s <(nm -gU "$WORK/at-default-no/inst/lib/libzookeeper_$fl.2.dylib" |
                awk '{ print $NF }' | sort -u) \
                <(nm -gU "$WORK/at-default-yes/inst/lib/libzookeeper_$fl.2.dylib" |
                    awk '{ print $NF }' | sort -u); then
                pass "gating-at-default-$fl: the Rust and legacy default exports are equal" \
                    "($(nm -gU "$WORK/at-default-yes/inst/lib/libzookeeper_$fl.2.dylib" | wc -l |
                        tr -d ' '))"
            else
                fail "gating-at-default-$fl: the Rust and legacy default exports differ"
            fi
            dylib_facts "gating-at-default-yes-$fl" \
                "$WORK/at-default-yes/inst/lib/libzookeeper_$fl.2.dylib" "$fl" \
                "$(mkvar default-yes ZKRS_ABI_CONFIG)"
        done
        check gating-at-default-abi make -C "$WORK/at-default-yes" abi-check abi-static
    }

    # --with-rust-tls=yes without OpenSSL headers. The compiler of this
    # host does not find openssl/ssl.h without a -I option.
    if echo '#include <openssl/ssl.h>' | cc -E -x c - >/dev/null 2>&1; then
        skip "gating-at-rusttls: the compiler finds openssl/ssl.h without -I"
    elif at_build rusttls yes rusttls 0 --with-openssl=yes --with-rust-tls=yes --without-sasl \
        --with-rust-tls-default-paths=/zkxbuild/etc/cert.pem:/zkxbuild/etc/certs; then
        if grep -q 'no OpenSSL headers' "$LOGS/at-rusttls-configure.log"; then
            pass "gating-at-rusttls: configure warns that the programs have no TLS option"
        else
            fail "gating-at-rusttls: configure gives no warning about the OpenSSL headers"
        fi
        at_rust_checks rusttls ssl
    fi

    # CMake: the default configure of the Rust core against the legacy
    # default. The legacy CMake build is static only, so the test compares
    # the TLS and SASL names of the two archives and the Rust export set.
    if cm_build default-legacy legacy -DWANT_SYNCAPI=ON &&
        cm_build default-rust default -DWITH_RUST_CLIENT=ON -DZOOKEEPER_BUILD_SHARED=ON; then
        local ls=0 la=0 cfg
        ar_globals "$WORK/cm-default-legacy/libzookeeper.a" | grep -cx '_zookeeper_init_ssl' >/dev/null && ls=1
        ar_globals "$WORK/cm-default-legacy/libzookeeper.a" | grep -cx '_zoo_sasl_connect' >/dev/null && la=1
        case "$ls$la" in 00) cfg=plain ;; 10) cfg=ssl ;; 01) cfg=sasl ;; *) cfg=full ;; esac
        info "gating: the legacy CMake default is $cfg"
        for s in _zookeeper_init_ssl _zoo_sasl_connect; do
            if [ "$(ar_globals "$WORK/cm-default-legacy/libzookeeper.a" | grep -cx "$s")" = \
                "$(ar_globals "$WORK/cm-default-rust/libzookeeper.a" | grep -cx "$s")" ]; then
                pass "gating-cm-default: $s is in both archives or in none"
            else
                fail "gating-cm-default: $s differs between the archives"
            fi
        done
        dylib_facts gating-cm-default "$WORK/cm-default-rust/libzookeeper_mt.2.dylib" mt "$cfg"
        [ "$RUNTIME" = 1 ] && check gating-cm-default-ctest ctest --test-dir "$WORK/cm-default-rust" \
            -L 'abi|link' --output-on-failure --timeout 1200
    fi

    # CMake WITH_RUST_TLS=ON with OpenSSL hidden from the probe.
    if cm_build rusttls rusttls -DWITH_RUST_CLIENT=ON -DZOOKEEPER_BUILD_SHARED=ON \
        -DWITH_RUST_TLS=ON -DWITH_CYRUS_SASL=OFF -DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=ON \
        -DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew \
        -DZK_RUST_TLS_DEFAULT_PATHS=/zkxbuild/etc/cert.pem:/zkxbuild/etc/certs; then
        if grep -q 'OpenSSL libraries not found. WITH_RUST_TLS=ON builds SSL support' \
            "$LOGS/cm-rusttls-configure.log"; then
            pass "gating-cm-rusttls: the probe finds no OpenSSL, and TLS is on"
        else
            fail "gating-cm-rusttls: no 'WITH_RUST_TLS=ON builds SSL support' message"
        fi
        # CMake wraps the warning text, so the test joins the lines.
        if tr -s ' \n' '  ' <"$LOGS/cm-rusttls-configure.log" |
            grep -c 'cli and load_gen skipped' >/dev/null && [ ! -f "$WORK/cm-rusttls/cli" ]; then
            pass "gating-cm-rusttls: no OpenSSL headers, so cli and load_gen are not built"
        else
            fail "gating-cm-rusttls: no 'cli and load_gen skipped' warning, or cli is built"
        fi
        cm_checks rusttls ssl mt ON
        paths_in_lib gating-cm-rusttls-paths "$WORK/cm-rusttls/libzookeeper_mt.2.dylib" \
            /zkxbuild/etc/cert.pem /zkxbuild/etc/certs
    fi
}

for s in "${STAGES[@]}"; do
    case "$s" in
    dev | autotools | cmake | provider | paths | gating | legacy)
        echo "==== stage $s ($(date '+%H:%M:%S'))" | tee -a "$RESULTS"
        "stage_$s"
        ;;
    *) echo "run-build-matrix.sh: unknown stage $s" >&2; exit 2 ;;
    esac
done

echo "run-build-matrix.sh: $PASS passed, $FAIL failed, $SKIP skipped, $KNOWN known" | tee -a "$RESULTS"
[ "$FAIL" = 0 ]
