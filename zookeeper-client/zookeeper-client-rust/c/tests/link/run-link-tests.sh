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

# Runs the link tests of a static Rust core archive (LINK-01..05;
# spec "Producing the libraries" and "Verification
# and delivery"). Each test links a program with the archive as an
# application does, and runs it when it links.
#
# Usage: run-link-tests.sh --flavor mt|st --archive FILE [options]
#   --flavor mt|st        the flavor of the archive (required)
#   --config C            the configuration plain, ssl, sasl or full of the
#                         archive (default plain). It selects the golden set
#                         and the TLS and SASL options of the consumer build
#   --cmake-arg ARG       an extra option of the consumer configure step. A
#                         later -D option overrides a -D option of --config
#   --archive FILE        the static Rust core: libzookeeper_FL.a (autotools)
#                         or libzookeeper.a (CMake) (required)
#   --hashtable FILE      the CMake hashtable archive (LINK-04)
#   --la FILE             the libtool file of the archive (LINK-05)
#   --pc FILE             the pkg-config file of the flavor (LINK-05)
#   --prefix DIR          a CMake install prefix. A hand-written
#                         -lzookeeper -lhashtable line links against it (LINK-04)
#   --cmake-consumer      configure and build tests/link/cmake-consumer, an
#                         add_subdirectory() application (LINK-04)
#   --cmake PATH          the cmake program (default: cmake)
#   --rust-staticlib FILE a prebuilt libzk_ffi.a for the consumer build; without
#                         it the consumer build runs cargo
#   --native-libs "LIBS"  the native libraries of the Rust core
#                         (ZKRS_NATIVE_LIBS; default: from rustc)
#   --ref DIR             the directory of a legacy libzookeeper_FL.a; the
#                         runner records how legacy links (DEV characterization)
#   --host H:P            a running server; without it the programs make only
#                         the calls that need no server
#   --out DIR             the build directory (default ${TMPDIR:-/tmp}/zk-link-tests-FL)
#   --no-xtask            do not run "cargo xtask abi static"
#   --no-rust             do not build the unrelated Rust staticlib (LINK-01)
#
# ZKRS_CARGO_SOURCE_CONFIG names the cargo-sources.toml of a configure or
# CMake build with a vendor directory or system crates. Each cargo call
# then runs offline with these crate sources. zklinkring then builds from
# a copy in the out directory. When its Cargo.lock does not match the
# crates, the runner writes the lock of the copy again.
#
# The runner does not start or stop a server. A KNOWN line is a known
# failure that the runner reports and does not count. The ELF parts
# (--whole-archive, glibc and the pkg-config link on glibc) are written
# for Linux, and this macOS host does not run them.
#
# Ledger rows: ABI-10 (only the golden globals stay global), ABI-13
# (LINK-03: the archive defines no legacy internals) and DV-BLD-6 (one
# prelinked member).
#
# Ledger: ABI-10, ABI-13, DV-ABI-1, DV-BLD-1, DV-BLD-6, DV-TLS-4

set -uo pipefail

# The script uses three roots. RCDIR is the Rust C tree. RDIR is the Rust
# workspace. CDIR is the legacy C tree, and ZK_C_DIR overrides it,
# for example with a copy outside the repository.
HERE="$(cd "$(dirname "$0")" && pwd)"
RCDIR="$(cd "$HERE/../.." && pwd)"
RDIR="$(cd "$RCDIR/.." && pwd)"
CDIR="$(cd "${ZK_C_DIR:-$RDIR/../zookeeper-client-c}" && pwd)"

FL=""
CONFIG=plain
CMAKE_EXTRA=()
ARCHIVE=""
HASHTABLE=""
LA=""
PC=""
PREFIX=""
CONSUMER=0
CMAKE=cmake
RUSTLIB=""
NATIVE=""
NATIVE_SET=0
REF=""
HOST=""
OUT=""
XTASK=1
RUST=1
while [ $# -gt 0 ]; do
    case "$1" in
    --flavor) FL="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --cmake-arg) CMAKE_EXTRA+=("$2"); shift 2 ;;
    --archive) ARCHIVE="$2"; shift 2 ;;
    --hashtable) HASHTABLE="$2"; shift 2 ;;
    --la) LA="$2"; shift 2 ;;
    --pc) PC="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --cmake-consumer) CONSUMER=1; shift ;;
    --cmake) CMAKE="$2"; shift 2 ;;
    --rust-staticlib) RUSTLIB="$2"; shift 2 ;;
    --native-libs) NATIVE="$2"; NATIVE_SET=1; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --no-xtask) XTASK=0; shift ;;
    --no-rust) RUST=0; shift ;;
    *) echo "run-link-tests.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
# The crate source options of each cargo call. The form keeps an empty
# array safe under "set -u" in bash 3.2.
SRCARGS=()
if [ -n "${ZKRS_CARGO_SOURCE_CONFIG:-}" ]; then
    if [ ! -f "$ZKRS_CARGO_SOURCE_CONFIG" ]; then
        echo "run-link-tests.sh: ZKRS_CARGO_SOURCE_CONFIG names no file: $ZKRS_CARGO_SOURCE_CONFIG" >&2
        exit 2
    fi
    SRCARGS=(--offline --config "$ZKRS_CARGO_SOURCE_CONFIG")
fi
cargo_src() {
    cargo ${SRCARGS[@]+"${SRCARGS[@]}"} "$@"
}
case "$FL" in
mt) FLDEF=(-DTHREADED) ;;
st) FLDEF=() ;;
*) echo "usage: run-link-tests.sh --flavor mt|st --archive FILE [options]" >&2; exit 2 ;;
esac
# The consumer build must make the TLS and SASL decision of the archive.
case "$CONFIG" in
plain) CONFIG_ARGS=(-DWITH_OPENSSL=OFF -DWITH_CYRUS_SASL=OFF) ;;
ssl) CONFIG_ARGS=(-DWITH_RUST_TLS=ON -DWITH_CYRUS_SASL=OFF) ;;
sasl) CONFIG_ARGS=(-DWITH_OPENSSL=OFF -DWITH_CYRUS_SASL=ON) ;;
full) CONFIG_ARGS=(-DWITH_RUST_TLS=ON -DWITH_CYRUS_SASL=ON) ;;
*) echo "run-link-tests.sh: unknown config $CONFIG (use plain, ssl, sasl or full)" >&2; exit 2 ;;
esac
if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
    echo "run-link-tests.sh: --archive names no file: $ARCHIVE" >&2
    exit 2
fi
OUT="${OUT:-${TMPDIR:-/tmp}/zk-link-tests-$FL}"
mkdir -p "$OUT"
# The TLS form of LINK-01 needs the TLS fixtures of zk-driver, which are
# not in git. The zk-fixtures bin of zk-testkit makes them on the first
# use. It prints their cache directory. ZK_TEST_OPENSSL selects
# the OpenSSL 3 tool for the build (default: OPENSSL, then Homebrew
# openssl@3). ZK_TEST_TLS_FIXTURES names a ready directory, and then cargo
# does not run.
FIX=""
case "$CONFIG" in
ssl | full)
    if [ "$RUST" = 1 ]; then
        if [ -n "${ZK_TEST_TLS_FIXTURES:-}" ]; then
            FIX="$ZK_TEST_TLS_FIXTURES"
        elif command -v cargo >/dev/null 2>&1; then
            FIX="$(cd "$RDIR" && \
                ZK_TEST_OPENSSL="${ZK_TEST_OPENSSL:-${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}}" \
                cargo_src run -q --locked --offline -p zk-testkit --bin zk-fixtures -- tls)" || {
                echo "run-link-tests.sh: zk-fixtures did not make the TLS fixtures (see above)" >&2
                exit 2
            }
        else
            echo "run-link-tests.sh: the TLS fixtures need cargo; install it," \
                "set ZK_TEST_TLS_FIXTURES=DIR or use --no-rust" >&2
            exit 2
        fi
        if [ ! -f "$FIX/ca.pem" ]; then
            echo "run-link-tests.sh: the TLS fixture directory $FIX has no ca.pem" >&2
            exit 2
        fi
        # The test program gets the path as a C string, so it must be
        # absolute.
        FIX="$(cd "$FIX" && pwd)"
    fi
    ;;
esac
CC="${CC:-cc}"
OS="$(uname -s)"
INC=(-I"$CDIR/include" -I"$CDIR/generated")
CFLAGS=(-std=c99 -Wall -Wextra -Werror -D_DARWIN_C_SOURCE -D_GNU_SOURCE ${FLDEF[@]+"${FLDEF[@]}"})

PASS=0
FAIL=0
SKIP=0
KNOWN=0
pass() { PASS=$((PASS + 1)); echo "PASS $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP $*"; }
known() { KNOWN=$((KNOWN + 1)); echo "KNOWN $*"; }
info() { echo "INFO $*"; }

# Runs a command. The test passes when the exit status is 0.
check() {
    local name="$1"
    shift
    if "$@" >"$OUT/$name.log" 2>&1; then
        pass "$name"
    else
        fail "$name (see $OUT/$name.log)"
        tail -20 "$OUT/$name.log"
    fi
}

# Links a program, then runs it. The link must give no warning about a
# duplicate symbol. Usage: link_run NAME LINK-COMMAND...
link_run() {
    local name="$1"
    shift
    if ! "$@" -o "$OUT/$name" >"$OUT/$name.link.log" 2>&1; then
        fail "$name: the link fails (see $OUT/$name.link.log)"
        head -20 "$OUT/$name.link.log"
        return
    fi
    if grep -qi 'duplicate' "$OUT/$name.link.log"; then
        fail "$name: the linker reports a duplicate symbol (see $OUT/$name.link.log)"
        return
    fi
    check "$name" "$OUT/$name" ${HOST:+"$HOST"}
}

# The defined global symbols of an archive or object, one per line.
globals() {
    nm -g "$1" 2>/dev/null | awk 'NF >= 3 && $(NF - 1) ~ /^[A-TV-Z]$/ { print $NF }' | sort -u
}

# LINK-05: the list LIBS names each native library of the Rust core
# (ZKRS_NATIVE_LIBS) and no OpenSSL library (DV-BLD-1, DV-TLS-4).
# CMake names an imported library by its path, so a path to libNAME
# also satisfies -lNAME.
has_native() {
    local what="$1" libs="$2" l
    for l in $NATIVE; do
        case " $libs " in
        *" $l "*) continue ;;
        esac
        case "$l" in
        -l*)
            if printf '%s\n' $libs |
                grep -Eq "/lib${l#-l}(\.[0-9]+)*\.(a|so|dylib|tbd)(\.[0-9]+)*$"; then
                continue
            fi
            ;;
        esac
        fail "LINK-05 $what does not name $l"
        return 1
    done
    case " $libs " in
    *ssl* | *crypto*) fail "LINK-05 $what names an OpenSSL library: $libs"; return 1 ;;
    esac
    pass "LINK-05 $what: '$libs'"
}

# The native libraries of a Rust staticlib, as m4/zk_rust.m4 and
# cmake/ZkRust.cmake compute them: the rustc list without -lc and
# -lSystem, which the compiler driver adds.
if [ "$NATIVE_SET" = 0 ] && command -v rustc >/dev/null 2>&1; then
    echo 'pub fn f() {}' >"$OUT/native.rs"
    NATIVE="$(rustc --crate-type staticlib --print native-static-libs "$OUT/native.rs" \
        -o "$OUT/native.a" 2>&1 | sed -n 's/.*native-static-libs: //p' | tr ' ' '\n' |
        grep -Ev '^(-lc|-lSystem)$' | awk 'NF && !seen[$0]++' | tr '\n' ' ')"
fi
read -r -a LIBS <<<"$NATIVE"
[ "$FL" = mt ] && LIBS+=(-lpthread)
[ "$OS" = Linux ] && LIBS+=(-lrt)
# A SASL archive also needs libsasl2. LIBRARY_PATH or --native-libs gives
# its directory when the linker does not find it.
case "$CONFIG" in
sasl | full)
    case " ${LIBS[*]-} " in
    *" -lsasl2 "*) ;;
    *) LIBS+=(-lsasl2) ;;
    esac
    ;;
esac
info "flavor $FL, config $CONFIG, archive $ARCHIVE, native libraries: ${NATIVE:-none}"

# ---- the golden global set of the archive ----
if [ "$XTASK" = 1 ] && [ -n "$RDIR" ] && command -v cargo >/dev/null 2>&1; then
    xtask_static() {
        (cd "$RDIR" && cargo_src xtask abi static "$ARCHIVE" --flavor "$FL" --config "$CONFIG")
    }
    check xtask-abi-static xtask_static
else
    skip "xtask abi static"
fi
globals "$ARCHIVE" >"$OUT/core-globals.txt"
NMEM="$(ar t "$ARCHIVE" | grep -cv '^__.SYMDEF')"
if [ "$NMEM" = 1 ]; then
    pass "S3 the archive has one member"
else
    fail "S3 the archive has $NMEM members"
fi

# ---- LINK-01: the Rust core and an unrelated Rust staticlib ----
# Each staticlib has its own copy of std. The pre-linked member keeps
# only the golden names global, so the two copies do
# not collide. The probe uses std in the second copy. In a TLS
# configuration the second staticlib is zklinkring: it adds its own
# rustls and ring, and the program runs a mutual TLS handshake from the
# core to the TLS server of zklinkring.
RUSTDEF=()
RUSTA=()
case "$CONFIG" in
ssl | full) RING=1 ;;
*) RING=0 ;;
esac
build_second() {
    if [ "$RING" = 1 ]; then
        command -v cargo >/dev/null 2>&1 || return 1
        local ring="$HERE/zklinkring"
        : >"$OUT/zklinkring.log"
        if [ ${#SRCARGS[@]} -gt 0 ]; then
            # The copy keeps the tracked Cargo.lock as it is. System
            # crates can have other versions than that lock. The copy
            # also has zklinkrs.rs, because zklinkring includes it.
            rm -rf "$OUT/zklinkring-src"
            ring="$OUT/zklinkring-src/zklinkring"
            mkdir -p "$ring"
            cp "$HERE/zklinkrs.rs" "$OUT/zklinkring-src/" || return 1
            cp -R "$HERE/zklinkring/Cargo.toml" "$HERE/zklinkring/Cargo.lock" \
                "$HERE/zklinkring/src" "$ring/" || return 1
            if ! cargo_src fetch --locked --manifest-path "$ring/Cargo.toml" \
                >>"$OUT/zklinkring.log" 2>&1; then
                info "zklinkring: Cargo.lock does not match the crate sources; writing it again"
                cargo_src generate-lockfile --manifest-path "$ring/Cargo.toml" \
                    >>"$OUT/zklinkring.log" 2>&1 || return 1
            fi
        fi
        cargo_src build --release --locked --offline --manifest-path "$ring/Cargo.toml" \
            --target-dir "$OUT/zklinkring-target" >>"$OUT/zklinkring.log" 2>&1 || return 1
        cp "$OUT/zklinkring-target/release/libzklinkring.a" "$OUT/libzklinkrs.a"
    else
        rustc --edition 2021 --crate-type staticlib --crate-name zklinkrs -C panic=abort \
            -C opt-level=1 "$HERE/zklinkrs.rs" -o "$OUT/libzklinkrs.a" >"$OUT/zklinkrs.log" 2>&1
    fi
}
if [ "$RUST" = 1 ] && command -v rustc >/dev/null 2>&1; then
    if build_second; then
        RUSTDEF=(-DZKLINK_RUST)
        if [ "$RING" = 1 ]; then
            RUSTDEF+=(-DZKLINK_RING
                "-DZKLINK_TLS_FIX=\"$FIX\"")
        fi
        RUSTA=("$OUT/libzklinkrs.a")
        globals "$OUT/libzklinkrs.a" >"$OUT/rust-globals.txt"
        COMMON="$(comm -12 "$OUT/core-globals.txt" "$OUT/rust-globals.txt")"
        if [ -z "$COMMON" ]; then
            pass "LINK-01 the core and the Rust staticlib define no common global" \
                "($(wc -l <"$OUT/rust-globals.txt" | tr -d ' ') Rust globals)"
        else
            fail "LINK-01 common globals: $(echo "$COMMON" | head -5 | tr '\n' ' ')"
        fi
        if [ "$RING" = 1 ]; then
            # The provider names are global in zklinkring and local in
            # the core, so this check has a real input.
            NRING="$(grep -c 'ring_core_' "$OUT/rust-globals.txt")"
            if [ "$NRING" -gt 0 ]; then
                pass "LINK-01 the Rust staticlib has its own ring ($NRING ring_core_ globals)"
            else
                fail "LINK-01 the Rust staticlib has no ring_core_ global"
            fi
        fi
        link_run link01-core-first "$CC" "${CFLAGS[@]}" "${INC[@]}" ${RUSTDEF[@]+"${RUSTDEF[@]}"} \
            "$HERE/link_app.c" "$ARCHIVE" ${RUSTA[@]+"${RUSTA[@]}"} ${LIBS[@]+"${LIBS[@]}"}
        link_run link01-rust-first "$CC" "${CFLAGS[@]}" "${INC[@]}" ${RUSTDEF[@]+"${RUSTDEF[@]}"} \
            "$HERE/link_app.c" ${RUSTA[@]+"${RUSTA[@]}"} "$ARCHIVE" ${LIBS[@]+"${LIBS[@]}"}
    elif [ "$RING" = 1 ]; then
        fail "LINK-01 zklinkring does not build (see $OUT/zklinkring.log)"
    else
        fail "LINK-01 the Rust staticlib does not build (see $OUT/zklinkrs.log)"
    fi
    if [ "$RING" = 0 ]; then
        info "LINK-01 has no TLS in this configuration: the crypto provider part is not run"
    fi
else
    skip "LINK-01 (no rustc)"
fi

# ---- LINK-02: a whole-archive link ----
# The macOS forms are -force_load and -all_load. With -all_load the
# linker also loads each member of the Rust staticlib. No global of the
# core may be a libc, libpthread or libSystem name.
if [ "$OS" = Darwin ]; then
    link_run link02-force-load "$CC" "${CFLAGS[@]}" "${INC[@]}" "$HERE/link_app.c" \
        -Wl,-force_load,"$ARCHIVE" ${LIBS[@]+"${LIBS[@]}"}
    link_run link02-all-load "$CC" "${CFLAGS[@]}" "${INC[@]}" ${RUSTDEF[@]+"${RUSTDEF[@]}"} \
        "$HERE/link_app.c" -Wl,-all_load "$ARCHIVE" ${RUSTA[@]+"${RUSTA[@]}"} ${LIBS[@]+"${LIBS[@]}"}
    # The SDK stubs of libSystem list the names of its sublibraries.
    SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
    if [ -n "$SDK" ] && [ -f "$SDK/usr/lib/libSystem.B.tbd" ]; then
        grep -ohE '_[A-Za-z0-9_$.]+' "$SDK/usr/lib/libSystem.B.tbd" "$SDK"/usr/lib/system/*.tbd |
            sort -u >"$OUT/libsystem-names.txt"
        if ! grep -qx '_malloc' "$OUT/libsystem-names.txt" ||
            ! grep -qx '_pthread_create' "$OUT/libsystem-names.txt"; then
            fail "LINK-02 the libSystem name list is not complete"
        else
            COMMON="$(comm -12 "$OUT/core-globals.txt" "$OUT/libsystem-names.txt")"
            if [ -z "$COMMON" ]; then
                pass "LINK-02 no global of the core is a libSystem name"
            else
                fail "LINK-02 libSystem names: $(echo "$COMMON" | head -5 | tr '\n' ' ')"
            fi
        fi
    else
        skip "LINK-02 libSystem names (no SDK stubs)"
    fi
elif [ "$OS" = Linux ]; then
    link_run link02-whole-archive "$CC" "${CFLAGS[@]}" "${INC[@]}" "$HERE/link_app.c" \
        -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive ${LIBS[@]+"${LIBS[@]}"}
    : >"$OUT/libc-names.txt"
    for so in libc.so.6 libpthread.so.0; do
        f="$("$CC" -print-file-name="$so")"
        [ -f "$f" ] && nm -D --defined-only "$f" | awk '{ sub(/@.*/, "", $NF); print $NF }' \
            >>"$OUT/libc-names.txt"
    done
    sort -u -o "$OUT/libc-names.txt" "$OUT/libc-names.txt"
    COMMON="$(comm -12 "$OUT/core-globals.txt" "$OUT/libc-names.txt")"
    if [ -z "$COMMON" ]; then
        pass "LINK-02 no global of the core is a libc or libpthread name"
    else
        fail "LINK-02 libc names: $(echo "$COMMON" | head -5 | tr '\n' ' ')"
    fi
else
    skip "LINK-02 (host is $OS)"
fi

# ---- LINK-03: the application defines legacy internal names (DV-ABI-1) ----
# own_symbols.c defines hash, do_io and other names of the removed set.
# The link works, and each name keeps the definition of the application.
link_run link03-own-symbols "$CC" "${CFLAGS[@]}" "${INC[@]}" -DZKLINK_OWN "$HERE/link_app.c" \
    "$HERE/own_symbols.c" "$ARCHIVE" ${LIBS[@]+"${LIBS[@]}"}
OWN="$(sed -En 's/^(int|void|long|double) \*?([A-Za-z_]+)[ (].*/\2/p' "$HERE/own_symbols.c" |
    grep -v '^zklink_own_check$' | sort -u)"
for s in $OWN; do
    grep -Eqx "_?$s" "$OUT/core-globals.txt" && fail "LINK-03 the core defines $s"
done
if [ -n "$REF" ] && [ -f "$REF/libzookeeper_$FL.a" ]; then
    # DEV characterization: legacy defines these names, so its link fails.
    if "$CC" "${CFLAGS[@]}" "${INC[@]}" -DZKLINK_OWN "$HERE/link_app.c" "$HERE/own_symbols.c" \
        "$REF/libzookeeper_$FL.a" -lm ${FLDEF[@]+-lpthread} -o "$OUT/link03-legacy" \
        >"$OUT/link03-legacy.log" 2>&1; then
        info "LINK-03 legacy: the link works"
    else
        info "LINK-03 legacy: the link fails, $(grep -ci 'duplicate symbol' \
            "$OUT/link03-legacy.log") duplicate symbols (DV-ABI-1)"
    fi
fi

# ---- LINK-04: the hashtable archive and the CMake application ----
# hashtable has one member and no global. The CMake application
# uses target_link_libraries(app zookeeper hashtable), and a hand-written
# line uses -lzookeeper -lhashtable.
check_hashtable() {
    local a="$1" n g
    n="$(ar t "$a" | grep -cv '^__.SYMDEF')"
    g="$(globals "$a" | tr '\n' ' ')"
    if [ "$n" = 1 ] && [ -z "$g" ]; then
        pass "LINK-04 $a has one member and no global"
    else
        fail "LINK-04 $a has $n members, globals: $g"
    fi
}
# Links with the hand-written line against DIR, then runs the program.
hand_link() {
    local name="$1" dir="$2"
    shift 2
    link_run "$name" "$CC" "${CFLAGS[@]}" "$@" "$HERE/link_app.c" -L"$dir" -lzookeeper \
        -lhashtable ${LIBS[@]+"${LIBS[@]}"}
}
[ -n "$HASHTABLE" ] && check_hashtable "$HASHTABLE"
if [ -n "$HASHTABLE" ] && [ "$(basename "$ARCHIVE")" = libzookeeper.a ]; then
    hand_link link04-build-tree "$(dirname "$ARCHIVE")" "${INC[@]}" -L"$(dirname "$HASHTABLE")"
fi
if [ -n "$PREFIX" ]; then
    check_hashtable "$PREFIX/lib/libhashtable.a"
    hand_link link04-prefix "$PREFIX/lib" -I"$PREFIX/include/zookeeper"
fi
if [ "$CONSUMER" = 1 ]; then
    B="$OUT/cmake-consumer"
    SYNC=OFF
    [ "$FL" = mt ] && SYNC=ON
    ARGS=(-S "$HERE/cmake-consumer" -B "$B" -DZK_C_SOURCE_DIR="$CDIR" -DWITH_RUST_CLIENT=ON
        "${CONFIG_ARGS[@]}" -DWANT_CPPUNIT=OFF "-DWANT_SYNCAPI=$SYNC"
        -DCMAKE_INSTALL_PREFIX="$B/inst" -DCMAKE_C_COMPILER="$CC" ${CMAKE_EXTRA[@]+"${CMAKE_EXTRA[@]}"})
    [ -n "$RUSTLIB" ] && ARGS+=(-DZKRS_STATICLIB="$RUSTLIB")
    if "$CMAKE" "${ARGS[@]}" >"$OUT/consumer.log" 2>&1 &&
        "$CMAKE" --build "$B" -j 4 >>"$OUT/consumer.log" 2>&1 &&
        "$CMAKE" --install "$B" >>"$OUT/consumer.log" 2>&1; then
        pass "LINK-04 the add_subdirectory() application configures and links"
        check link04-consumer "$B/zklink_consumer" ${HOST:+"$HOST"}
        # LINK-05 for CMake: the link interface of the zookeeper target
        # gives the native libraries and no OpenSSL library.
        LINKTXT="$B/CMakeFiles/zklink_consumer.dir/link.txt"
        if [ -f "$LINKTXT" ]; then
            CMLIBS="$(tr -s ' ' <"$LINKTXT" | tr ' ' '\n' | grep -E '^-l|\.(a|dylib|so|tbd)$' |
                tr '\n' ' ')"
            has_native "the CMake link interface" "$CMLIBS"
        fi
        check_hashtable "$B/inst/lib/libhashtable.a"
        hand_link link04-consumer-prefix "$B/inst/lib" -I"$B/inst/include/zookeeper"
    else
        fail "LINK-04 the add_subdirectory() application (see $OUT/consumer.log)"
        tail -20 "$OUT/consumer.log"
    fi
fi

# ---- LINK-05: the link metadata ----
# The .la dependency_libs and the .pc Libs.private pass has_native. A
# static link with only these libraries works. The glibc 2.28 part
# needs a Linux host.
if [ -n "$LA" ]; then
    # shellcheck disable=SC1090
    DEPS="$(. "$LA" && echo "${dependency_libs:-}" | tr -s ' ' | sed 's/^ //')"
    if has_native "$(basename "$LA") dependency_libs" "$DEPS"; then
        # shellcheck disable=SC2086
        link_run link05-la "$CC" "${CFLAGS[@]}" "${INC[@]}" "$HERE/link_app.c" "$ARCHIVE" $DEPS
    fi
else
    skip "LINK-05 .la (no --la)"
fi
if [ -z "$PC" ] && [ -n "$LA" ]; then
    PC="$(dirname "$LA")/pkgconfig/zookeeper_$FL.pc"
fi
if [ -n "$PC" ] && [ -f "$PC" ]; then
    PRIV="$(sed -n 's/^Libs.private:[[:space:]]*//p' "$PC")"
    if has_native "$(basename "$PC") Libs.private" "$PRIV" &&
        command -v pkg-config >/dev/null 2>&1; then
        # shellcheck disable=SC2046
        link_run link05-pc "$CC" "${CFLAGS[@]}" $(PKG_CONFIG_PATH="$(dirname "$PC")" \
            pkg-config --cflags "zookeeper_$FL") "$HERE/link_app.c" \
            $(PKG_CONFIG_PATH="$(dirname "$PC")" pkg-config --static --libs "zookeeper_$FL")
    fi
elif [ -n "$LA" ] || [ -n "$PC" ]; then
    known "LINK-05 .pc: the build installs no zookeeper_$FL.pc"
fi

echo "run-link-tests.sh: $PASS passed, $FAIL failed, $SKIP skipped, $KNOWN known"
[ "$FAIL" = 0 ]
