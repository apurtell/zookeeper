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

# Builds the Rust-core drop-in libraries libzookeeper_mt and libzookeeper_st
# on macOS, and checks them against the golden ABI files. Developers use it
# for a fast build without configure or CMake. The link tests in
# c/tests/link also call it.
#
# Platforms: macOS (Darwin) only, on arm64 or x86_64. The script uses Mach-O
# linker options and otool, and it stops on other hosts. On other platforms,
# use the main build of zookeeper-client-c. The autotools hooks
# (configure --with-rust-client=yes, c/m4/zk_rust.m4 and c/rust.am) and the
# CMake hooks (-DWITH_RUST_CLIENT=ON, c/cmake/ZkRustClient.cmake) build the
# same libraries. They support Linux and other hosts with GNU ld and
# objcopy, and macOS. They do not build the Rust core on Cygwin. The CMake
# hooks also do not build it on Windows.
#
# Each library has the configuration plain, ssl, sasl or full. For each
# flavor, the script joins the zk-ffi staticlib, the shim and the unchanged
# jute and recordio objects into one relocatable object. Only the golden
# symbols stay global in that object. The dylib links the object with the
# export list of the flavor. The static archive has the object as its only
# member. This is the layout of the main build (c/abi/prelink.sh). One
# zk-ffi staticlib serves both flavors.
#
# Usage: [VAR=VALUE ...] build-dropin.sh [ZK_CLIENT_ROOT] [OUT_DIR]
#   ZK_CLIENT_ROOT  the zookeeper-client directory (default: the one that
#                   contains this script)
#   OUT_DIR         the output directory (default: $ZK_CLIENT_ROOT/target-dropin)
#
# Outputs per flavor FL: libzookeeper_FL.2.dylib, libzookeeper_FL.dylib,
# libzookeeper_FL.a and cli_FL in OUT_DIR, and obj-FL/ with the objects,
# the symbol lists and the smoke programs (smoke, smoke-static and
# cli_FL-static).
#
# Prerequisites: the Xcode command line tools (cc, ar, nm, otool), a Rust
# toolchain with cargo, and the generated jute sources in
# zookeeper-client-c/generated. The ssl and full configurations use
# openssl for the default trust locations. The sasl and full
# configurations need the Cyrus SASL headers and library.
#
# Environment:
#   FLAVORS           the flavors to build: "mt", "st" or "mt st" (default: mt st)
#   CONFIG            plain, ssl, sasl or full (default: plain). ssl adds the
#                     zk-ffi TLS feature and zookeeper_init_ssl. sasl adds the
#                     Cyrus glue and links -lsasl2. full has both. The TLS
#                     code is rustls, so no configuration links OpenSSL.
#   TLS_PROVIDER      the rustls provider of ssl and full: ring or aws-lc-rs
#                     (default: ring). aws-lc-rs-fips needs Linux, so this
#                     script rejects it.
#   TLS_DEFAULT_PATHS FILE:DIR, the default trust locations of ssl and full,
#                     as --with-rust-tls-default-paths (default: the OPENSSLDIR
#                     of OPENSSL_PREFIX/bin/openssl, else the platform list)
#   SASL_PREFIX       the Cyrus SASL prefix with include/sasl and lib (default:
#                     the Homebrew cyrus-sasl prefix, from brew --prefix when
#                     brew is on PATH, else /opt/homebrew/opt/cyrus-sasl)
#   OPENSSL_PREFIX    an OpenSSL prefix whose headers the ssl cli_FL uses for
#                     zookeeper.h, and whose openssl command gives the default
#                     trust locations. The build never links it (default: the
#                     Homebrew openssl@3 prefix, found as for SASL_PREFIX.
#                     Without its headers, the cli has no TLS)
#   CARGO_TARGET_DIR  the cargo target directory (default: the workspace target)
#   ARCH              the Mach-O architecture (default: uname -m)
#   CC                the C compiler (default: cc)
#   INSTALL_DIR       the directory part of the dylib install names (default: OUT_DIR)
#   ABI_CHECK         1 runs "cargo xtask abi check" and "cargo xtask abi static"
#                     on the outputs (default: 0)
#   SMOKE_HOST        a running server (HOST:PORT). When it is set, the static
#                     cli_FL also runs the batch command "ls /" (default: unset)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${1:-$SCRIPT_DIR/../..}" && pwd)"
OUT="${2:-$ROOT/target-dropin}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# CDIR is the legacy C tree. RDIR is the Rust workspace. RCDIR is the Rust
# C tree. The shim and the ABI data come from RCDIR. The headers, the jute
# and recordio sources and cli.c come from CDIR.
CDIR="$ROOT/zookeeper-client-c"
RDIR="$ROOT/zookeeper-client-rust"
RCDIR="$RDIR/c"
ABI="$RCDIR/abi"
ARCH="${ARCH:-$(uname -m)}"
CC="${CC:-cc}"
TARGET_DIR="${CARGO_TARGET_DIR:-$RDIR/target}"
INSTALL_DIR="${INSTALL_DIR:-$OUT}"
FLAVORS="${FLAVORS:-mt st}"
ABI_CHECK="${ABI_CHECK:-0}"
SMOKE_HOST="${SMOKE_HOST:-}"
CONFIG="${CONFIG:-plain}"
TLS_PROVIDER="${TLS_PROVIDER:-ring}"
# Prints the Homebrew prefix of formula $1. Without brew, it prints the
# default prefix of Homebrew on Apple silicon.
brew_opt() {
    local prefix=""
    if command -v brew >/dev/null 2>&1; then
        prefix="$(brew --prefix 2>/dev/null || true)"
    fi
    echo "${prefix:-/opt/homebrew}/opt/$1"
}
SASL_PREFIX="${SASL_PREFIX:-$(brew_opt cyrus-sasl)}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$(brew_opt openssl@3)}"

case "$CONFIG" in
plain) WITH_TLS=0 WITH_SASL=0 ;;
ssl) WITH_TLS=1 WITH_SASL=0 ;;
sasl) WITH_TLS=0 WITH_SASL=1 ;;
full) WITH_TLS=1 WITH_SASL=1 ;;
*)
    echo "build-dropin.sh: unknown CONFIG $CONFIG (use plain, ssl, sasl or full)" >&2
    exit 1
    ;;
esac
case "$TLS_PROVIDER" in
ring | aws-lc-rs) ;;
aws-lc-rs-fips)
    echo "build-dropin.sh: TLS_PROVIDER=aws-lc-rs-fips needs a Linux host, not macOS" >&2
    exit 1
    ;;
*)
    echo "build-dropin.sh: unknown TLS_PROVIDER $TLS_PROVIDER (use ring or aws-lc-rs)" >&2
    exit 1
    ;;
esac
if [ "$WITH_SASL" = 1 ] && [ ! -f "$SASL_PREFIX/include/sasl/sasl.h" ]; then
    echo "build-dropin.sh: no sasl/sasl.h in $SASL_PREFIX/include (set SASL_PREFIX)" >&2
    exit 1
fi

if [ "$(uname -s)" != "Darwin" ]; then
    echo "build-dropin.sh: this script supports macOS only" >&2
    exit 1
fi
for f in "$ABI/symbols.tsv" "$ABI/static-symbols.tsv"; do
    if [ ! -f "$f" ]; then
        echo "build-dropin.sh: missing $f (run cargo xtask abi golden)" >&2
        exit 1
    fi
done
for fl in $FLAVORS; do
    case "$fl" in
    mt | st) ;;
    *)
        echo "build-dropin.sh: unknown flavor $fl (use mt or st)" >&2
        exit 1
        ;;
    esac
done

# 1. The zk-ffi staticlib: capi profile and the features of the
#    configuration. The build never uses --workspace, because cargo then
#    adds the zk-client features of shared crates to the staticlib. The
#    explicit crate type gives a native archive with fat LTO. The flavor is a run-time value of
#    zkrs_init_args, so both flavors use this archive. plain passes no
#    feature. The other configurations copy the archive to their own
#    directory, because a later build with other features replaces it.
FFI_FEATURES=()
if [ "$WITH_TLS" = 1 ]; then
    FFI_FEATURES+=("tls-$TLS_PROVIDER")
fi
if [ "$WITH_SASL" = 1 ]; then
    FFI_FEATURES+=(sasl)
fi
FFI_ARGS=()
if [ "${#FFI_FEATURES[@]}" -gt 0 ]; then
    FFI_ARGS=("--features=$(
        IFS=,
        echo "${FFI_FEATURES[*]}"
    )")
fi
# The default trust locations follow the rule of configure.
# abi/tls-probe.sh applies the rule. The plain and sasl staticlibs get
# empty values. cargo always gets both variables, so a change rebuilds.
TLS_CERT_FILE=
TLS_CERT_DIR=
if [ "$WITH_TLS" = 1 ]; then
    PROBE_ARGS=(--with-openssl="$OPENSSL_PREFIX" --with-rust-tls=yes)
    if [ -n "${TLS_DEFAULT_PATHS:-}" ]; then
        PROBE_ARGS+=(--with-rust-tls-default-paths="$TLS_DEFAULT_PATHS")
    fi
    PROBE_OUT="$(sh "$RCDIR/abi/tls-probe.sh" "${PROBE_ARGS[@]}")"
    TLS_CERT_FILE="$(printf '%s\n' "$PROBE_OUT" | sed -n 's/^cert_file=//p')"
    TLS_CERT_DIR="$(printf '%s\n' "$PROBE_OUT" | sed -n 's/^cert_dir=//p')"
    echo "build-dropin.sh: default trust locations: file=${TLS_CERT_FILE:-none} dir=${TLS_CERT_DIR:-none}"
fi
CARGO_TARGET_DIR="$TARGET_DIR" ZK_TLS_DEFAULT_CERT_FILE="$TLS_CERT_FILE" \
    ZK_TLS_DEFAULT_CERT_DIR="$TLS_CERT_DIR" cargo rustc --locked \
    --manifest-path "$RDIR/Cargo.toml" -p zk-ffi --profile capi --crate-type staticlib \
    ${FFI_ARGS[@]+"${FFI_ARGS[@]}"}
FFI_LIB="$TARGET_DIR/capi/libzk_ffi.a"
if [ "$CONFIG" != plain ]; then
    mkdir -p "$OUT/ffi-$CONFIG"
    cp "$FFI_LIB" "$OUT/ffi-$CONFIG/libzk_ffi.a"
    FFI_LIB="$OUT/ffi-$CONFIG/libzk_ffi.a"
fi

SHIM_WARN=(-std=c99 -Wall -Wextra -Wdeclaration-after-statement -Werror)
# The shim units of both flavors. The mt flavor adds the sync API and the
# library threads.
SHIM_SRCS=(zks_data zks_handle zks_async zks_multi zks_drain zks_log zks_env zks_errors
    zks_resolve zks_rng zks_compat zks_layout_check)
SHIM_MT_SRCS=(zks_sync zks_threads)
# The units and the flags of the configuration.
# HAVE_OPENSSL_H and HAVE_CYRUS_SASL_H are set as in legacy, so the
# programs see the legacy declarations. zks_internal.h removes them for
# the shim units, which use ZKS_WITH_TLS and ZKS_WITH_SASL. Only the two
# glue units keep HAVE_CYRUS_SASL_H. The Cyrus headers are system headers,
# so their own warnings do not fail the build.
CONFIG_DEFS=()
SASL_SRCS=()
CONFIG_LIBS=()
# The hardening sets of configure. Every shim unit gets
# HARDEN_FLAGS. The two glue units also get the conversion warnings. The
# probe drops each flag that the compiler does not accept.
cc_accepts() {
    echo 'int x;' | "$CC" -arch "$ARCH" -O2 -Werror "$@" -c -x c - -o /dev/null 2>/dev/null
}
HARDEN_FLAGS=()
if cc_accepts -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3; then
    HARDEN_FLAGS+=(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
elif cc_accepts -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2; then
    HARDEN_FLAGS+=(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
fi
for f in -fstack-protector-strong -fstack-clash-protection -ftrivial-auto-var-init=zero \
    -fno-strict-overflow -Wformat=2 -Wformat-security -mbranch-protection=standard \
    -fcf-protection; do
    if cc_accepts "$f"; then
        HARDEN_FLAGS+=("$f")
    else
        echo "build-dropin.sh: notice: $CC does not accept $f" >&2
    fi
done
SASL_FLAGS=("${HARDEN_FLAGS[@]}")
if [ "$WITH_TLS" = 1 ]; then
    SHIM_SRCS+=(zks_tls)
    CONFIG_DEFS+=(-DZKS_WITH_TLS -DHAVE_OPENSSL_H)
fi
if [ "$WITH_SASL" = 1 ]; then
    SASL_SRCS=(zks_sasl_cyrus zks_sasl_cb)
    CONFIG_DEFS+=(-DZKS_WITH_SASL -DHAVE_CYRUS_SASL_H)
    CONFIG_LIBS=(-L"$SASL_PREFIX/lib" -lsasl2)
    for f in -Wconversion -Wsign-conversion; do
        if cc_accepts "$f"; then
            SASL_FLAGS+=("$f")
        else
            echo "build-dropin.sh: notice: $CC does not accept $f" >&2
        fi
    done
fi
# The programs (cli_FL and the smoke programs) see the declarations of the
# configuration, as with a legacy build. The ssl cli needs the OpenSSL
# headers only for the zsock_t types of zookeeper.h. Nothing links OpenSSL.
PROG_DEFS=()
if [ "$WITH_TLS" = 1 ] && [ -f "$OPENSSL_PREFIX/include/openssl/ossl_typ.h" ]; then
    PROG_DEFS+=(-DHAVE_OPENSSL_H -isystem "$OPENSSL_PREFIX/include")
fi
if [ "$WITH_SASL" = 1 ]; then
    PROG_DEFS+=(-DHAVE_CYRUS_SASL_H -isystem "$SASL_PREFIX/include")
fi

# Runs a command and kills it after $1 seconds. The status is the status
# of the command, or 137 after a kill.
with_timeout() {
    local secs="$1" pid watchdog rc=0
    shift
    "$@" &
    pid=$!
    # The watchdog closes its output and stops its sleep on TERM, so no
    # orphan process holds a pipe of the caller.
    (
        exec >/dev/null 2>&1
        sleep "$secs" &
        s=$!
        trap 'kill "$s"; exit 0' TERM
        wait "$s"
        kill -9 "$pid"
    ) &
    watchdog=$!
    wait "$pid" || rc=$?
    kill "$watchdog" 2>/dev/null || true
    wait "$watchdog" 2>/dev/null || true
    return "$rc"
}

build_flavor() {
    local fl="$1"
    local obj="$OUT/obj-$fl"
    local defs=() srcs=("${SHIM_SRCS[@]}") libs=() objs=()
    mkdir -p "$obj"
    if [ "$fl" = mt ]; then
        defs=(-DTHREADED)
        srcs+=("${SHIM_MT_SRCS[@]}")
        libs=(-lpthread)
    fi
    libs+=(${CONFIG_LIBS[@]+"${CONFIG_LIBS[@]}"})

    # 2. The shim and the verbatim C units. The shim is C99 and warning-free
    #    in both flavors. st has no THREADED, as in legacy.
    local cflags=(-arch "$ARCH" -O2 -g -fPIC -fexceptions -D_GNU_SOURCE ${defs[@]+"${defs[@]}"}
        -I"$CDIR/include" -I"$CDIR/generated")
    local s
    for s in "${srcs[@]}"; do
        "$CC" "${cflags[@]}" "${SHIM_WARN[@]}" ${HARDEN_FLAGS[@]+"${HARDEN_FLAGS[@]}"} \
            ${CONFIG_DEFS[@]+"${CONFIG_DEFS[@]}"} -I"$RCDIR/shim" -c "$RCDIR/shim/$s.c" -o "$obj/$s.o"
        objs+=("$obj/$s.o")
    done
    for s in ${SASL_SRCS[@]+"${SASL_SRCS[@]}"}; do
        "$CC" "${cflags[@]}" "${SHIM_WARN[@]}" ${SASL_FLAGS[@]+"${SASL_FLAGS[@]}"} "${CONFIG_DEFS[@]}" \
            -isystem "$SASL_PREFIX/include" -I"$RCDIR/shim" \
            -c "$RCDIR/shim/$s.c" -o "$obj/$s.o"
        objs+=("$obj/$s.o")
    done
    "$CC" "${cflags[@]}" -c "$CDIR/generated/zookeeper.jute.c" -o "$obj/zookeeper.jute.o"
    "$CC" "${cflags[@]}" -c "$CDIR/src/recordio.c" -o "$obj/recordio.o"
    objs+=("$obj/zookeeper.jute.o" "$obj/recordio.o")
    rm -f "$obj/libzks_$fl.a"
    ar rcs "$obj/libzks_$fl.a" "${objs[@]}"

    # 3. The symbol lists. Exports: the rows of the flavor and the
    #    configuration in symbols.tsv. Keep set: the exports plus
    #    static-symbols.tsv, the symbols that only the archive exports.
    awk -f "$ABI/gen-exports.awk" -v flavor="$fl" -v fmt=exp -v ssl="$WITH_TLS" \
        -v sasl="$WITH_SASL" "$ABI/symbols.tsv" | sort -u >"$obj/exports.exp"
    awk -f "$ABI/gen-exports.awk" -v flavor="$fl" -v fmt=keep -v ssl="$WITH_TLS" \
        -v sasl="$WITH_SASL" "$ABI/symbols.tsv" "$ABI/static-symbols.tsv" \
        | sed 's/^/_/' | sort -u >"$obj/keep.exp"

    # 4. Pre-link: one relocatable object, localized to the keep set.
    local all="$obj/zookeeper_${fl}_all.o"
    "$CC" -r -nostdlib -arch "$ARCH" -Wl,-exported_symbols_list,"$obj/keep.exp" \
        -Wl,-force_load,"$obj/libzks_$fl.a" "$FFI_LIB" -o "$all"

    # 5. The dylib. No -Bsymbolic, so interposition stays as in legacy.
    local dylib="$OUT/libzookeeper_$fl.2.dylib"
    "$CC" -dynamiclib -arch "$ARCH" -install_name "$INSTALL_DIR/libzookeeper_$fl.2.dylib" \
        -compatibility_version 3.0.0 -current_version 3.0.0 \
        -Wl,-exported_symbols_list,"$obj/exports.exp" -Wl,-dead_strip \
        "$all" ${libs[@]+"${libs[@]}"} -o "$dylib"
    ln -sf "libzookeeper_$fl.2.dylib" "$OUT/libzookeeper_$fl.dylib"

    # 6. The static archive: the pre-linked object is the only member.
    #    An application links it with the native libraries of
    #    the Rust staticlib.
    local archive="$OUT/libzookeeper_$fl.a"
    rm -f "$archive"
    ar rcs "$archive" "$all"

    # 7. cli_FL from the unchanged legacy source, with the flavor flags of
    #    legacy.
    "$CC" -arch "$ARCH" -O2 -g ${defs[@]+"${defs[@]}"} ${PROG_DEFS[@]+"${PROG_DEFS[@]}"} \
        -I"$CDIR/include" -I"$CDIR/generated" -I"$CDIR/src" "$CDIR/src/cli.c" "$dylib" \
        ${CONFIG_LIBS[@]+"${CONFIG_LIBS[@]}"} -o "$OUT/cli_$fl"

    # 8. Checks: the export set equals the golden set, no private symbol is
    #    global, and the archive has one member.
    nm -gU "$dylib" | awk '{ print $NF }' | sort -u >"$obj/actual.exp"
    if ! diff -u "$obj/exports.exp" "$obj/actual.exp"; then
        echo "build-dropin.sh: the $fl export set differs from symbols.tsv" >&2
        exit 1
    fi
    if grep -Eq '^_(zkrs_|zks_|_?ZN|_R)' "$obj/actual.exp"; then
        echo "build-dropin.sh: a private symbol is global in $dylib" >&2
        exit 1
    fi
    if [ "$(ar t "$archive" | grep -cv '^__.SYMDEF')" != 1 ]; then
        echo "build-dropin.sh: $archive does not have exactly one member" >&2
        exit 1
    fi
    # The link libraries: never OpenSSL, and libsasl2 exactly when SASL
    # is on.
    otool -L "$dylib" | tail -n +2 | awk '{ print $1 }' >"$obj/deps.txt"
    if grep -Eq 'lib(ssl|crypto)[.0-9]*dylib' "$obj/deps.txt"; then
        echo "build-dropin.sh: $dylib links OpenSSL" >&2
        exit 1
    fi
    local has_sasl
    if grep -q 'libsasl2' "$obj/deps.txt"; then
        has_sasl=1
    else
        has_sasl=0
    fi
    if [ "$has_sasl" != "$WITH_SASL" ]; then
        echo "build-dropin.sh: $dylib has libsasl2=$has_sasl, but CONFIG=$CONFIG needs $WITH_SASL" >&2
        exit 1
    fi

    # 9. Smoke test: data exports, C-only entries and one Rust entry through
    #    the dylib, then through the archive.
    cat >"$obj/smoke.c" <<'SMOKE'
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zookeeper.h>
int main(void)
{
    int rc = zoo_acreate_ttl(NULL, "/a", NULL, -1, &ZOO_OPEN_ACL_UNSAFE, ZOO_PERSISTENT_WITH_TTL,
                             0, NULL, NULL);
    if (rc != ZBADARGUMENTS || ZOO_CONNECTED_STATE != 3 || strcmp(zerror(-15), "ssl connection error")
        || strcmp(zoo_version_str(), ZOO_VERSION)) {
        fprintf(stderr, "smoke: unexpected result %d\n", rc);
        return 1;
    }
#ifdef SMOKE_TLS
    {
        /* A NULL cert string fails before the init, as legacy. */
        zhandle_t *zookeeper_init_ssl(const char *, const char *, watcher_fn, int,
                                      const clientid_t *, void *, int);
        errno = 0;
        if (zookeeper_init_ssl("127.0.0.1:1", NULL, NULL, 1000, NULL, NULL, 0) != NULL
            || errno != EINVAL) {
            fprintf(stderr, "smoke: zookeeper_init_ssl(NULL cert) gives errno %d\n", errno);
            return 1;
        }
    }
#endif
#ifdef SMOKE_SASL
    {
        /* The library callback block keeps the legacy layout. */
        sasl_callback_t *cb = zoo_sasl_make_basic_callbacks("u", "r", NULL);
        errno = 0;
        if (cb == NULL || cb[0].id != SASL_CB_GETREALM || cb[3].id != SASL_CB_PASS
            || cb[4].id != SASL_CB_LIST_END
            || zoo_sasl_make_password_callbacks("u", NULL, NULL) != NULL || errno != EINVAL) {
            fprintf(stderr, "smoke: unexpected SASL callback block\n");
            return 1;
        }
        free(cb);
    }
#endif
    return 0;
}
SMOKE
    local sdefs=()
    if [ "$WITH_TLS" = 1 ]; then
        sdefs+=(-DSMOKE_TLS)
    fi
    if [ "$WITH_SASL" = 1 ]; then
        sdefs+=(-DSMOKE_SASL)
    fi
    "$CC" -arch "$ARCH" ${defs[@]+"${defs[@]}"} ${PROG_DEFS[@]+"${PROG_DEFS[@]}"} \
        ${sdefs[@]+"${sdefs[@]}"} -I"$CDIR/include" -I"$CDIR/generated" \
        "$obj/smoke.c" "$dylib" ${CONFIG_LIBS[@]+"${CONFIG_LIBS[@]}"} -o "$obj/smoke"
    "$obj/smoke"
    "$CC" -arch "$ARCH" ${defs[@]+"${defs[@]}"} ${PROG_DEFS[@]+"${PROG_DEFS[@]}"} \
        ${sdefs[@]+"${sdefs[@]}"} -I"$CDIR/include" -I"$CDIR/generated" \
        "$obj/smoke.c" "$archive" ${libs[@]+"${libs[@]}"} -o "$obj/smoke-static"
    "$obj/smoke-static"

    # 9a. The static cli_FL: the unchanged legacy source links with the
    #     archive. A bad host makes zookeeper_init fail with EINVAL, so the
    #     exit status is 22, as for the legacy cli. With SMOKE_HOST the
    #     batch command "ls /" runs against a real server.
    "$CC" -arch "$ARCH" -O2 -g ${defs[@]+"${defs[@]}"} ${PROG_DEFS[@]+"${PROG_DEFS[@]}"} \
        -I"$CDIR/include" -I"$CDIR/generated" -I"$CDIR/src" "$CDIR/src/cli.c" "$archive" \
        ${libs[@]+"${libs[@]}"} -o "$obj/cli_$fl-static"
    local rc=0
    "$obj/cli_$fl-static" -h "h:12x" </dev/null >"$obj/cli-static.log" 2>&1 || rc=$?
    if [ "$rc" != 22 ]; then
        echo "build-dropin.sh: the static cli_$fl with a bad host exits $rc, not 22" >&2
        exit 1
    fi
    if [ -n "$SMOKE_HOST" ]; then
        rc=0
        with_timeout 30 "$obj/cli_$fl-static" -h "$SMOKE_HOST" -c "ls /" </dev/null \
            >"$obj/cli-static-ls.log" 2>&1 || rc=$?
        if [ "$rc" != 0 ] || ! grep -q '^/: rc = 0' "$obj/cli-static-ls.log"; then
            echo "build-dropin.sh: the static cli_$fl \"ls /\" on $SMOKE_HOST fails ($rc)" >&2
            exit 1
        fi
    fi

    # 10. The golden checks of the shared library and the archive, by the
    #     ABI checker of the workspace (cargo xtask abi).
    if [ "$ABI_CHECK" = 1 ]; then
        (cd "$RDIR" && CARGO_TARGET_DIR="$TARGET_DIR" cargo xtask abi check "$dylib" \
            --flavor "$fl" --config "$CONFIG" --libdir "$OUT")
        (cd "$RDIR" && CARGO_TARGET_DIR="$TARGET_DIR" cargo xtask abi static "$archive" \
            --flavor "$fl" --config "$CONFIG")
    fi

    echo "build-dropin.sh: $(wc -l <"$obj/actual.exp" | tr -d ' ') exports in $dylib"
    echo "build-dropin.sh: $archive, $OUT/cli_$fl"
}

for fl in $FLAVORS; do
    build_flavor "$fl"
done
