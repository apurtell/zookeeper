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

# Runs the ABI and boundary tests of a drop-in libzookeeper_mt or
# libzookeeper_st. The tests build against the
# public headers and link with -lzookeeper_FL as an application does.
#
# Usage: run-abi-tests.sh --lib DIR [options]
#   --flavor mt|st   the library flavor (default mt). The st build of each
#                    test has no THREADED. The golden set is the st set
#   --config C       the configuration plain, ssl, sasl or full (default
#                    plain). It selects the golden set and the expected
#                    Mach-O dependencies
#   --lib DIR        the directory of the drop-in libzookeeper_FL (required)
#   --ref DIR        the directory of a legacy libzookeeper_FL; the runner
#                    compares the transcripts of the two cores
#   --debug-lib DIR  the directory of a debug drop-in with the handle
#                    registry; the runner runs the use-after-close test
#   --host H:P       a running server; without it the server tests skip
#   --dead-host H:P  an address without a server (default 127.0.0.1:22779)
#   --out DIR        the build and transcript directory (default
#                    ${TMPDIR:-/tmp}/zk-abi-tests, or zk-abi-tests-st for st)
#   --no-xtask       do not run "cargo xtask abi check"
#
# The runner does not start or stop a server. The ELF checks (PLT
# interposition and copy relocations) need a Linux host, and they skip
# on other hosts.

set -uo pipefail

# The script uses three roots. RCDIR is the Rust C tree. RDIR is the Rust
# workspace. CDIR is the legacy C tree, and ZK_C_DIR overrides it.
# The shipped golden set is in RCDIR/abi. The test-only ABI data
# (absent.tsv and layout/) is in this directory.
HERE="$(cd "$(dirname "$0")" && pwd)"
RCDIR="$(cd "$HERE/../.." && pwd)"
RDIR="$(cd "$RCDIR/.." && pwd)"
CDIR="$(cd "${ZK_C_DIR:-$RDIR/../zookeeper-client-c}" && pwd)"
ABI="$RCDIR/abi"

LIB=""
REF=""
DBG=""
HOST=""
DEAD="127.0.0.1:22779"
OUT=""
FL=mt
CONFIG=plain
XTASK=1
while [ $# -gt 0 ]; do
    case "$1" in
    --flavor) FL="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --lib) LIB="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --debug-lib) DBG="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --dead-host) DEAD="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --no-xtask) XTASK=0; shift ;;
    *) echo "run-abi-tests.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
if [ -z "$LIB" ]; then
    echo "usage: run-abi-tests.sh --lib DIR [--flavor mt|st] [--config C] [--ref DIR]" \
        "[--debug-lib DIR] [--host H:P]" >&2
    exit 2
fi
# The flavor sets the library name and the THREADED define, as in legacy.
case "$FL" in
mt) FLDEF=(-DTHREADED) ;;
st) FLDEF=() ;;
*) echo "run-abi-tests.sh: unknown flavor $FL (use mt or st)" >&2; exit 2 ;;
esac
# The configuration selects the feature column values of the golden set.
# A SASL configuration links libsasl2, and no configuration links OpenSSL.
case "$CONFIG" in
plain) FEATRE='^-$'; SASLDEP=0 ;;
ssl) FEATRE='^(-|ssl)$'; SASLDEP=0 ;;
sasl) FEATRE='^(-|sasl)$'; SASLDEP=1 ;;
full) FEATRE='^(-|ssl|sasl)$'; SASLDEP=1 ;;
*) echo "run-abi-tests.sh: unknown config $CONFIG (use plain, ssl, sasl or full)" >&2; exit 2 ;;
esac
if [ -z "$OUT" ]; then
    OUT="${TMPDIR:-/tmp}/zk-abi-tests"
    [ "$FL" = mt ] || OUT="$OUT-$FL"
fi

CC="${CC:-cc}"
OS="$(uname -s)"
if [ "$OS" = Darwin ]; then
    SOEXT=dylib
    SONAME=libzookeeper_$FL.2.dylib
else
    SOEXT=so
    SONAME=libzookeeper_$FL.so.2
fi
INC=(-I"$CDIR/include" -I"$CDIR/generated")
WARN=(-Wall -Wextra -Werror)
mkdir -p "$OUT"

PASS=0
FAIL=0
SKIP=0
pass() { PASS=$((PASS + 1)); echo "PASS $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP $*"; }

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

# Builds a test program against the library in directory $2.
build_app() {
    local out="$1" lib="$2" src="$3"
    shift 3
    "$CC" -std=c99 "${WARN[@]}" -D_DARWIN_C_SOURCE -D_GNU_SOURCE ${FLDEF[@]+"${FLDEF[@]}"} \
        "${INC[@]}" "$HERE/$src" "$@" -L"$lib" -lzookeeper_"$FL" -Wl,-rpath,"$lib" -o "$out"
}

# The golden name lists of the flavor and the configuration. absent.tsv
# lists the sync names as absent from st. A name of a feature outside the
# configuration must also be absent.
rows() { awk '!/^#/ && NF > 0' "$1"; }
FLRE="(^|,)$FL(,|\$)"
rows "$ABI/symbols.tsv" | awk -F'\t' -v re="$FLRE" -v fr="$FEATRE" \
    'NR > 1 && $3 ~ re && $4 ~ fr {print $1}' >"$OUT/golden-names.txt"
{
    rows "$HERE/absent.tsv" | awk -F'\t' -v re="$FLRE" 'NR > 1 && $2 ~ re {print $1}'
    rows "$ABI/symbols.tsv" | awk -F'\t' -v re="$FLRE" -v fr="$FEATRE" \
        'NR > 1 && $3 ~ re && $4 !~ fr {print $1}'
} >"$OUT/absent-names.txt"
NGOLD="$(wc -l <"$OUT/golden-names.txt" | tr -d ' ')"

# ---- the C layout facts ----
TARGET="$(cd "$RDIR" && rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')"
EXPECT="$HERE/layout/$TARGET.expect"
if [ -f "$EXPECT" ]; then
    awk -v config=plain -f "$HERE/layout-facts.awk" "$EXPECT" >"$OUT/layout_facts.inc"
    check layout-plain sh -c "\"$CC\" -std=c11 ${WARN[*]} ${FLDEF[*]-} ${INC[*]} -I\"$OUT\" \
        \"$HERE/layout_check.c\" -o \"$OUT/layout-plain\" && \"$OUT/layout-plain\""
    SSLINC="$(pkg-config --cflags openssl 2>/dev/null || true)"
    SASLINC="$(pkg-config --cflags libsasl2 2>/dev/null || true)"
    if [ -n "$SSLINC$SASLINC" ] || [ -f /usr/include/openssl/ssl.h ]; then
        mkdir -p "$OUT/tls-sasl"
        awk -v config=tls-sasl -f "$HERE/layout-facts.awk" "$EXPECT" >"$OUT/tls-sasl/layout_facts.inc"
        check layout-tls-sasl sh -c "\"$CC\" -std=c11 ${WARN[*]} ${FLDEF[*]-} -DHAVE_OPENSSL_H \
            -DHAVE_CYRUS_SASL_H $SSLINC $SASLINC ${INC[*]} -I\"$OUT/tls-sasl\" \
            \"$HERE/layout_check.c\" -o \"$OUT/layout-tls-sasl\" && \"$OUT/layout-tls-sasl\""
    else
        skip "layout-tls-sasl (no OpenSSL headers)"
    fi
else
    skip "layout (no $EXPECT)"
fi

# ---- the Mach-O shared library ----
DYLIB="$LIB/$SONAME"
if [ "$OS" = Darwin ]; then
    if [ "$(basename "$(otool -D "$DYLIB" | tail -1)")" = "$SONAME" ]; then
        pass "install name $(otool -D "$DYLIB" | tail -1)"
    else
        fail "install name $(otool -D "$DYLIB" | tail -1)"
    fi
    if otool -L "$DYLIB" | sed -n 2p | grep -Eq 'compatibility version 3\.0\.0, current version 3\.0\.0'; then
        pass "compatibility and current versions 3.0.0"
    else
        fail "compatibility and current versions: $(otool -L "$DYLIB" | sed -n 2p)"
    fi
    DEPS="$(otool -L "$DYLIB" | awk 'NR > 2 {print $1}' | grep -Ev '^/usr/lib/libSystem\.B\.dylib$' || true)"
    SASLDEPS="$(echo "$DEPS" | grep -E '/libsasl2(\.[0-9]+)*\.dylib$' || true)"
    OTHER="$(echo "$DEPS" | grep -Ev '^$|/libsasl2(\.[0-9]+)*\.dylib$' || true)"
    if [ -n "$OTHER" ]; then
        fail "unexpected dependencies: $OTHER"
    elif [ "$SASLDEP" = 1 ] && [ -z "$SASLDEPS" ]; then
        fail "the $CONFIG library does not link libsasl2"
    elif [ "$SASLDEP" = 0 ] && [ -n "$SASLDEPS" ]; then
        fail "the $CONFIG library links $SASLDEPS"
    elif [ "$SASLDEP" = 1 ]; then
        pass "the only dependencies are libSystem and $SASLDEPS"
    else
        pass "the only dependency is libSystem"
    fi
    nm -gU "$DYLIB" | awk '{print $3}' | sort >"$OUT/exports.txt"
    LEAKS="$(grep -E '^_(_ZN|_R[A-Z0-9]|rust_|__rust|__rdl_|__rg_|zkrs_|zks_|ring_core_|aws_lc_)' \
        "$OUT/exports.txt" || true)"
    if [ -z "$LEAKS" ]; then
        pass "no Rust, std or core symbol is exported"
    else
        fail "exported internal symbols: $(echo "$LEAKS" | head -5 | tr '\n' ' ')"
    fi
    sed 's/^/_/' "$OUT/golden-names.txt" | sort >"$OUT/golden-mangled.txt"
    if cmp -s "$OUT/exports.txt" "$OUT/golden-mangled.txt"; then
        pass "the exports are the $NGOLD golden names"
    else
        fail "the exports differ from the golden names"
        diff "$OUT/golden-mangled.txt" "$OUT/exports.txt" | head -10
    fi
else
    skip "Mach-O checks (host is $OS)"
fi
if [ "$XTASK" = 1 ] && command -v cargo >/dev/null 2>&1; then
    check xtask-abi-check sh -c "cd \"$RDIR\" && cargo xtask abi check \"$DYLIB\" \
        --flavor $FL --config $CONFIG --libdir \"$LIB\""
else
    skip "xtask abi check"
fi

# ---- dlsym of the golden and absent names ----
"$CC" -std=c99 "${WARN[@]}" "$HERE/dlsym_check.c" -ldl -o "$OUT/dlsym_check" 2>/dev/null ||
    "$CC" -std=c99 "${WARN[@]}" "$HERE/dlsym_check.c" -o "$OUT/dlsym_check"
check dlsym "$OUT/dlsym_check" "$DYLIB" "$OUT/golden-names.txt" "$OUT/absent-names.txt"
if [ -n "$REF" ]; then
    check dlsym-ref "$OUT/dlsym_check" "$REF/$SONAME" "$OUT/golden-names.txt" "$OUT/absent-names.txt"
fi

# ---- the runtime ABI tests ----
CORES=(lib)
build_app "$OUT/runtime-lib" "$LIB" runtime_abi.c || fail "build runtime_abi"
if [ -n "$REF" ]; then
    CORES+=(ref)
    build_app "$OUT/runtime-ref" "$REF" runtime_abi.c || fail "build runtime_abi (ref)"
fi
for core in "${CORES[@]}"; do
    check "runtime-common-$core" sh -c "\"$OUT/runtime-$core\" common >\"$OUT/common-$core.txt\""
    check "runtime-logging-$core" sh -c "\"$OUT/runtime-$core\" logging $DEAD >\"$OUT/logging-$core.txt\""
    if [ -n "$HOST" ]; then
        check "runtime-server-$core" sh -c "\"$OUT/runtime-$core\" server $HOST >\"$OUT/server-$core.txt\""
    fi
done
check runtime-dev "$OUT/runtime-lib" dev "$DEAD"
[ -n "$HOST" ] || skip "runtime server (no --host)"
if [ -n "$REF" ]; then
    MODES=(common logging)
    [ -n "$HOST" ] && MODES+=(server)
    for m in "${MODES[@]}"; do
        check "differential-$m" diff "$OUT/$m-ref.txt" "$OUT/$m-lib.txt"
    done
fi

# ---- interposition of the exported functions ----
if [ -n "$HOST" ]; then
    for core in "${CORES[@]}"; do
        dir="$LIB"
        [ "$core" = ref ] && dir="$REF"
        if [ "$OS" = Darwin ]; then
            build_app "$OUT/interpose-$core.$SOEXT" "$dir" interpose.c -dynamiclib
            PRELOAD=(env DYLD_INSERT_LIBRARIES="$OUT/interpose-$core.$SOEXT")
        else
            build_app "$OUT/interpose-$core.$SOEXT" "$dir" interpose.c -shared -fPIC -ldl
            PRELOAD=(env LD_PRELOAD="$OUT/interpose-$core.$SOEXT")
        fi
        build_app "$OUT/interpose-app-$core" "$dir" interpose_app.c
        check "interpose-$core" "${PRELOAD[@]}" ZK_INTERPOSE_OUT="$OUT/hits-$core.txt" \
            "$OUT/interpose-app-$core" "$HOST"
    done
    # The application calls zoo_awget, zoo_awexists, zoo_aget_acl, zoo_aset
    # and zoo_adelete once each. The interposer must see these calls.
    for f in zoo_awget zoo_awexists zoo_aget_acl zoo_aset zoo_adelete; do
        if ! grep -Eq "^$f [1-9]" "$OUT/hits-lib.txt" 2>/dev/null; then
            fail "interpose: the direct call of $f is not seen"
        fi
    done
    if [ -n "$REF" ]; then
        # The library calls of the two cores reach the interposer the same
        # number of times. On Mach-O both cores bind them directly (zero).
        check differential-interpose diff "$OUT/hits-ref.txt" "$OUT/hits-lib.txt"
    fi
    if [ "$OS" != Linux ]; then
        skip "interpose: the ELF PLT routing needs a Linux host"
    fi
else
    skip "interpose (no --host)"
fi

# ---- the handle registry of a debug build ----
if [ -n "$DBG" ]; then
    build_app "$OUT/use-after-close" "$DBG" use_after_close.c || fail "build use_after_close"
    check use-after-close "$OUT/use-after-close" "$DEAD"
else
    skip "use-after-close (no --debug-lib)"
fi

echo "run-abi-tests.sh: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]
