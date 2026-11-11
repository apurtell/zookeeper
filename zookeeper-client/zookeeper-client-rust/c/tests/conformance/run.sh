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

# Differential conformance runner.
#
# The script compiles each scenario once against the original headers and
# links it against the legacy library. It runs each scenario once per core.
# DYLD_LIBRARY_PATH selects the core, and the recorder rejects a run that
# loads a library from another directory. Each run gets fresh real
# servers. The script then normalizes and compares the two runs in the
# mode that the scenario declares.
#
# Usage: run.sh --rust LIBDIR [--legacy LIBDIR] [--flavor mt|st] [--out DIR]
#               [--port-base N] [--reps N] [--sasl] [--tls DIR] [CASE...]
#
#   --rust       the directory of the drop-in libzookeeper_FL.2.dylib
#   --legacy     the directory of the reference libzookeeper_FL.2.dylib
#                (default: /tmp/zk-legacy-ref/install-plain/lib)
#   --flavor     the library flavor FL (default: mt). An st case compiles
#                without THREADED and links libzookeeper_st.
#   --out        the work directory (default: /tmp/zkconf, or
#                /tmp/zkconf-st for st)
#   --port-base  the first of 12 server ports (default: 22750)
#   --reps       the repetitions per core (default: 1; a full run uses 3)
#   --sasl       give each server a JAAS "Server" section with the
#                DIGEST-MD5 user myuser and the password mypassword. It
#                sets ZKCONF_SASL=1 for the cases (sasl_glue). Use the
#                sasl or full libraries of both cores with it
#   --tls DIR    give each server a secureClientPort (its port + 6) with
#                the Netty factory and the keystores of DIR, the output of
#                ssl/gencerts.sh. ZKCONF_TLS_CLIENT_AUTH sets ssl.clientAuth
#                (default want). The cases get ZKCONF_TLS_HOSTS and
#                ZKCONF_TLS_DIR. The dead addresses move to BASE+12 and
#                BASE+13, so a run uses 14 ports. Use the ssl or full
#                libraries of both cores with it
#   CASE         case names (default: every cases/*.c and cases/*.cc)
#
# Flavors of a case: a line "zkconf-flavors: mt st" in the source names
# the flavors that the case supports. The default is mt only. A line
# "zkconf-skip-st: REASON" gives the reason of an st skip. The runner
# skips a case that does not support the flavor, and the summary shows
# the reason. A skip does not fail the run.
#
# A line "zkconf-preload: connect" inserts lib/zkconf_preload.c, which
# interposes connect(2) in both cores (DYLD_INSERT_LIBRARIES). A line
# "zkconf-preload: sasl" inserts lib/zkconf_sasl_preload.c, which records
# the Cyrus and socket call order. It builds against the Cyrus library of
# ZKCONF_SASL_PREFIX (default: the Homebrew cyrus-sasl prefix).
#
# A case in C++ (cases/NAME.cc) tests exceptions from callbacks (TH-10..13).
# It compiles with -fexceptions. The recorder stays C in both languages.
#
# Comparison modes:
#   EXACT     the normalized traces are equal
#   PER-ROLE  the subsequence of each role is equal
#   DEV       no trace comparison; each core asserts its own behavior
# A SET scenario puts the outcome set into the trace, so it uses EXACT.
# Log modes: ordered (INFO and above in order per role, DEBUG as a
# multiset), set (all lines as a multiset), uniq (the distinct INFO and
# above lines, for scenarios with a timing-dependent retry count) and
# ignore.
# Every run must exit 0: no harness failure and no failed DEV check.
# A known failure (KNOWN XFAIL in the .dev file) does not fail the case.
# The summary shows the count as xfail-CORE=N.

set -uo pipefail

# The script uses three roots. RCDIR is the Rust C tree. RDIR is the Rust
# workspace. CDIR is the legacy C tree, and ZK_C_DIR overrides it.
HERE="$(cd "$(dirname "$0")" && pwd)"
RCDIR="$(cd "$HERE/../.." && pwd)"
RDIR="$(cd "$RCDIR/.." && pwd)"
CDIR="$(cd "${ZK_C_DIR:-$RDIR/../zookeeper-client-c}" && pwd)"
# ZKCONF_SERVER names another server script, for example from a source copy.
SERVER="${ZKCONF_SERVER:-$RDIR/dev/test-server.sh}"
LEGACY=/tmp/zk-legacy-ref/install-plain/lib
RUST=""
OUT=""
FL=mt
BASE=22750
REPS=1
SASL=0
TLS=""
CASES=()
CASE_TIMEOUT="${ZKCONF_CASE_TIMEOUT:-180}"

while [ $# -gt 0 ]; do
    case "$1" in
    --rust) RUST="$2"; shift 2 ;;
    --legacy) LEGACY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --flavor) FL="$2"; shift 2 ;;
    --port-base) BASE="$2"; shift 2 ;;
    --reps) REPS="$2"; shift 2 ;;
    --sasl) SASL=1; shift ;;
    --tls) TLS="$2"; shift 2 ;;
    -h|--help) sed -n '18,79p' "$0"; exit 0 ;;
    *) CASES+=("$1"); shift ;;
    esac
done

if [ -z "$RUST" ]; then
    echo "run.sh: --rust LIBDIR is required" >&2
    exit 2
fi
case "$FL" in
mt) OUT="${OUT:-/tmp/zkconf}" ;;
st) OUT="${OUT:-/tmp/zkconf-st}" ;;
*) echo "run.sh: --flavor must be mt or st" >&2; exit 2 ;;
esac
for d in "$LEGACY" "$RUST"; do
    if [ ! -f "$d/libzookeeper_$FL.2.dylib" ]; then
        echo "run.sh: no libzookeeper_$FL.2.dylib in $d" >&2
        exit 2
    fi
done
LEGACY="$(cd "$LEGACY" && pwd)"
RUST="$(cd "$RUST" && pwd)"
mkdir -p "$OUT/bin"
OUT="$(cd "$OUT" && pwd)"

# The SASL servers: the JAAS file and the SASL provider go to every server
# start through the JVM options of the server script. The server checks
# DIGEST-MD5 only with the FIPS mode off.
if [ "$SASL" = 1 ]; then
    cat >"$OUT/jaas.conf" <<'JAAS'
Server {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    user_myuser="mypassword";
};
JAAS
    ZK_TEST_SERVER_JVM_OPTS="${ZK_TEST_SERVER_JVM_OPTS:-} \
-Djava.security.auth.login.config=$OUT/jaas.conf \
-Dzookeeper.authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider \
-Dzookeeper.fips-mode=false"
    export ZK_TEST_SERVER_JVM_OPTS
    export ZKCONF_SASL=1
fi

# The TLS servers: Netty and a secure port with the gencerts.sh
# keystores. The server needs the Netty factory for TLS.
if [ -n "$TLS" ]; then
    if [ ! -f "$TLS/server.jks" ] || [ ! -f "$TLS/servertrust.jks" ]; then
        echo "run.sh: --tls $TLS has no server.jks and servertrust.jks" >&2
        exit 2
    fi
    TLS="$(cd "$TLS" && pwd)"
    export ZKCONF_TLS_DIR="$TLS"
fi
# The extra zoo.cfg lines of the server on the client port $1. The lines
# of the caller's ZK_TEST_SERVER_PROPS come first.
server_props() {
    [ -z "${ZK_TEST_SERVER_PROPS:-}" ] || printf '%s\n' "$ZK_TEST_SERVER_PROPS"
    [ -n "$TLS" ] || return 0
    printf '%s\n' "secureClientPort=$(($1 + 6))" \
        "serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory" \
        "ssl.clientAuth=${ZKCONF_TLS_CLIENT_AUTH:-want}" \
        "ssl.keyStore.location=$TLS/server.jks" "ssl.keyStore.password=password" \
        "ssl.trustStore.location=$TLS/servertrust.jks" "ssl.trustStore.password=password"
}

if [ ${#CASES[@]} -eq 0 ]; then
    for f in "$HERE"/cases/*.c "$HERE"/cases/*.cc; do
        [ -f "$f" ] || continue
        f="$(basename "$f")"
        CASES+=("${f%.*}")
    done
fi

# Ports: the legacy run uses BASE..BASE+2, the Rust run BASE+3..BASE+5.
# BASE+10 and BASE+11 are dead addresses (no server listens there).
# ZKCONF_DEAD_OFFSET moves the dead addresses, so that a run fits in a
# range of ten ports (for example 6 gives BASE+6 and BASE+7).
if [ -n "$TLS" ]; then DEAD_OFF="${ZKCONF_DEAD_OFFSET:-12}"; else
    DEAD_OFF="${ZKCONF_DEAD_OFFSET:-10}"; fi
ports_for() {
    if [ "$1" = c ]; then echo "$BASE $((BASE + 1)) $((BASE + 2))"; else
        echo "$((BASE + 3)) $((BASE + 4)) $((BASE + 5))"; fi
}
dead_for() {
    if [ "$1" = c ]; then echo $((BASE + DEAD_OFF)); else echo $((BASE + DEAD_OFF + 1)); fi
}

STARTED=()
stop_all() {
    local entry
    for entry in "${STARTED[@]+"${STARTED[@]}"}"; do
        "$SERVER" stop "${entry%%@*}" "${entry#*@}" >/dev/null 2>&1 || true
    done
    STARTED=()
}
trap stop_all EXIT INT TERM

# The source of a case is NAME.c or NAME.cc.
case_src() {
    if [ -f "$HERE/cases/$1.cc" ]; then echo "$HERE/cases/$1.cc"; else
        echo "$HERE/cases/$1.c"; fi
}
# The flavors of a case come from its "zkconf-flavors:" line (default mt).
case_flavors() {
    local line
    line="$(grep -m1 'zkconf-flavors:' "$(case_src "$1")" 2>/dev/null)"
    if [ -z "$line" ]; then echo mt; else echo "${line#*zkconf-flavors:}"; fi
}
skip_reason() {
    local line
    if [ "$FL" = st ]; then
        line="$(grep -m1 'zkconf-skip-st:' "$(case_src "$1")" 2>/dev/null)"
        if [ -n "$line" ]; then
            echo "${line#*zkconf-skip-st: }" | sed -E 's/ *\*\/$//'
        else
            echo "the case uses the mt-only sync API or library threads"
        fi
    else
        echo "an st-only case"
    fi
}
RUN_CASES=()
SKIPPED=()
for c in "${CASES[@]}"; do
    if [ ! -f "$(case_src "$c")" ]; then
        echo "run.sh: no case $c" >&2
        exit 2
    fi
    if [[ " $(case_flavors "$c") " == *" $FL "* ]]; then
        RUN_CASES+=("$c")
    else
        SKIPPED+=("$c")
    fi
done

# The TLS fixtures of zk-driver are not in git. The zk-fixtures bin of
# zk-testkit makes them on the first use. It prints their cache directory.
# ZK_TEST_OPENSSL selects the OpenSSL 3 tool for the build (default:
# OPENSSL, then Homebrew openssl@3). ZK_TEST_TLS_FIXTURES names a ready
# directory, and then cargo does not run.
if [ -n "${ZK_TEST_TLS_FIXTURES:-}" ]; then
    FIX="$ZK_TEST_TLS_FIXTURES"
elif command -v cargo >/dev/null 2>&1; then
    FIX="$(cd "$RDIR" && \
        ZK_TEST_OPENSSL="${ZK_TEST_OPENSSL:-${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}}" \
        cargo run -q --locked --offline -p zk-testkit --bin zk-fixtures -- tls)" || {
        echo "run.sh: zk-fixtures did not make the TLS fixtures (see above)" >&2
        exit 2
    }
else
    echo "run.sh: the TLS fixtures need cargo; install it or set ZK_TEST_TLS_FIXTURES=DIR" >&2
    exit 2
fi
if [ ! -f "$FIX/ca.pem" ]; then
    echo "run.sh: the TLS fixture directory $FIX has no ca.pem" >&2
    exit 2
fi
# The case binaries get the path as a C string, so it must be absolute.
FIX="$(cd "$FIX" && pwd)"

# 1. Compile every case once against the original headers.
# Only mt defines THREADED. The cases link pthread in both flavors,
# because the recorder and the proxy are test threads. The runner gives
# the cases their directories as macros. ZKCONF_C_DIR is the legacy C
# tree. ZKCONF_TLS_FIX is the TLS fixture directory of zk-driver.
CFLAGS=(-std=c99 -Wall -Wextra -Werror -g -O1 -D_GNU_SOURCE
    -I"$CDIR/include" -I"$CDIR/generated" -I"$HERE/lib"
    "-DZKCONF_C_DIR=\"$CDIR\""
    "-DZKCONF_TLS_FIX=\"$FIX\"")
if [ "$FL" = mt ]; then
    CFLAGS+=(-DTHREADED)
fi
LIBOBJS=("$OUT/bin/zkconf.o" "$OUT/bin/zkconf_sync.o" "$OUT/bin/zkconf_tls.o")
PRELOAD="$OUT/bin/libzkconf_preload.dylib"
if ! cc -std=c99 -Wall -Wextra -Werror -g -O1 -dynamiclib -I"$HERE/lib" \
    "$HERE/lib/zkconf_preload.c" -o "$PRELOAD"; then
    echo "run.sh: build of lib/zkconf_preload.c failed" >&2
    exit 2
fi
# The SASL preload links the Cyrus library that both SASL cores use.
SASL_PRELOAD="$OUT/bin/libzkconf_sasl_preload.dylib"
SASL_PREFIX="${ZKCONF_SASL_PREFIX:-/opt/homebrew/opt/cyrus-sasl}"
for c in "${RUN_CASES[@]+"${RUN_CASES[@]}"}"; do
    if grep -q 'zkconf-preload: sasl' "$(case_src "$c")"; then
        if ! cc -std=c99 -Wall -Wextra -Werror -g -O1 -dynamiclib -I"$HERE/lib" \
            -I"$SASL_PREFIX/include" "$HERE/lib/zkconf_sasl_preload.c" \
            -L"$SASL_PREFIX/lib" -lsasl2 -o "$SASL_PRELOAD"; then
            echo "run.sh: build of lib/zkconf_sasl_preload.c failed" >&2
            exit 2
        fi
        break
    fi
done
for f in zkconf zkconf_sync zkconf_tls; do
    if ! cc "${CFLAGS[@]}" -c "$HERE/lib/$f.c" -o "$OUT/bin/$f.o"; then
        echo "run.sh: compile of lib/$f.c failed" >&2
        exit 2
    fi
done
CXXFLAGS=(-std=c++11 -fexceptions -Wall -Wextra -Werror -g -O1
    "${CFLAGS[@]:6}")
for c in "${RUN_CASES[@]+"${RUN_CASES[@]}"}"; do
    src="$(case_src "$c")"
    if [ "${src##*.}" = cc ]; then
        c++ "${CXXFLAGS[@]}" "$src" "${LIBOBJS[@]}" \
            -L"$LEGACY" -lzookeeper_"$FL" -lpthread -o "$OUT/bin/$c"
    else
        cc "${CFLAGS[@]}" "$src" "${LIBOBJS[@]}" \
            -L"$LEGACY" -lzookeeper_"$FL" -lpthread -o "$OUT/bin/$c"
    fi || {
        echo "run.sh: compile of $c failed" >&2
        exit 2
    }
done

# 2. One run of one case on one core. The servers are fresh per run.
run_one() {
    local c="$1" core="$2" rep="$3" nserv="$4"
    local libdir dir ports dead i p hosts tlshosts portmap rc pid preload
    if [ "$core" = c ]; then libdir="$LEGACY"; else libdir="$RUST"; fi
    dir="$OUT/$c/$core.$rep"
    rm -rf "$dir"
    mkdir -p "$dir"
    read -r -a ports <<<"$(ports_for "$core")"
    dead="$(dead_for "$core")"
    hosts=""
    tlshosts=""
    portmap="$dead=PD"
    for i in 0 1 2; do
        p="${ports[$i]}"
        portmap="$portmap,$p=P$((i + 1))"
        hosts="${hosts:+$hosts,}127.0.0.1:$p"
        if [ -n "$TLS" ]; then
            portmap="$portmap,$((p + 6))=T$((i + 1))"
            tlshosts="${tlshosts:+$tlshosts,}127.0.0.1:$((p + 6))"
        fi
    done
    {
        echo '#!/bin/sh'
        echo "case \"\$2\" in 0) P=${ports[0]};; 1) P=${ports[1]};; 2) P=${ports[2]};; *) exit 2;; esac"
        echo "ZK_TEST_SERVER_PROPS=\"\$(cat '$dir/props'\"\$2\")\""
        echo "export ZK_TEST_SERVER_PROPS"
        echo "exec '$SERVER' \"\$1\" \"\$P\" '$dir/srv'\"\$2\""
    } >"$dir/ctl.sh"
    chmod +x "$dir/ctl.sh"
    for i in 0 1 2; do
        server_props "${ports[$i]}" >"$dir/props$i"
    done
    preload=""
    if grep -q 'zkconf-preload: connect' "$(case_src "$c")"; then
        preload="$PRELOAD"
    elif grep -q 'zkconf-preload: sasl' "$(case_src "$c")"; then
        preload="$SASL_PRELOAD"
    fi
    for ((i = 0; i < nserv; i++)); do
        ZK_TEST_SERVER_PROPS="$(cat "$dir/props$i")" "$SERVER" start "${ports[$i]}" "$dir/srv$i" >"$dir/server$i.start" 2>&1 || {
            echo "run.sh: server start failed: $c $core port ${ports[$i]}" >&2
            return 1
        }
    done
    env DYLD_LIBRARY_PATH="$libdir" ZKCONF_LIBDIR="$libdir" ZKCONF_CORE="$core" \
        ZKCONF_OUT="$dir/out" ZKCONF_HOSTS="$hosts" ZKCONF_DEAD="127.0.0.1:$dead" \
        ZKCONF_PORTS="$portmap" ZKCONF_CTL="$dir/ctl.sh" TZ=UTC LC_ALL=C \
        ZKCONF_TLS_HOSTS="$tlshosts" ${preload:+DYLD_INSERT_LIBRARIES="$preload"} \
        "$OUT/bin/$c" >"$dir/stdout" 2>"$dir/stderr" &
    pid=$!
    # The watchdog keeps no pipe open, and its TERM handler stops its sleep.
    (
        exec >/dev/null 2>&1
        sleep "$CASE_TIMEOUT" &
        s=$!
        trap 'kill "$s"; exit 0' TERM
        wait "$s"
        kill -9 "$pid"
    ) &
    local watchdog=$!
    wait "$pid"
    rc=$?
    kill "$watchdog" 2>/dev/null
    wait "$watchdog" 2>/dev/null
    echo "$rc" >"$dir/exit"
    for ((i = 0; i < 3; i++)); do
        "$SERVER" stop "${ports[$i]}" "$dir/srv$i" >/dev/null 2>&1 || true
    done
    return 0
}

# Trace and log views for each comparison mode.
view_trace() {
    local mode="$1" f="$2"
    if [ ! -f "$f" ]; then echo "<missing>"; return; fi
    if [ "$mode" = PER-ROLE ]; then
        grep -v '^#' "$f" | sort -s -k1,1
    else
        grep -v '^#' "$f"
    fi
}
# The overshoot of a receive timeout and the lateness of an st interest
# call are timing values, so the view hides them.
log_norm() {
    sed -E -e 's/exceeded timeout by -?[0-9]+ms/exceeded timeout by Nms/' \
        -e 's/Exceeded deadline by -?[0-9]+ms/Exceeded deadline by Nms/' "$1"
}
view_log() {
    local mode="$1" f="$2"
    if [ ! -f "$f" ]; then echo "<missing>"; return; fi
    case "$mode" in
    ordered)
        log_norm "$f" | grep -v ' ZOO_DEBUG@' | sort -s -k1,1
        echo "--- debug multiset"
        log_norm "$f" | grep ' ZOO_DEBUG@' | sed -E 's/xid=-?[0-9a-fx]+/xid=X/g' | sort
        ;;
    set) log_norm "$f" | sort ;;
    uniq) log_norm "$f" | grep -v ' ZOO_DEBUG@' | sort -u ;;
    *) : ;;
    esac
}

# 3. Run and compare.
FAILED=0
SUMMARY="$OUT/summary.txt"
: >"$SUMMARY"
echo "run.sh: flavor $FL" | tee -a "$SUMMARY"
for c in "${SKIPPED[@]+"${SKIPPED[@]}"}"; do
    printf '%-24s %-8s %-8s SKIP (%s)\n' "$c" - - "$(skip_reason "$c")" | tee -a "$SUMMARY"
done
for c in "${RUN_CASES[@]+"${RUN_CASES[@]}"}"; do
    desc="$("$OUT/bin/$c" --describe)"
    nserv="$(sed -E 's/.*servers=([0-9]+).*/\1/' <<<"$desc")"
    mode="$(sed -E 's/.*mode=([A-Z-]+).*/\1/' <<<"$desc")"
    lmode="$(sed -E 's/.*log=([a-z]+).*/\1/' <<<"$desc")"
    verdict=PASS
    notes=""
    for ((r = 1; r <= REPS; r++)); do
        run_one "$c" c "$r" "$nserv" &
        p1=$!
        run_one "$c" rust "$r" "$nserv" &
        p2=$!
        wait $p1 || { verdict=FAIL; notes="$notes server-c"; }
        wait $p2 || { verdict=FAIL; notes="$notes server-rust"; }
        for core in c rust; do
            ex="$(cat "$OUT/$c/$core.$r/exit" 2>/dev/null || echo none)"
            if [ "$ex" != 0 ]; then
                verdict=FAIL
                notes="$notes exit-$core=$ex"
            fi
            # A known failure does not fail the case, but the summary shows it.
            xf="$(grep -c '^KNOWN .* XFAIL:' "$OUT/$c/$core.$r/out.dev" 2>/dev/null)"
            if [ "${xf:-0}" -gt 0 ]; then
                notes="$notes xfail-$core=$xf"
            fi
        done
        if [ "$mode" != DEV ]; then
            if ! diff -u <(view_trace "$mode" "$OUT/$c/c.$r/out.trace") \
                <(view_trace "$mode" "$OUT/$c/rust.$r/out.trace") \
                >"$OUT/$c/trace.$r.diff"; then
                verdict=FAIL
                notes="$notes trace"
            fi
        fi
        if [ "$lmode" != ignore ]; then
            if ! diff -u <(view_log "$lmode" "$OUT/$c/c.$r/out.log") \
                <(view_log "$lmode" "$OUT/$c/rust.$r/out.log") \
                >"$OUT/$c/log.$r.diff"; then
                verdict=FAIL
                notes="$notes log"
            fi
        fi
    done
    printf '%-24s %-8s %-8s %s%s\n' "$c" "$mode" "$lmode" "$verdict" "$notes" | tee -a "$SUMMARY"
    if [ "$verdict" != PASS ]; then
        FAILED=$((FAILED + 1))
    fi
done
echo "run.sh: $FAILED failed; results in $OUT" | tee -a "$SUMMARY"
[ "$FAILED" -eq 0 ]
