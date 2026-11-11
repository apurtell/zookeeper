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

# The server script of the public-API suites zktest-public-mt and
# zktest-public-st.
# It has the command interface of the legacy zookeeper-client-c/tests/zkServer.sh.
# It starts the server through zookeeper-client-rust/dev/test-server.sh.
#
# The differences from tests/zkServer.sh:
# - It stops only the server that it started. It does not kill the process
#   that has /tmp/zk.pid or that listens on the port.
# - All state is in ZKTEST_SERVER_DIR, not in /tmp.
# - The secure port is ZKTEST_SSL_PORT, and the certificates are in
#   ZKTEST_CERT_DIR. The script makes the certificates only when the
#   directory has no server.jks, so a run can bring its own set.
# - It waits until the server answers, also in the read-only and SASL modes.
#
# Usage: zkServer.sh startClean|start|startCleanReadOnly|stop [HOST:PORT]
#        zkServer.sh startRequireSASLAuth [JAAS_CONF] [READ_ONLY]
# The HOST:PORT argument is ignored, as in tests/zkServer.sh.
#
# Environment:
#   ZOOPORT              the client port (default 22181)
#   ZKMAXCNXNS           maxClientCnxns (default 100)
#   EXTRA_JVM_ARGS       more JVM arguments
#   ZKTEST_SERVER_DIR    the state directory (default ${TMPDIR:-/tmp}/zktest-public-$ZOOPORT)
#   ZKTEST_RO_PORT_BASE  the first of the six quorum and election ports of the
#                        read-only ensemble (0 or unset: the legacy 22881 and 33881)
#   ZKTEST_SERVER_SCRIPT the test-server.sh script (default: in this source tree)
#   ZKTEST_SSL_PORT      the secure client port (0 or unset: no secure port)
#   ZKTEST_CERT_DIR      the gencerts.sh output: server.jks, servertrust.jks and
#                        the client files of testSSL* (default /tmp/certs)
#   CLIENT_AUTH          ssl.clientAuth: need, want or none (default need)
#
# testSSL needs a CA file whose leaf has no AKID. OpenSSL 3.2
# and later add an AKID, so on such a host make the set first with LibreSSL
# or OpenSSL 3.1 or earlier (zookeeper-client-c/ssl/gencerts.sh), in ZKTEST_CERT_DIR.

set -euo pipefail

# The script uses three roots. RCDIR is the Rust C tree. RDIR is the Rust
# workspace. CDIR is the legacy C tree, and ZK_C_DIR overrides it.
HERE="$(cd "$(dirname "$0")" && pwd)"
RCDIR="$(cd "$HERE/../.." && pwd)"
RDIR="$(cd "$RCDIR/.." && pwd)"
CDIR="$(cd "${ZK_C_DIR:-$RDIR/../zookeeper-client-c}" && pwd)"
SERVER_SCRIPT="${ZKTEST_SERVER_SCRIPT:-$RDIR/dev/test-server.sh}"
ZOOPORT="${ZOOPORT:-22181}"
ZKMAXCNXNS="${ZKMAXCNXNS:-100}"
SSL_PORT="${ZKTEST_SSL_PORT:-0}"
CERT_DIR="${ZKTEST_CERT_DIR:-/tmp/certs}"
CLIENT_AUTH="${CLIENT_AUTH:-need}"
DIR="${ZKTEST_SERVER_DIR:-${TMPDIR:-/tmp}/zktest-public-$ZOOPORT}"
LOG="$DIR/wrapper.log"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 startClean|start|startCleanReadOnly|startRequireSASLAuth [jaasConf] [readOnly]|stop" >&2
    exit 2
fi
mkdir -p "$DIR"

# The read-only ensemble has three members, and only member 1 runs. The
# legacy ports are 22881-22883 (quorum) and 33881-33883 (election).
if [[ ${ZKTEST_RO_PORT_BASE:-0} != 0 ]]; then
    RO_QUORUM=$ZKTEST_RO_PORT_BASE
    RO_ELECTION=$((ZKTEST_RO_PORT_BASE + 3))
else
    RO_QUORUM=22881
    RO_ELECTION=33881
fi

stop_server() {
    "$SERVER_SCRIPT" stop "$ZOOPORT" "$DIR" >>"$LOG" 2>&1
}

# The server properties of tests/zoo.cfg without the TLS keys. The session
# timeout limits are the defaults of tickTime=500 (2 and 20 ticks).
base_props() {
    printf '%s\n' "tickTime=500" "initLimit=10" "syncLimit=5" \
        "maxClientCnxns=$ZKMAXCNXNS" "localSessionsEnabled=true" \
        "minSessionTimeout=1000" "maxSessionTimeout=10000" \
        "serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory"
    if [[ $SSL_PORT != 0 ]]; then
        printf '%s\n' "secureClientPort=$SSL_PORT" "ssl.clientAuth=$CLIENT_AUTH" \
            "ssl.keyStore.location=$CERT_DIR/server.jks" "ssl.keyStore.password=password" \
            "ssl.trustStore.location=$CERT_DIR/servertrust.jks" "ssl.trustStore.password=password"
    fi
}

# Makes the gencerts.sh set in CERT_DIR when it has no server keystore, as
# tests/zkServer.sh does. A set that exists stays as it is. When the set
# cannot be made, the server starts without the secure port, so that only
# the TLS cases fail.
ensure_certs() {
    [[ $SSL_PORT != 0 ]] || return 0
    [[ -f $CERT_DIR/server.jks ]] && return 0
    mkdir -p "$CERT_DIR"
    cp "$CDIR/ssl/gencerts.sh" "$CERT_DIR/"
    if ! (cd "$CERT_DIR" && ./gencerts.sh tests.zookeeper.apache.org >gencerts.stdout 2>gencerts.stderr); then
        echo "zkServer.sh: gencerts.sh failed, so the server has no secure port; see $CERT_DIR/gencerts.stderr" >&2
        rm -f "$CERT_DIR/server.jks"
        SSL_PORT=0
    fi
}

read_only_props() {
    local i
    for i in 1 2 3; do
        echo "server.$i=localhost:$((RO_QUORUM + i - 1)):$((RO_ELECTION + i - 1))"
    done
}

# Polls a four-letter command until the reply contains the expected text.
# The wait is bounded: 150 polls of at most 0.2 s plus the nc timeout.
wait_4lw() {
    local cmd=$1 want=$2 n
    for n in $(seq 1 150); do
        if echo "$cmd" | nc -w 1 127.0.0.1 "$ZOOPORT" 2>/dev/null | grep -q "$want"; then
            return 0
        fi
        sleep 0.2
    done
    echo "zkServer.sh: no '$want' reply to '$cmd' on port $ZOOPORT; see $DIR" >&2
    return 1
}

start_server() {
    local props=$1 jvm=$2
    if nc -z 127.0.0.1 "$ZOOPORT" 2>/dev/null; then
        echo "zkServer.sh: another process listens on port $ZOOPORT" >&2
        return 1
    fi
    ZK_TEST_SERVER_PROPS="$props" ZK_TEST_SERVER_JVM_OPTS="$jvm" \
        "$SERVER_SCRIPT" start "$ZOOPORT" "$DIR" >>"$LOG" 2>&1 || {
        echo "zkServer.sh: the server did not start; see $DIR/server.out" >&2
        return 1
    }
    # The server script waits only for the plain port. The secure port
    # can open later, and a TLS case that comes first then fails.
    if [[ $SSL_PORT != 0 ]]; then
        local n
        for n in $(seq 1 100); do
            nc -z 127.0.0.1 "$SSL_PORT" 2>/dev/null && break
            sleep 0.1
        done
    fi
    echo -n " ZooKeeper server started"
}

# The JVM properties of tests/zkServer.sh.
JVM="${EXTRA_JVM_ARGS:-} -Dzookeeper.extendedTypesEnabled=true -Dznode.container.checkIntervalMs=100"

# Each command first stops the server of an earlier command, as in
# tests/zkServer.sh.
stop_server
if [[ $1 != stop ]]; then
    ensure_certs
fi

case $1 in
startClean | start)
    if [[ $1 == startClean ]]; then
        rm -rf "$DIR/data"
    fi
    start_server "$(base_props)" "$JVM"
    ;;
startCleanReadOnly)
    rm -rf "$DIR/data"
    mkdir -p "$DIR/data"
    echo 1 >"$DIR/data/myid"
    start_server "$(base_props; read_only_props)" "-Dreadonlymode.enabled=true $JVM"
    wait_4lw isro ro
    ;;
startRequireSASLAuth)
    sasl="-Dzookeeper.sessionRequireClientSASLAuth=true"
    sasl="$sasl -Dzookeeper.authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider"
    sasl="$sasl -Dzookeeper.fips-mode=false"
    if [[ -n ${2:-} ]]; then
        # The test gives a path relative to its working directory.
        jaas="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
        sasl="$sasl -Djava.security.auth.login.config=$jaas"
    fi
    if [[ -n ${3:-} ]]; then
        mkdir -p "$DIR/data"
        echo 1 >"$DIR/data/myid"
        start_server "$(base_props; read_only_props)" "-Dreadonlymode.enabled=true $sasl $JVM"
        wait_4lw isro ro
    else
        start_server "$(base_props)" "$sasl $JVM"
    fi
    ;;
stop) ;;
*)
    echo "Unknown command $1" >&2
    exit 2
    ;;
esac
