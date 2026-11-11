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

# Starts or stops a standalone ZooKeeper server from this source tree for the
# Rust integration tests. The zk-client, zk-ffi and zk-recipes real-server
# tests call it. The C test runners (c/tests/conformance/run.sh and the
# scripts in c/tests/public) also call it. Build the server first with:
#   mvn -DskipTests install -pl zookeeper-server -am
#
# Usage: test-server.sh start|stop [PORT] [DATADIR]
#   PORT     the client port (default 22181)
#   DATADIR  the server directory (default ${TMPDIR:-/tmp}/zk-rust-test-PORT)
# The start waits until the server serves requests. The stop waits until
# the server exits.
#
# Platforms: macOS and Linux, with bash.
#
# Prerequisites: a JDK (java on PATH) and nc.
#
# Extra server properties come from ZK_TEST_SERVER_PROPS (newline separated).
# Extra JVM options come from ZK_TEST_SERVER_JVM_OPTS.
#
# A release server replaces the server of this source tree when one of these
# is set (get-release-server.sh downloads a release):
#   ZK_TEST_SERVER_HOME     the directory of an extracted binary release
#   ZK_TEST_SERVER_VERSION  a version below ZK_TEST_SERVERS_DIR
#                           (default /tmp/zk-servers)
# ZK_TEST_SOURCE_ROOT selects the source tree of the HEAD server. The default
# is the tree that holds this script. A copy of the Rust workspace uses it.

set -euo pipefail
ROOT="${ZK_TEST_SOURCE_ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}"
CMD="${1:-start}"
PORT="${2:-22181}"
DIR="${3:-${TMPDIR:-/tmp}/zk-rust-test-$PORT}"
PIDFILE="$DIR/server.pid"

# Gives success when PID is a ZooKeeper server. A stale pid file can hold the
# pid of another process, and the stop must not kill that process.
is_zk_server() {
    local cmd
    cmd="$(ps -ww -p "$1" -o command= 2>/dev/null || true)"
    case "$cmd" in
    *org.apache.zookeeper.server.quorum.QuorumPeerMain*) return 0 ;;
    esac
    return 1
}

case "$CMD" in
start)
    mkdir -p "$DIR/data"
    {
        echo "tickTime=2000"
        echo "dataDir=$DIR/data"
        echo "clientPort=$PORT"
        echo "admin.enableServer=false"
        echo "4lw.commands.whitelist=*"
        echo "extendedTypesEnabled=true"
        echo "localSessionsEnabled=false"
        echo "maxSessionTimeout=60000"
        echo "minSessionTimeout=1000"
        echo "${ZK_TEST_SERVER_PROPS:-}"
    } > "$DIR/zoo.cfg"
    CP="$ROOT/zookeeper-server/target/classes:$ROOT/zookeeper-server/target/lib/*"
    # A release server uses the jars and the log configuration of its release.
    if [ -z "${ZK_TEST_SERVER_HOME:-}" ] && [ -n "${ZK_TEST_SERVER_VERSION:-}" ]; then
        ZK_TEST_SERVER_HOME="${ZK_TEST_SERVERS_DIR:-/tmp/zk-servers}/$ZK_TEST_SERVER_VERSION/apache-zookeeper-$ZK_TEST_SERVER_VERSION-bin"
    fi
    if [ -n "${ZK_TEST_SERVER_HOME:-}" ]; then
        if [ ! -d "$ZK_TEST_SERVER_HOME/lib" ]; then
            echo "No release server in $ZK_TEST_SERVER_HOME; run get-release-server.sh" >&2
            exit 1
        fi
        CP="$ZK_TEST_SERVER_HOME/lib/*:$ZK_TEST_SERVER_HOME/conf"
    fi
    # ZK_TEST_SERVER_JVM_OPTS can hold several options, so it stays unquoted.
    # shellcheck disable=SC2086
    nohup java -Dzookeeper.extendedTypesEnabled=true -Dzookeeper.log.dir="$DIR" \
        ${ZK_TEST_SERVER_JVM_OPTS:-} -cp "$CP" \
        org.apache.zookeeper.server.quorum.QuorumPeerMain "$DIR/zoo.cfg" \
        > "$DIR/server.out" 2>&1 &
    echo $! > "$PIDFILE"
    for _ in $(seq 1 100); do
        # A server that exits at once (for example on a busy port) fails the
        # start without the full wait.
        if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "ZooKeeper exited at start; see $DIR/server.out" >&2
            rm -f "$PIDFILE"
            exit 1
        fi
        # A server answers ruok before it serves requests, and it closes a
        # session that comes too early. Thus a standalone server must also
        # give the Mode line of srvr. A quorum member returns at ruok,
        # because its caller waits for the quorum or for read-only mode.
        if echo ruok | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null | grep -q imok &&
            { grep -q '^server\.' "$DIR/zoo.cfg" ||
              echo srvr | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null | grep -q '^Mode: '; }; then
            echo "ZooKeeper listening on 127.0.0.1:$PORT (pid $(cat "$PIDFILE"))"
            exit 0
        fi
        sleep 0.2
    done
    echo "ZooKeeper failed to start; see $DIR/server.out" >&2
    exit 1
    ;;
stop)
    # The stop waits until the server exits, so a restart on the same port
    # cannot reach the old server. After 10 s the stop kills the server.
    if [ -f "$PIDFILE" ]; then
        PID="$(cat "$PIDFILE")"
        if is_zk_server "$PID"; then
            kill "$PID" 2>/dev/null || true
            for _ in $(seq 1 50); do
                kill -0 "$PID" 2>/dev/null || break
                sleep 0.2
            done
            kill -9 "$PID" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
    fi
    ;;
*)
    echo "usage: $0 start|stop [PORT] [DATADIR]" >&2
    exit 2
    ;;
esac
