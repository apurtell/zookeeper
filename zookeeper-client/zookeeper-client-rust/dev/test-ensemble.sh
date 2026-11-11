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

# Starts or stops a three-node ZooKeeper ensemble on loopback for the Rust
# real-server tests. The zk-recipes and zk-client real-server tests call it,
# and so does run-curator-interop.sh.
#
# Platforms: macOS and Linux, with bash.
#
# Prerequisites: a JDK (java on PATH) and nc. The HEAD server needs a
# built source tree:
#   mvn -DskipTests install -pl zookeeper-server -am
#
# Usage:
#   test-ensemble.sh start BASE [DIR]       start nodes 1 to 3
#   test-ensemble.sh stop BASE [DIR]        stop every node
#   test-ensemble.sh stop-node BASE N [DIR]
#   test-ensemble.sh start-node BASE N [DIR]
#   test-ensemble.sh leader BASE            print the number of the leader
#
# Node N (1 to 3) uses the client port BASE+N-1, the quorum port BASE+N+2 and
# the election port BASE+N+5, so the ensemble uses BASE to BASE+8. Each node
# has its own directory DIR/nodeN. The server comes from this source tree, or
# from a release with ZK_TEST_SERVER_HOME or ZK_TEST_SERVER_VERSION, as in
# test-server.sh. Extra server properties come from ZK_TEST_SERVER_PROPS.
# ZK_TEST_SOURCE_ROOT selects the source tree of the HEAD server, as in
# test-server.sh. Extra JVM options come from ZK_TEST_SERVER_JVM_OPTS.
# The default DIR is ${TMPDIR:-/tmp}/zk-rust-ensemble-BASE.

set -euo pipefail
ROOT="${ZK_TEST_SOURCE_ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}"
CMD="${1:?usage: $0 start|stop|stop-node|start-node|leader BASE ...}"
BASE="${2:?BASE port missing}"
case "$CMD" in
stop-node | start-node)
    NODE="${3:?node number missing}"
    DIR="${4:-${TMPDIR:-/tmp}/zk-rust-ensemble-$BASE}"
    ;;
*)
    DIR="${3:-${TMPDIR:-/tmp}/zk-rust-ensemble-$BASE}"
    ;;
esac

client_port() { echo $((BASE + $1 - 1)); }

classpath() {
    local home="${ZK_TEST_SERVER_HOME:-}"
    if [ -z "$home" ] && [ -n "${ZK_TEST_SERVER_VERSION:-}" ]; then
        home="${ZK_TEST_SERVERS_DIR:-/tmp/zk-servers}/$ZK_TEST_SERVER_VERSION/apache-zookeeper-$ZK_TEST_SERVER_VERSION-bin"
    fi
    if [ -n "$home" ]; then
        if [ ! -d "$home/lib" ]; then
            echo "No release server in $home; run get-release-server.sh" >&2
            return 1
        fi
        echo "$home/lib/*:$home/conf"
    else
        echo "$ROOT/zookeeper-server/target/classes:$ROOT/zookeeper-server/target/lib/*"
    fi
}

# The Mode line of the srvr command: leader, follower, or nothing.
mode() {
    echo srvr | nc -w 1 127.0.0.1 "$(client_port "$1")" 2>/dev/null |
        sed -n 's/^Mode: //p' | tr -d '\r'
}

write_config() {
    local n="$1" d="$DIR/node$1"
    mkdir -p "$d/data"
    echo "$n" > "$d/data/myid"
    {
        echo "tickTime=500"
        echo "initLimit=20"
        echo "syncLimit=10"
        echo "dataDir=$d/data"
        echo "clientPort=$(client_port "$n")"
        echo "clientPortAddress=127.0.0.1"
        echo "admin.enableServer=false"
        echo "4lw.commands.whitelist=*"
        echo "extendedTypesEnabled=true"
        echo "localSessionsEnabled=false"
        echo "standaloneEnabled=false"
        echo "reconfigEnabled=false"
        echo "maxSessionTimeout=60000"
        echo "minSessionTimeout=1000"
        for m in 1 2 3; do
            echo "server.$m=127.0.0.1:$((BASE + m + 2)):$((BASE + m + 5))"
        done
        echo "${ZK_TEST_SERVER_PROPS:-}"
    } > "$d/zoo.cfg"
}

start_node() {
    local n="$1" d="$DIR/node$1" cp
    cp="$(classpath)"
    [ -f "$d/zoo.cfg" ] || write_config "$n"
    # ZK_TEST_SERVER_JVM_OPTS can hold several options, so it stays unquoted.
    # shellcheck disable=SC2086
    nohup java -Dzookeeper.extendedTypesEnabled=true -Dzookeeper.log.dir="$d" \
        ${ZK_TEST_SERVER_JVM_OPTS:-} -cp "$cp" \
        org.apache.zookeeper.server.quorum.QuorumPeerMain "$d/zoo.cfg" \
        > "$d/server.out" 2>&1 &
    echo $! > "$d/server.pid"
}

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

# Stops one node and waits until it exits. After 10 s it kills the node.
stop_node() {
    local pidfile="$DIR/node$1/server.pid" pid
    [ -f "$pidfile" ] || return 0
    pid="$(cat "$pidfile")"
    if is_zk_server "$pid"; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
}

# Waits until node N serves as a leader or a follower.
# A node that exits fails the wait at once.
wait_serving() {
    local pidfile="$DIR/node$1/server.pid"
    for _ in $(seq 1 150); do
        if ! kill -0 "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null; then
            echo "node $1 exited; see $DIR/node$1/server.out" >&2
            return 1
        fi
        case "$(mode "$1")" in
        leader | follower) return 0 ;;
        esac
        sleep 0.2
    done
    echo "node $1 did not join; see $DIR/node$1/server.out" >&2
    return 1
}

case "$CMD" in
start)
    for n in 1 2 3; do write_config "$n"; done
    for n in 1 2 3; do start_node "$n"; done
    for n in 1 2 3; do
        if ! wait_serving "$n"; then
            for m in 1 2 3; do stop_node "$m"; done
            exit 1
        fi
    done
    echo "ZooKeeper ensemble on 127.0.0.1:$(client_port 1)-$(client_port 3)"
    ;;
stop)
    for n in 1 2 3; do stop_node "$n"; done
    ;;
start-node)
    start_node "$NODE"
    wait_serving "$NODE"
    ;;
stop-node)
    stop_node "$NODE"
    ;;
leader)
    for n in 1 2 3; do
        if [ "$(mode "$n")" = leader ]; then
            echo "$n"
            exit 0
        fi
    done
    exit 1
    ;;
*)
    echo "usage: $0 start|stop|stop-node|start-node|leader BASE ..." >&2
    exit 2
    ;;
esac
