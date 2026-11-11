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

# Runs a public-API suite, zktest-public-mt or zktest-public-st,
# against one client library. The suite is built once. --libdir
# selects the core at run time through the dynamic loader path, so the
# same binary runs against the legacy core and against the Rust core.
#
# Usage: run-public.sh [--libdir DIR] [--workdir DIR] BINARY [TEST_NAME]
#
# The port variables must have the values that the binary was built with:
#   ZKTEST_PORT, ZKTEST_QUORUM_PORT_BASE and ZKTEST_RO_PORT_BASE. For the two
#   base variables, 0 or unset means the legacy ports.
#
# ZKTEST_REPO is the ZooKeeper source tree with the built server (default:
# the tree of this script). Set it when this directory is a copy.
#
# The script stops every server that the run started, also on failure.

set -euo pipefail

# RCDIR is the Rust C tree. RDIR is the Rust workspace. The script uses no
# file of the legacy C tree.
HERE="$(cd "$(dirname "$0")" && pwd)"
RCDIR="$(cd "$HERE/../.." && pwd)"
RDIR="$(cd "$RCDIR/.." && pwd)"
REPO="$(cd "${ZKTEST_REPO:-$RDIR/../..}" && pwd)"
export ZKTEST_SERVER_SCRIPT="${ZKTEST_SERVER_SCRIPT:-$REPO/zookeeper-client/zookeeper-client-rust/dev/test-server.sh}"
LIBDIR=
WORK=

while [[ $# -gt 0 ]]; do
    case $1 in
    --libdir) LIBDIR=$2; shift 2 ;;
    --workdir) WORK=$2; shift 2 ;;
    --) shift; break ;;
    -*) echo "run-public.sh: unknown option $1" >&2; exit 2 ;;
    *) break ;;
    esac
done
if [[ $# -lt 1 ]]; then
    echo "usage: $0 [--libdir DIR] [--workdir DIR] BINARY [TEST_NAME]" >&2
    exit 2
fi
BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
shift

export ZOOPORT="${ZKTEST_PORT:-22181}"
WORK="${WORK:-${TMPDIR:-/tmp}/zktest-public-run-$ZOOPORT}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
export ZKTEST_SERVER_DIR="$WORK/server"
if [[ ${ZKTEST_RO_PORT_BASE:-0} != 0 ]]; then
    export ZKTEST_RO_PORT_BASE
fi

# TestReconfigServer runs $ZKROOT/bin/zkServer.sh and writes its quorum
# state below $ZKROOT/build. A private root keeps that state out of the
# source tree. Its own conf directory turns off the admin server, so that
# the three members do not need port 8080.
ROOT="$WORK/zkroot"
mkdir -p "$ROOT/conf"
ln -sfn "$REPO/bin" "$ROOT/bin"
ln -sfn "$REPO/zookeeper-server" "$ROOT/zookeeper-server"
cp "$REPO/conf/logback.xml" "$ROOT/conf/logback.xml"
# The test sets SERVER_JVMFLAGS for the quorum, so java.env adds to it.
echo 'SERVER_JVMFLAGS="${SERVER_JVMFLAGS:-} -Dzookeeper.admin.enableServer=false"' >"$ROOT/conf/java.env"
export ZKROOT="$ROOT"
export ZOOCFGDIR="$ROOT/conf"

cleanup() {
    "$HERE/zkServer.sh" stop >/dev/null 2>&1 || true
    local conf
    for conf in "$ROOT"/build/test/test-cppunit/conf/*.conf; do
        [[ -f $conf ]] || continue
        "$ROOT/bin/zkServer.sh" stop "$conf" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

if [[ -n $LIBDIR ]]; then
    LIBDIR="$(cd "$LIBDIR" && pwd)"
    export DYLD_LIBRARY_PATH="$LIBDIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

cd "$WORK"
echo "run-public.sh: $BIN${LIBDIR:+ with $LIBDIR}, port $ZOOPORT, work $WORK"
"$BIN" "$@"
