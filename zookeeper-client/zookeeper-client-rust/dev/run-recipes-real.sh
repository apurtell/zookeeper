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

# Runs the real-server tests of zk-recipes against each server version. The
# default versions are the server of this source tree (HEAD) and the 3.9.6
# release. The TreeCache test against 3.5.10 runs in each pass. It selects
# that release itself, because that server has no persistent watches and
# the test expects the start to fail. A developer or a CI-style job runs
# this script. No test calls it.
#
# Usage: run-recipes-real.sh [VERSION ...]
#   VERSION is "head" or a release version. The default is "head 3.9.6".
#
# Platforms: macOS and Linux, with bash.
#
# Prerequisites: cargo, a JDK, nc (for test-server.sh and
# test-ensemble.sh), and curl for a missing release.
#
# The tests use the ports ZK_TEST_PORT_BASE to ZK_TEST_PORT_BASE+9 (default
# 23400). Build the HEAD server first with:
#   mvn -DskipTests install -pl zookeeper-server -am
# ZK_TEST_SOURCE_ROOT selects another source tree for the HEAD server.
# The script downloads a missing release with get-release-server.sh.
# Extra cargo arguments come from ZK_RECIPES_CARGO_ARGS.
#
# The runner sets ZK_TEST_REQUIRE_SERVER=1 when it is not set. Then a test
# that cannot start its server fails and does not skip, so a pass means that
# every server ran.
# Each scenario runs on a standalone server and on the three-node ensemble.
# ZK_RECIPES_REPEAT (default 1) runs each pass that many times, to find
# flaky tests.
# Each pass runs to its end. The script exits with an error when one pass
# fails.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$HERE/.." && pwd)"
ROOT="${ZK_TEST_SOURCE_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export ZK_TEST_PORT_BASE="${ZK_TEST_PORT_BASE:-23400}"
export ZK_TEST_REQUIRE_SERVER="${ZK_TEST_REQUIRE_SERVER:-1}"
REPEAT="${ZK_RECIPES_REPEAT:-1}"
case "$REPEAT" in
'' | *[!0-9]* | 0)
    echo "ZK_RECIPES_REPEAT must be a positive number: $REPEAT" >&2
    exit 2
    ;;
esac
if [ "$#" -eq 0 ]; then
    set -- head 3.9.6
fi

"$HERE/get-release-server.sh" 3.5.10
for v in "$@"; do
    if [ "$v" = head ]; then
        if [ ! -d "$ROOT/zookeeper-server/target/classes" ] || [ ! -d "$ROOT/zookeeper-server/target/lib" ]; then
            echo "no HEAD server in $ROOT; run mvn -DskipTests install -pl zookeeper-server -am" >&2
            exit 1
        fi
    else
        "$HERE/get-release-server.sh" "$v"
    fi
done

TESTS=(--test real_infra --test lock_real --test latch_real --test tree_cache_real)
FAILED=()
# ZK_RECIPES_CARGO_ARGS holds several words, so it stays unquoted.
# shellcheck disable=SC2086
for v in "$@"; do
    for run in $(seq 1 "$REPEAT"); do
        echo "== zk-recipes real-server tests against $v, run $run of $REPEAT (ports $ZK_TEST_PORT_BASE+)"
        if [ "$v" = head ]; then
            if ! (cd "$WORKSPACE" && env -u ZK_TEST_SERVER_VERSION -u ZK_TEST_SERVER_HOME \
                cargo test --locked -p apache-zookeeper-recipes ${ZK_RECIPES_CARGO_ARGS:-} \
                "${TESTS[@]}" -- --ignored); then
                FAILED+=("$v#$run")
            fi
        else
            if ! (cd "$WORKSPACE" && env -u ZK_TEST_SERVER_HOME ZK_TEST_SERVER_VERSION="$v" \
                cargo test --locked -p apache-zookeeper-recipes ${ZK_RECIPES_CARGO_ARGS:-} \
                "${TESTS[@]}" -- --ignored); then
                FAILED+=("$v#$run")
            fi
        fi
    done
done

if [ "${#FAILED[@]}" -ne 0 ]; then
    echo "== zk-recipes real-server tests failed against: ${FAILED[*]}" >&2
    exit 1
fi
echo "== zk-recipes real-server tests passed against: $* ($REPEAT runs each)"
