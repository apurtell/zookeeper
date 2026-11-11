#!/bin/sh
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

# This script makes the sources of the public-API suites zktest-public-mt
# and zktest-public-st from the legacy test sources. The
# legacy sources stay as they are. The copies differ in three ways:
# - They use the ports and the certificate directory of the build, so
#   that a run does not use the ports of other runs.
# - They do not register the cases of omit-cases.txt. These cases use the
#   internals of the legacy core.
# - With a quorum base above 0, TestReconfigServer uses nine ports from
#   that base: first the client ports, then the quorum ports, then the
#   election ports. Member i uses base + i.
# The default values give the legacy ports.
#
# Each output name selects the legacy file of the same name in TESTS_DIR.
# The copies of the .cc files sit in one directory with the copy of
# ZooKeeperQuorumServer.h, so their quoted includes find that copy first.
#
# Usage: gen-sources.sh TESTS_DIR PORT DOWN_PORT SSL_PORT CERT_DIR QUORUM_BASE OUTPUT...

set -eu

if [ $# -lt 7 ]; then
    echo "usage: $0 TESTS_DIR PORT DOWN_PORT SSL_PORT CERT_DIR QUORUM_BASE OUTPUT..." >&2
    exit 2
fi
tests=$1 port=$2 down=$3 ssl=$4 certs=$5 quorum=$6
shift 6
for v in "$port" "$down" "$ssl" "$quorum"; do
    case $v in
    '' | *[!0-9]*) echo "gen-sources.sh: $v is not a port number" >&2; exit 2 ;;
    esac
done
omit="$(dirname "$0")/omit-cases.txt"

# The sed script changes the ports and the certificate directory, and it
# removes the omitted cases. The certificate directory can hold characters
# that are special to sed, so each of them gets a backslash.
certs_esc=$(printf '%s\n' "$certs" | sed 's/[\\|&]/\\&/g')
script="s|:22181|:$port|g
s|:22182|:$down|g
s|:22281|:$ssl|g
s|/tmp/certs/|$certs_esc/|g"
cases=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$omit")
for c in $cases; do
    script="$script
/^[[:space:]]*CPPUNIT_TEST($c);/d"
done
if [ "$quorum" -gt 0 ]; then
    script="$script
s|CLIENT_PORT_BASE = 4000;|CLIENT_PORT_BASE = $quorum;|
s|SERVER_PORT_BASE = 2000;|SERVER_PORT_BASE = $((quorum + 3));|
s|ELECTION_PORT_BASE = 3000;|ELECTION_PORT_BASE = $((quorum + 6));|"
fi

# The checks make sure that each edit applies. A failed check means that a
# legacy source changed. Then this script must change too. Without the
# checks, the suite can silently use the legacy ports or cases.
found=
for out in "$@"; do
    in="$tests/$(basename "$out")"
    mkdir -p "$(dirname "$out")"
    sed -e "$script" "$in" >"$out.tmp"
    for c in $cases; do
        if grep -q "CPPUNIT_TEST($c);" "$in"; then
            found="$found $c"
        fi
    done
    if [ "$quorum" -gt 0 ] && [ "$(basename "$out")" = ZooKeeperQuorumServer.h ]; then
        for b in "CLIENT_PORT_BASE = $quorum;" "SERVER_PORT_BASE = $((quorum + 3));" \
            "ELECTION_PORT_BASE = $((quorum + 6));"; do
            if ! grep -q "$b" "$out.tmp"; then
                echo "gen-sources.sh: $in has no legacy line for $b" >&2
                exit 1
            fi
        done
    fi
    mv "$out.tmp" "$out"
done
for c in $cases; do
    case " $found " in
    *" $c "*) ;;
    *) echo "gen-sources.sh: no source registers the omitted case $c" >&2; exit 1 ;;
    esac
done
