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

# Runs the TLS cases of the public suite (testSSL,
# testSSLNoClientCert, testSSLServerOnly, testReadOnlyWithSSL) against the
# legacy core and the Rust core, and compares their ERROR and WARN lines.
#
# Usage: run-public-tls.sh --legacy DIR --rust DIR --workdir DIR BINARY
#
# BINARY is zktest-public-mt, built with HAVE_OPENSSL_H, a ZKTEST_SSL_PORT
# and a ZKTEST_CERT_DIR that holds a gencerts.sh set. The testSSL
# fixture needs a leaf without AKID: run gencerts.sh with OpenSSL 3.1 or
# older, or with LibreSSL. The port variables are those of run-public.sh.
# Each test runs once per core, and run-public.sh stops its servers.
# The line view hides pointers and numbers of four or more digits.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LEGACY=
RUST=
WORK=
while [[ $# -gt 0 ]]; do
    case $1 in
    --legacy) LEGACY=$2; shift 2 ;;
    --rust) RUST=$2; shift 2 ;;
    --workdir) WORK=$2; shift 2 ;;
    *) break ;;
    esac
done
if [[ $# -ne 1 || -z $LEGACY || -z $RUST || -z $WORK ]]; then
    echo "usage: $0 --legacy DIR --rust DIR --workdir DIR BINARY" >&2
    exit 2
fi
BIN=$1
mkdir -p "$WORK"

lines() {
    grep -oE 'ZOO_(ERROR|WARN)@[a-z_]+@[0-9]+: .*' "$1" |
        sed -E 's/0x[0-9a-f]+/PTR/g; s/[0-9]{4,}/N/g' | sort -u || true
}

FAILED=0
for t in Zookeeper_simpleSystem::testSSL Zookeeper_simpleSystem::testSSLNoClientCert \
    Zookeeper_simpleSystem::testSSLServerOnly Zookeeper_readOnly::testReadOnlyWithSSL; do
    n=${t##*::}
    for core in legacy rust; do
        if [[ $core == legacy ]]; then lib=$LEGACY; else lib=$RUST; fi
        rm -rf "$WORK/$core-$n"
        if "$HERE/run-public.sh" --libdir "$lib" --workdir "$WORK/$core-$n" "$BIN" "$t" \
            >"$WORK/$core-$n.out" 2>&1; then
            echo "$n $core PASS"
        else
            echo "$n $core FAIL (see $WORK/$core-$n.out)"
            FAILED=1
        fi
    done
    if ! diff -u <(lines "$WORK/legacy-$n.out") <(lines "$WORK/rust-$n.out") \
        >"$WORK/$n.lines.diff"; then
        echo "$n lines DIFFER (see $WORK/$n.lines.diff)"
        FAILED=1
    fi
done
exit $FAILED
