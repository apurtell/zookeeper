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

# Runs the zeroization tests under the free scanner (free_scan.c). macOS
# only. The tests are the session test of sasl_native.rs, the long-nonce
# test of the DIGEST-MD5 module, the PEM reader test of zk-driver
# tls_identity.rs and the three transmit copy tests of zk-driver
# iocore_tests.rs.
#
# Usage: ZK_TEST_PORT_BASE=<base> free_scan.sh
#
# The session test uses port base + 8. The script builds the scanner and
# the test binaries, then runs each test with the scanner inserted. A test
# fails when a freed block holds its marker.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$(cd "$HERE/../.." && pwd)"
: "${ZK_TEST_PORT_BASE:?set ZK_TEST_PORT_BASE}"
TARGET="${CARGO_TARGET_DIR:-$CRATE/../../target}"
WORK="$TARGET/free_scan"
mkdir -p "$WORK"

cc -std=c99 -Wall -Wextra -Wdeclaration-after-statement -Werror -dynamiclib \
    "$HERE/free_scan.c" -o "$WORK/libfree_scan.dylib"

BIN="$(cd "$CRATE" && cargo test --locked --features sasl --test sasl_native --no-run \
    --message-format=json | jq -r 'select(.executable != null) | .executable' | tail -n 1)"

OUT="$WORK/hits.txt"
rm -f "$OUT"
# The marker is the password of the test (sasl_native.rs PASSWORD).
DYLD_INSERT_LIBRARIES="$WORK/libfree_scan.dylib" \
    ZK_FREE_SCAN_MARKER="zk-sasl-native-4c1e9b" \
    ZK_FREE_SCAN_OUT="$OUT" \
    "$BIN" --ignored --exact secrets_are_zero_before_free --test-threads=1

# The marker is the HA1 of the long-nonce challenge (digest_md5.rs tests).
LIB="$(cd "$CRATE" && cargo test --locked --features sasl --lib --no-run \
    --message-format=json | jq -r 'select(.executable != null) | .executable' | tail -n 1)"
rm -f "$OUT"
DYLD_INSERT_LIBRARIES="$WORK/libfree_scan.dylib" \
    ZK_FREE_SCAN_MARKER="66a1b64b6346800663dd35e9c207ad26" \
    ZK_FREE_SCAN_OUT="$OUT" \
    "$LIB" --ignored --exact sasl::digest_md5::tests::long_nonce_secrets_are_zero_before_free \
    --test-threads=1

# The TLS fixtures come from the zk-testkit cache. Each cache build makes
# new keys, so the marker comes from the key file of this build. The
# marker is the first 24 characters of line 3 of keys/rsa-pkcs1.pem. The
# scanner removes the marker variable from the environment. Thus the test
# finds the marker with the same rule.
FIX="$(cd "$CRATE/../.." && cargo run -q --locked --offline -p zk-testkit --bin zk-fixtures \
    -- tls)" || exit 1
MARKER="$(sed -n 3p "$FIX/keys/rsa-pkcs1.pem" | cut -c1-24)"
if [ "${#MARKER}" -ne 24 ]; then
    echo "free_scan.sh: no marker in $FIX/keys/rsa-pkcs1.pem" >&2
    exit 1
fi
DRV="$(cd "$CRATE/../zk-driver" && cargo test --locked --features tls-ring --test tls_identity \
    --no-run --message-format=json | jq -r 'select(.executable != null) | .executable' | tail -n 1)"
rm -f "$OUT"
# ZK_TEST_TLS_FIXTURES gives the ready fixtures to the test. Thus no
# openssl process starts under the scanner.
DYLD_INSERT_LIBRARIES="$WORK/libfree_scan.dylib" \
    ZK_TEST_TLS_FIXTURES="$FIX" \
    ZK_FREE_SCAN_MARKER="$MARKER" \
    ZK_FREE_SCAN_OUT="$OUT" \
    "$DRV" --ignored --exact pem_buffers_are_zero_before_free --test-threads=1

# The marker is the auth credential of the transmit copy test
# (iocore_tests.rs TX_MARKER).
DRVLIB="$(cd "$CRATE/../zk-driver" && cargo test --locked --lib --no-run \
    --message-format=json | jq -r 'select(.executable != null) | .executable' | tail -n 1)"
rm -f "$OUT"
DYLD_INSERT_LIBRARIES="$WORK/libfree_scan.dylib" \
    ZK_FREE_SCAN_MARKER="zk-tx-copy-secret-7b3e91" \
    ZK_FREE_SCAN_OUT="$OUT" \
    "$DRVLIB" --ignored --exact iocore_tests::tx_copy_is_zero_before_free --test-threads=1
# The TLS write path uses the same marker.
rm -f "$OUT"
DYLD_INSERT_LIBRARIES="$WORK/libfree_scan.dylib" \
    ZK_FREE_SCAN_MARKER="zk-tx-copy-secret-7b3e91" \
    ZK_FREE_SCAN_OUT="$OUT" \
    "$DRVLIB" --ignored --exact iocore_tests::tls_tx_copy_is_zero_before_free --test-threads=1
# The plaintext path with large frames uses the same marker.
rm -f "$OUT"
DYLD_INSERT_LIBRARIES="$WORK/libfree_scan.dylib" \
    ZK_FREE_SCAN_MARKER="zk-tx-copy-secret-7b3e91" \
    ZK_FREE_SCAN_OUT="$OUT" \
    "$DRVLIB" --ignored --exact iocore_tests::plain_large_tx_copy_is_zero_before_free \
    --test-threads=1
