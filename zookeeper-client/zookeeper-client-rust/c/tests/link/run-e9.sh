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


# The E9 check on macOS (ledger DV-TLS-4):
# no product of a drop-in build links, names or references OpenSSL.
# A configuration with SASL still links libsasl2.
#
# Usage: run-e9.sh DIR...
#   DIR  an output directory of dev/build-dropin.sh. The script checks
#        each Mach-O file and static archive in DIR and in its
#        subdirectories, to depth 2.
#
# Each file has three checks: no libssl or libcrypto load command
# (otool -L), no libssl or libcrypto path string, and no undefined
# OpenSSL name. A directory whose name ends in sasl or full must also
# load libsasl2 from its dylibs.
#
# Ledger row ABI-09: a build needs libsasl2 only with SASL, and it never
# needs libssl or libcrypto.
#
# Ledger: ABI-09, DV-TLS-4

set -uo pipefail

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
OSSL='^_?(SSL_|ERR_|EVP_|X509_|PEM_|BIO_|OPENSSL_|CRYPTO_)'

[ $# -gt 0 ] || { echo "usage: run-e9.sh DIR..." >&2; exit 2; }
for dir in "$@"; do
    [ -d "$dir" ] || { fail "$dir is not a directory"; continue; }
    n=0
    while IFS= read -r f; do
        case "$(file -b "$f")" in
        *Mach-O* | *"ar archive"*) ;;
        *) continue ;;
        esac
        n=$((n + 1))
        bad=""
        otool -L "$f" 2>/dev/null | tail -n +2 | grep -Eqi 'libssl|libcrypto' && bad="$bad load"
        strings -a "$f" | grep -Eq 'libssl\.|libcrypto\.' && bad="$bad string"
        nm -u "$f" 2>/dev/null | grep -Eq "$OSSL" && bad="$bad undefined"
        if [ -n "$bad" ]; then
            fail "E9 $f: OpenSSL$bad"
        fi
        case "$dir" in
        *sasl | *full | *sasl/ | *full/)
            case "$f" in
            *.2.dylib)
                otool -L "$f" | grep -q libsasl2 || fail "E9 $f does not load libsasl2"
                ;;
            esac
            ;;
        esac
    done < <(find "$dir" -maxdepth 2 -type f ! -path '*.dSYM/*' | sort)
    if [ "$n" = 0 ]; then
        fail "E9 $dir has no Mach-O file or archive"
    else
        pass "E9 $dir: $n files checked"
    fi
done
echo "run-e9.sh: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
