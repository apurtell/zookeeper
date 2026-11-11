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

# Compares the client-identity corpus step by step with the legacy core.
# Each case gives a cert string to
# keystep.c. Both cores must fail at the step that cases.tsv records,
# with the same log line. When the recorded steps differ, the row must
# name a registered deviation (DV-TLS-2, DV-TLS-5 or DV-FIX-10).
#
# The key fixtures are the client-identity corpus of zk-driver. They are
# not in git. The zk-fixtures bin of zk-testkit makes them with gen.sh on
# the first use. It prints their cache directory.
# ZK_TEST_TLS_FIXTURES names a ready directory, and then cargo does not
# run. The script makes the few extra inputs that need a special encoding
# in OUT/extra, with openssl@3.
#
# Usage: run-keycorpus.sh --rust LIBDIR [--legacy LIBDIR] [--flavor mt|st]
#                         [--provider ring|aws-lc-rs] [--port N] [--out DIR]
#
#   --rust      the directory of the ssl or full drop-in libzookeeper_FL.2.dylib
#   --legacy    the reference library directory
#               (default: /tmp/zk-legacy-ref/install-ssl/lib)
#   --flavor    mt or st (default: mt)
#   --provider  the rustls provider of the drop-in (default: ring). It
#               selects the Rust column of cases.tsv
#   --port      the port of the local listener (default: 23500)
#   --out       the work directory (default: /tmp/zk-keycorpus)
#
# OPENSSL selects the openssl binary, and OPENSSL_PREFIX the headers that
# zookeeper.h includes (default: Homebrew openssl@3). ZK_TEST_OPENSSL
# selects the openssl binary of the fixture build (default: OPENSSL). The
# script exits 1 when a case differs from cases.tsv.
#
# Ledger: DV-TLS-2

set -euo pipefail

# RCDIR is the Rust C tree. RDIR is the Rust workspace. Its zk-fixtures
# bin gives the key fixtures.
HERE=$(cd "$(dirname "$0")" && pwd)
RCDIR=$(cd "$HERE/../../../.." && pwd)
RDIR=$(cd "$RCDIR/.." && pwd)
OPENSSL_PREFIX=${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}
OPENSSL=${OPENSSL:-$OPENSSL_PREFIX/bin/openssl}
RUST=""
LEGACY=/tmp/zk-legacy-ref/install-ssl/lib
FL=mt
PROVIDER=ring
PORT=23500
OUT=/tmp/zk-keycorpus
while [ $# -gt 0 ]; do
  case $1 in
    --rust) RUST=$2; shift 2 ;;
    --legacy) LEGACY=$2; shift 2 ;;
    --flavor) FL=$2; shift 2 ;;
    --provider) PROVIDER=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    *) echo "run-keycorpus.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$RUST" ] || { echo "run-keycorpus.sh: --rust is required" >&2; exit 2; }
case $PROVIDER in
  ring | aws-lc-rs) ;;
  *) echo "run-keycorpus.sh: bad provider $PROVIDER" >&2; exit 2 ;;
esac
for d in "$RUST" "$LEGACY"; do
  [ -f "$d/libzookeeper_$FL.2.dylib" ] || {
    echo "run-keycorpus.sh: no libzookeeper_$FL.2.dylib in $d" >&2
    exit 2
  }
done
RUST=$(cd "$RUST" && pwd -P)
LEGACY=$(cd "$LEGACY" && pwd -P)
if [ -n "${ZK_TEST_TLS_FIXTURES:-}" ]; then
  FIX=$ZK_TEST_TLS_FIXTURES
elif command -v cargo > /dev/null 2>&1; then
  FIX=$(cd "$RDIR" && ZK_TEST_OPENSSL=${ZK_TEST_OPENSSL:-$OPENSSL} \
    cargo run -q --locked --offline -p zk-testkit --bin zk-fixtures -- tls) || {
    echo "run-keycorpus.sh: zk-fixtures did not make the TLS fixtures (see above)" >&2
    exit 2
  }
else
  echo "run-keycorpus.sh: the TLS fixtures need cargo; install it or set ZK_TEST_TLS_FIXTURES=DIR" >&2
  exit 2
fi
[ -f "$FIX/ca.pem" ] || {
  echo "run-keycorpus.sh: the TLS fixture directory $FIX has no ca.pem" >&2
  exit 2
}
FIX=$(cd "$FIX" && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd -P)
X=$OUT/extra
mkdir -p "$X"

# The program is compiled once, against the legacy headers, and linked
# with the legacy library. DYLD_LIBRARY_PATH selects the core at run time.
DEF=""
[ "$FL" = mt ] && DEF=-DTHREADED
INC=$(cd "$LEGACY/../include" && pwd)
"${CC:-cc}" -std=c99 -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L -DHAVE_OPENSSL_H $DEF \
  -Wall -Wextra -Wdeclaration-after-statement -Werror \
  -I"$INC" -I"$OPENSSL_PREFIX/include" -o "$OUT/keystep-$FL" "$HERE/keystep.c" \
  -L"$LEGACY" -lzookeeper_"$FL" -lpthread

# ---------------------------------------------------------------------
# Extra inputs. The passphrase of every encrypted key is "zk-test-pass".
# ---------------------------------------------------------------------
PASS=pass:zk-test-pass
VALID="-not_before 20240101000000Z -not_after 21240101000000Z"

# cert NAME KEY [ISSUER-PEM ISSUER-KEY [DIGEST [EXT]]]: a client leaf.
cert() {
  local name=$1 key=$2 ipem=${3:-$FIX/ca.pem} ikey=${4:-$FIX/ca.key} md=${5:-sha256}
  local ext=${6:-"basicConstraints=critical,CA:FALSE"}
  "$OPENSSL" req -new -key "$key" -subj "/CN=keycorpus $name" -out "$X/$name.csr" 2>/dev/null
  printf '%s\n' "$ext" > "$X/$name.ext"
  # shellcheck disable=SC2086
  "$OPENSSL" x509 -req -in "$X/$name.csr" -CA "$ipem" -CAkey "$ikey" -set_serial 7 \
    -"$md" $VALID -extfile "$X/$name.ext" -out "$X/$name.pem" 2>/dev/null
}
cert ed448 "$FIX/keys/ed448.key"
cert rsa1024 "$FIX/keys/rsa1024.key"
cert dsa "$FIX/keys/dsa.key"

# TK-20: a SHA-1-signed client leaf under an RSA-1024 intermediate.
[ -f "$X/int1024.key" ] ||
  "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$X/int1024.key" 2>/dev/null
cert int1024 "$X/int1024.key" "$FIX/ca.pem" "$FIX/ca.key" sha256 \
  "basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign"
cert sha1leaf "$FIX/client.key" "$X/int1024.pem" "$X/int1024.key" sha1
cat "$X/sha1leaf.pem" "$X/int1024.pem" > "$X/sha1-chain.pem"

# PBES1 (PBE-MD5-DES). OpenSSL writes it only with its legacy provider.
"$OPENSSL" pkcs8 -topk8 -in "$FIX/client.key" -v1 PBE-MD5-DES -provider legacy \
  -provider default -passout "$PASS" -out "$X/p8-pbes1.pem"

# A passphrase of 1500 bytes. OpenSSL uses the first 1024 bytes.
LONG=$(awk 'BEGIN { for (i = 0; i < 1500; i++) printf "%c", 97 + i % 26 }')
"$OPENSSL" pkcs8 -topk8 -in "$FIX/client.key" -v2 aes-256-cbc \
  -passout "pass:${LONG:0:1024}" -out "$X/p8-long.pem"

# Scrypt parameters that OpenSSL refuses to write. Each key takes the
# salt, IV and ciphertext of p8-scrypt.pem (N=1024, r=8, p=1).
HEX=()
while IFS= read -r h; do HEX+=("$h"); done < <("$OPENSSL" asn1parse -in "$FIX/keys/p8-scrypt.pem" |
  sed -n 's/.*\[HEX DUMP\]://p')
[ "${#HEX[@]}" = 3 ] || { echo "run-keycorpus.sh: p8-scrypt.pem has an odd layout" >&2; exit 2; }
# scrypt NAME N R P [KEYLENGTH]
scrypt() {
  {
    printf 'asn1=SEQUENCE:epki\n[epki]\nalg=SEQUENCE:alg\n'
    printf 'data=FORMAT:HEX,OCTETSTRING:%s\n' "${HEX[2]}"
    printf '[alg]\noid=OID:PBES2\nparams=SEQUENCE:pbes2\n'
    printf '[pbes2]\nkdf=SEQUENCE:kdf\nenc=SEQUENCE:enc\n'
    printf '[kdf]\noid=OID:1.3.6.1.4.1.11591.4.11\nparams=SEQUENCE:sp\n'
    printf '[sp]\nsalt=FORMAT:HEX,OCTETSTRING:%s\nn=INTEGER:%s\nr=INTEGER:%s\np=INTEGER:%s\n' \
      "${HEX[0]}" "$2" "$3" "$4"
    [ -z "${5:-}" ] || printf 'len=INTEGER:%s\n' "$5"
    printf '[enc]\noid=OID:aes-256-cbc\niv=FORMAT:HEX,OCTETSTRING:%s\n' "${HEX[1]}"
  } > "$X/$1.cnf"
  "$OPENSSL" asn1parse -genconf "$X/$1.cnf" -out "$X/$1.der" -noout
  {
    echo "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    "$OPENSSL" base64 -in "$X/$1.der"
    echo "-----END ENCRYPTED PRIVATE KEY-----"
  } > "$X/$1.pem"
}
scrypt scrypt-same 1024 8 1
scrypt scrypt-n 65536 8 1
scrypt scrypt-pr 1024 1 1073741824
scrypt scrypt-keylen 1024 8 1 16

# Malformed PEM: bad base64, a missing END line, and an empty file.
sed '3s/^..../!!!!/' "$FIX/client.key" > "$X/bad-base64.key"
sed '$d' "$FIX/client.key" > "$X/no-end.key"
: > "$X/empty.key"
sed '3s/^..../!!!!/' "$FIX/client.pem" > "$X/bad-base64.pem"
printf 'not a PEM file\n' > "$X/garbage.pem"

# ---------------------------------------------------------------------
# The cases.
# ---------------------------------------------------------------------
# run LIBDIR CERTSTRING: the step line of one core.
run() {
  DYLD_LIBRARY_PATH=$1 "$OUT/keystep-$FL" "$PORT" "$2" > "$OUT/step.out" 2>&1 || true
  local lib
  lib=$(sed -n 's/^LIB //p' "$OUT/step.out")
  case $lib in
    "$1"/*) ;;
    *) echo "BADLIB ${lib:-none}"; return ;;
  esac
  sed -n 's/^STEP //p' "$OUT/step.out"
}

fail=0
n=0
while IFS=$'\t' read -r name cs want_l want_ring want_aws tag rule; do
  case $name in '' | '#'*) continue ;; esac
  want_r=$want_ring
  [ "$PROVIDER" = aws-lc-rs ] && want_r=$want_aws
  cs=${cs//@F/$FIX}
  cs=${cs//@X/$X}
  cs=${cs//@LONG1023/${LONG:0:1023}}
  cs=${cs//@LONG/$LONG}
  got_l=$(run "$LEGACY" "$cs")
  got_r=$(run "$RUST" "$cs")
  tl=${got_l%% *}
  tr=${got_r%% *}
  verdict=ok
  if [ "$tl" != "$want_l" ] || [ "$tr" != "$want_r" ]; then
    verdict=DIFF
  elif [ "$tl" = "$tr" ] && [ "$got_l" != "$got_r" ]; then
    # The same step logs the same line.
    verdict=LINE
  elif [ "$tl" != "$tr" ]; then
    case $tag in
      DV-TLS-2 | DV-TLS-5 | DV-FIX-10) ;;
      *) verdict=TAG ;;
    esac
  fi
  n=$((n + 1))
  printf '%-22s legacy=%-7s rust=%-7s %-8s %s\n' "$name" "$tl" "$tr" "$tag" "$verdict"
  if [ "$verdict" != ok ]; then
    fail=1
    printf '    legacy: %s\n    rust:   %s\n    want:   legacy=%s rust=%s (%s)\n' \
      "$got_l" "$got_r" "$want_l" "$want_r" "$rule"
  fi
done < "$HERE/cases.tsv"
echo "run-keycorpus.sh: $FL $PROVIDER: $n cases, $([ "$fail" = 0 ] && echo pass || echo FAIL)"
exit "$fail"
