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

# Downloads an official ZooKeeper binary release for the Rust real-server
# tests, checks it against the .sha512 file of the same site, and extracts it.
# run-recipes-real.sh and run-curator-interop.sh call it. A developer runs
# it before a real-server test that sets ZK_TEST_SERVER_VERSION.
#
# Platforms: macOS and Linux, with bash.
#
# Prerequisites: curl, tar, and shasum or sha512sum. The script needs
# access to https://archive.apache.org.
#
# Usage: get-release-server.sh VERSION
# The release goes to $ZK_TEST_SERVERS_DIR/VERSION/apache-zookeeper-VERSION-bin
# (default /tmp/zk-servers). test-server.sh and test-ensemble.sh select it with
# ZK_TEST_SERVER_VERSION=VERSION.
#
# The download goes into a new, empty staging directory. The script only
# extracts the archive. It runs nothing from the release. After the check and
# the extraction, a rename moves the staging directory to its final name. Thus
# the release directory is complete or absent, also when two runs race.

set -euo pipefail
VERSION="${1:?usage: $0 VERSION}"
case "$VERSION" in
*[!0-9.]* | "") echo "bad version: $VERSION" >&2; exit 2 ;;
esac
SERVERS="${ZK_TEST_SERVERS_DIR:-/tmp/zk-servers}"
DEST="$SERVERS/$VERSION"
NAME="apache-zookeeper-$VERSION-bin"
TARBALL="$NAME.tar.gz"
URL="https://archive.apache.org/dist/zookeeper/zookeeper-$VERSION/$TARBALL"

if [ -d "$DEST/$NAME/lib" ]; then
    echo "ZooKeeper $VERSION is in $DEST/$NAME"
    exit 0
fi
if [ -e "$DEST" ]; then
    echo "$DEST exists but holds no complete release; remove it first" >&2
    exit 1
fi
mkdir -p "$SERVERS"
STAGE="$(mktemp -d "$SERVERS/.$VERSION.partial.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

# A reset connection is a common error of the archive site. Newer curl
# versions retry it with --retry-all-errors.
RETRY=(--retry 3 --retry-delay 2)
if curl --help all 2>/dev/null | grep -- '--retry-all-errors' >/dev/null; then
    RETRY+=(--retry-all-errors)
fi
curl -fsSL "${RETRY[@]}" -o "$STAGE/$TARBALL" "$URL"
curl -fsSL "${RETRY[@]}" -o "$STAGE/$TARBALL.sha512" "$URL.sha512"

# The .sha512 files have two forms: "HASH  NAME" and the "NAME: HEX HEX ..."
# output of gpg --print-md. The check removes the file name, keeps the hex
# digits, and compares them with the hash of the download.
EXPECTED="$(tr -d '\n\r' < "$STAGE/$TARBALL.sha512" | sed "s|$TARBALL||" | tr -cd '0-9a-fA-F' | tr 'A-F' 'a-f')"
if command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 512 "$STAGE/$TARBALL" | cut -d' ' -f1)"
else
    ACTUAL="$(sha512sum "$STAGE/$TARBALL" | cut -d' ' -f1)"
fi
if [ "${#EXPECTED}" -ne 128 ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "sha512 mismatch for $TARBALL" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 1
fi

tar -xzf "$STAGE/$TARBALL" -C "$STAGE"
if [ ! -d "$STAGE/$NAME/lib" ]; then
    echo "the archive has no $NAME/lib directory" >&2
    exit 1
fi
# Another run can make the release first. Then this run uses that release.
# In a close race, mv moves the staging directory into that release, and the
# script removes it there.
if [ ! -e "$DEST" ]; then
    mv "$STAGE" "$DEST" || true
fi
rm -rf "${DEST:?}/$(basename "$STAGE")"
if [ ! -d "$DEST/$NAME/lib" ]; then
    echo "cannot move the release to $DEST" >&2
    exit 1
fi
echo "ZooKeeper $VERSION is in $DEST/$NAME"
