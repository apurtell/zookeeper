<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
//-->

# Curator interop test of the Rust recipes

This Maven project checks that the Rust recipes of `zk-recipes` work
together with Apache Curator. The Rust `DistributedLock` and
`LeaderLatch` use the node layouts of Curator's `InterProcessMutex` and
`LeaderLatch`. Thus Rust and Java processes can contend on the same
paths. Only a live test against a real server proves that.

The project is standalone. It has no parent, and the root pom does not
list it. A CI job must call it.

## Parts

- `RustPeer` starts the `interop_peer` example of zk-recipes as a
  process. It sends one command for each line, and it reads one reply
  line for each command. It can also kill the process.
- `CuratorInteropTest` runs Curator recipes and Rust peers on the same
  paths. Its nested class `CutProxy` sits between a Rust peer and a
  server. It cuts the connection at a given request.

## Peer protocol

`interop_peer <connect-string>` connects one client on its own IO
thread and writes `READY`. Then it reads one command for each line of
stdin. It writes one reply line to stdout for each command, in order.
Diagnostics go to stderr.

| Command | Reply | Meaning |
|---|---|---|
| `LOCK <path> <ms> [<data>]` | `OK <node-name>`, `TIMEOUT`, `ERR <e>` | Calls `acquire` with a timeout. The guard stays in the peer. |
| `TRYLOCK <path> [<data>]` | `OK <node-name>`, `NONE`, `ERR <e>` | Calls `try_acquire`. |
| `UNLOCK` | `OK`, `ERR <e>` | Calls `release` on the held guard. |
| `DROP_LOCK` | `OK`, `ERR <e>` | Drops the held guard and replies at once. The guaranteed delete sends a lost `delete` again. |
| `ABANDON_LOCK <path> <ms>` | `OK`, `ERR <e>` | Starts `acquire`, and drops the future after the delay. |
| `LATCH <path> <id>` | `OK <node-name>`, `ERR <e>` | Calls `start`. The latch stays in the peer. |
| `AWAIT_LEADER <ms>` | `OK`, `TIMEOUT`, `ERR <e>` | Calls `await_leadership` with a timeout. |
| `IS_LEADER` | `OK true`, `OK false` | Calls `is_leader`. |
| `PARTICIPANTS` | `OK <id>:<0 or 1> ...`, `ERR <e>` | Calls `participants`. The ids come in latch order. |
| `CLOSE_LATCH` | `OK`, `ERR <e>` | Calls `close`. |
| `SESSION` | `OK <id-hex> <password-hex>` | Gives the session, so that Java can expire it. |
| `QUIT` | `OK` | Closes the client, and the process exits. |

The optional `<data>` is the UTF-8 node data of the lock node. It is
empty by default. The Java side reads it as the id of a Rust holder.

`ERR` carries the `Debug` form of the error. A bad line gives
`ERR BadCommand <line>`. A participant id must not contain a space or
a `:`. The module doc of `crates/zk-recipes/examples/interop_peer.rs`
gives the details of each command.

## Test cases

1. `lockIsExclusiveAndFairAcrossLanguages`: two Curator
   `InterProcessMutex` holders and two Rust peers use one path. Mutual
   exclusion holds, and the lock goes in creation order.
2. `latchOrderAndParticipantsAcrossLanguages`: Curator and Rust latches
   lead in creation order. Each side reads the ids of the other.
3. `rustCreateRecoveryLeavesNoOrphan`: a proxy cuts the connection of a
   Rust peer during its create. The peer adopts its protected node, and
   no orphan node stays.
4. `createsAndNodesMatchCurator`: each side talks through its own
   proxy. The create requests of Rust and Curator are equal, apart from
   the protected ids. The test compares the container parents, the
   participant create, the node data, the ACL and the flags.
5. `lockOrderCountsForeignChildren`: foreign children take part in the
   lock order on both sides, as Curator orders them.
6. `latchOrderCountsForeignChildren`: the same check for the latch
   order.
7. `abandonedRustAcquireLeavesNoNode`: `ABANDON_LOCK` leaves no node,
   and the next Curator waiter gets the lock.
8. `killedRustHolderFreesTheLockAtExpiry`: the node of a killed Rust
   holder stays while its session lives. When Java expires the session,
   the next Curator waiter gets the lock.
9. `lostRustDeleteIsRetriedInTheBackground`: a `CutProxy` cuts the
   connection of the peer in place of the `delete` of `DROP_LOCK`. A
   Curator waiter waits behind the ghost node. The Rust guaranteed
   delete sends the `delete` again after the reconnect in the same
   session, and Curator gets the lock.

## Run the test

The server set is the HEAD server and the 3.9.6 release, standalone and
as a three-node ensemble. The runner script does all steps for each
version and each topology:

```sh
cd zookeeper-client-rust
ZK_TEST_PORT_BASE=23400 dev/run-curator-interop.sh head 3.9.6
```

`ZK_INTEROP_REPEAT=<n>` runs each pass `n` times.

The manual steps for one standalone server:

```sh
cd zookeeper-client-rust
cargo build --locked -p apache-zookeeper-recipes --example interop_peer
dev/test-server.sh start 23400 /tmp/zk-interop
mvn -B -f interop/curator/pom.xml test \
  -Dzk.connect=127.0.0.1:23400 \
  -Drust.peer.bin=$CARGO_TARGET_DIR/debug/examples/interop_peer
dev/test-server.sh stop 23400 /tmp/zk-interop
```

With no `zk.connect`, or with no peer binary, the tests skip. Thus
`mvn -B -f interop/curator/pom.xml test` alone checks that the project
compiles.
