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

# zk-driver implementation guide

This guide describes the inner structure of the `zk-driver` crate for
contributors. It divides the crate into seven packages: `net`, `tls`,
`iocore`, `mt`, `st`, `native` and `tokio`. In this guide, a package is
a group of source files with one job. It is not a Cargo package. Read
the guide before you make a change that crosses packages.

The sources are this guide and `design/specification.md` (the spec). The
guide names spec sections by their titles. When the guide and the spec
disagree, the spec wins. Three rules of the spec shape the code:

- `TlsConn` has no `wants_read` and no handshake method (`net/tls/mod.rs`).
- The native threaded driver resolves on a short-lived DNS thread
  (`native.rs`, `DeferPolicy::DNS_THREAD`).
- The native drivers set `CLOEXEC`. The drop-in does not
  (`DriverConfig::cloexec`).

## 1. Rules for every package

### 1.1 Ownership

- Each package owns the files of section 3. The shared files of section
  2.1 hold the infrastructure of all packages. A change to a shared file
  affects every package, so keep it small and explain it in the review.
- `zk-proto` is the source of truth for the protocol. The driver never
  works around a proto bug. Fix the bug in `zk-proto`, with its own
  test.
- The doc comment on each function is its contract. When the contract
  and the spec disagree, the spec wins. Fix the code or the contract in
  the same change.
- A `pub` or `pub(crate)` signature is a contract with zk-ffi, zk-client
  or another package. When you change it, change every caller in the
  same commit. Private functions, fields and types are free to change.
- The fields of a struct belong to the file that declares it. Other files
  read them only through the methods of the owner. The `IoCore` fields
  belong to `iocore`. The `Core` fields have fixed writers (section 2.3).

### 1.2 Code rules

- MSRV is Rust 1.85, edition 2024. Let-chains are not available. `gen` is
  a reserved word.
- `fetch_update` is deprecated on new toolchains and 1.85 has no
  `try_update`. Use a `compare_exchange_weak` loop (see `dispatch.rs`).
- The workspace lints deny `unwrap_used`, `expect_used`, `panic`,
  `indexing_slicing`, `arithmetic_side_effects`, `dbg_macro`,
  `print_stdout`, `print_stderr`, `large_stack_arrays` and
  `large_stack_frames` (threshold 8192 bytes). `missing_docs` and
  `unreachable_pub` warn, and the checks use `-D warnings`. Use `get`,
  `checked_*`, `wrapping_*` and `saturating_*`. Do not use `as` casts.
- `unsafe_code` is forbidden in the crate and in its tests. Borrow file
  descriptors through `AsFd`, never through `BorrowedFd::borrow_raw`.
- Production code never panics. Test modules may use a module-level
  `#[allow(clippy::unwrap_used, clippy::indexing_slicing, ...)]`.
- The library emits diagnostics only as proto `LogRecord` items.
  Make them with `host::log_record`. Do not add a logging crate.
- The allowed dependencies are `zk-proto`, `zk-jute`, `zeroize`,
  `rustix`, the optional `tokio` (Unix only), and the optional TLS
  crates of `Cargo.toml`: `rustls`, `rustls-pki-types`,
  `rustls-webpki`, the RustCrypto parsers and key crates, and the
  provider crate. Do not use `socket2`, `mio`, `polling`, `nix`,
  `crossbeam`, `parking_lot`, `log` or `tracing`. A new dependency or a
  new feature needs a separate review, because it changes the supply
  chain of every build.
- The library starts threads only in `spawn_std.rs`. Other code gets a
  `Spawn` object.
- Big values go on the heap. `Connection` is in a `Box` in `Core`. Do not
  keep a `Connection` or a rustls session by value in a stack frame. The
  spec target is 4 KiB per frame ("Socket abstractions, polling, and
  wakeups"). The lint stops at 8 KiB.
- Every new file starts with the ASF header of the other files, then a
  blank line.
- Comments follow ASD-STE100: short sentences, active voice, present
  tense. They explain the design, not each line.

### 1.3 Checks for each package

Run these checks before you send a change. Use an explicit feature set.
Never use `--all-features`: exactly one TLS provider is allowed. In zsh,
put only the feature list in a variable (`fs=tls,tls-ring`), then pass
`--features $fs`.

```sh
for fs in "" "tls,tls-ring" "tls,tls-ring,tokio,std-thread"; do
  cargo build  -p zk-driver --no-default-features ${fs:+--features $fs}
  cargo clippy -p zk-driver --no-default-features ${fs:+--features $fs} --all-targets -- -D warnings
  cargo +1.85.0 check -p zk-driver --no-default-features ${fs:+--features $fs} --all-targets
  cargo test   -p zk-driver --no-default-features ${fs:+--features $fs}
done
cargo fmt -p zk-driver --check
```

The aws-lc providers (`tls-aws-lc-rs`, `tls-aws-lc-rs-fips`) need a C
toolchain and CMake. Check them when the machine has them.

A change to the locks, the atomics, the outbox or the dispatch FIFO
also needs the loom models and a clippy pass under `--cfg loom`:

```sh
cargo xtask loom -p zk-driver
RUSTFLAGS='--cfg loom' CARGO_TARGET_DIR=target/loom \
  cargo clippy -p zk-driver --all-targets -- -D warnings
```

A change to the socket code, the waker or other low-level code also
needs the Miri runs (nightly with the `miri` component):

```sh
cargo xtask miri --only zk-driver,zk-driver-tls
```

### 1.4 Tests

- Unit tests use the helpers of `src/testutil.rs`: `TestHost`,
  `test_config`, `test_connection`, `native_connection`,
  `exists_request`, `socket_pair`, `RealPoll`, `NullTls` and
  `FakeConnector`. `RealPoll` does not use `RustixPoll`. `socket_pair`
  does not use `TcpSock::open`. Thus a unit test of one package does
  not depend on the code of `net`.
- A test may drive a `Connection` with proto calls (`begin_interest`,
  `poll_action`, the `handle_*` calls) to reach a state, then give it
  to the code under test.
- Fake-server tests are in `tests/` (integration test crates) and in
  `src/iocore_tests.rs`. The shared helpers are in `tests/common/mod.rs`.
  A helper that only one test file uses stays in that file. A helper
  that several test files use goes in `tests/common/mod.rs`.
- Put a new fake-server test in the test file of its package. Tests
  that use only the public API go in `tests/`.
- The zeroization tests have `#[ignore = "free-scan"]`. They need a
  scanner of freed heap blocks.
- The loom models are in `src/loom_models.rs`. They compile only under
  `--cfg loom`, and `cargo xtask loom` runs them with a preemption bound
  of 3. loom threads play the IO thread, the dispatch thread and the
  application threads. The models check that each completion token has
  exactly one delivery, that results arrive in the wire order, that the
  dispatch thread leaves only after the close mark, and that a result of
  `destroy` reaches the dispatch thread once, in a foreign close and in
  a close from a completion callback. A loom wait never times out, so a
  model must notify every timed waiter.
- `cargo xtask miri` runs the unit and integration tests under Miri with
  strict provenance. The `zk-driver` run uses host loopback sockets. Miri
  has no `fcntl(F_SETFD)`, so these tests open the sockets and the waker
  pipe without CLOEXEC under Miri (`!cfg!(miri)`). The `zk-driver-tls`
  run takes the TLS unit tests. The task makes the TLS fixtures and the
  corpus outside Miri with the `zk-fixtures` tool of zk-testkit, because
  Miri cannot start OpenSSL. A test that Miri cannot run has
  `#[cfg_attr(miri, ignore = "<reason>")]`.

## 2. Shared structure

### 2.1 Shared files

These files hold the infrastructure of all packages. No single package
owns them.

| File | Content |
|---|---|
| `Cargo.toml` | Dependencies and the features `tls`, `tls-ring`, `tls-aws-lc-rs`, `tls-aws-lc-rs-fips`, `tokio`, `std-thread`. |
| `src/lib.rs` | The module tree, the re-exports and the provider `compile_error!` checks. |
| `src/sync.rs` | `Mutex`, `Guard`, `Condvar`, the `atomic` types and the `Unlocked` proof. Under `--cfg loom` these types wrap the loom types. |
| `src/clock.rs` | `Clock`, `MonotonicClock`, `TestClock`. |
| `src/host.rs` | `DriverTokens`, `HostLeaves`, `Discarded`, the proto hook adapters, `connection_hooks`, `log_record`, `discard_leftovers`. |
| `src/outbox.rs` | `Item`, `Step`, `Flavor`, `ResumeAt`, `Publish`, `Outbox`, `Requeued`, `pump` and the FIFO rule. |
| `src/loom_models.rs` | The loom models of the dispatch FIFO, the close mark and the close tail (`--cfg loom` only). |
| `src/state.rs` | `Env`, `SaslAnswer`, `Core`, `read_conn`. The API-entry helpers `read_at_entry`, `with_conn_at_entry`, `Core::submit_or`, `Core::add_auth_or` and `Core::set_servers_native`. |
| `src/lifecycle.rs` | `Lifecycle`: refs, prolog, epilog, the close flag, the fork check. |
| `src/dispatch.rs` | `RouteSink` and `ReadGate` of the native drivers. |
| `src/net/tls/mod.rs` | `TlsConn`, `TlsFailure`, `TlsSetupError`, `TlsPurpose`, `TlsConnector`, `ReadFailure`, `TlsTransport`, `alert_attempt`. |
| `src/net/tls/{pem,x509,trust,legacy_verify,v1_leaf}.rs` | The trust store and the certificate verifiers. |
| `src/net/tls/{identity,legacy_pem}.rs` | The client identity: `Identity::load`, `LegacyClientCert`, PBES2 and traditional PEM key decryption. |
| `src/testutil.rs` | Unit-test helpers (section 1.4). |
| `tests/common/mod.rs` | Fake-server helpers: `IpHost`, `legacy_connection`, `native_connection`, `env`, `drain`, `kinds`, `wait_until`, `fixture`, the sink `Collect`, `TestSpawner`, `SlowHost`, the requests `exists_at`, `exists` and `exists_native`, and the `tls` module (`TlsAcceptor`, `certs`, `key`, `provider`, `legacy_path`, `Native`, `native_connector`, `legacy_connector`). |
| `tests/fixtures/tls/` | `gen.sh` and `trust/gen.sh`. The tests do not use committed TLS material. `zk_testkit::fixtures::tls_dir` runs both scripts at test time and keeps the output in the test cache. The output is the EC P-256 test certificates, `crl.pem`, `keys/` (the client-identity corpus) and `trust/`. `zk_testkit::fixtures::tls_corpus_dir` gives the trust-decision corpus that `c/tests/conformance/tls/gencorpus.sh` makes. The scripts need OpenSSL 3.4 to 3.x. `ZK_TEST_OPENSSL` selects the binary. |

### 2.2 The layers

```
zk-ffi (drop-in C ABI)             zk-client (native API)
   |                                   |
   v                                   v
threaded::Shared (mt)              native::NativeHandle (threads)
polled::Polled   (st)              tokio::TaskHandle    (tokio task)
   |                                   |
   +---------------+-------------------+
                   v
   iocore: IoCore::{interest_step, process_step, resume,
                    complete_job, flush_once, close_flush}, run_job
                   |                         |
                   v                         v
   net: TcpSock, Poll, probe,       iocore_tls -> TlsConn (tls: RustlsConn)
        resolve::{run, apply_results}         -> TlsConnector (tls: RustlsConnector)
                   |
                   v
   zk-proto: Connection (the sans-IO state machine)
```

`init::Init` (net) makes the `Connection` of a drop-in handle. Its
`Ready` result goes to `Shared::from_init` or `Polled::from_init`.

### 2.3 Locks and the `Core` fields

The drop-in handles have two locks: `core` (a `Mutex<Core>`) and the IO
side (`io`, a `Mutex<IoCore>` or a wrapper). The mt handle also has the
`fifo` lock of the dispatch FIFO (`DispatchQueue`). The lock order is
`io`, then `core`, then `fifo`. The `fifo` lock is a leaf: no other lock
is taken under it. A call that blocks (resolve, probe, poll, close flush)
holds no `core` lock. `Unlocked` is the proof that the thread holds no
driver lock. Only `Mutex::lock(&mut Unlocked)` takes the `core` lock.

The drivers take every lock and every shared atomic from `src/sync.rs`,
never from `std::sync`. A build with `--cfg loom` then puts the loom
types under the real driver code, and the loom models explore its
interleavings. A `static` and the test clock keep the `std` atomics,
because the loom constructors are not `const`.

| `Core` field | Writer |
|---|---|
| `conn` | The driver packages (`mt`, `st`, `native`, `tokio`) at the final close (take). Every package calls proto through it. |
| `stopped` | `Core::pump` (shared) sets it. `iocore::resume` takes it. |
| `requeued` | Driver `requeue`. `IoCore` steps restore it first. |
| `local` | `Core::pump` with the st flavor. `st` drains it. |
| `peer` | `iocore` (connect and close). Drivers read it for `peer_addr`. |
| `sasl` | Driver `sasl_result`. `iocore::resume` takes it. |

### 2.4 Outputs and barriers

Every step call writes into a caller `Outbox`. `Core::pump` moves the
proto outputs into it, with the FIFO rule of the flavor. A
barrier (a SASL item, a LOG flush before a blocking call, a stopped stage)
ends the step with `Progress::More`. The driver then returns
`Step::Drain` (or the step of `ResumeAt`). C drains the outbox and calls
the resume entry point. The native drivers route the items to a
`RouteSink` instead and continue at once.

### 2.5 Call graph

| Caller | Callee |
|---|---|
| `init` | `host::connection_hooks`, `Connection::new`, `resolve::run`, `Core::pump` |
| `mt`, `st` | `IoCore::{interest_step, process_step, resume, flush_once, close_flush, sasl_addrs}`, `Core::{pump, restore_requeued}`, `Lifecycle`, `Waker` (mt), `Env::step_ctx` |
| `native` | `IoCore::{interest_step, process_step, resume, take_jobs, complete_job, close_flush}`, `iocore::run_job` (DNS thread), `Poll`, `Waker`, `ReadGate`, `RouteSink`, `Spawn` |
| `tokio` | as `native`, with `spawn_blocking` for `run_job`, `AsyncFd` for readiness (one registration per wait) and `Notify` for wake |
| `iocore` | `TcpSock::{open, start_connect, send, recv, socket_error, local_addr, peer_addr}`, `map_revents`, `request_flags`, `probe`, `resolve::{run, apply_results}`, `iocore_tls::*` |
| `iocore_tls` | `TlsConn` methods, `TlsConnector::new_conn`, `alert_attempt` |
| `net::probe` | `TcpSock`, `Poll`, `TlsConnector::new_conn` (TLS probe) |
| `tls` | rustls, the trust and identity files |

## 3. Packages

### net

Files: `src/net/sock.rs`, `src/net/poll.rs`, `src/net/probe.rs`,
`src/net/waker.rs`, `src/net/mod.rs`, `src/resolve.rs`, `src/init.rs`,
`tests/net_probe.rs`.

Sources: spec "Socket abstractions, polling, and wakeups";
zookeeper.c `zookeeper_init_internal`, `resolve_hosts`,
`zookeeper_set_sock_nodelay`, `ping_rw_server`.

Also in the package: `net/mod.rs`, `net/waker.rs` (`Waker`, `WakeRx`),
`TcpSock::{from_owned, into_owned, raw, send, recv,
socket_error, local_addr, peer_addr}`, `errno_value`, `ResolveRun::new`,
`shuffle_on`.

Main functions:

| Function | File |
|---|---|
| `TcpSock::open(addr, cloexec) -> Result<Opened, Errno>` | sock.rs |
| `TcpSock::start_connect(&self, addr) -> Result<ConnectStart, Errno>` | sock.rs |
| `RustixPoll::poll` | poll.rs |
| `map_revents`, `clamp_timeout_ms`, `request_flags` | poll.rs |
| `probe(..) -> ProbeEnd`, `is_rw_reply` | probe.rs |
| `resolve::run`, `resolve::apply_results` | resolve.rs |
| `Init::new`, `Init::step`, `Init::abandon` | init.rs |

Calls made: `host::connection_hooks`, `Connection::new`,
`zk_proto::legacy::connect::parse_init`, `HostLeaves::resolve`,
`HostLeaves::rng_reseed`, `Core::pump`, rustix.

Calls received: `iocore` (sock, poll, probe, resolve), every driver
(`Poll`), zk-ffi (`Init`).

Invariants:

- `open` sets `NONBLOCK`, `CLOEXEC` only when asked, `SO_NOSIGPIPE` on
  Apple, and `TCP_NODELAY`. A `TCP_NODELAY` failure is not an error
  (`Opened::nodelay_ok`).
- `start_connect` maps `EINPROGRESS`, `EWOULDBLOCK` and `EINTR` to
  in-progress.
- `map_revents`: IN gives READ; OUT or HUP gives WRITE; ERR or NVAL gives
  READ and WRITE.
- The probe never blocks past its phase budget, and the waker or the
  abort flag ends it.
- The resolution loop flushes LOG items before each `resolve` leaf
  (`Progress::More`), and holds no `core` lock in the leaf.
- `Init` gives the prefix log lines before a port error
  (`init_port_error_comes_after_the_prefix_lines`).

Test coverage: the bit maps and the clamp; `open` and `start_connect`
against a `TcpListener`; `is_rw_reply` with short and zero-filled
replies; the probe against a listener that replies "rw", "ro", and
nothing; the resolution loop with `TestHost` (order, the LOG barrier,
`EAI_NONAME`); `Init` with a good, an empty and a bad-port host string.
`tests/net_probe.rs` holds the fake-server tests.

### tls

Files: `src/net/tls/conn.rs`, `src/net/tls/connector.rs`,
`src/net/tls/verify.rs`, `tests/tls_conn.rs`.

Sources: spec "TLS transport integration" and "TLS verification". Only
the `tls` feature builds these files.

Main functions:

| Function | File |
|---|---|
| `RustlsConn::new`, `feed_all`, `process`, `latch` | conn.rs |
| `impl TlsConn for RustlsConn` (every method) | conn.rs |
| `RustlsConnector::legacy_config`, `TlsConnector::new_conn` | connector.rs |
| `impl ServerCertVerifier for ChainOnlyVerifier` | verify.rs |
| `webpki_verifier` | verify.rs |

Calls made: rustls, `rustls-webpki`, the trust and identity files
(`pem`, `trust`, `identity`), `default_provider`.

`legacy_config` runs these steps in order: `TrustSet::load_ca_file`,
`load_default_paths`, `Identity::load`, then the verifier. The legacy
verifier is `legacy_verify::LegacyChainOnly`, and the identity resolver
is `identity::LegacyClientCert`. `ChainOnlyVerifier` stays for the
`legacy_c_compat` mode of zk-client and for the session tests of
`conn.rs`. `tests/tls_identity.rs` holds the client-identity corpus.

Calls received: `iocore_tls` and `probe` through the `TlsConn` and
`TlsConnector` traits.

Invariants:

- The first `take_ciphertext` gives the ClientHello.
- A failure is latched once. Plaintext that arrived before it is given
  first.
- `feed` consumes every byte or latches a failure.
- Each attempt and each probe gets a new `ClientConfig`.
- Key bytes stay in `SecretBytes`.
- The trust and identity files are shared files (section 2.1).
  zk-client loads its TLS files through them too.

Test coverage: an in-memory handshake against a rustls
`ServerConnection`; `write_frame` and `read_plaintext` round trips; the
latch order; `feed_eof` in and after the handshake; chain-only and WebPKI
verification with the fixtures of `zk_testkit::fixtures::tls_dir`; a
missing CA file gives `TlsSetupError::Config`. `tests/tls_conn.rs` holds
the socket tests.

### iocore

Files: `src/iocore.rs`, `src/iocore_tls.rs`, `src/iocore_tests.rs`.

Sources: spec "Shared driver execution pipeline" and "Outbox management
and synchronization barriers"; zookeeper.c:2618-2824
(`zookeeper_interest`), 3530-3667 (`zookeeper_process`, `check_events`),
`flush_send_queue`, `recv_buffer`.

Main functions:

| Function | File |
|---|---|
| `run_job` | iocore.rs |
| `IoCore::{interest_step, process_step, resume, complete_job, flush_once, close_flush, sasl_addrs}` | iocore.rs |
| `handshake_start`, `handshake_step`, `tls_read`, `take_plaintext`, `tls_flush`, `pump_out`, `close_notify` | iocore_tls.rs |

Calls made: `net` (sock, poll, probe, resolve), `TlsConn`,
`TlsConnector::new_conn`, `alert_attempt`, `Core::{pump,
restore_requeued, resume_stopped}`, the proto handlers.

Calls received: `mt`, `st`, `native`, `tokio`.

Invariants:

- Pump the proto outputs after each proto call.
- A barrier stores `cont` and returns `More`. `resume` continues there.
- `interest_step` writes `out` only in the call that reaches
  `finish_interest`.
- Check `has_transport` after every relock of `core`.
- No `core` lock is held across a blocking call.
- The read gate is checked before each read and each `handle_read`.
- The st flavor reads `read_hint()` bytes for plaintext. When that read
  completes a frame length, the same call reads the frame body, as
  `recv_buffer` does. One call never reads past the end of one frame.
- In every plaintext flavor, a read that fills its request and leaves
  the frame open gives a read of the rest of that frame in the same
  call. After one of those reads blocks, the later calls for that frame
  make no more of them (`rx_more_blocked`).
- A plaintext read that is wholly inside the current frame body goes
  straight into the body (`body_room`, `recv`, `handle_body_read`) under
  one `core` lock. This occurs only when no received bytes wait. Other
  reads go to `rx`.
- `close_flush` returns `ZOK`, `ZOPERATIONTIMEOUT`, `ZCONNECTIONLOSS` or
  `ZSYSTEMERROR` and never exceeds its budgets.

Test coverage: the tests are in `src/iocore_tests.rs`. A unit test
installs a `Transport::Plain` or `Transport::Tls` from `socket_pair` and
`NullTls` directly. It reaches a connected proto state with proto
calls. It does not reach `TcpSock::open`, `start_connect`,
`map_revents`, `probe` or `resolve::run`, and it uses `PollEvents`
values directly. Thus a fault in `net` does not hide a fault in
`iocore`. The tests cover: frame reads split at every byte; the barrier
and `resume`; the stall on a negative length; the WRITE interest while
bytes wait; the TLS latch order with `NullTls` (`F`, `A`, `!`);
`flush_once` failure; `close_flush` timeouts with `TestClock`; `run_job`
with `FakeConnector`. The fake-server tests at the end of the file use
the real `net` code.

### mt

Files: `src/threaded.rs`, `tests/mt_fakeserver.rs`.

Sources: spec "multithreaded driver design (`libzookeeper_mt`)";
mt_adaptor.c (`adaptor_init`, `do_io`, `do_completion`,
`adaptor_finish`), zookeeper.c `zookeeper_close`.

Main functions:

| Function | File |
|---|---|
| `Shared::new` | threaded.rs |
| `thread_enter`, `thread_exit` | threaded.rs |
| `io_step`, `resume`, `wait_dispatch`, `close` | threaded.rs |
| `submit`, `submit_with_data`, `submit_multi_ref`, `add_auth`, `set_servers` | threaded.rs |
| `sasl_result`, `requeue`, `peer_addr` | threaded.rs |
| `interest_exported`, `process_exported` | threaded.rs |

Also in the package: `from_init`, `outbox`, `state`, `recv_timeout`,
`client_id`, `DispatchQueue` (`Publish`).

Calls made: `iocore` steps, `Waker::{new, wake}`, `WakeRx`, `Lifecycle`,
`Core::pump`, `Connection::{submit_with_data, submit_multi_ref, add_auth, set_servers, begin_close,
queue_close_op, close_step, destroy}`, `parse_init` (set_servers).

Calls received: zk-ffi (mt build).

Invariants:

- A submit takes the `core` lock, calls proto, then wakes the IO thread.
- The dispatch FIFO keeps the wire order. A result with no outbox entry
  ahead of it goes to the FIFO in the pump, under the `core` lock. A
  later result waits in the outbox as a publish entry, and goes to the
  FIFO when the C drain reaches it. A pump on another thread thus cannot
  put a later result before an earlier one.
- The pump stops when the outbox holds an item that C sees and proto has
  more output. The later results stay in proto. A close from the
  callback of that item then pumps them before its ZCLOSING results and
  its close mark. Thus the dispatch thread delivers every reply that
  was decoded before the close.
- The close tail is the "Closing" line, the CLOSE_OP, the flush and
  wait, the "Freeing" line and `destroy`. It runs exactly once. A
  foreign close runs it after the IO join and before the close mark, so
  the dispatch thread delivers the results of `destroy`. Before the
  tail, a foreign close waits until the dispatch thread has delivered
  every queued result (`DispatchQueue::wait_idle`). The tail lines thus
  follow those callbacks, as in the C client, where the completion
  thread runs its callbacks before the close logs. When a completion
  callback continues a requeued foreign close, the close skips this
  wait, because the dispatch thread cannot wait for itself. The auth
  completions that `destroy` fails run on the closing thread
  (zookeeper.c `free_completions`). A close from a completion callback
  leaves it
  to the exit of the dispatch thread. That thread runs the tail and
  delivers its results itself, in order (`Outbox::deliver_here`). A
  close from an IO callback leaves it to the final close on the IO
  thread, after the dispatch thread exits. There, the results of
  `destroy` go to `discard_token`, as zookeeper.c `destroy` frees them
  with no callback. With no socket, the tail
  skips `close_flush` and the rc is `ZOK` (zookeeper.c
  `zookeeper_close`).
- The final close runs in the call that drops the last ref. It runs the
  tail when no close ran it, then the release. Only the release and the
  tail of a close from an IO callback call `discard_token`.
- A callback can end the dispatch thread, for example with
  `pthread_exit`. The cleanup handler of the shim then calls
  `Shared::dispatch_ended`. It sends the untaken batch items to
  `discard_token`, sets `dispatch_ended` and wakes `wait_idle`. The
  wait returns when `dispatch_ended` is set, so a foreign close does
  not hang. The thread keeps its ref, because the last ref runs the
  final close. The join returns only after the handler ran. So the
  epilog of a later close from a foreign thread or an IO callback gives
  back the ref of the ended thread. The C client never frees the
  results that are left, because it leaks the handle. The drop-in
  discards them at the release, with no callback, and frees the handle.
  After a close from a completion callback, the thread exit runs the
  close tail. A `pthread_exit` after such a close thus leaks the
  handle, as in the C client.
- A forked child closes the socket and sends nothing.
- `interest_exported` reports fd -1 and `process_exported` gives
  `ZINVALIDSTATE`.

Test coverage (unit, in `threaded.rs`): thread refs and the epilog;
`wait_dispatch` order and the IO-exit wake; submit wakes the waker; close
from each role on a handle with no socket (no `iocore` call), and the
place of the close mark; `sasl_result` and `requeue` storage. The socket
pair tests in `iocore_tests.rs` cover the close tail: a reply during the
flush; a result that only `destroy` gives, for a foreign close and a
close from a completion callback; the discard of that result in a close
from an IO callback; and the order of the tail lines after the queued
callbacks in a foreign close. A unit test in `threaded.rs` covers a
completion callback that continues a requeued foreign close. Unit
tests in `threaded.rs` cover the end of the dispatch thread during and
before a foreign close, before a close from the IO thread, and after a
close from a callback. A loom model checks that the end always wakes
the wait of a foreign close.
`tests/mt_fakeserver.rs` holds the end-to-end tests.

### st

Files: `src/polled.rs`, `tests/st_fakeserver.rs`.

Sources: spec "single threaded driver design (`libzookeeper_st`)";
zookeeper.c `zookeeper_interest`, `zookeeper_process`,
`process_completions`, `zookeeper_close` (st paths).

Main functions:

| Function | File |
|---|---|
| `Polled::new` | polled.rs |
| `interest`, `process`, `resume` | polled.rs |
| `submit`, `submit_with_data`, `submit_multi_ref`, `add_auth`, `set_servers` | polled.rs |
| `close` | polled.rs |
| `wait_events` (a test and tool helper: poll the handle socket through `Env::poll`) | polled.rs |
| `sasl_result`, `requeue`, `peer_addr` | polled.rs |

Also in the package: `from_init`, `outbox`, the accessors.

Calls made: `iocore` steps, `IoCore::flush_once`, `close_flush`,
`Core::pump`, `Core::local`, `Lifecycle`, proto.

Calls received: zk-ffi (st build).

Invariants:

- The local FIFO drains at the C drain points.
- A submit runs one non-blocking flush pass when a socket exists. A send
  failure calls `handle_forced_close` and drops the transport.
- A close inside a callback defers to the end of the drain
  (`StClose::Deferred`).
- The final close flushes, then releases (`Step::Release`). With no
  socket, it skips `close_flush` and the rc is `ZOK`.

Test coverage (unit, in `polled.rs`): submit and close with no socket;
the deferred close; `set_servers` with a bad string; `requeue` and
`sasl_result` storage. `tests/st_fakeserver.rs` holds the end-to-end
tests.

### native

Files: `src/native.rs`, `src/spawn_std.rs`, `src/host_std.rs`,
`tests/native_fakeserver.rs`.

Sources: spec "Native driver implementations".

Main functions:

| Function | File |
|---|---|
| `start`, `io_loop`, `dns_thread` | native.rs |
| `NativeShared::{pass, route}` | native.rs |
| `NativeHandle::{submit, submit_with_data, submit_multi_ref, add_auth, set_servers, close, wait_closed, detach}` | native.rs |
| `impl Spawn for StdSpawner` | spawn_std.rs |
| `StdHostLeaves::new`, `log_enabled`, `rng_random`, `rng_drand48`, `rng_reseed`, `resolve` | host_std.rs |

Also in the package: `taken`, `wake`, `gate`, `state`, `client_id`,
`last_teardown_cause`, the other `StdHostLeaves` leaves.

Calls made: `iocore` steps, `take_jobs`, `run_job`, `complete_job`,
`Waker`, `Poll`, `ReadGate`, `RouteSink`, `Spawn`, proto.

Calls received: zk-client.

Invariants:

- Only the IO thread drives the `IoCore`. Handles take only the `core`
  lock, then wake.
- Resolution runs on one DNS thread at a time (`DnsSlot`). Its result
  wakes the IO thread.
- Routed items that count close the read gate at capacity. `taken`
  opens it.
- `wait_closed` returns the exit value of the IO thread, or `None` at the
  timeout.
- `StdHostLeaves::resolve` uses `ToSocketAddrs` and keeps the host order.

Test coverage (unit): build a `NativeShared` directly in `native.rs`
(no `start`) and test submit, wake, close flags and the gate; `StdSpawner`
names the thread; `StdHostLeaves` ranges and IP-literal resolution.
`tests/native_fakeserver.rs` holds the end-to-end tests. One of them
needs a resolver that knows `localhost`, so it has an `ignore` marker.

### tokio

Files: `src/tokio.rs`, `tests/tokio_fakeserver.rs`.

Sources: spec "Native driver implementations". Only Unix with the
`tokio` feature builds these files. Use `::tokio::` paths in the module.

Main functions:

| Function | File |
|---|---|
| `spawn`, `run` | tokio.rs |
| `TaskHandle::{submit, submit_with_data, submit_multi_ref, add_auth, set_servers, close, closed, detach}` | tokio.rs |

Also in the package: `taken`, `gate`, `state`, `client_id`,
`last_teardown_cause`.

Calls made: `iocore` steps, `take_jobs`, `run_job` in `spawn_blocking`,
`complete_job`, `AsyncFd`, `Notify`, `watch`, proto.

Calls received: zk-client.

Invariants:

- `DeferPolicy::ALL`: no blocking call runs on a runtime worker.
- `Progress::Wait` means the task waits for the deferred jobs.
- `closed` resolves once with the exit value.
- The task holds no `core` lock across an `.await`.

Test coverage (unit): build a `TaskShared` directly and test submit,
notify and close flags on a `current_thread` runtime.
`tests/tokio_fakeserver.rs` holds the end-to-end tests.

## 4. Cross-package order

The packages depend on the signatures of the other packages. The `net`
and `tls` packages depend on no other package. `iocore` uses `net` and
`tls`. Each driver package (`mt`, `st`, `native`, `tokio`) uses
`iocore`. The unit tests of each package use the helpers of section 1.4,
so they test the package alone. The fake-server tests in `tests/` and
at the end of `src/iocore_tests.rs` run the whole stack. After a change
to `net`, `tls` or `iocore`, run the fake-server tests of every driver.

## 5. Review checklist

1. Fix every new warning. Remove code that nothing uses.
2. The checks of section 1.3 pass with each feature set.
3. No `todo!` is left: `rg 'todo[!]' crates/zk-driver/src` prints
   nothing.
4. The aws-lc providers build and pass their tests when the machine has
   a C toolchain and CMake.
