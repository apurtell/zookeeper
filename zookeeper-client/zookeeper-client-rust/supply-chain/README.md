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

# Supply chain

This directory holds the supply-chain records of the Rust workspace. Three
tools check them: `cargo xtask closure`, `cargo-deny` and `cargo-vet`. Run
each command from the workspace directory, `zookeeper-client-rust`.

## Closure inventories

`closure/<target>/<configuration>.tsv` lists each crate that one shipped
build resolves. A row gives the name, the version, the source and the kind.
A `target` crate compiles into the library. A `host` crate runs only during
the build, as a build script or a procedural macro. Dev-dependencies are not
in an inventory.

The configurations are the drop-in feature sets of `zk-ffi` (`dropin-*`),
the native feature sets of `apache-zookeeper` (`native-*`) and the default
build of `apache-zookeeper-recipes` (`recipes`). The targets are the
supported targets of the three tiers, without Windows. The tables in
`xtask/src/closure.rs` are the full lists. Windows targets come with the
Windows support.

```sh
cargo xtask closure check     # fails when a closure differs from its file
cargo xtask closure update    # writes the files again
```

The task also applies the dependency rules of the specification. For
example, a drop-in closure must not contain `tokio` or `apache-zookeeper`,
and no closure contains a test crate or OpenSSL. A rule violation stops
both commands. After a dependency change, review the difference that
`check` shows. Then run `update` and commit the result with the change.

`check --semver-compatible` accepts semver-compatible versions. Use it for
builds against local crate sources, which can resolve other patch versions.
`--config FILE` gives the Cargo configuration of those crate sources to
each `cargo tree` call.

## cargo-deny

`../deny.toml` holds the license, ban, source and advisory policy for all
builds without the FIPS provider. `../deny-fips.toml` holds the policy for
the FIPS builds. Each file checks the union of its feature sets.

```sh
cargo deny --locked check
cargo deny --locked --config deny-fips.toml check
```

## cargo-vet

`config.toml`, `audits.toml` and `imports.lock` are the cargo-vet store.
`cargo vet init` made the store, so each third-party crate has an exemption
and no crate has an audit. A person must audit each crate of the drop-in
closures, or import audits from a trusted source, and then remove its
exemption. cargo-vet writes these files and removes comments, so the Apache
RAT check excludes them.

```sh
cargo vet --locked
```
