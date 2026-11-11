// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The Rust peer of the Curator interop test.
//!
//! The JUnit test in `interop/curator` starts this binary as a process:
//!
//! ```text
//! interop_peer <connect-string>
//! ```
//!
//! The peer connects one client on its own IO thread, writes `READY`,
//! and then reads one command for each line of stdin. It writes one
//! reply line to stdout for each command, in order. Diagnostics go to
//! stderr only. The commands and their replies:
//!
//! | Command                       | Reply                              |
//! |-------------------------------|------------------------------------|
//! | `LOCK <path> <ms> [<data>]`   | `OK <node-name>`, `TIMEOUT`, `ERR` |
//! | `TRYLOCK <path> [<data>]`     | `OK <node-name>`, `NONE`, `ERR`    |
//! | `UNLOCK`                      | `OK`, `ERR`                        |
//! | `DROP_LOCK`                   | `OK`, `ERR`                        |
//! | `ABANDON_LOCK <path> <ms>`    | `OK`, `ERR`                        |
//! | `LATCH <path> <id>`           | `OK <node-name>`, `ERR`            |
//! | `AWAIT_LEADER <timeout-ms>`   | `OK`, `TIMEOUT`, `ERR`             |
//! | `IS_LEADER`                   | `OK true`, `OK false`              |
//! | `PARTICIPANTS`                | `OK <id>:<0 or 1> ...`, `ERR`      |
//! | `CLOSE_LATCH`                 | `OK`, `ERR`                        |
//! | `SESSION`                     | `OK <id-hex> <password-hex>`       |
//! | `QUIT`                        | `OK`, then the process exits       |
//!
//! The optional `<data>` of `LOCK` and `TRYLOCK` is the node data of the
//! lock node, as UTF-8. With no `<data>`, the node data is empty, which is
//! the recipe default. The Java side reads it as the id of a Rust holder.
//!
//! `ERR` carries the `Debug` form of the error after one space, for
//! example `ERR NoNode`. A bad command gives `ERR BadCommand <text>`. A
//! command that does not agree with the peer state gives
//! `ERR BadState <text>`, for example `UNLOCK` with no held lock.
//!
//! The peer holds at most one lock guard and one latch. A `LOCK` that
//! times out and an `ABANDON_LOCK` drop an `acquire` future that waits.
//! The drop submits the delete of the participant node. The
//! peer then sends one more request on the lock path and awaits it.
//! The server replies in request order, so the delete is applied when
//! the reply line goes out. The Java side can thus check the nodes at
//! once.
//!
//! `DROP_LOCK` drops the held guard and replies at once. The drop sends
//! the `delete`, and the guaranteed delete of the recipes sends it again
//! when a connection loss stops it. Thus the Java side can cut the
//! connection at the `delete` and see the retry with no other command.
//!
//! `ABANDON_LOCK` expects a held lock. When its `acquire` completes
//! before the delay, the peer drops the guard and replies
//! `ERR Acquired <node-name>`.
//!
//! `interop/curator/README.md` gives the meaning of each command, the
//! test cases and the run steps.

// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

use std::io::{BufRead, Write};
use std::time::Duration;

use apache_zookeeper::{Client, Error, Runtime, ThreadOptions, ZPath};
use apache_zookeeper_recipes::{DistributedLock, Latch, LeaderLatch, LockGuard};

/// The session timeout of the peer client.
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// The marker of a latch node name.
const LATCH_MARKER: &str = "-latch-";

/// One parsed command line.
enum Command {
    Lock {
        path: String,
        timeout: Duration,
        data: Vec<u8>,
    },
    TryLock {
        path: String,
        data: Vec<u8>,
    },
    Unlock,
    DropLock,
    AbandonLock {
        path: String,
        after: Duration,
    },
    Latch {
        path: String,
        id: String,
    },
    AwaitLeader {
        timeout: Duration,
    },
    IsLeader,
    Participants,
    CloseLatch,
    Session,
    Quit,
}

impl Command {
    /// Parses one line. The error is the reply line.
    fn parse(line: &str) -> Result<Self, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let bad = || format!("ERR BadCommand {line}");
        let ms = |w: &str| {
            w.parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|_| bad())
        };
        match words.as_slice() {
            ["LOCK", path, t, data @ ..] if data.len() <= 1 => Ok(Self::Lock {
                path: (*path).to_owned(),
                timeout: ms(t)?,
                data: node_data(data),
            }),
            ["TRYLOCK", path, data @ ..] if data.len() <= 1 => Ok(Self::TryLock {
                path: (*path).to_owned(),
                data: node_data(data),
            }),
            ["UNLOCK"] => Ok(Self::Unlock),
            ["DROP_LOCK"] => Ok(Self::DropLock),
            ["ABANDON_LOCK", path, t] => Ok(Self::AbandonLock {
                path: (*path).to_owned(),
                after: ms(t)?,
            }),
            ["LATCH", path, id] if !id.contains(':') => Ok(Self::Latch {
                path: (*path).to_owned(),
                id: (*id).to_owned(),
            }),
            ["AWAIT_LEADER", t] => Ok(Self::AwaitLeader { timeout: ms(t)? }),
            ["IS_LEADER"] => Ok(Self::IsLeader),
            ["PARTICIPANTS"] => Ok(Self::Participants),
            ["CLOSE_LATCH"] => Ok(Self::CloseLatch),
            ["SESSION"] => Ok(Self::Session),
            ["QUIT"] => Ok(Self::Quit),
            _ => Err(bad()),
        }
    }
}

/// The state of the peer between commands.
struct Peer {
    client: Client,
    /// The held lock, after `LOCK` or `TRYLOCK`.
    guard: Option<LockGuard>,
    /// The started latch, after `LATCH`.
    latch: Option<Latch>,
}

impl Peer {
    /// Runs one command and gives its reply line.
    async fn run(&mut self, cmd: Command) -> String {
        let reply = match cmd {
            Command::Lock {
                path,
                timeout,
                data,
            } => self.lock(&path, timeout, data).await,
            Command::TryLock { path, data } => self.try_lock(&path, data).await,
            Command::Unlock => self.unlock().await,
            Command::DropLock => self.drop_lock(),
            Command::AbandonLock { path, after } => self.abandon_lock(&path, after).await,
            Command::Latch { path, id } => self.start_latch(&path, id).await,
            Command::AwaitLeader { timeout } => self.await_leader(timeout).await,
            Command::IsLeader => Ok(format!(
                "OK {}",
                self.latch.as_ref().is_some_and(Latch::is_leader)
            )),
            Command::Participants => self.participants().await,
            Command::CloseLatch => self.close_latch().await,
            Command::Session => {
                let (id, pw) = self.client.session();
                Ok(format!("OK {:x} {}", id.0, hex(pw.as_bytes())))
            }
            Command::Quit => {
                // The drops submit the deletes. The close of the client
                // then ends the session in any case.
                self.guard = None;
                self.latch = None;
                Ok("OK".to_owned())
            }
        };
        reply.unwrap_or_else(|e| e)
    }

    /// `LOCK`: waits for the lock up to `timeout`.
    async fn lock(
        &mut self,
        path: &str,
        timeout: Duration,
        data: Vec<u8>,
    ) -> Result<String, String> {
        self.no_guard()?;
        let lock = DistributedLock::new(&self.client, path)
            .map_err(err)?
            .node_data(data);
        match tokio::time::timeout(timeout, lock.acquire()).await {
            Ok(Ok(guard)) => Ok(format!("OK {}", self.hold(guard))),
            Ok(Err(e)) => Err(err(e)),
            Err(_) => {
                self.barrier(path).await?;
                Ok("TIMEOUT".to_owned())
            }
        }
    }

    /// `TRYLOCK`: takes the lock only when it is free.
    async fn try_lock(&mut self, path: &str, data: Vec<u8>) -> Result<String, String> {
        self.no_guard()?;
        let lock = DistributedLock::new(&self.client, path)
            .map_err(err)?
            .node_data(data);
        match lock.try_acquire().await.map_err(err)? {
            Some(guard) => Ok(format!("OK {}", self.hold(guard))),
            None => Ok("NONE".to_owned()),
        }
    }

    /// `UNLOCK`: releases the held lock and gives the server result.
    async fn unlock(&mut self) -> Result<String, String> {
        let guard = self
            .guard
            .take()
            .ok_or_else(|| "ERR BadState no lock held".to_owned())?;
        guard.release().await.map_err(err)?;
        Ok("OK".to_owned())
    }

    /// `DROP_LOCK`: drops the held guard with no wait for the `delete`.
    fn drop_lock(&mut self) -> Result<String, String> {
        self.guard
            .take()
            .map(drop)
            .ok_or_else(|| "ERR BadState no lock held".to_owned())?;
        Ok("OK".to_owned())
    }

    /// `ABANDON_LOCK`: starts an `acquire` and drops it after `after`.
    async fn abandon_lock(&mut self, path: &str, after: Duration) -> Result<String, String> {
        let lock = DistributedLock::new(&self.client, path).map_err(err)?;
        let outcome = tokio::time::timeout(after, lock.acquire()).await;
        // The drop of the future, or of the guard, submits the delete.
        self.barrier(path).await?;
        match outcome {
            Err(_) => Ok("OK".to_owned()),
            Ok(Ok(guard)) => {
                let name = node_name(guard.node());
                drop(guard);
                self.barrier(path).await?;
                Err(format!("ERR Acquired {name}"))
            }
            Ok(Err(e)) => Err(err(e)),
        }
    }

    /// `LATCH`: starts a latch with the participant id `id`.
    async fn start_latch(&mut self, path: &str, id: String) -> Result<String, String> {
        if self.latch.is_some() {
            return Err("ERR BadState a latch runs".to_owned());
        }
        let latch = LeaderLatch::new(&self.client, path, id.into_bytes())
            .map_err(err)?
            .start()
            .await
            .map_err(err)?;
        self.latch = Some(latch);
        let name = self.latch_node(path).await?;
        Ok(format!("OK {name}"))
    }

    /// `AWAIT_LEADER`: waits for leadership up to `timeout`. The latch
    /// keeps its state when the timeout drops the wait.
    async fn await_leader(&mut self, timeout: Duration) -> Result<String, String> {
        let latch = self.latch_mut()?;
        match tokio::time::timeout(timeout, latch.await_leadership()).await {
            Ok(Ok(())) => Ok("OK".to_owned()),
            Ok(Err(e)) => Err(err(e)),
            Err(_) => Ok("TIMEOUT".to_owned()),
        }
    }

    /// `PARTICIPANTS`: the ids and the leader flags in latch order.
    async fn participants(&mut self) -> Result<String, String> {
        let all = self.latch_mut()?.participants().await.map_err(err)?;
        let mut line = "OK".to_owned();
        for p in all {
            line.push(' ');
            line.push_str(&String::from_utf8_lossy(&p.id));
            line.push_str(if p.is_leader { ":1" } else { ":0" });
        }
        Ok(line)
    }

    /// `CLOSE_LATCH`: deletes the latch node and gives the server result.
    async fn close_latch(&mut self) -> Result<String, String> {
        let latch = self
            .latch
            .take()
            .ok_or_else(|| "ERR BadState no latch".to_owned())?;
        latch.close().await.map_err(err)?;
        Ok("OK".to_owned())
    }

    /// Keeps `guard` and gives the name of its node.
    fn hold(&mut self, guard: LockGuard) -> String {
        let name = node_name(guard.node());
        self.guard = Some(guard);
        name
    }

    /// Refuses a second lock, because the lock is not reentrant.
    fn no_guard(&self) -> Result<(), String> {
        match self.guard {
            Some(_) => Err("ERR BadState a lock is held".to_owned()),
            None => Ok(()),
        }
    }

    /// The started latch, or the reply for a peer with no latch.
    fn latch_mut(&mut self) -> Result<&mut Latch, String> {
        self.latch
            .as_mut()
            .ok_or_else(|| "ERR BadState no latch".to_owned())
    }

    /// Sends one read on `path` and awaits it. The server answers in
    /// request order, so each request that a drop submitted before is
    /// applied when this read completes.
    async fn barrier(&self, path: &str) -> Result<(), String> {
        self.client.exists(path).await.map(drop).map_err(err)
    }

    /// The name of the latch node of this session under `path`.
    ///
    /// The `Latch` API does not give its node. The session has one latch
    /// at a time, so its one ephemeral latch child under `path` is the
    /// node. `GetEphemerals` needs server 3.6 or later.
    async fn latch_node(&self, path: &str) -> Result<String, String> {
        let parent = ZPath::new(path).map_err(|e| err(Error::from(e)))?;
        let nodes = self.client.get_ephemerals(parent).await.map_err(err)?;
        nodes
            .iter()
            .map(|n| n.as_path())
            .find(|n| n.parent() == Some(parent) && n.name().is_some_and(is_latch_name))
            .map(node_name)
            .ok_or_else(|| "ERR NoNode".to_owned())
    }
}

/// Gives true for a protected latch node name, `_c_<uuid>-latch-<seq>`.
fn is_latch_name(name: &str) -> bool {
    name.starts_with("_c_") && name.contains(LATCH_MARKER)
}

/// The node data of an optional `<data>` word: its UTF-8 bytes, or empty.
fn node_data(words: &[&str]) -> Vec<u8> {
    words
        .first()
        .map(|w| w.as_bytes().to_vec())
        .unwrap_or_default()
}

/// The last component of a node path.
fn node_name(path: ZPath<'_>) -> String {
    path.name().unwrap_or_default().to_owned()
}

/// The `ERR` reply of an error.
fn err(e: Error) -> String {
    format!("ERR {e:?}")
}

/// The lowercase hex form of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes one reply line and flushes it, so the Java reader sees it.
fn reply(out: &mut impl Write, line: &str) -> std::io::Result<()> {
    writeln!(out, "{line}")?;
    out.flush()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connect = std::env::args()
        .nth(1)
        .ok_or("usage: interop_peer <connect-string>")?;
    let client = Client::builder(connect)
        .session_timeout(SESSION_TIMEOUT)
        .runtime(Runtime::Thread(ThreadOptions::default()))
        .connect()
        .await?;
    let mut peer = Peer {
        client,
        guard: None,
        latch: None,
    };
    let mut out = std::io::stdout().lock();
    reply(&mut out, "READY")?;
    // The reads of stdin block. The peer serves one command at a time,
    // and the client IO thread runs while it blocks.
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let (text, quit) = match Command::parse(&line) {
            Ok(cmd) => {
                let quit = matches!(cmd, Command::Quit);
                (peer.run(cmd).await, quit)
            }
            Err(text) => (text, false),
        };
        // The trace of each command helps when a JUnit test fails.
        writeln!(std::io::stderr().lock(), "interop_peer: {line} -> {text}")?;
        reply(&mut out, &text)?;
        if quit {
            break;
        }
    }
    peer.client.close().await?;
    Ok(())
}
