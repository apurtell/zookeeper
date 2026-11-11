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

//! A loopback TCP proxy for the real-server tests.
//!
//! The zk-client tests and the zk-recipes tests share this file. The
//! recipes `common` module includes it with a `#[path]` attribute.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A loopback TCP proxy in front of a server.
///
/// While it is cut, it closes every open connection and every new one
/// at once, and drops all bytes. While it holds, it keeps every
/// connection open and drops all bytes. While it is mute, it forwards
/// the bytes to the server and drops the bytes from the server. A test
/// uses it to end or stall the connections of one client while the
/// server stays up.
pub struct Proxy {
    addr: std::net::SocketAddr,
    inner: Arc<ProxyInner>,
}

struct ProxyInner {
    target: std::net::SocketAddr,
    mode: AtomicU8,
    /// The pause in milliseconds before each forwarded chunk.
    delay_ms: AtomicU64,
    stop: AtomicBool,
    conns: Mutex<Vec<std::net::TcpStream>>,
}

/// The proxy forwards bytes.
const OPEN: u8 = 0;
/// The proxy closes every connection and drops all bytes.
const CUT: u8 = 1;
/// The proxy keeps connections open and drops all bytes.
const HOLD: u8 = 2;
/// The proxy forwards requests and drops the replies.
const MUTE: u8 = 3;

impl Proxy {
    /// Starts a proxy on a free loopback port that forwards to
    /// `127.0.0.1:target_port`.
    pub fn start(target_port: u16) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let addr = listener.local_addr().expect("proxy addr");
        let inner = Arc::new(ProxyInner {
            target: std::net::SocketAddr::from(([127, 0, 0, 1], target_port)),
            mode: AtomicU8::new(OPEN),
            delay_ms: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            conns: Mutex::new(Vec::new()),
        });
        let i2 = Arc::clone(&inner);
        std::thread::spawn(move || accept_loop(&listener, &i2));
        Self { addr, inner }
    }

    /// `127.0.0.1:PORT` of the proxy.
    pub fn connect_string(&self) -> String {
        self.addr.to_string()
    }

    /// Closes every connection, and closes new connections at once.
    pub fn cut(&self) {
        self.inner.mode.store(CUT, Ordering::SeqCst);
        self.inner.close_all();
    }

    /// Keeps every connection open and drops all bytes. New connections
    /// open, but nothing reaches the server.
    pub fn hold(&self) {
        self.inner.mode.store(HOLD, Ordering::SeqCst);
    }

    /// Forwards the bytes to the server and drops every byte from the
    /// server. A test uses it to let a request through and lose only
    /// its reply.
    pub fn mute_replies(&self) {
        self.inner.mode.store(MUTE, Ordering::SeqCst);
    }

    /// Forwards new connections in both directions again. A held
    /// connection stays broken, so the client must reconnect.
    pub fn restore(&self) {
        self.inner.mode.store(OPEN, Ordering::SeqCst);
    }

    /// Pauses for `d` before each forwarded chunk, in both directions.
    /// A zero `d` forwards at once. A test uses it to make each round
    /// trip slow, so that a long read is still in progress when the
    /// test acts.
    pub fn delay(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.inner.delay_ms.store(ms, Ordering::SeqCst);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.close_all();
        // The connect wakes the accept call, so the thread sees the stop.
        let _ = std::net::TcpStream::connect(self.addr);
    }
}

impl ProxyInner {
    fn close_all(&self) {
        let conns = std::mem::take(&mut *self.conns.lock().unwrap_or_else(|e| e.into_inner()));
        for c in conns {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Tells if the proxy drops a chunk now. `from_server` marks the
    /// direction from the server to the client. A cut drops every chunk,
    /// so a muted reply also stays lost while the cut closes the
    /// connections.
    fn drops(&self, from_server: bool) -> bool {
        match self.mode.load(Ordering::SeqCst) {
            CUT | HOLD => true,
            MUTE => from_server,
            _ => false,
        }
    }
}

fn accept_loop(listener: &std::net::TcpListener, inner: &Arc<ProxyInner>) {
    for client in listener.incoming() {
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(client) = client else { continue };
        match inner.mode.load(Ordering::SeqCst) {
            CUT => {
                let _ = client.shutdown(std::net::Shutdown::Both);
                continue;
            }
            HOLD => {
                inner
                    .conns
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(client);
                continue;
            }
            _ => {}
        }
        let Ok(server) = std::net::TcpStream::connect(inner.target) else {
            let _ = client.shutdown(std::net::Shutdown::Both);
            continue;
        };
        let _ = client.set_nodelay(true);
        let _ = server.set_nodelay(true);
        let pair = (
            client.try_clone(),
            server.try_clone(),
            client.try_clone(),
            server.try_clone(),
        );
        let (Ok(c1), Ok(s1), Ok(c2), Ok(s2)) = pair else {
            continue;
        };
        {
            let mut conns = inner.conns.lock().unwrap_or_else(|e| e.into_inner());
            conns.push(c2);
            conns.push(s2);
        }
        let (i1, i2) = (Arc::clone(inner), Arc::clone(inner));
        std::thread::spawn(move || pump(client, server, &i1, false));
        std::thread::spawn(move || pump(s1, c1, &i2, true));
    }
}

/// Copies bytes from `from` to `to` until either side ends, then shuts
/// both down. It drops the bytes that the mode of the proxy drops.
fn pump(
    mut from: std::net::TcpStream,
    mut to: std::net::TcpStream,
    inner: &ProxyInner,
    from_server: bool,
) {
    use std::io::{Read, Write};
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if inner.drops(from_server) {
            continue;
        }
        let delay = inner.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = from.shutdown(std::net::Shutdown::Both);
    let _ = to.shutdown(std::net::Shutdown::Both);
}
