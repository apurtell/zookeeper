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

//! The stream seam between the listener and the protocol loop.
//!
//! The connection loop reads and writes through [`Transport`]. Plain TCP
//! is the default. A TLS acceptor wraps the accepted socket in a TLS
//! stream and gives it to the same loop, so the protocol code does not
//! change.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

/// A server-side byte stream over an accepted TCP socket.
pub trait Transport: Read + Write + Send {
    /// Returns the socket under the stream. The loop uses it for timeouts
    /// and shutdown.
    fn tcp(&self) -> &TcpStream;

    /// Ends the stream before the loop shuts the socket down.
    ///
    /// `graceful` is false when a stop or a kill ends the connection. A
    /// stream with its own close step, such as a TLS close_notify, does it
    /// here. Plain TCP has nothing to do.
    fn finish(&mut self, _graceful: bool) {}
}

impl Transport for TcpStream {
    fn tcp(&self) -> &TcpStream {
        self
    }
}

/// Turns an accepted socket into a [`Transport`]. The connection thread
/// calls it, so a slow handshake does not block the listener.
pub trait Acceptor: Send + Sync + fmt::Debug {
    /// Wraps the socket. An error closes the connection.
    fn accept(&self, tcp: TcpStream) -> io::Result<Box<dyn Transport>>;
}

/// The plain TCP acceptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlainAcceptor;

impl Acceptor for PlainAcceptor {
    fn accept(&self, tcp: TcpStream) -> io::Result<Box<dyn Transport>> {
        Ok(Box::new(tcp))
    }
}
