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

//! A small blocking client for tests.
//!
//! The client speaks the wire protocol with the `zk-jute` records and
//! nothing more. It has no session logic, no reconnect and no watch
//! table, so a test sees each frame that the server sends.

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use zk_jute::handshake::{ConnectRequest, ConnectResponse, PASSWD_LEN, decode_connect_response};
use zk_jute::proto::{ReplyHeader, RequestHeader, WatcherEvent};
use zk_jute::{DecodeError, FrameDecoder, Pushed, Reader, Record, begin_frame, finish_frame};

/// The default wait of the client for one frame.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(5);

/// A reply frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawReply {
    /// The xid.
    pub xid: i32,
    /// The zxid.
    pub zxid: i64,
    /// The error code.
    pub err: i32,
    /// The bytes after the reply header.
    pub body: Vec<u8>,
}

impl RawReply {
    /// Decodes the body as a record.
    ///
    /// # Errors
    ///
    /// Returns the decode error.
    pub fn decode<T: Record>(&self) -> Result<T, DecodeError> {
        T::from_bytes(&self.body)
    }

    /// Decodes a frame body.
    ///
    /// # Errors
    ///
    /// Returns the decode error for a body shorter than a reply header.
    pub fn parse(frame: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(frame);
        let h = ReplyHeader::decode(&mut r)?;
        Ok(Self {
            xid: h.xid,
            zxid: h.zxid,
            err: h.err,
            body: r.rest().to_vec(),
        })
    }
}

/// A watch event frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    /// The zxid in the header.
    pub zxid: i64,
    /// The event type.
    pub event_type: i32,
    /// The keeper state.
    pub state: i32,
    /// The path.
    pub path: String,
}

/// A blocking test client over one TCP connection.
#[derive(Debug)]
pub struct RawClient {
    stream: TcpStream,
    dec: FrameDecoder,
    frames: VecDeque<Vec<u8>>,
    events: VecDeque<RawEvent>,
    replies: VecDeque<RawReply>,
    next_xid: i32,
    eof: bool,
}

fn timed_out() -> io::Error {
    io::Error::new(ErrorKind::TimedOut, "no frame before the timeout")
}

fn eof() -> io::Error {
    io::Error::new(ErrorKind::UnexpectedEof, "the server closed the connection")
}

impl RawClient {
    /// Opens a TCP connection with no handshake.
    ///
    /// # Errors
    ///
    /// Returns the connect error.
    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, DEFAULT_WAIT)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            dec: FrameDecoder::new(None),
            frames: VecDeque::new(),
            events: VecDeque::new(),
            replies: VecDeque::new(),
            next_xid: 1,
            eof: false,
        })
    }

    /// Opens a connection and a new session.
    ///
    /// # Errors
    ///
    /// Returns an I/O error, or `UnexpectedEof` when the server closes the
    /// connection with no response.
    pub fn open(addr: SocketAddr, timeout_ms: i32) -> io::Result<(Self, ConnectResponse)> {
        Self::open_with(
            addr,
            &ConnectRequest {
                time_out: timeout_ms,
                ..ConnectRequest::default()
            },
        )
    }

    /// Opens a connection and sends this connect request.
    ///
    /// # Errors
    ///
    /// Returns an I/O error, or `UnexpectedEof` when the server closes the
    /// connection with no response.
    pub fn open_with(
        addr: SocketAddr,
        req: &ConnectRequest,
    ) -> io::Result<(Self, ConnectResponse)> {
        let mut c = Self::connect(addr)?;
        let resp = c.handshake(req)?;
        Ok((c, resp))
    }

    /// Resumes a session on a new connection.
    ///
    /// # Errors
    ///
    /// As for [`RawClient::open`].
    pub fn resume(
        addr: SocketAddr,
        session_id: i64,
        passwd: [u8; PASSWD_LEN],
        timeout_ms: i32,
        last_zxid_seen: i64,
    ) -> io::Result<(Self, ConnectResponse)> {
        Self::open_with(
            addr,
            &ConnectRequest {
                time_out: timeout_ms,
                session_id,
                passwd,
                last_zxid_seen,
                ..ConnectRequest::default()
            },
        )
    }

    /// Sends a connect request and reads the response.
    ///
    /// # Errors
    ///
    /// Returns an I/O error, `UnexpectedEof` when the server closes the
    /// connection, or `InvalidData` for a bad response length.
    pub fn handshake(&mut self, req: &ConnectRequest) -> io::Result<ConnectResponse> {
        self.send_raw(&req.encode_frame())?;
        let body = self.read_frame(DEFAULT_WAIT)?;
        decode_connect_response(&body).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }

    /// Returns the socket.
    #[must_use]
    pub const fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Writes bytes with no framing.
    ///
    /// # Errors
    ///
    /// Returns the write error.
    pub fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }

    /// Returns the next xid and moves the counter.
    pub fn take_xid(&mut self) -> i32 {
        let x = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        x
    }

    /// Sends a request frame with this xid and opcode. `body` is the
    /// encoded request record, or empty.
    ///
    /// # Errors
    ///
    /// Returns the write error.
    pub fn send(&mut self, xid: i32, op: i32, body: &[u8]) -> io::Result<()> {
        let mut out = Vec::new();
        let start = begin_frame(&mut out);
        RequestHeader { xid, r#type: op }.encode(&mut out);
        out.extend_from_slice(body);
        finish_frame(&mut out, start);
        self.send_raw(&out)
    }

    /// Sends a request with the next xid. It returns the xid.
    ///
    /// # Errors
    ///
    /// Returns the write error.
    pub fn send_record<R: Record>(&mut self, op: i32, req: &R) -> io::Result<i32> {
        let xid = self.take_xid();
        self.send(xid, op, &req.to_bytes())?;
        Ok(xid)
    }

    /// Reads the next frame body.
    ///
    /// # Errors
    ///
    /// Returns `TimedOut`, `UnexpectedEof`, `InvalidData` for a bad length
    /// prefix, or the read error.
    pub fn read_frame(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        let deadline = Instant::now().checked_add(timeout);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if let Some(f) = self.frames.pop_front() {
                return Ok(f);
            }
            if self.eof {
                return Err(eof());
            }
            let left = deadline
                .and_then(|d| d.checked_duration_since(Instant::now()))
                .filter(|d| !d.is_zero())
                .ok_or_else(timed_out)?;
            self.stream.set_read_timeout(Some(left))?;
            match self.stream.read(&mut buf) {
                Ok(0) => self.eof = true,
                Ok(n) => self.feed(buf.get(..n).unwrap_or_default())?,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(e) if e.kind() == ErrorKind::ConnectionReset => self.eof = true,
                Err(e) => return Err(e),
            }
        }
    }

    fn feed(&mut self, data: &[u8]) -> io::Result<()> {
        let mut data = data;
        while !data.is_empty() {
            let (n, p) = self.dec.push(data);
            data = data.get(n..).unwrap_or_default();
            match p {
                Pushed::Frame(f) => self.frames.push_back(f),
                Pushed::NeedMore => {}
                Pushed::Error(e) => return Err(io::Error::new(ErrorKind::InvalidData, e)),
            }
        }
        Ok(())
    }

    /// Reads one frame and sorts it into the event or the reply queue.
    fn read_one(&mut self, timeout: Duration) -> io::Result<()> {
        let f = self.read_frame(timeout)?;
        let r = RawReply::parse(&f).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        if r.xid == zk_jute::xid::WATCHER_EVENT {
            let ev = WatcherEvent::from_bytes(&r.body)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            self.events.push_back(RawEvent {
                zxid: r.zxid,
                event_type: ev.r#type,
                state: ev.state,
                path: ev.path.as_str().unwrap_or("").to_owned(),
            });
        } else {
            self.replies.push_back(r);
        }
        Ok(())
    }

    /// Returns the next reply that is not a watch event. Events that come
    /// first go to the event queue.
    ///
    /// # Errors
    ///
    /// As for [`RawClient::read_frame`], and `InvalidData` for a frame that
    /// is too short.
    pub fn read_reply(&mut self, timeout: Duration) -> io::Result<RawReply> {
        loop {
            if let Some(r) = self.replies.pop_front() {
                return Ok(r);
            }
            self.read_one(timeout)?;
        }
    }

    /// Sends a request and reads its reply.
    ///
    /// # Errors
    ///
    /// As for [`RawClient::read_reply`], and `InvalidData` when the next
    /// reply has another xid.
    pub fn call<R: Record>(&mut self, op: i32, req: &R) -> io::Result<RawReply> {
        let xid = self.send_record(op, req)?;
        self.expect_reply(xid)
    }

    /// Sends a request with no body and reads its reply.
    ///
    /// # Errors
    ///
    /// As for [`RawClient::call`].
    pub fn call_empty(&mut self, op: i32) -> io::Result<RawReply> {
        let xid = self.take_xid();
        self.send(xid, op, &[])?;
        self.expect_reply(xid)
    }

    /// Sends a ping with xid -2 and reads its reply.
    ///
    /// # Errors
    ///
    /// As for [`RawClient::read_reply`].
    pub fn ping(&mut self) -> io::Result<RawReply> {
        self.send(zk_jute::xid::PING, zk_jute::opcode::PING, &[])?;
        self.read_reply(DEFAULT_WAIT)
    }

    fn expect_reply(&mut self, xid: i32) -> io::Result<RawReply> {
        let r = self.read_reply(DEFAULT_WAIT)?;
        if r.xid != xid {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("reply xid {} for request xid {xid}", r.xid),
            ));
        }
        Ok(r)
    }

    /// Returns the next watch event. Replies that come first go to the
    /// reply queue.
    ///
    /// # Errors
    ///
    /// As for [`RawClient::read_frame`].
    pub fn next_event(&mut self, timeout: Duration) -> io::Result<RawEvent> {
        loop {
            if let Some(e) = self.events.pop_front() {
                return Ok(e);
            }
            self.read_one(timeout)?;
        }
    }

    /// Removes and returns the queued watch events.
    pub fn take_events(&mut self) -> Vec<RawEvent> {
        self.events.drain(..).collect()
    }

    /// Returns true when the server closes the connection before the
    /// timeout. Frames that arrive first are kept.
    pub fn wait_closed(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now().checked_add(timeout);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if self.eof {
                return true;
            }
            let Some(left) = deadline
                .and_then(|d| d.checked_duration_since(Instant::now()))
                .filter(|d| !d.is_zero())
            else {
                return false;
            };
            if self.stream.set_read_timeout(Some(left)).is_err() {
                return true;
            }
            match self.stream.read(&mut buf) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    if self.feed(buf.get(..n).unwrap_or_default()).is_err() {
                        return true;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(_) => self.eof = true,
            }
        }
    }

    /// Closes both directions of the socket.
    pub fn shutdown(&self) {
        drop(self.stream.shutdown(Shutdown::Both));
    }
}
