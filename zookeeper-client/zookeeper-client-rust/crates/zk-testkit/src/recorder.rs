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

//! The ordered record of everything that a harness run did.
//!
//! The harness records each output of the core in pop order, and each
//! driver input that it gave to the core. Tests read the record to check
//! the order of outputs and the exactly-once delivery of tokens.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use zk_proto::{
    InterestOutcome, LogRecord, Millis, OpResult, Output, ProbeOutcome, ReadOutcome, Route, Stage,
    State, TransportFailure, WatchedEvent,
};

use crate::net::ConnectPlan;
use crate::tokens::{AuthTicket, TestTokens, Ticket, WatcherId};

/// The kind of one mechanism call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaslKind {
    /// A `start` call.
    Start,
    /// A `step` call with this challenge.
    Step(Option<Vec<u8>>),
    /// The end of the session.
    Dispose,
}

/// One action that the harness ran for the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionRecord {
    /// A resolution of the host list.
    Resolve {
        /// The generation of the resolution.
        generation: u64,
        /// The number of host entries.
        hosts: usize,
        /// True for the first resolution of the handle.
        initial: bool,
        /// The rc of `handle_resolved`.
        rc: i32,
    },
    /// A connect attempt.
    Connect {
        /// The target address.
        addr: SocketAddr,
        /// True when the core asked for TLS. The harness has no TLS, so
        /// the connect is plain.
        tls: bool,
        /// The plan that applied.
        plan: ConnectPlan,
    },
    /// A close of the transport.
    CloseTransport,
    /// A read-write probe.
    ProbeRw {
        /// The probed address.
        addr: SocketAddr,
        /// The outcome that the harness gave.
        outcome: ProbeOutcome,
    },
    /// A mechanism call.
    Sasl {
        /// The SASL generation of the call.
        generation: u32,
        /// The call.
        kind: SaslKind,
    },
}

/// One recorded event.
#[derive(Debug)]
pub enum Event {
    /// An output of the core, in pop order.
    Output(Output<TestTokens>),
    /// The handle that `take_stopped` gave.
    Stopped(u64),
    /// The harness called `resume` with this handle.
    Resumed(u64),
    /// An action that the harness ran.
    Action(ActionRecord),
    /// The result of `finish_interest`.
    Interest(InterestOutcome),
    /// The rc of a refused `begin_interest`.
    InterestRefused(i32),
    /// One `handle_read` call.
    Read {
        /// The number of bytes that the harness gave.
        len: usize,
        /// The result.
        outcome: ReadOutcome,
    },
    /// One write to the server.
    Transmit {
        /// The bytes that the server took.
        bytes: usize,
    },
    /// One `handle_transport_failed` call.
    Failure {
        /// The failure.
        failure: TransportFailure,
        /// The rc of the call.
        rc: i32,
    },
    /// A queued submit.
    Submitted {
        /// The ticket of the request.
        ticket: Ticket,
        /// The xid of the request.
        xid: i32,
    },
    /// A submit that completed locally. The token came back at once.
    SubmitLocal(Ticket),
    /// A refused submit. The token came back at once.
    SubmitRejected {
        /// The ticket of the request.
        ticket: Ticket,
        /// The stage of the failure.
        stage: Stage,
        /// The legacy code.
        code: i32,
    },
    /// An accepted `add_auth`.
    AuthAdded(Option<AuthTicket>),
    /// A refused `add_auth`.
    AuthRejected {
        /// The ticket that came back.
        ticket: Option<AuthTicket>,
        /// The legacy code.
        code: i32,
    },
    /// The rc of one mechanism result that the harness gave to the core.
    SaslResult {
        /// The SASL generation.
        generation: u32,
        /// The rc of the `handle_sasl_*` call.
        rc: i32,
    },
    /// A free-form note from a test or the harness.
    Note(String),
}

/// One entry of the record.
#[derive(Debug)]
pub struct Recorded {
    /// The position in the record, from 0.
    pub seq: u64,
    /// The harness time of the event.
    pub at: Millis,
    /// The event.
    pub event: Event,
}

/// The completion of one ticket, as the record shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery<'a> {
    /// A `Completion` output.
    Completion(&'a OpResult),
    /// A local completion at submit.
    Local,
    /// A refused submit.
    Rejected(i32),
}

/// The ordered record of a harness run.
#[derive(Debug, Default)]
pub struct Recorder {
    items: Vec<Recorded>,
    issued: BTreeSet<Ticket>,
    leftover: Vec<Ticket>,
}

impl Recorder {
    /// Makes an empty record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an event.
    pub fn push(&mut self, at: Millis, event: Event) {
        let seq = u64::try_from(self.items.len()).unwrap_or(u64::MAX);
        self.items.push(Recorded { seq, at, event });
    }

    /// Notes that a test gave this ticket to the core.
    pub fn issue(&mut self, ticket: Ticket) {
        self.issued.insert(ticket);
    }

    /// Notes that this ticket came back in the leftovers of the
    /// connection.
    pub fn leftover(&mut self, ticket: Ticket) {
        self.leftover.push(ticket);
    }

    /// Returns every entry, oldest first.
    #[must_use]
    pub fn all(&self) -> &[Recorded] {
        &self.items
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when the record is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns a mark for [`Recorder::since`].
    #[must_use]
    pub fn mark(&self) -> usize {
        self.items.len()
    }

    /// Returns the entries after a mark.
    #[must_use]
    pub fn since(&self, mark: usize) -> &[Recorded] {
        self.items.get(mark..).unwrap_or_default()
    }

    /// Returns the outputs, in pop order.
    pub fn outputs(&self) -> impl Iterator<Item = &Output<TestTokens>> {
        self.items.iter().filter_map(|r| match &r.event {
            Event::Output(o) => Some(o),
            _ => None,
        })
    }

    /// Returns the outputs after a mark, in pop order.
    pub fn outputs_since(&self, mark: usize) -> impl Iterator<Item = &Output<TestTokens>> {
        self.since(mark).iter().filter_map(|r| match &r.event {
            Event::Output(o) => Some(o),
            _ => None,
        })
    }

    /// Returns the actions, in order.
    pub fn actions(&self) -> impl Iterator<Item = &ActionRecord> {
        self.items.iter().filter_map(|r| match &r.event {
            Event::Action(a) => Some(a),
            _ => None,
        })
    }

    /// Returns the transport failures that the harness reported, in order.
    pub fn failures(&self) -> impl Iterator<Item = (&TransportFailure, i32)> {
        self.items.iter().filter_map(|r| match &r.event {
            Event::Failure { failure, rc } => Some((failure, *rc)),
            _ => None,
        })
    }

    /// Returns the completion result of a ticket, if a `Completion` output
    /// carried it.
    #[must_use]
    pub fn completion(&self, ticket: Ticket) -> Option<&OpResult> {
        self.outputs().find_map(|o| match o {
            Output::Completion { token, result, .. } if token.ticket() == ticket => Some(result),
            _ => None,
        })
    }

    /// Returns the route of the completion of a ticket.
    #[must_use]
    pub fn completion_route(&self, ticket: Ticket) -> Option<Route> {
        self.outputs().find_map(|o| match o {
            Output::Completion { token, route, .. } if token.ticket() == ticket => Some(*route),
            _ => None,
        })
    }

    /// Returns how a ticket completed: a `Completion` output, a local
    /// completion or a refused submit.
    #[must_use]
    pub fn delivery(&self, ticket: Ticket) -> Option<Delivery<'_>> {
        self.items.iter().find_map(|r| match &r.event {
            Event::Output(Output::Completion { token, result, .. }) if token.ticket() == ticket => {
                Some(Delivery::Completion(result))
            }
            Event::SubmitLocal(t) if *t == ticket => Some(Delivery::Local),
            Event::SubmitRejected {
                ticket: t, code, ..
            } if *t == ticket => Some(Delivery::Rejected(*code)),
            _ => None,
        })
    }

    /// Returns the number of `Completion` outputs of a ticket.
    #[must_use]
    pub fn completion_count(&self, ticket: Ticket) -> usize {
        self.outputs()
            .filter(|o| matches!(o, Output::Completion { token, .. } if token.ticket() == ticket))
            .count()
    }

    /// Returns the tickets of the `Completion` outputs, in pop order.
    #[must_use]
    pub fn completion_order(&self) -> Vec<Ticket> {
        self.outputs()
            .filter_map(|o| match o {
                Output::Completion { token, .. } => Some(token.ticket()),
                _ => None,
            })
            .collect()
    }

    /// Returns the watch events and their watchers, in pop order.
    #[must_use]
    pub fn watch_events(&self) -> Vec<(&WatchedEvent, &[WatcherId])> {
        self.outputs()
            .filter_map(|o| match o {
                Output::Watch {
                    event, watchers, ..
                } => Some((event, watchers.as_slice())),
                _ => None,
            })
            .collect()
    }

    /// Returns the states of the session events, in pop order.
    #[must_use]
    pub fn session_states(&self) -> Vec<State> {
        self.outputs()
            .filter_map(|o| match o {
                Output::Session { state, .. } => Some(*state),
                _ => None,
            })
            .collect()
    }

    /// Returns the rc values of the auth outputs, in pop order.
    #[must_use]
    pub fn auth_results(&self) -> Vec<(Vec<AuthTicket>, i32)> {
        self.outputs()
            .filter_map(|o| match o {
                Output::Auth { tokens, rc, .. } => {
                    Some((tokens.iter().map(|t| t.ticket()).collect(), *rc))
                }
                _ => None,
            })
            .collect()
    }

    /// Returns every log record in pop order: the `Log` outputs and the
    /// delivery logs of other outputs.
    #[must_use]
    pub fn logs(&self) -> Vec<&LogRecord> {
        let mut out = Vec::new();
        for o in self.outputs() {
            match o {
                Output::Log(r) => out.push(r),
                Output::Completion { delivery_logs, .. }
                | Output::Watch { delivery_logs, .. }
                | Output::Session { delivery_logs, .. } => out.extend(delivery_logs.iter()),
                _ => {}
            }
        }
        out
    }

    /// Checks that each issued ticket completed exactly once. A ticket in
    /// the leftovers counts as one completion.
    ///
    /// # Errors
    ///
    /// Returns a text that names each ticket with no completion or with
    /// more than one.
    pub fn check_exactly_once(&self) -> Result<(), String> {
        let mut seen: BTreeMap<Ticket, usize> = BTreeMap::new();
        for r in &self.items {
            let t = match &r.event {
                Event::Output(Output::Completion { token, .. }) => Some(token.ticket()),
                Event::SubmitLocal(t) | Event::SubmitRejected { ticket: t, .. } => Some(*t),
                _ => None,
            };
            if let Some(t) = t {
                let n = seen.entry(t).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
        for t in &self.leftover {
            let n = seen.entry(*t).or_insert(0);
            *n = n.saturating_add(1);
        }
        let mut bad = Vec::new();
        for t in &self.issued {
            let n = seen.get(t).copied().unwrap_or(0);
            if n != 1 {
                bad.push(format!("ticket {} completed {n} times", t.0));
            }
        }
        for t in seen.keys() {
            if !self.issued.contains(t) {
                bad.push(format!("ticket {} was never issued", t.0));
            }
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(bad.join("; "))
        }
    }
}
