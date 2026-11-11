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

//! Interest loop tests through the public `Connection` API: the
//! connect action and the whole-list resolve failure.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Test code may assert and panic.
#![allow(clippy::disallowed_macros)]

mod common;

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use common::Tk;
use zk_jute::{JString, rc};
use zk_proto::{
    Connection,
    action::{Action, HostResolution, InterestOutcome, ResolveError},
    compat::{Compat, DnsFailure, TlsVerify},
    config::{Config, DriverMode, HostSpec},
    hooks::{AllLevels, NoDefaultWatcher, Rng},
    legacy::connect::HostSpec as LegacyHostSpec,
    log::LogRecord,
    output::Output,
    time::Millis,
};

/// Returns the address of a `Connect` action.
fn connect_addr(a: &Action) -> SocketAddr {
    match a {
        Action::Connect { endpoint, .. } => endpoint.addr,
        other => panic!("not a Connect: {other:?}"),
    }
}

/// The scripted values and the call counts of [`TestRng`].
#[derive(Default)]
struct Draws {
    /// The next `random` values. An empty queue gives 0.
    random: VecDeque<i64>,
    /// The next `drand48` values. An empty queue gives 0.0.
    drand: VecDeque<f64>,
    /// The count of `random` calls.
    random_calls: usize,
    /// The count of `drand48` calls.
    drand_calls: usize,
    /// The count of `on_resolution` calls.
    resolutions: usize,
}

/// A scripted random source with shared call counts.
struct TestRng(Arc<Mutex<Draws>>);

impl Rng for TestRng {
    fn on_resolution(&mut self) {
        self.0.lock().unwrap().resolutions += 1;
    }
    fn random(&mut self) -> i64 {
        let mut d = self.0.lock().unwrap();
        d.random_calls += 1;
        d.random.pop_front().unwrap_or(0)
    }
    fn drand48(&mut self) -> f64 {
        let mut d = self.0.lock().unwrap();
        d.drand_calls += 1;
        d.drand.pop_front().unwrap_or(0.0)
    }
}

/// Returns a socket address.
fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Returns a legacy host entry.
fn host(name: &str, port: u16) -> HostSpec {
    HostSpec::Legacy(LegacyHostSpec {
        host: name.as_bytes().to_vec(),
        service: port.to_string().into_bytes(),
        port: i32::from(port),
    })
}

/// Makes a connection with the hosts `a:2181` and `b:2181`.
fn conn_with(
    compat: Compat,
    mode: DriverMode,
    edit: impl FnOnce(&mut Config),
) -> (Connection<Tk>, Arc<Mutex<Draws>>) {
    let mut cfg = Config::legacy(30_000);
    cfg.hosts = vec![host("a", 2181), host("b", 2181)];
    cfg.host_text = JString::Bytes(b"a:2181,b:2181".to_vec());
    edit(&mut cfg);
    let draws = Arc::new(Mutex::new(Draws::default()));
    let conn = Connection::new(
        cfg,
        compat,
        mode,
        Box::new(TestRng(Arc::clone(&draws))),
        Box::new(AllLevels),
        Box::new(NoDefaultWatcher),
        Millis(0),
    );
    (conn, draws)
}

/// Takes every pending log record.
fn logs(conn: &mut Connection<Tk>) -> Vec<LogRecord> {
    let mut out = Vec::new();
    while let Some(o) = conn.poll_output() {
        if let Output::Log(r) = o {
            out.push(r);
        }
    }
    out
}

/// Answers a `Resolve` action: host 0 gives `a`, host 1 gives `b`.
/// `None` fails the host.
fn answer(
    conn: &mut Connection<Tk>,
    generation: u64,
    per_host: &[Option<&str>],
    now: Millis,
) -> i32 {
    for (i, a) in per_host.iter().enumerate() {
        let result = match a {
            Some(addr) => Ok(vec![sa(addr)]),
            None => Err(ResolveError {
                gai_rc: -2,
                errno: 2,
            }),
        };
        conn.handle_host_resolved(
            generation,
            HostResolution {
                host: i,
                result,
                skipped_families: Vec::new(),
            },
            now,
        );
    }
    conn.handle_resolved(generation, false, now)
}

/// Commits the list `a=10.0.0.1:2181`, `b=10.0.0.2:2181` through the
/// first `Resolve` action.
fn init_two(conn: &mut Connection<Tk>) {
    let Some(Action::Resolve {
        generation,
        initial: true,
        ..
    }) = conn.poll_action(Millis(0))
    else {
        panic!("no initial Resolve");
    };
    let rc = answer(
        conn,
        generation,
        &[Some("10.0.0.1:2181"), Some("10.0.0.2:2181")],
        Millis(0),
    );
    assert_eq!(rc, rc::ZOK);
    let _ = logs(conn);
}

/// Runs one iteration with no transport. Each `Resolve` gets the two
/// good addresses. It returns the other actions and the outcome.
fn iterate(conn: &mut Connection<Tk>, now: Millis) -> (Vec<Action>, InterestOutcome) {
    conn.begin_interest(now).unwrap();
    let mut actions = Vec::new();
    while let Some(a) = conn.poll_action(now) {
        if let Action::Resolve { generation, .. } = a {
            answer(
                conn,
                generation,
                &[Some("10.0.0.1:2181"), Some("10.0.0.2:2181")],
                now,
            );
        } else {
            actions.push(a);
        }
    }
    (actions, conn.finish_interest(now))
}

#[test]
fn tls_profile_is_in_the_connect_action() {
    let (mut c, _) = conn_with(Compat::LEGACY_C, DriverMode::ST, |cfg| cfg.tls = true);
    init_two(&mut c);
    let (actions, _) = iterate(&mut c, Millis(0));
    let Some(Action::Connect { tls, .. }) = actions.first() else {
        panic!("expected Connect");
    };
    assert_eq!(*tls, Some(TlsVerify::LegacyChainOnly));
}

#[test]
fn whole_list_failure_use_last_good_connects() {
    let mut compat = Compat::LEGACY_C;
    compat.dns_failure = DnsFailure::UseLastGood;
    let (mut c, _) = conn_with(compat, DriverMode::ST, |_| {});
    init_two(&mut c);
    c.begin_interest(Millis(5)).unwrap();
    let Some(Action::Resolve { generation, .. }) = c.poll_action(Millis(5)) else {
        panic!("expected Resolve");
    };
    let rc = answer(&mut c, generation, &[None, None], Millis(5));
    assert_eq!(rc, rc::ZSYSTEMERROR);
    let a = c.poll_action(Millis(5)).unwrap();
    assert_eq!(connect_addr(&a), sa("10.0.0.1:2181"));
    assert!(c.poll_action(Millis(5)).is_none());
    let out = c.finish_interest(Millis(5));
    assert_eq!(out.rc, rc::ZOK);
    assert!(out.outputs.is_some());
}
