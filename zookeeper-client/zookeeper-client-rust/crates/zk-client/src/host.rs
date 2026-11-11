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

//! `NativeHost`: the host leaves of the native client.
//!
//! The pure leaves run under the core lock, so they never call user
//! code. The blocking leaf `resolve` runs with no lock held. It calls
//! the user `Resolve` inside `catch_unwind` and inside the IO-side
//! marker, so a blocking wait in the resolver fails at once.

use std::net::{SocketAddr, ToSocketAddrs};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use zk_driver::host_std::EAI_NONAME;
use zk_driver::{Discarded, HostLeaves, Unlocked};
use zk_proto::{ClientId, HostResolution, HostSpec, LogLevel, ResolveError};

use crate::builder::{Resolve, ServerOrder};
use crate::observe::Observer;
use crate::rng::NativeRng;
use crate::sync::enter_io_side;
use crate::tokens::{NativeTokens, WatchId};

/// The host leaves of one client.
pub(crate) struct NativeHost {
    /// The private random source.
    rng: NativeRng,
    /// The resolver of the builder, or `StdResolve`.
    resolver: Arc<dyn Resolve>,
    /// The `server_order` value.
    order: ServerOrder,
    /// The log filter.
    observe: Arc<Observer>,
    /// The client id of the IO-side marker.
    client: u64,
}

impl std::fmt::Debug for NativeHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeHost")
            .field("order", &self.order)
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl NativeHost {
    /// Makes the leaves of client `client`.
    pub(crate) fn new(
        resolver: Arc<dyn Resolve>,
        order: ServerOrder,
        observe: Arc<Observer>,
        client: u64,
    ) -> Self {
        Self {
            rng: NativeRng::new(),
            resolver,
            order,
            observe,
            client,
        }
    }

    /// Runs the user resolver for one native entry.
    ///
    /// The IO-side marker makes a blocking wait in the resolver fail at
    /// once. A panic, an error and an empty list all fail the host. The
    /// observer logs a panic, because the panic message is not in the
    /// result.
    fn lookup(&self, spec: &HostSpec) -> Result<Vec<SocketAddr>, ResolveError> {
        let HostSpec::Native(entry) = spec else {
            return Err(not_found(0));
        };
        let outcome = {
            let _io = enter_io_side(self.client);
            catch_unwind(AssertUnwindSafe(|| {
                self.resolver.resolve(&entry.host, entry.port)
            }))
        };
        match outcome {
            Ok(Ok(addrs)) if !addrs.is_empty() => Ok(addrs),
            Ok(Ok(_)) => Err(not_found(0)),
            Ok(Err(e)) => Err(not_found(e.raw_os_error().unwrap_or(0))),
            Err(payload) => {
                self.observe.hook_panicked(
                    "the resolver panicked, so the host fails this resolution",
                    payload,
                );
                Err(not_found(0))
            }
        }
    }
}

/// The resolver error of a failed native entry. It is the error that
/// `zk_driver::StdHostLeaves` gives, so both resolvers fail the same way.
fn not_found(errno: i32) -> ResolveError {
    ResolveError {
        gai_rc: EAI_NONAME,
        errno,
    }
}

impl HostLeaves<NativeTokens> for NativeHost {
    /// Drops the token. A completion or auth token closes its slot when
    /// it drops, so its receiver sees the terminal error.
    fn discard_token(&self, token: Discarded<NativeTokens>) {
        drop(token);
    }

    /// The native client has no default watcher.
    fn snapshot_default_watcher(&self) -> Option<WatchId> {
        None
    }

    /// Does nothing: `Client::session` reads `Connection::client_id`
    /// under the core lock.
    fn store_client_id(&self, _id: &ClientId) {}

    fn log_enabled(&self, level: LogLevel) -> bool {
        self.observe.log_enabled(level)
    }

    fn conn_permute_disabled(&self) -> bool {
        self.order == ServerOrder::AsGiven
    }

    fn rng_random(&self) -> i64 {
        self.rng.random()
    }

    fn rng_drand48(&self) -> f64 {
        self.rng.drand48()
    }

    /// Does nothing: the generator is private to the client, so no
    /// process seed exists to reset.
    fn rng_reseed(&self, _proof: &Unlocked) {}

    /// Resolves one host entry with the user resolver.
    ///
    /// Contract:
    /// - Only `HostSpec::Native` entries reach a native client. A
    ///   `Legacy` entry gives `ResolveError { gai_rc: EAI_NONAME,
    ///   errno: 0 }`.
    /// - The call runs inside `enter_io_side(self.client)` and inside
    ///   `catch_unwind`. A panic counts as a resolve failure.
    /// - An `io::Error` maps as `zk_driver::StdHostLeaves` maps it: the
    ///   `EAI_NONAME` code with the raw OS error as `errno`, or 0.
    /// - An empty address list is a resolve failure.
    /// - `skipped_families` is empty: a `SocketAddr` is always IPv4 or
    ///   IPv6.
    fn resolve(&self, _proof: &Unlocked, host: usize, spec: &HostSpec) -> HostResolution {
        HostResolution {
            host,
            result: self.lookup(spec),
            skipped_families: Vec::new(),
        }
    }
}

/// The default resolver: `std::net::ToSocketAddrs`.
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct StdResolve;

impl Resolve for StdResolve {
    /// Resolves `(host, port)` with `ToSocketAddrs`, in resolver order,
    /// duplicates included. An IP literal resolves with no DNS lookup.
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use zk_proto::native::NativeHost as NativeEntry;

    use super::*;
    use crate::sync::{LockExt, blocking_refused, on_io_side};

    /// A resolver that runs a closure and counts its calls.
    struct FnResolve<F> {
        f: F,
        calls: Arc<AtomicUsize>,
    }

    impl<F> Resolve for FnResolve<F>
    where
        F: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    {
        fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.f)(host, port)
        }
    }

    fn host_with<F>(f: F) -> (NativeHost, Arc<AtomicUsize>)
    where
        F: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let r = FnResolve {
            f,
            calls: Arc::clone(&calls),
        };
        let h = NativeHost::new(
            Arc::new(r),
            ServerOrder::Shuffled,
            Arc::new(Observer::new(Some("t".into()), None)),
            7,
        );
        (h, calls)
    }

    fn native(host: &str, port: u16) -> HostSpec {
        HostSpec::Native(NativeEntry {
            host: host.into(),
            port,
        })
    }

    fn run(h: &NativeHost, index: usize, spec: &HostSpec) -> HostResolution {
        let proof = Unlocked::new_at_entry();
        HostLeaves::<NativeTokens>::resolve(h, &proof, index, spec)
    }

    fn failed(errno: i32) -> Result<Vec<SocketAddr>, ResolveError> {
        Err(ResolveError {
            gai_rc: EAI_NONAME,
            errno,
        })
    }

    #[test]
    fn the_pure_leaves_need_no_driver() {
        let h = NativeHost::new(
            Arc::new(StdResolve),
            ServerOrder::AsGiven,
            Arc::new(Observer::new(None, None)),
            1,
        );
        assert!(h.conn_permute_disabled());
        assert!(h.snapshot_default_watcher().is_none());
        let d = h.rng_drand48();
        assert!((0.0..1.0).contains(&d));
    }

    #[test]
    fn a_resolver_success_keeps_the_order_and_the_duplicates() {
        let a: SocketAddr = "10.0.0.2:2181".parse().unwrap();
        let b: SocketAddr = "[::1]:2181".parse().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        let (h, calls) = host_with(move |host, port| {
            seen2.lock_unpoisoned().push((host.to_owned(), port));
            Ok(vec![a, b, a])
        });
        let r = run(&h, 3, &native("zk.example", 2181));
        assert_eq!(r.host, 3);
        assert_eq!(r.result, Ok(vec![a, b, a]));
        assert!(r.skipped_families.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *seen.lock_unpoisoned(),
            vec![("zk.example".to_owned(), 2181)]
        );
    }

    #[test]
    fn a_resolver_error_maps_like_the_std_leaves() {
        let (h, _) = host_with(|_, _| Err(io::Error::from_raw_os_error(61)));
        assert_eq!(run(&h, 0, &native("a", 1)).result, failed(61));
        let (h, _) = host_with(|_, _| Err(io::Error::other("no such host")));
        assert_eq!(run(&h, 0, &native("a", 1)).result, failed(0));
    }

    #[test]
    fn an_empty_list_fails_the_host() {
        let (h, _) = host_with(|_, _| Ok(Vec::new()));
        let r = run(&h, 1, &native("a", 1));
        assert_eq!(r.host, 1);
        assert_eq!(r.result, failed(0));
        assert!(r.skipped_families.is_empty());
    }

    #[test]
    fn a_resolver_panic_fails_the_host_and_the_next_call_runs() {
        let flip = Arc::new(AtomicUsize::new(0));
        let flip2 = Arc::clone(&flip);
        let good: SocketAddr = "127.0.0.1:2181".parse().unwrap();
        let (h, calls) = host_with(move |_, _| {
            if flip2.fetch_add(1, Ordering::SeqCst) == 0 {
                std::panic::panic_any("resolver bug");
            }
            Ok(vec![good])
        });
        assert_eq!(run(&h, 0, &native("a", 1)).result, failed(0));
        // The marker is gone after the panic.
        assert!(!on_io_side());
        // A panic does not disable the resolver.
        assert_eq!(run(&h, 0, &native("a", 1)).result, Ok(vec![good]));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "the payload of the second panic leaks by design, and the Miri leak check fails on it"
    )]
    fn a_resolver_with_a_bad_payload_drop_does_not_unwind() {
        struct BadDrop;
        impl Drop for BadDrop {
            fn drop(&mut self) {
                std::panic::panic_any("drop bug");
            }
        }
        let (h, _) = host_with(|_, _| std::panic::panic_any(BadDrop));
        assert_eq!(run(&h, 0, &native("a", 1)).result, failed(0));
    }

    #[test]
    fn a_blocking_wait_inside_the_resolver_is_refused() {
        let inside = Arc::new(Mutex::new(None));
        let inside2 = Arc::clone(&inside);
        let (h, _) = host_with(move |_, _| {
            *inside2.lock_unpoisoned() = Some((on_io_side(), blocking_refused(false)));
            Ok(Vec::new())
        });
        assert!(!on_io_side());
        let _ = run(&h, 0, &native("a", 1));
        assert_eq!(*inside.lock_unpoisoned(), Some((true, true)));
        assert!(!on_io_side());
    }

    #[test]
    fn a_legacy_entry_fails_without_the_resolver() {
        let (h, calls) = host_with(|_, _| Ok(vec!["127.0.0.1:1".parse().unwrap()]));
        let spec = HostSpec::Legacy(zk_proto::legacy::connect::HostSpec {
            host: b"127.0.0.1".to_vec(),
            service: b"2181".to_vec(),
            port: 2181,
        });
        let r = run(&h, 2, &spec);
        assert_eq!(r.host, 2);
        assert_eq!(r.result, failed(0));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn std_resolve_takes_ip_literals_without_dns() {
        let v4 = StdResolve.resolve("127.0.0.1", 2181).unwrap();
        assert_eq!(v4, vec!["127.0.0.1:2181".parse::<SocketAddr>().unwrap()]);
        let v6 = StdResolve.resolve("::1", 2182).unwrap();
        assert_eq!(v6, vec!["[::1]:2182".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn std_resolve_rejects_a_bad_name() {
        // A NUL byte fails before any lookup.
        assert!(StdResolve.resolve("bad\0host", 2181).is_err());
    }

    #[test]
    fn the_default_resolver_runs_through_the_leaf() {
        let h = NativeHost::new(
            Arc::new(StdResolve),
            ServerOrder::AsGiven,
            Arc::new(Observer::new(None, None)),
            1,
        );
        let r = run(&h, 0, &native("127.0.0.1", 2181));
        assert_eq!(r.result, Ok(vec!["127.0.0.1:2181".parse().unwrap()]));
    }
}
