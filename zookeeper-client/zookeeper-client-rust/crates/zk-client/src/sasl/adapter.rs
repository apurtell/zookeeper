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

//! The adapter from [`SaslMechanism`] to `zk_proto::SaslSession`.
//!
//! The driver owns one adapter for the life of the client. Each `start`
//! makes a new mechanism from the factory, so no state carries over from
//! an earlier connection. The adapter changes each public error to the
//! proto error, and it keeps the public error for
//! `SessionInfo::last_error`. A panic of the mechanism or of the
//! credential source is a [`SaslErrorKind::Mechanism`] error. The
//! panic thus never crosses the driver.

use std::sync::{Arc, Mutex};

use crate::sync::LockExt;

use super::{
    SaslConfig, SaslContext, SaslError, SaslErrorKind, SaslMechanism, SaslMechanismFactory,
};

/// The rc of a mechanism error.
const ZSYSTEMERROR: i32 = -1;

/// The last public SASL error of a client. The adapter writes it, and the
/// state watcher reads it for `SessionInfo::last_error`.
pub(crate) type LastSaslError = Arc<Mutex<Option<SaslError>>>;

/// The native SASL session of one client.
pub(crate) struct NativeSasl {
    /// Makes one mechanism per connection.
    factory: Arc<dyn SaslMechanismFactory>,
    /// The connection of the next `start`, from
    /// `zk_proto::SaslSession::connection`.
    ctx: Option<SaslContext>,
    /// The mechanism of the current connection.
    mech: Option<Box<dyn SaslMechanism>>,
    /// The last public error.
    last_error: LastSaslError,
}

impl NativeSasl {
    /// Makes the adapter for `config`.
    pub(crate) fn new(config: SaslConfig, last_error: LastSaslError) -> Self {
        Self {
            factory: factory(config),
            ctx: None,
            mech: None,
            last_error,
        }
    }
}

impl NativeSasl {
    /// Makes the mechanism of this connection and runs its `start`.
    ///
    /// The context of the connection is used once. A later `start` with
    /// no new context thus fails.
    fn begin(&mut self) -> Result<(String, zk_proto::SaslStep), SaslError> {
        let ctx = self.ctx.take().ok_or_else(|| {
            SaslError::new(SaslErrorKind::Mechanism, "the SASL connection is not known")
        })?;
        let factory = Arc::clone(&self.factory);
        let mut mech = guard(|| factory.create(&ctx))?;
        let first = guard(|| mech.start());
        let name = guard(|| Ok(mech.name().to_owned()));
        let (first, name) = (first?, name?);
        self.mech = Some(mech);
        Ok((name, to_proto_step(first)))
    }

    /// Keeps the public error for `SessionInfo::last_error` and gives
    /// the proto error. A failed session drops its mechanism.
    fn answer<T>(&mut self, result: Result<T, SaslError>) -> Result<T, zk_proto::SaslError> {
        result.map_err(|e| {
            self.mech = None;
            let proto = to_proto(&e);
            *self.last_error.lock_unpoisoned() = Some(e);
            proto
        })
    }
}

/// Gives the factory of a configuration. The built-in mechanisms have
/// their own factory types.
fn factory(config: SaslConfig) -> Arc<dyn SaslMechanismFactory> {
    match config {
        SaslConfig::DigestMd5 {
            username,
            password,
            service,
            server_name,
        } => Arc::new(super::digest_md5::DigestMd5Factory::new(
            username,
            password,
            service,
            server_name,
        )),
        #[cfg(feature = "sasl-gssapi")]
        SaslConfig::Gssapi {
            service,
            server_name,
        } => Arc::new(super::gssapi::GssapiFactory::new(service, server_name)),
        SaslConfig::Custom(f) => f,
    }
}

impl zk_proto::SaslSession for NativeSasl {
    /// Drops the mechanism of the last connection, makes a new one with
    /// the stored context and calls its `start`.
    ///
    /// No context, a factory error, a mechanism error and a panic all
    /// give an error. The adapter stores the public error first.
    fn start(&mut self) -> Result<(String, zk_proto::SaslStep), zk_proto::SaslError> {
        self.mech = None;
        let result = self.begin();
        self.answer(result)
    }

    /// Calls `step` on the current mechanism. No mechanism and a panic
    /// give a mechanism error.
    fn step(
        &mut self,
        challenge: Option<&[u8]>,
    ) -> Result<zk_proto::SaslStep, zk_proto::SaslError> {
        let result = match self.mech.as_mut() {
            Some(mech) => guard(|| mech.step(challenge)),
            None => Err(SaslError::new(
                SaslErrorKind::Mechanism,
                "no SASL mechanism is running",
            )),
        };
        self.answer(result.map(to_proto_step))
    }

    fn connection(&mut self, host: &[u8], local: std::net::SocketAddr, peer: std::net::SocketAddr) {
        self.ctx = Some(SaslContext {
            server_host: String::from_utf8_lossy(host).into_owned(),
            server_addr: peer,
            local_addr: local,
        });
    }
}

/// Changes a public error to the proto error: the rc is `ZSYSTEMERROR`,
/// the error string is the message and the detail is empty.
pub(crate) fn to_proto(e: &SaslError) -> zk_proto::SaslError {
    zk_proto::SaslError {
        rc: ZSYSTEMERROR,
        errstring: e.message.as_bytes().to_vec(),
        errdetail: Vec::new(),
    }
}

/// Changes a public step to the proto step. The token goes into a
/// zeroizing buffer.
pub(crate) fn to_proto_step(s: super::SaslStep) -> zk_proto::SaslStep {
    zk_proto::SaslStep {
        token: s.token.map(zk_proto::SecretBytes::from),
        done: s.done,
    }
}

/// Runs `f` and changes a panic to a mechanism error.
pub(crate) fn guard<R>(f: impl FnOnce() -> Result<R, SaslError>) -> Result<R, SaslError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err(SaslError::new(
            SaslErrorKind::Mechanism,
            "the SASL mechanism panicked",
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "test code")]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use zk_proto::SaslSession;

    use super::*;
    use crate::sasl::SaslStep;

    /// A factory that counts its mechanisms. Each mechanism sends one
    /// token and is done at the first step. A `panic` factory panics.
    struct Counting {
        made: AtomicUsize,
        panic: bool,
    }

    impl SaslMechanismFactory for Counting {
        fn create(&self, ctx: &SaslContext) -> Result<Box<dyn SaslMechanism>, SaslError> {
            assert!(!self.panic, "the factory panics");
            self.made.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Once(ctx.server_host.clone())))
        }
    }

    struct Once(String);

    impl SaslMechanism for Once {
        fn name(&self) -> &str {
            "ONCE"
        }

        fn start(&mut self) -> Result<SaslStep, SaslError> {
            Ok(SaslStep {
                token: Some(self.0.as_bytes().to_vec()),
                done: false,
            })
        }

        fn step(&mut self, _challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
            Ok(SaslStep {
                token: None,
                done: true,
            })
        }
    }

    fn adapter(panic: bool) -> (NativeSasl, Arc<Counting>, LastSaslError) {
        let f = Arc::new(Counting {
            made: AtomicUsize::new(0),
            panic,
        });
        let last = LastSaslError::default();
        let factory: Arc<dyn SaslMechanismFactory> = f.clone();
        let s = NativeSasl::new(SaslConfig::Custom(factory), Arc::clone(&last));
        (s, f, last)
    }

    fn addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 2181))
    }

    fn kind(last: &LastSaslError) -> Option<SaslErrorKind> {
        last.lock_unpoisoned().as_ref().map(|e| e.kind.clone())
    }

    /// Rule: each connection gets a new mechanism with the host of that
    /// connection. The context is used once.
    #[test]
    fn each_start_makes_a_new_mechanism() {
        let (mut s, f, last) = adapter(false);
        for host in ["zk1", "zk2"] {
            s.connection(host.as_bytes(), addr(), addr());
            let (name, first) = s.start().unwrap();
            assert_eq!(name, "ONCE");
            assert_eq!(first.token.unwrap().expose(), host.as_bytes());
            assert!(s.step(Some(b"x")).unwrap().done);
        }
        assert_eq!(f.made.load(Ordering::SeqCst), 2);
        assert!(kind(&last).is_none());
        assert!(s.start().is_err());
        assert_eq!(kind(&last), Some(SaslErrorKind::Mechanism));
    }

    /// Rule: a step with no mechanism fails, and the error is stored.
    #[test]
    fn a_step_with_no_mechanism_fails() {
        let (mut s, _, last) = adapter(false);
        let e = s.step(None).unwrap_err();
        assert_eq!(e.rc, ZSYSTEMERROR);
        assert_eq!(e.errstring, b"no SASL mechanism is running");
        assert_eq!(kind(&last), Some(SaslErrorKind::Mechanism));
    }

    /// Rule: a factory panic is a mechanism error. The panic does not
    /// leave the adapter.
    #[test]
    fn a_factory_panic_is_a_mechanism_error() {
        let (mut s, _, last) = adapter(true);
        s.connection(b"zk1", addr(), addr());
        let e = s.start().unwrap_err();
        assert_eq!(e.errstring, b"the SASL mechanism panicked");
        assert_eq!(kind(&last), Some(SaslErrorKind::Mechanism));
        assert!(s.mech.is_none());
    }
}
