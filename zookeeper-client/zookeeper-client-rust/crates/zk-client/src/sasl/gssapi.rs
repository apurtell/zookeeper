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

//! GSSAPI (Kerberos) through `libgssapi` (`sasl-gssapi`).
//!
//! The credentials come from the GSSAPI default, a credential cache or a
//! keytab. The server principal is `service@host`, where the host is the
//! configured server name or the connect-string host of the current
//! server. The mechanism needs no integrity or confidentiality layer, so
//! it answers the security-layer message with layer 1 and no buffer size
//! (RFC 4752, section 3.1). zk-proto sends the final empty packet.
//!
//! The context asks for mutual authentication, as the Java and C clients
//! do. The server then sends one more context token. After the context
//! is complete, the client sends an empty token, and the server sends
//! the security-layer message.
//!
//! The `libgssapi` crate links the system GSSAPI library. That library is
//! outside the unsafe budget of this crate, as `ring` is.

use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};

use super::{SaslContext, SaslError, SaslErrorKind, SaslMechanism, SaslMechanismFactory, SaslStep};

/// The mechanism name.
pub(crate) const NAME: &str = "GSSAPI";

/// The security layer "no protection" (RFC 4752, section 3.1).
const LAYER_NONE: u8 = 1;

/// The factory of [`Gssapi`] sessions.
pub(crate) struct GssapiFactory {
    /// The service of the server principal.
    service: String,
    /// The host of the server principal, or `None` for the connect-string
    /// host.
    server_name: Option<String>,
}

impl GssapiFactory {
    /// Makes the factory.
    pub(crate) fn new(service: String, server_name: Option<String>) -> Self {
        Self {
            service,
            server_name,
        }
    }

    /// Gives the host-based name `service@host` of the server.
    pub(crate) fn principal(&self, ctx: &SaslContext) -> String {
        let host = self.server_name.as_deref().unwrap_or(&ctx.server_host);
        format!("{}@{}", self.service, host)
    }
}

impl SaslMechanismFactory for GssapiFactory {
    /// Imports the server principal and makes the client context with the
    /// default credentials.
    fn create(&self, ctx: &SaslContext) -> Result<Box<dyn SaslMechanism>, SaslError> {
        let principal = self.principal(ctx);
        let target = Name::new(principal.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE))
            .map_err(|e| gss_error("the server principal is not valid", &e))?;
        let flags = CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG;
        Ok(Box::new(Gssapi {
            ctx: ClientCtx::new(None, target, flags, Some(GSS_MECH_KRB5)),
            established: false,
        }))
    }
}

/// One GSSAPI session.
pub(crate) struct Gssapi {
    /// The client context.
    ctx: ClientCtx,
    /// True after the context is complete. The next token is the
    /// security-layer message.
    established: bool,
}

impl Gssapi {
    /// Runs one context step. A complete context gives an empty token,
    /// because the server waits for one more client message.
    fn context_step(&mut self, token: Option<&[u8]>) -> Result<SaslStep, SaslError> {
        let out = self
            .ctx
            .step(token, None)
            .map_err(|e| gss_error("the GSSAPI context setup failed", &e))?;
        if self.ctx.is_complete() {
            self.established = true;
        }
        Ok(SaslStep {
            token: Some(out.map(|b| b.to_vec()).unwrap_or_default()),
            done: false,
        })
    }

    /// Answers the security-layer message (RFC 4752, section 3.1). The
    /// client selects no protection and gives no authorization identity.
    fn layer_step(&mut self, message: &[u8]) -> Result<SaslStep, SaslError> {
        let plain = self
            .ctx
            .unwrap(message)
            .map_err(|e| gss_error("the security-layer message is not valid", &e))?;
        let offer = match &plain[..] {
            [layers, _, _, _] => *layers,
            _ => {
                return Err(mechanism_error(
                    "the security-layer message does not have four bytes",
                ));
            }
        };
        if offer & LAYER_NONE == 0 {
            return Err(mechanism_error(
                "the server needs a security layer, which the client does not support",
            ));
        }
        let answer = self
            .ctx
            .wrap(false, &[LAYER_NONE, 0, 0, 0])
            .map_err(|e| gss_error("the security-layer answer failed", &e))?;
        Ok(SaslStep {
            token: Some(answer.to_vec()),
            done: true,
        })
    }
}

impl SaslMechanism for Gssapi {
    fn name(&self) -> &str {
        NAME
    }

    /// Gives the first context token.
    fn start(&mut self) -> Result<SaslStep, SaslError> {
        self.context_step(None)
    }

    /// Gives the next context token, then the security-layer answer.
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<SaslStep, SaslError> {
        let token = challenge.unwrap_or_default();
        if self.established {
            self.layer_step(token)
        } else {
            self.context_step(Some(token))
        }
    }
}

/// Makes a mechanism error with `message` and the GSSAPI status text.
fn gss_error(message: &str, e: &libgssapi::error::Error) -> SaslError {
    SaslError::new(SaslErrorKind::Mechanism, format!("{message}: {e}"))
}

/// Makes a mechanism error with `message`.
fn mechanism_error(message: &str) -> SaslError {
    SaslError::new(SaslErrorKind::Mechanism, message)
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test code")]
mod tests {
    use super::*;

    fn ctx() -> SaslContext {
        SaslContext {
            server_host: "zk1.example.com".to_owned(),
            server_addr: "127.0.0.1:2181".parse().expect("addr"),
            local_addr: "127.0.0.1:40000".parse().expect("addr"),
        }
    }

    /// The principal uses the configured host, else the connect-string
    /// host. The test needs no KDC, so it does not make a context.
    #[test]
    fn the_principal_is_service_at_host() {
        let f = GssapiFactory::new("zookeeper".to_owned(), None);
        assert_eq!(f.principal(&ctx()), "zookeeper@zk1.example.com");
        let f = GssapiFactory::new("zk".to_owned(), Some("zk.realm.example".to_owned()));
        assert_eq!(f.principal(&ctx()), "zk@zk.realm.example");
    }
}
