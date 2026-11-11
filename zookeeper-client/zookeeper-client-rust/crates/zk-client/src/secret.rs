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

//! `SecretString`: a string that is wiped on drop.

use zeroize::Zeroizing;

/// A secret string, such as a TLS passphrase.
///
/// The memory is wiped on drop. `Debug` prints `<redacted>`. The type is
/// not `Clone`, so each copy of a secret is explicit.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Takes ownership of `s`.
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Returns the secret text. Callers must not log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Makes an explicit copy, for a second owner.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self::new(self.0.as_str().to_owned())
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_owned())
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}
