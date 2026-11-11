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

//! The Java syntax helpers of the native client.
//!
//! The native client parses its connect string and checks its paths with
//! the rules of the Java client. The helpers live in [`crate::legacy`],
//! because they share code with the legacy parsers. This module gives
//! them one documented place, so the native crates do not depend on the
//! legacy module layout.
//!
//! - [`parse_connect_string_native`] parses `"h1:2181,h2/chroot"`.
//! - [`validate_path_strict`] is the Java `PathUtils.validatePath` check.
//! - [`join_component`] adds the chroot on a component boundary.
//! - [`strip_str`] removes the chroot from a server path.

pub use crate::legacy::chroot::{join_component, strip_str};
pub use crate::legacy::connect::{
    NativeConnectString, NativeHost, NativeParseError, parse_connect_string_native,
};
pub use crate::legacy::path::{PathError, PathErrorKind, validate_path_strict};
