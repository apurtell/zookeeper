# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This module selects the client core. The legacy
# CMakeLists.txt includes it after the legacy probes and before the legacy
# targets. The module sets ZKRS_CORE. With the Rust core, the module adds
# all targets of the build. CMakeLists.txt then returns. With the legacy
# core, the module changes no flag, policy or target of the legacy build.
#
# The C sources stay in the legacy C tree, so the module finds them
# through CMAKE_CURRENT_SOURCE_DIR. ZKRS_DIR is the Rust C tree. It holds
# the shim, the ABI data and the test runners.
#
# CMakeLists.txt keeps the policies of CMake 3.5, so the legacy build
# does not change. The Rust core needs CMake 3.15. include()
# gives this module its own policy scope, so the policies of 3.15 apply
# only to the Rust part of the build.
#
# The legacy options, for example WANT_SYNCAPI and WITH_CYRUS_SASL, keep
# policy CMP0077 OLD, as in the legacy build. Thus, on the first run,
# option() removes a normal variable that an add_subdirectory() parent
# sets. A parent must set these options as cache entries, or set
# CMAKE_POLICY_DEFAULT_CMP0077 to NEW.
if(NOT CMAKE_VERSION VERSION_LESS 3.15)
  cmake_policy(VERSION 3.15)
endif()
get_filename_component(ZKRS_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

# WITH_RUST_CLIENT is ON, OFF or AUTO. Unset means OFF.
if(NOT DEFINED WITH_RUST_CLIENT)
  set(ZKRS_MODE OFF)
  set(ZKRS_MODE_DEFAULT ON)
elseif(WITH_RUST_CLIENT STREQUAL "AUTO")
  set(ZKRS_MODE AUTO)
elseif(WITH_RUST_CLIENT MATCHES "^(1|ON|YES|TRUE|Y|on|yes|true|y)$")
  set(ZKRS_MODE ON)
elseif(WITH_RUST_CLIENT MATCHES "^(0|OFF|NO|FALSE|N|off|no|false|n)$")
  set(ZKRS_MODE OFF)
else()
  message(FATAL_ERROR "WITH_RUST_CLIENT must be ON, OFF or AUTO")
endif()
option(ZOOKEEPER_BUILD_SHARED "Also build the zookeeper_mt or zookeeper_st shared library (Rust core)" OFF)
# A user value of ZK_RUST_TLS_PROVIDER is a request for the Rust core. The
# default is a normal variable, so a later run does not see it as a request.
if(DEFINED CACHE{ZK_RUST_TLS_PROVIDER} OR DEFINED ZK_RUST_TLS_PROVIDER)
  set(ZKRS_PROVIDER_GIVEN ON)
else()
  set(ZK_RUST_TLS_PROVIDER "ring")
endif()
# These are the TLS options of the Rust core. ZkRustTls
# applies them together with the OpenSSL and Cyrus SASL probes.
option(WITH_RUST_TLS "Build TLS into the Rust client also without OpenSSL (Rust core)" OFF)
set(ZK_RUST_TLS_DEFAULT_PATHS "" CACHE STRING
    "FILE:DIR of the default trust locations; empty means OPENSSLDIR, else the platform list")
set(ZKRS_WORKSPACE "" CACHE PATH "Rust workspace; empty means ../zookeeper-client-rust")
set(ZKRS_STATICLIB "" CACHE FILEPATH "Prebuilt libzk_ffi.a; empty means CMake runs cargo")
# The crate sources of cargo. zk_rust_check applies them.
set(ZOOKEEPER_CARGO_VENDOR "" CACHE PATH "cargo vendor directory; cargo then runs offline (Rust core)")
set(ZK_SYSTEM_RUST_CRATES "" CACHE PATH
    "System crate directory; cargo then runs offline and writes Cargo.lock again (Rust core)")
option(ZK_WERROR "Add -Werror (/WX) to the shim flags" ON)
# Only the Rust core changes these two variables. These normal variables
# hide a cache entry of the same name. Thus a legacy build always gets all
# of its targets.
set(ZKRS_CORE OFF)
set(ZKRS_SKIP_PROGRAMS OFF)
include("${CMAKE_CURRENT_LIST_DIR}/ZkRustDetect.cmake")

# The core selection follows the configure rule.
zk_rust_requested_by(ZKRS_REQUESTED_BY)
if(ZKRS_MODE_DEFAULT AND ZKRS_MODE STREQUAL "OFF" AND ZKRS_REQUESTED_BY)
  message(FATAL_ERROR "${ZKRS_REQUESTED_BY} needs -DWITH_RUST_CLIENT=ON")
endif()
if(NOT ZKRS_MODE STREQUAL "OFF")
  if(NOT ZOOKEEPER_CARGO_VENDOR STREQUAL "" AND NOT ZK_SYSTEM_RUST_CRATES STREQUAL "")
    message(FATAL_ERROR "give only one of -DZOOKEEPER_CARGO_VENDOR and -DZK_SYSTEM_RUST_CRATES")
  endif()
  zk_rust_check(ZKRS_OK ZKRS_WHY)
  if(ZKRS_OK)
    set(ZKRS_CORE ON)
  elseif(ZKRS_MODE STREQUAL "ON")
    message(FATAL_ERROR
      "WITH_RUST_CLIENT=ON: ${ZKRS_WHY}; -DWITH_RUST_CLIENT=OFF builds the legacy C client")
  elseif(ZKRS_REQUESTED_BY)
    message(FATAL_ERROR
      "${ZKRS_REQUESTED_BY} needs the Rust client, which this host cannot build: ${ZKRS_WHY}")
  else()
    message("-- building the legacy C client: ${ZKRS_WHY}")
  endif()
endif()

if(ZKRS_CORE)
  # Only the Rust core adds this directory to the module path, so the
  # legacy build finds its modules as before.
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
  # CMakeLists.txt finds the Find modules through CMAKE_SOURCE_DIR. In an
  # add_subdirectory() build, that path is not correct, so the legacy SASL
  # probe fails. The legacy core keeps that behavior. The Rust core adds
  # the correct path and does the SASL probe again.
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/cmake/Modules")
  if(NOT WITH_CYRUS_SASL STREQUAL "OFF" AND NOT CYRUS_SASL_FOUND)
    find_package(CyrusSASL)
    if(CYRUS_SASL_FOUND)
      message("-- Cyrus SASL 2.x found! will build with SASL support.")
    endif()
  endif()
  # WANT_SYNCAPI selects the flavor of the Rust core, as in the legacy core.
  include(ZkRustCore)

  # CMakeLists.txt returns after this module, so the module adds cli and
  # load_gen. These targets use the policies of CMake 3.5, as in the
  # legacy build.
  if(NOT ZKRS_SKIP_PROGRAMS)
    cmake_policy(PUSH)
    cmake_policy(VERSION 3.5)
    add_executable(cli ${CMAKE_CURRENT_SOURCE_DIR}/src/cli.c)
    target_link_libraries(cli zookeeper)
    if(WANT_SYNCAPI AND NOT WIN32)
      add_executable(load_gen ${CMAKE_CURRENT_SOURCE_DIR}/src/load_gen.c)
      target_link_libraries(load_gen zookeeper)
    endif()
    cmake_policy(POP)
  endif()

  # The CppUnit tests use the internals of the legacy core, so the Rust
  # core does not build zktest.
  if(WANT_CPPUNIT)
    message("-- zktest needs the legacy core; it is not built with the Rust core")
  endif()
  # The public-API suite links the targets above. The legacy build includes
  # this module at the end of CMakeLists.txt instead.
  include("${CMAKE_CURRENT_LIST_DIR}/ZkRustPublicTests.cmake")
endif()
