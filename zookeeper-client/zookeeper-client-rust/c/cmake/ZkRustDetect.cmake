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

# The selection of the client core. This module has the
# same rules as the configure check (ZK_RUST_CHECK in m4/zk_rust.m4).

# Sets OUT to the first Rust-only variable that the user set, else to "".
# Such a variable is a request for the Rust core.
function(zk_rust_requested_by out)
  set(by "")
  foreach(v WITH_RUST_TLS ZOOKEEPER_BUILD_SHARED)
    if(NOT by AND ${v})
      set(by "-D${v}=${${v}}")
    endif()
  endforeach()
  if(NOT by AND ZKRS_PROVIDER_GIVEN)
    set(by "-DZK_RUST_TLS_PROVIDER=${ZK_RUST_TLS_PROVIDER}")
  endif()
  foreach(v ZK_RUST_TLS_DEFAULT_PATHS ZKRS_WORKSPACE ZKRS_STATICLIB Rust_TARGET
            ZOOKEEPER_CARGO_VENDOR ZK_SYSTEM_RUST_CRATES)
    if(NOT by AND NOT "${${v}}" STREQUAL "")
      set(by "-D${v}=${${v}}")
    endif()
  endforeach()
  set(${out} "${by}" PARENT_SCOPE)
endfunction()

# Gives the version of a Rust tool as MAJOR * 1000 + MINOR, or 0.
function(zk_rust_tool_version tool out)
  set(v 0)
  if(tool)
    execute_process(COMMAND "${tool}" --version OUTPUT_VARIABLE text ERROR_QUIET
                    RESULT_VARIABLE rc)
    if(rc EQUAL 0 AND text MATCHES "^[a-z]+ ([0-9]+)\\.([0-9]+)")
      math(EXPR v "${CMAKE_MATCH_1} * 1000 + ${CMAKE_MATCH_2}")
    endif()
  endif()
  set(${out} ${v} PARENT_SCOPE)
endfunction()

# Gives the version of the [workspace.package] table of a Cargo.toml.
function(zk_rust_workspace_version toml out)
  set(found "")
  set(in_table OFF)
  file(STRINGS "${toml}" lines)
  foreach(line IN LISTS lines)
    if(line MATCHES "^\\[")
      if(line MATCHES "^\\[workspace\\.package\\]")
        set(in_table ON)
      else()
        set(in_table OFF)
      endif()
    elseif(in_table AND NOT found AND line MATCHES "^version *= *\"([^\"]*)\"")
      set(found "${CMAKE_MATCH_1}")
    endif()
  endforeach()
  set(${out} "${found}" PARENT_SCOPE)
endfunction()

# Decides whether this host can build the Rust core. OK gets ON or OFF.
# When the check fails, WHY names the first condition that failed. When the
# check passes, the function sets ZKRS_WORKSPACE to the workspace directory,
# CARGO_EXECUTABLE and RUSTC_EXECUTABLE, as normal variables. It also sets
# ZKRS_CARGO_SOURCE_ARGS, the crate source options of each cargo call, and
# ZKRS_CARGO_SOURCE_CONFIG, the file of those options. A prebuilt
# staticlib needs no cargo. TLS and SASL do not affect the check, because
# ZkRustTls selects them. Both flavors pass it.
function(zk_rust_check ok why)
  set(${ok} OFF PARENT_SCOPE)
  # The legacy core builds with CMake 3.5. The Rust core needs 3.15.
  if(CMAKE_VERSION VERSION_LESS 3.15)
    set(${why} "the Rust client needs CMake 3.15 or later" PARENT_SCOPE)
    return()
  endif()
  if(WIN32 OR CYGWIN)
    set(${why} "the Rust client does not support Windows yet" PARENT_SCOPE)
    return()
  endif()

  # The workspace is the variable, else the parent of ZKRS_DIR. That
  # default is ../zookeeper-client-rust, next to the legacy C tree.
  if(NOT ZKRS_WORKSPACE STREQUAL "")
    set(ws "${ZKRS_WORKSPACE}")
  else()
    set(ws "${ZKRS_DIR}/..")
  endif()
  get_filename_component(ws "${ws}" ABSOLUTE)
  if(NOT EXISTS "${ws}/Cargo.toml")
    set(${why} "no Rust workspace at ${ws} (give -DZKRS_WORKSPACE=DIR)" PARENT_SCOPE)
    return()
  endif()

  # The workspace version must equal ZOO_VERSION, as zk-ffi/build.rs checks.
  zk_rust_workspace_version("${ws}/Cargo.toml" ws_version)
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/zookeeper_version.h" zoo_line
       REGEX "^#define ZOO_VERSION \"")
  string(REGEX REPLACE "^#define ZOO_VERSION \"([^\"]*)\".*" "\\1" zoo_version "${zoo_line}")
  if(NOT ws_version STREQUAL zoo_version)
    set(${why} "the Rust workspace version ${ws_version} is not ZOO_VERSION ${zoo_version}"
        PARENT_SCOPE)
    return()
  endif()

  # The toolchain: rustc for a prebuilt staticlib, else cargo and rustc 1.85 or later.
  find_program(RUSTC_EXECUTABLE rustc)
  find_program(CARGO_EXECUTABLE cargo)
  if(NOT ZKRS_STATICLIB STREQUAL "")
    if(NOT EXISTS "${ZKRS_STATICLIB}")
      set(${why} "the staticlib ${ZKRS_STATICLIB} does not exist" PARENT_SCOPE)
      return()
    elseif(NOT RUSTC_EXECUTABLE)
      set(${why} "rustc not found (needed with ZKRS_STATICLIB)" PARENT_SCOPE)
      return()
    endif()
  else()
    zk_rust_tool_version("${RUSTC_EXECUTABLE}" v1)
    zk_rust_tool_version("${CARGO_EXECUTABLE}" v2)
    if(v1 LESS 1085 OR v2 LESS 1085)
      set(${why} "cargo and rustc 1.85 or later not found" PARENT_SCOPE)
      return()
    elseif(CMAKE_CROSSCOMPILING AND "${Rust_TARGET}" STREQUAL "")
      set(${why} "a cross build needs -DRust_TARGET=TRIPLE" PARENT_SCOPE)
      return()
    endif()
  endif()

  # The crate sources. Without a crate variable, cargo uses its default
  # sources, and cargo fetch --locked must pass. A vendor directory or a
  # system crate directory replaces crates.io. The build directory gets
  # that replacement in cargo-sources.toml. A TOML literal string holds
  # the directory, so the function rejects only a path with a "'".
  # The source replacement changes no tracked file. System crates can
  # have other versions than Cargo.lock, so system-crates mode writes the
  # workspace Cargo.lock again. A prebuilt staticlib skips cargo fetch,
  # but the xtask checks use the sources. A failed check removes
  # cargo-sources.toml.
  set(src_config "${CMAKE_BINARY_DIR}/cargo-sources.toml")
  file(REMOVE "${src_config}")
  set(src_var "")
  set(src_args "")
  set(src_note "")
  if(NOT ZOOKEEPER_CARGO_VENDOR STREQUAL "")
    set(src_var ZOOKEEPER_CARGO_VENDOR)
  elseif(NOT ZK_SYSTEM_RUST_CRATES STREQUAL "")
    set(src_var ZK_SYSTEM_RUST_CRATES)
  endif()
  if(src_var)
    get_filename_component(src_dir "${${src_var}}" ABSOLUTE BASE_DIR "${CMAKE_BINARY_DIR}")
    if(NOT IS_DIRECTORY "${src_dir}")
      set(${why} "the crate directory ${src_dir} of ${src_var} does not exist" PARENT_SCOPE)
      return()
    elseif(NOT CARGO_EXECUTABLE)
      set(${why} "cargo not found (needed with ${src_var})" PARENT_SCOPE)
      return()
    elseif("${src_dir}${src_config}" MATCHES "'")
      set(${why} "the build directory or the crate directory ${src_dir} of ${src_var} has a \"'\""
          PARENT_SCOPE)
      return()
    endif()
    set(kind directory)
    if(src_var STREQUAL "ZK_SYSTEM_RUST_CRATES" AND IS_DIRECTORY "${src_dir}/index")
      set(kind local-registry)
    endif()
    file(WRITE "${src_config}"
         "# The crate sources of this build. CMake writes this file.\n"
         "[source.crates-io]\nreplace-with = \"zk-local\"\n"
         "[source.zk-local]\n${kind} = '${src_dir}'\n")
    set(src_args --offline --config "${src_config}")
    set(src_note "cargo runs offline with the crates of ${src_dir} (${kind})")
    if(src_var STREQUAL "ZK_SYSTEM_RUST_CRATES")
      execute_process(COMMAND "${CARGO_EXECUTABLE}" generate-lockfile ${src_args}
                      WORKING_DIRECTORY "${ws}" RESULT_VARIABLE rc OUTPUT_QUIET ERROR_QUIET)
      if(NOT rc EQUAL 0)
        file(REMOVE "${src_config}")
        set(${why} "the system crates of ${src_dir} do not resolve the workspace: cargo generate-lockfile --offline failed"
            PARENT_SCOPE)
        return()
      endif()
      string(APPEND src_note "; cargo generate-lockfile wrote ${ws}/Cargo.lock again")
    endif()
  endif()
  # cargo fetch succeeds with network access, a full CARGO_HOME or a full
  # crate directory.
  if(ZKRS_STATICLIB STREQUAL "")
    execute_process(COMMAND "${CARGO_EXECUTABLE}" fetch --locked ${src_args} WORKING_DIRECTORY "${ws}"
                    RESULT_VARIABLE rc OUTPUT_QUIET ERROR_QUIET)
    if(NOT rc EQUAL 0 AND src_var)
      file(REMOVE "${src_config}")
      set(${why} "the crate directory ${src_dir} of ${src_var} does not have all crates of Cargo.lock: cargo fetch --locked --offline failed"
          PARENT_SCOPE)
      return()
    elseif(NOT rc EQUAL 0)
      set(${why} "no crate source: cargo fetch --locked failed" PARENT_SCOPE)
      return()
    endif()
  endif()
  if(src_note)
    message(STATUS "${src_note}")
  endif()

  set(ZKRS_CARGO_SOURCE_ARGS "${src_args}" PARENT_SCOPE)
  if(src_var)
    set(ZKRS_CARGO_SOURCE_CONFIG "${src_config}" PARENT_SCOPE)
  else()
    set(ZKRS_CARGO_SOURCE_CONFIG "" PARENT_SCOPE)
  endif()
  set(ZKRS_WORKSPACE "${ws}" PARENT_SCOPE)
  set(${ok} ON PARENT_SCOPE)
  set(${why} "" PARENT_SCOPE)
endfunction()
