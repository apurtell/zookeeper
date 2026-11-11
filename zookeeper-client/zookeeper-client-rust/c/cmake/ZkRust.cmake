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

# The Rust part of the Rust core build.
# zk_rust_check ran before this module, so the workspace and the tools are
# known. The module sets these variables:
#   ZKRS_PROFILE      the cargo profile: capi-dev for a Debug build, else capi
#   ZKRS_RUST_TARGET  the target triple: Rust_TARGET, else the rustc host
#   ZKRS_LIB          the zk-ffi staticlib
#   ZKRS_NATIVE_LIBS  the native libraries that a Rust staticlib needs
#   ZK_VERSION_H      the header that zk-ffi/build.rs reads
# It also adds the zkrs_cargo target and the function zk_rust_exports.

set(ZK_VERSION_H "${CMAKE_CURRENT_SOURCE_DIR}/include/zookeeper_version.h")
set(ZKRS_CARGO_DIR "${CMAKE_BINARY_DIR}/cargo")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(ZKRS_PROFILE capi-dev)
else()
  set(ZKRS_PROFILE capi)
endif()

if(NOT "${Rust_TARGET}" STREQUAL "")
  set(ZKRS_RUST_TARGET "${Rust_TARGET}")
  set(ZKRS_TARGET_ARGS --target "${Rust_TARGET}")
else()
  execute_process(COMMAND "${RUSTC_EXECUTABLE}" -vV OUTPUT_VARIABLE rustc_info ERROR_QUIET)
  string(REGEX MATCH "host: [^\n]*" rustc_host "${rustc_info}")
  string(REPLACE "host: " "" ZKRS_RUST_TARGET "${rustc_host}")
  set(ZKRS_TARGET_ARGS "")
endif()
string(REGEX REPLACE "[.-]" "_" zkrs_target_env "${ZKRS_RUST_TARGET}")

# The native libraries of an empty Rust staticlib, without the C library,
# which the C driver adds.
set(zkrs_probe "${CMAKE_BINARY_DIR}/CMakeFiles/zkrs-probe")
file(MAKE_DIRECTORY "${zkrs_probe}")
file(WRITE "${zkrs_probe}/conftest.rs" "")
execute_process(
  COMMAND "${RUSTC_EXECUTABLE}" --crate-type staticlib --crate-name conftest ${ZKRS_TARGET_ARGS}
          --print native-static-libs -o "${zkrs_probe}/libconftest.a" "${zkrs_probe}/conftest.rs"
  OUTPUT_VARIABLE zkrs_out ERROR_VARIABLE zkrs_err RESULT_VARIABLE zkrs_rc)
file(REMOVE_RECURSE "${zkrs_probe}")
if(NOT zkrs_rc EQUAL 0)
  message(FATAL_ERROR "rustc cannot build a staticlib for ${ZKRS_RUST_TARGET}:\n${zkrs_err}")
endif()
string(REGEX MATCH "native-static-libs: [^\n]*" zkrs_native "${zkrs_out}${zkrs_err}")
string(REPLACE "native-static-libs: " "" zkrs_native "${zkrs_native}")
separate_arguments(zkrs_native UNIX_COMMAND "${zkrs_native}")
set(ZKRS_NATIVE_LIBS "")
foreach(lib IN LISTS zkrs_native)
  if(NOT lib MATCHES "^-l(c|System)$")
    list(APPEND ZKRS_NATIVE_LIBS "${lib}")
  endif()
endforeach()
list(REMOVE_DUPLICATES ZKRS_NATIVE_LIBS)
message(STATUS "The native libraries of a Rust staticlib: ${ZKRS_NATIVE_LIBS}")

if(NOT ZKRS_STATICLIB STREQUAL "")
  # Another build made the staticlib. The build never runs cargo.
  get_filename_component(ZKRS_LIB "${ZKRS_STATICLIB}" ABSOLUTE)
  add_custom_target(zkrs_cargo)
else()
  if(NOT "${Rust_TARGET}" STREQUAL "")
    set(ZKRS_LIB "${ZKRS_CARGO_DIR}/${Rust_TARGET}/${ZKRS_PROFILE}/libzk_ffi.a")
  else()
    set(ZKRS_LIB "${ZKRS_CARGO_DIR}/${ZKRS_PROFILE}/libzk_ffi.a")
  endif()
  # cargo runs on each build. It does not write the staticlib again when
  # the sources do not change, so the pre-link runs only after a change.
  # A make recipe does not get the descriptors of the make jobserver, so
  # cargo gets no MAKEFLAGS and uses its own job count. Each cargo call
  # gets ZKRS_CARGO_SOURCE_ARGS, the crate sources of zk_rust_check.
  add_custom_target(zkrs_cargo
    COMMAND "${CMAKE_COMMAND}" -E env --unset=MAKEFLAGS --unset=MFLAGS
            "CARGO_TARGET_DIR=${ZKRS_CARGO_DIR}"
            "ZK_VERSION_H=${ZK_VERSION_H}" "CC_${zkrs_target_env}=${CMAKE_C_COMPILER}"
            "AR_${zkrs_target_env}=${CMAKE_AR}" ${ZKRS_TLS_ENV}
            "${CARGO_EXECUTABLE}" ${ZKRS_CARGO_SOURCE_ARGS} rustc --manifest-path "${ZKRS_WORKSPACE}/Cargo.toml" -p zk-ffi
            ${ZKRS_CARGO_FEATURES}
            --profile ${ZKRS_PROFILE} ${ZKRS_TARGET_ARGS} --locked --crate-type staticlib
    BYPRODUCTS "${ZKRS_LIB}"
    WORKING_DIRECTORY "${ZKRS_WORKSPACE}"
    COMMENT "Building the zk-ffi staticlib (${ZKRS_PROFILE})"
    USES_TERMINAL VERBATIM)
endif()

# Writes the symbol list FMT of FLAVOR to OUT (abi/gen-exports.awk). The
# list comes from the golden files at configure time. A change to those
# files runs the configure step again.
find_program(ZK_AWK NAMES awk gawk nawk mawk)
if(NOT ZK_AWK)
  message(FATAL_ERROR "the Rust core build needs awk")
endif()
function(zk_rust_exports flavor fmt out)
  set(abi "${ZKRS_DIR}/abi")
  set(inputs "${abi}/gen-exports.awk" "${abi}/symbols.tsv" "${abi}/static-symbols.tsv")
  execute_process(
    COMMAND "${ZK_AWK}" -f "${abi}/gen-exports.awk" -v flavor=${flavor} -v fmt=${fmt}
            -v ssl=${ZKRS_SSL01} -v sasl=${ZKRS_SASL01} "${abi}/symbols.tsv" "${abi}/static-symbols.tsv"
    OUTPUT_FILE "${out}" RESULT_VARIABLE rc)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "gen-exports.awk failed for ${flavor} ${fmt}")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${inputs})
endfunction()
