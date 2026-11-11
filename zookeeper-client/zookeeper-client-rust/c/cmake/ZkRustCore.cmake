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

# The zookeeper and hashtable targets of the Rust core.
# ZkRustTls selects the TLS and SASL configuration. The C sources and the
# legacy headers come from CMAKE_CURRENT_SOURCE_DIR, the legacy C tree.
# The shim, the ABI data and the test runners come from ZKRS_DIR, the Rust
# C tree.
#
# The flavor follows WANT_SYNCAPI, as in the legacy build: ON gives mt and
# OFF gives st. One configure run builds one flavor. CMakeLists.txt
# defines THREADED for the whole directory when WANT_SYNCAPI is ON. Thus
# the shim, cli and the application get the same flags as with legacy.
#
# The zk-ffi staticlib, the shim of the flavor and the verbatim jute units
# become one pre-linked object. Only the keep list of the flavor stays
# global in it. The static zookeeper archive has this object as its only
# member. The optional zookeeper_<flavor> shared library exports the
# golden set of the flavor.

include(GNUInstallDirs)
include(ZkRustTls)
include(ZkRust)
include(ZkHarden)
if(WANT_SYNCAPI)
  set(zks_fl mt)
  find_package(Threads REQUIRED)
else()
  set(zks_fl st)
endif()
message("-- building the ${zks_fl} flavor of the Rust client core from ${ZKRS_WORKSPACE}")

# recordio.c and zookeeper.jute.c compile unchanged, with the legacy flags.
set(zks_c "${CMAKE_CURRENT_SOURCE_DIR}")
add_library(zks_jute OBJECT ${zks_c}/src/recordio.c ${zks_c}/generated/zookeeper.jute.c)
target_include_directories(zks_jute PRIVATE ${zks_c}/include ${CMAKE_CURRENT_BINARY_DIR}/include
                           ${zks_c}/generated)
target_compile_options(zks_jute PRIVATE -ffunction-sections -fdata-sections)
set_target_properties(zks_jute PROPERTIES POSITION_INDEPENDENT_CODE ON)

# The shim of the flavor. Only mt has the sync API and
# the library threads. st has no THREADED, as the legacy st library.
# A Debug build adds the handle registry.
set(zks_shim_units
  zks_data.c zks_handle.c zks_async.c zks_multi.c zks_drain.c
  zks_log.c zks_env.c zks_errors.c zks_resolve.c zks_rng.c
  zks_compat.c zks_layout_check.c)
if(zks_fl STREQUAL "mt")
  list(APPEND zks_shim_units zks_sync.c zks_threads.c)
  set(zks_flavor_defs THREADED)
else()
  set(zks_flavor_defs "")
endif()
set(zks_sources "")
foreach(f ${zks_shim_units})
  list(APPEND zks_sources "${ZKRS_DIR}/shim/${f}")
endforeach()
list(APPEND zks_sources ${ZKS_CONFIG_SOURCES})
add_library(zks_${zks_fl} STATIC ${zks_sources} $<TARGET_OBJECTS:zks_jute>)
target_include_directories(zks_${zks_fl} PRIVATE ${zks_c}/include ${zks_c}/generated
                           ${ZKRS_DIR}/shim)
target_compile_definitions(zks_${zks_fl} PRIVATE _GNU_SOURCE ${zks_flavor_defs} ${ZKS_CONFIG_DEFS}
                           $<$<CONFIG:Debug>:ZKS_HANDLE_REGISTRY>)
target_compile_options(zks_${zks_fl} PRIVATE ${ZKS_WARN_CFLAGS} ${ZKS_CFLAGS} ${ZKS_HARDEN_CFLAGS}
                       -ffunction-sections -fdata-sections)
set_target_properties(zks_${zks_fl} PROPERTIES POSITION_INDEPENDENT_CODE ON)
# The two Cyrus glue units get HAVE_CYRUS_SASL_H through ZKS_CONFIG_DEFS,
# and zks_internal.h removes it from the other units.
# Only the glue units get the Cyrus include directory, as a system
# directory, and the SASL hardening set.
if(ZKS_SASL_SOURCES)
  set(ZKS_HARDEN_SASL_CFLAGS ${ZKS_HARDEN_CFLAGS})
  set(zks_sasl_flags -Wconversion -Wsign-conversion)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i.86)$")
    list(APPEND zks_sasl_flags -fcf-protection)
  endif()
  # The macOS SDK marks the Cyrus API as deprecated, and -Werror must not
  # stop the glue that uses the SDK headers.
  if(APPLE AND CYRUS_SASL_INCLUDE_DIR MATCHES "(\\.sdk/|^/usr/include)")
    list(APPEND zks_sasl_flags -Wno-deprecated-declarations)
  endif()
  foreach(f ${zks_sasl_flags})
    zk_harden_flag(ZKS_HARDEN_SASL_CFLAGS zks_sasl_flag_ok ${f})
    if(NOT zks_sasl_flag_ok)
      message(STATUS "dropped the SASL glue flag ${f}")
    endif()
  endforeach()
  set(zks_sasl_opts ${ZKS_HARDEN_SASL_CFLAGS})
  if(CYRUS_SASL_INCLUDE_DIR)
    list(APPEND zks_sasl_opts -isystem "${CYRUS_SASL_INCLUDE_DIR}")
  endif()
  set_source_files_properties(${ZKS_SASL_SOURCES} PROPERTIES
    COMPILE_DEFINITIONS HAVE_CYRUS_SASL_H COMPILE_OPTIONS "${zks_sasl_opts}")
endif()

# The pre-link (abi/prelink.sh of ZKRS_DIR). One driver target runs it,
# so the static and the shared library do not run it in parallel.
set(zks_keep "${CMAKE_CURRENT_BINARY_DIR}/zookeeper_${zks_fl}.keep")
zk_rust_exports(${zks_fl} keep "${zks_keep}")
set(ZK_ALL_OBJ "${CMAKE_CURRENT_BINARY_DIR}/zookeeper_${zks_fl}_all${CMAKE_C_OUTPUT_EXTENSION}")
if(APPLE)
  set(zks_prelink_args --host-os darwin)
  list(LENGTH CMAKE_OSX_ARCHITECTURES zks_narch)
  if(zks_narch EQUAL 1)
    list(APPEND zks_prelink_args --arch ${CMAKE_OSX_ARCHITECTURES})
  elseif(zks_narch GREATER 1)
    message(FATAL_ERROR "the Rust core builds one architecture; give one CMAKE_OSX_ARCHITECTURES")
  endif()
else()
  string(TOLOWER "${CMAKE_SYSTEM_NAME}" zks_host_os)
  set(zks_prelink_args --host-os ${zks_host_os} --ld "${CMAKE_LINKER}")
  if(NOT CMAKE_OBJCOPY)
    message(FATAL_ERROR "the Rust client pre-link needs objcopy")
  endif()
  list(APPEND zks_prelink_args --objcopy "${CMAKE_OBJCOPY}")
endif()
if(CMAKE_NM)
  list(APPEND zks_prelink_args --nm "${CMAKE_NM}")
  set(zks_nm "${CMAKE_NM}")
else()
  set(zks_nm nm)
endif()
add_custom_command(OUTPUT "${ZK_ALL_OBJ}"
  COMMAND sh "${ZKRS_DIR}/abi/prelink.sh" --cc "${CMAKE_C_COMPILER}"
          ${zks_prelink_args} --shim $<TARGET_FILE:zks_${zks_fl}> --rust "${ZKRS_LIB}"
          --keep "${zks_keep}" --object "${ZK_ALL_OBJ}"
  DEPENDS zks_${zks_fl} "${ZKRS_LIB}" "${zks_keep}" "${ZKRS_DIR}/abi/prelink.sh"
  COMMENT "Pre-linking the Rust core object (${zks_fl})"
  VERBATIM)
add_custom_target(zks_${zks_fl}_all DEPENDS "${ZK_ALL_OBJ}")
add_dependencies(zks_${zks_fl}_all zkrs_cargo)
set_source_files_properties("${ZK_ALL_OBJ}" PROPERTIES EXTERNAL_OBJECT ON GENERATED ON)

# The link libraries of the core: the Rust native libraries and, on Linux,
# librt. mt adds the thread library. st adds none, as the legacy st
# library. On Linux the Rust native libraries give libpthread to st.
# A SASL build links the CyrusSASL target of FindCyrusSASL. The
# pkg-config file names -lsasl2.
if(ZKRS_SASL)
  set(zks_link_libs CyrusSASL)
else()
  set(zks_link_libs "")
endif()
list(APPEND zks_link_libs ${ZKRS_NATIVE_LIBS} $<$<PLATFORM_ID:Linux>:rt>)
if(zks_fl STREQUAL "mt")
  list(APPEND zks_link_libs Threads::Threads)
endif()

# The hashtable archive stays for build compatibility. Its
# only member defines no global symbol.
add_library(hashtable STATIC ${ZKRS_DIR}/shim/zks_hashtable_stub.c)
target_include_directories(hashtable PUBLIC ${zks_c}/include)
target_compile_options(hashtable PRIVATE ${ZKS_WARN_CFLAGS})

# The hashtable check: hashtable has one member and no
# global definition. The archive symbol index is not a member. Each build
# of hashtable runs the check, and ctest runs it again. A semicolon is a
# list separator in CMake, so the shell code has none.
set(zks_hashtable_check sh -c
  "g=$(\"$1\" -g \"$3\" | awk 'NF >= 3 && $(NF - 1) ~ /^[A-TV-Z]$/ { print $NF }') && n=$(\"$2\" t \"$3\" | awk '!/^__.SYMDEF/ { n++ } END { print n + 0 }') && ( ( test -z \"$g\" && test \"$n\" = 1 ) || ( echo \"$3: $n members, globals: $g\" >&2 && exit 1 ) )"
  sh "${zks_nm}" "${CMAKE_AR}" $<TARGET_FILE:hashtable>)
add_custom_command(TARGET hashtable POST_BUILD
  COMMAND ${zks_hashtable_check}
  COMMENT "Checking that the hashtable archive has no global symbol"
  VERBATIM)

add_library(zookeeper STATIC "${ZK_ALL_OBJ}")
add_dependencies(zookeeper zks_${zks_fl}_all)
set_target_properties(zookeeper PROPERTIES LINKER_LANGUAGE C)
target_include_directories(zookeeper PUBLIC ${zks_c}/include ${CMAKE_CURRENT_BINARY_DIR}/include
                           ${zks_c}/generated)
target_link_libraries(zookeeper PUBLIC hashtable ${zks_link_libs})
# The consumers see the legacy feature macros of zookeeper.h. With TLS,
# zookeeper.h includes openssl/ossl_typ.h, so the consumers also get the
# OpenSSL include directory. The build never links OpenSSL.
if(ZKRS_TLS)
  target_compile_definitions(zookeeper PUBLIC HAVE_OPENSSL_H)
  if(ZKRS_OPENSSL_INCLUDE_DIR)
    target_include_directories(zookeeper SYSTEM PUBLIC "${ZKRS_OPENSSL_INCLUDE_DIR}")
  endif()
endif()
if(ZKRS_SASL)
  target_compile_definitions(zookeeper PUBLIC HAVE_CYRUS_SASL_H)
endif()
# Install also puts hashtable in the library directory. Thus a
# -lzookeeper -lhashtable line also links against the install prefix.
set(zks_install_targets zookeeper hashtable)

if(ZOOKEEPER_BUILD_SHARED)
  set(zks_shared zookeeper_${zks_fl})
  add_library(${zks_shared} SHARED "${ZK_ALL_OBJ}")
  add_dependencies(${zks_shared} zks_${zks_fl}_all)
  set_target_properties(${zks_shared} PROPERTIES LINKER_LANGUAGE C SOVERSION 2)
  target_link_libraries(${zks_shared} PRIVATE ${zks_link_libs})
  if(APPLE)
    # The legacy library: an absolute install name and version 3.0.0
    # (-version-info 2). No -Bsymbolic, so interposition is as in legacy.
    if(CMAKE_VERSION VERSION_LESS 3.17)
      message(FATAL_ERROR "the Mach-O shared library needs CMake 3.17 or later")
    endif()
    set(zks_exports "${CMAKE_CURRENT_BINARY_DIR}/zookeeper_${zks_fl}.exp")
    zk_rust_exports(${zks_fl} exp "${zks_exports}")
    set_target_properties(${zks_shared} PROPERTIES
      MACHO_COMPATIBILITY_VERSION 3.0.0 MACHO_CURRENT_VERSION 3.0.0
      INSTALL_NAME_DIR "${CMAKE_INSTALL_FULL_LIBDIR}")
    target_link_options(${zks_shared} PRIVATE "LINKER:-exported_symbols_list,${zks_exports}"
                        "LINKER:-dead_strip")
  else()
    set(zks_exports "${CMAKE_CURRENT_BINARY_DIR}/zookeeper_${zks_fl}.map")
    zk_rust_exports(${zks_fl} map "${zks_exports}")
    set_target_properties(${zks_shared} PROPERTIES VERSION 2.0.0)
    target_link_options(${zks_shared} PRIVATE "LINKER:--version-script=${zks_exports}"
                        "LINKER:--gc-sections")
  endif()
  set_property(TARGET ${zks_shared} APPEND PROPERTY LINK_DEPENDS "${zks_exports}")
  list(APPEND zks_install_targets ${zks_shared})
endif()

# The golden checks. abi-check checks the shared library. abi-static
# checks the static archive.
# xtask builds in the cargo directory of this build.
# The ctest tests zk_abi_check and zk_abi_static run the same commands.
if(CARGO_EXECUTABLE)
  set(zks_xtask "${CMAKE_COMMAND}" -E env "CARGO_TARGET_DIR=${ZKRS_CARGO_DIR}"
      "${CARGO_EXECUTABLE}" ${ZKRS_CARGO_SOURCE_ARGS} xtask abi)
  set(zks_abi_static_cmd ${zks_xtask} static $<TARGET_FILE:zookeeper> --flavor ${zks_fl}
      --config ${ZKRS_ABI_CONFIG})
  set(zks_abi_check_cmd ${zks_xtask} check $<TARGET_FILE:zookeeper_${zks_fl}> --flavor ${zks_fl}
      --config ${ZKRS_ABI_CONFIG})
  if(TARGET zookeeper_${zks_fl})
    add_custom_target(abi-check COMMAND ${zks_abi_check_cmd}
      DEPENDS zookeeper_${zks_fl}
      WORKING_DIRECTORY "${ZKRS_WORKSPACE}"
      USES_TERMINAL VERBATIM)
  endif()
  add_custom_target(abi-static COMMAND ${zks_abi_static_cmd}
    DEPENDS zookeeper
    WORKING_DIRECTORY "${ZKRS_WORKSPACE}"
    USES_TERMINAL VERBATIM)
endif()

# The six legacy headers, and the libraries.
install(FILES ${zks_c}/include/zookeeper.h ${zks_c}/include/zookeeper_version.h
              ${zks_c}/include/zookeeper_log.h ${zks_c}/include/proto.h
              ${zks_c}/include/recordio.h ${zks_c}/generated/zookeeper.jute.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/zookeeper")
install(TARGETS ${zks_install_targets}
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

# The pkg-config file of the flavor. Libs names the
# shared library when the build makes it, else the two archives.
# Libs.private has each link library of the core once, and no OpenSSL. A
# SASL build adds -lsasl2.
foreach(d LIBDIR INCLUDEDIR)
  if(IS_ABSOLUTE "${CMAKE_INSTALL_${d}}")
    set(zks_pc_${d} "${CMAKE_INSTALL_${d}}")
  else()
    set(zks_pc_${d} "\${prefix}/${CMAKE_INSTALL_${d}}")
  endif()
endforeach()
if(ZOOKEEPER_BUILD_SHARED)
  set(zks_pc_libs "-lzookeeper_${zks_fl}")
else()
  set(zks_pc_libs "-lzookeeper -lhashtable")
endif()
# The zk_abi_link_flags test also links with this list.
set(zks_core_libs ${ZKRS_SASL_LIBS} ${ZKRS_NATIVE_LIBS})
if(zks_fl STREQUAL "mt")
  set(zks_pc_desc "multi-threaded")
  list(APPEND zks_core_libs ${CMAKE_THREAD_LIBS_INIT})
else()
  set(zks_pc_desc "single-threaded")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND zks_core_libs -lrt)
endif()
list(REMOVE_DUPLICATES zks_core_libs)
string(JOIN " " zks_pc_private ${zks_core_libs})
set(zks_pc "${CMAKE_CURRENT_BINARY_DIR}/zookeeper_${zks_fl}.pc")
file(WRITE "${zks_pc}.in" "prefix=${CMAKE_INSTALL_PREFIX}
exec_prefix=\${prefix}
libdir=${zks_pc_LIBDIR}
includedir=${zks_pc_INCLUDEDIR}

Name: zookeeper_${zks_fl}
Description: Apache ZooKeeper C client library, ${zks_pc_desc}
Version: ${PROJECT_VERSION}
Cflags: -I\${includedir} -I\${includedir}/zookeeper
Libs: -L\${libdir} ${zks_pc_libs}
Libs.private: ${zks_pc_private}
")
configure_file("${zks_pc}.in" "${zks_pc}" COPYONLY)
install(FILES "${zks_pc}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# ctest runs the Rust tests (label "rust") when the build runs cargo. The
# CppUnit tests need the legacy core.
enable_testing()
if(ZKRS_STATICLIB STREQUAL "")
  add_test(NAME zkrs_workspace_tests
    COMMAND "${CMAKE_COMMAND}" -E env "CARGO_TARGET_DIR=${ZKRS_CARGO_DIR}"
            "${CARGO_EXECUTABLE}" ${ZKRS_CARGO_SOURCE_ARGS} test --locked --workspace --exclude zk-ffi
    WORKING_DIRECTORY "${ZKRS_WORKSPACE}")
  add_test(NAME zkrs_ffi_tests
    COMMAND "${CMAKE_COMMAND}" -E env "CARGO_TARGET_DIR=${ZKRS_CARGO_DIR}"
            ${ZKRS_TLS_ENV} "${CARGO_EXECUTABLE}" ${ZKRS_CARGO_SOURCE_ARGS} test --locked -p zk-ffi ${ZKRS_CARGO_FEATURES}
    WORKING_DIRECTORY "${ZKRS_WORKSPACE}")
  set_tests_properties(zkrs_workspace_tests zkrs_ffi_tests PROPERTIES LABELS rust)
endif()

# The ABI tests have the ctest label "abi" (ctest -L abi). They check the
# built artifacts, so they run after the build. The server tests of
# tests/abi run only when ZK_ABI_TEST_HOST names a running server.
# A source release can omit ZKRS_DIR/tests. Then the build registers only
# the tests that need no file from it.
set(ZK_ABI_TEST_HOST "" CACHE STRING "host:port of a running server for the ABI tests; empty skips them")
set(ZK_ABI_TEST_DEAD_HOST "" CACHE STRING "host:port with no server for the ABI tests; empty: the default")
set(ZK_ABI_TEST_REF "" CACHE PATH "Directory of a legacy library of this flavor for the ABI tests")
set(zks_abi_tests zk_abi_hashtable zk_abi_link_target zk_abi_link_flags)
add_test(NAME zk_abi_hashtable COMMAND ${zks_hashtable_check})

# The link check: an application links with target_link_libraries(app zookeeper
# hashtable), and with a hand-written -lzookeeper -lhashtable line. The
# program calls a C entry, a data object and a Rust entry. configure_file
# writes the source only when it changes.
set(zks_link_src "${CMAKE_CURRENT_BINARY_DIR}/zks_link_check.c")
file(WRITE "${zks_link_src}.in" "/* Generated by cmake/ZkRustCore.cmake. */
#include <stdio.h>
#include <string.h>
#ifdef ZKS_LINK_NO_OPENSSL_H
#undef HAVE_OPENSSL_H
#endif
#include <zookeeper.h>
int main(void)
{
    int rc = zoo_acreate_ttl(NULL, \"/a\", NULL, -1, &ZOO_OPEN_ACL_UNSAFE, ZOO_PERSISTENT_WITH_TTL,
                             0, NULL, NULL);
    if (rc != ZBADARGUMENTS || ZOO_CONNECTED_STATE != 3 || strcmp(zoo_version_str(), ZOO_VERSION)) {
        fprintf(stderr, \"zks_link_check: unexpected result %d\\n\", rc);
        return 1;
    }
    return 0;
}
")
configure_file("${zks_link_src}.in" "${zks_link_src}" COPYONLY)
add_executable(zks_link_check "${zks_link_src}")
target_link_libraries(zks_link_check zookeeper hashtable)
# WITH_RUST_TLS=ON can build TLS on a host without OpenSSL headers. The
# zookeeper target then gives HAVE_OPENSSL_H to its consumers, and they
# cannot compile zookeeper.h. This check tests the link
# interface only, so it compiles zookeeper.h without the OpenSSL part.
if(ZKRS_SKIP_PROGRAMS)
  target_compile_definitions(zks_link_check PRIVATE ZKS_LINK_NO_OPENSSL_H)
endif()
add_test(NAME zk_abi_link_target COMMAND zks_link_check)
# A SASL build finds libsasl2 in the directory of the Cyrus SASL probe.
set(zks_link_flags ${zks_core_libs})
if(ZKRS_SASL)
  get_filename_component(zks_sasl_libdir "${CYRUS_SASL_SHARED_LIB}" DIRECTORY)
  list(INSERT zks_link_flags 0 -L${zks_sasl_libdir})
endif()
set(zks_link_cflags "")
foreach(d ${zks_flavor_defs})
  list(APPEND zks_link_cflags -D${d})
endforeach()
add_test(NAME zk_abi_link_flags
  COMMAND sh -c "out=$1 && shift && \"$@\" -o \"$out\" && \"$out\"" sh
          "${CMAKE_CURRENT_BINARY_DIR}/zks_link_flags_check" "${CMAKE_C_COMPILER}"
          ${zks_link_cflags} -I${CMAKE_CURRENT_SOURCE_DIR}/include
          -I${CMAKE_CURRENT_BINARY_DIR}/include -I${CMAKE_CURRENT_SOURCE_DIR}/generated
          "${zks_link_src}" -L$<TARGET_FILE_DIR:zookeeper> -L$<TARGET_FILE_DIR:hashtable>
          -lzookeeper -lhashtable ${zks_link_flags})

if(CARGO_EXECUTABLE)
  add_test(NAME zk_abi_static COMMAND ${zks_abi_static_cmd} WORKING_DIRECTORY "${ZKRS_WORKSPACE}")
  list(APPEND zks_abi_tests zk_abi_static)
endif()
if(TARGET zookeeper_${zks_fl})
  if(CARGO_EXECUTABLE)
    add_test(NAME zk_abi_check COMMAND ${zks_abi_check_cmd} WORKING_DIRECTORY "${ZKRS_WORKSPACE}")
    list(APPEND zks_abi_tests zk_abi_check)
  endif()
  # The runner of tests/abi. Its xtask check compares the install name
  # with --lib. The build tree library has an @rpath install name, so
  # zk_abi_check runs the xtask check instead. The runner default is mt,
  # so only st gives the flavor option.
  set(zks_abi_args --lib $<TARGET_FILE_DIR:zookeeper_${zks_fl}> --no-xtask
      --out "${CMAKE_CURRENT_BINARY_DIR}/abi-tests")
  if(zks_fl STREQUAL "st")
    list(APPEND zks_abi_args --flavor st)
  endif()
  if(NOT ZK_ABI_TEST_HOST STREQUAL "")
    list(APPEND zks_abi_args --host "${ZK_ABI_TEST_HOST}")
  endif()
  if(NOT ZK_ABI_TEST_DEAD_HOST STREQUAL "")
    list(APPEND zks_abi_args --dead-host "${ZK_ABI_TEST_DEAD_HOST}")
  endif()
  if(NOT ZK_ABI_TEST_REF STREQUAL "")
    list(APPEND zks_abi_args --ref "${ZK_ABI_TEST_REF}")
  endif()
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    list(APPEND zks_abi_args --debug-lib $<TARGET_FILE_DIR:zookeeper_${zks_fl}>)
  endif()
  # The configuration selects the golden set and the expected libraries.
  list(APPEND zks_abi_args --config "${ZKRS_ABI_CONFIG}")
  if(EXISTS "${ZKRS_DIR}/tests/abi/run-abi-tests.sh")
    add_test(NAME zk_abi_tests
      COMMAND "${CMAKE_COMMAND}" -E env "CC=${CMAKE_C_COMPILER}"
              "${ZKRS_DIR}/tests/abi/run-abi-tests.sh" ${zks_abi_args})
    list(APPEND zks_abi_tests zk_abi_tests)
  endif()
endif()
set_tests_properties(${zks_abi_tests} PROPERTIES LABELS abi)

# The link tests of ZKRS_DIR/tests/link have the ctest label "link".
# They link programs with the static archive.
# They also build tests/link/cmake-consumer. That project includes the
# legacy C tree with add_subdirectory(). The consumer uses the zk-ffi
# staticlib of this build, so it does not run cargo.
# zk_abi_static runs the xtask check of the archive.
# A SASL archive also needs libsasl2. LIBRARY_PATH names its directory,
# because the link test programs do not get the link directories of CMake.
# ZKRS_WORKSPACE gives the runner the TLS fixtures, also when the C sources
# are a copy outside the repository. ZKRS_CARGO_SOURCE_CONFIG gives the
# cargo calls of the runner the crate sources of this build. check-link
# of rust.am does the same.
string(JOIN " " zks_native_str ${ZKRS_NATIVE_LIBS} ${ZKRS_SASL_LIBS})
set(zks_link_env "CC=${CMAKE_C_COMPILER}" "ZKRS_WORKSPACE=${ZKRS_WORKSPACE}"
    "ZKRS_CARGO_SOURCE_CONFIG=${ZKRS_CARGO_SOURCE_CONFIG}")
if(ZKRS_SASL)
  list(APPEND zks_link_env "LIBRARY_PATH=${zks_sasl_libdir}")
endif()
# The consumer gets the TLS and SASL options of this build, so that it
# makes the same decision as the staticlib. It also gets the workspace,
# because its core check needs the workspace also with a prebuilt staticlib.
set(zks_link_args --flavor ${zks_fl} --config ${ZKRS_ABI_CONFIG} --archive $<TARGET_FILE:zookeeper>
    --hashtable $<TARGET_FILE:hashtable> --native-libs "${zks_native_str}" --no-xtask
    --cmake-consumer --cmake "${CMAKE_COMMAND}" --rust-staticlib "${ZKRS_LIB}"
    --cmake-arg "-DWITH_OPENSSL=${WITH_OPENSSL}" --cmake-arg "-DWITH_CYRUS_SASL=${WITH_CYRUS_SASL}"
    --cmake-arg "-DZK_RUST_TLS_PROVIDER=${ZK_RUST_TLS_PROVIDER}"
    --cmake-arg "-DZKRS_WORKSPACE=${ZKRS_WORKSPACE}"
    --out "${CMAKE_CURRENT_BINARY_DIR}/link-tests")
if(WITH_RUST_TLS)
  list(APPEND zks_link_args --cmake-arg -DWITH_RUST_TLS=ON)
endif()
if(NOT ZK_ABI_TEST_HOST STREQUAL "")
  list(APPEND zks_link_args --host "${ZK_ABI_TEST_HOST}")
endif()
if(NOT ZK_ABI_TEST_REF STREQUAL "")
  list(APPEND zks_link_args --ref "${ZK_ABI_TEST_REF}")
endif()
if(EXISTS "${ZKRS_DIR}/tests/link/run-link-tests.sh")
  add_test(NAME zk_link_tests
    COMMAND "${CMAKE_COMMAND}" -E env ${zks_link_env}
            "${ZKRS_DIR}/tests/link/run-link-tests.sh" ${zks_link_args})
  set_tests_properties(zk_link_tests PROPERTIES LABELS link TIMEOUT 1200)
endif()
