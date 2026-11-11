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

# This module builds the public-API suite zktest-public-mt or
# zktest-public-st. The suite uses only the public API and
# no mocks, so it builds with either core. WANT_SYNCAPI selects the
# flavor, as for the library. The suite links the shared library of the
# flavor when the build has it. The ctest label is "public", and the
# check-public target runs the suite.
#
# The suite compiles copies of the legacy test sources, so the legacy
# sources stay as they are. tests/public/gen-sources.sh of the Rust C tree
# makes the copies with the ports of the cache variables below.
#
# The module needs the zookeeper targets. ZkRustClient.cmake includes it
# for the Rust core. The legacy CMakeLists.txt includes it at its end.
# The module uses the policies of CMake 3.15 when they are available, as
# the Rust core modules do.
#
# A source release can omit the tests directory of the Rust C tree. The
# build then works, but WANT_CPPUNIT_PUBLIC=ON stops the configure step.
if(NOT CMAKE_VERSION VERSION_LESS 3.15)
  cmake_policy(VERSION 3.15)
endif()
get_filename_component(zktest_public_dir "${CMAKE_CURRENT_LIST_DIR}/../tests/public" ABSOLUTE)
option(WANT_CPPUNIT_PUBLIC "Build the public-API CppUnit suite zktest-public-mt or -st" OFF)
if(WANT_CPPUNIT_PUBLIC AND NOT EXISTS "${zktest_public_dir}/gen-sources.sh")
  message(FATAL_ERROR "WANT_CPPUNIT_PUBLIC needs ${zktest_public_dir}")
endif()
set(ZKTEST_PORT 22181 CACHE STRING "Client port of the public-API suite server")
set(ZKTEST_DOWN_PORT 22182 CACHE STRING "A client port with no server, for the public-API suite")
set(ZKTEST_QUORUM_PORT_BASE 0 CACHE STRING "First of nine reconfig quorum ports (0: legacy ports)")
set(ZKTEST_RO_PORT_BASE 0 CACHE STRING "First of six read-only ensemble ports (0: legacy ports)")
set(ZKTEST_SSL_PORT 22281 CACHE STRING "Secure client port of the public-API suite server (testSSL*)")
set(ZKTEST_CERT_DIR /tmp/certs CACHE STRING "Directory of the gencerts.sh certificates (testSSL*)")
if(WANT_CPPUNIT_PUBLIC)
  if(WIN32)
    message(FATAL_ERROR "WANT_CPPUNIT_PUBLIC needs a POSIX host")
  endif()
  # The st suite has no THREADED, so it has only the cases that need
  # neither the sync API nor threads.
  if(WANT_SYNCAPI)
    set(zktest_fl mt)
  else()
    set(zktest_fl st)
  endif()
  set(zktest_public zktest-public-${zktest_fl})
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(ZKTEST_PC_CPPUNIT QUIET cppunit)
  endif()
  find_path(CPPUNIT_INCLUDE_DIR cppunit/TestFixture.h HINTS ${ZKTEST_PC_CPPUNIT_INCLUDE_DIRS})
  find_library(CPPUNIT_LIBRARY cppunit HINTS ${ZKTEST_PC_CPPUNIT_LIBRARY_DIRS})
  if(NOT CPPUNIT_INCLUDE_DIR OR NOT CPPUNIT_LIBRARY)
    message(FATAL_ERROR "WANT_CPPUNIT_PUBLIC needs CppUnit")
  endif()
  set(zktest_public_server
    "ZOOPORT=${ZKTEST_PORT} ZKTEST_RO_PORT_BASE=${ZKTEST_RO_PORT_BASE} ZKTEST_SSL_PORT=${ZKTEST_SSL_PORT} ZKTEST_CERT_DIR=${ZKTEST_CERT_DIR} ${zktest_public_dir}/zkServer.sh")
  # The suites run in link order. TestClient stops the server at its end,
  # so TestMulti must come before TestClient. This order is the order of
  # the legacy suite. The compatibility ledger reads this list.
  set(zktest_public_sources
    TestDriver.cc LibCSymTable.cc Util.cc ThreadingUtil.cc TestReconfigServer.cc
    TestClientRetry.cc TestMulti.cc TestClient.cc
    ZooKeeperQuorumServer.cc TestReadOnlyClient.cc TestLogClientEnv.cc
    TestSASLAuth.cc)
  # The copy of ZooKeeperQuorumServer.h holds the quorum ports. A change to
  # a port value changes the values file. Then the build makes the copies
  # again.
  set(zktest_public_gen ${CMAKE_CURRENT_BINARY_DIR}/zktest-public-src)
  set(zktest_public_args ${ZKTEST_PORT} ${ZKTEST_DOWN_PORT} ${ZKTEST_SSL_PORT}
    ${ZKTEST_CERT_DIR} ${ZKTEST_QUORUM_PORT_BASE})
  file(WRITE ${zktest_public_gen}/values.new "${zktest_public_args}\n")
  configure_file(${zktest_public_gen}/values.new ${zktest_public_gen}/values COPYONLY)
  set(zktest_public_out)
  set(zktest_public_in)
  foreach(f ${zktest_public_sources} ZooKeeperQuorumServer.h)
    list(APPEND zktest_public_out ${zktest_public_gen}/${f})
    list(APPEND zktest_public_in ${CMAKE_CURRENT_SOURCE_DIR}/tests/${f})
  endforeach()
  add_custom_command(OUTPUT ${zktest_public_out}
    COMMAND sh ${zktest_public_dir}/gen-sources.sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests ${zktest_public_args} ${zktest_public_out}
    DEPENDS ${zktest_public_dir}/gen-sources.sh
            ${zktest_public_dir}/omit-cases.txt
            ${zktest_public_gen}/values ${zktest_public_in}
    VERBATIM)
  add_executable(${zktest_public} ${zktest_public_out})
  set_target_properties(${zktest_public} PROPERTIES CXX_STANDARD 11)
  # The cases that the suite does not register still compile. They read
  # the internals, so they need the source root and config.h.
  target_include_directories(${zktest_public} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_SOURCE_DIR}/generated ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/include ${CPPUNIT_INCLUDE_DIR})
  target_compile_definitions(${zktest_public} PRIVATE
    "ZKSERVER_CMD=\"${zktest_public_server}\"")
  if(WANT_SYNCAPI)
    target_compile_definitions(${zktest_public} PRIVATE THREADED)
  endif()
  if(ZOO_IPV6_ENABLED)
    target_compile_definitions(${zktest_public} PRIVATE ZOO_IPV6_ENABLED)
  endif()
  # With the shared library, the loader path at run time selects the core.
  if(TARGET zookeeper_${zktest_fl})
    target_link_libraries(${zktest_public} PRIVATE zookeeper_${zktest_fl})
    set(zktest_public_libdir --libdir $<TARGET_FILE_DIR:zookeeper_${zktest_fl}>)
  else()
    target_link_libraries(${zktest_public} PRIVATE zookeeper)
    set(zktest_public_libdir)
  endif()
  # ThreadingUtil.cc gets the libc lock functions from LibCSymTable.cc
  # through dlsym, so the suite links the dl library.
  target_link_libraries(${zktest_public} PRIVATE ${CPPUNIT_LIBRARY} ${CMAKE_DL_LIBS})
  if(WANT_SYNCAPI)
    find_package(Threads REQUIRED)
    target_link_libraries(${zktest_public} PRIVATE Threads::Threads)
  endif()

  enable_testing()
  add_test(NAME zktest_public_${zktest_fl}
    COMMAND "${CMAKE_COMMAND}" -E env "ZKTEST_PORT=${ZKTEST_PORT}"
            "ZKTEST_RO_PORT_BASE=${ZKTEST_RO_PORT_BASE}"
            "${zktest_public_dir}/run-public.sh" ${zktest_public_libdir}
            --workdir "${CMAKE_CURRENT_BINARY_DIR}/zktest-public" $<TARGET_FILE:${zktest_public}>)
  set_tests_properties(zktest_public_${zktest_fl} PROPERTIES LABELS public TIMEOUT 1800)
  add_custom_target(check-public
    COMMAND "${CMAKE_CTEST_COMMAND}" -L public --output-on-failure
    DEPENDS ${zktest_public}
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    USES_TERMINAL)
endif()
