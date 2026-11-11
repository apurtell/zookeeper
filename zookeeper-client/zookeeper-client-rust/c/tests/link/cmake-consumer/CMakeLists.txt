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

# LINK-04: a CMake application that includes the C client with
# add_subdirectory(). It links with target_link_libraries(app zookeeper
# hashtable), as a legacy CMake application does. The zookeeper target gives
# the include directories and the native libraries of the Rust core. The C
# client defines THREADED only for its own directory, so the application
# defines it for the mt flavor, as with legacy.
#
# Give the C client directory as ZK_C_SOURCE_DIR. The options of the C
# client (WITH_RUST_CLIENT, WANT_SYNCAPI, ZKRS_STATICLIB and others) go
# to its CMakeLists.txt unchanged. The application source link_app.c is
# in the parent directory, tests/link.

cmake_minimum_required(VERSION 3.15)
project(zklink_consumer C)

if(NOT ZK_C_SOURCE_DIR)
  message(FATAL_ERROR "give -DZK_C_SOURCE_DIR=<zookeeper-client-c>")
endif()
add_subdirectory("${ZK_C_SOURCE_DIR}" zookeeper)

add_executable(zklink_consumer "${CMAKE_CURRENT_LIST_DIR}/../link_app.c")
target_link_libraries(zklink_consumer zookeeper hashtable)
if(WANT_SYNCAPI)
  target_compile_definitions(zklink_consumer PRIVATE THREADED)
endif()
