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

# The compile flags of the shim. The module probes each
# flag with -Werror and drops each flag that the compiler rejects, with a
# message. It sets these variables:
#   ZKS_CFLAGS         -fsemantic-interposition and -fexceptions
#   ZKS_HARDEN_CFLAGS  the hardening set
#   ZKS_WARN_CFLAGS    the warning set, with -Werror when ZK_WERROR is ON

include(CheckCSourceCompiles)

# Appends FLAGS (a list) to the variable VAR when the compiler accepts them
# without a warning. RESULT gets ON or OFF.
function(zk_harden_flag var result)
  string(MAKE_C_IDENTIFIER "ZKS_FLAG_${ARGN}" key)
  string(REPLACE ";" " " flags "${ARGN}")
  set(CMAKE_REQUIRED_FLAGS "-Werror ${flags}")
  set(CMAKE_REQUIRED_QUIET ON)
  check_c_source_compiles("#include <stdio.h>
#include <string.h>
int main(void) { char b[8]; snprintf(b, sizeof b, \"%d\", 1); return (int)strlen(b); }" ${key})
  if(${key})
    set(${var} ${${var}} ${ARGN} PARENT_SCOPE)
    set(${result} ON PARENT_SCOPE)
  else()
    set(${result} OFF PARENT_SCOPE)
  endif()
endfunction()

set(ZKS_CFLAGS "")
set(ZKS_HARDEN_CFLAGS "")
if(NOT MSVC)
  zk_harden_flag(ZKS_CFLAGS ok -fsemantic-interposition)
  zk_harden_flag(ZKS_CFLAGS ok -fexceptions)

  zk_harden_flag(ZKS_HARDEN_CFLAGS ok -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
  if(NOT ok)
    zk_harden_flag(ZKS_HARDEN_CFLAGS ok -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
    if(NOT ok)
      message(STATUS "Dropped the hardening flag -D_FORTIFY_SOURCE")
    endif()
  endif()
  set(zks_flags -fstack-protector-strong -fstack-clash-protection -ftrivial-auto-var-init=zero
      -fno-strict-overflow -Wformat=2 -Wformat-security)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)")
    list(APPEND zks_flags -mbranch-protection=standard)
  endif()
  foreach(flag IN LISTS zks_flags)
    zk_harden_flag(ZKS_HARDEN_CFLAGS ok ${flag})
    if(NOT ok)
      message(STATUS "Dropped the hardening flag ${flag}")
    endif()
  endforeach()
endif()

if(MSVC)
  set(ZKS_WARN_CFLAGS /W3)
  if(ZK_WERROR)
    list(APPEND ZKS_WARN_CFLAGS /WX)
  endif()
else()
  set(ZKS_WARN_CFLAGS -Wall -Wdeclaration-after-statement)
  if(ZK_WERROR)
    list(APPEND ZKS_WARN_CFLAGS -Werror)
  endif()
endif()
