/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The interface from the library callback file to the Cyrus glue, and the
 * C rules of both SASL units.
 *
 * This header has Cyrus types. Only zks_sasl_cyrus.c and zks_sasl_cb.c
 * include it, after they define ZKS_SASL_GLUE and include zks_internal.h.
 * CI checks the compiler depfiles for this rule.
 */

#ifndef ZKS_SASL_CB_H_
#define ZKS_SASL_CB_H_

#ifndef ZKS_SASL_GLUE
#error "zks_sasl_cb.h is for the two SASL glue units only"
#endif

#include "zks_internal.h"

#ifndef HAVE_CYRUS_SASL_H
#error "the SASL glue units need HAVE_CYRUS_SASL_H"
#endif

#include <sasl/sasl.h>

/* The longest password in characters, as legacy (zookeeper.h:693). */
#define ZSASL_MAX_PASSWORD_LEN 1023

/*
 * The overflow macros give nonzero on overflow, as the GCC and Clang
 * builtins do. The callers do not read *r after an overflow. ZKS_CLEANUP
 * runs a function when a variable goes out of scope, also during a C++
 * exception unwind.
 */
#define ZKS_ADD_OVF(a, b, r) __builtin_add_overflow((a), (b), (r))
#define ZKS_MUL_OVF(a, b, r) __builtin_mul_overflow((a), (b), (r))
#define ZKS_CLEANUP(fn) __attribute__((cleanup(fn)))

/*
 * A sink takes the password bytes of one PASS request. The glue sink
 * copies them into a buffer that the session owns, and it gives that
 * buffer to Cyrus.
 */
typedef int (*zks_secret_sink)(void *arg, const unsigned char *data, size_t len,
                               sasl_secret_t **out);

/*
 * The legacy password rules of the library callback, with no lock held.
 * The bytes go to the sink. The shared callback block is not written.
 */
ZKS_HIDDEN int zks_getsecret_unlocked(sasl_conn_t *conn, void *context, zks_secret_sink sink,
                                      void *sink_arg, sasl_secret_t **psecret);

/*
 * The type of sasl_callback_t.proc. Cyrus names it sasl_callback_ft only
 * in saslplug.h, and the glue does not include the plugin header.
 */
typedef int (*zks_sasl_proc)(void);

/*
 * Stores a callback in a proc field. The cast goes through void (*)(void),
 * because GCC and Clang accept that type with -Wcast-function-type.
 */
#define ZKS_SASL_PROC(f) ((zks_sasl_proc)(void (*)(void))(f))

/* Gives 1 when proc is the PASS callback of a library callback block. */
ZKS_HIDDEN int zks_is_library_pass_cb(zks_sasl_proc proc);

#endif
