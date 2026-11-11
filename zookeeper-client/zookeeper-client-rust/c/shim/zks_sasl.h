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
 * The view of the Cyrus glue from the drain and the init path.
 *
 * This header has no Cyrus type. The drain, zks_handle.c and the two SASL
 * glue units include it. Only SASL builds (ZKS_WITH_SASL) compile the
 * glue, so other units include this header only under that macro.
 *
 * Rust refers to a Cyrus connection only by its generation. Every glue
 * call carries the generation and rejects a stale one before any Cyrus
 * call. A rejected START or STEP gives ZKRS_SASL_STALE, and the drain then
 * gives no result to Rust. A rejected DISPOSE has no effect.
 */

#ifndef ZKS_SASL_H_
#define ZKS_SASL_H_

#include "zks_internal.h"

typedef zkrs_bytes zks_bytes;       /* {p, len, is_null}, from Rust or the drain */
typedef zkrs_sasl_out zks_sasl_out; /* {status, mech, token} */

/* Cyrus uses unsigned lengths. The glue keeps every length in int range. */
#define ZKS_SASL_LEN_CAP 0x7fffffffu
#define ZKS_SASL_OUT_FAIL {ZKRS_SASL_FAIL, {NULL, 0, 1}, {NULL, 0, 1}}

/* The session owns the strings. The callback array stays borrowed. */
struct zks_sasl_params {
    char *service, *host, *mechlist; /* NUL-terminated copies; each can be NULL */
    const void *callbacks;           /* the application sasl_callback_t[]; can be NULL */
};

struct zks_sasl_sess; /* defined in zks_sasl_cyrus.c */
typedef struct zks_sasl_sess zks_sasl_sess;
typedef struct zks_sasl_params zks_sasl_params;
struct zoo_sasl_params; /* incomplete outside the two glue units */

/*
 * Session life. zks_sasl_sess_new gives NULL when an
 * allocation fails, and the init then fails with ENOMEM. zks_sasl_sess_free
 * disposes the connection, frees the copies and frees the session.
 * zks_sasl_sess_clear does the same but keeps the session object.
 */
ZKS_HIDDEN struct zks_sasl_sess *zks_sasl_sess_new(zhandle_t *zh, const struct zoo_sasl_params *p);
ZKS_HIDDEN void zks_sasl_sess_free(struct zks_sasl_sess *s);
ZKS_HIDDEN void zks_sasl_sess_clear(struct zks_sasl_sess *s);

/* The generation is 0 without a connection. */
ZKS_HIDDEN void zks_sasl_set_gen(struct zks_sasl_sess *s, uint32_t gen);

/*
 * The three glue calls. START uses the session copies of the params, and
 * it rejects gen 0 and the live gen.
 * STEP and DISPOSE accept only the live gen. The glue clears out at the
 * start of each call, so every early return gives ZKRS_SASL_FAIL.
 */
ZKS_HIDDEN void zks_sasl_start(zks_sasl_sess *s, uint32_t gen, zks_bytes local, zks_bytes peer,
                               zkrs_sasl_out *out);
ZKS_HIDDEN void zks_sasl_step(zks_sasl_sess *s, uint32_t gen, zks_bytes challenge,
                              zkrs_sasl_out *out);
ZKS_HIDDEN void zks_sasl_dispose(zks_sasl_sess *s, uint32_t gen);

#endif
