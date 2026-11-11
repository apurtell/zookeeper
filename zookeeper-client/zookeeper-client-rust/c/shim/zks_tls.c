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
 * The TLS init entry of the ssl builds.
 *
 * The shim declares zookeeper_init_ssl itself, because zks_internal.h
 * removes HAVE_OPENSSL_H and the zookeeper.h prototype is under it. The
 * prototype uses no OpenSSL type. Only builds with ZKS_WITH_TLS compile
 * the body, so the plain library does not export the symbol.
 *
 * The cert string is "ca,cert,key,passwd". The parser splits it on "," as
 * legacy strtok does. Thus empty fields collapse, and the next field moves
 * into their place. Fields after the fourth do not count, and whitespace
 * stays. The parser uses strtok_r, so the strtok scan of the caller
 * continues. The copy holds the passphrase, so the parser zeroes
 * it before it frees it. The Rust core reads the four strings during
 * zkrs_handle_new and keeps no pointer to them.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* POSIX names under -std=c99 on glibc */
#endif
#include "zks_internal.h"

#ifdef ZKS_WITH_TLS

zhandle_t *zookeeper_init_ssl(const char *host, const char *cert, watcher_fn fn,
                              int recv_timeout, const clientid_t *clientid, void *context,
                              int flags);

/*
 * A NULL cert gives NULL with EINVAL. Legacy crashes there. A
 * failed copy gives ENOMEM. The errno of the init survives the zeroing and
 * the free. The Rust core reads no file here. Each connection attempt
 * loads the files again. The tls_init conformance case pins the
 * four fields.
 */
zhandle_t *zookeeper_init_ssl(const char *host, const char *cert, watcher_fn fn,
                              int recv_timeout, const clientid_t *clientid, void *context,
                              int flags)
{
    struct zks_tls_args t = {1, NULL, NULL, NULL, NULL};
    char *copy;
    char *save = NULL;
    size_t n;
    zhandle_t *zh;
    int err;

    /* The call binds this unit to a core with TLS. A plain core has no
     * such symbol, so the prelink check fails. */
    if (cert == NULL || zkrs_feature_tls() != 1u) {
        errno = EINVAL;
        return NULL;
    }
    n = strlen(cert);
    copy = strdup(cert);
    if (copy == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    t.ca = strtok_r(copy, ",", &save);
    t.cert = strtok_r(NULL, ",", &save);
    t.key = strtok_r(NULL, ",", &save);
    t.passwd = strtok_r(NULL, ",", &save);
    zh = zks_init_common(host, fn, recv_timeout, clientid, context, flags, NULL, &t, NULL);
    err = errno;
    zks_secure_zero(copy, n);
    free(copy);
    errno = err;
    return zh;
}

#else

/* ISO C needs one declaration in a unit. The plain builds compile this unit empty. */
typedef int zks_tls_unit_is_empty;

#endif
