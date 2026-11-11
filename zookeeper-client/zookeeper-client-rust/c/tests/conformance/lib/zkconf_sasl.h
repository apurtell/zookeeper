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
 * Shared helpers of the SASL cases. This is test code.
 *
 * The runner links every case against one library and gives no Cyrus
 * flags. Thus the helpers find the SASL functions of the library at run
 * time. They also find the functions of the SASL preload, if the case
 * runs with it. Every helper is static inline, so a case that does not
 * use a helper gets no warning.
 *
 * Cyrus guards its global state only with the mutex callbacks that the
 * application installs before sasl_client_init. The default callbacks do
 * nothing. Without real callbacks, two handles that finish DIGEST-MD5 at
 * the same time can free one entry of the reauth cache twice. Neither
 * library installs the callbacks. Thus every case initializes Cyrus
 * through zkcs_sasl_client_init.
 *
 * The server of a SASL run has a DigestLoginModule "Server" section with
 * user_myuser="mypassword" (run.sh --sasl). ZKCONF_SASL=1 tells the case
 * that the server has it.
 */

#ifndef ZKCONF_SASL_H_
#define ZKCONF_SASL_H_

#if defined(__has_include)
#if __has_include(<sasl/sasl.h>)
#ifndef HAVE_CYRUS_SASL_H
#define HAVE_CYRUS_SASL_H 1
#endif
#endif
#endif

#include "zkconf.h"
#include "zkconf_sasl_preload.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CYRUS_SASL_H

#define ZKCS_SASL_USER "myuser"
#define ZKCS_SASL_PASSWORD "mypassword"

typedef int (*zkcs_sasl_init_fn)(const sasl_callback_t *);
typedef zhandle_t *(*zkcs_init_sasl_fn)(const char *, watcher_fn, int, const clientid_t *,
                                        void *, int, log_callback_fn, zoo_sasl_params_t *);
typedef sasl_callback_t *(*zkcs_basic_fn)(const char *, const char *, const char *);
typedef sasl_callback_t *(*zkcs_password_fn)(const char *, const char *, zoo_sasl_password_t *);

/* The resolved functions. The preload functions are NULL without the preload. */
struct zkcs_sasl_api {
    zkcs_init_sasl_fn init_sasl;
    zkcs_basic_fn basic;
    zkcs_password_fn password;
    zkconf_sasl_events_fn events;
    zkconf_sasl_mark_fn mark;
    zkconf_sasl_fail_fn fail;
    zkconf_sasl_open_fn open;
    zkconf_sasl_gate_fn gate;
    zkconf_sasl_open_fn gated;
};

static inline struct zkcs_sasl_api *zkcs_sasl(void)
{
    static struct zkcs_sasl_api api;
    return &api;
}

/* POSIX allows the conversion of a dlsym result to a function pointer. */
static inline void zkcs_sym(void *out, size_t len, const char *name)
{
    void *p = dlsym(RTLD_DEFAULT, name);
    memset(out, 0, len);
    if (p != NULL) {
        memcpy(out, &p, len);
    }
}

/*
 * The type of sasl_set_mutex. It uses plain types, because the macOS SDK
 * marks the Cyrus mutex typedefs as deprecated.
 */
typedef void (*zkcs_set_mutex_fn)(void *(*)(void), int (*)(void *), int (*)(void *),
                                  void (*)(void *));

/* The Cyrus mutex callbacks of the cases. They use pthread mutexes. */
static inline void *zkcs_mutex_alloc(void)
{
    pthread_mutex_t *m = (pthread_mutex_t *)malloc(sizeof *m);

    if (m != NULL && pthread_mutex_init(m, NULL) != 0) {
        free(m);
        m = NULL;
    }
    return m;
}

static inline int zkcs_mutex_lock(void *m)
{
    return pthread_mutex_lock((pthread_mutex_t *)m) == 0 ? SASL_OK : SASL_FAIL;
}

static inline int zkcs_mutex_unlock(void *m)
{
    return pthread_mutex_unlock((pthread_mutex_t *)m) == 0 ? SASL_OK : SASL_FAIL;
}

static inline void zkcs_mutex_free(void *m)
{
    if (m != NULL) {
        (void)pthread_mutex_destroy((pthread_mutex_t *)m);
        free(m);
    }
}

/*
 * Initializes Cyrus as a correct multithreaded application does. It
 * installs the mutex callbacks first, because Cyrus ignores them after
 * sasl_client_init. Returns the result of sasl_client_init, or SASL_FAIL
 * when the process has no Cyrus functions.
 */
static inline int zkcs_sasl_client_init(void)
{
    zkcs_set_mutex_fn set_mutex;
    zkcs_sasl_init_fn init;

    zkcs_sym(&set_mutex, sizeof set_mutex, "sasl_set_mutex");
    zkcs_sym(&init, sizeof init, "sasl_client_init");
    if (set_mutex == NULL || init == NULL) {
        return SASL_FAIL;
    }
    set_mutex(zkcs_mutex_alloc, zkcs_mutex_lock, zkcs_mutex_unlock, zkcs_mutex_free);
    return init(NULL);
}

/*
 * Resolves the functions and initializes Cyrus through
 * zkcs_sasl_client_init. Returns 0 when the run can use SASL: the library
 * has the SASL functions and ZKCONF_SASL is set.
 */
static inline int zkcs_sasl_resolve(void)
{
    struct zkcs_sasl_api *a = zkcs_sasl();

    if (getenv("ZKCONF_SASL") == NULL) {
        return -1;
    }
    zkcs_sym(&a->init_sasl, sizeof a->init_sasl, "zookeeper_init_sasl");
    zkcs_sym(&a->basic, sizeof a->basic, "zoo_sasl_make_basic_callbacks");
    zkcs_sym(&a->password, sizeof a->password, "zoo_sasl_make_password_callbacks");
    zkcs_sym(&a->events, sizeof a->events, "zkconf_sasl_events");
    zkcs_sym(&a->mark, sizeof a->mark, "zkconf_sasl_mark");
    zkcs_sym(&a->fail, sizeof a->fail, "zkconf_sasl_fail");
    zkcs_sym(&a->open, sizeof a->open, "zkconf_sasl_open");
    zkcs_sym(&a->gate, sizeof a->gate, "zkconf_sasl_gate");
    zkcs_sym(&a->gated, sizeof a->gated, "zkconf_sasl_gated");
    if (a->init_sasl == NULL || a->basic == NULL || a->password == NULL) {
        return -1;
    }
    return zkcs_sasl_client_init() == SASL_OK ? 0 : -1;
}

/* Returns 1 when the SASL preload is in the process. */
static inline int zkcs_has_preload(void)
{
    return zkcs_sasl()->events != NULL;
}

/* Starts a DIGEST-MD5 session on hosts with the context label ctx. */
static inline zhandle_t *zkcs_sasl_init(const char *hosts, const char *ctx, sasl_callback_t *cb,
                                        watcher_fn w, log_callback_fn log, int timeout_ms)
{
    zoo_sasl_params_t sp;

    memset(&sp, 0, sizeof sp);
    sp.service = "zookeeper";
    sp.host = "zk-sasl-md5";
    sp.mechlist = "DIGEST-MD5";
    sp.callbacks = cb;
    return zkcs_sasl()->init_sasl(hosts, w, timeout_ms, NULL, (void *)ctx, 0, log, &sp);
}

/*
 * The preload events without the address reads. The address reads of
 * the two cores come in another order, so
 * the trace does not show them.
 */
static inline const char *zkcs_order(char *buf, size_t len)
{
    char all[512];
    size_t i;
    size_t j = 0;

    if (len == 0) {
        return buf;
    }
    buf[0] = '\0';
    if (!zkcs_has_preload()) {
        return buf;
    }
    zkcs_sasl()->events(all, (int)sizeof all);
    for (i = 0; all[i] != '\0' && j + 1 < len; i++) {
        if (all[i] != 'G' && all[i] != 'P') {
            buf[j++] = all[i];
        }
    }
    buf[j] = '\0';
    return buf;
}

static inline void zkcs_mark(char c)
{
    if (zkcs_sasl()->mark != NULL) {
        zkcs_sasl()->mark(c);
    }
}

/* Writes text to path. Returns 0 on success. */
static inline int zkcs_write_file(const char *path, const char *text, size_t len)
{
    FILE *f = fopen(path, "wb");
    int ok;

    if (f == NULL) {
        return -1;
    }
    ok = fwrite(text, 1, len, f) == len;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

/* An application SASL_CB_USER and SASL_CB_AUTHNAME callback. */
static inline int zkcs_app_simple(void *context, int id, const char **result, unsigned *len)
{
    (void)id;
    if (result == NULL) {
        return SASL_BADPARAM;
    }
    *result = (const char *)context;
    if (len != NULL) {
        *len = (unsigned)strlen((const char *)context);
    }
    return SASL_OK;
}

/* Fills cb[4] with USER, AUTHNAME, PASS and LIST_END. */
static inline void zkcs_app_array(sasl_callback_t cb[4], int (*pass)(sasl_conn_t *, void *, int,
                                                                      sasl_secret_t **),
                                  void *pass_ctx)
{
    memset(cb, 0, 4 * sizeof cb[0]);
    cb[0].id = SASL_CB_AUTHNAME;
    cb[0].proc = (int (*)(void))(void (*)(void))zkcs_app_simple;
    cb[0].context = (void *)ZKCS_SASL_USER;
    cb[1].id = SASL_CB_USER;
    cb[1].proc = (int (*)(void))(void (*)(void))zkcs_app_simple;
    cb[1].context = (void *)ZKCS_SASL_USER;
    cb[2].id = SASL_CB_PASS;
    cb[2].proc = (int (*)(void))(void (*)(void))pass;
    cb[2].context = pass_ctx;
    cb[3].id = SASL_CB_LIST_END;
}

#endif /* HAVE_CYRUS_SASL_H */

#endif /* ZKCONF_SASL_H_ */
