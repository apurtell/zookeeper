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
 * The SASL internals of the SASL builds (ABI-12, NUL-06; DV-ABI-2).
 * Mode DEV.
 *
 * No installed header declares the six zoo_sasl_* internals, but the
 * legacy SASL library exports them. The drop-in keeps every symbol:
 *
 * - zoo_sasl_client_create and zoo_sasl_client_destroy are real. The
 *   caller frees the object on both cores.
 * - zoo_sasl_mark_failed is faithful. It sets AUTH_FAILED on the handle.
 * - zoo_sasl_connect, zoo_sasl_client_start and zoo_sasl_client_step are
 *   stubs on the drop-in (DV-ABI-2). They return ZSYSTEMERROR and do not
 *   change the handle. The IO owner holds the negotiation state, so an
 *   application thread cannot drive it. Legacy returns ZINVALIDSTATE on
 *   a handle without a SASL client and marks the handle AUTH_FAILED.
 *
 * zoo_sasl_make_password_callbacks with a NULL password gives NULL and
 * errno EINVAL on the drop-in (NUL-06). Legacy reads through the NULL
 * pointer, so a forked child runs that call before any handle exists.
 *
 * A library without the SASL functions records only a skip line. Run the
 * case with the sasl or full libraries of both cores. It needs no server.
 *
 * zkconf-flavors: mt st
 */

#if defined(__has_include)
#if __has_include(<sasl/sasl.h>)
#define HAVE_CYRUS_SASL_H 1
#endif
#endif

#include "zkconf.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CYRUS_SASL_H

typedef sasl_callback_t *(*password_fn)(const char *, const char *, zoo_sasl_password_t *);
typedef void *(*create_fn)(zoo_sasl_params_t *);
typedef void (*destroy_fn)(void *);
typedef void (*mark_fn)(zhandle_t *);
typedef int (*drive_fn)(zhandle_t *);
typedef int (*step_fn)(zhandle_t *, const char *, int);

static password_fn g_password;

/* POSIX allows the conversion of a dlsym result to a function pointer. */
static void sym(void *out, size_t len, const char *name)
{
    void *p = dlsym(RTLD_DEFAULT, name);
    memset(out, 0, len);
    if (p != NULL) {
        memcpy(out, &p, len);
    }
}

/* Exit 0: NULL and EINVAL. Exit 1: another result. */
static int null_password(void)
{
    sasl_callback_t *cb;
    errno = 0;
    cb = g_password("u", NULL, NULL);
    if (cb == NULL && errno == EINVAL) {
        return 0;
    }
    free(cb);
    return 1;
}

/* A plain handle on the dead address. It has no SASL client. */
static zhandle_t *plain_handle(void)
{
    zhandle_t *zh = zookeeper_init(zkc_dead(), NULL, 30000, NULL, NULL, 0);
    if (zh == NULL) {
        zkc_fail("zookeeper_init gives NULL");
    }
    return zh;
}

/*
 * Runs one driver call on a fresh handle. It writes the rc and the states
 * before and after the call. Returns 0 when no handle opens, and then the
 * call does not run.
 */
static int call_once(drive_fn d, step_fn st, int *rc, int *before, int *after)
{
    zhandle_t *zh = plain_handle();
    if (zh == NULL) {
        return 0;
    }
    *before = zoo_state(zh);
    *rc = d != NULL ? d(zh) : st(zh, "x", 1);
    *after = zoo_state(zh);
    zookeeper_close(zh);
    return 1;
}

/*
 * On legacy, the call sets AUTH_FAILED. Only an overwrite by the IO
 * thread can give CONNECTING or 0 after the call.
 */
static int overwritten(int state)
{
    return state == ZOO_CONNECTING_STATE || state == 0;
}

#define DRIVE_TRIES 5

/*
 * Rust gives ZSYSTEMERROR and keeps the state. Legacy gives
 * ZINVALIDSTATE and sets AUTH_FAILED from the application thread. The
 * legacy IO thread checks is_unrecoverable first and writes the state
 * later, with no lock. It writes CONNECTING after a connect attempt
 * (zookeeper.c:2633, 2705) and 0 in cleanup (2116-2117). Thus it can
 * overwrite AUTH_FAILED. After an overwrite, the case tries again on a
 * fresh handle. Every try must give ZINVALIDSTATE, and one try must keep
 * AUTH_FAILED.
 */
static void drive(const char *what, drive_fn d, step_fn st)
{
    int before = 0;
    int after = 0;
    int rc = ZSYSTEMERROR;
    int tries;
    int rc_ok = 1;

    if (zkc_is_rust()) {
        if (!call_once(d, st, &rc, &before, &after)) {
            return;
        }
        zkc_dev("DV-ABI-2", rc == ZSYSTEMERROR && after == before,
                "rust %s is a stub: %s, state %s (want ZSYSTEMERROR, state %s)", what,
                zkc_rc(rc), zkc_state(after), zkc_state(before));
        return;
    }
    for (tries = 1; tries <= DRIVE_TRIES; tries++) {
        if (!call_once(d, st, &rc, &before, &after)) {
            return;
        }
        rc_ok = rc_ok && rc == ZINVALIDSTATE;
        if (!rc_ok || !overwritten(after)) {
            break;
        }
    }
    zkc_dev("DV-ABI-2", rc_ok && after == ZOO_AUTH_FAILED_STATE,
            "legacy %s without a SASL client: %s, state %s (want ZINVALIDSTATE, "
            "AUTH_FAILED)",
            what, zkc_rc(rc), zkc_state(after));
}

static void run(void)
{
    static const char *const names[] = {"zoo_sasl_client_create", "zoo_sasl_client_destroy",
                                        "zoo_sasl_mark_failed",   "zoo_sasl_connect",
                                        "zoo_sasl_client_start",  "zoo_sasl_client_step"};
    create_fn create;
    destroy_fn destroy;
    mark_fn mark;
    drive_fn connect_fn;
    drive_fn start;
    step_fn step;
    zoo_sasl_params_t sp;
    zhandle_t *zh;
    const char *res;
    void *sc;
    size_t i;
    int before = 0;
    int after = 0;
    int have = 0;

    /* NUL-06 first: the legacy child crashes, and no handle exists yet. */
    res = zkc_child("null_password", null_password, 10000);
    if (zkc_is_rust()) {
        zkc_dev("NUL-06", strcmp(res, "exit:0") == 0,
                "rust make_password_callbacks(NULL password): %s (want exit:0, NULL and EINVAL)",
                res);
    } else {
        zkc_dev("NUL-06", strncmp(res, "signal:", 7) == 0,
                "legacy make_password_callbacks(NULL password): %s (want a signal)", res);
    }

    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        zkc_dev("ABI-12", dlsym(RTLD_DEFAULT, names[i]) != NULL, "the library exports %s",
                names[i]);
    }
    sym(&create, sizeof create, "zoo_sasl_client_create");
    sym(&destroy, sizeof destroy, "zoo_sasl_client_destroy");
    sym(&mark, sizeof mark, "zoo_sasl_mark_failed");
    sym(&connect_fn, sizeof connect_fn, "zoo_sasl_connect");
    sym(&start, sizeof start, "zoo_sasl_client_start");
    sym(&step, sizeof step, "zoo_sasl_client_step");
    if (create == NULL || destroy == NULL || mark == NULL || connect_fn == NULL ||
        start == NULL || step == NULL) {
        return;
    }

    /* create and destroy are real. The caller frees the object. */
    memset(&sp, 0, sizeof sp);
    sp.service = "zookeeper";
    sp.host = "zk-sasl-md5";
    sp.mechlist = "DIGEST-MD5";
    sc = create(&sp);
    zkc_dev("ABI-12", sc != NULL, "zoo_sasl_client_create gives an object");
    if (sc != NULL) {
        destroy(sc);
        free(sc);
        zkc_dev("ABI-12", 1, "zoo_sasl_client_destroy and free complete");
    }

    /*
     * mark_failed sets AUTH_FAILED on both cores. The legacy IO thread
     * can overwrite it, as in drive(). A try that ends in CONNECTING or 0
     * runs again on a fresh handle.
     */
    for (i = 0; i < DRIVE_TRIES; i++) {
        zh = plain_handle();
        if (zh == NULL) {
            break;
        }
        have = 1;
        before = zoo_state(zh);
        mark(zh);
        after = zoo_state(zh);
        zookeeper_close(zh);
        if (zkc_is_rust() || !overwritten(after)) {
            break;
        }
    }
    if (have) {
        zkc_dev("ABI-12", before != ZOO_AUTH_FAILED_STATE && after == ZOO_AUTH_FAILED_STATE,
                "zoo_sasl_mark_failed: state %s then %s (want AUTH_FAILED)", zkc_state(before),
                zkc_state(after));
    }

    /* The three drivers, each on a fresh handle. */
    drive("zoo_sasl_connect", connect_fn, NULL);
    drive("zoo_sasl_client_start", start, NULL);
    drive("zoo_sasl_client_step", NULL, step);
}

#endif /* HAVE_CYRUS_SASL_H */

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "ldg_e_sasl", 0, "DEV", "ignore");
#ifdef HAVE_CYRUS_SASL_H
    sym(&g_password, sizeof g_password, "zoo_sasl_make_password_callbacks");
    if (g_password != NULL) {
        run();
    } else {
        zkc_ev("check", "skip: the library has no SASL functions");
    }
#else
    zkc_ev("check", "skip: no sasl/sasl.h");
#endif
    return zkc_finish();
}
