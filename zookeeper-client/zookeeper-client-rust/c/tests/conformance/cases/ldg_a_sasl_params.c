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
 * SASL parameters are not checked at init (INIT-15). Mode DEV.
 *
 * The case asks for the mechanism "LDG-A-NOPE", which no SASL plugin
 * gives. zookeeper_init_sasl does not check the mechanism list, so both
 * cores give a handle. The failure comes after the prime response, when
 * sasl_client_start finds no mechanism.
 *
 * - INIT-15: both cores give a handle, and the state then goes to
 *   AUTH_FAILED.
 * - INIT-15 with DV-FIX-3 and ST-03, Rust: one AUTH_FAILED session
 *   event comes.
 * - INIT-15 with DV-FIX-3 and ST-03, legacy: no session event comes.
 * - INIT-15: on both cores, a request after the failure gets
 *   ZINVALIDSTATE, because AUTH_FAILED is a state with no recovery.
 *
 * The case finds the SASL functions at run time, so it also builds
 * against a library without SASL. Then it records a skip and checks
 * nothing. Run it with --sasl and the SASL libraries of both cores.
 *
 * zkconf-flavors: mt
 */

#if defined(__has_include)
#if __has_include(<sasl/sasl.h>)
#ifndef HAVE_CYRUS_SASL_H
#define HAVE_CYRUS_SASL_H 1
#endif
#endif
#endif

#include "zkconf.h"
#include "zkconf_sasl.h"

#include <dlfcn.h>
#include <pthread.h>
#include <string.h>

#ifdef HAVE_CYRUS_SASL_H

typedef zhandle_t *(*init_sasl_fn)(const char *, watcher_fn, int,
                                   const clientid_t *, void *, int,
                                   log_callback_fn, zoo_sasl_params_t *);

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_states[16];
static int g_nstates;

static void params_watcher(zhandle_t *zh, int type, int state,
                           const char *path, void *ctx)
{
    (void)zh;
    (void)path;
    (void)ctx;
    if (type != ZOO_SESSION_EVENT) {
        return;
    }
    pthread_mutex_lock(&g_mu);
    if (g_nstates < (int)(sizeof(g_states) / sizeof(g_states[0]))) {
        g_states[g_nstates++] = state;
    }
    pthread_mutex_unlock(&g_mu);
}

/* A request after the failure must not complete. */
static void exists_cb(int rc, const struct Stat *st, const void *d)
{
    (void)st;
    (void)d;
    zkc_fail("INIT-15: an exists callback ran with %s", zkc_rc(rc));
}

static void run(init_sasl_fn init_sasl)
{
    static const sasl_callback_t cbs[] = {{SASL_CB_LIST_END, NULL, NULL}};
    zoo_sasl_params_t params;
    zhandle_t *zh;
    int rust = zkc_is_rust();
    int waited;
    int nauth = 0;
    int after = 0;
    int connected_at = -1;
    int i;

    memset(&params, 0, sizeof(params));
    params.service = "zookeeper";
    params.host = "zk-sasl-md5";
    params.mechlist = "LDG-A-NOPE";
    params.callbacks = cbs;
    zh = init_sasl(zkc_host(0), params_watcher, 10000, NULL, NULL, 0, NULL,
                   &params);
    zkc_dev("INIT-15", zh != NULL, "zookeeper_init_sasl with mechlist %s: %s",
            params.mechlist, zh != NULL ? "handle" : "NULL");
    if (zh == NULL) {
        return;
    }
    for (waited = 0; waited < 10000; waited += 50) {
        if (zoo_state(zh) == ZOO_AUTH_FAILED_STATE) {
            break;
        }
        zkc_sleep_ms(50);
    }
    /* The Rust session event can come just after the state change. */
    zkc_sleep_ms(300);
    zkc_dev("INIT-15", zoo_state(zh) == ZOO_AUTH_FAILED_STATE,
            "state after the prime response: %s", zkc_state(zoo_state(zh)));

    pthread_mutex_lock(&g_mu);
    for (i = 0; i < g_nstates; i++) {
        if (g_states[i] == ZOO_CONNECTED_STATE && connected_at < 0) {
            connected_at = i;
        } else if (connected_at >= 0) {
            after++;
        }
        if (g_states[i] == ZOO_AUTH_FAILED_STATE) {
            nauth++;
        }
    }
    zkc_dev("INIT-15",
            rust ? (nauth == 1 && g_nstates > 0 &&
                    g_states[g_nstates - 1] == ZOO_AUTH_FAILED_STATE)
                 : (nauth == 0 && after == 0),
            "session events %d: AUTH_FAILED events %d, events after "
            "CONNECTED %d", g_nstates, nauth, after);
    pthread_mutex_unlock(&g_mu);

    {
        int rc = zoo_aexists(zh, "/ldgA15", 0, exists_cb, NULL);
        zkc_dev("INIT-15", rc == ZINVALIDSTATE,
                "exists after the failure: submit %s", zkc_rc(rc));
    }
    zookeeper_close(zh);
}

#endif /* HAVE_CYRUS_SASL_H */

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "ldg_a_sasl_params", 1, "DEV", "ignore");
#ifdef HAVE_CYRUS_SASL_H
    {
        init_sasl_fn init_sasl;
        *(void **)&init_sasl = dlsym(RTLD_DEFAULT, "zookeeper_init_sasl");
        if (init_sasl != NULL && zkcs_sasl_client_init() == SASL_OK) {
            run(init_sasl);
            return zkc_finish();
        }
    }
#endif
    zkc_ev("check", "skip: no SASL library");
    return zkc_finish();
}
