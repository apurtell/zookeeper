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
 * The default watcher and its context (WAT-15). Mode DEV.
 *
 * - WAT-15 values: zoo_set_watcher(NULL) returns the previous watcher and
 *   installs the library null watcher. A later zoo_set_watcher returns
 *   that null watcher, and a call to it is harmless. zoo_set_context and
 *   zoo_get_context give the value that the application set. Both cores
 *   give the same values.
 * - WAT-15 race: two threads change the watcher and the context while the
 *   library delivers events to the default watcher. Legacy keeps the two
 *   fields unlocked, which is a data race. Rust keeps them in a spinlock
 *   cell. Each delivery and each read must give a value that the threads
 *   set. The check asserts this on Rust and records it on legacy.
 *
 * zkconf-skip-st: the race needs the library threads of mt
 */

#include "zkconf.h"

#include <pthread.h>
#include <string.h>

#define ROUNDS 40
#define FLIPS 200000

static char CTX_A[] = "ctxA";
static char CTX_B[] = "ctxB";

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_events;
static int g_bad;
static volatile int g_stop;

static int known_ctx(const void *ctx)
{
    return ctx == CTX_A || ctx == CTX_B;
}

static void count_event(int type, void *ctx)
{
    pthread_mutex_lock(&g_mu);
    if (type == ZOO_CREATED_EVENT) {
        g_events++;
        if (!known_ctx(ctx)) {
            g_bad++;
        }
    }
    pthread_mutex_unlock(&g_mu);
}

static void watcher_a(zhandle_t *zh, int type, int state, const char *path,
                      void *ctx)
{
    (void)zh;
    (void)state;
    (void)path;
    count_event(type, ctx);
}

static void watcher_b(zhandle_t *zh, int type, int state, const char *path,
                      void *ctx)
{
    (void)zh;
    (void)state;
    (void)path;
    count_event(type, ctx);
}

static void *flip_watcher(void *arg)
{
    zhandle_t *zh = arg;
    int i;
    for (i = 0; i < FLIPS && !g_stop; i++) {
        zoo_set_watcher(zh, (i & 1) != 0 ? watcher_a : watcher_b);
    }
    return NULL;
}

static void *flip_context(void *arg)
{
    zhandle_t *zh = arg;
    int i;
    for (i = 0; i < FLIPS && !g_stop; i++) {
        zoo_set_context(zh, (i & 1) != 0 ? CTX_A : CTX_B);
    }
    return NULL;
}

static int events_now(void)
{
    int n;
    pthread_mutex_lock(&g_mu);
    n = g_events;
    pthread_mutex_unlock(&g_mu);
    return n;
}

/* Fires one NODE_CREATED event on the default watcher. */
static void fire_one(zhandle_t *zh, int want)
{
    int i;
    zoo_exists(zh, "/ldgb_w", 1, NULL);
    zoo_create(zh, "/ldgb_w", "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
    for (i = 0; i < 200 && events_now() < want; i++) {
        zkc_sleep_ms(10);
    }
    zoo_delete(zh, "/ldgb_w", -1);
}

static void check_values(zhandle_t *zh)
{
    watcher_fn old;
    watcher_fn nullw;
    old = zoo_set_watcher(zh, NULL);
    zkc_dev("WAT-15", old == zkc_watcher,
            "zoo_set_watcher(NULL) returns the previous watcher: %s",
            old == zkc_watcher ? "zkc_watcher" : "OTHER");
    nullw = zoo_set_watcher(zh, watcher_a);
    zkc_dev("WAT-15", nullw != NULL && nullw != zkc_watcher,
            "the next zoo_set_watcher returns the null watcher: %s",
            nullw == NULL ? "NULL" : "LIBFN");
    if (nullw != NULL && nullw != zkc_watcher) {
        nullw(zh, ZOO_SESSION_EVENT, ZOO_CONNECTED_STATE, "", NULL);
    }
    zoo_set_context(zh, CTX_A);
    zkc_dev("WAT-15", zoo_get_context(zh) == CTX_A,
            "zoo_get_context gives the value of zoo_set_context");
}

static void check_race(zhandle_t *zh)
{
    pthread_t tw;
    pthread_t tc;
    int i;
    int reads_bad = 0;
    int events;
    int bad;
    g_stop = 0;
    if (pthread_create(&tw, NULL, flip_watcher, zh) != 0) {
        zkc_fail("pthread_create failed");
        return;
    }
    if (pthread_create(&tc, NULL, flip_context, zh) != 0) {
        g_stop = 1;
        pthread_join(tw, NULL);
        zkc_fail("pthread_create failed");
        return;
    }
    for (i = 0; i < ROUNDS; i++) {
        fire_one(zh, i + 1);
        if (!known_ctx(zoo_get_context(zh))) {
            reads_bad++;
        }
    }
    g_stop = 1;
    pthread_join(tw, NULL);
    pthread_join(tc, NULL);
    pthread_mutex_lock(&g_mu);
    events = g_events;
    bad = g_bad;
    pthread_mutex_unlock(&g_mu);
    zkc_dev("WAT-15",
            zkc_is_rust() ? (events == ROUNDS && bad == 0 && reads_bad == 0) : 1,
            "race: events=%d/%d unknown ctx=%d bad reads=%d (legacy: an "
            "unlocked race, recorded; rust: the spinlock cell)",
            events, ROUNDS, bad, reads_bad);
}

int main(int argc, char **argv)
{
    zhandle_t *zh;

    zkc_init(argc, argv, "ldg_b_watcher", 1, "DEV", "ignore");
    zh = zkc_connect(zkc_host(0), 10000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    check_values(zh);
    check_race(zh);
    zoo_set_watcher(zh, zkc_watcher);
    zoo_set_context(zh, "default");
    zkc_close(zh);
    return zkc_finish();
}
