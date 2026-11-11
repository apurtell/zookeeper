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
 * A callback ends the completion thread with pthread_exit (CLS-15).
 * Mode DEV.
 *
 * The completion thread of legacy holds a handle reference that it never
 * gives back after pthread_exit. Its join returns, so zookeeper_close
 * returns ZOK, and no later completion runs. The drop-in gives the same
 * results. It also sends the close request and frees the handle, where
 * legacy keeps both. Each scenario runs in a forked child under a
 * timeout, before the parent makes a handle.
 *
 * - during: a completion waits until the application thread is in
 *   zookeeper_close, then calls pthread_exit. Four completions wait
 *   behind it. The close returns ZOK in the time bound, and none of the
 *   four completions runs.
 * - before: a completion calls pthread_exit at once. A later close from
 *   the application thread returns ZOK in the time bound.
 * - watcher: a watcher calls pthread_exit. A later close returns ZOK in
 *   the time bound.
 * - in-callback: a completion closes the handle, then calls
 *   pthread_exit. The close returns ZOK, and the process exits.
 *
 * zkconf-skip-st: it needs the completion thread
 */

#include "zkconf.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* The longest time that a close can take. The close tail alone has 4.5 s. */
#define CLOSE_BOUND_MS 8000

static zhandle_t *volatile g_zh;
static volatile int g_entered;
static volatile int g_closing;
static volatile int g_rest;
static volatile int g_rest_on_closer;
static volatile int g_closer_set;
static pthread_t g_closer;
static volatile int g_cb_close_rc = -999;

static void quiet_watcher(zhandle_t *zh, int type, int state,
                          const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static void quiet_log(const char *msg)
{
    (void)msg;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Waits for a flag. Returns 0 when the flag is set. */
static int wait_flag(volatile int *flag, int ms)
{
    int waited;
    for (waited = 0; waited < ms; waited += 10) {
        if (*flag) {
            return 0;
        }
        zkc_sleep_ms(10);
    }
    return -1;
}

static zhandle_t *child_connect(void)
{
    zhandle_t *zh = zookeeper_init2(zkc_host(0), quiet_watcher, 10000, NULL,
                                    NULL, 0, quiet_log);
    int waited;
    g_zh = zh;
    for (waited = 0; zh != NULL && waited < 10000; waited += 10) {
        if (zoo_state(zh) == ZOO_CONNECTED_STATE) {
            return zh;
        }
        zkc_sleep_ms(10);
    }
    return NULL;
}

/*
 * Closes from the application thread. Exit codes: 0 ZOK in the bound,
 * 1 another rc, 2 over the bound, 3 a later completion ran, 7 a later
 * completion ran on the closing thread. A drain that gives the items of
 * the ended thread back to the handle fails with code 3 or 7.
 */
static int timed_close(zhandle_t *zh)
{
    long start;
    long took;
    int rc;
    g_closer = pthread_self();
    g_closer_set = 1;
    start = now_ms();
    rc = zookeeper_close(zh);
    took = now_ms() - start;
    if (g_rest_on_closer != 0) {
        return 7;
    }
    if (rc != ZOK) {
        return 1;
    }
    if (took > CLOSE_BOUND_MS) {
        return 2;
    }
    return g_rest == 0 ? 0 : 3;
}

static void rest_cb(int rc, const struct Stat *st, const void *d)
{
    (void)rc;
    (void)st;
    (void)d;
    if (g_closer_set && pthread_equal(pthread_self(), g_closer)) {
        g_rest_on_closer++;
    }
    g_rest++;
}

/* Ends the thread after the application thread starts the close. */
static void exit_in_close_cb(int rc, const struct Stat *st, const void *d)
{
    (void)rc;
    (void)st;
    (void)d;
    g_entered = 1;
    wait_flag(&g_closing, 5000);
    /* The close joins the IO thread first, then it waits for this thread. */
    zkc_sleep_ms(300);
    pthread_exit(NULL);
}

static void exit_now_cb(int rc, const struct Stat *st, const void *d)
{
    (void)rc;
    (void)st;
    (void)d;
    g_entered = 1;
    pthread_exit(NULL);
}

/* Submits one exists call with cb, then four with rest_cb behind it. */
static int submit_five(zhandle_t *zh, stat_completion_t cb)
{
    int i;
    if (zoo_aexists(zh, "/", 0, cb, NULL) != ZOK) {
        return -1;
    }
    for (i = 0; i < 4; i++) {
        if (zoo_aexists(zh, "/", 0, rest_cb, NULL) != ZOK) {
            return -1;
        }
    }
    return 0;
}

static int child_during(void)
{
    zhandle_t *zh = child_connect();
    if (zh == NULL) {
        return 4;
    }
    if (submit_five(zh, exit_in_close_cb) != 0) {
        return 5;
    }
    if (wait_flag(&g_entered, 8000) != 0) {
        return 6;
    }
    g_closing = 1;
    return timed_close(zh);
}

static int child_before(void)
{
    zhandle_t *zh = child_connect();
    if (zh == NULL) {
        return 4;
    }
    if (submit_five(zh, exit_now_cb) != 0) {
        return 5;
    }
    if (wait_flag(&g_entered, 8000) != 0) {
        return 6;
    }
    /* The thread ends a short time after the flag. */
    zkc_sleep_ms(200);
    return timed_close(zh);
}

static void exit_watcher(zhandle_t *zh, int type, int state, const char *path,
                         void *ctx)
{
    (void)zh;
    (void)state;
    (void)path;
    (void)ctx;
    if (type == ZOO_CREATED_EVENT) {
        g_entered = 1;
        pthread_exit(NULL);
    }
}

static int child_watcher(void)
{
    char path[64];
    struct Stat st;
    zhandle_t *zh = child_connect();
    if (zh == NULL) {
        return 4;
    }
    snprintf(path, sizeof(path), "/close_exit_%s", zkc_core());
    if (zoo_wexists(zh, path, exit_watcher, NULL, &st) != ZNONODE) {
        return 5;
    }
    if (zoo_create(zh, path, "a", 1, &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL,
                   NULL, 0) != ZOK) {
        return 5;
    }
    if (wait_flag(&g_entered, 8000) != 0) {
        return 6;
    }
    zkc_sleep_ms(200);
    return timed_close(zh);
}

static void close_then_exit_cb(int rc, const struct Stat *st, const void *d)
{
    (void)rc;
    (void)st;
    (void)d;
    g_cb_close_rc = zookeeper_close(g_zh);
    g_entered = 1;
    pthread_exit(NULL);
}

/* Exit codes: 0 ZOK, 1 another rc, 6 no callback. */
static int child_in_callback(void)
{
    zhandle_t *zh = child_connect();
    if (zh == NULL) {
        return 4;
    }
    if (zoo_aexists(zh, "/", 0, close_then_exit_cb, NULL) != ZOK) {
        return 5;
    }
    if (wait_flag(&g_entered, 8000) != 0) {
        return 6;
    }
    zkc_sleep_ms(200);
    return g_cb_close_rc == ZOK ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *res;

    zkc_init(argc, argv, "close_exit", 1, "DEV", "ignore");

    res = zkc_child("CLS-15-during", child_during, 20000);
    zkc_dev("CLS-15", strcmp(res, "exit:0") == 0,
            "pthread_exit in a completion during a foreign close: %s", res);
    res = zkc_child("CLS-15-before", child_before, 20000);
    zkc_dev("CLS-15", strcmp(res, "exit:0") == 0,
            "pthread_exit in a completion before a foreign close: %s", res);
    res = zkc_child("CLS-15-watcher", child_watcher, 20000);
    zkc_dev("CLS-15", strcmp(res, "exit:0") == 0,
            "pthread_exit in a watcher before a foreign close: %s", res);
    res = zkc_child("CLS-15-in-callback", child_in_callback, 20000);
    zkc_dev("CLS-15", strcmp(res, "exit:0") == 0,
            "pthread_exit in a completion after its own close: %s", res);
    return zkc_finish();
}
