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
 * A C++ exception from an st SASL password callback (ledger DSP-14).
 * Mode EXACT. The log is ignored,
 * because the SASL log lines of a broken negotiation depend on timing.
 *
 * The legacy library is not exception safe across a throw. Thus the
 * trace shows only where the exception lands and that a second handle
 * then authenticates. The recovery of the first handle goes to the DEV
 * file only.
 *
 * Rules:
 * - Callback-frame rule: the SASL_CB_PASS callback of the application
 *   runs on the app thread inside zookeeper_process, with no Rust frame
 *   below it (TH-15). Its exception reaches the catch of the app around
 *   zookeeper_process.
 * - No library lock is held across the callback: a second handle on the
 *   same process authenticates after the throw.
 * - Rust: the unanswered SASL item ends with the receive timeout. The
 *   next connection disposes the old Cyrus connection and starts again,
 *   so the handle reaches CONNECTED. The
 *   legacy result is recorded, not checked.
 *
 * Run it with --sasl and the SASL libraries of both cores.
 *
 * zkconf-flavors: st
 */

#include "zkconf_sasl.h"

#include <cstring>
#include <stdexcept>
#include <sys/select.h>
#include <sys/time.h>

#ifdef HAVE_CYRUS_SASL_H

static int g_arm;
static int g_thrown;
static int g_h1_connected;

static long now_ms()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (long)now.tv_sec * 1000L + (long)(now.tv_usec / 1000);
}

/* The SASL_CB_PASS callback. It throws once when armed. */
static int throwing_pass(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
{
    static unsigned char storage[sizeof(sasl_secret_t) + sizeof ZKCS_SASL_PASSWORD];
    sasl_secret_t *secret = reinterpret_cast<sasl_secret_t *>(storage);
    (void)conn;
    (void)context;
    (void)id;
    if (g_arm) {
        g_arm = 0;
        g_thrown++;
        zkc_frame_check("sasl-pass");
        throw std::runtime_error("sasl-pass");
    }
    if (psecret == NULL) {
        return SASL_BADPARAM;
    }
    secret->len = sizeof ZKCS_SASL_PASSWORD - 1;
    std::memcpy(secret->data, ZKCS_SASL_PASSWORD, sizeof ZKCS_SASL_PASSWORD);
    *psecret = secret;
    return SASL_OK;
}

/* The watcher of the first handle counts CONNECTED and records nothing. */
static void quiet_watcher(zhandle_t *zh, int type, int state, const char *path, void *ctx)
{
    (void)zh;
    (void)path;
    (void)ctx;
    if (type == ZOO_SESSION_EVENT && state == ZOO_CONNECTED_STATE) {
        g_h1_connected++;
    }
}

/*
 * One st pass over zh: interest, select for at most 50 ms, then process
 * with a catch. Returns 1 if the catch ran.
 */
static int drive_once(zhandle_t *zh)
{
    int fd = -1;
    int interest = 0;
    struct timeval tv = {0, 0};
    fd_set rd;
    fd_set wr;
    int events = 0;
    if (zkc_interest(zh, &fd, &interest, &tv) != ZOK || fd < 0) {
        zkc_sleep_ms(10);
        return 0;
    }
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    if (interest & ZOOKEEPER_READ) {
        FD_SET(fd, &rd);
    }
    if (interest & ZOOKEEPER_WRITE) {
        FD_SET(fd, &wr);
    }
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    if (select(fd + 1, &rd, &wr, NULL, &tv) < 0) {
        return 0;
    }
    if (FD_ISSET(fd, &rd)) {
        events |= ZOOKEEPER_READ;
    }
    if (FD_ISSET(fd, &wr)) {
        events |= ZOOKEEPER_WRITE;
    }
    try {
        zkc_process(zh, events);
    } catch (const std::exception &e) {
        /* The throw skipped the end mark of the wrapper. */
        zkc_in_call(0);
        zkc_ev("check", "caught %s around zookeeper_process", e.what());
        return 1;
    }
    return 0;
}

static void run()
{
    sasl_callback_t cb1[4];
    sasl_callback_t cb2[4];
    zhandle_t *h1;
    zhandle_t *h2;
    long deadline;
    int caught = 0;

    zkcs_app_array(cb1, throwing_pass, NULL);
    zkcs_app_array(cb2, throwing_pass, NULL);
    /* The server minimum is 4 s, so the receive timeout is short. */
    h1 = zkcs_sasl_init(zkc_host(0), "h1", cb1, quiet_watcher, NULL, 4000);
    zkc_ev("call", "zookeeper_init_sasl h1 -> %s", h1 != NULL ? "zh" : "NULL");
    if (h1 == NULL) {
        return;
    }
    g_arm = 1;
    deadline = now_ms() + 15000;
    while (!caught && now_ms() < deadline) {
        caught = drive_once(h1);
    }
    if (!caught) {
        zkc_fail("no exception around zookeeper_process");
        return;
    }
    zkc_ev("ret", "thrown=%d", g_thrown);

    /* A second handle authenticates while the first one is broken. */
    h2 = zkcs_sasl_init(zkc_host(0), "h2", cb2, zkc_watcher, NULL, 10000);
    zkc_ev("call", "zookeeper_init_sasl h2 -> %s", h2 != NULL ? "zh" : "NULL");
    if (h2 == NULL) {
        return;
    }
    zkc_poll_add(h2);
    zkc_await("session:CONNECTED@h2", 1, 15000);
    zkc_close(h2);

    /* The recovery of h1. 20 s bounds the wait. */
    deadline = now_ms() + 20000;
    while (g_h1_connected == 0 && now_ms() < deadline) {
        if (drive_once(h1)) {
            zkc_fail("a second exception from h1");
            return;
        }
    }
    if (zkc_is_rust()) {
        zkc_dev("DSP-14", g_h1_connected > 0, "SASL-THROW: rust h1 connected=%d", g_h1_connected);
    } else {
        zkc_dev("DSP-14", 1, "SASL-THROW: legacy h1 connected=%d (recorded only)", g_h1_connected);
    }
    if (g_h1_connected > 0) {
        zkc_in_call(1);
        (void)zookeeper_close(h1);
        zkc_in_call(0);
    }
}
#endif

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "st_sasl_except", 1, "EXACT", "ignore");
#ifdef HAVE_CYRUS_SASL_H
    if (zkcs_sasl_resolve() == 0) {
        run();
        return zkc_finish();
    }
#endif
    zkc_ev("check", "skip: no SASL library or no SASL server");
    return zkc_finish();
}
