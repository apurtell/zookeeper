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
 * C++ exceptions from st callbacks (TH-10..13; ledger DSP-14). Mode
 * EXACT.
 *
 * The legacy library is not exception safe across a throw. Thus each
 * check asserts only where the exception lands, that the handler of the
 * app runs, and what the next driving calls deliver. The case
 * does not close a handle that a throw left. It does no other work with
 * such a handle.
 *
 * Rules:
 * - TH-10: a path watcher throws inside zookeeper_process. The exception
 *   reaches the catch of the app around zookeeper_process. A later
 *   process call delivers the next reply.
 * - TH-11: the log callback throws on the DEBUG line inside zoo_awget
 *   (logLevel 4). The exception reaches the catch around zoo_awget. The
 *   completion of the request runs in a later driving call.
 * - TH-13: a ZCLOSING auth completion throws inside zookeeper_close. The
 *   exception reaches the catch around zookeeper_close.
 * - TH-12: the log callback throws on the first line of
 *   zookeeper_init2. The exception reaches the catch around the init.
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"
#include "zkconf_sync.h"

#include <cstring>
#include <stdexcept>
#include <sys/select.h>
#include <sys/time.h>

static int g_arm_watch;
static int g_arm_log;

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

static long now_ms()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (long)now.tv_sec * 1000L + (long)(now.tv_usec / 1000);
}

static bool lbl_is(const void *d, const char *s)
{
    return d != NULL && std::strcmp(static_cast<const char *>(d), s) == 0;
}

/* Records the line, then throws once when armed. */
static void throwing_log_cb(const char *msg)
{
    zkc_log_cb(msg);
    if (g_arm_log) {
        g_arm_log = 0;
        throw std::runtime_error("log");
    }
}

/* TH-10: watcher W1 throws once when armed. */
static void watch_hook(zhandle_t *zh, int type, int state, const char *path,
                       void *ctx)
{
    (void)zh;
    (void)state;
    (void)path;
    if (g_arm_watch && type == ZOO_CHANGED_EVENT && lbl_is(ctx, "W1")) {
        g_arm_watch = 0;
        throw std::runtime_error("watch");
    }
}

/* TH-13: the auth completion throws on ZCLOSING. */
static void auth_cb(int rc, const void *d)
{
    zkc_void_cb(rc, d);
    if (rc == ZCLOSING) {
        throw std::runtime_error("auth");
    }
}

/*
 * Drives zh with a catch around zookeeper_process, until a throw lands
 * there or timeout_ms passes. Returns 1 if the catch ran.
 */
static int drive_until_throw(zhandle_t *zh, int timeout_ms)
{
    long deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        int fd = -1;
        int interest = 0;
        struct timeval tv = {0, 0};
        fd_set rd;
        fd_set wr;
        int events = 0;
        if (zkc_interest(zh, &fd, &interest, &tv) != ZOK || fd < 0) {
            zkc_sleep_ms(10);
            continue;
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
        if (select(fd + 1, &rd, &wr, NULL, &tv) <= 0) {
            continue;
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
    }
    zkc_fail("no exception around zookeeper_process");
    return 0;
}

int main(int argc, char **argv)
{
    zhandle_t *zh;
    zhandle_t *az;
    const char *px;

    zkc_init(argc, argv, "st_except", 1, "EXACT", "ordered");
    zkc_set_watch_hook(watch_hook);
    zh = zookeeper_init2(zkc_host(0), zkc_watcher, 10000, NULL,
                         (void *)"default", 0, throwing_log_cb);
    zkc_ev("call", "zookeeper_init2 -> %s", zh ? "zh" : "NULL");
    if (zh == NULL) {
        return zkc_finish();
    }
    zkc_poll_add(zh);
    zkc_await("session:CONNECTED", 1, 15000);
    call("create /se", zkcs_create(zh, "/se", "v", 1, &ZOO_OPEN_ACL_UNSAFE,
                                   ZOO_EPHEMERAL, NULL, 0));

    /* TH-10: W1 throws on the change. */
    call("zoo_awexists W1",
         zoo_awexists(zh, "/se", zkc_watcher, (void *)"W1", zkc_stat_cb,
                      "E1"));
    call("zoo_awget W2",
         zoo_awget(zh, "/se", zkc_watcher, (void *)"W2", zkc_data_cb, "G2"));
    zkc_await("cb", 2, 10000);
    g_arm_watch = 1;
    call("zoo_aset S1", zoo_aset(zh, "/se", "w", 1, -1, zkc_stat_cb, "S1"));
    drive_until_throw(zh, 10000);
    zkc_await("cb", 1, 10000);
    call("zoo_aset S2", zoo_aset(zh, "/se", "x", 1, -1, zkc_stat_cb, "S2"));
    zkc_await("cb", 1, 10000);
    zkc_poll(300);

    /* TH-11: the DEBUG line inside zoo_awget throws. */
    zoo_set_debug_level(ZOO_LOG_LEVEL_DEBUG);
    g_arm_log = 1;
    try {
        call("zoo_awget W3",
             zoo_awget(zh, "/se", zkc_watcher, (void *)"W3", zkc_data_cb,
                       "G3"));
    } catch (const std::exception &e) {
        zkc_ev("check", "caught %s around zoo_awget", e.what());
    }
    g_arm_log = 0;
    zoo_set_debug_level(ZOO_LOG_LEVEL_INFO);
    zkc_await("cb", 1, 10000);
    zkc_poll_remove(zh);

    /* TH-13: the proxy holds the auth reply, so close fails the auth. */
    px = zkc_proxy_start(zkc_host(0));
    if (px == NULL) {
        return zkc_finish();
    }
    az = zkc_connect(px, 10000, 0);
    if (az != NULL) {
        zkc_proxy_hold(1);
        call("zoo_add_auth",
             zoo_add_auth(az, "digest", "u:p", 3, auth_cb, "auth"));
        zkc_poll(300);
        zkc_poll_remove(az);
        try {
            zkc_in_call(1);
            call("zookeeper_close", zookeeper_close(az));
            zkc_in_call(0);
        } catch (const std::exception &e) {
            zkc_in_call(0);
            zkc_ev("check", "caught %s around zookeeper_close", e.what());
        }
        zkc_proxy_hold(0);
    }
    zkc_proxy_stop();

    /* TH-12: the first log line of the init throws. */
    g_arm_log = 1;
    try {
        zhandle_t *lz = zookeeper_init2(zkc_host(0), zkc_watcher, 10000, NULL,
                                        (void *)"th12", 0, throwing_log_cb);
        zkc_ev("call", "zookeeper_init2 th12 -> %s", lz ? "zh" : "NULL");
    } catch (const std::exception &e) {
        zkc_ev("check", "caught %s around zookeeper_init2", e.what());
    }
    g_arm_log = 0;
    return zkc_finish();
}
