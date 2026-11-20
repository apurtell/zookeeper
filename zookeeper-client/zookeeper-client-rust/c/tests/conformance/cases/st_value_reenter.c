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
 * The value of a data completion across reentrant calls in the single
 * threaded library. Mode: EXACT.
 *
 * Invariants:
 * - The value that a data completion gets stays valid and unchanged until the
 *   completion returns. This is true when the completion submits a request,
 *   runs a nested zookeeper_process call that delivers other data replies, or
 *   closes the handle.
 * - This is true for small values and for values of 64 KiB and more.
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"
#include "zkconf_sync.h"

#include <string.h>
#include <sys/select.h>

#define SMALL_LEN 100
#define LARGE_LEN 70000

static zhandle_t *g_zh;
static int g_depth;
static int g_closed;
static char g_small[SMALL_LEN];
static char g_large1[LARGE_LEN];
static char g_large2[LARGE_LEN];

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

static void fill(char *p, int len, int seed)
{
    int i;
    for (i = 0; i < len; i++) {
        p[i] = (char)('a' + (i * 7 + seed) % 26);
    }
}

static int lbl_is(const void *d, const char *s)
{
    return d != NULL && strcmp((const char *)d, s) == 0;
}

/* Returns the bytes that the server holds for the node that a label reads. */
static const char *expected(const void *d, int *len)
{
    if (lbl_is(d, "B")) {
        *len = LARGE_LEN;
        return g_large2;
    }
    if (lbl_is(d, "C") || lbl_is(d, "S")) {
        *len = SMALL_LEN;
        return g_small;
    }
    *len = LARGE_LEN;
    return g_large1;
}

static const char *same(const char *v, int len, const void *d)
{
    int want_len = 0;
    const char *want = expected(d, &want_len);
    if (v == NULL || len != want_len || memcmp(v, want, (size_t)want_len) != 0) {
        return "changed";
    }
    return "unchanged";
}

/*
 * Records the reply, then makes reentrant calls from completions "A", "S"
 * and "closer". Each one reads its value again after the calls.
 */
static void value_cb(int rc, const char *v, int len, const struct Stat *s,
                     const void *d)
{
    zkc_data_cb(rc, v, len, s, d);
    if (rc != ZOK) {
        return;
    }
    zkc_ev("check", "%s at depth %d: value %s", zkc_lbl(d), g_depth,
           same(v, len, d));
    if (lbl_is(d, "A") || lbl_is(d, "S")) {
        call("zoo_aget D", zoo_aget(g_zh, "/vl1", 0, value_cb, "D"));
        zkc_ev("check", "%s after the submit: value %s", zkc_lbl(d),
               same(v, len, d));
        g_depth++;
        call("nested zookeeper_process(READ)", zkc_process(g_zh, ZOOKEEPER_READ));
        g_depth--;
        zkc_ev("check", "%s after the nested call: value %s", zkc_lbl(d),
               same(v, len, d));
    } else if (lbl_is(d, "closer") && !g_closed) {
        g_closed = 1;
        zkc_close(g_zh);
        zkc_ev("check", "closer after the close: value %s", same(v, len, d));
    }
}

/* Drives g_zh until a completion closes the handle. */
static void drive_until_closed(int timeout_ms)
{
    int waited = 0;
    while (!g_closed && waited < timeout_ms) {
        int fd = -1;
        int interest = 0;
        struct timeval tv = {0, 0};
        struct timeval stv = {0, 50000};
        fd_set rd;
        fd_set wr;
        int events = 0;
        zkc_interest(g_zh, &fd, &interest, &tv);
        if (g_closed) {
            return;
        }
        FD_ZERO(&rd);
        FD_ZERO(&wr);
        if (fd >= 0) {
            if (interest & ZOOKEEPER_READ) {
                FD_SET(fd, &rd);
            }
            if (interest & ZOOKEEPER_WRITE) {
                FD_SET(fd, &wr);
            }
        }
        if (tv.tv_sec == 0 && tv.tv_usec < stv.tv_usec) {
            stv = tv;
        }
        if (select(fd >= 0 ? fd + 1 : 0, &rd, &wr, NULL, &stv) > 0) {
            if (FD_ISSET(fd, &rd)) {
                events |= ZOOKEEPER_READ;
            }
            if (FD_ISSET(fd, &wr)) {
                events |= ZOOKEEPER_WRITE;
            }
        }
        waited += 50;
        if (events != 0) {
            zkc_process(g_zh, events);
        }
    }
    if (!g_closed) {
        zkc_fail("no completion closed the handle");
    }
}

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "st_value_reenter", 1, "EXACT", "ordered");
    fill(g_small, SMALL_LEN, 1);
    fill(g_large1, LARGE_LEN, 2);
    fill(g_large2, LARGE_LEN, 3);
    g_zh = zkc_connect(zkc_host(0), 10000, 0);
    if (g_zh == NULL) {
        return zkc_finish();
    }
    call("create /vs", zkcs_create(g_zh, "/vs", g_small, SMALL_LEN,
                                   &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0));
    call("create /vl1", zkcs_create(g_zh, "/vl1", g_large1, LARGE_LEN,
                                    &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0));
    call("create /vl2", zkcs_create(g_zh, "/vl2", g_large2, LARGE_LEN,
                                    &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0));

    /* A large value stays valid while its completion submits and nests. */
    call("zoo_aget A", zoo_aget(g_zh, "/vl1", 0, value_cb, "A"));
    call("zoo_aget B", zoo_aget(g_zh, "/vl2", 0, value_cb, "B"));
    call("zoo_aget C", zoo_aget(g_zh, "/vs", 0, value_cb, "C"));
    zkc_sleep_ms(300);
    zkc_await("cb", 4, 10000);

    /* A small value stays valid while its completion submits and nests. */
    call("zoo_aget S", zoo_aget(g_zh, "/vs", 0, value_cb, "S"));
    call("zoo_aget B", zoo_aget(g_zh, "/vl2", 0, value_cb, "B"));
    zkc_sleep_ms(300);
    zkc_await("cb", 3, 10000);

    /* A value stays valid after its completion closes the handle. */
    zkc_poll_remove(g_zh);
    call("zoo_aget closer", zoo_aget(g_zh, "/vl1", 0, value_cb, "closer"));
    call("zoo_aget pending", zoo_aget(g_zh, "/vl2", 0, value_cb, "pending"));
    drive_until_closed(10000);
    return zkc_finish();
}
