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
 * A refused connect in an st loop that maps POLLHUP to READ (ST-20;
 * zookeeper.c 3126-3136, 1932-1952). Mode EXACT.
 *
 * Many st programs map POLLIN, POLLHUP and POLLERR to ZOOKEEPER_READ and
 * only POLLOUT to ZOOKEEPER_WRITE. On macOS a refused nonblocking connect
 * wakes poll with POLLIN and POLLHUP and no POLLOUT. The case asks poll
 * for POLLIN alone, so each core gets READ alone.
 *
 * Rules:
 * - ST-20: READ without WRITE while the TCP connect runs reads the frame
 *   length. A refused connect fails this read. zookeeper_process returns
 *   ZCONNECTIONLOSS and logs "failed while receiving a server response".
 *   The attempt ends in one call, and the loop does not spin.
 * - ST-20: a platform can refuse the connect in connect() itself. Then
 *   zookeeper_interest returns ZCONNECTIONLOSS in both cores.
 * - ST-14: on the first pass of a new handle, the failed attempt is not
 *   at the end of the list. Both cores try the next server with no delay.
 *
 * The list is the dead address, then server 0, in this order.
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"

#include <poll.h>
#include <stdio.h>
#include <sys/time.h>

#define T_MS 6000
/* A spin runs until 2T/3. A correct core ends the attempt at once. */
#define REFUSED_MS 1000
#define MAX_CALLS 20

static zhandle_t *g_zh;
static int g_connected;

static long now_ms(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (long)now.tv_sec * 1000L + (long)(now.tv_usec / 1000);
}

static void watch_hook(zhandle_t *zh, int type, int state, const char *path,
                       void *ctx)
{
    (void)zh;
    (void)path;
    (void)ctx;
    if (type == ZOO_SESSION_EVENT && state == ZOO_CONNECTED_STATE) {
        g_connected = 1;
    }
}

static const char *bits(int events)
{
    if ((events & ZOOKEEPER_READ) && (events & ZOOKEEPER_WRITE)) {
        return "RW";
    }
    if (events & ZOOKEEPER_READ) {
        return "R";
    }
    if (events & ZOOKEEPER_WRITE) {
        return "W";
    }
    return "0";
}

/*
 * One pass: interest, poll and process. With read_only set, the pass asks
 * poll for POLLIN alone. The map is the common one: POLLIN, POLLHUP and
 * POLLERR give READ, and POLLOUT gives WRITE. The pass records each rc
 * other than ZOK and ZNOTHING, and returns the rc.
 */
static int pass(int read_only, int *calls)
{
    int fd = -1;
    int interest = 0;
    struct timeval tv = {0, 0};
    struct pollfd p;
    int events = 0;
    long wait;
    int rc = zkc_interest(g_zh, &fd, &interest, &tv);
    (*calls)++;
    if (rc != ZOK) {
        zkc_ev("interest", "rc=%s state=%s", zkc_rc(rc),
               zkc_state(zoo_state(g_zh)));
        return rc;
    }
    wait = (long)tv.tv_sec * 1000L + (long)(tv.tv_usec / 1000);
    if (wait > 100) {
        wait = 100;
    }
    if (fd < 0) {
        zkc_sleep_ms((int)wait);
        return ZOK;
    }
    p.fd = fd;
    p.events = 0;
    p.revents = 0;
    if (interest & ZOOKEEPER_READ) {
        p.events |= POLLIN;
    }
    if (!read_only && (interest & ZOOKEEPER_WRITE)) {
        p.events |= POLLOUT;
    }
    if (poll(&p, 1, (int)wait) > 0) {
        if (p.revents & (POLLIN | POLLHUP | POLLERR)) {
            events |= ZOOKEEPER_READ;
        }
        if (p.revents & POLLOUT) {
            events |= ZOOKEEPER_WRITE;
        }
    }
    if (events == 0) {
        return ZOK;
    }
    rc = zkc_process(g_zh, events);
    if (rc != ZOK && rc != ZNOTHING) {
        zkc_ev("process", "events=%s rc=%s state=%s", bits(events),
               zkc_rc(rc), zkc_state(zoo_state(g_zh)));
    }
    return rc;
}

int main(int argc, char **argv)
{
    char hosts[256];
    int calls = 0;
    int ended = 0;
    long start;
    long elapsed;
    long deadline;

    zkc_init(argc, argv, "st_refused_read", 1, "EXACT", "ordered");
    zkc_set_watch_hook(watch_hook);
    zoo_deterministic_conn_order(1);
    snprintf(hosts, sizeof(hosts), "%s,%s", zkc_dead(), zkc_host(0));
    g_zh = zookeeper_init2(hosts, zkc_watcher, T_MS, NULL, "refused", 0,
                           zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 -> %s", g_zh ? "zh" : "NULL");
    if (g_zh == NULL) {
        return zkc_finish();
    }

    /* ST-20: the attempt on the dead address gets READ alone. */
    start = now_ms();
    while (now_ms() - start < 3 * REFUSED_MS / 2) {
        int rc = pass(1, &calls);
        if (rc != ZOK && rc != ZNOTHING) {
            ended = 1;
            break;
        }
    }
    elapsed = now_ms() - start;
    zkc_ev("check", "refused attempt ended: %s", ended ? "yes" : "no");
    zkc_ev("check", "ended within %d ms: %s", REFUSED_MS,
           ended && elapsed <= REFUSED_MS ? "yes" : "no");
    zkc_ev("check", "interest calls <= %d: %s", MAX_CALLS,
           calls <= MAX_CALLS ? "yes" : "no");

    /* ST-14: the next server follows at once. The pass uses POLLOUT too. */
    deadline = now_ms() + 5000;
    while (!g_connected && now_ms() < deadline) {
        pass(0, &calls);
    }
    zkc_ev("check", "connected to the next server: %s",
           g_connected ? "yes" : "no");

    zkc_in_call(1);
    zkc_ev("call", "zookeeper_close -> %s", zkc_rc(zookeeper_close(g_zh)));
    zkc_in_call(0);
    g_zh = NULL;
    return zkc_finish();
}
