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
 * A refused TLS connect in an st loop that maps POLLHUP to READ (ST-20;
 * zookeeper.c 3126-3136, 1932-1952, 412-419). Mode EXACT.
 *
 * This is the TLS form of st_refused_read. The connect to the dead address
 * reports EINPROGRESS, so the handle is in state 7 (SSL_CONNECTING). The
 * case asks poll for POLLIN alone, so each core gets READ alone.
 *
 * Rules:
 * - ST-20: in state 7 before SSL_connect, READ without WRITE reads the
 *   frame length on the TCP socket, because no TLS session exists yet. A
 *   refused connect fails this read. zookeeper_process returns
 *   ZCONNECTIONLOSS and logs "failed while receiving a server response".
 *   The attempt ends in one call, and no receive timeout fires.
 * - ST-20: a platform can refuse the connect in connect() itself. Then
 *   zookeeper_interest returns ZCONNECTIONLOSS in both cores.
 * - ST-14: on the first pass of a new handle, both cores try the next
 *   server with no delay.
 *
 * The list is the dead address, then the secure port of server 0. The
 * trust is the testSSL fixture, as in tls_state.
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"
#include "zkconf_tls.h"

#include <poll.h>
#include <stdio.h>
#include <sys/time.h>

#define T_MS 6000
/* A spin runs until 2T/3. A correct core ends the attempt at once. */
#define REFUSED_MS 1000
#define MAX_CALLS 20

static zhandle_t *g_zh;
static int g_connected;

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
 * One pass: interest, poll and process, as in st_refused_read. With
 * read_only set, the pass asks poll for POLLIN alone. POLLIN, POLLHUP and
 * POLLERR give READ, and POLLOUT gives WRITE. The pass records each rc
 * other than ZOK and ZNOTHING, with the state before the call.
 */
static int pass(int read_only, int *calls)
{
    int fd = -1;
    int interest = 0;
    struct timeval tv = {0, 0};
    struct pollfd p;
    int events = 0;
    int before;
    long wait;
    int rc = zkc_interest(g_zh, &fd, &interest, &tv);
    (*calls)++;
    if (rc != ZOK) {
        zkc_ev("interest", "rc=%s state=%s", zkc_rc(rc),
               zkc_state(zoo_state(g_zh)));
        return rc;
    }
    wait = (long)tv.tv_sec * 1000L + (long)(tv.tv_usec / 1000);
    if (wait > 100 || wait < 0) {
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
    before = zoo_state(g_zh);
    rc = zkc_process(g_zh, events);
    if (rc != ZOK && rc != ZNOTHING) {
        zkc_ev("process", "events=%s rc=%s state=%s -> %s", bits(events),
               zkc_rc(rc), zkc_state(before), zkc_state(zoo_state(g_zh)));
    }
    return rc;
}

int main(int argc, char **argv)
{
    char cert[4096];
    char hosts[512];
    const char *c;
    int calls = 0;
    int ended = 0;
    long start;
    long elapsed;
    long deadline;

    zkc_init(argc, argv, "tls_refused_read", 1, "EXACT", "ignore");
    if (zkt_setup(1) != 0) {
        return zkc_finish();
    }
    zkc_set_watch_hook(watch_hook);
    zoo_deterministic_conn_order(1);
    c = zkt_certs();
    snprintf(cert, sizeof(cert),
             "%s/server.crt,%s/client.crt,%s/clientkey.pem,password", c, c, c);
    snprintf(hosts, sizeof(hosts), "%s,%s", zkc_dead(), zkt_host(0));
    zkt_log_reset();
    g_zh = zkt_init(hosts, cert, T_MS, NULL, "refused", 0);
    if (g_zh == NULL) {
        return zkc_finish();
    }
    /* The pass loop below drives the handle, so it leaves the registry. */
    zkc_poll_remove(g_zh);

    /* ST-20: the attempt on the dead address gets READ alone. */
    start = zkt_now_ms();
    while (zkt_now_ms() - start < 3 * REFUSED_MS / 2) {
        int rc = pass(1, &calls);
        if (rc != ZOK && rc != ZNOTHING) {
            ended = 1;
            break;
        }
    }
    elapsed = zkt_now_ms() - start;
    zkc_ev("check", "refused attempt ended: %s", ended ? "yes" : "no");
    zkc_ev("check", "ended within %d ms: %s", REFUSED_MS,
           ended && elapsed <= REFUSED_MS ? "yes" : "no");
    zkc_ev("check", "interest calls <= %d: %s", MAX_CALLS,
           calls <= MAX_CALLS ? "yes" : "no");

    /* ST-14: the next server follows at once. The pass uses POLLOUT too. */
    deadline = zkt_now_ms() + 5000;
    while (!g_connected && zkt_now_ms() < deadline) {
        pass(0, &calls);
    }
    zkc_ev("check", "connected to the next server: %s",
           g_connected ? "yes" : "no");

    zkc_close(g_zh);
    g_zh = NULL;
    zkt_log_record("refused", "failed while receiving", 0);
    zkt_log_record("refused", "timed out", 1);
    return zkc_finish();
}
