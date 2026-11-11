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
 * The st interest values (ST-19, ST-14, ST-15, ST-01; zookeeper.c
 * 2618-2824). Mode EXACT.
 *
 * The case drives one handle with its own loop. The session timeout T is
 * 6000 ms. The case measures the idle times on its own clock and gives
 * each tv a formula name. A tv that matches no formula shows its value,
 * so the traces differ.
 *
 * Rules:
 * - ST-19: tv is T/3 while the handle connects. A connected handle gives
 *   min(2T/3 - idle_recv, T/3 - idle_send). The interest is READ and
 *   WRITE while the TCP connect runs, READ when connected and idle. fd is
 *   the socket of the current connection, and -1 without a socket. Each
 *   reconnect gives a new socket.
 * - ST-15: a connected handle sends a ping when T/3 passed without a send
 *   and no request waits for a reply. Then tv uses T/3 for the send part.
 *   With a request in flight, no ping goes out.
 * - ST-14: after the last server of the list fails, one interest call
 *   gives fd -1, no interest and tv T/60, and it logs "Delaying
 *   connection". The next call connects.
 * - ST-01: the state is 0 after a connection loss until the next
 *   interest call that connects.
 * - Loss: zookeeper_process sees the loss. It returns
 *   ZCONNECTIONLOSS, and the CONNECTING event runs inside it.
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#define T_MS 6000
/* The tolerance of a tv match. Each idle time comes from a clock read. */
#define TV_SLACK 40

static zhandle_t *g_zh;
static int g_connected;
static int g_connecting;
static int g_done;
static long g_t_recv;
static int g_last_lport = -1;

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
    if (type == ZOO_SESSION_EVENT && state == ZOO_CONNECTING_STATE) {
        g_connecting = 1;
    }
}

/* The reply time is the clock read in the completion. */
static void done_cb(int rc, const struct Stat *s, const void *d)
{
    zkc_stat_cb(rc, s, d);
    g_t_recv = now_ms();
    g_done++;
}

static const char *bits(int interest)
{
    if ((interest & ZOOKEEPER_READ) && (interest & ZOOKEEPER_WRITE)) {
        return "RW";
    }
    if (interest & ZOOKEEPER_READ) {
        return "R";
    }
    if (interest & ZOOKEEPER_WRITE) {
        return "W";
    }
    return interest == 0 ? "0" : "?";
}

/*
 * Names the descriptor: -1, or whether the local port is new since the
 * last call that named a socket. The peer is not used, because a socket
 * in the TCP connect has no peer yet.
 */
static void fd_name(char *buf, size_t len, int fd)
{
    struct sockaddr_in local;
    socklen_t ll = sizeof(local);
    int lport;
    if (fd < 0) {
        snprintf(buf, len, "-1");
        return;
    }
    if (getsockname(fd, (struct sockaddr *)&local, &ll) != 0) {
        snprintf(buf, len, "sock(unbound)");
        return;
    }
    lport = ntohs(local.sin_port);
    snprintf(buf, len, "sock(%s)", lport == g_last_lport ? "same" : "new");
    g_last_lport = lport;
}

static long tv_ms(const struct timeval *tv)
{
    return (long)tv->tv_sec * 1000L + (long)(tv->tv_usec / 1000);
}

/* Names a tv of the connect phase. */
static void tv_connecting(char *buf, size_t len, long tv)
{
    if (tv >= T_MS / 3 - TV_SLACK && tv <= T_MS / 3) {
        snprintf(buf, len, "T/3");
    } else if (tv == T_MS / 60) {
        snprintf(buf, len, "T/60");
    } else {
        snprintf(buf, len, "other(%ld)", tv);
    }
}

/*
 * One pass: interest, select and process. Records the interest outputs
 * when the line changes, and every process result except ZNOTHING. A
 * connected tv depends on the timing, so connected_tv checks it and the
 * pass records no value.
 */
static void pass(char *last, size_t lastlen, int max_wait_ms)
{
    char fdn[96];
    char tvn[32];
    char line[256];
    int fd = -1;
    int interest = 0;
    struct timeval tv = {0, 0};
    struct timeval stv;
    fd_set rd;
    fd_set wr;
    int events = 0;
    long wait;
    int rc = zkc_interest(g_zh, &fd, &interest, &tv);
    if (zoo_state(g_zh) == ZOO_CONNECTED_STATE) {
        snprintf(tvn, sizeof(tvn), "connected");
    } else {
        tv_connecting(tvn, sizeof(tvn), tv_ms(&tv));
    }
    if (fd >= 0) {
        fd_name(fdn, sizeof(fdn), fd);
    } else {
        snprintf(fdn, sizeof(fdn), "-1");
    }
    snprintf(line, sizeof(line), "rc=%s fd=%s interest=%s tv=%s state=%s",
             zkc_rc(rc), fdn, bits(interest), tvn, zkc_state(zoo_state(g_zh)));
    if (strcmp(line, last) != 0) {
        snprintf(last, lastlen, "%s", line);
        zkc_ev("interest", "%s", line);
    }
    wait = tv_ms(&tv);
    if (wait > max_wait_ms) {
        wait = max_wait_ms;
    }
    stv.tv_sec = wait / 1000;
    stv.tv_usec = (wait % 1000) * 1000;
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
    if (select(fd >= 0 ? fd + 1 : 0, &rd, &wr, NULL, &stv) > 0) {
        if (FD_ISSET(fd, &rd)) {
            events |= ZOOKEEPER_READ;
        }
        if (FD_ISSET(fd, &wr)) {
            events |= ZOOKEEPER_WRITE;
        }
    }
    if (events != 0) {
        int shown = events;
        /*
         * A failed TCP connect always makes the socket writable. The socket
         * is also readable only if the error arrives before select runs.
         * Thus the record of the connect phase omits the read bit.
         */
        if (zoo_state(g_zh) == ZOO_CONNECTING_STATE &&
            (events & ZOOKEEPER_WRITE)) {
            shown = ZOOKEEPER_WRITE;
        }
        rc = zkc_process(g_zh, events);
        if (rc != ZOK && rc != ZNOTHING) {
            zkc_ev("process", "events=%s rc=%s state=%s", bits(shown),
                   zkc_rc(rc), zkc_state(zoo_state(g_zh)));
        }
    }
}

/* Drives the handle until *flag is set, at most timeout_ms. */
static void drive_until(const int *flag, const char *what, int timeout_ms)
{
    char last[256] = "";
    long deadline = now_ms() + timeout_ms;
    while (!*flag && now_ms() < deadline) {
        pass(last, sizeof(last), 50);
    }
    if (!*flag) {
        zkc_fail("timeout waiting for %s", what);
    }
}

/* Waits up to 300 ms for the proxy to count new bytes from the client. */
static long up_delta(long before)
{
    long deadline = now_ms() + 300;
    long d = zkc_proxy_up_bytes() - before;
    long stable_until;
    while (d == 0 && now_ms() < deadline) {
        zkc_sleep_ms(10);
        d = zkc_proxy_up_bytes() - before;
    }
    /* Legacy can write one frame in two parts. Count the full frame. */
    stable_until = now_ms() + 100;
    while (d != 0 && now_ms() < stable_until) {
        long n;
        zkc_sleep_ms(10);
        n = zkc_proxy_up_bytes() - before;
        if (n != d) {
            d = n;
            stable_until = now_ms() + 100;
        }
    }
    return d;
}

/*
 * One interest call on a connected handle. t_send and t_recv are the
 * clock reads at the last send and the last reply. The case records the
 * formula that tv matches and the bytes that the call sent.
 */
static void connected_tv(const char *label, long t_send, long t_recv)
{
    int fd = -1;
    int interest = 0;
    struct timeval tv = {0, 0};
    long before = zkc_proxy_up_bytes();
    long t = now_ms();
    long send_to = T_MS / 3 - (t - t_send);
    long recv_to = 2 * T_MS / 3 - (t - t_recv);
    const char *bound;
    long expect;
    long got;
    char fdn[96];
    int rc = zkc_interest(g_zh, &fd, &interest, &tv);
    got = tv_ms(&tv);
    if (send_to <= 0) {
        send_to = T_MS / 3;
        bound = "T/3 after the ping rule";
    } else {
        bound = "T/3-idle_send";
    }
    if (recv_to < send_to) {
        bound = "2T/3-idle_recv";
        expect = recv_to;
    } else {
        expect = send_to;
    }
    fd_name(fdn, sizeof(fdn), fd);
    if (got >= expect - TV_SLACK && got <= expect + TV_SLACK) {
        zkc_ev("interest", "%s: rc=%s fd=%s interest=%s tv=%s sent=%ld",
               label, zkc_rc(rc), fdn, bits(interest), bound,
               up_delta(before));
    } else {
        zkc_ev("interest", "%s: rc=%s fd=%s interest=%s tv=other(%ld, %s "
               "%ld) sent=%ld", label, zkc_rc(rc), fdn, bits(interest), got,
               bound, expect, up_delta(before));
    }
}

/* The size of the exists frame for "/", with its length prefix. */
#define EXISTS_FRAME 18

/*
 * Submits an exists request. Returns the clock read after the submit.
 * The st submit flushes the frame. Legacy sends the length
 * prefix and the body in two sends. Thus the case waits until the proxy
 * counted the whole frame, so that a later byte count holds no part of it.
 */
static long submit(const char *label)
{
    long before = zkc_proxy_up_bytes();
    int rc = zoo_aexists(g_zh, "/", 0, done_cb, label);
    long t = now_ms();
    long deadline = t + 300;
    zkc_ev("call", "zoo_aexists %s -> %s", label, zkc_rc(rc));
    while (zkc_proxy_up_bytes() - before < EXISTS_FRAME &&
           now_ms() < deadline) {
        zkc_sleep_ms(5);
    }
    return t;
}

static void wait_reply(int n)
{
    int target = g_done + n;
    int reached = 0;
    char last[256] = "";
    long deadline = now_ms() + 10000;
    while (now_ms() < deadline) {
        if (g_done >= target) {
            reached = 1;
            break;
        }
        pass(last, sizeof(last), 50);
    }
    if (!reached) {
        zkc_fail("timeout waiting for %d replies", n);
    }
}

/* ST-14 with the dead address: two failed attempts on a list of one. */
static void dead_server(void)
{
    char last[256] = "";
    int i;
    g_last_lport = -1;
    g_zh = zookeeper_init2(zkc_dead(), zkc_watcher, T_MS, NULL, "dead", 0,
                           zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 dead -> %s", g_zh ? "zh" : "NULL");
    if (g_zh == NULL) {
        return;
    }
    /* Each attempt takes one pass to connect, one to fail, one to wait. */
    for (i = 0; i < 6; i++) {
        pass(last, sizeof(last), 500);
    }
    zkc_ev("check", "dead server state=%s", zkc_state(zoo_state(g_zh)));
    zkc_in_call(1);
    zkc_ev("call", "zookeeper_close dead -> %s",
           zkc_rc(zookeeper_close(g_zh)));
    zkc_in_call(0);
    g_zh = NULL;
}

int main(int argc, char **argv)
{
    const char *px;
    long t_send;
    long t;

    zkc_init(argc, argv, "st_tv", 1, "EXACT", "ordered");
    zkc_set_watch_hook(watch_hook);
    px = zkc_proxy_start(zkc_host(0));
    if (px == NULL) {
        return zkc_finish();
    }
    g_zh = zookeeper_init2(px, zkc_watcher, T_MS, NULL, "default", 0,
                           zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 -> %s", g_zh ? "zh" : "NULL");
    if (g_zh == NULL) {
        zkc_proxy_stop();
        return zkc_finish();
    }

    /* ST-19: the connect phase, T/3 with READ and WRITE. */
    drive_until(&g_connected, "CONNECTED", 15000);
    zkc_ev("check", "recv timeout %d", zoo_recv_timeout(g_zh));

    /* ST-19: idle send and idle receive after a reply. */
    t_send = submit("idle");
    wait_reply(1);
    zkc_sleep_ms(500);
    connected_tv("idle 500 ms", t_send, g_t_recv);

    /* ST-19: the receive part is smaller when no reply came for long. */
    t_send = submit("recv-bound-0");
    wait_reply(1);
    zkc_sleep_ms(2500);
    zkc_proxy_hold(1);
    t_send = submit("recv-bound");
    connected_tv("reply 2500 ms ago, send now", t_send, g_t_recv);
    zkc_proxy_hold(0);
    wait_reply(1);

    /* ST-15: a request in flight suppresses the ping. */
    zkc_proxy_hold(1);
    t_send = submit("in-flight");
    zkc_sleep_ms(2400);
    connected_tv("send 2400 ms ago, request in flight", t_send, g_t_recv);
    zkc_proxy_hold(0);
    wait_reply(1);

    /* ST-15: an idle handle sends a ping after T/3. */
    t_send = submit("before-ping");
    wait_reply(1);
    zkc_sleep_ms(2400);
    t = now_ms();
    connected_tv("send 2400 ms ago, nothing in flight", t_send, g_t_recv);
    zkc_poll(0);
    {
        char last[256] = "";
        long end = now_ms() + 300;
        while (now_ms() < end) {
            pass(last, sizeof(last), 50);
        }
    }
    connected_tv("after the ping", t, t);

    /* ST-01, ST-14: the loss, the T/60 delay and the reconnect. */
    g_connected = 0;
    g_connecting = 0;
    zkc_proxy_reset();
    drive_until(&g_connecting, "CONNECTING", 10000);
    zkc_ev("check", "state after the loss=%s", zkc_state(zoo_state(g_zh)));
    drive_until(&g_connected, "CONNECTED again", 15000);

    zkc_in_call(1);
    zkc_ev("call", "zookeeper_close -> %s", zkc_rc(zookeeper_close(g_zh)));
    zkc_in_call(0);
    g_zh = NULL;
    zkc_proxy_stop();

    dead_server();
    return zkc_finish();
}
