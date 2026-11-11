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
 * st errno after a failed driving call (ST-09, ST-15; zookeeper.c
 * zookeeper_interest, zookeeper_process, check_events). Mode EXACT.
 *
 * The case drives each handle with its own loop. It records the rc and
 * the errno of each failed zookeeper_interest and zookeeper_process
 * call. The errno shows as a symbolic name.
 *
 * Rules:
 * - A refused connect gives ZCONNECTIONLOSS and ECONNREFUSED.
 * - A receive timeout gives ZOPERATIONTIMEOUT and ETIMEDOUT (ST-15). The
 *   proxy holds the server bytes until the timeout.
 * - A server that closes the connection gives ZCONNECTIONLOSS and
 *   EHOSTDOWN.
 * - A reconnect to an expired session gives ZSESSIONEXPIRED and ESTALE
 *   (ST-09).
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>

static const char *errno_name(int e)
{
    static char buf[32];
    switch (e) {
    case 0:
        return "0";
    case ECONNREFUSED:
        return "ECONNREFUSED";
    case ETIMEDOUT:
        return "ETIMEDOUT";
    case ESTALE:
        return "ESTALE";
    case EHOSTDOWN:
        return "EHOSTDOWN";
    case ECONNRESET:
        return "ECONNRESET";
    case EPIPE:
        return "EPIPE";
    case EINVAL:
        return "EINVAL";
    default:
        snprintf(buf, sizeof(buf), "errno-%d", e);
        return buf;
    }
}

/* Returns 1 for an rc that ends a step with a failure. */
static int is_failure(int rc)
{
    return rc != ZOK && rc != ZNOTHING && rc != ZINVALIDSTATE;
}

static void record(const char *what, int rc, int err)
{
    zkc_ev("fail", "%s -> %s errno=%s", what, zkc_rc(rc), errno_name(err));
}

/*
 * Drives zh for at most timeout_ms. It records each failed call, and it
 * stops at the first failure with rc stop_rc. It returns 1 at that stop.
 */
static int drive_until(zhandle_t *zh, int stop_rc, int timeout_ms)
{
    int waited = 0;
    while (waited < timeout_ms) {
        int fd = -1;
        int interest = 0;
        struct timeval tv = {0, 0};
        struct timeval stv = {0, 50000};
        fd_set rd;
        fd_set wr;
        int events = 0;
        int rc;
        errno = 0;
        rc = zkc_interest(zh, &fd, &interest, &tv);
        if (is_failure(rc)) {
            record("zookeeper_interest", rc, errno);
            if (rc == stop_rc) {
                return 1;
            }
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
        if (select(fd >= 0 ? fd + 1 : 0, &rd, &wr, NULL, &stv) > 0 &&
            fd >= 0) {
            if (FD_ISSET(fd, &rd)) {
                events |= ZOOKEEPER_READ;
            }
            if (FD_ISSET(fd, &wr)) {
                events |= ZOOKEEPER_WRITE;
            }
        }
        waited += 50;
        errno = 0;
        rc = zkc_process(zh, events);
        if (is_failure(rc)) {
            record("zookeeper_process", rc, errno);
            if (rc == stop_rc) {
                return 1;
            }
        }
    }
    zkc_fail("no call gave %s", zkc_rc(stop_rc));
    return 0;
}

static zhandle_t *open_handle(const char *hosts, int timeout_ms,
                              const clientid_t *id, const char *label)
{
    zhandle_t *zh = zookeeper_init2(hosts, zkc_watcher, timeout_ms, id,
                                    (void *)label, 0, zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 %s -> %s", label, zh ? "zh" : "NULL");
    return zh;
}

static void connected(zhandle_t *zh, const char *label)
{
    char key[96];
    snprintf(key, sizeof(key), "session:CONNECTED@%s", label);
    zkc_poll_add(zh);
    zkc_await(key, 1, 15000);
    zkc_poll_remove(zh);
}

int main(int argc, char **argv)
{
    zhandle_t *zh;
    zhandle_t *clone;
    const char *px;
    clientid_t copy;

    zkc_init(argc, argv, "st_errno", 1, "EXACT", "ignore");

    /* ECONNREFUSED: no server listens. */
    zh = open_handle(zkc_dead(), 6000, NULL, "refused");
    if (zh != NULL) {
        drive_until(zh, ZCONNECTIONLOSS, 10000);
        zkc_close(zh);
    }

    /* ETIMEDOUT (ST-15): the proxy holds the server bytes. */
    px = zkc_proxy_start(zkc_host(0));
    if (px == NULL) {
        return zkc_finish();
    }
    zh = open_handle(px, 3000, NULL, "timeout");
    if (zh != NULL) {
        connected(zh, "timeout");
        zkc_proxy_hold(1);
        drive_until(zh, ZOPERATIONTIMEOUT, 10000);
        zkc_proxy_hold(0);
        zkc_close(zh);
    }
    zkc_proxy_stop();

    /*
     * EHOSTDOWN, then ESTALE (ST-09): a clone takes the session and
     * closes it. The server then drops the handle, and its reconnect
     * finds the session expired.
     */
    zh = open_handle(zkc_host(0), 4000, NULL, "expire");
    if (zh == NULL) {
        return zkc_finish();
    }
    connected(zh, "expire");
    memcpy(&copy, zoo_client_id(zh), sizeof(copy));
    clone = open_handle(zkc_host(0), 4000, &copy, "clone");
    if (clone != NULL) {
        connected(clone, "clone");
        zkc_close(clone);
    }
    drive_until(zh, ZSESSIONEXPIRED, 15000);
    zkc_close(zh);
    return zkc_finish();
}
