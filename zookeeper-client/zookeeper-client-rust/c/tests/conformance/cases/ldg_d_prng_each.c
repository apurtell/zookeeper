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
 * Reseed of process-global libc PRNG state on each resolve of a connected handle.
 * Mode: EXACT.
 *
 * With the default resolution delay of 0, each zookeeper_interest call re-resolves
 * the host list and reseeds srandom() and srand48(). The test seeds both generators
 * with a fixed value and then makes one resolve trigger: one zookeeper_interest call
 * in st, or one synchronous zoo_exists in mt. After each trigger, both random() and
 * drand48() must differ from the fixed-seed values. With a delay of -1, a connected
 * handle does not resolve, so the fixed-seed values stay. The lowest free descriptor
 * must be the same before and after the loop, so a reseed leaves no descriptor open.
 * The checks do not depend on the entropy source.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"

#include <stdlib.h>
#include <unistd.h>

/* Returns the lowest free descriptor number. */
static int lowest_free_fd(void)
{
    int fd = dup(0);

    if (fd >= 0) {
        close(fd);
    }
    return fd;
}

/* Makes one call that resolves the host list once or more on a connected handle. */
static void trigger(zhandle_t *zh)
{
#ifdef THREADED
    struct Stat st;
    int rc = zoo_exists(zh, "/", 0, &st);

    if (rc != ZOK) {
        zkc_fail("zoo_exists: %s", zkc_rc(rc));
    }
#else
    int fd = -1;
    int interest = 0;
    struct timeval tv;
    int rc = zkc_interest(zh, &fd, &interest, &tv);

    if (rc != ZOK) {
        zkc_fail("zookeeper_interest: %s", zkc_rc(rc));
    }
#endif
}

/* Seeds both generators with 42, makes one trigger, and reports which generator moved. */
static void step(zhandle_t *zh, const char *label, long want_r, double want_d)
{
    long got_r;
    double got_d;

    srandom(42);
    srand48(42);
    trigger(zh);
    got_r = random();
    got_d = drand48();
    zkc_ev("check", "%s: random reseeded=%d drand48 reseeded=%d", label, got_r != want_r,
           got_d != want_d);
}

int main(int argc, char **argv)
{
    long want_r;
    double want_d;
    int fd_before;
    int fd_after;
    int i;
    zhandle_t *zh;

    zkc_init(argc, argv, "ldg_d_prng_each", 1, "EXACT", "ignore");
    srandom(42);
    want_r = random();
    srand48(42);
    want_d = drand48();
    zh = zkc_connect(zkc_host(0), 10000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    /*
     * A delay of -1 stops the resolves of a connected handle. The trigger after it lets
     * a resolve that is in progress on the mt I/O thread finish first. Thus no
     * transient resolve descriptor and no late reseed affect the next check.
     */
    zoo_set_servers_resolution_delay(zh, -1);
    trigger(zh);
    fd_before = lowest_free_fd();
    zoo_set_servers_resolution_delay(zh, 0);
    for (i = 0; i < 5; i++) {
        step(zh, "delay 0", want_r, want_d);
    }
    zoo_set_servers_resolution_delay(zh, -1);
    trigger(zh);
    step(zh, "delay -1", want_r, want_d);
    fd_after = lowest_free_fd();
    zkc_ev("check", "fd_same=%d", fd_before == fd_after);
    zkc_close(zh);
    return zkc_finish();
}
