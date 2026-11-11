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
 * The libc random state after a host resolution (ledger SRV-04;
 * zookeeper.c setup_random, update_addrs). Mode EXACT.
 *
 * Unless deterministic order is set, each resolution reseeds the
 * process-global srandom() and srand48() state from /dev/urandom. The
 * drop-in makes the same libc calls. The case seeds both generators with
 * a fixed value, connects, and then checks if the next draw still
 * follows the fixed seed. The trace records only that result, so the
 * traces of the two cores are equal.
 *
 * - With the shuffle, the next draws do not follow the fixed seed.
 * - With zoo_deterministic_conn_order(1), random() is not reseeded. The
 *   drand48() state still moves, because the handle draws drand48() for
 *   its reconfig choice in each mode.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"

#include <stdlib.h>

/* Connects after a fixed seed. Records if the connect reseeded libc. */
static void run(const char *label)
{
    long want_r;
    double want_d;
    long got_r;
    double got_d;
    zhandle_t *zh;
    srandom(42);
    want_r = random();
    srand48(42);
    want_d = drand48();
    srandom(42);
    srand48(42);
    zh = zkc_connect(zkc_host(0), 10000, 0);
    if (zh == NULL) {
        return;
    }
    got_r = random();
    got_d = drand48();
    zkc_ev("check", "%s: random reseeded=%d drand48 moved=%d", label,
           got_r != want_r, got_d != want_d);
    zkc_close(zh);
}

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "ldg_d_prng", 1, "EXACT", "ignore");
    run("shuffle");
    zoo_deterministic_conn_order(1);
    run("deterministic");
    return zkc_finish();
}
