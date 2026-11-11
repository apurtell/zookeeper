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
 * A reconnect with two servers when the first server refuses connections
 * (ledger DV-FIX-1, SRV-01; OR-26; zookeeper.c handle_error,
 * zoo_cycle_next_server). Mode DEV.
 *
 * The host list is the dead address, then a proxy to server 0. No
 * process listens on the dead address, so each connect to it gets a
 * refusal. zoo_deterministic_conn_order(1) turns off the shuffle. The
 * first pass tries the dead address, then the proxy, and connects. The
 * case then resets the proxy connections and waits for a reconnect.
 *
 * The cores differ after the loss (DV-FIX-1):
 * - Rust advances the cursor once per failure. It tries the dead
 *   address once, then the proxy, and connects again.
 * - Legacy advances the cursor twice per failure. It tries only the
 *   dead address and never connects again. The cursor is never at the
 *   end of the list in handle_error, so no T/60 pause occurs and the
 *   connects spin.
 *
 * The Rust wait stops at the reconnect. Its limit is long, so a slow
 * reconnect does not fail the case. The legacy wait is a fixed window.
 * The connect preload counts the connects in the wait. The bound is ten
 * times the most connects that a client with a T/60 pause before each
 * connect can make in the measured time. Without the preload, the case
 * does not do the count checks.
 *
 * In st, zkc_poll uses select. The case does not cover a poll loop that
 * maps POLLHUP only to READ.
 *
 * zkconf-flavors: mt st
 * zkconf-preload: connect
 */

#include "zkconf.h"
#include "zkconf_tls.h"

#include <stdio.h>

#define T_MS 6000
#define RUST_WAIT_MS 15000
#define LEGACY_WAIT_MS 5000

/* The number of CONNECTED session events. */
static int g_connected;

static void watch_hook(zhandle_t *zh, int type, int state, const char *path,
                       void *ctx)
{
    (void)zh;
    (void)path;
    (void)ctx;
    if (type == ZOO_SESSION_EVENT && state == ZOO_CONNECTED_STATE) {
        __atomic_fetch_add(&g_connected, 1, __ATOMIC_SEQ_CST);
    }
}

static int connected(void)
{
    return __atomic_load_n(&g_connected, __ATOMIC_SEQ_CST);
}

int main(int argc, char **argv)
{
    char hosts[256];
    const char *px;
    zhandle_t *zh;
    long start;
    long elapsed;
    int limit;
    int have;
    int c1;
    int a1;
    int n1;
    int back;
    int da;
    int dn;
    int step;
    int spin_min;

    zkc_init(argc, argv, "ldg_d_refused_first", 1, "DEV", "ignore");
    zkc_set_watch_hook(watch_hook);
    have = zkt_have_preload();
    px = zkc_proxy_start(zkc_host(0));
    if (px == NULL) {
        return zkc_finish();
    }
    snprintf(hosts, sizeof(hosts), "%s,%s", zkc_dead(), px);
    zoo_deterministic_conn_order(1);
    zh = zkc_connect(hosts, T_MS, 0);
    if (zh == NULL) {
        zkc_fail("zookeeper_init2 failed");
        zkc_proxy_stop();
        return zkc_finish();
    }
    c1 = connected();
    a1 = zkc_proxy_accepted();
    zkc_dev("DV-FIX-1", c1 >= 1 && a1 == 1,
            "the first pass connects through the proxy: connected=%d "
            "accepted=%d",
            c1, a1);

    /* Legacy logs one ERROR line for each failed connect, so the spin
     * floods the log. The case turns off the log. */
    zoo_set_debug_level((ZooLogLevel)0);
    limit = zkc_is_rust() ? RUST_WAIT_MS : LEGACY_WAIT_MS;
    n1 = zkt_connect_count();
    zkc_proxy_reset();
    start = zkt_now_ms();
    while (connected() <= c1 && zkt_now_ms() - start < limit) {
        zkc_poll(20);
    }
    elapsed = zkt_now_ms() - start;
    back = connected() > c1;
    da = zkc_proxy_accepted() - a1;
    dn = zkt_connect_count() - n1;
    step = zoo_recv_timeout(zh) / 60;
    if (step < 1) {
        step = 1;
    }
    /* A client with a T/60 pause before each connect makes at most
     * elapsed / step + 1 connects in the wait. */
    spin_min = 10 * (int)(elapsed / step + 1);
    zkc_ev("check", "back=%d accepted=%d", back, da);

    if (zkc_is_rust()) {
        zkc_dev("DV-FIX-1", back && da == 1,
                "rust: the client tries the dead address, then reconnects "
                "through the proxy: back=%d accepted=%d ms=%ld",
                back, da, elapsed);
        if (have) {
            zkc_dev("DV-FIX-1", dn >= 2 && dn < spin_min,
                    "rust: a few connects before the reconnect: "
                    "connects=%d bound=%d",
                    dn, spin_min);
        }
    } else {
        zkc_dev("DV-FIX-1", !back && da == 0,
                "legacy: no reconnect, and no connect to the live server "
                "in %ld ms: back=%d accepted=%d",
                elapsed, back, da);
        if (have) {
            zkc_dev("DV-FIX-1", dn > spin_min,
                    "legacy: the connects to the dead address spin, and no "
                    "T/60 pause occurs: connects=%d bound=%d",
                    dn, spin_min);
        }
    }

    zkc_close(zh);
    zkc_proxy_stop();
    return zkc_finish();
}
