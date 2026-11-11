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
 * Server list deviations. Mode DEV: each core asserts its own
 * result, the legacy result on the oracle and the fixed result on Rust.
 *
 * - DV-FIX-2 (SRV-02, OR-20): a port-only zoo_set_servers change. Legacy
 *   compares the IP only, so it stays on the old server. Rust compares IP
 *   and port, so it moves: CONNECTING, then a connect to the new port. The
 *   servers are standalone, so the new server reports EXPIRED.
 * - D9 (SRV-07): an unparsable string gives ZBADARGUMENTS on both cores.
 *   Legacy commits it and never reconnects after a server restart. Rust
 *   keeps the old list and reconnects. In legacy st, each
 *   zookeeper_interest call resolves the committed string again and
 *   gives ZBADARGUMENTS (zookeeper.c update_addrs). So the handle never
 *   sees the loss and sends no CONNECTING event.
 * - RC-09 (DV-FIX): legacy installs the empty list of
 *   zoo_set_servers(zh, ""). It gives ZOK and state 999, and later work
 *   fails with ZSYSTEMERROR (SRV-08). Rust refuses the empty string with
 *   ZBADARGUMENTS. The handle stays connected and sends no session event.
 *   Thus the call does not reach the forced close of DV-FIX-8 on Rust.
 *
 * In st, the waits drive the handle, and zkcs_exists replaces the sync
 * call.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_sync.h"

#include <string.h>

/* Waits until zoo_state is CONNECTED. Returns 1 on success. */
static int wait_connected(zhandle_t *zh, int ms)
{
    int waited;
    for (waited = 0; waited < ms; waited += 50) {
        if (zoo_state(zh) == ZOO_CONNECTED_STATE) {
            return 1;
        }
        zkc_poll(50);
    }
    return 0;
}

static void port_only_change(void)
{
    zhandle_t *zh = zkc_connect(zkc_host(0), 20000, 0);
    char cur[64];
    int rc;
    int moved;
    if (zh == NULL) {
        return;
    }
    rc = zoo_set_servers(zh, zkc_host(1));
    zkc_ev("call", "zoo_set_servers port-only -> %s", zkc_rc(rc));
    if (zkc_is_rust()) {
        /* The servers are standalone, so P2 does not know the session. */
        zkc_await("session:CONNECTING@default", 1, 10000);
        moved = zkc_await("session:EXPIRED@default", 1, 15000) == 0;
        snprintf(cur, sizeof(cur), "%s", zoo_get_current_server(zh));
        zkc_norm_text(cur, sizeof(cur), cur);
        zkc_dev("DV-FIX-2", rc == ZOK && moved && strstr(cur, ":P2") != NULL,
                "rc=%s moved=%d current=%s", zkc_rc(rc), moved, cur);
    } else {
        moved = zkc_await_none("watch", 2000);
        snprintf(cur, sizeof(cur), "%s", zoo_get_current_server(zh));
        zkc_norm_text(cur, sizeof(cur), cur);
        zkc_dev("DV-FIX-2", rc == ZOK && moved == 0 &&
                                strstr(cur, ":P1") != NULL,
                "rc=%s events=%d current=%s", zkc_rc(rc), moved, cur);
    }
    zkc_close(zh);
}

static void bad_string_not_committed(void)
{
    zhandle_t *zh = zkc_connect(zkc_host(2), 30000, 0);
    struct Stat st;
    int rc;
    int back;
    if (zh == NULL) {
        return;
    }
    rc = zoo_set_servers(zh, "127.0.0.1:12x");
    zkc_ev("call", "zoo_set_servers bad -> %s", zkc_rc(rc));
    zkc_server("stop", 2);
#ifndef THREADED
    if (!zkc_is_rust()) {
        int fd = -1;
        int interest = 0;
        struct timeval tv;
        int ncon = zkc_await_none("session:CONNECTING@default", 3000);
        int irc = zkc_interest(zh, &fd, &interest, &tv);
        zkc_server("start", 2);
        zkc_dev("D9", ncon == 0 && irc == ZBADARGUMENTS,
                "st: CONNECTING=%d interest=%s (legacy keeps the bad list)",
                ncon, zkc_rc(irc));
        zkc_close(zh);
        return;
    }
#endif
    zkc_await("session:CONNECTING@default", 1, 10000);
    zkc_server("start", 2);
    if (zkc_is_rust()) {
        back = zkc_await("session:CONNECTED@default", 1, 20000) == 0;
        rc = back ? zkcs_exists(zh, "/", 0, &st) : ZCONNECTIONLOSS;
        zkc_dev("D9", back && rc == ZOK,
                "reconnected=%d exists=%s", back, zkc_rc(rc));
    } else {
        back = wait_connected(zh, 6000);
        zkc_dev("D9", back == 0, "reconnected=%d (legacy keeps the bad list)",
                back);
    }
    zkc_close(zh);
}

static void empty_list(void)
{
    zhandle_t *zh = zkc_connect(zkc_host(0), 10000, 0);
    int rc;
    int arc;
    int st0;
    int ncb;
    int nev;
    if (zh == NULL) {
        return;
    }
    rc = zoo_set_servers(zh, "");
    st0 = zoo_state(zh);
    arc = zoo_aexists(zh, "/", 0, zkc_stat_cb, "after-empty");
    /*
     * Both cores must give one completion, and a loaded host can delay it.
     * The wait stops at the first completion, so the long wait adds no
     * time on a pass.
     */
    ncb = zkc_await_none("cb", 10000);
    nev = zkc_await_none("session:CONNECTING@default", 1);
    if (zkc_is_rust()) {
        zkc_dev("RC-09", rc == ZBADARGUMENTS &&
                                   st0 == ZOO_CONNECTED_STATE && arc == ZOK &&
                                   ncb == 1 && nev == 0,
                "RC-09-empty: rc=%s state=%s aexists=%s completions=%d CONNECTING=%d",
                zkc_rc(rc), zkc_state(st0), zkc_rc(arc), ncb, nev);
    } else {
        zkc_dev("RC-09", rc == ZOK && st0 == ZOO_NOTCONNECTED_STATE &&
                                   arc == ZOK && ncb == 1 && nev == 0,
                "RC-09-empty: rc=%s state=%s aexists=%s completions=%d CONNECTING=%d",
                zkc_rc(rc), zkc_state(st0), zkc_rc(arc), ncb, nev);
    }
    zkc_close(zh);
}

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "dev_servers", 3, "DEV", "ignore");
    port_only_change();
    bad_string_not_committed();
    empty_list();
    return zkc_finish();
}
