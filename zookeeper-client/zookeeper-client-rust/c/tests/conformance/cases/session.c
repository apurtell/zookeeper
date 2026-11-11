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
 * Session lifecycle and expiry (OR-03, OR-12, RC-01, RC-06,
 * RC-07, DA-07, TH-01, CL-01; spec "Initialization and shutdown
 * lifecycles"). Mode PER-ROLE: two handles, each with its own threads.
 *
 * The scenario expires the session of the first handle with zkc_expire. A
 * second handle attaches to the same session and closes it. The server
 * then drops the first connection, and the reconnect finds the session
 * gone. The first handle holds its IO thread meanwhile, so it cannot
 * attach again before the close.
 *
 * Rules:
 * - TH-01: an mt handle adds two threads; close restores the count.
 *   CL-01: close restores the descriptor count.
 * - DA-07: zoo_client_id returns a stable pointer with the session id.
 * - OR-03: CONNECTING, then the EXPIRED session event; afterwards every
 *   op gives ZINVALIDSTATE and is_unrecoverable gives ZINVALIDSTATE.
 * - RC-01: on an expired handle a bad path gives ZBADARGUMENTS first
 *   (zookeeper.c 4112-4131; validation order, spec lines 562-575).
 * - RC-06: zoo_add_auth on an expired handle gives ZINVALIDSTATE. An
 *   empty multi on an expired handle is a DEV check in dev_misc, because
 *   the cores differ there (DV-FIX).
 * - RC-07: zoo_set_servers never gives ZINVALIDSTATE.
 * - Ephemeral nodes go away with the session.
 *
 * In st, TH-01 expects no added thread. The zkcs helpers replace the sync
 * calls. zkc_expire keeps the handle out of the poll registry while the
 * clone closes the session.
 *
 * Ledger rows: ST-03.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_sync.h"

#include <string.h>

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

/*
 * The server sets a random password of 16 bytes. Any one byte can be zero
 * by chance, so the check reads all 16 bytes.
 */
static int passwd_nonzero(const clientid_t *cid)
{
    size_t i;
    for (i = 0; i < sizeof(cid->passwd); i++) {
        if (cid->passwd[i] != 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    zhandle_t *zh;
    zhandle_t *other;
    const clientid_t *cid;
    const clientid_t *cid2;
    struct Stat st;
    char buf[32];
    int len = sizeof(buf);
    int t0;
    int f0;
    int t1;

    zkc_init(argc, argv, "session", 1, "PER-ROLE", "ordered");
    t0 = zkc_threads();
    f0 = zkc_fds();
    zh = zkc_connect(zkc_host(0), 4000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    t1 = zkc_threads();
    zkc_ev("check", "threads added by init: %d", t1 - t0);
    zkc_ev("ret", "zoo_state -> %s", zkc_state(zoo_state(zh)));
    zkc_ev("ret", "zoo_recv_timeout -> %d", zoo_recv_timeout(zh));
    zkc_ev("ret", "zoo_get_context -> %s",
           zkc_lbl(zoo_get_context(zh)));
    zoo_set_context(zh, "ctx2");
    zkc_ev("ret", "zoo_get_context after set -> %s",
           zkc_lbl(zoo_get_context(zh)));
    zkc_ev("ret", "is_unrecoverable -> %s", zkc_rc(is_unrecoverable(zh)));
    cid = zoo_client_id(zh);
    zkc_ev("ret", "zoo_client_id -> sid=%s passwd_nonzero=%d",
           zkc_sid(cid->client_id), passwd_nonzero(cid));
    call("zoo_create /s-eph", zkcs_create(zh, "/s-eph", "e", 1,
                                         &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL,
                                         NULL, 0));

    /* OR-03: CONNECTING, then EXPIRED. */
    zkc_expire(zh, zkc_host(0));
    zkc_await("session:CONNECTING", 1, 15000);
    zkc_ev("ret", "zoo_state -> %s", zkc_state(zoo_state(zh)));
    zkc_ev("ret", "is_unrecoverable -> %s", zkc_rc(is_unrecoverable(zh)));
    cid2 = zoo_client_id(zh);
    zkc_ev("ret", "zoo_client_id same pointer=%d sid=%s", cid2 == cid,
           zkc_sid(cid2->client_id));

    /* RC-01 and the validation order on an expired handle. */
    call("zoo_aget /s-eph", zoo_aget(zh, "/s-eph", 0, zkc_data_cb, "x"));
    call("zoo_aget bad path", zoo_aget(zh, "bad", 0, zkc_data_cb, "x"));
    call("zoo_aget empty path", zoo_aget(zh, "", 0, zkc_data_cb, "x"));
    call("zoo_acreate bad ttl", zoo_acreate_ttl(zh, "/t", "v", 1,
                                                &ZOO_OPEN_ACL_UNSAFE, 0, 5,
                                                zkc_string_cb, "x"));
    call("zoo_get", zkcs_get(zh, "/s-eph", 0, buf, &len, &st));
    call("zoo_set", zkcs_set(zh, "/s-eph", "v", 1, -1));
    call("zoo_exists", zkcs_exists(zh, "/s-eph", 0, NULL));
    call("zoo_add_auth", zoo_add_auth(zh, "digest", "u:p", 3, NULL, NULL));
    call("zoo_add_auth NULL scheme",
         zoo_add_auth(zh, NULL, "u:p", 3, NULL, NULL));
    call("zoo_set_servers", zoo_set_servers(zh, zkc_host(0)));
    call("zoo_set_servers NULL", zoo_set_servers(zh, NULL));
    zkc_ev("check", "callbacks after expiry: %d", zkc_await_none("cb", 300));

    /* The ephemeral node went away with the session. */
    other = zkc_connect(zkc_host(0), 4000, 0);
    if (other != NULL) {
        call("other zoo_exists /s-eph", zkcs_exists(other, "/s-eph", 0, NULL));
        zkc_close(other);
    }
    zkc_close(zh);
    zkc_sleep_ms(200);
    zkc_ev("check", "threads after close: %d", zkc_threads() - t0);
    zkc_ev("check", "fds after close: %d", zkc_fds() - f0);
    return zkc_finish();
}
