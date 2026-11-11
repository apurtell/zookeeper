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
 * Connection loss and reconnect through a server stop and start
 * (OR-01, OR-11, OR-15; spec "Drivers and I/O Architecture"). Mode
 * PER-ROLE. Log mode uniq: the number of refused attempts depends on the
 * restart time.
 *
 * Rules:
 * - OR-01: a lost connection gives the CONNECTING event first. Requests
 *   that wait for a reply fail with ZCONNECTIONLOSS in submission order.
 * - A request made while disconnected fails with ZCONNECTIONLOSS at the
 *   next failed attempt (zookeeper.c handle_error, cleanup_bufs).
 * - The session survives a restart within the timeout: CONNECTED again,
 *   the same session id, and the watches come back (SetWatches, OR-15).
 *
 * In st, the zkcs helpers replace the sync calls. The handle sees the
 * loss and tries the server again only while a wait drives it.
 *
 * Ledger rows: ST-03 and ST-06.
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

int main(int argc, char **argv)
{
    zhandle_t *zh;
    struct Stat st;
    char buf[32];
    int len = sizeof(buf);
    int64_t sid;
    int state;

    zkc_init(argc, argv, "connloss", 1, "PER-ROLE", "uniq");
    zh = zkc_connect(zkc_host(0), 20000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    sid = zoo_client_id(zh)->client_id;
    zkc_ev("ret", "session %s", zkc_sid(sid));
    call("zoo_create /cl", zkcs_create(zh, "/cl", "a", 1, &ZOO_OPEN_ACL_UNSAFE,
                                      0, NULL, 0));
    call("zoo_wget /cl", zkcs_wget(zh, "/cl", zkc_watcher, "survivor", buf,
                                  &len, &st));
    call("zoo_wexists /cl/new", zkcs_wexists(zh, "/cl/new", zkc_watcher,
                                            "later", &st));

    /* OR-01: the server goes away. */
    zkc_server("stop", 0);
    zkc_await("session:CONNECTING@default", 1, 15000);
    state = zoo_state(zh);
    zkc_ev("ret", "zoo_state connected=%d", state == ZOO_CONNECTED_STATE);

    /* A request while disconnected fails at the next failed attempt. */
    call("zoo_aget /cl", zoo_aget(zh, "/cl", 0, zkc_data_cb, "while-down"));
    zkc_await("cb", 1, 15000);
    len = sizeof(buf);
    call("zoo_get while down", zkcs_get(zh, "/cl", 0, buf, &len, &st));

    /* The session survives the restart. */
    zkc_server("start", 0);
    zkc_await("session:CONNECTED@default", 1, 20000);
    zkc_ev("ret", "same session=%d", zoo_client_id(zh)->client_id == sid);
    zkc_ev("ret", "zoo_state -> %s", zkc_state(zoo_state(zh)));

    /* OR-15: the watches came back with SetWatches. */
    call("zoo_aset /cl", zoo_aset(zh, "/cl", "b", 1, -1, zkc_stat_cb, "set"));
    zkc_await("watch", 1, 10000);
    zkc_await("cb", 1, 10000);
    call("zoo_acreate /cl/new", zoo_acreate(zh, "/cl/new", "n", 1,
                                            &ZOO_OPEN_ACL_UNSAFE, 0,
                                            zkc_string_cb, "mk"));
    zkc_await("watch", 1, 10000);
    zkc_await("cb", 1, 10000);
    len = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    call("zoo_get /cl", zkcs_get(zh, "/cl", 0, buf, &len, &st));
    zkc_ev("ret", "data=%.*s", len, buf);

    /* OR-01: a request in flight when the server stops. */
    call("zoo_async /cl", zoo_async(zh, "/cl", zkc_string_cb, "sync"));
    zkc_await("cb", 1, 10000);
    zkc_server("stop", 0);
    zkc_await("session:CONNECTING@default", 1, 15000);
    call("zoo_aexists /cl", zoo_aexists(zh, "/cl", 0, zkc_stat_cb, "down2"));
    zkc_await("cb", 1, 15000);
    zkc_server("start", 0);
    zkc_await("session:CONNECTED@default", 1, 20000);
    call("zoo_exists /cl", zkcs_exists(zh, "/cl", 0, &st));
    zkc_close(zh);
    return zkc_finish();
}
