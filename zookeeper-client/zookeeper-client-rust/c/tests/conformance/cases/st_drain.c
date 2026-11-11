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
 * The st drain order (OR-01, CL-02). Mode EXACT.
 *
 * The handle connects through the test proxy. The proxy holds the
 * replies, so the requests stay pending at the loss and at the close.
 *
 * Rules:
 * - Connection loss: the CONNECTING event goes to the path watchers and
 *   then to the default watcher. Then the pending auth gets its result,
 *   and then each pending request gets ZCONNECTIONLOSS in submission
 *   order. All of this runs inside the driving call that sees the loss.
 * - Close: the pending auth gets ZCLOSING first. Then each pending
 *   request gets ZCLOSING in submission order, inside zookeeper_close.
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"

#include <string.h>

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

int main(int argc, char **argv)
{
    const char *px;
    zhandle_t *zh;

    zkc_init(argc, argv, "st_drain", 1, "EXACT", "ordered");
    px = zkc_proxy_start(zkc_host(0));
    if (px == NULL) {
        return zkc_finish();
    }
    zh = zkc_connect(px, 10000, 0);
    if (zh == NULL) {
        zkc_proxy_stop();
        return zkc_finish();
    }
    call("zoo_acreate /sd", zoo_acreate(zh, "/sd", "v", 1, &ZOO_OPEN_ACL_UNSAFE,
                                        0, zkc_string_cb, "create"));
    zkc_await("cb", 1, 10000);
    call("zoo_awexists /sd W1",
         zoo_awexists(zh, "/sd", zkc_watcher, "W1", zkc_stat_cb, "w1"));
    call("zoo_awget /sd W2",
         zoo_awget(zh, "/sd", zkc_watcher, "W2", zkc_data_cb, "w2"));
    zkc_await("cb", 2, 10000);

    /* Connection loss with an auth and two requests pending. */
    zkc_proxy_hold(1);
    call("zoo_aget /sd A", zoo_aget(zh, "/sd", 0, zkc_data_cb, "A"));
    call("zoo_add_auth auth1", zoo_add_auth(zh, "digest", "u1:p1", 5,
                                            zkc_void_cb, "auth1"));
    call("zoo_aexists /sd B", zoo_aexists(zh, "/sd", 0, zkc_stat_cb, "B"));
    zkc_sleep_ms(200);
    zkc_proxy_reset();
    zkc_proxy_hold(0);
    zkc_sleep_ms(200);
    zkc_await("session:CONNECTING@default", 1, 10000);
    zkc_await("cb", 3, 10000);
    zkc_await("session:CONNECTED@default", 1, 15000);
    zkc_ev("check", "callbacks after the reconnect: %d",
           zkc_await_none("cb", 500));

    /* Close with an auth and two requests pending. */
    zkc_proxy_hold(1);
    call("zoo_aget /sd C", zoo_aget(zh, "/sd", 0, zkc_data_cb, "C"));
    call("zoo_add_auth auth2", zoo_add_auth(zh, "digest", "u2:p2", 5,
                                            zkc_void_cb, "auth2"));
    call("zoo_aexists /sd D", zoo_aexists(zh, "/sd", 0, zkc_stat_cb, "D"));
    zkc_sleep_ms(200);
    zkc_close(zh);
    zkc_proxy_hold(0);
    zkc_proxy_stop();
    return zkc_finish();
}
