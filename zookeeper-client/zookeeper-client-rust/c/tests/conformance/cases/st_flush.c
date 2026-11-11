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
 * st flush after a submit (OR-22; zookeeper.c
 * nonblocking_send). Mode EXACT.
 *
 * The handle connects through the test proxy, and the proxy counts the
 * bytes from the client. The case does not drive the handle between a
 * submit and the count, so only the submit can send.
 *
 * Rules:
 * - An async call on a connected handle sends its request before it
 *   returns. No driving call is necessary.
 * - Before the first driving call there is no connection. A submit then
 *   only queues. The request goes out after the connect, and its
 *   completion gets the reply.
 * - A submit that fails its argument check sends nothing.
 *
 * zkconf-flavors: st
 */

#include "zkconf.h"

#include <string.h>

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

/* Waits up to 2 s, without a driving call, for more client bytes. */
static int sent_since(long before)
{
    int i;
    for (i = 0; i < 200; i++) {
        if (zkc_proxy_up_bytes() > before) {
            return 1;
        }
        zkc_sleep_ms(10);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *px;
    zhandle_t *zh;
    long up;

    zkc_init(argc, argv, "st_flush", 1, "EXACT", "ordered");
    px = zkc_proxy_start(zkc_host(0));
    if (px == NULL) {
        return zkc_finish();
    }
    zh = zookeeper_init2(px, zkc_watcher, 10000, NULL, "default", 0,
                         zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 proxy -> %s", zh ? "zh" : "NULL");
    if (zh == NULL) {
        zkc_proxy_stop();
        return zkc_finish();
    }

    /* Before the first driving call. */
    call("zoo_aexists / early", zoo_aexists(zh, "/", 0, zkc_stat_cb, "early"));
    zkc_sleep_ms(200);
    zkc_ev("check", "before the first driving call: accepted=%d up=%ld",
           zkc_proxy_accepted(), zkc_proxy_up_bytes());
    zkc_poll_add(zh);
    zkc_await("session:CONNECTED@default", 1, 15000);
    zkc_await("cb", 1, 10000);

    /* A submit on a connected handle. */
    up = zkc_proxy_up_bytes();
    call("zoo_aexists / flush", zoo_aexists(zh, "/", 0, zkc_stat_cb, "flush"));
    zkc_ev("check", "sent before the next driving call: %d", sent_since(up));
    zkc_await("cb", 1, 10000);

    up = zkc_proxy_up_bytes();
    call("zoo_acreate bad path", zoo_acreate(zh, "bad", "v", 1,
                                             &ZOO_OPEN_ACL_UNSAFE, 0,
                                             zkc_string_cb, "bad"));
    zkc_sleep_ms(200);
    zkc_ev("check", "bytes sent by a rejected submit: %ld",
           zkc_proxy_up_bytes() - up);

    /* Two submits go out in order, before the next driving call. */
    up = zkc_proxy_up_bytes();
    call("zoo_aget / f1", zoo_aget(zh, "/", 0, zkc_data_cb, "f1"));
    call("zoo_aexists / f2", zoo_aexists(zh, "/", 0, zkc_stat_cb, "f2"));
    zkc_ev("check", "sent before the next driving call: %d", sent_since(up));
    zkc_await("cb", 2, 10000);
    zkc_close(zh);
    zkc_proxy_stop();
    return zkc_finish();
}
