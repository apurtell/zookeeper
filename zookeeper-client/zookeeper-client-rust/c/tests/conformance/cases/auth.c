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
 * Authentication (OR-04, RC-06, TH-03; spec "Request validation
 * and submission ordering", zoo_add_auth). Mode PER-ROLE: the auth
 * completion runs on the IO thread (L2), the session events on L1.
 *
 * Rules:
 * - RC-06: a NULL scheme gives ZBADARGUMENTS.
 * - A digest credential gives a ZOK auth completion and the digest ACL
 *   identity; a handle without it gets ZNOAUTH.
 * - OR-04: an unknown scheme gives the ZAUTHFAILED auth completion and
 *   the AUTH_FAILED session event; the state is then AUTH_FAILED, and
 *   later calls give ZINVALIDSTATE.
 *
 * In st, the auth completion and the session events run on the app
 * thread inside zookeeper_process. The zkcs helpers replace the sync
 * calls.
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

static void show_acl(zhandle_t *zh, const char *path)
{
    struct ACL_vector acl;
    struct Stat st;
    int rc;
    memset(&acl, 0, sizeof(acl));
    rc = zkcs_get_acl(zh, path, &acl, &st);
    zkc_ev("ret", "zoo_get_acl %s -> %s count=%d perms=%d scheme=%s", path,
           zkc_rc(rc), acl.count, acl.count > 0 ? acl.data[0].perms : -1,
           acl.count > 0 ? acl.data[0].id.scheme : "-");
    deallocate_ACL_vector(&acl);
}

int main(int argc, char **argv)
{
    zhandle_t *zh;
    zhandle_t *other;
    zhandle_t *bad;
    char buf[32];
    int len;

    zkc_init(argc, argv, "auth", 1, "PER-ROLE", "ordered");
    zh = zkc_connect(zkc_host(0), 10000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    call("zoo_add_auth NULL scheme",
         zoo_add_auth(zh, NULL, "u:p", 3, zkc_void_cb, "auth-null"));
    call("zoo_add_auth digest", zoo_add_auth(zh, "digest", "user:pass", 9,
                                             zkc_void_cb, "auth-ok"));
    zkc_await("cb", 1, 10000);
    call("zoo_add_auth digest NULL completion",
         zoo_add_auth(zh, "digest", "user2:pass2", 11, NULL, NULL));
    call("zoo_create /au CREATOR_ALL",
         zkcs_create(zh, "/au", "secret", 6, &ZOO_CREATOR_ALL_ACL, 0, NULL, 0));
    show_acl(zh, "/au");
    len = sizeof(buf);
    call("zoo_get /au", zkcs_get(zh, "/au", 0, buf, &len, NULL));

    other = zkc_connect(zkc_host(0), 10000, 0);
    if (other != NULL) {
        len = sizeof(buf);
        call("other zoo_get /au", zkcs_get(other, "/au", 0, buf, &len, NULL));
        call("other zoo_add_auth wrong", zoo_add_auth(other, "digest",
                                                      "user:wrong", 10,
                                                      zkc_void_cb, "auth-wrong"));
        zkc_await("cb", 1, 10000);
        len = sizeof(buf);
        call("other zoo_get /au", zkcs_get(other, "/au", 0, buf, &len, NULL));
        call("other zoo_add_auth right", zoo_add_auth(other, "digest",
                                                      "user:pass", 9,
                                                      zkc_void_cb, "auth-right"));
        zkc_await("cb", 1, 10000);
        len = sizeof(buf);
        call("other zoo_get /au", zkcs_get(other, "/au", 0, buf, &len, NULL));
        zkc_close(other);
    }
    call("zoo_delete /au", zkcs_delete(zh, "/au", -1));
    zkc_close(zh);

    /* OR-04: an unknown scheme fails the session. */
    bad = zookeeper_init2(zkc_host(0), zkc_watcher, 10000, NULL, "bad", 0,
                          zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 bad -> %s", bad ? "zh" : "NULL");
    if (bad != NULL) {
        zkc_poll_add(bad);
        zkc_await("session:CONNECTED@bad", 1, 15000);
        call("zoo_add_auth bogus", zoo_add_auth(bad, "bogus", "x", 1,
                                                zkc_void_cb, "auth-bogus"));
        zkc_await("cb", 1, 10000);
        zkc_await("session:AUTH_FAILED@bad", 1, 10000);
        zkc_ev("ret", "zoo_state -> %s", zkc_state(zoo_state(bad)));
        zkc_ev("ret", "is_unrecoverable -> %s", zkc_rc(is_unrecoverable(bad)));
        call("zoo_aexists after auth failure",
             zoo_aexists(bad, "/", 0, zkc_stat_cb, "late"));
        len = sizeof(buf);
        call("zoo_get after auth failure",
             zkcs_get(bad, "/", 0, buf, &len, NULL));
        call("zoo_add_auth after auth failure",
             zoo_add_auth(bad, "digest", "u:p", 3, zkc_void_cb, "late-auth"));
        zkc_ev("check", "callbacks: %d", zkc_await_none("cb", 300));
        zkc_close(bad);
    }
    return zkc_finish();
}
