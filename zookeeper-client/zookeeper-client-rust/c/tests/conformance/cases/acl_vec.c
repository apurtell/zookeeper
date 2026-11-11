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
 * ACL vectors of create and set ACL (spec "Request validation and
 * submission ordering"). Mode PER-ROLE: the app waits for each
 * completion before the next call.
 *
 * Rules:
 * - A create with a 20-entry ACL sends all entries in order, and
 *   zoo_aget_acl gives the same 20 entries back.
 * - A set ACL with a 20-entry ACL also round-trips all entries.
 * - A create with a NULL ACL vector sends an empty ACL
 *   (zookeeper.c:4347-4349). The server rejects it with ZINVALIDACL.
 * - A create with a count of 0 also sends an empty ACL, with NULL data
 *   and with non-NULL data.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"

#include <stdio.h>

#define WAIT1() zkc_await("cb", 1, 10000)
#define NACL 20

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

/* Fills 20 distinct entries. Entry 0 lets the test read the node. */
static void fill(struct ACL *a, char ids[NACL][32], int base)
{
    int i;
    a[0].perms = ZOO_PERM_ALL;
    a[0].id.scheme = "world";
    a[0].id.id = "anyone";
    for (i = 1; i < NACL; i++) {
        snprintf(ids[i], sizeof ids[i], "10.%d.0.%d", base, i);
        a[i].perms = 1 + (i % 31);
        a[i].id.scheme = "ip";
        a[i].id.id = ids[i];
    }
}

int main(int argc, char **argv)
{
    zhandle_t *zh;
    struct ACL a[NACL];
    struct ACL b[NACL];
    char ida[NACL][32];
    char idb[NACL][32];
    struct ACL_vector va = {NACL, a};
    struct ACL_vector vb = {NACL, b};
    struct ACL_vector empty_null = {0, NULL};
    struct ACL_vector empty_data = {0, a};

    zkc_init(argc, argv, "acl_vec", 1, "PER-ROLE", "ordered");
    zh = zkc_connect(zkc_host(0), 10000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    fill(a, ida, 1);
    fill(b, idb, 2);

    call("zoo_acreate /av20", zoo_acreate(zh, "/av20", "v", 1, &va, 0,
                                          zkc_string_cb, "create20"));
    WAIT1();
    call("zoo_aget_acl /av20", zoo_aget_acl(zh, "/av20", zkc_acl_cb, "get20"));
    WAIT1();
    call("zoo_aset_acl /av20", zoo_aset_acl(zh, "/av20", -1, &vb, zkc_void_cb,
                                            "set20"));
    WAIT1();
    call("zoo_aget_acl /av20 set", zoo_aget_acl(zh, "/av20", zkc_acl_cb,
                                                "get20-set"));
    WAIT1();

    call("zoo_acreate /avnull", zoo_acreate(zh, "/avnull", "v", 1, NULL, 0,
                                            zkc_string_cb, "create-null"));
    WAIT1();
    call("zoo_acreate /av0", zoo_acreate(zh, "/av0", "v", 1, &empty_null, 0,
                                         zkc_string_cb, "create-0-null"));
    WAIT1();
    call("zoo_acreate /av0d", zoo_acreate(zh, "/av0d", "v", 1, &empty_data, 0,
                                          zkc_string_cb, "create-0-data"));
    WAIT1();
    call("zoo_aexists /avnull", zoo_aexists(zh, "/avnull", 0, zkc_stat_cb,
                                            "ex-null"));
    WAIT1();

    zkc_close(zh);
    return zkc_finish();
}
