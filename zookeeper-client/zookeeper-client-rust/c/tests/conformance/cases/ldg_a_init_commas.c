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
 * A host string of commas only (INIT-06, class RE; ER-04).
 * Mode EXACT.
 *
 * Rules:
 * - zookeeper_init with "," or ",," gives NULL on both cores. The trace
 *   records the result and not errno.
 * - Legacy leaves errno stale. The drop-in defines it as EINVAL.
 *   The case checks this only on Rust, and only a failure writes to the
 *   trace. Thus the traces stay equal.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"

#include <errno.h>

static void quiet_watcher(zhandle_t *zh, int type, int state,
                          const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static void one(const char *hosts)
{
    zhandle_t *zh;
    int err;

    errno = 12345;
    zh = zookeeper_init(hosts, quiet_watcher, 10000, NULL, NULL, 0);
    err = errno;
    zkc_ev("call", "zookeeper_init \"%s\" -> %s", hosts, zh ? "zh" : "NULL");
    if (zh != NULL) {
        zookeeper_close(zh);
    } else if (zkc_is_rust() && err != EINVAL) {
        zkc_fail("INIT-06: \"%s\": errno %d, not EINVAL", hosts, err);
    }
}

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "ldg_a_init_commas", 0, "EXACT", "ignore");
    one(",");
    one(",,");
    return zkc_finish();
}
