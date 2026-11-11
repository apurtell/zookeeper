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
 * Multi deviations of the ledger (MUL-05, MUL-07). Mode DEV.
 *
 * - MUL-07: a container create inside a multi. The server
 *   answers it with a create2 result. Legacy parses the result by the
 *   expected type, so the stream desyncs. Rust parses each result by the
 *   wire type and fills value as for a create. Each multi runs in a forked
 *   child, because legacy crashes there (an assert in deserialize_multi).
 *   The check asserts a correct result on Rust and a crash or a wrong
 *   result on legacy. The .dev file keeps the legacy outcome.
 * - MUL-05: a sync zoo_multi that fails on a teardown or a close. Legacy
 *   returns the rc and leaves results[] untouched. Rust writes the rc into
 *   each results[i].err (spec "Defined Results in Synchronous
 *   Multi-Operations"). The proxy holds the reply, so the multi waits.
 *   Then a reset or a close ends the wait.
 *
 * zkconf-skip-st: the case tests the sync zoo_multi of the mt library
 */

#include "zkconf.h"

#include <pthread.h>
#include <string.h>

#define UNTOUCHED 12345

static void quiet_watcher(zhandle_t *zh, int type, int state,
                          const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static void quiet_log(const char *msg)
{
    (void)msg;
}

/* A child handle on the first server. It does not record. */
static zhandle_t *child_connect(void)
{
    zhandle_t *zh = zookeeper_init2(zkc_host(0), quiet_watcher, 10000, NULL,
                                    NULL, 0, quiet_log);
    int i;
    for (i = 0; zh != NULL && i < 200; i++) {
        if (zoo_state(zh) == ZOO_CONNECTED_STATE) {
            return zh;
        }
        zkc_sleep_ms(50);
    }
    return NULL;
}

/*
 * MUL-07: the multi of the child. Exit 0 means that each create result
 * holds its path and ZOK. Exit 2 means that the result is wrong.
 */
static int g_with_child;

static int child_container(void)
{
    zhandle_t *zh = child_connect();
    zoo_op_t ops[2];
    zoo_op_result_t res[2];
    char buf[2][64];
    int n = g_with_child ? 2 : 1;
    int rc;
    int ok;
    const char *path = g_with_child ? "/ldgb_c2" : "/ldgb_c1";
    char kid[64];
    if (zh == NULL) {
        return 3;
    }
    snprintf(kid, sizeof(kid), "%s/k", path);
    memset(buf, 0, sizeof(buf));
    memset(res, 0, sizeof(res));
    zoo_create_op_init(&ops[0], path, "", 0, &ZOO_OPEN_ACL_UNSAFE,
                       ZOO_CONTAINER, buf[0], sizeof(buf[0]));
    zoo_create_op_init(&ops[1], kid, "k", 1, &ZOO_OPEN_ACL_UNSAFE, 0,
                       buf[1], sizeof(buf[1]));
    rc = zoo_multi(zh, n, ops, res);
    ok = rc == ZOK && res[0].err == ZOK && res[0].value == buf[0] &&
         strcmp(buf[0], path) == 0;
    if (g_with_child) {
        ok = ok && res[1].err == ZOK && strcmp(buf[1], kid) == 0;
    }
    zookeeper_close(zh);
    return ok ? 0 : 2;
}

/* MUL-05: one sync multi on a helper thread. */
struct multi_job {
    zhandle_t *zh;
    zoo_op_t ops[2];
    zoo_op_result_t res[2];
    char buf[64];
    struct Stat st;
    int rc;
};

static void *multi_thread(void *arg)
{
    struct multi_job *j = arg;
    j->rc = zoo_multi(j->zh, 2, j->ops, j->res);
    return NULL;
}

static void job_init(struct multi_job *j, zhandle_t *zh, const char *path)
{
    int i;
    memset(j, 0, sizeof(*j));
    j->zh = zh;
    zoo_create_op_init(&j->ops[0], path, "a", 1, &ZOO_OPEN_ACL_UNSAFE, 0,
                       j->buf, sizeof(j->buf));
    zoo_set_op_init(&j->ops[1], path, "b", 1, -1, &j->st);
    for (i = 0; i < 2; i++) {
        j->res[i].err = UNTOUCHED;
    }
}

/*
 * Starts the multi while the proxy holds the replies. The end function
 * then fails the request. The job keeps the multi rc.
 */
static void held_multi(struct multi_job *j, void (*end)(zhandle_t *zh))
{
    pthread_t th;
    zkc_proxy_hold(1);
    if (pthread_create(&th, NULL, multi_thread, j) != 0) {
        zkc_fail("pthread_create failed");
        zkc_proxy_hold(0);
        return;
    }
    zkc_sleep_ms(500);
    end(j->zh);
    pthread_join(th, NULL);
    zkc_proxy_hold(0);
}

static void end_reset(zhandle_t *zh)
{
    (void)zh;
    zkc_proxy_reset();
}

static void end_close(zhandle_t *zh)
{
    zkc_close(zh);
}

static void check_mul05(const char *what, const struct multi_job *j)
{
    int filled = j->res[0].err == j->rc && j->res[1].err == j->rc;
    int untouched = j->res[0].err == UNTOUCHED && j->res[1].err == UNTOUCHED;
    zkc_dev("MUL-05",
            j->rc != ZOK && (zkc_is_rust() ? filled : untouched),
            "%s: rc=%s results[].err=%d,%d (legacy: untouched; rust: rc)",
            what, zkc_rc(j->rc), j->res[0].err, j->res[1].err);
}

int main(int argc, char **argv)
{
    const char *res;
    const char *px;
    zhandle_t *zh;
    struct multi_job job;
    int rust;

    zkc_init(argc, argv, "ldg_b_multi", 1, "DEV", "ignore");
    rust = zkc_is_rust();

    /* MUL-07 runs first, because a child must fork with no handle. */
    g_with_child = 0;
    res = zkc_child("MUL-07 container create alone", child_container, 20000);
    zkc_dev("MUL-07", (strcmp(res, "exit:0") == 0) == rust,
            "container create alone: %s (legacy: a crash or a wrong result;"
            " rust: exit:0)", res);
    g_with_child = 1;
    res = zkc_child("MUL-07 container create then create", child_container,
                    20000);
    zkc_dev("MUL-07", (strcmp(res, "exit:0") == 0) == rust,
            "container create then create: %s (legacy: a crash or a wrong"
            " result; rust: exit:0)", res);

    px = zkc_proxy_start(zkc_host(0));
    if (px == NULL) {
        return zkc_finish();
    }

    /* MUL-05 on a teardown: the reset loses the connection. */
    zh = zkc_connect(px, 10000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    job_init(&job, zh, "/ldgb_m1");
    held_multi(&job, end_reset);
    check_mul05("teardown", &job);
    zkc_close(zh);

    /* MUL-05 on a close of the handle. */
    zh = zkc_connect(px, 10000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    job_init(&job, zh, "/ldgb_m2");
    held_multi(&job, end_close);
    check_mul05("close", &job);

    zkc_proxy_stop();
    return zkc_finish();
}
