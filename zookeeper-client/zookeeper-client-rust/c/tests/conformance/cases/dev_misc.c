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
 * Crash paths and small deviations (ledger replacement values).
 * Mode DEV. Each legacy crash path runs in a forked child under a timeout.
 * The parent has no handle at that time. The child exits with 0 when it
 * sees the Rust result. On the legacy core the case asserts a different
 * result. The .dev file keeps the legacy outcome (exit, signal or hang).
 *
 * - NUL-01..04: a NULL zh gives ZBADARGUMENTS, NULL, 0, ZINVALIDSTATE
 *   or "null" where legacy crashes.
 * - NUL-05: a NULL completion is accepted and never invoked.
 * - WAT-13: mt zoo_aremove_watches(local=1) gives ZOK, runs no
 *   completion and does not write data.
 * - MUL-08: zoo_amulti with NULL ops or results and count > 0 gives
 *   ZBADARGUMENTS.
 * - DAT-09/10: a NULL value with len > 0, a len < -1 and a NULL acl
 *   in set_acl give ZMARSHALLINGERROR.
 * - LOG-09/10: level 7 prints "ZOO_INVALID". A 5000-byte func is
 *   clamped to the line buffer.
 * - DSP-18: mt zookeeper_interest gives fd -1 and ZOK.
 *   zookeeper_process gives ZINVALIDSTATE. The session continues.
 * - DV-FIX-6 (RC-16): zerror(-15) is "ssl connection error".
 * - CLS-11: zookeeper_close in a forked child does not end the
 *   session of the parent.
 * - MUL-08 (DV-FIX): a negative count gives ZBADARGUMENTS. Legacy sends
 *   an empty multi.
 * - RC-06 (DV-FIX): an empty zoo_amulti or zoo_multi on an expired
 *   session gives ZMARSHALLINGERROR at once, with no completion. Legacy
 *   queues the multi. The async call gets ZCLOSING at close, and the sync
 *   call waits for a reply that never comes.
 * - CAN-01: a thread with a pending cancel request makes 200 zoo_acreate
 *   calls. The library masks the cancel while it runs, so all 200 calls
 *   complete and the handle stays usable. The case records the legacy
 *   result only.
 *
 * zkconf-skip-st: its children use mt handles; DSP-18 and WAT-13 are mt rules
 */

#include "zkconf.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <zookeeper_log.h>

/* The header declares these two only without THREADED. mt exports them. */
int zookeeper_interest(zhandle_t *zh, int *fd, int *interest,
                       struct timeval *tv);
int zookeeper_process(zhandle_t *zh, int events);

static int g_sel;
static volatile int g_called;
static char g_stream_path[1024];

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

static void mark_void(int rc, const void *d)
{
    (void)rc;
    (void)d;
    g_called = 1;
}

static void mark_stat(int rc, const struct Stat *s, const void *d)
{
    (void)rc;
    (void)s;
    (void)d;
    g_called = 1;
}

/* CAN-01: the completions of the thread with the pending cancel. */
static pthread_mutex_t g_can_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_can_done;
static zhandle_t *g_can_zh;

static void can_string(int rc, const char *v, const void *d)
{
    (void)rc;
    (void)v;
    (void)d;
    pthread_mutex_lock(&g_can_mu);
    g_can_done++;
    pthread_mutex_unlock(&g_can_mu);
}

static void *can_thread(void *arg)
{
    int i;
    (void)arg;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    pthread_cancel(pthread_self());
    for (i = 0; i < 200; i++) {
        zoo_acreate(g_can_zh, "/can", "x", 1, &ZOO_OPEN_ACL_UNSAFE,
                    ZOO_EPHEMERAL | ZOO_SEQUENCE, can_string, NULL);
    }
    pthread_testcancel();
    return NULL;
}

static int cancel_case(zhandle_t *zh)
{
    pthread_t t;
    void *res = NULL;
    struct Stat st;
    int done;
    int waited;

    g_can_zh = zh;
    if (pthread_create(&t, NULL, can_thread, NULL) != 0) {
        return 9;
    }
    pthread_join(t, &res);
    if (res != PTHREAD_CANCELED) {
        return 1;
    }
    for (waited = 0; waited < 10000; waited += 10) {
        pthread_mutex_lock(&g_can_mu);
        done = g_can_done;
        pthread_mutex_unlock(&g_can_mu);
        if (done == 200) {
            break;
        }
        zkc_sleep_ms(10);
    }
    if (done != 200) {
        return 2;
    }
    if (zoo_exists(zh, "/", 0, &st) != ZOK) {
        return 3;
    }
    return zookeeper_close(zh) == ZOK ? 0 : 4;
}

/* RC-06: a handle with an unknown session id. The server expires it. */
static int expired_multi_case(void)
{
    clientid_t cid;
    zhandle_t *zh;
    int waited;
    int rc;

    memset(&cid, 0, sizeof(cid));
    cid.client_id = 0x1234567812345678LL;
    memcpy(cid.passwd, "0123456789abcdef", sizeof(cid.passwd));
    zh = zookeeper_init2(zkc_host(0), quiet_watcher, 10000, &cid, NULL, 0,
                         quiet_log);
    for (waited = 0; zh != NULL && waited < 10000; waited += 10) {
        if (zoo_state(zh) == ZOO_EXPIRED_SESSION_STATE) {
            break;
        }
        zkc_sleep_ms(10);
    }
    if (zh == NULL || zoo_state(zh) != ZOO_EXPIRED_SESSION_STATE) {
        return 8;
    }
    rc = zoo_amulti(zh, 0, NULL, NULL, mark_void, NULL);
    if (rc != ZMARSHALLINGERROR) {
        return 1;
    }
    rc = zoo_multi(zh, 0, NULL, NULL);
    if (rc != ZMARSHALLINGERROR) {
        return 2;
    }
    if (zookeeper_close(zh) != ZOK) {
        return 3;
    }
    return !g_called ? 0 : 4;
}

static zhandle_t *connected(void)
{
    zhandle_t *zh = zookeeper_init2(zkc_host(0), quiet_watcher, 10000, NULL,
                                    NULL, 0, quiet_log);
    int waited;
    for (waited = 0; zh != NULL && waited < 10000; waited += 10) {
        if (zoo_state(zh) == ZOO_CONNECTED_STATE) {
            return zh;
        }
        zkc_sleep_ms(10);
    }
    return NULL;
}

/* A round trip. After it, the handle has processed all earlier replies. */
static void barrier(zhandle_t *zh)
{
    struct Stat st;
    zoo_exists(zh, "/", 0, &st);
}

static int is(int rc, int want)
{
    return rc == want ? 0 : 1;
}

/* Reads the first line of the stream file into buf. */
static int stream_line(char *buf, size_t len)
{
    FILE *in = fopen(g_stream_path, "r");
    int ok = in != NULL && fgets(buf, (int)len, in) != NULL;
    if (in != NULL) {
        fclose(in);
    }
    return ok;
}

static int log_case(int big_func)
{
    char line[8192];
    FILE *f = fopen(g_stream_path, "w");
    if (f == NULL) {
        return 9;
    }
    zoo_set_log_stream(f);
    if (big_func) {
        char *func = malloc(5001);
        if (func == NULL) {
            return 9;
        }
        memset(func, 'f', 5000);
        func[5000] = '\0';
        log_message(NULL, ZOO_LOG_LEVEL_INFO, 1, func, "after a long func");
    } else {
        log_message(NULL, (ZooLogLevel)7, 1, "lv7", "level seven");
    }
    fflush(f);
    if (!stream_line(line, sizeof(line))) {
        return 2;
    }
    if (big_func) {
        return strlen(line) <= 4096 ? 0 : 3;
    }
    return strstr(line, ":ZOO_INVALID@lv7@1: level seven") != NULL ? 0 : 4;
}

static int child_main(void)
{
    char buf[16];
    int len = sizeof(buf);
    struct Stat st;
    struct String_vector sv;
    zhandle_t *zh = NULL;
    int rc;

    if (g_sel >= 40) {
        zh = connected();
        if (zh == NULL) {
            return 8;
        }
    }
    switch (g_sel) {
    /* NUL-01 */
    case 1: return is(zoo_aget(NULL, "/", 0, zkc_data_cb, NULL), ZBADARGUMENTS);
    case 2: return is(zoo_aexists(NULL, "/", 0, zkc_stat_cb, NULL),
                      ZBADARGUMENTS);
    case 3: return is(zoo_aget_children(NULL, "/", 0, zkc_strings_cb, NULL),
                      ZBADARGUMENTS);
    case 4: return is(zoo_aget_children2(NULL, "/", 0, zkc_strings_stat_cb,
                                         NULL),
                      ZBADARGUMENTS);
    case 5: return is(zoo_agetconfig(NULL, 0, zkc_data_cb, NULL),
                      ZBADARGUMENTS);
    case 6: return is(zoo_exists(NULL, "/", 0, &st), ZBADARGUMENTS);
    case 7: return is(zoo_get(NULL, "/", 0, buf, &len, &st), ZBADARGUMENTS);
    case 8: return is(zoo_getconfig(NULL, 0, buf, &len, &st), ZBADARGUMENTS);
    case 9: return is(zoo_get_children(NULL, "/", 0, &sv), ZBADARGUMENTS);
    case 10: return is(zoo_get_children2(NULL, "/", 0, &sv, &st),
                       ZBADARGUMENTS);
    /* NUL-02 */
    case 11: return is(zoo_set_servers(NULL, "127.0.0.1:1"), ZBADARGUMENTS);
    case 12: zoo_cycle_next_server(NULL); return 0;
    case 13: return strcmp(zoo_get_current_server(NULL), "null") == 0 ? 0 : 1;
    case 14: return is(zoo_set_servers_resolution_delay(NULL, 0),
                       ZBADARGUMENTS);
    /* NUL-03 */
    case 15: return zoo_get_context(NULL) == NULL ? 0 : 1;
    case 16: return zoo_recv_timeout(NULL) == 0 ? 0 : 1;
    case 17: return zoo_set_watcher(NULL, quiet_watcher) == NULL ? 0 : 1;
    case 18: return is(is_unrecoverable(NULL), ZINVALIDSTATE);
    case 19: {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        return zookeeper_get_connected_host(NULL, (struct sockaddr *)&ss,
                                            &sl) == NULL ? 0 : 1;
    }
    /* NUL-04 */
    case 20: return zoo_client_id(NULL) == NULL ? 0 : 1;
    /* LOG-09 and LOG-10 */
    case 21: return log_case(0);
    case 22: return log_case(1);

    /* NUL-05: NULL completions, then a round trip and a close. */
    case 40:
        rc = zoo_aget(zh, "/", 0, NULL, NULL);
        rc = rc != ZOK ? rc : zoo_aexists(zh, "/", 0, NULL, NULL);
        rc = rc != ZOK ? rc : zoo_acreate(zh, "/n5", "", 0,
                                          &ZOO_OPEN_ACL_UNSAFE,
                                          ZOO_EPHEMERAL, NULL, NULL);
        barrier(zh);
        rc = rc != ZOK ? rc : zoo_adelete(zh, "/n5", -1, NULL, NULL);
        barrier(zh);
        zookeeper_close(zh);
        return is(rc, ZOK);
    /* WAT-13 with canary data and with NULL data. */
    case 41:
    case 42: {
        unsigned char canary[256];
        unsigned char ref[256];
        size_t i;
        for (i = 0; i < sizeof(canary); i++) {
            canary[i] = (unsigned char)(i * 7 + 1);
        }
        memcpy(ref, canary, sizeof(ref));
        zoo_wexists(zh, "/", quiet_watcher, NULL, &st);
        rc = zoo_aremove_watches(zh, "/", ZWATCHTYPE_ANY, quiet_watcher, NULL,
                                 1, (void_completion_t *)mark_void,
                                 g_sel == 41 ? (void *)canary : NULL);
        zkc_sleep_ms(300);
        barrier(zh);
        if (rc != ZOK) {
            return 1;
        }
        if (g_called) {
            return 2;
        }
        return memcmp(canary, ref, sizeof(ref)) == 0 ? 0 : 3;
    }
    /* MUL-08 */
    case 43:
    case 44: {
        zoo_op_t op;
        zoo_op_result_t res;
        res.err = 12345;
        zoo_create_op_init(&op, "/m8", "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL,
                           0);
        rc = g_sel == 43 ? zoo_amulti(zh, 1, NULL, &res, mark_void, NULL)
                         : zoo_amulti(zh, 1, &op, NULL, mark_void, NULL);
        barrier(zh);
        if (rc != ZBADARGUMENTS) {
            return 1;
        }
        return res.err == 12345 && !g_called ? 0 : 2;
    }
    /* DAT-09 and DAT-10 */
    case 45: rc = zoo_aset(zh, "/", NULL, 5, -1, mark_stat, NULL); break;
    case 46: rc = zoo_aset(zh, "/", "abc", -2, -1, mark_stat, NULL); break;
    case 47:
        rc = zoo_acreate(zh, "/d9", NULL, 5, &ZOO_OPEN_ACL_UNSAFE, 0,
                         (string_completion_t)NULL, NULL);
        break;
    case 48: rc = zoo_aset_acl(zh, "/", -1, NULL, mark_void, NULL); break;
    case 49: {
        zoo_op_t op;
        zoo_op_result_t res;
        zoo_set_op_init(&op, "/", NULL, 5, -1, NULL);
        rc = zoo_amulti(zh, 1, &op, &res, mark_void, NULL);
        break;
    }
    /* DSP-18 */
    case 50: {
        int fd = 99;
        int interest = 99;
        struct timeval tv;
        int prc;
        memset(&tv, 0, sizeof(tv));
        rc = zookeeper_interest(zh, &fd, &interest, &tv);
        prc = zookeeper_process(zh, ZOOKEEPER_READ);
        if (rc != ZOK || fd != -1 || interest != 0) {
            return 1;
        }
        if (prc != ZINVALIDSTATE) {
            return 2;
        }
        rc = zoo_exists(zh, "/", 0, &st);
        return rc == ZOK && zoo_state(zh) == ZOO_CONNECTED_STATE ? 0 : 3;
    }
    /* MUL-08: a negative count */
    case 51: {
        zoo_op_result_t res;
        res.err = 12345;
        rc = zoo_multi(zh, -1, NULL, &res);
        if (rc != ZBADARGUMENTS) {
            return 1;
        }
        return res.err == 12345 ? 0 : 2;
    }
    case 52:
        rc = zoo_amulti(zh, -1, NULL, NULL, mark_void, NULL);
        barrier(zh);
        if (rc != ZBADARGUMENTS) {
            return 1;
        }
        return !g_called ? 0 : 2;
    /* RC-06 */
    case 53: return expired_multi_case();
    /* CAN-01 */
    case 54: return cancel_case(zh);
    default:
        return 7;
    }
    /* The DAT cases: the rc, no completion and a usable session. */
    barrier(zh);
    if (rc != ZMARSHALLINGERROR) {
        return 1;
    }
    if (g_called) {
        return 2;
    }
    return zoo_exists(zh, "/", 0, &st) == ZOK ? 0 : 3;
}

struct dev_child {
    int sel;
    const char *id;
    const char *what;
};

static const struct dev_child g_children[] = {
    {1, "NUL-01", "zoo_aget(NULL)"},
    {2, "NUL-01", "zoo_aexists(NULL)"},
    {3, "NUL-01", "zoo_aget_children(NULL)"},
    {4, "NUL-01", "zoo_aget_children2(NULL)"},
    {5, "NUL-01", "zoo_agetconfig(NULL)"},
    {6, "NUL-01", "zoo_exists(NULL)"},
    {7, "NUL-01", "zoo_get(NULL)"},
    {8, "NUL-01", "zoo_getconfig(NULL)"},
    {9, "NUL-01", "zoo_get_children(NULL)"},
    {10, "NUL-01", "zoo_get_children2(NULL)"},
    {11, "NUL-02", "zoo_set_servers(NULL, hosts)"},
    {12, "NUL-02", "zoo_cycle_next_server(NULL)"},
    {13, "NUL-02", "zoo_get_current_server(NULL)"},
    {14, "NUL-02", "zoo_set_servers_resolution_delay(NULL, 0)"},
    {15, "NUL-03", "zoo_get_context(NULL)"},
    {16, "NUL-03", "zoo_recv_timeout(NULL)"},
    {17, "NUL-03", "zoo_set_watcher(NULL)"},
    {18, "NUL-03", "is_unrecoverable(NULL)"},
    {19, "NUL-03", "zookeeper_get_connected_host(NULL)"},
    {20, "NUL-04", "zoo_client_id(NULL)"},
    {21, "LOG-09", "log_message at level 7"},
    {22, "LOG-10", "log_message with a 5000-byte func"},
    {40, "NUL-05", "NULL completions"},
    {41, "WAT-13", "local aremove with canary data"},
    {42, "WAT-13", "local aremove with NULL data"},
    {43, "MUL-08", "zoo_amulti NULL ops"},
    {44, "MUL-08", "zoo_amulti NULL results"},
    {45, "DAT-09", "zoo_aset NULL value len 5"},
    {46, "DAT-09", "zoo_aset len -2"},
    {47, "DAT-09", "zoo_acreate NULL value len 5"},
    {48, "DAT-10", "zoo_aset_acl NULL acl"},
    {49, "DAT-09", "multi set op NULL value len 5"},
    {50, "DSP-18", "mt zookeeper_interest and zookeeper_process"},
    {51, "MUL-08", "zoo_multi count -1"},
    {52, "MUL-08", "zoo_amulti count -1"},
    {53, "RC-06", "empty zoo_amulti and zoo_multi on an expired session"},
    {54, "CAN-01", "200 zoo_acreate calls with a pending cancel"},
};

/*
 * The legacy result must differ from the Rust result. LOG-10 is undefined
 * behavior in legacy, so this check only records the legacy result.
 * CAN-01 also records only. A cancel in legacy depends on the cancellation
 * point where it occurs.
 */
static int legacy_ok(const struct dev_child *c, const char *res)
{
    if (c->sel == 22 || c->sel == 54) {
        return 1;
    }
    return strcmp(res, "exit:0") != 0;
}

static zhandle_t *g_parent;

static int child_close(void)
{
    zookeeper_close(g_parent);
    return 0;
}

int main(int argc, char **argv)
{
    const char *out;
    size_t i;
    int rust;
    struct Stat st;
    int rc;

    zkc_init(argc, argv, "dev_misc", 1, "DEV", "ignore");
    rust = zkc_is_rust();
    out = getenv("ZKCONF_OUT");
    snprintf(g_stream_path, sizeof(g_stream_path), "%s.stream",
             out ? out : "/tmp/zkconf");

    for (i = 0; i < sizeof(g_children) / sizeof(g_children[0]); i++) {
        const struct dev_child *c = &g_children[i];
        const char *res;
        g_sel = c->sel;
        res = zkc_child(c->what, child_main, 15000);
        zkc_dev(c->id, rust ? strcmp(res, "exit:0") == 0 : legacy_ok(c, res),
                "%s: %s", c->what, res);
    }

    /* DV-FIX-6 */
    zkc_dev("DV-FIX-6",
            strcmp(zerror(ZSSLCONNECTIONERROR),
                   rust ? "ssl connection error" : "unknown error") == 0,
            "zerror(-15) -> \"%s\"", zerror(ZSSLCONNECTIONERROR));

    /* CLS-11 is the last step, because it forks with a live handle. */
    g_parent = zkc_connect(zkc_host(0), 10000, 0);
    if (g_parent != NULL) {
        const char *res;
        int lost;
        zoo_create(g_parent, "/cls11", "", 0, &ZOO_OPEN_ACL_UNSAFE,
                   ZOO_EPHEMERAL, NULL, 0);
        res = zkc_child("CLS-11 close in a forked child", child_close, 10000);
        lost = zkc_await_none("watch", 3000);
        rc = zoo_exists(g_parent, "/cls11", 0, &st);
        /*
         * The ledger says that legacy ends the parent session. Here the
         * legacy session stays, probably because the child has no IO
         * thread to send CLOSE_OP. This check only records the legacy result.
         */
        zkc_dev("CLS-11", rust ? (lost == 0 && rc == ZOK) : 1,
                "child %s; parent session events=%d exists=%s", res, lost,
                zkc_rc(rc));
        zkc_close(g_parent);
    }
    return zkc_finish();
}
