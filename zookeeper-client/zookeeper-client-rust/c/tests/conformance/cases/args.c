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
 * Invalid arguments and the validation order (spec lines 562-575;
 * RC-01, RC-03, RC-10, RC-11, RC-12, ER-01, ER-03, ER-04, DA-06;
 * ledger RC-01, PTH-01..03, NUL-07, LOG-06). Mode PER-ROLE.
 *
 * Rules:
 * - Spec 562-575, ledger RC-01: buffer_len NULL in zoo_wget and
 *   zoo_reconfig first, then TTL, then the handle, then the path, then
 *   the state (ZINVALIDSTATE), then serialization (ZMARSHALLINGERROR).
 * - RC-03: a non-TTL mode needs ttl < 0; a TTL mode needs 0 < ttl <=
 *   0xFFFFFFFFFF (zookeeper.c 4409-4431).
 * - RC-10, PTH-02: isValidPath over "/a" plus each byte, for the modes
 *   0, 2, 3 and 6, with and without a chroot (4064-4106). The handle is
 *   expired, so a valid path gives ZINVALIDSTATE and nothing is sent.
 * - NUL-07: the NULL-safe calls give ZBADARGUMENTS, and zoo_state gives 0.
 * - ER-01: bad host strings give NULL and EINVAL (1417-1446, 875-889).
 * - ER-03: "h1/app,h2" makes "/app,h2" the chroot and h1 the only host.
 * - ER-04: "/foo" gives a handle with an empty list.
 * The relative chroot path of DA-05 is a known failure in dev_chroot.
 * - DA-06, PTH-05: async getconfig under a chroot reads the raw
 *   "/zookeeper/config".
 * - LOG-06: the init line shows the sessionPasswd marker of fixed client
 *   ids (zookeeper.c 1393-1402). The trace keeps the raw marker, because
 *   N11 changes the marker in the log.
 *
 * The st library has no sync API, so the st run skips the sync checks of
 * RC-12 and NUL-07. The zkcs helpers replace the other sync calls.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_sync.h"

#include <errno.h>
#include <string.h>
#include <sys/time.h>

/* The header declares these two only without THREADED. mt exports them. */
int zookeeper_interest(zhandle_t *zh, int *fd, int *interest,
                       struct timeval *tv);
int zookeeper_process(zhandle_t *zh, int events);

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

static char code_of(int rc)
{
    if (rc == ZBADARGUMENTS) return 'B';
    if (rc == ZINVALIDSTATE) return 'I';
    if (rc == ZOK) return 'K';
    return '?';
}

/* RC-10: one line of 64 result codes per quarter of the byte range. */
static void path_matrix(zhandle_t *zh, const char *label)
{
    static const int modes[4] = {0, 2, 3, 6};
    char path[4];
    char codes[65];
    int m;
    int b;
    for (m = 0; m < 4; m++) {
        int64_t ttl = (modes[m] & 4) ? 100 : -1;
        for (b = 0; b < 256; b++) {
            int rc;
            path[0] = '/';
            path[1] = 'a';
            path[2] = (char)b;
            path[3] = '\0';
            rc = zoo_acreate_ttl(zh, path, "", 0, &ZOO_OPEN_ACL_UNSAFE,
                                 modes[m], ttl, zkc_string_cb, "matrix");
            codes[b % 64] = code_of(rc);
            if (b % 64 == 63) {
                codes[64] = '\0';
                zkc_ev("check", "isValidPath %s mode=%d bytes %02x-%02x: %s",
                       label, modes[m], b - 63, b, codes);
            }
        }
    }
    /*
     * The special components and the trailing slash. Under a chroot the
     * paths "/", "", "a" and "x" are DEV tests in dev_chroot (DV-FIX-7).
     */
    {
        int chroot = strcmp(label, "chroot") == 0;
        size_t first = chroot ? 1 : 0;
        size_t last = chroot ? 13 : 16;
        static const char *const extra[] = {"/", "//", "/a/", "/a//b", "/.",
                                            "/..", "/a/.", "/a/..", "/a/./b",
                                            "/a/../b", "/.a", "/a.", "/..a",
                                            "", "a", "x"};
        size_t i;
        for (m = 0; m < 4; m++) {
            int64_t ttl = (modes[m] & 4) ? 100 : -1;
            char line[64];
            for (i = first; i < last; i++) {
                line[i - first] = code_of(zoo_acreate_ttl(
                    zh, extra[i], "", 0, &ZOO_OPEN_ACL_UNSAFE, modes[m], ttl,
                    zkc_string_cb, "matrix"));
            }
            line[i - first] = '\0';
            zkc_ev("check", "isValidPath %s mode=%d specials: %s", label,
                   modes[m], line);
        }
    }
}

static void null_handle(void)
{
    char buf[16];
    int len = sizeof(buf);
    int fd = 0;
    int interest = 0;
    struct timeval tv;
    struct Stat st;
    call("zoo_awget NULL", zoo_awget(NULL, "/", NULL, NULL, zkc_data_cb, "n"));
    call("zoo_awexists NULL",
         zoo_awexists(NULL, "/", NULL, NULL, zkc_stat_cb, "n"));
    call("zoo_awget_children NULL",
         zoo_awget_children(NULL, "/", NULL, NULL, zkc_strings_cb, "n"));
    call("zoo_awget_children2 NULL",
         zoo_awget_children2(NULL, "/", NULL, NULL, zkc_strings_stat_cb, "n"));
    call("zoo_acreate NULL", zoo_acreate(NULL, "/n", "", 0,
                                         &ZOO_OPEN_ACL_UNSAFE, 0,
                                         zkc_string_cb, "n"));
    call("zoo_acreate_ttl NULL bad ttl",
         zoo_acreate_ttl(NULL, "bad", "", 0, &ZOO_OPEN_ACL_UNSAFE, 5, 0,
                         zkc_string_cb, "n"));
    call("zoo_adelete NULL", zoo_adelete(NULL, "/n", -1, zkc_void_cb, "n"));
    call("zoo_aset NULL", zoo_aset(NULL, "/n", "v", 1, -1, zkc_stat_cb, "n"));
    call("zoo_async NULL", zoo_async(NULL, "/", zkc_string_cb, "n"));
    call("zoo_aget_acl NULL", zoo_aget_acl(NULL, "/", zkc_acl_cb, "n"));
    call("zoo_aset_acl NULL", zoo_aset_acl(NULL, "/", -1, &ZOO_OPEN_ACL_UNSAFE,
                                           zkc_void_cb, "n"));
    call("zoo_awgetconfig NULL",
         zoo_awgetconfig(NULL, NULL, NULL, zkc_data_cb, "n"));
#ifdef THREADED
    call("zoo_create NULL", zoo_create(NULL, "/n", "", 0, &ZOO_OPEN_ACL_UNSAFE,
                                       0, NULL, 0));
    call("zoo_delete NULL", zoo_delete(NULL, "/n", -1));
    call("zoo_set NULL", zoo_set(NULL, "/n", "v", 1, -1));
    call("zoo_wget NULL", zoo_wget(NULL, "/", NULL, NULL, buf, &len, &st));
    call("zoo_wget NULL bad path NULL len",
         zoo_wget(NULL, "bad", NULL, NULL, buf, NULL, &st));
#else
    (void)buf;
    (void)len;
    (void)st;
#endif
    call("zoo_add_auth NULL", zoo_add_auth(NULL, "digest", "u:p", 3, NULL,
                                           NULL));
    call("zookeeper_interest NULL",
         zookeeper_interest(NULL, &fd, &interest, &tv));
    call("zookeeper_process NULL", zookeeper_process(NULL, 0));
    zkc_ev("ret", "zoo_state NULL -> %d", zoo_state(NULL));
}

static void init_errors(void)
{
    char h[160];
    zhandle_t *zh;
    size_t i;
    static const char *const bad[] = {"", " ", "  ", "127.0.0.1",
                                      "127.0.0.1:", "127.0.0.1:0",
                                      "127.0.0.1:12x"};
    errno = 0;
    zh = zookeeper_init(NULL, zkc_watcher, 10000, NULL, "init", 0);
    zkc_ev("call", "zookeeper_init NULL -> %s errno=%s", zh ? "zh" : "NULL",
           errno == EINVAL ? "EINVAL" : "other");
    if (zh != NULL) {
        zookeeper_close(zh);
    }
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        errno = 0;
        zh = zookeeper_init(bad[i], zkc_watcher, 10000, NULL, "init", 0);
        zkc_ev("call", "zookeeper_init \"%s\" -> %s errno=%s", bad[i],
               zh ? "zh" : "NULL", errno == EINVAL ? "EINVAL" : "other");
        if (zh != NULL) {
            zookeeper_close(zh);
        }
    }
    snprintf(h, sizeof(h), "%s/a/", zkc_host(0));
    errno = 0;
    zh = zookeeper_init(h, zkc_watcher, 10000, NULL, "init", 0);
    zkc_ev("call", "zookeeper_init %s -> %s errno=%s", h, zh ? "zh" : "NULL",
           errno == EINVAL ? "EINVAL" : "other");
    if (zh != NULL) {
        zookeeper_close(zh);
    }
    /* ER-04: a chroot alone gives a handle with no servers. */
    zh = zookeeper_init("/foo", zkc_watcher, 10000, NULL, "init", 0);
    zkc_ev("call", "zookeeper_init \"/foo\" -> %s", zh ? "zh" : "NULL");
    if (zh != NULL) {
        zkc_ev("ret", "zoo_get_current_server -> %s",
               zoo_get_current_server(zh));
        call("zookeeper_close /foo", zookeeper_close(zh));
    }
    zh = zookeeper_init(",,", zkc_watcher, 10000, NULL, "init", 0);
    zkc_ev("call", "zookeeper_init \",,\" -> %s", zh ? "zh" : "NULL");
    if (zh != NULL) {
        zookeeper_close(zh);
    }
}

/* The marker of the last init line, as the library prints it. */
static char g_marker[32];
static int g_marker_lines;

/*
 * Records the raw sessionPasswd marker of the init line. Then it logs the
 * line through the usual callback.
 */
static void marker_log(const char *msg)
{
    const char *p = msg == NULL ? NULL : strstr(msg, "Initiating client");
    const char *m = p == NULL ? NULL : strstr(p, " sessionPasswd=");
    size_t n = 0;
    if (m != NULL) {
        m += strlen(" sessionPasswd=");
        while (m[n] != '\0' && m[n] != ' ' && n + 1 < sizeof(g_marker)) {
            n++;
        }
        memcpy(g_marker, m, n);
        g_marker[n] = '\0';
        g_marker_lines++;
    }
    zkc_log_cb(msg);
}

/*
 * LOG-06: the init line shows "<null>" for a NULL clientid or a zero
 * passwd[0], else "<hidden>". The line comes before the host check, so
 * a NULL host gives the line without a connection. The trace records the
 * raw marker, because N11 folds the marker of a nonzero session id in
 * the log.
 */
static void init_markers(void)
{
    static const struct {
        const char *label;
        int64_t id;
        unsigned char pw0;
        unsigned char rest;
    } in[] = {
        {"cid NULL", 0, 0, 0},
        {"id=0 passwd[0]!=0", 0, 'x', 0},
        {"id!=0 passwd[0]=0", 0x1234567812345678LL, 0, 'y'},
        {"id!=0 passwd[0]!=0", 0x1234567812345678LL, 'x', 0},
    };
    clientid_t cid;
    zhandle_t *zh;
    size_t i;
    for (i = 0; i < sizeof(in) / sizeof(in[0]); i++) {
        memset(&cid, 0, sizeof(cid));
        cid.client_id = in[i].id;
        memset(cid.passwd, in[i].rest, sizeof(cid.passwd));
        cid.passwd[0] = (char)in[i].pw0;
        g_marker[0] = '\0';
        g_marker_lines = 0;
        zh = zookeeper_init2(NULL, zkc_watcher, 10000, i == 0 ? NULL : &cid,
                             "init", ZOO_NO_LOG_CLIENTENV, marker_log);
        zkc_ev("check", "init marker %s -> sessionPasswd=%s lines=%d",
               in[i].label, g_marker[0] ? g_marker : "none", g_marker_lines);
        if (zh != NULL) {
            zookeeper_close(zh);
        }
    }
}

int main(int argc, char **argv)
{
    zhandle_t *zh;
    zhandle_t *ch;
    char host[160];
#ifdef THREADED
    char buf[64];
    int len;
#endif
    struct Stat st;
    zoo_op_t op;
    zoo_op_result_t res;

    zkc_init(argc, argv, "args", 2, "PER-ROLE", "ordered");
    null_handle();
    init_errors();
    init_markers();

    /* Set up "/ch" for the chroot steps. */
    zh = zkc_connect(zkc_host(0), 4000, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    call("zoo_create /ch", zkcs_create(zh, "/ch", "", 0, &ZOO_OPEN_ACL_UNSAFE,
                                      0, NULL, 0));

    /* The validation order on a connected handle. */
#ifdef THREADED
    len = sizeof(buf);
    call("zoo_wget bad path NULL len",
         zoo_wget(zh, "bad", NULL, NULL, buf, NULL, &st));
    call("zoo_reconfig NULL len",
         zoo_reconfig(zh, NULL, NULL, NULL, -1, buf, NULL, &st));
#endif
    call("zoo_acreate_ttl mode 0 ttl 0",
         zoo_acreate_ttl(zh, "/t", "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, 0,
                         zkc_string_cb, "t"));
    call("zoo_acreate_ttl mode 5 ttl 0",
         zoo_acreate_ttl(zh, "/t", "", 0, &ZOO_OPEN_ACL_UNSAFE, 5, 0,
                         zkc_string_cb, "t"));
    call("zoo_acreate_ttl mode 5 ttl max+1",
         zoo_acreate_ttl(zh, "/t", "", 0, &ZOO_OPEN_ACL_UNSAFE, 5,
                         0x10000000000LL, zkc_string_cb, "t"));
    call("zoo_acreate_ttl mode 6 ttl max",
         zoo_acreate_ttl(zh, "/t", "", 0, &ZOO_OPEN_ACL_UNSAFE, 6,
                         0xFFFFFFFFFFLL, zkc_string_cb, "t-max"));
    zkc_await("cb", 1, 10000);
    call("zoo_aget empty path", zoo_aget(zh, "", 0, zkc_data_cb, "e"));
    call("zoo_aget no slash", zoo_aget(zh, "a", 0, zkc_data_cb, "e"));

    snprintf(host, sizeof(host), "%s/ch", zkc_host(0));
    ch = zkc_connect(host, 4000, 0);
    if (ch != NULL) {
        /* DA-06: async getconfig ignores the chroot. */
        call("chroot zoo_agetconfig",
             zoo_agetconfig(ch, 0, zkc_data_cb, "cfg"));
        zkc_await("cb", 1, 10000);
        /* RC-10 with a chroot on an expired handle. */
        if (zkc_expire(ch, zkc_host(0)) == 0) {
            path_matrix(ch, "chroot");
        }
        zkc_close(ch);
    }

    /* ER-03: the chroot takes the rest of the string. */
    snprintf(host, sizeof(host), "%s/app,%s", zkc_host(0), zkc_host(1));
    ch = zkc_connect(host, 4000, 0);
    if (ch != NULL) {
        zkc_ev("ret", "zoo_get_current_server -> %s",
               zoo_get_current_server(ch));
        call("ER-03 zoo_exists /", zkcs_exists(ch, "/", 0, &st));
        zkc_close(ch);
    }

    /* RC-01 and RC-10 on the expired plain handle. */
    if (zkc_expire(zh, zkc_host(0)) == 0) {
#ifdef THREADED
        len = sizeof(buf);
        call("expired zoo_wget NULL len",
             zoo_wget(zh, "/", NULL, NULL, buf, NULL, &st));
        call("expired zoo_wget", zoo_wget(zh, "/", NULL, NULL, buf, &len, &st));
        call("expired zoo_reconfig NULL len",
             zoo_reconfig(zh, NULL, NULL, NULL, -1, buf, NULL, &st));
#endif
        call("expired zoo_areconfig",
             zoo_areconfig(zh, NULL, NULL, NULL, -1, zkc_data_cb, "r"));
        call("expired zoo_acreate_ttl bad ttl bad path",
             zoo_acreate_ttl(zh, "bad", "", 0, &ZOO_OPEN_ACL_UNSAFE, 5, 0,
                             zkc_string_cb, "x"));
        call("expired zoo_acreate_ttl bad path",
             zoo_acreate_ttl(zh, "bad", "", 0, &ZOO_OPEN_ACL_UNSAFE, 5, 100,
                             zkc_string_cb, "x"));
        call("expired zoo_acreate_ttl",
             zoo_acreate_ttl(zh, "/ok", "", 0, &ZOO_OPEN_ACL_UNSAFE, 5, 100,
                             zkc_string_cb, "x"));
        zoo_create_op_init(&op, "bad", "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
        call("expired zoo_amulti bad sub-path",
             zoo_amulti(zh, 1, &op, &res, zkc_void_cb, "m"));
        call("expired zoo_aget_children",
             zoo_aget_children(zh, "/", 0, zkc_strings_cb, "x"));
        path_matrix(zh, "plain");
        zkc_ev("check", "callbacks after expiry: %d",
               zkc_await_none("cb", 300));
    }
    zkc_close(zh);
    return zkc_finish();
}
