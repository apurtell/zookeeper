// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * SAS-05 and SAS-14: a test of the Cyrus call order of
 * the SASL glue. The file has two parts.
 *
 * The interposer part wraps sasl_client_new, sasl_client_start,
 * sasl_client_step and sasl_dispose. Each wrapper adds one event to a
 * trace and then calls the library function. A connection gets a new
 * number at each sasl_client_new call. On Mach-O the wrappers are dyld
 * interpose tuples. On ELF they are LD_PRELOAD definitions.
 *
 * The application part (ZK_SASL_INTERPOSE_APP) opens a SASL session,
 * reads the trace and examines these rules:
 *  - A sasl_client_new call occurs only when no connection is live. Thus
 *    the glue disposes the old connection before a reconnect.
 *  - Each connection gets one sasl_dispose call.
 *  - No Cyrus call occurs after zookeeper_close returns.
 *  - Both address images have the "host;port" form.
 *
 * With ZK_SASL_FAIL_NEW=1, the first sasl_client_new call makes a
 * connection and then returns SASL_FAIL. The glue must dispose that
 * connection and must not call sasl_client_start on it.
 *
 * With ZK_SASL_RESTART set, the application runs that command after the
 * first authentication. The command restarts the server. The session
 * then reconnects and authenticates again.
 *
 * Build (macOS; on ELF use -shared -fPIC, LD_PRELOAD and -ldl):
 *   SASL=$(brew --prefix cyrus-sasl)
 *   INC="-Iinclude -Igenerated -I$SASL/include -DTHREADED -DHAVE_CYRUS_SASL_H"
 *   cc -std=c99 -Wall -Wextra -Werror -dynamiclib $INC sasl_interpose.c \
 *      -L$SASL/lib -lsasl2 -o libsasl_interpose.dylib
 *   cc -std=c99 -Wall -Wextra -Werror -DZK_SASL_INTERPOSE_APP $INC \
 *      sasl_interpose.c -L$LIB -lzookeeper_mt -L$SASL/lib -lsasl2 \
 *      -Wl,-rpath,$LIB -o sasl_interpose_app
 * Run (a DIGEST-MD5 server with user_myuser="mypassword"):
 *   DYLD_INSERT_LIBRARIES=./libsasl_interpose.dylib \
 *      ./sasl_interpose_app 127.0.0.1:PORT [ZK_SASL_FAIL_NEW=1]
 *
 * Ledger: SAS-05, SAS-14
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <sasl/sasl.h>

#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

/* The capacity of the trace in events. */
#define ZKSI_CAP 256

/* One trace event: a kind letter, a connection number and a flag. */
typedef struct {
    char kind;
    int id;
    int ok;
} zksi_ev;

/* The application finds these interposer functions through dlsym. */
typedef int (*zksi_copy_fn)(zksi_ev *, int);
typedef void (*zksi_mark_fn)(char);

#ifndef ZK_SASL_INTERPOSE_APP

static pthread_mutex_t zksi_mu = PTHREAD_MUTEX_INITIALIZER;
static zksi_ev zksi_trace[ZKSI_CAP];
static int zksi_n;
static int zksi_next_id;
static int zksi_fail_used;

/* The live connections: a pointer and its number. */
static struct {
    sasl_conn_t *c;
    int id;
} zksi_live[16];

static void zksi_add(char kind, int id, int ok)
{
    if (zksi_n < ZKSI_CAP) {
        zksi_trace[zksi_n].kind = kind;
        zksi_trace[zksi_n].id = id;
        zksi_trace[zksi_n].ok = ok;
        zksi_n++;
    }
}

static int zksi_find(const sasl_conn_t *c)
{
    size_t i;

    for (i = 0; i < sizeof zksi_live / sizeof zksi_live[0]; i++) {
        if (zksi_live[i].c != NULL && zksi_live[i].c == c) {
            return zksi_live[i].id;
        }
    }
    return 0;
}

static int zksi_live_count(void)
{
    size_t i;
    int n = 0;

    for (i = 0; i < sizeof zksi_live / sizeof zksi_live[0]; i++) {
        if (zksi_live[i].c != NULL) {
            n++;
        }
    }
    return n;
}

static void zksi_put(sasl_conn_t *c, int id)
{
    size_t i;

    for (i = 0; i < sizeof zksi_live / sizeof zksi_live[0]; i++) {
        if (zksi_live[i].c == NULL) {
            zksi_live[i].c = c;
            zksi_live[i].id = id;
            return;
        }
    }
}

static int zksi_drop(const sasl_conn_t *c)
{
    size_t i;

    for (i = 0; i < sizeof zksi_live / sizeof zksi_live[0]; i++) {
        if (zksi_live[i].c != NULL && zksi_live[i].c == c) {
            zksi_live[i].c = NULL;
            return zksi_live[i].id;
        }
    }
    return 0;
}

/* Gives a copy of the trace. The application calls it through dlsym. */
__attribute__((visibility("default"))) int zksi_copy(zksi_ev *out, int cap)
{
    int n;

    pthread_mutex_lock(&zksi_mu);
    n = zksi_n < cap ? zksi_n : cap;
    memcpy(out, zksi_trace, (size_t)n * sizeof *out);
    pthread_mutex_unlock(&zksi_mu);
    return n;
}

/* Adds an application event, for example the return of zookeeper_close. */
__attribute__((visibility("default"))) void zksi_mark(char kind)
{
    pthread_mutex_lock(&zksi_mu);
    zksi_add(kind, 0, 1);
    pthread_mutex_unlock(&zksi_mu);
}

/* Is 1 when the address image has the "host;port" form. */
static int zksi_ipport_ok(const char *s)
{
    const char *semi;

    if (s == NULL) {
        return 0;
    }
    semi = strchr(s, ';');
    return semi != NULL && semi != s && semi[1] != '\0' ? 1 : 0;
}

#ifdef __APPLE__
#define ZKSI_WRAP(name) zksi_w_##name
#define ZKSI_INTERPOSE(name)                                                   \
    __attribute__((used, section("__DATA,__interpose"))) static const struct { \
        const void *repl;                                                      \
        const void *orig;                                                      \
    } zksi_i_##name = {(const void *)(unsigned long)&zksi_w_##name,            \
                       (const void *)(unsigned long)&name};
#define ZKSI_STATIC static
#else
#define ZKSI_WRAP(name) name
#define ZKSI_INTERPOSE(name)
#define ZKSI_STATIC
#endif

#ifndef __APPLE__
static void *zksi_next(const char *name)
{
    return dlsym(RTLD_NEXT, name);
}
#endif

typedef int (*zksi_new_fn)(const char *, const char *, const char *, const char *,
                           const sasl_callback_t *, unsigned, sasl_conn_t **);
typedef int (*zksi_start_fn)(sasl_conn_t *, const char *, sasl_interact_t **, const char **,
                             unsigned *, const char **);
typedef int (*zksi_step_fn)(sasl_conn_t *, const char *, unsigned, sasl_interact_t **,
                            const char **, unsigned *);
typedef void (*zksi_dispose_fn)(sasl_conn_t **);

ZKSI_STATIC int ZKSI_WRAP(sasl_client_new)(const char *service, const char *fqdn,
                                           const char *lip, const char *rip,
                                           const sasl_callback_t *cb, unsigned flags,
                                           sasl_conn_t **pconn)
{
    zksi_new_fn real;
    const char *fail = getenv("ZK_SASL_FAIL_NEW");
    int r;
    int id;
    int busy;

#ifdef __APPLE__
    real = &sasl_client_new;
#else
    *(void **)&real = zksi_next("sasl_client_new");
#endif
    r = real(service, fqdn, lip, rip, cb, flags, pconn);
    pthread_mutex_lock(&zksi_mu);
    busy = zksi_live_count();
    id = ++zksi_next_id;
    if (r == SASL_OK && fail != NULL && strcmp(fail, "1") == 0 && zksi_fail_used == 0) {
        zksi_fail_used = 1;
        r = SASL_FAIL;
    }
    if (pconn != NULL && *pconn != NULL) {
        zksi_put(*pconn, id);
    }
    /* 'N' is a call with no live connection; 'B' is a call with one. */
    zksi_add(busy == 0 ? 'N' : 'B', id, r == SASL_OK ? 1 : 0);
    zksi_add('A', id, zksi_ipport_ok(lip) && zksi_ipport_ok(rip));
    pthread_mutex_unlock(&zksi_mu);
    return r;
}
ZKSI_INTERPOSE(sasl_client_new)

ZKSI_STATIC int ZKSI_WRAP(sasl_client_start)(sasl_conn_t *conn, const char *mechlist,
                                             sasl_interact_t **need, const char **out,
                                             unsigned *outlen, const char **mech)
{
    zksi_start_fn real;
    int r;

#ifdef __APPLE__
    real = &sasl_client_start;
#else
    *(void **)&real = zksi_next("sasl_client_start");
#endif
    r = real(conn, mechlist, need, out, outlen, mech);
    pthread_mutex_lock(&zksi_mu);
    zksi_add('S', zksi_find(conn), r == SASL_OK || r == SASL_CONTINUE ? 1 : 0);
    pthread_mutex_unlock(&zksi_mu);
    return r;
}
ZKSI_INTERPOSE(sasl_client_start)

ZKSI_STATIC int ZKSI_WRAP(sasl_client_step)(sasl_conn_t *conn, const char *in, unsigned inlen,
                                            sasl_interact_t **need, const char **out,
                                            unsigned *outlen)
{
    zksi_step_fn real;
    int r;

#ifdef __APPLE__
    real = &sasl_client_step;
#else
    *(void **)&real = zksi_next("sasl_client_step");
#endif
    r = real(conn, in, inlen, need, out, outlen);
    pthread_mutex_lock(&zksi_mu);
    zksi_add('T', zksi_find(conn), r == SASL_OK || r == SASL_CONTINUE ? 1 : 0);
    pthread_mutex_unlock(&zksi_mu);
    return r;
}
ZKSI_INTERPOSE(sasl_client_step)

ZKSI_STATIC void ZKSI_WRAP(sasl_dispose)(sasl_conn_t **pconn)
{
    zksi_dispose_fn real;

#ifdef __APPLE__
    real = &sasl_dispose;
#else
    *(void **)&real = zksi_next("sasl_dispose");
#endif
    pthread_mutex_lock(&zksi_mu);
    /* A dispose of a NULL connection is a no-op; the trace ignores it. */
    if (pconn != NULL && *pconn != NULL) {
        zksi_add('D', zksi_drop(*pconn), 1);
    }
    pthread_mutex_unlock(&zksi_mu);
    real(pconn);
}
ZKSI_INTERPOSE(sasl_dispose)

#else /* ZK_SASL_INTERPOSE_APP */

#include <time.h>
#include <unistd.h>

#include <zookeeper.h>

static zksi_copy_fn zksi_copy_p;
static zksi_mark_fn zksi_mark_p;

static void quiet(zhandle_t *zh, int type, int state, const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static void nap_ms(long ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* Counts the trace events of one kind. */
static int count_kind(const zksi_ev *ev, int n, char kind)
{
    int i;
    int c = 0;

    for (i = 0; i < n; i++) {
        if (ev[i].kind == kind) {
            c++;
        }
    }
    return c;
}

/* Counts the successful 'T' or 'S' events after the last 'N' event. */
static int auth_since_last_new(const zksi_ev *ev, int n)
{
    int i;
    int last = -1;
    int c = 0;

    for (i = 0; i < n; i++) {
        if (ev[i].kind == 'N') {
            last = i;
        }
    }
    for (i = last + 1; last >= 0 && i < n; i++) {
        if ((ev[i].kind == 'S' || ev[i].kind == 'T') && ev[i].ok) {
            c++;
        }
    }
    return c;
}

static void print_trace(const zksi_ev *ev, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        printf("%c%d%s ", ev[i].kind, ev[i].id, ev[i].ok ? "" : "!");
    }
    printf("\n");
}

/* Waits for a connected state and a successful zoo_exists call. */
static int wait_ready(zhandle_t *zh, int news)
{
    zksi_ev ev[ZKSI_CAP];
    struct Stat st;
    int i;
    int n;

    for (i = 0; i < 300; i++) {
        n = zksi_copy_p(ev, ZKSI_CAP);
        if (count_kind(ev, n, 'N') >= news && zoo_state(zh) == ZOO_CONNECTED_STATE &&
            auth_since_last_new(ev, n) > 0 && zoo_exists(zh, "/", 0, &st) == ZOK) {
            return 1;
        }
        nap_ms(100);
    }
    return 0;
}

static int run(const char *hosts, sasl_callback_t *cb, int fail_new, const char *restart)
{
    zoo_sasl_params_t sp;
    zhandle_t *zh;
    zksi_ev ev[ZKSI_CAP];
    int n;
    int n2;
    int i;
    int bad = 0;
    int ok = 1;

    memset(&sp, 0, sizeof sp);
    sp.service = "zookeeper";
    sp.host = "zk-sasl-md5";
    sp.mechlist = "DIGEST-MD5";
    sp.callbacks = cb;
    zh = zookeeper_init_sasl(hosts, quiet, 10000, NULL, NULL, 0, NULL, &sp);
    if (zh == NULL) {
        printf("FAIL zookeeper_init_sasl\n");
        return 0;
    }
    if (fail_new) {
        /* The first connection fails; the glue disposes it. */
        for (i = 0; i < 100; i++) {
            n = zksi_copy_p(ev, ZKSI_CAP);
            if (count_kind(ev, n, 'D') > 0) {
                break;
            }
            nap_ms(100);
        }
    } else {
        ok = wait_ready(zh, 1);
        if (ok && restart != NULL) {
            if (system(restart) != 0) {
                printf("FAIL restart command\n");
                ok = 0;
            }
            ok = ok && wait_ready(zh, 2);
        }
    }
    zookeeper_close(zh);
    zksi_mark_p('C');
    nap_ms(500);
    n = zksi_copy_p(ev, ZKSI_CAP);
    print_trace(ev, n);
    if (!ok) {
        printf("FAIL no authenticated session\n");
        bad++;
    }
    if (count_kind(ev, n, 'B') != 0) {
        printf("FAIL sasl_client_new with a live connection\n");
        bad++;
    }
    for (i = 0; i < n; i++) {
        if (ev[i].kind == 'A' && !ev[i].ok) {
            printf("FAIL an address image is not host;port\n");
            bad++;
        }
        if ((ev[i].kind == 'S' || ev[i].kind == 'T' || ev[i].kind == 'D') && ev[i].id == 0) {
            printf("FAIL a call on an unknown connection\n");
            bad++;
        }
    }
    if (count_kind(ev, n, 'D') != count_kind(ev, n, 'N')) {
        printf("FAIL each connection needs one sasl_dispose\n");
        bad++;
    }
    if (n == 0 || ev[n - 1].kind != 'C') {
        printf("FAIL a Cyrus call after zookeeper_close\n");
        bad++;
    }
    if (fail_new) {
        /* The first events: N1! A1 D1, and no start on connection 1. */
        if (n < 3 || ev[0].kind != 'N' || ev[0].ok || ev[2].kind != 'D' || ev[2].id != 1) {
            printf("FAIL the failed sasl_client_new is not disposed first\n");
            bad++;
        }
        for (i = 0; i < n; i++) {
            if (ev[i].kind == 'S' && ev[i].id == 1) {
                printf("FAIL sasl_client_start on the failed connection\n");
                bad++;
            }
        }
    } else if (restart != NULL && count_kind(ev, n, 'N') < 2) {
        printf("FAIL no second connection after the restart\n");
        bad++;
    }
    nap_ms(200);
    n2 = zksi_copy_p(ev, ZKSI_CAP);
    if (n2 != n) {
        printf("FAIL a late Cyrus call after zookeeper_close\n");
        bad++;
    }
    return bad == 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    const char *fail = getenv("ZK_SASL_FAIL_NEW");
    const char *restart = getenv("ZK_SASL_RESTART");
    const char *passfile = "sasl_interpose.pass";
    sasl_callback_t *cb;
    FILE *f;
    void *p;
    int fail_new = fail != NULL && strcmp(fail, "1") == 0 ? 1 : 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s host:port\n", argv[0]);
        return 2;
    }
    p = dlsym(RTLD_DEFAULT, "zksi_copy");
    memcpy(&zksi_copy_p, &p, sizeof p);
    p = dlsym(RTLD_DEFAULT, "zksi_mark");
    memcpy(&zksi_mark_p, &p, sizeof p);
    if (zksi_copy_p == NULL || zksi_mark_p == NULL) {
        fprintf(stderr, "the interposer is not loaded\n");
        return 2;
    }
    zoo_set_debug_level(ZOO_LOG_LEVEL_ERROR);
    f = fopen(passfile, "w");
    if (f == NULL) {
        return 2;
    }
    fputs("mypassword\n", f);
    fclose(f);
    if (sasl_client_init(NULL) != SASL_OK) {
        fprintf(stderr, "sasl_client_init failed\n");
        return 2;
    }
    cb = zoo_sasl_make_basic_callbacks("myuser", NULL, passfile);
    if (!run(argv[1], cb, fail_new, fail_new ? NULL : restart)) {
        remove(passfile);
        return 1;
    }
    remove(passfile);
    printf("PASS\n");
    return 0;
}

#endif /* ZK_SASL_INTERPOSE_APP */
