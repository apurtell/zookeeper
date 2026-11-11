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
 * A SASL failure (DV-FIX-3, ST-18). Mode DEV, because the two cores differ
 * by design. The log is ignored. The case reads the SASL lines through its
 * own log callback.
 *
 * Scenarios:
 * - reply: the server rejects the password with an error reply.
 * - glue: the application PASS callback fails inside sasl_client_step.
 * - addr: getsockname fails at the SASL start (the preload makes it fail).
 *
 * Rules:
 * - LOG-SASL: "SASL authentication failed. rc=%d" comes once after a glue
 *   failure and once after an address failure, with rc ZSYSTEMERROR. It
 *   does not come after an error reply (zookeeper.c:3147-3150).
 *   The address failure also gives the line "getsockname" (zk_sasl.c:224).
 * - ST-RC: in st, the driving call that sees the failure returns the
 *   SASL rc: the error code of the reply, or ZSYSTEMERROR.
 * - DV-FIX-3, Rust: the state is AUTH_FAILED, one AUTH_FAILED session
 *   event comes, the socket closes, and pending async, sync and auth work
 *   gets ZAUTHFAILED before the close. The close then disposes the Cyrus
 *   connection.
 * - DV-FIX-3, legacy: the state is AUTH_FAILED with no event, the socket
 *   stays open, and pending work completes only at zookeeper_close.
 * - No sasl_client_new runs after an address failure.
 *
 * In mt the preload holds the sasl_client_new call of the IO thread. The case
 * queues its work in that time, so the work is pending at the failure.
 * In st the case drives the handle itself and queues the work after the
 * first zookeeper_interest call.
 *
 * Run it with --sasl and the SASL libraries of both cores.
 *
 * Ledger rows: ST-03 and ST-06.
 *
 * zkconf-flavors: mt st
 * zkconf-preload: sasl
 */

#include "zkconf_sasl.h"

#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>

#ifdef HAVE_CYRUS_SASL_H

/* The observations of one scenario. The library threads write them. */
struct obs {
    int events;    /* AUTH_FAILED session events */
    int failed;    /* "SASL authentication failed" lines */
    int failed_rc; /* the rc of the last such line */
    int step;      /* "During SASL negotiation" lines */
    int addr;      /* "getsockname" lines */
    int async_rc;  /* the rc of zoo_aexists, 1 while pending */
    int auth_rc;   /* the rc of zoo_add_auth, 1 while pending */
    int sync_rc;   /* the rc of the sync zoo_exists, 1 while pending */
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct obs g_obs;

static void obs_reset(void)
{
    pthread_mutex_lock(&g_mu);
    memset(&g_obs, 0, sizeof g_obs);
    g_obs.async_rc = 1;
    g_obs.auth_rc = 1;
    g_obs.sync_rc = 1;
    pthread_mutex_unlock(&g_mu);
}

static struct obs obs_get(void)
{
    struct obs o;
    pthread_mutex_lock(&g_mu);
    o = g_obs;
    pthread_mutex_unlock(&g_mu);
    return o;
}

static void fail_watcher(zhandle_t *zh, int type, int state, const char *path, void *ctx)
{
    (void)zh;
    (void)path;
    (void)ctx;
    if (type == ZOO_SESSION_EVENT && state == ZOO_AUTH_FAILED_STATE) {
        pthread_mutex_lock(&g_mu);
        g_obs.events++;
        pthread_mutex_unlock(&g_mu);
    }
}

static void fail_log(const char *msg)
{
    const char *p;
    pthread_mutex_lock(&g_mu);
    p = msg != NULL ? strstr(msg, "SASL authentication failed. rc=") : NULL;
    if (p != NULL) {
        g_obs.failed++;
        g_obs.failed_rc = atoi(p + strlen("SASL authentication failed. rc="));
    }
    if (msg != NULL && strstr(msg, "During SASL negotiation") != NULL) {
        g_obs.step++;
    }
    if (msg != NULL && strstr(msg, "zoo_sasl_connect") != NULL
        && strstr(msg, "getsockname") != NULL) {
        g_obs.addr++;
    }
    pthread_mutex_unlock(&g_mu);
}

static void async_cb(int rc, const struct Stat *stat, const void *data)
{
    (void)stat;
    (void)data;
    pthread_mutex_lock(&g_mu);
    g_obs.async_rc = rc;
    pthread_mutex_unlock(&g_mu);
}

static void auth_cb(int rc, const void *data)
{
    (void)data;
    pthread_mutex_lock(&g_mu);
    g_obs.auth_rc = rc;
    pthread_mutex_unlock(&g_mu);
}

/* The application PASS callback. The context is the password or NULL. */
static int app_pass(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
{
    static sasl_secret_t *secret;
    const char *pw = (const char *)context;
    size_t len;
    (void)conn;
    (void)id;
    if (pw == NULL) {
        return SASL_FAIL;
    }
    len = strlen(pw);
    free(secret);
    secret = (sasl_secret_t *)malloc(sizeof(sasl_secret_t) + len);
    if (secret == NULL) {
        return SASL_NOMEM;
    }
    secret->len = (unsigned long)len;
    memcpy(secret->data, pw, len);
    *psecret = secret;
    return SASL_OK;
}

static long now_ms(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (long)now.tv_sec * 1000L + (long)(now.tv_usec / 1000);
}

/* Waits up to ms milliseconds until the server socket is closed. */
static int wait_closed(int ms)
{
    long deadline = now_ms() + ms;
    while (zkcs_sasl()->open() != 0 && now_ms() < deadline) {
        zkc_sleep_ms(10);
    }
    return zkcs_sasl()->open();
}

/* The filtered order of the preload events from the last mark m on. */
static const char *order_from(char m, char *buf, size_t len)
{
    const char *p;
    zkcs_order(buf, len);
    p = strrchr(buf, m);
    return p != NULL ? p : "";
}

/* Queues an async request and an auth request. */
static void queue_work(zhandle_t *zh)
{
    int rc = zoo_aexists(zh, "/", 0, async_cb, "ex");
    zkc_ev("call", "zoo_aexists -> %s", zkc_rc(rc));
    rc = zoo_add_auth(zh, "digest", "u:p", 3, auth_cb, "auth");
    zkc_ev("call", "zoo_add_auth -> %s", zkc_rc(rc));
}

#ifdef THREADED
static pthread_mutex_t g_tmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_tcv = PTHREAD_COND_INITIALIZER;
static int g_tstarted;

static void *sync_thread(void *arg)
{
    struct Stat st;
    int rc;
    pthread_mutex_lock(&g_tmu);
    g_tstarted = 1;
    pthread_cond_broadcast(&g_tcv);
    pthread_mutex_unlock(&g_tmu);
    rc = zoo_exists((zhandle_t *)arg, "/", 0, &st);
    pthread_mutex_lock(&g_mu);
    g_obs.sync_rc = rc;
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

/*
 * Holds the IO thread at its SASL start, queues the async, auth and sync
 * work, then frees the IO thread. Without work there is no hold. Returns 1 when the sync thread runs.
 */
static int mt_queue(zhandle_t *zh, int with_work, pthread_t *tid)
{
    long deadline = now_ms() + 10000;
    int started = 0;
    if (!with_work) {
        return 0;
    }
    while (!zkcs_sasl()->gated() && now_ms() < deadline) {
        zkc_sleep_ms(5);
    }
    zkc_ev("ret", "IO thread held at sasl_client_new -> %d", zkcs_sasl()->gated());
    queue_work(zh);
    g_tstarted = 0;
    if (pthread_create(tid, NULL, sync_thread, zh) == 0) {
        started = 1;
        pthread_mutex_lock(&g_tmu);
        while (!g_tstarted) {
            pthread_cond_wait(&g_tcv, &g_tmu);
        }
        pthread_mutex_unlock(&g_tmu);
        /* The thread queues its request just after the signal. */
        zkc_sleep_ms(300);
    }
    zkcs_sasl()->gate(0);
    return started;
}
#else
/*
 * Drives zh until its state is AUTH_FAILED or ms milliseconds pass. It
 * queues the work after the first zookeeper_interest call. Returns the
 * first negative rc of a driving call, other than ZNOTHING.
 */
static int st_drive(zhandle_t *zh, int with_work, int ms)
{
    long deadline = now_ms() + ms;
    int first = 0;
    int queued = 0;
    while (now_ms() < deadline && zoo_state(zh) != ZOO_AUTH_FAILED_STATE) {
        int fd = -1;
        int interest = 0;
        struct timeval tv = {0, 0};
        fd_set rd;
        fd_set wr;
        int events = 0;
        int rc = zkc_interest(zh, &fd, &interest, &tv);
        if (with_work && !queued) {
            queue_work(zh);
            queued = 1;
        }
        if (rc != ZOK) {
            if (first == 0) {
                first = rc;
            }
            break;
        }
        if (fd < 0) {
            zkc_sleep_ms(10);
            continue;
        }
        FD_ZERO(&rd);
        FD_ZERO(&wr);
        if (interest & ZOOKEEPER_READ) {
            FD_SET(fd, &rd);
        }
        if (interest & ZOOKEEPER_WRITE) {
            FD_SET(fd, &wr);
        }
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        if (select(fd + 1, &rd, &wr, NULL, &tv) < 0) {
            continue;
        }
        if (FD_ISSET(fd, &rd)) {
            events |= ZOOKEEPER_READ;
        }
        if (FD_ISSET(fd, &wr)) {
            events |= ZOOKEEPER_WRITE;
        }
        rc = zkc_process(zh, events);
        if (rc < 0 && rc != ZNOTHING && first == 0) {
            first = rc;
        }
    }
    return first;
}
#endif

/*
 * Runs one scenario. pass_ctx is the password of the PASS callback, or
 * NULL for a failing callback. addr_fail arms the getsockname failure.
 * want_rc is the SASL rc and want_line the count of the "failed" line.
 */
static void scenario(const char *name, char mark, const char *pass_ctx, int addr_fail,
                     int want_rc, int want_line)
{
    sasl_callback_t app[4];
    zhandle_t *zh;
    struct obs o;
    char buf[512];
    int with_work = addr_fail == 0;
    int open_after;
    int rust = zkc_is_rust();
    int st_rc = 0;
#ifdef THREADED
    pthread_t tid;
    int started = 0;
#endif

    obs_reset();
    zkcs_mark(mark);
    zkcs_app_array(app, app_pass, (void *)pass_ctx);
    if (addr_fail) {
        zkcs_sasl()->fail(1);
    }
#ifdef THREADED
    zkcs_sasl()->gate(with_work);
#endif
    zh = zkcs_sasl_init(zkc_host(0), name, app, fail_watcher, fail_log, 10000);
    zkc_ev("call", "zookeeper_init_sasl %s -> %s", name, zh != NULL ? "zh" : "NULL");
    if (zh == NULL) {
        zkcs_sasl()->gate(0);
        zkcs_sasl()->fail(0);
        return;
    }
#ifdef THREADED
    started = mt_queue(zh, with_work, &tid);
    {
        long deadline = now_ms() + 15000;
        while (zoo_state(zh) != ZOO_AUTH_FAILED_STATE && now_ms() < deadline) {
            zkc_sleep_ms(10);
        }
    }
#else
    st_rc = st_drive(zh, with_work, 15000);
#endif
    zkc_ev("ret", "%s: zoo_state -> %s", name, zkc_state(zoo_state(zh)));
    /* Rust closes the socket in the failure step. Legacy keeps it open. */
    open_after = wait_closed(rust ? 3000 : 500);
#ifdef THREADED
    if (started && rust) {
        long deadline = now_ms() + 3000;
        while (obs_get().sync_rc == 1 && now_ms() < deadline) {
            zkc_sleep_ms(10);
        }
    }
#endif
    o = obs_get();
    zkc_ev("ret", "%s: events=%d failed=%d rc=%d step=%d addr=%d open=%d st_rc=%d", name,
           o.events, o.failed, o.failed_rc, o.step, o.addr, open_after, st_rc);
    zkc_ev("ret", "%s: async=%d auth=%d sync=%d", name, o.async_rc, o.auth_rc, o.sync_rc);

    zkc_dev("DV-FIX-3", o.failed == want_line && (want_line == 0 || o.failed_rc == want_rc),
            "LOG-SASL: %s: \"SASL authentication failed\" lines=%d rc=%d", name, o.failed,
            o.failed_rc);
    if (pass_ctx == NULL) {
        zkc_dev("DV-FIX-3", o.step == 1, "LOG-SASL: %s: \"During SASL negotiation\" lines=%d",
                name, o.step);
    }
    if (addr_fail) {
        zkc_dev("DV-FIX-3", o.addr == 1, "LOG-SASL: %s: \"getsockname\" lines=%d", name, o.addr);
        zkc_dev("DV-FIX-3", strchr(order_from(mark, buf, sizeof buf), 'N') == NULL,
                "SASL-ADDR: %s: no sasl_client_new after the failure: %s", name, buf);
    }
    if (!zkc_is_st()) {
        st_rc = want_rc;
    }
    zkc_dev("DV-FIX-3", st_rc == want_rc, "ST-RC: %s: driving rc=%d", name, st_rc);
    zkc_dev("DV-FIX-3", zoo_state(zh) == ZOO_AUTH_FAILED_STATE, "%s: state=%d", name,
            zoo_state(zh));
    if (rust) {
        zkc_dev("DV-FIX-3", o.events == 1, "%s: AUTH_FAILED events=%d", name, o.events);
        zkc_dev("DV-FIX-3", open_after == 0, "%s: open server sockets=%d", name, open_after);
        if (with_work) {
            zkc_dev("DV-FIX-3", o.async_rc == ZAUTHFAILED && o.auth_rc == ZAUTHFAILED,
                    "%s: pending async=%d auth=%d before the close", name, o.async_rc,
                    o.auth_rc);
        }
#ifdef THREADED
        if (started) {
            zkc_dev("DV-FIX-3", o.sync_rc == ZAUTHFAILED, "%s: pending sync=%d before the close",
                    name, o.sync_rc);
        }
#endif
    } else {
        zkc_dev("DV-FIX-3", o.events == 0, "%s: legacy AUTH_FAILED events=%d", name, o.events);
        zkc_dev("DV-FIX-3", open_after == 1, "%s: legacy open server sockets=%d", name,
                open_after);
        if (with_work) {
            zkc_dev("DV-FIX-3", o.async_rc == 1 && o.auth_rc == 1 && o.sync_rc == 1,
                    "%s: legacy pending work waits for the close", name);
        }
    }

    /* Close order: Rust closed the socket at the failure; legacy at close. */
    zkcs_mark('f');
    zkc_close(zh);
#ifdef THREADED
    if (started) {
        pthread_join(tid, NULL);
    }
#endif
    o = obs_get();
    zkc_ev("ret", "%s: after close async=%d auth=%d sync=%d", name, o.async_rc, o.auth_rc,
           o.sync_rc);
    {
        const char *got = order_from(mark, buf, sizeof buf);
        const char *want;
        if (addr_fail) {
            want = rust ? "Cf" : "fC";
        } else {
            want = rust ? "NCfD" : "NfCD";
        }
        zkc_ev("order", "%s: %s", name, got);
        zkc_dev("DV-FIX-3", got[0] == mark && strcmp(got + 1, want) == 0,
                "SASL-CLOSE: %s: order %s, want %c%s", name, got, mark, want);
    }
    zkcs_sasl()->fail(0);
}

static void run(void)
{
    scenario("reply", 'r', "wrong", 0, ZAUTHFAILED, 0);
    scenario("glue", 'g', NULL, 0, ZSYSTEMERROR, 1);
    scenario("addr", 'a', ZKCS_SASL_PASSWORD, 1, ZSYSTEMERROR, 1);
}
#endif

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "sasl_fail", 1, "DEV", "ignore");
#ifdef HAVE_CYRUS_SASL_H
    if (zkcs_sasl_resolve() == 0 && zkcs_has_preload()) {
        run();
        return zkc_finish();
    }
#endif
    zkc_ev("check", "skip: no SASL library, no SASL server or no SASL preload");
    return zkc_finish();
}
