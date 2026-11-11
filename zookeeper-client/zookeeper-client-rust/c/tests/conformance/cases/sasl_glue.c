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
 * SAS-12.
 * The Cyrus glue of the SASL builds.
 * Mode PER-ROLE: the session events run on the IO thread in mt and on
 * the app thread in st.
 *
 * Rules:
 * - A DIGEST-MD5 session with the library callbacks and a password file
 *   connects, and the creator ACL shows the SASL identity.
 * - The transform callback of zoo_sasl_make_password_callbacks changes
 *   the file content into the password.
 * - The glue wraps the PASS callback of an application array. The
 *   application callback runs, and its secret authenticates the session.
 * - A wrong password gives the state AUTH_FAILED. C gives no session
 *   event there. The drop-in tears the connection down and gives the
 *   AUTH_FAILED event (DV-FIX-3, ST-18), so a DEV check covers the event.
 * - After a server restart, the session authenticates again on the new
 *   connection. The connect retry lines of the restart depend on timing,
 *   so that handle gives its log lines to no file.
 *
 * The case needs a SASL build of both cores and a server with a
 * DigestLoginModule "Server" section with user_myuser="mypassword".
 * ZKCONF_SASL=1 tells the case that the server has it. Without
 * ZKCONF_SASL, or with a library that has no zookeeper_init_sasl, the
 * case records only a skip line. Both cores then give the same trace.
 *
 * Run it from tests/conformance with the SASL libraries, for example:
 *
 *   ./run.sh --sasl --rust DROPIN_SASL --legacy /tmp/zk-legacy-ref/install-sasl/lib \
 *     --port-base N [--flavor st] sasl_glue
 *
 * The option --sasl writes the JAAS file and sets ZKCONF_SASL=1.
 *
 * The case resolves the SASL functions at run time, because the runner
 * links every case against one library and gives no Cyrus flags.
 *
 * zkconf-flavors: mt st
 */

#if defined(__has_include)
#if __has_include(<sasl/sasl.h>)
#define HAVE_CYRUS_SASL_H 1
#endif
#endif

#include "zkconf.h"
#include "zkconf_sasl.h"
#include "zkconf_sync.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void call(const char *what, int rc)
{
    zkc_ev("call", "%s -> %s", what, zkc_rc(rc));
}

#ifdef HAVE_CYRUS_SASL_H

typedef zhandle_t *(*init_sasl_fn)(const char *, watcher_fn, int, const clientid_t *, void *,
                                   int, log_callback_fn, zoo_sasl_params_t *);
typedef sasl_callback_t *(*basic_fn)(const char *, const char *, const char *);
typedef sasl_callback_t *(*password_fn)(const char *, const char *, zoo_sasl_password_t *);

static init_sasl_fn p_init_sasl;
static basic_fn p_basic;
static password_fn p_password;

/* The case resolves each function through a data pointer, as dlsym gives it. */
static void *sym(const char *name)
{
    return dlsym(RTLD_DEFAULT, name);
}

/* The secret that the application PASS callback gives. */
static union {
    sasl_secret_t s;
    char space[sizeof(sasl_secret_t) + 32];
} g_secret;
static int g_pass_calls;

static int app_simple(void *context, int id, const char **result, unsigned *len)
{
    (void)id;
    if (result == NULL) {
        return SASL_BADPARAM;
    }
    *result = (const char *)context;
    if (len != NULL) {
        *len = (unsigned)strlen((const char *)context);
    }
    return SASL_OK;
}

static int app_pass(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
{
    const char *pw = (const char *)context;
    size_t n = strlen(pw);

    (void)conn;
    if (id != SASL_CB_PASS || psecret == NULL || n >= 32) {
        return SASL_BADPARAM;
    }
    g_pass_calls++;
    memset(&g_secret, 0, sizeof g_secret);
    g_secret.s.len = (unsigned long)n;
    memcpy((char *)&g_secret + offsetof(sasl_secret_t, data), pw, n);
    *psecret = &g_secret.s;
    return SASL_OK;
}

/* The transform callback: the file holds the password in reverse order. */
static int reverse_cb(const char *content, size_t content_len, void *context, char *buf,
                      size_t buf_len, size_t *passwd_len)
{
    size_t i;

    (void)context;
    if (content_len > buf_len) {
        return SASL_BUFOVER;
    }
    for (i = 0; i < content_len; i++) {
        buf[i] = content[content_len - 1 - i];
    }
    *passwd_len = content_len;
    return SASL_OK;
}

static int write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    int ok;

    if (f == NULL) {
        return -1;
    }
    ok = fputs(text, f) >= 0;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

/* The AUTH_FAILED session events of the handle with the wrong password. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_auth_failed_events;

static void quiet_watcher(zhandle_t *zh, int type, int state, const char *path, void *ctx)
{
    (void)zh;
    (void)path;
    (void)ctx;
    if (type == ZOO_SESSION_EVENT && state == ZOO_AUTH_FAILED_STATE) {
        pthread_mutex_lock(&g_mu);
        g_auth_failed_events++;
        pthread_mutex_unlock(&g_mu);
    }
}

static int auth_failed_events(void)
{
    int n;

    pthread_mutex_lock(&g_mu);
    n = g_auth_failed_events;
    pthread_mutex_unlock(&g_mu);
    return n;
}

/* The log callback of the restart handle. */
static void drop_log(const char *msg)
{
    (void)msg;
}

/* Starts a DIGEST-MD5 session with the context label ctx. */
static zhandle_t *sasl_open_with(const char *ctx, sasl_callback_t *cb, watcher_fn w,
                                 log_callback_fn log)
{
    zoo_sasl_params_t sp;
    zhandle_t *zh;

    memset(&sp, 0, sizeof sp);
    sp.service = "zookeeper";
    sp.host = "zk-sasl-md5";
    sp.mechlist = "DIGEST-MD5";
    sp.callbacks = cb;
    zh = p_init_sasl(zkc_host(0), w, 10000, NULL, (void *)ctx, 0, log, &sp);
    zkc_ev("call", "zookeeper_init_sasl %s -> %s", ctx, zh != NULL ? "zh" : "NULL");
    if (zh != NULL) {
        zkc_poll_add(zh);
    }
    return zh;
}

static zhandle_t *sasl_open(const char *ctx, sasl_callback_t *cb)
{
    return sasl_open_with(ctx, cb, zkc_watcher, zkc_log_cb);
}

/* Shows the identity of the creator ACL of a new node. */
static void show_identity(zhandle_t *zh, const char *path)
{
    struct ACL_vector acl;
    struct Stat st;
    int rc;

    call("zoo_create CREATOR_ALL",
         zkcs_create(zh, path, "v", 1, &ZOO_CREATOR_ALL_ACL, ZOO_EPHEMERAL, NULL, 0));
    memset(&acl, 0, sizeof acl);
    rc = zkcs_get_acl(zh, path, &acl, &st);
    zkc_ev("ret", "zoo_get_acl -> %s count=%d scheme=%s id=%s", zkc_rc(rc), acl.count,
           acl.count > 0 ? acl.data[0].id.scheme : "-", acl.count > 0 ? acl.data[0].id.id : "-");
    deallocate_ACL_vector(&acl);
}

static void finish_handle(zhandle_t *zh, sasl_callback_t *cb)
{
    zkc_close(zh);
    free(cb);
}

static void run_sasl(const char *prefix)
{
    char pwfile[1024];
    char revfile[1024];
    sasl_callback_t *cb;
    zoo_sasl_password_t password;
    sasl_callback_t app[4];
    zhandle_t *zh;
    int i;
    int n;

    snprintf(pwfile, sizeof pwfile, "%s.pw", prefix);
    snprintf(revfile, sizeof revfile, "%s.rev", prefix);
    if (write_file(pwfile, "mypassword\nsecond line\n") != 0
        || write_file(revfile, "drowssapym") != 0) {
        zkc_fail("cannot write the password files");
        return;
    }

    /* The library callbacks with the first line of the file. */
    cb = p_basic("myuser", NULL, pwfile);
    zh = cb != NULL ? sasl_open_with("file", cb, zkc_watcher, drop_log) : NULL;
    if (zh != NULL) {
        zkc_await("session:CONNECTED@file", 1, 15000);
        show_identity(zh, "/sg-file");

        /* A new connection authenticates again. */
        zkc_server("stop", 0);
        zkc_await("session:CONNECTING@file", 1, 15000);
        zkc_server("start", 0);
        zkc_await("session:CONNECTED@file", 1, 30000);
        zkc_ev("ret", "zoo_state -> %s", zkc_state(zoo_state(zh)));
        show_identity(zh, "/sg-again");
    }
    finish_handle(zh, cb);

    /* The transform callback gives the password. */
    memset(&password, 0, sizeof password);
    password.password_file = revfile;
    password.callback = reverse_cb;
    cb = p_password("myuser", NULL, &password);
    zh = cb != NULL ? sasl_open("transform", cb) : NULL;
    if (zh != NULL) {
        zkc_await("session:CONNECTED@transform", 1, 15000);
        show_identity(zh, "/sg-transform");
    }
    finish_handle(zh, cb);

    /* An application array: the glue wraps its PASS entry. */
    memset(app, 0, sizeof app);
    app[0].id = SASL_CB_AUTHNAME;
    app[0].proc = (int (*)(void))(void (*)(void))app_simple;
    app[0].context = (void *)"myuser";
    app[1].id = SASL_CB_USER;
    app[1].proc = (int (*)(void))(void (*)(void))app_simple;
    app[1].context = (void *)"myuser";
    app[2].id = SASL_CB_PASS;
    app[2].proc = (int (*)(void))(void (*)(void))app_pass;
    app[2].context = (void *)"mypassword";
    app[3].id = SASL_CB_LIST_END;
    zh = sasl_open("app", app);
    if (zh != NULL) {
        zkc_await("session:CONNECTED@app", 1, 15000);
        show_identity(zh, "/sg-app");
        zkc_ev("ret", "application PASS called=%d", g_pass_calls > 0);
    }
    finish_handle(zh, NULL);

    /* A wrong password fails the session. */
    app[2].context = (void *)"wrong";
    zh = sasl_open_with("bad", app, quiet_watcher, zkc_log_cb);
    if (zh != NULL) {
        for (i = 0; i < 150 && zoo_state(zh) != ZOO_AUTH_FAILED_STATE; i++) {
            zkc_poll(100);
        }
        zkc_poll(500);
        zkc_ev("ret", "zoo_state -> %s", zkc_state(zoo_state(zh)));
        n = auth_failed_events();
        zkc_dev("DV-FIX-3", zkc_is_rust() ? n == 1 : n == 0, "AUTH_FAILED session events=%d", n);
        call("zoo_exists after the failure", zkcs_exists(zh, "/", 0, NULL));
    }
    finish_handle(zh, NULL);
    (void)remove(pwfile);
    (void)remove(revfile);
}

static int resolve(void)
{
    void *a = sym("zookeeper_init_sasl");
    void *b = sym("zoo_sasl_make_basic_callbacks");
    void *c = sym("zoo_sasl_make_password_callbacks");

    if (a == NULL || b == NULL || c == NULL) {
        return -1;
    }
    /* POSIX allows the conversion of a dlsym result to a function pointer. */
    memcpy(&p_init_sasl, &a, sizeof p_init_sasl);
    memcpy(&p_basic, &b, sizeof p_basic);
    memcpy(&p_password, &c, sizeof p_password);
    /* The application initializes Cyrus. Neither library does (SAS-01). */
    return zkcs_sasl_client_init() == SASL_OK ? 0 : -1;
}

#endif /* HAVE_CYRUS_SASL_H */

int main(int argc, char **argv)
{
    const char *prefix;

    zkc_init(argc, argv, "sasl_glue", 1, "PER-ROLE", "ordered");
    prefix = getenv("ZKCONF_OUT");
#ifdef HAVE_CYRUS_SASL_H
    if (getenv("ZKCONF_SASL") != NULL && prefix != NULL && resolve() == 0) {
        run_sasl(prefix);
        return zkc_finish();
    }
#endif
    (void)prefix;
    zkc_ev("check", "skip: no SASL library or no SASL server");
    return zkc_finish();
}
