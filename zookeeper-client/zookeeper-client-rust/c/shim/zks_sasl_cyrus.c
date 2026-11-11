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
 * The Cyrus engine glue of the SASL builds.
 *
 * The drain calls the glue on the IO owner for each SASL item, with no
 * Rust frame on the stack. Rust allows at most one START or STEP in
 * flight for each handle, so the session needs no lock.
 * The unit also holds zookeeper_init_sasl and the six leaked zoo_sasl_*
 * internals, so the SASL symbols come only from the two glue
 * units.
 *
 * The glue gives Cyrus a per-session copy of the callback array. In that
 * copy, a trampoline wraps the first SASL_CB_PASS entry, so the secret
 * copies belong to the session. Every view, length and
 * generation is checked on entry. A failure gives ZKRS_SASL_FAIL, and
 * zk-proto then logs the legacy failure line.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* POSIX names under -std=c99 on glibc */
#endif
#define ZKS_SASL_GLUE 1
#include "zks_internal.h"
#include "zks_sasl.h"
#include "zks_sasl_cb.h"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* The bounds of hostile or corrupt input. Legacy has no such limits. */
#define ZKS_SASL_MAX_CB 4096u     /* entries before SASL_CB_LIST_END */
#define ZKS_SASL_MAX_SECRETS 16u  /* PASS requests for each connection */

/*
 * C99 has no _Alignas and no max_align_t. The union gives buf the
 * strictest alignment of the basic types, so buf can hold a
 * sasl_secret_t.
 */
union zks_max_align {
    long double ld;
    long long ll;
    double d;
    void *p;
    void (*fp)(void);
};

/* One secret that the glue gives to Cyrus for one connection. */
struct zks_secret {
    struct zks_secret *next;
    size_t size;                /* bytes in buf */
    union zks_max_align buf[];  /* a sasl_secret_t, then its data */
};

/* The context of the PASS trampoline. */
struct zks_pass_ctx {
    zks_sasl_proc orig_proc;    /* the application SASL_CB_PASS proc */
    void *orig_ctx;             /* and its context */
    int is_library;             /* orig_proc is the library callback */
    struct zks_secret *secrets; /* all copies for this connection */
    unsigned nsecrets;
};

/*
 * conn, cb and the secrets exist only from a START to the next dispose.
 * After a dispose, conn is NULL, gen is 0 and cb is NULL.
 */
struct zks_sasl_sess {
    struct zks_sasl_params params; /* owned copies; borrowed callbacks */
    zhandle_t *log_zh;             /* the log target only; NULL when no handle owns the session */
    sasl_conn_t *conn;             /* NULL without a connection */
    uint32_t gen;                  /* the gen of conn; 0 without a connection */
    sasl_callback_t *cb;           /* the per-session callback copy, or NULL */
    struct zks_pass_ctx pass;
};

/* Every early return of a glue call gives this FAIL result. */
static void zks_out_clear(zks_sasl_out *o)
{
    const zks_sasl_out fail = ZKS_SASL_OUT_FAIL;

    *o = fail;
}

/* A view is valid when its length is in range and its pointer agrees with is_null. */
static int zks_bytes_ok(zks_bytes b)
{
    if (b.len > ZKS_SASL_LEN_CAP) {
        return 0;
    }
    if (b.is_null) {
        return b.len == 0 && b.p == NULL;
    }
    return b.len == 0 || b.p != NULL;
}

/*
 * Sets the token view of a Cyrus output. A NULL output is the null token.
 * The caller checks that a NULL output has no length.
 */
static void zks_token_out(const char *cout, unsigned coutlen, zkrs_sasl_out *out)
{
    out->token.p = (const uint8_t *)cout;
    out->token.len = (uint32_t)coutlen;
    out->token.is_null = (uint8_t)(cout == NULL ? 1 : 0);
}

/*
 * The internal dispose. It has no generation check. START, a matching
 * DISPOSE and the session clear use it. Cyrus can use the secrets and
 * the callback copy until sasl_dispose returns, so the frees come after it.
 */
static void zks_conn_dispose(struct zks_sasl_sess *s)
{
    struct zks_secret *x;
    struct zks_secret *nx;

    if (s->conn != NULL) {
        sasl_dispose(&s->conn);
    }
    s->conn = NULL;
    s->gen = 0;
    for (x = s->pass.secrets; x != NULL; x = nx) {
        nx = x->next;
        zks_secure_zero(x->buf, x->size);
        free(x);
    }
    s->pass.secrets = NULL;
    s->pass.nsecrets = 0;
    free(s->cb);
    s->cb = NULL;
}

/* The size of an "ip;port" string with its NUL, as legacy. */
#define ZKS_IPPORT_CAP ((size_t)NI_MAXHOST + (size_t)NI_MAXSERV)

/*
 * Formats "ip;port" as _zsasl_getipport does. The view holds the image
 * of a sockaddr_in or a sockaddr_in6. The function gives ZOK or
 * ZSYSTEMERROR. Only a getnameinfo error writes a log line.
 */
static int zks_ipport(const struct zks_sasl_sess *s, zks_bytes a, char out[ZKS_IPPORT_CAP],
                      char host[NI_MAXHOST])
{
    struct sockaddr_storage ss;
    char hb[NI_MAXHOST];
    char pb[NI_MAXSERV];
    int fl = NI_NUMERICHOST | NI_NUMERICSERV;
    int e;
    int n;
    sa_family_t fam;
    const size_t fam_off = offsetof(struct sockaddr, sa_family);

    if (!zks_bytes_ok(a) || a.is_null || a.len < fam_off + sizeof fam) {
        return ZSYSTEMERROR;
    }
    memcpy(&fam, a.p + fam_off, sizeof fam);
    if (!((fam == AF_INET && a.len == sizeof(struct sockaddr_in))
          || (fam == AF_INET6 && a.len == sizeof(struct sockaddr_in6)))) {
        return ZSYSTEMERROR;
    }
    memset(&ss, 0, sizeof ss);
    memcpy(&ss, a.p, a.len);
#ifdef NI_WITHSCOPEID
    if (fam == AF_INET6) {
        fl |= NI_WITHSCOPEID;
    }
#endif
    e = getnameinfo((const struct sockaddr *)(const void *)&ss, (socklen_t)a.len, hb, sizeof hb,
                    pb, sizeof pb, fl);
    if (e != 0) {
        zks_log_site(s->log_zh, ZKS_SITE_SASL_GETNAMEINFO, gai_strerror(e));
        return ZSYSTEMERROR;
    }
    n = snprintf(out, ZKS_IPPORT_CAP, "%s;%s", hb, pb);
    if (n < 0 || (size_t)n >= ZKS_IPPORT_CAP) {
        return ZSYSTEMERROR;
    }
    if (host != NULL) {
        memcpy(host, hb, sizeof hb);
    }
    return ZOK;
}

/* The type of a SASL_CB_PASS proc. */
typedef int (*zks_pass_fn)(sasl_conn_t *, void *, int, sasl_secret_t **);

static int zks_sasl_pass_trampoline(sasl_conn_t *conn, void *context, int id,
                                    sasl_secret_t **psecret);

/*
 * Copies the application callback array into s->cb. The copy wraps the
 * first SASL_CB_PASS entry, because Cyrus uses only the first entry of
 * an id. A NULL array gives a NULL copy, and Cyrus then uses its global
 * callbacks. An array of ZKS_SASL_MAX_CB or more entries fails.
 */
static int zks_cb_build(struct zks_sasl_sess *s, const struct zks_sasl_params *p)
{
    const sasl_callback_t *app = (const sasl_callback_t *)p->callbacks;
    size_t n = 0;
    size_t bytes;
    size_t i;

    s->cb = NULL;
    s->pass.orig_proc = NULL;
    s->pass.orig_ctx = NULL;
    s->pass.is_library = 0;
    if (app == NULL) {
        return 0;
    }
    while (app[n].id != SASL_CB_LIST_END) {
        n++;
        if (n >= ZKS_SASL_MAX_CB) {
            return -1;
        }
    }
    if (ZKS_ADD_OVF(n, (size_t)1, &bytes) || ZKS_MUL_OVF(bytes, sizeof *app, &bytes)) {
        return -1;
    }
    s->cb = (sasl_callback_t *)malloc(bytes);
    if (s->cb == NULL) {
        abort(); /* the drop-in aborts when its own buffer allocation fails */
    }
    memcpy(s->cb, app, bytes); /* also the SASL_CB_LIST_END entry */
    for (i = 0; i < n; i++) {
        if (s->cb[i].id == SASL_CB_PASS) {
            s->pass.orig_proc = s->cb[i].proc;
            s->pass.orig_ctx = s->cb[i].context;
            s->pass.is_library = zks_is_library_pass_cb(s->cb[i].proc);
            s->cb[i].proc = ZKS_SASL_PROC(&zks_sasl_pass_trampoline);
            s->cb[i].context = &s->pass;
            break;
        }
    }
    return 0;
}

/*
 * The session sink. It copies the secret into a new zero-filled buffer
 * that the session owns, and gives that buffer to Cyrus. The buffer is
 * never smaller than a sasl_secret_t. It stays valid until the dispose.
 */
static int zks_pass_store(void *arg, const unsigned char *data, size_t len, sasl_secret_t **out)
{
    struct zks_pass_ctx *pc = (struct zks_pass_ctx *)arg;
    const size_t hdr = offsetof(sasl_secret_t, data);
    size_t need;
    size_t total;
    struct zks_secret *x;
    unsigned char *dst;
    sasl_secret_t *sec;

    if (len > ZKS_SASL_LEN_CAP) {
        return SASL_BUFOVER;
    }
    if (pc->nsecrets >= ZKS_SASL_MAX_SECRETS) {
        return SASL_NOMEM;
    }
    if (ZKS_ADD_OVF(hdr, len, &need) || ZKS_ADD_OVF(need, (size_t)1, &need)) {
        return SASL_BUFOVER;
    }
    if (need < sizeof(sasl_secret_t)) {
        need = sizeof(sasl_secret_t);
    }
    if (ZKS_ADD_OVF(offsetof(struct zks_secret, buf), need, &total)) {
        return SASL_BUFOVER;
    }
    x = (struct zks_secret *)calloc(1, total);
    if (x == NULL) {
        return SASL_NOMEM;
    }
    x->size = need;
    sec = (sasl_secret_t *)(void *)x->buf;
    sec->len = (unsigned long)len;
    /*
     * The copy uses the buffer address, not sec->data. Thus
     * _FORTIFY_SOURCE sees the true size of the object.
     */
    dst = (unsigned char *)x->buf + hdr;
    if (len > 0) {
        memcpy(dst, data, len);
    }
    dst[len] = '\0';
    x->next = pc->secrets;
    pc->secrets = x;
    pc->nsecrets++;
    *out = sec;
    return SASL_OK;
}

/*
 * The proc of the wrapped SASL_CB_PASS entry. The library callback uses
 * the legacy password rules. An application callback runs with its own
 * context. In both cases the session sink keeps the bytes, and no lock
 * is held while the callback runs.
 */
static int zks_sasl_pass_trampoline(sasl_conn_t *conn, void *context, int id,
                                    sasl_secret_t **psecret)
{
    struct zks_pass_ctx *pc = (struct zks_pass_ctx *)context;
    sasl_secret_t *got = NULL;
    zks_pass_fn fn;
    int rc;

    if (pc == NULL || psecret == NULL || id != SASL_CB_PASS) {
        return SASL_BADPARAM;
    }
    *psecret = NULL;
    if (pc->is_library) {
        return zks_getsecret_unlocked(conn, pc->orig_ctx, zks_pass_store, pc, psecret);
    }
    if (pc->orig_proc == NULL) {
        return SASL_FAIL;
    }
    fn = (zks_pass_fn)(void (*)(void))pc->orig_proc;
    rc = fn(conn, pc->orig_ctx, id, &got);
    if (rc != SASL_OK) {
        return rc;
    }
    if (got == NULL) {
        return SASL_FAIL;
    }
    if (got->len > ZKS_SASL_LEN_CAP) {
        return SASL_BUFOVER;
    }
    return zks_pass_store(pc, (const unsigned char *)got + offsetof(sasl_secret_t, data),
                          (size_t)got->len, psecret);
}

/* Copies a string of external origin. A string at the cap fails. */
static int zks_copy_str(const char *src, char **dst)
{
    size_t n;
    size_t sz;

    *dst = NULL;
    if (src == NULL) {
        return 0;
    }
    n = strnlen(src, ZKS_SASL_LEN_CAP);
    if (n >= ZKS_SASL_LEN_CAP || ZKS_ADD_OVF(n, (size_t)1, &sz)) {
        return -1;
    }
    *dst = (char *)malloc(sz);
    if (*dst == NULL) {
        return -1;
    }
    memcpy(*dst, src, n);
    (*dst)[n] = '\0';
    return 0;
}

/* ---- session life ---- */

/*
 * The init calls this at the SASL point, after the first resolve and
 * before the mt waker, as legacy does. The application callback array
 * stays borrowed and must live as long as the handle (zk_sasl.c:90-114).
 */
ZKS_HIDDEN struct zks_sasl_sess *zks_sasl_sess_new(zhandle_t *zh, const struct zoo_sasl_params *p)
{
    struct zks_sasl_sess *s;

    if (p == NULL) {
        return NULL;
    }
    s = (struct zks_sasl_sess *)calloc(1, sizeof *s);
    if (s == NULL) {
        return NULL;
    }
    s->log_zh = zh;
    if (zks_copy_str(p->service, &s->params.service) != 0
        || zks_copy_str(p->host, &s->params.host) != 0
        || zks_copy_str(p->mechlist, &s->params.mechlist) != 0) {
        zks_sasl_sess_free(s);
        return NULL;
    }
    s->params.callbacks = p->callbacks;
    return s;
}

ZKS_HIDDEN void zks_sasl_sess_clear(struct zks_sasl_sess *s)
{
    if (s == NULL) {
        return;
    }
    zks_conn_dispose(s);
    free(s->params.service);
    free(s->params.host);
    free(s->params.mechlist);
    s->params.service = NULL;
    s->params.host = NULL;
    s->params.mechlist = NULL;
}

/* zks_release calls this before it frees the handle. */
ZKS_HIDDEN void zks_sasl_sess_free(struct zks_sasl_sess *s)
{
    if (s == NULL) {
        return;
    }
    zks_sasl_sess_clear(s);
    free(s);
}

/* The drain records the gen after each START that the glue did not reject. */
ZKS_HIDDEN void zks_sasl_set_gen(struct zks_sasl_sess *s, uint32_t gen)
{
    if (s->conn != NULL) {
        s->gen = gen;
    }
}

/* ---- start, step and dispose ---- */

/*
 * A START disposes the old connection first, as zoo_sasl_connect does.
 * It then makes the connection and gives the first client token.
 */
ZKS_HIDDEN void zks_sasl_start(zks_sasl_sess *s, uint32_t gen, zks_bytes local, zks_bytes peer,
                               zkrs_sasl_out *out)
{
    const zks_sasl_params *p = &s->params;
    char lip[ZKS_IPPORT_CAP];
    char rip[ZKS_IPPORT_CAP];
    char host[NI_MAXHOST];
    const char *chosen = NULL;
    const char *cout = NULL;
    unsigned coutlen = 0;
    size_t mlen;
    int sr;

    zks_out_clear(out);
    if (gen == 0 || gen == s->gen) {
        out->status = ZKRS_SASL_STALE;
        return;
    }
    zks_conn_dispose(s);
    if (zks_ipport(s, local, lip, NULL) != ZOK || zks_ipport(s, peer, rip, host) != ZOK) {
        return;
    }
    zks_log_site(s->log_zh, ZKS_SITE_SASL_HOST, lip, rip);
    /* A callback array that is too long is a SASL_NOMEM of sasl_client_new. */
    if (zks_cb_build(s, p) != 0) {
        zks_log_site(s->log_zh, ZKS_SITE_SASL_NEW, sasl_errstring(SASL_NOMEM, NULL, NULL));
        return;
    }
    sr = sasl_client_new(p->service, p->host != NULL ? p->host : host, lip, rip, s->cb, 0,
                         &s->conn);
    if (sr != SASL_OK) {
        zks_log_site(s->log_zh, ZKS_SITE_SASL_NEW, sasl_errstring(sr, NULL, NULL));
        /* Cyrus can fail and still set the connection, which uses s->cb. */
        zks_conn_dispose(s);
        return;
    }
    sr = sasl_client_start(s->conn, p->mechlist, NULL, &cout, &coutlen, &chosen);
    if (sr != SASL_OK && sr != SASL_CONTINUE) {
        zks_log_site(s->log_zh, ZKS_SITE_SASL_START_ERR, sasl_errstring(sr, NULL, NULL),
                     sasl_errdetail(s->conn));
        return;
    }
    if (chosen == NULL) {
        return;
    }
    mlen = strnlen(chosen, (size_t)SASL_MECHNAMEMAX + 1u);
    if (mlen == 0 || mlen > SASL_MECHNAMEMAX || coutlen > ZKS_SASL_LEN_CAP
        || (coutlen > 0 && cout == NULL)) {
        return;
    }
    zks_log_site(s->log_zh, ZKS_SITE_SASL_START, sr, chosen, (int)coutlen);
    out->status = sr == SASL_CONTINUE ? ZKRS_SASL_CONTINUE : ZKRS_SASL_DONE;
    out->mech.p = (const uint8_t *)chosen;
    out->mech.len = (uint32_t)mlen;
    out->mech.is_null = 0;
    zks_token_out(cout, coutlen, out);
}

/* A -1 server token goes to Cyrus as (NULL, 0). */
ZKS_HIDDEN void zks_sasl_step(zks_sasl_sess *s, uint32_t gen, zks_bytes challenge,
                              zkrs_sasl_out *out)
{
    const char *cout = NULL;
    unsigned coutlen = 0;
    int sr;

    zks_out_clear(out);
    if (gen == 0 || gen != s->gen) {
        out->status = ZKRS_SASL_STALE;
        return;
    }
    if (s->conn == NULL || !zks_bytes_ok(challenge)) {
        return;
    }
    sr = sasl_client_step(s->conn, challenge.is_null ? NULL : (const char *)challenge.p,
                          challenge.is_null ? 0u : (unsigned)challenge.len, NULL, &cout, &coutlen);
    zks_log_site(s->log_zh, ZKS_SITE_SASL_STEP_OUT, sr, (int)coutlen);
    if (sr != SASL_OK && sr != SASL_CONTINUE) {
        zks_log_site(s->log_zh, ZKS_SITE_SASL_STEP_ERR, sasl_errstring(sr, NULL, NULL),
                     sasl_errdetail(s->conn));
        return;
    }
    if (coutlen > ZKS_SASL_LEN_CAP || (coutlen > 0 && cout == NULL)) {
        return;
    }
    out->status = sr == SASL_CONTINUE ? ZKRS_SASL_CONTINUE : ZKRS_SASL_DONE;
    zks_token_out(cout, coutlen, out);
}

/* A stale gen has no effect. */
ZKS_HIDDEN void zks_sasl_dispose(zks_sasl_sess *s, uint32_t gen)
{
    if (gen != 0 && gen == s->gen) {
        zks_conn_dispose(s);
    }
}

/* ---- the public entry ---- */

/* NULL sasl_params gives the zookeeper_init2 behavior. */
zhandle_t *zookeeper_init_sasl(const char *host, watcher_fn fn, int recv_timeout,
                               const clientid_t *clientid, void *context, int flags,
                               log_callback_fn log_callback, zoo_sasl_params_t *sasl_params)
{
    return zks_init_common(host, fn, recv_timeout, clientid, context, flags, log_callback, NULL,
                           sasl_params);
}

/* ---- the leaked internals ---- */

/*
 * No installed header declares these six symbols. The object of
 * zoo_sasl_client_create is opaque. It is not attached to a handle.
 */
struct zks_sasl_sess *zoo_sasl_client_create(zoo_sasl_params_t *sasl_params);
void zoo_sasl_client_destroy(struct zks_sasl_sess *sasl_client);
void zoo_sasl_mark_failed(zhandle_t *zh);
int zoo_sasl_connect(zhandle_t *zh);
int zoo_sasl_client_start(zhandle_t *zh);
int zoo_sasl_client_step(zhandle_t *zh, const char *server_data, int server_data_len);

struct zks_sasl_sess *zoo_sasl_client_create(zoo_sasl_params_t *sasl_params)
{
    return zks_sasl_sess_new(NULL, sasl_params);
}

/* The caller frees the object, as with legacy (zk_sasl.c:116-133). */
void zoo_sasl_client_destroy(struct zks_sasl_sess *sasl_client)
{
    zks_sasl_sess_clear(sasl_client);
}

/* State only: no event and no teardown (zk_sasl.c:135-141). */
void zoo_sasl_mark_failed(zhandle_t *zh)
{
    if (zh == NULL) {
        return;
    }
    ZKS_CALL_VOID(zkrs_sasl_mark_failed(zh->core));
}

/*
 * The three drivers of the negotiation are stubs. The IO owner
 * holds the negotiation state, so an application thread cannot drive it.
 */
int zoo_sasl_connect(zhandle_t *zh)
{
    ZKS_UNUSED(zh);
    return ZSYSTEMERROR;
}

int zoo_sasl_client_start(zhandle_t *zh)
{
    ZKS_UNUSED(zh);
    return ZSYSTEMERROR;
}

int zoo_sasl_client_step(zhandle_t *zh, const char *server_data, int server_data_len)
{
    ZKS_UNUSED(zh);
    ZKS_UNUSED(server_data);
    ZKS_UNUSED(server_data_len);
    return ZSYSTEMERROR;
}
