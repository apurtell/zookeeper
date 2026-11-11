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
 * Sync API wrappers. mt only.
 *
 * Each wrapper makes a sync record on the heap. It submits the request
 * through the exported async entry with ZKS_SYNC_MARKER and waits on the
 * record. The calling thread then copies the reply into the outputs of
 * the caller. A wrapper on the IO thread returns ZSYSTEMERROR with errno
 * EDEADLK.
 */

#include "zks_internal.h"

#ifdef THREADED

/* ------------------------------------------------------------------------
 * The sync record.
 *
 * A record has two references. The waiter holds one, and the completer
 * holds the other. The last reference frees the record and every reply
 * object that it still holds. The completer writes only record members.
 * The waiter reads them only after it sees done under the mutex.
 * ---------------------------------------------------------------------- */

/* Frees the record and the reply objects that it still holds. */
static void zks_sync_free(struct zks_sync *s)
{
    int32_t i;
    free(s->data);
    free(s->path);
    deallocate_String_vector(&s->strs);
    deallocate_ACL_vector(&s->acl);
    if (s->ops != NULL) {
        for (i = 0; i < s->nops; i++) {
            free(s->ops[i].path);
        }
        free(s->ops);
    }
    free(s->op_kind);
    pthread_cond_destroy(&s->c);
    pthread_mutex_destroy(&s->m);
    free(s);
}

/*
 * Allocates a record with two references. Returns NULL on failure, and
 * the wrapper then returns ZSYSTEMERROR, as alloc_sync_completion does
 * (mt_adaptor.c:72-80).
 */
static struct zks_sync *zks_sync_new(uint32_t kind)
{
    struct zks_sync *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&s->m, NULL) != 0) {
        free(s);
        return NULL;
    }
    if (pthread_cond_init(&s->c, NULL) != 0) {
        pthread_mutex_destroy(&s->m);
        free(s);
        return NULL;
    }
    s->refs = 2;
    s->kind = kind;
    s->data_len = -1;
    return s;
}

/* Drops one reference. The thread that drops the last one frees the record. */
static void zks_sync_unref(struct zks_sync *s)
{
    int last;
    pthread_mutex_lock(&s->m);
    s->refs--;
    last = s->refs == 0;
    pthread_mutex_unlock(&s->m);
    if (last) {
        zks_sync_free(s);
    }
}

/*
 * Ends the wait of a record and drops the completer reference. The
 * completer touches nothing after this call. The reference drops in the
 * same critical section, so the signal comes before the waiter can free
 * the record.
 */
static void zks_sync_signal(struct zks_sync *s, int rc, int failed, int origin)
{
    int last;
    pthread_mutex_lock(&s->m);
    s->rc = rc;
    s->failed = failed;
    s->origin = origin;
    s->done = 1;
    pthread_cond_signal(&s->c);
    s->refs--;
    last = s->refs == 0;
    pthread_mutex_unlock(&s->m);
    if (last) {
        zks_sync_free(s);
    }
}

/*
 * The cancellation handler of the wait. The cancelled thread holds the
 * mutex again when this handler runs. The handler drops the waiter
 * reference. The completer then frees the record when it finishes.
 */
static void zks_sync_wait_cancelled(void *arg)
{
    struct zks_sync *s = arg;
    int last;
    s->refs--;
    last = s->refs == 0;
    pthread_mutex_unlock(&s->m);
    if (last) {
        zks_sync_free(s);
    }
}

/* Waits until the completer sets done, as wait_sync_completion does. */
static void zks_sync_wait(struct zks_sync *s)
{
    pthread_mutex_lock(&s->m);
    pthread_cleanup_push(zks_sync_wait_cancelled, s);
    while (!s->done) {
        pthread_cond_wait(&s->c, &s->m);
    }
    pthread_cleanup_pop(0);
    pthread_mutex_unlock(&s->m);
}

/* Makes the copy-out source from the record members. */
static zkrs_sync_src zks_sync_src(const struct zks_sync *s)
{
    zkrs_sync_src src;
    memset(&src, 0, sizeof(src));
    src.kind = s->kind;
    src.rc = s->rc;
    src.failed = s->failed;
    src.origin = s->origin;
    src.data = s->data;
    src.data_len = s->data_len;
    src.path = s->path;
    src.path_len = s->path_len;
    src.stat = &s->stat;
    src.ops = s->ops;
    src.nops = s->nops;
    src.op_kind = s->op_kind;
    return src;
}

/*
 * Starts a wrapper before the submit. It applies the debug registry check
 * and the IO-thread guard, then makes the record. A sync call on
 * the IO thread can never complete, because that thread completes it.
 * Returns NULL when the wrapper must return ZSYSTEMERROR. A NULL handle
 * passes, and the async entry then returns ZBADARGUMENTS, as in legacy.
 */
static struct zks_sync *zks_sync_begin(const zhandle_t *zh, const char *func, uint32_t kind)
{
    ZKS_UNUSED(func); /* only the debug registry check reads it */
    if (zh != NULL) {
        ZKS_REGISTRY_CHECK(zh, func);
        if (zks_current_role(zh) == ZKRS_ROLE_IO) {
            errno = EDEADLK;
            return NULL;
        }
    }
    return zks_sync_new(kind);
}

/* Starts a wrapper, or returns ZSYSTEMERROR from it when the start fails. */
#define ZKS_SYNC_BEGIN_OR_RETURN(s, zh, func, kind)                                                \
    do {                                                                                           \
        if (((s) = zks_sync_begin((zh), (func), (kind))) == NULL) {                                \
            return ZSYSTEMERROR;                                                                   \
        }                                                                                          \
    } while (0)

/*
 * Finishes a wrapper after the submit gave rc. For a refused submit, no
 * completion comes, so the wrapper drops the completer reference. For an
 * accepted submit, the wrapper waits and takes the record rc. The caller
 * outputs change only on this thread and only on ZOK, except MULTI: its
 * per-op writers run for every rc. The caller still holds the
 * waiter reference after the return.
 */
static int zks_sync_finish(struct zks_sync *s, int rc, const zkrs_sync_dst *dst)
{
    zkrs_sync_src src;
    if (rc != ZOK) {
        zks_sync_unref(s);
        return rc;
    }
    zks_sync_wait(s);
    rc = s->rc;
    if (rc == ZOK || s->kind == ZKRS_K_MULTI) {
        src = zks_sync_src(s);
        ZKS_CALL_VOID(zkrs_sync_copy_out(&src, dst));
    }
    return rc;
}

/* Finishes a wrapper that takes no vector, and drops the waiter reference. */
static int zks_sync_end(struct zks_sync *s, int rc, const zkrs_sync_dst *dst)
{
    rc = zks_sync_finish(s, rc, dst);
    zks_sync_unref(s);
    return rc;
}

/*
 * Finishes a data wrapper. len is the capacity that the wrapper read
 * before the submit, as legacy reads it at call time. The caller length
 * changes only on ZOK.
 */
static int zks_sync_end_data(struct zks_sync *s, int rc, char *buffer, int32_t len,
                             int *buffer_len, struct Stat *stat)
{
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    dst.buffer = buffer;
    dst.buffer_len = &len;
    dst.stat = stat;
    rc = zks_sync_end(s, rc, &dst);
    if (rc == ZOK) {
        *buffer_len = len;
    }
    return rc;
}

/* Gives the children vector to the caller, or frees it for a NULL output. */
static void zks_sync_take_strings(struct zks_sync *s, struct String_vector *strings)
{
    if (strings != NULL) {
        *strings = s->strs;
    } else {
        deallocate_String_vector(&s->strs);
    }
    s->strs.count = 0;
    s->strs.data = NULL;
}

/* Gives the ACL vector to the caller, or frees it for a NULL output. */
static void zks_sync_take_acl(struct zks_sync *s, struct ACL_vector *acl)
{
    if (acl != NULL) {
        *acl = s->acl;
    } else {
        deallocate_ACL_vector(&s->acl);
    }
    s->acl.count = 0;
    s->acl.data = NULL;
}

/*
 * Completes a record from a RESULT view on the completing thread. The
 * writers fill the record members with no lock held. MULTI always gets
 * its per-op copies, and the record takes the per-op kinds of the
 * request. Other kinds get the reply objects only for a decoded ZOK
 * reply. The delivery code frees the request after this call.
 */
ZKS_HIDDEN void zks_sync_complete(struct zks_req *r, const zkrs_result_view *v)
{
    struct zks_sync *s = r->sync;
    zkrs_result_dst d = ZKRS_RESULT_DST_INIT;
    if (s == NULL) {
        return;
    }
    if (r->kind == ZKRS_K_MULTI) {
        s->op_kind = r->op_kind;
        r->op_kind = NULL;
        d.ops = &s->ops;
        d.nops = &s->nops;
        ZKS_CALL_VOID(zkrs_write_result(v, &d));
    } else if (v->rc == ZOK && !v->failed) {
        d.stat = &s->stat;
        d.value = &s->data;
        d.value_len = &s->data_len;
        d.strings = &s->strs;
        d.acl = &s->acl;
        d.str = &s->path;
        d.str_len = &s->path_len;
        ZKS_CALL_VOID(zkrs_write_result(v, &d));
    }
    zks_sync_signal(s, v->rc, v->failed, (int)v->origin);
}

/*
 * Completes a record for a local watch removal. The rc stays ZOK, as
 * legacy notify_sync_completion leaves it (zookeeper.c:5021-5029).
 */
ZKS_HIDDEN void zks_sync_complete_local(struct zks_sync *s)
{
    zks_sync_signal(s, ZOK, 0, ZKRS_ORIGIN_REPLY);
}

/*
 * Completes a record whose token Rust discards. This runs in a
 * vtable entry, so it makes no Rust call. The teardown origin makes the
 * copy-out write nothing, except for MULTI. A MULTI record takes the
 * per-op kinds, so the copy-out can fail every result slot with
 * ZCLOSING. Legacy free_completions leaves the slots untouched
 * (zookeeper.c:2032-2040).
 */
ZKS_HIDDEN void zks_sync_complete_closing(struct zks_req *r)
{
    struct zks_sync *s = r->sync;
    if (s == NULL) {
        return;
    }
    if (r->kind == ZKRS_K_MULTI) {
        s->op_kind = r->op_kind;
        r->op_kind = NULL;
    }
    zks_sync_signal(s, ZCLOSING, 1, ZKRS_ORIGIN_TEARDOWN);
}

/* ------------------------------------------------------------------------
 * Static helpers that mirror the legacy static helpers.
 * ---------------------------------------------------------------------- */

/*
 * The body of zoo_wget with the exported zoo_awgetconfig in place of
 * zoo_awget. The request reads the absolute config node under
 * any chroot, as async getconfig does.
 */
static int zks_wgetconfig_(zhandle_t *zh, watcher_fn watcher, void *watcherCtx, char *buffer,
                           int *buffer_len, struct Stat *stat, const char *func)
{
    struct zks_sync *s;
    int32_t len;
    int rc;
    if (buffer_len == NULL) {
        return ZBADARGUMENTS;
    }
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, func, ZKRS_K_DATA);
    len = *buffer_len; /* legacy reads the capacity at call time */
    rc = zoo_awgetconfig(zh, watcher, watcherCtx, (data_completion_t)ZKS_SYNC_MARKER, s);
    return zks_sync_end_data(s, rc, buffer, len, buffer_len, stat);
}

/* The legacy static zoo_wget_children_ (zookeeper.c:5745-5767). */
static int zks_wget_children_(zhandle_t *zh, const char *path, watcher_fn watcher,
                              void *watcherCtx, struct String_vector *strings, const char *func)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, func, ZKRS_K_STRINGLIST);
    rc = zoo_awget_children(zh, path, watcher, watcherCtx, (strings_completion_t)ZKS_SYNC_MARKER,
                            s);
    rc = zks_sync_finish(s, rc, &dst);
    if (rc == ZOK) {
        zks_sync_take_strings(s, strings);
    }
    zks_sync_unref(s);
    return rc;
}

/*
 * The legacy static zoo_wget_children2_ (zookeeper.c:5769-5795). A NULL
 * stat is tolerated.
 */
static int zks_wget_children2_(zhandle_t *zh, const char *path, watcher_fn watcher,
                               void *watcherCtx, struct String_vector *strings, struct Stat *stat,
                               const char *func)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, func, ZKRS_K_STRINGLIST_STAT);
    rc = zoo_awget_children2(zh, path, watcher, watcherCtx,
                             (strings_stat_completion_t)ZKS_SYNC_MARKER, s);
    dst.stat = stat;
    rc = zks_sync_finish(s, rc, &dst);
    if (rc == ZOK) {
        zks_sync_take_strings(s, strings);
    }
    zks_sync_unref(s);
    return rc;
}

/*
 * The legacy static remove_watches (zookeeper.c:5868-5890). A local
 * removal completes the record in zks_aremove_watches, so the wait ends
 * at once with ZOK.
 */
static int zks_remove_watches(zhandle_t *zh, const char *path, ZooWatcherType wtype,
                              watcher_fn watcher, void *watcherCtx, int local, int all,
                              const char *func)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    if (path == NULL) {
        return ZBADARGUMENTS;
    }
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, func, ZKRS_K_VOID);
    rc = zks_aremove_watches(zh, path, wtype, watcher, watcherCtx, local, NULL, s, all, 1);
    return zks_sync_end(s, rc, &dst);
}

/* ------------------------------------------------------------------------
 * The 23 exported sync wrappers. They delegate as legacy does.
 * ---------------------------------------------------------------------- */

int zoo_create(zhandle_t *zh, const char *path, const char *value, int valuelen,
               const struct ACL_vector *acl, int mode, char *path_buffer, int path_buffer_len)
{
    return zoo_create_ttl(zh, path, value, valuelen, acl, mode, -1, path_buffer, path_buffer_len);
}

int zoo_create_ttl(zhandle_t *zh, const char *path, const char *value, int valuelen,
                   const struct ACL_vector *acl, int mode, int64_t ttl, char *path_buffer,
                   int path_buffer_len)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_STRING);
    rc = zoo_acreate_ttl(zh, path, value, valuelen, acl, mode, ttl,
                         (string_completion_t)ZKS_SYNC_MARKER, s);
    dst.path_buffer = path_buffer;
    dst.path_buffer_len = path_buffer_len;
    return zks_sync_end(s, rc, &dst);
}

int zoo_create2(zhandle_t *zh, const char *path, const char *value, int valuelen,
                const struct ACL_vector *acl, int mode, char *path_buffer, int path_buffer_len,
                struct Stat *stat)
{
    return zoo_create2_ttl(zh, path, value, valuelen, acl, mode, -1, path_buffer,
                           path_buffer_len, stat);
}

int zoo_create2_ttl(zhandle_t *zh, const char *path, const char *value, int valuelen,
                    const struct ACL_vector *acl, int mode, int64_t ttl, char *path_buffer,
                    int path_buffer_len, struct Stat *stat)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_STRING_STAT);
    rc = zoo_acreate2_ttl(zh, path, value, valuelen, acl, mode, ttl,
                          (string_stat_completion_t)ZKS_SYNC_MARKER, s);
    dst.path_buffer = path_buffer;
    dst.path_buffer_len = path_buffer_len;
    dst.stat = stat;
    return zks_sync_end(s, rc, &dst);
}

int zoo_delete(zhandle_t *zh, const char *path, int version)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_VOID);
    rc = zoo_adelete(zh, path, version, (void_completion_t)ZKS_SYNC_MARKER, s);
    return zks_sync_end(s, rc, &dst);
}

int zoo_exists(zhandle_t *zh, const char *path, int watch, struct Stat *stat)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zoo_wexists(zh, path, p.fn, p.ctx, stat);
}

int zoo_wexists(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx,
                struct Stat *stat)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_STAT);
    rc = zoo_awexists(zh, path, watcher, watcherCtx, (stat_completion_t)ZKS_SYNC_MARKER, s);
    dst.stat = stat;
    return zks_sync_end(s, rc, &dst);
}

int zoo_get(zhandle_t *zh, const char *path, int watch, char *buffer, int *buffer_len,
            struct Stat *stat)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zoo_wget(zh, path, p.fn, p.ctx, buffer, buffer_len, stat);
}

int zoo_wget(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx, char *buffer,
             int *buffer_len, struct Stat *stat)
{
    struct zks_sync *s;
    int32_t len;
    int rc;
    if (buffer_len == NULL) {
        return ZBADARGUMENTS;
    }
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_DATA);
    len = *buffer_len; /* legacy reads the capacity at call time */
    rc = zoo_awget(zh, path, watcher, watcherCtx, (data_completion_t)ZKS_SYNC_MARKER, s);
    return zks_sync_end_data(s, rc, buffer, len, buffer_len, stat);
}

int zoo_getconfig(zhandle_t *zh, int watch, char *buffer, int *buffer_len, struct Stat *stat)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zks_wgetconfig_(zh, p.fn, p.ctx, buffer, buffer_len, stat, __func__);
}

int zoo_wgetconfig(zhandle_t *zh, watcher_fn watcher, void *watcherCtx, char *buffer,
                   int *buffer_len, struct Stat *stat)
{
    return zks_wgetconfig_(zh, watcher, watcherCtx, buffer, buffer_len, stat, __func__);
}

int zoo_reconfig(zhandle_t *zh, const char *joining, const char *leaving, const char *members,
                 int64_t version, char *buffer, int *buffer_len, struct Stat *stat)
{
    struct zks_sync *s;
    int32_t len;
    int rc;
    if (buffer_len == NULL) {
        return ZBADARGUMENTS;
    }
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_DATA);
    len = *buffer_len; /* legacy reads the capacity at call time */
    rc = zoo_areconfig(zh, joining, leaving, members, version,
                       (data_completion_t)ZKS_SYNC_MARKER, s);
    return zks_sync_end_data(s, rc, buffer, len, buffer_len, stat);
}

int zoo_set(zhandle_t *zh, const char *path, const char *buffer, int buflen, int version)
{
    return zoo_set2(zh, path, buffer, buflen, version, NULL);
}

int zoo_set2(zhandle_t *zh, const char *path, const char *buffer, int buflen, int version,
             struct Stat *stat)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_STAT);
    rc = zoo_aset(zh, path, buffer, buflen, version, (stat_completion_t)ZKS_SYNC_MARKER, s);
    dst.stat = stat;
    return zks_sync_end(s, rc, &dst);
}

int zoo_get_children(zhandle_t *zh, const char *path, int watch, struct String_vector *strings)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zks_wget_children_(zh, path, p.fn, p.ctx, strings, __func__);
}

int zoo_wget_children(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx,
                      struct String_vector *strings)
{
    return zks_wget_children_(zh, path, watcher, watcherCtx, strings, __func__);
}

int zoo_get_children2(zhandle_t *zh, const char *path, int watch, struct String_vector *strings,
                      struct Stat *stat)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zks_wget_children2_(zh, path, p.fn, p.ctx, strings, stat, __func__);
}

int zoo_wget_children2(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx,
                       struct String_vector *strings, struct Stat *stat)
{
    return zks_wget_children2_(zh, path, watcher, watcherCtx, strings, stat, __func__);
}

int zoo_get_acl(zhandle_t *zh, const char *path, struct ACL_vector *acl, struct Stat *stat)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_ACLLIST);
    rc = zoo_aget_acl(zh, path, (acl_completion_t)ZKS_SYNC_MARKER, s);
    dst.stat = stat;
    rc = zks_sync_finish(s, rc, &dst);
    if (rc == ZOK) {
        zks_sync_take_acl(s, acl);
    }
    zks_sync_unref(s);
    return rc;
}

int zoo_set_acl(zhandle_t *zh, const char *path, int version, const struct ACL_vector *acl)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int rc;
    ZKS_SYNC_BEGIN_OR_RETURN(s, zh, __func__, ZKRS_K_VOID);
    /* Legacy casts away const here too (zookeeper.c:5858). */
    rc = zoo_aset_acl(zh, path, version, (struct ACL_vector *)acl,
                      (void_completion_t)ZKS_SYNC_MARKER, s);
    return zks_sync_end(s, rc, &dst);
}

/*
 * Fails every result slot of a sync multi that sent no request. Then the
 * caller reads no stale err (spec "Defined Results in Synchronous
 * Multi-Operations"). The call-time writes of value and stat stay. A
 * ZBADARGUMENTS result writes nothing, because results can be invalid
 * then.
 */
static int zks_multi_refused(zoo_op_result_t *results, int count, int rc)
{
    int i;
    if (rc != ZBADARGUMENTS && results != NULL) {
        for (i = 0; i < count; i++) {
            results[i].err = rc;
        }
    }
    return rc;
}

/*
 * The multi writers run on this thread from the per-op copies of the
 * record, for every rc. The results array belongs to the
 * caller and stays valid for the whole call.
 */
int zoo_multi(zhandle_t *zh, int count, const zoo_op_t *ops, zoo_op_result_t *results)
{
    struct zks_sync *s;
    zkrs_sync_dst dst = ZKRS_SYNC_DST_INIT;
    int refused;
    int rc;
    if ((s = zks_sync_begin(zh, __func__, ZKRS_K_MULTI)) == NULL) {
        return zks_multi_refused(results, count, ZSYSTEMERROR);
    }
    rc = zoo_amulti(zh, count, ops, results, (void_completion_t)ZKS_SYNC_MARKER, s);
    refused = rc != ZOK;
    dst.results = results;
    dst.count = count;
    rc = zks_sync_end(s, rc, &dst);
    return refused ? zks_multi_refused(results, count, rc) : rc;
}

int zoo_remove_watches(zhandle_t *zh, const char *path, ZooWatcherType wtype, watcher_fn watcher,
                       void *watcherCtx, int local)
{
    return zks_remove_watches(zh, path, wtype, watcher, watcherCtx, local, 0, __func__);
}

int zoo_remove_all_watches(zhandle_t *zh, const char *path, ZooWatcherType wtype, int local)
{
    return zks_remove_watches(zh, path, wtype, NULL, NULL, local, 1, __func__);
}

#endif /* THREADED */
