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
 * Async entry points and the return-code funnel.
 *
 * Every zoo_a* body fills a zkrs_request and calls one submit template.
 * The template allocates the zks_req, calls zkrs_submit, drains the
 * outbox and frees the request unless Rust kept it (status ZKRS_OK).
 * Wrappers that legacy calls by exported name keep that call, so
 * interposition sees the same edges.
 */

#include "zks_internal.h"

/* The address of this function is the sync marker. It never runs. */
ZKS_HIDDEN void zks_sync_marker(void)
{
}

/* Maps a submit status to the legacy return code. */
static int zks_funnel(zkrs_status s)
{
    switch (s) {
    case ZKRS_OK:
    case ZKRS_OK_LOCAL:
        return ZOK;
    case ZKRS_EARLY_BADARGS:
        return ZBADARGUMENTS;
    case ZKRS_EARLY_STATE:
        return ZINVALIDSTATE;
    case ZKRS_UNIMPLEMENTED:
        return ZUNIMPLEMENTED;
    case ZKRS_NOWATCHER:
        return ZNOWATCHER;
    case ZKRS_SYSTEM:
        return ZSYSTEMERROR;
    default:
        return ZMARSHALLINGERROR; /* LATE */
    }
}

/* A create with a NULL handle: stage 1 (the TTL check) comes before stage 2. */
static int zks_create_null_handle(int mode, int64_t ttl)
{
    zkrs_status s = ZKS_CALL(zkrs_validate_ttl(mode, ttl));
    return s != ZKRS_OK ? zks_funnel(s) : ZBADARGUMENTS;
}

/*
 * zoo_aremove_watches gets its completion as a void_completion_t * whose
 * value is the function (zookeeper.c:3747). The shim copies that value
 * into a function pointer, so both types must have the same size.
 */
typedef char zks_fn_size_ok[sizeof(void_completion_t) == sizeof(void_completion_t *) ? 1 : -1];

ZKS_HIDDEN struct zks_req *zks_req_new(unsigned kind, unsigned mode, zks_fn fn, const void *data)
{
    struct zks_req *r = malloc(sizeof *r);
    if (r == NULL) {
        return NULL;
    }
    r->kind = (uint8_t)kind;
    r->mode = (uint8_t)mode;
    r->fn = fn;
    r->data = data;
    /* A sync request carries its record in data. */
    r->sync = mode == ZKS_REQ_SYNC ? (struct zks_sync *)(uintptr_t)data : NULL;
    r->results = NULL;
    r->count = 0;
    r->op_kind = NULL;
    return r;
}

ZKS_HIDDEN void zks_req_free(struct zks_req *r)
{
    if (r == NULL) {
        return;
    }
    free(r->op_kind);
    free(r);
}

/*
 * Submits a request that the caller allocated. r can be NULL after an
 * allocation failure. Rust then sees token 0 and reports it at the
 * serialization stage, so the rc order stays legacy.
 *
 * Rust keeps r only for ZKRS_OK. For every other status, C frees it here.
 * The outbox then holds only log lines of the calling thread, so the free
 * comes before the drain. A log callback that unwinds then leaks nothing.
 */
static zkrs_status zks_submit_req(zhandle_t *zh, const zkrs_request *rq, struct zks_req *r)
{
    /*
     * In mt one mask covers the submit and the drain of its outbox. In st
     * only the call into Rust is masked. The st submit runs its flush pass
     * and a forced close inside Rust, and it gives LOG items only. The
     * next driving call delivers the results.
     */
    ZKS_HOLD_SCOPE;
    const zkrs_handle *core = zh->core;
    zkrs_outbox ob = ZKRS_OUTBOX_INIT;
    uint32_t delivery =
        (r != NULL && r->mode != ZKS_REQ_ASYNC) ? ZKRS_DELIVER_DIRECT : ZKRS_DELIVER_QUEUED;
    zkrs_status s = ZKS_CALL(zkrs_submit(core, rq, (uintptr_t)r, delivery, &ob));
    if (s != ZKRS_OK) {
        zks_req_free(r);
    }
    zks_drain(zh, &ob);
    return s;
}

/*
 * Allocates the request and submits it. It returns the raw status, so
 * zks_aremove_watches can tell ZKRS_OK_LOCAL from ZKRS_OK.
 */
static zkrs_status zks_submit_raw(zhandle_t *zh, const zkrs_request *rq, unsigned kind, zks_fn fn,
                                  const void *data)
{
    return zks_submit_req(zh, rq, zks_req_new(kind, zks_req_mode_of(fn), fn, data));
}

static int zks_submit(zhandle_t *zh, const zkrs_request *rq, unsigned kind, zks_fn fn,
                      const void *data)
{
    return zks_funnel(zks_submit_raw(zh, rq, kind, fn, data));
}

ZKS_HIDDEN int zks_submit_prepared(zhandle_t *zh, zkrs_request *rq, struct zks_req *r)
{
    return zks_funnel(zks_submit_req(zh, rq, r));
}

/* ---- reads ---- */

/* Submits a read that can set a watch. zh is not NULL. */
static int zks_submit_read(zhandle_t *zh, uint32_t op, uint32_t flags, const char *path,
                           watcher_fn watcher, void *watcherCtx, unsigned kind, zks_fn fn,
                           const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(op);
    rq.flags = flags;
    rq.path = path;
    rq.watch_fn = (uintptr_t)watcher;
    rq.watch_ctx = (uintptr_t)watcherCtx;
    return zks_submit(zh, &rq, kind, fn, data);
}

int zoo_awget(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx,
              data_completion_t completion, const void *data)
{
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    return zks_submit_read(zh, ZKRS_OP_GETDATA, 0, path, watcher, watcherCtx, ZKRS_K_DATA,
                           ZKS_FN(completion), data);
}

int zoo_aget(zhandle_t *zh, const char *path, int watch, data_completion_t completion,
             const void *data)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zoo_awget(zh, path, p.fn, p.ctx, completion, data);
}

int zoo_awgetconfig(zhandle_t *zh, watcher_fn watcher, void *watcherCtx,
                    data_completion_t completion, const void *data)
{
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    /*
     * Getconfig is a GETDATA of the config node. The node gets no chroot
     * prefix (zookeeper.c:4214-4250). The core sends it
     * as its own operation, so the log line names zoo_awgetconfig.
     */
    return zks_submit_read(zh, ZKRS_OP_GETCONFIG, ZKRS_F_RAW_PATH, ZOO_CONFIG_NODE, watcher,
                           watcherCtx, ZKRS_K_DATA, ZKS_FN(completion), data);
}

int zoo_agetconfig(zhandle_t *zh, int watch, data_completion_t completion, const void *data)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zoo_awgetconfig(zh, p.fn, p.ctx, completion, data);
}

int zoo_awexists(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx,
                 stat_completion_t completion, const void *data)
{
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    return zks_submit_read(zh, ZKRS_OP_EXISTS, 0, path, watcher, watcherCtx, ZKRS_K_STAT,
                           ZKS_FN(completion), data);
}

int zoo_aexists(zhandle_t *zh, const char *path, int watch, stat_completion_t completion,
                const void *data)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zoo_awexists(zh, path, p.fn, p.ctx, completion, data);
}

/* The static helper of zookeeper.c:4606-4637. Both children entries call it. */
static int zks_awget_children_(zhandle_t *zh, const char *path, watcher_fn watcher,
                               void *watcherCtx, strings_completion_t completion,
                               const void *data)
{
    return zks_submit_read(zh, ZKRS_OP_GETCHILDREN, 0, path, watcher, watcherCtx,
                           ZKRS_K_STRINGLIST, ZKS_FN(completion), data);
}

/* The static helper of zookeeper.c:4653-4685. */
static int zks_awget_children2_(zhandle_t *zh, const char *path, watcher_fn watcher,
                                void *watcherCtx, strings_stat_completion_t completion,
                                const void *data)
{
    return zks_submit_read(zh, ZKRS_OP_GETCHILDREN2, 0, path, watcher, watcherCtx,
                           ZKRS_K_STRINGLIST_STAT, ZKS_FN(completion), data);
}

int zoo_awget_children(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx,
                       strings_completion_t completion, const void *data)
{
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    return zks_awget_children_(zh, path, watcher, watcherCtx, completion, data);
}

int zoo_aget_children(zhandle_t *zh, const char *path, int watch,
                      strings_completion_t completion, const void *data)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zks_awget_children_(zh, path, p.fn, p.ctx, completion, data);
}

int zoo_awget_children2(zhandle_t *zh, const char *path, watcher_fn watcher, void *watcherCtx,
                        strings_stat_completion_t completion, const void *data)
{
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    return zks_awget_children2_(zh, path, watcher, watcherCtx, completion, data);
}

int zoo_aget_children2(zhandle_t *zh, const char *path, int watch,
                       strings_stat_completion_t completion, const void *data)
{
    struct zks_pair p;
    if (!zks_watch_arg(zh, watch, __func__, &p)) {
        return ZBADARGUMENTS;
    }
    return zks_awget_children2_(zh, path, p.fn, p.ctx, completion, data);
}

int zoo_aget_acl(zhandle_t *zh, const char *path, acl_completion_t completion, const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_GETACL);
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    rq.path = path;
    return zks_submit(zh, &rq, ZKRS_K_ACLLIST, ZKS_FN(completion), data);
}

/* ---- writes ---- */

/*
 * The body of both TTL create entries. zh is not NULL. Rust runs the TTL
 * stage first and picks the wire opcode from the mode.
 */
static int zks_acreate(zhandle_t *zh, const char *path, const char *value, int valuelen,
                       const struct ACL_vector *acl, int mode, int64_t ttl, uint32_t flags,
                       unsigned kind, zks_fn fn, const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_CREATE);
    rq.flags = flags;
    rq.path = path;
    rq.data = value;
    rq.datalen = valuelen;
    rq.mode = mode;
    rq.ttl = ttl;
    /* Rust reads the vector. A NULL vector sends count 0 (zookeeper.c:4347-4349). */
    rq.acl = acl;
    return zks_submit(zh, &rq, kind, fn, data);
}

int zoo_acreate_ttl(zhandle_t *zh, const char *path, const char *value, int valuelen,
                    const struct ACL_vector *acl, int mode, int64_t ttl,
                    string_completion_t completion, const void *data)
{
    if (zh == NULL) {
        return zks_create_null_handle(mode, ttl);
    }
    ZKS_REGISTRY_CHECK(zh, __func__);
    return zks_acreate(zh, path, value, valuelen, acl, mode, ttl, 0, ZKRS_K_STRING,
                       ZKS_FN(completion), data);
}

int zoo_acreate(zhandle_t *zh, const char *path, const char *value, int valuelen,
                const struct ACL_vector *acl, int mode, string_completion_t completion,
                const void *data)
{
    return zoo_acreate_ttl(zh, path, value, valuelen, acl, mode, -1, completion, data);
}

int zoo_acreate2_ttl(zhandle_t *zh, const char *path, const char *value, int valuelen,
                     const struct ACL_vector *acl, int mode, int64_t ttl,
                     string_stat_completion_t completion, const void *data)
{
    if (zh == NULL) {
        return zks_create_null_handle(mode, ttl);
    }
    ZKS_REGISTRY_CHECK(zh, __func__);
    return zks_acreate(zh, path, value, valuelen, acl, mode, ttl, ZKRS_F_CREATE2,
                       ZKRS_K_STRING_STAT, ZKS_FN(completion), data);
}

int zoo_acreate2(zhandle_t *zh, const char *path, const char *value, int valuelen,
                 const struct ACL_vector *acl, int mode, string_stat_completion_t completion,
                 const void *data)
{
    return zoo_acreate2_ttl(zh, path, value, valuelen, acl, mode, -1, completion, data);
}

int zoo_adelete(zhandle_t *zh, const char *path, int version, void_completion_t completion,
                const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_DELETE);
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    rq.path = path;
    rq.version = version;
    return zks_submit(zh, &rq, ZKRS_K_VOID, ZKS_FN(completion), data);
}

int zoo_aset(zhandle_t *zh, const char *path, const char *buffer, int buflen, int version,
             stat_completion_t completion, const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_SETDATA);
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    rq.path = path;
    rq.data = buffer;
    rq.datalen = buflen;
    rq.version = version;
    return zks_submit(zh, &rq, ZKRS_K_STAT, ZKS_FN(completion), data);
}

int zoo_async(zhandle_t *zh, const char *path, string_completion_t completion, const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_SYNC);
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    rq.path = path;
    return zks_submit(zh, &rq, ZKRS_K_STRING, ZKS_FN(completion), data);
}

int zoo_aset_acl(zhandle_t *zh, const char *path, int version, struct ACL_vector *acl,
                 void_completion_t completion, const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_SETACL);
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    rq.path = path;
    rq.version = version;
    /*
     * Legacy reads *acl after the path stage (zookeeper.c:4767-4772). Rust
     * reads the vector when it builds the request, before the path check.
     * A NULL vector fails at the serialization stage, so the order of the
     * return codes does not change.
     */
    rq.acl = acl;
    return zks_submit(zh, &rq, ZKRS_K_VOID, ZKS_FN(completion), data);
}

int zoo_areconfig(zhandle_t *zh, const char *joining, const char *leaving, const char *members,
                  int64_t version, data_completion_t dc, const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_RECONFIG);
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    /* NULL strings go to the wire as jute null strings. */
    rq.joining = joining;
    rq.leaving = leaving;
    rq.members = members;
    rq.reconfig_version = version;
    return zks_submit(zh, &rq, ZKRS_K_DATA, ZKS_FN(dc), data);
}

/* ---- auth and watch removal ---- */

int zoo_add_auth(zhandle_t *zh, const char *scheme, const char *cert, int certLen,
                 void_completion_t completion, const void *data)
{
    const zkrs_handle *core;
    zkrs_outbox ob = ZKRS_OUTBOX_INIT;
    struct zks_req *r = NULL;
    uint32_t f = 0;
    zkrs_status s;
    if (scheme == NULL) {
        return ZBADARGUMENTS;
    }
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    core = zh->core;
    if (completion != NULL) {
        r = zks_req_new(ZKRS_K_VOID, ZKS_REQ_AUTH, ZKS_FN(completion), data);
        if (r == NULL) {
            /* Rust reports it after the state stages, as legacy. */
            f = ZKRS_AUTH_F_ALLOC_FAILED;
        }
    }
    /* Stages 1 to 3 run without the lock, as zookeeper.c:5309-5328. */
    s = ZKS_CALL(zkrs_add_auth_check(core, cert, certLen));
    if (s != ZKRS_OK) {
        zks_req_free(r);
        return zks_funnel(s);
    }
    /*
     * One auth_lock hold covers the whole call. The lock order
     * is auth_lock, then the core locks. The exported functions keep the
     * legacy interposition edges.
     */
    zoo_lock_auth(zh);
    s = ZKS_CALL(zkrs_add_auth(core, scheme, cert, certLen, (uintptr_t)r, f, &ob));
    zoo_unlock_auth(zh);
    if (s != ZKRS_OK) {
        zks_req_free(r);
    }
    zks_drain(zh, &ob);
    return zks_funnel(s);
}

ZKS_HIDDEN int zks_aremove_watches(zhandle_t *zh, const char *path, ZooWatcherType wtype,
                                   watcher_fn w, void *wctx, int local, void_completion_t fn,
                                   const void *data, int all, int sync)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_REMOVE_WATCHES);
    zkrs_status s;
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    rq.path = path;
    rq.wtype = (int32_t)wtype;
    rq.watch_fn = (uintptr_t)w;
    rq.watch_ctx = (uintptr_t)wctx;
    rq.flags = (local ? ZKRS_F_LOCAL : 0) | (all ? ZKRS_F_REMOVE_ALL : 0);
    s = zks_submit_raw(zh, &rq, ZKRS_K_VOID, sync ? ZKS_FN(ZKS_SYNC_MARKER) : ZKS_FN(fn), data);
    if (s == ZKRS_OK_LOCAL && sync) {
        /*
         * A local removal finished at once and Rust kept no token. A sync
         * record completes with ZOK, as legacy notify_sync_completion. An
         * async call never touches data.
         */
#ifdef THREADED
        zks_sync_complete_local((struct zks_sync *)(uintptr_t)data);
#endif
    }
    return zks_funnel(s);
}

int zoo_aremove_watches(zhandle_t *zh, const char *path, ZooWatcherType wtype,
                        watcher_fn watcher, void *watcherCtx, int local,
                        void_completion_t *completion, const void *data)
{
    void_completion_t fn;
    /* The pointer value is the function (zookeeper.c:3747). */
    memcpy(&fn, &completion, sizeof fn);
    return zks_aremove_watches(zh, path, wtype, watcher, watcherCtx, local, fn, data, 0, 0);
}

int zoo_aremove_all_watches(zhandle_t *zh, const char *path, ZooWatcherType wtype, int local,
                            void_completion_t *completion, const void *data)
{
    void_completion_t fn;
    memcpy(&fn, &completion, sizeof fn);
    return zks_aremove_watches(zh, path, wtype, NULL, NULL, local, fn, data, 1, 0);
}
