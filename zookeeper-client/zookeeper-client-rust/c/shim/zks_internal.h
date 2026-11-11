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
 * Private shim interface. This header is never installed.
 *
 * Every shim translation unit includes this header first. It is the only
 * place that includes zookeeper.h. It removes the TLS and SASL feature
 * macros before that include, so no shim unit parses an OpenSSL or Cyrus
 * header. The two SASL glue units define ZKS_SASL_GLUE to keep the Cyrus
 * declarations.
 *
 * Names with the zks_ prefix are shim internals. They are static or have
 * hidden visibility, and the final link makes them local.
 */

#ifndef ZKS_INTERNAL_H_
#define ZKS_INTERNAL_H_

#undef HAVE_OPENSSL_H
#ifndef ZKS_SASL_GLUE
#undef HAVE_CYRUS_SASL_H
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
 * Both flavors need it for the cancel mask (zk-ffi IMPLEMENTATION_GUIDE.md,
 * "The cancel mask in st").
 */
#include <pthread.h>

#include "zookeeper.h"
#include "zookeeper_log.h"
#include "zkrs.h"

/* ------------------------------------------------------------------------
 * Toolchain macros. The shim supports GCC-compatible compilers only.
 * The Rust client does not support Windows or MSVC yet.
 * ---------------------------------------------------------------------- */

#define ZKS_HIDDEN __attribute__((visibility("hidden")))
#define ZKS_THREAD_LOCAL __thread
#define ZKS_NORETURN __attribute__((noreturn))
#define ZKS_UNUSED(x) ((void)(x))

/* A relaxed atomic cell. Legacy uses plain stores for these values. */
#define ZKS_ATOMIC(T) T
#define ZKS_LOAD(p) __atomic_load_n((p), __ATOMIC_RELAXED)
#define ZKS_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELAXED)

/* ------------------------------------------------------------------------
 * Re-entry guard.
 *
 * A vtable entry sets zks_in_vtable while it runs. ZKS_CALL and
 * ZKS_CALL_VOID wrap every call into Rust. They abort when the flag is
 * set. Rust can hold a lock on this thread during a vtable call.
 * ---------------------------------------------------------------------- */

extern ZKS_HIDDEN ZKS_THREAD_LOCAL int zks_in_vtable;

static inline void zks_check_call(const char *what)
{
    if (zks_in_vtable) {
        fprintf(stderr, "zookeeper: Rust call from a vtable entry: %s\n", what);
        abort();
    }
}

#define ZKS_ASSERT_NOT_IN_RUST() zks_check_call(__func__)

/* ------------------------------------------------------------------------
 * Cancellation mask (spec "Unwind and Cancellation Safety").
 *
 * A cancellation inside a Rust frame ends the thread with Rust locks held
 * and runs no Rust destructor. Thus the shim turns cancellation off for
 * each call into Rust. In mt it also turns it off while C holds
 * Rust-owned state, such as an outbox during a drain.
 *
 * A thread-local flag records an open mask. A nested mask then makes no
 * system call. The library threads keep a mask for their full life. The
 * sync waiter waits outside every mask, so it stays a cancellation point.
 * A callback that leaves a drain with longjmp leaves the mask open on its
 * thread in mt.
 *
 * Both flavors mask each call into Rust, because a cancel in a Rust frame
 * breaks Rust state in st too. The scopes that run application callbacks
 * differ by flavor (ZKS_HOLD_SCOPE). pthread_setcancelstate is in
 * libSystem on macOS, and in libc on glibc 2.34 and later and on musl.
 * On an older glibc the Rust standard library already needs libpthread,
 * so the st mask adds no link dependency.
 * ---------------------------------------------------------------------- */

#define ZKS_CANCEL_NONE (-1)

extern ZKS_HIDDEN ZKS_THREAD_LOCAL int zks_cancel_masked;

/*
 * Opens a mask. It returns the state to restore, or ZKS_CANCEL_NONE. The
 * mask functions keep errno, because errno is a result of some calls.
 */
static inline int zks_cancel_mask(void)
{
    int saved_errno;
    int old;
    if (zks_cancel_masked) {
        return ZKS_CANCEL_NONE;
    }
    saved_errno = errno;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) != 0) {
        old = ZKS_CANCEL_NONE;
    } else {
        zks_cancel_masked = 1;
    }
    errno = saved_errno;
    return old;
}

/* Closes the mask that zks_cancel_mask opened. */
static inline void zks_cancel_unmask(int old)
{
    int saved_errno;
    if (old != ZKS_CANCEL_NONE) {
        saved_errno = errno;
        zks_cancel_masked = 0;
        pthread_setcancelstate(old, NULL);
        errno = saved_errno;
    }
}

static inline void zks_cancel_scope_end(int *old)
{
    zks_cancel_unmask(*old);
}

/*
 * Declares a mask that ends with the enclosing block, also when a C++
 * exception unwinds the block. Use it as the first declaration.
 */
#define ZKS_CANCEL_SCOPE                                                                 \
    int zks_cancel_scope_ __attribute__((cleanup(zks_cancel_scope_end))) = zks_cancel_mask()

/*
 * Declares the mask of a scope that runs application callbacks: a drain,
 * a drive loop, a submit with its drain, or a close. mt masks the full
 * scope. st masks only the calls into Rust, because no Rust frame and no
 * Rust lock exist while an st callback runs. Thus an st
 * callback keeps the cancel state of legacy st. The st form is an unused
 * declaration, so the scopes keep the C99 order of declarations.
 */
#ifdef THREADED
#define ZKS_HOLD_SCOPE ZKS_CANCEL_SCOPE
#else
#define ZKS_HOLD_SCOPE int zks_hold_scope_ __attribute__((unused)) = 0
#endif

/* The entry check of every call into Rust. It returns the open mask. */
static inline int zks_rust_enter(const char *what)
{
    zks_check_call(what);
    return zks_cancel_mask();
}

/* Calls Rust with a result. ZKS_CALL_VOID calls Rust with no result. */
#define ZKS_CALL(x)                                                                      \
    __extension__({                                                                      \
        int zks_cm_ = zks_rust_enter(#x);                                                \
        __typeof__(x) zks_cr_ = (x);                                                     \
        zks_cancel_unmask(zks_cm_);                                                      \
        zks_cr_;                                                                         \
    })
#define ZKS_CALL_VOID(x)                                                                 \
    do {                                                                                 \
        int zks_cm_ = zks_rust_enter(#x);                                                \
        (x);                                                                             \
        zks_cancel_unmask(zks_cm_);                                                      \
    } while (0)

/* ------------------------------------------------------------------------
 * Thread roles.
 *
 * Each library thread sets these variables in its start routine before it
 * arrives at the start latch. zks_handle.c defines them.
 * ---------------------------------------------------------------------- */

extern ZKS_HIDDEN ZKS_THREAD_LOCAL const zhandle_t *zks_tls_zh;
extern ZKS_HIDDEN ZKS_THREAD_LOCAL uint32_t zks_tls_role;

/*
 * The outbox of the dispatch loop while that loop runs, else NULL. Only
 * a thread exit unwinds a drain of this outbox, because no frame above
 * the loop catches an exception. The cleanup handler of the thread then
 * frees its items, so the drain does not requeue them.
 */
extern ZKS_HIDDEN ZKS_THREAD_LOCAL zkrs_outbox *zks_tls_dispatch_ob;

/* Returns the role of the calling thread for zh. Other threads are FOREIGN. */
static inline uint32_t zks_current_role(const zhandle_t *zh)
{
    return zks_tls_zh == zh ? zks_tls_role : ZKRS_ROLE_FOREIGN;
}

/* ------------------------------------------------------------------------
 * Default watcher pair cell.
 *
 * A spinlock keeps the watcher and its context together, so no reader sees
 * a new watcher with an old context. The lock is a leaf. No code holds it
 * around a Rust call or application code.
 * ---------------------------------------------------------------------- */

typedef struct zks_spin {
    unsigned char flag;
} zks_spin_t;

static inline void zks_spin_lock(zks_spin_t *s)
{
    while (__atomic_test_and_set(&s->flag, __ATOMIC_ACQUIRE)) {
        /* spin */
    }
}

static inline void zks_spin_unlock(zks_spin_t *s)
{
    __atomic_clear(&s->flag, __ATOMIC_RELEASE);
}

struct zks_pair {
    watcher_fn fn;
    void *ctx;
};

struct zks_watch_cell {
    zks_spin_t lock;
    watcher_fn fn; /* never NULL: zks_null_watcher is the sentinel */
    void *ctx;
};

/* The watcher that the cell holds when the application gives none. */
ZKS_HIDDEN void zks_null_watcher(zhandle_t *zh, int type, int state, const char *path,
                                 void *ctx);

static inline void zks_watch_cell_init(struct zks_watch_cell *c, watcher_fn fn, void *ctx)
{
    c->lock.flag = 0;
    c->fn = fn;
    c->ctx = ctx;
}

static inline struct zks_pair zks_watch_cell_read(struct zks_watch_cell *c)
{
    struct zks_pair p;
    zks_spin_lock(&c->lock);
    p.fn = c->fn;
    p.ctx = c->ctx;
    zks_spin_unlock(&c->lock);
    return p;
}

/* Stores fn, or the sentinel for NULL, and returns the previous watcher. */
static inline watcher_fn zks_watch_cell_set_fn(struct zks_watch_cell *c, watcher_fn fn)
{
    watcher_fn old;
    zks_spin_lock(&c->lock);
    old = c->fn;
    c->fn = fn != NULL ? fn : zks_null_watcher;
    zks_spin_unlock(&c->lock);
    return old;
}

static inline void zks_watch_cell_set_ctx(struct zks_watch_cell *c, void *ctx)
{
    zks_spin_lock(&c->lock);
    c->ctx = ctx;
    zks_spin_unlock(&c->lock);
}

/* ------------------------------------------------------------------------
 * Start latch. mt only.
 * ---------------------------------------------------------------------- */

#ifdef THREADED
struct zks_latch {
    pthread_mutex_t m;
    pthread_cond_t c;
    int remaining;
};

ZKS_HIDDEN int zks_latch_init(struct zks_latch *l, int parties);
ZKS_HIDDEN void zks_latch_arrive_and_wait(struct zks_latch *l);
ZKS_HIDDEN void zks_latch_destroy(struct zks_latch *l);
#endif

/* ------------------------------------------------------------------------
 * The handle. The tag _zhandle appears in C++ mangled names.
 * ---------------------------------------------------------------------- */

struct zks_sasl_sess; /* SASL builds only; NULL in the other builds */

struct _zhandle {
    clientid_t client_id; /* zoo_client_id() returns &zh->client_id */
    struct zks_watch_cell dw;
    ZKS_ATOMIC(log_callback_fn) log_callback; /* NULL: use the log stream */
    const zkrs_handle *core; /* C-owned strong reference */
    int flags;
    struct zks_sasl_sess *sasl;
#ifdef THREADED
    pthread_t io_thread, dispatch_thread;
    pthread_mutex_t auth_lock; /* zoo_lock_auth, zoo_unlock_auth */
    struct zks_latch start_latch; /* IO, dispatch and init thread */
#endif
};

/* ------------------------------------------------------------------------
 * Completion function cell.
 *
 * A request stores its completion as a generic function pointer. Delivery
 * reads the member that agrees with the request kind. The cast through
 * void (*)(void) is the portable conversion between function types.
 * ---------------------------------------------------------------------- */

typedef void (*zks_generic_fn)(void);

typedef union zks_fn {
    zks_generic_fn g;
    void_completion_t v;
    stat_completion_t s;
    data_completion_t d;
    strings_completion_t sl;
    strings_stat_completion_t sls;
    acl_completion_t acl;
    string_completion_t str;
    string_stat_completion_t strs;
} zks_fn;

static inline zks_fn zks_fn_make(zks_generic_fn f)
{
    zks_fn u;
    u.g = f;
    return u;
}

#define ZKS_FN(f) zks_fn_make((zks_generic_fn)(f))

/*
 * The completion value that marks a sync request. Its address
 * is the marker. zks_async.c defines it, so both flavors have it.
 */
ZKS_HIDDEN void zks_sync_marker(void);
#define ZKS_SYNC_MARKER (&zks_sync_marker)

/* ------------------------------------------------------------------------
 * Requests.
 *
 * One zks_req exists per accepted request. Rust holds its address as the
 * completion token. The token reaches C again exactly once: in a RESULT
 * item or through the discard_token vtable entry.
 * ---------------------------------------------------------------------- */

enum zks_req_mode {
    ZKS_REQ_ASYNC = 0,
    ZKS_REQ_SYNC = 1,
    ZKS_REQ_AUTH = 2
};

/* Returns the mode of a request. Only the mt sync wrappers send the marker. */
static inline unsigned zks_req_mode_of(zks_fn fn)
{
#ifdef THREADED
    if (fn.g == ZKS_SYNC_MARKER) {
        return ZKS_REQ_SYNC;
    }
#else
    ZKS_UNUSED(fn);
#endif
    return ZKS_REQ_ASYNC;
}

struct zks_sync;

struct zks_req {
    uint8_t kind; /* ZKRS_K_* */
    uint8_t mode; /* enum zks_req_mode */
    zks_fn fn;
    const void *data;
    struct zks_sync *sync; /* ZKS_REQ_SYNC only */
    /* MULTI only: the caller's results and one writer kind per op */
    zoo_op_result_t *results;
    int32_t count;
    uint8_t *op_kind;
};

/* Allocates a request. Returns NULL when malloc fails. */
ZKS_HIDDEN struct zks_req *zks_req_new(unsigned kind, unsigned mode, zks_fn fn, const void *data);
/* Frees a request and its op_kind array. NULL is a no-op. */
ZKS_HIDDEN void zks_req_free(struct zks_req *r);

/* ------------------------------------------------------------------------
 * Sync records. mt only.
 * ---------------------------------------------------------------------- */

#ifdef THREADED
struct zks_sync {
    pthread_mutex_t m;
    pthread_cond_t c;
    int refs, done, rc, failed, origin;
    uint32_t kind; /* ZKRS_K_* of the wrapper */
    char *data;
    int32_t data_len; /* -1 for a null znode */
    char *path;
    int32_t path_len;
    struct Stat stat;
    struct String_vector strs;
    struct ACL_vector acl;
    zkrs_multi_copy *ops;
    int32_t nops;
    uint8_t *op_kind;
};

/* Completes a record from a RESULT view. Runs no application code. */
ZKS_HIDDEN void zks_sync_complete(struct zks_req *r, const zkrs_result_view *v);
/* Completes a record for a local watch removal: rc ZOK, then signal. */
ZKS_HIDDEN void zks_sync_complete_local(struct zks_sync *s);
/* Completes the record of a request whose token Rust discards: rc ZCLOSING, then signal. */
ZKS_HIDDEN void zks_sync_complete_closing(struct zks_req *r);
#endif

/* ------------------------------------------------------------------------
 * Init arguments that only some builds use.
 * ---------------------------------------------------------------------- */

struct zks_tls_args {
    int tls;
    const char *ca, *cert, *key, *passwd;
};

struct zoo_sasl_params;

/* ------------------------------------------------------------------------
 * Cross-unit helpers. Each comment names the defining unit.
 * ---------------------------------------------------------------------- */

/* zks_handle.c */
ZKS_HIDDEN zhandle_t *zks_init_common(const char *host, watcher_fn fn, int recv_timeout,
                                      const clientid_t *cid, void *ctx, int flags,
                                      log_callback_fn logcb, const struct zks_tls_args *tls,
                                      const struct zoo_sasl_params *sasl);
ZKS_HIDDEN void zks_release(zhandle_t *zh, const zkrs_handle *core);
ZKS_HIDDEN void zks_secure_zero(void *p, size_t n);
extern ZKS_HIDDEN const zkrs_host_vtable zks_vtable;

/* zks_drain.c */
ZKS_HIDDEN void zks_drain(zhandle_t *zh, zkrs_outbox *ob);
ZKS_HIDDEN int zks_drive(zhandle_t *zh, const zkrs_handle *core, zkrs_step s, zkrs_outbox *ob,
                         int *rc);
ZKS_HIDDEN int zks_drive_errno(zhandle_t *zh, const zkrs_handle *core, zkrs_step s,
                               zkrs_outbox *ob, int *rc, int *err);

/* zks_async.c */
ZKS_HIDDEN int zks_submit_prepared(zhandle_t *zh, zkrs_request *rq, struct zks_req *r);
ZKS_HIDDEN int zks_aremove_watches(zhandle_t *zh, const char *path, ZooWatcherType wtype,
                                   watcher_fn w, void *wctx, int local, void_completion_t fn,
                                   const void *data, int all, int sync);

/* zks_multi.c */
ZKS_HIDDEN void zks_multi_complete(struct zks_req *r, const zkrs_result_view *v);

/* zks_threads.c (mt only) */
#ifdef THREADED
ZKS_HIDDEN int zks_start_threads(zhandle_t *zh);
ZKS_HIDDEN void zks_thread_item(zhandle_t *zh, uint32_t op, uint32_t role);
#endif

/* zks_log.c */
ZKS_HIDDEN void zks_log_emit(zhandle_t *zh, const zkrs_log_view *v);
ZKS_HIDDEN void zks_log_site(zhandle_t *zh, uint32_t site, ...);
ZKS_HIDDEN void zks_log_site_cb(log_callback_fn cb, uint32_t site, ...);

/* zks_env.c */
ZKS_HIDDEN void zks_log_env(zhandle_t *zh);

/* zks_resolve.c: formats into a per-thread buffer of 134 bytes */
ZKS_HIDDEN const char *zks_format_endpoint(const zkrs_sockaddr_view *v);

/* Host vtable entries. Each entry sets zks_in_vtable while it runs. */
ZKS_HIDDEN void zks_vt_discard_token(uintptr_t token);                           /* zks_drain.c */
ZKS_HIDDEN void zks_vt_snapshot_default_watcher(uintptr_t host, zkrs_watcher *out); /* zks_handle.c */
ZKS_HIDDEN void zks_vt_store_client_id(uintptr_t host, int64_t id, const uint8_t *passwd); /* zks_handle.c */
ZKS_HIDDEN int zks_vt_log_enabled(uint32_t level);                               /* zks_log.c */
ZKS_HIDDEN int zks_vt_conn_permute_disabled(void);                               /* zks_rng.c */
ZKS_HIDDEN long zks_vt_rng_random(void);                                         /* zks_rng.c */
ZKS_HIDDEN double zks_vt_rng_drand48(void);                                      /* zks_rng.c */
ZKS_HIDDEN void zks_vt_rng_reseed(void);                                         /* zks_rng.c */
ZKS_HIDDEN int zks_vt_resolve(const char *name, const char *port, int32_t *gai_rc,
                              void (*push)(void *sink, const zkrs_sockaddr_view *addr),
                              void (*skip)(void *sink, int32_t family), void *sink); /* zks_resolve.c */

/* ------------------------------------------------------------------------
 * C-emitted log sites.
 *
 * C emits these lines itself with real arguments. Each key names a row of
 * tests/abi/log-sites.tsv. The generated zks_log_sites.h has the keys and
 * the pinned level, func, line and format of each row. Core sites arrive
 * in LOG items and use the Rust site index.
 * ---------------------------------------------------------------------- */

#include "zks_log_sites.h"

#define ZKS_C_SITE_KEY(name, level, func, line, line_end, fmt) name,

enum zks_c_site { ZKS_C_SITES(ZKS_C_SITE_KEY) ZKS_SITE_C_COUNT };

/* The log macros take a handle or a captured callback, a site key and the
 * site arguments. The level check is inside the emitter. */
#define ZKS_LOG(...) zks_log_site(__VA_ARGS__)
#define ZKS_LOG_CB(...) zks_log_site_cb(__VA_ARGS__)

/* ------------------------------------------------------------------------
 * Debug-build handle registry.
 *
 * Rust keeps the set of live handles. In registry builds the macros call
 * it, and a failed check aborts with a message. In release builds the
 * macros are empty, so a release entry point has no registry cost.
 * ---------------------------------------------------------------------- */

#ifdef ZKS_HANDLE_REGISTRY
#define ZKS_REGISTRY_ADD(zh) ZKS_CALL_VOID(zkrs_registry_add(zh))
#define ZKS_REGISTRY_REMOVE(zh) ZKS_CALL_VOID(zkrs_registry_remove(zh))
#define ZKS_REGISTRY_CHECK(zh, func) ZKS_CALL_VOID(zkrs_registry_check((zh), (func)))
#else
#define ZKS_REGISTRY_ADD(zh) ((void)0)
#define ZKS_REGISTRY_REMOVE(zh) ((void)0)
#define ZKS_REGISTRY_CHECK(zh, func) ((void)0)
#endif

/*
 * The entry guard of an exported function. A NULL handle returns rv at
 * once. In registry builds, the guard then makes sure that the handle is
 * live, and the abort message names the entry.
 */
#define ZKS_RETURN_IF_NO_HANDLE(zh, rv)                                                            \
    do {                                                                                           \
        if ((zh) == NULL) {                                                                        \
            return rv;                                                                             \
        }                                                                                          \
        ZKS_REGISTRY_CHECK((zh), __func__);                                                        \
    } while (0)
#define ZKS_RETURN_VOID_IF_NO_HANDLE(zh) ZKS_RETURN_IF_NO_HANDLE(zh, )

/*
 * Resolves the watch flag of an entry such as zoo_aget to the default
 * watcher of the handle. Returns 0 for a NULL handle, and the entry then
 * returns ZBADARGUMENTS. The context always comes from the cell.
 */
static inline int zks_watch_arg(zhandle_t *zh, int watch, const char *func, struct zks_pair *p)
{
    ZKS_UNUSED(func); /* only the debug registry check reads it */
    if (zh == NULL) {
        return 0;
    }
    ZKS_REGISTRY_CHECK(zh, func);
    *p = zks_watch_cell_read(&zh->dw);
    if (!watch) {
        p->fn = NULL;
    }
    return 1;
}

/* ------------------------------------------------------------------------
 * Leaked legacy internals. src/zk_adaptor.h declares them, but
 * that header is not part of the shim, so the shim repeats the prototypes.
 * ---------------------------------------------------------------------- */

int zoo_lock_auth(zhandle_t *zh);
int zoo_unlock_auth(zhandle_t *zh);

/* Defined by zookeeper.c in legacy; no installed header declares them. */
void zoo_create2_op_init(zoo_op_t *op, const char *path, const char *value, int valuelen,
                         const struct ACL_vector *acl, int mode, char *path_buffer,
                         int path_buffer_len);
extern ZOOAPI const int ZOO_SSL_CONNECTING_STATE;

#endif /* ZKS_INTERNAL_H_ */
