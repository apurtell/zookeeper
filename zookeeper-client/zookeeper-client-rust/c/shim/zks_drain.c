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
 * Outbox drain and result delivery.
 *
 * The drain runs every queued effect in C frames, so no Rust frame is
 * below an application callback. A cleanup handler gives untaken items
 * back to the handle when a callback unwinds the drain.
 */

#include "zks_internal.h"
#ifdef ZKS_WITH_SASL
#include "zks_sasl.h"
#endif

/* ---- result temporaries ---- */

/*
 * The legacy objects of one completion. The writer fills only the members
 * of the request kind. The other members stay zero, so the free calls do
 * nothing for them.
 */
struct zks_tmp {
    struct zks_req *req;
    char *val;
    int32_t val_len;
    struct String_vector sv;
    struct ACL_vector av;
    char *str;
    int32_t str_len;
};

/* Frees the temporaries as the callback left them, then the request. */
static void zks_tmp_free(struct zks_tmp *t)
{
    free(t->val);
    deallocate_String_vector(&t->sv);
    deallocate_ACL_vector(&t->av);
    free(t->str);
    zks_req_free(t->req);
}

static void zks_free_charp(char **p)
{
    free(*p);
}

static void zks_emit_logs(zhandle_t *zh, const zkrs_log_view *logs, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) {
        zks_log_emit(zh, &logs[i]);
    }
}

/*
 * Delivers one RESULT item. The cleanup handler frees the
 * temporaries and the request on return and on unwind.
 */
static void zks_deliver_result(zhandle_t *zh, uintptr_t token, const zkrs_result_view *v)
{
    struct zks_req *r = (struct zks_req *)token;
    struct zks_tmp tmp __attribute__((cleanup(zks_tmp_free)));
    struct Stat st;
    zkrs_result_dst d = ZKRS_RESULT_DST_INIT;
    /* A failed result gives each completion NULL for its result values. */
    struct Stat *stp = NULL;
    struct String_vector *svp = NULL;
    struct ACL_vector *avp = NULL;

    memset(&tmp, 0, sizeof tmp);
    memset(&st, 0, sizeof st);
    tmp.req = r;
    /* The core gives the delivery lines in legacy order. C emits them before the completion. */
    zks_emit_logs(zh, v->delivery_logs, v->n_delivery_logs);
#ifdef THREADED
    if (r->mode == ZKS_REQ_SYNC) {
        /* A sync record runs no application code. */
        zks_sync_complete(r, v);
        return;
    }
#endif
    if (r->kind == ZKRS_K_MULTI) {
        zks_multi_complete(r, v);
        return;
    }
    if (r->fn.g == NULL) {
        /* No completion. The cleanup still frees the request. */
        return;
    }
    if (!v->failed) {
        d.stat = &st;
        d.value = &tmp.val;
        d.value_len = &tmp.val_len;
        d.strings = &tmp.sv;
        d.acl = &tmp.av;
        d.str = &tmp.str;
        d.str_len = &tmp.str_len;
        ZKS_CALL_VOID(zkrs_write_result(v, &d));
        stp = &st;
        svp = &tmp.sv;
        avp = &tmp.av;
    }
    /* A failed result leaves tmp zeroed, so the value is (NULL, 0) and the string is NULL. */
    switch (r->kind) {
    case ZKRS_K_VOID:
        r->fn.v(v->rc, r->data);
        break;
    case ZKRS_K_STAT:
        r->fn.s(v->rc, stp, r->data);
        break;
    case ZKRS_K_DATA:
        /* A null znode gives (NULL, -1). */
        r->fn.d(v->rc, tmp.val, tmp.val_len, stp, r->data);
        break;
    case ZKRS_K_STRINGLIST:
        r->fn.sl(v->rc, svp, r->data);
        break;
    case ZKRS_K_STRINGLIST_STAT:
        r->fn.sls(v->rc, svp, stp, r->data);
        break;
    case ZKRS_K_ACLLIST:
        r->fn.acl(v->rc, avp, stp, r->data);
        break;
    case ZKRS_K_STRING:
        r->fn.str(v->rc, tmp.str, r->data);
        break;
    case ZKRS_K_STRING_STAT:
        r->fn.strs(v->rc, tmp.str, stp, r->data);
        break;
    default:
        break;
    }
}

/*
 * Delivers one WATCH item. The core resolved the list and its
 * order. The sentinel watcher is never called.
 */
static void zks_deliver_watch(zhandle_t *zh, const zkrs_watch_event_view *ev)
{
    char *path __attribute__((cleanup(zks_free_charp))) = NULL;
    uint32_t i;

    zks_emit_logs(zh, ev->delivery_logs, ev->n_delivery_logs);
    if (ev->n == 0) {
        /* An empty list or an unknown event type gives the lines only. */
        return;
    }
    path = ZKS_CALL(zkrs_write_path(&ev->path));
    for (i = 0; i < ev->n; i++) {
        watcher_fn w = (watcher_fn)ev->list[i].fn;
        if (w == NULL || w == zks_null_watcher) {
            continue;
        }
        w(zh, ev->type, ev->state, path, (void *)ev->list[i].ctx);
    }
}

/*
 * The legacy lock point. A thread that holds the auth lock
 * delays this point. In st both calls do nothing.
 */
static void zks_auth_lockpoint(zhandle_t *zh)
{
    zoo_lock_auth(zh);
    zoo_unlock_auth(zh);
}

#ifdef ZKS_WITH_SASL
/*
 * Gives one SASL item to the glue. The glue units exist only in
 * SASL builds, so this function is under ZKS_WITH_SASL. Rust gives SASL
 * items only when the init had SASL params, so the session exists. The
 * drain records the gen after each START that the glue did not reject.
 * A STALE result does not go back to Rust.
 */
static void zks_sasl_item(zhandle_t *zh, const zkrs_sasl_call *c)
{
    struct zks_sasl_sess *s = zh->sasl;
    zks_sasl_out out = ZKS_SASL_OUT_FAIL;

    if (s == NULL) {
        if (c->kind != ZKRS_SASL_DISPOSE) {
            ZKS_CALL_VOID(zkrs_sasl_result(zh->core, c->gen, &out));
        }
        return;
    }
    switch (c->kind) {
    case ZKRS_SASL_START:
        zks_sasl_start(s, c->gen, c->local, c->peer, &out);
        if (out.status != ZKRS_SASL_STALE) {
            zks_sasl_set_gen(s, c->gen);
        }
        break;
    case ZKRS_SASL_STEP:
        zks_sasl_step(s, c->gen, c->token, &out);
        break;
    case ZKRS_SASL_DISPOSE:
        zks_sasl_dispose(s, c->gen);
        return;
    default:
        return;
    }
    if (out.status == ZKRS_SASL_STALE) {
        return;
    }
    ZKS_CALL_VOID(zkrs_sasl_result(zh->core, c->gen, &out));
}
#endif

/*
 * Gives the untaken items back to the handle when a callback unwinds. An
 * unwind of the dispatch loop ends its thread, so its cleanup handler
 * frees the items instead.
 */
static void zks_outbox_unwind(zkrs_outbox **g)
{
    if (*g != NULL && *g != zks_tls_dispatch_ob) {
        ZKS_CALL_VOID(zkrs_outbox_requeue(*g));
    }
}

/* ---- drain and drive ---- */

ZKS_HIDDEN void zks_drain(zhandle_t *zh, zkrs_outbox *ob)
{
    /*
     * The outbox holds Rust state until the finish. In mt the requeue runs
     * masked too. In st only the calls into Rust run masked.
     */
    ZKS_HOLD_SCOPE;
    zkrs_outbox *guard __attribute__((cleanup(zks_outbox_unwind))) = ob;
    zkrs_item it;

    ZKS_ASSERT_NOT_IN_RUST();
    while (ZKS_CALL(zkrs_outbox_next(ob, &it))) {
        switch (it.type) {
        case ZKRS_ITEM_LOG:
            zks_log_emit(zh, it.log);
            break;
        case ZKRS_ITEM_RESULT:
            zks_deliver_result(zh, it.token, it.result);
            break;
        case ZKRS_ITEM_WATCH:
            zks_deliver_watch(zh, it.watch);
            break;
        case ZKRS_ITEM_AUTH_LOCKPOINT:
            zks_auth_lockpoint(zh);
            break;
#ifdef THREADED
        case ZKRS_ITEM_THREAD:
            zks_thread_item(zh, it.thread_op, it.thread_role);
            break;
#endif
#ifdef ZKS_WITH_SASL
        case ZKRS_ITEM_SASL:
            zks_sasl_item(zh, it.sasl);
            break;
#endif
        default:
            /* Rust gives SASL items only to SASL builds. */
            break;
        }
    }
    guard = NULL;
    ZKS_CALL_VOID(zkrs_outbox_finish(ob));
}

ZKS_HIDDEN int zks_drive(zhandle_t *zh, const zkrs_handle *core, zkrs_step s, zkrs_outbox *ob,
                         int *rc)
{
    return zks_drive_errno(zh, core, s, ob, rc, NULL);
}

/*
 * The st driving calls set errno as legacy does. The value
 * comes from Rust after the last step. The read comes before the drain,
 * because a callback can make a nested call or release zh.
 */
ZKS_HIDDEN int zks_drive_errno(zhandle_t *zh, const zkrs_handle *core, zkrs_step s,
                               zkrs_outbox *ob, int *rc, int *err)
{
    ZKS_HOLD_SCOPE;
    for (;;) {
        if (s != ZKRS_MORE && err != NULL) {
            *err = ZKS_CALL(zkrs_last_errno(core));
        }
        zks_drain(zh, ob);
        if (s == ZKRS_MORE) {
            s = ZKS_CALL(zkrs_resume(core, ob, rc));
            continue;
        }
        if (s == ZKRS_RELEASE) {
            /* zh and core are not valid after this call. */
            zks_release(zh, core);
        }
        return *rc;
    }
}

/* ---- vtable entry (Pure) ---- */

ZKS_HIDDEN void zks_vt_discard_token(uintptr_t token)
{
    struct zks_req *r = (struct zks_req *)token;
    int prev = zks_in_vtable;

    zks_in_vtable = 1;
#ifdef THREADED
    if (r != NULL && r->mode == ZKS_REQ_SYNC) {
        /* The waiter gets ZCLOSING. The waiter owns the record. */
        zks_sync_complete_closing(r);
    }
#endif
    zks_req_free(r);
    zks_in_vtable = prev;
}
