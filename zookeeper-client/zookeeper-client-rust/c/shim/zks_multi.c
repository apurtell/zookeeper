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
 * Multi requests.
 *
 * The five op-init helpers repeat zookeeper.c:5084-5142, with a live
 * assert. zoo_amulti gives the op array of the caller to Rust, which reads
 * it during the call. The request keeps only the results array and one
 * writer kind per op, so the application can reuse the ops at once.
 */

#include "zks_internal.h"

#include <assert.h>

/* zookeeper.c:4382-4390 */
static int zks_create_op_type(int mode, int default_op)
{
    if (mode == ZOO_CONTAINER) {
        return ZOO_CREATE_CONTAINER_OP;
    } else if (mode == ZOO_PERSISTENT_WITH_TTL || mode == ZOO_PERSISTENT_SEQUENTIAL_WITH_TTL) {
        return ZOO_CREATE_TTL_OP;
    } else {
        return default_op;
    }
}

void zoo_create_op_init(zoo_op_t *op, const char *path, const char *value, int valuelen,
                        const struct ACL_vector *acl, int mode, char *path_buffer,
                        int path_buffer_len)
{
    assert(op);
    op->type = zks_create_op_type(mode, ZOO_CREATE_OP);
    op->create_op.path = path;
    op->create_op.data = value;
    op->create_op.datalen = valuelen;
    op->create_op.acl = acl;
    op->create_op.flags = mode;
    op->create_op.ttl = 0;
    op->create_op.buf = path_buffer;
    op->create_op.buflen = path_buffer_len;
}

void zoo_create2_op_init(zoo_op_t *op, const char *path, const char *value, int valuelen,
                         const struct ACL_vector *acl, int mode, char *path_buffer,
                         int path_buffer_len)
{
    assert(op);
    op->type = zks_create_op_type(mode, ZOO_CREATE2_OP);
    op->create_op.path = path;
    op->create_op.data = value;
    op->create_op.datalen = valuelen;
    op->create_op.acl = acl;
    op->create_op.flags = mode;
    op->create_op.buf = path_buffer;
    op->create_op.buflen = path_buffer_len;
}

void zoo_delete_op_init(zoo_op_t *op, const char *path, int version)
{
    assert(op);
    op->type = ZOO_DELETE_OP;
    op->delete_op.path = path;
    op->delete_op.version = version;
}

void zoo_set_op_init(zoo_op_t *op, const char *path, const char *buffer, int buflen, int version,
                     struct Stat *stat)
{
    assert(op);
    op->type = ZOO_SETDATA_OP;
    op->set_op.path = path;
    op->set_op.data = buffer;
    op->set_op.datalen = buflen;
    op->set_op.version = version;
    op->set_op.stat = stat;
}

void zoo_check_op_init(zoo_op_t *op, const char *path, int version)
{
    assert(op);
    op->type = ZOO_CHECK_OP;
    op->check_op.path = path;
    op->check_op.version = version;
}

/* Returns 1 for the sub-op types of legacy multi (zookeeper.c:4867-4935). */
static int zks_multi_supported(int type)
{
    switch (type) {
    case ZOO_CREATE_OP:
    case ZOO_CREATE_CONTAINER_OP:
    case ZOO_DELETE_OP:
    case ZOO_SETDATA_OP:
    case ZOO_CHECK_OP:
        return 1;
    default:
        return 0;
    }
}

/* The result writer kind of a sub-op, as the legacy op_result completions. */
static uint8_t zks_multi_kind(int type)
{
    switch (type) {
    case ZOO_CREATE_OP:
    case ZOO_CREATE_CONTAINER_OP:
        return ZKRS_K_STRING;
    case ZOO_SETDATA_OP:
        return ZKRS_K_STAT;
    default:
        return ZKRS_K_VOID;
    }
}

/*
 * Allocates the multi request. It keeps the results array and one writer
 * kind per op, but not the ops. A NULL return is token 0,
 * which Rust reports as ZMARSHALLINGERROR.
 */
static struct zks_req *zks_req_new_multi(void_completion_t completion, const void *data,
                                         zoo_op_result_t *results, int count,
                                         const zoo_op_t *ops)
{
    zks_fn fn = ZKS_FN(completion);
    struct zks_req *r;
    int i;
    /* zoo_multi passes the marker and its sync record. */
    r = zks_req_new(ZKRS_K_MULTI, zks_req_mode_of(fn), fn, data);
    if (r == NULL) {
        return NULL;
    }
    r->results = results;
    if (count <= 0) {
        return r;
    }
    r->op_kind = malloc((size_t)count);
    if (r->op_kind == NULL) {
        zks_req_free(r);
        return NULL;
    }
    r->count = count;
    for (i = 0; i < count; i++) {
        r->op_kind[i] = zks_multi_kind(ops[i].type);
    }
    return r;
}

int zoo_amulti(zhandle_t *zh, int count, const zoo_op_t *ops, zoo_op_result_t *results,
               void_completion_t completion, const void *data)
{
    zkrs_request rq = ZKRS_REQUEST_INIT(ZKRS_OP_MULTI);
    struct zks_req *r;
    int i;
    ZKS_RETURN_IF_NO_HANDLE(zh, ZBADARGUMENTS);
    /* The check comes before any write. Legacy sends a negative count as an empty multi. */
    if (count < 0 || (count > 0 && (ops == NULL || results == NULL))) {
        return ZBADARGUMENTS;
    }
    /*
     * The call-time writes of zookeeper.c:4880-4912. Legacy does them for
     * every op before the first unsupported type, also after an error.
     */
    for (i = 0; i < count && zks_multi_supported(ops[i].type); i++) {
        if (ops[i].type == ZOO_CREATE_OP || ops[i].type == ZOO_CREATE_CONTAINER_OP) {
            results[i].value = ops[i].create_op.buf;
            results[i].valuelen = ops[i].create_op.buflen;
        } else if (ops[i].type == ZOO_SETDATA_OP) {
            results[i].stat = ops[i].set_op.stat;
        }
    }
    r = zks_req_new_multi(completion, data, results, count, ops);
    /*
     * Rust reads the ops in place, up to and including the first
     * unsupported type. Legacy stops at that op (zookeeper.c:4930-4939).
     */
    rq.ops = ops;
    rq.ops_len = i < count ? i + 1 : i;
    rq.count = count;
    return zks_submit_prepared(zh, &rq, r);
}

/*
 * Writes the per-op results, then calls the completion. zks_deliver_result
 * calls it and then frees the request. The results array belongs to the
 * pending multi until this point.
 */
ZKS_HIDDEN void zks_multi_complete(struct zks_req *r, const zkrs_result_view *v)
{
    ZKS_CALL_VOID(zkrs_write_multi(v, r->results, r->op_kind, r->count));
    if (r->fn.v != NULL) {
        r->fn.v(v->rc, r->data);
    }
}
