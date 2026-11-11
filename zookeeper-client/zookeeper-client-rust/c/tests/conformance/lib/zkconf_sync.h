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
 * Blocking helpers for the cases that run in both flavors.
 * This is test code. It is never installed or shipped.
 *
 * The st library has no sync API (spec "single threaded driver design").
 * A case that needs a result before its next step uses these helpers.
 * Each helper has the arguments and the result of the sync call of the
 * same name.
 *
 * - mt: the helper calls the sync API. The mt trace does not change.
 * - st: the helper makes the async call and drives the poll registry
 *   until the completion runs. The completion records nothing. It copies
 *   the result into the caller outputs, as the legacy sync wrapper does.
 *   The handle must be in the registry.
 *
 * A helper waits at most 20 s. A timeout is a harness failure, and the
 * result is then ZOPERATIONTIMEOUT. A case does not call a helper from a
 * callback.
 */

#ifndef ZKCONF_SYNC_H_
#define ZKCONF_SYNC_H_

#include <zookeeper.h>

#ifdef __cplusplus
extern "C" {
#endif

int zkcs_create(zhandle_t *zh, const char *path, const char *value,
                int valuelen, const struct ACL_vector *acl, int mode,
                char *path_buffer, int path_buffer_len);
int zkcs_delete(zhandle_t *zh, const char *path, int version);
int zkcs_exists(zhandle_t *zh, const char *path, int watch,
                struct Stat *stat);
int zkcs_wexists(zhandle_t *zh, const char *path, watcher_fn watcher,
                 void *ctx, struct Stat *stat);
int zkcs_get(zhandle_t *zh, const char *path, int watch, char *buffer,
             int *buffer_len, struct Stat *stat);
int zkcs_wget(zhandle_t *zh, const char *path, watcher_fn watcher,
              void *ctx, char *buffer, int *buffer_len, struct Stat *stat);
int zkcs_set(zhandle_t *zh, const char *path, const char *buffer, int buflen,
             int version);
int zkcs_get_children(zhandle_t *zh, const char *path, int watch,
                      struct String_vector *strings);
int zkcs_wget_children(zhandle_t *zh, const char *path, watcher_fn watcher,
                       void *ctx, struct String_vector *strings);
int zkcs_get_acl(zhandle_t *zh, const char *path, struct ACL_vector *acl,
                 struct Stat *stat);
int zkcs_multi(zhandle_t *zh, int count, const zoo_op_t *ops,
               zoo_op_result_t *results);
int zkcs_remove_watches(zhandle_t *zh, const char *path,
                        ZooWatcherType wtype, watcher_fn watcher,
                        void *ctx, int local);
int zkcs_remove_all_watches(zhandle_t *zh, const char *path,
                            ZooWatcherType wtype, int local);

#ifdef __cplusplus
}
#endif

#endif /* ZKCONF_SYNC_H_ */
