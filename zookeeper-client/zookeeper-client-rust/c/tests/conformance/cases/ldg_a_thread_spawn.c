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
 * A pthread_create failure in zookeeper_init (INIT-12, class FU).
 * Mode DEV.
 *
 * A forked child starts idle threads until pthread_create fails. Then
 * it calls zookeeper_init, which cannot start its library threads.
 *
 * - INIT-12, Rust: zookeeper_init gives NULL with errno EAGAIN, and the
 *   child exits normally.
 * - INIT-12, legacy: an assert aborts the child, or the child hangs at
 *   the start barrier under NDEBUG. The .dev file keeps the outcome.
 *
 * zkconf-skip-st: an st handle starts no threads
 */

#include "zkconf.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

static int g_pipe[2];

static void quiet_watcher(zhandle_t *zh, int type, int state,
                          const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static void quiet_log(const char *msg)
{
    (void)msg;
}

/* An idle thread. It waits on a pipe that never gets data. */
static void *idle_main(void *arg)
{
    char c;
    (void)arg;
    while (read(g_pipe[0], &c, 1) < 0 && errno == EINTR) {
    }
    return NULL;
}

/*
 * Exit codes: 0 NULL with EAGAIN (the Rust result), 1 a handle, 2 NULL
 * with another errno, 3 the thread limit was not reached.
 */
static int child_spawn_fail(void)
{
    pthread_attr_t attr;
    pthread_t t;
    zhandle_t *zh;
    int n;
    int err = 0;
    int saved;

    if (pipe(g_pipe) != 0) {
        return 4;
    }
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    for (n = 0; n < 100000; n++) {
        err = pthread_create(&t, &attr, idle_main, NULL);
        if (err != 0) {
            break;
        }
    }
    pthread_attr_destroy(&attr);
    if (err != EAGAIN) {
        return 3;
    }
    errno = 0;
    zh = zookeeper_init2(zkc_dead(), quiet_watcher, 10000, NULL, NULL, 0,
                         quiet_log);
    saved = errno;
    if (zh != NULL) {
        return 1;
    }
    return saved == EAGAIN ? 0 : 2;
}

int main(int argc, char **argv)
{
    const char *res;
    int rust;

    zkc_init(argc, argv, "ldg_a_thread_spawn", 0, "DEV", "ignore");
    rust = zkc_is_rust();
    res = zkc_child("INIT-12 thread spawn failure", child_spawn_fail, 15000);
    zkc_dev("INIT-12",
            rust ? strcmp(res, "exit:0") == 0
                 : strncmp(res, "signal:", 7) == 0 || strcmp(res, "hang") == 0,
            "zookeeper_init after pthread_create fails: %s", res);
    return zkc_finish();
}
