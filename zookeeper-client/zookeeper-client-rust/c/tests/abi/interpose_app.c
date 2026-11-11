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
 * The application of the interposition test. It calls
 * the wrapped functions directly, and it calls the functions that wrap
 * them inside the library (zoo_aget, zoo_get, zoo_create and others).
 * interpose.c counts the calls that it sees. The runner compares the
 * counts of the two cores.
 *
 * Usage: interpose_app HOST
 * HOST must have a server. Each wait is bounded.
 *
 * The st build has no sync calls. It makes the test node with an async
 * call, and its waits drive the caller event loop.
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <zookeeper.h>

static int failures;
static volatile int done;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
            failures++;                                                   \
        }                                                                 \
    } while (0)

static void sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

#ifdef THREADED
/* Lets the library threads work for about 20 ms. */
static void drive(zhandle_t *zh)
{
    (void)zh;
    sleep_ms(20);
}
#else
/* Does one pass of the st event loop for at most 20 ms. */
static void drive(zhandle_t *zh)
{
    struct timeval tv = {0, 0};
    fd_set rd;
    fd_set wr;
    int fd = -1;
    int interest = 0;
    int events = 0;
    int rc = zookeeper_interest(zh, &fd, &interest, &tv);

    if (rc != ZOK || fd < 0 || fd >= FD_SETSIZE) {
        sleep_ms(rc == ZOK ? 1 : 20);
        return;
    }
    if (tv.tv_sec > 0 || tv.tv_usec > 20000) {
        tv.tv_sec = 0;
        tv.tv_usec = 20000;
    }
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    if (interest & ZOOKEEPER_READ) {
        FD_SET(fd, &rd);
    }
    if (interest & ZOOKEEPER_WRITE) {
        FD_SET(fd, &wr);
    }
    if (select(fd + 1, &rd, &wr, NULL, &tv) > 0) {
        events |= FD_ISSET(fd, &rd) ? ZOOKEEPER_READ : 0;
        events |= FD_ISSET(fd, &wr) ? ZOOKEEPER_WRITE : 0;
    }
    zookeeper_process(zh, events);
}
#endif

/* Waits up to 10 s for the completion count to reach want. */
static int wait_done(zhandle_t *zh, int want)
{
    int i;
    for (i = 0; i < 500; i++) {
        if (__atomic_load_n(&done, __ATOMIC_SEQ_CST) >= want) {
            return 1;
        }
        drive(zh);
    }
    return 0;
}

static void bump(void)
{
    __atomic_fetch_add(&done, 1, __ATOMIC_SEQ_CST);
}

static void noop_watcher(zhandle_t *zh, int type, int state, const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static void data_done(int rc, const char *v, int vl, const struct Stat *st, const void *d)
{
    (void)rc;
    (void)v;
    (void)vl;
    (void)st;
    (void)d;
    bump();
}

static void stat_done(int rc, const struct Stat *st, const void *d)
{
    (void)rc;
    (void)st;
    (void)d;
    bump();
}

static void void_done(int rc, const void *d)
{
    (void)rc;
    (void)d;
    bump();
}

static void string_done(int rc, const char *v, const void *d)
{
    (void)rc;
    (void)v;
    (void)d;
    bump();
}

static void strings_done(int rc, const struct String_vector *s, const void *d)
{
    (void)rc;
    (void)s;
    (void)d;
    bump();
}

static void acl_done(int rc, struct ACL_vector *acl, struct Stat *st, const void *d)
{
    (void)rc;
    (void)acl;
    (void)st;
    (void)d;
    bump();
}

int main(int argc, char **argv)
{
    char path[64];
    char child[80];
    int want = 0;
#ifdef THREADED
    char buf[64];
    int len;
    struct Stat st;
    struct String_vector sv;
    struct ACL_vector acl;
    zoo_op_t ops[1];
    zoo_op_result_t res[1];
#endif
    zhandle_t *zh;
    int i;

    if (argc != 2) {
        fprintf(stderr, "usage: interpose_app HOST\n");
        return 2;
    }
#ifndef THREADED
    /* The caller thread writes the socket, so a reset must not stop it. */
    signal(SIGPIPE, SIG_IGN);
#endif
    zoo_set_debug_level(0);
    zh = zookeeper_init(argv[1], noop_watcher, 10000, NULL, NULL, 0);
    if (zh == NULL) {
        printf("FAIL zookeeper_init\n");
        return 1;
    }
    for (i = 0; i < 500 && zoo_state(zh) != ZOO_CONNECTED_STATE; i++) {
        drive(zh);
    }
    CHECK(zoo_state(zh) == ZOO_CONNECTED_STATE);
    snprintf(path, sizeof(path), "/zk-interpose-%ld", (long)getpid());
    snprintf(child, sizeof(child), "%s/c", path);

#ifdef THREADED
    /* The synchronous calls. */
    CHECK(zoo_create(zh, path, "ab", 2, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0) == ZOK);
    CHECK(zoo_exists(zh, path, 0, &st) == ZOK);
    len = (int)sizeof(buf);
    CHECK(zoo_get(zh, path, 0, buf, &len, &st) == ZOK);
    CHECK(zoo_set(zh, path, "cd", 2, -1) == ZOK);
    CHECK(zoo_get_children(zh, path, 0, &sv) == ZOK);
    deallocate_String_vector(&sv);
    CHECK(zoo_get_children2(zh, path, 0, &sv, &st) == ZOK);
    deallocate_String_vector(&sv);
    CHECK(zoo_get_acl(zh, path, &acl, &st) == ZOK);
    deallocate_ACL_vector(&acl);
    CHECK(zoo_set_acl(zh, path, -1, &ZOO_OPEN_ACL_UNSAFE) == ZOK);
    zoo_create_op_init(&ops[0], child, "x", 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
    CHECK(zoo_multi(zh, 1, ops, res) == ZOK);
    CHECK(zoo_delete(zh, child, -1) == ZOK);
#else
    CHECK(zoo_acreate(zh, path, "ab", 2, &ZOO_OPEN_ACL_UNSAFE, 0, string_done, NULL) == ZOK);
    want += 1;
    CHECK(wait_done(zh, want));
#endif

    /* The asynchronous calls of the wrappers inside the library. */
    CHECK(zoo_aget(zh, path, 0, data_done, NULL) == ZOK);
    CHECK(zoo_aexists(zh, path, 0, stat_done, NULL) == ZOK);
    CHECK(zoo_aget_children(zh, path, 0, strings_done, NULL) == ZOK);
    CHECK(zoo_acreate(zh, child, "y", 1, &ZOO_OPEN_ACL_UNSAFE, 0, string_done, NULL) == ZOK);
    want += 4;
    CHECK(wait_done(zh, want));

    /* The direct calls of the wrapped functions. */
    CHECK(zoo_awget(zh, path, noop_watcher, NULL, data_done, NULL) == ZOK);
    CHECK(zoo_awexists(zh, path, noop_watcher, NULL, stat_done, NULL) == ZOK);
    CHECK(zoo_aget_acl(zh, path, acl_done, NULL) == ZOK);
    CHECK(zoo_aset(zh, path, "ef", 2, -1, stat_done, NULL) == ZOK);
    CHECK(zoo_adelete(zh, child, -1, void_done, NULL) == ZOK);
    want += 5;
    CHECK(wait_done(zh, want));
#ifdef THREADED
    CHECK(zoo_delete(zh, path, -1) == ZOK);
#else
    CHECK(zoo_adelete(zh, path, -1, void_done, NULL) == ZOK);
    want += 1;
    CHECK(wait_done(zh, want));
#endif

    CHECK(zookeeper_close(zh) == ZOK);
    printf("interpose_app: %d failures\n", failures);
    return failures == 0 ? 0 : 1;
}
