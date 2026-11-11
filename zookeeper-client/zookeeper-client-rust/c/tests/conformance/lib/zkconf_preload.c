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
 * The connect preload of the TLS cases (TL-01, TL-02, ST-17). This is
 * test code. It is never installed or shipped.
 *
 * run.sh builds this file as a dylib and inserts it with
 * DYLD_INSERT_LIBRARIES into a case that has the line
 * "zkconf-preload: connect". The dylib interposes connect(2) for both
 * cores, so a case can force the path of a non-blocking connect:
 *
 * - ZKCONF_CONNECT_EINPROGRESS: a connect that completes at once still
 *   reports EINPROGRESS. The socket is then already connected.
 * - ZKCONF_CONNECT_IMMEDIATE: a connect that reports EINPROGRESS waits
 *   up to 5 s for the result, then reports it as a synchronous result.
 * - ZKCONF_CONNECT_PASS: the real result (the default).
 *
 * The dylib also records the time of each connect call. A case finds
 * the functions with dlsym, so it also runs without the preload.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "zkconf_preload.h"

#define MAX_CALLS 256

static int g_mode = ZKCONF_CONNECT_PASS;
/* A call takes a slot from g_next. It increments g_count only after it
 * records its time, so a reader never sees a slot without a time. */
static int g_next;
static int g_count;
static long g_times[MAX_CALLS];

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void zkconf_connect_mode(int mode)
{
    __atomic_store_n(&g_mode, mode, __ATOMIC_SEQ_CST);
}

int zkconf_connect_count(void)
{
    return __atomic_load_n(&g_count, __ATOMIC_SEQ_CST);
}

long zkconf_connect_time(int index)
{
    if (index < 0 || index >= MAX_CALLS) {
        return -1;
    }
    return __atomic_load_n(&g_times[index], __ATOMIC_SEQ_CST);
}

/* Waits for a pending connect and gives its result as connect does. */
static int finish_connect(int fd)
{
    struct pollfd p;
    int err = 0;
    socklen_t len = sizeof(err);
    int rc;
    p.fd = fd;
    p.events = POLLOUT;
    p.revents = 0;
    do {
        rc = poll(&p, 1, 5000);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0) {
        errno = EINPROGRESS;
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        return -1;
    }
    if (err != 0) {
        errno = err;
        return -1;
    }
    return 0;
}

static int zkconf_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    int mode = __atomic_load_n(&g_mode, __ATOMIC_SEQ_CST);
    int nonblock = (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0;
    int i = __atomic_fetch_add(&g_next, 1, __ATOMIC_SEQ_CST);
    /* The interposed name calls the real connect inside this image. */
    int rc = connect(fd, addr, len);
    int saved = errno;
    if (i >= 0 && i < MAX_CALLS) {
        __atomic_store_n(&g_times[i], now_ms(), __ATOMIC_SEQ_CST);
    }
    __atomic_fetch_add(&g_count, 1, __ATOMIC_SEQ_CST);
    errno = saved;
    if (!nonblock) {
        return rc;
    }
    if (mode == ZKCONF_CONNECT_EINPROGRESS && rc == 0) {
        errno = EINPROGRESS;
        return -1;
    }
    if (mode == ZKCONF_CONNECT_IMMEDIATE && rc == -1 && errno == EINPROGRESS) {
        return finish_connect(fd);
    }
    return rc;
}

/* The dyld interpose tuple: the replacement, then the replaced function. */
__attribute__((used)) static struct {
    const void *replacement;
    const void *replacee;
} zkconf_interpose_connect __attribute__((section("__DATA,__interpose"))) = {
    (const void *)(uintptr_t)&zkconf_connect,
    (const void *)(uintptr_t)&connect,
};
