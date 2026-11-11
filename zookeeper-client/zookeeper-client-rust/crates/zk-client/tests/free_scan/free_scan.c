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
 * The free scanner of the zeroization test in sasl_native.rs. This is
 * test code. It is never installed or shipped.
 *
 * The workspace forbids unsafe Rust, so a Rust test allocator is not
 * possible. This dylib is the equivalent. free_scan.sh inserts it into
 * the test binary with DYLD_INSERT_LIBRARIES (macOS only).
 *
 * Before each free, the scanner searches the full block for the marker
 * in ZK_FREE_SCAN_MARKER. A hit appends one line to the file in
 * ZK_FREE_SCAN_OUT. Thus a secret that is not zero before free gives a
 * line. The realloc replacement always moves the block and scans the old
 * block, so a secret buffer that grows also gives a line.
 */

#include <execinfo.h>
#include <fcntl.h>
#include <malloc/malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Appends "hit SIZE\n" to the output file. With ZK_FREE_SCAN_TRACE set, the
 * call stack follows the line. It does not allocate.
 */
static void report(size_t size)
{
    const char *out = getenv("ZK_FREE_SCAN_OUT");
    char line[40];
    char digits[24];
    size_t n = 0;
    size_t d = 0;
    int fd;

    if (out == NULL) {
        return;
    }
    do {
        digits[d++] = (char)('0' + size % 10);
        size /= 10;
    } while (size != 0 && d < sizeof digits);
    memcpy(line, "hit ", 4);
    n = 4;
    while (d > 0) {
        line[n++] = digits[--d];
    }
    line[n++] = '\n';
    fd = open(out, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd >= 0) {
        (void)write(fd, line, n);
        if (getenv("ZK_FREE_SCAN_TRACE") != NULL) {
            void *frames[48];
            int depth = backtrace(frames, 48);
            backtrace_symbols_fd(frames, depth, fd);
        }
        (void)close(fd);
    }
}

/* The marker. The constructor sets it before main runs. */
static char g_marker[256];
static size_t g_marker_len;

/*
 * Copies the marker and removes it from the environment. Otherwise each
 * process spawn of the test copies the environment and frees the copy,
 * and that gives false hits.
 */
__attribute__((constructor)) static void zkfs_init(void)
{
    const char *m = getenv("ZK_FREE_SCAN_MARKER");
    size_t len;

    if (m == NULL) {
        return;
    }
    len = strlen(m);
    if (len == 0 || len >= sizeof g_marker) {
        return;
    }
    memcpy(g_marker, m, len);
    g_marker_len = len;
    (void)unsetenv("ZK_FREE_SCAN_MARKER");
}

/* Reports a hit when the block at p holds the marker. */
static void scan(const void *p)
{
    size_t size;

    if (p == NULL || g_marker_len == 0) {
        return;
    }
    size = malloc_size(p);
    if (size >= g_marker_len && memmem(p, size, g_marker, g_marker_len) != NULL) {
        report(size);
    }
}

/* The interposed names call the real functions inside this image. */
static void zkfs_free(void *p)
{
    scan(p);
    free(p);
}

static void *zkfs_realloc(void *p, size_t n)
{
    void *q;
    size_t old;

    if (p == NULL || n == 0) {
        scan(p);
        return realloc(p, n);
    }
    q = malloc(n);
    if (q == NULL) {
        return NULL;
    }
    old = malloc_size(p);
    memcpy(q, p, old < n ? old : n);
    scan(p);
    free(p);
    return q;
}

/* The dyld interpose tuples: the replacement, then the replaced function. */
struct zkfs_interpose {
    const void *replacement;
    const void *replacee;
};

__attribute__((used)) static struct zkfs_interpose zkfs_interpose_free
    __attribute__((section("__DATA,__interpose"))) = {
        (const void *)(uintptr_t)&zkfs_free,
        (const void *)(uintptr_t)&free,
};

__attribute__((used)) static struct zkfs_interpose zkfs_interpose_realloc
    __attribute__((section("__DATA,__interpose"))) = {
        (const void *)(uintptr_t)&zkfs_realloc,
        (const void *)(uintptr_t)&realloc,
};
