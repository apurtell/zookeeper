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
 * Log output format (LG-01, LG-03..07, LG-10, LG-12; zk_log.c
 * 130-200). Mode EXACT. The case writes lines to a log stream file, reads
 * the file back and records each line in normalized form.
 *
 * Rules:
 * - LG-01: an mt stream line is "DATE TIME,MS:PID(0xTID):ZOO_LEVEL@func@
 *   line: text". The recorder checks the shape, the pid and the thread.
 *   An st line has no "(0xTID)" part (zk_log.c 165-182). The trace then
 *   shows tid=none, and a line with a tid fails the shape check.
 * - LG-03: a direct log_message call is not filtered by logLevel.
 * - LG-04: zoo_set_debug_level with 0, 1, 4, 5 and -1 sets 0/1/4/4/4.
 * - LG-05: with logLevel=5 the macros print ERROR, WARN and INFO, but not
 *   DEBUG (LOG_DEBUG tests equality).
 * - LG-06: a callback gets no trailing newline; the stream gets "\n".
 * - LG-07: the first callback line is the client environment, and none
 *   comes with ZOO_NO_LOG_CLIENTENV.
 * - LG-10: a long message is cut at 4094 bytes of line.
 * - LG-12 (DV-FIX, spec "pid per line"): legacy caches the pid, so a
 *   forked child prints the pid of the parent. Rust reads the pid for
 *   each line, so the child prints its own pid. The trace hides the pid
 *   of that line, and a DEV check asserts the result of each core.
 *
 * In st, the waits drive the session handle.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zookeeper_log.h>

static char g_path[1024];
static FILE *g_stream;
static char g_first[256];
static int g_ncb;
static size_t g_cb_len;
static int g_cb_newline;
/* LG-12: the lines from the forked child. */
static int g_child_step;

static int is_d(char c)
{
    return c >= '0' && c <= '9';
}

/* Checks one stream line and records the normalized text after the tid. */
static void record_line(const char *line)
{
    static const char shape[] = "dddd-dd-dd dd:dd:dd,ddd:";
    char tid[32];
    const char *p = line;
    const char *rest;
    char *end;
    size_t i;
    long pid;
    unsigned long t;
    int ok = 1;
    if (line[0] == '\0') {
        zkc_ev("log", "empty line");
        return;
    }
    for (i = 0; i + 1 < sizeof(shape) && ok; i++) {
        ok = shape[i] == 'd' ? is_d(p[i]) : p[i] == shape[i];
    }
    if (!ok) {
        zkc_ev("log", "bad shape: %.60s", line);
        return;
    }
    p += sizeof(shape) - 1;
    pid = strtol(p, &end, 10);
    if (end == p) {
        zkc_ev("log", "bad pid: %.60s", line);
        return;
    }
    if (zkc_is_st()) {
        /* LG-01: the st line has no thread id. */
        if (*end != ':') {
            zkc_ev("log", "bad st pid end: %.60s", line);
            return;
        }
        rest = end + 1;
        snprintf(tid, sizeof(tid), "none");
    } else {
        if (strncmp(end, "(0x", 3) != 0) {
            zkc_ev("log", "bad pid or tid: %.60s", line);
            return;
        }
        t = strtoul(end + 3, &end, 16);
        if (strncmp(end, "):", 2) != 0) {
            zkc_ev("log", "bad tid end: %.60s", line);
            return;
        }
        rest = end + 2;
        snprintf(tid, sizeof(tid), "%s",
                 t == (unsigned long)pthread_self() ? "self" : "other");
    }
    if (g_child_step) {
        zkc_dev("GLB-06",
                zkc_is_rust() ? pid != (long)getpid() : pid == (long)getpid(),
                "LG-12: the forked child printed the pid of the %s",
                pid == (long)getpid() ? "parent" : "child");
    }
    zkc_ev("log", "pid=%s tid=%s line=%d text=%.200s",
           g_child_step ? "child" : pid == (long)getpid() ? "self" : "other",
           tid, (int)strlen(line), rest);
}

/* Reads every line that the stream file holds and truncates the file. */
static void drain_stream(const char *what)
{
    char *line = malloc(16384);
    FILE *in;
    zkc_ev("step", "%s", what);
    fflush(g_stream);
    in = fopen(g_path, "r");
    if (in == NULL || line == NULL) {
        zkc_fail("cannot read %s", g_path);
        free(line);
        return;
    }
    while (fgets(line, 16384, in) != NULL) {
        size_t n = strlen(line);
        int nl = n > 0 && line[n - 1] == '\n';
        if (nl) {
            line[n - 1] = '\0';
        }
        if (strstr(line, "Client environment:") != NULL &&
            strstr(line, "zookeeper.version") == NULL) {
            continue;
        }
        record_line(line);
        if (!nl) {
            zkc_ev("log", "no newline at the end");
        }
    }
    fclose(in);
    free(line);
    if (ftruncate(fileno(g_stream), 0) != 0) {
        zkc_fail("ftruncate failed");
    }
    rewind(g_stream);
}

static void first_cb(const char *msg)
{
    const char *p = strstr(msg, "ZOO_");
    size_t n = strlen(msg);
    if (g_ncb == 0) {
        snprintf(g_first, sizeof(g_first), "%.60s", p ? p : msg);
    }
    g_ncb++;
    g_cb_len = n;
    g_cb_newline = n > 0 && msg[n - 1] == '\n';
}

static int child_log(void)
{
    LOG_ERROR(NULL, "from the forked child");
    return 0;
}

static void callback_first(int flags, const char *label)
{
    zhandle_t *zh;
    g_ncb = 0;
    g_first[0] = '\0';
    zh = zookeeper_init2(zkc_host(0), NULL, 10000, NULL, NULL, flags,
                         first_cb);
    if (zh != NULL) {
        zookeeper_close(zh);
    }
    zkc_ev("check", "%s first callback line: %s", label, g_first);
}

int main(int argc, char **argv)
{
    static const int levels[5] = {0, 1, 4, 5, -1};
    char big[5000];
    const char *out;
    zhandle_t *zh;
    int i;

    zkc_init(argc, argv, "log", 1, "EXACT", "ignore");

    /* LG-04 */
    for (i = 0; i < 5; i++) {
        zoo_set_debug_level((ZooLogLevel)levels[i]);
        zkc_ev("ret", "zoo_set_debug_level(%d) -> logLevel=%d", levels[i],
               (int)logLevel);
    }
    zoo_set_debug_level(ZOO_LOG_LEVEL_INFO);

    out = getenv("ZKCONF_OUT");
    snprintf(g_path, sizeof(g_path), "%s.stream", out ? out : "/tmp/zkconf");
    g_stream = fopen(g_path, "w+");
    if (g_stream == NULL) {
        zkc_fail("cannot open %s", g_path);
        return zkc_finish();
    }
    zoo_set_log_stream(g_stream);

    /* LG-01 and the INFO filter of the macros. */
    LOG_ERROR(NULL, "error %d", 1);
    LOG_WARN(NULL, "warn %s", "two");
    LOG_INFO(NULL, "info");
    LOG_DEBUG(NULL, "debug, filtered");
    drain_stream("macros at INFO");

    /* LG-03 */
    zoo_set_debug_level(ZOO_LOG_LEVEL_ERROR);
    log_message(NULL, ZOO_LOG_LEVEL_DEBUG, 42, "lg03", "direct debug %d", 3);
    drain_stream("direct log_message at DEBUG with logLevel=1");

    /* LG-05 */
    logLevel = (ZooLogLevel)5;
    LOG_ERROR(NULL, "e5");
    LOG_WARN(NULL, "w5");
    LOG_INFO(NULL, "i5");
    LOG_DEBUG(NULL, "d5");
    drain_stream("macros with logLevel=5");
    zoo_set_debug_level(ZOO_LOG_LEVEL_INFO);

    /* LG-10 */
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    log_message(NULL, ZOO_LOG_LEVEL_INFO, 7, "lg10", "%s", big);
    drain_stream("a 4999-byte message");

    /* LG-06: the callback form. */
    log_message(first_cb, ZOO_LOG_LEVEL_INFO, 8, "lg06", "to the callback");
    zkc_ev("check", "callback line: newline=%d len_ok=%d", g_cb_newline,
           g_cb_len > strlen("to the callback"));

    /* LG-12 */
    zkc_child("LG-12", child_log, 5000);
    g_child_step = 1;
    drain_stream("a line from a forked child");
    g_child_step = 0;

    /* Library lines on the stream: init, connect and close. */
    zh = zookeeper_init(zkc_host(0), zkc_watcher, 10000, NULL, "default", 0);
    zkc_poll_add(zh);
    zkc_await("session:CONNECTED", 1, 15000);
    zkc_poll_remove(zh);
    zookeeper_close(zh);
    drain_stream("library lines of one session");

    /* LG-07 */
    callback_first(0, "flags=0");
    callback_first(ZOO_NO_LOG_CLIENTENV, "ZOO_NO_LOG_CLIENTENV");
    drain_stream("stream after the callback handles");

    zoo_set_log_stream(NULL);
    fclose(g_stream);
    return zkc_finish();
}
