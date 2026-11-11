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
 * Runtime ABI tests of the public C API (spec "The C
 * Compatibility Layer").
 *
 * The program links with -lzookeeper_mt or -lzookeeper_st as an
 * application does. The st build has no THREADED and no sync API, and
 * its waits drive the zookeeper_interest and zookeeper_process loop.
 * Each mode prints a transcript to stdout and gives a non-zero exit
 * status when a rule fails. The runner compares the "common" and "server"
 * transcripts of the Rust core and the legacy core. The "dev" mode
 * checks the registered deviations of the Rust core, so it runs only
 * against the Rust core.
 *
 * Usage: runtime_abi common
 *        runtime_abi dev UNUSED_HOST:PORT
 *        runtime_abi server HOST:PORT
 *        runtime_abi logging UNUSED_HOST:PORT
 *
 * Ledger: ABI-01, DV-FIX-6, LOG-01, LOG-15
 * Ledger: NUL-01, NUL-02, NUL-03, NUL-04, NUL-07
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <zookeeper.h>
#include <zookeeper_log.h>
#include <zookeeper_version.h>

/* ZOO_SSL_CONNECTING_STATE is exported but no installed header declares
 * it (abi/symbols.tsv, ABI-01). */
extern ZOOAPI const int ZOO_SSL_CONNECTING_STATE;

/* zookeeper.h declares these two only without THREADED, but the mt
 * library exports them too (abi/symbols.tsv). */
#ifdef THREADED
ZOOAPI int zookeeper_interest(zhandle_t *zh, int *fd, int *interest, struct timeval *tv);
ZOOAPI int zookeeper_process(zhandle_t *zh, int events);
#endif

static int failures;

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("FAIL %s:%d: ", __func__, __LINE__);                     \
            printf(__VA_ARGS__);                                            \
            printf("\n");                                                   \
            failures++;                                                     \
        }                                                                   \
    } while (0)

/* ---- helpers ---- */

/* Sleeps for ms milliseconds. */
static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* Runs fn(arg) in a child process. Returns "ok" when the child exits
 * with status 0, "fault" when SIGSEGV or SIGBUS stops it, "abort" for
 * SIGABRT, and "other" for any other result. */
static const char *in_child(void (*fn)(void *), void *arg)
{
    int status = 0;
    pid_t pid;

    fflush(stdout);
    fflush(stderr);
    pid = fork();
    if (pid < 0) {
        return "fork-failed";
    }
    if (pid == 0) {
        fn(arg);
        _exit(0);
    }
    if (waitpid(pid, &status, 0) != pid) {
        return "wait-failed";
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return "ok";
    }
    if (WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS)) {
        return "fault";
    }
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT) {
        return "abort";
    }
    return "other";
}

/* Writes through a const object. The volatile pointer keeps the store. */
static void write_const_int(void *arg)
{
    volatile int *p = (volatile int *)arg;
    *p = 12345;
}

static void write_first_char(void *arg)
{
    volatile char *p = (volatile char *)arg;
    *p = 'X';
}

static void noop_watcher(zhandle_t *zh, int type, int state, const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static void noop_stat(int rc, const struct Stat *stat, const void *data)
{
    (void)rc;
    (void)stat;
    (void)data;
}

static void noop_data(int rc, const char *value, int len, const struct Stat *stat, const void *data)
{
    (void)rc;
    (void)value;
    (void)len;
    (void)stat;
    (void)data;
}

static void print_acl_vector(const char *name, const struct ACL_vector *v)
{
    int i;
    printf("%s: sizeof=%lu count=%d\n", name, (unsigned long)sizeof(*v), v->count);
    for (i = 0; i < v->count; i++) {
        printf("%s[%d]: perms=%d scheme=%s id=%s\n", name, i, v->data[i].perms,
               v->data[i].id.scheme, v->data[i].id.id);
    }
}

#ifdef THREADED
/* Lets the library threads work for about 20 ms. */
static void drive(zhandle_t *zh)
{
    (void)zh;
    sleep_ms(20);
}
#else
/* Does one pass of the st event loop for at most 20 ms. The caller
 * thread does all the I/O and runs all the callbacks. */
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

/* Waits up to ms milliseconds for the handle to reach state. */
static int wait_state(zhandle_t *zh, int state, int ms)
{
    int waited = 0;
    while (zoo_state(zh) != state && waited < ms) {
        drive(zh);
        waited += 20;
    }
    return zoo_state(zh) == state;
}

/* ---- common mode: both cores, compared by the runner ---- */

/* Rule: the 30 read-only exports are const int
 * objects with the legacy values. The values are part of the ABI. */
static void common_constants(void)
{
#define ZK_INT(n) printf("int %s=%d sizeof=%lu\n", #n, n, (unsigned long)sizeof(n))
    ZK_INT(ZOOKEEPER_READ);
    ZK_INT(ZOOKEEPER_WRITE);
    ZK_INT(ZOO_ASSOCIATING_STATE);
    ZK_INT(ZOO_AUTH_FAILED_STATE);
    ZK_INT(ZOO_CHANGED_EVENT);
    ZK_INT(ZOO_CHILD_EVENT);
    ZK_INT(ZOO_CONNECTED_STATE);
    ZK_INT(ZOO_CONNECTING_STATE);
    ZK_INT(ZOO_CONTAINER);
    ZK_INT(ZOO_CREATED_EVENT);
    ZK_INT(ZOO_DELETED_EVENT);
    ZK_INT(ZOO_EPHEMERAL);
    ZK_INT(ZOO_EPHEMERAL_SEQUENTIAL);
    ZK_INT(ZOO_EXPIRED_SESSION_STATE);
    ZK_INT(ZOO_NOTCONNECTED_STATE);
    ZK_INT(ZOO_NOTWATCHING_EVENT);
    ZK_INT(ZOO_PERM_ADMIN);
    ZK_INT(ZOO_PERM_ALL);
    ZK_INT(ZOO_PERM_CREATE);
    ZK_INT(ZOO_PERM_DELETE);
    ZK_INT(ZOO_PERM_READ);
    ZK_INT(ZOO_PERM_WRITE);
    ZK_INT(ZOO_PERSISTENT);
    ZK_INT(ZOO_PERSISTENT_SEQUENTIAL);
    ZK_INT(ZOO_PERSISTENT_SEQUENTIAL_WITH_TTL);
    ZK_INT(ZOO_PERSISTENT_WITH_TTL);
    ZK_INT(ZOO_READONLY_STATE);
    ZK_INT(ZOO_SEQUENCE);
    ZK_INT(ZOO_SESSION_EVENT);
    ZK_INT(ZOO_SSL_CONNECTING_STATE);
#undef ZK_INT
}

/* Rule: the five writable records have
 * the legacy contents. The records are writable, but the strings in
 * them are literals, so a write to a string faults. */
static void common_records(void)
{
    int saved;

    print_acl_vector("ZOO_OPEN_ACL_UNSAFE", &ZOO_OPEN_ACL_UNSAFE);
    print_acl_vector("ZOO_READ_ACL_UNSAFE", &ZOO_READ_ACL_UNSAFE);
    print_acl_vector("ZOO_CREATOR_ALL_ACL", &ZOO_CREATOR_ALL_ACL);
    printf("ZOO_ANYONE_ID_UNSAFE: sizeof=%lu scheme=%s id=%s\n",
           (unsigned long)sizeof(ZOO_ANYONE_ID_UNSAFE), ZOO_ANYONE_ID_UNSAFE.scheme,
           ZOO_ANYONE_ID_UNSAFE.id);
    printf("ZOO_AUTH_IDS: sizeof=%lu scheme=%s id=%s\n", (unsigned long)sizeof(ZOO_AUTH_IDS),
           ZOO_AUTH_IDS.scheme, ZOO_AUTH_IDS.id);

    /* The ACL vectors are writable data. */
    saved = ZOO_OPEN_ACL_UNSAFE.data[0].perms;
    ZOO_OPEN_ACL_UNSAFE.data[0].perms = ZOO_PERM_READ;
    CHECK(ZOO_OPEN_ACL_UNSAFE.data[0].perms == ZOO_PERM_READ, "ACL entry is not writable");
    ZOO_OPEN_ACL_UNSAFE.data[0].perms = saved;

    printf("write ZOO_PERM_READ: %s\n", in_child(write_const_int, (void *)&ZOO_PERM_READ));
    printf("write ZOO_CONNECTED_STATE: %s\n",
           in_child(write_const_int, (void *)&ZOO_CONNECTED_STATE));
    printf("write ZOO_ANYONE_ID_UNSAFE.scheme[0]: %s\n",
           in_child(write_first_char, ZOO_ANYONE_ID_UNSAFE.scheme));
    printf("write ZOO_OPEN_ACL_UNSAFE.data[0].id.id[0]: %s\n",
           in_child(write_first_char, ZOO_OPEN_ACL_UNSAFE.data[0].id.id));
}

/* Rule (LOG-01): logLevel is one writable
 * 4-byte object that the application and the library share. Its default
 * is INFO, and zoo_set_debug_level writes the same object. */
static void common_loglevel(void)
{
    printf("logLevel: sizeof=%lu default=%d\n", (unsigned long)sizeof(logLevel), (int)logLevel);
    logLevel = ZOO_LOG_LEVEL_DEBUG;
    CHECK(logLevel == ZOO_LOG_LEVEL_DEBUG, "logLevel is not writable");
    zoo_set_debug_level((ZooLogLevel)0);
    printf("after zoo_set_debug_level(0): %d\n", (int)logLevel);
    zoo_set_debug_level((ZooLogLevel)9);
    printf("after zoo_set_debug_level(9): %d\n", (int)logLevel);
    zoo_set_debug_level(ZOO_LOG_LEVEL_WARN);
    printf("after zoo_set_debug_level(WARN): %d\n", (int)logLevel);
    logLevel = ZOO_LOG_LEVEL_INFO;
}

/* Rule (LOG-15): zerror gives the legacy text for
 * every code, and strerror for a positive code. -15 is the DV-FIX-6 row
 * and the dev mode checks it. */
static void common_zerror(void)
{
    int c;
    for (c = -200; c <= 200; c++) {
        if (c == ZSSLCONNECTIONERROR) {
            continue;
        }
        printf("zerror(%d)=%s\n", c, zerror(c));
    }
}

/* Rule (LOG-15): one version source. */
static void common_version(void)
{
    printf("ZOO_VERSION=%s zoo_version_str=%s\n", ZOO_VERSION, zoo_version_str());
    CHECK(strcmp(ZOO_VERSION, zoo_version_str()) == 0, "version strings differ");
}

/* Rule (NUL-07, NUL-01 w* variants): the accessors that legacy
 * already makes NULL-safe keep their results. The st library does not
 * have the sync calls. */
static void common_null_safe(void)
{
    struct Stat st;
    int interest = 0;
    int fd = -1;
    struct timeval tv;
#ifdef THREADED
    char buf[8];
    int len = (int)sizeof(buf);
    struct String_vector sv;
#endif

    printf("zoo_state(NULL)=%d\n", zoo_state(NULL));
    zoo_set_context(NULL, &st);
    printf("zoo_get_log_callback(NULL)=%s\n", zoo_get_log_callback(NULL) == NULL ? "NULL" : "set");
    zoo_set_log_callback(NULL, NULL);
    printf("zookeeper_close(NULL)=%d\n", zookeeper_close(NULL));
    printf("zookeeper_interest(NULL)=%d\n", zookeeper_interest(NULL, &fd, &interest, &tv));
    printf("zookeeper_process(NULL)=%d\n", zookeeper_process(NULL, 0));
#ifdef THREADED
    printf("zoo_create(NULL)=%d\n",
           zoo_create(NULL, "/a", NULL, -1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0));
#endif
    printf("zoo_awget(NULL)=%d\n", zoo_awget(NULL, "/a", NULL, NULL, noop_data, NULL));
    printf("zoo_awexists(NULL)=%d\n", zoo_awexists(NULL, "/a", NULL, NULL, noop_stat, NULL));
#ifdef THREADED
    printf("zoo_wget(NULL)=%d\n", zoo_wget(NULL, "/a", NULL, NULL, buf, &len, &st));
    printf("zoo_wexists(NULL)=%d\n", zoo_wexists(NULL, "/a", NULL, NULL, &st));
    printf("zoo_wget_children(NULL)=%d\n", zoo_wget_children(NULL, "/a", NULL, NULL, &sv));
    printf("zoo_delete(NULL)=%d\n", zoo_delete(NULL, "/a", -1));
    printf("zoo_set(NULL)=%d\n", zoo_set(NULL, "/a", "x", 1, -1));
#endif
}

static int run_common(void)
{
    common_constants();
    common_records();
    common_loglevel();
    common_zerror();
    common_version();
    common_null_safe();
    return 0;
}

/* ---- logging mode: both cores ---- */

/* Counts the lines of f that contain needle. */
static int count_lines(FILE *f, const char *needle)
{
    char line[4096];
    int n = 0;
    rewind(f);
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, needle) != NULL) {
            n++;
        }
    }
    return n;
}

#ifdef THREADED
/* start_threads writes its DEBUG line in the calling thread, so the line
 * is in the file when zookeeper_init returns. */
#define LIB_DEBUG_LINE "ZOO_DEBUG@start_threads@"
#else
/* The first zookeeper_interest call starts a connection and writes this
 * DEBUG line in the caller thread. */
#define LIB_DEBUG_LINE "[zk] connect()"
#endif

/* Opens a handle to host, closes it, and counts the log lines. */
static void log_session(const char *host, ZooLogLevel level, const char *label)
{
    FILE *f = tmpfile();
    zhandle_t *zh;
    int debug_app;
#ifndef THREADED
    struct timeval tv;
    int fd = -1;
    int interest = 0;
#endif

    if (f == NULL) {
        CHECK(0, "tmpfile: %s", strerror(errno));
        return;
    }
    zoo_set_log_stream(f);
    /* The application writes logLevel directly, as the ABI allows. */
    logLevel = level;
    zh = zookeeper_init(host, noop_watcher, 10000, NULL, NULL, 0);
    CHECK(zh != NULL, "zookeeper_init failed");
    if (zh != NULL) {
#ifndef THREADED
        CHECK(zookeeper_interest(zh, &fd, &interest, &tv) == ZOK, "zookeeper_interest failed");
#endif
        zookeeper_close(zh);
    }
    /* The application macro reads the same object. */
    LOG_DEBUG(NULL, "application debug line");
    fflush(f);
    debug_app = count_lines(f, "application debug line");
    printf("%s: lines=%s info=%s lib_debug=%s any_debug=%s debug_app=%d\n", label,
           count_lines(f, "") > 0 ? "some" : "none",
           count_lines(f, "Initiating client connection") > 0 ? "yes" : "no",
           count_lines(f, LIB_DEBUG_LINE) > 0 ? "yes" : "no",
           count_lines(f, "ZOO_DEBUG@") > 0 ? "yes" : "no", debug_app);
    zoo_set_log_stream(NULL);
    fclose(f);
}

/* Rule (LOG-01): the library reads the logLevel object
 * that the application writes, at every site, with no cached copy. */
static int run_logging(const char *host)
{
    log_session(host, (ZooLogLevel)0, "level 0");
    log_session(host, ZOO_LOG_LEVEL_ERROR, "level ERROR");
    log_session(host, ZOO_LOG_LEVEL_INFO, "level INFO");
    log_session(host, ZOO_LOG_LEVEL_DEBUG, "level DEBUG");
    logLevel = ZOO_LOG_LEVEL_INFO;
    return 0;
}

/* ---- server mode: both cores, a real server ---- */

/* Rule: the application changes ZOO_OPEN_ACL_UNSAFE in
 * place, and the library sends the changed ACL. The rule (spec line 538)
 * on value lengths: -1 stores a null payload and 0 an empty one. */
#ifdef THREADED
static int run_server(const char *host)
{
    struct ACL_vector acl;
    struct Stat st;
    char buf[16];
    char path[64];
    int len;
    int rc;
    int saved;
    zhandle_t *zh;

    logLevel = ZOO_LOG_LEVEL_ERROR;
    zh = zookeeper_init(host, noop_watcher, 10000, NULL, NULL, 0);
    if (zh == NULL || !wait_state(zh, ZOO_CONNECTED_STATE, 10000)) {
        printf("FAIL: no session with %s\n", host);
        return 1;
    }
    snprintf(path, sizeof(path), "/zk-abi-%ld", (long)getpid());

    saved = ZOO_OPEN_ACL_UNSAFE.data[0].perms;
    ZOO_OPEN_ACL_UNSAFE.data[0].perms = ZOO_PERM_READ | ZOO_PERM_WRITE | ZOO_PERM_DELETE;
    rc = zoo_create(zh, path, "v", 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
    ZOO_OPEN_ACL_UNSAFE.data[0].perms = saved;
    printf("create with changed ACL: %s\n", zerror(rc));
    memset(&acl, 0, sizeof(acl));
    rc = zoo_get_acl(zh, path, &acl, &st);
    printf("get_acl: %s count=%d perms=%d\n", zerror(rc), acl.count,
           acl.count > 0 ? acl.data[0].perms : -1);
    CHECK(rc == ZOK && acl.count == 1
              && acl.data[0].perms == (ZOO_PERM_READ | ZOO_PERM_WRITE | ZOO_PERM_DELETE),
          "the server did not get the changed ACL");
    deallocate_ACL_vector(&acl);

    rc = zoo_set(zh, path, "ignored", -1, -1);
    len = (int)sizeof(buf);
    rc = rc == ZOK ? zoo_get(zh, path, 0, buf, &len, &st) : rc;
    printf("set len -1: %s buffer_len=%d dataLength=%d\n", zerror(rc), len, st.dataLength);
    rc = zoo_set(zh, path, NULL, 0, -1);
    len = (int)sizeof(buf);
    rc = rc == ZOK ? zoo_get(zh, path, 0, buf, &len, &st) : rc;
    printf("set len 0: %s buffer_len=%d dataLength=%d\n", zerror(rc), len, st.dataLength);
    rc = zoo_set(zh, path, "abc", 3, -1);
    len = 2;
    rc = rc == ZOK ? zoo_get(zh, path, 0, buf, &len, &st) : rc;
    printf("get into 2 bytes: %s buffer_len=%d bytes=%.2s dataLength=%d\n", zerror(rc), len, buf,
           st.dataLength);

    rc = zoo_delete(zh, path, -1);
    printf("delete: %s\n", zerror(rc));
    printf("is_unrecoverable(connected)=%d\n", is_unrecoverable(zh));
    rc = zookeeper_close(zh);
    printf("close: %s\n", zerror(rc));
    return 0;
}
#endif

#ifndef THREADED
/* The result of one async request in the st server mode. */
struct result {
    int done;
    int rc;
    int len;
    int data_length;
    int count;
    int perms;
    char bytes[16];
};

static void result_string(int rc, const char *value, const void *data)
{
    struct result *r = (struct result *)data;
    (void)value;
    r->rc = rc;
    r->done = 1;
}

static void result_stat(int rc, const struct Stat *stat, const void *data)
{
    struct result *r = (struct result *)data;
    (void)stat;
    r->rc = rc;
    r->done = 1;
}

static void result_void(int rc, const void *data)
{
    struct result *r = (struct result *)data;
    r->rc = rc;
    r->done = 1;
}

static void result_data(int rc, const char *value, int len, const struct Stat *stat,
                        const void *data)
{
    struct result *r = (struct result *)data;
    r->rc = rc;
    r->len = len;
    r->data_length = stat != NULL ? stat->dataLength : -1;
    memset(r->bytes, 0, sizeof(r->bytes));
    if (value != NULL && len > 0) {
        size_t n = (size_t)len < sizeof(r->bytes) - 1 ? (size_t)len : sizeof(r->bytes) - 1;
        memcpy(r->bytes, value, n);
    }
    r->done = 1;
}

static void result_acl(int rc, struct ACL_vector *acl, struct Stat *stat, const void *data)
{
    struct result *r = (struct result *)data;
    (void)stat;
    r->rc = rc;
    r->count = acl != NULL ? acl->count : -1;
    r->perms = acl != NULL && acl->count > 0 ? acl->data[0].perms : -1;
    r->done = 1;
}

/* Drives the event loop until the request completes. rc is the submit
 * result. A failed submit or a timeout gives a non-ZOK code. */
static int await_result(zhandle_t *zh, int rc, struct result *r)
{
    int waited = 0;
    if (rc != ZOK) {
        return rc;
    }
    while (!r->done && waited < 10000) {
        drive(zh);
        waited += 20;
    }
    return r->done ? r->rc : ZOPERATIONTIMEOUT;
}

/* The st form of the server mode. It uses the async calls and the
 * caller event loop, and it checks the same rules as the mt form. The
 * async get gives the value length and not a buffer length. */
static int run_server(const char *host)
{
    struct result r;
    char path[64];
    int rc;
    int saved;
    zhandle_t *zh;

    signal(SIGPIPE, SIG_IGN);
    logLevel = ZOO_LOG_LEVEL_ERROR;
    zh = zookeeper_init(host, noop_watcher, 10000, NULL, NULL, 0);
    if (zh == NULL || !wait_state(zh, ZOO_CONNECTED_STATE, 10000)) {
        printf("FAIL: no session with %s\n", host);
        return 1;
    }
    snprintf(path, sizeof(path), "/zk-abi-%ld", (long)getpid());

    /* The library encodes the ACL at the submit, so the test restores
     * the record after the submit. */
    saved = ZOO_OPEN_ACL_UNSAFE.data[0].perms;
    ZOO_OPEN_ACL_UNSAFE.data[0].perms = ZOO_PERM_READ | ZOO_PERM_WRITE | ZOO_PERM_DELETE;
    memset(&r, 0, sizeof(r));
    rc = zoo_acreate(zh, path, "v", 1, &ZOO_OPEN_ACL_UNSAFE, 0, result_string, &r);
    ZOO_OPEN_ACL_UNSAFE.data[0].perms = saved;
    rc = await_result(zh, rc, &r);
    printf("create with changed ACL: %s\n", zerror(rc));
    memset(&r, 0, sizeof(r));
    rc = await_result(zh, zoo_aget_acl(zh, path, result_acl, &r), &r);
    printf("get_acl: %s count=%d perms=%d\n", zerror(rc), r.count, r.perms);
    CHECK(rc == ZOK && r.count == 1
              && r.perms == (ZOO_PERM_READ | ZOO_PERM_WRITE | ZOO_PERM_DELETE),
          "the server did not get the changed ACL");

    memset(&r, 0, sizeof(r));
    rc = await_result(zh, zoo_aset(zh, path, "ignored", -1, -1, result_stat, &r), &r);
    memset(&r, 0, sizeof(r));
    rc = rc == ZOK ? await_result(zh, zoo_aget(zh, path, 0, result_data, &r), &r) : rc;
    printf("set len -1: %s value_len=%d dataLength=%d\n", zerror(rc), r.len, r.data_length);
    memset(&r, 0, sizeof(r));
    rc = await_result(zh, zoo_aset(zh, path, NULL, 0, -1, result_stat, &r), &r);
    memset(&r, 0, sizeof(r));
    rc = rc == ZOK ? await_result(zh, zoo_aget(zh, path, 0, result_data, &r), &r) : rc;
    printf("set len 0: %s value_len=%d dataLength=%d\n", zerror(rc), r.len, r.data_length);
    memset(&r, 0, sizeof(r));
    rc = await_result(zh, zoo_aset(zh, path, "abc", 3, -1, result_stat, &r), &r);
    memset(&r, 0, sizeof(r));
    rc = rc == ZOK ? await_result(zh, zoo_aget(zh, path, 0, result_data, &r), &r) : rc;
    printf("set abc: %s value_len=%d bytes=%s dataLength=%d\n", zerror(rc), r.len, r.bytes,
           r.data_length);

    memset(&r, 0, sizeof(r));
    rc = await_result(zh, zoo_adelete(zh, path, -1, result_void, &r), &r);
    printf("delete: %s\n", zerror(rc));
    printf("is_unrecoverable(connected)=%d\n", is_unrecoverable(zh));
    rc = zookeeper_close(zh);
    printf("close: %s\n", zerror(rc));
    return 0;
}
#endif

/* ---- dev mode: the Rust core only ---- */

static int completions;

static void count_stat(int rc, const struct Stat *stat, const void *data)
{
    (void)rc;
    (void)stat;
    (void)data;
    completions++;
}

/* Rule (NUL-01..04, DV-FIX-6 and spec line 538): the
 * Rust core turns the legacy NULL-handle crashes into defined results,
 * gives the TLS text for -15, and rejects a bad value buffer with
 * ZMARSHALLINGERROR after the state check. */
static int run_dev(const char *host)
{
#ifdef THREADED
    struct Stat st;
    struct String_vector sv;
    char buf[8];
    int len = (int)sizeof(buf);
#endif
    const char *srv;
    zhandle_t *zh;
    int rc;

    /* NUL-01: the int-watch wrappers. The sync forms are mt only. */
    CHECK(zoo_aget(NULL, "/a", 0, noop_data, NULL) == ZBADARGUMENTS, "zoo_aget(NULL)");
    CHECK(zoo_aexists(NULL, "/a", 0, noop_stat, NULL) == ZBADARGUMENTS, "zoo_aexists(NULL)");
#ifdef THREADED
    CHECK(zoo_get(NULL, "/a", 0, buf, &len, &st) == ZBADARGUMENTS, "zoo_get(NULL)");
    CHECK(zoo_exists(NULL, "/a", 0, &st) == ZBADARGUMENTS, "zoo_exists(NULL)");
    CHECK(zoo_get_children(NULL, "/a", 0, &sv) == ZBADARGUMENTS, "zoo_get_children(NULL)");
    CHECK(zoo_getconfig(NULL, 0, buf, &len, &st) == ZBADARGUMENTS, "zoo_getconfig(NULL)");
#endif
    /* NUL-02. A NULL handle gives the "null" endpoint text. */
    srv = zoo_get_current_server(NULL);
    printf("zoo_get_current_server(NULL)=%s\n", srv == NULL ? "(NULL)" : srv);
    CHECK(srv != NULL && strcmp(srv, "null") == 0, "zoo_get_current_server(NULL)");
    CHECK(zoo_set_servers(NULL, "127.0.0.1:1") == ZBADARGUMENTS, "zoo_set_servers(NULL)");
    CHECK(zoo_set_servers_resolution_delay(NULL, 0) == ZBADARGUMENTS,
          "zoo_set_servers_resolution_delay(NULL)");
    zoo_cycle_next_server(NULL);
    /* NUL-03 and NUL-04. */
    CHECK(zoo_get_context(NULL) == NULL, "zoo_get_context(NULL)");
    CHECK(zoo_recv_timeout(NULL) == 0, "zoo_recv_timeout(NULL)");
    CHECK(zoo_set_watcher(NULL, noop_watcher) == NULL, "zoo_set_watcher(NULL)");
    CHECK(is_unrecoverable(NULL) == ZINVALIDSTATE, "is_unrecoverable(NULL)");
    CHECK(zookeeper_get_connected_host(NULL, NULL, NULL) == NULL,
          "zookeeper_get_connected_host(NULL)");
    CHECK(zoo_client_id(NULL) == NULL, "zoo_client_id(NULL)");
    /* DV-FIX-6. */
    printf("zerror(-15)=%s\n", zerror(ZSSLCONNECTIONERROR));
    CHECK(strcmp(zerror(ZSSLCONNECTIONERROR), "ssl connection error") == 0, "zerror(-15)");

    /* The value-length rules on a handle that is still connecting. */
    logLevel = (ZooLogLevel)0;
    zh = zookeeper_init(host, noop_watcher, 10000, NULL, NULL, 0);
    CHECK(zh != NULL, "zookeeper_init(%s)", host);
    if (zh != NULL) {
        CHECK(is_unrecoverable(zh) == ZOK, "is_unrecoverable(connecting)");
        rc = zoo_aset(zh, "/a", "x", -1, -1, count_stat, NULL);
        CHECK(rc == ZOK, "zoo_aset len -1 gives %d", rc);
        rc = zoo_aset(zh, "/a", NULL, 0, -1, count_stat, NULL);
        CHECK(rc == ZOK, "zoo_aset len 0 gives %d", rc);
        rc = zoo_aset(zh, "/a", "x", -2, -1, count_stat, NULL);
        CHECK(rc == ZMARSHALLINGERROR, "zoo_aset len -2 gives %d", rc);
        rc = zoo_aset(zh, "/a", NULL, 4, -1, count_stat, NULL);
        CHECK(rc == ZMARSHALLINGERROR, "zoo_aset NULL with len 4 gives %d", rc);
        rc = zoo_acreate(zh, "/a", "x", -7, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, NULL);
        CHECK(rc == ZMARSHALLINGERROR, "zoo_acreate len -7 gives %d", rc);
        rc = zookeeper_close(zh);
        CHECK(rc == ZOK, "zookeeper_close gives %d", rc);
        /* Close fails the two queued requests, and the two rejected
         * requests have no completion. */
        CHECK(completions == 2, "completions=%d", completions);
    }
    logLevel = ZOO_LOG_LEVEL_INFO;
    printf("dev: %d failures\n", failures);
    return 0;
}

int main(int argc, char **argv)
{
    int rc;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 2 && strcmp(argv[1], "common") == 0) {
        rc = run_common();
    } else if (argc >= 3 && strcmp(argv[1], "logging") == 0) {
        rc = run_logging(argv[2]);
    } else if (argc >= 3 && strcmp(argv[1], "server") == 0) {
        rc = run_server(argv[2]);
    } else if (argc >= 3 && strcmp(argv[1], "dev") == 0) {
        rc = run_dev(argv[2]);
    } else {
        fprintf(stderr, "usage: runtime_abi common|logging HOST|server HOST|dev HOST\n");
        return 2;
    }
    return rc != 0 || failures != 0 ? 1 : 0;
}
