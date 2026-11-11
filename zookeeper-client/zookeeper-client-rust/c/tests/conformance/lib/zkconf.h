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
 * Trace recorder of the differential conformance suite.
 * This is test code. It is never installed or shipped.
 *
 * A scenario program uses only the public headers. The runner links it
 * once against the legacy library and selects the core at run time
 * through DYLD_LIBRARY_PATH. The recorder writes a normalized
 * trace, so the two traces of a deterministic scenario are equal.
 *
 * Normalization: session ids become S<n> and zxids become Z<n>
 * in the order of first observation (N1, N2). Contexts are string labels
 * that the scenario gives (N3). Threads become roles (N4). Ports become
 * names (N5). Log lines keep the level, func@line and the text (N7).
 *
 * Environment (set by run.sh):
 *   ZKCONF_CORE    "c" or "rust": the core under test
 *   ZKCONF_LIBDIR  the directory that must hold the loaded library
 *   ZKCONF_OUT     the output prefix: <prefix>.trace, .log and .dev
 *   ZKCONF_HOSTS   the real servers, comma separated
 *   ZKCONF_DEAD    an address where no server listens
 *   ZKCONF_PORTS   "port=name,..." for N5
 *   ZKCONF_CTL     the server control command: CTL start|stop INDEX
 */

#ifndef ZKCONF_H_
#define ZKCONF_H_

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <zookeeper.h>

/*
 * The send flag for the sockets of the harness. A harness send to a
 * closed peer gives EPIPE and does not raise SIGPIPE. Thus a SIGPIPE in a
 * case comes only from the core under test. A platform without
 * MSG_NOSIGNAL gets 0, and then zkc_init ignores SIGPIPE.
 */
#ifdef MSG_NOSIGNAL
#define ZKC_NOSIGNAL MSG_NOSIGNAL
#else
#define ZKC_NOSIGNAL 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* A case calls zkc_init first. "--describe" prints the needs and exits. */
void zkc_init(int argc, char **argv, const char *test_id, int nservers,
              const char *mode, const char *logmode);
int zkc_finish(void);

/* The core under test and the configured addresses. */
int zkc_is_rust(void);
const char *zkc_core(void);
const char *zkc_host(int index);
const char *zkc_hosts(int count);
const char *zkc_dead(void);

/* Roles: "app", "L1" (the thread of the first watcher call), "L2", ... */
void zkc_role_app(void);
const char *zkc_role(void);

/* One trace event. The role of the calling thread is the first field. */
void zkc_ev(const char *kind, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Normalizers. The returned strings stay valid until zkc_finish. */
const char *zkc_rc(int rc);
const char *zkc_sid(int64_t session_id);
const char *zkc_zxid(int64_t zxid);
const char *zkc_state(int state);
const char *zkc_type(int type);
const char *zkc_lbl(const void *ctx);
void zkc_stat_str(char *buf, size_t len, const struct Stat *stat);
void zkc_norm_text(char *out, size_t outlen, const char *in);

/* Records any Rust frame below the current callback (TH-15). */
void zkc_frame_check(const char *site);

/* Recording callbacks. The context is a string label or NULL. */
void zkc_watcher(zhandle_t *zh, int type, int state, const char *path,
                 void *ctx);
void zkc_void_cb(int rc, const void *d);
void zkc_stat_cb(int rc, const struct Stat *s, const void *d);
void zkc_data_cb(int rc, const char *v, int len, const struct Stat *s,
                 const void *d);
void zkc_strings_cb(int rc, const struct String_vector *sv, const void *d);
void zkc_strings_stat_cb(int rc, const struct String_vector *sv,
                         const struct Stat *s, const void *d);
void zkc_string_cb(int rc, const char *v, const void *d);
void zkc_string_stat_cb(int rc, const char *v, const struct Stat *s,
                        const void *d);
void zkc_acl_cb(int rc, struct ACL_vector *acl, struct Stat *s,
                const void *d);
void zkc_log_cb(const char *msg);

/* Hooks that run inside a recording callback after the record. */
typedef void (*zkc_hook_fn)(const char *kind, int rc, const void *d);
void zkc_set_hook(zkc_hook_fn hook);
typedef void (*zkc_whook_fn)(zhandle_t *zh, int type, int state,
                             const char *path, void *ctx);
void zkc_set_watch_hook(zkc_whook_fn hook);

/*
 * Bounded waits. Keys: "cb", "watch", "session:<STATE>" (any watcher) and
 * "session:<STATE>@<ctx>" (the watcher with that context label). In st,
 * the waits drive the poll registry, because no library thread runs the
 * callbacks. zkc_sleep_ms never drives the registry.
 */
int zkc_await(const char *key, int n, int timeout_ms);
int zkc_await_none(const char *key, int wait_ms);
void zkc_sleep_ms(int ms);

/*
 * Connects with zookeeper_init2 and waits for CONNECTED. In st, the new
 * handle goes into the poll registry. zkc_close takes it out first.
 */
zhandle_t *zkc_connect(const char *hosts, int timeout_ms, int flags);
void zkc_close(zhandle_t *zh);

/*
 * The st poll loop. The case thread drives every handle in the
 * registry, as cli_st does: zookeeper_interest for each handle, one
 * select over the descriptors with the smallest tv, then
 * zookeeper_process for each handle with a ready event. A callback can
 * close its handle. It must then call zkc_poll_remove before it returns.
 * In mt, the registry calls do nothing and zkc_poll only sleeps.
 */
int zkc_is_st(void);
void zkc_poll_add(zhandle_t *zh);
void zkc_poll_remove(zhandle_t *zh);
/* Returns 1 if zh is in the registry. */
int zkc_polled(const zhandle_t *zh);
/* Drives the registry for ms milliseconds. Returns the number of passes. */
int zkc_poll(int ms);
/* One pass that waits at most ms milliseconds in select. */
void zkc_poll_once(int ms);

/*
 * TH-02: a driving call starts with zkc_in_call(1) and ends
 * with zkc_in_call(0). In st, each callback record gets "in=<call>", the
 * innermost driving call, or "in=none" outside of all calls. The wrappers
 * below and zkc_close mark their calls.
 */
void zkc_in_call(int entering);
const char *zkc_call_name(void);
#ifndef THREADED
int zkc_interest(zhandle_t *zh, int *fd, int *interest, struct timeval *tv);
int zkc_process(zhandle_t *zh, int events);
#endif

/*
 * A TCP proxy in the test process for st loss and flush scenarios. It
 * listens on an ephemeral port of 127.0.0.1, which the trace shows as PX.
 * Each accepted connection goes to target. The proxy is a test thread,
 * so a case measures TH-01 before it starts the proxy.
 *
 * zkc_proxy_hold(1) keeps the bytes from the server in the proxy until
 * zkc_proxy_hold(0). zkc_proxy_reset ends every client connection with a
 * TCP reset and closes the server side. It returns after the reset.
 */
const char *zkc_proxy_start(const char *target);
void zkc_proxy_hold(int on);
int zkc_proxy_reset(void);
long zkc_proxy_up_bytes(void);
int zkc_proxy_accepted(void);
void zkc_proxy_stop(void);

/*
 * Expires the session of zh. The context of zh must be a string label. A
 * clone handle on hosts attaches to the session and closes it. In mt, the
 * IO thread of zh is held in its log callback meanwhile, so zh cannot
 * attach again first. In st, zh stays out of the poll registry meanwhile.
 * Returns 0 after the EXPIRED event of zh.
 */
int zkc_expire(zhandle_t *zh, const char *hosts);

/* Resource counts (TH-01, CL-01). */
int zkc_threads(void);
int zkc_fds(void);

/* Server control through ZKCONF_CTL. */
int zkc_server(const char *cmd, int index);

/* DEV checks. A failed check makes zkc_finish return 1. */
void zkc_dev(const char *id, int ok, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
/*
 * A known failure: a check whose fix is outside this suite. A failed check
 * is recorded as XFAIL and does not fail the run. A passed check is XPASS.
 */
void zkc_known(const char *id, int ok, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
/* A harness failure. It is recorded in the trace and fails the run. */
void zkc_fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * Runs fn in a forked child under a timeout. Call it before the first
 * handle exists, so no library thread is lost in the child. The result
 * is "exit:N", "signal:N" or "hang". It goes to the DEV file only.
 */
const char *zkc_child(const char *label, int (*fn)(void), int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* ZKCONF_H_ */
