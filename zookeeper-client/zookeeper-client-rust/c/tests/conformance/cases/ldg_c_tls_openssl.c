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
 * What the system OpenSSL gives the legacy client and does not give the
 * Rust core: the protocol floor, the policy source and the linkage
 * (TLS-12, TLS-13, TLS-14, TLS-15, TLS-02; DV-TLS-1, DV-TLS-2).
 * Mode DEV.
 *
 * Rules:
 * - TLS-12, DV-TLS-1: the Rust core offers TLS 1.2 and TLS 1.3 only.
 *   A server that offers only TLS 1.1 fails the handshake. Legacy
 *   connects to it when openssl.cnf allows TLS 1.1. With a neutral
 *   openssl.cnf, both cores refuse that server.
 * - DV-TLS-1: the Rust core refuses a renegotiation that the server
 *   starts, so the server ends the connection. Legacy renegotiates
 *   (SSL_MODE_AUTO_RETRY), and the connection stays.
 * - TLS-13, DV-TLS-2: openssl.cnf does not change the Rust core. A
 *   MinProtocol of TLS 1.3, or security level 5, makes legacy refuse a
 *   TLS 1.2 server. The Rust core connects to it. With a neutral
 *   openssl.cnf, both cores connect.
 * - TLS-15: the Rust core does not need libssl or libcrypto, so neither
 *   is in the process. The legacy library needs both.
 * - TLS-14: the Rust core offers only AEAD ECDHE suites. A TLS 1.2
 *   server with only a CBC suite fails the handshake, and legacy
 *   connects to it.
 * - TLS-02: a TLS attempt of the Rust core loads no OpenSSL and makes
 *   no process-global OpenSSL state.
 *
 * The peers are `openssl s_server` processes of the case. One offers
 * only TLS 1.1 at security level 0, one offers only TLS 1.2, and one
 * offers only TLS 1.2 with one CBC suite. Their ports are 4, 6 and 2
 * above the dead port of the core, which the run with --tls leaves
 * free. Each attempt runs in a child process, because
 * OpenSSL reads OPENSSL_CONF once per process. The child gives its
 * result as its exit code: 0 when the state reaches ASSOCIATING (the
 * handshake is done), 1 when the handshake fails with "error in ssl
 * connect", and 2 when neither occurs in 8 seconds. In the
 * renegotiation child, 3 means that the server logs the refusal or the
 * end of the connection after the request. The CA file is the zk-driver fixture CA, which signs the
 * server certificate of both peers.
 *
 * OPENSSL selects the openssl command (default: Homebrew openssl@3).
 * Run the case with --tls and the ssl or full libraries of both cores.
 *
 * zkconf-flavors: mt st
 */

/* glibc declares dl_iterate_phdr only with _GNU_SOURCE. */
#if !defined(__APPLE__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "zkconf.h"
#include "zkconf_tls.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#else
#include <link.h>
#endif

#define T_MS 30000
#define WAIT_MS 8000
#define OPENSSL_DEFAULT "/opt/homebrew/opt/openssl@3/bin/openssl"

/* One s_server peer. */
struct peer {
    pid_t pid;
    int in;
    char addr[64];
    char out[1100];
};

static struct peer g_s11;
static struct peer g_s12;
static struct peer g_cbc;
static char g_cert[4096];
static const char *g_target;
static const char *g_conf;
static int g_reneg;
static int g_reneg_fd;
static const char *g_reneg_out;

static void quiet_watcher(zhandle_t *zh, int type, int state,
                          const char *path, void *ctx)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)ctx;
}

static int write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        return -1;
    }
    fputs(text, f);
    return fclose(f);
}

/* Counts the lines of path that contain needle. */
static int count_in(const char *path, const char *needle)
{
    char line[4096];
    int n = 0;
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, needle) != NULL) {
            n++;
        }
    }
    fclose(f);
    return n;
}

/* Returns 1 when a loaded image has name in its path. */
#if defined(__APPLE__)
static int image_loaded(const char *name)
{
    uint32_t i;
    for (i = 0; i < _dyld_image_count(); i++) {
        const char *p = _dyld_get_image_name(i);
        if (p != NULL && strstr(p, name) != NULL) {
            return 1;
        }
    }
    return 0;
}
#else
static int image_cb(struct dl_phdr_info *info, size_t size, void *arg)
{
    (void)size;
    return info->dlpi_name != NULL &&
           strstr(info->dlpi_name, (const char *)arg) != NULL;
}

static int image_loaded(const char *name)
{
    return dl_iterate_phdr(image_cb, (void *)name);
}
#endif

static int openssl_loaded(void)
{
    return image_loaded("libssl") || image_loaded("libcrypto");
}

/*
 * Starts `openssl s_server` on port with the protocol option proto and
 * the TLS 1.2 cipher list cipher. The
 * server reads its commands from a pipe that the case keeps open, so it
 * does not end at the end of its input.
 */
static int peer_start(struct peer *p, const char *tag, int port,
                      const char *proto, const char *cipher)
{
    char accept[64];
    char cert[1100];
    char key[1100];
    const char *ossl = getenv("OPENSSL");
    int fds[2];
    long end;
    if (ossl == NULL || *ossl == '\0') {
        ossl = OPENSSL_DEFAULT;
    }
    snprintf(p->addr, sizeof(p->addr), "127.0.0.1:%d", port);
    snprintf(accept, sizeof(accept), "127.0.0.1:%d", port);
    snprintf(p->out, sizeof(p->out), "%s.%s.out", zkt_out(), tag);
    snprintf(cert, sizeof(cert), "%s/server.pem", zkt_fix());
    snprintf(key, sizeof(key), "%s/server.key", zkt_fix());
    if (access(ossl, X_OK) != 0 || pipe(fds) != 0) {
        return -1;
    }
    fflush(NULL);
    p->pid = fork();
    if (p->pid < 0) {
        return -1;
    }
    if (p->pid == 0) {
        FILE *o = fopen(p->out, "w");
        if (o == NULL) {
            _exit(127);
        }
        dup2(fds[0], 0);
        dup2(fileno(o), 1);
        dup2(fileno(o), 2);
        close(fds[1]);
        execl(ossl, ossl, "s_server", "-accept", accept, proto, "-cipher",
              cipher, "-cert", cert, "-key", key, (char *)NULL);
        _exit(127);
    }
    close(fds[0]);
    p->in = fds[1];
    end = zkt_now_ms() + 10000;
    while (count_in(p->out, "ACCEPT") == 0) {
        if (zkt_now_ms() >= end) {
            return -1;
        }
        zkc_sleep_ms(20);
    }
    return 0;
}

static void peer_stop(struct peer *p)
{
    if (p->pid > 0) {
        close(p->in);
        kill(p->pid, SIGTERM);
        waitpid(p->pid, NULL, 0);
        p->pid = 0;
    }
}

/* One pass of the handle: a sleep in mt, an interest and process in st. */
static void pass(zhandle_t *zh)
{
#ifdef THREADED
    (void)zh;
    zkc_sleep_ms(10);
#else
    int interest;
    int err;
    int mid;
    const char *where;
    (void)zkt_st_pass(zh, 10, &interest, &err, &where, &mid);
#endif
}

/*
 * The child of one attempt. It sets OPENSSL_CONF before the first TLS
 * use of the process, and connects to g_target.
 */
static int attempt_child(void)
{
    zhandle_t *zh;
    long end;
    int done = 0;
    if (g_conf != NULL) {
        setenv("OPENSSL_CONF", g_conf, 1);
    } else {
        unsetenv("OPENSSL_CONF");
    }
    zkt_log_reset();
    zh = zkt_init_raw(g_target, g_cert, quiet_watcher, T_MS, NULL, NULL, 0);
    if (zh == NULL) {
        return 4;
    }
    end = zkt_now_ms() + WAIT_MS;
    while (zkt_now_ms() < end) {
        if (zoo_state(zh) == ZOO_ASSOCIATING_STATE) {
            done = 1;
            break;
        }
        if (zkt_log_count("error in ssl connect") > 0) {
            return 1;
        }
        pass(zh);
    }
    if (!done) {
        return 2;
    }
    if (g_reneg) {
        /*
         * s_server: "r" asks for a renegotiation of the live session. The
         * server logs "no renegotiation" when the client refuses it. The
         * client can connect again fast, so the state is not a sure sign.
         */
        int closed = count_in(g_reneg_out, "CONNECTION CLOSED");
        if (write(g_reneg_fd, "r\n", 2) != 2) {
            return 5;
        }
        end = zkt_now_ms() + 3000;
        while (zkt_now_ms() < end) {
            if (zoo_state(zh) != ZOO_ASSOCIATING_STATE ||
                count_in(g_reneg_out, "no renegotiation") > 0 ||
                count_in(g_reneg_out, "CONNECTION CLOSED") > closed) {
                return 3;
            }
            pass(zh);
        }
    }
    return 0;
}

static const char *attempt(const char *label, struct peer *p, const char *conf,
                           int reneg)
{
    g_target = p->addr;
    g_conf = conf;
    g_reneg = reneg;
    g_reneg_fd = p->in;
    g_reneg_out = p->out;
    return zkc_child(label, attempt_child, WAIT_MS + 8000);
}

static int is(const char *res, const char *want)
{
    return strcmp(res, want) == 0;
}

int main(int argc, char **argv)
{
    char neutral[1100];
    char open[1100];
    char min13[1100];
    char sec5[1100];
    const char *dead;
    const char *colon;
    const char *r;
    int port;
    int rust;
    zhandle_t *zh;
    long end;
    int assoc = 0;

    zkc_init(argc, argv, "ldg_c_tls_openssl", 0, "DEV", "ignore");
    if (zkt_setup(0) != 0) {
        return zkc_finish();
    }
    rust = zkc_is_rust();
    snprintf(g_cert, sizeof(g_cert), "%s/ca.pem,,,", zkt_fix());

    /* TLS-15: the library alone decides what the process loads. */
    zkc_dev("TLS-15", rust ? !openssl_loaded() : openssl_loaded(),
            "libssl or libcrypto loaded at start: %d", openssl_loaded());

    snprintf(neutral, sizeof(neutral), "%s.neutral.cnf", zkt_out());
    snprintf(open, sizeof(open), "%s.open.cnf", zkt_out());
    snprintf(min13, sizeof(min13), "%s.min13.cnf", zkt_out());
    snprintf(sec5, sizeof(sec5), "%s.sec5.cnf", zkt_out());
#define CNF_HEAD                                                          \
    "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n"  \
    "[ssl_sect]\nsystem_default = sys\n[sys]\n"
    if (write_file(neutral, CNF_HEAD) != 0 ||
        write_file(open, CNF_HEAD "MinProtocol = TLSv1\n"
                                  "CipherString = DEFAULT@SECLEVEL=0\n") != 0 ||
        write_file(min13, CNF_HEAD "MinProtocol = TLSv1.3\n") != 0 ||
        write_file(sec5, CNF_HEAD "CipherString = DEFAULT@SECLEVEL=5\n") != 0) {
        zkc_fail("cannot write the openssl.cnf files");
        return zkc_finish();
    }

    dead = zkc_dead();
    colon = strrchr(dead, ':');
    port = colon != NULL ? atoi(colon + 1) : 0;
    if (port <= 0) {
        zkc_fail("no dead port in %s", dead);
        return zkc_finish();
    }
    if (peer_start(&g_s11, "s11", port + 4, "-tls1_1", "DEFAULT@SECLEVEL=0") !=
            0 ||
        peer_start(&g_s12, "s12", port + 6, "-tls1_2", "DEFAULT@SECLEVEL=0") !=
            0 ||
        peer_start(&g_cbc, "cbc", port + 2, "-tls1_2",
                   "ECDHE-ECDSA-AES128-SHA256") != 0) {
        zkc_fail("cannot start openssl s_server");
        peer_stop(&g_s11);
        peer_stop(&g_s12);
        peer_stop(&g_cbc);
        return zkc_finish();
    }

    /* The protocol floor (TLS-12, DV-TLS-1). */
    r = attempt("floor-neutral", &g_s11, neutral, 0);
    zkc_dev("DV-TLS-1", is(r, "exit:1"),
            "TLS 1.1 server, neutral openssl.cnf: %s (both refuse)", r);
    r = attempt("floor-open", &g_s11, open, 0);
    zkc_dev("TLS-12", rust ? is(r, "exit:1") : is(r, "exit:0"),
            "TLS 1.1 server, openssl.cnf allows TLS 1.1: %s (%s)", r,
            rust ? "the Rust core refuses" : "legacy connects");

    /* A renegotiation that the server starts (DV-TLS-1). */
    r = attempt("reneg", &g_s12, neutral, 1);
    zkc_dev("DV-TLS-1", rust ? is(r, "exit:3") : is(r, "exit:0"),
            "server renegotiation: %s (%s)", r,
            rust ? "the Rust core refuses, the server ends the connection"
                 : "legacy renegotiates");

    /* The policy source (TLS-13, DV-TLS-2). */
    r = attempt("policy-neutral", &g_s12, neutral, 0);
    zkc_dev("TLS-13", is(r, "exit:0"),
            "TLS 1.2 server, neutral openssl.cnf: %s (both connect)", r);
    r = attempt("policy-min13", &g_s12, min13, 0);
    zkc_dev("TLS-13", rust ? is(r, "exit:0") : is(r, "exit:1"),
            "TLS 1.2 server, MinProtocol TLSv1.3: %s (%s)", r,
            rust ? "openssl.cnf does not apply" : "legacy refuses");
    r = attempt("policy-seclevel5", &g_s12, sec5, 0);
    zkc_dev("DV-TLS-2", rust ? is(r, "exit:0") : is(r, "exit:1"),
            "TLS 1.2 server, SECLEVEL 5: %s (%s)", r,
            rust ? "the OpenSSL security level does not apply"
                 : "legacy refuses");

    /* The cipher-suite floor (TLS-14). */
    r = attempt("cbc-only", &g_cbc, neutral, 0);
    zkc_dev("TLS-14", rust ? is(r, "exit:1") : is(r, "exit:0"),
            "TLS 1.2 server with only a CBC suite: %s (%s)", r,
            rust ? "the Rust core offers only AEAD ECDHE suites"
                 : "legacy offers CBC suites");

    /* TLS-02: a TLS attempt in this process. */
    setenv("OPENSSL_CONF", neutral, 1);
    zh = zkt_init_raw(g_s12.addr, g_cert, quiet_watcher, T_MS, NULL, NULL, 0);
    if (zh == NULL) {
        zkc_fail("init failed: errno %d", errno);
    } else {
        end = zkt_now_ms() + WAIT_MS;
        while (zkt_now_ms() < end && !assoc) {
            assoc = zoo_state(zh) == ZOO_ASSOCIATING_STATE;
            pass(zh);
        }
        zkc_dev("TLS-02", assoc && (rust ? !openssl_loaded() : openssl_loaded()),
                "after a TLS handshake: associating %d, libssl or libcrypto "
                "loaded %d", assoc, openssl_loaded());
        zookeeper_close(zh);
    }
    peer_stop(&g_s11);
    peer_stop(&g_s12);
    peer_stop(&g_cbc);
    return zkc_finish();
}
