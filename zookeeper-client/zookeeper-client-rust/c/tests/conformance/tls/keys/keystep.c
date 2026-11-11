/*
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
 * keystep: reports which TLS setup step of zookeeper_init_ssl fails, for
 * the client-identity corpus. The legacy core and the Rust core must fail
 * at the same step with the same log line.
 *
 * Usage: keystep PORT CERTSTRING
 *
 * The program listens on 127.0.0.1:PORT. The listener reads what the
 * client sends and then closes the connection, so a client that passes
 * every setup step fails the handshake with "error in ssl connect".
 * The program prints one line "STEP <token> <log text>" and exits 0. The
 * tokens are CA, CERT, KEY, CHECK, CONNECT (every setup step passed) and
 * TIMEOUT. The program also prints "LIB <path>", the library that defines
 * zookeeper_init_ssl. Build with -DTHREADED for the mt library.
 */

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <zookeeper/zookeeper.h>

/* The wait for the step line. It bounds every run. */
#define WAIT_MS 8000

struct step_rule {
    const char *token;
    const char *text;
};

/* The log lines of the setup steps and of the handshake. */
static const struct step_rule RULES[] = {
    {"CA", "Failed to load CA file"},
    {"CA", "Call to SSL_CTX_set_default_verify_paths failed"},
    {"CERT", "Failed to load client certificate chain from"},
    {"KEY", "Failed to load client private key from"},
    {"CHECK", "SSL_CTX_check_private_key failed"},
    {"CONNECT", "error in ssl connect"},
    {"CONTEXT", "error creating ssl context"},
};

static int listen_fd = -1;
static volatile int stop_listener = 0;

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) ts.tv_sec * 1000L + (long) (ts.tv_nsec / 1000000L);
}

/* Accepts each client, reads its first bytes and closes it. */
static void *listener(void *arg)
{
    (void) arg;
    while (!stop_listener) {
        struct pollfd p;
        int c;
        char buf[512];
        struct timeval tv;

        p.fd = listen_fd;
        p.events = POLLIN;
        p.revents = 0;
        if (poll(&p, 1, 50) <= 0) {
            continue;
        }
        c = accept(listen_fd, NULL, NULL);
        if (c < 0) {
            continue;
        }
        /* Read until the client waits for the server, so that the close
         * sends a FIN and no RST. */
        tv.tv_sec = 0;
        tv.tv_usec = 300000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        while (recv(c, buf, sizeof(buf), 0) > 0) {
        }
        close(c);
    }
    return NULL;
}

static int open_listener(int port)
{
    struct sockaddr_in a;
    int one = 1;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return -1;
    }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short) port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr *) &a, sizeof(a)) != 0) {
        return -1;
    }
    return listen(listen_fd, 8);
}

static void watcher(zhandle_t *zh, int type, int state, const char *path, void *ctx)
{
    (void) zh;
    (void) type;
    (void) state;
    (void) path;
    (void) ctx;
}

/* Finds the first step line in the log file. It returns the rule or NULL. */
static const struct step_rule *scan_log(const char *log, char *line, size_t cap)
{
    FILE *f = fopen(log, "r");
    const struct step_rule *found = NULL;

    if (f == NULL) {
        return NULL;
    }
    while (found == NULL && fgets(line, (int) cap, f) != NULL) {
        size_t i;
        for (i = 0; i < sizeof(RULES) / sizeof(RULES[0]); i++) {
            if (strstr(line, RULES[i].text) != NULL) {
                found = &RULES[i];
                break;
            }
        }
    }
    fclose(f);
    return found;
}

#ifndef THREADED
/* Drives the st library for one interval. */
static void drive_st(zhandle_t *zh)
{
    int fd = -1;
    int interest = 0;
    struct timeval tv;
    struct pollfd p;
    int events = 0;
    int ms;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (zookeeper_interest(zh, &fd, &interest, &tv) != ZOK || fd < 0) {
        usleep(10000);
        return;
    }
    ms = (int) (tv.tv_sec * 1000 + tv.tv_usec / 1000);
    if (ms > 20 || ms < 0) {
        ms = 20;
    }
    p.fd = fd;
    p.events = (short) (((interest & ZOOKEEPER_READ) ? POLLIN : 0) |
                        ((interest & ZOOKEEPER_WRITE) ? POLLOUT : 0));
    p.revents = 0;
    if (poll(&p, 1, ms) > 0) {
        if (p.revents & (POLLIN | POLLHUP | POLLERR)) {
            events |= ZOOKEEPER_READ;
        }
        if (p.revents & POLLOUT) {
            events |= ZOOKEEPER_WRITE;
        }
    }
    (void) zookeeper_process(zh, events);
}
#endif

int main(int argc, char **argv)
{
    char log[] = "/tmp/keystep-log-XXXXXX";
    char host[64];
    char line[4096];
    const struct step_rule *found = NULL;
    pthread_t tid;
    zhandle_t *zh;
    FILE *stream;
    Dl_info info;
    long deadline;
    int port;
    int fd;
    char *msg;
    size_t n;

    if (argc != 3) {
        fprintf(stderr, "usage: keystep PORT CERTSTRING\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    port = atoi(argv[1]);
    if (open_listener(port) != 0) {
        fprintf(stderr, "keystep: cannot listen on port %d: %s\n", port, strerror(errno));
        return 2;
    }
    if (pthread_create(&tid, NULL, listener, NULL) != 0) {
        return 2;
    }
    fd = mkstemp(log);
    if (fd < 0) {
        return 2;
    }
    stream = fdopen(fd, "w");
    if (stream == NULL) {
        return 2;
    }
    if (dladdr((void *) zookeeper_init_ssl, &info) != 0 && info.dli_fname != NULL) {
        printf("LIB %s\n", info.dli_fname);
    }
    zoo_set_log_stream(stream);
    zoo_set_debug_level(ZOO_LOG_LEVEL_ERROR);
    snprintf(host, sizeof(host), "127.0.0.1:%d", port);
    zh = zookeeper_init_ssl(host, argv[2], watcher, 30000, NULL, NULL, 0);
    if (zh == NULL) {
        printf("STEP INIT zookeeper_init_ssl returned NULL errno=%d\n", errno);
        unlink(log);
        return 0;
    }
    deadline = now_ms() + WAIT_MS;
    while (found == NULL && now_ms() < deadline) {
#ifdef THREADED
        usleep(10000);
#else
        drive_st(zh);
#endif
        fflush(stream);
        found = scan_log(log, line, sizeof(line));
    }
    zookeeper_close(zh);
    stop_listener = 1;
    pthread_join(tid, NULL);
    close(listen_fd);
    if (found == NULL) {
        printf("STEP TIMEOUT -\n");
    } else {
        /* The text from the level tag on, without the time and thread id. */
        msg = strstr(line, "ZOO_");
        if (msg == NULL) {
            msg = line;
        }
        n = strlen(msg);
        while (n > 0 && (msg[n - 1] == '\n' || msg[n - 1] == '\r')) {
            msg[--n] = '\0';
        }
        printf("STEP %s %s\n", found->token, msg);
    }
    fclose(stream);
    unlink(log);
    return 0;
}
