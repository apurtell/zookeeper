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
 * TLS-09.
 * TLS against a real server: the default trust paths and the cert
 * string (TL-04, TL-05, TL-08, ER-05). Mode EXACT.
 *
 * Rules:
 * - Default paths: SSL_CERT_FILE names an existing empty or unparsable file,
 *   and SSL_CERT_DIR names an empty directory. The default paths step
 *   succeeds with no anchor, as in legacy, and the CA file alone decides
 *   the handshake. The testSSL CA file (server.crt) connects. The
 *   zk-driver CA does not sign the server, so that attempt fails with
 *   "error in ssl connect" (TL-08).
 * - TL-04, ER-05: the client identity loads only when cert and key
 *   are present, after the legacy strtok split. An empty field
 *   collapses, and a fifth field does not count. The server asks for a
 *   client certificate (ssl.clientAuth=want), so each string connects.
 *   A create with the creator ACL shows the identity: the x509 provider
 *   of the server gives the session an auth id only with a client
 *   certificate.
 * - DV-FIX-10: without passwd, legacy skips the identity and the Rust
 *   core loads it. The trace omits the create result of that attempt,
 *   and a DEV check records it for each core.
 *
 * The case sets the variables before the first handle, and changes
 * SSL_CERT_FILE between attempts. Both cores read the default paths at
 * each attempt (a fresh SSL_CTX per attempt in legacy).
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_tls.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SITE "@init_ssl_for_socket@"

static int g_node;

/* The create result of a DV-FIX-10 attempt. */
static pthread_mutex_t g_dev_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_dev_rc;
static int g_dev_done;

static void dev_cb(int rc, const char *v, const void *d)
{
    (void)v;
    (void)d;
    pthread_mutex_lock(&g_dev_mu);
    g_dev_rc = rc;
    g_dev_done = 1;
    pthread_mutex_unlock(&g_dev_mu);
}

/* Waits for dev_cb. Returns 0 and sets rc, or returns -1 at the timeout. */
static int dev_wait(int timeout_ms, int *rc)
{
    long end = zkt_now_ms() + timeout_ms;
    for (;;) {
        int done;
        pthread_mutex_lock(&g_dev_mu);
        done = g_dev_done;
        *rc = g_dev_rc;
        pthread_mutex_unlock(&g_dev_mu);
        if (done) {
            return 0;
        }
        if (zkt_now_ms() >= end) {
            return -1;
        }
#ifdef THREADED
        zkc_sleep_ms(20);
#else
        zkc_poll(20);
#endif
    }
}

/*
 * Connects with cert and records the create rc of the creator ACL. When
 * dev is set, the rc is a DV-FIX-10 check and not a trace event.
 */
static void live(const char *label, const char *cert, int dev)
{
    char shown[4096];
    char path[64];
    zhandle_t *zh;
    zkt_norm_paths(shown, sizeof(shown), cert);
    zkc_ev("case", "%s cert=\"%s\"", label, shown);
    zh = zkt_init(zkt_host(0), cert, 30000, NULL, label, 0);
    if (zh == NULL) {
        return;
    }
    {
        char key[128];
        snprintf(key, sizeof(key), "session:CONNECTED@%s", label);
        if (zkc_await(key, 1, 15000) != 0) {
            zkc_ev("wait", "%s no CONNECTED in 15 s", label);
            zkc_close(zh);
            return;
        }
    }
    snprintf(path, sizeof(path), "/tls_live_%d", g_node++);
    if (dev) {
        int rc = ZSYSTEMERROR;
        pthread_mutex_lock(&g_dev_mu);
        g_dev_done = 0;
        pthread_mutex_unlock(&g_dev_mu);
        zkc_ev("call", "zoo_acreate %s CREATOR_ALL_ACL -> %s", path,
               zkc_rc(zoo_acreate(zh, path, "x", 1, &ZOO_CREATOR_ALL_ACL, 0,
                                  dev_cb, "create")));
        if (dev_wait(10000, &rc) != 0) {
            zkc_ev("wait", "%s no create completion in 10 s", label);
        }
        /* The x509 auth id permits the create only with the identity. */
        zkc_dev("DV-FIX-10", zkc_is_rust() ? rc == ZOK : rc == ZINVALIDACL,
                "%s: create rc=%s", label, zkc_rc(rc));
    } else {
        zkc_ev("call", "zoo_acreate %s CREATOR_ALL_ACL -> %s", path,
               zkc_rc(zoo_acreate(zh, path, "x", 1, &ZOO_CREATOR_ALL_ACL, 0,
                                  zkc_string_cb, "create")));
        zkc_await("cb", 1, 10000);
    }
    zkc_close(zh);
}

/* An attempt that must fail in the handshake. Records its line. */
static void refused(const char *label, const char *cert)
{
    char shown[4096];
    zhandle_t *zh;
    long end;
    zkt_norm_paths(shown, sizeof(shown), cert);
    zkc_ev("case", "%s cert=\"%s\"", label, shown);
    zkt_log_reset();
    zh = zkt_init(zkt_host(0), cert, 30000, NULL, label, 0);
    if (zh == NULL) {
        return;
    }
    end = zkt_now_ms() + 10000;
    while (zkt_log_count(SITE) == 0 && zkt_now_ms() < end) {
#ifdef THREADED
        zkc_sleep_ms(20);
#else
        zkc_poll(20);
#endif
    }
    zkc_close(zh);
    zkt_log_record(label, SITE, 1);
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

int main(int argc, char **argv)
{
    char empty[1100];
    char junk[1100];
    char dir[1100];
    char cs[4096];
    const char *c;
    const char *f;

    zkc_init(argc, argv, "tls_live", 1, "EXACT", "ignore");
    if (zkt_setup(1) != 0) {
        return zkc_finish();
    }
    c = zkt_certs();
    f = zkt_fix();
    snprintf(empty, sizeof(empty), "%s.empty.pem", zkt_out());
    snprintf(junk, sizeof(junk), "%s.junk.pem", zkt_out());
    snprintf(dir, sizeof(dir), "%s.certdir", zkt_out());
    if (write_file(empty, "") != 0 ||
        write_file(junk, "-----BEGIN CERTIFICATE-----\nnot base64\n") != 0 ||
        (mkdir(dir, 0700) != 0 && access(dir, W_OK) != 0)) {
        zkc_fail("cannot write the default path files");
        return zkc_finish();
    }
    setenv("SSL_CERT_DIR", dir, 1);

    setenv("SSL_CERT_FILE", empty, 1);
    snprintf(cs, sizeof(cs),
             "%s/server.crt,%s/client.crt,%s/clientkey.pem,password", c, c, c);
    live("empty-file", cs, 0);
    snprintf(cs, sizeof(cs), "%s/ca.pem,%s/client.crt,%s/clientkey.pem,password",
             f, c, c);
    refused("empty-file-other-ca", cs);

    setenv("SSL_CERT_FILE", junk, 1);
    snprintf(cs, sizeof(cs),
             "%s/server.crt,%s/client.crt,%s/clientkey.pem,password", c, c, c);
    live("junk-file", cs, 0);
    snprintf(cs, sizeof(cs), "%s/ca.pem,%s/client.crt,%s/clientkey.pem,password",
             f, c, c);
    refused("junk-file-other-ca", cs);

    /* Cert string shifts (ER-05) on a live server. */
    snprintf(cs, sizeof(cs),
             "%s/server.crt,,%s/client.crt,%s/clientkey.pem,password", c, c, c);
    live("collapse", cs, 0);
    snprintf(cs, sizeof(cs), "%s/server.crt,%s/client.crt,%s/clientkey.pem", c,
             c, c);
    live("no-passwd", cs, 1);
    snprintf(cs, sizeof(cs),
             "%s/server.crt,%s/client.crt,%s/clientkey.pem,password,extra", c,
             c, c);
    live("five-fields", cs, 0);
    snprintf(cs, sizeof(cs), "%s/server.crt,,,", c);
    live("ca-only", cs, 0);
    return zkc_finish();
}
