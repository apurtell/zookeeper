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
 * TLS against a real server: the CA file is read again at each
 * connection attempt (TLS-02). Mode EXACT.
 *
 * Rules:
 * - TLS-02: each attempt makes a new TLS configuration from the
 *   files. Legacy makes a new SSL_CTX, and the Rust core makes a new
 *   rustls configuration. The handle does not keep the trust of an
 *   earlier attempt.
 * - The CA file of one handle holds the zk-driver CA first. That CA
 *   does not sign the server, so each attempt fails with "error in ssl
 *   connect". The case then writes the testSSL CA (server.crt) to the
 *   same path. The next attempt of the same handle connects, and a
 *   create succeeds.
 * - The case then writes the zk-driver CA to the path again, and stops
 *   and starts the server. The handle cannot connect again, because the
 *   next attempts read the wrong CA. The case writes the right CA again,
 *   and the same handle connects in the same session.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_sync.h"
#include "zkconf_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SITE "@init_ssl_for_socket@"
#define LABEL "rotate"

/* Copies the file from to the file to. */
static int copy_file(const char *from, const char *to)
{
    char buf[4096];
    size_t n;
    int rc = 0;
    FILE *in = fopen(from, "rb");
    FILE *out;
    if (in == NULL) {
        return -1;
    }
    out = fopen(to, "wb");
    if (out == NULL) {
        fclose(in);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            rc = -1;
        }
    }
    fclose(in);
    if (fclose(out) != 0) {
        rc = -1;
    }
    return rc;
}

/* Drives the handle for ms. */
static void drive(int ms)
{
#ifdef THREADED
    zkc_sleep_ms(ms);
#else
    zkc_poll(ms);
#endif
}

/* Waits until the log has at least n lines with the site. */
static int refusals(int n, int timeout_ms)
{
    long end = zkt_now_ms() + timeout_ms;
    while (zkt_log_count(SITE) < n) {
        if (zkt_now_ms() >= end) {
            return -1;
        }
        drive(20);
    }
    return 0;
}

int main(int argc, char **argv)
{
    char ca[1100];
    char good[1100];
    char bad[1100];
    char cs[4096];
    zhandle_t *zh;
    int64_t sid;
    struct Stat st;

    zkc_init(argc, argv, "ldg_c_tls_rotate", 1, "EXACT", "ignore");
    if (zkt_setup(1) != 0) {
        return zkc_finish();
    }
    snprintf(ca, sizeof(ca), "%s.ca.pem", zkt_out());
    snprintf(good, sizeof(good), "%s/server.crt", zkt_certs());
    snprintf(bad, sizeof(bad), "%s/ca.pem", zkt_fix());
    snprintf(cs, sizeof(cs), "%s,,,", ca);
    if (copy_file(bad, ca) != 0) {
        zkc_fail("cannot write the CA file");
        return zkc_finish();
    }

    /* The first attempts read the zk-driver CA and fail. */
    zkc_ev("case", "%s CA file holds the zk-driver CA", LABEL);
    zkt_log_reset();
    zh = zkt_init(zkt_host(0), cs, 30000, NULL, LABEL, 0);
    if (zh == NULL) {
        return zkc_finish();
    }
    if (refusals(1, 10000) != 0) {
        zkc_ev("wait", "%s no refusal in 10 s", LABEL);
    }
    zkt_log_record(LABEL, SITE, 1);

    /* A later attempt of the same handle reads the testSSL CA. */
    zkc_ev("case", "%s CA file holds the testSSL CA", LABEL);
    if (copy_file(good, ca) != 0) {
        zkc_fail("cannot write the CA file");
    }
    if (zkc_await("session:CONNECTED@" LABEL, 1, 20000) != 0) {
        zkc_ev("wait", "%s no CONNECTED in 20 s", LABEL);
        zkc_close(zh);
        return zkc_finish();
    }
    sid = zoo_client_id(zh)->client_id;
    zkc_ev("call", "zoo_acreate /ldg_c_tls_rotate -> %s",
           zkc_rc(zoo_acreate(zh, "/ldg_c_tls_rotate", "x", 1,
                              &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL,
                              zkc_string_cb, "create")));
    zkc_await("cb", 1, 10000);

    /* The wrong CA again: the attempts after a server restart fail. */
    zkc_ev("case", "%s CA file holds the zk-driver CA, server restarts",
           LABEL);
    if (copy_file(bad, ca) != 0) {
        zkc_fail("cannot write the CA file");
    }
    zkt_log_reset();
    zkc_server("stop", 0);
    zkc_await("session:CONNECTING@" LABEL, 1, 15000);
    zkc_server("start", 0);
    if (refusals(1, 20000) != 0) {
        zkc_ev("wait", "%s no refusal in 20 s", LABEL);
    }
    zkt_log_record(LABEL, SITE, 1);

    /* The right CA again: the same handle connects in the same session. */
    zkc_ev("case", "%s CA file holds the testSSL CA again", LABEL);
    if (copy_file(good, ca) != 0) {
        zkc_fail("cannot write the CA file");
    }
    if (zkc_await("session:CONNECTED@" LABEL, 1, 20000) != 0) {
        zkc_ev("wait", "%s no CONNECTED in 20 s", LABEL);
    } else {
        zkc_ev("ret", "same session=%d", zoo_client_id(zh)->client_id == sid);
        zkc_ev("call", "zoo_exists /ldg_c_tls_rotate -> %s",
               zkc_rc(zkcs_exists(zh, "/ldg_c_tls_rotate", 0, &st)));
    }
    zkc_close(zh);
    return zkc_finish();
}
