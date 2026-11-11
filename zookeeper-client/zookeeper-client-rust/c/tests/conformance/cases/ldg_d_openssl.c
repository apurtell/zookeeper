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
 * The process-global OpenSSL state of a TLS session (ledger GLB-08,
 * DV-TLS-4; zookeeper.c init_ssl_for_socket). Mode DEV.
 *
 * The case connects with zookeeper_init_ssl and runs one exists call
 * on the secure port. Both cores must complete the call with ZOK. Then
 * the case looks for OpenSSL symbols in the images of the process. The
 * case itself links only the library under test.
 *
 * The cores differ in the OpenSSL state (GLB-08):
 * - Legacy links libssl and libcrypto and initializes them for the
 *   whole process. The OpenSSL symbols are present.
 * - Rust contains no OpenSSL code. No image of the process gives the
 *   OpenSSL symbols, so the library creates and touches no OpenSSL
 *   state.
 *
 * The case needs run.sh --tls and an ssl or full library on both cores.
 * Without them, zkt_setup records a skip.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_sync.h"
#include "zkconf_tls.h"

#include <dlfcn.h>
#include <stdio.h>

static const char *const g_syms[] = {"OPENSSL_init_ssl", "SSL_CTX_new",
                                     "ERR_get_error"};

int main(int argc, char **argv)
{
    char cert[4096];
    const char *c;
    zhandle_t *zh;
    struct Stat st;
    int rc;
    int found = 0;
    size_t i;

    zkc_init(argc, argv, "ldg_d_openssl", 1, "DEV", "ignore");
    if (zkt_setup(1) != 0) {
        return zkc_finish();
    }
    c = zkt_certs();
    snprintf(cert, sizeof(cert),
             "%s/server.crt,%s/client.crt,%s/clientkey.pem,password", c, c, c);
    zh = zkt_init(zkt_host(0), cert, 30000, NULL, "tls", 0);
    if (zh == NULL) {
        zkc_fail("zookeeper_init_ssl failed");
        return zkc_finish();
    }
    rc = zkcs_exists(zh, "/", 0, &st);
    zkc_dev("GLB-08", rc == ZOK, "exists over TLS -> %s", zkc_rc(rc));

    for (i = 0; i < sizeof(g_syms) / sizeof(g_syms[0]); i++) {
        int has = dlsym(RTLD_DEFAULT, g_syms[i]) != NULL;
        zkc_ev("check", "%s %s", g_syms[i], has ? "present" : "absent");
        found += has;
    }
    if (zkc_is_rust()) {
        zkc_dev("GLB-08", found == 0,
                "%d of 3 OpenSSL symbols are in the process", found);
    } else {
        zkc_dev("GLB-08", found == 3,
                "legacy: %d of 3 OpenSSL symbols are in the process", found);
    }
    zkc_close(zh);
    return zkc_finish();
}
