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
 * SAS-15.
 * The order of the Cyrus calls and the socket close (SAS-13).
 * Mode PER-ROLE. The log is ignored, because the connect retries of the
 * restart depend on timing.
 *
 * The SASL preload records sasl_client_new (N), sasl_dispose (D) and the
 * close of a server socket that reached a SASL start (C). The case adds
 * its own marks (lower-case letters). The trace shows the list without
 * the address reads. Their position against the dispose is a syscall
 * order that is not compared, because an application cannot see it.
 *
 * Rules:
 * - Dispose timing: a teardown does not dispose. The old connection is
 *   disposed at the next SASL start, just before its sasl_client_new
 *   ("C b D N"), as legacy zoo_sasl_connect does (zk_sasl.c:215-217).
 * - Close order: at zookeeper_close the socket closes before
 *   sasl_dispose runs ("z C D"), as legacy destroy does
 *   (zookeeper.c:719-749).
 *
 * Run it with --sasl and the SASL libraries of both cores.
 *
 * zkconf-flavors: mt st
 * zkconf-preload: sasl
 */

#include "zkconf_sasl.h"
#include "zkconf_sync.h"

static void show_order(const char *when)
{
#ifdef HAVE_CYRUS_SASL_H
    char buf[256];
    zkc_ev("order", "%s: %s", when, zkcs_order(buf, sizeof buf));
#else
    (void)when;
#endif
}

#ifdef HAVE_CYRUS_SASL_H
static void run(void)
{
    sasl_callback_t *cb;
    zhandle_t *zh;
    char pwfile[1024];
    const char *prefix = getenv("ZKCONF_OUT");

    snprintf(pwfile, sizeof pwfile, "%s.pw", prefix != NULL ? prefix : "/tmp/zkconf");
    if (zkcs_write_file(pwfile, "mypassword\n", 11) != 0) {
        zkc_fail("cannot write the password file");
        return;
    }
    cb = zkcs_sasl()->basic(ZKCS_SASL_USER, NULL, pwfile);
    zh = cb != NULL ? zkcs_sasl_init(zkc_host(0), "order", cb, zkc_watcher, NULL, 10000) : NULL;
    zkc_ev("call", "zookeeper_init_sasl -> %s", zh != NULL ? "zh" : "NULL");
    if (zh == NULL) {
        free(cb);
        return;
    }
    zkc_poll_add(zh);
    zkc_await("session:CONNECTED@order", 1, 15000);
    zkcs_mark('a');
    show_order("connected");

    /* A teardown closes the socket and keeps the Cyrus connection. */
    zkc_server("stop", 0);
    zkc_await("session:CONNECTING@order", 1, 15000);
    zkcs_mark('b');
    show_order("connecting");

    /* The next start disposes the old connection first. */
    zkc_server("start", 0);
    zkc_await("session:CONNECTED@order", 1, 30000);
    zkcs_mark('c');
    show_order("reconnected");

    /* The final close: the socket first, then the dispose. */
    zkcs_mark('z');
    zkc_close(zh);
    show_order("closed");
    free(cb);
    (void)remove(pwfile);
}
#endif

int main(int argc, char **argv)
{
    zkc_init(argc, argv, "sasl_order", 1, "PER-ROLE", "ignore");
#ifdef HAVE_CYRUS_SASL_H
    if (zkcs_sasl_resolve() == 0 && zkcs_has_preload()) {
        run();
        return zkc_finish();
    }
#endif
    show_order("none");
    zkc_ev("check", "skip: no SASL library, no SASL server or no SASL preload");
    return zkc_finish();
}
