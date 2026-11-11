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
 * TLS records at close, at errors and with plaintext next to an error
 * (TLS-05, TLS-06; TL-09, TL-09b, TL-13). Mode PER-ROLE. TLS-06 is a P6
 * row, so its rules are zkc_fail assertions for each core and not DEV
 * checks.
 *
 * Rules:
 * - TL-13(a), TLS-06: legacy sends no close_notify, so a graceful close
 *   sends no client record after the CloseSession reply. The Rust core
 *   sends one close_notify record there.
 * - TL-09: a received EOF gives ZCONNECTIONLOSS. The Rust core
 *   sends nothing on that connection (TLS-06). OpenSSL 3 sends a fatal
 *   alert there, so the case does not check the legacy count.
 * - TL-13(d): a corrupt record gives ZCONNECTIONLOSS. The client sends
 *   one fatal alert record and no close_notify. A verify failure in the
 *   handshake also sends one fatal alert record.
 * - TL-09b(a): a ConnectResponse that reports expiry and the close_notify
 *   of the server in one read give EXPIRED, not ZCONNECTIONLOSS.
 * - TL-09b(b): a reply and a bad record in one read deliver the reply
 *   with its own rc first, then the ZCONNECTIONLOSS teardown.
 *
 * Each handle connects through the record proxy of zkconf_tls.c. The
 * proxy counts the TLS records of each direction. The counts leave out
 * ChangeCipherSpec records (type 20), because TLS 1.3 sends them only
 * for middlebox compatibility. Legacy sends the length of a frame and
 * its body in two records, so the case counts the client records after
 * a server record, not the records of a request. At a graceful close,
 * that record is the CloseSession reply, the first server record after
 * the close starts. The server can send one more record when it closes
 * its side. That record can come before or after the close_notify of the
 * client, so the case does not count from it. The case does
 * not compare the alert description (TL-13). The bad record of
 * TL-09b(b) is a replay of the reply record, which fails the record MAC
 * check.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_tls.h"

#include <stdio.h>
#include <string.h>

#define T_MS 30000

static char g_cert[4096];
static const char *g_px;

/* Client records of conn since a mark, without ChangeCipherSpec. */
static int client_records(int conn, long since)
{
    return zkt_proxy_count(ZKT_C2S, since, conn, 0) -
           zkt_proxy_count(ZKT_C2S, since, conn, 20);
}

static zhandle_t *open_px(const char *ctx)
{
    char key[128];
    zhandle_t *zh = zkt_init(g_px, g_cert, T_MS, NULL, ctx, 0);
    if (zh == NULL) {
        return NULL;
    }
    snprintf(key, sizeof(key), "session:CONNECTED@%s", ctx);
    if (zkc_await(key, 1, 15000) != 0) {
        zkc_fail("%s: no CONNECTED", ctx);
    }
    return zh;
}

static void wait_end(const char *what, int conn)
{
    int rc = zkt_proxy_wait_end(conn, 10000);
    zkc_ev("proxy", "%s: the client ends its connection: %s", what,
           rc == 0 ? "yes" : "no");
}

/* Client records of conn after its last server record. */
static int records_after_server(int conn)
{
    long last_s = zkt_proxy_last(ZKT_S2C, conn);
    return client_records(conn, last_s + 1);
}

static void graceful(void)
{
    zhandle_t *zh = open_px("graceful");
    char ev[2048];
    int conn;
    long mark;
    long reply;
    int n;
    if (zh == NULL) {
        return;
    }
    conn = zkt_proxy_conns();
    mark = zkt_proxy_mark();
    zkc_close(zh);
    wait_end("graceful", conn);
    /* The first server record after the mark is the CloseSession reply. */
    reply = zkt_proxy_first(ZKT_S2C, conn, mark);
    n = reply < 0 ? -1 : client_records(conn, reply + 1);
    zkt_proxy_events(ev, sizeof(ev), conn, mark);
    if (zkc_is_rust() && n != 1) {
        zkc_fail("TLS-06 graceful close: %d client records after the "
                 "CloseSession reply, want 1 (close_notify); records %s", n, ev);
    } else if (!zkc_is_rust() && n != 0) {
        zkc_fail("TLS-06 graceful close: %d client records after the "
                 "CloseSession reply, want 0 (no close_notify); records %s",
                 n, ev);
    }
}

static void eof(void)
{
    zhandle_t *zh = open_px("eof");
    char ev[2048];
    int conn;
    long mark;
    int n;
    if (zh == NULL) {
        return;
    }
    conn = zkt_proxy_conns();
    mark = zkt_proxy_mark();
    zkt_proxy_arm(ZKT_PX_EOF);
    zkc_await("session:CONNECTING@eof", 1, 10000);
    wait_end("eof", conn);
    n = client_records(conn, mark);
    zkt_proxy_events(ev, sizeof(ev), conn, mark);
    /*
     * TLS-06 says that an EOF sends nothing. OpenSSL 3 takes an EOF
     * without close_notify as a fatal record error, and sends one alert.
     * Thus the case does not check the legacy record count.
     */
    if (zkc_is_rust() && n != 0) {
        zkc_fail("TLS-06 eof: %d client records after the EOF, want 0; "
                 "records %s", n, ev);
    }
    zkc_await("session:CONNECTED@eof", 1, 15000);
    zkc_close(zh);
}

static void corrupt(void)
{
    zhandle_t *zh = open_px("corrupt");
    int conn;
    long mark;
    if (zh == NULL) {
        return;
    }
    conn = zkt_proxy_conns();
    mark = zkt_proxy_mark();
    zkt_proxy_arm(ZKT_PX_CORRUPT);
    zkc_ev("call", "zoo_aexists / -> %s",
           zkc_rc(zoo_aexists(zh, "/", 0, zkc_stat_cb, "exists")));
    zkc_await("cb", 1, 10000);
    zkc_await("session:CONNECTING@corrupt", 1, 10000);
    wait_end("corrupt", conn);
    /* One fatal alert after the bad record. */
    zkc_ev("proxy", "corrupt: client records after the bad record: %d",
           records_after_server(conn));
    (void)mark;
    zkc_await("session:CONNECTED@corrupt", 1, 15000);
    zkc_close(zh);
}

static void verify_failure(void)
{
    char cert[4096];
    zhandle_t *zh;
    int conn;
    long mark = zkt_proxy_mark();
    int n;
    snprintf(cert, sizeof(cert), "%s/ca.pem,,,", zkt_fix());
    zh = zkt_init(g_px, cert, T_MS, NULL, "verify", 0);
    if (zh == NULL) {
        return;
    }
    conn = zkt_proxy_conns() + 1;
    {
        long end = zkt_now_ms() + 10000;
        while (zkt_proxy_conns() < conn && zkt_now_ms() < end) {
            zkc_poll(20);
        }
    }
    {
        long end = zkt_now_ms() + 10000;
        while (zkt_proxy_wait_end(conn, 20) != 0 && zkt_now_ms() < end) {
            zkc_poll(20);
        }
    }
    zkc_close(zh);
    /* The ClientHello and one fatal alert. */
    n = client_records(conn, mark) -
        zkt_proxy_count(ZKT_C2S, mark, conn, 22);
    zkc_ev("proxy", "verify: client records after the ClientHello: %d", n);
}

static void expired_coalesced(void)
{
    zhandle_t *zh = open_px("expired");
    int recs = 0;
    long bytes;
    if (zh == NULL) {
        return;
    }
    zkt_proxy_arm(ZKT_PX_COALESCE);
    zkc_ev("expire", "-> %s",
           zkc_expire(zh, zkc_host(0)) == 0 ? "EXPIRED" : "no EXPIRED");
    bytes = zkt_proxy_coalesced(&recs);
    zkc_ev("proxy", "expired: one send of %d records%s", recs,
           bytes > 0 ? "" : " (no bytes)");
    zkc_ev("call", "zoo_state -> %s", zkc_state(zoo_state(zh)));
    zkc_close(zh);
}

static void reply_then_error(void)
{
    zhandle_t *zh = open_px("replay");
    if (zh == NULL) {
        return;
    }
    zkt_proxy_arm(ZKT_PX_REPLAY);
    zkc_ev("call", "zoo_aexists / -> %s",
           zkc_rc(zoo_aexists(zh, "/", 0, zkc_stat_cb, "exists")));
    zkc_await("cb", 1, 10000);
    zkc_await("session:CONNECTING@replay", 1, 10000);
    zkc_await("session:CONNECTED@replay", 1, 15000);
    zkc_close(zh);
}

int main(int argc, char **argv)
{
    const char *c;
    zkc_init(argc, argv, "tls_close", 1, "PER-ROLE", "ignore");
    if (zkt_setup(1) != 0) {
        return zkc_finish();
    }
    c = zkt_certs();
    snprintf(g_cert, sizeof(g_cert),
             "%s/server.crt,%s/client.crt,%s/clientkey.pem,password", c, c, c);
    g_px = zkt_proxy_start(zkt_host(0));
    if (g_px == NULL) {
        return zkc_finish();
    }
    graceful();
    eof();
    corrupt();
    verify_failure();
    expired_coalesced();
    reply_then_error();
    zkt_proxy_stop();
    return zkc_finish();
}
