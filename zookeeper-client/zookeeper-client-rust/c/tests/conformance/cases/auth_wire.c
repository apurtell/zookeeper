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
 * Digest auth on the wire (AUT-01, AUT-03, AUT-04; DV-FIX-11;
 * ZOOKEEPER-800). Mode PER-ROLE. The log is ignored, because the reconnect
 * log lines depend on timing.
 *
 * The handle connects through the capture proxy of zkconf_wire.h. The
 * proxy records the request frames and can hold the replies.
 *
 * Timing (DSP-12): in the legacy mt core, zoo_add_auth on a connected
 * handle does not wake the IO thread (zookeeper.c:5340-5349). The AUTH
 * frame waits for the next IO event, which can be the ping timer at T/3.
 * T is 15 s here, so a legacy auth can take 5 s to reach the proxy. Each
 * wait for an AUTH frame on a connected handle allows 10 s. A wait for an
 * auth completion also allows 10 s, because a loaded host can delay a
 * relayed reply. One wait is short: the wait for a second completion from
 * one reply. Only the legacy core gives that completion. The Rust core
 * wakes its IO thread at once. The proxy passes the ping replies during a
 * hold. The ping replies refresh the receive time of the client. Thus the
 * client does not reach its 2T/3 receive timeout during the hold
 * (zookeeper.c:2745-2762).
 *
 * Rules:
 * - AUT-01: after a reconnect, the client sends every auth before the
 *   SetWatches frame and the held-back requests (send_auth_info pushes
 *   each auth to the front, zookeeper.c:2212-2229).
 * - AUT-01: zoo_add_auth while ASSOCIATING without SASL queues its AUTH
 *   frame at the front (zookeeper.c:5340-5347). The frame goes out after
 *   the connect reply, behind the resent auths and SetWatches, so the
 *   server gets the new auth twice.
 * - DV-FIX-11 (AUT-03): the legacy core completes every pending auth on
 *   one AUTH reply (auth_completion_func, zookeeper.c:2151-2189). The
 *   Rust core completes only the auth of that reply, in wire order. The
 *   trace omits these results, and a DEV check records them for each
 *   core.
 * - DV-FIX-11 (AUT-03, AUT-04): a second handle sends a digest auth and then an
 *   auth that the server rejects. Both replies arrive before the server
 *   close. The legacy core gives ZOK to both auths. The Rust core gives
 *   ZOK to the first and ZAUTHFAILED to the second. Both cores then go
 *   to AUTH_FAILED. In the legacy core, each of the two auths can wait
 *   T/3 for the ping timer. The proxy holds the replies for up to 2T/3,
 *   but the ping replies pass.
 * - DV-FIX-11 (AUT-04): a third handle adds a digest auth and then a
 *   rejected auth while it waits for the connect reply. The resend puts
 *   the rejected auth first on the wire. The legacy core completes both
 *   auths on that one reply, in list order. The Rust core completes the
 *   rejected auth on its reply, and the AUTH_FAILED teardown then
 *   completes the other auth. Both get ZAUTHFAILED in both cores.
 * - ZOOKEEPER-800: zoo_add_auth in the state-0 gap after a connection
 *   loss gives ZINVALIDSTATE. This is st only, because the mt IO thread
 *   leaves state 0 at once.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"
#include "zkconf_wire.h"

#include <string.h>

static volatile int g_auth;
static volatile int g_exists;

static void auth_cb(int rc, const void *d)
{
    zkc_void_cb(rc, d);
    __atomic_fetch_add(&g_auth, 1, __ATOMIC_SEQ_CST);
}

static void exists_cb(int rc, const struct Stat *s, const void *d)
{
    zkc_stat_cb(rc, s, d);
    __atomic_fetch_add(&g_exists, 1, __ATOMIC_SEQ_CST);
}

static int count(const volatile int *v)
{
    return __atomic_load_n(v, __ATOMIC_SEQ_CST);
}

/*
 * The auths of the DV-FIX-11 checks. Their callback writes no trace
 * event, because the completion order depends on the core.
 */
struct dev_auth {
    const char *cred;
    int rc;
    int done;
    int seq;
};

#define DEV_AUTHS 6

static struct dev_auth g_dev[DEV_AUTHS] = {
    {"b1:p", 0, 0, 0},
    {"b2:p", 0, 0, 0},
    {"c1:p", 0, 0, 0},
    {"c2:p", 0, 0, 0},
    {"e1:p", 0, 0, 0},
    {"e2:p", 0, 0, 0},
};

/* The completion count of the DV-FIX-11 auths. It gives the order. */
static volatile int g_dev_seq;

static void dev_auth_cb(int rc, const void *d)
{
    int i;
    for (i = 0; i < DEV_AUTHS; i++) {
        if (d == (const void *)&g_dev[i]) {
            __atomic_store_n(&g_dev[i].seq, __atomic_add_fetch(&g_dev_seq, 1, __ATOMIC_SEQ_CST),
                             __ATOMIC_SEQ_CST);
            __atomic_store_n(&g_dev[i].rc, rc, __ATOMIC_SEQ_CST);
            __atomic_fetch_add(&g_dev[i].done, 1, __ATOMIC_SEQ_CST);
        }
    }
    __atomic_fetch_add(&g_auth, 1, __ATOMIC_SEQ_CST);
}

static void dev_add_auth(zhandle_t *zh, const char *scheme, int i)
{
    const char *cred = g_dev[i].cred;
    int rc = zoo_add_auth(zh, scheme, cred, (int)strlen(cred), dev_auth_cb, &g_dev[i]);
    zkc_ev("call", "zoo_add_auth %s %s -> %s", scheme, cred, zkc_rc(rc));
}

static int dev_done(int i)
{
    return __atomic_load_n(&g_dev[i].done, __ATOMIC_SEQ_CST);
}

static int dev_rc(int i)
{
    return __atomic_load_n(&g_dev[i].rc, __ATOMIC_SEQ_CST);
}

static int dev_seq(int i)
{
    return __atomic_load_n(&g_dev[i].seq, __ATOMIC_SEQ_CST);
}

static void show_wire(const char *when)
{
    char buf[ZKW_LABEL_CAP];
    zkc_ev("wire", "%s: %s", when, zkw_labels(buf, sizeof buf));
}

static void add_auth(zhandle_t *zh, const char *cred)
{
    int rc = zoo_add_auth(zh, "digest", cred, (int)strlen(cred), auth_cb, cred);
    zkc_ev("call", "zoo_add_auth %s -> %s", cred, zkc_rc(rc));
}

static void aexists(zhandle_t *zh, const char *label, int watch)
{
    int rc = zoo_aexists(zh, "/zkconf-auth-wire-none", watch, exists_cb, label);
    zkc_ev("call", "zoo_aexists %s -> %s", label, zkc_rc(rc));
}

#ifndef THREADED
/*
 * ZOOKEEPER-800: a connection loss sets the state to 0 until the next
 * zookeeper_interest (handle_error, zookeeper.c:2116-2118). The st
 * watcher call comes after that, so the case is inside the gap.
 */
static void state_zero_gap(zhandle_t *zh)
{
    int state;
    int rc;
    zkw_clear();
    zkw_reset();
    zkc_await("session:CONNECTING@wire", 1, 10000);
    state = zoo_state(zh);
    rc = zoo_add_auth(zh, "digest", "gap:p", 5, auth_cb, "gap");
    zkc_ev("call", "zoo_add_auth gap:p state=%d -> %s", state, zkc_rc(rc));
    zkc_dev("RC-08", state == 0 && rc == ZINVALIDSTATE, "ZOOKEEPER-800: state=%d rc=%d", state, rc);
    zkc_await("session:CONNECTED@wire", 1, 10000);
    /* The resent auths and SetWatches go out after the CONNECTED event. */
    if (zkw_wait_count("W", 1, 5000) != 0) {
        zkc_fail("no SetWatches after the reconnect");
    }
}
#endif

/* AUT-01: the frame order of a reconnect, with an auth while ASSOCIATING. */
static void reconnect_order(zhandle_t *zh)
{
    zkw_clear();
    zkw_budget(0);
    zkw_reset();
    zkc_await("session:CONNECTING@wire", 1, 10000);
    if (zkw_wait_count("K", 1, 10000) != 0) {
        zkc_fail("no reconnect through the proxy");
        return;
    }
    zkc_ev("ret", "held state=%s", zkc_state(zoo_state(zh)));
    aexists(zh, "q1", 0);
    aexists(zh, "q2", 0);
    add_auth(zh, "a3:p");
    /* No frame may go out before the connect reply. 2 s bounds the wait. */
    (void)zkw_wait_count("A:a3", 1, 2000);
    show_wire("associating");

    zkw_budget(-1);
    zkc_await("session:CONNECTED@wire", 1, 10000);
    if (zkw_wait_int(&g_auth, 3, 10000) != 0 || zkw_wait_int(&g_exists, 3, 10000) != 0 ||
        zkw_wait_count("E", 2, 10000) != 0) {
        zkc_fail("the reconnect did not complete the queued work");
    }
    show_wire("reconnected");
}

/*
 * DV-FIX-11 (AUT-03, AUT-04): two auths, and the server rejects the second. The
 * replies wait in the proxy until both auths reach the server. The
 * unknown scheme "bogus" makes the server send AUTHFAILED and close.
 * In the legacy core, each auth can wait T/3 for the ping timer. The
 * ping replies pass the hold, so the client receive timeout does not
 * end the connection before the release.
 */
static void rejected_second(const char *px)
{
    zhandle_t *zh;
    int ok;
    zkw_budget(-1);
    zh = zookeeper_init2(px, zkc_watcher, 15000, NULL, "rej", 0, zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 rej -> %s", zh != NULL ? "zh" : "NULL");
    if (zh == NULL) {
        return;
    }
    zkc_poll_add(zh);
    if (zkc_await("session:CONNECTED@rej", 1, 15000) != 0) {
        zkc_close(zh);
        return;
    }
    zkw_clear();
    zkw_budget(0);
    dev_add_auth(zh, "digest", 2);
    /* The first auth must go out before the second one is queued. */
    if (zkw_wait_count("A:c1", 1, 10000) != 0) {
        zkc_fail("the first auth did not reach the proxy");
    }
    dev_add_auth(zh, "bogus", 3);
    if (zkw_wait_count("A:c2", 1, 10000) != 0) {
        zkc_fail("the second auth did not reach the proxy");
    }
    zkw_budget(-1);
    zkc_await("session:AUTH_FAILED@rej", 1, 10000);
    if (zkw_wait_int(&g_dev[2].done, 1, 10000) != 0 ||
        zkw_wait_int(&g_dev[3].done, 1, 10000) != 0) {
        zkc_fail("an auth did not complete");
    }
    show_wire("rejected second");
    zkc_ev("ret", "zoo_state rej -> %s", zkc_state(zoo_state(zh)));
    if (zkc_is_rust()) {
        ok = dev_rc(2) == ZOK && dev_rc(3) == ZAUTHFAILED;
    } else {
        ok = dev_rc(2) == ZOK && dev_rc(3) == ZOK;
    }
    zkc_dev("DV-FIX-11", ok && dev_done(2) == 1 && dev_done(3) == 1,
            "c1 done=%d rc=%s c2 done=%d rc=%s", dev_done(2), zkc_rc(dev_rc(2)), dev_done(3),
            zkc_rc(dev_rc(3)));
    zkc_close(zh);
}

/*
 * DV-FIX-11 (AUT-04): two auths wait in the list for the connect reply,
 * and the server rejects the one that goes first on the wire. The
 * resend sends the list in reverse order (AUT-01), so the rejected auth
 * goes first. The trace omits the wire labels, because the server close
 * can cut the capture of the later frames.
 */
static void rejected_first(const char *px)
{
    zhandle_t *zh;
    int ok;
    char labels[ZKW_LABEL_CAP];
    zkw_clear();
    zkw_budget(0);
    zh = zookeeper_init2(px, zkc_watcher, 15000, NULL, "fst", 0, zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 fst -> %s", zh != NULL ? "zh" : "NULL");
    if (zh == NULL) {
        zkw_budget(-1);
        return;
    }
    zkc_poll_add(zh);
    if (zkw_wait_count("K", 1, 10000) != 0) {
        zkc_fail("no connect through the proxy");
        zkw_budget(-1);
        zkc_close(zh);
        return;
    }
    dev_add_auth(zh, "digest", 4);
    dev_add_auth(zh, "bogus", 5);
    zkw_budget(-1);
    zkc_await("session:AUTH_FAILED@fst", 1, 10000);
    if (zkw_wait_int(&g_dev[4].done, 1, 10000) != 0 ||
        zkw_wait_int(&g_dev[5].done, 1, 10000) != 0) {
        zkc_fail("an auth did not complete");
    }
    zkc_ev("ret", "zoo_state fst -> %s", zkc_state(zoo_state(zh)));
    ok = dev_done(4) == 1 && dev_done(5) == 1 && dev_rc(4) == ZAUTHFAILED &&
         dev_rc(5) == ZAUTHFAILED;
    if (zkc_is_rust()) {
        ok = ok && dev_seq(5) < dev_seq(4);
    } else {
        ok = ok && dev_seq(4) < dev_seq(5);
    }
    zkc_dev("DV-FIX-11", ok, "e1 seq=%d rc=%s e2 seq=%d rc=%s wire=%s", dev_seq(4),
            zkc_rc(dev_rc(4)), dev_seq(5), zkc_rc(dev_rc(5)),
            zkw_labels(labels, sizeof labels));
    zkc_close(zh);
}

int main(int argc, char **argv)
{
    const char *px;
    zhandle_t *zh;
    int rc;
    int base;
    int n0;
    int n1;
    int first;
    char labels[ZKW_LABEL_CAP];

    zkc_init(argc, argv, "auth_wire", 1, "PER-ROLE", "ignore");
    px = zkw_start(zkc_host(0), -1);
    if (px == NULL) {
        return zkc_finish();
    }
    zh = zookeeper_init2(px, zkc_watcher, 15000, NULL, "wire", 0, zkc_log_cb);
    zkc_ev("call", "zookeeper_init2 proxy -> %s", zh != NULL ? "zh" : "NULL");
    if (zh == NULL) {
        zkw_stop();
        return zkc_finish();
    }
    zkc_poll_add(zh);
    if (zkc_await("session:CONNECTED@wire", 1, 15000) != 0) {
        zkc_close(zh);
        zkw_stop();
        return zkc_finish();
    }
    add_auth(zh, "a1:p");
    (void)zkw_wait_int(&g_auth, 1, 10000);
    add_auth(zh, "a2:p");
    (void)zkw_wait_int(&g_auth, 2, 10000);
    aexists(zh, "w", 1);
    (void)zkw_wait_int(&g_exists, 1, 10000);
    show_wire("connected");

    reconnect_order(zh);
#ifndef THREADED
    state_zero_gap(zh);
#endif

    /*
     * DV-FIX-11 (AUT-03): hold the replies, send two auths, then relay one
     * reply. The first auth on the wire owns the first reply.
     */
    base = count(&g_auth);
    zkw_clear();
    zkw_budget(0);
    dev_add_auth(zh, "digest", 0);
    dev_add_auth(zh, "digest", 1);
    /* The legacy core can send the two frames at the next ping, after T/3. */
    if (zkw_wait_count("A:b", 2, 10000) != 0) {
        zkc_fail("the auth frames did not reach the proxy");
    }
    n0 = count(&g_auth) - base;
    zkc_ev("ret", "auth completions held=%d", n0);
    first = strstr(zkw_labels(labels, sizeof labels), "A:b2") == labels ? 1 : 0;
    zkw_budget(1);
    /*
     * The one relayed reply completes at least one auth in both cores. A
     * loaded host can delay that reply, so the first wait is long. The
     * legacy core completes the second auth in the same pass as the first,
     * so the second wait needs no margin for load. The proxy holds the
     * second reply, so a long wait cannot complete a second Rust auth.
     */
    (void)zkw_wait_int(&g_auth, base + 1, 10000);
    (void)zkw_wait_int(&g_auth, base + 2, 2000);
    n1 = count(&g_auth) - base;
    if (zkc_is_rust()) {
        zkc_dev("DV-FIX-11", n0 == 0 && n1 == 1 && dev_done(first) == 1 && dev_rc(first) == ZOK,
                "held=%d after one reply=%d first=b%d done=%d", n0, n1, first + 1,
                dev_done(first));
    } else {
        zkc_dev("DV-FIX-11", n0 == 0 && n1 == 2, "held=%d after one reply=%d", n0, n1);
    }
    zkw_budget(-1);
    (void)zkw_wait_int(&g_auth, base + 2, 10000);
    show_wire("two auths");
    zkc_dev("DV-FIX-11", dev_done(0) == 1 && dev_done(1) == 1 && dev_rc(0) == ZOK &&
                             dev_rc(1) == ZOK,
            "b1 done=%d rc=%s b2 done=%d rc=%s", dev_done(0), zkc_rc(dev_rc(0)), dev_done(1),
            zkc_rc(dev_rc(1)));

    zkc_close(zh);
    rc = count(&g_auth) - base;
    zkc_ev("ret", "auth completions total=%d", rc);

    rejected_second(px);
    rejected_first(px);
    zkw_stop();
    return zkc_finish();
}
