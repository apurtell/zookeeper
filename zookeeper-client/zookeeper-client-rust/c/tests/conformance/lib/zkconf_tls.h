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
 * Helpers of the TLS cases. This is test code. It is never
 * installed or shipped.
 *
 * A TLS case finds zookeeper_init_ssl at run time, because the headers
 * declare it only with HAVE_OPENSSL_H. The servers come from run.sh
 * --tls: ZKCONF_TLS_HOSTS has the secure ports, and ZKCONF_TLS_DIR has
 * the gencerts.sh files. A handle of zookeeper_init_ssl has no log
 * callback, so the helpers send the library log to a stream file and
 * read the lines back.
 *
 * The proxy is a TLS record counter between a client and one server. It
 * forwards whole TLS records and records the content type and the length
 * of each record. It can also change the records from the server, so
 * that a case can make a record error, two records in one read, or an
 * end of stream at a known point.
 */

#ifndef ZKCONF_TLS_H_
#define ZKCONF_TLS_H_

#include <stddef.h>
#include <zookeeper.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Finds zookeeper_init_ssl and the certificate directories, waits for the
 * secure ports of the first nservers servers, and opens the log stream
 * file. Returns 0 on success. On -1 the trace has a "skip" event or a
 * failure, and the case must call zkc_finish.
 */
int zkt_setup(int nservers);

/* The secure address of server index, and a list of count of them. */
const char *zkt_host(int index);
const char *zkt_hosts(int count);

/* The gencerts.sh directory and the zk-driver TLS fixture directory. */
const char *zkt_certs(void);
const char *zkt_fix(void);
/* The output prefix of the case (ZKCONF_OUT), for files of the case. */
const char *zkt_out(void);

/*
 * zookeeper_init_ssl with the recording watcher and the context label
 * ctx. Records the call. In st, the new handle goes into the poll
 * registry.
 */
zhandle_t *zkt_init(const char *hosts, const char *cert, int timeout_ms,
                    const clientid_t *id, const char *ctx, int flags);
/* The raw entry point, with no record. */
zhandle_t *zkt_init_raw(const char *hosts, const char *cert, watcher_fn fn,
                        int timeout_ms, const clientid_t *id, void *ctx,
                        int flags);

/* Copies in to out with the directories as CERTS, FIX and OUT. */
void zkt_norm_paths(char *out, size_t outlen, const char *in);

/*
 * The log stream. zkt_log_reset empties the file. zkt_log_count gives the
 * number of lines that contain needle. zkt_log_record adds each distinct
 * line with needle to the trace, in the order of first sight. The text
 * starts at "ZOO_", the paths and ports are normalized, and the errno
 * value of the line is hidden when hide_errno is 1.
 */
void zkt_log_reset(void);
int zkt_log_count(const char *needle);
void zkt_log_record(const char *label, const char *needle, int hide_errno);

/* The connect preload. Each function does nothing without the preload. */
int zkt_have_preload(void);
void zkt_connect_mode(int mode);
int zkt_connect_count(void);
long zkt_connect_time(int index);

/* The monotonic time and the CPU time of the process, in ms. */
long zkt_now_ms(void);
long zkt_cpu_ms(void);

/* The errno name of the traces. */
const char *zkt_errno(int e);

/* Writes an Ed25519 PKCS#8 key from a fixed seed (RFC 8410). */
int zkt_write_ed25519(const char *path);

#ifndef THREADED
/*
 * One st pass: zookeeper_interest, one select of at most max_ms, and
 * zookeeper_process for a ready socket. Returns the first rc that is not
 * ZOK or ZNOTHING, and *where names its call. *interest gets the interest
 * of the pass, *err gets errno after the failed call, and *mid gets
 * zoo_state after zookeeper_interest.
 */
int zkt_st_pass(zhandle_t *zh, int max_ms, int *interest, int *err,
                const char **where, int *mid);
#endif

/* The proxy record directions. */
#define ZKT_C2S 0
#define ZKT_S2C 1

/* Actions of the proxy (zkt_proxy_arm). */
#define ZKT_PX_PASS 0
/* The last byte of the next server record of type 23 changes. */
#define ZKT_PX_CORRUPT 1
/* The next server record of type 23 goes to the client twice, in one send. */
#define ZKT_PX_REPLAY 2
/*
 * The next connection holds the server bytes after the ConnectRequest.
 * At the end of the server stream, the proxy sends them in one send and
 * then ends the client stream.
 */
#define ZKT_PX_COALESCE 3
/* The proxy ends the client stream now and closes the server side. */
#define ZKT_PX_EOF 4

/* Starts the proxy to target. Returns "127.0.0.1:PORT", or NULL. */
const char *zkt_proxy_start(const char *target);
/* The server of the next connections. */
void zkt_proxy_target(const char *target);
void zkt_proxy_arm(int action);
/* The sequence number of the next record event. */
long zkt_proxy_mark(void);
/* The number of accepted connections. The first connection is 1. */
int zkt_proxy_conns(void);
/*
 * The number of records of dir since the mark, on connection conn (0:
 * any), with type 0 for any type.
 */
int zkt_proxy_count(int dir, long since, int conn, int type);
/* The sequence number of the last record of dir on conn, or -1. */
long zkt_proxy_last(int dir, int conn);
/*
 * The sequence number of the first record of dir on conn since the mark,
 * or -1.
 */
long zkt_proxy_first(int dir, int conn, long since);
/* Waits until the client ends connection conn. Returns 0 on success. */
int zkt_proxy_wait_end(int conn, int timeout_ms);
/* The bytes that the last coalesced send had, and its record count. */
long zkt_proxy_coalesced(int *records);
/* Writes the record events of conn as "C23/66 S23/40 ...". */
void zkt_proxy_events(char *buf, size_t len, int conn, long since);
void zkt_proxy_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* ZKCONF_TLS_H_ */
