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
 * The SASL preload of the SASL cases (zkconf_sasl_preload.c). A case
 * finds these functions with dlsym(RTLD_DEFAULT, ...), because the
 * preload is not in its link.
 *
 * Event letters, in call order:
 *   N  sasl_client_new
 *   D  sasl_dispose of a live connection
 *   C  close of a server socket after an address read on it
 *   G  getsockname on a server socket
 *   P  getpeername on a server socket
 *   other letters: the marks of the case (zkconf_sasl_mark)
 */

#ifndef ZKCONF_SASL_PRELOAD_H_
#define ZKCONF_SASL_PRELOAD_H_

/* Copies the event letters into buf with a NUL. Returns the count. */
typedef int (*zkconf_sasl_events_fn)(char *buf, int cap);
/* Adds the letter c to the event list. */
typedef void (*zkconf_sasl_mark_fn)(char c);
/* The next n address reads (getsockname or getpeername) on a server socket fail. */
typedef void (*zkconf_sasl_fail_fn)(int n);
/* The number of open server sockets. Also the type of zkconf_sasl_gated. */
typedef int (*zkconf_sasl_open_fn)(void);
/*
 * on=1 holds the next sasl_client_new until on=0, for at most 10
 * seconds. zkconf_sasl_gated returns 1 while a thread waits.
 */
typedef void (*zkconf_sasl_gate_fn)(int on);

#endif /* ZKCONF_SASL_PRELOAD_H_ */
