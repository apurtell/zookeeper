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
 * LINK-03 (ledger DV-ABI-1): the application defines its own global symbols
 * with the names of undeclared legacy internals. The legacy static archives
 * define these names too, so a static link with legacy can fail. The Rust
 * core does not define them, so the link works, and each name keeps the
 * definition of the application.
 *
 * The names come from the removed set of DV-ABI-1: the globals of the
 * legacy archives that are in neither abi/symbols.tsv nor
 * abi/static-symbols.tsv. The types are those of the application, not
 * those of legacy.
 *
 * Ledger: DV-ABI-1
 */

int hash(void *key);
int do_io(void *zh);
int get_xid(void);
int flush_send_queue(void *zh, int timeout);
int adaptor_init(void *zh);
void adaptor_finish(void *zh);
int api_prolog(void *zh);
int api_epilog(void *zh, int rc);
int addrvec_init(void *avec);
void *hashtable_search(void *h, void *k);
void *create_hashtable(unsigned int minsize);
void deliverWatchers(void *zh, int type, int state, char *path, void **list);
void enter_critical(void *zh);
long get_system_time(void);
int send_ping(void *zh);
void process_completions(void *zh);
int zklink_own_check(void);

/* The legacy data objects with these names are read-only. These ones
 * are writable, and they have other values. */
int MAX_RW_TIMEOUT = 4242;
int MIN_RW_TIMEOUT = 4343;
double max_load_factor = 0.25;

static int calls;

int hash(void *key)
{
    (void)key;
    calls++;
    return 101;
}

int do_io(void *zh)
{
    (void)zh;
    calls++;
    return 102;
}

int get_xid(void)
{
    calls++;
    return 103;
}

int flush_send_queue(void *zh, int timeout)
{
    (void)zh;
    calls++;
    return 104 + timeout;
}

int adaptor_init(void *zh)
{
    (void)zh;
    calls++;
    return 105;
}

void adaptor_finish(void *zh)
{
    (void)zh;
    calls++;
}

int api_prolog(void *zh)
{
    (void)zh;
    calls++;
    return 106;
}

int api_epilog(void *zh, int rc)
{
    (void)zh;
    calls++;
    return rc;
}

int addrvec_init(void *avec)
{
    (void)avec;
    calls++;
    return 107;
}

void *hashtable_search(void *h, void *k)
{
    (void)k;
    calls++;
    return h;
}

void *create_hashtable(unsigned int minsize)
{
    calls++;
    return minsize == 108 ? &calls : 0;
}

void deliverWatchers(void *zh, int type, int state, char *path, void **list)
{
    (void)zh;
    (void)type;
    (void)state;
    (void)path;
    (void)list;
    calls++;
}

void enter_critical(void *zh)
{
    (void)zh;
    calls++;
}

long get_system_time(void)
{
    calls++;
    return 109;
}

int send_ping(void *zh)
{
    (void)zh;
    calls++;
    return 110;
}

void process_completions(void *zh)
{
    (void)zh;
    calls++;
}

/* Calls each definition once. The result is 0 when each one gives the
 * value of this file and the core called none of them. */
int zklink_own_check(void)
{
    /* No call came from the core since the last check. */
    int bad = calls != 0;

    bad += hash(0) != 101;
    bad += do_io(0) != 102;
    bad += get_xid() != 103;
    bad += flush_send_queue(0, 1) != 105;
    bad += adaptor_init(0) != 105;
    adaptor_finish(0);
    bad += api_prolog(0) != 106;
    bad += api_epilog(0, 7) != 7;
    bad += addrvec_init(0) != 107;
    bad += hashtable_search(&bad, 0) != &bad;
    bad += create_hashtable(108) != &calls;
    deliverWatchers(0, 0, 0, 0, 0);
    enter_critical(0);
    bad += get_system_time() != 109;
    bad += send_ping(0) != 110;
    process_completions(0);
    bad += MAX_RW_TIMEOUT != 4242 || MIN_RW_TIMEOUT != 4343 || max_load_factor != 0.25;
    /* This function made 16 calls. Any other call came from the core. */
    bad += calls != 16;
    calls = 0;
    return bad;
}
