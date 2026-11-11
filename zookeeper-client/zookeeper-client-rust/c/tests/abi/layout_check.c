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
 * Layout check of the public types (spec "The C
 * Compatibility Layer": public layouts match upstream on each ABI).
 *
 * The program includes the public headers as an application does. The
 * fact table comes from tests/abi/layout/<target>.expect through
 * layout-facts.awk. Each fact is a _Static_assert, so a wrong layout
 * stops the build. The program also compares the facts at run time and
 * prints each mismatch, so that a report shows all of them.
 *
 * Build: cc -std=c11 -I<include dirs> -I<dir of layout_facts.inc>
 * layout_check.c. Define HAVE_OPENSSL_H and HAVE_CYRUS_SASL_H for the
 * tls-sasl table. _Static_assert needs C11. The library itself stays
 * C99.
 */

#include <stddef.h>
#include <stdio.h>

#include <zookeeper.h>
#include <zookeeper_log.h>
#include <recordio.h>
#include <proto.h>

/* Compile-time check of every fact. */
#define ZK_FACT(expr, want, what) _Static_assert((expr) == (want), what);
#include "layout_facts.inc"
#undef ZK_FACT

struct zk_fact {
    const char *what;
    unsigned long long got;
    unsigned long long want;
};

/* Run-time copy of the same facts, for the report. */
#define ZK_FACT(expr, want, what) {what, (unsigned long long)(expr), (want)},
static const struct zk_fact zk_facts[] = {
#include "layout_facts.inc"
};
#undef ZK_FACT

int main(void)
{
    size_t i;
    size_t n = sizeof(zk_facts) / sizeof(zk_facts[0]);
    int bad = 0;

    for (i = 0; i < n; i++) {
        if (zk_facts[i].got != zk_facts[i].want) {
            printf("FAIL %s: measured %llu\n", zk_facts[i].what, zk_facts[i].got);
            bad++;
        }
    }
    printf("layout_check: %lu facts, %d mismatches\n", (unsigned long)n, bad);
    return bad == 0 ? 0 : 1;
}
