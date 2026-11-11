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
 * The artifacts of each core (ABI-09, ABI-10, ABI-13, ABI-14;
 * DV-BLD-6). Mode DEV. The case needs no server.
 *
 * The case reads the shared library and the static archive of the core
 * under test with the platform tools. It checks these rules:
 *
 * - ABI-09: the identity of the shared library does not change. The
 *   name is libzookeeper_FL.2.dylib with the versions 3.0.0 (macOS), or
 *   the SONAME libzookeeper_FL.so.2 (Linux). The drop-in never needs
 *   libssl or libcrypto. A SASL build needs libsasl2.
 * - ABI-14: the drop-in needs only the system libraries and, with SASL,
 *   libsasl2. On Linux, the drop-in also needs libgcc_s.so.1.
 * - ABI-10 and DV-BLD-6: the drop-in archive has one prelinked member,
 *   and no global of the Rust core or its crypto crates. Legacy has one
 *   member for each source file.
 * - ABI-13: the drop-in archive does not define the internal globals of
 *   legacy (hash, do_io, get_xid, addrvec_*, hashtable_*, adaptor_*,
 *   MAX_RW_TIMEOUT). The legacy archive defines them.
 * - DV-BLD-8 (Linux only): the drop-in shared library has no GNU
 *   property note for IBT, SHSTK or BTI. The Rust objects carry no
 *   marker, so the link drops the note. Mach-O has no such note.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef THREADED
#define FL "mt"
#else
#define FL "st"
#endif

#ifdef __APPLE__
#define SYM_PREFIX "_"
#else
#define SYM_PREFIX ""
#endif

/* The output of one command. Each line ends with a newline. */
static char g_out[1 << 20];

static int run_cmd(const char *cmd)
{
    size_t n = 0;
    size_t r;
    FILE *p = popen(cmd, "r");
    g_out[0] = '\0';
    if (p == NULL) {
        return -1;
    }
    while (n + 1 < sizeof g_out && (r = fread(g_out + n, 1, sizeof g_out - 1 - n, p)) > 0) {
        n += r;
    }
    g_out[n] = '\0';
    return pclose(p) == 0 ? 0 : -1;
}

static int out_has(const char *text)
{
    return strstr(g_out, text) != NULL;
}

/* Counts the lines of g_out. skip excludes lines that start with it. */
static int count_lines(const char *skip)
{
    int n = 0;
    char *s = g_out;
    while (*s != '\0') {
        char *e = strchr(s, '\n');
        if (skip == NULL || strncmp(s, skip, strlen(skip)) != 0) {
            n++;
        }
        if (e == NULL) {
            break;
        }
        s = e + 1;
    }
    return n;
}

/*
 * Counts the defined globals of an nm listing with a name that starts
 * with one of the prefixes. The first match goes into first.
 */
static int count_defined(const char *const *prefixes, size_t np, char *first, size_t flen)
{
    int n = 0;
    char *s = g_out;
    first[0] = '\0';
    while (*s != '\0') {
        char addr[64];
        char type[8];
        char name[512];
        char *e = strchr(s, '\n');
        size_t i;
        if (e != NULL) {
            *e = '\0';
        }
        if (sscanf(s, "%63s %7s %511s", addr, type, name) == 3 && strcmp(type, "U") != 0) {
            for (i = 0; i < np; i++) {
                if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0) {
                    if (n == 0) {
                        snprintf(first, flen, "%s", name);
                    }
                    n++;
                    break;
                }
            }
        }
        if (e == NULL) {
            break;
        }
        *e = '\n';
        s = e + 1;
    }
    return n;
}

/* ABI-09, ABI-14 and DV-BLD-8: the identity, the needed libraries and the notes. */
static void shared(const char *libdir, int rust, int sasl, int tls)
{
    char cmd[1400];
#ifdef __APPLE__
    snprintf(cmd, sizeof cmd, "otool -L '%s/libzookeeper_%s.2.dylib' 2>&1", libdir, FL);
    if (run_cmd(cmd) != 0) {
        zkc_dev("ABI-09", 0, "otool -L fails: %s", g_out);
        return;
    }
    zkc_ev("check", "the property note rule (DV-BLD-8) applies to ELF only");
    zkc_dev("ABI-09",
            out_has("/libzookeeper_" FL ".2.dylib"
                    " (compatibility version 3.0.0, current version 3.0.0)"),
            "the install name is libzookeeper_%s.2.dylib with versions 3.0.0", FL);
    zkc_dev("ABI-09", out_has("/libsasl2.") == sasl, "libsasl2 is needed: %d (want %d)",
            out_has("/libsasl2."), sasl);
    if (rust) {
        zkc_dev("ABI-09", !out_has("/libssl.") && !out_has("/libcrypto."),
                "rust needs no libssl and no libcrypto");
        /* Every needed library other than the own name, libSystem and libsasl2. */
        {
            int extra = 0;
            char *s = strchr(g_out, '\n');
            while (s != NULL && s[1] != '\0') {
                char *line = s + 1;
                s = strchr(line, '\n');
                if (strstr(line, "/libzookeeper_") == NULL &&
                    strstr(line, "/usr/lib/libSystem.B.dylib") == NULL &&
                    strstr(line, "/libsasl2.") == NULL) {
                    extra++;
                }
            }
            zkc_dev("ABI-14", extra == 0,
                    "rust needs only libSystem and, with SASL, libsasl2: %d other libraries",
                    extra);
        }
    } else {
        zkc_dev("ABI-14", out_has("/libssl.") == tls && out_has("/libcrypto.") == tls,
                "legacy needs libssl and libcrypto only with TLS (tls %d)", tls);
    }
#else
    snprintf(cmd, sizeof cmd, "readelf -d '%s/libzookeeper_%s.so.2' 2>&1", libdir, FL);
    if (run_cmd(cmd) != 0) {
        zkc_dev("ABI-09", 0, "readelf -d fails: %s", g_out);
        return;
    }
    zkc_dev("ABI-09", out_has("Library soname: [libzookeeper_" FL ".so.2]"),
            "the SONAME is libzookeeper_%s.so.2", FL);
    zkc_dev("ABI-09", out_has("[libsasl2.so") == sasl, "libsasl2 is needed: %d (want %d)",
            out_has("[libsasl2.so"), sasl);
    if (rust) {
        zkc_dev("ABI-09", !out_has("[libssl.so") && !out_has("[libcrypto.so"),
                "rust needs no libssl and no libcrypto");
        zkc_dev("ABI-14", out_has("[libgcc_s.so.1]"), "rust needs libgcc_s.so.1");
    } else {
        zkc_dev("ABI-14", out_has("[libssl.so") == tls, "legacy needs libssl only with TLS");
    }
    snprintf(cmd, sizeof cmd, "readelf -n '%s/libzookeeper_%s.so.2' 2>&1", libdir, FL);
    if (run_cmd(cmd) != 0) {
        zkc_dev("DV-BLD-8", 0, "readelf -n fails: %s", g_out);
        return;
    }
    if (rust) {
        zkc_dev("DV-BLD-8", !out_has("IBT") && !out_has("SHSTK") && !out_has("BTI"),
                "rust has no IBT, SHSTK or BTI property note");
    } else {
        zkc_ev("check", "legacy property note: ibt %d shstk %d bti %d", out_has("IBT"),
               out_has("SHSTK"), out_has("BTI"));
    }
#endif
}

/* ABI-10, ABI-13 and DV-BLD-6: the archive members and globals. */
static void archive(const char *libdir, int rust)
{
    static const char *const core[] = {SYM_PREFIX "zks_", SYM_PREFIX "zkrs_", "__ZN", "_ZN",
                                       SYM_PREFIX "ring_", SYM_PREFIX "aws_lc"};
    static const char *const internal[] = {
        SYM_PREFIX "hash",     SYM_PREFIX "do_io",      SYM_PREFIX "get_xid",
        SYM_PREFIX "addrvec_", SYM_PREFIX "hashtable_", SYM_PREFIX "adaptor_",
        SYM_PREFIX "MAX_RW_TIMEOUT"};
    char cmd[1400];
    char first[512];
    int members;
    int n;

    snprintf(cmd, sizeof cmd, "ar t '%s/libzookeeper_%s.a' 2>&1", libdir, FL);
    if (run_cmd(cmd) != 0) {
        zkc_dev("DV-BLD-6", 0, "ar t fails: %s", g_out);
        return;
    }
    members = count_lines("__.SYMDEF");
    if (rust) {
        zkc_dev("DV-BLD-6", members == 1 && out_has("zookeeper_" FL "_all.o"),
                "rust has one prelinked member: %d members", members);
    } else {
        zkc_dev("DV-BLD-6", members > 1, "legacy has one member per source: %d members",
                members);
    }

    snprintf(cmd, sizeof cmd, "nm -g '%s/libzookeeper_%s.a' 2>&1", libdir, FL);
    if (run_cmd(cmd) != 0) {
        zkc_dev("ABI-10", 0, "nm -g fails: %s", g_out);
        return;
    }
    if (rust) {
        n = count_defined(core, sizeof core / sizeof core[0], first, sizeof first);
        zkc_dev("ABI-10", n == 0, "rust defines no global of the core: %d (first %s)", n,
                first);
    }
    n = count_defined(internal, sizeof internal / sizeof internal[0], first, sizeof first);
    if (rust) {
        zkc_dev("ABI-13", n == 0, "rust defines no internal global of legacy: %d (first %s)", n,
                first);
    } else {
        zkc_dev("ABI-13", n > 0, "legacy defines its internal globals: %d (first %s)", n, first);
    }
}

int main(int argc, char **argv)
{
    const char *libdir;
    int sasl;
    int tls;

    zkc_init(argc, argv, "ldg_e_libs", 0, "DEV", "ignore");
    libdir = getenv("ZKCONF_LIBDIR");
    if (libdir == NULL) {
        zkc_fail("no ZKCONF_LIBDIR");
        return zkc_finish();
    }
    sasl = dlsym(RTLD_DEFAULT, "zoo_sasl_make_basic_callbacks") != NULL;
    tls = dlsym(RTLD_DEFAULT, "zookeeper_init_ssl") != NULL;
    zkc_ev("check", "sasl %d tls %d", sasl, tls);
    shared(libdir, zkc_is_rust(), sasl, tls);
    archive(libdir, zkc_is_rust());
    return zkc_finish();
}
