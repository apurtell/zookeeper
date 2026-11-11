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
 * close_zsock of the static archives (ABI-02). Mode DEV.
 *
 * zookeeper.h declares close_zsock, but only the static archives define
 * it. The case checks both facts on the libraries of each core. Then it
 * links a helper program with the archive of the core and runs the
 * helper in a forked child, because legacy can crash there.
 *
 * - Narrow: the helper has the 16-byte zsock_t of an application that
 *   does not define HAVE_OPENSSL_H. Guard bytes follow the struct.
 * - Wide: the helper defines HAVE_OPENSSL_H. ssl_sock and ssl_ctx hold
 *   pointers to memory of the application.
 *
 * Rust closes sock, sets it to -1 and never reads ssl_sock or ssl_ctx.
 * Thus both helpers exit 0 in every configuration. A legacy archive
 * without OpenSSL also reads only sock. A legacy archive with OpenSSL
 * reads the guard bytes as ssl_sock and calls SSL_free on them, so the
 * narrow helper crashes. The wide helper gives application memory to
 * SSL_free, so it does not exit 0. The .dev file keeps each outcome.
 *
 * zkconf-flavors: mt st
 */

#include "zkconf.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef THREADED
#define FL "mt"
#else
#define FL "st"
#endif

/* Mach-O symbol names start with an underscore. ELF names do not. */
#ifdef __APPLE__
#define SYM_PREFIX "_"
#else
#define SYM_PREFIX ""
#endif

/*
 * The helper program. Exit 0: sock is -1, the descriptor is closed and
 * the bytes after sock are unchanged. A second call with sock -1 changes
 * nothing. Exit 1 to 4 name the first failed step.
 */
static const char helper_src[] =
    "#include <errno.h>\n"
    "#include <fcntl.h>\n"
    "#include <string.h>\n"
    "#include <sys/socket.h>\n"
    "#include <unistd.h>\n"
    "#include <zookeeper.h>\n"
    "static unsigned char own_ssl[4096];\n"
    "static unsigned char own_ctx[4096];\n"
    "struct app { zsock_t z; unsigned char guard[2 * sizeof(void *)]; };\n"
    "int main(void)\n"
    "{\n"
    "    static struct app a;\n"
    "    struct app want;\n"
    "    int fd = socket(AF_INET, SOCK_STREAM, 0);\n"
    "    if (fd < 0) return 4;\n"
    "    memset(&a, 0, sizeof a);\n"
    "    memset(a.guard, 0xa5, sizeof a.guard);\n"
    "    a.z.sock = fd;\n"
    "#ifdef HAVE_OPENSSL_H\n"
    "    a.z.ssl_sock = (SSL *)(void *)own_ssl;\n"
    "    a.z.ssl_ctx = (SSL_CTX *)(void *)own_ctx;\n"
    "#else\n"
    "    (void)own_ssl;\n"
    "    (void)own_ctx;\n"
    "#endif\n"
    "    want = a;\n"
    "    want.z.sock = -1;\n"
    "    close_zsock(&a.z);\n"
    "    if (a.z.sock != -1) return 1;\n"
    "    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 2;\n"
    "    if (memcmp(&a, &want, sizeof a) != 0) return 3;\n"
    "    close_zsock(&a.z);\n"
    "    if (memcmp(&a, &want, sizeof a) != 0) return 3;\n"
    "    return 0;\n"
    "}\n";

static char g_helper[1200];

/* The child runs the helper. The alarm of zkc_child stays set. */
static int run_helper(void)
{
    char *argv[2];
    argv[0] = g_helper;
    argv[1] = NULL;
    execv(g_helper, argv);
    return 127;
}

/*
 * The runner gives the legacy C tree as ZKCONF_C_DIR. The source does not
 * find the directory from its own path.
 */
#ifndef ZKCONF_C_DIR
#error "give -DZKCONF_C_DIR=<zookeeper-client-c directory> (run.sh does)"
#endif

/* Gives the legacy C tree. A path longer than the buffer is an error. */
static int c_dir(char *out, size_t len)
{
    int n = snprintf(out, len, "%s", ZKCONF_C_DIR);
    return n < 0 || (size_t)n >= len ? -1 : 0;
}

/* The dependency_libs of a libtool file, or "" without one. */
static void la_deps(const char *la, char *out, size_t len)
{
    char line[1024];
    FILE *f = fopen(la, "r");
    out[0] = '\0';
    if (f == NULL) {
        return;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char *s = strstr(line, "dependency_libs='");
        char *e;
        if (s != line) {
            continue;
        }
        s += strlen("dependency_libs='");
        e = strchr(s, '\'');
        if (e != NULL) {
            *e = '\0';
            snprintf(out, len, "%s", s);
        }
    }
    fclose(f);
}

/* Returns 1 when the output of cmd has a line that contains text. */
static int cmd_has(const char *cmd, const char *text)
{
    char line[1024];
    int found = 0;
    FILE *p = popen(cmd, "r");
    if (p == NULL) {
        return 0;
    }
    while (fgets(line, sizeof line, p) != NULL) {
        if (strstr(line, text) != NULL) {
            found = 1;
        }
    }
    pclose(p);
    return found;
}

/*
 * Links the helper as NAME with the archive of the core. wide adds
 * HAVE_OPENSSL_H and the OpenSSL headers. Returns 0 on success.
 */
static int build_helper(const char *cdir, const char *libdir, const char *name, int wide,
                        const char *ossl_inc)
{
    char src[1100];
    char log[1100];
    char la[1100];
    char deps[1024];
    char cmd[6000];
    const char *out = getenv("ZKCONF_OUT");
    const char *sasl = getenv("ZKCONF_SASL_PREFIX");
    FILE *f;
    int rc;

    snprintf(src, sizeof src, "%s.zsock.c", out != NULL ? out : "/tmp/ldg_e_zsock");
    snprintf(g_helper, sizeof g_helper, "%s.%s", out != NULL ? out : "/tmp/ldg_e_zsock", name);
    snprintf(log, sizeof log, "%s.build.log", g_helper);
    f = fopen(src, "w");
    if (f == NULL || fputs(helper_src, f) < 0 || fclose(f) != 0) {
        return -1;
    }
    /* Legacy archives name their libraries in the .la file. The drop-in
     * archive needs pthread and, with SASL, libsasl2. */
    snprintf(la, sizeof la, "%s/libzookeeper_%s.la", libdir, FL);
    la_deps(la, deps, sizeof deps);
    if (deps[0] == '\0') {
        snprintf(deps, sizeof deps, "-lpthread%s%s%s",
                 dlsym(RTLD_DEFAULT, "zoo_sasl_make_basic_callbacks") != NULL ? " -L" : "",
                 dlsym(RTLD_DEFAULT, "zoo_sasl_make_basic_callbacks") != NULL
                     ? (sasl != NULL ? sasl : "/opt/homebrew/opt/cyrus-sasl")
                     : "",
                 dlsym(RTLD_DEFAULT, "zoo_sasl_make_basic_callbacks") != NULL
                     ? "/lib -lsasl2"
                     : "");
    }
    snprintf(cmd, sizeof cmd,
             "cc -std=c99 -D_GNU_SOURCE %s %s%s%s -I'%s/include' -I'%s/generated' '%s'"
             " '%s/libzookeeper_%s.a' %s -o '%s' >'%s' 2>&1",
#ifdef THREADED
             "-DTHREADED",
#else
             "",
#endif
             wide ? "-DHAVE_OPENSSL_H -isystem '" : "", wide ? ossl_inc : "", wide ? "'" : "",
             cdir, cdir, src, libdir, FL, deps, g_helper, log);
    rc = system(cmd);
    return rc == 0 ? 0 : -1;
}

/* Runs one helper and checks the outcome of each core. */
static void scenario(const char *cdir, const char *libdir, const char *name, int wide,
                     const char *ossl_inc, int legacy_tls)
{
    const char *res;
    int ok;

    if (build_helper(cdir, libdir, name, wide, ossl_inc) != 0) {
        zkc_dev("ABI-02", 0,
                "%s: the helper does not link with libzookeeper_%s.a (see %s.build.log)", name,
                FL, g_helper);
        return;
    }
    res = zkc_child(name, run_helper, 10000);
    if (zkc_is_rust()) {
        ok = strcmp(res, "exit:0") == 0;
        zkc_dev("ABI-02", ok,
                "%s: rust closes sock, sets -1 and keeps the other bytes: %s (want exit:0)", name,
                res);
    } else if (legacy_tls) {
        ok = wide ? strcmp(res, "exit:0") != 0 : strncmp(res, "signal:", 7) == 0;
        zkc_dev("ABI-02", ok, "%s: legacy with OpenSSL frees ssl_sock: %s (want %s)", name, res,
                wide ? "not exit:0" : "a signal");
    } else {
        ok = strcmp(res, "exit:0") == 0;
        zkc_dev("ABI-02", ok, "%s: legacy without OpenSSL closes sock only: %s (want exit:0)",
                name, res);
    }
}

int main(int argc, char **argv)
{
    char cdir[1024];
    char cmd[1400];
    char ossl_inc[1100];
    struct stat st;
    const char *libdir;
    const char *ossl;
    int legacy_tls;

    zkc_init(argc, argv, "ldg_e_close_zsock", 0, "DEV", "ignore");
    libdir = getenv("ZKCONF_LIBDIR");
    if (libdir == NULL || c_dir(cdir, sizeof cdir) != 0) {
        zkc_fail("no ZKCONF_LIBDIR or no source directory");
        return zkc_finish();
    }
    legacy_tls = !zkc_is_rust() && dlsym(RTLD_DEFAULT, "zookeeper_init_ssl") != NULL;

    /* The shared library does not export close_zsock. The archive defines it. */
    zkc_dev("ABI-02", dlsym(RTLD_DEFAULT, "close_zsock") == NULL,
            "the shared library does not export close_zsock");
    snprintf(cmd, sizeof cmd, "nm -g '%s/libzookeeper_%s.a' 2>/dev/null", libdir, FL);
    zkc_dev("ABI-02", cmd_has(cmd, " T " SYM_PREFIX "close_zsock"),
            "libzookeeper_%s.a defines close_zsock", FL);

    scenario(cdir, libdir, "narrow", 0, "", legacy_tls);
    ossl = getenv("OPENSSL_PREFIX");
    snprintf(ossl_inc, sizeof ossl_inc, "%s/include",
             ossl != NULL ? ossl : "/opt/homebrew/opt/openssl@3");
    snprintf(cmd, sizeof cmd, "%s/openssl/ossl_typ.h", ossl_inc);
    if (stat(cmd, &st) == 0) {
        scenario(cdir, libdir, "wide", 1, ossl_inc, legacy_tls);
    } else {
        zkc_ev("check", "skip wide: no OpenSSL headers in %s", ossl_inc);
    }
    return zkc_finish();
}
