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
 * The library SASL callback block and its callbacks.
 *
 * The block keeps the layout and the rules of zk_sasl.c:440-666. One
 * calloc holds the callback array at offset 0, the secret context, the
 * in-block secret and the strings, so one free() releases it. The PASS
 * callback re-reads the password file on each call.
 *
 * The ZooKeeper sessions never write the block. The glue trampoline calls
 * zks_getsecret_unlocked, which gives the bytes to a session sink. Only a
 * direct Cyrus user of the block reaches _zsasl_getsecret, and a static
 * mutex guards its short in-block copy. No lock is held while application
 * code runs.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* POSIX names under -std=c99 on glibc */
#endif
#define ZKS_SASL_GLUE 1
#include "zks_internal.h"
#include "zks_sasl.h"
#include "zks_sasl_cb.h"

#include <stdio.h>
#include <unistd.h>

struct zsasl_secret_ctx {
    const char *password_file;
    void *context;
    zoo_sasl_password_callback_t callback;
    sasl_secret_t *secret;
};

/* The legacy layout. The application frees the block with one free(). */
struct zsasl_callbacks_block {
    sasl_callback_t callbacks[5];
    struct zsasl_secret_ctx secret_ctx;
    union {
        sasl_secret_t secret;
        char space[sizeof(sasl_secret_t) + ZSASL_MAX_PASSWORD_LEN];
    } secret;
    char strings[1];
};

/*
 * The only global mutable state of the SASL units. Only _zsasl_getsecret
 * takes it, around the in-block copy, and no application code runs while
 * it is held.
 */
static pthread_mutex_t zks_sasl_pass_mutex = PTHREAD_MUTEX_INITIALIZER;

static void zks_sasl_pass_lock(void)
{
    (void)pthread_mutex_lock(&zks_sasl_pass_mutex);
}

static void zks_sasl_pass_unlock(void)
{
    (void)pthread_mutex_unlock(&zks_sasl_pass_mutex);
}

/*
 * Zeroes a password buffer. Each function zeroes its buffers at its
 * single exit label. ZKS_CLEANUP also zeroes them when a C++ exception
 * unwinds the frame.
 */
static void zks_zero_pw(char (*b)[ZSASL_MAX_PASSWORD_LEN + 1])
{
    zks_secure_zero(*b, sizeof *b);
}

/*
 * The legacy password rules. It writes at most 1023 bytes
 * and a NUL to pw. It calls application code, so no library lock is held.
 */
static int zks_getsecret_compute(struct zsasl_secret_ctx *c, char pw[ZSASL_MAX_PASSWORD_LEN + 1],
                                 size_t *out_len)
{
    char buf[ZSASL_MAX_PASSWORD_LEN + 1] ZKS_CLEANUP(zks_zero_pw);
    char np[ZSASL_MAX_PASSWORD_LEN + 1] ZKS_CLEANUP(zks_zero_pw);
    char *password = NULL;
    char *nl;
    size_t len = 0;
    int res = SASL_OK;
    FILE *fh;

    *out_len = 0;
    if (c->password_file != NULL) {
        /* The file can hold binary data for the transform callback, so fread reads it. */
        fh = fopen(c->password_file, "rt");
        if (fh == NULL) {
            res = SASL_FAIL;
            goto out;
        }
        len = fread(buf, 1, ZSASL_MAX_PASSWORD_LEN, fh);
        if (ferror(fh)) {
            (void)fclose(fh);
            res = SASL_FAIL;
            goto out;
        }
        /*
         * Without a callback, a first line longer than the bound gives
         * SASL_BUFOVER. Legacy uses the truncated line (spec "Detection of
         * Truncated SASL Password Files").
         */
        if (c->callback == NULL && len == ZSASL_MAX_PASSWORD_LEN &&
            memchr(buf, '\n', len) == NULL) {
            int next = fgetc(fh);
            if (next != EOF && next != '\n') {
                (void)fclose(fh);
                res = SASL_BUFOVER;
                goto out;
            }
        }
        (void)fclose(fh);
        buf[len] = '\0';
        password = buf;
    }
    if (c->callback != NULL) {
        /* The transform callback needs the password file. */
        if (password == NULL) {
            res = SASL_BADPARAM;
            goto out;
        }
        res = c->callback(password, len, c->context, np, ZSASL_MAX_PASSWORD_LEN, &len);
        if (res != SASL_OK) {
            goto out;
        }
        if (len > ZSASL_MAX_PASSWORD_LEN) {
            res = SASL_BUFOVER;
            goto out;
        }
        np[len] = '\0';
        password = np;
    } else if (password != NULL) {
        /* Without a callback, only the first line of the file is the password. */
        nl = (char *)memchr(password, '\n', len);
        if (nl != NULL) {
            *nl = '\0';
        }
    } else {
        /* Without a file, the user types the password, as legacy does. */
#ifdef HAVE_GETPASSPHRASE
        password = getpassphrase("Password: ");
#else
        password = getpass("Password: ");
#endif
        if (password == NULL) {
            res = SASL_FAIL;
            goto out;
        }
    }
    /* A NUL ends the password, whatever its source. */
    len = strnlen(password, (size_t)ZSASL_MAX_PASSWORD_LEN + 1u);
    if (len > ZSASL_MAX_PASSWORD_LEN) {
        zks_secure_zero(password, strnlen(password, ZKS_SASL_LEN_CAP));
        res = SASL_BUFOVER;
        goto out;
    }
    memcpy(pw, password, len);
    pw[len] = '\0';
    if (password != buf && password != np) {
        zks_secure_zero(password, len); /* the static buffer of the prompt */
    }
    *out_len = len;
out:
    zks_zero_pw(&buf);
    zks_zero_pw(&np);
    return res;
}

/* The SASL_CB_PASS proc of the block. It keeps the legacy behavior for direct Cyrus users. */
static int _zsasl_getsecret(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
{
    struct zsasl_secret_ctx *c = (struct zsasl_secret_ctx *)context;
    char pw[ZSASL_MAX_PASSWORD_LEN + 1] ZKS_CLEANUP(zks_zero_pw);
    size_t len = 0;
    int res;
    sasl_secret_t *x;

    if (conn == NULL || psecret == NULL || id != SASL_CB_PASS) {
        return SASL_BADPARAM;
    }
    res = zks_getsecret_compute(c, pw, &len);
    if (res != SASL_OK) {
        goto out;
    }
    x = c->secret;
    zks_sasl_pass_lock();
    memcpy((unsigned char *)x + offsetof(sasl_secret_t, data), pw, len + 1);
    memset((unsigned char *)x + offsetof(sasl_secret_t, data) + len + 1, 0,
           ZSASL_MAX_PASSWORD_LEN - len);
    x->len = (unsigned long)len;
    zks_sasl_pass_unlock();
    *psecret = x;
out:
    zks_zero_pw(&pw);
    return res;
}

/* The trampoline body for the library callback. The block is not written. */
ZKS_HIDDEN int zks_getsecret_unlocked(sasl_conn_t *conn, void *context, zks_secret_sink sink,
                                      void *sink_arg, sasl_secret_t **psecret)
{
    char pw[ZSASL_MAX_PASSWORD_LEN + 1] ZKS_CLEANUP(zks_zero_pw);
    size_t len = 0;
    int res;

    if (conn == NULL || psecret == NULL) {
        return SASL_BADPARAM;
    }
    res = zks_getsecret_compute((struct zsasl_secret_ctx *)context, pw, &len);
    if (res == SASL_OK) {
        res = sink(sink_arg, (const unsigned char *)pw, len, psecret);
    }
    zks_zero_pw(&pw);
    return res;
}

ZKS_HIDDEN int zks_is_library_pass_cb(zks_sasl_proc proc)
{
    return proc == ZKS_SASL_PROC(&_zsasl_getsecret);
}

/* SASL_CB_GETREALM: the canned realm, or NULL. */
static int _zsasl_getrealm(void *context, int id, const char **availrealms, const char **result)
{
    ZKS_UNUSED(id);
    ZKS_UNUSED(availrealms);
    *result = (const char *)context;
    return SASL_OK;
}

/* SASL_CB_USER and SASL_CB_AUTHNAME: the canned user. */
static int _zsasl_simple(void *context, int id, const char **result, unsigned *len)
{
    ZKS_UNUSED(len);
    if (result == NULL) {
        return SASL_BADPARAM;
    }
    switch (id) {
    case SASL_CB_USER:
    case SASL_CB_AUTHNAME:
        *result = (const char *)context;
        return SASL_OK;
    default:
        return SASL_BADPARAM;
    }
}

/* The length of an optional string with its NUL, or 0 for NULL. */
static int zks_opt_len(const char *s, size_t *out)
{
    size_t n;

    *out = 0;
    if (s == NULL) {
        return 0;
    }
    n = strnlen(s, ZKS_SASL_LEN_CAP);
    if (n >= ZKS_SASL_LEN_CAP) {
        return -1;
    }
    return ZKS_ADD_OVF(n, (size_t)1, out) ? -1 : 0;
}

/*
 * A NULL password gives NULL with EINVAL, where legacy reads through NULL.
 * A size overflow gives NULL with ENOMEM, the legacy
 * result of a failed allocation.
 */
sasl_callback_t *zoo_sasl_make_password_callbacks(const char *user, const char *realm,
                                                  zoo_sasl_password_t *password)
{
    size_t user_len;
    size_t realm_len;
    size_t file_len;
    size_t total = offsetof(struct zsasl_callbacks_block, strings);
    struct zsasl_callbacks_block *b;
    const char *user_ctx = NULL;
    const char *realm_ctx = NULL;
    char *p;

    if (password == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (zks_opt_len(user, &user_len) != 0 || zks_opt_len(realm, &realm_len) != 0
        || zks_opt_len(password->password_file, &file_len) != 0
        || ZKS_ADD_OVF(total, user_len, &total) || ZKS_ADD_OVF(total, realm_len, &total)
        || ZKS_ADD_OVF(total, file_len, &total)) {
        errno = ENOMEM;
        return NULL;
    }
    b = (struct zsasl_callbacks_block *)calloc(1, total);
    if (b == NULL) {
        return NULL;
    }
    p = b->strings;
    if (user != NULL) {
        memcpy(p, user, user_len);
        user_ctx = p;
        p += user_len;
    }
    if (realm != NULL) {
        memcpy(p, realm, realm_len);
        realm_ctx = p;
        p += realm_len;
    }
    if (password->password_file != NULL) {
        memcpy(p, password->password_file, file_len);
        b->secret_ctx.password_file = p;
    }
    b->secret_ctx.context = password->context;
    b->secret_ctx.callback = password->callback;
    b->secret_ctx.secret = &b->secret.secret;
    b->callbacks[0].id = SASL_CB_GETREALM;
    b->callbacks[0].proc = ZKS_SASL_PROC(&_zsasl_getrealm);
    b->callbacks[0].context = (void *)(uintptr_t)realm_ctx;
    b->callbacks[1].id = SASL_CB_USER;
    b->callbacks[1].proc = ZKS_SASL_PROC(&_zsasl_simple);
    b->callbacks[1].context = (void *)(uintptr_t)user_ctx;
    b->callbacks[2].id = SASL_CB_AUTHNAME;
    b->callbacks[2].proc = ZKS_SASL_PROC(&_zsasl_simple);
    b->callbacks[2].context = (void *)(uintptr_t)user_ctx;
    b->callbacks[3].id = SASL_CB_PASS;
    b->callbacks[3].proc = ZKS_SASL_PROC(&_zsasl_getsecret);
    b->callbacks[3].context = &b->secret_ctx;
    b->callbacks[4].id = SASL_CB_LIST_END;
    return b->callbacks;
}

sasl_callback_t *zoo_sasl_make_basic_callbacks(const char *user, const char *realm,
                                               const char *password_file)
{
    zoo_sasl_password_t password = {password_file, NULL, NULL};

    return zoo_sasl_make_password_callbacks(user, realm, &password);
}
