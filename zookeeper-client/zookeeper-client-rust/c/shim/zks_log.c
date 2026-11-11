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
 * Logging.
 *
 * This unit owns log_message and the level and stream functions. It also
 * owns the emitter for the core sites of LOG items and the emitter for the
 * C sites. The level and stream functions repeat zk_log.c.
 *
 * All three emitters make the legacy line: the zk_log.c prefix, then the
 * pinned format of the site with its arguments. The buffers are per thread
 * in both flavors, so no TSD key and no constructor exist.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* POSIX names under -std=c99 on glibc */
#endif
#include "zks_internal.h"

#include <netdb.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/*
 * The formats of this unit come from the site tables or from the caller of
 * log_message, so they are not literals at the printf call. The hardening
 * set has -Wformat=2, which warns about each such call. The warning is off
 * for this unit only. -Wformat still checks each literal format.
 */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

#define ZKS_TIME_BUF_SIZE 1024
#define ZKS_LOG_BUF_SIZE 4096

/* The size limit of the prefix. Legacy uses one byte less in the mt flavor. */
#ifdef THREADED
#define ZKS_LOG_HDR_SIZE (ZKS_LOG_BUF_SIZE - 1)
#else
#define ZKS_LOG_HDR_SIZE ZKS_LOG_BUF_SIZE
#endif

static ZKS_THREAD_LOCAL char zks_log_buf[ZKS_LOG_BUF_SIZE];
static ZKS_THREAD_LOCAL char zks_time_buf[ZKS_TIME_BUF_SIZE];
/* The message text of a site. log_message then adds the prefix. */
static ZKS_THREAD_LOCAL char zks_log_body[ZKS_LOG_BUF_SIZE];

/* ------------------------------------------------------------------------
 * Site tables.
 *
 * Each site has the func, line and format of its tests/abi/log-sites.tsv row.
 * The tsv gives two lines for a call that spans lines: the line of the
 * macro name and the line of the closing parenthesis. Clang expands
 * __LINE__ to the second line, and the legacy reference build uses clang.
 * Other compilers get the first line.
 * ---------------------------------------------------------------------- */

#if defined(__clang__)
#define ZKS_SITE_LINE(line, line_end) (line_end)
#else
#define ZKS_SITE_LINE(line, line_end) (line)
#endif

struct zks_site {
    const char *func;
    int line;
    const char *fmt;
};

struct zks_c_site_info {
    ZooLogLevel level;
    const char *func;
    int line;
    const char *fmt;
};

/*
 * The core sites come from the generated zks_log_sites.h. Its rows are in
 * the order of zk_proto::LogSite::ALL, so the row index is the site id of a
 * LOG item.
 */
#define ZKS_CORE_SITE_ROW(name, level, func, line, line_end, fmt) \
    {func, ZKS_SITE_LINE(line, line_end), fmt},

static const struct zks_site zks_core_sites[] = {ZKS_CORE_SITES(ZKS_CORE_SITE_ROW)};

#define ZKS_CORE_SITE_COUNT (sizeof(zks_core_sites) / sizeof(zks_core_sites[0]))

#define ZKS_C_SITE_ROW(name, level, func, line, line_end, fmt) \
    {level, func, ZKS_SITE_LINE(line, line_end), fmt},

/* The C sites, in the order of enum zks_c_site. */
static const struct zks_c_site_info zks_c_sites[ZKS_SITE_C_COUNT] = {ZKS_C_SITES(ZKS_C_SITE_ROW)};

/* ------------------------------------------------------------------------
 * Stream and level.
 * ---------------------------------------------------------------------- */

static FILE *logStream = 0;

/*
 * Library lines use this function, not the exported zoo_get_log_stream.
 * Legacy calls the exported function for these lines. The shim does not
 * repeat this internal call, because its call count is not part of the ABI.
 */
static FILE *zks_log_stream(void)
{
    if (logStream == 0) {
        logStream = stderr;
    }
    return logStream;
}

FILE *zoo_get_log_stream(void)
{
    return zks_log_stream();
}

void zoo_set_log_stream(FILE *stream)
{
    logStream = stream;
}

void zoo_set_debug_level(ZooLogLevel level)
{
    if (level == 0) {
        /* disable logging (unit tests do this) */
        logLevel = (ZooLogLevel)0;
        return;
    }
    if (level < ZOO_LOG_LEVEL_ERROR) {
        level = ZOO_LOG_LEVEL_ERROR;
    }
    if (level > ZOO_LOG_LEVEL_DEBUG) {
        level = ZOO_LOG_LEVEL_DEBUG;
    }
    logLevel = level;
}

/*
 * The rule of the legacy LOG_* macros. ERROR, WARN and INFO need a
 * logLevel of that level or more. DEBUG needs a logLevel of exactly DEBUG.
 * The application can write logLevel at any time, so no code keeps a copy.
 */
static int zks_level_on(uint32_t level)
{
    uint32_t cur = (uint32_t)ZKS_LOAD(&logLevel);

    switch (level) {
    case ZOO_LOG_LEVEL_ERROR:
    case ZOO_LOG_LEVEL_WARN:
    case ZOO_LOG_LEVEL_INFO:
        return cur >= level;
    case ZOO_LOG_LEVEL_DEBUG:
        return cur == ZOO_LOG_LEVEL_DEBUG;
    default:
        return 0;
    }
}

ZKS_HIDDEN int zks_vt_log_enabled(uint32_t level)
{
    int saved = zks_in_vtable;
    int on;

    zks_in_vtable = 1;
    on = zks_level_on(level);
    zks_in_vtable = saved;
    return on;
}

/* ------------------------------------------------------------------------
 * The line: prefix, body and sink (zk_log.c:139-196).
 * ---------------------------------------------------------------------- */

/* The logback ISO8601 format "yyyy-MM-dd HH:mm:ss,SSS" in local time, as time_now. */
static const char *zks_time_text(time_t sec, long usec)
{
    struct tm lt;
    size_t len;

    memset(&lt, 0, sizeof(lt));
    localtime_r(&sec, &lt);
    len = strftime(zks_time_buf, ZKS_TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", &lt);
    snprintf(zks_time_buf + len, ZKS_TIME_BUF_SIZE - len, ",%03d", (int)(usec / 1000));
    return zks_time_buf;
}

/*
 * Legacy reads the pid once and keeps it, also after a fork. The shim
 * reads it for each line, so a forked child logs its own pid (spec
 * "Diagnostic logging compatibility").
 */
static long zks_log_pid(void)
{
    return (long)getpid();
}

/*
 * Writes the prefix into zks_log_buf and returns its length. A level
 * outside 0..4 prints ZOO_INVALID. The length is clamped to the
 * text that snprintf wrote, so a long function name cannot move the body
 * out of the buffer.
 */
static int zks_log_header(ZooLogLevel level, const char *func, int line, time_t sec, long usec)
{
    static const char *const names[] = {"ZOO_INVALID", "ZOO_ERROR", "ZOO_WARN", "ZOO_INFO",
                                        "ZOO_DEBUG"};
    const char *time = zks_time_text(sec, usec);
    const char *name = (unsigned)level <= ZOO_LOG_LEVEL_DEBUG ? names[level] : names[0];
    int ofs;

    if (func == NULL) {
        func = "(null)";
    }
#ifdef THREADED
    ofs = snprintf(zks_log_buf, ZKS_LOG_HDR_SIZE, "%s:%ld(0x%lx):%s@%s@%d: ", time, zks_log_pid(),
                   (unsigned long)pthread_self(), name, func, line);
#else
    ofs = snprintf(zks_log_buf, ZKS_LOG_HDR_SIZE, "%s:%ld:%s@%s@%d: ", time, zks_log_pid(), name,
                   func, line);
#endif
    if (ofs < 0) {
        zks_log_buf[0] = '\0';
        ofs = 0;
    } else if (ofs > ZKS_LOG_HDR_SIZE - 1) {
        ofs = ZKS_LOG_HDR_SIZE - 1;
    }
    return ofs;
}

/* The space for the body after a prefix of ofs bytes, as the legacy vsnprintf call. */
static size_t zks_log_room(int ofs)
{
    return ofs < ZKS_LOG_BUF_SIZE - 1 ? (size_t)(ZKS_LOG_BUF_SIZE - 1 - ofs) : 0;
}

/* The callback gets the line without a newline. The stream gets a newline and a flush. */
static void zks_log_sink(log_callback_fn cb, const char *buf)
{
    if (cb) {
        cb(buf);
    } else {
        FILE *f = zks_log_stream();
        fprintf(f, "%s\n", buf);
        fflush(f);
    }
}

static void zks_log_now(time_t *sec, long *usec)
{
    struct timeval tv;

    gettimeofday(&tv, 0);
    *sec = tv.tv_sec;
    *usec = (long)tv.tv_usec;
}

void log_message(log_callback_fn callback, ZooLogLevel curLevel, int line, const char *funcName,
                 const char *format, ...)
{
    va_list va;
    time_t sec;
    long usec;
    int ofs;
    size_t room;

    zks_log_now(&sec, &usec);
    ofs = zks_log_header(curLevel, funcName, line, sec, usec);
    room = zks_log_room(ofs);
    if (room > 0) {
        va_start(va, format);
        vsnprintf(zks_log_buf + ofs, room, format, va);
        va_end(va);
    }
    zks_log_sink(callback, zks_log_buf);
}

/* ------------------------------------------------------------------------
 * The printf driver of the core sites.
 *
 * The driver calls snprintf once for each conversion, with one argument of
 * the C type of that conversion. The platform printf thus gives the legacy
 * text, also for "%p" of NULL and for "%#llx". The output stops where the
 * legacy vsnprintf call stops.
 * ---------------------------------------------------------------------- */

struct zks_out {
    char *p;
    size_t cap; /* bytes with the NUL; 0 means no space */
    size_t len; /* always less than cap when cap is not 0 */
};

static void zks_out_bytes(struct zks_out *o, const char *s, size_t n)
{
    size_t room;

    if (o->cap == 0) {
        return;
    }
    room = o->cap - 1 - o->len;
    if (n > room) {
        n = room;
    }
    memcpy(o->p + o->len, s, n);
    o->len += n;
    o->p[o->len] = '\0';
}

/* Adds the length that snprintf reports, limited to the text that it wrote. */
static void zks_out_wrote(struct zks_out *o, int n)
{
    size_t room = o->cap - 1 - o->len;

    if (n < 0) {
        o->p[o->len] = '\0';
        return;
    }
    o->len += (size_t)n < room ? (size_t)n : room;
}

static uint64_t zks_arg_bits(const zkrs_log_arg *a)
{
    if (a == NULL) {
        return 0;
    }
    switch (a->kind) {
    case ZKRS_ARG_I64:
        return (uint64_t)a->i;
    case ZKRS_ARG_U64:
        return a->u;
    case ZKRS_ARG_PTR:
        return (uint64_t)a->p;
    default:
        return 0;
    }
}

/* The text of a "%s" argument. A NULL string prints "(null)" on every platform. */
static const char *zks_arg_text(const zkrs_log_arg *a)
{
    if (a == NULL) {
        return "(null)";
    }
    switch (a->kind) {
    case ZKRS_ARG_STR:
        return a->s.ptr != NULL ? a->s.ptr : "(null)";
    case ZKRS_ARG_ENDPOINT:
        return zks_format_endpoint(&a->ep);
    case ZKRS_ARG_ERRNO_STR:
        return strerror(a->err);
    case ZKRS_ARG_GAI_STR:
        /* The platform split of legacy resolve_hosts (zookeeper.c:982-988). */
#if defined(_WIN32) || (defined(__linux__) && defined(__GNUC__))
        return gai_strerror(a->gai_rc);
#else
        return strerror(a->err);
#endif
    default:
        return "(null)";
    }
}

/*
 * Writes one conversion. The spec argument is the full conversion text. The
 * len argument is the length modifier: 0, 'l', or 'L' for ll.
 */
static void zks_out_conv(struct zks_out *o, const char *spec, char len, char conv,
                         const zkrs_log_arg *a)
{
    char *dst;
    size_t size;
    uint64_t bits;
    int n;

    if (o->cap == 0) {
        return;
    }
    dst = o->p + o->len;
    size = o->cap - o->len;
    bits = zks_arg_bits(a);
    switch (conv) {
    case 'd':
    case 'i':
        if (len == 'L') {
            n = snprintf(dst, size, spec, (long long)bits);
        } else if (len == 'l') {
            n = snprintf(dst, size, spec, (long)bits);
        } else {
            n = snprintf(dst, size, spec, (int)bits);
        }
        break;
    case 'u':
    case 'x':
    case 'X':
    case 'o':
        if (len == 'L') {
            n = snprintf(dst, size, spec, (unsigned long long)bits);
        } else if (len == 'l') {
            n = snprintf(dst, size, spec, (unsigned long)bits);
        } else {
            n = snprintf(dst, size, spec, (unsigned)bits);
        }
        break;
    case 'c':
        n = snprintf(dst, size, spec, (int)bits);
        break;
    case 'p':
        n = snprintf(dst, size, spec, (void *)(uintptr_t)bits);
        break;
    default: /* 's' */
        n = snprintf(dst, size, spec, zks_arg_text(a));
        break;
    }
    zks_out_wrote(o, n);
}

/*
 * Renders fmt with the typed arguments. The site formats use only the
 * flags, the width, the precision, the h, l and ll modifiers and the
 * conversions d i u x X o c p s. Other text is copied as it is.
 */
static void zks_printf_driver(struct zks_out *o, const char *fmt, const zkrs_log_arg *args,
                              uint32_t nargs)
{
    uint32_t next = 0;
    const char *lit = fmt;
    const char *p = fmt;

    while (*p != '\0') {
        const char *start;
        char spec[32];
        size_t speclen;
        char len = 0;

        if (*p != '%') {
            p++;
            continue;
        }
        zks_out_bytes(o, lit, (size_t)(p - lit));
        start = p++;
        if (*p == '%') {
            zks_out_bytes(o, "%", 1);
            lit = ++p;
            continue;
        }
        while (*p != '\0' && strchr("-+ #0", *p) != NULL) {
            p++;
        }
        while (*p >= '0' && *p <= '9') {
            p++;
        }
        if (*p == '.') {
            p++;
            while (*p >= '0' && *p <= '9') {
                p++;
            }
        }
        if (*p == 'h') {
            p += p[1] == 'h' ? 2 : 1;
        } else if (*p == 'l') {
            len = p[1] == 'l' ? 'L' : 'l';
            p += p[1] == 'l' ? 2 : 1;
        }
        speclen = (size_t)(p - start) + 1;
        if (*p == '\0' || strchr("diuxXocps", *p) == NULL || speclen >= sizeof(spec)) {
            /* Not a conversion of the site tables: copy the text. */
            lit = start;
            if (*p != '\0') {
                p++;
            }
            continue;
        }
        memcpy(spec, start, speclen);
        spec[speclen] = '\0';
        zks_out_conv(o, spec, len, *p, args != NULL && next < nargs ? &args[next] : NULL);
        next++;
        lit = ++p;
    }
    zks_out_bytes(o, lit, (size_t)(p - lit));
}

/*
 * Emits one LOG item of the core. The level can change after Rust queued
 * the item, so the emitter checks it again. An unknown site id gives no
 * line. The emitters keep errno, so a log line does not change the errno
 * result of a call.
 *
 * The emitters give the message text to the exported log_message, as the
 * legacy LOG_* macros do. Thus an application that interposes log_message
 * sees every line of the library. log_message takes the time when it
 * runs, so the time that zk-ffi stamped is not used.
 */
ZKS_HIDDEN void zks_log_emit(zhandle_t *zh, const zkrs_log_view *v)
{
    const struct zks_site *s;
    struct zks_out o;
    int saved_errno;

    if (v == NULL || v->site >= ZKS_CORE_SITE_COUNT || !zks_level_on(v->level)) {
        return;
    }
    saved_errno = errno;
    s = &zks_core_sites[v->site];
    o.p = zks_log_body;
    o.cap = sizeof(zks_log_body) - 1;
    o.len = 0;
    zks_printf_driver(&o, s->fmt, v->args, v->nargs);
    log_message(zh != NULL ? ZKS_LOAD(&zh->log_callback) : NULL, (ZooLogLevel)v->level, s->line,
                s->func, "%s", zks_log_body);
    errno = saved_errno;
}

/* Emits a C site with real arguments, as a LOG_* macro of legacy does. */
static void zks_log_c_site(log_callback_fn cb, uint32_t site, va_list va)
{
    const struct zks_c_site_info *s;
    int saved_errno;

    if (site >= ZKS_SITE_C_COUNT) {
        return;
    }
    s = &zks_c_sites[site];
    if (s->func == NULL || !zks_level_on(s->level)) {
        return;
    }
    saved_errno = errno;
    vsnprintf(zks_log_body, sizeof(zks_log_body), s->fmt, va);
    log_message(cb, s->level, s->line, s->func, "%s", zks_log_body);
    errno = saved_errno;
}

ZKS_HIDDEN void zks_log_site(zhandle_t *zh, uint32_t site, ...)
{
    va_list va;

    va_start(va, site);
    zks_log_c_site(zh != NULL ? ZKS_LOAD(&zh->log_callback) : NULL, site, va);
    va_end(va);
}

/* For lines after the handle can be gone, such as the thread exit lines. */
ZKS_HIDDEN void zks_log_site_cb(log_callback_fn cb, uint32_t site, ...)
{
    va_list va;

    va_start(va, site);
    zks_log_c_site(cb, site, va);
    va_end(va);
}
