/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: helpers of the four hypothesis tests (ts_h1 .. ts_h4)
 *
 * A finder of TypeScript example directories, a collector of the listening
 * ports of a process (tapi_netexpose), a raw TCP exchange with a time
 * limit and a classifier of HTTP error replies.
 */

#ifndef MDE_TSH_LIB_H
#define MDE_TSH_LIB_H

#include "tsx_lib.h"

#include <dirent.h>

#define TSH_MAX_HITS    16
#define TSH_MAX_DEPTH   5
#define TSH_MAX_PORTS   32

/** True when @p name ends with @p suffix. */
static bool
tsh_ends(const char *name, const char *suffix)
{
    size_t n = strlen(name);
    size_t s = strlen(suffix);

    return n >= s && strcmp(name + n - s, suffix) == 0;
}

/**
 * Walk @p dir (at most TSH_MAX_DEPTH levels, no node_modules, dist, .git
 * or other dot directory) and record every directory that holds a .ts
 * source file (not a .d.ts) and a package.json or a tsconfig.json.
 * Every directory read is logged as a listing line. Returns the number of
 * hits found so far.
 */
static int
tsh_find(const char *id, const char *dir, int depth, char hits[][700],
         int nhits)
{
    DIR           *d = opendir(dir);
    struct dirent *e;
    bool           has_ts = false;
    bool           has_cfg = false;
    char           subs[64][256];
    int            nsubs = 0;
    int            i;

    if (d == NULL)
        return nhits;
    while ((e = readdir(d)) != NULL)
    {
        char        p[1100];
        struct stat st;

        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(p, sizeof(p), "%.500s/%.250s", dir, e->d_name);
        if (stat(p, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
        {
            if (e->d_name[0] == '.' || strcmp(e->d_name, "node_modules") == 0
                || strcmp(e->d_name, "dist") == 0 ||
                strcmp(e->d_name, "target") == 0)
                continue;
            if (nsubs < 64)
                snprintf(subs[nsubs++], sizeof(subs[0]), "%s", e->d_name);
        }
        else
        {
            if (tsh_ends(e->d_name, ".ts") && !tsh_ends(e->d_name, ".d.ts"))
                has_ts = true;
            if (strcmp(e->d_name, "package.json") == 0 ||
                strcmp(e->d_name, "tsconfig.json") == 0)
                has_cfg = true;
        }
    }
    closedir(d);
    RING("%s: listing %s: %d subdirectory(ies), .ts file %s, package.json "
         "or tsconfig.json %s", id, dir, nsubs, has_ts ? "yes" : "no",
         has_cfg ? "yes" : "no");
    if (has_ts && has_cfg && nhits < TSH_MAX_HITS)
        snprintf(hits[nhits++], 700, "%s", dir);
    if (depth >= TSH_MAX_DEPTH)
        return nhits;
    for (i = 0; i < nsubs; i++)
    {
        char p[1100];

        snprintf(p, sizeof(p), "%.500s/%.250s", dir, subs[i]);
        nhits = tsh_find(id, p, depth + 1, hits, nhits);
    }
    return nhits;
}

/**
 * The TCP ports the process @p pid listens on, as tapi_netexpose reports
 * them. Returns how many (at most TSH_MAX_PORTS), or -1 when the socket
 * tables could not be read.
 */
static int
tsh_listen_ports(const char *id, tsapi_mde_session *session, pid_t pid,
                 unsigned *ports, unsigned *total)
{
    unsigned long                ino[MAX_INO];
    tapi_netexpose_opt           opt = tapi_netexpose_default_opt;
    te_vec                       socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    size_t                       n = pid_inodes(pid, ino, MAX_INO);
    size_t                       k;
    int                          cnt = 0;

    *total = 0;
    opt.udp = false;
    opt.tcp = true;
    if (tapi_netexpose_sockets(session->factory, &opt, &socks) != 0)
    {
        te_vec_free(&socks);
        return -1;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        for (k = 0; k < n; k++)
        {
            char la[64];

            if (ino[k] != s->inode)
                continue;
            (*total)++;
            sock_addr(&s->local, la, sizeof(la));
            if (tapi_netexpose_socket_is_listening(s))
            {
                RING("%s: pid %d listens on %s:%u (tapi_netexpose)", id,
                     (int)pid, la, sock_port(&s->local));
                if (cnt < TSH_MAX_PORTS)
                    ports[cnt++] = sock_port(&s->local);
            }
        }
    }
    te_vec_free(&socks);
    return cnt;
}

/** A free TCP port on 127.0.0.1: bound to 0, read back, released. */
static unsigned
tsh_free_port(void)
{
    struct sockaddr_in a;
    socklen_t          l = sizeof(a);
    int                s = socket(AF_INET, SOCK_STREAM, 0);
    unsigned           port = 0;

    if (s < 0)
        return 0;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) == 0 &&
        getsockname(s, (struct sockaddr *)&a, &l) == 0)
        port = ntohs(a.sin_port);
    close(s);
    return port;
}

/** Outcome of one raw exchange. */
typedef struct tsh_xchg_t {
    bool    connected;
    bool    reset;          /**< The peer reset the connection. */
    bool    timeout;        /**< No end of reply within the limit. */
    size_t  len;
    double  secs;
    char    data[4096];
} tsh_xchg_t;

/**
 * Connect to 127.0.0.1:@p port, send @p n bytes (may be zero), half-close
 * when @p fin, read until the peer closes or @p limit_s seconds pass.
 */
static void
tsh_xchg(unsigned port, const char *req, size_t n, bool fin, double limit_s,
         tsh_xchg_t *x)
{
    struct sockaddr_in a;
    double             t0 = now_s();
    int                s = socket(AF_INET, SOCK_STREAM, 0);

    memset(x, 0, sizeof(*x));
    if (s < 0)
        return;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0)
    {
        close(s);
        x->secs = now_s() - t0;
        return;
    }
    x->connected = true;
    if (n > 0)
    {
        size_t off = 0;

        while (off < n)
        {
            ssize_t w = send(s, req + off, n - off, MSG_NOSIGNAL);

            if (w <= 0)
                break;
            off += (size_t)w;
        }
    }
    if (fin)
        shutdown(s, SHUT_WR);
    for (;;)
    {
        double      left = limit_s - (now_s() - t0);
        struct pollfd p = { .fd = s, .events = POLLIN };
        ssize_t     r;

        if (left <= 0)
        {
            x->timeout = true;
            break;
        }
        if (poll(&p, 1, (int)(left * 1000) + 1) <= 0)
        {
            x->timeout = true;
            break;
        }
        r = recv(s, x->data + x->len, sizeof(x->data) - 1 - x->len, 0);
        if (r < 0)
        {
            x->reset = true;
            break;
        }
        if (r == 0)
            break;
        x->len += (size_t)r;
        if (x->len >= sizeof(x->data) - 1)
            break;
    }
    x->data[x->len] = '\0';
    x->secs = now_s() - t0;
    close(s);
}

/** The HTTP status code at the start of @p s; 0 when it is not a reply. */
static int
tsh_status(const char *s)
{
    int code = 0;

    if (strncmp(s, "HTTP/1.", 7) != 0 || strlen(s) < 12)
        return 0;
    if (sscanf(s + 9, "%3d", &code) != 1)
        return 0;
    return code;
}

/** A normal error reply is a 4xx status line. */
static bool
tsh_is_error_reply(const char *s)
{
    int c = tsh_status(s);

    return c >= 400 && c < 500;
}

/** Known-bad control of tsh_is_error_reply(). */
static bool
tsh_reply_control_ok(char *why, size_t size)
{
    if (!tsh_is_error_reply("HTTP/1.1 400 Bad Request\r\n\r\n") ||
        !tsh_is_error_reply("HTTP/1.0 404 Not Found\r\n"))
    {
        snprintf(why, size, "a planted 4xx reply was not accepted");
        return false;
    }
    if (tsh_is_error_reply("HTTP/1.1 200 OK\r\n\r\n") ||
        tsh_is_error_reply("HTTP/1.1 500 Internal Server Error\r\n") ||
        tsh_is_error_reply("") || tsh_is_error_reply("garbage 400") ||
        tsh_is_error_reply("HTTP/1.1 4"))
    {
        snprintf(why, size, "a planted 200, 500, empty or non-HTTP reply "
                 "was accepted as a normal error reply");
        return false;
    }
    return true;
}

/** True while process @p pid has not exited (reaps it when it has). */
static bool
tsh_alive(pid_t pid)
{
    int st;

    return waitpid(pid, &st, WNOHANG) == 0;
}

#endif /* MDE_TSH_LIB_H */
