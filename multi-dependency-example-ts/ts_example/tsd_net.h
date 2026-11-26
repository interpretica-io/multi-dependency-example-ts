/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: the listen-address and reply scenarios (H3, H4)
 *
 * Nothing here ends a test: every step writes a verdict, a failed step is
 * recorded with tsd_bad() and the test fails once at its end.
 * tsd_listeners() reads the listening TCP sockets of a process with
 * tapi_netexpose. tsd_h4_scenario() starts the TypeScript example with and
 * without the address variables, checks where it listens, sends bad input
 * and stops it with a signal. tsd_h3_scenario() sends fixed inputs to the
 * Go example and the TypeScript example and compares the replies.
 *
 * @author midair <midair@localhost>
 */

#ifndef MDE_TSD_NET_H
#define MDE_TSD_NET_H

#include "tsd.h"

#include <dirent.h>

#include "tsapi_mde.h"
#include "tapi_netexpose.h"

#define TSD_MAXL    16

/** Process started by the scenario, killed by tsd_cleanup(). */
static pid_t tsd_child = 0;
static pid_t tsd_child2 = 0;
static tsapi_mde_session tsd_session = { .ta = NULL };
static bool tsd_have_session = false;

static inline void
tsd_cleanup(void)
{
    if (tsd_child > 0)
        tsd_stop(tsd_child, SIGKILL, 5);
    if (tsd_child2 > 0)
        tsd_stop(tsd_child2, SIGKILL, 5);
    tsd_child = tsd_child2 = 0;
    if (tsd_have_session)
        tsapi_mde_session_fini(&tsd_session);
    tsd_have_session = false;
}

/** Inode numbers of the sockets a process holds. */
static inline size_t
tsd_inodes(pid_t pid, unsigned long *out, size_t max)
{
    char           dir[64];
    DIR           *d;
    struct dirent *e;
    size_t         n = 0;

    snprintf(dir, sizeof(dir), "/proc/%d/fd", (int)pid);
    d = opendir(dir);
    if (d == NULL)
        return 0;
    while ((e = readdir(d)) != NULL && n < max)
    {
        char    path[300];
        char    link[64];
        ssize_t l;
        unsigned long ino;

        snprintf(path, sizeof(path), "%s/%.200s", dir, e->d_name);
        l = readlink(path, link, sizeof(link) - 1);
        if (l <= 0)
            continue;
        link[l] = '\0';
        if (sscanf(link, "socket:[%lu]", &ino) == 1)
            out[n++] = ino;
    }
    closedir(d);
    return n;
}

/**
 * Listening TCP sockets of @p pid as tapi_netexpose reports them.
 * Returns the count (at most TSD_MAXL), -1 when the tables cannot be read.
 */
static inline int
tsd_listeners(pid_t pid, char addr[][48], unsigned *port)
{
    unsigned long                ino[256];
    tapi_netexpose_opt           opt = tapi_netexpose_default_opt;
    te_vec                       socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    size_t                       n = tsd_inodes(pid, ino, 256);
    size_t                       k;
    int                          cnt = 0;

    opt.udp = false;
    opt.tcp = true;
    if (tapi_netexpose_sockets(tsd_session.factory, &opt, &socks) != 0)
    {
        te_vec_free(&socks);
        return -1;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        if (!tapi_netexpose_socket_is_listening(s))
            continue;
        for (k = 0; k < n; k++)
        {
            if (ino[k] != s->inode || cnt >= TSD_MAXL)
                continue;
            snprintf(addr[cnt], 48, "?");
            if (s->local.ss_family == AF_INET)
            {
                const struct sockaddr_in *a = (const void *)&s->local;

                inet_ntop(AF_INET, &a->sin_addr, addr[cnt], 48);
                port[cnt] = ntohs(a->sin_port);
            }
            else
            {
                const struct sockaddr_in6 *a = (const void *)&s->local;

                inet_ntop(AF_INET6, &a->sin6_addr, addr[cnt], 48);
                port[cnt] = ntohs(a->sin6_port);
            }
            RING("pid %d listens on %s:%u (tapi_netexpose)", (int)pid,
                 addr[cnt], port[cnt]);
            cnt++;
        }
    }
    te_vec_free(&socks);
    return cnt;
}

/** Text "a:p a:p" of the listeners, for a message. */
static inline void
tsd_listeners_text(char addr[][48], unsigned *port, int n, char *buf,
                   size_t size)
{
    int i;

    buf[0] = '\0';
    for (i = 0; i < n; i++)
        snprintf(buf + strlen(buf), size - strlen(buf), "%s:%u ", addr[i],
                 port[i]);
    if (n <= 0)
        snprintf(buf, size, "(none)");
}

/**
 * Known-bad control for the listener check: this process listens on
 * 127.0.0.1 and on 0.0.0.0, and tapi_netexpose must report both.
 */
static inline void
tsd_listener_control(void)
{
    struct sockaddr_in a = { .sin_family = AF_INET };
    int                f1 = socket(AF_INET, SOCK_STREAM, 0);
    int                f2 = socket(AF_INET, SOCK_STREAM, 0);
    char               addr[TSD_MAXL][48];
    unsigned           port[TSD_MAXL];
    char               txt[800];
    bool               saw_lo = false;
    bool               saw_any = false;
    int                i;
    int                n;

    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (f1 < 0 || f2 < 0 || bind(f1, (void *)&a, sizeof(a)) != 0 ||
        listen(f1, 1) != 0)
    {
        tsd_bad("H4", "listener control", "cannot plant a listener: %s",
                strerror(errno));
        return;
    }
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = 0;
    if (bind(f2, (void *)&a, sizeof(a)) != 0 || listen(f2, 1) != 0)
    {
        tsd_bad("H4", "listener control", "cannot plant a second listener: "
                "%s", strerror(errno));
        return;
    }
    n = tsd_listeners(getpid(), addr, port);
    tsd_listeners_text(addr, port, n, txt, sizeof(txt));
    for (i = 0; i < n; i++)
    {
        if (strcmp(addr[i], "127.0.0.1") == 0)
            saw_lo = true;
        if (strcmp(addr[i], "0.0.0.0") == 0)
            saw_any = true;
    }
    close(f1);
    close(f2);
    if (n < 0 || !saw_lo || !saw_any)
        tsd_bad("H4", "listener control", "planted listeners on 127.0.0.1 "
                "and 0.0.0.0 were reported as [%s] (n=%d)", txt, n);
    else
        tsd_say("H4 listener control: planted listeners seen as [%s]", txt);
}

/** One request with value=<v> hops=0. */
static inline ssize_t
tsd_ring(unsigned port, const char *value, char *out, size_t size)
{
    size_t  vl = strlen(value);
    char   *req = malloc(vl + 200);
    ssize_t n;

    out[0] = '\0';
    if (req == NULL)
        return -1;
    snprintf(req, vl + 200, "GET /ring?value=%s&hops=0 HTTP/1.0\r\n"
             "Host: 127.0.0.1\r\n\r\n", value);
    n = tsd_exchange(port, req, strlen(req), 5000, out, size);
    free(req);
    return n;
}

/**
 * H4: start the example with the address variables set (@p set) or unset,
 * check where it listens, send empty, non-numeric and oversized input,
 * stop it with @p sig and require exit code 0. @p hostile adds raw garbage,
 * a bad method, a path walk and a silent peer.
 */
static inline void
tsd_h4_run(const char *id, bool set, unsigned port, int sig, bool hostile)
{
    char        ts[PATH_MAX];
    char        cmd[400];
    char        log[64];
    char        addr[TSD_MAXL][48];
    unsigned    lp[TSD_MAXL];
    char        txt[800];
    char        logtext[401];
    char        reply[4096];
    char       *big = malloc(70001);
    const char *bad[3] = { "", "abc", NULL };
    const char *names[3] = { "empty", "non-numeric", "70000-byte" };
    const char *sname = sig == SIGTERM ? "SIGTERM" : "SIGINT";
    int         n = -1;
    int         i;
    int         code;
    bool        lo = false;
    bool        wild = false;
    bool        other = false;
    int         st = 0;

    snprintf(ts, sizeof(ts), "%s/ts", tsd_src());
    snprintf(log, sizeof(log), "/tmp/%s_%u_%d.log", id, port, sig);
    if (big == NULL)
    {
        tsd_bad(id, "memory", "out of memory");
        return;
    }
    memset(big, 'a', 70000);
    big[70000] = '\0';
    bad[2] = big;

    if (set)
        snprintf(cmd, sizeof(cmd), "EXAMPLE_PORT=%u EXAMPLE_HOST=127.0.0.1 "
                 "exec node dist/main.js", port);
    else
        snprintf(cmd, sizeof(cmd), "exec env -u EXAMPLE_PORT -u EXAMPLE_HOST "
                 "node dist/main.js");
    if (tsd_connect(port) >= 0)
    {
        tsd_bad(id, set ? "port in use" : "default port in use",
                "something already listens on 127.0.0.1:%u before the "
                "start", port);
        free(big);
        return;
    }
    TEST_STEP("Start node dist/main.js (%s), expect 127.0.0.1:%u",
              set ? "EXAMPLE_PORT and EXAMPLE_HOST set" : "variables unset",
              port);
    tsd_child = tsd_spawn(ts, cmd, log);
    if (!tsd_wait_port(port, 15) || !tsd_alive(tsd_child, &st))
    {
        tsd_tail(log, logtext, sizeof(logtext));
        tsd_bad(id, set ? "listens on configured port" : "default port",
                "[%s] did not listen on port %u within 15 s (alive %d); "
                "output: [%s]", cmd, port, tsd_alive(tsd_child, &st),
                logtext);
        tsd_stop(tsd_child, SIGKILL, 5);
        tsd_child = 0;
        free(big);
        return;
    }
    if (tsd_have_session)
        n = tsd_listeners(tsd_child, addr, lp);
    tsd_listeners_text(addr, lp, n, txt, sizeof(txt));
    for (i = 0; i < n; i++)
    {
        if (lp[i] == port && strcmp(addr[i], "127.0.0.1") == 0)
            lo = true;
        else if (strcmp(addr[i], "0.0.0.0") == 0 || strcmp(addr[i], "::") == 0)
            wild = true;
        else
            other = true;
    }
    if (n < 0)
        tsd_say("%s %s: port %u accepts connections (connect check; "
                "tapi_netexpose not available)", id,
                set ? "listens on configured port" : "default port", port);
    else if (!lo || wild || other)
        tsd_bad(id, set ? "listens on configured port" : "default port",
                "expected only 127.0.0.1:%u, tapi_netexpose reports [%s] "
                "(wildcard %d, other %d)", port, txt, wild, other);
    else
        tsd_say("%s %s: 127.0.0.1:%u only (tapi_netexpose [%s])", id,
                set ? "listens on configured port" : "default port", port,
                txt);

    TEST_STEP("A valid request gets 200");
    tsd_ring(port, "42", reply, sizeof(reply));
    if (tsd_status(reply) != 200)
        tsd_bad(id, "valid input", "a valid request got [%.300s]", reply);
    else
        tsd_say("%s valid input reply: status 200", id);

    for (i = 0; i < 3; i++)
    {
        ssize_t r;
        int     status;

        TEST_STEP("Send %s input", names[i]);
        r = tsd_ring(port, bad[i], reply, sizeof(reply));
        status = tsd_status(reply);
        if (r <= 0 || status < 400 || status > 499)
            tsd_bad(id, "bad input reply", "%s input got no error reply "
                    "(read %zd, status %d, reply [%.300s])", names[i], r,
                    status, reply);
        else
            tsd_say("%s bad input reply: %s input -> status %d [%.200s]",
                    id, names[i], status, tsd_body(reply));
        if (!tsd_alive(tsd_child, &st))
        {
            tsd_tail(log, logtext, sizeof(logtext));
            tsd_bad(id, "alive after bad input", "the process ended after "
                    "%s input with code %d; output: [%s]", names[i],
                    tsd_code(st), logtext);
            tsd_child = 0;
            free(big);
            return;
        }
    }
    tsd_ring(port, "42", reply, sizeof(reply));
    if (tsd_status(reply) != 200)
        tsd_bad(id, "valid input after bad input", "got [%.300s]", reply);
    else
        tsd_say("%s alive after bad input: a later valid input got 200", id);

    if (hostile)
    {
        static const char junk[] = "\x00\xff\x01\x02 GET \x80\x81 HTTP/9\r\n"
            "\r\n\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03";
        static const char *const more[] = {
            "TRACE /ring HTTP/1.0\r\n\r\n",
            "GET /../../etc/passwd HTTP/1.0\r\n\r\n",
            "GET /ring?value=1&hops=1000000000 HTTP/1.0\r\n\r\n",
            "GET /ring?value=1&value=2&hops=-1 HTTP/1.0\r\n\r\n",
        };

        TEST_STEP("Send raw garbage and a silent connection");
        tsd_exchange(port, junk, sizeof(junk) - 1, 2000, reply,
                     sizeof(reply));
        tsd_exchange(port, "", 0, 500, reply, sizeof(reply));
        for (i = 0; i < 4; i++)
        {
            int status;

            tsd_exchange(port, more[i], strlen(more[i]), 5000, reply,
                         sizeof(reply));
            status = tsd_status(reply);
            if (status < 400 || status > 499)
                tsd_bad(id, "hostile input", "hostile request %d got "
                        "status %d (reply [%.300s])", i, status, reply);
            else
                tsd_say("%s hostile input %d: status %d", id, i, status);
        }
        if (!tsd_alive(tsd_child, &st))
        {
            tsd_tail(log, logtext, sizeof(logtext));
            tsd_bad(id, "alive after hostile input", "the process ended "
                    "with code %d; output: [%s]", tsd_code(st), logtext);
            tsd_child = 0;
            free(big);
            return;
        }
    }
    free(big);

    TEST_STEP("Send %s, expect exit code 0", sname);
    code = tsd_stop(tsd_child, sig, 10);
    tsd_child = 0;
    tsd_tail(log, logtext, sizeof(logtext));
    if (code != 0)
        tsd_bad(id, sig == SIGTERM ? "SIGTERM exit" : "SIGINT exit",
                "%s exit=%d (-2: still running after 10 s; 128+n: killed "
                "by signal n); output: [%s]", sname, code, logtext);
    else
        tsd_say("%s %s exit=%d (%s, 127.0.0.1:%u)", id, sname, code,
                set ? "configured" : "default", port);
}

/** Full H4 scenario: four runs (set/unset, SIGTERM/SIGINT). */
static inline void
tsd_h4_scenario(const char *id, bool hostile)
{
    unsigned p1 = tsd_free_port();
    unsigned p2;

    signal(SIGPIPE, SIG_IGN);
    TEST_STEP("Open a tapi_netexpose session");
    if (tsapi_mde_session_init(&tsd_session, id) != 0)
        tsd_say("%s: no session on the agent; the listening ports are "
                "checked by connecting only", id);
    else
    {
        tsd_have_session = true;
        TEST_STEP("Control: tapi_netexpose reports planted listeners");
        tsd_listener_control();
    }
    tsd_h4_run(id, true, p1, SIGTERM, hostile);
    p2 = tsd_free_port();
    tsd_h4_run(id, true, p2 == p1 ? p2 + 1 : p2, SIGINT, hostile);
    tsd_h4_run(id, false, 9100, SIGTERM, hostile);
    tsd_h4_run(id, false, 9100, SIGINT, hostile);
}

#define TSD_GO_PORT     8082

/** True when files @p a and @p b are equal (cmp, exit code in @p code). */
static inline bool
tsd_cmp(const char *a, const char *b, int *code)
{
    char cmd[400];

    snprintf(cmd, sizeof(cmd), "cmp '%s' '%s' > /dev/null 2>&1", a, b);
    *code = tsd_code(system(cmd));
    return *code == 0;
}

/**
 * Known-bad control for the H3 comparison: a tiny script prints a reply
 * that differs from the reference, and cmp must fail on it; the same script
 * compared with itself must pass.
 */
static inline void
tsd_h3_control(const char *id)
{
    int code1 = -1;
    int code2 = -1;
    int code3 = -1;

    tsd_put("/tmp/ts_h3_ctl_bad.sh", "#!/bin/sh\necho 'status 200'\necho "
            "'value=999'\n");
    tsd_put("/tmp/ts_h3_ctl_ref.txt", "status 200\nvalue=42\n");
    code1 = tsd_sh("/tmp", "sh /tmp/ts_h3_ctl_bad.sh", 10,
                   "/tmp/ts_h3_ctl_out.txt");
    (void)tsd_cmp("/tmp/ts_h3_ctl_ref.txt", "/tmp/ts_h3_ctl_out.txt", &code2);
    (void)tsd_cmp("/tmp/ts_h3_ctl_out.txt", "/tmp/ts_h3_ctl_out.txt", &code3);
    if (code1 != 0 || code2 == 0 || code3 != 0)
        tsd_bad(id, "known-bad control", "script exit=%d, cmp on a "
                "different reply exit=%d (must be non-zero), cmp on equal "
                "replies exit=%d (must be 0)", code1, code2, code3);
    else
        tsd_say("%s control known-bad: cmp exit=%d on the script printing a "
                "different reply (difference caught), exit=%d on equal "
                "files", id, code2, code3);
}

#define TSD_H3_N    4
static const char *const tsd_h3_kind[TSD_H3_N] = {
    "valid", "empty", "non-numeric", "oversized"
};

static inline void
tsd_h3_paths(unsigned i, char *pg, char *pt, size_t size)
{
    snprintf(pg, size, "/tmp/ts_h3_go_%u.txt", i + 1);
    snprintf(pt, size, "/tmp/ts_h3_ts_%u.txt", i + 1);
}

/** True when all reply files of a previous run exist. */
static inline bool
tsd_h3_files_exist(void)
{
    unsigned i;

    for (i = 0; i < TSD_H3_N; i++)
    {
        char pg[64], pt[64];

        tsd_h3_paths(i, pg, pt, sizeof(pg));
        if (access(pg, R_OK) != 0 || access(pt, R_OK) != 0)
            return false;
    }
    return true;
}

/**
 * Start the Go and the TypeScript example, send the four fixed inputs to
 * both with a 5 s timeout and save the replies (status line and body) to
 * /tmp/ts_h3_{go,ts}_N.txt. Failures are verdicts under @p id.
 */
static inline void
tsd_h3_collect(const char *id)
{
    const char *src = tsd_src();
    char        ts[PATH_MAX];
    char        cmd[600];
    char        glog[401];
    char       *big = malloc(70100);
    char       *req = malloc(70300);
    char       *rg = malloc(16384);
    char       *rt = malloc(16384);
    char        fb[16500];
    unsigned    tsport = tsd_free_port();
    int         st = 0;
    unsigned    i;

    signal(SIGPIPE, SIG_IGN);
    snprintf(ts, sizeof(ts), "%s/ts", src);
    if (big == NULL || req == NULL || rg == NULL || rt == NULL)
    {
        tsd_bad(id, "memory", "out of memory");
        goto out;
    }
    memset(big, 'a', 70000);
    big[70000] = '\0';

    TEST_STEP("Start the Go example (its port is fixed by the contract: %d)",
              TSD_GO_PORT);
    if (tsd_connect(TSD_GO_PORT) >= 0)
        tsd_say("%s: something already listens on port %d; the Go example "
                "takes its port from web/contract/services.tab and has no "
                "variable for it", id, TSD_GO_PORT);
    snprintf(cmd, sizeof(cmd), "test -x dist/bin/service-go && "
             "LD_LIBRARY_PATH=\"$PWD/dist/lib:$LD_LIBRARY_PATH\" "
             "exec dist/bin/service-go");
    tsd_child = tsd_spawn(src, cmd, "/tmp/ts_h3_go.log");
    if (!tsd_wait_port(TSD_GO_PORT, 20) || !tsd_alive(tsd_child, &st))
    {
        tsd_tail("/tmp/ts_h3_go.log", glog, sizeof(glog));
        tsd_bad(id, "start Go", "the Go example did not listen on port %d "
                "(%s/dist/bin/service-go); output: [%s]", TSD_GO_PORT, src,
                glog);
        goto out;
    }
    tsd_say("%s start Go: listening on port %d", id, TSD_GO_PORT);

    TEST_STEP("Start the TypeScript example on port %u", tsport);
    snprintf(cmd, sizeof(cmd), "EXAMPLE_PORT=%u EXAMPLE_HOST=127.0.0.1 "
             "exec node dist/main.js", tsport);
    tsd_child2 = tsd_spawn(ts, cmd, "/tmp/ts_h3_ts.log");
    if (!tsd_wait_port(tsport, 15) || !tsd_alive(tsd_child2, &st))
    {
        tsd_tail("/tmp/ts_h3_ts.log", glog, sizeof(glog));
        tsd_bad(id, "start TypeScript", "the TypeScript example did not "
                "listen on port %u; output: [%s]", tsport, glog);
        goto out;
    }
    tsd_say("%s start TypeScript: listening on port %u", id, tsport);

    for (i = 0; i < TSD_H3_N; i++)
    {
        char    pg[64], pt[64];
        char    val[80];
        ssize_t ng, nt;
        const char *v;

        v = i == 0 ? "42" : i == 1 ? "" : i == 2 ? "abc" : big;
        snprintf(val, sizeof(val), "%.60s", v);
        snprintf(req, 70300, "GET /ring?value=%s&hops=0 HTTP/1.0\r\n"
                 "Host: 127.0.0.1\r\n\r\n", v);
        TEST_STEP("Send the %s input to both", tsd_h3_kind[i]);
        ng = tsd_exchange(TSD_GO_PORT, req, strlen(req), 5000, rg, 16384);
        nt = tsd_exchange(tsport, req, strlen(req), 5000, rt, 16384);
        tsd_h3_paths(i, pg, pt, sizeof(pg));
        snprintf(fb, sizeof(fb), "status %d\n%s", tsd_status(rg),
                 tsd_body(rg));
        tsd_put(pg, fb);
        snprintf(fb, sizeof(fb), "status %d\n%s", tsd_status(rt),
                 tsd_body(rt));
        tsd_put(pt, fb);
        tsd_say("%s input %u collected (%s, value=%.40s): Go read %zd "
                "bytes status %d, TypeScript read %zd bytes status %d",
                id, i + 1, tsd_h3_kind[i], val, ng, tsd_status(rg), nt,
                tsd_status(rt));
        if (ng < 0 || nt < 0)
            tsd_bad(id, "send input", "input %u: connect failed (Go %zd, "
                    "TypeScript %zd)", i + 1, ng, nt);
    }
out:
    tsd_cleanup();
    free(big);
    free(req);
    free(rg);
    free(rt);
}

/**
 * H3 comparison of the saved files, one verdict per input: 'H3 input N
 * same' or 'H3 input N differs' with both replies. Nothing is weakened:
 * one differing byte fails the test.
 */
static inline void
tsd_h3_compare(const char *id)
{
    unsigned i;

    for (i = 0; i < TSD_H3_N; i++)
    {
        char pg[64], pt[64];
        char a[401], b[401];
        int  code;
        bool same;

        tsd_h3_paths(i, pg, pt, sizeof(pg));
        same = tsd_cmp(pg, pt, &code);
        tsd_head(pg, a, sizeof(a));
        tsd_head(pt, b, sizeof(b));
        if (same)
            tsd_say("H3 input %u same (%s; cmp exit=%d) reply: [%s]", i + 1,
                    tsd_h3_kind[i], code, a);
        else
        {
            char nm[40];

            snprintf(nm, sizeof(nm), "input %u differs", i + 1);
            tsd_say("H3 input %u differs (%s; cmp exit=%d) Go reply: [%s] "
                    "TypeScript reply: [%s]", i + 1, tsd_h3_kind[i], code,
                    a, b);
            tsd_flag(nm);
        }
    }
    (void)id;
}

#endif /* MDE_TSD_NET_H */
