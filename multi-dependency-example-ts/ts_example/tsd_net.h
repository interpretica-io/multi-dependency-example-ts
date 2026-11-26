/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: the listen-address and reply scenarios (H3, H4)
 *
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
    socklen_t          l = sizeof(a);
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
        TEST_FAIL("H4 control: cannot plant a listener: %s", strerror(errno));
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(f2, (void *)&a, sizeof(a)) != 0 || listen(f2, 1) != 0)
        TEST_FAIL("H4 control: cannot plant a second listener: %s",
                  strerror(errno));
    (void)l;
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
    if (n < 0)
        TEST_FAIL("H4 NOT SETTLED: tapi_netexpose cannot read the socket "
                  "tables");
    if (!saw_lo || !saw_any)
        TEST_FAIL("H4 control failed: planted listeners on 127.0.0.1 and "
                  "0.0.0.0 were reported as [%s]", txt);
}

/** One request with value=<v> hops=0. */
static inline ssize_t
tsd_ring(unsigned port, const char *value, char *out, size_t size)
{
    size_t vl = strlen(value);
    char  *req = malloc(vl + 200);
    ssize_t n;

    if (req == NULL)
        return -1;
    snprintf(req, vl + 200, "GET /ring?value=%s&hops=0 HTTP/1.0\r\n"
             "Host: 127.0.0.1\r\n\r\n", value);
    n = tsd_exchange(port, req, strlen(req), 8000, out, size);
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
    char        logtext[1500];
    char       *big = malloc(100001);
    char        reply[4096];
    const char *bad[4] = { "", "abc", NULL, "1e999999" };
    const char *names[4] = { "empty", "non-numeric", "100000 characters",
                             "out of range" };
    int         n;
    int         i;
    int         code;
    bool        lo = false;
    bool        wild = false;
    bool        other = false;
    int         st = 0;

    snprintf(ts, sizeof(ts), "%s/ts", tsd_src());
    snprintf(log, sizeof(log), "/tmp/%s_%u_%d.log", id, port, sig);
    if (big == NULL)
        TEST_FAIL("%s NOT SETTLED: out of memory", id);
    memset(big, 'a', 100000);
    big[100000] = '\0';
    bad[2] = big;

    if (set)
        snprintf(cmd, sizeof(cmd), "EXAMPLE_PORT=%u EXAMPLE_HOST=127.0.0.1 "
                 "exec node dist/main.js", port);
    else
        snprintf(cmd, sizeof(cmd), "exec env -u EXAMPLE_PORT -u EXAMPLE_HOST "
                 "node dist/main.js");
    TEST_STEP("Start node dist/main.js (%s), expect 127.0.0.1:%u",
              set ? "EXAMPLE_PORT and EXAMPLE_HOST set" : "variables unset",
              port);
    tsd_child = tsd_spawn(ts, cmd, log);
    if (!tsd_wait_port(port, 15) || !tsd_alive(tsd_child, &st))
    {
        tsd_tail(log, logtext, sizeof(logtext));
        TEST_FAIL("%s FAIL: [%s] did not listen on port %u within 15 s "
                  "(alive %d); output: [%s]", id, cmd, port,
                  tsd_alive(tsd_child, &st), logtext);
    }
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
    RING_VERDICT("%s listeners (%s): %s", id, set ? "variables set" :
                 "variables unset", txt);
    if (n < 0 || !lo || wild || other)
    {
        tsd_tail(log, logtext, sizeof(logtext));
        TEST_FAIL("%s FAIL: expected only 127.0.0.1:%u, tapi_netexpose "
                  "reports [%s] (wildcard %d, other %d); output: [%s]", id,
                  port, txt, wild, other, logtext);
    }

    TEST_STEP("A valid request gets 200");
    tsd_ring(port, "42", reply, sizeof(reply));
    if (tsd_status(reply) != 200)
    {
        tsd_tail(log, logtext, sizeof(logtext));
        TEST_FAIL("%s FAIL: a valid request got [%.300s]; output: [%s]", id,
                  reply, logtext);
    }

    for (i = 0; i < 4; i++)
    {
        ssize_t r;
        int     status;

        TEST_STEP("Send %s input", names[i]);
        r = tsd_ring(port, bad[i], reply, sizeof(reply));
        status = tsd_status(reply);
        if (r <= 0 || status < 400 || status > 499)
        {
            tsd_tail(log, logtext, sizeof(logtext));
            TEST_FAIL("%s FAIL: %s input got no error reply (read %zd, "
                      "status %d, reply [%.300s]); process alive %d; "
                      "output: [%s]", id, names[i], r, status, reply,
                      tsd_alive(tsd_child, &st), logtext);
        }
        if (!tsd_alive(tsd_child, &st))
        {
            tsd_tail(log, logtext, sizeof(logtext));
            TEST_FAIL("%s FAIL: the process ended after %s input with "
                      "code %d; output: [%s]", id, names[i], tsd_code(st),
                      logtext);
        }
        RING("%s: %s input -> status %d", id, names[i], status);
    }

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
            {
                tsd_tail(log, logtext, sizeof(logtext));
                TEST_FAIL("%s FAIL: hostile request %d got status %d "
                          "(reply [%.300s]); output: [%s]", id, i, status,
                          reply, logtext);
            }
        }
        if (!tsd_alive(tsd_child, &st))
        {
            tsd_tail(log, logtext, sizeof(logtext));
            TEST_FAIL("%s FAIL: the process ended on hostile input with "
                      "code %d; output: [%s]", id, tsd_code(st), logtext);
        }
    }
    free(big);

    TEST_STEP("Send signal %d, expect exit code 0", sig);
    code = tsd_stop(tsd_child, sig, 10);
    tsd_child = 0;
    tsd_tail(log, logtext, sizeof(logtext));
    if (code != 0)
        TEST_FAIL("%s FAIL: after signal %d the exit code is %d (-2: it did "
                  "not end in 10 s; 128+n: killed by signal n); output: [%s]",
                  id, sig, code, logtext);
    RING_VERDICT("%s PASS: %s on 127.0.0.1:%u, error replies to bad input, "
                 "exit code 0 on signal %d", id,
                 set ? "configured" : "default", port, sig);
}

/** Full H4 scenario: four runs (set/unset, SIGTERM/SIGINT). */
static inline void
tsd_h4_scenario(const char *id, bool hostile)
{
    TEST_STEP("Open a tapi_netexpose session");
    if (tsapi_mde_session_init(&tsd_session, id) != 0)
        TEST_FAIL("%s NOT SETTLED: no session on the agent, the listening "
                  "ports cannot be checked", id);
    tsd_have_session = true;
    TEST_STEP("Control: tapi_netexpose reports planted listeners");
    tsd_listener_control();
    tsd_h4_run(id, true, 9101, SIGTERM, hostile);
    tsd_h4_run(id, false, 9100, SIGTERM, hostile);
    tsd_h4_run(id, true, 9101, SIGINT, hostile);
    tsd_h4_run(id, false, 9100, SIGINT, hostile);
}

#define TSD_GO_PORT     8082
#define TSD_TS_PORT     9103

/**
 * H3: send the same fixed inputs to the Go and the TypeScript example,
 * save status and body of each reply to files and compare them byte for
 * byte. @p structure also checks the shape of the TypeScript reply.
 */
static inline void
tsd_h3_scenario(const char *id, bool structure)
{
    static const char *const inputs[] = {
        "value=42&hops=0",      /* a valid guess */
        "value=1&hops=0",       /* a low guess */
        "value=1000&hops=0",    /* a high guess */
        "value=42&hops=0",      /* a repeat */
    };
    static const char *const kind[] = { "valid", "low", "high", "repeat" };
    const char *src = tsd_src();
    char        ts[PATH_MAX];
    char        cmd[600];
    char        gtxt[2200] = "";
    char        glog[1500];
    char        rg[4096], rt[4096];
    char        fg[2200], ft[2200];
    int         st = 0;
    unsigned    i;

    snprintf(ts, sizeof(ts), "%s/ts", src);
    TEST_STEP("Control: a differing byte is seen");
    {
        char a[] = "status 200\nvalue=1\n";
        char b[] = "status 200\nvalue=2\n";

        if (memcmp(a, a, sizeof(a)) != 0 || memcmp(a, b, sizeof(a)) == 0)
            TEST_FAIL("%s control failed: the byte comparison does not "
                      "see a planted difference", id);
    }

    TEST_STEP("Start the Go example");
    snprintf(cmd, sizeof(cmd), "test -x dist/bin/service-go && "
             "LD_LIBRARY_PATH=\"$PWD/dist/lib:$LD_LIBRARY_PATH\" "
             "exec dist/bin/service-go");
    tsd_child = tsd_spawn(src, cmd, "/tmp/ts_h3_go.log");
    if (!tsd_wait_port(TSD_GO_PORT, 20) || !tsd_alive(tsd_child, &st))
    {
        tsd_tail("/tmp/ts_h3_go.log", glog, sizeof(glog));
        RING_VERDICT("%s SKIPPED: the Go example cannot start", id);
        TEST_SKIP("%s SKIPPED: the Go example cannot start (%s/dist/bin/"
                  "service-go, port %d); H3 cannot be compared; its output: "
                  "[%s]", id, src, TSD_GO_PORT, glog);
    }
    TEST_STEP("Start the TypeScript example on port %d", TSD_TS_PORT);
    snprintf(cmd, sizeof(cmd), "EXAMPLE_PORT=%d EXAMPLE_HOST=127.0.0.1 "
             "exec node dist/main.js", TSD_TS_PORT);
    tsd_child2 = tsd_spawn(ts, cmd, "/tmp/ts_h3_ts.log");
    if (!tsd_wait_port(TSD_TS_PORT, 15))
    {
        tsd_tail("/tmp/ts_h3_ts.log", glog, sizeof(glog));
        TEST_FAIL("%s FAIL: the TypeScript example did not listen on port "
                  "%d; output: [%s]", id, TSD_TS_PORT, glog);
    }

    for (i = 0; i < 4; i++)
    {
        char req[200];
        char pg[64], pt[64];
        FILE *f;

        snprintf(req, sizeof(req), "GET /ring?%s HTTP/1.0\r\nHost: "
                 "127.0.0.1\r\n\r\n", inputs[i]);
        TEST_STEP("Send the %s input [%s] to both", kind[i], inputs[i]);
        tsd_exchange(TSD_GO_PORT, req, strlen(req), 8000, rg, sizeof(rg));
        tsd_exchange(TSD_TS_PORT, req, strlen(req), 8000, rt, sizeof(rt));
        snprintf(fg, sizeof(fg), "status %d\n%s", tsd_status(rg),
                 tsd_body(rg));
        snprintf(ft, sizeof(ft), "status %d\n%s", tsd_status(rt),
                 tsd_body(rt));
        snprintf(pg, sizeof(pg), "/tmp/ts_h3_go_%u.txt", i + 1);
        snprintf(pt, sizeof(pt), "/tmp/ts_h3_ts_%u.txt", i + 1);
        f = fopen(pg, "w");
        if (f != NULL)
            fputs(fg, f), fclose(f);
        f = fopen(pt, "w");
        if (f != NULL)
            fputs(ft, f), fclose(f);
        RING("%s: %s input: Go reply [%s] TypeScript reply [%s]", id,
             kind[i], fg, ft);
        if (strlen(fg) != strlen(ft) || memcmp(fg, ft, strlen(fg)) != 0)
        {
            RING_VERDICT("%s mismatch on the %s input", id, kind[i]);
            TEST_FAIL("%s FAIL: replies differ on the %s input [%s]. "
                      "Go reply: [%s] TypeScript reply: [%s]", id, kind[i],
                      inputs[i], fg, ft);
        }
        if (structure && (tsd_status(rt) != 200 ||
                          strstr(tsd_body(rt), "value=") == NULL))
            TEST_FAIL("%s FAIL: the TypeScript reply to the %s input has "
                      "no status 200 and value= line: [%s]", id, kind[i],
                      ft);
        snprintf(gtxt + strlen(gtxt), sizeof(gtxt) - strlen(gtxt), "%s ok; ",
                 kind[i]);
    }
    RING_VERDICT("%s PASS: Go and TypeScript replies equal byte for byte "
                 "(%s)", id, gtxt);
}

#endif /* MDE_TSD_NET_H */
