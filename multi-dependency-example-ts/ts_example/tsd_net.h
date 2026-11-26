/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: the listen-address, exit-time and reply scenarios (H2, H3)
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
        tsd_bad("H3", "listener control", "cannot plant a listener: %s",
                strerror(errno));
        return;
    }
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = 0;
    if (bind(f2, (void *)&a, sizeof(a)) != 0 || listen(f2, 1) != 0)
    {
        tsd_bad("H3", "listener control", "cannot plant a second listener: "
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
        tsd_bad("H3", "listener control", "planted listeners on 127.0.0.1 "
                "and 0.0.0.0 were reported as [%s] (n=%d)", txt, n);
    else
        tsd_say("H3 listener control: planted listeners seen as [%s]", txt);
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
 * Wait for the process @p pid to listen on @p port or to exit, at most
 * @p secs. Logs what is waited for, and the time of the process start
 * (@p t0), of its first output line (the log file gets a byte) and of its
 * exit, all relative to the start. Returns 1 when the port accepts, 0 when
 * the process exited (status in @p st), -1 at the limit.
 */
static inline int
tsd_wait_up_or_exit(const char *id, pid_t pid, unsigned port, int secs,
                    const char *log, long long t0, int *st)
{
    long long end = t0 + secs * 1000LL;
    long long t_first = -1;
    long long now;
    struct stat sb;
    int       r = -1;

    tsd_say("%s waits for: 127.0.0.1:%u to accept, or the process to exit, "
            "at most %d s; process started at +0 ms", id, port, secs);
    while ((now = tsd_ms()) < end)
    {
        int fd;

        if (t_first < 0 && stat(log, &sb) == 0 && sb.st_size > 0)
        {
            t_first = now - t0;
            tsd_say("%s first output line at +%lld ms", id, t_first);
        }
        if (!tsd_alive(pid, st))
        {
            if (t_first < 0 && stat(log, &sb) == 0 && sb.st_size > 0)
                t_first = now - t0;
            tsd_say("%s process exited at +%lld ms, first output at %lld ms "
                    "(-1: none)", id, now - t0, t_first);
            return 0;
        }
        fd = tsd_connect(port);
        if (fd >= 0)
        {
            close(fd);
            tsd_say("%s listener accepts at +%lld ms", id, now - t0);
            return 1;
        }
        usleep(20000);
    }
    tsd_say("%s neither a listener nor an exit within %d s: the delay is "
            "in the service, not in the test wait", id, secs);
    return r;
}

/**
 * H3: start the example with the address variables set (@p set) or unset,
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
    int         up;
    long long   t_start;
    long long   t_up;

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
                 "RING_PORT=%u RING_HOST=127.0.0.1 exec node dist/main.js",
                 port, port);
    else
        snprintf(cmd, sizeof(cmd), "exec env -u EXAMPLE_PORT -u EXAMPLE_HOST "
                 "-u RING_PORT -u RING_HOST node dist/main.js");
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
    t_start = tsd_ms();
    tsd_child = tsd_spawn(ts, cmd, log);
    up = tsd_wait_up_or_exit(id, tsd_child, port, 15, log, t_start, &st);
    t_up = tsd_ms() - t_start;
    if (up != 1)
    {
        tsd_tail(log, logtext, sizeof(logtext));
        if (up == 0 && !set)
        {
            /* the host and port setting is required: one line, exit 1, at once */
            bool one = tsd_code(st) == 1 && strstr(logtext, "\n    at ") == NULL &&
                       strchr(logtext, '\n') == strrchr(logtext, '\n');

            tsd_say("%s unset variables: exit %d after %lld ms, output "
                    "[%s]", id, tsd_code(st), t_up, logtext);
            if (!one)
                tsd_bad(id, "unset variables", "want exit 1 and one line "
                        "without a trace, got exit %d: [%s]", tsd_code(st),
                        logtext);
            else if (t_up > 2000)
                tsd_bad(id, "unset variables", "the service takes %lld ms "
                        "to exit (limit 2000): the delay is in the service",
                        t_up);
            else
                tsd_say("%s default port: no default, the process says so "
                        "in one line and exits 1 after %lld ms; any wait "
                        "beyond that was the test's, not the service's", id,
                        t_up);
            tsd_child = 0;
            free(big);
            return;
        }
        tsd_bad(id, set ? "listens on configured port" : "default port",
                "[%s] did not listen on port %u (%s after %lld ms); "
                "output: [%s]", cmd, port, up == 0 ? "exited" :
                "still running, the delay is in the service", t_up,
                logtext);
        if (up != 0)
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

/** Full H3 scenario: four runs (set/unset, SIGTERM/SIGINT). */
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

/** Value of the last "value=" line of a reply body; false when absent. */
static inline bool
tsd_contract_value(const char *body, double *v)
{
    const char *p = NULL;
    const char *q = body;
    char       *end = NULL;

    while ((q = strstr(q, "value=")) != NULL)
    {
        p = q;
        q += 6;
    }
    if (p == NULL)
        return false;
    *v = strtod(p + 6, &end);
    return end != p + 6;
}

/**
 * The documented contract of the TypeScript service: a valid request gets
 * 200 and a finite value (and, when @p formula is set, the value of the
 * stage formula), a bad one gets 400 and an "error:" line. Returns NULL
 * when the reply is as documented, otherwise the reason.
 */
static inline const char *
tsd_contract_check(unsigned kind, int status, const char *body, bool formula,
                   double expect)
{
    double v = 0;

    if (kind == 0)
    {
        if (status != 200)
            return "status is not 200";
        if (!tsd_contract_value(body, &v) || v != v || v > 1e300 || v < -1e300)
            return "no finite value";
        if (formula && (v - expect > 1e-9 || expect - v > 1e-9))
            return "value differs from the documented formula";
        return NULL;
    }
    if (status != 400)
        return "status is not 400";
    if (strncmp(tsd_body(body), "error:", 6) != 0)
        return "no error: line";
    return NULL;
}

/** Known-bad control: planted replies that the check must reject. */
static inline void
tsd_contract_control(const char *id)
{
    bool ok = tsd_contract_check(0, 200, "value=nan\n", false, 0) != NULL &&
              tsd_contract_check(0, 500, "value=1\n", false, 0) != NULL &&
              tsd_contract_check(0, 200, "value=35\n", true, 34.5) != NULL &&
              tsd_contract_check(1, 200, "error: x\n", false, 0) != NULL &&
              tsd_contract_check(1, 400, "oops\n", false, 0) != NULL &&
              tsd_contract_check(0, 200, "value=34.5\n", true, 34.5) == NULL &&
              tsd_contract_check(2, 400, "error: x\n", false, 0) == NULL;

    if (!ok)
        tsd_bad(id, "known-bad control", "the contract check accepted a "
                "planted wrong reply or rejected a planted good one");
    else
        tsd_say("%s control known-bad: planted wrong replies are rejected",
                id);
}

#define TSD_H3_N    4
static const char *const tsd_h3_kind[TSD_H3_N] = {
    "valid", "empty", "non-numeric", "oversized"
};

/**
 * Contract of the TypeScript service against its own documentation: four
 * inputs, status code and finite value (the formula as well when the README
 * gives one). The Go reply is logged as information only.
 */
static inline void
tsd_contract_run(const char *id)
{
    const char *src = tsd_src();
    char        ts[PATH_MAX];
    char        cmd[600];
    char        tlog[401];
    char       *big = malloc(70100);
    char       *req = malloc(70300);
    char       *rt = malloc(16384);
    char       *rg = malloc(16384);
    unsigned    tsport = tsd_free_port();
    bool        formula = false;
    double      expect = 0;
    int         st = 0;
    unsigned    i;

    signal(SIGPIPE, SIG_IGN);
    snprintf(ts, sizeof(ts), "%s/ts", src);
    if (big == NULL || req == NULL || rt == NULL || rg == NULL)
    {
        tsd_bad(id, "memory", "out of memory");
        goto out;
    }
    memset(big, 'a', 70000);
    big[70000] = '\0';

    TEST_STEP("Does the TypeScript README give the stage formula");
    if (tsd_sh(src, "grep -nE '0\\.75' README.md ts/README.md",
               10, "/tmp/ts_ct_readme.log") == 0)
    {
        formula = true;
        expect = 42 * 0.75 + 3;
        tsd_say("%s README formula found: value = v * 0.75 + 3 times the "
                "weight 1.0", id);
    }
    else
        tsd_say("%s README gives no stage formula: only the status code "
                "and a finite value are checked", id);

    TEST_STEP("Start the TypeScript example on port %u", tsport);
    snprintf(cmd, sizeof(cmd), "EXAMPLE_PORT=%u EXAMPLE_HOST=127.0.0.1 "
             "RING_PORT=%u RING_HOST=127.0.0.1 exec node dist/main.js",
             tsport, tsport);
    tsd_child2 = tsd_spawn(ts, cmd, "/tmp/ts_ct_ts.log");
    if (!tsd_wait_port(tsport, 15) || !tsd_alive(tsd_child2, &st))
    {
        tsd_tail("/tmp/ts_ct_ts.log", tlog, sizeof(tlog));
        tsd_bad(id, "start TypeScript", "did not listen on port %u; "
                "output: [%s]", tsport, tlog);
        goto out;
    }

    TEST_STEP("Start the Go example for information only");
    snprintf(cmd, sizeof(cmd), "test -x dist/bin/service-go && "
             "LD_LIBRARY_PATH=\"$PWD/dist/lib:$LD_LIBRARY_PATH\" "
             "exec dist/bin/service-go");
    tsd_child = tsd_spawn(src, cmd, "/tmp/ts_ct_go.log");
    if (!tsd_wait_port(TSD_GO_PORT, 10))
        tsd_say("%s Go example not available: its value is not logged", id);

    for (i = 0; i < TSD_H3_N; i++)
    {
        const char *v = i == 0 ? "42" : i == 1 ? "" : i == 2 ? "abc" : big;
        const char *why;
        double      gv = 0;
        int         status;
        ssize_t     nt;

        snprintf(req, 70300, "GET /ring?value=%s&hops=0 HTTP/1.0\r\n"
                 "Host: ts\r\n\r\n", v);
        TEST_STEP("Send the %s input", tsd_h3_kind[i]);
        nt = tsd_exchange(tsport, req, strlen(req), 5000, rt, 16384);
        status = tsd_status(rt);
        if (nt <= 0)
        {
            char nm[40];

            snprintf(nm, sizeof(nm), "input %u no reply", i + 1);
            tsd_say("%s input %u (%s): no reply (read %zd)", id, i + 1,
                    tsd_h3_kind[i], nt);
            tsd_flag(nm);
            continue;
        }
        why = tsd_contract_check(i, status, tsd_body(rt), formula, expect);
        if (why != NULL)
        {
            char nm[40];

            snprintf(nm, sizeof(nm), "input %u %s", i + 1, why);
            tsd_say("%s input %u (%s) breaks the contract: %s; status %d "
                    "reply [%.200s]", id, i + 1, tsd_h3_kind[i], why, status,
                    tsd_body(rt));
            tsd_flag(nm);
        }
        else
            tsd_say("%s input %u (%s) follows the contract: status %d "
                    "[%.120s]", id, i + 1, tsd_h3_kind[i], status,
                    tsd_body(rt));
        if (tsd_exchange(TSD_GO_PORT, req, strlen(req), 5000, rg, 16384) > 0)
        {
            bool have = tsd_contract_value(tsd_body(rg), &gv);

            tsd_say("%s info only, Go input %u: status %d value %s%.4f", id,
                    i + 1, tsd_status(rg), have ? "" : "(none) ", have ? gv : 0.0);
        }
    }
out:
    tsd_cleanup();
    free(big);
    free(req);
    free(rt);
    free(rg);
}

#endif /* MDE_TSD_NET_H */
