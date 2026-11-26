/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_slow_peer, the TypeScript service ends a request
 *        cleanly when its peer is silent, slow or refuses (settles H3)
 *
 * The peer is a child of the test that binds port 0, reads the port from the
 * OS and logs every accepted connection with a monotonic time. The service
 * (service-ts) gets its own free port, a different one, chosen with port 0
 * too. RING_HOST and RING_PORT give the service its listen address and
 * SERVICE_TS_UPSTREAM gives it the peer. A valid request (value 42, 3 hops)
 * is sent, so input rejection cannot be the cause of an answer.
 *
 * Cases: (a) the peer accepts and never replies; (b) the peer refuses the
 * connection; (c) the peer replies after 20 s. For (a) and (c) the service
 * must answer or exit within 15 s with an error that names a timeout, and
 * the peer must have logged an accepted connection before the answer;
 * without one the reply came from input rejection and the case fails. For
 * (b) the error must name a refused connection. A stack trace or a leftover
 * process fails. The Go service timeout gap is an information line only.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_slow_peer"

#include "tsd.h"

#define LIMIT_MS        15000
#define SLOW_REPLY_MS   20000
#define LOOP            "127.0.0.1"
#define VALID_REQ       "GET /ring?value=42&hops=3 HTTP/1.0\r\nHost: t\r\n\r\n"
#define NOHOP_REQ       "GET /ring?value=42&hops=0 HTTP/1.0\r\nHost: t\r\n\r\n"

/** True when text holds a stack trace or an unhandled rejection. */
static bool
has_trace(const char *t)
{
    return strstr(t, "\n    at ") != NULL || strstr(t, "node:internal") != NULL ||
           strstr(t, "Unhandled") != NULL || strstr(t, "UNHANDLED") != NULL ||
           strstr(t, "Traceback") != NULL || strstr(t, "    at ") == t;
}

/** Case-insensitive substring. */
static bool
has_word(const char *text, const char *word)
{
    return strcasestr(text, word) != NULL;
}

/** The error text of a service names a timeout. */
static bool
names_timeout(const char *t)
{
    return has_word(t, "timed out") || has_word(t, "timeout") ||
           has_word(t, "ETIMEDOUT");
}

/** The error text of a service names a refused connection. */
static bool
names_refused(const char *t)
{
    return has_word(t, "refused");
}

/**
 * Child that binds port 0 on the loopback, writes its port to the parent,
 * appends "accepted <ms>" to @p plog for every connection and then keeps it
 * open. With @p reply_ms > 0 it answers a connection with a valid reply
 * after that many ms, otherwise it never replies.
 */
static pid_t
start_peer(unsigned *port, const char *plog, int reply_ms)
{
    int                fds[2];
    pid_t              pid;
    struct sockaddr_in sa = { .sin_family = AF_INET };
    socklen_t          l = sizeof(sa);

    *port = 0;
    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
    {
        int       ls = socket(AF_INET, SOCK_STREAM, 0);
        int       held[64];
        long long when[64];
        int       nheld = 0;
        unsigned  p;
        int       i;
        int       lf = open(plog, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND,
                            0644);

        setpgid(0, 0);
        inet_pton(AF_INET, LOOP, &sa.sin_addr);
        sa.sin_port = 0;
        if (ls < 0 || lf < 0 || bind(ls, (void *)&sa, sizeof(sa)) != 0 ||
            listen(ls, 16) != 0 || getsockname(ls, (void *)&sa, &l) != 0)
            _exit(1);
        p = ntohs(sa.sin_port);
        (void)!write(fds[1], &p, sizeof(p));
        close(fds[1]);
        for (;;)
        {
            struct pollfd pf = { .fd = ls, .events = POLLIN };

            if (poll(&pf, 1, 100) > 0 && nheld < 64)
            {
                int c = accept(ls, NULL, NULL);

                if (c >= 0)
                {
                    char line[64];

                    snprintf(line, sizeof(line), "accepted %lld\n",
                             tsd_ms());
                    (void)!write(lf, line, strlen(line));
                    held[nheld] = c;
                    when[nheld++] = tsd_ms();
                }
            }
            for (i = 0; i < nheld; i++)
            {
                if (held[i] >= 0 && reply_ms > 0 &&
                    tsd_ms() - when[i] >= reply_ms)
                {
                    static const char r[] = "HTTP/1.0 200 OK\r\n"
                        "Content-Type: text/plain\r\n\r\nvalue=1.0\n";

                    (void)!send(held[i], r, sizeof(r) - 1, MSG_NOSIGNAL);
                    close(held[i]);
                    held[i] = -1;
                }
            }
        }
    }
    close(fds[1]);
    if (read(fds[0], port, sizeof(*port)) != (ssize_t)sizeof(*port))
        *port = 0;
    close(fds[0]);
    return pid;
}

/** Number of "accepted" lines of the peer log, and the time of the first. */
static int
peer_seen(const char *plog, long long *first)
{
    char  buf[2000];
    char *p;
    int   n = 0;

    tsd_head(plog, buf, sizeof(buf));
    *first = -1;
    for (p = buf; (p = strstr(p, "accepted ")) != NULL; p += 9)
    {
        if (n++ == 0)
            *first = atoll(p + 9);
    }
    return n;
}

/** An ephemeral port from the OS that is neither @p a nor @p b. */
static unsigned
other_port(unsigned a, unsigned b)
{
    unsigned p;
    int      i;

    for (i = 0; i < 20; i++)
    {
        p = tsd_free_port();
        if (p != a && p != b)
            return p;
    }
    return p + 1;
}

/** End a started service: SIGTERM, then check nothing of its group is left. */
static void
finish_service(const char *name, pid_t pid)
{
    int code;

    if (tsd_alive(pid, NULL))
    {
        code = tsd_stop(pid, SIGTERM, 10);
        tsd_say("H3 %s: service stopped with SIGTERM, exit %d", name, code);
    }
    usleep(300000);
    if (kill(-pid, 0) == 0)
    {
        tsd_bad("H3", name, "a process of the service group %d is left "
                "behind", (int)pid);
        kill(-pid, SIGKILL);
    }
}

/**
 * One case. @p peer_mode: 0 silent, 1 refused, 2 slow. The service listens
 * on its own port, its upstream is the peer. A valid request is sent.
 */
static void
one_case(const char *name, const char *svc, int peer_mode)
{
    char        plog[96];
    char        slog[96];
    char        cmd[1024];
    char        reply[8192];
    char        text[1201];
    char        shown[401];
    unsigned    pport = 0;
    unsigned    own;
    pid_t       peer = -1;
    pid_t       pid;
    long long   t0;
    long long   t_answer;
    long long   t_first;
    int         seen;
    int         st = 0;
    ssize_t     n;
    bool        exited = false;
    bool        want_peer = peer_mode != 1;

    snprintf(plog, sizeof(plog), "/tmp/ts_sp_%s_peer.log", name);
    snprintf(slog, sizeof(slog), "/tmp/ts_sp_%s_svc.log", name);
    if (peer_mode == 1)
    {
        unlink(plog);
        pport = tsd_free_port();
        if (tsd_connect(pport) >= 0)
        {
            tsd_bad("H3", name, "control: port %u accepts, it is not a "
                    "refusing peer", pport);
            return;
        }
        tsd_say("H3 %s: the peer port %u refuses (control)", name, pport);
    }
    else
    {
        peer = start_peer(&pport, plog, peer_mode == 2 ? SLOW_REPLY_MS : 0);
        if (peer < 0 || pport == 0)
        {
            tsd_bad("H3", name, "the peer did not start");
            return;
        }
        tsd_say("H3 %s: peer bound port 0 and got port %u from the OS",
                name, pport);
    }
    own = other_port(pport, 0);
    tsd_say("H3 %s: service on its own port %u, peer port %u", name, own,
            pport);

    snprintf(cmd, sizeof(cmd), "RING_HOST=" LOOP " RING_PORT=%u "
             "SERVICE_TS_UPSTREAM=" LOOP ":%u exec '%s'", own, pport, svc);
    pid = tsd_spawn(tsd_src(), cmd, slog);
    if (!tsd_wait_port(own, 10))
    {
        tsd_head(slog, text, sizeof(text));
        tsd_clean(text, shown, sizeof(shown));
        tsd_bad("H3", name, "the service did not listen on port %u in 10 s: "
                "[%s]", own, shown);
        finish_service(name, pid);
        goto out;
    }

    if (want_peer)
    {
        /* Control: a request that needs no upstream must leave the peer log
         * empty, so an empty log means the peer was not reached. */
        n = tsd_exchange(own, NOHOP_REQ, sizeof(NOHOP_REQ) - 1, 5000, reply,
                         sizeof(reply));
        seen = peer_seen(plog, &t_first);
        if (n <= 0 || tsd_status(reply) != 200 || seen != 0)
        {
            tsd_bad("H3", name, "control: a request with hops=0 gave "
                    "status %d, peer saw %d connection(s) (want 200, 0)",
                    tsd_status(reply), seen);
            finish_service(name, pid);
            goto out;
        }
        tsd_say("H3 %s control: hops=0 answered 200, peer saw 0 connections",
                name);
    }

    t0 = tsd_ms();
    n = tsd_exchange(own, VALID_REQ, sizeof(VALID_REQ) - 1, LIMIT_MS, reply,
                     sizeof(reply));
    t_answer = tsd_ms();
    if (n <= 0 && !tsd_alive(pid, &st))
    {
        exited = true;
        tsd_head(slog, text, sizeof(text));
        tsd_say("H3 %s: the service exited with code %d after %lld ms: [%.300s]",
                name, tsd_code(st), t_answer - t0, text);
        snprintf(reply, sizeof(reply), "%s", text);
    }
    else if (n <= 0)
    {
        tsd_bad("H3", name, "no answer and no exit within %d s (read %zd): "
                "a hang", LIMIT_MS / 1000, n);
        finish_service(name, pid);
        goto out;
    }
    else
    {
        tsd_clean(tsd_body(reply), text, sizeof(text));
        tsd_say("H3 %s answered in %lld ms: status %d [%.300s]", name,
                t_answer - t0, tsd_status(reply), text);
    }
    if (t_answer - t0 > LIMIT_MS)
        tsd_bad("H3", name, "took %lld ms (limit %d)", t_answer - t0,
                LIMIT_MS);

    seen = peer_seen(plog, &t_first);
    if (want_peer)
    {
        if (seen < 1)
            tsd_bad("H3", name, "the peer saw no connection: the answer "
                    "came from input rejection, not from the peer timeout");
        else if (!exited && t_first > t_answer)
            tsd_bad("H3", name, "the peer logged its connection at %lld, "
                    "after the answer at %lld", t_first, t_answer);
        else
            tsd_say("H3 %s: the peer logged %d accepted connection(s), the "
                    "first at %lld ms, before the answer at %lld ms", name,
                    seen, t_first, t_answer);
    }
    if (!exited && tsd_status(reply) == 400)
        tsd_bad("H3", name, "status 400 on a valid request: input "
                "rejection, not the peer");
    if (has_trace(reply))
        tsd_bad("H3", name, "the answer holds a trace");
    if (peer_mode == 1)
    {
        if (!names_refused(reply))
            tsd_bad("H3", name, "the error does not name a refused "
                    "connection: [%.300s]", reply);
    }
    else if (!names_timeout(reply))
        tsd_bad("H3", name, "the error does not name a timeout: [%.300s]",
                reply);

    if (!tsd_alive(pid, &st))
    {
        int code = tsd_code(st);

        if (code > 128)
            tsd_bad("H3", name, "the service was killed by signal %d",
                    code - 128);
    }
    else
        finish_service(name, pid);
    tsd_head(slog, text, sizeof(text));
    if (has_trace(text))
    {
        tsd_clean(text, shown, sizeof(shown));
        tsd_bad("H3", name, "stack trace or unhandled rejection in the "
                "service output: [%s]", shown);
    }
    if (kill(-pid, 0) == 0)
    {
        tsd_bad("H3", name, "a process of the service group is left");
        kill(-pid, SIGKILL);
    }

out:
    if (peer > 0)
    {
        kill(peer, SIGKILL);
        waitpid(peer, NULL, 0);
        if (kill(peer, 0) == 0 || errno != ESRCH)
            tsd_bad("H3", name, "the peer process %d is left behind",
                    (int)peer);
    }
}

int
main(int argc, char **argv)
{
    const char *src = tsd_src();
    char        svc[PATH_MAX];
    char        path[PATH_MAX];
    char        reply[1024];
    char        text[401];
    unsigned    cport;
    unsigned    ownport;
    long long   first;
    pid_t       cpeer;
    pid_t       ringpid;
    char        cmd[1024];
    int         seen;

    TEST_START;
    signal(SIGPIPE, SIG_IGN);

    TEST_STEP("Control: the detectors see planted text");
    if (!has_trace("(node:1) UnhandledPromiseRejectionWarning: x\n") ||
        !has_trace("Error: x\n    at f (a.js:1:1)\n") ||
        has_trace("[service-ts] upstream unreachable: read timed out\n") ||
        !names_timeout("upstream unreachable: read timed out") ||
        !names_timeout("connect ETIMEDOUT") ||
        names_timeout("connect ECONNREFUSED 127.0.0.1:1") ||
        !names_refused("connect ECONNREFUSED 127.0.0.1:1") ||
        names_refused("read timed out"))
        TEST_FAIL("H3 NOT SETTLED: a detector is wrong");

    TEST_STEP("The project root and the build");
    if (src[0] == '\0' || access(src, X_OK) != 0)
        TEST_FAIL("H3 FAIL: TE_TS_MDE_SRC is [%s], not a directory", src);
    if (!tsd_have_main(path, sizeof(path)))
        TEST_FAIL("H3 blocked by H1: %s is missing, ./build.sh did not make "
                  "the TypeScript example", path);
    snprintf(svc, sizeof(svc), "%s/dist/bin/service-ts", src);
    if (access(svc, X_OK) != 0)
        TEST_FAIL("H3 FAIL: %s does not exist, build.sh did not make the "
                  "TypeScript service", svc);

    TEST_STEP("Control: the logging peer records a connection, the closed "
              "port refuses");
    cpeer = start_peer(&cport, "/tmp/ts_sp_ctl_peer.log", 0);
    if (cpeer < 0 || cport == 0)
        TEST_FAIL("H3 NOT SETTLED: the local peer did not start");
    {
        int fd = tsd_connect(cport);

        usleep(300000);
        seen = peer_seen("/tmp/ts_sp_ctl_peer.log", &first);
        if (fd < 0 || seen != 1)
            tsd_bad("H3", "control peer", "the peer logged %d connection(s) "
                    "for one connect (want 1)", seen);
        if (fd >= 0)
        {
            ssize_t n = tsd_exchange(cport, "GET / HTTP/1.0\r\n\r\n", 18,
                                     1000, reply, sizeof(reply));

            if (n != 0)
                tsd_bad("H3", "control peer", "the planted peer is not "
                        "silent");
            close(fd);
        }
    }
    kill(cpeer, SIGKILL);
    waitpid(cpeer, NULL, 0);
    if (tsd_connect(tsd_free_port()) >= 0)
        tsd_bad("H3", "control refused", "a free port is not closed");

    TEST_STEP("Control: the ring server of the example, own port, answers");
    ownport = tsd_free_port();
    snprintf(cmd, sizeof(cmd), "RING_HOST=" LOOP " RING_PORT=%u exec node "
             "dist/main.js", ownport);
    snprintf(path, sizeof(path), "%s/ts", src);
    ringpid = tsd_spawn(path, cmd, "/tmp/ts_sp_ring.log");
    if (!tsd_wait_port(ownport, 10))
        tsd_bad("H3", "ring server", "no listener on its own port %u",
                ownport);
    else if (tsd_exchange(ownport, VALID_REQ, sizeof(VALID_REQ) - 1, 5000,
                          reply, sizeof(reply)) <= 0 ||
             tsd_status(reply) != 200)
        tsd_bad("H3", "ring server", "no 200 for a valid request, status "
                "%d", tsd_status(reply));
    else
        tsd_say("H3 ring server (no upstream) answers 200 on its own port %u",
                ownport);
    tsd_stop(ringpid, SIGTERM, 10);
    if (kill(-ringpid, 0) == 0)
    {
        tsd_bad("H3", "ring server", "a process is left");
        kill(-ringpid, SIGKILL);
    }

    TEST_STEP("(a) the peer accepts and never replies");
    one_case("silent", svc, 0);
    TEST_STEP("(b) the peer refuses the connection");
    one_case("refused", svc, 1);
    TEST_STEP("(c) the peer replies after %d s", SLOW_REPLY_MS / 1000);
    one_case("slow", svc, 2);

    TEST_STEP("Information: the Go service timeout gap");
    snprintf(path, sizeof(path), "%s/web/service-go/main.go", src);
    tsd_sh(src, "grep -n 'Timeout' web/service-go/main.go | head -n 4", 10,
           "/tmp/ts_sp_go.log");
    tsd_head("/tmp/ts_sp_go.log", text, sizeof(text));
    tsd_say("H3 info only (not a check): the timeout lines of %s around "
            "main.go:54 (Go service timeout gap): [%s]", path, text);

    TSD_PASS("H3", "a silent, slow or refusing peer gives an answer within "
             "15 s naming a timeout or a refused connection, the peer saw "
             "the connection, no trace, no leftover process");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
