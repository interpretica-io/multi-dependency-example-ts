/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_slow_peer, the TypeScript service copes with a peer
 *        that never answers or refuses (settles H3)
 *
 * Opens a local TCP listener on an ephemeral port. In the "silent" mode it
 * accepts and never replies; in the "refused" mode the port is closed. The
 * TypeScript web node (service-ts, upstream from SERVICE_TS_UPSTREAM) and
 * the TypeScript example (host and port from RING_HOST and RING_PORT) are
 * started with that host and port. Each must answer or exit with a clear
 * error within 15 s, print no stack trace or unhandled rejection, and leave
 * no process of its group behind. A hang, a trace or a leftover fails.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_slow_peer"

#include "tsd.h"

#define LIMIT_MS    15000

/** True when text holds a stack trace or an unhandled rejection. */
static bool
has_trace(const char *t)
{
    return strstr(t, "\n    at ") != NULL || strstr(t, "node:internal") != NULL ||
           strstr(t, "Unhandled") != NULL || strstr(t, "UNHANDLED") != NULL ||
           strstr(t, "Traceback") != NULL || strstr(t, "    at ") == t;
}

/** Child that accepts connections on an ephemeral port and never replies. */
static pid_t
start_silent_peer(unsigned *port)
{
    int                fds[2];
    pid_t              pid;
    struct sockaddr_in sa = { .sin_family = AF_INET };
    socklen_t          l = sizeof(sa);
    int                ls;

    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
    {
        unsigned p;

        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        ls = socket(AF_INET, SOCK_STREAM, 0);
        if (ls < 0 || bind(ls, (void *)&sa, sizeof(sa)) != 0 ||
            listen(ls, 16) != 0 || getsockname(ls, (void *)&sa, &l) != 0)
            _exit(1);
        p = ntohs(sa.sin_port);
        (void)!write(fds[1], &p, sizeof(p));
        close(fds[1]);
        for (;;)
        {
            int c = accept(ls, NULL, NULL);

            if (c < 0)
                _exit(0);       /* connections are held open, never read */
        }
    }
    close(fds[1]);
    if (read(fds[0], port, sizeof(*port)) != (ssize_t)sizeof(*port))
        *port = 0;
    close(fds[0]);
    return pid;
}

/**
 * One case: start @p cmd in @p cwd; when @p own is non-zero it is a server
 * on that port and gets a /ring request with hops, otherwise it must end by
 * itself. Fails the step on a hang, a trace or a leftover process.
 */
static void
one_case(const char *name, const char *cwd, const char *cmd, unsigned own)
{
    char      log[96];
    char      text[801];
    char      shown[401];
    char      reply[8192];
    pid_t     pid;
    long long t0 = tsd_ms();
    int       st = 0;
    int       code;
    bool      alive;

    snprintf(log, sizeof(log), "/tmp/ts_sp_%s.log", name);
    pid = tsd_spawn(cwd, cmd, log);
    if (own != 0)
    {
        long long end = t0 + 10000;

        while (tsd_ms() < end && tsd_alive(pid, &st) &&
               !tsd_wait_port(own, 1))
            ;
    }
    alive = tsd_alive(pid, &st);
    if (alive && own != 0)
    {
        ssize_t n = tsd_exchange(own, "GET /ring?value=42&hops=3 HTTP/1.0\r\n"
                                 "Host: peer\r\n\r\n", 60, LIMIT_MS, reply,
                                 sizeof(reply));

        if (n <= 0)
            tsd_bad("H3", name, "no answer in %d s (read %zd): a hang",
                    LIMIT_MS / 1000, n);
        else if (has_trace(reply))
            tsd_bad("H3", name, "the reply holds a trace: [%.300s]", reply);
        else
            tsd_say("H3 %s answered in %lld ms: status %d [%.160s]", name,
                    tsd_ms() - t0, tsd_status(reply), tsd_body(reply));
        alive = tsd_alive(pid, &st);
    }
    else if (alive)
    {
        /* must end by itself */
        while (tsd_ms() < t0 + LIMIT_MS && tsd_alive(pid, &st))
            usleep(100000);
        alive = tsd_alive(pid, &st);
        if (alive)
            tsd_bad("H3", name, "still running after %d s: a hang",
                    LIMIT_MS / 1000);
    }
    if (!alive)
    {
        code = tsd_code(st);
        tsd_head(log, text, sizeof(text));
        tsd_clean(text, shown, sizeof(shown));
        if (code > 128)
            tsd_bad("H3", name, "killed by signal %d: [%s]", code - 128,
                    shown);
        else
            tsd_say("H3 %s ended by itself with exit %d after %lld ms: [%s]",
                    name, code, tsd_ms() - t0, shown);
    }
    else
    {
        code = tsd_stop(pid, SIGTERM, 10);
        tsd_say("H3 %s stopped with SIGTERM: exit %d", name, code);
    }
    tsd_head(log, text, sizeof(text));
    tsd_clean(text, shown, sizeof(shown));
    if (has_trace(text))
        tsd_bad("H3", name, "stack trace or unhandled rejection in the "
                "output: [%s]", shown);
    usleep(300000);
    if (kill(-pid, 0) == 0)
    {
        tsd_bad("H3", name, "a process of the group %d is left behind",
                (int)pid);
        kill(-pid, SIGKILL);
    }
}

int
main(int argc, char **argv)
{
    const char *src = tsd_src();
    char        ts[PATH_MAX];
    char        path[PATH_MAX];
    char        cmd[PATH_MAX + 400];
    char        reply[256];
    unsigned    peer = 0;
    unsigned    closed;
    unsigned    own;
    pid_t       peerpid;
    int         mode;

    TEST_START;
    signal(SIGPIPE, SIG_IGN);

    TEST_STEP("Control: the trace detector sees a planted rejection");
    if (!has_trace("(node:1) UnhandledPromiseRejectionWarning: x\n") ||
        !has_trace("Error: x\n    at f (a.js:1:1)\n") ||
        has_trace("[example-ts] error: connect refused\n"))
        TEST_FAIL("H3 NOT SETTLED: the trace detector is wrong");

    TEST_STEP("The project root and the build");
    if (src[0] == '\0' || access(src, X_OK) != 0)
        TEST_FAIL("H3 FAIL: TE_TS_MDE_SRC is [%s], not a directory", src);
    if (!tsd_have_main(path, sizeof(path)))
        TEST_FAIL("H3 blocked by H1: %s is missing, ./build.sh did not make "
                  "the TypeScript example", path);
    snprintf(ts, sizeof(ts), "%s/ts", src);

    TEST_STEP("Open the silent peer on an ephemeral port");
    peerpid = start_silent_peer(&peer);
    if (peerpid < 0 || peer == 0)
        TEST_FAIL("H3 NOT SETTLED: the local listener did not start");
    tsd_say("H3 silent peer on port %u", peer);

    TEST_STEP("Control: the silent peer never replies, a closed port refuses");
    closed = tsd_free_port();
    if (tsd_exchange(peer, "GET / HTTP/1.0\r\n\r\n", 18, 1000, reply,
                     sizeof(reply)) != 0)
        tsd_bad("H3", "control silent", "the planted peer is not silent");
    if (tsd_connect(closed) >= 0)
        tsd_bad("H3", "control refused", "port %u is not closed", closed);

    for (mode = 0; mode < 2; mode++)
    {
        const char *mname = mode == 0 ? "silent" : "refused";
        unsigned    pp = mode == 0 ? peer : closed;
        char        nm[64];

        own = tsd_free_port();
        if (own == pp)
            own++;
        /* the web node, upstream is the peer */
        snprintf(path, sizeof(path), "%s/dist/bin/service-ts", src);
        TEST_STEP("service-ts with the %s peer as upstream", mname);
        if (access(path, X_OK) == 0)
        {
            snprintf(nm, sizeof(nm), "service_ts_%s", mname);
            snprintf(cmd, sizeof(cmd), "SERVICE_TS_HOST=127.0.0.1 "
                     "SERVICE_TS_PORT=%u SERVICE_TS_UPSTREAM=127.0.0.1:%u "
                     "exec '%s'", own, pp, path);
            one_case(nm, src, cmd, own);
        }
        else
            tsd_say("H3 %s: %s does not exist, case not run", mname, path);

        /* the example, host and port from RING_HOST and RING_PORT */
        TEST_STEP("node dist/main.js with RING_HOST and RING_PORT of the "
                  "%s peer", mname);
        snprintf(nm, sizeof(nm), "ring_%s", mname);
        snprintf(cmd, sizeof(cmd), "RING_HOST=127.0.0.1 RING_PORT=%u "
                 "EXAMPLE_HOST=127.0.0.1 EXAMPLE_PORT=%u "
                 "exec node dist/main.js", pp, pp);
        one_case(nm, ts, cmd, mode == 1 ? pp : 0);
    }

    kill(peerpid, SIGKILL);
    waitpid(peerpid, NULL, 0);
    TSD_PASS("H3", "a silent or refusing peer gives an answer or a clean "
             "exit, no trace and no leftover process");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
