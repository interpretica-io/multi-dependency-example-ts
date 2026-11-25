/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: go_idle_connection, how long service-go holds idle and
 *        half-sent connections (settles H2)
 *
 * Hypothesis H2: service-go holds an idle client connection open with no
 * limit (main.go:54). The listen port comes from the service contract
 * table (the run script reads the same one).
 *
 * 20 TCP connections are opened: 10 send nothing, 10 send the partial
 * request line "GET / HTTP/1.1\r\n" and nothing more. All are kept for
 * 60 s; once per second each is polled for a close by the server (read
 * returns 0). Then a normal request on a new connection is timed (answer
 * within 2 s or not), recorded as extra data.
 *
 * Verdicts (each starts with H2):
 *  - "H2 FAIL (H2 confirmed)": 15 or more of the 20 are open after 60 s;
 *  - "H2 PASS (H2 disproved)": the server closed all 20 before 60 s;
 *  - "H2 NOT SETTLED": anything in between, counts printed (fails);
 *  - "H2 SETUP_FAILED": service-go did not start; reason printed.
 * Close time of each group is reported (first and last close, seconds).
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/go_idle_connection"

#include "te_config.h"

#include "webdeps_lib.h"

#define HOLD_MAX    60
#define N_PER_GROUP 10
#define N_CONN      (2 * N_PER_GROUP)
#define FAIL_OPEN   15
#define NEW_REQ_S   2

/** True when the peer closed the connection (read returns 0 or fails). */
static bool
closed_by_peer(int s)
{
    struct pollfd pfd = { .fd = s, .events = POLLIN };

    for (;;)
    {
        char    b[512];
        ssize_t n;

        if (poll(&pfd, 1, 0) <= 0)
            return false;
        n = read(s, b, sizeof(b));
        if (n == 0)
            return true;
        if (n < 0)
            return errno != EINTR && errno != EAGAIN;
        /* Data (an error reply) is drained; the close follows or not. */
    }
}

/** Text of the close times of one group. */
static void
group_text(const char *name, const double *t, int open_n, char *buf,
           size_t size)
{
    double first = -1;
    double last = -1;
    int    i;

    for (i = 0; i < N_PER_GROUP; i++)
    {
        if (t[i] < 0)
            continue;
        if (first < 0 || t[i] < first)
            first = t[i];
        if (t[i] > last)
            last = t[i];
    }
    if (first < 0)
        snprintf(buf, size, "%s: none closed, %d of %d open after %d s",
                 name, open_n, N_PER_GROUP, HOLD_MAX);
    else
        snprintf(buf, size, "%s: %d closed (first at %.0f s, last at "
                 "%.0f s), %d of %d open after %d s", name,
                 N_PER_GROUP - open_n, first, last, open_n, N_PER_GROUP,
                 HOLD_MAX);
}

int
main(int argc, char **argv)
{
    static const char partial[] = "GET / HTTP/1.1\r\n";
    res_t    res = { .kind = R_PASS };
    proc_t  *go;
    int      fds[N_CONN];
    double   tclose[N_CONN];
    int      open_g[2] = { 0, 0 };
    hg_res   h = { .how = HG_NORESP };
    char     gtext[2][220];
    char     extra[200] = "";
    char     state[200] = "service-go running";
    char     why[2200] = "";
    double   t0;
    int      i;
    int      sec;
    bool     setup_failed = false;

    TEST_START;
    t_report_begin();
    for (i = 0; i < N_CONN; i++)
    {
        fds[i] = -1;
        tclose[i] = -1;
    }
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        setup_failed = true;
        goto verdict;
    }
    TEST_STEP("Start service-go");
    go = svc_start(&res, GO);
    if (go == NULL)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        setup_failed = true;
        goto verdict;
    }

    TEST_STEP("Open %d connections: %d silent, %d with a partial line",
              N_CONN, N_PER_GROUP, N_PER_GROUP);
    for (i = 0; i < N_CONN; i++)
    {
        fds[i] = connect_loop(go->port);
        if (fds[i] < 0)
        {
            snprintf(why, sizeof(why), "connection %d to 127.0.0.1:%u "
                     "failed", i, go->port);
            setup_failed = true;
            goto verdict;
        }
        if (i >= N_PER_GROUP &&
            write(fds[i], partial, sizeof(partial) - 1) < 0)
            tclose[i] = 0;
    }

    TEST_STEP("Hold %d s, poll once per second", HOLD_MAX);
    t0 = now_s();
    for (sec = 1; sec <= HOLD_MAX; sec++)
    {
        double wait = t0 + sec - now_s();

        if (wait > 0)
            usleep((useconds_t)(wait * 1e6));
        for (i = 0; i < N_CONN; i++)
        {
            if (fds[i] >= 0 && tclose[i] < 0 && closed_by_peer(fds[i]))
                tclose[i] = now_s() - t0;
        }
    }
    for (i = 0; i < N_CONN; i++)
    {
        if (tclose[i] < 0)
            open_g[i / N_PER_GROUP]++;
    }
    group_text("silent", tclose, open_g[0], gtext[0], sizeof(gtext[0]));
    group_text("partial-request", tclose + N_PER_GROUP, open_g[1], gtext[1],
               sizeof(gtext[1]));
    RING("webdeps H2: %s", gtext[0]);
    RING("webdeps H2: %s", gtext[1]);

    TEST_STEP("Normal request on a new connection");
    http_get(go->port, REQUEST, NEW_REQ_S, &h);
    snprintf(extra, sizeof(extra), "new request %s within %d s (%.1f s)",
             h.how == HG_OK ? "answered" : "NOT answered", NEW_REQ_S,
             h.elapsed);
    RING("webdeps H2: %s", extra);
    if (proc_gone(go))
        proc_describe(go, state, sizeof(state));
    T_FINDING(open_g[0] + open_g[1] >= FAIL_OPEN ? TAPI_CYBERSEC_SEV_HIGH :
              TAPI_CYBERSEC_SEV_INFO, "go.hold-time", "service-go",
              "%s; %s; %s", gtext[0], gtext[1], extra);

verdict:
    for (i = 0; i < N_CONN; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }
    if (setup_failed)
        res_set(&res, R_SETUP, "H2 SETUP_FAILED: service-go: %.900s (no "
                "verdict on H2)", why);
    else if (open_g[0] + open_g[1] >= FAIL_OPEN)
        res_set(&res, R_FAIL, "H2 FAIL (H2 confirmed): %d of %d connections "
                "still open after %d s; %s; %s; %s (extra data); %s",
                open_g[0] + open_g[1], N_CONN, HOLD_MAX, gtext[0], gtext[1],
                extra, state);
    else if (open_g[0] + open_g[1] == 0)
        res_set(&res, R_PASS, "H2 PASS (H2 disproved): the server closed all "
                "%d connections before %d s; %s; %s; %s (extra data); %s",
                N_CONN, HOLD_MAX, gtext[0], gtext[1], extra, state);
    else
        res_set(&res, R_FAIL, "H2 NOT SETTLED: %d of %d connections open "
                "after %d s; %s; %s; %s (extra data); %s",
                open_g[0] + open_g[1], N_CONN, HOLD_MAX, gtext[0], gtext[1],
                extra, state);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
