/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: go_idle_connection, how long service-go holds a silent
 *        connection (settles H2)
 *
 * Hypothesis H2: service-go holds a connection open with no timeout
 * (main.go:54). The test needs nothing from the other tests of the group.
 *
 *  1. one idle connection, nothing sent: hold time, up to 60 s;
 *  2. one connection sending "GET / HTTP/1.1" one byte every 5 s and never
 *     the end of the headers: hold time, up to 60 s;
 *  3. 50 idle connections, then one normal request on a new connection:
 *     does it answer within 5 s.
 *
 * Verdicts (each starts with H2 and carries the hold times and the exit
 * state of the service):
 *  - "H2 CONFIRMED": a connection was still held at 60 s;
 *  - "H2 DISPROVED": both were closed by the server in under 30 s;
 *  - "H2 NOT SETTLED": both closed, one between 30 s and 60 s;
 *  - "H2 NOT RUN": service-go did not start, the reason is printed.
 * A blocked normal request with 50 idle connections is added as extra
 * evidence for H2.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/go_idle_connection"

#include "te_config.h"

#include "webdeps_lib.h"

#define HOLD_MAX    60
#define DISPROVE_S  30
#define TICK_S      5
#define N_IDLE      50

/** Outcome of one hold measurement. */
typedef struct hold_t {
    double  secs;
    bool    held;       /**< Still open at HOLD_MAX. */
} hold_t;

/** True when the peer closed (EOF or error); drains any reply. */
static bool
peer_closed(int s, int wait_ms)
{
    struct pollfd pfd = { .fd = s, .events = POLLIN };

    for (;;)
    {
        char    b[512];
        ssize_t n;

        if (poll(&pfd, 1, wait_ms) <= 0)
            return false;
        n = read(s, b, sizeof(b));
        if (n <= 0)
            return true;
        wait_ms = 0;
    }
}

/** Hold time of a connection that sends @p drip bytes one per tick. */
static hold_t
measure(unsigned port, bool drip)
{
    static const char  head[] = "GET / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    hold_t  h = { 0, true };
    int     s = connect_loop(port);
    double  t0 = now_s();
    size_t  sent = 0;

    if (s < 0)
    {
        h.held = false;
        return h;
    }
    while (now_s() - t0 < HOLD_MAX)
    {
        if (drip && sent < sizeof(head) - 1)
        {
            if (write(s, head + sent, 1) < 0)
            {
                h.held = false;
                break;
            }
            sent++;
        }
        if (peer_closed(s, TICK_S * 1000))
        {
            h.held = false;
            break;
        }
    }
    h.secs = now_s() - t0;
    if (h.held && h.secs > HOLD_MAX)
        h.secs = HOLD_MAX;
    close(s);
    return h;
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *go;
    hold_t   idle = { 0, false };
    hold_t   drip = { 0, false };
    int      fds[N_IDLE];
    int      n_open = 0;
    hg_res   h = { .how = HG_NORESP };
    char     state[200] = "service-go running";
    char     times[300] = "";
    char     extra[200] = "";
    char     why[500] = "";
    bool     blocked = false;
    bool     not_run = false;
    int      i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        not_run = true;
        goto verdict;
    }
    TEST_STEP("Start service-go");
    go = svc_start(&res, GO);
    if (go == NULL)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        not_run = true;
        goto verdict;
    }

    TEST_STEP("One idle connection, nothing sent, up to %d s", HOLD_MAX);
    idle = measure(go->port, false);
    RING("webdeps H2: idle connection %s after %.1f s",
         idle.held ? "still held" : "closed by the server", idle.secs);

    TEST_STEP("One connection, request line one byte per %d s, up to %d s",
              TICK_S, HOLD_MAX);
    drip = measure(go->port, true);
    RING("webdeps H2: slow connection %s after %.1f s",
         drip.held ? "still held" : "closed by the server", drip.secs);

    TEST_STEP("%d idle connections, then one normal request", N_IDLE);
    for (i = 0; i < N_IDLE; i++)
    {
        int s = connect_loop(go->port);

        if (s >= 0)
            fds[n_open++] = s;
    }
    http_get(go->port, REQUEST, 5, &h);
    blocked = h.how != HG_OK;
    RING("webdeps H2: with %d idle connections open the normal request %s "
         "(%.1f s)", n_open, hg_str(h.how), h.elapsed);
    for (i = 0; i < n_open; i++)
        close(fds[i]);

    if (proc_gone(go))
        proc_describe(go, state, sizeof(state));
    snprintf(times, sizeof(times), "idle connection %s %.0f s, slow "
             "connection %s %.0f s", idle.held ? "held to" : "closed at",
             idle.secs, drip.held ? "held to" : "closed at", drip.secs);
    snprintf(extra, sizeof(extra), "normal request with %d idle connections: "
             "%s in %.1f s", n_open, blocked ? "NOT answered" : "answered",
             h.elapsed);
    T_FINDING(idle.held || drip.held ? TAPI_CYBERSEC_SEV_HIGH :
              TAPI_CYBERSEC_SEV_INFO, "go.hold-time", "service-go", "%s; %s",
              times, extra);

verdict:
    if (not_run)
        res_set(&res, R_FAIL, "H2 NOT RUN: service-go did not start, no "
                "measurement and no exit code: %.600s", why);
    else if (idle.held || drip.held)
        res_set(&res, R_FAIL, "H2 CONFIRMED: service-go still held a "
                "connection at %d s; %s; %s%s; %s", HOLD_MAX, times, extra,
                blocked ? " (extra evidence for H2)" : "", state);
    else if (idle.secs < DISPROVE_S && drip.secs < DISPROVE_S)
        res_set(&res, R_PASS, "H2 DISPROVED: service-go closed both "
                "connections in under %d s; %s; %s; %s", DISPROVE_S, times,
                extra, state);
    else
        res_set(&res, R_FAIL, "H2 NOT SETTLED: both connections closed, but "
                "one only after %d s or more; %s; %s; %s", DISPROVE_S, times,
                extra, state);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
