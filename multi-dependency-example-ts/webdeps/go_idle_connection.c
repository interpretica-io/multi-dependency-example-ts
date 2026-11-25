/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: go_idle_connection, how long service-go holds an idle and
 *        a half-sent connection (settles H2)
 *
 * Hypothesis H2: service-go keeps an idle or slow connection open with no
 * time limit (main.go:54). service-go is started and its listen port is
 * found with tapi_netexpose.
 *
 * Connection A is opened and sends nothing. Connection B sends the
 * partial request line "GET / HTTP/1.1" without the final CRLF. Both are
 * polled for 60 s (a status line every 5 s; the close is noticed within
 * 0.25 s and its time printed in whole seconds, the number that
 * examples/idle_socket.ts prints for one connection). Then 200 more idle
 * connections are opened and a normal GET must be answered within 2 s;
 * this is extra evidence for H2.
 *
 * Verdicts (each starts with H2):
 *  - "H2 CONFIRMED": both connections still held at 60 s (hold time
 *    printed); the test fails;
 *  - "H2 REFUTED": the server closed both before 60 s (close times
 *    printed); the test passes. When only one is closed the verdict reads
 *    "H2 CONFIRMED for <held>; H2 REFUTED for <closed>" and the test fails;
 *  - "H2 SKIPPED": service-go cannot be started or its port not found;
 *    the reason is printed.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/go_idle_connection"

#include "te_config.h"

#include "webdeps_lib.h"

#define HOLD_MAX    60
#define POLL_S      5
#define N_EXTRA     200
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

int
main(int argc, char **argv)
{
    static const char * const label[2] = { "idle (nothing sent)",
                                           "partial request line" };
    static const char partial[] = "GET / HTTP/1.1";
    res_t              res = { .kind = R_PASS };
    tsapi_mde_session  session = { .ta = NULL };
    bool               session_up = false;
    proc_t            *go;
    int                fds[2] = { -1, -1 };
    int               *extra = NULL;
    double             tclose[2] = { -1, -1 };
    hg_res             h = { .how = HG_NORESP };
    char               ex[300] = "no extra check run";
    char               why[1200] = "";
    char               part[2][160];
    char               state[200] = "service-go running";
    double             t0;
    double             next_status;
    int                i;
    int                n_extra = 0;
    int                held = 0;
    bool               skipped = false;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        skipped = true;
        goto verdict;
    }
    if (tsapi_mde_session_init(&session, "go_idle_connection") != 0)
    {
        snprintf(why, sizeof(why), "no session on the agent for "
                 "tapi_netexpose");
        skipped = true;
        goto verdict;
    }
    session_up = true;

    TEST_STEP("Start service-go and find its port with tapi_netexpose");
    go = svc_start_exposed(&res, &session, GO);
    if (go == NULL)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        skipped = true;
        goto verdict;
    }

    TEST_STEP("Open one silent connection and one with a partial line");
    for (i = 0; i < 2; i++)
    {
        fds[i] = connect_loop(go->port);
        if (fds[i] < 0)
        {
            snprintf(why, sizeof(why), "connection %d to 127.0.0.1:%u "
                     "failed", i, go->port);
            skipped = true;
            goto verdict;
        }
    }
    if (write(fds[1], partial, sizeof(partial) - 1) < 0)
        tclose[1] = 0;

    TEST_STEP("Poll both for %d s, status every %d s", HOLD_MAX, POLL_S);
    t0 = now_s();
    next_status = POLL_S;
    while (now_s() - t0 < HOLD_MAX)
    {
        double el;

        usleep(250000);
        el = now_s() - t0;
        for (i = 0; i < 2; i++)
        {
            if (tclose[i] < 0 && closed_by_peer(fds[i]))
            {
                tclose[i] = el;
                RING("webdeps H2: %s closed by the server after %.0f s",
                     label[i], el);
            }
        }
        if (el >= next_status)
        {
            RING("webdeps H2: at %.0f s: %s %s, %s %s", el, label[0],
                 tclose[0] < 0 ? "open" : "closed", label[1],
                 tclose[1] < 0 ? "open" : "closed");
            next_status += POLL_S;
        }
        if (tclose[0] >= 0 && tclose[1] >= 0)
            break;
    }
    for (i = 0; i < 2; i++)
    {
        if (tclose[i] < 0)
        {
            held++;
            snprintf(part[i], sizeof(part[i]), "%s: still held at %d s "
                     "(hold time %.0f s)", label[i], HOLD_MAX,
                     now_s() - t0);
        }
        else
            snprintf(part[i], sizeof(part[i]), "%s: closed by the server "
                     "after %.0f s", label[i], tclose[i]);
    }

    TEST_STEP("Open %d idle connections, then one normal GET", N_EXTRA);
    extra = calloc(N_EXTRA, sizeof(*extra));
    if (extra == NULL)
    {
        snprintf(why, sizeof(why), "out of memory");
        skipped = true;
        goto verdict;
    }
    for (i = 0; i < N_EXTRA; i++)
    {
        extra[n_extra] = connect_loop(go->port);
        if (extra[n_extra] < 0)
            break;
        n_extra++;
    }
    http_get(go->port, REQUEST, NEW_REQ_S, &h);
    snprintf(ex, sizeof(ex), "%d idle connections open (of %d), a normal "
             "GET %s within %d s (%.1f s)", n_extra, N_EXTRA,
             h.how == HG_OK ? "was answered" : "was NOT answered", NEW_REQ_S,
             h.elapsed);
    RING("webdeps H2: %s", ex);
    if (proc_gone(go))
        proc_describe(go, state, sizeof(state));
    T_FINDING(held > 0 ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
              "go.hold-time", "service-go", "%s; %s; %s", part[0], part[1],
              ex);

verdict:
    for (i = 0; i < 2; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }
    for (i = 0; i < n_extra; i++)
        close(extra[i]);
    free(extra);
    if (session_up)
        tsapi_mde_session_fini(&session);
    if (skipped)
        res_set(&res, R_SKIP, "H2 SKIPPED: service-go: %.900s (no verdict "
                "on H2)", why);
    else if (held == 2)
        res_set(&res, R_FAIL, "H2 CONFIRMED: the server holds both "
                "connections at %d s; %s; %s; extra evidence: %s; %s",
                HOLD_MAX, part[0], part[1], ex, state);
    else if (held == 1)
        res_set(&res, R_FAIL, "H2 CONFIRMED for the %s connection, H2 "
                "REFUTED for the %s connection; %s; %s; extra evidence: "
                "%s; %s", tclose[0] < 0 ? label[0] : label[1],
                tclose[0] < 0 ? label[1] : label[0], part[0], part[1], ex,
                state);
    else
        res_set(&res, R_PASS, "H2 REFUTED: the server closed both "
                "connections before %d s; %s; %s; extra evidence: %s; %s",
                HOLD_MAX, part[0], part[1], ex, state);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
