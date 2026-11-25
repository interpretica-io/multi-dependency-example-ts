/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: go_idle_connection, idle sockets to service-go
 *        (settles H2)
 *
 * Socket 1 is opened and nothing is sent; socket 2 gets the partial
 * request line "GET / HTTP/1.1" without the end of headers. Each is
 * polled with a non-blocking recv once per second for 35 s and the
 * second at which the server closes it is recorded.
 *
 * Verdicts (each starts with H2; never empty, never a skip):
 *  - "H2 CONFIRMED": the server keeps a socket open for the full 35 s;
 *    the test fails and logs the hold time;
 *  - "H2 REFUTED": both sockets closed earlier; passes, close times logged;
 *  - "H2 NOT SETTLED": the port does not open in 20 s or a harness step
 *    broke (the step is named); the test fails.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/go_idle_connection"

#include "te_config.h"

#include "webdeps_lib.h"

#define HOLD_MAX    35
#define POLL_S      5
#define N_EXTRA     200
#define NEW_REQ_S   2

/** True when the peer closed the connection (recv returns 0 or fails). */
static bool
closed_by_peer(int s)
{
    for (;;)
    {
        char    b[512];
        ssize_t n = recv(s, b, sizeof(b), MSG_DONTWAIT);

        if (n == 0)
            return true;
        if (n < 0)
            return errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK;
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
    char               ex[8] = "";
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
        snprintf(why, sizeof(why), "step prepare work dir broke: %.1100s", res.msg);
        skipped = true;
        goto verdict;
    }
    if (tsapi_mde_session_init(&session, "go_idle_connection") != 0)
    {
        snprintf(why, sizeof(why), "step open session broke: no session for "
                 "tapi_netexpose");
        skipped = true;
        goto verdict;
    }
    session_up = true;

    TEST_STEP("Start service-go and find its port with tapi_netexpose");
    go = svc_start_exposed(&res, &session, GO);
    if (go == NULL)
    {
        snprintf(why, sizeof(why), "step start service-go / port wait (20 s) broke: %.1100s", res.msg);
        skipped = true;
        goto verdict;
    }

    TEST_STEP("Open one silent connection and one with a partial line");
    for (i = 0; i < 2; i++)
    {
        fds[i] = connect_loop(go->port);
        if (fds[i] < 0)
        {
            snprintf(why, sizeof(why), "step open socket broke: connection %d to 127.0.0.1:%u "
                     "failed", i, go->port);
            skipped = true;
            goto verdict;
        }
    }
    if (write(fds[1], partial, sizeof(partial) - 1) < 0)
    {
        snprintf(why, sizeof(why), "step send partial line broke: %s",
                 strerror(errno));
        skipped = true;
        goto verdict;
    }

    TEST_STEP("Poll both for %d s, status every %d s", HOLD_MAX, POLL_S);
    t0 = now_s();
    next_status = POLL_S;
    while (now_s() - t0 < HOLD_MAX)
    {
        double el;

        usleep(1000000);
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

    if (proc_gone(go))
        proc_describe(go, state, sizeof(state));
    T_FINDING(held > 0 ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
              "go.hold-time", "service-go", "%s; %s", part[0], part[1]);

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
        res_set(&res, R_FAIL, "H2 NOT SETTLED: service-go: %.900s", why);
    else if (held == 2)
        res_set(&res, R_FAIL, "H2 CONFIRMED: the server holds both "
                "connections at %d s; %s; %s; %s%s",
                HOLD_MAX, part[0], part[1], ex, state);
    else if (held == 1)
        res_set(&res, R_FAIL, "H2 CONFIRMED for the %s connection, H2 "
                "REFUTED for the %s connection; %s; %s; %s%s", tclose[0] < 0 ? label[0] : label[1],
                tclose[0] < 0 ? label[1] : label[0], part[0], part[1], ex,
                state);
    else
        res_set(&res, R_PASS, "H2 REFUTED: the server closed both "
                "connections before %d s; %s; %s; %s%s",
                HOLD_MAX, part[0], part[1], ex, state);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
