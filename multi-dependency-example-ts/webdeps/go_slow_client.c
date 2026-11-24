/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: go_slow_client, how long service-go keeps a slow
 *        connection open (settles H2)
 *
 * Hypothesis H2: service-go has no timeout, so a client that sends nothing,
 * or one byte per second, holds its connection for good (main.go:46-54).
 *
 * Steps: start service-go; open one socket that sends nothing and one that
 * sends the head of a request one byte per second; watch both for up to
 * 120 s and record when the server closes each. Then open 200 idle
 * connections and send a normal request, which must be answered within 5 s.
 *
 * Verdicts (every one starts with H2):
 *  - "H2 CONFIRMED held-120s" (fail): a connection stayed open the whole
 *    120 s; "H2 CONFIRMED service-blocked-by-200-idle" (fail): the normal
 *    request got no reply within 5 s with 200 idle connections open.
 *  - "H2 DISPROVED closed-at-Ns" (pass): both connections were closed
 *    earlier (the close times are logged) and the normal request was
 *    answered.
 *  - "H2 setup-<step>-failed: ..." (fail): nothing is settled.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/go_slow_client"

#include "te_config.h"

#include <sys/resource.h>

#include "webdeps_lib.h"

#define MAX_HOLD_S  120     /**< s, longest wait per connection. */
#define N_IDLE      200     /**< Idle connections of the second phase. */
#define GOOD_S      5       /**< s, longest normal request. */

static const char slow_head[] = "GET /ring?value=1&hops=1 HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\nX-Slow: aaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/** True once the peer has closed @p s (EOF or error); data is discarded. */
static bool
peer_closed(int s)
{
    struct pollfd pfd = { .fd = s, .events = POLLIN };
    char          buf[512];

    while (poll(&pfd, 1, 0) > 0)
    {
        ssize_t n = read(s, buf, sizeof(buf));

        if (n == 0)
            return true;
        if (n < 0)
            return errno != EINTR && errno != EAGAIN;
    }
    return false;
}

int
main(int argc, char **argv)
{
    res_t           res = { .kind = R_PASS };
    proc_t         *go;
    struct rlimit   rl;
    int             idle = -1;
    int             slow = -1;
    double          t0 = 0;
    double          idle_end = -1;
    double          slow_end = -1;
    size_t          sent = 0;
    int             many[N_IDLE];
    int             n_many = 0;
    int             i;
    hg_res          h;
    double          req_t = 0;
    char            idle_txt[80] = "";
    char            slow_txt[80] = "";
    bool            held = false;

    TEST_START;
    t_report_begin();
    for (i = 0; i < N_IDLE; i++)
        many[i] = -1;

    TEST_STEP("Start service-go");
    wd_init(&res);
    go = (res.kind == R_SETUP) ? NULL : svc_start(&res, GO);
    if (go == NULL)
    {
        char orig[sizeof(res.msg)];

        snprintf(orig, sizeof(orig), "%s", res.msg);
        res_set(&res, R_SETUP, "H2 setup-start-service-go-failed: %.1400s",
                orig);
        goto verdict;
    }
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < 1024)
    {
        rl.rlim_cur = rl.rlim_max < 1024 ? rl.rlim_max : 1024;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    TEST_STEP("Open an idle connection and a one-byte-per-second one; watch "
              "up to %d s", MAX_HOLD_S);
    idle = connect_loop(go->port);
    slow = connect_loop(go->port);
    if (idle < 0 || slow < 0)
    {
        res_set(&res, R_SETUP, "H2 setup-connect-failed: cannot connect to "
                "127.0.0.1:%u", go->port);
        goto verdict;
    }
    t0 = now_s();
    while (now_s() - t0 < MAX_HOLD_S && (idle_end < 0 || slow_end < 0))
    {
        double t = now_s() - t0;

        if (idle_end < 0 && peer_closed(idle))
        {
            idle_end = t;
            RING("webdeps H2: the idle connection was closed by the server "
                 "after %.1f s", t);
        }
        if (slow_end < 0)
        {
            if (peer_closed(slow))
            {
                slow_end = t;
                RING("webdeps H2: the slow connection was closed by the "
                     "server after %.1f s (%zu byte(s) sent)", t, sent);
            }
            else if (sent < sizeof(slow_head) - 1)
            {
                if (write(slow, slow_head + sent, 1) == 1)
                    sent++;
                else if (errno != EAGAIN && errno != EINTR)
                {
                    slow_end = t;
                    RING("webdeps H2: write to the slow connection failed "
                         "after %.1f s: %s", t, strerror(errno));
                }
            }
        }
        sleep(1);
    }
    if (idle_end >= 0)
        snprintf(idle_txt, sizeof(idle_txt), "closed at %.1fs", idle_end);
    else
        snprintf(idle_txt, sizeof(idle_txt), "held %d s", MAX_HOLD_S);
    if (slow_end >= 0)
        snprintf(slow_txt, sizeof(slow_txt), "closed at %.1fs", slow_end);
    else
        snprintf(slow_txt, sizeof(slow_txt), "held %d s", MAX_HOLD_S);
    held = idle_end < 0 || slow_end < 0;
    T_FINDING(idle_end < 0 ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
              "go.idle-connection", "service-go", "idle connection %s",
              idle_txt);
    T_FINDING(slow_end < 0 ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
              "go.slow-connection", "service-go",
              "one byte per second, %zu byte(s) sent: %s", sent, slow_txt);
    if (idle >= 0)
        close(idle);
    if (slow >= 0)
        close(slow);
    idle = slow = -1;

    TEST_STEP("Open %d idle connections and send a normal request", N_IDLE);
    for (i = 0; i < N_IDLE; i++)
    {
        many[i] = connect_loop(go->port);
        if (many[i] >= 0)
            n_many++;
    }
    RING("webdeps H2: %d of %d idle connections open", n_many, N_IDLE);
    req_t = now_s();
    http_get(go->port, REQUEST, GOOD_S, &h);
    req_t = now_s() - req_t;
    RING("webdeps H2: normal request with %d idle connections: %s, HTTP %d, "
         "%.2f s", n_many, hg_str(h.how), h.status, req_t);
    T_FINDING(h.how != HG_OK ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
              "go.exhaustion", "service-go", "%d idle connections; normal "
              "request %s, HTTP %d, %.2f s", n_many, hg_str(h.how), h.status,
              req_t);

    if (held || h.how != HG_OK || req_t > GOOD_S)
    {
        if (held)
            res_set(&res, R_FAIL, "H2 CONFIRMED held-%ds: service-go kept a "
                    "connection open for the whole %d s (idle: %s; one byte "
                    "per second: %s)%s", MAX_HOLD_S, MAX_HOLD_S, idle_txt,
                    slow_txt, h.how != HG_OK ? "; the normal request with "
                    "200 idle connections also failed" : "");
        else
            res_set(&res, R_FAIL, "H2 CONFIRMED service-blocked-by-%d-idle: "
                    "with %d idle connections the normal request got %s "
                    "(HTTP %d) in %.2f s, limit %d s (idle: %s; slow: %s)",
                    N_IDLE, n_many, hg_str(h.how), h.status, req_t, GOOD_S,
                    idle_txt, slow_txt);
    }
    else
        res_set(&res, R_PASS, "H2 DISPROVED closed-at-%.0fs: service-go "
                "closed the idle connection (%s) and the slow one (%s) "
                "before %d s, and answered a normal request in %.2f s with "
                "%d idle connections open", slow_end > idle_end ? slow_end :
                idle_end, idle_txt, slow_txt, MAX_HOLD_S, req_t, n_many);

verdict:
    for (i = 0; i < N_IDLE; i++)
        if (many[i] >= 0)
            close(many[i]);
    if (idle >= 0)
        close(idle);
    if (slow >= 0)
        close(slow);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
