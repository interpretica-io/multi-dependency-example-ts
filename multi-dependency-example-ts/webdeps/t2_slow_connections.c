/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T2, slow clients of service-go (settles H2)
 *
 * A plain TCP/HTTP client. Open 50 connections to service-go and send one
 * byte of a request header every 2 s on each. While they are open, send a
 * normal request. H2 FAIL if the normal request takes longer than 3 s or
 * is refused (or answered with a non-2xx status); H2 PASS otherwise. The
 * number of connections opened, and how many were still held when the
 * normal request was sent, go in the verdict and the tapi_cybersec_report.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t2_slow_connections"

#include "te_config.h"

#include "webdeps_lib.h"

#define T2_CONNS    50
#define T2_GOOD_S   3       /**< s, longest normal request. */
#define T2_ROUNDS   3       /**< One byte per connection every 2 s. */

static const char drip[] = "GET /ring?value=1&hops=1 HTTP/1.1\r\nHost: x\r\n";

/** Send the next byte on each connection that is still open. */
static int
drip_round(const int *fds, bool *open_, int round)
{
    int i;
    int sent = 0;

    for (i = 0; i < T2_CONNS; i++)
    {
        char c;

        if (!open_[i])
            continue;
        c = drip[round % (sizeof(drip) - 1)];
        if (write(fds[i], &c, 1) != 1)
            open_[i] = false;
        else
            sent++;
    }
    return sent;
}

/** Connections the peer has not closed (a read would not return 0). */
static int
count_open(const int *fds, bool *open_)
{
    int i;
    int n = 0;

    for (i = 0; i < T2_CONNS; i++)
    {
        struct pollfd pfd = { .fd = fds[i], .events = POLLIN };

        if (!open_[i])
            continue;
        if (poll(&pfd, 1, 0) > 0)
        {
            char c;

            if (recv(fds[i], &c, 1, MSG_PEEK | MSG_DONTWAIT) <= 0)
            {
                open_[i] = false;
                continue;
            }
        }
        n++;
    }
    return n;
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *go;
    hg_res   good;
    int      fds[T2_CONNS];
    bool     open_[T2_CONNS];
    int      opened = 0;
    int      held_at_request;
    int      held_end;
    int      round;
    int      i;

    TEST_START;
    for (i = 0; i < T2_CONNS; i++)
    {
        fds[i] = -1;
        open_[i] = false;
    }

    TEST_STEP("Start service-go and wait for its port");
    go = svc_start_t(&res, "H2", GO);
    if (go == NULL)
        goto verdict;

    TEST_STEP("Open %d connections and send the first byte on each", T2_CONNS);
    for (i = 0; i < T2_CONNS; i++)
    {
        fds[i] = connect_loop(go->port);
        if (fds[i] < 0)
            break;
        open_[i] = true;
        opened++;
    }
    if (opened < T2_CONNS)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.slow-conns", "service-go",
                  "only %d of %d connections accepted", opened, T2_CONNS);
        res_set(&res, R_FAIL, "H2 FAIL: service-go refused connection %d of "
                "%d, errno %d (%s)", opened + 1, T2_CONNS, errno,
                strerror(errno));
        goto verdict;
    }
    drip_round(fds, open_, 0);

    TEST_STEP("A normal request while the connections are open");
    sleep(1);
    held_at_request = count_open(fds, open_);
    http_get(go->port, REQUEST, T2_GOOD_S + 2, &good);
    RING("webdeps: normal request %s, HTTP %d, %.2f s, %d connections held",
         hg_str(good.how), good.status, good.elapsed, held_at_request);

    TEST_STEP("Keep sending one byte every 2 s");
    for (round = 1; round <= T2_ROUNDS; round++)
    {
        sleep(2);
        drip_round(fds, open_, round);
    }
    held_end = count_open(fds, open_);

    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "go.slow-conns", "service-go",
              "connections opened %d, held at the normal request %d, held "
              "after %d s %d", opened, held_at_request, 1 + 2 * T2_ROUNDS,
              held_end);
    if (good.how != HG_OK || good.status < 200 || good.status >= 300 ||
        good.elapsed > T2_GOOD_S)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.no-timeout", "service-go",
                  "normal request %s, HTTP %d, %.2f s (limit %d s) with %d "
                  "connections held", hg_str(good.how), good.status,
                  good.elapsed, T2_GOOD_S, held_at_request);
        res_set(&res, R_FAIL, "H2 FAIL: with %d connections opened and %d "
                "held the normal request %s, HTTP %d, %.2f s (limit %d s)",
                opened, held_at_request, hg_str(good.how), good.status,
                good.elapsed, T2_GOOD_S);
    }
    else
        res_set(&res, R_PASS, "H2 PASS: with %d connections opened and %d "
                "held the normal request got HTTP %d in %.2f s (limit %d "
                "s); %d still held after %d s", opened, held_at_request,
                good.status, good.elapsed, T2_GOOD_S, held_end,
                1 + 2 * T2_ROUNDS);

verdict:
    for (i = 0; i < T2_CONNS; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
