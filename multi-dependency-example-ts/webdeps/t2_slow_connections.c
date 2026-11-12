/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T2, idle clients of service-go (settles H2)
 *
 * A plain TCP/HTTP client. Open 50 connections to service-go and send
 * nothing on them. Wait 30 s, then count the connections the service
 * still holds (a read that returns 0 or an error means the service closed
 * it). H2 FAIL if the service keeps all 50 open. Then send one valid
 * request: H2 FAIL if it gets no answer within 5 s. Otherwise H2 PASS.
 * The counts and the time go in the verdict and in the
 * tapi_cybersec_report. A service-go that does not start is NOT RUN.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t2_slow_connections"

#include "te_config.h"

#include "webdeps_lib.h"

#define T2_CONNS    50
#define T2_IDLE_S   30      /**< s, idle wait. */
#define T2_GOOD_S   5       /**< s, longest valid request. */

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
    int      held;
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

    TEST_STEP("Open %d connections and send nothing", T2_CONNS);
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
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.idle-conns", "service-go",
                  "only %d of %d connections accepted", opened, T2_CONNS);
        res_set(&res, R_FAIL, "H2 FAIL: service-go refused connection %d of "
                "%d, errno %d (%s)", opened + 1, T2_CONNS, errno,
                strerror(errno));
        goto verdict;
    }

    TEST_STEP("Wait %d s", T2_IDLE_S);
    sleep(T2_IDLE_S);
    held = count_open(fds, open_);
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "go.idle-conns", "service-go",
              "connections opened %d, still open after %d s: %d", opened,
              T2_IDLE_S, held);
    if (held >= T2_CONNS)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.no-timeout", "service-go",
                  "all %d idle connections still open after %d s", held,
                  T2_IDLE_S);
        res_set(&res, R_FAIL, "H2 FAIL: service-go kept all %d idle "
                "connections open for %d s", held, T2_IDLE_S);
        goto verdict;
    }

    TEST_STEP("A valid request after the idle wait");
    http_get(go->port, REQUEST, T2_GOOD_S, &good);
    RING("webdeps: valid request %s, HTTP %d, %.2f s, %d connections held",
         hg_str(good.how), good.status, good.elapsed, held);
    if (good.how != HG_OK || good.status < 200 || good.status >= 300 ||
        good.elapsed > T2_GOOD_S)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.no-answer", "service-go",
                  "valid request %s, HTTP %d, %.2f s (limit %d s)",
                  hg_str(good.how), good.status, good.elapsed, T2_GOOD_S);
        res_set(&res, R_FAIL, "H2 FAIL: after the idle wait the valid "
                "request %s, HTTP %d, %.2f s (limit %d s); %d of %d idle "
                "connections were still open", hg_str(good.how), good.status,
                good.elapsed, T2_GOOD_S, held, opened);
    }
    else
        res_set(&res, R_PASS, "H2 PASS: service-go closed %d of %d idle "
                "connections within %d s and answered the valid request "
                "with HTTP %d in %.2f s", opened - held, opened, T2_IDLE_S,
                good.status, good.elapsed);

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
