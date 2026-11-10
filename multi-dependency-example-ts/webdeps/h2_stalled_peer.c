/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H2, stalled peers of service-go
 *
 * A plain TCP/HTTP client. Start service-go and wait for its port. Open
 * 20 sockets, ten that send nothing and ten that send half a request,
 * then send a good request on a new connection and time the reply, and
 * measure for each stalled socket how long the server keeps it open, up
 * to 30 s.
 *
 * H2 FAIL if any stalled socket is still open after 30 s, or the good
 * request fails or takes more than 5 s. H2 PASS otherwise. The longest
 * hold time and the good request time are printed.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/h2_stalled_peer"

#include "te_config.h"

#include "webdeps_lib.h"

#define H2_SOCKS    20
#define H2_CAP_S    30      /**< s, longest wait for the close. */
#define H2_GOOD_S   5       /**< s, longest good reply. */

int
main(int argc, char **argv)
{
    static const char half[] =
        "GET /ring?value=1&hops=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    res_t    res = { .kind = R_PASS };
    proc_t  *go;
    hg_res   good;
    int      fds[H2_SOCKS];
    double   held[H2_SOCKS];
    bool     open_[H2_SOCKS];
    double   t0;
    double   maxhold = 0;
    int      still = 0;
    int      i;

    TEST_START;
    for (i = 0; i < H2_SOCKS; i++)
        fds[i] = -1;

    TEST_STEP("Start service-go and wait for its port");
    go = svc_start_or_fail(&res, "H2", GO);
    if (go == NULL)
        goto verdict;

    TEST_STEP("Open %d stalled sockets: silent and half a request", H2_SOCKS);
    t0 = now_s();
    for (i = 0; i < H2_SOCKS; i++)
    {
        fds[i] = connect_loop(go->port);
        if (fds[i] < 0)
        {
            res_set(&res, R_FAIL, "H2 FAIL: socket %d: connect to "
                    "127.0.0.1:%u failed, errno %d (%s)", i, go->port, errno,
                    strerror(errno));
            goto verdict;
        }
        open_[i] = true;
        held[i] = 0;
        if (i % 2 == 1 && write(fds[i], half, sizeof(half) - 1) < 0)
            WARN("webdeps: half request on socket %d: %s", i,
                 strerror(errno));
    }

    TEST_STEP("A good request while the sockets are stalled");
    http_get(go->port, REQUEST, H2_GOOD_S + 1, &good);
    RING("webdeps: good request HTTP %d, %s, %.2f s", good.status,
         hg_str(good.how), good.elapsed);

    TEST_STEP("Measure the hold time of each socket, up to %d s", H2_CAP_S);
    while (now_s() - t0 < H2_CAP_S)
    {
        struct pollfd pfds[H2_SOCKS];
        int           idx[H2_SOCKS];
        int           n = 0;

        for (i = 0; i < H2_SOCKS; i++)
        {
            if (!open_[i])
                continue;
            pfds[n] = (struct pollfd){ .fd = fds[i], .events = POLLIN };
            idx[n++] = i;
        }
        if (n == 0)
            break;
        if (poll(pfds, n, 200) <= 0)
            continue;
        for (i = 0; i < n; i++)
        {
            char buf[512];

            if (pfds[i].revents == 0)
                continue;
            if (read(pfds[i].fd, buf, sizeof(buf)) <= 0)
            {
                open_[idx[i]] = false;
                held[idx[i]] = now_s() - t0;
            }
        }
    }
    for (i = 0; i < H2_SOCKS; i++)
    {
        if (open_[i])
        {
            still++;
            held[i] = now_s() - t0;
        }
        if (held[i] > maxhold)
            maxhold = held[i];
    }

    if (still > 0)
        res_set(&res, R_FAIL, "H2 FAIL: service-go held %d of %d stalled "
                "sockets for the full %.1f s (limit %d s); good request "
                "HTTP %d in %.2f s", still, H2_SOCKS, maxhold, H2_CAP_S,
                good.status, good.elapsed);
    else if (good.how != HG_OK || good.status < 200 || good.status >= 300 ||
             good.elapsed > H2_GOOD_S)
        res_set(&res, R_FAIL, "H2 FAIL: the good request with %d stalled "
                "sockets open: %s, HTTP %d, %.2f s (limit %d s); longest "
                "hold %.1f s", H2_SOCKS, hg_str(good.how), good.status,
                good.elapsed, H2_GOOD_S, maxhold);
    else
        res_set(&res, R_PASS, "H2 PASS: service-go closed every stalled "
                "socket, longest hold %.1f s (limit %d s); good request "
                "HTTP %d in %.2f s", maxhold, H2_CAP_S, good.status,
                good.elapsed);

verdict:
    for (i = 0; i < H2_SOCKS; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }
    HYP_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
