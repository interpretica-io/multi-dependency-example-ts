/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H2, half-sent request held by service-go
 *
 * Start service-go, send a request without the final blank line, keep the
 * socket open and measure how long the server holds it (up to 60 s). H2 is
 * proven (the test fails) if it is still held at 60 s. Then 200 such sockets
 * are opened and a valid request on a new one is timed against 5 s.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t_h2_go_slow_client"

#include "te_config.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "te_sockaddr.h"
#include "tsapi_mde.h"

#include "webdeps_lib.h"

#define HOLD_LIMIT  60      /**< s, H2 limit for a half-sent request. */
#define FLOOD       200
#define FLOOD_TO    5       /**< s, valid request under the flood. */

static const char half_request[] = "GET / HTTP/1.1\r\nHost: x\r\n";

/** Connect and send the half request; -1 on failure. */
static int
half_open(unsigned port)
{
    int s = connect_loop(port);

    if (s >= 0 && write(s, half_request, sizeof(half_request) - 1) < 0)
    {
        close(s);
        return -1;
    }
    return s;
}

/** True if the server closed the socket (EOF or reset) by now. */
static bool
closed_by_peer(int s, int wait_ms)
{
    struct pollfd pfd = { .fd = s, .events = POLLIN };
    char          buf[1024];

    for (;;)
    {
        ssize_t n;

        if (poll(&pfd, 1, wait_ms) <= 0)
            return false;
        n = read(s, buf, sizeof(buf));
        if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN))
            return true;
        wait_ms = 0;
    }
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_SETUP };
    proc_t  *go;
    int      s;
    double   t0;
    double   held = 0;
    bool     closed = false;
    int      flood[FLOOD];
    unsigned opened = 0;
    unsigned i;
    hg_res   h;
    char     flood_txt[300];

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start service-go and wait for its port");
    go = svc_start(&res, GO);
    if (go == NULL)
        goto verdict;

    TEST_STEP("Send a half request and wait up to %d s for the close",
              HOLD_LIMIT);
    s = half_open(go->port);
    if (s < 0)
    {
        res_set(&res, R_SETUP, "cannot open and write to 127.0.0.1:%u",
                go->port);
        goto verdict;
    }
    t0 = now_s();
    while ((held = now_s() - t0) < HOLD_LIMIT)
    {
        if (closed_by_peer(s, 200))
        {
            closed = true;
            held = now_s() - t0;
            break;
        }
        if (proc_gone(go))
        {
            char why[900];

            proc_describe(go, why, sizeof(why));
            go->stopped = true;
            res_set(&res, R_SETUP, "service-go died during the wait: %s",
                    why);
            close(s);
            goto verdict;
        }
    }
    close(s);

    TEST_STEP("Open %d half-sent sockets, then send a valid request", FLOOD);
    for (i = 0; i < FLOOD; i++)
    {
        flood[i] = half_open(go->port);
        if (flood[i] >= 0)
            opened++;
    }
    http_get(go->port, REQUEST, FLOOD_TO, &h);
    snprintf(flood_txt, sizeof(flood_txt), "%u/%d half-sent sockets open, "
             "valid request on a new socket %s within %d s (%.2f s, "
             "HTTP %d)", opened, FLOOD, h.how == HG_OK ? "got a reply" :
             "got NO reply", FLOOD_TO, h.elapsed, h.status);
    for (i = 0; i < FLOOD; i++)
    {
        if (flood[i] >= 0)
            close(flood[i]);
    }

    if (!closed)
        res_set(&res, R_FAIL, "t_h2_go_slow_client H2:proven: service-go "
                "still held the half-sent request at %d s; %s", HOLD_LIMIT,
                flood_txt);
    else
        res_set(&res, R_PASS, "t_h2_go_slow_client H2:disproved: service-go "
                "closed the half-sent request after %.1f s; %s", held,
                flood_txt);

verdict:
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}
