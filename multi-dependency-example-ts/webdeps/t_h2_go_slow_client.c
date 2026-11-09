/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H2, idle connections held by service-go
 *
 * Start service-go and read its port with tapi_netexpose. Open ten
 * connections and send nothing on them; at the same time send one normal
 * request. H2 is proven (the test fails) if the normal request takes more
 * than 5 s or an idle connection is still open after 30 s.
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

#define IDLE_CONNS  10
#define IDLE_LIMIT  30      /**< s, an idle connection must be closed by then. */
#define NORMAL_LIMIT 5      /**< s, the normal request must be answered by then. */

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
    tsapi_mde_session session = { .ta = NULL };
    int      idle[IDLE_CONNS];
    bool     shut[IDLE_CONNS] = { false };
    unsigned opened = 0;
    unsigned open_left;
    unsigned i;
    double   t0;
    hg_res   h;
    char     detail[400];

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start service-go and read its port with tapi_netexpose");
    if (tsapi_mde_session_init(&session, "t_h2") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_netexpose");
        goto verdict;
    }
    go = svc_start_exposed(&res, &session, GO);
    if (go == NULL)
        goto verdict;

    TEST_STEP("Open %d idle connections and send nothing", IDLE_CONNS);
    for (i = 0; i < IDLE_CONNS; i++)
    {
        idle[i] = connect_loop(go->port);
        if (idle[i] >= 0)
            opened++;
    }
    if (opened < IDLE_CONNS)
    {
        res_set(&res, R_SETUP, "only %u of %d idle connections opened to "
                "127.0.0.1:%u", opened, IDLE_CONNS, go->port);
        goto close_idle;
    }

    TEST_STEP("Send one normal request while the connections are idle");
    http_get(go->port, REQUEST, NORMAL_LIMIT + 2, &h);
    if (proc_gone(go))
    {
        char why[900];

        proc_describe(go, why, sizeof(why));
        go->stopped = true;
        res_set(&res, R_SETUP, "service-go died during the test: %s", why);
        goto close_idle;
    }

    TEST_STEP("Wait up to %d s for the server to close the idle connections",
              IDLE_LIMIT);
    t0 = now_s();
    open_left = IDLE_CONNS;
    while (open_left > 0 && now_s() - t0 < IDLE_LIMIT)
    {
        for (i = 0; i < IDLE_CONNS; i++)
        {
            if (!shut[i] && closed_by_peer(idle[i], 100))
            {
                shut[i] = true;
                open_left--;
            }
        }
    }

    snprintf(detail, sizeof(detail), "normal request: %s, HTTP %d, %.2f s "
             "(limit %d s); idle connections still open after %.1f s: "
             "%u of %d", h.how == HG_OK ? "answered" : hg_str(h.how),
             h.status, h.elapsed, NORMAL_LIMIT, now_s() - t0, open_left,
             IDLE_CONNS);
    if (h.how != HG_OK || h.elapsed > NORMAL_LIMIT)
        res_set(&res, R_FAIL, "t_h2_go_slow_client H2:proven: service-go "
                "was slow to a normal request next to %d idle connections; "
                "%s", IDLE_CONNS, detail);
    else if (open_left > 0)
        res_set(&res, R_FAIL, "t_h2_go_slow_client H2:proven: service-go "
                "kept idle connections open past %d s; %s", IDLE_LIMIT,
                detail);
    else
        res_set(&res, R_PASS, "t_h2_go_slow_client H2:disproved: service-go "
                "answered in time and closed every idle connection; %s",
                detail);

close_idle:
    for (i = 0; i < IDLE_CONNS; i++)
    {
        if (idle[i] >= 0)
            close(idle[i]);
    }

verdict:
    tsapi_mde_session_fini(&session);
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}
