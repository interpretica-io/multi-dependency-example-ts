/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T2, idle clients of service-go (settles H2)
 *
 * A plain TCP/HTTP client. Open 50 connections to service-go and send
 * nothing on them. Wait 60 s, then count with tapi_netexpose the
 * established sockets the service still holds on its port (the client's own
 * view is recorded next to it). H2 FAIL if none of the 50 is closed. Then send one
 * valid request on a new connection with a 5 s limit: H2 FAIL if it times out. Otherwise H2
 * PASS. The counts and the time go in the verdict and in the
 * tapi_cybersec_report. A service-go that does not start, or a socket
 * table that cannot be read, is INCONCLUSIVE with the reason.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t2_slow_connections"

#include "te_config.h"

#include <sys/resource.h>

#include "webdeps_lib.h"

#define T2_CONNS    50
#define T2_IDLE_S   60      /**< s, idle wait. */
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

/** Established sockets of the service's port, from tapi_netexpose. */
static int
server_held(res_t *r, tsapi_mde_session *session, unsigned port)
{
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    te_vec               socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    int                  n = 0;

    opt.udp = false;
    opt.tcp = true;
    if (tapi_netexpose_sockets(session->factory, &opt, &socks) != 0)
    {
        setup_svc = "agent";
        res_set(r, R_INCONCLUSIVE, "tapi_netexpose cannot read the socket "
                "tables, so the held connections cannot be counted");
        te_vec_free(&socks);
        return -1;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        if (s->state == TAPI_NETEXPOSE_TCP_ESTABLISHED &&
            sock_port(&s->local) == port)
            n++;
    }
    te_vec_free(&socks);
    return n;
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    tsapi_mde_session session = { .ta = NULL };
    struct rlimit rl = { 4096, 4096 };
    int      client_held;
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
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        WARN("cannot raise the descriptor limit: %s", strerror(errno));
    if (tsapi_mde_session_init(&session, "t2_idle") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_INCONCLUSIVE, "no session on the agent to read the "
                "socket table");
        goto verdict;
    }

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
    client_held = count_open(fds, open_);
    held = server_held(&res, &session, go->port);
    if (held < 0)
        goto verdict;
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "go.idle-conns", "service-go",
              "connections opened %d, held by the server after %d s: %d "
              "(tapi_netexpose), %d (client view)", opened, T2_IDLE_S, held,
              client_held);
    if (held >= T2_CONNS)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.no-timeout", "service-go",
                  "all %d idle connections still open after %d s", held,
                  T2_IDLE_S);
        res_set(&res, R_FAIL, "H2 FAIL: service-go closed none of the %d idle "
                "connections in %d s, %d still open", T2_CONNS, T2_IDLE_S, held);
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
        res_set(&res, R_PASS, "H2 PASS: service-go closed %d of %d idle (%d still open) "
                "connections within %d s and answered the valid request "
                "with HTTP %d in %.2f s", opened - held, opened, held, T2_IDLE_S,
                good.status, good.elapsed);

verdict:
    tsapi_mde_session_fini(&session);
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
