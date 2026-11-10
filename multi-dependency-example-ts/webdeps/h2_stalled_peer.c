/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H2, a stalled peer of service-go
 *
 * Start service-go (its port is read with tapi_netexpose), open a TCP
 * connection, send half of a request (the request line and one header,
 * no blank line) and then send nothing. Measure the seconds until the
 * server closes the socket, up to 60 s.
 *
 * H2 FAIL if the server holds the socket for 30 s or more; H2 PASS if it
 * closes sooner. If the connect itself fails, the verdict is H2 NOSTART
 * with the errno, which tells a test error from a service fault.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/h2_stalled_peer"

#include "te_config.h"

#include "webdeps_lib.h"

#define H2_CAP_S    60      /**< s, longest wait for the close. */
#define H2_LIMIT_S  30      /**< s, holding the socket this long fails. */

int
main(int argc, char **argv)
{
    static const char half[] =
        "GET /ring?value=1&hops=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    res_t    res = { .kind = R_SETUP };
    proc_t  *go;
    tsapi_mde_session session = { .ta = NULL };
    struct sockaddr_in sa = { .sin_family = AF_INET };
    char     reply[256] = "";
    size_t   got = 0;
    double   t0;
    double   end;
    bool     closed = false;
    int      s = -1;
    int      err;

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start service-go and read its port with tapi_netexpose");
    if (tsapi_mde_session_init(&session, "h2") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_netexpose");
        goto verdict;
    }
    go = svc_start_exposed(&res, &session, GO);
    if (go == NULL)
    {
        char why[sizeof(res.msg)];

        /* The service never accepted a connection: say which errno. */
        errno = 0;
        s = connect_loop(tab_port[GO]);
        err = errno;
        snprintf(why, sizeof(why), "%s", res.msg);
        if (s >= 0)
        {
            close(s);
            res_set(&res, R_FAIL, "H2 NOSTART: service-go is not reachable "
                    "(%s); a late connect to 127.0.0.1:%u succeeded", why,
                    tab_port[GO]);
        }
        else
            res_set(&res, R_FAIL, "H2 NOSTART: service-go is not reachable "
                    "(%s); connect to 127.0.0.1:%u failed, errno %d (%s)",
                    why, tab_port[GO], err, strerror(err));
        s = -1;
        goto verdict;
    }

    TEST_STEP("Open a TCP connection to service-go");
    sa.sin_port = htons(go->port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    {
        err = errno;
        res_set(&res, R_FAIL, "H2 NOSTART: connect to 127.0.0.1:%u failed, "
                "errno %d (%s)", go->port, err, strerror(err));
        goto verdict;
    }

    TEST_STEP("Send half a request, then stop and wait for the close");
    if (write(s, half, sizeof(half) - 1) != (ssize_t)(sizeof(half) - 1))
    {
        err = errno;
        res_set(&res, R_FAIL, "H2 NOSTART: sending half a request failed, "
                "errno %d (%s)", err, strerror(err));
        goto verdict;
    }
    t0 = now_s();
    end = t0 + H2_CAP_S;
    while (!closed && now_s() < end)
    {
        struct pollfd pfd = { .fd = s, .events = POLLIN };
        char          buf[512];
        ssize_t       n;
        int           left_ms = (int)((end - now_s()) * 1000) + 1;

        if (poll(&pfd, 1, left_ms) <= 0)
            continue;
        n = read(s, buf, sizeof(buf));
        if (n <= 0)
        {
            closed = true;
            break;
        }
        if (got < sizeof(reply) - 1)
        {
            size_t c = sizeof(reply) - 1 - got;

            memcpy(reply + got, buf, (size_t)n < c ? (size_t)n : c);
            got += (size_t)n < c ? (size_t)n : c;
            reply[got] = '\0';
        }
    }
    {
        double held = now_s() - t0;
        char   first[80];

        snprintf(first, sizeof(first), "%.60s", reply);
        if (strchr(first, '\r') != NULL)
            *strchr(first, '\r') = '\0';
        RING("webdeps: service-go %s after %.1f s; reply before close [%s]",
             closed ? "closed the socket" : "still held the socket", held,
             first);
        if (!closed || held >= H2_LIMIT_S)
            res_set(&res, R_FAIL, "H2 FAIL: service-go held the stalled "
                    "socket for %.1f s (%s, limit %d s, cap %d s)", held,
                    closed ? "then closed it" : "not closed within the cap",
                    H2_LIMIT_S, H2_CAP_S);
        else
            res_set(&res, R_PASS, "H2 PASS: service-go closed the stalled "
                    "socket after %.1f s (limit %d s); reply before the "
                    "close [%s]", held, H2_LIMIT_S, first);
    }

verdict:
    if (s >= 0)
        close(s);
    tsapi_mde_session_fini(&session);
    HYP_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
