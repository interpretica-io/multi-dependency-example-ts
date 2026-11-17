/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t12_go_idle, stalled clients of service-go (settles H2)
 *
 * Hypothesis H2: service-go keeps a stalled connection open with no
 * timeout (main.go:54).
 *
 * Sends: five TCP connections to the port of service-go (main.go:46-51);
 * three send nothing, two send half a request line ("GET /ring?val"
 * without the end of the line). All five are held for 35 s, then each
 * socket is checked: a read that would block means the server still holds
 * it, EOF or a reset means the server closed it. A normal request on a new
 * connection follows, to show that the service still answers.
 *
 * H2 CONFIRMED (fail) if any socket is still open after 35 s. H2 DISPROVED
 * (pass) if the server closed all five and still answers a normal request.
 * INCONCLUSIVE if service-go does not start or does not build (then H2 and
 * H3 are open for it), or if it does not answer the normal request after
 * the hold. Every outcome is appended to the tapi_cybersec_report with its
 * reason.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t12_go_idle"

#include "te_config.h"

#include <sys/resource.h>

#include "webdeps_lib.h"

#define IDLE_CONNS  5
#define HALF_FROM   3       /**< Connections from this index send half a line. */
#define HOLD_S      35      /**< s, how long the sockets are held. */
#define EARLY_S     6       /**< s, first look at the sockets. */
#define GOOD_S      5       /**< s, longest normal request. */

/** What a socket is doing, as seen by the client. */
typedef enum sock_state_t { S_OPEN, S_EOF, S_RESET } sock_state_t;

/** State names for the log. */
static const char * const state_name[] = {
    "open (a read blocks)", "closed by the server (EOF)",
    "closed by the server (reset)",
};

/**
 * Look at one socket without waiting: a read that would block is "open";
 * data is drained (a 408 reply may come before the close) and the look
 * repeated; EOF and errors mean the server closed it.
 */
static sock_state_t
sock_look(int fd)
{
    char buf[512];

    for (;;)
    {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        ssize_t       n;

        if (poll(&pfd, 1, 200) <= 0)
            return S_OPEN;
        n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n == 0)
            return S_EOF;
        if (n < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK ? S_OPEN : S_RESET;
    }
}

/** Look at every socket; returns how many are still open and fills @p text. */
static int
look_all(const int *fds, sock_state_t *st, char *text, size_t size)
{
    int i;
    int n_open = 0;

    text[0] = '\0';
    for (i = 0; i < IDLE_CONNS; i++)
    {
        if (st[i] == S_OPEN)
            st[i] = sock_look(fds[i]);
        if (st[i] == S_OPEN)
            n_open++;
        append(text, size, "#%d (%s) %s; ", i, i >= HALF_FROM ?
               "half request line" : "nothing sent", state_name[st[i]]);
    }
    return n_open;
}

int
main(int argc, char **argv)
{
    static const char half[] = "GET /ring?val";
    res_t         res = { .kind = R_PASS };
    struct rlimit rl = { 4096, 4096 };
    sock_state_t  st[IDLE_CONNS];
    int           fds[IDLE_CONNS];
    char          text[700];
    proc_t       *go;
    hg_res        good;
    int           opened = 0;
    int           n_open;
    int           i;

    TEST_START;
    for (i = 0; i < IDLE_CONNS; i++)
    {
        fds[i] = -1;
        st[i] = S_OPEN;
    }

    TEST_STEP("Start service-go and wait for its port");
    go = svc_start_t(&res, "H2", GO);
    if (go == NULL)
        goto verdict;
    RING("webdeps H2: service-go pid %d, port %u", (int)go->pid, go->port);
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        WARN("cannot raise the descriptor limit: %s", strerror(errno));

    TEST_STEP("Open %d connections: nothing, or half a request line",
              IDLE_CONNS);
    for (i = 0; i < IDLE_CONNS; i++)
    {
        fds[i] = connect_loop(go->port);
        if (fds[i] < 0)
            break;
        opened++;
        if (i >= HALF_FROM && write(fds[i], half, sizeof(half) - 1) < 0)
            WARN("cannot send the half line on connection %d: %s", i,
                 strerror(errno));
    }
    if (opened < IDLE_CONNS)
    {
        res_set(&res, R_INCONCLUSIVE, "service-go accepted only %d of %d "
                "connections (errno %d, %s), so the idle sockets were not "
                "all opened", opened, IDLE_CONNS, errno, strerror(errno));
        goto verdict;
    }

    TEST_STEP("Hold the sockets %d s and look at them at %d s and at %d s",
              HOLD_S, EARLY_S, HOLD_S);
    sleep(EARLY_S);
    n_open = look_all(fds, st, text, sizeof(text));
    RING("webdeps H2: after %d s, %d of %d sockets open: %s", EARLY_S, n_open,
         IDLE_CONNS, text);
    sleep(HOLD_S - EARLY_S);
    n_open = look_all(fds, st, text, sizeof(text));
    RING("webdeps H2: after %d s, %d of %d sockets open: %s", HOLD_S, n_open,
         IDLE_CONNS, text);
    T_FINDING(n_open > 0 ? TAPI_CYBERSEC_SEV_MEDIUM : TAPI_CYBERSEC_SEV_INFO,
              n_open > 0 ? "go.no-timeout" : "go.idle-closed", "service-go",
              "after %d s, %d of %d stalled sockets open: %s", HOLD_S, n_open,
              IDLE_CONNS, text);

    TEST_STEP("A normal request on a new connection, timeout %d s", GOOD_S);
    http_get(go->port, REQUEST, GOOD_S, &good);
    RING("webdeps H2: normal request %s, HTTP %d, %.2f s", hg_str(good.how),
         good.status, good.elapsed);
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "go.still-answers", "service-go",
              "normal request %s, HTTP %d, %.2f s", hg_str(good.how),
              good.status, good.elapsed);

    if (n_open > 0)
        res_set(&res, R_FAIL, "H2 CONFIRMED: %d of %d stalled sockets are "
                "still open after %d s, the server set no timeout: %s; a "
                "normal request was %s (HTTP %d)", n_open, IDLE_CONNS, HOLD_S,
                text, hg_str(good.how), good.status);
    else if (good.how != HG_OK || good.status < 200 || good.status >= 300)
        res_set(&res, R_INCONCLUSIVE, "the server closed all %d stalled "
                "sockets within %d s, but a normal request got no 2xx (%s, "
                "HTTP %d), so the service state is unknown: %s", IDLE_CONNS,
                HOLD_S, hg_str(good.how), good.status, text);
    else
        res_set(&res, R_PASS, "H2 DISPROVED: the server closed all %d "
                "stalled sockets within %d s (%s); a normal request on a new "
                "connection was answered, HTTP %d in %.2f s", IDLE_CONNS,
                HOLD_S, text, good.status, good.elapsed);

verdict:
    for (i = 0; i < IDLE_CONNS; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
