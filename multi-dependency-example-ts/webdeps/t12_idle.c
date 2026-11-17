/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t12_idle, stalled clients of service-go (settles H2)
 *
 * Hypothesis H2: service-go keeps a stalled connection open with no
 * timeout (main.go:54).
 *
 * Sends and reads: service-go is started. Five TCP sockets are opened to
 * its port (main.go:46-51) and send nothing. Two more send half a request
 * line ("GET /ring?val") and are counted apart. All are held for 35 s.
 * Every 5 s each of the five idle sockets is read with a 1 s poll: EOF or a
 * reset means the server closed it, a poll that times out means it is
 * still open. During the hold, at 15 s, one valid request is sent on a new
 * connection and must get a reply.
 *
 * Verdicts (each starts with H2, all are logged, the last ends the test):
 *  - "H2 idle-closed-N-of-5": N of the five idle sockets were closed by
 *    the server at 35 s. N=0 means the server never closed an idle socket
 *    and H2 is true (the test fails). 0<N<5 fails too: a socket was held.
 *    N=5 passes and H2 is false.
 *  - "H2 service-responsive-during-idle" (pass) or
 *    "H2 service-blocked-during-idle" (fail): the valid request sent while
 *    the sockets were held got, or did not get, a reply.
 *  - "H2 setup-<step>-failed: ..." (fail): the step named did not work,
 *    nothing is settled.
 * Half-line sockets still open at 35 s are a finding in the
 * tapi_cybersec_report and fail the test as well. Every outcome is
 * appended to the report with its reason.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t12_idle"

#include "te_config.h"

#include <sys/resource.h>

#include "webdeps_lib.h"

#define IDLE_N      5       /**< Sockets that send nothing. */
#define IDLE_CONNS  7       /**< Those, then two that send half a line. */
#define HALF_FROM   IDLE_N  /**< Connections from this index send half a line. */
#define HOLD_S      35      /**< s, how long the sockets are held. */
#define LOOK_EVERY  5       /**< s, between two looks at the sockets. */
#define LOOK_POLL   1000    /**< ms, poll of one read. */
#define REQ_AT      15      /**< s into the hold, the valid request. */
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

        if (poll(&pfd, 1, LOOK_POLL) <= 0)
            return S_OPEN;
        n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n == 0)
            return S_EOF;
        if (n < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK ? S_OPEN : S_RESET;
    }
}

/**
 * Look at the sockets from @p from up to @p to (exclusive) that are still
 * open; returns how many of those are open and fills @p text.
 */
static int
look_range(const int *fds, sock_state_t *st, int from, int to, char *text,
           size_t size)
{
    int i;
    int n_open = 0;

    text[0] = '\0';
    for (i = from; i < to; i++)
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

/** H2: five idle sockets held 35 s, one valid request during the hold. */
int
main(int argc, char **argv)
{
    static const char half[] = "GET /ring?val";
    res_t         res = { .kind = R_PASS };
    struct rlimit rl = { 4096, 4096 };
    sock_state_t  st[IDLE_CONNS];
    int           fds[IDLE_CONNS];
    char          text[800];
    char          htext[400];
    proc_t       *go;
    hg_res        good = { .how = HG_REFUSED, .status = -1 };
    bool          requested = false;
    int           opened = 0;
    int           n_open = IDLE_N;
    int           h_open = 0;
    int           closed;
    int           i;
    double        t0;
    int           round;
    bool          responsive;

    TEST_START;
    for (i = 0; i < IDLE_CONNS; i++)
    {
        fds[i] = -1;
        st[i] = S_OPEN;
    }

    TEST_STEP("Start service-go and wait for its port");
    go = svc_start_t(&res, "H2", GO);
    if (go == NULL)
    {
        char orig[sizeof(res.msg)];

        snprintf(orig, sizeof(orig), "%s", res.msg);
        res_set(&res, R_SETUP, "H2 setup-start-service-go-failed: %.1400s",
                orig);
        goto verdict;
    }
    RING("webdeps H2: service-go pid %d, port %u", (int)go->pid, go->port);
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        WARN("cannot raise the descriptor limit: %s", strerror(errno));

    TEST_STEP("Open %d sockets that send nothing and %d that send half a "
              "request line", IDLE_N, IDLE_CONNS - IDLE_N);
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
        res_set(&res, R_SETUP, "H2 setup-open-sockets-failed: service-go "
                "accepted only %d of %d connections (errno %d, %s)", opened,
                IDLE_CONNS, errno, strerror(errno));
        goto verdict;
    }

    TEST_STEP("Hold %d s; every %d s read each idle socket with a %d ms "
              "poll; send one valid request at %d s", HOLD_S, LOOK_EVERY,
              LOOK_POLL, REQ_AT);
    t0 = now_s();
    for (round = 1; now_s() - t0 < HOLD_S; round++)
    {
        double at = t0 + round * LOOK_EVERY;

        if (at > now_s())
            usleep((useconds_t)((at - now_s()) * 1e6));
        n_open = look_range(fds, st, 0, IDLE_N, text, sizeof(text));
        RING("webdeps H2: at %.0f s, %d of %d idle sockets open: %s",
             now_s() - t0, n_open, IDLE_N, text);
        if (!requested && now_s() - t0 >= REQ_AT)
        {
            requested = true;
            http_get(go->port, REQUEST, GOOD_S, &good);
            RING("webdeps H2: valid request during the hold %s, HTTP %d, "
                 "%.2f s", hg_str(good.how), good.status, good.elapsed);
        }
    }
    if (!requested)
        http_get(go->port, REQUEST, GOOD_S, &good);
    h_open = look_range(fds, st, HALF_FROM, IDLE_CONNS, htext,
                        sizeof(htext));
    n_open = look_range(fds, st, 0, IDLE_N, text, sizeof(text));
    closed = IDLE_N - n_open;
    responsive = good.how == HG_OK;
    RING("webdeps H2: at the end, %d of %d idle sockets closed by the "
         "server: %s; half-line sockets open: %d: %s", closed, IDLE_N, text,
         h_open, htext);
    T_FINDING(n_open > 0 ? TAPI_CYBERSEC_SEV_MEDIUM : TAPI_CYBERSEC_SEV_INFO,
              n_open > 0 ? "go.no-timeout" : "go.idle-closed", "service-go",
              "after %d s, %d of %d idle sockets closed: %s", HOLD_S, closed,
              IDLE_N, text);
    T_FINDING(h_open > 0 ? TAPI_CYBERSEC_SEV_MEDIUM : TAPI_CYBERSEC_SEV_INFO,
              h_open > 0 ? "go.no-timeout-half-line" : "go.half-line-closed",
              "service-go", "after %d s, %d of %d half-line sockets open: %s",
              HOLD_S, h_open, IDLE_CONNS - IDLE_N, htext);
    T_FINDING(responsive ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
              responsive ? "go.responsive-during-idle" :
              "go.blocked-during-idle", "service-go",
              "valid request %s, HTTP %d, %.2f s", hg_str(good.how),
              good.status, good.elapsed);

    RING_VERDICT("H2 idle-closed-%d-of-%d", closed, IDLE_N);
    if (responsive)
        RING_VERDICT("H2 service-responsive-during-idle");
    else
        RING_VERDICT("H2 service-blocked-during-idle");

    if (closed < IDLE_N)
        res_set(&res, R_FAIL, "H2 idle-closed-%d-of-%d: %d idle sockets "
                "are still open after %d s, the server set no timeout "
                "(H2 %s): %s; valid request during the hold: %s (HTTP %d)"
                "%s", closed, IDLE_N, n_open, HOLD_S,
                closed == 0 ? "true" : "partly true", text,
                hg_str(good.how), good.status,
                responsive ? "; H2 service-responsive-during-idle" :
                "; H2 service-blocked-during-idle");
    else if (h_open > 0)
        res_set(&res, R_FAIL, "H2 idle-closed-%d-of-%d: the idle sockets "
                "were closed but %d half-line sockets are still open after "
                "%d s: %s", closed, IDLE_N, h_open, HOLD_S, htext);
    else if (!responsive)
        res_set(&res, R_FAIL, "H2 service-blocked-during-idle: H2 "
                "idle-closed-%d-of-%d, but a valid request during the hold "
                "got no reply (%s)", closed, IDLE_N, hg_str(good.how));
    else
        res_set(&res, R_PASS, "H2 idle-closed-%d-of-%d; H2 "
                "service-responsive-during-idle: the server closed all idle "
                "sockets within %d s (%s); the valid request was answered, "
                "HTTP %d in %.2f s", closed, IDLE_N, HOLD_S, text,
                good.status, good.elapsed);

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
