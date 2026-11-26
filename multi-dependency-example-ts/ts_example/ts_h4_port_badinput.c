/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h4_port_badinput, the TypeScript example listens
 *        only on the configured port and survives bad input (settles H4)
 *
 *  1. A free port is chosen and put in the configuration of the example
 *     (PORT, GUESS_PORT, LISTEN_PORT and GUESS_LISTEN, all the same port).
 *  2. The example is started; within 5 s tapi_netexpose must show that its
 *     process listens on that port and on no other.
 *  3. An empty request and malformed requests are sent. Each needs a 4xx
 *     reply (a zero-byte connection may also be closed without a reply),
 *     the process must still be alive, and every answer must come within
 *     5 s.
 * Known-bad controls: tapi_netexpose reports a planted listener on exactly
 * its port, a planted second listener is told apart as "another port", and
 * the reply classifier refuses 200, 500, empty and non-HTTP replies.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h4_port_badinput"

#include "te_config.h"

#include "tsh_lib.h"

#define ANSWER_S    5.0
#define START_S     5.0

/** One bad request. */
typedef struct bad_t {
    const char *name;
    const char *data;
    size_t      len;
    bool        fin;
    bool        silent_ok;  /**< A clean close without a reply is fine. */
} bad_t;

#define BAD(_n, _s, _fin, _ok) \
    { _n, _s, sizeof(_s) - 1, _fin, _ok }

static const bad_t bads[] = {
    BAD("zero bytes, then close", "", true, true),
    BAD("empty body POST", "POST /ring HTTP/1.1\r\nHost: x\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n", true, false),
    BAD("blank lines only", "\r\n\r\n", true, false),
    BAD("binary garbage", "\x00\xff\xfe\x80 \x01\r\n\r\n", true, false),
    BAD("bad percent escape", "GET /ring?value=%zz&hops=-1 HTTP/1.1\r\n"
        "Host: x\r\nConnection: close\r\n\r\n", true, false),
    BAD("bad protocol version", "GET /ring HTTP/9.9\r\nHost: x\r\n\r\n",
        true, false),
};

/** True when @p port is in @p ports[n] and nothing else is. */
static bool
only_port(const unsigned *ports, int n, unsigned port)
{
    int i;

    if (n < 1)
        return false;
    for (i = 0; i < n; i++)
    {
        if (ports[i] != port)
            return false;
    }
    return true;
}

int
main(int argc, char **argv)
{
    res_t             res = { .kind = R_PASS };
    tsapi_mde_session session = { .ta = NULL };
    bool              have_session = false;
    ts_peer_t         pa;
    bool              pa_up = false;
    char              tsdir[700];
    char              index[800];
    char              why[400];
    char              bd[1000] = "";
    unsigned          ports[TSH_MAX_PORTS];
    unsigned          total = 0;
    unsigned          port;
    pid_t             pid = 0;
    double            end;
    int               n = 0;
    size_t            i;

    TEST_START;
    t_report_begin();
    memset(&pa, 0, sizeof(pa));
    pa.lfd = -1;
    if (!tsx_init(&res, "H4"))
        goto verdict;

    TEST_STEP("Known-bad control: the reply classifier");
    if (!tsh_reply_control_ok(why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    TEST_STEP("Open a tapi_netexpose session on the agent");
    if (tsapi_mde_session_init(&session, "ts_h4_port_badinput") != 0)
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: no tapi_netexpose session "
                "on the agent, the listening ports cannot be checked");
        goto verdict;
    }
    have_session = true;

    TEST_STEP("Known-bad control: tapi_netexpose names the port of a "
              "planted listener and refuses a port it does not use");
    if (!ts_peer_start(&pa, workdir))
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: cannot start the planted "
                "listener");
        goto verdict;
    }
    pa_up = true;
    n = tsh_listen_ports("H4 control", &session, pa.pid, ports, &total);
    if (!only_port(ports, n, pa.port))
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: control failed: the planted "
                "listener on port %u was reported as %d port(s), first %u",
                pa.port, n, n > 0 ? ports[0] : 0);
        goto verdict;
    }
    if (only_port(ports, n, pa.port + 1))
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: control failed: a port the "
                "listener does not use was accepted");
        goto verdict;
    }
    ts_peer_stop(&pa);
    pa_up = false;

    TEST_STEP("Check that the TypeScript build exists");
    tsx_index_js(src_root, tsdir, sizeof(tsdir), index, sizeof(index));
    if (access(index, R_OK) != 0)
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: H1 build missing: %s does "
                "not exist, so there is no TypeScript example to start",
                index);
        goto verdict;
    }

    TEST_STEP("Start the example with another port in its configuration");
    port = tsh_free_port();
    if (port == 0)
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: no free port");
        goto verdict;
    }
    pid = fork();
    if (pid < 0)
    {
        res_set(&res, R_FAIL, "H4 NOT SETTLED: fork failed");
        goto verdict;
    }
    if (pid == 0)
    {
        char val[64];
        char ep[100];
        int  z = open("/dev/null", O_RDWR);
        char errp[200];
        int  e;

        setpgid(0, 0);
        snprintf(errp, sizeof(errp), "%s/h4.stderr", workdir);
        e = open(errp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(z, 0);
        dup2(z, 1);
        dup2(e, 2);
        snprintf(val, sizeof(val), "%u", port);
        snprintf(ep, sizeof(ep), "127.0.0.1:%u", port);
        setenv("PORT", val, 1);
        setenv("GUESS_PORT", val, 1);
        setenv("LISTEN_PORT", val, 1);
        setenv("GUESS_LISTEN", ep, 1);
        execlp("node", "node", index, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    RING("H4: started node %s with the port %u in PORT, GUESS_PORT, "
         "LISTEN_PORT and GUESS_LISTEN (pid %d)", index, port, (int)pid);

    TEST_STEP("tapi_netexpose: it listens on port %u and on no other", port);
    end = now_s() + START_S;
    n = 0;
    while (now_s() < end && tsh_alive(pid))
    {
        n = tsh_listen_ports("H4", &session, pid, ports, &total);
        if (n > 0 && port_accepts(port))
            break;
        usleep(250000);
    }
    if (!tsh_alive(pid))
    {
        char tail[300];
        char p[300];

        snprintf(p, sizeof(p), "%s/h4.stderr", workdir);
        file_tail(p, tail, sizeof(tail));
        res_set(&res, R_FAIL, "H4 FAIL: the example exited within %.0f s "
                "of the start with port %u configured; stderr [%s]",
                START_S, port, tail);
        goto verdict;
    }
    if (n <= 0)
        res_set(&res, R_FAIL, "H4 FAIL: the example holds %u socket(s) but "
                "listens on none; the configured port %u is not used",
                total, port);
    else if (!only_port(ports, n, port))
    {
        char l[200] = "";
        int  k;

        for (k = 0; k < n; k++)
            append(l, sizeof(l), "%u ", ports[k]);
        res_set(&res, R_FAIL, "H4 FAIL: the example listens on [%s] and "
                "not only on the configured port %u", l, port);
    }
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.listen", "configured port",
              "%d listening port(s), configured %u", n, port);
    if (res.kind != R_PASS)
        goto verdict;

    TEST_STEP("Send an empty and malformed requests; each within %.0f s",
              ANSWER_S);
    for (i = 0; i < sizeof(bads) / sizeof(bads[0]); i++)
    {
        tsh_xchg_t x;
        bool       ok;
        char       first[100];

        tsh_xchg(port, bads[i].data, bads[i].len, bads[i].fin, ANSWER_S, &x);
        ts_flat(x.data, 60, first, sizeof(first));
        RING("H4: %s: connected %d, %zu byte(s) in %.2f s, reset %d, "
             "timeout %d, first [%s], process alive %d", bads[i].name,
             x.connected, x.len, x.secs, x.reset, x.timeout, first,
             (int)tsh_alive(pid));
        ok = x.connected && !x.timeout && x.secs <= ANSWER_S &&
             (tsh_is_error_reply(x.data) ||
              (bads[i].silent_ok && x.len == 0 && !x.reset));
        if (!ok)
            append(bd, sizeof(bd), "%s: %s [%s]; ", bads[i].name,
                   !x.connected ? "no connection" : x.timeout ?
                   "no answer within the limit" : x.reset ?
                   "connection reset" : "not a 4xx reply", first);
        if (!tsh_alive(pid))
        {
            append(bd, sizeof(bd), "the process died after %s; ",
                   bads[i].name);
            break;
        }
    }
    if (bd[0] != '\0')
        res_set(&res, R_FAIL, "H4 FAIL: bad input: %s", bd);
    else if (!port_accepts(port))
        res_set(&res, R_FAIL, "H4 FAIL: the process is alive but port %u "
                "no longer accepts after the bad input", port);
    else
        res_set(&res, R_PASS, "H4 PASS: the example listens only on the "
                "configured port %u (tapi_netexpose) and answered %zu empty "
                "or malformed requests with a normal error within %.0f s "
                "each, still alive", port, sizeof(bads) / sizeof(bads[0]),
                ANSWER_S);
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.bad-input", "empty and malformed "
              "requests", "%s", res.msg);

verdict:
    if (pid > 0)
    {
        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    if (pa_up)
        ts_peer_stop(&pa);
    if (have_session)
        tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}
