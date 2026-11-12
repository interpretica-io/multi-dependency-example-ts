/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T1, bad input to gateway-rs (settles H1)
 *
 * A plain TCP/HTTP client. Start gateway-rs, send a valid request and
 * expect a normal answer, then send an empty body, an oversized header
 * and several bad path values. After each input the valid request is
 * sent again. The process is identified by its pid and its start time
 * from /proc, so a restart is seen even when a supervisor brings it back
 * under the same pid.
 *
 * main.rs:30 (upstream missing from the contract) and main.rs:34 (bind
 * failure) panic only while main() starts, before any request is read, and
 * the request path has no panic! of its own. So the test records whether
 * a "panicked" line reached stderr and which of the two lines it named;
 * a request that did not reach them is recorded, never counted as a pass
 * for that code path.
 *
 * H1 FAIL if the process exits or restarts, or a valid request gets no
 * answer; H1 PASS if it answers every time. Every step is a finding in
 * the tapi_cybersec_report. A gateway-rs that does not start is NOT RUN.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t1_gateway_bad_request"

#include "te_config.h"

#include "webdeps_lib.h"

#define BIG_HDR     70000

typedef struct bad_input {
    const char *what;
    const char *raw;    /**< Request bytes; NULL: the oversized header. */
    size_t      len;
} bad_input;

#define BAD(_w, _s) { _w, _s, sizeof(_s) - 1 }

static const bad_input inputs[] = {
    BAD("an empty body", "\r\n\r\n"),
    { "an oversized header", NULL, 0 },
    BAD("path with percent-encoded junk",
        "GET /ring?value=%ff&hops=%00 HTTP/1.1\r\nHost: x\r\n\r\n"),
    BAD("path traversal", "GET /../../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"),
    BAD("path with a NUL and a bare LF",
        "GET /ring\0/x\n\n"),
    BAD("path without a leading slash", "GET ring HTTP/1.1\r\nHost: x\r\n\r\n"),
    BAD("unknown HTTP version", "GET\r\n\xff\xfe /ring HTTP/9\r\n\r\n"),
};

/** Valid request, then pid and start time; true when the gateway is fine. */
static bool
survived(res_t *res, proc_t *gw, unsigned long long start, const char *what,
         char *seen, size_t size)
{
    hg_res             h;
    char               code[32];
    char               last[300];
    bool               alive;
    unsigned long long now_start;
    bool               same;

    http_get(gw->port, REQUEST, PROBE_TO, &h);
    alive = pid_alive(gw);
    now_start = alive ? pid_starttime(gw->pid) : 0;
    same = alive && now_start == start;
    exit_code_str(gw, code, sizeof(code));
    last_line(gw->err, last, sizeof(last));
    append(seen, size, "%s: %s, HTTP %d; ", what, alive ? "alive" : "gone",
           h.status);
    RING("webdeps: after %s: alive=%d, same process=%d, exit code %s, valid "
         "request %s (HTTP %d, %.2f s)", what, alive, same, code,
         hg_str(h.how), h.status, h.elapsed);
    if (same && h.how == HG_OK && h.status >= 200 && h.status < 300)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.survived", "gateway-rs",
                  "after %s: pid %d, answered HTTP %d", what, (int)gw->pid,
                  h.status);
        return true;
    }
    if (!alive)
        gw->stopped = true;
    T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.died", "gateway-rs",
              "after %s: %s, valid request %s", what,
              !alive ? "process exited" : (!same ? "process restarted" :
                                           "process alive"), hg_str(h.how));
    res_set(res, R_FAIL, "H1 FAIL: after %s gateway-rs %s and the valid "
            "request %s (HTTP %d); exit code %s; last stderr line [%s]", what,
            !alive ? "exited" : (!same ? "restarted" : "is alive"),
            hg_str(h.how), h.status, code, last);
    return false;
}

int
main(int argc, char **argv)
{
    res_t              res = { .kind = R_PASS };
    proc_t            *gw;
    unsigned long long start;
    char               seen[900] = "";
    char              *big = NULL;
    size_t             i;
    bool               reached;

    TEST_START;

    TEST_STEP("Start gateway-rs and wait for its port");
    gw = svc_start_t(&res, "H1", GW);
    if (gw == NULL)
        goto verdict;
    start = pid_starttime(gw->pid);

    TEST_STEP("A valid request first");
    if (!survived(&res, gw, start, "the first valid request", seen,
                  sizeof(seen)))
        goto verdict;

    for (i = 0; i < TE_ARRAY_LEN(inputs); i++)
    {
        TEST_STEP("Send %s, then the valid request", inputs[i].what);
        if (inputs[i].raw != NULL)
        {
            send_once(gw->port, inputs[i].raw, inputs[i].len, false, 500);
        }
        else
        {
            size_t n = BIG_HDR + 128;

            big = malloc(n);
            if (big == NULL)
                TEST_FAIL("out of memory");
            n = snprintf(big, n, "GET /ring?value=1&hops=1 HTTP/1.1\r\n"
                         "Host: x\r\nX-Pad: ");
            memset(big + n, 'A', BIG_HDR);
            memcpy(big + n + BIG_HDR, "\r\n\r\n", 4);
            send_once(gw->port, big, n + BIG_HDR + 4, false, 500);
            free(big);
            big = NULL;
        }
        if (!survived(&res, gw, start, inputs[i].what, seen, sizeof(seen)))
            goto verdict;
    }

    reached = file_has(gw->err, "main.rs:30") ||
              file_has(gw->err, "main.rs:34");
    if (reached)
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.panic-site", "gateway-rs",
                  "stderr names main.rs:30 or main.rs:34");
    else
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.panic-site", "gateway-rs",
                  "no request reached main.rs:30 or main.rs:34; those "
                  "panics are start-up only, the code path is not tested "
                  "by this pass");
    res_set(&res, R_PASS, "H1 PASS: gateway-rs (pid %d) stayed the same "
            "process and answered the valid request after each of %zu bad "
            "inputs; %s; %s", (int)gw->pid, TE_ARRAY_LEN(inputs), seen,
            reached ? "stderr names main.rs:30/34" :
            "no request reached main.rs:30 or main.rs:34 (not a pass for "
            "that code path)");

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    free(big);
    cleanup_all();
    TEST_END;
}
