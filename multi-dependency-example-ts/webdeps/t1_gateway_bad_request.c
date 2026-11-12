/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T1, bad input to gateway-rs (settles H1)
 *
 * Start gateway-rs as a child process and send three bad inputs to its
 * listening port: an empty request, an oversized request, and a request
 * that names an upstream the contract does not have and the port the
 * gateway is bound to (the two conditions main.rs:30 and main.rs:34 test).
 * After each input wait up to 2 s and read the child's exit status. The
 * test fails, naming the input, when the child exits by panic (exit code
 * 101) or SIGABRT; it passes when the child stays up and answers a valid
 * request afterwards. A gateway that does not start is INCONCLUSIVE and
 * its stderr is printed.
 *
 * Both panic! calls sit in main() before the first request is read, so a
 * request cannot reach them. To record that, a second gateway is started
 * on the taken port after the three inputs and its exit status and stderr
 * are put in the report as information; that start-up panic is not the
 * child under test and does not change the verdict.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t1_gateway_bad_request"

#include "te_config.h"

#include "webdeps_lib.h"

#define BIG_HDR     70000
#define WAIT_S      2

/** The inputs, in the order they are sent. */
enum { IN_EMPTY, IN_OVERSIZED, IN_BRANCH, N_INPUTS };

static const char * const in_name[N_INPUTS] = {
    "the empty request", "the oversized request",
    "the request for the main.rs:30/34 branch",
};

/** Wait up to WAIT_S s for the child to exit; true when it is gone. */
static bool
exited_within(proc_t *gw)
{
    double end = now_s() + WAIT_S;

    do {
        if (proc_gone(gw))
            return true;
        usleep(100000);
    } while (now_s() < end);

    return proc_gone(gw);
}

/** Send one of the inputs. */
static void
send_input(unsigned port, int which)
{
    char    req[256];
    char   *big;
    size_t  n;

    switch (which)
    {
        case IN_EMPTY:
            send_once(port, "", 0, true, 300);
            break;

        case IN_OVERSIZED:
            big = malloc(BIG_HDR + 256);
            if (big == NULL)
                return;
            n = snprintf(big, 256, "GET /ring?value=1&hops=1 HTTP/1.1\r\n"
                         "Host: x\r\nX-Pad: ");
            memset(big + n, 'A', BIG_HDR);
            memcpy(big + n + BIG_HDR, "\r\n\r\n", 4);
            send_once(port, big, n + BIG_HDR + 4, false, 500);
            free(big);
            break;

        default:
            n = snprintf(req, sizeof(req),
                         "GET /ring?value=1&hops=1&upstream=no-such-service"
                         " HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                         "X-Upstream: no-such-service\r\n\r\n", port);
            send_once(port, req, n, false, 500);
            break;
    }
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *gw;
    proc_t  *second = NULL;
    hg_res   h;
    char     code[48] = "";
    char     last[300];
    char     seen[600] = "";
    char     gpath[512];
    char    *gargv[2] = { gpath, NULL };
    res_t    r2 = { .kind = R_PASS };
    int      i;

    TEST_START;

    TEST_STEP("Start gateway-rs and wait for its port");
    gw = svc_start_t(&res, "H1", GW);
    if (gw == NULL)
    {
        ERROR("gateway-rs did not start; its output is in the verdict");
        goto verdict;
    }

    for (i = 0; i < N_INPUTS; i++)
    {
        TEST_STEP("Send %s and read the exit status within %d s", in_name[i],
                  WAIT_S);
        send_input(gw->port, i);
        if (exited_within(gw))
        {
            int  st = gw->status;
            bool panic = (WIFEXITED(st) && WEXITSTATUS(st) == 101) ||
                         (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT);

            exit_code_str(gw, code, sizeof(code));
            last_line(gw->err, last, sizeof(last));
            gw->stopped = true;
            T_FINDING(panic ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_MEDIUM,
                      "gateway.exited", in_name[i], "exit status %s; last "
                      "stderr line [%s]", code, last);
            if (panic)
                res_set(&res, R_FAIL, "H1 FAIL: gateway-rs panicked after "
                        "%s: exit status %s; last stderr line [%s]",
                        in_name[i], code, last);
            else
                res_set(&res, R_FAIL, "H1 FAIL: gateway-rs exited after %s "
                        "(not a panic): exit status %s; last stderr line "
                        "[%s]", in_name[i], code, last);
            goto verdict;
        }
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.survived", in_name[i],
                  "still running %d s after the input", WAIT_S);
        append(seen, sizeof(seen), "%s: up; ", in_name[i]);
    }

    TEST_STEP("A valid request after the three inputs");
    http_get(gw->port, REQUEST, PROBE_TO, &h);
    if (proc_gone(gw) || h.how != HG_OK || h.status < 200 || h.status >= 300)
    {
        exit_code_str(gw, code, sizeof(code));
        last_line(gw->err, last, sizeof(last));
        res_set(&res, R_FAIL, "H1 FAIL: after the three bad inputs the valid "
                "request %s (HTTP %d); exit status %s; last stderr line [%s]",
                hg_str(h.how), h.status, code, last);
        goto verdict;
    }

    TEST_STEP("Record what a second gateway on the taken port does");
    TE_SPRINTF(gpath, "%s/dist/bin/gateway-rs", src_root);
    second = run_once(&r2, "gateway-rs-2", gpath, gargv, WAIT_S + 3);
    if (second == NULL)
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.second-instance",
                  "gateway-rs", "no exit seen: %s", r2.msg);
    else
    {
        exit_code_str(second, code, sizeof(code));
        last_line(second->err, last, sizeof(last));
        second->stopped = true;
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.second-instance",
                  "gateway-rs", "second instance on the taken port: exit "
                  "status %s; last stderr line [%s] (start-up only)", code,
                  last);
    }

    res_set(&res, R_PASS, "H1 PASS: gateway-rs (pid %d) stayed up %d s after "
            "each of the three bad inputs (%s) and answered the valid "
            "request with HTTP %d; the main.rs:30/34 panics are start-up "
            "only (second instance: %s)", (int)gw->pid, WAIT_S, seen,
            h.status, second == NULL ? "no exit seen" : code);

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
