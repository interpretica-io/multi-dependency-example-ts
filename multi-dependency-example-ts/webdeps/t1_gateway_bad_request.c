/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T1, bad input to gateway-rs (settles H1)
 *
 * Start gateway-rs as a child process and send it two malformed requests:
 * one aimed at the branch of main.rs:30 (a request that names an upstream
 * the contract does not have) and one aimed at the branch of main.rs:34
 * (a request that is cut off mid-line and addressed to the port the
 * gateway itself is bound to). After each request the exit code of the
 * child ("still running" or the status) and whether a second, valid
 * request gets an answer are recorded in the tapi_cybersec_report and in
 * the verdict. The test fails when the process exits or aborts, or when
 * the valid request is not answered. A gateway that does not start is
 * INCONCLUSIVE and its stderr is printed.
 *
 * Both panic! calls sit in main() before the first request is read, so a
 * request cannot reach them. To record that, a second gateway is started
 * on the taken port after the two requests and its exit status and stderr
 * are put in the report as information; that start-up panic is not the
 * child under test and does not change the verdict.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t1_gateway_bad_request"

#include "te_config.h"

#include "webdeps_lib.h"

#define WAIT_S      2

/** The inputs, in the order they are sent. */
enum { IN_L30, IN_L34, N_INPUTS };

static const char * const in_name[N_INPUTS] = {
    "the malformed request for main.rs:30",
    "the malformed request for main.rs:34",
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
    size_t  n;

    if (which == IN_L30)
        n = snprintf(req, sizeof(req),
                     "GET /ring?value=1&hops=1&upstream=no-such-service"
                     " HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                     "X-Upstream: no-such-service\r\n\r\n", port);
    else
        n = snprintf(req, sizeof(req),
                     "GET /ring?value=%%00&hops=-1 HTTP/1.1\r\n"
                     "Host: 127.0.0.1:%u\r\nX-Bind: %u\r\n"
                     "Content-Length: 99999\r\n\r\nGE", port, port);
    send_once(port, req, n, which == IN_L34, 500);
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
    char     seen[700] = "";
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
        TEST_STEP("Send %s and read the exit code within %d s", in_name[i],
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
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.exited", in_name[i],
                      "exit code %s; last stderr line [%s]", code, last);
            res_set(&res, R_FAIL, "H1 FAIL: gateway-rs %s after %s: exit "
                    "code %s; last stderr line [%s]",
                    panic ? "panicked" : "exited", in_name[i], code, last);
            goto verdict;
        }

        TEST_STEP("A valid request after %s", in_name[i]);
        http_get(gw->port, REQUEST, PROBE_TO, &h);
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.survived", in_name[i],
                  "exit code: none (still running); second valid request "
                  "%s, HTTP %d", hg_str(h.how), h.status);
        RING("webdeps H1: after %s: exit code none, valid request %s, HTTP "
             "%d", in_name[i], hg_str(h.how), h.status);
        append(seen, sizeof(seen), "%s: exit code none, valid request %s "
               "(HTTP %d); ", in_name[i], hg_str(h.how), h.status);
        if (proc_gone(gw) || h.how != HG_OK || h.status < 200 ||
            h.status >= 300)
        {
            exit_code_str(gw, code, sizeof(code));
            last_line(gw->err, last, sizeof(last));
            res_set(&res, R_FAIL, "H1 FAIL: after %s the valid request %s "
                    "(HTTP %d); exit code %s; last stderr line [%s]",
                    in_name[i], hg_str(h.how), h.status, code, last);
            goto verdict;
        }
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
                  "code %s; last stderr line [%s] (start-up only)", code,
                  last);
    }

    res_set(&res, R_PASS, "H1 PASS: gateway-rs (pid %d) stayed up after both "
            "malformed requests and answered the valid request after each "
            "(%s); the main.rs:30/34 panics are start-up only (second "
            "instance: %s)", (int)gw->pid, seen,
            second == NULL ? "no exit seen" : code);

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
