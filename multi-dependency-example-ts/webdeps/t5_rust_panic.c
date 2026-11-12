/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t5_rust_panic, bad input to gateway-rs (settles H1)
 *
 * Start gateway-rs and send it malformed input aimed at the two panic!
 * calls of main.rs:30 and main.rs:34: an empty body (a connection that
 * sends nothing), an oversized header, an oversized request line and a
 * truncated request line. After each one the test checks that the process
 * is alive and that a new valid request is answered with a 2xx.
 *
 * H1 FAIL if the process exits or panics at any point: the verdict carries
 * the exit code and the tail of the stderr. H1 PASS if it survives all of
 * them and keeps answering. A gateway that does not start is H1
 * INCONCLUSIVE with its output.
 *
 * The port of the gateway is the one of the shared contract; the test
 * checks it is free before the start and reports it when it is not.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t5_rust_panic"

#include "te_config.h"

#include "webdeps_lib.h"

#define WAIT_S      2
#define BIG_HEADER  (256 * 1024)
#define BIG_LINE    (4 * 1024 * 1024)

enum { IN_EMPTY, IN_BIG_HEADER, IN_BIG_LINE, IN_TRUNCATED, N_INPUTS };

static const char * const in_name[N_INPUTS] = {
    "an empty body",
    "an oversized header",
    "an oversized request line",
    "a truncated request line",
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
    char    head[256];
    char   *big;
    size_t  n;

    switch (which)
    {
        case IN_EMPTY:
            send_once(port, "", 0, true, 500);
            break;

        case IN_TRUNCATED:
            send_once(port, "GET /ring?value=", 16, true, 500);
            break;

        case IN_BIG_HEADER:
            big = malloc(BIG_HEADER + 512);
            if (big == NULL)
                return;
            n = snprintf(big, 512, "GET /ring?value=1&hops=1 HTTP/1.1\r\n"
                         "Host: 127.0.0.1\r\nX-Big: ");
            memset(big + n, 'A', BIG_HEADER);
            n += BIG_HEADER;
            n += snprintf(big + n, 16, "\r\n\r\n");
            send_once(port, big, n, false, 500);
            free(big);
            break;

        default:
            big = malloc(BIG_LINE + 64);
            if (big == NULL)
                return;
            n = snprintf(head, sizeof(head), "GET /");
            memcpy(big, head, n);
            memset(big + n, 'B', BIG_LINE);
            n += BIG_LINE;
            send_once(port, big, n, true, 500);
            free(big);
            break;
    }
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *gw;
    hg_res   h;
    char     code[48];
    char     tail[400];
    char     seen[700] = "";
    int      i;

    TEST_START;

    TEST_STEP("Start gateway-rs and wait for its port");
    gw = svc_start_t(&res, "H1", GW);
    if (gw == NULL)
    {
        ERROR("gateway-rs did not start: %s", res.msg);
        goto verdict;
    }

    for (i = 0; i < N_INPUTS; i++)
    {
        TEST_STEP("Send %s and check the process within %d s", in_name[i],
                  WAIT_S);
        send_input(gw->port, i);
        if (exited_within(gw))
        {
            int  st = gw->status;
            bool panic = (WIFEXITED(st) && WEXITSTATUS(st) == 101) ||
                         (WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT);

            exit_code_str(gw, code, sizeof(code));
            file_tail(gw->err, tail, sizeof(tail));
            gw->stopped = true;
            ERROR("webdeps H1: gateway-rs gone after %s: exit code %s, "
                  "stderr tail [%s]", in_name[i], code, tail);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.exited", in_name[i],
                      "exit code %s; stderr tail [%s]", code, tail);
            res_set(&res, R_FAIL, "H1 FAIL: gateway-rs %s after %s: exit "
                    "code %s; stderr tail [%s]",
                    panic ? "panicked" : "exited", in_name[i], code, tail);
            goto verdict;
        }

        TEST_STEP("A new valid request after %s", in_name[i]);
        http_get(gw->port, REQUEST, PROBE_TO, &h);
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.survived", in_name[i],
                  "still running; a new valid request %s, HTTP %d",
                  hg_str(h.how), h.status);
        RING("webdeps H1: after %s: still running, new request %s, HTTP %d",
             in_name[i], hg_str(h.how), h.status);
        append(seen, sizeof(seen), "%s: alive, new request HTTP %d; ",
               in_name[i], h.status);
        if (proc_gone(gw) || h.how != HG_OK || h.status < 200 ||
            h.status >= 300)
        {
            exit_code_str(gw, code, sizeof(code));
            file_tail(gw->err, tail, sizeof(tail));
            ERROR("webdeps H1: after %s: exit code %s, stderr tail [%s]",
                  in_name[i], code, tail);
            res_set(&res, R_FAIL, "H1 FAIL: after %s the new valid request "
                    "%s (HTTP %d); exit code %s; stderr tail [%s]",
                    in_name[i], hg_str(h.how), h.status, code, tail);
            goto verdict;
        }
    }

    file_tail(gw->err, tail, sizeof(tail));
    res_set(&res, R_PASS, "H1 PASS: gateway-rs (pid %d) survived %d bad "
            "inputs and answered a new request after each (%s); stderr "
            "tail [%s]", (int)gw->pid, N_INPUTS, seen, tail);

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
