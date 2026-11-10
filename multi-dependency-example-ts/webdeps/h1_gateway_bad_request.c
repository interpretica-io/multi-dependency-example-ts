/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H1, bad requests to gateway-rs
 *
 * A plain TCP/HTTP client. Start gateway-rs and wait for its listen port.
 * The panic at main.rs:30 (upstream missing from the contract) and the
 * one at main.rs:34 (bind fails) both sit in main() before the accept
 * loop, so a request cannot reach them. The bad request path is probed
 * with an empty and a malformed request, and the input that does reach
 * main.rs:34 is a second gateway-rs started on the busy port. The
 * contract is compiled into the binary (include_str!), so no input at
 * run time reaches main.rs:30; the verdict says so.
 *
 * After each input the test checks by pid that gateway-rs is alive and
 * that a good request still gets a reply. H1 FAIL if the process exits
 * or the good request gets no reply (exit code recorded), H1 PASS
 * otherwise. Every client socket has its own timeout.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/h1_gateway_bad_request"

#include "te_config.h"

#include "webdeps_lib.h"

/** Check pid and a good request after an input; true when both are fine. */
static bool
survived(res_t *res, proc_t *gw, const char *what, char *seen, size_t size)
{
    hg_res h;
    char   code[32];
    char   last[300];
    bool   alive;
    double t0 = now_s();

    http_get(gw->port, REQUEST, PROBE_TO, &h);
    alive = pid_alive(gw);
    exit_code_str(gw, code, sizeof(code));
    last_line(gw->err, last, sizeof(last));
    append(seen, size, "%s: pid %d %s, good request %s (HTTP %d, %.2f s); ",
           what, (int)gw->pid, alive ? "alive" : "gone", hg_str(h.how),
           h.status, now_s() - t0);
    RING("webdeps: after %s: alive=%d, exit code %s, good request HTTP %d "
         "in %.2f s", what, alive, code, h.status, h.elapsed);
    if (alive && h.how == HG_OK)
        return true;
    if (!alive)
        gw->stopped = true;
    res_set(res, R_FAIL, "H1 FAIL: after %s gateway-rs %s and the good "
            "request %s; exit code %s; last stderr line [%s]", what,
            alive ? "is alive" : "exited", hg_str(h.how), code, last);
    return false;
}

int
main(int argc, char **argv)
{
    static const char empty_req[] = "\r\n\r\n";
    static const char malformed[] =
        "GET\r\n\xff\xfe /ring?value=%ff&hops=%00 HTTP/9\r\n\r\n";
    res_t    res = { .kind = R_PASS };
    res_t    scratch = { .kind = R_PASS };
    proc_t  *gw;
    proc_t  *second;
    char     path[512];
    char    *second_argv[] = { path, NULL };
    char     seen[900] = "";
    char     scode[32] = "n/a";
    char     slast[300] = "";
    bool     hit34 = false;

    TEST_START;

    TEST_STEP("Start gateway-rs and wait for its port");
    gw = svc_start_or_fail(&res, "H1", GW);
    if (gw == NULL)
        goto verdict;

    TEST_STEP("Empty request, then a good one");
    send_once(gw->port, empty_req, sizeof(empty_req) - 1, false, 500);
    if (!survived(&res, gw, "an empty request", seen, sizeof(seen)))
        goto verdict;

    TEST_STEP("Malformed request, then a good one");
    send_once(gw->port, malformed, sizeof(malformed) - 1, false, 500);
    if (!survived(&res, gw, "a malformed request", seen, sizeof(seen)))
        goto verdict;

    TEST_STEP("Second gateway-rs on the busy port (reaches main.rs:34)");
    snprintf(path, sizeof(path), "%s/dist/bin/gateway-rs", src_root);
    second = run_once(&scratch, "gateway-rs-second", path, second_argv, 5);
    if (second != NULL)
    {
        exit_code_str(second, scode, sizeof(scode));
        last_line(second->err, slast, sizeof(slast));
        hit34 = file_has(second->err, "main.rs:34");
        second->stopped = true;
    }
    if (!survived(&res, gw, "a second instance on the busy port", seen,
                  sizeof(seen)))
        goto verdict;

    res_set(&res, R_PASS, "H1 PASS: gateway-rs stayed alive and answered "
            "every good request; %s the second instance exited with code "
            "%s%s, last stderr line [%s]; main.rs:30 cannot be reached at "
            "run time (contract is compiled in); %s", hit34 ?
            "main.rs:34 was reached:" : "main.rs:34 was not seen:", scode,
            hit34 ? " at main.rs:34" : "", slast, seen);

verdict:
    HYP_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
