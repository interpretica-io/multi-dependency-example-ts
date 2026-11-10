/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H1, panics of gateway-rs
 *
 * Start gateway-rs (its port is read with tapi_netexpose) and send the
 * malformed requests that could reach the panics at main.rs:30 (upstream
 * missing from the contract) and main.rs:34 (bind fails). Both sit in
 * main() before the accept loop, so no request can reach them; the
 * inputs sent are the ones that take the request path furthest: no
 * request target, a non-UTF-8 request line, an unterminated 4 MiB line,
 * unparsable and extreme query values. After every request a valid one
 * goes to the same port. As a startup input, a second gateway-rs is
 * started on the busy port, which does reach main.rs:34.
 *
 * H1 FAIL if gateway-rs exits or a valid request gets no reply (exit code
 * and last stderr line recorded); H1 PASS if a request reached a panic
 * line and the process kept serving; H1 UNREACHED, with the inputs tried,
 * if no request reached either line. The verdict starts with the id.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/h1_gateway_panic"

#include "te_config.h"

#include "webdeps_lib.h"

#define BIG_LINE    (4u * 1024 * 1024)

/** A panic location of main.rs reached, according to the stderr log. */
static bool
panic_seen(const proc_t *gw)
{
    return file_has(gw->err, "main.rs:30") || file_has(gw->err, "main.rs:34");
}

int
main(int argc, char **argv)
{
    static const char no_target[] = "GET\r\n\r\n";
    static const char blank[] = "\r\n\r\n";
    static const char bad_utf8[] = "GET /ring\xff\xfe\xfd HTTP/1.1\r\n\r\n";
    static const char bad_query[] =
        "GET /ring?value=%ff&hops=%00 HTTP/1.1\r\nHost: x\r\n\r\n";
    static const char extreme[] =
        "GET /ring?value=NaN&hops=2147483647 HTTP/1.1\r\nHost: x\r\n\r\n";
    static const char negative[] =
        "GET /ring?value=1e999&hops=-2147483648 HTTP/1.1\r\n\r\n";
    struct {
        const char *name;
        const char *data;
        size_t      len;
    } reqs[] = {
        { "no request target", no_target, sizeof(no_target) - 1 },
        { "blank request", blank, sizeof(blank) - 1 },
        { "non-UTF-8 request line", bad_utf8, sizeof(bad_utf8) - 1 },
        { "unterminated 4 MiB request line", NULL, 0 },
        { "unparsable query values", bad_query, sizeof(bad_query) - 1 },
        { "NaN value, hops=INT_MAX", extreme, sizeof(extreme) - 1 },
        { "overflowing value, hops=INT_MIN", negative,
          sizeof(negative) - 1 },
    };
    res_t    res = { .kind = R_SETUP };
    res_t    scratch = { .kind = R_PASS };
    proc_t  *gw;
    proc_t  *second;
    tsapi_mde_session session = { .ta = NULL };
    char    *big = NULL;
    char     tried[900] = "";
    char     path[512];
    char    *second_argv[] = { path, NULL };
    char     code[32];
    char     last[300];
    char     second_info[500] = "no second instance run";
    bool     reached = false;
    unsigned i;

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start gateway-rs and read its port with tapi_netexpose");
    if (tsapi_mde_session_init(&session, "h1") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_netexpose");
        goto verdict;
    }
    gw = svc_start_exposed(&res, &session, GW);
    if (gw == NULL)
        goto verdict;

    big = malloc(BIG_LINE);
    if (big == NULL)
    {
        res_set(&res, R_SETUP, "no memory for the long request line");
        goto verdict;
    }
    memcpy(big, "GET /", 5);
    memset(big + 5, 'A', BIG_LINE - 5);
    reqs[3].data = big;
    reqs[3].len = BIG_LINE;

    for (i = 0; i < sizeof(reqs) / sizeof(reqs[0]); i++)
    {
        hg_res h;

        TEST_STEP("Send: %s; then a valid request", reqs[i].name);
        send_once(gw->port, reqs[i].data, reqs[i].len, false, 500);
        http_get(gw->port, REQUEST, PROBE_TO, &h);
        append(tried, sizeof(tried), "%s%s", i > 0 ? "; " : "",
               reqs[i].name);
        if (proc_gone(gw) || h.how != HG_OK)
        {
            bool gone = proc_gone(gw);

            exit_code_str(gw, code, sizeof(code));
            last_line(gw->err, last, sizeof(last));
            if (gone)
                gw->stopped = true;
            res_set(&res, R_FAIL, "H1 FAIL: after '%s' %s; exit code %s; "
                    "last stderr line [%s]; inputs so far: %s", reqs[i].name,
                    gone ? "gateway-rs exited" :
                    "the valid request got no reply while gateway-rs runs",
                    code, last, tried);
            goto verdict;
        }
        if (panic_seen(gw))
            reached = true;
        RING("webdeps: after '%s' the valid request got HTTP %d", reqs[i].name,
             h.status);
    }

    TEST_STEP("Startup input: a second gateway-rs on the busy port");
    snprintf(path, sizeof(path), "%s/dist/bin/gateway-rs", src_root);
    second = run_once(&scratch, "gateway-rs-second", path, second_argv, 5);
    if (second != NULL)
    {
        char scode[32];
        char slast[300];
        hg_res h;

        exit_code_str(second, scode, sizeof(scode));
        last_line(second->err, slast, sizeof(slast));
        snprintf(second_info, sizeof(second_info), "a second instance on the "
                 "busy port exited with code %s%s, last stderr line [%s]",
                 scode, file_has(second->err, "main.rs:34") ?
                 " at main.rs:34" : "", slast);
        second->stopped = true;
        http_get(gw->port, REQUEST, PROBE_TO, &h);
        if (proc_gone(gw) || h.how != HG_OK)
        {
            exit_code_str(gw, code, sizeof(code));
            last_line(gw->err, last, sizeof(last));
            res_set(&res, R_FAIL, "H1 FAIL: after the second instance (%s) "
                    "the first gateway-rs is gone or silent; exit code %s; "
                    "last stderr line [%s]", second_info, code, last);
            goto verdict;
        }
    }
    else
        snprintf(second_info, sizeof(second_info), "second instance: %s",
                 scratch.msg);

    if (reached)
        res_set(&res, R_PASS, "H1 PASS: a request reached a panic line of "
                "main.rs and gateway-rs kept serving (no exit code); "
                "inputs: %s; %s", tried, second_info);
    else
        res_set(&res, R_PASS, "H1 UNREACHED: no request reached main.rs:30 "
                "or main.rs:34 (startup code); gateway-rs stayed up (no "
                "exit code) and answered every valid request; inputs "
                "tried: %s; %s", tried, second_info);

verdict:
    free(big);
    tsapi_mde_session_fini(&session);
    HYP_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
