/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H3, the swallowed error in service-cs
 *
 * A plain TCP/HTTP client with its own client timeouts.
 *
 * Program.cs:85 catches HttpRequestException and TaskCanceledException
 * around the GET to the upstream gateway-rs and turns them into "no
 * result". The only input that makes the code throw inside that try block
 * is a request with a hop budget above zero while gateway-rs is not
 * listening: the connect is refused. Start service-cs alone (its port is
 * listening), send that bad input (hops=3), and as a
 * control a valid one (hops=0, which never calls the upstream). A request
 * with an unparsable value is sent as well and only recorded.
 *
 * H3 FAIL if the bad input returns HTTP 200; H3 PASS if it returns 4xx or
 * 5xx. Both status codes and the body of the bad one are in the verdict.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/h3_csharp_bad_input"

#include "te_config.h"

#include "webdeps_lib.h"

#define BAD_REQUEST     "/ring?value=1&hops=3"
#define CONTROL_REQUEST "/ring?value=1&hops=0"
#define PARSE_REQUEST   "/ring?value=not-a-number&hops=3"

/** Body of a response as one short line. */
static void
flat(const char *body, char *out, size_t size)
{
    const char *p = strstr(body, "\r\n\r\n");
    size_t      i;

    snprintf(out, size, "%s", p != NULL ? p + 4 : body);
    for (i = 0; out[i] != '\0'; i++)
    {
        if (out[i] == '\n' || out[i] == '\r')
            out[i] = '|';
    }
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *cs;
    hg_res   control;
    hg_res   bad;
    hg_res   parse;
    char     body[400];
    char     cbody[200];
    char     pbody[200];

    TEST_START;

    TEST_STEP("Start service-cs alone and wait for its port");
    cs = svc_start_or_fail(&res, "H3", CS);
    if (cs == NULL)
        goto verdict;

    TEST_STEP("Control: a valid input, %s", CONTROL_REQUEST);
    http_get(cs->port, CONTROL_REQUEST, PROBE_TO + 2, &control);
    flat(control.body, cbody, sizeof(cbody));

    TEST_STEP("Bad input: %s, gateway-rs is down so the upstream GET throws",
              BAD_REQUEST);
    http_get(cs->port, BAD_REQUEST, PROBE_TO + 2, &bad);
    flat(bad.body, body, sizeof(body));

    TEST_STEP("Record an unparsable value: %s", PARSE_REQUEST);
    http_get(cs->port, PARSE_REQUEST, PROBE_TO + 2, &parse);
    flat(parse.body, pbody, sizeof(pbody));

    RING("webdeps: service-cs control HTTP %d [%s] in %.2f s; bad input HTTP %d [%s] in "
         "%.2f s; unparsable value HTTP %d [%s]", control.status, cbody,
         control.elapsed, bad.status, body, bad.elapsed, parse.status,
         pbody);

    if (control.how != HG_OK || bad.how != HG_OK)
    {
        res_set(&res, R_FAIL, "H3 FAIL: no HTTP reply (control: %s, bad input: %s); "
                "control status %d, bad input status %d",
                hg_str(control.how), hg_str(bad.how), control.status,
                bad.status);
        goto verdict;
    }
    if (bad.status >= 400 && bad.status <= 599)
        res_set(&res, R_PASS, "H3 PASS: bad input HTTP %d, control HTTP %d; "
                "bad input body [%s]; bad input took %.2f s", bad.status,
                control.status, body, bad.elapsed);
    else
        res_set(&res, R_FAIL, "H3 FAIL: bad input HTTP %d, control HTTP %d; "
                "bad input body [%s]; bad input took %.2f s", bad.status,
                control.status, body, bad.elapsed);

verdict:
    HYP_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}
