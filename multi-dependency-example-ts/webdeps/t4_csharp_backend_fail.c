/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T4, the swallowed backend error in service-cs (settles H4)
 *
 * A plain TCP/HTTP client. The catch in Program.cs turns a failed call
 * to the upstream gateway-rs into "no result". The input that makes the
 * call fail is a hop budget above zero while gateway-rs is not
 * listening. Start service-cs alone, send that input (hops=3) and, as a
 * control, hops=0 which never calls the upstream.
 *
 * H4 FAIL if the failed call returns HTTP 200 (with an empty body or a
 * default body that carries a value as if the call had worked); H4 PASS
 * if it returns 4xx or 5xx. A service-cs that does not start is NOT RUN.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t4_csharp_backend_fail"

#include "te_config.h"

#include "webdeps_lib.h"

#define BAD_REQUEST     "/ring?value=1&hops=3"
#define CONTROL_REQUEST "/ring?value=1&hops=0"

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *cs;
    hg_res   control;
    hg_res   bad;
    char     body[400];
    char     cbody[200];

    TEST_START;

    TEST_STEP("Start service-cs alone and wait for its port");
    cs = svc_start_t(&res, "H4", CS);
    if (cs == NULL)
        goto verdict;

    TEST_STEP("Control: a request that needs no upstream, %s",
              CONTROL_REQUEST);
    http_get(cs->port, CONTROL_REQUEST, PROBE_TO + 2, &control);
    body_flat(&control, cbody, sizeof(cbody));

    TEST_STEP("Failing call: %s, gateway-rs is down so the upstream call "
              "fails", BAD_REQUEST);
    http_get(cs->port, BAD_REQUEST, PROBE_TO + 2, &bad);
    body_flat(&bad, body, sizeof(body));

    RING("webdeps: service-cs control HTTP %d [%s]; failing call HTTP %d "
         "[%s] in %.2f s", control.status, cbody, bad.status, body,
         bad.elapsed);

    if (control.how != HG_OK || bad.how != HG_OK)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "cs.no-reply", "service-cs",
                  "no HTTP reply (control: %s, failing call: %s)",
                  hg_str(control.how), hg_str(bad.how));
        res_set(&res, R_FAIL, "H4 FAIL: no HTTP reply (control: %s, failing "
                "call: %s); control status %d, failing call status %d",
                hg_str(control.how), hg_str(bad.how), control.status,
                bad.status);
        goto verdict;
    }
    if (bad.status >= 400 && bad.status <= 599)
    {
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "cs.error-status", "service-cs",
                  "failed backend call -> HTTP %d", bad.status);
        res_set(&res, R_PASS, "H4 PASS: failing call HTTP %d, control HTTP "
                "%d; body [%s]", bad.status, control.status, body);
    }
    else
    {
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "cs.swallowed-error", "service-cs",
                  "failed backend call -> HTTP %d with body [%s]",
                  bad.status, body);
        res_set(&res, R_FAIL, "H4 FAIL: failing call HTTP %d (%s body), "
                "control HTTP %d; body [%s]; took %.2f s", bad.status,
                body[0] == '\0' ? "empty" : "default", control.status, body,
                bad.elapsed);
    }

verdict:
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}
