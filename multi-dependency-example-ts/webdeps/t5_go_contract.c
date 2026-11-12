/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T5, the contract of service-go (settles H5)
 *
 * Code read first: contract.go:33 opens services.tab and findService()
 * at contract.go:73 returns the first row whose name matches, so the
 * table is only about service names and ports; the contract of a request
 * is the one /ring states, and main.go floatParam()/intParam() fall back
 * to the default (value=1.0, hops=6) on text that does not parse and
 * apply no range, so a bad value is answered as if it were the default.
 * The inputs below are therefore a missing field, a non-number, a
 * negative and a huge hop count and an overflowing value.
 *
 * A plain TCP/HTTP client. The contract of /ring is: value is a number
 * and hops is an integer in 0..64, both present. Start service-go, send
 * one message that follows it as a control, then messages that break it:
 * a missing field, a wrong type and a value out of range.
 *
 * H5 FAIL if any broken message gets a 2xx answer (or any answer
 * that is not 4xx); H5 PASS if every one
 * is rejected with 4xx. The status of each is in the verdict and in the
 * tapi_cybersec_report. A service-go that does not start is NOT RUN.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t5_go_contract"

#include "te_config.h"

#include "webdeps_lib.h"

#define VALID_MSG   "/ring?value=1&hops=1"

static const struct {
    const char *what;
    const char *path;
} broken[] = {
    { "missing value", "/ring?hops=1" },
    { "missing hops", "/ring?value=1" },
    { "wrong type of value", "/ring?value=abc&hops=1" },
    { "wrong type of hops", "/ring?value=1&hops=x" },
    { "hops out of range (negative)", "/ring?value=1&hops=-5" },
    { "hops out of range (huge)", "/ring?value=1&hops=999999" },
    { "value out of range", "/ring?value=1e999&hops=1" },
};

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *go;
    hg_res   valid;
    hg_res   h;
    char     seen[900] = "";
    char     accepted[600] = "";
    int      n_acc = 0;
    size_t   i;

    TEST_START;

    TEST_STEP("Start service-go and wait for its port");
    go = svc_start_t(&res, "H5", GO);
    if (go == NULL)
        goto verdict;

    TEST_STEP("Control: a message that follows the contract: %s", VALID_MSG);
    http_get(go->port, VALID_MSG, PROBE_TO, &valid);
    if (valid.how != HG_OK || valid.status < 200 || valid.status >= 300)
    {
        res_set(&res, R_FAIL, "H5 FAIL: the control message got %s, HTTP %d",
                hg_str(valid.how), valid.status);
        goto verdict;
    }

    for (i = 0; i < TE_ARRAY_LEN(broken); i++)
    {
        TEST_STEP("Broken message: %s, %s", broken[i].what, broken[i].path);
        http_get(go->port, broken[i].path, PROBE_TO, &h);
        RING("webdeps: service-go %s %s -> %s, HTTP %d", broken[i].what,
             broken[i].path, hg_str(h.how), h.status);
        append(seen, sizeof(seen), "%s: HTTP %d; ", broken[i].what, h.status);
        if (h.how != HG_OK)
        {
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.contract", "service-go",
                      "%s: no reply (%s)", broken[i].what, hg_str(h.how));
            res_set(&res, R_FAIL, "H5 FAIL: %s: no HTTP reply (%s)",
                    broken[i].what, hg_str(h.how));
            goto verdict;
        }
        if (h.status < 400 || h.status >= 500)
        {
            n_acc++;
            append(accepted, sizeof(accepted), "%s (%s) -> %d; ",
                   broken[i].what, broken[i].path, h.status);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "go.contract", "service-go",
                      "%s not rejected with 4xx: %s -> HTTP %d",
                      broken[i].what, broken[i].path, h.status);
        }
        else
            T_FINDING(TAPI_CYBERSEC_SEV_INFO, "go.contract", "service-go",
                      "%s rejected: HTTP %d", broken[i].what, h.status);
    }

    if (n_acc > 0)
        res_set(&res, R_FAIL, "H5 FAIL: service-go did not answer 4xx to %d of %zu "
                "broken messages: %s", n_acc, TE_ARRAY_LEN(broken), accepted);
    else
        res_set(&res, R_PASS, "H5 PASS: service-go rejected every broken "
                "message (control HTTP %d); %s", valid.status, seen);

verdict:
    T_VERDICT(&res, "H5");

cleanup:
    cleanup_all();
    TEST_END;
}
