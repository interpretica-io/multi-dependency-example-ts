/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t9_go_contract, service-go accepts input that breaks
 *        the contract (settles H5)
 *
 * Start service-go and send it requests that break the rule checked at
 * contract.go:33: a missing field, a negative value and a wrong type.
 *
 * H5 FAIL if any of them gets a 2xx (the verdict names each one with its
 * status). H5 PASS if each gets a 4xx. A service-go that does not start
 * is H5 INCONCLUSIVE.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t9_go_contract"

#include "te_config.h"

#include "webdeps_lib.h"

typedef struct in_t {
    const char *what;
    const char *path;
} in_t;

static const in_t inputs[] = {
    { "a missing value", "/ring?hops=2" },
    { "a missing hops", "/ring?value=1" },
    { "a negative value", "/ring?value=-5&hops=2" },
    { "a negative hops", "/ring?value=1&hops=-3" },
    { "a value of the wrong type", "/ring?value=abc&hops=2" },
    { "a hops of the wrong type", "/ring?value=1&hops=xyz" },
};

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *go;
    hg_res   h;
    char     flat[200];
    char     bad[1100] = "";
    char     seen[500] = "";
    unsigned n_bad = 0;
    size_t   i;

    TEST_START;

    TEST_STEP("Start service-go and wait for its port");
    go = svc_start_t(&res, "H5", GO);
    if (go == NULL)
    {
        ERROR("service-go did not start: %s", res.msg);
        goto verdict;
    }

    for (i = 0; i < TE_ARRAY_LEN(inputs); i++)
    {
        bool fail;

        TEST_STEP("Send %s", inputs[i].what);
        http_get(go->port, inputs[i].path, 10, &h);
        body_flat(&h, flat, sizeof(flat));
        RING("webdeps H5: %s (%s): %s, HTTP %d, body [%s]", inputs[i].what,
             inputs[i].path, hg_str(h.how), h.status, flat);
        fail = h.how != HG_OK || h.status < 400 || h.status >= 500;
        T_FINDING(fail ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
                  fail ? "go.contract-accepted" : "go.contract-rejected",
                  inputs[i].what, "%s, HTTP %d; body [%s]", hg_str(h.how),
                  h.status, flat);
        append(seen, sizeof(seen), "HTTP %d; ", h.status);
        if (fail)
        {
            n_bad++;
            append(bad, sizeof(bad), "%s (%s) -> %s HTTP %d, body [%.100s] "
                   "| ", inputs[i].what, inputs[i].path,
                   h.how == HG_OK ? "answered" : hg_str(h.how), h.status,
                   flat);
        }
    }

    if (n_bad > 0)
        res_set(&res, R_FAIL, "H5 FAIL: service-go did not answer %u of %zu "
                "contract-breaking requests with a 4xx: %s", n_bad,
                TE_ARRAY_LEN(inputs), bad);
    else
        res_set(&res, R_PASS, "H5 PASS: service-go answered all %zu "
                "contract-breaking requests with 4xx (%s)",
                TE_ARRAY_LEN(inputs), seen);

verdict:
    T_VERDICT(&res, "H5");

cleanup:
    cleanup_all();
    TEST_END;
}
