/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t13_cs_swallow, service-cs answers success on errors
 *        (settles H3)
 *
 * Start service-cs alone and check that a valid request gets 200. Then
 * send it inputs that reach the exception handling near Program.cs:85:
 * payloads that cannot be parsed (value and hops of the wrong type) and a
 * valid request whose upstream is unreachable (gateway-rs is not running,
 * so the HttpRequestException of the forward is caught).
 *
 * The contract that a service owes its client is that an error is told
 * with a 4xx or 5xx status and a body that says what failed.
 *
 * H3 CONFIRMED if an input is answered with a 2xx status and an empty or
 * success body (or a body that itself admits the failure). H3 DISPROVED if
 * every input gets a 4xx or 5xx with an error body. A 4xx or 5xx with an
 * empty body, or no HTTP status, is reported as not settled. A service-cs
 * that does not start fails the test with the reason "not started" and
 * settles nothing.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t13_cs_swallow"

#include "te_config.h"

#include "webdeps_lib.h"

typedef struct in_t {
    const char *what;
    const char *path;
    bool        backend;    /**< The input needs the unreachable backend. */
} in_t;

static const in_t inputs[] = {
    { "a value that is not a number", "/ring?value=abc&hops=1", false },
    { "a hop count that is not a number", "/ring?value=1&hops=xyz", false },
    { "a hop count that overflows", "/ring?value=1&hops=99999999999999999999",
      false },
    { "an unreachable backend (hops=3, gateway-rs is not running)",
      "/ring?value=1&hops=3", true },
};

static bool
body_shows_error(const char *body)
{
    static const char * const words[] = {
        "unreachable", "error", "exception", "failed", "refused",
    };
    size_t i;

    for (i = 0; i < TE_ARRAY_LEN(words); i++)
    {
        if (strcasestr(body, words[i]) != NULL)
            return true;
    }
    return false;
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *cs;
    hg_res   h;
    char     flat[300];
    char     bad[1000] = "";
    char     unsure[600] = "";
    char     seen[500] = "";
    unsigned n_bad = 0;
    unsigned n_unsure = 0;
    size_t   i;

    TEST_START;

    TEST_STEP("Start service-cs and wait for its port");
    cs = svc_start_t(&res, "H3", CS);
    if (cs == NULL)
    {
        ERROR("service-cs did not start: %s", res.msg);
        goto verdict;
    }

    TEST_STEP("A valid request gets 200");
    http_get(cs->port, "/ring?value=1&hops=0", 20, &h);
    body_flat(&h, flat, sizeof(flat));
    RING("webdeps H3: valid request: %s, HTTP %d, body [%s]", hg_str(h.how),
         h.status, flat);
    if (proc_gone(cs) || h.how != HG_OK || h.status != 200)
    {
        res_set(&res, R_SETUP, "H3 not started: service-cs did not answer "
                "the valid request with 200 (%s, HTTP %d, body [%s]); "
                "settles nothing", hg_str(h.how), h.status, flat);
        goto verdict;
    }

    for (i = 0; i < TE_ARRAY_LEN(inputs); i++)
    {
        bool        swallowed = false;
        bool        unclear = false;
        const char *why = "";

        TEST_STEP("Send %s", inputs[i].what);
        http_get(cs->port, inputs[i].path, 20, &h);
        body_flat(&h, flat, sizeof(flat));
        RING("webdeps H3: GET %s (%s): %s, HTTP %d, body [%s]",
             inputs[i].path, inputs[i].what, hg_str(h.how), h.status, flat);

        if (h.how != HG_OK)
        {
            unclear = true;
            why = "no HTTP status";
        }
        else if (h.status >= 200 && h.status < 300)
        {
            swallowed = true;
            why = flat[0] == '\0' ? "2xx with an empty body" :
                  body_shows_error(h.body) ?
                  "2xx whose body admits the error" :
                  inputs[i].backend ? "2xx with a success body although "
                  "the backend work did not happen" :
                  "2xx with a success body for a payload that cannot be "
                  "parsed";
        }
        else if (h.status >= 400 && h.status < 600)
        {
            if (flat[0] == '\0')
            {
                unclear = true;
                why = "4xx/5xx with an empty body";
            }
        }
        else
        {
            unclear = true;
            why = "status neither 2xx, 4xx nor 5xx";
        }

        T_FINDING(swallowed ? TAPI_CYBERSEC_SEV_HIGH : unclear ?
                  TAPI_CYBERSEC_SEV_LOW : TAPI_CYBERSEC_SEV_INFO,
                  swallowed ? "csharp.swallowed" : "csharp.rejected",
                  inputs[i].what, "%s, HTTP %d%s%s; body [%s]",
                  hg_str(h.how), h.status, why[0] != '\0' ? ": " : "", why,
                  flat);
        append(seen, sizeof(seen), "HTTP %d; ", h.status);
        if (swallowed)
        {
            n_bad++;
            append(bad, sizeof(bad), "%s -> HTTP %d (%s), body [%.120s] | ",
                   inputs[i].what, h.status, why, flat);
        }
        else if (unclear)
        {
            n_unsure++;
            append(unsure, sizeof(unsure), "%s -> HTTP %d (%s) | ",
                   inputs[i].what, h.status, why);
        }
    }

    if (n_bad > 0)
        res_set(&res, R_FAIL, "H3 CONFIRMED: service-cs answered %u of %zu "
                "bad inputs with a 2xx instead of an error: %s", n_bad,
                TE_ARRAY_LEN(inputs), bad);
    else if (n_unsure > 0)
        res_set(&res, R_FAIL, "H3 not settled: no input got a 2xx, but %u "
                "of %zu got no 4xx/5xx with an error body: %s", n_unsure,
                TE_ARRAY_LEN(inputs), unsure);
    else
        res_set(&res, R_PASS, "H3 DISPROVED: service-cs answered all %zu "
                "bad inputs with a 4xx/5xx and an error body (%s)",
                TE_ARRAY_LEN(inputs), seen);

verdict:
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}
