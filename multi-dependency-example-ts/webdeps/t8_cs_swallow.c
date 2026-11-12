/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t8_cs_swallow, service-cs answers success on errors
 *        (settles H4)
 *
 * Start service-cs alone and send it inputs that reach the exception
 * handling of Program.cs:85: payloads that cannot be parsed (value and
 * hops of the wrong type) and a valid request whose backend is
 * unreachable (gateway-rs, its upstream, is not running).
 *
 * H4 FAIL for any input answered with a 2xx status whose body shows an
 * error ("unreachable", "error", "exception", "failed") or whose work did
 * not happen (an unreachable backend cannot have done its part); also when
 * there is no HTTP status at all. H4 PASS when every input got a 4xx or
 * 5xx. A service-cs that does not start is H4 INCONCLUSIVE.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t8_cs_swallow"

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
    char     seen[500] = "";
    unsigned n_bad = 0;
    size_t   i;

    TEST_START;

    TEST_STEP("Start service-cs and wait for its port");
    cs = svc_start_t(&res, "H4", CS);
    if (cs == NULL)
    {
        ERROR("service-cs did not start: %s", res.msg);
        goto verdict;
    }

    for (i = 0; i < TE_ARRAY_LEN(inputs); i++)
    {
        bool        fail;
        const char *why = "";

        TEST_STEP("Send %s", inputs[i].what);
        http_get(cs->port, inputs[i].path, 20, &h);
        body_flat(&h, flat, sizeof(flat));
        RING("webdeps H4: %s: %s, HTTP %d, body [%s]", inputs[i].what,
             hg_str(h.how), h.status, flat);

        if (h.how != HG_OK)
        {
            fail = true;
            why = "no HTTP status";
        }
        else if (h.status >= 200 && h.status < 300)
        {
            fail = true;
            why = body_shows_error(h.body) ? "2xx with an error in the body" :
                  inputs[i].backend ? "2xx although the backend work did "
                  "not happen" : "2xx for a payload that cannot be parsed";
        }
        else
            fail = h.status < 400 || h.status >= 600;
        if (fail && *why == '\0')
            why = "status neither 4xx nor 5xx";

        T_FINDING(fail ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
                  fail ? "csharp.swallowed" : "csharp.rejected",
                  inputs[i].what, "%s, HTTP %d%s%s; body [%s]",
                  hg_str(h.how), h.status, fail ? ": " : "", why, flat);
        append(seen, sizeof(seen), "HTTP %d; ", h.status);
        if (fail)
        {
            n_bad++;
            append(bad, sizeof(bad), "%s -> HTTP %d (%s), body [%.120s] | ",
                   inputs[i].what, h.status, why, flat);
        }
    }

    if (n_bad > 0)
        res_set(&res, R_FAIL, "H4 FAIL: service-cs answered %u of %zu bad "
                "inputs without a 4xx/5xx: %s", n_bad,
                TE_ARRAY_LEN(inputs), bad);
    else
        res_set(&res, R_PASS, "H4 PASS: service-cs answered all %zu bad "
                "inputs with 4xx/5xx (%s)", TE_ARRAY_LEN(inputs), seen);

verdict:
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}
