/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H2: service-go does not isolate itself from callers that
 * break its contract.
 *
 * service-go is started and sent requests that break the contract of its
 * /ring endpoint: a missing value, wrong-typed value and hops, a hop
 * count that overflows, an oversized field, and a POST with a JSON body
 * of wrong types. After each one the process must still be alive.
 *
 * - FAIL (H2 confirmed): the service crashes, or returns success (2xx),
 *   or any answer other than 4xx for a violation.
 * - PASS: every violation is rejected with a 4xx and the service lives.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_contract_violation"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

#define T   "webdeps_contract_violation"
#define H   "H2"

/** Size of the oversized field. */
#define BIG     50000

/** A contract violation. */
typedef struct violation {
    const char *name;   /**< Label. */
    const char *opts;   /**< curl options. */
    const char *path;   /**< Path with query; @c NULL for the big one. */
} violation;

static const violation violations[] = {
    { "missing-value",   "", "/ring?hops=1" },
    { "wrong-type-value", "", "/ring?value=abc&hops=1" },
    { "wrong-type-hops", "", "/ring?value=1&hops=xyz" },
    { "hops-overflow",   "", "/ring?value=1&hops=99999999999999999999" },
    { "negative-hops",   "", "/ring?value=1&hops=-5" },
    { "oversized-value", "", NULL },
    { "json-wrong-types", "-X POST -H 'Content-Type: application/json' "
      "-d '{\"value\":[1,2],\"hops\":\"many\"}'", "/ring" },
};
#define N_VIOL  TE_ARRAY_LEN(violations)

int
main(int argc, char **argv)
{
    wd_ctx       ctx = WD_CTX_INIT;
    web_reply    reply = WEB_REPLY_INIT;
    te_string    url = TE_STRING_INIT;
    te_string    bad = TE_STRING_INIT;
    const char  *labels[N_VIOL];
    double       codes[N_VIOL];
    unsigned int n_bad = 0;
    size_t       i;

    TEST_START;

    TEST_STEP("Open a session and learn the ports of the three binaries");
    WD_OPEN(ctx, T, H);
    WD_LEARN(ctx, T, H);

    TEST_STEP("Start service-go");
    WD_START(ctx, WD_GO, T, H);

    for (i = 0; i < N_VIOL; i++)
    {
        const violation *v = &violations[i];
        bool             alive;
        int              rc;

        TEST_STEP("Violation: %s", v->name);
        te_string_reset(&url);
        te_string_append(&url, "http://127.0.0.1:%u%s", ctx.port[WD_GO],
                         v->path != NULL ? v->path : "/ring?value=");
        if (v->path == NULL)
        {
            size_t k;

            for (k = 0; k < BIG; k++)
                te_string_append(&url, "9");
            te_string_append(&url, "&hops=1");
        }
        if (web_get(&ctx.session, v->opts, url.ptr, 15, &reply) != 0)
            WD_FAIL(T, H, "cannot run curl on the agent");

        alive = wd_alive(&ctx, wd_names[WD_GO], &rc);
        labels[i] = v->name;
        codes[i] = reply.code;
        TEST_ARTIFACT("H2 %s: HTTP %d in %.3f s; service-go alive=%s",
                      v->name, reply.code, reply.time_s, alive ? "yes" : "no");

        if (!alive)
        {
            WD_FAIL(T, H, "H2 confirmed: service-go crashed (exit status "
                    "%d) on the '%s' request", rc, v->name);
        }
        if (reply.code < 400 || reply.code >= 500)
        {
            n_bad++;
            te_string_append(&bad, "%s%s -> %s", bad.len > 0 ? "; " : "",
                             v->name, reply.code == 0 ? "no answer" :
                             WD_IS_2XX(reply.code) ? "success" :
                             "not a 4xx");
            te_string_append(&bad, " (HTTP %d)", reply.code);
        }
    }

    tsapi_mde_mi_bars("webdeps", "H2: HTTP status of contract violations",
                      TE_MI_MEAS_UNITLESS_VALUE, "status", N_VIOL, labels,
                      codes, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on H2");
    if (n_bad > 0)
        WD_FAIL(T, H, "H2 confirmed: service-go accepted or mis-answered "
                "%u of %zu contract violation(s): %s", n_bad,
                (size_t)N_VIOL, bad.ptr);

    WD_PASS(T, H, "H2 disproved: service-go rejected all %zu contract "
            "violations with a 4xx and stayed up", (size_t)N_VIOL);

    TEST_SUCCESS;

cleanup:

    wd_close(&ctx);
    te_string_free(&url);
    te_string_free(&bad);
    te_string_free(&reply.body);

    TEST_END;
}
