/** @file
 * @brief http Group
 *
 * http group prologue: report which of the tools the group drives the agent
 * has and their versions, so the skips later in the group are easy to
 * read, and chart what was found.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "http/prologue"

#include "te_config.h"

#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/* The programs the tests of the group drive on the agent. */
static const char *tools[] = {
    "curl",
    "python3",
};

/* How each of them tells its version, in the order of tools[]. */
static const char *versions[] = {
    "curl --version",
    "python3 --version",
};

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                session_up = false;
    double              have[TE_ARRAY_LEN(tools)];
    unsigned int        n_have = 0;
    unsigned int        i;

    TEST_START;

    tsapi_evo_analysis_hint(
        "HTTP audits of the web tier with tsf-http: response headers, "
        "methods, unknown paths and a load curve. Every audit is preceded "
        "by a known-bad control endpoint.");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "http_prologue"));
    session_up = true;

    TEST_STEP("Report the tools of the group");
    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        have[i] = tsapi_mde_have(&session, tools[i]) ? 1 : 0;
        if (have[i] == 0)
        {
            TEST_ARTIFACT("%s: missing - its tests will skip", tools[i]);
            continue;
        }

        n_have++;
        if (tsapi_mde_sh(&session, 10000, &res, "%s 2>&1 | head -n 1",
                         versions[i]) == 0 && tsapi_mde_sh_ok(&res))
        {
            const char *text = te_string_value(&res.out);

            TEST_ARTIFACT("%s: %.*s", tools[i], (int)strcspn(text, "\n"),
                          text);
        }
    }

    tsapi_mde_mi_bars("http", "Tools of the group present (1/0)",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(tools), tools, have,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("%u of %u tool(s) of the http group present", n_have,
                  (unsigned int)TE_ARRAY_LEN(tools));

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
