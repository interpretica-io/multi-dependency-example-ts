/** @file
 * @brief Browser Group
 *
 * browser group prologue: record what the browser stack on the agent is
 * made of - Node.js, the playwright package and its version, the browsers
 * installed for it, @playwright/test - so that a skip further down the
 * group has its reason in the log, and chart it.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "browser/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "browser_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const char         *labels[] = { "node", "playwright", "browsers",
                                     "@playwright/test", "npx", "curl",
                                     "python3" };
    double              found[7];
    unsigned int        n_browsers = 0;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "browser_prologue"));
    session_up = true;

    TEST_STEP("Install what the group needs on the agent and check it");
    TSAPI_MDE_ENSURE(session, "browser");

    TEST_STEP("Inventory the browser stack");
    found[0] = tsapi_mde_have(&session, "node");
    found[1] = tsapi_mde_exists(&session,
                                BROWSER_PW_DIR "/node_modules/playwright");
    found[2] = tsapi_mde_exists(&session, BROWSER_PW_BROWSERS);
    found[3] = tsapi_mde_exists(&session,
                                BROWSER_PW_DIR "/node_modules/@playwright/test");
    found[4] = tsapi_mde_have(&session, "npx");
    found[5] = tsapi_mde_have(&session, "curl");
    found[6] = tsapi_mde_have(&session, "python3");

    if (found[0] > 0)
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "node --version"));
        TEST_ARTIFACT("Node.js %s", sh.out.ptr != NULL ? sh.out.ptr : "?");
    }
    if (found[0] > 0 && found[1] > 0)
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              "node -e \"console.log(require('"
                              BROWSER_PW_DIR "/node_modules/playwright/"
                              "package.json').version)\""));
        TEST_ARTIFACT("playwright %s", sh.out.ptr != NULL ? sh.out.ptr : "?");
    }
    if (found[2] > 0)
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              "ls -1 '" BROWSER_PW_BROWSERS "'"));
        if (sh.out.ptr != NULL)
        {
            const char *p;

            for (p = sh.out.ptr; *p != '\0'; p++)
            {
                if (*p == '\n')
                    n_browsers++;
            }
            TEST_ARTIFACT("Browsers in " BROWSER_PW_BROWSERS ":\n%s",
                          sh.out.ptr);
        }
    }

    TEST_STEP("Chart the inventory");
    tsapi_mde_mi_bars("browser", "Browser stack on the agent (1 = present)",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(labels), labels, found,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("browser", "Browser builds installed for Playwright",
                       TE_MI_MEAS_UNITLESS_VALUE, "browsers", n_browsers,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
