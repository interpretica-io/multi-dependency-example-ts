/** @file
 * @brief devtool Group
 *
 * devtool group prologue: which compilers and build tools the agent has,
 * and their versions. Never skips - the tests skip on their own.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "devtool/prologue"

#include "te_config.h"

#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

/* Compilers first; the build tools after them are not counted as such. */
static const char *devtool_tools[] = {
    "cc", "gcc", "clang", "tcc", "c++", "g++", "clang++",
    "make", "ld", "python3-config",
};
/* How many of devtool_tools are compilers. */
#define DEVTOOL_N_COMPILERS 7

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    double              present[TE_ARRAY_LEN(devtool_tools)];
    unsigned int        n_compilers = 0;
    unsigned int        i;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    rc = tsapi_mde_session_init(&session, "dev_prologue");
    session_up = true;
    if (rc != 0)
        TEST_FAIL("Cannot open a session on the agent: %r", rc);

    TEST_STEP("Ask every compiler and build tool for its version");
    for (i = 0; i < TE_ARRAY_LEN(devtool_tools); i++)
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              "p=$(command -v '%s') || exit 3; "
                              "echo \"$p\"; '%s' --version 2>&1 | head -n1",
                              devtool_tools[i], devtool_tools[i]));
        present[i] = tsapi_mde_sh_ok(&sh) ? 1 : 0;
        if (present[i] > 0)
        {
            if (i < DEVTOOL_N_COMPILERS)
                n_compilers++;
            TEST_ARTIFACT("%s: %s", devtool_tools[i],
                          te_string_value(&sh.out));
        }
        else
        {
            TEST_ARTIFACT("%s: not available", devtool_tools[i]);
        }
    }

    TEST_STEP("Chart what was found");
    tsapi_mde_mi_point("devtool", "Compilers available on the agent",
                       TE_MI_MEAS_UNITLESS_VALUE, "compilers", n_compilers,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("devtool", "Build tools available on the agent",
                      TE_MI_MEAS_UNITLESS_VALUE, "available",
                      TE_ARRAY_LEN(devtool_tools), devtool_tools, present,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
