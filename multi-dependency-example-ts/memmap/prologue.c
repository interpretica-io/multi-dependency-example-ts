/** @file
 * @brief Memory Map Group
 *
 * memmap group prologue: record which of the tools the group leans on are
 * on the agent - readelf for the second view of every image, gcc for the
 * known-bad controls, python3 for the live RWX control, pgrep and curl to
 * find and drive the web tier.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "memmap/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

int
main(int argc, char **argv)
{
    static const char *tools[] = {
        "readelf", "gcc", "python3", "pgrep", "curl",
    };
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    double              have[TE_ARRAY_LEN(tools)];
    unsigned int        n_have = 0;
    unsigned int        i;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "mmprologue"));
    session_up = true;

    TEST_STEP("Remove what an earlier run may have left");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh, "rm -rf /tmp/mde-memmap-*"));

    TEST_STEP("Record the tools the group uses");
    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        bool ok = tsapi_mde_have(&session, tools[i]);

        have[i] = ok ? 1 : 0;
        if (ok)
            n_have++;
        TEST_ARTIFACT("tool %s: %s", tools[i], ok ? "available" : "missing");
    }
    if (tsapi_mde_have(&session, "readelf"))
    {
        CHECK_RC(tsapi_mde_sh(&session, 10000, &sh,
                              "readelf --version | head -n 1"));
        TEST_ARTIFACT("readelf: %s", te_string_value(&sh.out));
    }
    tsapi_mde_mi_bars("memmap/prologue", "Tools available (1 = yes)",
                      TE_MI_MEAS_UNITLESS_VALUE, "available",
                      TE_ARRAY_LEN(tools), tools, have,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("tools available: %u of %zu", n_have, TE_ARRAY_LEN(tools));

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
