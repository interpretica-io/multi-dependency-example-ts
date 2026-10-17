/** @file
 * @brief bench Group
 *
 * bench group prologue: chart which bench tools the agent has, so the
 * group's skips can be read against what was present.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "bench/prologue"

#include "te_config.h"

#include "tapi_test.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

int
main(int argc, char **argv)
{
    static const char *tools[] = {
        "openocd", "flashrom", "dfu-util", "esptool", "snmpset", "uhubctl",
    };
    tsapi_mde_session session;
    bool              session_up = false;
    double            present[TE_ARRAY_LEN(tools)];
    unsigned int      i;

    TEST_START;

    TEST_STEP("Probe the bench tools on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "bench_prologue"));
    session_up = true;

    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        bool have = tsapi_mde_have(&session, tools[i]);

        present[i] = have ? 1 : 0;
        TEST_ARTIFACT("bench tool %s: %s", tools[i],
                      have ? "present" : "absent");
    }
    tsapi_mde_mi_bars("bench", "Bench tool availability on the agent",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(tools), tools, present,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
