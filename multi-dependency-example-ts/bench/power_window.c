/** @file
 * @brief bench Group
 *
 * Energy over a window needs an instrument tsf-power can read. Its
 * measurement backends are SCPI bench meters (over TCP), USB energy
 * profilers (a vendor tool on the agent) and switchable outlets - none
 * of which is a software or RAPL reader of the host's own energy. So
 * this charts what the kernel's powercap interface exposes, confirms the
 * profiler backends report themselves unavailable with no device, and
 * skips the measurement with the concrete reason.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "bench/power_window"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_string.h"
#include "tapi_power_profiler.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

static const tapi_power_profiler_kind profilers[] = {
    TAPI_POWER_PROFILER_NORDIC_PPK2,
    TAPI_POWER_PROFILER_JOULESCOPE,
    TAPI_POWER_PROFILER_QOITECH_OTII,
    TAPI_POWER_PROFILER_MONSOON,
};

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *labels[TE_ARRAY_LEN(profilers)];
    double              present[TE_ARRAY_LEN(profilers)];
    unsigned int        zones = 0;
    unsigned int        i;

    TEST_START;

    memset(&dut, 0, sizeof(dut));

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "bench_power", dut, session_up);

    TEST_STEP("Chart what the kernel's powercap interface exposes");
    if (tsapi_mde_sh(&session, 10000, &res,
                     "ls -1 /sys/class/powercap 2>/dev/null | wc -l") == 0 &&
        tsapi_mde_sh_ok(&res))
    {
        zones = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);
    }
    tsapi_mde_sh_result_free(&res);
    TEST_ARTIFACT("powercap: %u zone(s) under /sys/class/powercap on the "
                  "agent", zones);
    tsapi_mde_mi_point("tapi_power", "Kernel powercap zones available",
                       TE_MI_MEAS_UNITLESS_VALUE, "zones", zones,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Every USB profiler backend must report itself absent here");
    for (i = 0; i < TE_ARRAY_LEN(profilers); i++)
    {
        tapi_power_profiler prof;
        bool                have = false;

        memset(&prof, 0, sizeof(prof));
        prof.kind = profilers[i];
        CHECK_RC(tapi_power_profiler_available(session.factory, &prof,
                                               &have));
        labels[i] = tapi_power_profiler_kind2str(profilers[i]);
        present[i] = have ? 1 : 0;
        TEST_ARTIFACT("power profiler %s: vendor tool %s on the agent",
                      labels[i], have ? "present" : "absent");
    }
    tsapi_mde_mi_bars("tapi_power", "USB energy profiler tool availability",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(profilers), labels, present,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Skip the energy measurement: nothing can measure it here");
    TEST_SKIP("tsf-power measures energy through SCPI bench instruments, USB "
              "energy profilers or switchable outlets; there is no SCPI "
              "instrument on the bench network, no profiler vendor tool on "
              "the agent and the module has no RAPL/powercap software "
              "backend, so the energy of running the ring cannot be measured");

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
