/** @file
 * @brief Exposure Group
 *
 * Exposure group prologue: start nothing, record which of the tools the
 * group relies on are on the agent, so that a skip further down has its
 * reason in the log.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "exposure_common.h"

/** Tools the tests of the group use on the agent. */
static const char * const tools[] = {
    "curl", "python3", "setsid", "ip", "tcpdump", "sudo", "frida",
};

int
main(int argc, char **argv)
{
    tsapi_mde_session session = { .ta = NULL };
    tsapi_mde_dut     dut = { .root = NULL };
    bool              session_up = false;
    const char       *labels[TE_ARRAY_LEN(tools) + 2];
    double            have[TE_ARRAY_LEN(tools) + 2];
    size_t            n = 0;
    size_t            i;

    TEST_START;

    TEST_STEP("Prepare the exposure group");
    CHECK_RC(tsapi_mde_session_init(&session, "exposure_prologue"));
    session_up = true;

    TEST_STEP("Install what the group needs on the agent and check it");
    TSAPI_MDE_ENSURE(session, "exposure base build");

    TEST_STEP("Record the tools available on the agent");
    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        labels[n] = tools[i];
        have[n] = tsapi_mde_have(&session, tools[i]) ? 1 : 0;
        TEST_ARTIFACT("tool %s: %s", tools[i],
                      have[n] != 0 ? "present" : "missing");
        n++;
    }

    labels[n] = "sudo -n";
    have[n] = exposure_sh_quiet(&session, "sudo -n true") ? 1 : 0;
    TEST_ARTIFACT("passwordless sudo: %s", have[n] != 0 ? "yes" : "no");
    n++;

    labels[n] = "web tier";
    have[n] = 0;
    if (tsapi_mde_dut_open(&session, &dut) == 0)
        have[n] = tsapi_mde_web_built(&session, &dut) ? 1 : 0;
    TEST_ARTIFACT("web tier built: %s", have[n] != 0 ? "yes" : "no");
    n++;

    tsapi_mde_mi_bars("exposure", "Tools and prerequisites (1 present)",
                      TE_MI_MEAS_UNITLESS_VALUE, "present", n, labels, have,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
