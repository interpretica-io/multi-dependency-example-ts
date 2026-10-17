/** @file
 * @brief Binary Group
 *
 * Binary group prologue: record which of the tools the group relies on
 * are on the agent and which artifacts of the example are built, so a
 * skip further down has its reason in the log.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "binary/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "binary_common.h"

/** Tools the tests of the group use on the agent. */
static const char * const tools[] = {
    "readelf", "objdump", "gcc", "cc", "sha256sum",
};

int
main(int argc, char **argv)
{
    tsapi_mde_session session = { .ta = NULL };
    tsapi_mde_dut     dut = { .root = NULL };
    bool              session_up = false;
    double            have[TE_ARRAY_LEN(tools)];
    const char       *names[BINARY_N_ARTIFACTS];
    double            built[BINARY_N_ARTIFACTS];
    unsigned int      n_built = 0;
    unsigned int      n = 0;
    unsigned int      i;

    TEST_START;

    TEST_STEP("Prepare the binary group");
    CHECK_RC(tsapi_mde_session_init(&session, "binary_prologue"));
    session_up = true;

    TEST_STEP("Record the tools available on the agent");
    for (i = 0; i < TE_ARRAY_LEN(tools); i++)
    {
        have[i] = tsapi_mde_have(&session, tools[i]) ? 1 : 0;
        TEST_ARTIFACT("tool %s: %s", tools[i],
                      have[i] != 0 ? "present" : "missing");
    }
    tsapi_mde_mi_bars("binary", "Tools on the agent (1 present)",
                      TE_MI_MEAS_UNITLESS_VALUE, "present",
                      TE_ARRAY_LEN(tools), tools, have,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Record which artifacts of the example are built");
    if (tsapi_mde_dut_open(&session, &dut) != 0)
    {
        TEST_ARTIFACT("The example is not built: the group will skip");
        TEST_SUCCESS;
    }

    for (i = 0; i < binary_n_artifacts() && i < BINARY_N_ARTIFACTS; i++)
    {
        te_string path = TE_STRING_INIT;

        names[n] = binary_artifact_name(i);
        binary_artifact_path(&dut, names[n], &path);
        built[n] = tsapi_mde_exists(&session, path.ptr) ? 1 : 0;
        if (built[n] != 0)
            n_built++;
        TEST_ARTIFACT("artifact %s: %s", names[n],
                      built[n] != 0 ? path.ptr : "not built");
        te_string_free(&path);
        n++;
    }
    tsapi_mde_mi_bars("binary", "Artifacts built (1 built)",
                      TE_MI_MEAS_UNITLESS_VALUE, "built", n, names, built,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("%u of %u artifacts are built", n_built, n);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
