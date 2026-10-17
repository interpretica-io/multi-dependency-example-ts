/** @file
 * @brief Filesystem Group
 *
 * fs group prologue: remove what an earlier run may have left on the
 * agent, and record the size of the built tree the group audits.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fs/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    bool                dut_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    unsigned long       kb = 0;
    unsigned long       files = 0;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "fsprologue"));
    session_up = true;

    TEST_STEP("Remove the control directories of an earlier run");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh, "rm -rf /tmp/mde-fs-*"));

    TEST_STEP("Record the size of the built tree");
    if (tsapi_mde_dut_open(&session, &dut) == 0)
    {
        dut_up = true;
        CHECK_RC(tsapi_mde_sh(&session, 60000, &sh,
                              "du -sk '%s/dist' | cut -f1; "
                              "find '%s/dist' -type f | wc -l",
                              dut.root, dut.root));
        if (sscanf(te_string_value(&sh.out), "%lu %lu", &kb, &files) == 2)
        {
            TEST_ARTIFACT("dist: %lu kB in %lu file(s)", kb, files);
            tsapi_mde_mi_point("fs/prologue", "Size of dist",
                               TE_MI_MEAS_MEMORY, "dist_size", kb,
                               TE_MI_MEAS_MULTIPLIER_KIBI);
            tsapi_mde_mi_point("fs/prologue", "Files in dist",
                               TE_MI_MEAS_UNITLESS_VALUE, "dist_files",
                               files, TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
    }
    else
    {
        RING("The example is not built: the tests of the group will skip");
    }

    TEST_SUCCESS;

cleanup:

    if (dut_up)
        tsapi_mde_dut_free(&dut);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
