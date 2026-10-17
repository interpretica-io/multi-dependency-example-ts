/** @file
 * @brief Fuzz Group
 *
 * Fuzz group epilogue: remove the build directories. The seeds under
 * /tmp/mde-fuzz-seeds stay - they are the regression corpus fuzz/replay
 * runs next time.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fuzz/epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "fuzz_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

    TEST_START;

    TEST_STEP("Remove the build directories, keep the seeds");
    if (tsapi_mde_session_init(&session, "fuzz_epilogue") == 0)
    {
        session_up = true;
        (void)tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                           "rm -rf " MDE_FUZZ_BUILD_DIR "; "
                           "ls " MDE_FUZZ_SEEDS_DIR " 2>/dev/null; true");
        RING("Seed directories kept:\n%s", te_string_value(&sh.out));
    }

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
