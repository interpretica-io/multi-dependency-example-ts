/** @file
 * @brief Memory Map Group
 *
 * memmap group epilogue: remove the known-bad controls built on the agent.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "memmap/epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_mde.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

    TEST_START;

    TEST_STEP("Remove the known-bad controls");
    CHECK_RC(tsapi_mde_session_init(&session, "mmepilogue"));
    session_up = true;
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh, "rm -rf /tmp/mde-memmap-*"));

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
