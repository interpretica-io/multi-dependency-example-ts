/** @file
 * @brief Kernel Group
 *
 * kernel group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "kernel/epilogue"

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

    TEST_STEP("Remove what the kernel group left on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "kepilogue"));
    session_up = true;
    CHECK_RC(tsapi_mde_sh(&session, 20000, &sh,
                          "rm -rf /tmp/mde-kernel-*"));

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
