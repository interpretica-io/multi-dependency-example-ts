/** @file
 * @brief Container Group
 *
 * Container group epilogue: remove whatever container a failed test of
 * the group may have left behind under its stable name.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "container/epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "container_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

    TEST_START;

    TEST_STEP("Remove containers left over by the group");
    if (tsapi_mde_session_init(&session, "ct_epilogue") == 0)
    {
        session_up = true;
        (void)tsapi_mde_sh(&session, MDE_CT_TIMEOUT_MS, &sh,
                           "docker ps -aq --filter name=mde-ring-inside- "
                           "2>/dev/null | "
                           "xargs -r docker rm -f >/dev/null 2>&1; "
                           "rm -rf /tmp/mde-container-rt; true");
    }

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
