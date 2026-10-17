/** @file
 * @brief Emulator Group
 *
 * Emulator group epilogue: remove the scratch directory (the guest, the
 * qcow2 disk, the console files) and the screendump.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "emu/epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "emu_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

    TEST_START;

    TEST_STEP("Remove what the group left on the agent");
    if (tsapi_mde_session_init(&session, "emu_epilogue") == 0)
    {
        session_up = true;
        (void)tsapi_mde_sh(&session, MDE_EMU_TIMEOUT_MS, &sh,
                           "rm -rf " MDE_EMU_DIR
                           " /tmp/mde-emu-screen.ppm; true");
    }

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
