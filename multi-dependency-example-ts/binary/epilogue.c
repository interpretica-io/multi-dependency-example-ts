/** @file
 * @brief Binary Group
 *
 * Binary group epilogue: remove whatever control a test left behind on
 * the agent if it was stopped before its own cleanup.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "binary/epilogue"

#include "te_config.h"
#include "tapi_test.h"

#include "binary_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session session = { .ta = NULL };
    bool              session_up = false;

    TEST_START;

    TEST_STEP("Finalize the binary group");
    CHECK_RC(tsapi_mde_session_init(&session, "binary_epilogue"));
    session_up = true;

    TEST_STEP("Remove the controls the tests build on the agent");
    binary_rm(&session, "/tmp/mde-binary-control /tmp/mde-binary-control.c "
                        "/tmp/mde-binary-disasm-control.so "
                        "/tmp/mde-binary-disasm-control.c "
                        "/tmp/mde-binary-libs-control "
                        "/tmp/mde-binary-libs-control.c");

    TEST_SUCCESS;

cleanup:

    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
