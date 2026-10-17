/** @file
 * @brief devtool Group
 *
 * devtool group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "devtool/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the devtool group");
    /* Each test removes its own temporary files on the agent. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
