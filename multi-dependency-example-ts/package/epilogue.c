/** @file
 * @brief package Group
 *
 * package group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "package/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the package group");
    /* Nothing to undo: the tests only ask questions. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
