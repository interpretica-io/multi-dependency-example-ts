/** @file
 * @brief time Group
 *
 * time group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "time/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the time group");
    /* Every test stops what it started; nothing is left to clean up. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
