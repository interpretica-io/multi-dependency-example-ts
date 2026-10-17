/** @file
 * @brief http Group
 *
 * http group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "http/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the http group");
    /* Every test stops what it started; nothing is left to clean up. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
