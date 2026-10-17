/** @file
 * @brief cwmp Group
 *
 * cwmp group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "cwmp/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the cwmp group");
    /* No cleanup actions required. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
