/** @file
 * @brief ring Group
 *
 * ring group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the ring group");
    /* No cleanup actions required. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
