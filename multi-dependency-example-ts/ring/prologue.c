/** @file
 * @brief ring Group
 *
 * ring group prologue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/prologue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Prepare the ring group");
    /* No special setup; each test opens its own session. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
