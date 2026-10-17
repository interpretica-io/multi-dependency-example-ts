/** @file
 * @brief AI Group
 *
 * ai group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ai/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the ai group");
    /* Each test closes its own connection; tsf-ai removes its files. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
