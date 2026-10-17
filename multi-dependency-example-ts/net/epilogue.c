/** @file
 * @brief net Group
 *
 * net group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "net/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the net group");
    /* Each test removes the instances it added. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
