/** @file
 * @brief web Group
 *
 * web group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the web group");
    /* No cleanup actions required. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
