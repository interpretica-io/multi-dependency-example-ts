/** @file
 * @brief iot Group
 *
 * iot group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "iot/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the iot group");
    /* Each test removes its own vcan interface and temp files. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
