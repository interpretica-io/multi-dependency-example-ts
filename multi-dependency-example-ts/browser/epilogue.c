/** @file
 * @brief Browser Group
 *
 * browser group epilogue. The evidence the tests kept under
 * /tmp/mde-browser-walk-* stays on the agent on purpose: the AI group
 * reads the screenshot later.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "browser/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the browser group");
    /* Each test stops its own browser and web tier. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
