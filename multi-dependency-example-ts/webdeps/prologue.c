/** @file
 * @brief Webdeps Group
 *
 * Webdeps group prologue: nothing to prepare. Each test starts the three
 * binaries itself and ends with an explicit PASS or FAIL verdict.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/prologue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Prepare the webdeps group");
    /* Nothing to prepare: every test starts and stops its own processes. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
