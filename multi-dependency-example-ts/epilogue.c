/** @file
 * @brief Test Suite
 *
 * Test Suite epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_evo.h"

int
main(int argc, char **argv)
{
    TEST_START;

    tsapi_evo_analysis_hint("Test suite epilogue. Finalizing the test environment.");

    TEST_STEP("Finalize test suite");
    /* No actions required; each group cleans up after itself. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
