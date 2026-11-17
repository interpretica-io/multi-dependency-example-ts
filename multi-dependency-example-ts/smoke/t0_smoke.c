/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Smoke: t0_smoke, the run reports a verdict (settles H0)
 *
 * Hypothesis H0: the suite run reports a verdict for each test.
 *
 * Sends and reads nothing: no service is started and no agent call is
 * made. The test calls TEST_VERDICT with one fixed string,
 * "H0 smoke-verdict-reported", and then TEST_SUCCESS.
 *
 * Pass or fail: the run log must hold the verdict text
 * "H0 smoke-verdict-reported" for this test. If it does, H0 is true for
 * this run (a verdict is reported). If the log holds no verdict for this
 * test, H0 is false and no other result of the run can be trusted.
 * TEST_VERDICT ends the test as a failure carrying the verdict, so the
 * expected result in conf/trc.xml is FAILED with that verdict;
 * TEST_SUCCESS after it is the path a build without that stop would take.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "smoke/t0_smoke"

#include "te_config.h"

#include "tapi_test.h"

/** H0: report one fixed verdict; FAILED with it is the reported result. */
int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Report the fixed verdict");
    TEST_VERDICT("H0 smoke-verdict-reported");

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
