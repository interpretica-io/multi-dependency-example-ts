/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_contract, the TypeScript service against its own
 *        documented contract (V5 of round 1)
 *
 * Starts the TypeScript example and sends a valid, an empty, a non-numeric
 * and a 70000-byte input. A valid request must get 200 and a finite value
 * (and the stage formula when the README gives one); the others 400 with an
 * "error:" line. The Go value is logged as information only: the two
 * services are different ring stages and are not compared.
 *
 * @author midair <midair@localhost>
 */

#ifndef TE_TEST_NAME
#define TE_TEST_NAME    "ts_example/ts_contract"
#endif

#include "tsd_net.h"

int
main(int argc, char **argv)
{
    TEST_START;
    tsd_say("H3 start");
    TEST_STEP("Control: the contract check rejects planted wrong replies");
    tsd_contract_control("H3");
    if (tsd_build_gate("H3"))
        tsd_contract_run("H3");
    TSD_PASS("H3", "the four inputs follow the documented contract");
    TEST_SUCCESS;

cleanup:
    tsd_cleanup();
    TEST_END;
}
