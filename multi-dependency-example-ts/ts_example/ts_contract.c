/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_contract, same reply as the Go example (settles H3)
 *
 * Runs only after ts_build passed; when it did not, logs "blocked by H2"
 * and fails. Starts the Go and the TypeScript example, sends a valid, a
 * low, a high and a repeated guess, saves both replies to files and
 * compares them byte for byte; both replies are in the error on a mismatch.
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
    tsd_say("H5 start");
    if (tsd_build_gate("H3"))
    {
        tsd_h3_control("H3");
        tsd_h3_collect("H3");
        if (tsd_h3_files_exist())
            tsd_h3_compare("H3");
        else
            tsd_flag("no reply files");
    }
    TSD_FINISH("H3");
    TEST_SUCCESS;

cleanup:
    tsd_cleanup();
    TEST_END;
}
