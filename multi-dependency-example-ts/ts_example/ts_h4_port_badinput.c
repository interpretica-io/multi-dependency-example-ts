/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h4_port_badinput, address, port, bad input, exit
 *        code (settles H4)
 *
 * Starts node dist/main.js with EXAMPLE_PORT=9101 and EXAMPLE_HOST=
 * 127.0.0.1 and requires, with tapi_netexpose, that it listens on
 * 127.0.0.1:9101 only; then with both unset on 127.0.0.1:9100. Empty,
 * non-numeric, 100000-character and out-of-range input must get a 4xx
 * reply and leave the process alive; SIGTERM and SIGINT must give exit
 * code 0. Runs only after ts_build passed (else "blocked by H2").
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h4_port_badinput"

#include "tsd_net.h"

int
main(int argc, char **argv)
{
    TEST_START;
    TSD_NEED_BUILD("H4");
    tsd_h4_scenario("H4", false);
    TEST_SUCCESS;

cleanup:
    tsd_cleanup();
    TEST_END;
}
