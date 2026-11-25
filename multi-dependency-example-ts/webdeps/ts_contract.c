/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: ts_contract, the TypeScript example gives the same answer
 *        as the Go and C# examples (settles H2)
 *
 * The same test as ts_example/ts_contract, run in the webdeps group: a
 * missing build reads "H1 build missing", a service that does not open its
 * port within 10 s reads "start-up fault", and a different answer reads
 * "mismatch" with both values.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/ts_contract"

#include "../ts_example/ts_contract.c"
