/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: ts_robust, the TypeScript example reads GUESS_ENDPOINT,
 *        has no hardcoded URL and ends in time against a silent peer
 *        (settles H3)
 *
 * The same test as ts_example/ts_robust, run in the webdeps group; the
 * verdict names which of the checks (a), (b), (c) and (d) failed.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/ts_robust"

#include "../ts_example/ts_robust.c"
