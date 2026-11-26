/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h2_build_guess, scripts/run.sh guess starts (H2)
 *
 * Runs `scripts/run.sh guess` for 30 seconds with output in a file. It
 * passes when the command does not exit non-zero before the limit (the
 * limit itself, exit code 124, is the expected end of a server). The file
 * text is logged. A planted command that exits 2 at once checks that an
 * early non-zero exit is seen.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h2_build_guess"

#include "tsd.h"

int
main(int argc, char **argv)
{
    char        text[3001];
    const char *src = tsd_src();
    int         code;
    long long   t0;

    TEST_START;

    TEST_STEP("Control: an early non-zero exit is not taken for a server");
    code = tsd_sh("/", "echo planted >&2; exit 2", 30, "/tmp/ts_h2_ctl.log");
    if (code == 0 || code == 124)
        TEST_FAIL("H2 control failed: planted exit 2 was read as %d", code);

    TEST_STEP("Run scripts/run.sh guess for 30 s in %s", src);
    t0 = tsd_ms();
    code = tsd_sh(src, "scripts/run.sh guess", 30, "/tmp/ts_h2_guess.log");
    tsd_head("/tmp/ts_h2_guess.log", text, sizeof(text));
    RING("H2 scripts/run.sh guess exit code %d after %lld ms; output: [%s]",
         code, tsd_ms() - t0, text);
    if (code != 0 && code != 124)
    {
        RING_VERDICT("H2 guess exited with %d before the limit", code);
        TEST_FAIL("H2 scripts/run.sh guess exited with %d after %lld ms "
                  "before the 30 s limit; output: [%s]", code,
                  tsd_ms() - t0, text);
    }
    RING_VERDICT("H2 guess ran (exit code %d, 124 is the time limit); "
                 "output [%.300s]", code, text);
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
