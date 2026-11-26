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
    char        text[401];
    const char *src = tsd_src();
    int         code;
    long long   t0;

    TEST_START;
    tsd_say("H2 start");

    TEST_STEP("Control: an early non-zero exit is not taken for a server");
    code = tsd_sh("/", "echo planted >&2; exit 2", 30, "/tmp/ts_h2_ctl.log");
    if (code == 0 || code == 124)
        tsd_bad("H2", "control", "planted exit 2 was read as %d", code);
    else
        tsd_say("H2 control exit=%d: planted early failure seen", code);

    TEST_STEP("Run scripts/run.sh guess for 30 s in %s", src);
    t0 = tsd_ms();
    code = tsd_sh(src, "scripts/run.sh guess", 30, "/tmp/ts_h2_guess.log");
    tsd_head("/tmp/ts_h2_guess.log", text, sizeof(text));
    (void)!system("pkill -f 'node dist/main.js' > /dev/null 2>&1");
    if (code != 0 && code != 124)
        tsd_bad("H2", "guess alive", "scripts/run.sh guess exit=%d after "
                "%lld ms before the 30 s limit: [%.400s]", code,
                tsd_ms() - t0, text);
    else
        tsd_say("H2 guess alive: exit=%d after %lld ms (124: still running "
                "at the 30 s limit; 0: ended cleanly): [%.400s]", code,
                tsd_ms() - t0, text);
    TSD_FINISH("H2");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
