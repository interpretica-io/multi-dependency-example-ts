/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_build, ./build.sh builds the example (settles H2)
 *
 * Runs ./build.sh in the project root with output in /tmp/ts_build.log.
 * On a failure the last 2000 bytes of the log and the exit code are in the
 * error message. It passes on exit 0 and when ts/dist/main.js exists, and
 * then leaves a marker for the later tests. A planted failing script
 * checks that a non-zero exit is seen with its output.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_build"

#include "tsd.h"

int
main(int argc, char **argv)
{
    char        tail[2001];
    char        main_js[PATH_MAX];
    const char *src = tsd_src();
    int         code;
    long long   t0;

    TEST_START;
    tsd_say("H2 start");
    unlink(TSD_BUILD_MARK);

    TEST_STEP("Control: a command that fails is seen with exit code and text");
    code = tsd_sh("/", "echo planted-failure >&2; exit 3", 30,
                  "/tmp/ts_build_ctl.log");
    tsd_tail("/tmp/ts_build_ctl.log", tail, sizeof(tail));
    if (code != 3 || strstr(tail, "planted-failure") == NULL)
        tsd_bad("H2", "control", "exit code %d, text [%s]; expected 3 and "
                "planted-failure", code, tail);
    else
        tsd_say("H2 control exit=%d: [%.400s]", code, tail);

    TEST_STEP("Run ./build.sh in %s", src);
    t0 = tsd_ms();
    code = tsd_sh(src, "./build.sh", 540, "/tmp/ts_build.log");
    tsd_tail("/tmp/ts_build.log", tail, sizeof(tail));
    tsd_say("H2 build exit=%d after %lld ms (124 is the 540 s limit), last "
            "400 bytes of /tmp/ts_build.log: [%.400s]", code, tsd_ms() - t0,
            tail + (strlen(tail) > 400 ? strlen(tail) - 400 : 0));
    if (code != 0)
        tsd_flag("H2 build exit not 0");
    snprintf(main_js, sizeof(main_js), "%s/ts/dist/main.js", src);
    if (access(main_js, R_OK) != 0)
    {
        tsd_say("H2 dist/main.js missing: %s does not exist", main_js);
        tsd_flag("H2 dist/main.js missing");
    }
    else
        tsd_say("H2 dist/main.js exists: %s", main_js);
    if (tsd_nfail == 0)
    {
        FILE *mk = fopen(TSD_BUILD_MARK, "w");

        if (mk != NULL)
        {
            fprintf(mk, "built\n");
            fclose(mk);
        }
    }
    TSD_FINISH("H2");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
