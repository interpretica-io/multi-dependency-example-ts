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
    unlink(TSD_BUILD_MARK);

    TEST_STEP("Control: a command that fails is seen with exit code and text");
    code = tsd_sh("/", "echo planted-failure >&2; exit 3", 30,
                  "/tmp/ts_build_ctl.log");
    tsd_tail("/tmp/ts_build_ctl.log", tail, sizeof(tail));
    if (code != 3 || strstr(tail, "planted-failure") == NULL)
        TEST_FAIL("H2 control failed: exit code %d, text [%s]; expected 3 "
                  "and planted-failure", code, tail);

    TEST_STEP("Run ./build.sh in %s", src);
    t0 = tsd_ms();
    code = tsd_sh(src, "./build.sh", 540, "/tmp/ts_build.log");
    tsd_tail("/tmp/ts_build.log", tail, sizeof(tail));
    RING("H2 ./build.sh exit code %d after %lld ms; last 2000 bytes of "
         "/tmp/ts_build.log: %s", code, tsd_ms() - t0, tail);
    if (code != 0)
    {
        RING_VERDICT("H2 build failed with exit code %d", code);
        TEST_FAIL("H2 ./build.sh exit code %d (124 means the 540 s limit); "
                  "last 2000 bytes of /tmp/ts_build.log: [%s]", code, tail);
    }
    snprintf(main_js, sizeof(main_js), "%s/ts/dist/main.js", src);
    if (access(main_js, R_OK) != 0)
    {
        RING_VERDICT("H2 build exit 0 but no dist/main.js");
        TEST_FAIL("H2 ./build.sh exit code 0 but %s does not exist; last "
                  "2000 bytes of /tmp/ts_build.log: [%s]", main_js, tail);
    }
    {
        FILE *mk = fopen(TSD_BUILD_MARK, "w");

        if (mk != NULL)
        {
            fprintf(mk, "built\n");
            fclose(mk);
        }
    }
    RING_VERDICT("H2 build passed: exit code 0 and %s exists", main_js);
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
