/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_build, ./build.sh makes the TypeScript example (settles H1)
 *
 * Runs ./build.sh in the project root (TE_TS_MDE_SRC), output in
 * /tmp/ts_build.log. Passes only on exit code 0 and when the compiled
 * output, ts/dist with its .js files, exists. A planted failing command
 * checks that the helper sees a non-zero exit with its text.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_build"

#include "tsd.h"

int
main(int argc, char **argv)
{
    char        tail[2001];
    char        path[PATH_MAX];
    const char *src = tsd_src();
    int         code;
    long long   t0;
    bool        out_ok = false;

    TEST_START;
    unlink(TSD_BUILD_MARK);

    TEST_STEP("Control: a failing command is seen with its exit code and text");
    code = tsd_sh("/", "echo planted-failure >&2; exit 3", 30,
                  "/tmp/ts_build_ctl.log");
    tsd_tail("/tmp/ts_build_ctl.log", tail, sizeof(tail));
    if (code != 3 || strstr(tail, "planted-failure") == NULL)
        tsd_bad("H1", "control", "exit %d, text [%.300s]; expected 3 and "
                "planted-failure", code, tail);
    else
        tsd_say("H1 control ok: exit=%d", code);

    TEST_STEP("The project root is known");
    if (src[0] == '\0' || access(src, X_OK) != 0)
    {
        tsd_bad("H1", "project", "TE_TS_MDE_SRC is [%s], not a directory", src);
        TSD_FINISH("H1");
    }

    TEST_STEP("Run ./build.sh in %s", src);
    t0 = tsd_ms();
    code = tsd_sh(src, "./build.sh", 540, "/tmp/ts_build.log");
    tsd_tail("/tmp/ts_build.log", tail, sizeof(tail));
    if (strlen(tail) > 400)
        memmove(tail, tail + strlen(tail) - 400, 401);
    if (code != 0)
        tsd_bad("H1", "build", "./build.sh exit=%d after %lld ms (124 is "
                "the limit); last output [%s]", code, tsd_ms() - t0, tail);
    else
        tsd_say("H1 build ok: exit=0 after %lld ms", tsd_ms() - t0);

    TEST_STEP("The compiled TypeScript output exists");
    snprintf(path, sizeof(path), "%s/ts/dist", src);
    {
        char cmd[PATH_MAX + 80];

        snprintf(cmd, sizeof(cmd), "ls '%s'/*.js", path);
        out_ok = access(path, R_OK | X_OK) == 0 &&
                 tsd_sh("/", cmd, 10, "/tmp/ts_build_ls.log") == 0;
    }
    if (!out_ok)
        tsd_bad("H1", "output", "%s is missing or has no .js file", path);
    else
    {
        tsd_head("/tmp/ts_build_ls.log", tail, 401);
        tsd_say("H1 output exists: [%s]", tail);
    }

    if (tsd_nfail == 0)
        tsd_put(TSD_BUILD_MARK, "built\n");
    tsd_say("H1 PASS: ./build.sh exited 0 and %s exists", path);
    TSD_PASS("H1 H4", "build ok and reported as passed");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
