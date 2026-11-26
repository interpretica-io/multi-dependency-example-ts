/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_run_guess, the TypeScript example gives the result
 *        of the C++ demo (settles H2)
 *
 * Runs ./scripts/run.sh guess 42 3 and the existing demo for the same input
 * (dist/bin/cpp-demo, which enters the ring at the same stage; otherwise
 * dist/bin/rust-demo) and compares stdout and exit code. The name of each
 * demo in front of its lines and the indentation are removed first, since
 * they differ by design. Fails on any other difference.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_run_guess"

#include "tsd.h"

#define NORM "sed -E 's/^[[:space:]]*[a-z]+-demo: //; s/^[[:space:]]+//'"

int
main(int argc, char **argv)
{
    char        a[401];
    char        b[401];
    char        cmd[2048];
    const char *src = tsd_src();
    const char *ref = "cpp-demo";
    int         ts_code;
    int         ref_code;

    TEST_START;

    TEST_STEP("Control: cmp sees a planted difference");
    tsd_put("/tmp/ts_rg_c1", "result = 1.0000\n");
    tsd_put("/tmp/ts_rg_c2", "result = 1.0001\n");
    if (tsd_sh("/", "cmp -s /tmp/ts_rg_c1 /tmp/ts_rg_c2", 10,
               "/tmp/ts_rg_c.log") != 1)
        TEST_FAIL("H2 NOT SETTLED: the comparison does not see a difference");

    TEST_STEP("The project root and the reference demo exist");
    if (src[0] == '\0' || access(src, X_OK) != 0)
        TEST_FAIL("H2 FAIL: TE_TS_MDE_SRC is [%s], not a directory", src);
    snprintf(cmd, sizeof(cmd), "%s/dist/bin/cpp-demo", src);
    if (access(cmd, X_OK) != 0)
    {
        ref = "rust-demo";
        snprintf(cmd, sizeof(cmd), "%s/dist/bin/rust-demo", src);
    }
    if (access(cmd, X_OK) != 0)
        TEST_FAIL("H2 NOT SETTLED: neither dist/bin/cpp-demo nor "
                  "dist/bin/rust-demo exists under %s (run ts_build)", src);
    tsd_say("H2 reference demo: %s", ref);

    TEST_STEP("Run ./scripts/run.sh guess 42 3");
    snprintf(cmd, sizeof(cmd), "./scripts/run.sh guess 42 3 2>/tmp/ts_rg_ts.err "
             "> /tmp/ts_rg_ts.out; echo $? > /tmp/ts_rg_ts.code");
    ts_code = tsd_sh(src, cmd, 60, "/tmp/ts_rg_ts.log");
    tsd_head("/tmp/ts_rg_ts.code", a, sizeof(a));
    ts_code = atoi(a);
    tsd_head("/tmp/ts_rg_ts.out", a, sizeof(a));
    tsd_say("H2 run.sh guess exit=%d stdout [%s]", ts_code, a);

    TEST_STEP("Run %s 42 3", ref);
    snprintf(cmd, sizeof(cmd), "LD_LIBRARY_PATH=dist/lib:$LD_LIBRARY_PATH "
             "./dist/bin/%s 42 3 2>/tmp/ts_rg_ref.err > /tmp/ts_rg_ref.out; "
             "echo $? > /tmp/ts_rg_ref.code", ref);
    tsd_sh(src, cmd, 60, "/tmp/ts_rg_ref.log");
    tsd_head("/tmp/ts_rg_ref.code", b, sizeof(b));
    ref_code = atoi(b);
    tsd_head("/tmp/ts_rg_ref.out", b, sizeof(b));
    tsd_say("H2 %s exit=%d stdout [%s]", ref, ref_code, b);

    TEST_STEP("Compare exit code and stdout");
    if (ts_code != ref_code)
        tsd_bad("H2", "exit code", "run.sh guess %d, %s %d", ts_code, ref,
                ref_code);
    tsd_sh("/", NORM " /tmp/ts_rg_ts.out > /tmp/ts_rg_ts.norm; " NORM
           " /tmp/ts_rg_ref.out > /tmp/ts_rg_ref.norm", 10,
           "/tmp/ts_rg_n.log");
    if (tsd_sh("/", "test -s /tmp/ts_rg_ts.norm && cmp /tmp/ts_rg_ts.norm "
               "/tmp/ts_rg_ref.norm", 10, "/tmp/ts_rg_cmp.log") != 0)
    {
        tsd_head("/tmp/ts_rg_ts.norm", a, sizeof(a));
        tsd_head("/tmp/ts_rg_ref.norm", b, sizeof(b));
        tsd_bad("H2", "stdout", "differs or is empty; run.sh [%s] %s [%s]",
                a, ref, b);
    }
    TSD_FINISH("H2");
    TEST_VERDICT("H2 PASS: run.sh guess 42 3 and %s give the same stdout "
                 "and exit code %d", ref, ts_code);
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
