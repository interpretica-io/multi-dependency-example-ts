/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h2_build_guess, scripts/run.sh guess starts and
 *        prints the right ring value (settles H1)
 *
 * Runs `scripts/run.sh guess` for 30 seconds with output in a file. It
 * fails when the command exits non-zero before the limit (exit code 124 is
 * the limit) or when no final ring value can be parsed from its output.
 * Then runs `scripts/run.sh guess 42 3` and every reference demo with the
 * same arguments; the final ring value of the TypeScript run must equal the
 * final value of the first reference that ran all 4 stages. An exit code
 * of 0 or a running process alone does not pass. Planted outputs check the
 * parser and the comparison, and a planted exit 2 checks that an early
 * non-zero exit is seen.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h2_build_guess"

#include "tsd.h"

/** Shell text that prints the final ring value of the file $1 or nothing. */
#define FINAL_OF    "grep -E 'result *=' '%s' | tail -n 1 | sed -E 's/.*= *//; s/[[:space:]]+$//'"
#define STAGES_OF   "grep -cE '^[[:space:]]*(([A-Za-z0-9_]+-demo): *)?\\[.*\\] +hops=' '%s'"

/** Final value of @p file into @p out (empty when none). */
static void
final_value(const char *file, char *out, size_t size)
{
    char cmd[400];

    snprintf(cmd, sizeof(cmd), FINAL_OF, file);
    tsd_sh("/", cmd, 10, "/tmp/ts_h2_fv.log");
    tsd_head("/tmp/ts_h2_fv.log", out, size);
    out[strcspn(out, "\n")] = '\0';
}

/** Number of stage lines of @p file. */
static int
stage_count(const char *file)
{
    char cmd[400];
    char buf[32];

    snprintf(cmd, sizeof(cmd), STAGES_OF, file);
    tsd_sh("/", cmd, 10, "/tmp/ts_h2_sc.log");
    tsd_head("/tmp/ts_h2_sc.log", buf, sizeof(buf));
    return atoi(buf);
}

static const char *const refs[5][3] = {
    { "go-demo", "dist/bin/go-demo", "./dist/bin/go-demo" },
    { "cs-demo", "dist/bin/cs-demo", "./dist/bin/cs-demo" },
    { "cpp-demo", "dist/bin/cpp-demo", "./dist/bin/cpp-demo" },
    { "rust-demo", "dist/bin/rust-demo", "./dist/bin/rust-demo" },
    { "python-demo", "python/demo.py", "python3 python/demo.py" },
};

int
main(int argc, char **argv)
{
    char        text[401];
    char        fv[64];
    char        tsv[64];
    char        rv[64];
    char        ref[64] = "";
    char        refname[32] = "";
    char        cmd[600];
    int         rcode;
    int         i;
    const char *src = tsd_src();
    int         code;
    long long   t0;

    TEST_START;
    tsd_say("H1 start");

    TEST_STEP("Control: an early non-zero exit is not taken for a server");
    code = tsd_sh("/", "echo planted >&2; exit 2", 30, "/tmp/ts_h2_ctl.log");
    if (code == 0 || code == 124)
        tsd_bad("H1", "control", "planted exit 2 was read as %d", code);
    else
        tsd_say("H1 control exit=%d: planted early failure seen", code);

    TEST_STEP("Control: the value parser reads a planted result and sees a "
              "wrong one");
    tsd_put("/tmp/ts_h2_c1", "[a] hops=1 v=2\nts-demo: result = 38.9640\n");
    tsd_put("/tmp/ts_h2_c2", "[a] hops=1 v=2\ncpp-demo: result = 66.5600\n");
    final_value("/tmp/ts_h2_c1", fv, sizeof(fv));
    final_value("/tmp/ts_h2_c2", rv, sizeof(rv));
    if (strcmp(fv, "38.9640") != 0 || strcmp(rv, "66.5600") != 0 ||
        stage_count("/tmp/ts_h2_c1") != 1)
        TEST_FAIL("H1 NOT SETTLED: the value parser read [%s] and [%s] "
                  "from planted outputs", fv, rv);
    tsd_say("H1 control: planted values read as [%s] and [%s], different",
            fv, rv);

    TEST_STEP("Run scripts/run.sh guess for 30 s in %s", src);
    t0 = tsd_ms();
    code = tsd_sh(src, "scripts/run.sh guess", 30, "/tmp/ts_h2_guess.log");
    tsd_head("/tmp/ts_h2_guess.log", text, sizeof(text));
    (void)!system("pkill -f 'node dist/main.js' > /dev/null 2>&1");
    if (code != 0 && code != 124)
        tsd_bad("H1", "guess alive", "scripts/run.sh guess exit=%d after "
                "%lld ms before the 30 s limit: [%.400s]", code,
                tsd_ms() - t0, text);
    else
        tsd_say("H1 guess alive: exit=%d after %lld ms (124: still running "
                "at the 30 s limit; 0: ended cleanly): [%.400s]", code,
                tsd_ms() - t0, text);
    TEST_STEP("The default run printed a final ring value");
    final_value("/tmp/ts_h2_guess.log", fv, sizeof(fv));
    if (fv[0] == '\0')
        tsd_bad("H1", "final value", "the output of run.sh guess holds no "
                "final ring value (exit %d); exit 0 alone is not a pass",
                code);
    else
        tsd_say("H1 default run: %d stage line(s), final value %s",
                stage_count("/tmp/ts_h2_guess.log"), fv);

    TEST_STEP("Run guess 42 3 and the references with the same input");
    code = tsd_sh(src, "scripts/run.sh guess 42 3 > /tmp/ts_h2_ts.out 2>&1",
                  60, "/tmp/ts_h2_ts.log");
    final_value("/tmp/ts_h2_ts.out", tsv, sizeof(tsv));
    tsd_say("H1 TypeScript guess 42 3: exit=%d, %d stage line(s), final "
            "value [%s]", code, stage_count("/tmp/ts_h2_ts.out"), tsv);
    if (code != 0 || tsv[0] == '\0')
        tsd_bad("H1", "typescript guess 42 3", "exit %d, final value [%s]",
                code, tsv);
    for (i = 0; i < 5; i++)
    {
        char out[64];
        char l5[401];

        snprintf(out, sizeof(out), "/tmp/ts_h2_%s.out", refs[i][0]);
        snprintf(cmd, sizeof(cmd), "LD_LIBRARY_PATH=dist/lib %s 42 3 > %s "
                 "2>&1", refs[i][2], out);
        rcode = tsd_sh(src, cmd, 60, "/tmp/ts_h2_ref.log");
        final_value(out, rv, sizeof(rv));
        snprintf(cmd, sizeof(cmd), "tail -n 5 %s", out);
        tsd_sh("/", cmd, 10, "/tmp/ts_h2_l5.log");
        tsd_head("/tmp/ts_h2_l5.log", l5, sizeof(l5));
        tsd_say("H1 reference %s: exit=%d stages=%d final=[%s] last "
                "lines [%s]", refs[i][0], rcode, stage_count(out), rv, l5);
        if (ref[0] == '\0' && stage_count(out) == 4 && rv[0] != '\0')
        {
            snprintf(ref, sizeof(ref), "%s", rv);
            snprintf(refname, sizeof(refname), "%s", refs[i][0]);
        }
    }

    TEST_STEP("Compare the final ring value with the reference");
    if (ref[0] == '\0')
        tsd_bad("H1", "reference", "no reference ran all 4 stages, so the "
                "ring value has nothing to be compared with (H1 open)");
    else if (strcmp(ref, tsv) != 0)
        tsd_bad("H1", "ring value", "TypeScript final value [%s] differs "
                "from %s [%s]", tsv, refname, ref);
    else
        tsd_say("H1 ring value: TypeScript [%s] equals %s [%s]", tsv,
                refname, ref);
    
    TSD_PASS("H1", "run.sh guess printed a final ring value equal to the "
             "reference ring value");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
