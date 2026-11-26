/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h2_build_guess, run.sh guess with RING_HOST and
 *        RING_PORT set exits 0 with 4 stage lines and a final value
 *        (settles H1)
 *
 * Runs `scripts/run.sh guess` for 30 seconds with output in a file, then
 * `scripts/run.sh guess 42 3`, then every reference demo alone with 42 3.
 * RING_HOST=127.0.0.1 and RING_PORT=9100 are set for every job. The final
 * values are not compared, the demos start at different ring stages; the
 * stage count and the formula text of the stage lines are compared with the
 * TypeScript demo. Planted outputs check the parser and the comparison.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h2_build_guess"

#include "tsr.h"

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

/** Formula text of each stage line of @p file, sorted, into @p out. */
static void
formulas(const char *file, const char *out)
{
    char cmd[600];

    snprintf(cmd, sizeof(cmd), "grep -E '^[[:space:]]*(([A-Za-z0-9_]+-demo): "
             "*)?\\[.*\\] +hops=' '%s' | sed -E 's/^[[:space:]]*"
             "([A-Za-z0-9_]+-demo: *)?//; s/^\\[[^]]*\\] +hops=[0-9]+ +"
             "[-0-9.]+ +-> +[-0-9.]+ +//; s/[[:space:]]+$//' | sort > '%s'",
             file, out);
    tsd_sh("/", cmd, 10, "/tmp/ts_h2_fm.log");
}

int
main(int argc, char **argv)
{
    char        text[401];
    char        fv[64];
    char        tsv[64];
    char        rv[64];
    char        ref[64] = "";
    char        refname[32] = "";
    char        tag[96];
    int         i;
    const char *src = tsd_src();
    int         code;
    long long   t0;

    TEST_START;
    tsd_say("H1 start");
    setenv("RING_HOST", "127.0.0.1", 1);
    setenv("RING_PORT", "9100", 1);

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
    for (i = 0; i < TSR_NREF; i++)
    {
        struct tsr_res r;
        char           tag[48];
        char           what[400];
        char           errf[64];

        snprintf(tag, sizeof(tag), "h2_%s", tsr_refs[i].name);
        tsr_run(i, "42 3", tag, 40, "dist/lib", &r);
        tsr_describe(tsr_refs[i].name, &r, what, sizeof(what));
        tsd_say("H1 reference %s: exit=%d signal=%s(%d) stages=%d last "
                "stage [%.120s] final=[%s]", tsr_refs[i].name, r.code,
                tsr_signame(r.sig), r.sig, r.stages, r.last, r.fin);
        if (!r.ok)
        {
            snprintf(errf, sizeof(errf), "/tmp/ts_ref_%s.err", tag);
            tsr_tail("H1 last 40 stderr lines", errf, 40);
            tsd_say("H1 reference %s did not finish: %s", tsr_refs[i].name,
                    what);
            continue;
        }
        if (ref[0] == '\0')
        {
            snprintf(ref, sizeof(ref), "%s", r.fin);
            snprintf(refname, sizeof(refname), "%s", tsr_refs[i].name);
        }
    }

    TEST_STEP("Compare the stage count and formula text with the TypeScript "
              "demo");
    if (ref[0] == '\0')
        tsd_bad("H1", "no reference finished", "H1 failed: no reference "
                "exited 0 with 4 stage lines, so no stage text was compared");
    else
    {
        tsd_say("H1 finished reference %s: final value [%s]; the TypeScript "
                "value [%s] differs by design", refname, ref, tsv);
        formulas("/tmp/ts_h2_ts.out", "/tmp/ts_h2_fm_ts.txt");
        snprintf(tag, sizeof(tag), "/tmp/ts_ref_h2_%s.out", refname);
        formulas(tag, "/tmp/ts_h2_fm_ref.txt");
        if (stage_count("/tmp/ts_h2_ts.out") != 4)
            tsd_bad("H1", "typescript stages", "%d stage line(s), want 4",
                    stage_count("/tmp/ts_h2_ts.out"));
        if (tsd_sh("/", "test -s /tmp/ts_h2_fm_ts.txt && cmp "
                   "/tmp/ts_h2_fm_ts.txt /tmp/ts_h2_fm_ref.txt", 10,
                   "/tmp/ts_h2_cmp.log") != 0)
            tsd_bad("H1", "formula text", "the formula text of the stage "
                    "lines of TypeScript and %s differs", refname);
        else
            tsd_say("H1 formula text of TypeScript and %s is equal", refname);
    }

    TSD_FINISH("H1");
    TEST_ARTIFACT("H1 run.sh guess exited 0 with 4 stage lines and a final "
                  "value with RING_HOST and RING_PORT set; stage count and "
                  "formula text match a reference");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
