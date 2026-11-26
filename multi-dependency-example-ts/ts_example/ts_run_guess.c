/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_run_guess, the TypeScript demo prints the same ring
 *        result as a reference demo that runs all stages (settles H1)
 *
 * First checks that dist/bin/go-demo and dist/bin/cs-demo exist; a missing
 * one is named and the test fails with "reference not built". Then runs the
 * TypeScript demo and every reference for "guess 42 3" (the arguments of the
 * full ring: hops + 1 stages). Program names are removed from the outputs
 * and only the stage lines and the final value are compared. A reference
 * with fewer stages than the TypeScript demo, or one that fails, is
 * inconclusive, never passed. The test passes only when at least one
 * full-ring reference exists and the TypeScript stage lines and final value
 * equal it. Full-ring references that disagree with each other are logged
 * as a finding on the references and do not fail the TypeScript demo.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_run_guess"

#include "tsd.h"

#define HOPS    3
#define NREF    5

/** Drop a leading program name, then indentation, trailing spaces and ends. */
#define NORM(_in, _out) \
    "sed -E 's/^[[:space:]]*[A-Za-z0-9_]+-demo: //; s/^[[:space:]]+//; " \
    "s/[[:space:]]+$//' " _in " | sed -e :a -e '/^[[:space:]]*$/{$d;N;ba}' " \
    "> " _out

static const struct {
    const char *name;
    const char *file;   /**< checked with test -e, relative to the project */
    const char *cmd;    /**< run from the project root with "42 3" added */
} refs[NREF] = {
    { "cpp-demo",  "dist/bin/cpp-demo",
      "LD_LIBRARY_PATH=dist/lib ./dist/bin/cpp-demo" },
    { "rust-demo", "dist/bin/rust-demo",
      "LD_LIBRARY_PATH=dist/lib ./dist/bin/rust-demo" },
    { "python-demo", "python/demo.py", "python3 python/demo.py" },
    { "go-demo",   "dist/bin/go-demo",
      "LD_LIBRARY_PATH=dist/lib ./dist/bin/go-demo" },
    { "cs-demo",   "dist/bin/cs-demo",
      "LD_LIBRARY_PATH=dist/lib ./dist/bin/cs-demo" },
};

/** The stage lines and the final value of a normalised file. */
#define CMPF(_in, _out) \
    "grep -E '^\\[.*\\] +hops=|result *=' " _in " > " _out

/** Print the stage count and final value of a normalised file. */
static void
facts(const char *norm, int *stages, char *final, size_t size)
{
    char cmd[300];
    char buf[64];

    snprintf(cmd, sizeof(cmd), "grep -cE '^\\[.*\\] +hops=' %s > "
             "/tmp/ts_rg_f.txt; grep -E 'result *=' %s | tail -n 1 | "
             "sed -E 's/.*= *//' >> /tmp/ts_rg_f.txt", norm, norm);
    tsd_sh("/", cmd, 10, "/tmp/ts_rg_f.log");
    tsd_head("/tmp/ts_rg_f.txt", buf, sizeof(buf));
    *stages = atoi(buf);
    final[0] = '\0';
    if (strchr(buf, '\n') != NULL)
        snprintf(final, size, "%s", strchr(buf, '\n') + 1);
    final[strcspn(final, "\n")] = '\0';
    if (final[0] == '\0')
        snprintf(final, size, "none");
}

/** Path of the compared lines of a reference. */
static const char *
ref_cmp(const char *name)
{
    static char path[96];

    snprintf(path, sizeof(path), "/tmp/ts_rg_%s.cmp", name);
    return path;
}

/**
 * Name the first stage whose line differs between the compared files @p a
 * (TypeScript) and @p b (reference), with both lines; the final value line
 * is named "final value". Writes the text to @p out.
 */
static void
first_diff(const char *a, const char *b, char *out, size_t size)
{
    char  ta[2000];
    char  tb[2000];
    char *pa = ta;
    char *pb = tb;

    tsd_head(a, ta, sizeof(ta));
    tsd_head(b, tb, sizeof(tb));
    snprintf(out, size, "(no differing line found)");
    for (;;)
    {
        char *ea = strchr(pa, '\n');
        char *eb = strchr(pb, '\n');
        char  la[300];
        char  lb[300];

        snprintf(la, sizeof(la), "%.*s", ea != NULL ? (int)(ea - pa) : (int)strlen(pa) > 290 ? 290 : (int)strlen(pa), pa);
        snprintf(lb, sizeof(lb), "%.*s", eb != NULL ? (int)(eb - pb) : (int)strlen(pb) > 290 ? 290 : (int)strlen(pb), pb);
        if (strcmp(la, lb) != 0)
        {
            char stage[120] = "final value";
            const char *r = strstr(la[0] != '\0' ? la : lb, "] ");

            if (la[0] == '[' || lb[0] == '[')
                snprintf(stage, sizeof(stage), "%.*s",
                         r != NULL ? (int)(r - (la[0] != '\0' ? la : lb)) + 1 :
                         20, la[0] != '\0' ? la : lb);
            snprintf(out, size, "differs at stage %s: typescript [%s] "
                     "reference [%s]", stage, la, lb);
            return;
        }
        if (ea == NULL || eb == NULL)
            return;
        pa = ea + 1;
        pb = eb + 1;
    }
}

int
main(int argc, char **argv)
{
    char        a[1201];
    char        cmd[1024];
    char        log[96];
    char        fin[64];
    char        tsfin[64];
    const char *src = tsd_src();
    int         ts_code;
    int         ts_stages;
    int         code[NREF];
    bool        kept[NREF] = { false };
    int         nfull = 0;
    int         nmatch = 0;
    int         i;
    char        firstfull[64] = "";

    TEST_START;

    TEST_STEP("Control: cmp sees a planted difference");
    tsd_put("/tmp/ts_rg_c1", "result = 1.0000\n");
    tsd_put("/tmp/ts_rg_c2", "result = 1.0001\n");
    if (tsd_sh("/", "cmp -s /tmp/ts_rg_c1 /tmp/ts_rg_c2", 10,
               "/tmp/ts_rg_c.log") != 1)
        TEST_FAIL("H1 NOT SETTLED: the comparison does not see a difference");
    tsd_put("/tmp/ts_rg_c1", "ts-demo: result = 1.0000  \n\n\n");
    tsd_put("/tmp/ts_rg_c2", "cpp-demo: result = 1.0000\n");
    tsd_sh("/", NORM("/tmp/ts_rg_c1", "/tmp/ts_rg_c1.n") "; "
           NORM("/tmp/ts_rg_c2", "/tmp/ts_rg_c2.n"), 10, "/tmp/ts_rg_c.log");
    if (tsd_sh("/", "cmp -s /tmp/ts_rg_c1.n /tmp/ts_rg_c2.n", 10,
               "/tmp/ts_rg_c.log") != 0)
        TEST_FAIL("H1 NOT SETTLED: the normaliser keeps a program name or "
                  "trailing space");

    TEST_STEP("The project root");
    if (src[0] == '\0' || access(src, X_OK) != 0)
        TEST_FAIL("H1 FAIL: TE_TS_MDE_SRC is [%s], not a directory", src);

    TEST_STEP("Check that the Go and C# references are built");
    {
        static const char * const must[] = { "go-demo", "cs-demo" };
        char                      miss[160] = "";
        size_t                    k;

        for (k = 0; k < 2; k++)
        {
            char path[PATH_MAX];

            snprintf(path, sizeof(path), "%s/dist/bin/%s", src, must[k]);
            if (access(path, X_OK) != 0)
            {
                tsd_say("H1 reference %s: %s does not exist", must[k], path);
                strncat(miss, must[k], sizeof(miss) - strlen(miss) - 2);
                strncat(miss, " ", sizeof(miss) - strlen(miss) - 1);
            }
            else
                tsd_say("H1 reference %s exists: %s", must[k], path);
        }
        if (miss[0] != '\0')
            TEST_FAIL("H1 FAIL: reference not built: %s(dist/bin of the "
                      "project has no such file; build.sh did not make it)",
                      miss);
    }

    TEST_STEP("Run ./scripts/run.sh guess 42 %d", HOPS);
    snprintf(cmd, sizeof(cmd), "./scripts/run.sh guess 42 %d 2>/tmp/ts_rg_ts.err "
             "> /tmp/ts_rg_ts.out", HOPS);
    ts_code = tsd_sh(src, cmd, 60, "/tmp/ts_rg_ts.log");
    tsd_sh("/", NORM("/tmp/ts_rg_ts.out", "/tmp/ts_rg_ts.norm") "; "
           CMPF("/tmp/ts_rg_ts.norm", "/tmp/ts_rg_ts.cmp"), 10,
           "/tmp/ts_rg_n.log");
    facts("/tmp/ts_rg_ts.norm", &ts_stages, tsfin, sizeof(tsfin));
    tsd_say("H1 TypeScript: exit=%d stages=%d final=%s", ts_code, ts_stages,
            tsfin);
    if (ts_code != 0)
    {
        tsd_head("/tmp/ts_rg_ts.err", a, 401);
        tsd_bad("H1", "typescript run", "exit %d, stderr [%s]", ts_code, a);
    }
    if (ts_stages != HOPS + 1)
        tsd_bad("H1", "typescript stages", "%d stage line(s), want %d",
                ts_stages, HOPS + 1);

    for (i = 0; i < NREF; i++)
    {
        char path[PATH_MAX];
        char all[64];
        char l5[601];
        char hit[301];
        int  st;

        TEST_STEP("Run the reference %s with the same input", refs[i].name);
        snprintf(path, sizeof(path), "%s/%s", src, refs[i].file);
        code[i] = -1;
        if (access(path, R_OK) != 0)
        {
            tsd_say("H1 reference %s inconclusive: %s is missing",
                    refs[i].name, refs[i].file);
            continue;
        }
        snprintf(cmd, sizeof(cmd), "%s 42 %d 2>/tmp/ts_rg_%s.err "
                 "> /tmp/ts_rg_%s.out", refs[i].cmd, HOPS, refs[i].name,
                 refs[i].name);
        snprintf(log, sizeof(log), "/tmp/ts_rg_%s.log", refs[i].name);
        code[i] = tsd_sh(src, cmd, 60, log);
        snprintf(cmd, sizeof(cmd), NORM("/tmp/ts_rg_%s.out",
                 "/tmp/ts_rg_%s.norm") "; " CMPF("/tmp/ts_rg_%s.norm",
                 "/tmp/ts_rg_%s.cmp") "; cat /tmp/ts_rg_%s.out "
                 "/tmp/ts_rg_%s.err > /tmp/ts_rg_%s.all", refs[i].name,
                 refs[i].name, refs[i].name, refs[i].name, refs[i].name,
                 refs[i].name, refs[i].name);
        tsd_sh("/", cmd, 10, "/tmp/ts_rg_n.log");

        /* exit code and the last 5 log lines of every reference */
        snprintf(all, sizeof(all), "/tmp/ts_rg_%s.all", refs[i].name);
        snprintf(cmd, sizeof(cmd), "tail -n 5 %s", all);
        tsd_sh("/", cmd, 10, "/tmp/ts_rg_l5.log");
        tsd_head("/tmp/ts_rg_l5.log", l5, sizeof(l5));
        tsd_say("H1 reference %s: exit=%d, last 5 log lines: [%s]",
                refs[i].name, code[i], l5);

        snprintf(cmd, sizeof(cmd), "grep -m1 -iE 'libSystem|dlopen' %s",
                 all);
        if (tsd_sh("/", cmd, 10, "/tmp/ts_rg_hit.log") == 0)
        {
            char step[200];

            tsd_head("/tmp/ts_rg_hit.log", hit, sizeof(hit));
            hit[strcspn(hit, "\n")] = '\0';
            snprintf(step, sizeof(step), "%s library load error [%.80s], "
                     "H1 is open because of the build", refs[i].name, hit);
            tsd_bad("H1", step, "%s exit %d prints a libSystem or dlopen "
                    "error: [%s]; H1 is open because of the build, not "
                    "inconclusive", refs[i].name, code[i], hit);
            continue;
        }
        snprintf(log, sizeof(log), "/tmp/ts_rg_%s.norm", refs[i].name);
        facts(log, &st, fin, sizeof(fin));
        if (code[i] != 0)
            tsd_say("H1 reference %s ended with exit %d", refs[i].name,
                    code[i]);
        tsd_say("H1 reference %s: stages=%d final=%s%s", refs[i].name, st,
                fin, st == HOPS + 1 && strcmp(fin, "none") != 0 ?
                " (all stages)" : " (inconclusive: stopped short)");
        if (st == HOPS + 1 && strcmp(fin, "none") != 0)
        {
            kept[i] = true;
            nfull++;
        }
        else
            tsd_say("H1 reference %s inconclusive, not passed: %d stage(s)",
                    refs[i].name, st);
    }

    TEST_STEP("At least one reference ran all %d stages", HOPS + 1);
    if (nfull == 0)
        tsd_bad("H1", "reference", "no reference ran all %d stages with a "
                "final value; the TypeScript output has nothing to be "
                "compared with", HOPS + 1);
    else
        tsd_say("H1 %d reference(s) ran all %d stages", nfull, HOPS + 1);

    TEST_STEP("Compare the stage lines and the final value with every "
              "reference that ran all stages");
    for (i = 0; i < NREF; i++)
    {
        if (!kept[i])
            continue;
        snprintf(cmd, sizeof(cmd), "test -s /tmp/ts_rg_ts.cmp && cmp "
                 "/tmp/ts_rg_ts.cmp /tmp/ts_rg_%s.cmp", refs[i].name);
        if (tsd_sh("/", cmd, 10, "/tmp/ts_rg_cmp.log") == 0)
        {
            nmatch++;
            tsd_say("H1 TypeScript stage lines and final value equal %s",
                    refs[i].name);
        }
        else
        {
            char d[601];

            first_diff("/tmp/ts_rg_ts.cmp", ref_cmp(refs[i].name), d,
                       sizeof(d));
            tsd_bad("H1", "value differs", "TypeScript and %s print "
                    "different values: %s", refs[i].name, d);
        }
        if (firstfull[0] == '\0')
            snprintf(firstfull, sizeof(firstfull), "%s", refs[i].name);
        else
        {
            snprintf(cmd, sizeof(cmd), "cmp -s /tmp/ts_rg_%s.cmp "
                     "/tmp/ts_rg_%s.cmp", firstfull, refs[i].name);
            if (tsd_sh("/", cmd, 10, "/tmp/ts_rg_cmp.log") != 0)
                tsd_say("H1 FINDING on the references: %s and %s run all "
                        "stages and disagree with each other", firstfull,
                        refs[i].name);
        }
    }
    if (nfull > 0 && nmatch == 0)
    {
        tsd_head("/tmp/ts_rg_ts.cmp", a, 601);
        tsd_bad("H1", "stdout", "matches none of %d reference(s) that "
                "ran all stages; TypeScript [%s]", nfull, a);
    }

    TSD_PASS("H1", "the TypeScript stage lines and final value equal a "
             "reference that ran all stages");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
