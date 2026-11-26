/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_run_guess, each reference demo run alone with 42 3
 *        exits 0 with 4 stages (settles H1)
 *
 * Every reference (C++, Rust, Python, Go, C#) is started alone with the input
 * 42 3. Stdout, stderr, the exit code and the signal are saved. On any
 * failure the last 40 lines of stderr and the last stage line are logged.
 * H1 passes only when the exit code is 0 and 4 stage lines appear; a crash
 * is named with the language, the signal and the last stage reached, and a
 * libSystem, dlopen or wrong ELF class text in the output is named too.
 * After that (H4) the formula lines and the final value of the TypeScript
 * demo are compared with cpp-demo only; the other demos start at different
 * ring stages, so their finals are recorded as artifacts, not compared. RING_HOST and RING_PORT are set for every job. ./scripts/run.sh guess without arguments is run
 * too, to log its stage count and final value against the defaults of the
 * demo.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_run_guess"

#include "tsr.h"

/** Drop a leading program name, then indentation, trailing spaces and ends. */
#define NORM(_in, _out) \
    "sed -E 's/^[[:space:]]*[A-Za-z0-9_]+-demo: //; s/^[[:space:]]+//; " \
    "s/[[:space:]]+$//' " _in " | sed -e :a -e '/^[[:space:]]*$/{$d;N;ba}' " \
    "> " _out

/** The formula text of each stage line of a normalised file, sorted. */
#define CMPF(_in, _out) \
    "grep -E '^\\[.*\\] +hops=' " _in " | sed -E 's/^\\[[^]]*\\] +hops=[0-9]+ +" \
    "[-0-9.]+ +-> +[-0-9.]+ +//; s/[[:space:]]+$//' | sort > " _out

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
 * Name the first formula text that differs between the compared files @p a
 * (TypeScript) and @p b (reference). Writes the text to @p out.
 */
static void
first_diff(const char *a, const char *b, char *out, size_t size)
{
    char  ta[2000];
    char  tb[2000];
    char *pa = ta;
    char *pb = tb;
    int   n = 1;

    tsd_head(a, ta, sizeof(ta));
    tsd_head(b, tb, sizeof(tb));
    snprintf(out, size, "(no differing line found)");
    for (;; n++)
    {
        char *ea = strchr(pa, '\n');
        char *eb = strchr(pb, '\n');
        char  la[200];
        char  lb[200];

        snprintf(la, sizeof(la), "%.*s", ea != NULL ? (int)(ea - pa) :
                 (int)strlen(pa) > 190 ? 190 : (int)strlen(pa), pa);
        snprintf(lb, sizeof(lb), "%.*s", eb != NULL ? (int)(eb - pb) :
                 (int)strlen(pb) > 190 ? 190 : (int)strlen(pb), pb);
        if (strcmp(la, lb) != 0)
        {
            snprintf(out, size, "formula %d: typescript [%s] reference [%s]",
                     n, la, lb);
            return;
        }
        if (ea == NULL || eb == NULL)
            return;
        pa = ea + 1;
        pb = eb + 1;
    }
}

/** Value of a DEFAULT_ constant of ts/src/core.ts, or "unknown". */
static void
default_of(const char *name, char *out, size_t size)
{
    char cmd[300];

    snprintf(cmd, sizeof(cmd), "grep -hE 'const %s *=' ts/src/core.ts | head "
             "-n 1 | sed -E 's/.*= *//; s/[;[:space:]]+$//'", name);
    tsd_sh(tsd_src(), cmd, 10, "/tmp/ts_rg_def.log");
    tsd_head("/tmp/ts_rg_def.log", out, size);
    out[strcspn(out, "\n")] = '\0';
    if (out[0] == '\0')
        snprintf(out, size, "unknown");
}

int
main(int argc, char **argv)
{
    char             a[1201];
    char             cmd[1024];
    char             tsfin[64];
    const char      *src = tsd_src();
    int              ts_code;
    int              ts_stages;
    struct tsr_res   r[TSR_NREF];
    int              nok = 0;
    int              i;

    TEST_START;

    TEST_STEP("Set RING_HOST and RING_PORT for every run.sh job");
    setenv("RING_HOST", "127.0.0.1", 1);
    setenv("RING_PORT", "9100", 1);
    TEST_ARTIFACT("H1 run.sh guess needs RING_HOST and RING_PORT in the "
                  "environment only: the demo does not connect to a peer, "
                  "so no listener is started");

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

    TEST_STEP("Control: the runner reports a planted crash, a planted exit "
              "and a planted library error");
    {
        struct tsr_res c;

        tsr_install();
        tsd_sh("/", "python3 -I /tmp/ts_refrun.py 20 /tmp/ts_ref_c1.out "
               "/tmp/ts_ref_c1.err /tmp/ts_ref_c1.res -- python3 -I -c "
               "'import os,signal;print(\"[a] hops=1 v=2\",flush=True);"
               "os.kill(os.getpid(),signal.SIGSEGV)'", 30,
               "/tmp/ts_rg_c.log");
        tsr_read("c1", &c);
        if (!c.ran || c.sig != 11 || c.code != -1 || c.stages != 1 || c.ok)
            TEST_FAIL("H1 NOT SETTLED: the runner read a planted SIGSEGV as "
                      "exit %d signal %d stages %d", c.code, c.sig, c.stages);
        tsr_describe("planted", &c, a, sizeof(a));
        if (strstr(a, "SIGSEGV") == NULL || strstr(a, "after 1 stage") == NULL)
            TEST_FAIL("H1 NOT SETTLED: planted crash verdict is [%s]", a);
        tsd_say("H1 control: planted crash read as [%s]", a);

        tsd_sh("/", "python3 -I /tmp/ts_refrun.py 20 /tmp/ts_ref_c2.out "
               "/tmp/ts_ref_c2.err /tmp/ts_ref_c2.res -- python3 -I -c "
               "'import sys;print(\"[a] hops=1 v=2\");print(\"[b] hops=2 v=3\");"
               "print(\"[c] hops=3 v=3\");print(\"[d] hops=4 v=3\");"
               "print(\"ts-demo: result = 1.5000\")'", 30, "/tmp/ts_rg_c.log");
        tsr_read("c2", &c);
        if (!c.ok || strcmp(c.fin, "1.5000") != 0)
            TEST_FAIL("H1 NOT SETTLED: a planted good run was read as "
                      "exit %d stages %d final [%s]", c.code, c.stages, c.fin);
        tsd_sh("/", "python3 -I /tmp/ts_refrun.py 20 /tmp/ts_ref_c3.out "
               "/tmp/ts_ref_c3.err /tmp/ts_ref_c3.res -- python3 -I -c "
               "'import sys;print(\"dlopen failed: libSystem.dylib: wrong "
               "ELF class\",file=sys.stderr);sys.exit(3)'", 30,
               "/tmp/ts_rg_c.log");
        tsr_read("c3", &c);
        if (c.ok || c.code != 3 || c.sig != 0 ||
            strstr(c.tags, "libSystem") == NULL ||
            strstr(c.tags, "dlopen") == NULL ||
            strstr(c.tags, "wrong-ELF-class") == NULL)
            TEST_FAIL("H1 NOT SETTLED: planted library error read as exit "
                      "%d signal %d tags [%s]", c.code, c.sig, c.tags);
        tsd_say("H1 control: planted exit 3 and library error read as "
                "exit %d, tags [%s]", c.code, c.tags);
    }

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
            tsd_bad("H1", "reference not built", "reference not built: %s"
                    "(dist/bin of the project has no such file; build.sh "
                    "did not make it)", miss);
    }

    TEST_STEP("Run ./scripts/run.sh guess 42 3");
    snprintf(cmd, sizeof(cmd), "./scripts/run.sh guess 42 3 2>/tmp/ts_rg_ts.err "
             "> /tmp/ts_rg_ts.out");
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
    if (ts_stages != 4)
        tsd_bad("H1", "typescript stages", "%d stage line(s), want 4",
                ts_stages);
    if (strcmp(tsfin, "none") == 0)
        tsd_bad("H1", "typescript final value", "no final value printed");

    for (i = 0; i < TSR_NREF; i++)
    {
        char path[PATH_MAX];
        char tag[40];
        char what[400];

        TEST_STEP("Run the reference %s alone with 42 3", tsr_refs[i].name);
        memset(&r[i], 0, sizeof(r[i]));
        r[i].code = -1;
        snprintf(path, sizeof(path), "%s/%s", src, tsr_refs[i].file);
        if (access(path, R_OK) != 0)
        {
            tsd_bad("H1", tsr_refs[i].name, "%s is missing: %s",
                    tsr_refs[i].name, tsr_refs[i].file);
            continue;
        }
        snprintf(tag, sizeof(tag), "g_%s", tsr_refs[i].name);
        tsr_run(i, "42 3", tag, 40, "dist/lib", &r[i]);
        tsr_describe(tsr_refs[i].name, &r[i], what, sizeof(what));
        tsd_say("H1 reference %s: exit=%d signal=%s(%d) stages=%d last "
                "stage [%.120s] final [%s]", tsr_refs[i].name, r[i].code,
                tsr_signame(r[i].sig), r[i].sig, r[i].stages, r[i].last,
                r[i].fin);
        if (r[i].ok)
        {
            nok++;
            tsd_say("H1 PASS for %s: %s", tsr_refs[i].name, what);
            continue;
        }
        snprintf(path, sizeof(path), "/tmp/ts_ref_%s.err", tag);
        tsr_tail("H1 last 40 stderr lines", path, 40);
        tsd_say("H1 last stage line of %s: [%s]", tsr_refs[i].name,
                r[i].last[0] != '\0' ? r[i].last : "(no stage line)");
        tsd_bad("H1", what, "%s", what);
    }

    TEST_STEP("H1: every reference exited 0 with 4 stage lines");
    tsd_say("H1 %d of %d references exited 0 with 4 stage lines", nok,
            TSR_NREF);

    TEST_STEP("H4: record the final value of every demo as an artifact");
    for (i = 0; i < TSR_NREF; i++)
        TEST_ARTIFACT("H4 %s 42 3: exit %d, %d stage line(s), final [%s]",
                      tsr_refs[i].name, r[i].code, r[i].stages,
                      r[i].fin[0] != '\0' ? r[i].fin : "none");
    TEST_ARTIFACT("H4 typescript 42 3: exit %d, %d stage line(s), final [%s]",
                  ts_code, ts_stages, tsfin);

    TEST_STEP("H4: compare the formula lines and the final value of the "
              "TypeScript demo with cpp-demo only");
    {
        char tag[40];
        char d[601];

        /* Known-bad control: a planted different formula must be seen. */
        tsd_put("/tmp/ts_rg_k1", "(v*0.8+3)*go_weight\n");
        tsd_put("/tmp/ts_rg_k2", "(v*1.5+1)*cs_weight\n");
        if (tsd_sh("/", "cmp -s /tmp/ts_rg_k1 /tmp/ts_rg_k2", 10,
                   "/tmp/ts_rg_k.log") != 1)
            TEST_FAIL("H4 NOT SETTLED: the formula comparison does not see a "
                      "planted difference");
        if (!r[0].ok)
            tsd_say("H4 cpp-demo did not pass H1, so it is not compared");
        else
        {
            snprintf(tag, sizeof(tag), "g_%s", tsr_refs[0].name);
            snprintf(cmd, sizeof(cmd), NORM("/tmp/ts_ref_%s.out",
                     "/tmp/ts_rg_%s.norm") "; " CMPF("/tmp/ts_rg_%s.norm",
                     "/tmp/ts_rg_%s.cmp"), tag, tsr_refs[0].name,
                     tsr_refs[0].name, tsr_refs[0].name);
            tsd_sh("/", cmd, 10, "/tmp/ts_rg_n.log");
            snprintf(cmd, sizeof(cmd), "test -s /tmp/ts_rg_ts.cmp && cmp "
                     "/tmp/ts_rg_ts.cmp %s", ref_cmp(tsr_refs[0].name));
            if (tsd_sh("/", cmd, 10, "/tmp/ts_rg_cmp.log") == 0)
                tsd_say("H4 TypeScript formula lines equal cpp-demo");
            else
            {
                first_diff("/tmp/ts_rg_ts.cmp", ref_cmp(tsr_refs[0].name), d,
                           sizeof(d));
                tsd_bad("H4", "cpp-demo formula lines", "TypeScript and "
                        "cpp-demo print different formula lines: %s", d);
            }
            if (strcmp(tsfin, r[0].fin) != 0)
                tsd_bad("H4", "cpp-demo final value", "TypeScript final %s, "
                        "cpp-demo final %s", tsfin, r[0].fin);
            else
                tsd_say("H4 TypeScript and cpp-demo both end at %s", tsfin);
        }
    }

    TEST_STEP("H1: run ./scripts/run.sh guess with no arguments");
    {
        char dv[64];
        char dh[64];
        int  code;
        int  st;
        char fin[64];

        code = tsd_sh(src, "./scripts/run.sh guess > /tmp/ts_rg_def.out "
                      "2>&1", 60, "/tmp/ts_rg_d.log");
        tsd_sh("/", NORM("/tmp/ts_rg_def.out", "/tmp/ts_rg_def.norm"), 10,
               "/tmp/ts_rg_n.log");
        facts("/tmp/ts_rg_def.norm", &st, fin, sizeof(fin));
        default_of("DEFAULT_VALUE", dv, sizeof(dv));
        default_of("DEFAULT_HOPS", dh, sizeof(dh));
        tsd_say("H1 default run: exit=%d, %d stage line(s), final value %s; "
                "ts/src/core.ts has DEFAULT_VALUE=%s DEFAULT_HOPS=%s", code,
                st, fin, dv, dh);
        if (code != 0)
        {
            tsd_head("/tmp/ts_rg_def.out", a, 401);
            tsd_bad("H1", "default run", "exit %d: [%s]", code, a);
        }
        else if (atoi(dh) > 0 && st == atoi(dh) + 1)
            tsd_say("H1 explained: the default run is another input (value "
                    "%s, hops %s), so it has hops + 1 = %d stage lines and "
                    "the final value %s; the input 42 3 has 4 stages and "
                    "the value %s; the two runs are not comparable", dv, dh,
                    st, fin, tsfin);
        else
            tsd_say("H1 NOT explained: the default run has %d stage lines "
                    "while DEFAULT_HOPS is %s", st, dh);
    }

    TSD_FINISH("H1/H4");
    TEST_ARTIFACT("H4 the TypeScript run exited 0 with 4 stage lines and a "
                  "final value that equals cpp-demo, with the same formula "
                  "lines; all five demos exited 0 with 4 stage lines");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
