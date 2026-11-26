/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_run_guess, the TypeScript demo prints the same ring
 *        result as the other demos (settles H1)
 *
 * Runs every reference demo that exists (C++, Rust, Python, and Go or C#
 * when the project has them) for "guess 42 3" first and keeps its exit code.
 * A reference that is missing or exits non-zero is dropped and logged. The
 * outputs are normalised (program name and indentation in front of a line,
 * trailing spaces and trailing line ends removed). A reference is "full
 * ring" when it ran hops + 1 stages. The TypeScript output, from
 * ./scripts/run.sh guess 42 3, must equal at least one full-ring reference
 * with the same exit code. A short reference (the C++ demo stops after
 * stage 1) is logged in full and is not read as a TypeScript fault.
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
    { "go-demo",   "dist/bin/go-demo", "./dist/bin/go-demo" },
    { "cs-demo",   "dist/bin/cs-demo", "./dist/bin/cs-demo" },
};

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

    for (i = 0; i < NREF; i++)
    {
        char path[PATH_MAX];

        TEST_STEP("Run the reference %s first", refs[i].name);
        snprintf(path, sizeof(path), "%s/%s", src, refs[i].file);
        code[i] = -1;
        if (access(path, R_OK) != 0)
        {
            tsd_say("H1 reference %s dropped: %s is missing", refs[i].name,
                    refs[i].file);
            continue;
        }
        snprintf(cmd, sizeof(cmd), "%s 42 %d 2>/tmp/ts_rg_%s.err "
                 "> /tmp/ts_rg_%s.out", refs[i].cmd, HOPS, refs[i].name,
                 refs[i].name);
        snprintf(log, sizeof(log), "/tmp/ts_rg_%s.log", refs[i].name);
        code[i] = tsd_sh(src, cmd, 60, log);
        snprintf(cmd, sizeof(cmd), NORM("/tmp/ts_rg_%s.out",
                 "/tmp/ts_rg_%s.norm"), refs[i].name, refs[i].name);
        tsd_sh("/", cmd, 10, "/tmp/ts_rg_n.log");
        snprintf(log, sizeof(log), "/tmp/ts_rg_%s.out", refs[i].name);
        tsd_head(log, a, sizeof(a));
        if (strcmp(refs[i].name, "cpp-demo") == 0)
        {
            char e[301];

            snprintf(log, sizeof(log), "/tmp/ts_rg_%s.err", refs[i].name);
            tsd_head(log, e, sizeof(e));
            tsd_say("H1 cpp-demo stops early? exit=%d, full stdout [%s], "
                    "stderr [%s]", code[i], a, e);
        }
        if (code[i] != 0)
        {
            tsd_say("H1 reference %s dropped: exit code %d", refs[i].name,
                    code[i]);
            continue;
        }
        kept[i] = true;
        {
            int  st;

            snprintf(log, sizeof(log), "/tmp/ts_rg_%s.norm", refs[i].name);
            facts(log, &st, fin, sizeof(fin));
            tsd_say("H1 reference %s: exit=0 stages=%d final=%s%s",
                    refs[i].name, st, fin,
                    st == HOPS + 1 ? " (full ring)" : " (short: not used)");
            if (st == HOPS + 1)
                nfull++;
            else
                kept[i] = false;
        }
    }

    TEST_STEP("Run ./scripts/run.sh guess 42 %d", HOPS);
    snprintf(cmd, sizeof(cmd), "./scripts/run.sh guess 42 %d 2>/tmp/ts_rg_ts.err "
             "> /tmp/ts_rg_ts.out", HOPS);
    ts_code = tsd_sh(src, cmd, 60, "/tmp/ts_rg_ts.log");
    tsd_sh("/", NORM("/tmp/ts_rg_ts.out", "/tmp/ts_rg_ts.norm"), 10,
           "/tmp/ts_rg_n.log");
    facts("/tmp/ts_rg_ts.norm", &ts_stages, tsfin, sizeof(tsfin));
    tsd_say("H1 TypeScript: exit=%d stages=%d final=%s", ts_code, ts_stages,
            tsfin);
    if (ts_code != 0)
    {
        tsd_head("/tmp/ts_rg_ts.err", a, 401);
        tsd_bad("H1", "typescript run", "exit %d, stderr [%s]", ts_code, a);
    }

    TEST_STEP("Compare with every full-ring reference");
    for (i = 0; i < NREF; i++)
    {
        if (!kept[i])
            continue;
        snprintf(cmd, sizeof(cmd), "test -s /tmp/ts_rg_ts.norm && cmp "
                 "/tmp/ts_rg_ts.norm /tmp/ts_rg_%s.norm", refs[i].name);
        if (tsd_sh("/", cmd, 10, "/tmp/ts_rg_cmp.log") == 0 &&
            ts_code == code[i])
        {
            nmatch++;
            tsd_say("H1 TypeScript equals %s (exit codes %d and %d)",
                    refs[i].name, ts_code, code[i]);
        }
        else
            tsd_say("H1 TypeScript differs from %s (exit %d and %d)",
                    refs[i].name, ts_code, code[i]);
        if (firstfull[0] == '\0')
            snprintf(firstfull, sizeof(firstfull), "%s", refs[i].name);
        else
        {
            snprintf(cmd, sizeof(cmd), "cmp -s /tmp/ts_rg_%s.norm "
                     "/tmp/ts_rg_%s.norm", firstfull, refs[i].name);
            if (tsd_sh("/", cmd, 10, "/tmp/ts_rg_cmp.log") != 0)
                tsd_say("H1 the references %s and %s disagree with each "
                        "other", firstfull, refs[i].name);
        }
    }
    if (nfull == 0)
        tsd_bad("H1", "reference", "no reference ran the full %d stages; "
                "the TypeScript output has nothing to be compared with",
                HOPS + 1);
    else if (nmatch == 0 && ts_code == 0)
    {
        tsd_head("/tmp/ts_rg_ts.norm", a, 601);
        tsd_bad("H1", "stdout", "matches none of %d full-ring reference(s); "
                "TypeScript [%s]", nfull, a);
    }

    TSD_PASS("H1", "the TypeScript output equals a full-ring reference");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
