/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h1_listing, the project has a TypeScript example
 *        directory (settles H1)
 *
 * Runs `find /work/src -iname '*.ts' -o -iname 'tsconfig.json' -o -iname
 * 'package.json'` from the project root and logs the command, its exit
 * code, stdout and stderr in full. The test passes when find runs; it fails
 * only when find itself errors (the error is in the verdict). Whether a
 * TypeScript example exists is recorded as a finding in the log and in the
 * verdict text, never as a failure. Known-bad controls: find on a path that
 * does not exist must report an error, and a planted tree with one real
 * example and four look-alikes must give exactly the real one in the
 * finding.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h1_listing"

#include "te_config.h"

#include "tsh_lib.h"

#define WORK_SRC    "/work/src"

/** Write an empty file. */
static void
touch(const char *dir, const char *name)
{
    char  p[600];
    FILE *f;

    snprintf(p, sizeof(p), "%s/%s", dir, name);
    f = fopen(p, "w");
    if (f != NULL)
        fclose(f);
}

static bool
plant_control(const char *base, char *why, size_t size)
{
    static const char * const dirs[] = {
        "real", "only-ts", "only-json", "typings", "node_modules",
        "node_modules/dep",
    };
    char   hits[TSH_MAX_HITS][700];
    char   p[600];
    size_t i;
    int    n;

    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
    {
        snprintf(p, sizeof(p), "%s/%s", base, dirs[i]);
        if (mkdir(p, 0700) != 0)
        {
            snprintf(why, size, "cannot create %s", p);
            return false;
        }
    }
    snprintf(p, sizeof(p), "%s/real", base);
    touch(p, "main.ts");
    touch(p, "package.json");
    snprintf(p, sizeof(p), "%s/only-ts", base);
    touch(p, "main.ts");
    snprintf(p, sizeof(p), "%s/only-json", base);
    touch(p, "package.json");
    snprintf(p, sizeof(p), "%s/typings", base);
    touch(p, "types.d.ts");
    touch(p, "tsconfig.json");
    snprintf(p, sizeof(p), "%s/node_modules/dep", base);
    touch(p, "index.ts");
    touch(p, "package.json");
    n = tsh_find("H1 control", base, 0, hits, 0);
    snprintf(p, sizeof(p), "%s/real", base);
    if (n != 1 || strcmp(hits[0], p) != 0)
    {
        snprintf(why, size, "the finder returned %d hit(s) in the planted "
                 "tree (first [%s]); expected exactly %s", n,
                 n > 0 ? hits[0] : "", p);
        return false;
    }
    return true;
}

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *f = calloc(1, sizeof(*f));
    char        why[400];
    char        base[200];
    char        hits[TSH_MAX_HITS][700];
    char        list[1500] = "";
    char        e[400];
    char        cmd[400];
    char        finding[1700];
    int         n = 0;
    int         i;
    int         lines = 0;
    const char *p;

    TEST_START;
    t_report_begin();
    if (f == NULL)
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H1"))
        goto verdict;

    TSX_STEP("Known-bad control: the finder tells a real example from "
             "look-alikes");
    snprintf(base, sizeof(base), "%s/h1-control", workdir);
    if (mkdir(base, 0700) != 0 || !plant_control(base, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    TSX_STEP("Known-bad control: find reports an error for a path that does "
             "not exist");
    snprintf(cmd, sizeof(cmd), "find '%s/no-such-dir' -iname '*.ts'",
             workdir);
    if (!ts_run(f, src_root, cmd, NULL, NULL, NULL, 30, "h1-ctl-find") ||
        f->hung || f->code == 0 || f->err_len == 0)
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: control failed: find on a "
                "missing directory did not exit non-zero with a message "
                "(exit code %d)", f->code);
        goto verdict;
    }

    TSX_STEP("Run find over " WORK_SRC " for TypeScript files, tsconfig.json "
             "and package.json");
    snprintf(cmd, sizeof(cmd), "find " WORK_SRC " -iname '*.ts' -o -iname "
             "'tsconfig.json' -o -iname 'package.json'");
    if (!ts_run(f, src_root, cmd, NULL, NULL, NULL, 120, "find"))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: cannot start find");
        goto verdict;
    }
    tsx_log_step("H1", "find", cmd, f);
    if (f->hung || f->sig != 0 || f->code != 0)
    {
        ts_flat(f->err, 300, e, sizeof(e));
        res_set(&res, R_FAIL, "H1 FAIL: step find: find itself failed: %s, "
                "exit code %d, signal %d; stderr [%s]; stdout [%.150s]",
                f->hung ? "killed on the time limit" : "ended", f->code,
                f->sig, e, f->out);
        goto verdict;
    }
    for (p = f->out; *p != '\0'; p++)
    {
        if (*p == '\n')
            lines++;
    }
    RING("H1: find printed %d path(s) under " WORK_SRC, lines);

    TSX_STEP("Record whether a TypeScript example exists (a finding, not a "
             "failure)");
    n = tsh_find("H1", WORK_SRC, 0, hits, 0);
    for (i = 0; i < n; i++)
        append(list, sizeof(list), "%s; ", hits[i]);
    if (n == 0)
        snprintf(finding, sizeof(finding), "FINDING: no TypeScript example "
                 "exists under " WORK_SRC " (no directory with a .ts file "
                 "and a package.json or tsconfig.json); the project has no "
                 "TypeScript example");
    else
        snprintf(finding, sizeof(finding), "FINDING: %d TypeScript example "
                 "director%s exist%s: %s", n, n == 1 ? "y" : "ies",
                 n == 1 ? "s" : "", list);
    RING("H1: %s", finding);
    res_set(&res, R_PASS, "H1 PASS: find ran (exit code 0, %d path(s) "
            "listed); %s", lines, finding);
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "ts.listing", "typescript example",
              "%s", res.msg);

verdict:
    free(f);
    TSX_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
