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
    tsx_sh_t   *sh = calloc(1, sizeof(*sh));
    tsx_sh_t   *fi = calloc(1, sizeof(*fi));
    tsx_sh_t   *fd = calloc(1, sizeof(*fd));
    const char *ls_lines = "";
    bool        ts_dir_ok = false;
    char        vtext[4200];
    char        why[400];
    char        base[200];
    char        hits[TSH_MAX_HITS][700];
    char        list[1500] = "";
    char        cmd[400];
    char        finding[1700];
    int         n = 0;
    int         i;
    int         lines = 0;
    const char *p;

    TEST_START;
    t_report_begin();
    if (f == NULL || sh == NULL || fi == NULL || fd == NULL)
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

    TSX_STEP("Run ls -la " WORK_SRC);
    if (!tsx_sh(sh, "H1", "ls", src_root, "ls -la " WORK_SRC, 60, NULL))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: cannot start the shell for "
                "ls -la " WORK_SRC);
        goto verdict;
    }
    if (!tsx_sh_ok(sh))
    {
        tsx_sh_text(sh, vtext, sizeof(vtext));
        res_set(&res, R_FAIL, "H1 FAIL: " WORK_SRC " is missing or cannot "
                "be listed: ls -la " WORK_SRC ": %s", vtext);
        goto verdict;
    }
    ls_lines = sh->tail;

    TSX_STEP("Run find over " WORK_SRC " for .ts files");
    snprintf(cmd, sizeof(cmd), "find " WORK_SRC " -name '*.ts' -not -path "
             "'*/node_modules/*'");
    if (!tsx_sh(fi, "H1", "find-ts", src_root, cmd, 120, NULL) ||
        !tsx_sh_ok(fi))
    {
        tsx_sh_text(fi, vtext, sizeof(vtext));
        res_set(&res, R_FAIL, "H1 FAIL: step find of .ts files: find itself "
                "failed: %s", vtext);
        goto verdict;
    }
    for (p = fi->text; *p != '\0'; p++)
    {
        if (*p == '\n')
            lines++;
    }

    TSX_STEP("Run find /work/src/ts -maxdepth 1");
    if (!tsx_sh(fd, "H1", "find-ts-dir", src_root,
                "find " WORK_SRC "/ts -maxdepth 1", 60, NULL))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: cannot start the shell for "
                "find " WORK_SRC "/ts");
        goto verdict;
    }
    ts_dir_ok = tsx_sh_ok(fd);
    RING("H1: ls exit code %d, find .ts exit code %d (%d path(s)), find "
         WORK_SRC "/ts exit code %d", sh->code, fi->code, lines, fd->code);

    TSX_STEP("Record whether a TypeScript example exists");
    n = tsh_find("H1", WORK_SRC, 0, hits, 0);
    for (i = 0; i < n; i++)
        append(list, sizeof(list), "%s; ", hits[i]);
    if (n == 0 && lines == 0)
        snprintf(finding, sizeof(finding), "FINDING: no TypeScript example "
                 "exists under " WORK_SRC " (no .ts file outside "
                 "node_modules, no directory with a .ts file and a "
                 "package.json or tsconfig.json)");
    else
        snprintf(finding, sizeof(finding), "FINDING: a TypeScript example "
                 "exists: %d .ts file(s), %d director%s with package.json "
                 "or tsconfig.json: %s", lines, n, n == 1 ? "y" : "ies",
                 list);
    RING("H1: %s", finding);

    TSX_STEP("Require " WORK_SRC "/ts/package.json, tsconfig.json and a .ts "
             "source file");
    {
        const char *need[2] = { "package.json", "tsconfig.json" };
        char        pth[400];
        char        miss[300] = "";
        int         ts_src = 0;
        size_t      k;

        for (k = 0; k < 2; k++)
        {
            snprintf(pth, sizeof(pth), WORK_SRC "/ts/%s", need[k]);
            if (access(pth, R_OK) != 0)
                append(miss, sizeof(miss), "%s ", pth);
        }
        for (p = fi->text; *p != '\0'; p += strcspn(p, "\n") +
             (p[strcspn(p, "\n")] == '\n' ? 1 : 0))
        {
            if (strncmp(p, WORK_SRC "/ts/", sizeof(WORK_SRC "/ts/") - 1) == 0)
                ts_src++;
        }
        if (ts_src == 0)
            append(miss, sizeof(miss), "(no .ts file under " WORK_SRC
                   "/ts) ");
        if (!ts_dir_ok)
            append(miss, sizeof(miss), "(" WORK_SRC "/ts cannot be listed) ");
        if (miss[0] != '\0')
            res_set(&res, R_FAIL, "H1 FAIL: the TypeScript example is "
                    "incomplete, missing: %s; %s; ls -la " WORK_SRC ": exit "
                    "code 0, last %d lines [%s]", miss, finding, TSX_TAIL,
                    ls_lines);
        else
            res_set(&res, R_PASS, "H1 PASS: ls -la " WORK_SRC " exit code 0, "
                    "find exit code 0; %s; " WORK_SRC "/ts has package.json, "
                    "tsconfig.json and %d .ts file(s)", finding, ts_src);
    }
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.listing", "typescript example",
              "%s", res.msg);

verdict:
    free(f);
    free(sh);
    free(fi);
    free(fd);
    TSX_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
