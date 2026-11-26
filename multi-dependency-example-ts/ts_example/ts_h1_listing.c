/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h1_listing, the project has a TypeScript example
 *        directory (settles H1)
 *
 * Lists /work/src (when it exists) and the project root TE_TS_MDE_SRC, and
 * fails unless a directory holds a .ts source file and a package.json or a
 * tsconfig.json. node_modules, dist and dot directories are not counted.
 * Known-bad control: a planted tree with one real example and four look-
 * alikes (only .ts, only package.json, only .d.ts with tsconfig.json, an
 * example inside node_modules); exactly the real one must be found.
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
    res_t   res = { .kind = R_PASS };
    char    why[400];
    char    base[200];
    char    hits[TSH_MAX_HITS][700];
    char    list[1500] = "";
    int     n = 0;
    int     i;
    int     roots = 0;

    TEST_START;
    t_report_begin();
    if (!tsx_init(&res, "H1"))
        goto verdict;

    TEST_STEP("Known-bad control: the finder tells a real example from "
              "look-alikes");
    snprintf(base, sizeof(base), "%s/h1-control", workdir);
    if (mkdir(base, 0700) != 0 || !plant_control(base, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    TEST_STEP("List %s and the project root %s", WORK_SRC, src_root);
    if (access(WORK_SRC, X_OK) == 0)
    {
        roots++;
        n = tsh_find("H1", WORK_SRC, 0, hits, n);
    }
    else
        RING("H1: %s does not exist on this agent; only the project root "
             "is listed", WORK_SRC);
    if (n == 0 || strcmp(WORK_SRC, src_root) != 0)
    {
        roots++;
        n = tsh_find("H1", src_root, 0, hits, n);
    }
    for (i = 0; i < n; i++)
        append(list, sizeof(list), "%s; ", hits[i]);

    if (n == 0)
        res_set(&res, R_FAIL, "H1 FAIL: no TypeScript example directory "
                "(a .ts file and a package.json or tsconfig.json) under "
                "%d root(s): %s%s; the project has no TypeScript example",
                roots, access(WORK_SRC, X_OK) == 0 ? WORK_SRC " and " : "",
                src_root);
    else
        res_set(&res, R_PASS, "H1 PASS: %d TypeScript example "
                "director%s found: %s", n, n == 1 ? "y" : "ies", list);
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.listing", "typescript example",
              "%s", res.msg);

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
