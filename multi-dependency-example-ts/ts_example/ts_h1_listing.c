/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h1_listing, is there a TypeScript example (settles H1)
 *
 * Lists the project like ts_diag does (system() with output in a file,
 * read back, a verdict per command) and then checks strictly that
 * ts/package.json, ts/tsconfig.json and at least one .ts file outside
 * node_modules exist. A planted tree with package.json only, and one with
 * all three, check the checker first.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h1_listing"

#include "tsd.h"

/** Number of .ts files outside node_modules under @p dir/src (or dir). */
static int
count_ts(const char *dir)
{
    char  cmd[600];
    char  out[64];
    FILE *p;

    snprintf(cmd, sizeof(cmd), "find '%s' -name '*.ts' -not -path "
             "'*/node_modules/*' 2>/dev/null | wc -l", dir);
    p = popen(cmd, "r");
    if (p == NULL)
        return -1;
    if (fgets(out, sizeof(out), p) == NULL)
        out[0] = '0', out[1] = '\0';
    pclose(p);
    return atoi(out);
}

/** The strict check: package.json, tsconfig.json and one .ts file. */
static bool
example_ok(const char *tsdir, char *why, size_t size)
{
    char p[PATH_MAX];

    snprintf(p, sizeof(p), "%s/package.json", tsdir);
    if (access(p, R_OK) != 0)
    {
        snprintf(why, size, "%s is missing", p);
        return false;
    }
    snprintf(p, sizeof(p), "%s/tsconfig.json", tsdir);
    if (access(p, R_OK) != 0)
    {
        snprintf(why, size, "%s is missing", p);
        return false;
    }
    if (count_ts(tsdir) < 1)
    {
        snprintf(why, size, "no .ts file under %s", tsdir);
        return false;
    }
    why[0] = '\0';
    return true;
}

int
main(int argc, char **argv)
{
    char        ctl[] = "/tmp/ts_h1_ctl_XXXXXX";
    char        why[PATH_MAX + 64];
    char        cmd[PATH_MAX + 128];
    char        tsdir[PATH_MAX];
    char        text[401];
    char        all[3000] = "";
    const char *src = tsd_src();
    unsigned    i;
    bool        ok;

    TEST_START;

    TEST_STEP("Control: a tree with only package.json is not an example");
    if (mkdtemp(ctl) == NULL)
        TEST_FAIL("H1 NOT SETTLED: cannot create %s: %s", ctl,
                  strerror(errno));
    snprintf(cmd, sizeof(cmd), "touch %s/package.json", ctl);
    if (system(cmd) != 0 || example_ok(ctl, why, sizeof(why)))
        TEST_FAIL("H1 control failed: package.json alone was accepted as "
                  "a TypeScript example");
    TEST_STEP("Control: package.json, tsconfig.json and a .ts file are one");
    snprintf(cmd, sizeof(cmd), "touch %s/tsconfig.json %s/main.ts", ctl, ctl);
    if (system(cmd) != 0 || !example_ok(ctl, why, sizeof(why)))
        TEST_FAIL("H1 control failed: a complete planted example was "
                  "rejected: %s", why);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", ctl);
    (void)!system(cmd);

    snprintf(tsdir, sizeof(tsdir), "%s/ts", src);
    for (i = 0; i < 3; i++)
    {
        char path[64];
        int  code;

        snprintf(path, sizeof(path), "/tmp/ts_h1_%u.log", i + 1);
        if (i == 0)
            snprintf(cmd, sizeof(cmd), "ls -la %s", src);
        else if (i == 1)
            snprintf(cmd, sizeof(cmd), "ls -la %s", tsdir);
        else
            snprintf(cmd, sizeof(cmd), "find %s -name '*.ts' -not -path "
                     "'*/node_modules/*'", src);
        TEST_STEP("Run %s", cmd);
        code = tsd_sh("/", cmd, 60, path);
        tsd_head(path, text, sizeof(text));
        RING_VERDICT("H1 command [%s] exit code %d, first 400 bytes: [%s]",
                     cmd, code, text);
        snprintf(all + strlen(all), sizeof(all) - strlen(all),
                 "[%s] exit %d: %.350s\n", cmd, code, text);
    }

    TEST_STEP("Check ts/package.json, ts/tsconfig.json and a .ts file");
    ok = example_ok(tsdir, why, sizeof(why));
    if (!ok)
    {
        RING_VERDICT("H1 no TypeScript example found");
        TEST_FAIL("H1 no TypeScript example found: %s. Listing: %s", why, all);
    }
    RING_VERDICT("H1 TypeScript example found");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
