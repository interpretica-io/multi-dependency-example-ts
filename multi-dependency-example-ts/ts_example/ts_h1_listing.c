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
    char        p[PATH_MAX + 32];
    const char *src = tsd_src();
    static const char *const need[] = { "package.json", "tsconfig.json",
                                        "src/main.ts" };
    unsigned    i;

    TEST_START;
    tsd_say("H1 start");

    TEST_STEP("Control: a tree with only package.json is not an example");
    if (mkdtemp(ctl) == NULL)
        tsd_bad("H1", "control", "cannot create %s: %s", ctl, strerror(errno));
    else
    {
        snprintf(cmd, sizeof(cmd), "touch %s/package.json", ctl);
        if (system(cmd) != 0 || example_ok(ctl, why, sizeof(why)))
            tsd_bad("H1", "control", "package.json alone was accepted as "
                    "a TypeScript example");
        snprintf(cmd, sizeof(cmd), "touch %s/tsconfig.json %s/main.ts", ctl,
                 ctl);
        if (system(cmd) != 0 || !example_ok(ctl, why, sizeof(why)))
            tsd_bad("H1", "control", "a complete planted example was "
                    "rejected: %s", why);
        else
            tsd_say("H1 control: package.json alone rejected, a complete "
                    "planted tree accepted");
        snprintf(cmd, sizeof(cmd), "rm -rf %s", ctl);
        (void)!system(cmd);
    }

    snprintf(tsdir, sizeof(tsdir), "%s/ts", src);
    TEST_STEP("Run ls -R of %s without node_modules", tsdir);
    snprintf(cmd, sizeof(cmd), "ls -R -I node_modules %s", tsdir);
    tsd_cmd("H1 listing", "/", cmd, 60, "/tmp/ts_h1_listing.log", false);

    for (i = 0; i < 3; i++)
    {
        snprintf(p, sizeof(p), "%s/%s", tsdir, need[i]);
        TEST_STEP("Check %s", p);
        if (access(p, R_OK) == 0)
            tsd_say("H1 %s exists: %s", need[i], p);
        else
        {
            tsd_say("H1 missing %s: %s does not exist", need[i], p);
            tsd_flag(need[i]);
        }
    }

    if (tsd_nfail == 0)
        tsd_say("H1 TypeScript example found");
    else
        tsd_say("H1 no TypeScript example found: missing %s", tsd_fails);
    TSD_FINISH("H1");
    TEST_SUCCESS;

cleanup:
    TEST_END;
}
