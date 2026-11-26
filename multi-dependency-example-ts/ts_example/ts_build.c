/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_build, the TypeScript example builds from the
 *        project root (settles H2)
 *
 * Runs build.sh by absolute path with the project root as the working
 * directory. Passes when it exits 0 and compiled .js files written by this
 * build exist in the TypeScript dist directory, and ./scripts/run.sh exists and is
 * executable. On a failure the verdict names the step: npm install, tsc,
 * an earlier stage of build.sh, or a missing file; the two TypeScript steps
 * are then also run on their own so that the log shows each of them.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_build"

#include "te_config.h"

#include "tsx_lib.h"

#define BUILD_LIMIT_S   540
#define STEP_LIMIT_S    120

/** Name the failing step of a build.sh run from the tails of its output. */
static void
classify(const char *tail, char *step, size_t size)
{
    const char *m = NULL;
    const char *p;

    if (strstr(tail, "TypeScript") != NULL || strstr(tail, "[10/10]") != NULL)
    {
        if (strstr(tail, "npm ERR") != NULL ||
            strstr(tail, "npm is required") != NULL ||
            strstr(tail, "npm: command not found") != NULL ||
            strstr(tail, "npm: not found") != NULL ||
            strstr(tail, "EAI_AGAIN") != NULL ||
            strstr(tail, "ENOTFOUND") != NULL)
            snprintf(step, size, "npm install");
        else if (strstr(tail, "error TS") != NULL ||
                 strstr(tail, "tsc") != NULL)
            snprintf(step, size, "tsc");
        else
            snprintf(step, size, "the TypeScript stage of build.sh "
                     "(neither npm nor tsc is named in its output)");
        return;
    }
    for (p = strstr(tail, "==> ["); p != NULL; p = strstr(p + 1, "==> ["))
        m = p;
    if (m != NULL)
    {
        int  n = 0;
        char title[80] = "";

        if (sscanf(m, "==> [%d/", &n) == 1)
        {
            const char *t = strchr(m, ']');

            if (t != NULL)
            {
                size_t k = strcspn(t + 1, "|\n");

                if (k >= sizeof(title))
                    k = sizeof(title) - 1;
                memcpy(title, t + 1, k);
                title[k] = '\0';
            }
            snprintf(step, size, "the C build (build.sh stage %d,%s, before "
                     "the TypeScript step)", n, title);
            return;
        }
    }
    snprintf(step, size, "build.sh before any stage was reported");
}

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *b = calloc(1, sizeof(*b));
    ts_run_t   *d = calloc(1, sizeof(*d));
    char        shim[300];
    char        script[700];
    char        runsh[700];
    char        tsdir[700] = "";
    char        found[900];
    char        tail[16384];
    char        errtail[4096];
    char        step[300] = "";
    char        diag[600] = "";
    char        why[400];
    char        cmd[900];
    char        path[400];
    const char *env[] = { "RuntimeIdentifier=linux-x64", NULL };
    struct stat st;
    time_t      since;
    int         njs;

    TEST_START;
    t_report_begin();
    if (b == NULL || d == NULL)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H2"))
        goto verdict;
    snprintf(script, sizeof(script), "%s/build.sh", src_root);
    snprintf(runsh, sizeof(runsh), "%s/scripts/run.sh", src_root);

    TSX_STEP("Known-bad control: the runner reports a hang and a signal");
    if (!ts_runner_control_ok(workdir, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    TSX_STEP("Check that %s exists and is executable", script);
    if (access(script, X_OK) != 0)
    {
        res_set(&res, R_FAIL, "H2 FAIL: step missing file: %s does not "
                "exist or is not executable", script);
        goto verdict;
    }
    if (!ts_cc_shim(workdir, shim, sizeof(shim)))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot write the compiler "
                "shim in %s", workdir);
        goto verdict;
    }

    TSX_STEP("Run %s in %s, at most %d s", script, src_root, BUILD_LIMIT_S);
    since = time(NULL);
    snprintf(cmd, sizeof(cmd), "'%s'", script);
    if (!ts_run(b, src_root, cmd, NULL, env, shim, BUILD_LIMIT_S, "build"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start %s", script);
        goto verdict;
    }
    tsx_log_step("H2", "build", cmd, b);
    snprintf(path, sizeof(path), "%s/build.stdout", workdir);
    file_tail(path, tail, sizeof(tail));
    snprintf(path, sizeof(path), "%s/build.stderr", workdir);
    file_tail(path, errtail, sizeof(errtail));
    strncat(tail, errtail, sizeof(tail) - strlen(tail) - 1);
    ts_find_dir(src_root, tsdir, sizeof(tsdir));

    if (b->hung || b->sig != 0 || b->code != 0)
    {
        classify(tail, step, sizeof(step));
        if (tsdir[0] != '\0' && strncmp(step, "the C build", 11) == 0)
        {
            /* The earlier stage broke first: still try the two
             * TypeScript steps alone, so the log tells their state. */
            TSX_STEP("Run npm install in %s on its own", tsdir);
            snprintf(cmd, sizeof(cmd), "cd '%s' && npm install --no-audit "
                     "--no-fund", tsdir);
            if (ts_run(d, src_root, cmd, NULL, NULL, NULL, STEP_LIMIT_S,
                       "npm"))
            {
                tsx_log_step("H2", "npm", cmd, d);
                append(diag, sizeof(diag), "npm install alone: exit %d; ",
                       d->hung ? -1 : d->code);
            }
            if (d->code == 0 && !d->hung)
            {
                TSX_STEP("Run tsc in %s on its own", tsdir);
                snprintf(cmd, sizeof(cmd), "cd '%s' && npx --no-install tsc "
                         "-p tsconfig.json", tsdir);
                if (ts_run(d, src_root, cmd, NULL, NULL, NULL, STEP_LIMIT_S,
                           "tsc"))
                {
                    tsx_log_step("H2", "tsc", cmd, d);
                    append(diag, sizeof(diag), "tsc alone: exit %d; ",
                           d->hung ? -1 : d->code);
                }
            }
        }
        ts_flat(tail + (strlen(tail) > 600 ? strlen(tail) - 600 : 0), 600,
                why, sizeof(why));
        res_set(&res, R_FAIL, "H2 FAIL: step %s: %s exit code %d signal %d%s;"
                " %send of the output [%s]", step, script, b->code, b->sig,
                b->hung ? " (killed on the time limit)" : "", diag, why);
        goto verdict;
    }

    TSX_STEP("Check the compiled JavaScript and %s", runsh);
    if (tsdir[0] == '\0')
        res_set(&res, R_FAIL, "H2 FAIL: step missing file: build.sh exited "
                "0 but no TypeScript directory with a package.json exists "
                "under %s", src_root);
    else if ((njs = tsx_dist_js(tsdir, since, found, sizeof(found))) <= 0)
        res_set(&res, R_FAIL, "H2 FAIL: step tsc: build.sh exited 0 but "
                "%s/dist holds %s", tsdir, njs < 0 ?
                "no compiled .js files (the directory has none)" :
                "no .js file written by this build");
    else if (stat(runsh, &st) != 0)
        res_set(&res, R_FAIL, "H2 FAIL: step missing file: %s does not "
                "exist", runsh);
    else if (access(runsh, X_OK) != 0)
        res_set(&res, R_FAIL, "H2 FAIL: step missing file: %s exists but "
                "is not executable (mode %o)", runsh,
                (unsigned)(st.st_mode & 0777));
    else
        res_set(&res, R_PASS, "H2 PASS: %s exited 0 in %.1f s, %d compiled "
                "JavaScript file(s) written in %s/dist (first %s) and %s is "
                "executable", script, b->secs, njs, tsdir, found, runsh);
    RING("H2 ts_build: %s", res.msg);
    T_FINDING(res.kind == R_PASS ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.build", "build.sh", "%s",
              res.msg);

verdict:
    free(b);
    free(d);
    TSX_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
