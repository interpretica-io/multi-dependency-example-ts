/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h2_build_guess, ./build.sh and ./scripts/run.sh
 *        guess both exit 0 (settles H2)
 *
 * Runs build.sh (absolute path, project root as working directory) and
 * requires exit code 0 and compiled .js files written by it in the
 * TypeScript dist directory; on a failure the last 50 lines of the build
 * output are logged and put in the verdict. Then runs scripts/run.sh guess
 * with a 30 s timeout and passes when it starts without a crash: it exits 0
 * or is still running at the limit (killed by the test), with no signal and
 * no stack trace. The web services the example talks to are started first. Each step has its own
 * verdict text. Known-bad control: the runner reports a planted hang and a
 * planted signal, and a planted non-zero exit.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h2_build_guess"

#include "te_config.h"

#include "tsx_lib.h"

#define BUILD_LIMIT_S   540
#define GUESS_LIMIT_S   30

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *b = calloc(1, sizeof(*b));
    ts_run_t   *g = calloc(1, sizeof(*g));
    tsx_sh_t   *sh = calloc(1, sizeof(*sh));
    char        vtext[4200];
    char        shim[300];
    char        why[400];
    char        note[900];
    char        e[300];
    char        url[200];
    char        bcmd[800];
    char        gcmd[800];
    char        tsdir[700] = "";
    char        found[900];
    time_t      since;
    int         njs = 0;
    bool        crash;
    const char *genv[3];
    int         up;

    TEST_START;
    t_report_begin();
    if (b == NULL || g == NULL || sh == NULL)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H2"))
        goto verdict;

    TSX_STEP("Known-bad control: the runner reports a hang, a signal and "
              "a non-zero exit");
    if (!ts_runner_control_ok(workdir, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }
    if (!ts_run(b, workdir, "exit 7", NULL, NULL, NULL, 5, "ctl-exit") ||
        b->code != 7)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: a planted "
                "exit code 7 was read as %d", b->code);
        goto verdict;
    }
    if (!ts_cc_shim(workdir, shim, sizeof(shim)))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot write the compiler "
                "shim");
        goto verdict;
    }

    TSX_STEP("Run %s/build.sh, at most %d s", src_root, BUILD_LIMIT_S);
    since = time(NULL);
    snprintf(bcmd, sizeof(bcmd), "ls -la '%s' && RuntimeIdentifier=linux-x64 "
             "PATH='%s':\"$PATH\" '%s/build.sh'", src_root, shim, src_root);
    if (!tsx_sh(sh, "H2", "build", src_root, bcmd, BUILD_LIMIT_S, NULL))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start the build "
                "through the shell helper");
        goto verdict;
    }
    b->secs = sh->secs;
    T_FINDING(tsx_sh_ok(sh) ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.build", "build.sh",
              "exit code %d, signal %d, hung %d", sh->code, sh->sig,
              sh->hung);
    if (!tsx_sh_ok(sh))
    {
        tsx_sh_text(sh, vtext, sizeof(vtext));
        res_set(&res, R_FAIL, "H2 FAIL: step build: build.sh in %s: %s; "
                "scripts/run.sh guess was not run", src_root, vtext);
        goto verdict;
    }
    TSX_STEP("Check that the build produced compiled JavaScript");
    if (!ts_find_dir(src_root, tsdir, sizeof(tsdir)) ||
        (njs = tsx_dist_js(tsdir, since, found, sizeof(found))) <= 0)
    {
        res_set(&res, R_FAIL, "H2 FAIL: step tsc: build.sh exited 0 but it "
                "wrote no compiled .js file in dist of the TypeScript "
                "directory [%s] (build output is in the log)", tsdir);
        goto verdict;
    }
    RING("H2: %d compiled JavaScript file(s) in %s/dist, first %s", njs,
         tsdir, found);

    TSX_STEP("Start the web services the example talks to");
    up = tsx_services_up("H2", note, sizeof(note));
    snprintf(url, sizeof(url), "RING_GATEWAY_URL=%s", tsx_url);
    genv[0] = url;
    genv[1] = "RING_TIMEOUT_MS=20000";
    genv[2] = NULL;

    TSX_STEP("Run %s/scripts/run.sh guess, at most %d s", src_root,
             GUESS_LIMIT_S);
    snprintf(gcmd, sizeof(gcmd), "'%s/scripts/run.sh' guess", src_root);
    if (!tsx_sh(sh, "H2", "guess", src_root, gcmd, GUESS_LIMIT_S, genv))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start guess through "
                "the shell helper");
        goto verdict;
    }
    g->code = sh->code;
    g->sig = sh->sig;
    g->hung = sh->hung;
    g->secs = sh->secs;
    ts_flat(sh->tail + (strlen(sh->tail) > 300 ? strlen(sh->tail) - 300 : 0),
            300, e, sizeof(e));
    crash = g->sig != 0 || ts_has_trace(sh->text);
    T_FINDING(!crash && (g->hung || g->code == 0) ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.run", "run.sh guess",
              "exit code %d, signal %d, still running at the limit %d, "
              "%.1f s", g->code, g->sig, g->hung, g->secs);
    if (g->sig != 0)
        res_set(&res, R_FAIL, "H2 FAIL: step guess: %s died of signal %d; "
                "services up %d of 3 %s; stderr [%s]", gcmd, g->sig, up,
                note, e);
    else if (crash)
        res_set(&res, R_FAIL, "H2 FAIL: step guess: %s printed a crash "
                "trace, exit code %d; services up %d of 3 %s; stderr [%s]",
                gcmd, g->code, up, note, e);
    else if (!g->hung && g->code != 0)
        res_set(&res, R_FAIL, "H2 FAIL: step guess: %s exit code %d, "
                "required 0 or still running; services up %d of 3 %s; "
                "stderr [%s]", gcmd, g->code, up, note, e);
    else
        res_set(&res, R_PASS, "H2 PASS: build.sh exited 0 in %.1f s with %d "
                "compiled .js file(s) in %s/dist and scripts/run.sh guess "
                "started without a crash (%s after %.1f s, limit %d s)",
                b->secs, njs, tsdir, g->hung ? "still running, stopped at "
                "the limit" : "exit code 0", g->secs, GUESS_LIMIT_S);

verdict:
    free(b);
    free(g);
    free(sh);
    TSX_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
