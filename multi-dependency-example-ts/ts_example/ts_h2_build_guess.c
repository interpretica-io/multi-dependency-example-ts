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
    const char *benv[] = { "RuntimeIdentifier=linux-x64", NULL };
    const char *genv[3];
    int         up;

    TEST_START;
    t_report_begin();
    if (b == NULL || g == NULL)
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
    snprintf(bcmd, sizeof(bcmd), "'%s/build.sh'", src_root);
    if (!ts_run(b, src_root, bcmd, NULL, benv, shim, BUILD_LIMIT_S, "build"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start %s", bcmd);
        goto verdict;
    }
    tsx_log_step("H2", "build", bcmd, b);
    T_FINDING(b->code == 0 && !b->hung ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.build", "build.sh",
              "exit code %d, signal %d, hung %d", b->code, b->sig, b->hung);
    if (b->hung || b->sig != 0 || b->code != 0)
    {
        char t50[3000];
        char p[300];

        snprintf(p, sizeof(p), "%s/build.stderr", workdir);
        file_tail(p, t50, sizeof(t50));
        ts_flat(t50 + (strlen(t50) > 1200 ? strlen(t50) - 1200 : 0), 1200,
                e, sizeof(e));
        res_set(&res, R_FAIL, "H2 FAIL: step build: %s %s, exit code %d, "
                "signal %d, required 0; end of the build output (stderr) "
                "[%s]; the last %d lines of stdout and stderr are in the "
                "log; scripts/run.sh guess was not run", bcmd, b->hung ?
                "did not finish within the limit" : "failed", b->code,
                b->sig, e, TSX_TAIL);
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
    if (!ts_run(g, src_root, gcmd, NULL, genv, NULL, GUESS_LIMIT_S, "guess"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start guess");
        goto verdict;
    }
    tsx_log_step("H2", "guess", gcmd, g);
    ts_flat(g->err, 200, e, sizeof(e));
    crash = g->sig != 0 || ts_has_trace(g->err) || ts_has_trace(g->out);
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
    TSX_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
