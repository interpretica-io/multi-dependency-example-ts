/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_h2_build_guess, ./build.sh and ./scripts/run.sh
 *        guess both exit 0 (settles H2)
 *
 * Runs ./build.sh in the project root and requires exit code 0, then runs
 * ./scripts/run.sh guess and requires exit code 0 within 60 s. The web
 * services the example talks to are started first. Each step has its own
 * verdict text. Known-bad control: the runner reports a planted hang and a
 * planted signal, and a planted non-zero exit.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_h2_build_guess"

#include "te_config.h"

#include "tsx_lib.h"

#define BUILD_LIMIT_S   540
#define GUESS_LIMIT_S   60

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

    TEST_STEP("Known-bad control: the runner reports a hang, a signal and "
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

    TEST_STEP("Run ./build.sh, at most %d s", BUILD_LIMIT_S);
    if (!ts_run(b, src_root, "./build.sh", NULL, benv, shim, BUILD_LIMIT_S,
                "build"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start ./build.sh");
        goto verdict;
    }
    tsx_log_step("H2", "build", "./build.sh", b);
    ts_flat(b->err, 200, e, sizeof(e));
    T_FINDING(b->code == 0 && !b->hung ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.build", "./build.sh",
              "exit code %d, signal %d, hung %d", b->code, b->sig, b->hung);
    if (b->hung || b->sig != 0 || b->code != 0)
    {
        res_set(&res, R_FAIL, "H2 FAIL: step build: ./build.sh %s, exit "
                "code %d, required 0; stderr [%s]; ./scripts/run.sh guess "
                "was not run", b->hung ? "did not finish within the limit"
                : b->sig != 0 ? "was killed by a signal" : "failed",
                b->code, e);
        goto verdict;
    }

    TEST_STEP("Start the web services the example talks to");
    up = tsx_services_up("H2", note, sizeof(note));
    snprintf(url, sizeof(url), "RING_GATEWAY_URL=%s", tsx_url);
    genv[0] = url;
    genv[1] = "RING_TIMEOUT_MS=20000";
    genv[2] = NULL;

    TEST_STEP("Run ./scripts/run.sh guess, at most %d s", GUESS_LIMIT_S);
    if (!ts_run(g, src_root, "./scripts/run.sh guess", NULL, genv, NULL,
                GUESS_LIMIT_S, "guess"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start guess");
        goto verdict;
    }
    tsx_log_step("H2", "guess", "./scripts/run.sh guess", g);
    ts_flat(g->err, 200, e, sizeof(e));
    T_FINDING(g->code == 0 && !g->hung ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.run", "./scripts/run.sh guess",
              "exit code %d, signal %d, hung %d, %.1f s", g->code, g->sig,
              g->hung, g->secs);
    if (g->hung)
        res_set(&res, R_FAIL, "H2 FAIL: step guess: ./scripts/run.sh guess "
                "did not exit within %d s (killed); services up %d of 3 %s; "
                "stderr [%s]", GUESS_LIMIT_S, up, note, e);
    else if (g->sig != 0 || g->code != 0)
        res_set(&res, R_FAIL, "H2 FAIL: step guess: ./scripts/run.sh guess "
                "exit code %d signal %d, required 0; services up %d of 3 %s; "
                "stderr [%s]", g->code, g->sig, up, note, e);
    else
        res_set(&res, R_PASS, "H2 PASS: ./build.sh exited 0 in %.1f s and "
                "./scripts/run.sh guess exited 0 in %.1f s (limit %d s)",
                b->secs, g->secs, GUESS_LIMIT_S);

verdict:
    free(b);
    free(g);
    T_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
