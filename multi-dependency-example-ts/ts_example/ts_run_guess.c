/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_run_guess, the TypeScript example starts and prints
 *        something (settles H1)
 *
 * Starts the web services that exist (the TypeScript example is a client of
 * the gateway), then runs ./scripts/run.sh guess under a 30 s limit with the
 * gateway address in RING_GATEWAY_URL. Passes on exit code 0 and a non-empty
 * stdout. Fails on a non-zero exit code, a timeout kill or an empty stdout.
 * The verdict names which services were not up, since a run that cannot
 * reach the gateway fails for that reason and not in the example itself.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_run_guess"

#include "te_config.h"

#include "tsx_lib.h"

#define RUN_LIMIT_S     30

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *r = calloc(1, sizeof(*r));
    char        why[400];
    char        note[900];
    char        what[200];
    char        e[300];
    char        o[300];
    char        url[200];
    char        runsh[700];
    const char *env[3];
    int         up;

    TEST_START;
    t_report_begin();
    if (r == NULL)
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H1"))
        goto verdict;
    snprintf(runsh, sizeof(runsh), "%s/scripts/run.sh", src_root);

    TEST_STEP("Known-bad control: the runner reports a hang and a signal");
    if (!ts_runner_control_ok(workdir, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }
    if (access(runsh, X_OK) != 0)
    {
        res_set(&res, R_FAIL, "H1 FAIL: step missing file: %s does not "
                "exist or is not executable (run ts_build first)", runsh);
        goto verdict;
    }

    TEST_STEP("Start the web services the example talks to");
    up = tsx_services_up("H1", note, sizeof(note));
    snprintf(url, sizeof(url), "RING_GATEWAY_URL=%s", tsx_url);
    env[0] = url;
    env[1] = "RING_TIMEOUT_MS=20000";
    env[2] = NULL;

    TEST_STEP("Run ./scripts/run.sh guess, at most %d s", RUN_LIMIT_S);
    if (!ts_run(r, src_root, "./scripts/run.sh guess", NULL, env, NULL,
                RUN_LIMIT_S, "guess"))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: cannot start the example");
        goto verdict;
    }
    tsx_log_step("H1", "guess", "./scripts/run.sh guess", r);
    ts_end_text(r, what, sizeof(what));
    ts_flat(r->err, 200, e, sizeof(e));
    ts_flat(r->out, 200, o, sizeof(o));
    T_FINDING(r->code == 0 && !r->hung && r->out_len > 0 ?
              TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH, "ts.run",
              "./scripts/run.sh guess", "%s", what);
    if (r->hung)
        res_set(&res, R_FAIL, "H1 FAIL: step start: ./scripts/run.sh guess "
                "was killed after %d s (timeout); services up: %d of 3 %s; "
                "stderr [%s]", RUN_LIMIT_S, up, note, e);
    else if (r->sig != 0)
        res_set(&res, R_FAIL, "H1 FAIL: step start: killed by signal %d; "
                "stderr [%s]", r->sig, e);
    else if (r->code != 0)
        res_set(&res, R_FAIL, "H1 FAIL: step start: exit code %d (%s); "
                "services up: %d of 3 %s; stderr [%s]", r->code, what, up,
                note, e);
    else if (r->out_len == 0)
        res_set(&res, R_FAIL, "H1 FAIL: step start: exit code 0 but stdout "
                "is empty; stderr [%s]", e);
    else
        res_set(&res, R_PASS, "H1 PASS: ./scripts/run.sh guess exited 0 in "
                "%.1f s with %zu bytes on stdout [%s]; services up: %d of 3",
                r->secs, r->out_len, o, up);

verdict:
    free(r);
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
