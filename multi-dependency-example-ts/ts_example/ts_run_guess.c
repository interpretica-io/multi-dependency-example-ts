/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_run_guess, the TypeScript example starts and prints
 *        something (settles H2)
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
    char        gcmd[800];
    const char *env[3];
    int         up;

    TEST_START;
    t_report_begin();
    if (r == NULL)
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: out of memory");
        goto verdict;
    }
    if (!tsx_init(&res, "H2"))
        goto verdict;
    snprintf(runsh, sizeof(runsh), "%s/scripts/run.sh", src_root);

    TSX_STEP("Known-bad control: the runner reports a hang and a signal");
    if (!ts_runner_control_ok(workdir, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }
    if (access(runsh, X_OK) != 0)
    {
        res_set(&res, R_FAIL, "H2 FAIL: step missing file: %s does not "
                "exist or is not executable (run ts_build first)", runsh);
        goto verdict;
    }

    TSX_STEP("Start the web services the example talks to");
    up = tsx_services_up("H2", note, sizeof(note));
    snprintf(url, sizeof(url), "RING_GATEWAY_URL=%s", tsx_url);
    env[0] = url;
    env[1] = "RING_TIMEOUT_MS=20000";
    env[2] = NULL;

    TSX_STEP("Run ./scripts/run.sh guess, at most %d s", RUN_LIMIT_S);
    snprintf(gcmd, sizeof(gcmd), "'%s/scripts/run.sh' guess", src_root);
    if (!ts_run(r, src_root, gcmd, NULL, env, NULL, RUN_LIMIT_S, "guess"))
    {
        res_set(&res, R_FAIL, "H2 NOT SETTLED: cannot start the example");
        goto verdict;
    }
    tsx_log_step("H2", "guess", gcmd, r);
    ts_end_text(r, what, sizeof(what));
    ts_flat(r->err, 200, e, sizeof(e));
    ts_flat(r->out, 200, o, sizeof(o));
    T_FINDING(r->code == 0 && !r->hung && r->out_len > 0 ?
              TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH, "ts.run",
              "run.sh guess", "%s", what);
    if (r->hung && (ts_has_trace(r->err) || ts_has_trace(r->out)))
        res_set(&res, R_FAIL, "H2 FAIL: step start: %s printed a crash "
                "trace and was still running after %d s; services up: %d of "
                "3 %s; stderr [%s]", gcmd, RUN_LIMIT_S, up, note, e);
    else if (r->hung)
        res_set(&res, R_PASS, "H2 PASS: %s started and was still running "
                "without a crash after %d s (stopped by the test); services "
                "up: %d of 3", gcmd, RUN_LIMIT_S, up);
    else if (r->sig != 0)
        res_set(&res, R_FAIL, "H2 FAIL: step start: killed by signal %d; "
                "stderr [%s]", r->sig, e);
    else if (r->code != 0)
        res_set(&res, R_FAIL, "H2 FAIL: step start: exit code %d (%s); "
                "services up: %d of 3 %s; stderr [%s]", r->code, what, up,
                note, e);
    else if (r->out_len == 0)
        res_set(&res, R_FAIL, "H2 FAIL: step start: exit code 0 but stdout "
                "is empty; stderr [%s]", e);
    else
        res_set(&res, R_PASS, "H2 PASS: ./scripts/run.sh guess exited 0 in "
                "%.1f s with %zu bytes on stdout [%s]; services up: %d of 3",
                r->secs, r->out_len, o, up);

verdict:
    free(r);
    TSX_VERDICT(&res, "H2");

cleanup:
    cleanup_all();
    TEST_END;
}
