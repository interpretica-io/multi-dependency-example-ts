/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: ts_build_run, the TypeScript example builds and runs
 *        (settles H1)
 *
 * Runs ./build.sh in the example root, then starts the TypeScript example
 * through ./scripts/run.sh guess. Pass when the build exits 0 and the
 * example exits 0 within 120 s. Every verdict starts with H1.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/ts_build_run"

#include "te_config.h"

#include "ts_lib.h"

#define BUILD_LIMIT_S   120
#define RUN_LIMIT_S     120

int
main(int argc, char **argv)
{
    res_t       res = { .kind = R_PASS };
    ts_run_t   *b = calloc(1, sizeof(*b));
    ts_run_t   *r = calloc(1, sizeof(*r));
    char        shim[300];
    char        why[400];
    char        t1[200];
    char        t2[200];
    char        e1[300];
    char        e2[300];
    char        o2[300];
    char        script[600];
    char        tsdir[600];
    char        pro[600];
    char        eb[300];
    const char *env[] = { "RuntimeIdentifier=linux-x64", NULL };

    TEST_START;
    t_report_begin();
    if (b == NULL || r == NULL)
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: out of memory");
        goto verdict;
    }
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: harness step broke: %.800s",
                res.msg);
        goto verdict;
    }
    if (!ts_cc_shim(workdir, shim, sizeof(shim)))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: cannot write the compiler "
                "shim in %s", workdir);
        goto verdict;
    }
    if (!ts_find_dir(src_root, tsdir, sizeof(tsdir)))
    {
        snprintf(tsdir, sizeof(tsdir), "%s/typescript", src_root);
        build_log_tail(pro, sizeof(pro));
        RING("webdeps H1: prologue build log: %s", pro);
        res_set(&res, R_FAIL, "H1 FAIL: the TypeScript directory %s is "
                "missing; earlier prologue failure text: [%s]", tsdir, pro);
        goto verdict;
    }
    snprintf(script, sizeof(script), "%s/build.sh", src_root);
    if (access(script, X_OK) != 0)
    {
        res_set(&res, R_FAIL, "H1 FAIL: %s does not exist or is not "
                "executable", script);
        goto verdict;
    }

    TEST_STEP("Known-bad control: the runner reports a hang and a signal");
    if (!ts_runner_control_ok(workdir, why, sizeof(why)))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: control failed: %s", why);
        goto verdict;
    }

    TEST_STEP("Run ./build.sh");
    if (!ts_run(b, src_root, "./build.sh", NULL, env, shim, BUILD_LIMIT_S,
                "build"))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: cannot start ./build.sh");
        goto verdict;
    }
    ts_end_text(b, t1, sizeof(t1));
    ts_flat(b->err_len > 0 ? b->err : b->out, 200, e1, sizeof(e1));
    ts_flat(b->err, 200, eb, sizeof(eb));
    RING("webdeps H1: command [./build.sh]; %s; stderr(200 B) [%s]", t1, eb);
    T_FINDING(b->code == 0 ? TAPI_CYBERSEC_SEV_INFO : TAPI_CYBERSEC_SEV_HIGH,
              "ts.build", "./build.sh", "%s", t1);
    if (b->code != 0)
    {
        build_log_tail(pro, sizeof(pro));
        RING("webdeps H1: cause of the earlier prologue failure, if any: %s",
             pro);
        res_set(&res, R_FAIL, "H1 FAIL: step build: ./build.sh exit code %d "
                "(%s); stderr [%s]; prologue log [%s]", b->code, t1, e1, pro);
        goto verdict;
    }

    TEST_STEP("Run ./scripts/run.sh guess, at most %d s", RUN_LIMIT_S);
    if (!ts_run(r, src_root, "./scripts/run.sh guess", NULL, NULL, NULL,
                RUN_LIMIT_S, "run"))
    {
        res_set(&res, R_FAIL, "H1 NOT SETTLED: cannot start the example");
        goto verdict;
    }
    ts_end_text(r, t2, sizeof(t2));
    ts_flat(r->err, 200, e2, sizeof(e2));
    ts_flat(r->out, 200, o2, sizeof(o2));
    RING("webdeps H1: command [./scripts/run.sh guess]; %s; stdout [%s] "
         "stderr(200 B) [%s]", t2, o2, e2);
    T_FINDING(r->code == 0 && !r->hung ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_HIGH, "ts.run", "./scripts/run.sh guess",
              "%s", t2);
    if (r->code != 0 || r->hung || r->sig != 0)
        res_set(&res, R_FAIL, "H1 FAIL: step run: ./scripts/run.sh guess "
                "exit code %d, not 0 within %d s (%s); stderr [%s]", r->code,
                RUN_LIMIT_S, t2, e2);
    else
        res_set(&res, R_PASS, "H1 PASS: ./build.sh exited 0 (%s) and the "
                "example exited 0 (%s) within %d s; stdout [%s]", t1, t2,
                RUN_LIMIT_S, o2);

verdict:
    free(b);
    free(r);
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
