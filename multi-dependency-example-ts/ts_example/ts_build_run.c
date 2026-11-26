/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_build_run, ./build.sh and ./scripts/run.sh guess
 *        (settles H1)
 *
 * Runs ./build.sh and then ./scripts/run.sh guess in TE_TS_MDE_SRC through
 * tapi_job. Both must exit 0. The standard output of the run is recorded as
 * an artifact. A missing node is a skip.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_build_run"

#include "tsj.h"

static void
run_step(tsapi_mde_session *s, const char *what, const char *cmd, int tmo_ms,
         tsapi_mde_sh_result *res)
{
    te_errno rc = tsapi_mde_sh(s, tmo_ms, res, "%s", cmd);

    if (rc != 0 || !res->started)
        TEST_VERDICT("H1 NOT SETTLED: %s could not be started", what);
    if (res->status.type != TAPI_JOB_STATUS_EXITED ||
        res->status.value != 0)
    {
        tsj_log_text("stdout", web_str(&res->out));
        tsj_log_text("stderr", web_str(&res->err));
        TEST_VERDICT("H1 FAILED: %s did not exit with code 0", what);
    }
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    char                cmd[600];
    const char         *root;
    const char         *p;
    size_t              n;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_build_run"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H1 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: a failing command is seen with its exit code");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &res,
                          "echo planted >&2; exit 3"));
    if (res.status.type != TAPI_JOB_STATUS_EXITED ||
        res.status.value != 3 || strstr(web_str(&res.err), "planted") == NULL)
        TEST_VERDICT("H1 NOT SETTLED: the job runner does not report exit "
                     "code and stderr of a failing command");

    TEST_STEP("Skip when node is missing");
    if (!tsapi_mde_have(&session, "node"))
        TEST_SKIP("node is not on the agent and the setup script could not "
                  "install it");

    TEST_STEP("Run ./build.sh");
    snprintf(cmd, sizeof(cmd), "cd '%s' && ./build.sh", root);
    run_step(&session, "./build.sh", cmd, 600000, &res);
    RING("build.sh exited 0");

    TEST_STEP("Run ./scripts/run.sh guess");
    snprintf(cmd, sizeof(cmd), "cd '%s' && RING_HOST=127.0.0.1 "
             "RING_PORT=9100 timeout 120 ./scripts/run.sh guess", root);
    run_step(&session, "./scripts/run.sh guess", cmd, 150000, &res);

    TEST_STEP("Record the standard output as an artifact");
    p = web_str(&res.out);
    n = strlen(p);
    if (n == 0)
        TEST_VERDICT("H1 FAILED: ./scripts/run.sh guess printed nothing");
    for (size_t off = 0; off < n && off < 4000; off += 400)
        TEST_ARTIFACT("H1 run.sh guess stdout [%zu]: %.400s", off, p + off);

    TEST_SUCCESS;

cleanup:
    tsapi_mde_sh_result_free(&res);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
