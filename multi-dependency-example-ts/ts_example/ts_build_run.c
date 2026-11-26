/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_build_run, ./build.sh and ./scripts/run.sh guess
 *        (settles H1)
 *
 * Runs scripts/ensure-web-deps.sh base exposure ts, then ./build.sh with
 * RING_HOST and RING_PORT set (output in a file, its tail read back through
 * a job), then ./scripts/run.sh guess in TE_TS_MDE_SRC through tapi_job. The
 * exit code of each must be 0; a failed ensure step is named as the likely
 * cause of H1. The standard output of the run is recorded as
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

/** The last 20 lines of @p text on one line of at most 1500 bytes. */
static void
last20(const char *text, char *out, size_t size)
{
    tsj_cut(out, size, tsj_last_lines(text, 20));
    for (char *c = out; *c != '\0'; c++)
        if (*c == '\n')
            *c = '|';
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    char                cmd[600];
    char                piece[401];
    char                last[1501];
    const char         *top;
    int                 code = -1;
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

    TEST_STEP("Run scripts/ensure-web-deps.sh base exposure ts as its own "
              "job");
    top = getenv("TS_TOPDIR");
    if (top == NULL || top[0] == '\0')
        TEST_VERDICT("H1 NOT SETTLED: TS_TOPDIR is not set, so "
                     "scripts/ensure-web-deps.sh cannot be found");
    snprintf(cmd, sizeof(cmd), "'%s/scripts/ensure-web-deps.sh' '%s' base "
             "exposure ts > /tmp/ensure.log 2>&1; echo exit=$?; "
             "tail -n 30 /tmp/ensure.log", top, root);
    CHECK_RC(tsapi_mde_sh(&session, 1800000, &res, "%s", cmd));
    p = strstr(web_str(&res.out), "exit=");
    code = p != NULL ? atoi(p + 5) : -1;
    snprintf(piece, sizeof(piece), "%s", tsj_last_lines(web_str(&res.out), 8));
    for (char *c = piece; *c != '\0'; c++)
        if (*c == '\n')
            *c = '|';
    TEST_ARTIFACT("H1 ensure-web-deps.sh base exposure ts: exit %d, output "
                  "[%s]", code, piece);
    if (code != 0)
    {
        last20(web_str(&res.out), last, sizeof(last));
        TEST_VERDICT("H1 FAILED: scripts/ensure-web-deps.sh base exposure ts "
                     "failed, the likely cause of the build failure: %s",
                     last);
    }
    tsapi_mde_sh_result_free(&res);
    res = (tsapi_mde_sh_result)TSAPI_MDE_SH_RESULT_INIT;

    TEST_STEP("Run ./build.sh with RING_HOST and RING_PORT set");
    snprintf(cmd, sizeof(cmd), "cd '%s' && export RING_HOST=127.0.0.1 "
             "RING_PORT=9100 && { ./build.sh >/tmp/build.log 2>&1; echo "
             "exit=$?; tail -n 60 /tmp/build.log; }", root);
    CHECK_RC(tsapi_mde_sh(&session, 900000, &res, "%s", cmd));
    p = strstr(web_str(&res.out), "exit=");
    code = p != NULL ? atoi(p + 5) : -1;
    tsj_log_text("build tail", web_str(&res.out));
    n = strlen(web_str(&res.out));
    for (size_t off = 0; off < n && off < 4000; off += 400)
    {
        snprintf(piece, sizeof(piece), "%s", web_str(&res.out) + off);
        TEST_ARTIFACT("H1 build.sh exit and tail [%zu]: %s", off, piece);
    }
    if (code != 0)
    {
        last20(web_str(&res.out), last, sizeof(last));
        TEST_VERDICT("H1 FAILED: ./build.sh did not exit with code 0, last "
                     "lines: %s", last);
    }
    tsapi_mde_sh_result_free(&res);
    res = (tsapi_mde_sh_result)TSAPI_MDE_SH_RESULT_INIT;

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
    {
        snprintf(piece, sizeof(piece), "%s", p + off);
        TEST_ARTIFACT("H1 run.sh guess stdout [%zu]: %s", off, piece);
    }

    TEST_SUCCESS;

cleanup:
    tsapi_mde_sh_result_free(&res);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
