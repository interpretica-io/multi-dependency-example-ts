/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_build_run, ./build.sh and ./scripts/run.sh guess
 *        (settles H1)
 *
 * Runs scripts/ensure-web-deps.sh base exposure ts, then ./build.sh with
 * RING_HOST and RING_PORT set (output in a file, its tail read back through
 * a job), then ./scripts/run.sh guess in TE_TS_MDE_SRC through tapi_job. The
 * exit code of the build must be 0 and its output must exist; the ensure
 * step is recorded as an artifact and, when it alone fails, named as a defect. The standard output of the run is recorded as
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

/** Record @p text as artifacts of 700 bytes, at most @p max bytes. */
static void
tsj_artifact_text(const char *label, const char *text, size_t max)
{
    size_t n = strlen(text);
    char   piece[701];
    char   clean[701];

    for (size_t off = 0; off < n && off < max; off += 700)
    {
        snprintf(piece, sizeof(piece), "%s", text + off);
        TEST_ARTIFACT("%s [%zu]: %s", label, off,
                      tsj_cut(clean, sizeof(clean), piece));
    }
    if (n == 0)
        TEST_ARTIFACT("%s: (empty)", label);
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
    int                 ensure_code = -1;
    bool                have_out = false;
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

    TEST_STEP("Step A: log node, npm, ts-node and tsc versions");
    snprintf(cmd, sizeof(cmd), "echo node $(node --version 2>&1); echo npm "
             "$(npm --version 2>&1); for d in ts web/service-ts; do cd '%s/'"
             "$d || continue; echo \"== $d ts-node:\"; npx --no-install "
             "ts-node --version 2>&1 | head -n 8; echo \"== $d tsc:\"; npx "
             "--no-install tsc --version 2>&1 | head -n 8; done", root);
    CHECK_RC(tsapi_mde_sh(&session, 120000, &res, "%s", cmd));
    tsj_artifact_text("H1 versions", web_str(&res.out), 4000);
    tsapi_mde_sh_result_free(&res);
    res = (tsapi_mde_sh_result)TSAPI_MDE_SH_RESULT_INIT;

    TEST_STEP("Step B: run scripts/ensure-web-deps.sh base exposure ts, keep "
              "the whole output and the exit code as artifacts");
    top = getenv("TS_TOPDIR");
    if (top == NULL || top[0] == '\0')
        TEST_VERDICT("H1 NOT SETTLED: TS_TOPDIR is not set, so "
                     "scripts/ensure-web-deps.sh cannot be found");
    snprintf(cmd, sizeof(cmd), "'%s/scripts/ensure-web-deps.sh' '%s' base "
             "exposure ts > /tmp/ensure.log 2>&1; echo exit=$? > "
             "/tmp/ensure.rc; cat /tmp/ensure.rc; tr -c '[:print:]\\n' '.' "
             "< /tmp/ensure.log | tr '\\n' '|'", top, root);
    CHECK_RC(tsapi_mde_sh(&session, 1800000, &res, "%s", cmd));
    p = strstr(web_str(&res.out), "exit=");
    code = p != NULL ? atoi(p + 5) : -1;
    ensure_code = code;
    TEST_ARTIFACT("H1 ensure-web-deps.sh base exposure ts exit code: %d",
                  code);
    p = strchr(web_str(&res.out), '\n');
    tsj_artifact_text("H1 ensure-web-deps.sh output", p != NULL ? p + 1 : "",
                      60000);
    tsapi_mde_sh_result_free(&res);
    res = (tsapi_mde_sh_result)TSAPI_MDE_SH_RESULT_INIT;

    TEST_STEP("Step C: run ./build.sh with RING_HOST and RING_PORT set, "
              "whatever step B gave");
    snprintf(cmd, sizeof(cmd), "cd '%s' && export RING_HOST=127.0.0.1 "
             "RING_PORT=9100 && { ./build.sh >/tmp/build.log 2>/tmp/build.err;"
             " echo exit=$?; tr -c '[:print:]\\n' '.' < /tmp/build.err | "
             "tail -n 30 | tr '\\n' '|'; }", root);
    CHECK_RC(tsapi_mde_sh(&session, 900000, &res, "%s", cmd));
    p = strstr(web_str(&res.out), "exit=");
    code = p != NULL ? atoi(p + 5) : -1;
    TEST_ARTIFACT("H1 build.sh exit code: %d", code);
    p = strchr(web_str(&res.out), '\n');
    snprintf(last, sizeof(last), "%s", p != NULL ? p + 1 : "");
    tsapi_mde_sh_result_free(&res);
    res = (tsapi_mde_sh_result)TSAPI_MDE_SH_RESULT_INIT;

    TEST_STEP("Step D: list the build output");
    snprintf(cmd, sizeof(cmd), "cd '%s' && ls -l ts/out/main.js "
             "web/service-ts/out/main.js 2>&1; ls ts/dist 2>&1 | head -n 20",
             root);
    CHECK_RC(tsapi_mde_sh(&session, 30000, &res, "%s", cmd));
    tsj_artifact_text("H1 build output ls", web_str(&res.out), 3000);
    tsapi_mde_sh_result_free(&res);
    res = (tsapi_mde_sh_result)TSAPI_MDE_SH_RESULT_INIT;
    snprintf(cmd, sizeof(cmd), "test -f '%s/ts/out/main.js' || test -d "
             "'%s/ts/dist'", root, root);
    have_out = tsj_ok(&session, 10000, cmd);

    TEST_STEP("Verdict");
    if (code != 0)
        TEST_VERDICT("H1 FAILED: ./build.sh did not exit with code 0, last "
                     "lines of stderr: %s", last);
    if (!have_out)
        TEST_VERDICT("H1 FAILED: ./build.sh exited 0 but neither "
                     "ts/out/main.js nor ts/dist exists");
    if (ensure_code != 0)
        TEST_ARTIFACT("H1 project_spec defect: scripts/ensure-web-deps.sh "
                      "base exposure ts exited %d while ./build.sh passed "
                      "and the build output exists", ensure_code);
    else
        TEST_ARTIFACT("H1 ./build.sh exits 0 and the build output exists");

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
