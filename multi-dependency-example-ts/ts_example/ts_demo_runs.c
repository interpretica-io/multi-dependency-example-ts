/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_demo_runs, the demo runs from the run script
 *        (settles H1)
 *
 * Starts `./scripts/run.sh guess` as a job with RING_HOST and RING_PORT
 * set. It must exit 0 and print something; the output is recorded as an
 * artifact. Control: a command that prints nothing is rejected by the same
 * judge. Skipped when node is missing.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_demo_runs"

#include "tsg.h"

/** NULL when a run is the documented one: exit 0 and non-empty output. */
static const char *
judge(const tsapi_mde_sh_result *r)
{
    if (tsg_code(r) != 0)
        return "exit code is not 0";
    if (web_str(&r->out)[0] == '\0')
        return "stdout is empty";
    return NULL;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_sh_result plant = TSAPI_MDE_SH_RESULT_INIT;
    const char         *root;
    const char         *why;
    char                cut[501];
    size_t              i;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_demo_runs"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H1 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the judge rejects an empty output and a bad exit");
    TSG_NEED_NODE(session);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &plant, "true"));
    if (judge(&plant) == NULL)
        TEST_VERDICT("H1 NOT SETTLED: the judge accepts an empty output");
    tsapi_mde_sh_result_free(&plant);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &plant, "echo x; exit 3"));
    if (judge(&plant) == NULL)
        TEST_VERDICT("H1 NOT SETTLED: the judge accepts exit 3");
    tsapi_mde_sh_result_free(&plant);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &plant, "echo x"));
    if (judge(&plant) != NULL)
        TEST_VERDICT("H1 NOT SETTLED: the judge rejects a good run");

    TEST_STEP("Run ./scripts/run.sh guess");
    CHECK_RC(tsg_guess(&session, root, TSG_ENV, "", 900, &res));
    tsj_log_text("stdout", web_str(&res.out));
    tsj_log_text("stderr", web_str(&res.err));
    why = judge(&res);
    if (why != NULL)
    {
        tsj_cut(cut, sizeof(cut), tsj_last_lines(web_str(&res.err), 5));
        for (i = 0; cut[i] != '\0'; i++)
            if (cut[i] == '\n')
                cut[i] = '|';
        TEST_VERDICT("H1 FAILED: ./scripts/run.sh guess: %s, stderr end "
                     "[%s]", why, cut);
    }

    TEST_STEP("Record the output as an artifact");
    tsg_art("H1", "run.sh guess", &res);
    TEST_ARTIFACT("H1 the demo runs from scripts/run.sh guess: exit 0, "
                  "%d stage lines", tsg_stages(web_str(&res.out)));
    TEST_SUCCESS;

cleanup:
    tsapi_mde_sh_result_free(&res);
    tsapi_mde_sh_result_free(&plant);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
