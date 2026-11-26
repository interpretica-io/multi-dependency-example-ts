/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_guess_default, the documented trace of the demo
 *        (settles H1)
 *
 * Runs `./scripts/run.sh guess` (7 stages, last value 17.6799) and
 * `guess 42 3` (4 stages, last value 38.9640) as jobs on the agent with
 * RING_HOST and RING_PORT in their environment. Output is recorded as
 * artifacts.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_guess_default"

#include "tsg.h"

static const char *
judge(const tsapi_mde_sh_result *r, int stages, const char *last)
{
    if (tsg_code(r) != 0)
        return "exit code is not 0";
    if (tsg_stages(web_str(&r->out)) != stages)
        return "wrong number of stages";
    if (!tsg_last_value_is(web_str(&r->out), last))
        return "wrong last value";
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

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_guess_default"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H1 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the judge rejects planted wrong traces");
    te_string_append(&plant.out, "  [a] hops=1  1.0 -> 2.0\n"
                     "ts-demo: result = 17.6798\n");
    plant.started = true;
    plant.status.type = TAPI_JOB_STATUS_EXITED;
    if (judge(&plant, 7, "17.6799") == NULL ||
        judge(&plant, 1, "17.6799") == NULL ||
        judge(&plant, 1, "17.6798") != NULL)
        TEST_VERDICT("H1 NOT SETTLED: the trace judge is wrong");
    plant.status.value = 1;
    if (judge(&plant, 1, "17.6798") == NULL)
        TEST_VERDICT("H1 NOT SETTLED: the trace judge accepts exit 1");

    TSG_NEED_NODE(session);

    TEST_STEP("Run ./scripts/run.sh guess");
    CHECK_RC(tsg_guess(&session, root, TSG_ENV, "", 900, &res));
    tsg_art("H1 guess", "default run", &res);
    why = judge(&res, 7, "17.6799");
    if (why != NULL)
    {
        tsj_log_text("stderr", web_str(&res.err));
        TEST_VERDICT("H1 FAILED: guess with no arguments: %s (want exit 0, "
                     "7 stages, last value 17.6799)", why);
    }

    TEST_STEP("Run ./scripts/run.sh guess 42 3");
    CHECK_RC(tsg_guess(&session, root, TSG_ENV, "42 3", 120, &res));
    tsg_art("H1 guess", "42 3 run", &res);
    why = judge(&res, 4, "38.9640");
    if (why != NULL)
    {
        tsj_log_text("stderr", web_str(&res.err));
        TEST_VERDICT("H1 FAILED: guess 42 3: %s (want exit 0, 4 stages, "
                     "last value 38.9640)", why);
    }
    TEST_ARTIFACT("H1 the demo prints 7 stages ending at 17.6799 and 4 "
                  "stages ending at 38.9640");

    TEST_SUCCESS;

cleanup:
    tsapi_mde_sh_result_free(&res);
    tsapi_mde_sh_result_free(&plant);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
