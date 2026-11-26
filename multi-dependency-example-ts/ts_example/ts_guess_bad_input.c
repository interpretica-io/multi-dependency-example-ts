/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_guess_bad_input, bad input is refused with exit 1
 *        (settles H2)
 *
 * Known-bad controls for ts_guess_default: RING_HOST unset, RING_PORT unset,
 * `guess 1 65` and `guess abc 3`. Each must exit 1 with the documented
 * error line. A good run is made first so a refusal is not an environment
 * fault.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_guess_bad_input"

#include "tsg.h"

/** NULL when the run is the documented refusal with @p line in @p text. */
static const char *
refused(const tsapi_mde_sh_result *r, const char *text, const char *line)
{
    if (tsg_code(r) != 1)
        return "exit code is not 1";
    if (strstr(text, line) == NULL)
        return "the error line is missing";
    return NULL;
}

int
main(int argc, char **argv)
{
    static const struct {
        const char *what;
        const char *env;
        const char *args;
        const char *line;
    } cases[] = {
        { "RING_HOST unset", "-u RING_HOST RING_PORT=9100", "",
          "is not set" },
        { "RING_PORT unset", "-u RING_PORT RING_HOST=127.0.0.1", "",
          "is not set" },
        { "hops 65", TSG_ENV, "1 65", "ts-demo: error:" },
        { "value abc", TSG_ENV, "abc 3", "ts-demo: error:" },
    };
    tsapi_mde_session   session;
    bool                up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_sh_result plant = TSAPI_MDE_SH_RESULT_INIT;
    const char         *root;
    const char         *why;
    size_t              i;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_guess_bad_input"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H2 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the judge rejects a good run and a wrong code");
    plant.started = true;
    plant.status.type = TAPI_JOB_STATUS_EXITED;
    if (refused(&plant, "x is not set", "is not set") == NULL)
        TEST_VERDICT("H2 NOT SETTLED: the judge accepts exit 0");
    plant.status.value = 1;
    if (refused(&plant, "all fine", "is not set") == NULL ||
        refused(&plant, "x is not set", "is not set") != NULL)
        TEST_VERDICT("H2 NOT SETTLED: the judge is wrong");

    TSG_NEED_NODE(session);

    TEST_STEP("Known-good control: a valid run exits 0");
    CHECK_RC(tsg_guess(&session, root, TSG_ENV, "42 3", 900, &res));
    if (tsg_code(&res) != 0)
    {
        tsj_log_text("stderr", web_str(&res.err));
        TEST_VERDICT("H2 NOT SETTLED: the valid control run `guess 42 3` "
                     "did not exit 0, so a refusal proves nothing");
    }

    for (i = 0; i < TE_ARRAY_LEN(cases); i++)
    {
        TEST_STEP("Run guess with bad input: %s", cases[i].what);
        CHECK_RC(tsg_guess(&session, root, cases[i].env, cases[i].args, 120,
                           &res));
        tsg_art("H2", cases[i].what, &res);
        why = refused(&res, web_str(&res.err), cases[i].line);
        if (why != NULL)
            TEST_VERDICT("H2 FAILED: %s: %s (want exit 1 and a line with "
                         "'%s' on stderr)", cases[i].what, why,
                         cases[i].line);
    }
    TEST_ARTIFACT("H2 bad input is refused with exit 1 and one error line "
                  "in all four cases");

    TEST_SUCCESS;

cleanup:
    tsapi_mde_sh_result_free(&res);
    tsapi_mde_sh_result_free(&plant);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
