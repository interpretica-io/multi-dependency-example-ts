/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_env_failfast, a missing ring variable fails at once
 *        (settles H2)
 *
 * Runs `./scripts/run.sh guess serve` with RING_HOST unset, then with
 * RING_PORT unset: each must exit 1 with an "is not set" line. Control:
 * with both set the run must not exit 1 at once (the server is stopped
 * after a short time).
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_env_failfast"

#include "tsg.h"

/** NULL when the run is the documented refusal. */
static const char *
refused(const tsapi_mde_sh_result *r)
{
    if (tsg_code(r) != 1)
        return "exit code is not 1";
    if (strstr(web_str(&r->err), "is not set") == NULL)
        return "no 'is not set' line on stderr";
    return NULL;
}

int
main(int argc, char **argv)
{
    static const struct {
        const char *what;
        const char *env;
    } cases[] = {
        { "RING_HOST unset", "-u RING_HOST RING_PORT=9100" },
        { "RING_PORT unset", "-u RING_PORT RING_HOST=127.0.0.1" },
    };
    tsapi_mde_session   session;
    bool                up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_sh_result plant = TSAPI_MDE_SH_RESULT_INIT;
    const char         *root;
    const char         *why;
    unsigned int        port;
    size_t              i;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_env_failfast"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H2 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the judge rejects a run that does not refuse");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &plant, "echo x is not set >&2; "
                          "exit 2"));
    if (refused(&plant) == NULL)
        TEST_VERDICT("H2 NOT SETTLED: the judge accepts exit 2");
    tsapi_mde_sh_result_free(&plant);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &plant, "echo x is not set >&2; "
                          "exit 1"));
    if (refused(&plant) != NULL)
        TEST_VERDICT("H2 NOT SETTLED: the judge rejects a planted refusal");
    tsapi_mde_sh_result_free(&plant);

    TSG_NEED_NODE(session);

    TEST_STEP("Known-good control: with both set the server does not exit "
              "1 at once");
    port = tsj_free_port(&session);
    if (port == 0)
        TEST_VERDICT("H2 NOT SETTLED: no free port on the agent");
    CHECK_RC(tsapi_mde_sh(&session, 60000, &res,
                          "cd '%s' && env RING_HOST=127.0.0.1 RING_PORT=%u "
                          "timeout 3 ./scripts/run.sh guess serve", root,
                          port));
    tsg_art("H2", "both set (control)", &res);
    if (tsg_code(&res) == 1)
        TEST_VERDICT("H2 NOT SETTLED: the control run with both variables "
                     "set exited 1, so a refusal proves nothing");
    tsapi_mde_sh_result_free(&res);

    for (i = 0; i < TE_ARRAY_LEN(cases); i++)
    {
        TEST_STEP("Run guess serve with %s", cases[i].what);
        CHECK_RC(tsg_guess(&session, root, cases[i].env, "serve", 60, &res));
        tsg_art("H2", cases[i].what, &res);
        why = refused(&res);
        if (why != NULL)
            TEST_VERDICT("H2 FAILED: %s: %s (want exit 1 and an "
                         "'is not set' line on stderr)", cases[i].what, why);
        tsapi_mde_sh_result_free(&res);
    }

    TEST_ARTIFACT("H2 run.sh guess serve exits 1 with an 'is not set' "
                  "line when RING_HOST or RING_PORT is unset; with both "
                  "set it does not exit 1 at once");
    TEST_SUCCESS;

cleanup:
    tsapi_mde_sh_result_free(&res);
    tsapi_mde_sh_result_free(&plant);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
