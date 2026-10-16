/** @file
 * @brief Ring Group
 *
 * The one documented numeric oracle of the ring: cpp-demo with value=1 and
 * hops=7 produces 20.0735 when the ring is correct (README reference output).
 * The injected defect stops the ring at the first stage, so it yields the
 * first stage's value instead.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/reference"

#include "te_config.h"
#include <math.h>
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"

#define REF_RESULT_RE   "result = (-?[0-9]+\\.[0-9]+)"
#define REF_EXPECTED    20.0735
#define REF_EPS         1.0e-3

int
main(int argc, char **argv)
{
    const char          *src;
    te_string            program = TE_STRING_INIT;
    const char          *cmd[4];
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_run_result res;
    tsapi_evo_schart     chart;
    char                 metric[32];

    TEST_START;

    TEST_STEP("Locate the example under test");
    src = tsapi_mde_src();
    if (src == NULL)
        TEST_SKIP("TE_TS_MDE_SRC is not set");

    te_string_append(&program, "%s/dist/bin/cpp-demo", src);
    cmd[0] = program.ptr;
    cmd[1] = "1";
    cmd[2] = "7";
    cmd[3] = NULL;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "reference"));
    session_up = true;

    TEST_STEP("Skip unless the demo can be run");
    if (!tsapi_mde_exists(&session, program.ptr))
        TEST_SKIP("%s is missing - build the example first", program.ptr);

    TEST_STEP("Run cpp-demo 1 7 and read the result");
    CHECK_RC(tsapi_mde_run(&session, cmd[0], cmd, 30000, NULL,
                           REF_RESULT_RE, &res));
    if (!res.started)
        TEST_FAIL("The demo could not be started");
    if (!res.have_value)
        TEST_VERDICT("cpp-demo printed no result line");

    RING("cpp-demo 1 7 -> %.4f (expected %.4f)", res.value, REF_EXPECTED);

    TEST_STEP("Record the result against the reference");
    tsapi_evo_analysis_hint(
        "cpp-demo 1 7 should return 20.0735 (README reference). The injected "
        "defect returns the first stage's value, about 2.6, instead.");
    tsapi_evo_schart_init(&chart, "Ring reference result",
                          "Result / cpp 1 7", "20.0735", "value");
    TE_SPRINTF(metric, "%.4f", res.value);
    tsapi_evo_schart_add_metric(&chart, "cpp/1/7", metric, NULL);
    tsapi_evo_schart_print(&chart);
    tsapi_evo_schart_fini(&chart);

    TEST_STEP("Check the result matches the reference");
    if (fabs(res.value - REF_EXPECTED) > REF_EPS)
    {
        TEST_VERDICT("Ring result %.4f, expected %.4f (value=1, hops=7)",
                     res.value, REF_EXPECTED);
    }

    TEST_SUCCESS;

cleanup:

    te_string_free(&program);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
