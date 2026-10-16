/** @file
 * @brief Test Suite
 *
 * Test Suite prologue: report where the example under test is and whether it
 * has been built, so the per-group skips later in the run are easy to read.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session session;
    const char       *src;
    te_string         dist_bin = TE_STRING_INIT;
    bool              session_up = false;

    TEST_START;

    tsapi_evo_analysis_hint(
        "multi-dependency-example suite. Drives the built example's demos and "
        "HTTP services as programs on the agent and checks that a value still "
        "propagates through every stage of each dependency cycle.");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "prologue"));
    session_up = true;

    TEST_STEP("Report the example under test");
    src = tsapi_mde_src();
    if (src == NULL)
    {
        RING("TE_TS_MDE_SRC is not set: the suite has no example to test and "
             "every group will skip.");
    }
    else
    {
        RING("Example under test: %s", src);
        te_string_append(&dist_bin, "%s/dist/bin", src);
        if (tsapi_mde_exists(&session, dist_bin.ptr))
            RING("Found %s - the example is built.", dist_bin.ptr);
        else
            RING("No %s: build the example (./build.sh) or the groups will "
                 "skip.", dist_bin.ptr);
    }

    TEST_SUCCESS;

cleanup:

    te_string_free(&dist_bin);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
