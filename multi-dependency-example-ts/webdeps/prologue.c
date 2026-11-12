/** @file
 * @brief webdeps Group
 *
 * webdeps group prologue: install what the group needs on the agent (the
 * C, Go, Rust, .NET and Python toolchains, the socket viewer and the
 * binary tools), then check that the example is built, building it when
 * it is not. Fails with what went wrong when a tool cannot be installed
 * or the build does not produce the web tier.
 *
 * Copyright (C) 2026 midair <midair@localhost>
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/prologue"

#include "te_config.h"

#include <stdlib.h>

#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "webdeps_prologue"));
    session_up = true;

    TEST_STEP("Install the toolchains and build the example if needed");
    TSAPI_MDE_ENSURE(session, "base build");

    TEST_SUCCESS;

cleanup:

    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
