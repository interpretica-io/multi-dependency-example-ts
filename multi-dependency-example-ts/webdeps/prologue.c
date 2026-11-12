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
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *top = getenv("TS_TOPDIR");
    const char         *src = tsapi_mde_src();

    TEST_START;

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "webdeps_prologue"));
    session_up = true;

    if (src == NULL)
        TEST_FAIL("TE_TS_MDE_SRC is not set: the example is not available");
    if (top == NULL || top[0] == '\0')
        TEST_FAIL("TS_TOPDIR is not set: cannot find "
                  "scripts/ensure-web-deps.sh");

    TEST_STEP("Install the toolchains and build the example if needed");
    rc = tsapi_mde_sh(&session, 1800000, &res, "'%s/scripts/ensure-web-deps.sh' "
                      "'%s'", top, src);
    if (rc != 0 || !tsapi_mde_sh_ok(&res))
        TEST_FAIL("webdeps dependencies are not in place: %s",
                  res.err.ptr != NULL && res.err.ptr[0] != '\0' ?
                  res.err.ptr : "the install script did not run");
    RING("webdeps: %s", res.out.ptr != NULL ? res.out.ptr : "ready");

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
