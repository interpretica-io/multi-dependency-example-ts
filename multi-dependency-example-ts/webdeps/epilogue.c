/** @file
 * @brief Webdeps Group
 *
 * Webdeps group epilogue: stop whatever a failed test left of the web
 * tier and of the stub peers.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session session = { .ta = NULL };
    bool              session_up = false;

    TEST_START;

    TEST_STEP("Finalize the webdeps group");
    CHECK_RC(tsapi_mde_session_init(&session, "webdeps_epilogue"));
    session_up = true;

    TEST_STEP("Stop whatever is left (safety net)");
    /* The patterns never match the command line of the shell running them. */
    (void)exposure_sh_quiet(&session,
                            "pkill -f 'dist/bin/(gateway-rs|service-go|"
                            "service-cs)'; pkill -f 'mde-wd/stu[b][.]py'; "
                            "rm -rf /tmp/mde-wd; true");

    TEST_SUCCESS;

cleanup:

    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
