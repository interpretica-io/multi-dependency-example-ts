/** @file
 * @brief Exposure Group
 *
 * Exposure group epilogue: make sure no process of the web tier, no
 * control listener and no capture is left behind on the agent, whatever
 * happened to the tests.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "exposure_common.h"

int
main(int argc, char **argv)
{
    tsapi_mde_session   session = { .ta = NULL };
    bool                session_up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int        left = 0;

    TEST_START;

    TEST_STEP("Finalize the exposure group");
    CHECK_RC(tsapi_mde_session_init(&session, "exposure_epilogue"));
    session_up = true;

    TEST_STEP("Count what is left of the web tier and the controls");
    /*
     * The patterns are written so that they never match the command line
     * of the shell that runs them: "dist/bin/(" and "server [1]" are not
     * what they match.
     */
    CHECK_RC(tsapi_mde_sh(&session, 20000, &res,
                          "pgrep -f 'dist/bin/(gateway-rs|service-go|"
                          "service-cs)' | wc -l; "
                          "pgrep -f 'http[.]server 180(9[6-9])' | wc -l"));
    {
        unsigned int a = 0;
        unsigned int b = 0;

        if (sscanf(te_string_value(&res.out), "%u %u", &a, &b) == 2)
            left = a + b;
        TEST_ARTIFACT("Left behind: %u web tier process(es), %u control "
                      "listener(s)", a, b);
    }
    if (left != 0)
        WARN("Processes were left behind by the tests of the group");

    TEST_STEP("Stop whatever is left (safety net)");
    CHECK_RC(tsapi_mde_sh(&session, 20000, &res,
                          "pkill -f 'dist/bin/(gateway-rs|service-go|"
                          "service-cs)'; "
                          "pkill -f 'http[.]server 180(9[6-9])'; "
                          "pkill -f 'curl -s -m 8 http://198[.]51'; "
                          "sudo -n pkill -INT -f "
                          "'tcpdum[p] -i lo -U -nn -s 0 -w /tmp/mde-exposure'; "
                          "rm -f /tmp/mde-exposure-egress.out; "
                          "sudo -n rm -f /tmp/mde-exposure-sniff.log; true"));

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
