/** @file
 * @brief printing Group
 *
 * printing group epilogue: stop the CUPS scheduler the prologue started,
 * and only that one - the marker /tmp/mde-cupsd.started says whether the
 * suite started it. Its configuration copy and queues in /tmp/mde-cupsd
 * go with it. A scheduler that was running before the suite is left
 * alone.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "printing/epilogue"

#include "te_config.h"
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"

#include "tsapi_mde.h"

/**
 * Stop the suite's own cupsd if the marker says it was started by the
 * suite. Prints "MDE-CUPSD: stopped" or "MDE-CUPSD: nothing to undo".
 */
static const char stop_cupsd[] =
    "D=/tmp/mde-cupsd; M=/tmp/mde-cupsd.started\n"
    "P='/tmp/mde-cupsd/cupsd[.]conf'; Q=/dev/null\n"
    "if [ ! -f \"$M\" ]; then\n"
    "    echo 'MDE-CUPSD: nothing to undo'; exit 0\n"
    "fi\n"
    "sudo -n pkill -TERM -f \"$P\"\n"
    "i=0\n"
    "while [ $i -lt 50 ] && pgrep -f \"$P\" >$Q; do\n"
    "    sleep 0.2; i=$((i + 1))\n"
    "done\n"
    "pgrep -f \"$P\" >$Q && sudo -n pkill -KILL -f \"$P\"\n"
    "sudo -n rm -rf \"$D\"\n"
    "rm -f \"$M\"\n"
    "echo 'MDE-CUPSD: stopped'\n"
    "exit 0\n"
    ;

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const char         *state;

    TEST_START;

    TEST_STEP("Finalize the printing group");
    CHECK_RC(tsapi_mde_session_init(&session, "printing_epilogue"));
    session_up = true;

    TEST_STEP("Stop the scheduler the prologue started, if it did");
    CHECK_RC(tsapi_mde_sh(&session, 60000, &sh, "%s", stop_cupsd));
    if (!tsapi_mde_sh_ok(&sh))
        WARN("Stopping the scheduler did not finish cleanly");
    state = strstr(te_string_value(&sh.out), "MDE-CUPSD: ");
    TEST_ARTIFACT("printing epilogue: %.*s",
                  state != NULL ? (int)strcspn(state, "\n") : 7,
                  state != NULL ? state : "unknown");

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
