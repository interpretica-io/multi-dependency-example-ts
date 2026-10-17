/** @file
 * @brief printing Group
 *
 * printing group prologue: make sure a CUPS scheduler answers on the
 * agent. A container has no init to start one, so when none answers
 * and passwordless sudo is there, a cupsd of the suite's own is started
 * from a copy of the image's configuration in /tmp/mde-cupsd: the copy
 * permits the file: device (FileDevice Yes) the job tests print to and
 * makes the agent user's group a system group, so that it may add and
 * remove queues. The image's /etc/cups is left as it is. The marker
 * /tmp/mde-cupsd.started records that the suite started the scheduler,
 * so the epilogue stops only what was started here. Without sudo
 * nothing is started, and the tests skip as before.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "printing/prologue"

#include "te_config.h"
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"

#include "tsapi_mde.h"

#include "tapi_print.h"

#define T_MS    30000

/**
 * Start a cupsd of the suite's own unless one answers already. It
 * prints one "MDE-CUPSD: <state>" line: present (a scheduler was
 * running), adopted (the suite's own from an earlier run), started,
 * not-answering, start-failed, no-sudo, no-cupsd, no-client, no-dir.
 */
static const char start_cupsd[] =
    "D=/tmp/mde-cupsd; M=/tmp/mde-cupsd.started\n"
    "P='/tmp/mde-cupsd/cupsd[.]conf'; Q=/dev/null\n"
    "running() { lpstat -r 2>$Q | grep -q 'scheduler is running'; }\n"
    "if running; then\n"
    "    if pgrep -f \"$P\" >$Q 2>&1; then\n"
    "        echo started > \"$M\"\n"
    "        echo 'MDE-CUPSD: adopted'\n"
    "    else\n"
    "        echo 'MDE-CUPSD: present'\n"
    "    fi\n"
    "    exit 0\n"
    "fi\n"
    "if ! command -v lpstat >$Q 2>&1; then\n"
    "    echo 'MDE-CUPSD: no-client'; exit 0\n"
    "fi\n"
    "C=/usr/sbin/cupsd; [ -x \"$C\" ] || C=$(command -v cupsd)\n"
    "if [ -z \"$C\" ] || [ ! -x \"$C\" ] ||\n"
    "   [ ! -r /etc/cups/cupsd.conf ]; then\n"
    "    echo 'MDE-CUPSD: no-cupsd'; exit 0\n"
    "fi\n"
    "if ! sudo -n true >$Q 2>&1; then\n"
    "    echo 'MDE-CUPSD: no-sudo'; exit 0\n"
    "fi\n"
    "G=$(id -gn 2>$Q)\n"
    "sudo -n rm -rf \"$D\"\n"
    "mkdir -p \"$D\" || { echo 'MDE-CUPSD: no-dir'; exit 0; }\n"
    "cp /etc/cups/cupsd.conf \"$D/cupsd.conf\"\n"
    "cp /etc/cups/*.types /etc/cups/*.convs \"$D/\" 2>$Q\n"
    "F=\"$D/cups-files.conf\"\n"
    "if [ -r /etc/cups/cups-files.conf ]; then\n"
    "    sed -e '/^[[:space:]]*FileDevice[[:space:]]/d' \\\n"
    "        -e '/^[[:space:]]*SystemGroup[[:space:]]/d' \\\n"
    "        /etc/cups/cups-files.conf > \"$F\"\n"
    "fi\n"
    "echo \"SystemGroup root lpadmin $G\" >> \"$F\"\n"
    "echo 'FileDevice Yes' >> \"$F\"\n"
    "if ! sudo -n \"$C\" -c \"$D/cupsd.conf\" -s \"$F\" <$Q >$Q 2>&1; then\n"
    "    echo 'MDE-CUPSD: start-failed'; exit 0\n"
    "fi\n"
    "echo started > \"$M\"\n"
    "i=0\n"
    "while [ $i -lt 60 ] && ! running; do\n"
    "    sleep 0.5; i=$((i + 1))\n"
    "done\n"
    "if running; then\n"
    "    echo 'MDE-CUPSD: started'\n"
    "else\n"
    "    echo 'MDE-CUPSD: not-answering'\n"
    "    sudo -n tail -n 20 /var/log/cups/error_log 2>$Q\n"
    "fi\n"
    "exit 0\n"
    ;

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const char         *state;
    bool                avail;

    TEST_START;

    TEST_STEP("Prepare the printing group");
    CHECK_RC(tsapi_mde_session_init(&session, "printing_prologue"));
    session_up = true;

    TEST_STEP("Start a CUPS scheduler of the suite's own if none answers");
    CHECK_RC(tsapi_mde_sh(&session, 90000, &sh, "%s", start_cupsd));
    if (!tsapi_mde_sh_ok(&sh))
        WARN("Starting a scheduler did not finish cleanly");
    state = strstr(te_string_value(&sh.out), "MDE-CUPSD: ");
    RING("Scheduler set-up said:\n%s%s", te_string_value(&sh.out),
         te_string_value(&sh.err));
    if (state != NULL && strncmp(state, "MDE-CUPSD: no-sudo", 18) == 0)
        RING("No passwordless sudo: nothing started, CUPS tests skip");

    TEST_STEP("Check what the tests of the group will see");
    avail = tapi_print_available(session.factory, TAPI_PRINT_CUPS, T_MS);
    TEST_ARTIFACT("printing prologue: %.*s, CUPS %s",
                  state != NULL ? (int)strcspn(state, "\n") : 7,
                  state != NULL ? state : "unknown",
                  avail ? "running" : "not running");

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
