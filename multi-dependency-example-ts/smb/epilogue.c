/** @file
 * @brief smb Group
 *
 * smb group epilogue: undo what the prologue changed, and only that, as
 * the marker /tmp/mde-smbd.started lists it - stop the suite's own smbd
 * (with the RPC helpers it spawned) and remove /tmp/mde-smb with its
 * passdb, and take back the ACL entry on the usershare directory. The
 * usershares the tests serve are removed too, in case a test did not
 * get to its cleanup. An SMB server that was running before the suite
 * is left alone.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "smb/epilogue"

#include "te_config.h"
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"

#include "tsapi_mde.h"

/**
 * Undo what the marker lists. Prints "MDE-SMB: smbd stopped", the ACL
 * lines, or "MDE-SMB: nothing to undo".
 */
static const char stop_smbd[] =
    "D=/tmp/mde-smb; M=/tmp/mde-smbd.started; U=$(id -un)\n"
    "P='/tmp/mde-smb/smb[.]conf'; Q=/dev/null\n"
    "if [ ! -f \"$M\" ]; then\n"
    "    echo 'MDE-SMB: nothing to undo'; exit 0\n"
    "fi\n"
    "for s in mdedist mdebadshare; do\n"
    "    net usershare delete \"$s\" >$Q 2>&1\n"
    "done\n"
    "if grep -qx smbd \"$M\"; then\n"
    "    sudo -n pkill -TERM -f \"$P\"\n"
    "    i=0\n"
    "    while [ $i -lt 50 ] && pgrep -f \"$P\" >$Q; do\n"
    "        sleep 0.2; i=$((i + 1))\n"
    "    done\n"
    "    pgrep -f \"$P\" >$Q && sudo -n pkill -KILL -f \"$P\"\n"
    "    sudo -n rm -rf \"$D\"\n"
    "    echo 'MDE-SMB: smbd stopped'\n"
    "fi\n"
    "sed -n 's/^acl //p' \"$M\" | while IFS= read -r p; do\n"
    "    sudo -n setfacl -x \"u:$U\" \"$p\" &&\n"
    "        echo \"MDE-SMB: acl entry off $p\"\n"
    "done\n"
    "sed -n 's/^aclnew //p' \"$M\" | while IFS= read -r p; do\n"
    "    sudo -n setfacl -b \"$p\" && echo \"MDE-SMB: acl removed from $p\"\n"
    "done\n"
    "rm -f \"$M\"\n"
    "exit 0\n"
    ;

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const char         *out;

    TEST_START;

    TEST_STEP("Finalize the smb group");
    CHECK_RC(tsapi_mde_session_init(&session, "smb_epilogue"));
    session_up = true;

    TEST_STEP("Undo what the prologue changed, if anything");
    CHECK_RC(tsapi_mde_sh(&session, 60000, &sh, "%s", stop_smbd));
    if (!tsapi_mde_sh_ok(&sh))
        WARN("Undoing the SMB set-up did not finish cleanly");
    out = te_string_value(&sh.out);
    RING("SMB server tear-down said:\n%s%s", out, te_string_value(&sh.err));
    TEST_ARTIFACT("smb epilogue: %s",
                  strstr(out, "MDE-SMB: smbd stopped") != NULL ?
                      "the suite's smbd stopped" :
                  strstr(out, "nothing to undo") != NULL ?
                      "nothing to undo" : "set-up undone");

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
