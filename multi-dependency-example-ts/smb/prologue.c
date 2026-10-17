/** @file
 * @brief smb Group
 *
 * smb group prologue: make sure an SMB server answers on the agent and
 * that the agent user may serve a usershare. A container has no init to
 * start smbd, so when nothing answers on 127.0.0.1:445 and passwordless
 * sudo is there, an smbd of the suite's own is started with a minimal
 * configuration in /tmp/mde-smb (bound to the loopback interface only,
 * SMB2 and up, signing required, no anonymous IPC, guests mapped to
 * nobody, the system's usershare directory). An account for the agent
 * user with a random password is added to its private passdb and left
 * in /tmp/mde-smb/cred for the tests that need an authenticated
 * session. When "net usershare" is refused, the agent user is given an
 * ACL entry on the usershare directory. Everything changed is listed in
 * the marker /tmp/mde-smbd.started, and the epilogue undoes only that.
 * Without sudo nothing is started, and the tests skip as before.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "smb/prologue"

#include "te_config.h"
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"

#include "tsapi_mde.h"

#include "tapi_smb.h"
#include "tapi_smb_share.h"

#include "smb_common.h"

#define T_MS    30000

/**
 * Start an smbd of the suite's own unless one answers already, and let
 * the agent user serve usershares. It prints "MDE-SMB: <state>" lines:
 * smbd present / adopted / started / not answering / start failed,
 * user added / not added, usershare allowed / allowed (acl) / denied,
 * or no-sudo, no-smbd, no-smbclient.
 */
static const char start_smbd[] =
    "D=/tmp/mde-smb; M=/tmp/mde-smbd.started; U=$(id -un)\n"
    "P='/tmp/mde-smb/smb[.]conf'; Q=/dev/null\n"
    "answers() {\n"
    "    o=$(timeout 15 smbclient -N -L //127.0.0.1 -g 2>&1)\n"
    "    case \"$o\" in\n"
    "        *CONNECTION_REFUSED*|*IO_TIMEOUT*) return 1 ;;\n"
    "        *HOST_UNREACHABLE*|*NETWORK_UNREACHABLE*) return 1 ;;\n"
    "    esac\n"
    "    return 0\n"
    "}\n"
    "usershare_path() {\n"
    "    p=$(testparm -s --parameter-name='usershare path' 2>$Q)\n"
    "    echo \"${p:-/var/lib/samba/usershares}\"\n"
    "}\n"
    "if ! command -v smbclient >$Q 2>&1; then\n"
    "    echo 'MDE-SMB: no-smbclient'; exit 0\n"
    "fi\n"
    "SUDO=no; sudo -n true >$Q 2>&1 && SUDO=yes\n"
    "UP=$(usershare_path)\n"
    "if answers; then\n"
    "    if pgrep -f \"$P\" >$Q 2>&1; then\n"
    "        grep -qx smbd \"$M\" 2>$Q || echo smbd >> \"$M\"\n"
    "        echo 'MDE-SMB: smbd adopted'\n"
    "    else\n"
    "        echo 'MDE-SMB: smbd present'\n"
    "    fi\n"
    "elif [ $SUDO = no ]; then\n"
    "    echo 'MDE-SMB: no-sudo'\n"
    "else\n"
    "    SMBD=/usr/sbin/smbd; [ -x \"$SMBD\" ] || SMBD=$(command -v smbd)\n"
    "    if [ -z \"$SMBD\" ] || [ ! -x \"$SMBD\" ]; then\n"
    "        echo 'MDE-SMB: no-smbd'\n"
    "    else\n"
    "        sudo -n rm -rf \"$D\"; mkdir -p \"$D\"\n"
    "        sudo -n install -d -m 0700 \"$D/private\"\n"
    "        for d in lock state cache run ncalrpc; do\n"
    "            sudo -n install -d -m 0755 \"$D/$d\"\n"
    "        done\n"
    "        cat > \"$D/smb.conf\" <<CONF\n"
    "[global]\n"
    "   workgroup = WORKGROUP\n"
    "   server string = mde suite smbd\n"
    "   server role = standalone server\n"
    "   security = user\n"
    "   interfaces = lo\n"
    "   bind interfaces only = yes\n"
    "   disable netbios = yes\n"
    "   server min protocol = SMB2_02\n"
    "   server signing = mandatory\n"
    "   restrict anonymous = 2\n"
    "   map to guest = bad user\n"
    "   guest account = nobody\n"
    "   passdb backend = tdbsam:$D/private/passdb.tdb\n"
    "   private dir = $D/private\n"
    "   lock directory = $D/lock\n"
    "   state directory = $D/state\n"
    "   cache directory = $D/cache\n"
    "   pid directory = $D/run\n"
    "   ncalrpc dir = $D/ncalrpc\n"
    "   logging = file\n"
    "   log file = $D/log.smbd\n"
    "   max log size = 1000\n"
    "   load printers = no\n"
    "   printing = bsd\n"
    "   printcap name = /dev/null\n"
    "   disable spoolss = yes\n"
    "   usershare path = $UP\n"
    "   usershare max shares = 100\n"
    "   usershare allow guests = yes\n"
    "   usershare owner only = yes\n"
    "CONF\n"
    "        if sudo -n \"$SMBD\" -D -s \"$D/smb.conf\" <$Q >$Q 2>&1; then\n"
    "            echo smbd >> \"$M\"\n"
    "            i=0\n"
    "            while [ $i -lt 60 ] && ! answers; do\n"
    "                sleep 0.5; i=$((i + 1))\n"
    "            done\n"
    "            if answers; then\n"
    "                echo 'MDE-SMB: smbd started'\n"
    "            else\n"
    "                echo 'MDE-SMB: smbd not answering'\n"
    "                sudo -n tail -n 20 \"$D/log.smbd\" 2>$Q\n"
    "            fi\n"
    "            PW=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \\n')\n"
    "            umask 077\n"
    "            printf '%s\\n%s\\n' \"$PW\" \"$PW\" > \"$D/pw.in\"\n"
    "            if sudo -n smbpasswd -c \"$D/smb.conf\" -a -s \"$U\" \\\n"
    "                    < \"$D/pw.in\" >$Q 2>&1; then\n"
    "                printf '%s %s\\n' \"$U\" \"$PW\" > \"$D/cred\"\n"
    "                echo \"MDE-SMB: user $U added\"\n"
    "            else\n"
    "                echo 'MDE-SMB: user not added'\n"
    "            fi\n"
    "            rm -f \"$D/pw.in\"\n"
    "        else\n"
    "            echo 'MDE-SMB: smbd start failed'\n"
    "        fi\n"
    "    fi\n"
    "fi\n"
    "if net usershare list >$Q 2>&1; then\n"
    "    echo 'MDE-SMB: usershare allowed'\n"
    "elif [ $SUDO = yes ] && [ -d \"$UP\" ]; then\n"
    "    # Remember whether the directory had an extended ACL before.\n"
    "    T=aclnew\n"
    "    getfacl -cp \"$UP\" 2>$Q | grep -q '^mask::' && T=acl\n"
    "    if sudo -n setfacl -m \"u:$U:rwx\" \"$UP\" 2>$Q; then\n"
    "        echo \"$T $UP\" >> \"$M\"\n"
    "    fi\n"
    "    if net usershare list >$Q 2>&1; then\n"
    "        echo 'MDE-SMB: usershare allowed (acl)'\n"
    "    else\n"
    "        echo 'MDE-SMB: usershare denied'\n"
    "    fi\n"
    "else\n"
    "    echo 'MDE-SMB: usershare denied'\n"
    "fi\n"
    "exit 0\n"
    ;

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    const char         *out;
    bool                can_serve;
    bool                have_account;

    TEST_START;

    TEST_STEP("Prepare the smb group");
    CHECK_RC(tsapi_mde_session_init(&session, "smb_prologue"));
    session_up = true;

    TEST_STEP("Start an SMB server of the suite's own if none answers");
    CHECK_RC(tsapi_mde_sh(&session, 120000, &sh, "%s", start_smbd));
    if (!tsapi_mde_sh_ok(&sh))
        WARN("Starting an SMB server did not finish cleanly");
    out = te_string_value(&sh.out);
    RING("SMB server set-up said:\n%s%s", out, te_string_value(&sh.err));
    if (strstr(out, "MDE-SMB: no-sudo") != NULL)
        RING("No passwordless sudo: nothing started, SMB tests skip");

    TEST_STEP("Check what the tests of the group will see");
    can_serve = tapi_smb_available(session.factory, TAPI_SMB_SAMBA, T_MS) &&
                tapi_smb_can_serve(session.factory, TAPI_SMB_SAMBA, T_MS);
    have_account = tsapi_mde_exists(&session, MDE_SMB_CRED);
    TEST_ARTIFACT("smb prologue: smbd %s, usershare %s, account %s",
                  strstr(out, "MDE-SMB: smbd started") != NULL ?
                      "started by the suite" :
                  strstr(out, "MDE-SMB: smbd adopted") != NULL ?
                      "the suite's own, adopted" :
                  strstr(out, "MDE-SMB: smbd present") != NULL ?
                      "already running" : "not running",
                  can_serve ? "allowed" : "refused",
                  have_account ? "made" : "none");

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&sh);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
