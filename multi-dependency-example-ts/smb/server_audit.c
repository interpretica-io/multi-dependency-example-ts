/** @file
 * @brief smb Group
 *
 * The posture of the SMB server the agent runs: what it negotiates
 * (SMB1? signing? encryption?) and whether a null session lists its
 * shares, read over the wire by tapi_smb_audit. The known-bad control,
 * run only where the server allows it, is a guest-ok share the agent
 * serves: the audit must then report smb.guest-writable. The control's
 * findings are dropped so they do not fail the DUT gate.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "smb/server_audit"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "tsapi_mde.h"
#include "tsapi_mde_report.h"

#include "tapi_smb.h"
#include "tapi_smb_share.h"
#include "tapi_smb_audit.h"

#define T_MS    30000
#define SHARE   "mdebadshare"
#define BK      TAPI_SMB_SAMBA

int
main(int argc, char **argv)
{
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_report       report;
    bool                   report_up = false;
    tapi_smb_served        served = TAPI_SMB_SERVED_INIT;
    bool                   serving = false;
    tapi_smb_target        target = TAPI_SMB_TARGET_INIT;
    tapi_smb_policy        policy = tapi_smb_default_policy;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string              dir = TE_STRING_INIT;

    TEST_START;

    TEST_STEP("Parse the severity threshold");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session");
    CHECK_RC(tsapi_mde_session_init(&session, "smb_server_audit"));
    session_up = true;

    TEST_STEP("Skip unless an SMB server answers on the agent");
    if (!tapi_smb_available(session.factory, BK, T_MS))
        TEST_SKIP("There is no SMB client on the agent to reach a server");

    target.server = "localhost";

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Try to plant a guest-ok control share (feasible only if the "
              "server allows guests)");
    te_string_append(&dir, "/tmp/mde-smb-badshare");
    (void)tsapi_mde_sh(&session, T_MS, &sh, "mkdir -p '%s' && "
                       "chmod 0777 '%s'", dir.ptr, dir.ptr);
    if (tapi_smb_can_serve(session.factory, BK, T_MS))
    {
        served.name = SHARE;
        served.path = dir.ptr;
        served.comment = "mde guest control";
        served.writable = true;
        served.guest_ok = true;
        if (tapi_smb_serve(session.factory, BK, &served, T_MS) == 0)
        {
            serving = true;
            policy.guest_share = SHARE;
        }
        else
        {
            RING("The server forbids a guest share - no known-bad control");
        }
    }

    TEST_STEP("Read the server's posture");
    rc = tapi_smb_audit(session.factory, BK, &target, &policy, T_MS,
                        &report.cyber);
    if (TE_RC_GET_ERROR(rc) == TE_ECONNREFUSED)
        TEST_SKIP("No SMB server answers on the agent");
    if (rc != 0)
        TEST_FAIL("Reading the SMB posture failed: %r", rc);

    TEST_STEP("Where the control was planted, the audit must catch it");
    if (serving)
    {
        if (!tsapi_mde_report_expect(&report, "smb.guest-writable", SHARE))
            TEST_VERDICT("The SMB audit missed a guest-writable share");
        tsapi_mde_report_drop_subject(&report, SHARE);
    }

    TEST_ARTIFACT("smb server_audit: server=%s, control %s", target.server,
                  serving ? "planted (guest share)" : "not feasible");

    TEST_STEP("Decide once on the server's posture");
    TSAPI_MDE_REPORT_GATE(&report, "smb", min_sev);

    TEST_SUCCESS;

cleanup:

    if (serving)
        (void)tapi_smb_unserve(session.factory, BK, SHARE, T_MS);
    (void)tsapi_mde_sh(&session, T_MS, &sh, "rm -rf '%s'", dir.ptr);
    te_string_free(&dir);
    tsapi_mde_sh_result_free(&sh);
    if (report_up)
        tsapi_mde_report_free(&report);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
