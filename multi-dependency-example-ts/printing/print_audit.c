/** @file
 * @brief printing Group
 *
 * The posture of the agent's print system. tapi_print_audit reads the
 * CUPS scheduler and every queue. The known-bad control is a queue
 * planted to send documents in clear text to another host
 * (socket://192.0.2.1:9100, TEST-NET-1, where nothing answers and
 * nothing is sent): the audit must report print.cleartext-device. The
 * control's findings are dropped so they do not fail the DUT gate.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "printing/print_audit"

#include "te_config.h"
#include "tapi_test.h"

#include "tsapi_mde.h"
#include "tsapi_mde_report.h"

#include "tapi_print.h"
#include "tapi_print_audit.h"

#define T_MS    30000
#define QUEUE   "mde_cleartext_q"
#define BK      TAPI_PRINT_CUPS

int
main(int argc, char **argv)
{
    tapi_cybersec_severity min_sev;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_report       report;
    bool                   report_up = false;
    bool                   queue_added = false;
    tapi_print_queue_spec  spec = { .name = QUEUE };

    TEST_START;

    TEST_STEP("Parse the severity threshold");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session");
    CHECK_RC(tsapi_mde_session_init(&session, "printing_print_audit"));
    session_up = true;

    TEST_STEP("Skip unless a CUPS scheduler is running on the agent");
    if (!tapi_print_available(session.factory, BK, T_MS))
        TEST_SKIP("No running CUPS on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Plant a queue that sends in clear text to another host");
    spec.device = "socket://192.0.2.1:9100";
    spec.model = "raw";
    rc = tapi_print_queue_add(session.factory, BK, &spec, T_MS);
    if (rc != 0)
        RING("Could not plant the cleartext control queue: %r", rc);
    else
        queue_added = true;

    TEST_STEP("Read the print posture");
    CHECK_RC(tapi_print_audit(session.factory, BK, NULL, NULL, T_MS,
                              &report.cyber));

    TEST_STEP("Where the control was planted, the audit must catch it");
    if (queue_added)
    {
        if (!tsapi_mde_report_expect(&report, "print.cleartext-device",
                                     QUEUE))
        {
            TEST_VERDICT("The print audit missed a cleartext queue");
        }
        tsapi_mde_report_drop_subject(&report, QUEUE);
    }

    TEST_ARTIFACT("printing print_audit: control %s",
                  queue_added ? "planted (cleartext queue)" : "not feasible");

    TEST_STEP("Decide once on the print system's posture");
    TSAPI_MDE_REPORT_GATE(&report, "printing", min_sev);

    TEST_SUCCESS;

cleanup:

    if (queue_added)
        (void)tapi_print_queue_del(session.factory, BK, QUEUE, T_MS);
    if (report_up)
        tsapi_mde_report_free(&report);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
