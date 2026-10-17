/** @file
 * @brief mqtt Group
 *
 * The posture of an MQTT broker. A hardened broker (no anonymous, a
 * password file in place) is stood up and audited - it should come back
 * clean. Next to it, a known-bad control: a second broker opened to
 * anonymous clients on another port, which the same audit must flag with
 * the mqtt.* anonymous / no-tls family. The control's own findings are
 * dropped so they cannot fail the DUT gate; a control that found nothing
 * is itself a failure, because an audit that is blind proves nothing.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mqtt/broker_audit"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "tsapi_mde.h"
#include "tsapi_mde_report.h"

#include "tapi_mqtt.h"
#include "tapi_mqtt_broker.h"
#include "tapi_mqtt_audit.h"

#define T_MS            30000
/* The hardened broker (the "DUT") and the planted-bad control. */
#define GOOD_PORT       11884
#define BAD_PORT        11885

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session;
    bool                    session_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    tapi_mqtt_broker       *good = NULL;
    tapi_mqtt_broker       *bad = NULL;
    tapi_mqtt_broker_opt    bopt = tapi_mqtt_broker_default_opt;
    tapi_mqtt_conn          conn = tapi_mqtt_default_conn;
    tapi_mqtt_policy        policy = tapi_mqtt_default_policy;
    te_string               bad_subject = TE_STRING_INIT;

    TEST_START;

    TEST_STEP("Parse the severity threshold");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session (the example need not be built to audit)");
    CHECK_RC(tsapi_mde_session_init(&session, "mqtt_broker_audit"));
    session_up = true;

    TEST_STEP("Skip unless mosquitto and its clients are on the agent");
    if (!tapi_mqtt_available(session.factory, T_MS))
        TEST_SKIP("There is no MQTT client on the agent");
    if (!tsapi_mde_have(&session, "mosquitto"))
        TEST_SKIP("There is no mosquitto broker on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Stand up the hardened broker and audit it as a stranger");
    bopt.port = GOOD_PORT;
    bopt.defects = 0;
    CHECK_RC(tapi_mqtt_broker_start(session.factory, &bopt, T_MS, &good));
    conn.host = "127.0.0.1";
    conn.port = GOOD_PORT;
    CHECK_RC(tapi_mqtt_audit(session.factory, &conn, &policy, T_MS,
                             &report.cyber));

    TEST_STEP("Stand up the open broker as a known-bad control");
    bopt.port = BAD_PORT;
    bopt.defects = TAPI_MQTT_DEFECT_ANONYMOUS;
    CHECK_RC(tapi_mqtt_broker_start(session.factory, &bopt, T_MS, &bad));
    conn.port = BAD_PORT;
    CHECK_RC(tapi_mqtt_audit(session.factory, &conn, &policy, T_MS,
                             &report.cyber));

    TEST_STEP("The control must have been caught");
    te_string_append(&bad_subject, "127.0.0.1:%u", BAD_PORT);
    if (!tsapi_mde_report_expect(&report, "mqtt.anonymous-allowed",
                                 bad_subject.ptr))
    {
        TEST_VERDICT("The MQTT audit missed an anonymous broker");
    }
    (void)tsapi_mde_report_expect(&report, "mqtt.no-tls", bad_subject.ptr);

    TEST_STEP("Drop the control's findings so they do not fail the gate");
    tsapi_mde_report_drop_subject(&report, bad_subject.ptr);

    TEST_ARTIFACT("mqtt audit: hardened broker on %u, control (anonymous) "
                  "on %u", GOOD_PORT, BAD_PORT);

    TEST_STEP("Decide once: the hardened broker should be clean");
    TSAPI_MDE_REPORT_GATE(&report, "mqtt", min_sev);

    TEST_SUCCESS;

cleanup:

    if (good != NULL)
        tapi_mqtt_broker_stop(good);
    if (bad != NULL)
        tapi_mqtt_broker_stop(bad);
    te_string_free(&bad_subject);
    if (report_up)
        tsapi_mde_report_free(&report);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
