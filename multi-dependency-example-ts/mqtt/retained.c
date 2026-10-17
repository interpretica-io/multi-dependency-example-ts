/** @file
 * @brief mqtt Group
 *
 * Retained delivery, the one publish that outlives a connection. A ring
 * result is published retained; a fresh subscription must then receive
 * it exactly once with an identical payload (the proof it was kept by
 * the broker, not merely seen live). The control is the clear: once the
 * retained message is cleared, a fresh subscription must find nothing.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mqtt/retained"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"

#include "tsapi_mde.h"
#include "tsapi_mde_ring.h"
#include "tsapi_mde_mi.h"

#include "tapi_mqtt.h"
#include "tapi_mqtt_broker.h"

#define T_MS            30000
#define RETAINED_PORT   11886
#define RETAINED_TOPIC  "mde/ring/result"

int
main(int argc, char **argv)
{
    tsapi_mde_session     session;
    bool                  session_up = false;
    tsapi_mde_dut         dut;
    tapi_mqtt_broker     *broker = NULL;
    tapi_mqtt_broker_opt  bopt = tapi_mqtt_broker_default_opt;
    tapi_mqtt_conn        conn = tapi_mqtt_default_conn;
    tsapi_mde_sh_result   sh = TSAPI_MDE_SH_RESULT_INIT;
    te_vec                messages = TE_VEC_INIT(tapi_mqtt_message);
    bool                  published = false;
    te_string             payload = TE_STRING_INIT;
    double                ring_result = 0.0;

    TEST_START;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "mqtt_retained", dut, session_up);

    TEST_STEP("Skip unless mosquitto and its clients are on the agent");
    if (!tapi_mqtt_available(session.factory, T_MS))
        TEST_SKIP("There is no MQTT client on the agent");
    if (!tsapi_mde_have(&session, "mosquitto"))
        TEST_SKIP("There is no mosquitto broker on the agent");

    TEST_STEP("Stand up an authenticated broker");
    bopt.port = RETAINED_PORT;
    bopt.defects = 0;
    CHECK_RC(tapi_mqtt_broker_start(session.factory, &bopt, T_MS, &broker));
    conn.host = "127.0.0.1";
    conn.port = RETAINED_PORT;
    conn.username = tapi_mqtt_broker_username(broker);
    conn.password = tapi_mqtt_broker_password(broker);

    TEST_STEP("Build the ring result to publish retained");
    CHECK_RC(tsapi_mde_sh(&session, T_MS, &sh, "'%s/cpp-demo' 1 7", dut.bin));
    if (!sh.started ||
        !tsapi_mde_ring_parse_result(te_string_value(&sh.out), &ring_result))
    {
        TEST_VERDICT("cpp-demo printed no result line to retain");
    }
    te_string_append(&payload, "%.4f", ring_result);

    TEST_STEP("Publish it retained");
    {
        tapi_mqtt_result res;

        CHECK_RC(tapi_mqtt_publish_retained(session.factory, &conn,
                                            RETAINED_TOPIC, payload.ptr, T_MS,
                                            &res));
        if (res != TAPI_MQTT_ACCEPTED)
            TEST_VERDICT("The broker did not take the retained publish");
        published = true;
    }

    TEST_STEP("A fresh subscription receives it exactly once, identical");
    CHECK_RC(tapi_mqtt_collect(session.factory, &conn, RETAINED_TOPIC, 3, 0,
                               T_MS, &messages));
    tapi_mqtt_messages_log("retained, read back", &messages);
    if (te_vec_size(&messages) != 1)
        TEST_VERDICT("A retained topic returned %zu message(s), expected 1",
                     te_vec_size(&messages));
    {
        const tapi_mqtt_message *m = te_vec_get(&messages, 0);

        if (strcmp(m->topic, RETAINED_TOPIC) != 0 ||
            strcmp(m->payload, payload.ptr) != 0)
        {
            TEST_VERDICT("The retained message came back changed");
        }
    }
    TEST_ARTIFACT("retained %s = %s (%zu bytes)", RETAINED_TOPIC, payload.ptr,
                  payload.len);
    tsapi_mde_mi_point("mqtt", "Retained payload size", TE_MI_MEAS_MEMORY,
                       "retained_bytes", (double)payload.len,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Clear it, and a fresh subscription finds nothing (control)");
    {
        tapi_mqtt_result res;

        CHECK_RC(tapi_mqtt_publish_retained(session.factory, &conn,
                                            RETAINED_TOPIC, "", T_MS, &res));
        if (res != TAPI_MQTT_ACCEPTED)
            TEST_VERDICT("The broker did not take the retained clear");
        published = false;
    }
    tapi_mqtt_messages_free(&messages);
    CHECK_RC(tapi_mqtt_collect(session.factory, &conn, RETAINED_TOPIC, 2, 0,
                               T_MS, &messages));
    if (te_vec_size(&messages) != 0)
        TEST_VERDICT("A cleared retained topic still returned %zu message(s)",
                     te_vec_size(&messages));

    TEST_SUCCESS;

cleanup:

    if (published)
    {
        (void)tapi_mqtt_publish_retained(session.factory, &conn,
                                         RETAINED_TOPIC, "", T_MS, NULL);
    }
    tapi_mqtt_messages_free(&messages);
    if (broker != NULL)
        tapi_mqtt_broker_stop(broker);
    te_string_free(&payload);
    tsapi_mde_sh_result_free(&sh);
    if (session_up)
    {
        tsapi_mde_dut_free(&dut);
        tsapi_mde_session_fini(&session);
    }

    TEST_END;
}
