/** @file
 * @brief mqtt Group
 *
 * The ring's trace carried over a real MQTT broker. A mosquitto broker
 * is stood up on the agent; the test runs cpp-demo, publishes every
 * parsed stage step as a retained message on mde/ring/<i>/<stage>, reads
 * them all back over a fresh subscription, and verifies the count and
 * every payload byte-for-byte (a transport round-trip). It then compares
 * the observed trace against the reference model, so the injected
 * always-true defect shows up through MQTT just as it does on the
 * command line.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mqtt/ring_bus"

#include "te_config.h"
#include <math.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"

#include "tsapi_mde.h"
#include "tsapi_mde_ring.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"

#include "tapi_mqtt.h"
#include "tapi_mqtt_broker.h"

#include "mqtt_common.h"

/* The broker's loopback port for this test. */
#define RING_BUS_PORT   11883
/* Where the parsed trace lines look like "  [rust] hops=7 ...". */
#define T_MS            30000
/* The trace prints four decimals, so this is the right tolerance. */
#define RING_TOL        1.0e-3

int
main(int argc, char **argv)
{
    int                    qos;
    int                    hops;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_report       report;
    bool                   report_up = false;
    tapi_mqtt_broker      *broker = NULL;
    tapi_mqtt_broker_opt   bopt = tapi_mqtt_broker_default_opt;
    tapi_mqtt_conn         conn = tapi_mqtt_default_conn;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    te_vec                 observed = TE_VEC_INIT(tsapi_mde_step);
    te_vec                 expected = TE_VEC_INIT(tsapi_mde_step);
    te_vec                 messages = TE_VEC_INIT(tapi_mqtt_message);
    bool                   collected = false;
    char                   qos_str[8];
    const char            *extra[2];
    double                 exp_result;
    double                 obs_result = 0.0;
    bool                   have_result;
    double                 pub_latency[64];
    double                 per_stage[TSAPI_MDE_STAGE_N] = { 0 };
    static const char     *stage_labels[TSAPI_MDE_STAGE_N] = {
        "cpp", "rust", "go", "cs", "py",
    };
    unsigned int           n_steps;
    unsigned int           matched = 0;
    double                 t_recv;
    size_t                 i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(qos);
    TEST_GET_INT_PARAM(hops);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "mqtt_ring_bus", dut, session_up);

    TEST_STEP("Skip unless mosquitto and its clients are on the agent");
    if (!tapi_mqtt_available(session.factory, T_MS))
        TEST_SKIP("There is no MQTT client on the agent");
    if (!tsapi_mde_have(&session, "mosquitto"))
        TEST_SKIP("There is no mosquitto broker on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Stand up an authenticated broker on the agent");
    bopt.port = RING_BUS_PORT;
    bopt.defects = 0;
    CHECK_RC(tapi_mqtt_broker_start(session.factory, &bopt, T_MS, &broker));

    conn.host = "127.0.0.1";
    conn.port = RING_BUS_PORT;
    conn.username = tapi_mqtt_broker_username(broker);
    conn.password = tapi_mqtt_broker_password(broker);
    TE_SPRINTF(qos_str, "%d", qos);
    extra[0] = "-q";
    extra[1] = qos_str;
    conn.extra_args = extra;
    conn.n_extra_args = TE_ARRAY_LEN(extra);

    TEST_STEP("Run cpp-demo and parse the stage trace it printed");
    CHECK_RC(tsapi_mde_sh(&session, T_MS, &sh, "'%s/cpp-demo' 1 %d",
                          dut.bin, hops));
    if (!sh.started)
        TEST_FAIL("cpp-demo could not be started");
    RING("cpp-demo 1 %d said:\n%s", hops, te_string_value(&sh.out));

    n_steps = tsapi_mde_ring_parse(te_string_value(&sh.out), &observed);
    if (n_steps == 0)
        TEST_VERDICT("cpp-demo printed no stage trace to carry over MQTT");
    have_result = tsapi_mde_ring_parse_result(te_string_value(&sh.out),
                                              &obs_result);

    TEST_STEP("Publish every parsed step as a retained message");
    for (i = 0; i < n_steps; i++)
    {
        const tsapi_mde_step *step = te_vec_get(&observed, i);
        te_string             topic = TE_STRING_INIT;
        te_string             payload = TE_STRING_INIT;
        tapi_mqtt_result      res;
        double                t0;

        mde_mqtt_step_topic(i, step->stage, &topic);
        mde_mqtt_step_payload(step, &payload);

        t0 = tsapi_mde_now();
        rc = tapi_mqtt_publish_retained(session.factory, &conn, topic.ptr,
                                        payload.ptr, T_MS, &res);
        if (i < TE_ARRAY_LEN(pub_latency))
            pub_latency[i] = tsapi_mde_now() - t0;
        if (rc == 0 && res != TAPI_MQTT_ACCEPTED)
            rc = TE_RC(TE_TAPI, TE_EFAIL);
        if (rc != 0)
        {
            te_string_free(&topic);
            te_string_free(&payload);
            TEST_VERDICT("The broker refused a ring step publish");
        }
        if (step->stage < TSAPI_MDE_STAGE_N)
            per_stage[step->stage]++;
        te_string_free(&topic);
        te_string_free(&payload);
    }

    TEST_STEP("Subscribe afresh and collect every step back");
    t_recv = tsapi_mde_now();
    CHECK_RC(tapi_mqtt_collect(session.factory, &conn, "mde/ring/#", 5,
                               n_steps, T_MS, &messages));
    collected = true;
    t_recv = tsapi_mde_now() - t_recv;
    tapi_mqtt_messages_log("came back over MQTT", &messages);

    TEST_STEP("Deep round-trip: every step is there with the exact payload");
    for (i = 0; i < n_steps; i++)
    {
        const tsapi_mde_step    *step = te_vec_get(&observed, i);
        te_string                topic = TE_STRING_INIT;
        te_string                payload = TE_STRING_INIT;
        const tapi_mqtt_message *got;

        mde_mqtt_step_topic(i, step->stage, &topic);
        mde_mqtt_step_payload(step, &payload);
        got = tapi_mqtt_message_find(&messages, topic.ptr);
        if (got != NULL && strcmp(got->payload, payload.ptr) == 0)
            matched++;
        else
            RING("step %zu (%s) did not round-trip: sent '%s', got '%s'", i,
                 topic.ptr, payload.ptr,
                 got != NULL ? got->payload : "(nothing)");
        te_string_free(&topic);
        te_string_free(&payload);
    }

    TEST_ARTIFACT("mqtt qos=%d hops=%d: published %u step(s), %u matched "
                  "on the way back, receive took %.3f s", qos, hops, n_steps,
                  matched, t_recv);

    TEST_STEP("Chart the publish latency and the messages per stage");
    tsapi_mde_mi_series("mqtt", "Publish latency per ring step",
                        TE_MI_MEAS_TIME, "publish_latency",
                        n_steps < TE_ARRAY_LEN(pub_latency) ? n_steps :
                        TE_ARRAY_LEN(pub_latency), pub_latency,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("mqtt", "Messages carried per stage",
                      TE_MI_MEAS_UNITLESS_VALUE, "messages",
                      TSAPI_MDE_STAGE_N, (const char * const *)stage_labels,
                      per_stage,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("mqtt", "Total receive time", TE_MI_MEAS_TIME,
                       "receive_time", t_recv, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("The transport is sound only when all steps round-tripped");
    if (matched != n_steps)
        TEST_VERDICT("MQTT round-trip lost steps: %u of %u matched", matched,
                     n_steps);

    TEST_STEP("Compare the MQTT-carried trace against the model");
    exp_result = tsapi_mde_ring_predict(MDE_MQTT_ENTRY, 1.0, hops, &expected);
    tsapi_mde_ring_compare(MDE_MQTT_ENTRY, &expected, &observed,
                           have_result, exp_result, obs_result,
                           RING_TOL, &report.cyber);

    TEST_STEP("Decide once on the report");
    TSAPI_MDE_REPORT_GATE(&report, "mqtt", TAPI_CYBERSEC_SEV_MEDIUM);

    TEST_SUCCESS;

cleanup:

    if (collected)
    {
        /* Clear the retained messages we left on the broker. */
        for (i = 0; i < te_vec_size(&observed); i++)
        {
            const tsapi_mde_step *step = te_vec_get(&observed, i);
            te_string             topic = TE_STRING_INIT;

            mde_mqtt_step_topic(i, step->stage, &topic);
            (void)tapi_mqtt_publish_retained(session.factory, &conn,
                                             topic.ptr, "", T_MS, NULL);
            te_string_free(&topic);
        }
    }
    tapi_mqtt_messages_free(&messages);
    if (broker != NULL)
        tapi_mqtt_broker_stop(broker);
    te_vec_free(&observed);
    te_vec_free(&expected);
    tsapi_mde_sh_result_free(&sh);
    if (report_up)
        tsapi_mde_report_free(&report);
    if (session_up)
    {
        tsapi_mde_dut_free(&dut);
        tsapi_mde_session_fini(&session);
    }

    TEST_END;
}
