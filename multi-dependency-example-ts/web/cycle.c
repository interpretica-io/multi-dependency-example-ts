/** @file
 * @brief Web Group
 *
 * Start the three HTTP services of the web tier and send one request into the
 * cycle. Correct code walks gateway-rs -> service-go -> service-cs and back,
 * tracing hops+1 node steps in the response body; the injected always-true
 * defect in each node's forward() stops the walk after the first node.
 *
 * The node-step count is checked first and keeps its historical verdict;
 * then every body line is checked against the model of the cycle (order,
 * hop counter, hand-off, each node's formula, the returned value) and the
 * findings are gated by min_severity.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/cycle"

#include "web_common.h"

/** Value sent into the cycle. */
#define CYCLE_VALUE     1.0

/** A body planted with a wrong gateway step, for the control. */
#define CYCLE_PLANTED \
    "[gateway-rs] hops=1      1.0000 ->     9.9999   (rust_step)\n"   \
    "[service-go] hops=0      9.9999 ->    15.5999   ((v + 5) * w)\n" \
    "value=15.5999\n"

int
main(int argc, char **argv)
{
    int                    hops;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut = { .root = NULL };
    tsapi_mde_report       report;
    bool                   report_up = false;
    tsapi_mde_web          web;
    bool                   web_up = false;
    web_trace              trace = WEB_TRACE_INIT;
    web_reply              reply = WEB_REPLY_INIT;
    te_vec                 model = TE_VEC_INIT(web_step);
    te_string              url = TE_STRING_INIT;
    double                 model_value;
    unsigned int           traced;
    unsigned int           expected;
    bool                   count_bad = false;
    const char            *why;
    te_mi_logger          *logger = NULL;
    size_t                 n;
    size_t                 i;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(hops);
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "web", dut, session_up);

    TEST_STEP("Skip unless the services and curl can be run");
    why = web_unavailable(&session, &dut);
    if (why != NULL)
        TEST_SKIP("%s", why);

    TEST_STEP("Known-bad control: a body with a wrong gateway step must "
              "give web.formula");
    web_trace_parse(CYCLE_PLANTED, &trace);
    web_predict(WEB_NODE_GW, 1.0, 1, &model);
    web_compare("control", &model, 0, &trace, &report.cyber);
    tsapi_mde_report_expect(&report, "web.formula",
                            "control/step0:gateway-rs");
    web_report_drop_prefix(&report, "control/");
    te_vec_reset(&model);

    TEST_STEP("Start the three HTTP services");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    web_chart_start(&web);

    TEST_STEP("Send one request into the cycle with value=%g hops=%d",
              CYCLE_VALUE, hops);
    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, CYCLE_VALUE, hops, &url);
    CHECK_RC(web_get(&session, "", url.ptr, 60, &reply));
    if (!reply.ran)
        TEST_FAIL("curl could not be run");
    if (reply.code != 200)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "web.status", "gateway-rs/request",
                                 "HTTP %d", reply.code);
    }

    web_trace_parse(web_str(&reply.body), &trace);
    traced = te_vec_size(&trace.steps);
    if (traced == 0)
        TEST_VERDICT("The gateway returned no node trace - is it serving?");

    TEST_STEP("Check the number of node steps");
    model_value = web_predict(WEB_NODE_GW, CYCLE_VALUE, hops, &model);
    expected = (unsigned int)hops + 1;
    if (traced != expected)
    {
        /* Historical verdict first; the report gate adds the deep one. */
        ERROR_VERDICT("Web ring propagated through %u node step(s), "
                      "expected %u", traced, expected);
        count_bad = true;
    }

    TEST_STEP("Check every body line against the model of the cycle");
    web_compare("gateway-rs", &model, model_value, &trace, &report.cyber);

    TEST_STEP("Record the walk: charts and artifacts");
    n = MAX(te_vec_size(&model), te_vec_size(&trace.steps));
    if (tsapi_mde_mi_create("web", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "hops", "%d", hops);
        te_mi_logger_add_meas_key(logger, NULL, "node_axis", "%s",
                                  "0=gateway-rs 1=service-go 2=service-cs");
        for (i = 0; i < n; i++)
        {
            const web_step *e = i < te_vec_size(&model) ?
                                te_vec_get(&model, i) : NULL;
            const web_step *o = i < te_vec_size(&trace.steps) ?
                                te_vec_get(&trace.steps, i) : NULL;

            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "step", TE_MI_MEAS_AGGR_SINGLE, i,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_out", TE_MI_MEAS_AGGR_SINGLE,
                                  e != NULL ? e->out : 0,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_out", TE_MI_MEAS_AGGR_SINGLE,
                                  o != NULL ? o->out : 0,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_hops", TE_MI_MEAS_AGGR_SINGLE,
                                  e != NULL ? e->hops : -1,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_hops", TE_MI_MEAS_AGGR_SINGLE,
                                  o != NULL ? o->hops : -1,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_node", TE_MI_MEAS_AGGR_SINGLE,
                                  e != NULL ? (double)e->node : -1,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_node", TE_MI_MEAS_AGGR_SINGLE,
                                  o != NULL ? (double)o->node : -1,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        tsapi_mde_mi_line(logger, "values", "Value per node step: model vs "
                          "observed", "step", "model_out", "observed_out",
                          NULL);
        tsapi_mde_mi_line(logger, "hops", "Hop counter per node step: model "
                          "vs observed", "step", "model_hops",
                          "observed_hops", NULL);
        tsapi_mde_mi_line(logger, "nodes", "Node per step: model vs "
                          "observed", "step", "model_node", "observed_node",
                          NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    /* Steps per node: how the walk spread over the three services. */
    if (tsapi_mde_mi_create("web", &logger) == 0)
    {
        unsigned int node;

        for (node = 0; node < WEB_NODE_N; node++)
        {
            unsigned int     n_obs = 0;
            unsigned int     n_exp = 0;
            const web_step  *s;
            char             key[16];

            TE_VEC_FOREACH(&trace.steps, s)
                n_obs += s->node == node;
            TE_VEC_FOREACH(&model, s)
                n_exp += s->node == node;

            TE_SPRINTF(key, "x%u", node);
            te_mi_logger_add_meas_key(logger, NULL, key, "%s",
                                      web_node2str(node));
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "node", TE_MI_MEAS_AGGR_SINGLE, node,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_steps", TE_MI_MEAS_AGGR_SINGLE,
                                  n_obs, TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_steps", TE_MI_MEAS_AGGR_SINGLE,
                                  n_exp, TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(logger, NULL, "hops", "%d", hops);
        tsapi_mde_mi_line(logger, "per_node", "Node steps per service: "
                          "model vs observed", "node", "observed_steps",
                          "model_steps", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    if (tsapi_mde_mi_create("web", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "hops", "%d", hops);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_steps", TE_MI_MEAS_AGGR_SINGLE,
                              traced, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "expected_steps", TE_MI_MEAS_AGGR_SINGLE,
                              expected, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY, "request",
                              TE_MI_MEAS_AGGR_SINGLE, reply.time_s,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_value", TE_MI_MEAS_AGGR_SINGLE,
                              trace.have_value ? trace.value : 0,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "model_value", TE_MI_MEAS_AGGR_SINGLE,
                              model_value, TE_MI_MEAS_MULTIPLIER_PLAIN);
        /*
         * Several single values: a line graph over the sequence
         * number draws each as a point (a point view takes one).
         */
        te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                                   "summary", "Node steps vs hops");
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              "summary", TE_MI_GRAPH_AXIS_X,
                                              TE_MI_GRAPH_AUTO_SEQNO);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    TEST_ARTIFACT("hops=%d: HTTP %d, %u node step(s) traced (model %u), "
                  "%zu unreachable upstream(s)", hops, reply.code, traced,
                  expected, te_vec_size(&trace.unreach));
    TEST_ARTIFACT("Observed value %s%.4f, model value %.4f, request %.3f s",
                  trace.have_value ? "" : "(none) ",
                  trace.have_value ? trace.value : 0.0, model_value,
                  reply.time_s);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "web", min_severity);
    if (count_bad)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    if (web_up)
        tsapi_mde_web_stop(&web);
    te_string_free(&url);
    te_string_free(&reply.body);
    te_vec_free(&model);
    web_trace_free(&trace);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
