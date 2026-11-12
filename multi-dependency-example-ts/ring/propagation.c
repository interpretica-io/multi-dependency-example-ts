/** @file
 * @brief Ring Group
 *
 * Enter the native FFI ring from one language and check the whole walk.
 * Correct code carries the value through hops+1 stages; the injected
 * always-true defect stops it after the first.
 *
 * The stage count is checked first and keeps its historical verdict. Then
 * the whole trace is compared with the reference model step by step (order,
 * hop counter, hand-off, formula, value, result) and the findings are gated
 * by min_severity.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/propagation"

#include "ring_common.h"

int
main(int argc, char **argv)
{
    ring_demo              entry;
    int                    hops;
    double                 value;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut = { .root = NULL };
    tsapi_mde_report       report;
    bool                   report_up = false;
    ring_walk              walk = RING_WALK_INIT;
    te_vec                 model = TE_VEC_INIT(tsapi_mde_step);
    tsapi_mde_stage        stage;
    double                 model_result;
    unsigned int           traced;
    unsigned int           expected;
    bool                   count_bad = false;
    const char            *why;
    te_mi_logger          *logger = NULL;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(entry, RING_DEMO_LIST);
    TEST_GET_INT_PARAM(hops);
    TEST_GET_DOUBLE_PARAM(value);
    TEST_GET_MDE_SEVERITY(min_severity);
    stage = ring_demo_entry(entry);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "ring", dut, session_up);

    TEST_STEP("Skip unless the demo can be run");
    why = ring_demo_unavailable(&session, &dut, entry);
    if (why != NULL)
        TEST_VERDICT("%s", why);

    TEST_STEP("Known-bad controls: a planted trace defect and a planted "
              "crash must both be detected");
    ring_control_compare(&report, stage);
    CHECK_RC(ring_control_crash(&session, &report));

    TEST_STEP("Run the %s demo with value=%g hops=%d and capture its trace",
              ring_demo2str(entry), value, hops);
    CHECK_RC(ring_walk_run(&session, &dut, entry, value, hops, &walk));
    if (!walk.started)
        TEST_FAIL("The demo could not be started");

    TEST_STEP("Predict the walk with the reference model");
    model_result = tsapi_mde_ring_predict(stage, value, hops, &model);

    TEST_STEP("Check the number of stages the value visited");
    traced = te_vec_size(&walk.steps);
    expected = (unsigned int)hops + 1;
    if (traced != expected)
    {
        /*
         * The historical verdict comes first (TRC matches it); the report
         * gate below adds the deep one.
         */
        ERROR_VERDICT("Ring propagated through %u stage(s), expected %u",
                      traced, expected);
        count_bad = true;
    }

    TEST_STEP("Compare the trace with the model step by step");
    ring_check_crash(&walk, stage, tsapi_mde_stage2str(stage), &report.cyber);
    tsapi_mde_ring_compare(stage, &model, &walk.steps, walk.have_result,
                           model_result, walk.result, RING_TOLERANCE,
                           &report.cyber);

    TEST_STEP("Record the walk: charts and artifacts");
    if (tsapi_mde_mi_create("ring", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "entry", "%s",
                                  ring_demo2str(entry));
        te_mi_logger_add_meas_key(logger, NULL, "hops", "%d", hops);
        te_mi_logger_add_meas_key(logger, NULL, "value", "%g", value);
        tsapi_mde_ring_chart(logger, "walk", &model, &walk.steps);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    ring_chart_residuals("Per-step residuals of the observed trace",
                         &walk.steps);
    if (tsapi_mde_mi_create("ring", &logger) == 0)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_stages", TE_MI_MEAS_AGGR_SINGLE,
                              traced, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "expected_stages", TE_MI_MEAS_AGGR_SINGLE,
                              expected, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "demo_wall",
                              TE_MI_MEAS_AGGR_SINGLE, walk.wall_s,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_result", TE_MI_MEAS_AGGR_SINGLE,
                              walk.have_result ? walk.result : 0,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "model_result", TE_MI_MEAS_AGGR_SINGLE,
                              model_result, TE_MI_MEAS_MULTIPLIER_PLAIN);
        /*
         * Several single values: a line graph over the sequence
         * number draws each as a point (a point view takes one).
         */
        te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                                   "summary", "Ring walk summary");
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              "summary", TE_MI_GRAPH_AXIS_X,
                                              TE_MI_GRAPH_AUTO_SEQNO);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    TEST_ARTIFACT("%s demo value=%g hops=%d: %u stage(s) traced, model %u",
                  ring_demo2str(entry), value, hops, traced, expected);
    TEST_ARTIFACT("Observed result %s%.4f, model result %.4f",
                  walk.have_result ? "" : "(none) ",
                  walk.have_result ? walk.result : 0.0, model_result);
    TEST_ARTIFACT("Exit code %d, wall time %.3f s, stdout fnv1a64 %016" PRIx64,
                  walk.rc, walk.wall_s, ring_fnv1a(ring_str(&walk.out)));

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ring", min_severity);
    if (count_bad)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    te_vec_free(&model);
    ring_walk_free(&walk);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
