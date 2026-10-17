/** @file
 * @brief Ring Group
 *
 * The one documented numeric oracle of the ring: cpp-demo with value=1 and
 * hops=7 produces 20.0735 when the ring is correct (README reference output).
 * The injected defect stops the ring at the first stage, so it yields the
 * first stage's value instead.
 *
 * Two independent views are cross-checked: the reference model must
 * reproduce the README oracle (otherwise the model, not the DUT, is wrong),
 * and the observed trace is compared with the model step by step.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/reference"

#include "ring_common.h"

#define REF_VALUE       1.0
#define REF_HOPS        7
#define REF_EXPECTED    20.0735
#define REF_EPS         1.0e-3

int
main(int argc, char **argv)
{
    tsapi_mde_session  session;
    bool               session_up = false;
    tsapi_mde_dut      dut = { .root = NULL };
    tsapi_mde_report   report;
    bool               report_up = false;
    ring_walk          walk = RING_WALK_INIT;
    te_vec             model = TE_VEC_INIT(tsapi_mde_step);
    double             model_result;
    bool               oracle_bad = false;
    const char        *why;
    te_mi_logger      *logger = NULL;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "reference", dut, session_up);

    TEST_STEP("Skip unless the demo can be run");
    why = ring_demo_unavailable(&session, &dut, RING_DEMO_CPP);
    if (why != NULL)
        TEST_SKIP("%s", why);

    TEST_STEP("The reference model must reproduce the README oracle");
    model_result = tsapi_mde_ring_predict(TSAPI_MDE_STAGE_RUST, REF_VALUE,
                                          REF_HOPS, &model);
    RING("Model: cpp-demo 1 7 -> %.4f (README %.4f)", model_result,
         REF_EXPECTED);
    if (fabs(model_result - REF_EXPECTED) > REF_EPS)
    {
        TEST_FAIL("The reference model gives %.4f for cpp-demo 1 7, the "
                  "README says %.4f: the model is wrong", model_result,
                  REF_EXPECTED);
    }

    TEST_STEP("Known-bad control: a planted trace defect must be detected");
    ring_control_compare(&report, TSAPI_MDE_STAGE_RUST);

    TEST_STEP("Run cpp-demo 1 7 and read the trace and the result");
    CHECK_RC(ring_walk_run(&session, &dut, RING_DEMO_CPP, REF_VALUE, REF_HOPS,
                           &walk));
    if (!walk.started)
        TEST_FAIL("The demo could not be started");
    if (!walk.have_result)
        TEST_VERDICT("cpp-demo printed no result line");

    RING("cpp-demo 1 7 -> %.4f (expected %.4f)", walk.result, REF_EXPECTED);

    TEST_STEP("Check the result matches the reference");
    if (fabs(walk.result - REF_EXPECTED) > REF_EPS)
    {
        /* The historical verdict first; the model gate adds the deep one. */
        ERROR_VERDICT("Ring result %.4f, expected %.4f (value=1, hops=7)",
                      walk.result, REF_EXPECTED);
        oracle_bad = true;
    }

    TEST_STEP("Cross-check the whole trace against the model");
    ring_check_crash(&walk, TSAPI_MDE_STAGE_RUST, "rust", &report.cyber);
    tsapi_mde_ring_compare(TSAPI_MDE_STAGE_RUST, &model, &walk.steps,
                           walk.have_result, model_result, walk.result,
                           RING_TOLERANCE, &report.cyber);

    TEST_STEP("Record the result: charts and artifacts");
    if (tsapi_mde_mi_create("ring", &logger) == 0)
    {
        tsapi_mde_ring_chart(logger, "reference", &model, &walk.steps);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    ring_chart_residuals("cpp-demo 1 7: per-step residuals", &walk.steps);
    if (tsapi_mde_mi_create("ring", &logger) == 0)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_result", TE_MI_MEAS_AGGR_SINGLE,
                              walk.result, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "readme_oracle", TE_MI_MEAS_AGGR_SINGLE,
                              REF_EXPECTED, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "model_result", TE_MI_MEAS_AGGR_SINGLE,
                              model_result, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed_stages", TE_MI_MEAS_AGGR_SINGLE,
                              te_vec_size(&walk.steps),
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME, "demo_wall",
                              TE_MI_MEAS_AGGR_SINGLE, walk.wall_s,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        /*
         * Several single values: a line graph over the sequence
         * number draws each as a point (a point view takes one).
         */
        te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                                   "oracle", "cpp-demo 1 7: observed vs " "README vs model");
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              "oracle", TE_MI_GRAPH_AXIS_X,
                                              TE_MI_GRAPH_AUTO_SEQNO);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    TEST_ARTIFACT("Observed result %.4f, model result %.4f, README %.4f",
                  walk.result, model_result, REF_EXPECTED);
    TEST_ARTIFACT("Trace: %zu stage(s), model %zu; stdout fnv1a64 %016"
                  PRIx64, te_vec_size(&walk.steps), te_vec_size(&model),
                  ring_fnv1a(ring_str(&walk.out)));

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ring", TAPI_CYBERSEC_SEV_MEDIUM);
    if (oracle_bad)
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
