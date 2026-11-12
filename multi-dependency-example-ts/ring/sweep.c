/** @file
 * @brief Ring Group
 *
 * Sweep the hop budget of cpp-demo from 0 to 12 in one test and draw the
 * observed depth and result next to the model's over the whole range. A
 * healthy ring follows the model exactly at every budget; the injected
 * defect follows it only at hops=0 and stays flat afterwards.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/sweep"

#include "ring_common.h"

/** Highest hop budget of the sweep. */
#define SWEEP_MAX_HOPS  12
/** Points of the sweep. */
#define SWEEP_N         (SWEEP_MAX_HOPS + 1)

int
main(int argc, char **argv)
{
    double                 value;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut = { .root = NULL };
    tsapi_mde_report       report;
    bool                   report_up = false;
    ring_walk              walk = RING_WALK_INIT;
    te_vec                 model = TE_VEC_INIT(tsapi_mde_step);
    double                 obs_depth[SWEEP_N];
    double                 exp_depth[SWEEP_N];
    double                 obs_result[SWEEP_N];
    double                 exp_result[SWEEP_N];
    double                 wall_ms[SWEEP_N];
    int                    first_mismatch = -1;
    unsigned int           n_match = 0;
    const char            *why;
    te_mi_logger          *logger = NULL;
    char                   subject[64];
    int                    h;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_DOUBLE_PARAM(value);
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "sweep", dut, session_up);

    TEST_STEP("Skip unless the demo can be run");
    why = ring_demo_unavailable(&session, &dut, RING_DEMO_CPP);
    if (why != NULL)
        TEST_VERDICT("%s", why);

    TEST_STEP("Known-bad control: a planted trace defect must be detected");
    ring_control_compare(&report, TSAPI_MDE_STAGE_RUST);

    TEST_STEP("Sweep cpp-demo over hops 0..%d", SWEEP_MAX_HOPS);
    for (h = 0; h <= SWEEP_MAX_HOPS; h++)
    {
        double model_res;
        bool   match;

        TEST_SUBSTEP("hops=%d", h);
        CHECK_RC(ring_walk_run(&session, &dut, RING_DEMO_CPP, value, h,
                               &walk));
        if (!walk.started)
            TEST_FAIL("The demo could not be started");

        te_vec_reset(&model);
        model_res = tsapi_mde_ring_predict(TSAPI_MDE_STAGE_RUST, value, h,
                                           &model);

        obs_depth[h] = te_vec_size(&walk.steps);
        exp_depth[h] = te_vec_size(&model);
        obs_result[h] = walk.have_result ? walk.result : 0;
        exp_result[h] = model_res;
        wall_ms[h] = walk.wall_s * 1000.0;

        ring_check_crash(&walk, TSAPI_MDE_STAGE_RUST, "rust", &report.cyber);
        tsapi_mde_ring_compare(TSAPI_MDE_STAGE_RUST, &model, &walk.steps,
                               walk.have_result, model_res, walk.result,
                               RING_TOLERANCE, &report.cyber);

        /* The model itself: exactly one more stage per hop. */
        if (exp_depth[h] != h + 1)
            TEST_FAIL("The model predicts %.0f stage(s) for hops=%d",
                      exp_depth[h], h);

        match = !walk.crashed && walk.have_result &&
                obs_depth[h] == exp_depth[h] &&
                fabs(obs_result[h] - exp_result[h]) <= RING_TOLERANCE;
        if (match)
            n_match++;
        else if (first_mismatch < 0)
            first_mismatch = h;

        /* Deeper budgets must never make the walk shorter. */
        if (h > 0 && obs_depth[h] < obs_depth[h - 1])
        {
            TE_SPRINTF(subject, "rust/sweep:hops=%d", h);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "ring.monotonic", subject,
                                     "%.0f stage(s) at hops=%d, %.0f at "
                                     "hops=%d", obs_depth[h], h,
                                     obs_depth[h - 1], h - 1);
        }

        TEST_ARTIFACT("hops=%d: depth %.0f (model %.0f), result %.4f "
                      "(model %.4f), exit %d, %.1f ms", h, obs_depth[h],
                      exp_depth[h], obs_result[h], exp_result[h], walk.rc,
                      wall_ms[h]);
    }

    TEST_STEP("Chart the sweep: observed vs model over hops");
    if (tsapi_mde_mi_create("ring", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "value", "%g", value);
        for (h = 0; h <= SWEEP_MAX_HOPS; h++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "hops", TE_MI_MEAS_AGGR_SINGLE, h,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_depth", TE_MI_MEAS_AGGR_SINGLE,
                                  obs_depth[h], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_depth", TE_MI_MEAS_AGGR_SINGLE,
                                  exp_depth[h], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_result", TE_MI_MEAS_AGGR_SINGLE,
                                  obs_result[h], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_result", TE_MI_MEAS_AGGR_SINGLE,
                                  exp_result[h], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "wall", TE_MI_MEAS_AGGR_SINGLE, wall_ms[h],
                                  TE_MI_MEAS_MULTIPLIER_MILLI);
        }
        tsapi_mde_mi_line(logger, "depth", "Stages visited over hops: "
                          "observed vs model", "hops", "observed_depth",
                          "model_depth", NULL);
        tsapi_mde_mi_line(logger, "result", "Result over hops: observed vs "
                          "model", "hops", "observed_result", "model_result",
                          NULL);
        tsapi_mde_mi_line(logger, "wall", "Demo wall time over hops", "hops",
                          "wall", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    TEST_ARTIFACT("Sweep: %u of %d hop budget(s) match the model, first "
                  "mismatch at hops=%d", n_match, SWEEP_N, first_mismatch);

    TEST_STEP("Check the sweep follows the model at every budget");
    if (first_mismatch >= 0)
    {
        ERROR_VERDICT("Ring sweep diverges from the model first at hops=%d",
                      first_mismatch);
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ring", min_severity);
    if (first_mismatch >= 0)
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
