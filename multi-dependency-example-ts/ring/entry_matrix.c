/** @file
 * @brief Ring Group
 *
 * Enter the ring from one demo with a set of awkward values (zero, one, a
 * negative, a large one, a non-round one) and check that every step the
 * trace shows is self-consistent: each stage computed its own formula from
 * what it received, received what the previous stage computed, counted the
 * hops down by one, called its ring successor, and the printed result is
 * the last step's output.
 *
 * These hold whatever the depth of the walk, so they must be clean even on
 * the defective example. The model-relative findings (depth, value,
 * result) are kept as information only: ring/propagation gates on them.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/entry_matrix"

#include "ring_common.h"

/** Values every demo is entered with. */
static const double matrix_values[] = { 0, 1, -1, 1e6, 3.14159 };
/** Their labels in charts and subjects. */
static const char * const matrix_labels[] = {
    "0", "1", "-1", "1e6", "3.14159",
};

#define MATRIX_N    TE_ARRAY_LEN(matrix_values)

/** Whether a check measures the trace against itself, not the model. */
static bool
matrix_self_check(const char *check)
{
    return strcmp(check, "ring.formula") == 0 ||
           strcmp(check, "ring.handoff") == 0 ||
           strcmp(check, "ring.hop-counter") == 0 ||
           strcmp(check, "ring.order") == 0;
}

int
main(int argc, char **argv)
{
    ring_demo              entry;
    int                    hops;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut = { .root = NULL };
    tsapi_mde_report       report;
    bool                   report_up = false;
    tapi_cybersec_report   scratch;
    bool                   scratch_up = false;
    ring_walk              walk = RING_WALK_INIT;
    te_vec                 model = TE_VEC_INIT(tsapi_mde_step);
    tsapi_mde_stage        stage;
    double                 obs_first[MATRIX_N];
    double                 exp_first[MATRIX_N];
    double                 obs_res[MATRIX_N];
    double                 exp_res[MATRIX_N];
    double                 depth[MATRIX_N];
    const char            *why;
    te_mi_logger          *logger = NULL;
    char                   prefix[64];
    char                   subject[128];
    char                   key[16];
    unsigned int           n_self = 0;
    size_t                 i;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;
    tapi_cybersec_report_init(&scratch);
    scratch_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(entry, RING_DEMO_LIST);
    TEST_GET_INT_PARAM(hops);
    TEST_GET_MDE_SEVERITY(min_severity);
    stage = ring_demo_entry(entry);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "entry_matrix", dut, session_up);

    TEST_STEP("Skip unless the demo can be run");
    why = ring_demo_unavailable(&session, &dut, entry);
    if (why != NULL)
        TEST_VERDICT("%s", why);

    TEST_STEP("Known-bad controls: a planted formula defect and a planted "
              "crash must both be detected");
    ring_control_compare(&report, stage);
    CHECK_RC(ring_control_crash(&session, &report));

    for (i = 0; i < MATRIX_N; i++)
    {
        const tapi_cybersec_finding *f;
        const tsapi_mde_step        *first;
        double                       model_res;
        double                       v = matrix_values[i];
        size_t                       n;

        TEST_STEP("Enter the ring from %s with value=%s hops=%d",
                  ring_demo2str(entry), matrix_labels[i], hops);
        CHECK_RC(ring_walk_run(&session, &dut, entry, v, hops, &walk));
        if (!walk.started)
            TEST_FAIL("The demo could not be started");

        te_vec_reset(&model);
        model_res = tsapi_mde_ring_predict(stage, v, hops, &model);
        n = te_vec_size(&walk.steps);
        TE_SPRINTF(prefix, "v=%s/%s", matrix_labels[i],
                   tsapi_mde_stage2str(stage));

        /* Compare into a scratch report, then keep what is self-checking. */
        tapi_cybersec_report_free(&scratch);
        tapi_cybersec_report_init(&scratch);
        tsapi_mde_ring_compare(stage, &model, &walk.steps, walk.have_result,
                               model_res, walk.result, RING_TOLERANCE,
                               &scratch);
        TE_VEC_FOREACH(&scratch.findings, f)
        {
            bool self = matrix_self_check(f->check);

            TE_SPRINTF(subject, "v=%s/%s", matrix_labels[i], f->subject);
            tapi_cybersec_report_add(&report.cyber,
                                     self ? f->severity :
                                            TAPI_CYBERSEC_SEV_INFO,
                                     f->check, subject, "%s",
                                     f->detail != NULL ? f->detail : "");
            if (self)
                n_self++;
        }

        ring_check_crash(&walk, stage, prefix, &report.cyber);

        /* The walk must start where the demo says, with what it was given. */
        if (n == 0)
        {
            TE_SPRINTF(subject, "%s/walk", prefix);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "ring.no-trace", subject,
                                     "no stage line printed");
            obs_first[i] = 0;
        }
        else
        {
            first = te_vec_get(&walk.steps, 0);
            obs_first[i] = first->out;
            TE_SPRINTF(subject, "%s/step0", prefix);
            if (first->stage != stage)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "ring.entry-stage", subject,
                                         "entered at %s, the demo enters "
                                         "at %s",
                                         tsapi_mde_stage2str(first->stage),
                                         tsapi_mde_stage2str(stage));
            }
            if (fabs(first->in - v) > RING_TOLERANCE)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "ring.entry-value", subject,
                                         "received %.4f, the demo was "
                                         "given %s", first->in,
                                         matrix_labels[i]);
            }
            if (first->hops != hops)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "ring.entry-hops", subject,
                                         "hops=%d, the demo was given %d",
                                         first->hops, hops);
            }
        }

        /* Whatever the depth, the result is what the last step computed. */
        if (n > 0 && walk.have_result)
        {
            const tsapi_mde_step *last = te_vec_get(&walk.steps, n - 1);

            if (fabs(last->out - walk.result) > RING_TOLERANCE)
            {
                TE_SPRINTF(subject, "%s/result", prefix);
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_HIGH,
                                         "ring.result-consistency", subject,
                                         "printed %.4f, the last step "
                                         "computed %.4f", walk.result,
                                         last->out);
            }
        }

        exp_first[i] = te_vec_size(&model) > 0 ?
            ((const tsapi_mde_step *)te_vec_get(&model, 0))->out : 0;
        obs_res[i] = walk.have_result ? walk.result : 0;
        exp_res[i] = model_res;
        depth[i] = n;

        TEST_ARTIFACT("%s value=%s: %zu stage(s), first step %.4f (model "
                      "%.4f), result %.4f (model %.4f), exit %d",
                      ring_demo2str(entry), matrix_labels[i], n,
                      obs_first[i], exp_first[i], obs_res[i], exp_res[i],
                      walk.rc);
    }

    TEST_STEP("Chart the output per entry value");
    if (tsapi_mde_mi_create("ring", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "entry", "%s",
                                  ring_demo2str(entry));
        te_mi_logger_add_meas_key(logger, NULL, "hops", "%d", hops);
        for (i = 0; i < MATRIX_N; i++)
        {
            TE_SPRINTF(key, "x%zu", i);
            te_mi_logger_add_meas_key(logger, NULL, key, "%s",
                                      matrix_labels[i]);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "value_index", TE_MI_MEAS_AGGR_SINGLE, i,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_first_out",
                                  TE_MI_MEAS_AGGR_SINGLE, obs_first[i],
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_first_out", TE_MI_MEAS_AGGR_SINGLE,
                                  exp_first[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_result", TE_MI_MEAS_AGGR_SINGLE,
                                  obs_res[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "model_result", TE_MI_MEAS_AGGR_SINGLE,
                                  exp_res[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_depth", TE_MI_MEAS_AGGR_SINGLE,
                                  depth[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        tsapi_mde_mi_line(logger, "first", "First stage output per entry "
                          "value: observed vs model", "value_index",
                          "observed_first_out", "model_first_out", NULL);
        tsapi_mde_mi_line(logger, "result", "Result per entry value: "
                          "observed vs model", "value_index",
                          "observed_result", "model_result", NULL);
        tsapi_mde_mi_line(logger, "depth", "Stages visited per entry value",
                          "value_index", "observed_depth", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    TEST_ARTIFACT("%s: %zu value(s), %u self-consistency finding(s)",
                  ring_demo2str(entry), MATRIX_N, n_self);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ring", min_severity);

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    te_vec_free(&model);
    ring_walk_free(&walk);
    if (scratch_up)
        tapi_cybersec_report_free(&scratch);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
