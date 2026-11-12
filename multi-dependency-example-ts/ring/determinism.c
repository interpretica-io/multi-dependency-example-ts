/** @file
 * @brief Ring Group
 *
 * Run the same demo with the same input N times and require byte-identical
 * traces: the ring is pure arithmetic over five languages, so any difference
 * between runs (an uninitialised value, a racing flush, a stage that reads
 * the clock) is a defect of its own. The wall time of every run is charted
 * as a latency series with its min/mean/max.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ring/determinism"

#include "ring_common.h"

/** Input of every run. */
#define DET_VALUE   1.0
#define DET_HOPS    7

/**
 * Compare a run's fingerprint with the reference one; a difference is a
 * finding @c ring.nondeterministic about @p subject.
 */
static bool
det_check(tapi_cybersec_report *cyber, const char *subject, uint64_t ref,
          uint64_t got, unsigned int run)
{
    if (ref == got)
        return true;

    tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                             "ring.nondeterministic", subject,
                             "run %u printed fnv1a64 %016" PRIx64 ", run 0 "
                             "printed %016" PRIx64, run, got, ref);
    return false;
}

int
main(int argc, char **argv)
{
    ring_demo          entry;
    unsigned int       runs;
    tsapi_mde_session  session;
    bool               session_up = false;
    tsapi_mde_dut      dut = { .root = NULL };
    tsapi_mde_report   report;
    bool               report_up = false;
    ring_walk          walk = RING_WALK_INIT;
    te_string          ref_trace = TE_STRING_INIT;
    te_string          planted = TE_STRING_INIT;
    tsapi_mde_stage    stage;
    uint64_t           ref_hash = 0;
    double             ref_result = 0;
    bool               ref_have = false;
    size_t             ref_steps = 0;
    double            *wall_ms = NULL;
    double             w_min = 0;
    double             w_max = 0;
    double             w_sum = 0;
    unsigned int       n_diff = 0;
    unsigned int       n_crash = 0;
    bool               diff_reported = false;
    bool               crash_reported = false;
    const char        *why;
    te_mi_logger      *logger = NULL;
    char               subject[64];
    unsigned int       i;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(entry, RING_DEMO_LIST);
    TEST_GET_UINT_PARAM(runs);
    if (runs < 2)
        TEST_FAIL("runs must be at least 2");
    stage = ring_demo_entry(entry);
    wall_ms = calloc(runs, sizeof(*wall_ms));
    if (wall_ms == NULL)
        TEST_FAIL("Out of memory");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "determinism", dut, session_up);

    TEST_STEP("Skip unless the demo can be run");
    why = ring_demo_unavailable(&session, &dut, entry);
    if (why != NULL)
        TEST_VERDICT("%s", why);

    TEST_STEP("Known-bad controls: a one-byte change of a trace and a "
              "planted crash must both be detected");
    te_string_append(&planted, "  [rust] hops=0      1.0000 ->     2.6000\n");
    det_check(&report.cyber, "control/trace", ring_fnv1a(planted.ptr),
              ring_fnv1a("  [rust] hops=0      1.0000 ->     2.6001\n"), 1);
    tsapi_mde_report_expect(&report, "ring.nondeterministic",
                            "control/trace");
    ring_report_drop_prefix(&report, "control/");
    CHECK_RC(ring_control_crash(&session, &report));

    TEST_STEP("Run the %s demo %u times with value=%g hops=%d",
              ring_demo2str(entry), runs, DET_VALUE, DET_HOPS);
    TE_SPRINTF(subject, "%s/trace", ring_demo2str(entry));
    for (i = 0; i < runs; i++)
    {
        uint64_t hash;

        CHECK_RC(ring_walk_run(&session, &dut, entry, DET_VALUE, DET_HOPS,
                               &walk));
        if (!walk.started)
            TEST_FAIL("The demo could not be started");

        hash = ring_fnv1a(ring_str(&walk.out));
        wall_ms[i] = walk.wall_s * 1000.0;
        w_sum += wall_ms[i];
        if (i == 0 || wall_ms[i] < w_min)
            w_min = wall_ms[i];
        if (i == 0 || wall_ms[i] > w_max)
            w_max = wall_ms[i];

        if (walk.crashed)
        {
            n_crash++;
            /* One finding is enough: the subject is the same every run. */
            if (!crash_reported)
                crash_reported = ring_check_crash(&walk, stage,
                                                  tsapi_mde_stage2str(stage),
                                                  &report.cyber);
        }

        if (i == 0)
        {
            ref_hash = hash;
            ref_have = walk.have_result;
            ref_result = walk.have_result ? walk.result : 0;
            ref_steps = te_vec_size(&walk.steps);
            te_string_append(&ref_trace, "%s", ring_str(&walk.out));
            TEST_ARTIFACT("Run 0: %zu stage(s), result %.4f, stdout "
                          "fnv1a64 %016" PRIx64 " (%zu byte(s))", ref_steps,
                          ref_result, ref_hash, walk.out.len);
            continue;
        }

        /* Two views of sameness: the hash, and the parsed trace. */
        if (hash != ref_hash || te_vec_size(&walk.steps) != ref_steps ||
            walk.have_result != ref_have ||
            (ref_have && fabs(walk.result - ref_result) > 0))
        {
            n_diff++;
            RING("Run %u differs from run 0:\n--- run 0 ---\n%s\n"
                 "--- run %u ---\n%s", i, ring_str(&ref_trace), i,
                 ring_str(&walk.out));
            if (!diff_reported)
            {
                diff_reported = !det_check(&report.cyber, subject, ref_hash,
                                           hash, i);
                if (!diff_reported)
                {
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_HIGH,
                                             "ring.nondeterministic",
                                             subject,
                                             "run %u: same bytes but a "
                                             "different parse", i);
                    diff_reported = true;
                }
            }
        }
    }

    TEST_STEP("Chart the run times");
    tsapi_mde_mi_series("ring", "Demo wall time per run", TE_MI_MEAS_LATENCY,
                        "wall", runs, wall_ms, TE_MI_MEAS_MULTIPLIER_MILLI);
    if (tsapi_mde_mi_create("ring", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "entry", "%s",
                                  ring_demo2str(entry));
        te_mi_logger_add_meas_key(logger, NULL, "runs", "%u", runs);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY, "wall",
                              TE_MI_MEAS_AGGR_MIN, w_min,
                              TE_MI_MEAS_MULTIPLIER_MILLI);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY, "wall",
                              TE_MI_MEAS_AGGR_MEAN, w_sum / runs,
                              TE_MI_MEAS_MULTIPLIER_MILLI);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY, "wall",
                              TE_MI_MEAS_AGGR_MAX, w_max,
                              TE_MI_MEAS_MULTIPLIER_MILLI);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "differing_runs", TE_MI_MEAS_AGGR_SINGLE,
                              n_diff, TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "crashed_runs", TE_MI_MEAS_AGGR_SINGLE,
                              n_crash, TE_MI_MEAS_MULTIPLIER_PLAIN);
        /*
         * Several single values: a line graph over the sequence
         * number draws each as a point (a point view takes one).
         */
        te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                                   "stats", "Run time statistics");
        te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                                              TE_MI_MEAS_VIEW_LINE_GRAPH,
                                              "stats", TE_MI_GRAPH_AXIS_X,
                                              TE_MI_GRAPH_AUTO_SEQNO);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    TEST_ARTIFACT("%u run(s): %u differ from run 0, %u crashed; wall "
                  "min/mean/max %.1f/%.1f/%.1f ms", runs, n_diff, n_crash,
                  w_min, w_sum / runs, w_max);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ring", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    free(wall_ms);
    te_string_free(&ref_trace);
    te_string_free(&planted);
    ring_walk_free(&walk);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
