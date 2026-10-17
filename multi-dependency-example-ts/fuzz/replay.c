/** @file
 * @brief Fuzz Group
 *
 * Replay the regression corpus: every crash fuzz/ring_abi ever kept under
 * /tmp/mde-fuzz-seeds/<target> is run against a freshly built harness of
 * that target. Each one either still reproduces - a known issue, reported
 * as the stable finding fuzz.ring-abi-crash about the target - or is
 * fixed. Before trusting a "fixed", the harness must be shown to reach the
 * stage on a valid input, a planted 'X' seed replayed against the control
 * harness must come back as an ASan report through the planted function
 * (known-bad control), and the seed itself must run to a clean exit.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fuzz/replay"

#include "te_config.h"
#include "tapi_test.h"
#include "fuzz_common.h"

/** Scratch directory of this test on the agent. */
#define REPLAY_DIR      MDE_FUZZ_BUILD_DIR "/replay"

/** Fill the options a replay needs: the harness and where the seeds are. */
static void
replay_opt_init(tapi_fuzz_opt *opt, const char *harness, const char *dir)
{
    *opt = tapi_fuzz_default_opt;
    opt->kind = TAPI_FUZZ_LIBFUZZER;
    opt->target = harness;
    opt->corpus_dir = dir;
    /* tapi_fuzz_crashes_collect() replays what is in the output dir. */
    opt->output_dir = dir;
    opt->detect_leaks = false;
}

/**
 * Run a harness on one valid input (value 1.0, hops 0) and check it
 * reached the stage: a harness that cannot load the ring exits without a
 * sanitizer report, and every seed would look fixed.
 */
static bool
replay_harness_works(tsapi_mde_session *session, const char *harness,
                     const char *dir, const char *tag)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, MDE_FUZZ_TIMEOUT_MS, &sh,
                      "printf '\\000\\000\\000\\000\\000\\000\\360\\077"
                      "\\000\\000\\000\\000' > '%s/smoke.bin' && "
                      "'%s' '%s/smoke.bin'", dir, harness, dir) == 0 &&
         tsapi_mde_sh_ok(&sh) &&
         strstr(te_string_value(&sh.out), tag) != NULL;
    RING("Harness %s on a valid input:\nstdout:\n%s\nstderr:\n%s", harness,
         te_string_value(&sh.out), te_string_value(&sh.err));
    tsapi_mde_sh_result_free(&sh);

    return ok;
}

/**
 * Run a harness on a seed that triage found nothing in, and say whether
 * it exited cleanly. A crash the sanitizer parser does not recognise
 * (a runtime that handles the signal itself, libFuzzer's own "deadly
 * signal") leaves kind NONE too, and must not be called fixed.
 */
static bool
replay_seed_clean(tsapi_mde_session *session, const char *harness,
                  const char *seed)
{
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok;

    ok = tsapi_mde_sh(session, MDE_FUZZ_TIMEOUT_MS, &sh, "'%s' '%s'",
                      harness, seed) == 0 &&
         tsapi_mde_sh_ok(&sh);
    RING("Harness %s on %s: %s\nstderr:\n%s", harness, seed,
         ok ? "clean exit" : "failed", te_string_value(&sh.err));
    tsapi_mde_sh_result_free(&sh);

    return ok;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session;
    bool                    session_up = false;
    tsapi_mde_dut           dut = { .root = NULL };
    tsapi_mde_report        report;
    tsapi_mde_sh_result     sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string               seeds = TE_STRING_INIT;
    te_string               dir = TE_STRING_INIT;
    te_string               harness = TE_STRING_INIT;
    tapi_fuzz_opt           opt;
    te_vec                  crashes;
    bool                    collected = false;
    const tapi_fuzz_crash  *crash;
    tsapi_mde_stage         stage = TSAPI_MDE_STAGE_CPP;
    const char             *tag = "";
    const char             *labels[MDE_FUZZ_N_TARGETS];
    double                  n_seeds[MDE_FUZZ_N_TARGETS] = { 0 };
    double                  n_repro[MDE_FUZZ_N_TARGETS] = { 0 };
    double                  n_fixed[MDE_FUZZ_N_TARGETS] = { 0 };
    double                  t_build[MDE_FUZZ_N_TARGETS] = { 0 };
    double                  t_replay[MDE_FUZZ_N_TARGETS] = { 0 };
    unsigned int            total = 0;
    unsigned int            count = 0;
    unsigned int            accounted;
    unsigned int            ctl_repro = 0;
    unsigned int            first = MDE_FUZZ_N_TARGETS;
    unsigned int            i;
    double                  build_s = 0;
    double                  t0;

    TEST_START;
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "fuzz_replay", dut, session_up);

    TEST_STEP("Count the regression seeds of every target");
    for (i = 0; i < MDE_FUZZ_N_TARGETS; i++)
    {
        labels[i] = mde_fuzz_target(i);
        te_string_reset(&seeds);
        te_string_append(&seeds, MDE_FUZZ_SEEDS_DIR "/%s", labels[i]);
        CHECK_RC(mde_fuzz_count_files(&session, seeds.ptr, &count));
        n_seeds[i] = count;
        total += count;
        if (count > 0 && first == MDE_FUZZ_N_TARGETS)
            first = i;
        TEST_ARTIFACT("%s: %u seed(s) in %s", labels[i], count, seeds.ptr);
    }
    tsapi_mde_mi_bars("fuzz/replay", "Regression seeds per target",
                      TE_MI_MEAS_UNITLESS_VALUE, "seeds", MDE_FUZZ_N_TARGETS,
                      labels, n_seeds, TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (total == 0)
    {
        TEST_ARTIFACT("no seeds to replay");
        TEST_SUCCESS;
    }

    TEST_STEP("Check clang can build a libFuzzer + ASan target");
    if (!mde_fuzz_supported(&session))
        TEST_SKIP("clang with -fsanitize=fuzzer,address is not available "
                  "on the agent");
    CHECK_RC(mde_fuzz_fresh_dir(&session, REPLAY_DIR));

    TEST_STEP("Known-bad control: a planted 'X' seed must reproduce on the "
              "control harness");
    CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                          "mkdir -p '" REPLAY_DIR "/control-seeds' && "
                          "printf 'XXXXXXXXXXXXXXXX' > '" REPLAY_DIR
                          "/control-seeds/x'"));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot plant the control seed on the agent");
    rc = mde_fuzz_build_harness(&session, &dut, labels[first], true,
                                REPLAY_DIR, &harness, &build_s);
    if (rc != 0)
        TEST_VERDICT("clang cannot build the control harness");
    replay_opt_init(&opt, harness.ptr, REPLAY_DIR "/control-seeds");
    CHECK_RC(tapi_fuzz_crashes_collect(session.factory, &opt, NULL,
                                       MDE_FUZZ_TIMEOUT_MS, &crashes));
    collected = true;
    tapi_fuzz_crashes_log(&crashes);
    CHECK_RC(tapi_fuzz_crashes_check(&crashes, &report.cyber));
    (void)tsapi_mde_report_expect(&report, "fuzz.crash", NULL);
    TE_VEC_FOREACH(&crashes, crash)
    {
        if (mde_fuzz_crash_is_planted(crash))
            ctl_repro++;
        if (crash->report.signature != NULL)
            tsapi_mde_report_drop_subject(&report, crash->report.signature);
    }
    TEST_ARTIFACT("control: %u replayed, %u triaged to the planted defect "
                  "(control harness "
                  "built in %.3f s)", (unsigned int)te_vec_size(&crashes),
                  ctl_repro, build_s);
    if (ctl_repro == 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "fuzz.control-not-reproduced", "control",
                                 "the planted abort did not come back as "
                                 "ASan ABRT in " MDE_FUZZ_PLANTED_FRAME
                                 "(): a 'fixed' seed would mean nothing");
    }
    tapi_fuzz_crashes_free(&crashes);
    collected = false;

    for (i = 0; i < MDE_FUZZ_N_TARGETS; i++)
    {
        if (n_seeds[i] == 0)
            continue;

        TEST_STEP("Replay the seeds of %s", labels[i]);
        if (!mde_fuzz_target_stage(labels[i], &stage, &tag))
            TEST_FAIL("Unknown target '%s'", labels[i]);

        te_string_reset(&seeds);
        te_string_append(&seeds, MDE_FUZZ_SEEDS_DIR "/%s", labels[i]);
        te_string_reset(&dir);
        te_string_append(&dir, REPLAY_DIR "/%s", labels[i]);
        te_string_reset(&harness);
        CHECK_RC(mde_fuzz_fresh_dir(&session, dir.ptr));

        rc = mde_fuzz_build_harness(&session, &dut, labels[i], false,
                                    dir.ptr, &harness, &t_build[i]);
        if (rc != 0)
            TEST_VERDICT("clang cannot build the replay harness for %s",
                         labels[i]);
        if (!replay_harness_works(&session, harness.ptr, dir.ptr, tag))
            TEST_VERDICT("The replay harness for %s cannot call the stage",
                         labels[i]);

        replay_opt_init(&opt, harness.ptr, seeds.ptr);
        t0 = tsapi_mde_now();
        CHECK_RC(tapi_fuzz_crashes_collect(session.factory, &opt, NULL,
                                           MDE_FUZZ_TIMEOUT_MS, &crashes));
        collected = true;
        t_replay[i] = tsapi_mde_now() - t0;
        tapi_fuzz_crashes_log(&crashes);

        accounted = 0;
        TE_VEC_FOREACH(&crashes, crash)
        {
            bool repro = crash->report.kind != TAPI_SANITIZER_NONE ||
                         !replay_seed_clean(&session, harness.ptr,
                                            crash->artifact);

            accounted += crash->count;
            if (repro)
                n_repro[i] += crash->count;
            else
                n_fixed[i] += crash->count;
            TEST_ARTIFACT("%s: %s -> %s (%s), %u seed(s)", labels[i],
                          crash->artifact,
                          repro ? "still crashes" : "fixed",
                          crash->report.signature != NULL ?
                              crash->report.signature : "(none)",
                          crash->count);
        }
        tapi_fuzz_crashes_free(&crashes);
        collected = false;

        TEST_ARTIFACT("%s: %.0f seed(s), %.0f still crash, %.0f fixed, "
                      "replayed in %.3f s (harness built in %.3f s)",
                      labels[i], n_seeds[i], n_repro[i], n_fixed[i],
                      t_replay[i], t_build[i]);

        if ((double)accounted != n_seeds[i])
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "fuzz.replay-unaccounted", labels[i],
                                     "%.0f seed(s) listed, %u replayed",
                                     n_seeds[i], accounted);
        }
        if (n_repro[i] > 0)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "fuzz.ring-abi-crash", labels[i],
                                     "%.0f of %.0f regression seed(s) still "
                                     "crash the stage", n_repro[i],
                                     n_seeds[i]);
        }
        if (n_fixed[i] > 0)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "fuzz.replay-fixed", labels[i],
                                     "%.0f of %.0f regression seed(s) no "
                                     "longer crash", n_fixed[i],
                                     n_seeds[i]);
        }
    }

    TEST_STEP("Chart the replay");
    {
        te_mi_logger *logger;
        char          key[16];

        if (tsapi_mde_mi_create("fuzz/replay", &logger) == 0)
        {
            for (i = 0; i < MDE_FUZZ_N_TARGETS; i++)
            {
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "index",
                                      TE_MI_MEAS_AGGR_SINGLE, i,
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "seeds",
                                      TE_MI_MEAS_AGGR_SINGLE, n_seeds[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE,
                                      "reproduced", TE_MI_MEAS_AGGR_SINGLE,
                                      n_repro[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "fixed",
                                      TE_MI_MEAS_AGGR_SINGLE, n_fixed[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                TE_SPRINTF(key, "x%u", i);
                te_mi_logger_add_meas_key(logger, NULL, key, "%s",
                                          labels[i]);
            }
            tsapi_mde_mi_line(logger, "replays",
                              "Replays per target: seeds, still crashing, "
                              "fixed", "index", "seeds", "reproduced",
                              "fixed", NULL);
            te_mi_logger_destroy(logger);
        }
    }
    tsapi_mde_mi_bars("fuzz/replay", "Replay time per target",
                      TE_MI_MEAS_TIME, "replay_s", MDE_FUZZ_N_TARGETS,
                      labels, t_replay, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("fuzz/replay", "Replay harness build time per target",
                      TE_MI_MEAS_TIME, "build_s", MDE_FUZZ_N_TARGETS,
                      labels, t_build, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the report");
    TSAPI_MDE_REPORT_GATE(&report, "fuzz", min_sev);

    TEST_SUCCESS;

cleanup:

    if (collected)
        tapi_fuzz_crashes_free(&crashes);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&seeds);
    te_string_free(&dir);
    te_string_free(&harness);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
