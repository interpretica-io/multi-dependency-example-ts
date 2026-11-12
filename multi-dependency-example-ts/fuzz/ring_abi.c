/** @file
 * @brief Fuzz Group
 *
 * Fuzz one stage of the ring's C ABI (double X_step(double, int)) with
 * libFuzzer + ASan. The harness dlopen()s the five ring libraries from
 * dist/lib, feeds the stage a finite value and a hop budget of 0..3 read
 * from the input, and abort()s when the result is not finite.
 *
 * Before the campaign: the harness must reach the stage and agree with
 * the ring model on a one-stage walk (hops=0, which the injected defect
 * does not affect), and a known-bad control variant (SIGABRT on 'X') must
 * be found within seconds and, replayed, come back as an AddressSanitizer
 * report whose stack goes through the planted function. After it: libFuzzer's progress
 * must show inputs executed and coverage reached, its final statistics
 * must agree with its progress lines, and every crash becomes an
 * artifact, a regression seed under /tmp/mde-fuzz-seeds/<target>, and
 * one stable finding fuzz.ring-abi-crash about the target.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "fuzz/ring_abi"

#include "te_config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "tapi_test.h"
#include "fuzz_common.h"

/** Tail of libFuzzer's output kept in the log, bytes. */
#define ABI_LOG_TAIL    4096

/** A seed input: a value and a hop budget, as octal escapes for printf. */
typedef struct abi_seed {
    const char *value;  /**< 8 bytes of a little-endian double. */
    unsigned int hops;  /**< Hop budget (low byte of the int). */
} abi_seed;

/** 1.0 and -2.5 as little-endian doubles. */
#define ABI_ONE         "\\000\\000\\000\\000\\000\\000\\360\\077"
#define ABI_MINUS_2_5   "\\000\\000\\000\\000\\000\\000\\004\\300"

/** Read "stat::<key>: N" from libFuzzer's final statistics. */
static bool
abi_final_stat(const char *text, const char *key, double *value)
{
    char        pattern[64];
    const char *p;

    TE_SPRINTF(pattern, "stat::%s:", key);
    p = strstr(text, pattern);
    if (p == NULL)
        return false;
    *value = strtod(p + strlen(pattern), NULL);
    return true;
}

/** Fill the libFuzzer options shared by the control and the campaign. */
static void
abi_opt_init(tapi_fuzz_opt *opt, const char *harness, const char *corpus,
             const char *artifacts, unsigned int seconds)
{
    static const char *extra[] = {
        /* Every stage prints its trace line; keep it out of the job. */
        "-close_fd_mask=1",
        "-print_final_stats=1",
    };

    *opt = tapi_fuzz_default_opt;
    opt->kind = TAPI_FUZZ_LIBFUZZER;
    opt->target = harness;
    opt->corpus_dir = corpus;
    opt->output_dir = artifacts;
    opt->max_total_time = seconds;
    opt->max_len = 64;
    opt->timeout_s = 10;
    opt->rss_limit_mb = 4096;
    /* Python, Go and .NET keep memory to the end by design. */
    opt->detect_leaks = false;
    opt->extra_args = extra;
    opt->n_extra_args = TE_ARRAY_LEN(extra);
}

/** Exit status of a job as text. */
static const char *
abi_status_str(const tapi_job_status_t *st, bool completed, char *buf,
               size_t size)
{
    if (!completed)
        snprintf(buf, size, "no exit status (did not complete)");
    else if (st->type == TAPI_JOB_STATUS_EXITED)
        snprintf(buf, size, "exit code %d", st->value);
    else if (st->type == TAPI_JOB_STATUS_SIGNALED)
        snprintf(buf, size, "killed by signal %d", st->value);
    else
        snprintf(buf, size, "exit status unknown");

    return buf;
}

/** Last line of the text, at most 240 bytes of it. */
static const char *
abi_last_line(const char *text, char *buf, size_t size)
{
    size_t      len = text != NULL ? strlen(text) : 0;
    const char *p;

    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r'))
        len--;
    p = text;
    while (p != NULL && p < text + len)
    {
        const char *nl = memchr(p, '\n', text + len - p);

        if (nl == NULL)
            break;
        p = nl + 1;
    }
    snprintf(buf, size, "%.*s", p != NULL ? (int)MIN(len - (p - text), 240) : 0,
             p != NULL ? p : "");

    return buf;
}

/**
 * Say why a campaign did not start or did not finish: the error of the
 * start, the exit status of the harness and the last line it printed on
 * stderr.
 */
static void
abi_describe(const char *target, const char *what, te_errno rc,
             const tapi_fuzz_app *app, char *buf, size_t size)
{
    tapi_devtool_output out;
    char                st[64];
    char                last[256];

    if (app == NULL)
    {
        snprintf(buf, size, "FUZZ %s: the %s did not start: harness start "
                 "error %s (no job was created)", target, what,
                 te_rc_err2str(rc));
        return;
    }
    tapi_fuzz_get_output(app, &out);
    snprintf(buf, size, "FUZZ %s: the %s did not run to the end: harness "
             "start error %s, %s, last stderr line [%s]", target, what,
             te_rc_err2str(rc),
             abi_status_str(&out.status, out.completed, st, sizeof(st)),
             abi_last_line(out.err, last, sizeof(last)));
}

/** Run a campaign; on a failure give the verdict with the start error. */
#define ABI_RUN(_what, _opt, _timeout_ms, _app) \
    do {                                                                    \
        char why_[600];                                                     \
                                                                            \
        rc = tapi_fuzz_do(session.factory, _opt, _timeout_ms, _app);        \
        if (rc != 0)                                                        \
        {                                                                   \
            abi_describe(target, _what, rc, *(_app), why_, sizeof(why_));   \
            TEST_VERDICT("%s", why_);                                       \
        }                                                                   \
    } while (0)

int
main(int argc, char **argv)
{
    const char             *target;
    int                     duration;
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session;
    bool                    session_up = false;
    tsapi_mde_dut           dut = { .root = NULL };
    tsapi_mde_report        report;
    tsapi_mde_sh_result     sh = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_stage         stage = TSAPI_MDE_STAGE_CPP;
    const char             *tag = "";
    te_string               base = TE_STRING_INIT;
    te_string               corpus = TE_STRING_INIT;
    te_string               arts = TE_STRING_INIT;
    te_string               ctl_corpus = TE_STRING_INIT;
    te_string               ctl_arts = TE_STRING_INIT;
    te_string               seeds = TE_STRING_INIT;
    te_string               save_dir = TE_STRING_INIT;
    te_string               harness = TE_STRING_INIT;
    te_string               ctl_harness = TE_STRING_INIT;
    tapi_fuzz_opt           opt;
    tapi_fuzz_opt           ctl_opt;
    tapi_fuzz_app          *app = NULL;
    tapi_fuzz_app          *ctl_app = NULL;
    tapi_fuzz_stats         stats;
    tapi_devtool_output     out;
    mde_fuzz_series         series;
    te_vec                  crashes;
    te_vec                  ctl_crashes;
    bool                    collected = false;
    bool                    ctl_collected = false;
    const tapi_fuzz_crash  *crash;
    te_vec                  model = TE_VEC_INIT(tsapi_mde_step);
    static const abi_seed   corpus_seeds[] = {
        { ABI_ONE, 0 }, { ABI_ONE, 1 }, { ABI_ONE, 2 }, { ABI_ONE, 3 },
        { ABI_MINUS_2_5, 1 },
    };
    double                  build_s = 0;
    double                  ctl_build_s = 0;
    double                  t0;
    double                  t_ctl = 0;
    double                  t_campaign = 0;
    double                  expected;
    double                  observed;
    double                  final_execs = 0;
    double                  peak_rss = 0;
    bool                    have_final;
    bool                    have_rss;
    bool                    no_progress;
    size_t                  n_lines;
    unsigned int            ctl_repro = 0;
    unsigned int            n_distinct = 0;
    unsigned int            n_inputs = 0;
    unsigned int            n_repro = 0;
    unsigned int            n_seeded = 0;
    unsigned int            n_seeds_total = 0;
    unsigned int            i;
    const char             *p;

    TEST_START;
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(target);
    TEST_GET_INT_PARAM(duration);
    TEST_GET_MDE_SEVERITY(min_sev);
    if (!mde_fuzz_target_stage(target, &stage, &tag))
        TEST_FAIL("Unknown target '%s'", target);
    if (duration <= 0)
        TEST_FAIL("duration must be positive");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "fuzz_abi", dut, session_up);

    TEST_STEP("Check clang can build a libFuzzer + ASan target");
    if (!mde_fuzz_supported(&session))
        TEST_VERDICT("clang with -fsanitize=fuzzer,address is not available "
                  "on the agent");

    TEST_STEP("Prepare the scratch, corpus and seed directories");
    te_string_append(&base, MDE_FUZZ_BUILD_DIR "/%s", target);
    te_string_append(&corpus, "%s/corpus", base.ptr);
    te_string_append(&arts, "%s/artifacts", base.ptr);
    te_string_append(&ctl_corpus, "%s/control-corpus", base.ptr);
    te_string_append(&ctl_arts, "%s/control-artifacts", base.ptr);
    te_string_append(&seeds, MDE_FUZZ_SEEDS_DIR "/%s", target);
    te_string_append(&save_dir, MDE_FUZZ_SAVE_DIR "/%s", target);
    CHECK_RC(mde_fuzz_fresh_dir(&session, base.ptr));
    CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                          "mkdir -p '%s' '%s' '%s' '%s' '%s'", corpus.ptr,
                          arts.ptr, ctl_corpus.ptr, ctl_arts.ptr,
                          seeds.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot create the fuzzing directories on the agent");
    CHECK_RC(mde_fuzz_count_files(&session, seeds.ptr, &n_seeds_total));
    TEST_ARTIFACT("%s: %u regression seed(s) already kept in %s", target,
                  n_seeds_total, seeds.ptr);

    TEST_STEP("Build the harness and its known-bad control variant");
    rc = mde_fuzz_build_harness(&session, &dut, target, false, base.ptr,
                                &harness, &build_s);
    if (rc != 0)
        TEST_VERDICT("FUZZ %s: clang cannot build the ring ABI harness: "
                     "harness start error %s", target, te_rc_err2str(rc));
    rc = mde_fuzz_build_harness(&session, &dut, target, true, base.ptr,
                                &ctl_harness, &ctl_build_s);
    if (rc != 0)
        TEST_VERDICT("FUZZ %s: clang cannot build the control harness: "
                     "harness start error %s", target, te_rc_err2str(rc));
    TEST_ARTIFACT("%s harness built in %.3f s, control in %.3f s", target,
                  build_s, ctl_build_s);
    CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                          "ls -l '%s' && sha256sum '%s'", harness.ptr,
                          harness.ptr));
    TEST_ARTIFACT("harness: %s", te_string_value(&sh.out));

    TEST_STEP("Oracle: one stage (hops=0) through the harness against the "
              "ring model");
    CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                          "printf '" ABI_ONE "\\000\\000\\000\\000' > "
                          "'%s/smoke.bin' && '%s' '%s/smoke.bin'",
                          base.ptr, harness.ptr, base.ptr));
    RING("Harness on value=1 hops=0:\nstdout:\n%s\nstderr:\n%s",
         te_string_value(&sh.out), te_string_value(&sh.err));
    if (!tsapi_mde_sh_ok(&sh))
    {
        char st[64];
        char last[256];

        TEST_VERDICT("FUZZ %s: the harness cannot call the stage through "
                     "the ring libraries: %s, last stderr line [%s]", target,
                     !sh.started ? "harness start error, the shell did not "
                     "start" : abi_status_str(&sh.status, true, st,
                                              sizeof(st)),
                     abi_last_line(te_string_value(&sh.err), last,
                                   sizeof(last)));
    }
    if (strstr(te_string_value(&sh.out), tag) == NULL)
        TEST_VERDICT("FUZZ %s: the harness started (exit code 0) but the stage "
                     "printed no trace line", target);
    p = strstr(te_string_value(&sh.out), "result=");
    if (p == NULL)
        TEST_VERDICT("FUZZ %s: the harness started (exit code 0) but printed no "
                     "result", target);
    observed = strtod(p + strlen("result="), NULL);
    expected = tsapi_mde_ring_predict(stage, 1.0, 0, &model);
    TEST_ARTIFACT("%s(1.0, 0): harness %.17g, model %.17g", target,
                  observed, expected);
    RING("FUZZ %s: the harness started (exit code 0) and the ring code ran: "
         "the stage printed its trace line and returned %.17g", target,
         observed);
    if (fabs(observed - expected) > 1e-9 * MAX(1.0, fabs(expected)))
        TEST_VERDICT("FUZZ %s: the harness started and the ring code ran, "
                     "but its result for value=1 hops=0 disagrees with the "
                     "ring model", target);

    TEST_STEP("Known-bad control: a harness that aborts on 'X', seeded "
              "with 'X...', must be caught within seconds and triaged");
    CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                          "printf 'XXXXXXXXXXXXXXXX' > '%s/x'",
                          ctl_corpus.ptr));
    abi_opt_init(&ctl_opt, ctl_harness.ptr, ctl_corpus.ptr, ctl_arts.ptr,
                 MDE_FUZZ_CONTROL_S);
    t0 = tsapi_mde_now();
    ABI_RUN("control campaign", &ctl_opt, (MDE_FUZZ_CONTROL_S + 120) * 1000,
            &ctl_app);
    t_ctl = tsapi_mde_now() - t0;
    CHECK_RC(tapi_fuzz_crashes_collect(session.factory, &ctl_opt, NULL,
                                       MDE_FUZZ_TIMEOUT_MS, &ctl_crashes));
    ctl_collected = true;
    tapi_fuzz_crashes_log(&ctl_crashes);
    CHECK_RC(tapi_fuzz_crashes_check(&ctl_crashes, &report.cyber));
    (void)tsapi_mde_report_expect(&report, "fuzz.crash", NULL);
    TE_VEC_FOREACH(&ctl_crashes, crash)
    {
        if (mde_fuzz_crash_is_planted(crash))
            ctl_repro++;
        TEST_ARTIFACT("control crash: %s (%s), %u input(s)",
                      crash->report.signature != NULL ?
                          crash->report.signature : "(none)",
                      tapi_sanitizer_kind2str(crash->report.kind),
                      crash->count);
        if (crash->report.signature != NULL)
            tsapi_mde_report_drop_subject(&report, crash->report.signature);
    }
    TEST_ARTIFACT("control: %u distinct crash(es), %u triaged to the "
                  "planted defect on replay, campaign ended after %.3f s", (unsigned int)
                  te_vec_size(&ctl_crashes), ctl_repro, t_ctl);
    if (te_vec_size(&ctl_crashes) > 0 && ctl_repro == 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "fuzz.control-not-reproduced", "control",
                                 "the planted abort was found but replay "
                                 "did not report it as ASan ABRT in "
                                 MDE_FUZZ_PLANTED_FRAME "(): crash triage "
                                 "is blind");
    }

    TEST_STEP("Seed the corpus with valid walks");
    for (i = 0; i < TE_ARRAY_LEN(corpus_seeds); i++)
    {
        CHECK_RC(tsapi_mde_sh(&session, MDE_FUZZ_TIMEOUT_MS, &sh,
                              "printf '%s\\%03o\\000\\000\\000' > "
                              "'%s/seed-%u'", corpus_seeds[i].value,
                              corpus_seeds[i].hops, corpus.ptr, i));
        if (!tsapi_mde_sh_ok(&sh))
            TEST_FAIL("Cannot write a corpus seed on the agent");
    }

    TEST_STEP("Run the campaign for the duration parameter");
    abi_opt_init(&opt, harness.ptr, corpus.ptr, arts.ptr,
                 (unsigned int)duration);
    t0 = tsapi_mde_now();
    ABI_RUN("campaign", &opt, (duration + 180) * 1000, &app);
    t_campaign = tsapi_mde_now() - t0;

    TEST_STEP("Read the campaign's statistics two ways");
    CHECK_RC(tapi_fuzz_get_stats(app, &stats));
    tapi_fuzz_stats_log(&stats);
    tapi_fuzz_get_output(app, &out);
    n_lines = mde_fuzz_parse_series(out.err, &series);
    have_final = abi_final_stat(out.err, "number_of_executed_units",
                                &final_execs);
    have_rss = abi_final_stat(out.err, "peak_rss_mb", &peak_rss);
    {
        size_t len = strlen(out.err);

        RING("libFuzzer output (tail):\n%s",
             len > ABI_LOG_TAIL ? out.err + len - ABI_LOG_TAIL : out.err);
    }
    TEST_ARTIFACT("%s campaign: %" PRIu64 " execs, %" PRIu64 " exec/s, "
                  "cov %" PRIu64 ", ft %" PRIu64 ", corpus %" PRIu64
                  ", %zu progress line(s), %.1f s wall", target, stats.execs,
                  stats.execs_per_sec, stats.coverage, stats.features,
                  stats.corpus_size, n_lines, t_campaign);
    if (have_final)
        TEST_ARTIFACT("final stats: %.0f units executed%s", final_execs,
                      have_rss ? "" : ", no peak RSS line");
    if (stats.valid != (n_lines > 0))
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "fuzz.stats-inconsistent", target,
                                 "tapi_fuzz_get_stats %s statistics but "
                                 "%zu progress lines were parsed",
                                 stats.valid ? "found" : "found no",
                                 n_lines);
    }
    if (have_final && final_execs < (double)stats.execs)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "fuzz.stats-inconsistent", target,
                                 "final statistics count %.0f units, fewer "
                                 "than the %" PRIu64 " of the last progress "
                                 "line", final_execs, stats.execs);
    }

    TEST_STEP("Collect, triage and keep the crashes");
    (void)mkdir(MDE_FUZZ_SAVE_DIR, 0755);
    (void)mkdir(save_dir.ptr, 0755);
    CHECK_RC(tapi_fuzz_crashes_collect(session.factory, &opt, save_dir.ptr,
                                       MDE_FUZZ_TIMEOUT_MS, &crashes));
    collected = true;
    tapi_fuzz_crashes_log(&crashes);
    CHECK_RC(tapi_fuzz_crashes_check(&crashes, &report.cyber));
    TE_VEC_FOREACH(&crashes, crash)
    {
        n_distinct++;
        n_inputs += crash->count;
        if (crash->report.kind != TAPI_SANITIZER_NONE)
            n_repro++;
        TEST_ARTIFACT("%s crash %u: %s (%s), %u input(s), artifact %s",
                      target, n_distinct,
                      crash->report.signature != NULL ?
                          crash->report.signature : "(none)",
                      tapi_sanitizer_kind2str(crash->report.kind),
                      crash->count, crash->artifact);
        /* Signatures depend on the input: they must not reach a verdict. */
        if (crash->report.signature != NULL)
            tsapi_mde_report_drop_subject(&report, crash->report.signature);
        if (crash->saved != NULL)
        {
            if (tapi_fuzz_seed_add(session.ta, seeds.ptr,
                                   crash->saved) == 0)
                n_seeded++;
            (void)unlink(crash->saved);
        }
    }
    if (n_distinct > 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "fuzz.ring-abi-crash", target,
                                 "%u distinct crash(es) reached by %u "
                                 "input(s), %u reproduced on replay; %u "
                                 "kept as seeds in %s", n_distinct,
                                 n_inputs, n_repro, n_seeded, seeds.ptr);
    }
    CHECK_RC(mde_fuzz_count_files(&session, seeds.ptr, &n_seeds_total));
    TEST_ARTIFACT("%s: %u crash(es), %u new seed(s), %u seed(s) in %s",
                  target, n_distinct, n_seeded, n_seeds_total, seeds.ptr);

    TEST_STEP("Check the campaign made progress");
    /* libFuzzer stops at the first crash, so a crash is progress too. */
    CHECK_RC(tapi_fuzz_check_progress(&stats,
                                      n_inputs > 0 ? 1 : MDE_FUZZ_MIN_EXECS,
                                      1, &report.cyber));
    no_progress = tsapi_mde_report_has(&report, "fuzz.no-statistics",
                                       NULL) +
                  tsapi_mde_report_has(&report, "fuzz.no-progress", NULL) +
                  tsapi_mde_report_has(&report, "fuzz.low-coverage",
                                       NULL) > 0;

    TEST_STEP("Chart the campaign");
    if (series.n > 0)
    {
        te_mi_logger *logger;

        if (tsapi_mde_mi_create("fuzz/ring_abi", &logger) == 0)
        {
            te_mi_logger_add_meas_key(logger, NULL, "target", "%s", target);
            for (i = 0; i < series.n; i++)
            {
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "execs",
                                      TE_MI_MEAS_AGGR_SINGLE,
                                      series.execs[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "cov",
                                      TE_MI_MEAS_AGGR_SINGLE, series.cov[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL,
                                      TE_MI_MEAS_UNITLESS_VALUE, "ft",
                                      TE_MI_MEAS_AGGR_SINGLE, series.ft[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
                te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_RPS,
                                      "exec_s", TE_MI_MEAS_AGGR_SINGLE,
                                      series.eps[i],
                                      TE_MI_MEAS_MULTIPLIER_PLAIN);
            }
            tsapi_mde_mi_line(logger, "coverage",
                              "Coverage and features over inputs executed",
                              "execs", "cov", "ft", NULL);
            tsapi_mde_mi_line(logger, "speed",
                              "Inputs per second over inputs executed",
                              "execs", "exec_s", NULL);
            te_mi_logger_destroy(logger);
        }
    }
    tsapi_mde_mi_point("fuzz/ring_abi", "Total inputs executed",
                       TE_MI_MEAS_UNITLESS_VALUE, "execs",
                       (double)stats.execs, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("fuzz/ring_abi", "Final coverage (edges)",
                       TE_MI_MEAS_UNITLESS_VALUE, "cov",
                       (double)stats.coverage, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("fuzz/ring_abi", "Distinct crashes found",
                       TE_MI_MEAS_UNITLESS_VALUE, "crashes", n_distinct,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("fuzz/ring_abi", "Crashing inputs",
                       TE_MI_MEAS_UNITLESS_VALUE, "crash_inputs", n_inputs,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("fuzz/ring_abi", "Regression seeds kept",
                       TE_MI_MEAS_UNITLESS_VALUE, "seeds", n_seeds_total,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("fuzz/ring_abi", "Campaign wall time",
                       TE_MI_MEAS_TIME, "campaign_s", t_campaign,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("fuzz/ring_abi", "Control: time to the planted crash",
                       TE_MI_MEAS_TIME, "control_s", t_ctl,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (have_rss)
        tsapi_mde_mi_point("fuzz/ring_abi", "Peak RSS of the campaign (MB)",
                           TE_MI_MEAS_UNITLESS_VALUE, "peak_rss_mb",
                           peak_rss, TE_MI_MEAS_MULTIPLIER_PLAIN);
    {
        static const char * const labels[] = { "harness", "control" };
        double                    times[] = { build_s, ctl_build_s };

        tsapi_mde_mi_bars("fuzz/ring_abi", "Harness build time",
                          TE_MI_MEAS_TIME, "build_s", TE_ARRAY_LEN(times),
                          labels, times, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    if (no_progress)
    {
        tapi_cybersec_report_log(&report.cyber);
        TEST_VERDICT("FUZZ %s: the campaign made no progress: no evidence "
                     "the harness fuzzed", target);
    }

    {
        char st[64];

        RING_VERDICT("FUZZ %s: harness started, ring code ran; campaign "
                     "%s after %.1f s, %.0f units executed (settles no "
                     "hypothesis)", target,
                     abi_status_str(&out.status, out.completed, st,
                                    sizeof(st)), t_campaign, final_execs);
    }

    TEST_STEP("Decide on the report");
    TSAPI_MDE_REPORT_GATE(&report, "fuzz", min_sev);

    TEST_SUCCESS;

cleanup:

    if (collected)
        tapi_fuzz_crashes_free(&crashes);
    if (ctl_collected)
        tapi_fuzz_crashes_free(&ctl_crashes);
    CLEANUP_CHECK_RC(tapi_fuzz_destroy(app));
    CLEANUP_CHECK_RC(tapi_fuzz_destroy(ctl_app));
    if (save_dir.ptr != NULL)
        (void)rmdir(save_dir.ptr);
    te_vec_free(&model);
    tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&base);
    te_string_free(&corpus);
    te_string_free(&arts);
    te_string_free(&ctl_corpus);
    te_string_free(&ctl_arts);
    te_string_free(&seeds);
    te_string_free(&save_dir);
    te_string_free(&harness);
    te_string_free(&ctl_harness);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
