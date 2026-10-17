/** @file
 * @brief Time Group
 *
 * The ring's arithmetic must not depend on the wall clock. Run a demo of
 * the ring on the real clock and again under libfaketime (tapi_time_wrap)
 * years away, and compare the two runs: exit status, the whole printed
 * trace (hash), every parsed stage step and the result. A crash under the
 * fake clock (the Go and .NET runtimes in the ring may react to it) is a
 * finding, not a test failure. `date +%Y` run through the same comparison
 * is the known-bad control: its output must be seen to change.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "time/ring_under_time"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_time.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_ring.h"
#include "time_common.h"

/** Which demo enters the ring. */
typedef enum ring_demo {
    RING_DEMO_CPP,
    RING_DEMO_RUST,
    RING_DEMO_PY,
} ring_demo;

#define RING_DEMO_LIST \
    { "cpp",  RING_DEMO_CPP }, \
    { "rust", RING_DEMO_RUST }, \
    { "py",   RING_DEMO_PY }

/** Time a demo is given, ms. */
#define RING_TIMEOUT_MS     60000

/**
 * Compare a real-clock run with a fake-clock run of the same program and
 * add what differs to the report under @p subject.
 *
 * @return Number of findings added.
 */
static unsigned int
ring_compare_runs(tsapi_mde_report *report, const char *subject,
                  const mde_time_run_result *real,
                  const mde_time_run_result *faked)
{
    const char  *a = te_string_value(&real->out);
    const char  *b = te_string_value(&faked->out);
    unsigned int n = 0;

    if (!faked->started || faked->status.type == TAPI_JOB_STATUS_UNKNOWN)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
            "time.hang", subject,
            "the program did not finish under the fake clock");
        return 1;
    }

    /* faketime reports a child killed by a signal as an exit >= 128. */
    if (faked->status.type == TAPI_JOB_STATUS_SIGNALED ||
        (faked->status.type == TAPI_JOB_STATUS_EXITED &&
         faked->status.value >= 128))
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_CRITICAL,
            "time.crash", subject,
            "the program died under the fake clock (status %d/%d): %s",
            (int)faked->status.type, faked->status.value,
            te_string_value(&faked->err));
        return 1;
    }

    if (faked->status.type != real->status.type ||
        faked->status.value != real->status.value)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
            "time.behaviour-changes", subject,
            "exit status %d under the fake clock, %d on the real one",
            faked->status.value, real->status.value);
        n++;
    }

    if (strcmp(a, b) != 0)
    {
        size_t at = 0;

        while (a[at] != '\0' && a[at] == b[at])
            at++;
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
            "time.behaviour-changes", subject,
            "the output differs from byte %zu: real '%.40s', faked '%.40s'",
            at, a + at, b + at);
        n++;
    }

    return n;
}

int
main(int argc, char **argv)
{
    const char             *offset;
    ring_demo               demo;
    tapi_cybersec_severity  min_severity;
    tsapi_mde_session       session;
    tsapi_mde_dut           dut;
    tsapi_mde_report        report;
    tapi_time_opt           clock;
    mde_time_run_result     real = MDE_TIME_RUN_RESULT_INIT;
    mde_time_run_result     faked = MDE_TIME_RUN_RESULT_INIT;
    te_vec                  steps_real = TE_VEC_INIT(tsapi_mde_step);
    te_vec                  steps_faked = TE_VEC_INIT(tsapi_mde_step);
    te_string               program = TE_STRING_INIT;
    te_string               script = TE_STRING_INIT;
    te_string               subject = TE_STRING_INIT;
    te_mi_logger           *logger = NULL;
    const char             *run_argv[6];
    const char             *date_argv[] = { "date", "+%Y", NULL };
    const char             *demo_name;
    const char             *labels[2] = { "real", "faked" };
    double                  times[2];
    double                  counts[2];
    double                  res_real = 0.0;
    double                  res_faked = 0.0;
    bool                    have_real;
    bool                    have_faked;
    int64_t                 requested = 0;
    int64_t                 skew = 0;
    int64_t                 err;
    bool                    session_up = false;
    size_t                  n_real;
    size_t                  n_faked;
    size_t                  i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_STRING_PARAM(offset);
    TEST_GET_ENUM_PARAM(demo, RING_DEMO_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);
    if (!mde_time_offset_seconds(offset, &requested))
        TEST_FAIL("Cannot parse offset '%s'", offset);
    demo_name = demo == RING_DEMO_CPP ? "cpp" :
                demo == RING_DEMO_RUST ? "rust" : "py";

    memset(&dut, 0, sizeof(dut));
    tsapi_mde_report_init(&report);
    te_string_append(&subject, "%s@%s", demo_name, offset);

    tsapi_evo_analysis_hint(
        "A demo of the ring run on the real clock and under libfaketime. "
        "The ring computes from its inputs only, so the two traces must be "
        "byte-identical. The date control must change, or the comparison "
        "or the shim is blind.");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "time_ring", dut, session_up);

    if (!tapi_time_available(session.factory, MDE_TIME_TIMEOUT_MS))
        TEST_SKIP("libfaketime is not installed on the agent");
    if (!tsapi_mde_have(&session, "faketime"))
        TEST_SKIP("The faketime program is not installed on the agent");

    switch (demo)
    {
        case RING_DEMO_CPP:
            te_string_append(&program, "%s/cpp-demo", dut.bin);
            run_argv[0] = program.ptr;
            run_argv[1] = "1";
            run_argv[2] = "7";
            run_argv[3] = NULL;
            break;

        case RING_DEMO_RUST:
            te_string_append(&program, "%s/rust-demo", dut.bin);
            run_argv[0] = program.ptr;
            run_argv[1] = "2";
            run_argv[2] = "4";
            run_argv[3] = NULL;
            break;

        case RING_DEMO_PY:
        default:
            if (!tsapi_mde_have(&session, "python3"))
                TEST_SKIP("There is no python3 on the agent");
            te_string_append(&program, "python3");
            te_string_append(&script, "%s/demo.py", dut.python);
            run_argv[0] = program.ptr;
            run_argv[1] = script.ptr;
            run_argv[2] = "1";
            run_argv[3] = "5";
            run_argv[4] = NULL;
            break;
    }
    if (demo != RING_DEMO_PY && !tsapi_mde_exists(&session, program.ptr))
        TEST_SKIP("%s is not built", demo_name);

    clock = tapi_time_default_opt;
    clock.offset = offset;

    TEST_STEP("Prove the clock moves by the offset");
    CHECK_RC(tapi_time_check(session.factory, &clock, MDE_TIME_TIMEOUT_MS,
                             &skew));
    err = skew - requested;
    TEST_ARTIFACT("%s: requested %" PRId64 " s, date saw %" PRId64 " s",
                  offset, requested, skew);
    if (err > MDE_TIME_TOLERANCE_S || err < -MDE_TIME_TOLERANCE_S)
        TEST_VERDICT("The fake clock did not move by the requested offset");

    TEST_STEP("Known-bad control: date must be seen to change");
    CHECK_RC(mde_time_run(&session, NULL, date_argv, MDE_TIME_TIMEOUT_MS,
                          &real));
    CHECK_RC(mde_time_run(&session, &clock, date_argv, MDE_TIME_TIMEOUT_MS,
                          &faked));
    TEST_ARTIFACT("Control: date +%%Y is '%.4s' on the real clock and '%.4s' "
                  "under %s", te_string_value(&real.out),
                  te_string_value(&faked.out), offset);
    ring_compare_runs(&report, "control:date", &real, &faked);
    tsapi_mde_report_expect(&report, "time.behaviour-changes",
                            "control:date");
    tsapi_mde_report_drop_subject(&report, "control:date");

    TEST_STEP("Run the demo on the real clock");
    CHECK_RC(mde_time_run(&session, NULL, run_argv, RING_TIMEOUT_MS, &real));
    if (!mde_time_run_ok(&real))
        TEST_VERDICT("The %s demo fails on the real clock", demo_name);

    TEST_STEP("Run the demo under the fake clock");
    CHECK_RC(mde_time_run(&session, &clock, run_argv, RING_TIMEOUT_MS,
                          &faked));
    RING("Real clock:\n%s\nFake clock (%s):\n%s", te_string_value(&real.out),
         offset, te_string_value(&faked.out));
    TEST_ARTIFACT("%s: trace hash %016" PRIx64 " real, %016" PRIx64
                  " under %s; exit %d / %d; %.3f s / %.3f s", demo_name,
                  mde_time_fnv1a(te_string_value(&real.out)),
                  mde_time_fnv1a(te_string_value(&faked.out)), offset,
                  real.status.value, faked.status.value, real.elapsed_s,
                  faked.elapsed_s);

    TEST_STEP("Compare the two runs");
    ring_compare_runs(&report, subject.ptr, &real, &faked);

    n_real = tsapi_mde_ring_parse(te_string_value(&real.out), &steps_real);
    n_faked = tsapi_mde_ring_parse(te_string_value(&faked.out),
                                   &steps_faked);
    have_real = tsapi_mde_ring_parse_result(te_string_value(&real.out),
                                            &res_real);
    have_faked = tsapi_mde_ring_parse_result(te_string_value(&faked.out),
                                             &res_faked);
    TEST_ARTIFACT("%s: %zu step(s) real, %zu under %s; result %g / %g",
                  demo_name, n_real, n_faked, offset, res_real, res_faked);
    if (n_real == 0)
        TEST_VERDICT("The %s demo printed no stage trace", demo_name);

    if (n_real != n_faked || have_real != have_faked ||
        (have_real && res_real != res_faked))
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
            "time.behaviour-changes", subject.ptr,
            "%zu stage step(s) and result %g on the real clock, %zu and %g "
            "under the fake one", n_real, res_real, n_faked, res_faked);
    }
    for (i = 0; i < n_real && i < n_faked; i++)
    {
        const tsapi_mde_step *r = te_vec_get(&steps_real, i);
        const tsapi_mde_step *f = te_vec_get(&steps_faked, i);

        if (r->stage != f->stage || r->hops != f->hops ||
            r->in != f->in || r->out != f->out)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                "time.behaviour-changes", subject.ptr,
                "step %zu: [%s] hops=%d %g -> %g real, [%s] hops=%d "
                "%g -> %g faked", i, tsapi_mde_stage2str(r->stage), r->hops,
                r->in, r->out, tsapi_mde_stage2str(f->stage), f->hops,
                f->in, f->out);
            break;
        }
    }

    TEST_STEP("Chart both runs");
    if (tsapi_mde_mi_create("time-ring", &logger) == 0)
    {
        for (i = 0; i < n_real || i < n_faked; i++)
        {
            const tsapi_mde_step *r = i < n_real ?
                                      te_vec_get(&steps_real, i) : NULL;
            const tsapi_mde_step *f = i < n_faked ?
                                      te_vec_get(&steps_faked, i) : NULL;

            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "step", TE_MI_MEAS_AGGR_SINGLE, i,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "out_real", TE_MI_MEAS_AGGR_SINGLE,
                                  r != NULL ? r->out : 0.0,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "out_faked", TE_MI_MEAS_AGGR_SINGLE,
                                  f != NULL ? f->out : 0.0,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(logger, NULL, "demo", "%s", demo_name);
        te_mi_logger_add_meas_key(logger, NULL, "offset", "%s", offset);
        tsapi_mde_mi_line(logger, "values",
                          "Stage output per step: real vs fake clock",
                          "step", "out_real", "out_faked", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    times[0] = real.elapsed_s;
    times[1] = faked.elapsed_s;
    counts[0] = n_real;
    counts[1] = n_faked;
    tsapi_mde_mi_bars("time-ring", "Run time: real vs fake clock",
                      TE_MI_MEAS_TIME, "run_time", 2, labels, times,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("time-ring", "Stage steps traced: real vs fake clock",
                      TE_MI_MEAS_UNITLESS_VALUE, "steps", 2, labels, counts,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "time", min_severity);

    TEST_SUCCESS;

cleanup:

    mde_time_run_result_free(&real);
    mde_time_run_result_free(&faked);
    te_vec_free(&steps_real);
    te_vec_free(&steps_faked);
    te_string_free(&program);
    te_string_free(&script);
    te_string_free(&subject);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
