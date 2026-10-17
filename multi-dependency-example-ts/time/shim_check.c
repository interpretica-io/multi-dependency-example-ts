/** @file
 * @brief Time Group
 *
 * Prove the fake clock works before any other test of the group trusts
 * it: for a sweep of offsets, a run of `date +%s` under the shim must
 * differ from the real clock by the requested offset, within a few
 * seconds. Two ways of loading the shim are covered: the environment
 * built by tapi_time_env() (through tapi_time_check()) and the faketime
 * program in front of the job (tapi_time_wrap()). A shim that cannot load
 * (a library path that does not exist) is the known-bad control: the
 * check must notice that the clock did not move.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "time/shim_check"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_time.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "time_common.h"

/** How the shim is put into the process. */
typedef enum shim_method {
    SHIM_ENV,   /**< tapi_time_env() through tapi_time_check(). */
    SHIM_WRAP,  /**< tapi_time_wrap(): faketime in front of the job. */
} shim_method;

#define SHIM_METHOD_LIST \
    { "env",  SHIM_ENV }, \
    { "wrap", SHIM_WRAP }

/** The offsets swept. */
static const char *const shim_offsets[] = {
    "-1y", "-1d", "+0", "+1d", "+10y",
};

#define SHIM_N_OFFSETS  TE_ARRAY_LEN(shim_offsets)

/** Add a finding if the observed skew is not the requested one. */
static void
shim_judge(tsapi_mde_report *report, const char *subject, int64_t requested,
           int64_t observed)
{
    int64_t error = observed - requested;

    if (error < 0)
        error = -error;

    if (error > MDE_TIME_TOLERANCE_S)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
            "time.shim-not-effective", subject,
            "asked for a skew of %" PRId64 " s, the program saw %" PRId64
            " s", requested, observed);
    }
}

/** Measure the skew a program sees under @p clock with the wrapper. */
static te_errno
shim_skew_wrap(tsapi_mde_session *session, const tapi_time_opt *clock,
               int64_t *skew)
{
    mde_time_run_result res = MDE_TIME_RUN_RESULT_INIT;
    const char         *argv[] = { "date", "+%s", NULL };
    int64_t             before = 0;
    int64_t             after = 0;
    long long           faked;
    char               *end = NULL;
    te_errno            rc;

    rc = tapi_time_now(session->factory, MDE_TIME_TIMEOUT_MS, &before);
    if (rc == 0)
        rc = mde_time_run(session, clock, argv, MDE_TIME_TIMEOUT_MS, &res);
    if (rc == 0)
        rc = tapi_time_now(session->factory, MDE_TIME_TIMEOUT_MS, &after);
    if (rc == 0)
    {
        faked = strtoll(te_string_value(&res.out), &end, 10);
        if (!mde_time_run_ok(&res) || end == te_string_value(&res.out))
        {
            ERROR("date under faketime printed '%s' / '%s'",
                  te_string_value(&res.out), te_string_value(&res.err));
            rc = TE_RC(TE_TAPI, TE_EFAIL);
        }
        else
        {
            /* The run happened between the two reads of the real clock. */
            *skew = (int64_t)faked - (before + after) / 2;
        }
    }

    mde_time_run_result_free(&res);

    return rc;
}

int
main(int argc, char **argv)
{
    shim_method         method;
    tsapi_mde_session   session;
    tsapi_mde_report    report;
    tapi_time_opt       clock;
    te_string           subject = TE_STRING_INIT;
    te_mi_logger       *logger = NULL;
    double              req_days[SHIM_N_OFFSETS];
    double              obs_days[SHIM_N_OFFSETS];
    double              err_s[SHIM_N_OFFSETS];
    int64_t             requested = 0;
    int64_t             observed = 0;
    bool                session_up = false;
    unsigned int        i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(method, SHIM_METHOD_LIST);
    tsapi_mde_report_init(&report);

    tsapi_evo_analysis_hint(
        "date +%s under the fake clock vs the real clock, for offsets from "
        "-1y to +10y. Observed and requested days must be the same line; "
        "the error stays within a few seconds. The missing-library control "
        "must be reported as time.shim-not-effective.");

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "time_shim"));
    session_up = true;

    if (!tapi_time_available(session.factory, MDE_TIME_TIMEOUT_MS))
        TEST_SKIP("libfaketime is not installed on the agent");
    if (method == SHIM_WRAP && !tsapi_mde_have(&session, "faketime"))
        TEST_SKIP("The faketime program is not installed on the agent");

    TEST_STEP("Known-bad control: a shim that cannot load must be noticed");
    clock = tapi_time_default_opt;
    clock.offset = "+1d";
    clock.library = "/nonexistent/mde/libfaketime.so.1";
    CHECK_RC(tapi_time_check(session.factory, &clock, MDE_TIME_TIMEOUT_MS,
                             &observed));
    TEST_ARTIFACT("Control (missing library): +1d requested, %" PRId64
                  " s observed", observed);
    shim_judge(&report, "control:missing-library", 86400, observed);
    tsapi_mde_report_expect(&report, "time.shim-not-effective",
                            "control:missing-library");
    tsapi_mde_report_drop_subject(&report, "control:missing-library");

    TEST_STEP("Sweep the offsets");
    for (i = 0; i < SHIM_N_OFFSETS; i++)
    {
        if (!mde_time_offset_seconds(shim_offsets[i], &requested))
            TEST_FAIL("Cannot parse offset %s", shim_offsets[i]);

        clock = tapi_time_default_opt;
        clock.offset = shim_offsets[i];

        if (method == SHIM_ENV)
        {
            CHECK_RC(tapi_time_check(session.factory, &clock,
                                     MDE_TIME_TIMEOUT_MS, &observed));
        }
        else
        {
            CHECK_RC(shim_skew_wrap(&session, &clock, &observed));
        }

        req_days[i] = requested / 86400.0;
        obs_days[i] = observed / 86400.0;
        err_s[i] = (double)(observed - requested);
        TEST_ARTIFACT("%s: requested %" PRId64 " s, observed %" PRId64
                      " s, error %.0f s", shim_offsets[i], requested,
                      observed, err_s[i]);

        te_string_reset(&subject);
        te_string_append(&subject, "offset:%s", shim_offsets[i]);
        shim_judge(&report, subject.ptr, requested, observed);
    }

    TEST_STEP("Chart requested vs observed");
    if (tsapi_mde_mi_create("time-shim", &logger) == 0)
    {
        for (i = 0; i < SHIM_N_OFFSETS; i++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "requested_days", TE_MI_MEAS_AGGR_SINGLE,
                                  req_days[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "observed_days", TE_MI_MEAS_AGGR_SINGLE,
                                  obs_days[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_TIME,
                                  "error", TE_MI_MEAS_AGGR_SINGLE, err_s[i],
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(logger, NULL, "method", "%s",
                                  method == SHIM_ENV ? "env" : "wrap");
        tsapi_mde_mi_line(logger, "skew",
                          "Observed vs requested clock offset, days",
                          "requested_days", "observed_days",
                          "requested_days", NULL);
        tsapi_mde_mi_line(logger, "error",
                          "Observed minus requested offset, seconds",
                          "requested_days", "error", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "time", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    te_string_free(&subject);
    tsapi_mde_report_free(&report);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
