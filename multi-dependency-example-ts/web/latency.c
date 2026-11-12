/** @file
 * @brief Web Group
 *
 * Start the web tier once and send K requests per hop budget (0..6) to the
 * gateway, timing each one with curl. Every answer must be HTTP 200 with a
 * non-empty body, under a generous latency bound. Mean, median and maximum
 * latency are charted per hop budget, with the start-up time of each
 * service.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/latency"

#include "web_common.h"

/** Highest hop budget measured. */
#define LAT_MAX_HOPS    6
/** Points measured. */
#define LAT_N           (LAT_MAX_HOPS + 1)

/** One batch of requests to the same URL. */
typedef struct lat_batch {
    unsigned int n;         /**< Requests answered with a status line. */
    unsigned int n_ok;      /**< HTTP 200. */
    unsigned int n_empty;   /**< HTTP 200 with an empty body. */
    unsigned int n_slow;    /**< Over the bound. */
    int          bad_code;  /**< First status other than 200. */
    double      *ms;        /**< Latency of each request. */
} lat_batch;

static int
lat_cmp(const void *a, const void *b)
{
    double x = *(const double *)a;
    double y = *(const double *)b;

    return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * Send @p k requests in one shell loop on the agent and collect status,
 * time and size of each.
 */
static te_errno
lat_run(tsapi_mde_session *session, const char *url, unsigned int k,
        double max_ms, lat_batch *batch)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    const char         *line;
    te_errno            rc;

    batch->n = batch->n_ok = batch->n_empty = batch->n_slow = 0;
    batch->bad_code = 200;

    rc = tsapi_mde_sh(session, (int)k * 15000 + 10000, &res,
                      "i=0; while [ $i -lt %u ]; do i=$((i + 1)); "
                      "curl -s -o /dev/null --max-time 10 "
                      "-w '%%{http_code} %%{time_total} %%{size_download}\\n' "
                      "'%s'; done", k, url);
    if (rc != 0)
    {
        tsapi_mde_sh_result_free(&res);
        return rc;
    }

    for (line = res.out.ptr; line != NULL && *line != '\0'; )
    {
        const char *eol = strchr(line, '\n');
        int         code;
        double      t;
        long        size;

        if (sscanf(line, "%d %lf %ld", &code, &t, &size) == 3 &&
            batch->n < k)
        {
            batch->ms[batch->n++] = t * 1000.0;
            if (code == 200)
            {
                batch->n_ok++;
                if (size <= 0)
                    batch->n_empty++;
            }
            else if (batch->bad_code == 200)
            {
                batch->bad_code = code;
            }
            if (t * 1000.0 > max_ms)
                batch->n_slow++;
        }
        line = eol != NULL ? eol + 1 : NULL;
    }

    tsapi_mde_sh_result_free(&res);
    return 0;
}

/** Turn a batch into findings about @p subject. */
static void
lat_check(tapi_cybersec_report *cyber, const char *subject,
          const lat_batch *batch, unsigned int k, double max_ms)
{
    if (batch->n != k)
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "web.lost-request", subject,
                                 "%u of %u request(s) left no status line",
                                 k - batch->n, k);
    }
    if (batch->n_ok != batch->n)
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "web.status", subject,
                                 "%u of %u answer(s) not HTTP 200 (first: "
                                 "%d)", batch->n - batch->n_ok, batch->n,
                                 batch->bad_code);
    }
    if (batch->n_empty > 0)
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "web.empty-body", subject,
                                 "%u answer(s) with an empty body",
                                 batch->n_empty);
    }
    if (batch->n_slow > 0)
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "web.latency", subject,
                                 "%u answer(s) slower than %.0f ms",
                                 batch->n_slow, max_ms);
    }
}

int
main(int argc, char **argv)
{
    unsigned int       requests;
    double             max_ms;
    tsapi_mde_session  session;
    bool               session_up = false;
    tsapi_mde_dut      dut = { .root = NULL };
    tsapi_mde_report   report;
    bool               report_up = false;
    tsapi_mde_web      web;
    bool               web_up = false;
    lat_batch          batch = { .ms = NULL };
    te_string          url = TE_STRING_INIT;
    double             mean_ms[LAT_N];
    double             p50_ms[LAT_N];
    double             top_ms[LAT_N];
    double            *all_ms = NULL;
    size_t             n_all = 0;
    const char        *why;
    te_mi_logger      *logger = NULL;
    char               subject[32];
    int                h;
    unsigned int       i;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_UINT_PARAM(requests);
    TEST_GET_DOUBLE_PARAM(max_ms);
    if (requests == 0)
        TEST_FAIL("requests must be positive");
    batch.ms = calloc(requests, sizeof(*batch.ms));
    all_ms = calloc((size_t)requests * LAT_N, sizeof(*all_ms));
    if (batch.ms == NULL || all_ms == NULL)
        TEST_FAIL("Out of memory");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "latency", dut, session_up);

    TEST_STEP("Skip unless the services and curl can be run");
    why = web_unavailable(&session, &dut);
    if (why != NULL)
        TEST_VERDICT("%s", why);

    TEST_STEP("Start the three HTTP services");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    web_chart_start(&web);

    TEST_STEP("Known-bad control: a port nothing listens on must give "
              "web.status");
    CHECK_RC(lat_run(&session, "http://127.0.0.1:1/ring?value=1&hops=0", 1,
                     max_ms, &batch));
    lat_check(&report.cyber, "control/closed-port", &batch, 1, max_ms);
    tsapi_mde_report_expect(&report, "web.status", "control/closed-port");
    web_report_drop_prefix(&report, "control/");

    for (h = 0; h <= LAT_MAX_HOPS; h++)
    {
        double sum = 0;

        TEST_STEP("Send %u request(s) with hops=%d", requests, h);
        te_string_reset(&url);
        tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1.0, h, &url);
        CHECK_RC(lat_run(&session, url.ptr, requests, max_ms, &batch));

        TE_SPRINTF(subject, "gateway-rs/hops=%d", h);
        lat_check(&report.cyber, subject, &batch, requests, max_ms);

        for (i = 0; i < batch.n; i++)
        {
            sum += batch.ms[i];
            all_ms[n_all++] = batch.ms[i];
        }
        qsort(batch.ms, batch.n, sizeof(*batch.ms), lat_cmp);
        mean_ms[h] = batch.n > 0 ? sum / batch.n : 0;
        p50_ms[h] = batch.n > 0 ? batch.ms[batch.n / 2] : 0;
        top_ms[h] = batch.n > 0 ? batch.ms[batch.n - 1] : 0;

        TEST_ARTIFACT("hops=%d: %u/%u answered 200, mean %.2f ms, p50 %.2f "
                      "ms, max %.2f ms", h, batch.n_ok, requests, mean_ms[h],
                      p50_ms[h], top_ms[h]);
    }

    TEST_STEP("Chart latency per hop budget");
    if (tsapi_mde_mi_create("web", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "requests", "%u", requests);
        te_mi_logger_add_meas_key(logger, NULL, "max_ms", "%.0f", max_ms);
        for (h = 0; h <= LAT_MAX_HOPS; h++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "hops", TE_MI_MEAS_AGGR_SINGLE, h,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "mean", TE_MI_MEAS_AGGR_SINGLE, mean_ms[h],
                                  TE_MI_MEAS_MULTIPLIER_MILLI);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "p50", TE_MI_MEAS_AGGR_SINGLE, p50_ms[h],
                                  TE_MI_MEAS_MULTIPLIER_MILLI);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "max", TE_MI_MEAS_AGGR_SINGLE, top_ms[h],
                                  TE_MI_MEAS_MULTIPLIER_MILLI);
        }
        tsapi_mde_mi_line(logger, "latency", "Gateway latency per hop budget",
                          "hops", "mean", "p50", "max", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    tsapi_mde_mi_series("web", "Latency of every request, in order",
                        TE_MI_MEAS_LATENCY, "request", n_all, all_ms,
                        TE_MI_MEAS_MULTIPLIER_MILLI);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "web", TAPI_CYBERSEC_SEV_MEDIUM);

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    if (web_up)
        tsapi_mde_web_stop(&web);
    free(batch.ms);
    free(all_ms);
    te_string_free(&url);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
