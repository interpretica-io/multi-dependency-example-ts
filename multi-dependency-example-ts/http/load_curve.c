/** @file
 * @brief HTTP Group
 *
 * Drive the entry node of the web tier with a fixed number of GET /ring
 * requests, @c concurrency of them at a time, and draw the curve: latency
 * per request and per batch, and the throughput the tier sustained. Every
 * request must succeed and the tier must still answer afterwards.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "http/load_curve"

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_http.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "http_common.h"

/** Requests per iteration; divisible by every concurrency of package.xml. */
#define LOAD_REQUESTS   48

/** Hop budget of every request. */
#define LOAD_HOPS       5

int
main(int argc, char **argv)
{
    int                     concurrency;
    tsapi_mde_session       session;
    tsapi_mde_dut           dut;
    tsapi_mde_web           web;
    tsapi_mde_report        report;
    tapi_http_request_opt   opt;
    tapi_http_response      resp;
    tsapi_mde_sh_result     sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string               url = TE_STRING_INIT;
    te_string               subject = TE_STRING_INIT;
    te_mi_logger           *logger = NULL;
    double                  lat_ms[LOAD_REQUESTS];
    unsigned int            batch_of[LOAD_REQUESTS];
    double                  batch_mean[LOAD_REQUESTS];
    double                  batch_max[LOAD_REQUESTS];
    unsigned int            batch_n[LOAD_REQUESTS];
    unsigned int            n_batches;
    unsigned int            n_seen = 0;
    unsigned int            n_errors = 0;
    double                  t_start = 0.0;
    double                  t_end = 0.0;
    double                  wall_s;
    double                  engine_s;
    double                  rps;
    double                  mean_ms = 0.0;
    double                  max_ms = 0.0;
    const char             *line;
    bool                    session_up = false;
    bool                    web_up = false;
    unsigned int            i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(concurrency);
    if (concurrency <= 0 || LOAD_REQUESTS % concurrency != 0)
        TEST_FAIL("concurrency must divide %d", LOAD_REQUESTS);
    n_batches = LOAD_REQUESTS / (unsigned int)concurrency;

    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    memset(batch_mean, 0, sizeof(batch_mean));
    memset(batch_max, 0, sizeof(batch_max));
    memset(batch_n, 0, sizeof(batch_n));
    tsapi_mde_report_init(&report);
    te_string_append(&subject, "gateway-rs@c=%d", concurrency);

    tsapi_evo_analysis_hint(
        "48 GET /ring requests to gateway-rs in batches of 'concurrency' "
        "parallel curl processes. Latency should grow with concurrency "
        "while errors stay at zero; any failed request or a tier that "
        "stops answering afterwards is a finding.");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "http_load", dut, session_up);

    if (!tapi_http_available(session.factory, 10000))
        TEST_VERDICT("There is no curl on the agent");
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_VERDICT("The web tier is not built");

    TEST_STEP("Start the web tier and warm it up");
    web_up = true;
    if (tsapi_mde_web_start(&session, &dut, &web) != 0)
        TEST_VERDICT("The web tier did not start");

    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1.0, LOAD_HOPS, &url);
    opt = tapi_http_request_default_opt;
    opt.url = url.ptr;
    CHECK_RC(tapi_http_request(session.factory, &opt, MDE_HTTP_TIMEOUT_MS,
                               &resp));
    if (resp.status != 200)
    {
        tapi_http_response_free(&resp);
        TEST_VERDICT("gateway-rs did not answer the warm-up request with "
                     "200");
    }
    tapi_http_response_free(&resp);

    TEST_STEP("Fire the batches");
    engine_s = tsapi_mde_now();
    CHECK_RC(tsapi_mde_sh(&session, 300000, &sh,
        "echo S $(date +%%s.%%N); b=0; "
        "while [ $b -lt %u ]; do j=0; "
        "while [ $j -lt %d ]; do "
        "curl -s -o /dev/null -m 20 -w \"R $b %%{http_code} "
        "%%{time_total}\\n\" '%s' & j=$((j+1)); done; "
        "wait; b=$((b+1)); done; echo E $(date +%%s.%%N)",
        n_batches, concurrency, url.ptr));
    engine_s = tsapi_mde_now() - engine_s;
    if (!sh.started)
        TEST_FAIL("The load script could not be started");

    TEST_STEP("Parse every request's status and latency");
    for (line = te_string_value(&sh.out); line != NULL && *line != '\0'; )
    {
        unsigned int b;
        unsigned int code;
        double       t;
        const char  *eol = strchr(line, '\n');

        if (sscanf(line, "R %u %u %lf", &b, &code, &t) == 3)
        {
            if (n_seen < LOAD_REQUESTS && b < n_batches)
            {
                lat_ms[n_seen] = t * 1000.0;
                batch_of[n_seen] = b;
                batch_mean[b] += t * 1000.0;
                batch_n[b]++;
                if (t * 1000.0 > batch_max[b])
                    batch_max[b] = t * 1000.0;
                mean_ms += t * 1000.0;
                if (t * 1000.0 > max_ms)
                    max_ms = t * 1000.0;
                n_seen++;
            }
            if (code != 200)
                n_errors++;
        }
        else if (sscanf(line, "S %lf", &t) == 1)
        {
            t_start = t;
        }
        else if (sscanf(line, "E %lf", &t) == 1)
        {
            t_end = t;
        }

        line = (eol != NULL) ? eol + 1 : NULL;
    }

    for (i = 0; i < n_batches; i++)
    {
        if (batch_n[i] > 0)
            batch_mean[i] /= batch_n[i];
    }
    if (n_seen > 0)
        mean_ms /= n_seen;

    wall_s = (t_end > t_start && t_start > 0.0) ? t_end - t_start : engine_s;
    rps = wall_s > 0.0 ? n_seen / wall_s : 0.0;

    TEST_ARTIFACT("c=%d: %u/%d request(s) reported, %u error(s), "
                  "%.1f req/s over %.3f s, latency mean %.1f ms max %.1f ms",
                  concurrency, n_seen, LOAD_REQUESTS, n_errors, rps, wall_s,
                  mean_ms, max_ms);

    TEST_STEP("Every request must be accounted for and succeed");
    if (n_seen != LOAD_REQUESTS)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
            "http.load-lost", subject.ptr,
            "%u of %d request(s) reported back", n_seen, LOAD_REQUESTS);
    }
    if (n_errors > 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
            "http.load-errors", subject.ptr,
            "%u request(s) did not get 200 under %d parallel client(s)",
            n_errors, concurrency);
    }

    TEST_STEP("The tier must still answer after the load");
    if (tapi_http_request(session.factory, &opt, MDE_HTTP_TIMEOUT_MS,
                          &resp) != 0)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_CRITICAL,
            "http.load-crash", subject.ptr,
            "gateway-rs stopped answering after the load");
    }
    else
    {
        unsigned int nodes = mde_http_count_nodes(
                                    te_string_value(&resp.body));

        TEST_ARTIFACT("After the load: status %u, %u node line(s) for "
                      "hops=%d", resp.status, nodes, LOAD_HOPS);
        if (resp.status != 200)
        {
            tapi_cybersec_report_add(&report.cyber,
                TAPI_CYBERSEC_SEV_CRITICAL, "http.load-crash", subject.ptr,
                "gateway-rs answers %u after the load", resp.status);
        }
        tapi_http_response_free(&resp);
    }

    TEST_STEP("Chart the curve");
    if (tsapi_mde_mi_create("http-load", &logger) == 0)
    {
        for (i = 0; i < n_seen; i++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "request", TE_MI_MEAS_AGGR_SINGLE, i,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "latency", TE_MI_MEAS_AGGR_SINGLE,
                                  lat_ms[i], TE_MI_MEAS_MULTIPLIER_MILLI);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "batch", TE_MI_MEAS_AGGR_SINGLE,
                                  batch_of[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(logger, NULL, "concurrency", "%d",
                                  concurrency);
        tsapi_mde_mi_line(logger, "latency", "Latency per request",
                          "request", "latency", NULL);
        tsapi_mde_mi_line(logger, "batch_of", "Batch of each request",
                          "request", "batch", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    if (tsapi_mde_mi_create("http-load", &logger) == 0)
    {
        for (i = 0; i < n_batches; i++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "batch_index", TE_MI_MEAS_AGGR_SINGLE, i,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "batch_mean", TE_MI_MEAS_AGGR_SINGLE,
                                  batch_mean[i], TE_MI_MEAS_MULTIPLIER_MILLI);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "batch_max", TE_MI_MEAS_AGGR_SINGLE,
                                  batch_max[i], TE_MI_MEAS_MULTIPLIER_MILLI);
        }
        te_mi_logger_add_meas_key(logger, NULL, "concurrency", "%d",
                                  concurrency);
        tsapi_mde_mi_line(logger, "batches",
                          "Latency mean and max per batch", "batch_index",
                          "batch_mean", "batch_max", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    tsapi_mde_mi_point("http-load", "Throughput (requests per second)",
                       TE_MI_MEAS_RPS, "rps", rps,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("http-load", "Failed requests",
                       TE_MI_MEAS_UNITLESS_VALUE, "errors", n_errors,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_point("http-load", "Mean latency", TE_MI_MEAS_LATENCY,
                       "mean_latency", mean_ms, TE_MI_MEAS_MULTIPLIER_MILLI);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "http", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    if (web_up)
        tsapi_mde_web_stop(&web);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&url);
    te_string_free(&subject);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
