/** @file
 * @brief Web Group
 *
 * Throw malformed requests at one service of the web tier - a missing
 * value, a negative and a huge hop budget, a NaN, a garbage number, an
 * 8 KiB query, an unknown path, HEAD and POST - and require a well-formed
 * HTTP status for each. After every case the service must still be running
 * and still answer a normal request.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/robustness"

#include "web_common.h"

/** Size of the padding of the long-query case. */
#define ROB_LONG_PAD    8192

/** One malformed request. */
typedef struct rob_case {
    const char *name;   /**< Stable name (subjects, chart labels). */
    const char *opts;   /**< Extra curl options. */
    const char *target; /**< Path and query; NULL for the long query. */
} rob_case;

static const rob_case rob_cases[] = {
    { "missing-value",  "",               "/ring?hops=0" },
    { "negative-hops",  "",               "/ring?value=1&hops=-1" },
    { "huge-hops",      "",               "/ring?value=1&hops=1000" },
    { "nan-value",      "",               "/ring?value=NaN&hops=0" },
    { "garbage-hops",   "",               "/ring?value=1&hops=abc" },
    { "long-query",     "",               NULL },
    { "unknown-path",   "",               "/no/such/path" },
    { "head",           "-I",             "/ring?value=1&hops=0" },
    { "post",           "-X POST -d x=1", "/ring?value=1&hops=0" },
};

#define ROB_N   TE_ARRAY_LEN(rob_cases)

/** Mapping of the @c service parameter to the index in the tier. */
#define ROB_SERVICE_LIST \
    { "gateway-rs", 0 }, \
    { "service-go", 1 }, \
    { "service-cs", 2 }

/**
 * Judge one answer: no status line at all is @c web.no-status; a 5xx is
 * @c web.server-error (well-formed, but the input was not handled).
 */
static void
rob_judge(tapi_cybersec_report *cyber, const char *subject,
          const web_reply *reply)
{
    if (!reply->ran || reply->code < 100 || reply->code > 599)
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "web.no-status", subject,
                                 "no well-formed HTTP status (got %d)",
                                 reply->code);
    }
    else if (reply->code >= 500)
    {
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "web.server-error", subject, "HTTP %d",
                                 reply->code);
    }
}

int
main(int argc, char **argv)
{
    int                service;
    tsapi_mde_session  session;
    bool               session_up = false;
    tsapi_mde_dut      dut = { .root = NULL };
    tsapi_mde_report   report;
    bool               report_up = false;
    tsapi_mde_web      web;
    bool               web_up = false;
    web_reply          reply = WEB_REPLY_INIT;
    web_trace          trace = WEB_TRACE_INIT;
    te_string          url = TE_STRING_INIT;
    te_string          probe = TE_STRING_INIT;
    tsapi_mde_web_service *svc;
    double             codes[ROB_N];
    double             times_ms[ROB_N];
    const char        *labels[ROB_N];
    unsigned int       n_done = 0;
    bool               dead = false;
    const char        *why;
    char               subject[96];
    char               expect_line[64];
    size_t             i;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(service, ROB_SERVICE_LIST);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "robustness", dut, session_up);

    TEST_STEP("Skip unless the services and curl can be run");
    why = web_unavailable(&session, &dut);
    if (why != NULL)
        TEST_VERDICT("%s", why);

    TEST_STEP("Known-bad control: a port nothing listens on must give "
              "web.no-status");
    CHECK_RC(web_get(&session, "", "http://127.0.0.1:1/ring", 5, &reply));
    rob_judge(&report.cyber, "control/closed-port", &reply);
    tsapi_mde_report_expect(&report, "web.no-status", "control/closed-port");
    web_report_drop_prefix(&report, "control/");

    TEST_STEP("Start the three HTTP services");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    web_chart_start(&web);
    svc = &web.svc[service];

    te_string_append(&probe, "http://127.0.0.1:%u/ring?value=1&hops=0",
                     svc->port);
    TE_SPRINTF(expect_line, "[%s] hops=0", svc->name);

    for (i = 0; i < ROB_N; i++)
    {
        const rob_case *c = &rob_cases[i];
        te_errno        wrc;

        TEST_STEP("Case %s against %s", c->name, svc->name);
        labels[i] = c->name;
        codes[i] = 0;
        times_ms[i] = 0;
        TE_SPRINTF(subject, "%s/%s", svc->name, c->name);

        te_string_reset(&url);
        te_string_append(&url, "http://127.0.0.1:%u", svc->port);
        if (c->target != NULL)
        {
            te_string_append(&url, "%s", c->target);
        }
        else
        {
            unsigned int k;

            te_string_append(&url, "/ring?value=1&hops=0&pad=");
            for (k = 0; k < ROB_LONG_PAD; k++)
                te_string_append(&url, "A");
        }

        CHECK_RC(web_get(&session, c->opts, url.ptr, 20, &reply));
        rob_judge(&report.cyber, subject, &reply);
        codes[i] = reply.code;
        times_ms[i] = reply.time_s * 1000.0;
        n_done++;
        TEST_ARTIFACT("%s %s: HTTP %d in %.2f ms", svc->name, c->name,
                      reply.code, times_ms[i]);

        /* Still running? */
        wrc = tapi_job_wait(svc->job, 0, NULL);
        if (TE_RC_GET_ERROR(wrc) != TE_EINPROGRESS)
        {
            tapi_cybersec_report_add(&report.cyber,
                                     TAPI_CYBERSEC_SEV_CRITICAL, "web.crash",
                                     subject, "the process is gone");
            dead = true;
            break;
        }

        /* Still serving? */
        CHECK_RC(web_get(&session, "", probe.ptr, 15, &reply));
        web_trace_parse(web_str(&reply.body), &trace);
        if (reply.code != 200 ||
            strstr(web_str(&reply.body), expect_line) == NULL ||
            !trace.have_value)
        {
            tapi_cybersec_report_add(&report.cyber,
                                     TAPI_CYBERSEC_SEV_CRITICAL, "web.crash",
                                     subject, "still running but a normal "
                                     "request now gets HTTP %d", reply.code);
            dead = true;
            break;
        }
    }

    TEST_STEP("Chart the status code and time per case");
    tsapi_mde_mi_bars("web", "HTTP status per malformed request",
                      TE_MI_MEAS_UNITLESS_VALUE, "status", n_done, labels,
                      codes, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("web", "Answer time per malformed request",
                      TE_MI_MEAS_LATENCY, "answer", n_done, labels, times_ms,
                      TE_MI_MEAS_MULTIPLIER_MILLI);
    TEST_ARTIFACT("%s: %u of %zu case(s) run, service %s", svc->name, n_done,
                  ROB_N, dead ? "died or stopped serving" : "alive");

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "web", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    if (web_up)
        tsapi_mde_web_stop(&web);
    te_string_free(&url);
    te_string_free(&probe);
    te_string_free(&reply.body);
    web_trace_free(&trace);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
