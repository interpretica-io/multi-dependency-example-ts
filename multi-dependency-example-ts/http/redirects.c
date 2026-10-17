/** @file
 * @brief HTTP Group
 *
 * Ask one node of the web tier for paths it does not serve and follow
 * whatever it answers. A service that answers 200 to any path (a
 * catch-all) hides typos and probes alike; one that redirects off-host is
 * an open redirect. The redirect machinery of tapi_http is first checked
 * against an endpoint that is known to redirect and to catch everything.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "http/redirects"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_http.h"
#include "tapi_http_server.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "http_common.h"

/** Port of the control endpoint. */
#define REDIRECTS_CTRL_PORT 34512

/** A path nothing should serve. */
#define REDIRECTS_GARBAGE   "/mde-no-such-path-7f3a9c"

/** What one probe asks and whether a 2xx answer is a catch-all. */
typedef struct redirects_probe {
    const char *label;      /**< Chart label. */
    const char *path;       /**< Path and query. */
    bool        must_miss;  /**< 2xx here means a catch-all. */
} redirects_probe;

static const redirects_probe redirects_probes[] = {
    { "ring",      "/ring?value=1&hops=0",  false },
    { "garbage",   REDIRECTS_GARBAGE,       true },
    { "root",      "/",                     true },
    { "subpath",   "/ring/extra",           true },
    { "dotfile",   "/.env",                 true },
    { "uppercase", "/RING?value=1&hops=0",  false },
};

#define REDIRECTS_N TE_ARRAY_LEN(redirects_probes)

/** What one probe got. */
typedef struct redirects_result {
    unsigned int status;    /**< Final status, 0 if nothing answered. */
    size_t       n_chain;   /**< Responses including redirects. */
    double       time_ms;   /**< Time of the request. */
} redirects_result;

/**
 * Request @p base + @p path following redirects, record what came back
 * and check that the chain tapi_http reports is self-consistent.
 */
static void
redirects_ask(tsapi_mde_session *session, const char *base, const char *path,
              tsapi_mde_report *report, const char *who,
              redirects_result *out)
{
    tapi_http_request_opt opt = tapi_http_request_default_opt;
    tapi_http_response    resp;
    te_string             url = TE_STRING_INIT;
    double                t0;

    memset(out, 0, sizeof(*out));
    te_string_append(&url, "%s%s", base, path);
    opt.url = url.ptr;
    opt.follow = true;
    opt.max_redirects = 5;

    t0 = tsapi_mde_now();
    if (tapi_http_request(session->factory, &opt, MDE_HTTP_TIMEOUT_MS,
                          &resp) != 0)
    {
        out->time_ms = (tsapi_mde_now() - t0) * 1000.0;
        RING("%s%s: nothing answered", base, path);
        te_string_free(&url);
        return;
    }
    out->time_ms = (tsapi_mde_now() - t0) * 1000.0;
    out->status = resp.status;
    out->n_chain = resp.n_chain;

    tapi_http_response_log(&resp);

    if (resp.n_chain == 0 || resp.chain[resp.n_chain - 1] != resp.status)
    {
        TEST_VERDICT("The redirect chain does not end at the final status");
    }

    /* Redirected somewhere that is not the host that was asked. */
    if (resp.n_chain > 1 && resp.final_url != NULL &&
        strncmp(resp.final_url, base, strlen(base)) != 0)
    {
        te_string subject = TE_STRING_INIT;

        te_string_append(&subject, "%s:%s", who, path);
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
            "http.open-redirect", subject.ptr,
            "%s redirected off-host to %s", path, resp.final_url);
        te_string_free(&subject);
    }

    tapi_http_response_free(&resp);
    te_string_free(&url);
}

/** Report a catch-all if a path nobody serves answered with success. */
static void
redirects_catch_all(tsapi_mde_report *report, const char *who,
                    const char *path, unsigned int status)
{
    te_string subject = TE_STRING_INIT;

    if (status < 200 || status >= 300)
        return;

    te_string_append(&subject, "%s:%s", who, path);
    tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
        "http.catch-all", subject.ptr,
        "%s answered %u for a path it does not serve, so a typo, a probe "
        "and a real request all look alike", path, status);
    te_string_free(&subject);
}

int
main(int argc, char **argv)
{
    mde_http_service        service;
    tapi_cybersec_severity  min_severity;
    tsapi_mde_session       session;
    tsapi_mde_dut           dut;
    tsapi_mde_web           web;
    tsapi_mde_report        report;
    tapi_http_server_opt    server_opt;
    tapi_http_server       *server = NULL;
    tapi_http_request_opt   opt;
    tapi_http_response      resp;
    redirects_result        res[REDIRECTS_N];
    redirects_result        ctrl_res;
    te_string               base = TE_STRING_INIT;
    te_string               url = TE_STRING_INIT;
    te_string               ctrl_subject = TE_STRING_INIT;
    const char             *labels[REDIRECTS_N];
    double                  status[REDIRECTS_N];
    double                  chain[REDIRECTS_N];
    double                  time_ms[REDIRECTS_N];
    const char             *name;
    unsigned int            port;
    bool                    session_up = false;
    bool                    web_up = false;
    bool                    resp_up = false;
    size_t                  i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(service, MDE_HTTP_SERVICE_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);
    name = mde_http_service_name(service);
    port = mde_http_service_port(service);

    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    tsapi_mde_report_init(&report);

    tsapi_evo_analysis_hint(
        "Unknown paths must be 404 and nothing should redirect off-host. "
        "The control endpoint answers 200 to every path and redirects "
        "/redirect, so http.catch-all must fire on it and its redirect "
        "chain must read 302 -> 200.");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "http_redirects", dut, session_up);

    if (!tapi_http_available(session.factory, 10000))
        TEST_SKIP("There is no curl on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("There is no python3 on the agent for the control endpoint");
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built");

    TEST_STEP("Control: the redirect machinery on an endpoint that "
              "redirects");
    server_opt = tapi_http_server_default_opt;
    server_opt.port = REDIRECTS_CTRL_PORT;
    CHECK_RC(tapi_http_server_start(session.factory, &server_opt,
                                    MDE_HTTP_TIMEOUT_MS, &server));

    te_string_append(&url, "%s/redirect", tapi_http_server_url(server));
    opt = tapi_http_request_default_opt;
    opt.url = url.ptr;
    opt.follow = true;
    CHECK_RC(tapi_http_request(session.factory, &opt, MDE_HTTP_TIMEOUT_MS,
                               &resp));
    resp_up = true;
    tapi_http_response_log(&resp);
    if (resp.status != 200 || resp.n_chain != 2 || resp.chain[0] != 302)
        TEST_VERDICT("The control redirect was not reported as 302 -> 200");
    tapi_http_response_free(&resp);
    resp_up = false;

    opt.follow = false;
    CHECK_RC(tapi_http_request(session.factory, &opt, MDE_HTTP_TIMEOUT_MS,
                               &resp));
    resp_up = true;
    if (resp.status != 302 || tapi_http_header(&resp, "Location") == NULL)
        TEST_VERDICT("Without following, the control redirect is not a 302 "
                     "with a Location");
    TEST_ARTIFACT("Control redirect: 302 -> Location %s",
                  tapi_http_header(&resp, "Location"));
    tapi_http_response_free(&resp);
    resp_up = false;

    TEST_STEP("Known-bad control: a catch-all endpoint must be reported");
    redirects_ask(&session, tapi_http_server_url(server), REDIRECTS_GARBAGE,
                  &report, "control", &ctrl_res);
    redirects_catch_all(&report, "control", REDIRECTS_GARBAGE,
                        ctrl_res.status);
    te_string_append(&ctrl_subject, "control:%s", REDIRECTS_GARBAGE);
    tsapi_mde_report_expect(&report, "http.catch-all", ctrl_subject.ptr);
    tsapi_mde_report_drop_subject(&report, ctrl_subject.ptr);

    CHECK_RC(tapi_http_server_stop(server));
    server = NULL;

    TEST_STEP("Start the web tier");
    web_up = true;
    if (tsapi_mde_web_start(&session, &dut, &web) != 0)
        TEST_VERDICT("The web tier did not start");

    TEST_STEP("Ask the node for paths it serves and paths it does not");
    te_string_append(&base, "http://127.0.0.1:%u", port);
    for (i = 0; i < REDIRECTS_N; i++)
    {
        redirects_ask(&session, base.ptr, redirects_probes[i].path, &report,
                      name, &res[i]);
        labels[i] = redirects_probes[i].label;
        status[i] = res[i].status;
        chain[i] = res[i].n_chain;
        time_ms[i] = res[i].time_ms;

        TEST_ARTIFACT("%s %s -> %u (%zu response(s) in the chain)", name,
                      redirects_probes[i].path, res[i].status,
                      res[i].n_chain);

        if (redirects_probes[i].must_miss)
            redirects_catch_all(&report, name, redirects_probes[i].path,
                                res[i].status);
    }

    TEST_STEP("The served path must be served");
    if (res[0].status != 200)
        TEST_VERDICT("%s answered GET /ring with %u, expected 200", name,
                     res[0].status);
    if (res[1].status != 404)
    {
        RING("%s answers an unknown path with %u rather than 404", name,
             res[1].status);
    }

    TEST_STEP("Chart the answers");
    tsapi_mde_mi_bars("http-redirects", "Status per probed path",
                      TE_MI_MEAS_UNITLESS_VALUE, "status", REDIRECTS_N,
                      labels, status, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("http-redirects", "Responses in the redirect chain",
                      TE_MI_MEAS_UNITLESS_VALUE, "chain", REDIRECTS_N,
                      labels, chain, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("http-redirects", "Response time per probed path",
                      TE_MI_MEAS_LATENCY, "response_time", REDIRECTS_N,
                      labels, time_ms, TE_MI_MEAS_MULTIPLIER_MILLI);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "http", min_severity);

    TEST_SUCCESS;

cleanup:

    if (resp_up)
        tapi_http_response_free(&resp);
    if (server != NULL)
        CLEANUP_CHECK_RC(tapi_http_server_stop(server));
    if (web_up)
        tsapi_mde_web_stop(&web);
    te_string_free(&base);
    te_string_free(&url);
    te_string_free(&ctrl_subject);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
