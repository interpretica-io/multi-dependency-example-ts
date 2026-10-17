/** @file
 * @brief HTTP Group
 *
 * Ask one node of the web tier for GET /ring and read the response as a
 * security posture (tapi_http_headers_check) and as a contract: status,
 * content type, a Content-Length that matches the body, and a body that
 * traces hops+1 node steps. A deliberately bare endpoint is audited first
 * so that a blind header check cannot pass for a clean service.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "http/headers"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_http.h"
#include "tapi_http_headers.h"
#include "tapi_http_server.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "http_common.h"

/** Port of the known-bad endpoint. */
#define HEADERS_CTRL_PORT   34510

/** The hop budgets swept; the last one is the audited request. */
#define HEADERS_MAX_HOPS    5

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
    tsapi_mde_sh_result     sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string               url = TE_STRING_INIT;
    te_string               ctrl_url = TE_STRING_INIT;
    te_string               subject = TE_STRING_INIT;
    te_mi_logger           *logger = NULL;
    const char             *name;
    unsigned int            port;
    bool                    session_up = false;
    bool                    web_up = false;
    bool                    resp_up = false;
    double                  time_ms[HEADERS_MAX_HOPS + 1];
    double                  n_headers[HEADERS_MAX_HOPS + 1];
    double                  body_len[HEADERS_MAX_HOPS + 1];
    double                  nodes[HEADERS_MAX_HOPS + 1];
    unsigned int            ctrl_findings;
    int                     hops;
    int                     i;

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
        "GET /ring on one node of the web tier, read as a header posture "
        "and as a contract. The bare control endpoint must produce http.* "
        "findings, or the audit is blind. http.walk-depth is the injected "
        "always-true defect in forward(): the body traces 1 node instead "
        "of hops+1.");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "http_headers", dut, session_up);

    if (!tapi_http_available(session.factory, 10000))
        TEST_SKIP("There is no curl on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("There is no python3 on the agent for the control endpoint");
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built");

    TEST_STEP("Known-bad control: an endpoint that sends no security "
              "headers must be reported");
    server_opt = tapi_http_server_default_opt;
    server_opt.port = HEADERS_CTRL_PORT;
    server_opt.defects = TAPI_HTTP_DEFECT_NO_SECURITY_HEADERS;
    CHECK_RC(tapi_http_server_start(session.factory, &server_opt,
                                    MDE_HTTP_TIMEOUT_MS, &server));

    te_string_append(&ctrl_url, "%s/", tapi_http_server_url(server));
    opt = tapi_http_request_default_opt;
    opt.url = ctrl_url.ptr;
    CHECK_RC(tapi_http_request(session.factory, &opt, MDE_HTTP_TIMEOUT_MS,
                               &resp));
    resp_up = true;
    tapi_http_response_log(&resp);

    /* The findings are about the URL the request ended at. */
    te_string_append(&subject, "%s",
                     resp.final_url != NULL ? resp.final_url : "endpoint");
    tapi_http_headers_check(&resp, NULL, &report.cyber);
    ctrl_findings = tsapi_mde_report_has(&report, "http.", subject.ptr);
    TEST_ARTIFACT("Control endpoint: %u header(s), %u http.* finding(s)",
                  (unsigned int)resp.n_headers, ctrl_findings);
    tsapi_mde_report_expect(&report, "http.no-csp", subject.ptr);
    tsapi_mde_report_expect(&report, "http.no-nosniff", subject.ptr);
    tsapi_mde_report_expect(&report, "http.framable", subject.ptr);
    tsapi_mde_report_drop_subject(&report, subject.ptr);

    tapi_http_response_free(&resp);
    resp_up = false;
    CHECK_RC(tapi_http_server_stop(server));
    server = NULL;

    TEST_STEP("Start the web tier");
    web_up = true;
    if (tsapi_mde_web_start(&session, &dut, &web) != 0)
        TEST_VERDICT("The web tier did not start");

    TEST_STEP("Sweep the hop budget and read every response");
    for (hops = 0; hops <= HEADERS_MAX_HOPS; hops++)
    {
        const char *ctype;
        double      t0;
        te_errno    req_rc;

        te_string_reset(&url);
        tsapi_mde_web_url(port, 1.0, hops, &url);

        opt = tapi_http_request_default_opt;
        opt.url = url.ptr;

        t0 = tsapi_mde_now();
        req_rc = tapi_http_request(session.factory, &opt,
                                   MDE_HTTP_TIMEOUT_MS, &resp);
        time_ms[hops] = (tsapi_mde_now() - t0) * 1000.0;
        if (req_rc != 0)
            TEST_VERDICT("%s did not answer GET /ring", name);
        resp_up = true;

        n_headers[hops] = resp.n_headers;
        body_len[hops] = resp.body.len;
        nodes[hops] = mde_http_count_nodes(te_string_value(&resp.body));

        RING("hops=%d: status %u, %zu header(s), %zu body byte(s), "
             "%.0f node line(s), %.1f ms", hops, resp.status,
             resp.n_headers, resp.body.len, nodes[hops], time_ms[hops]);

        if (resp.status != 200)
            TEST_VERDICT("%s answered GET /ring with %u, expected 200", name,
                         resp.status);

        ctype = tapi_http_header(&resp, "Content-Type");
        if (ctype == NULL || strstr(ctype, "text/plain") == NULL)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                "http.content-type", resp.final_url != NULL ?
                    resp.final_url : name,
                "The trace is plain text but Content-Type is '%s'",
                ctype != NULL ? ctype : "(none)");
        }

        if (hops == 0 && nodes[hops] != 1)
        {
            TEST_VERDICT("GET /ring with hops=0 traced %.0f node line(s), "
                         "expected 1", nodes[hops]);
        }

        if (hops < HEADERS_MAX_HOPS)
        {
            tapi_http_response_free(&resp);
            resp_up = false;
        }
    }

    TEST_STEP("Read the security headers of the audited response");
    tapi_http_response_log(&resp);
    te_string_reset(&subject);
    te_string_append(&subject, "%s",
                     resp.final_url != NULL ? resp.final_url : name);
    tapi_http_headers_check(&resp, NULL, &report.cyber);
    TEST_ARTIFACT("%s: %u header(s), %u http.* header finding(s)", name,
                  (unsigned int)resp.n_headers,
                  tsapi_mde_report_has(&report, "http.", NULL));

    TEST_STEP("Check the walk depth: correct code traces hops+1 nodes");
    if (nodes[HEADERS_MAX_HOPS] != HEADERS_MAX_HOPS + 1)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
            "http.walk-depth", subject.ptr,
            "The body traces %.0f node line(s) for hops=%d, expected %d: "
            "the request did not travel the cycle", nodes[HEADERS_MAX_HOPS],
            HEADERS_MAX_HOPS, HEADERS_MAX_HOPS + 1);
    }

    {
        double value = 0.0;

        if (!mde_http_body_value(te_string_value(&resp.body), &value))
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                "http.contract", subject.ptr,
                "The body has no 'value=' line, which is the contract "
                "between the nodes");
        }
        else
        {
            TEST_ARTIFACT("%s: value=%g for hops=%d", name, value,
                          HEADERS_MAX_HOPS);
        }
    }

    TEST_STEP("Check Content-Length against an independent byte count");
    CHECK_RC(tsapi_mde_sh(&session, MDE_HTTP_TIMEOUT_MS, &sh,
                          "curl -s -D '/tmp/mde-http-headers-%s.hdr' "
                          "-o '/tmp/mde-http-headers-%s.body' '%s' && "
                          "wc -c < '/tmp/mde-http-headers-%s.body' && "
                          "sha256sum '/tmp/mde-http-headers-%s.body'",
                          name, name, url.ptr, name, name));
    if (!tsapi_mde_sh_ok(&sh))
    {
        TEST_VERDICT("Cannot save the body of %s with curl", name);
    }
    else
    {
        const char   *cl = tapi_http_header(&resp, "Content-Length");
        char         *end = NULL;
        unsigned long bytes = strtoul(te_string_value(&sh.out), &end, 10);
        const char   *sha = (end != NULL) ? strchr(end, '\n') : NULL;

        if (sha != NULL)
            sha++;
        TEST_ARTIFACT("Body of %s saved to /tmp/mde-http-headers-%s.body: "
                      "%lu byte(s), sha256 %.64s", name, name, bytes,
                      sha != NULL ? sha : "?");

        /*
         * tapi_http cuts trailing newlines off the body together with
         * its own marker, so its body is the saved one or one byte less.
         */
        if (resp.body.len != bytes && resp.body.len + 1 != bytes)
        {
            TEST_VERDICT("tapi_http and curl disagree on the body size of "
                         "%s", name);
        }

        if (cl == NULL)
        {
            RING("%s sends no Content-Length (chunked or close-delimited)",
                 name);
        }
        else if (strtoul(cl, NULL, 10) != bytes)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                "http.content-length", subject.ptr,
                "Content-Length says %s but %lu byte(s) arrived", cl, bytes);
        }
    }

    TEST_STEP("Chart the sweep");
    if (tsapi_mde_mi_create("http-headers", &logger) == 0)
    {
        for (i = 0; i <= HEADERS_MAX_HOPS; i++)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "hops", TE_MI_MEAS_AGGR_SINGLE, i,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_LATENCY,
                                  "response_time", TE_MI_MEAS_AGGR_SINGLE,
                                  time_ms[i], TE_MI_MEAS_MULTIPLIER_MILLI);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "header_count", TE_MI_MEAS_AGGR_SINGLE,
                                  n_headers[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_MEMORY,
                                  "body_size", TE_MI_MEAS_AGGR_SINGLE,
                                  body_len[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "node_lines", TE_MI_MEAS_AGGR_SINGLE,
                                  nodes[i], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "node_lines_expected",
                                  TE_MI_MEAS_AGGR_SINGLE, i + 1,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        te_mi_logger_add_meas_key(logger, NULL, "service", "%s", name);
        tsapi_mde_mi_line(logger, "time", "Response time per hop budget",
                          "hops", "response_time", NULL);
        tsapi_mde_mi_line(logger, "headers", "Header count per hop budget",
                          "hops", "header_count", NULL);
        tsapi_mde_mi_line(logger, "body", "Body size per hop budget",
                          "hops", "body_size", NULL);
        tsapi_mde_mi_line(logger, "depth",
                          "Node lines traced vs expected (hops+1)", "hops",
                          "node_lines", "node_lines_expected", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

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
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&url);
    te_string_free(&ctrl_url);
    te_string_free(&subject);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
