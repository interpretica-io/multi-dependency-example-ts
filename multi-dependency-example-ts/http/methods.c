/** @file
 * @brief HTTP Group
 *
 * Ask one node of the web tier what it lets a client do to /ring. A read
 * only service should answer GET, HEAD and OPTIONS and nothing else; TRACE
 * echoing the request back, or a state-changing method answered with
 * success, is a finding. A deliberately permissive endpoint is probed
 * first so that a blind probe cannot pass for a strict service.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "http/methods"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "tapi_test.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_http.h"
#include "tapi_http_methods.h"
#include "tapi_http_server.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "http_common.h"

/** Port of the known-bad endpoint. */
#define METHODS_CTRL_PORT   34511

/**
 * State-changing methods that tapi_http_methods deliberately never sends.
 * The web tier is a stateless toy of our own, so here they are sent: what
 * matters is whether it says "yes" to them.
 */
static const char *const methods_changing[] = {
    "POST", "PUT", "DELETE", "PATCH",
};

/** Maximum labels in the charts: the probe's table plus ours. */
#define METHODS_MAX     32

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
    tapi_http_methods       methods;
    tapi_http_methods       ctrl;
    te_string               url = TE_STRING_INIT;
    te_string               ctrl_url = TE_STRING_INIT;
    te_string               subject = TE_STRING_INIT;
    const char             *labels[METHODS_MAX];
    double                  status[METHODS_MAX];
    double                  allowed[METHODS_MAX];
    double                  advertised[METHODS_MAX];
    size_t                  n = 0;
    size_t                  i;
    const char             *name;
    unsigned int            port;
    unsigned int            get_status;
    unsigned int            head_status;
    unsigned int            n_allowed = 0;
    bool                    session_up = false;
    bool                    web_up = false;
    bool                    probed = false;
    bool                    ctrl_probed = false;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(service, MDE_HTTP_SERVICE_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);
    name = mde_http_service_name(service);
    port = mde_http_service_port(service);

    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    memset(&methods, 0, sizeof(methods));
    memset(&ctrl, 0, sizeof(ctrl));
    tsapi_mde_report_init(&report);

    tsapi_evo_analysis_hint(
        "Methods a node of the web tier answers on /ring. Only GET, HEAD "
        "and OPTIONS belong to a read-only service. The toy nodes route by "
        "path only, so TRACE and the state-changing methods are expected "
        "to come back 200 on gateway-rs and service-go.");

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "http_methods", dut, session_up);

    if (!tapi_http_available(session.factory, 10000))
        TEST_SKIP("There is no curl on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("There is no python3 on the agent for the control endpoint");
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built");

    TEST_STEP("Known-bad control: an endpoint answering TRACE and "
              "advertising PUT and DELETE must be reported");
    server_opt = tapi_http_server_default_opt;
    server_opt.port = METHODS_CTRL_PORT;
    server_opt.defects = TAPI_HTTP_DEFECT_TRACE |
                         TAPI_HTTP_DEFECT_WRITE_METHODS;
    CHECK_RC(tapi_http_server_start(session.factory, &server_opt,
                                    MDE_HTTP_TIMEOUT_MS, &server));
    te_string_append(&ctrl_url, "%s/", tapi_http_server_url(server));

    CHECK_RC(tapi_http_methods_probe(session.factory, ctrl_url.ptr,
                                     MDE_HTTP_TIMEOUT_MS, &ctrl));
    ctrl_probed = true;
    tapi_http_methods_log(&ctrl);
    if (tapi_http_methods_status(&ctrl, "GET") != 200)
        TEST_VERDICT("The control endpoint did not answer GET with 200");

    tapi_http_methods_check(&ctrl, &report.cyber);
    tsapi_mde_report_expect(&report, "http.trace-enabled", ctrl_url.ptr);
    tsapi_mde_report_expect(&report, "http.changing-method-allowed", "PUT");
    tsapi_mde_report_expect(&report, "http.changing-method-allowed",
                            "DELETE");
    tsapi_mde_report_drop_subject(&report, ctrl_url.ptr);
    tsapi_mde_report_drop_subject(&report, "PUT");
    tsapi_mde_report_drop_subject(&report, "DELETE");
    tsapi_mde_report_drop_subject(&report, "PATCH");

    tapi_http_methods_free(&ctrl);
    ctrl_probed = false;
    CHECK_RC(tapi_http_server_stop(server));
    server = NULL;

    TEST_STEP("Start the web tier");
    web_up = true;
    if (tsapi_mde_web_start(&session, &dut, &web) != 0)
        TEST_VERDICT("The web tier did not start");

    TEST_STEP("Probe the safe methods with tapi_http_methods");
    /* hops=0: every node answers for itself and calls nothing else. */
    tsapi_mde_web_url(port, 1.0, 0, &url);
    CHECK_RC(tapi_http_methods_probe(session.factory, url.ptr,
                                     MDE_HTTP_TIMEOUT_MS, &methods));
    probed = true;
    tapi_http_methods_log(&methods);
    tapi_http_methods_check(&methods, &report.cyber);

    get_status = tapi_http_methods_status(&methods, "GET");
    head_status = tapi_http_methods_status(&methods, "HEAD");
    TEST_ARTIFACT("%s: GET %u, HEAD %u, OPTIONS %u, TRACE %u, Allow: %s",
                  name, get_status, head_status,
                  tapi_http_methods_status(&methods, "OPTIONS"),
                  tapi_http_methods_status(&methods, "TRACE"),
                  methods.allow != NULL ? methods.allow : "(none)");

    if (get_status != 200)
        TEST_VERDICT("%s did not answer GET /ring with 200", name);

    TEST_STEP("HEAD must agree with GET");
    if (head_status != get_status)
    {
        te_string_reset(&subject);
        te_string_append(&subject, "%s:HEAD", name);
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
            "http.head-mismatch", subject.ptr,
            "HEAD answered %u while GET answered %u", head_status,
            get_status);
    }

    for (i = 0; i < methods.n_results && n < METHODS_MAX; i++)
    {
        const tapi_http_method_result *r = &methods.results[i];

        labels[n] = r->method;
        status[n] = r->status;
        allowed[n] = (r->status >= 200 && r->status < 300) ? 1 : 0;
        advertised[n] = r->advertised ? 1 : 0;
        n++;
    }

    TEST_STEP("Send the state-changing methods the module does not send");
    for (i = 0; i < TE_ARRAY_LEN(methods_changing) && n < METHODS_MAX; i++)
    {
        tapi_http_request_opt opt = tapi_http_request_default_opt;
        tapi_http_response    resp;
        unsigned int          code = 0;
        size_t                j;

        opt.url = url.ptr;
        opt.method = methods_changing[i];
        opt.follow = false;
        if (tapi_http_request(session.factory, &opt, MDE_HTTP_TIMEOUT_MS,
                              &resp) == 0)
        {
            code = resp.status;
            tapi_http_response_free(&resp);
        }
        RING("%s %s -> %u", methods_changing[i], url.ptr, code);

        /* The probe's table lists these as "not sent": replace those. */
        for (j = 0; j < n; j++)
        {
            if (strcasecmp(labels[j], methods_changing[i]) == 0)
                break;
        }
        if (j == n)
        {
            labels[n] = methods_changing[i];
            advertised[n] = 0;
            n++;
        }
        status[j] = code;
        allowed[j] = (code >= 200 && code < 300) ? 1 : 0;

        if (code >= 200 && code < 300)
        {
            te_string_reset(&subject);
            te_string_append(&subject, "%s:%s", name, methods_changing[i]);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                "http.unsafe-method-accepted", subject.ptr,
                "%s on a read-only endpoint was answered %u; the node routes "
                "by path and ignores the method", methods_changing[i], code);
        }
    }

    TEST_STEP("Cross-check Allow against what was actually answered");
    for (i = 0; i < n; i++)
    {
        if (allowed[i] > 0)
            n_allowed++;

        if (methods.allow != NULL && allowed[i] > 0 && advertised[i] == 0)
        {
            te_string_reset(&subject);
            te_string_append(&subject, "%s:%s", name, labels[i]);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                "http.allow-inconsistent", subject.ptr,
                "%s is answered with success but Allow says '%s'",
                labels[i], methods.allow);
        }
    }
    TEST_ARTIFACT("%s answers %u of %zu method(s) with success", name,
                  n_allowed, n);

    TEST_STEP("Chart what each method got");
    tsapi_mde_mi_bars("http-methods", "Status per method",
                      TE_MI_MEAS_UNITLESS_VALUE, "status", n, labels, status,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("http-methods", "Method allowed (2xx) 1/0",
                      TE_MI_MEAS_UNITLESS_VALUE, "allowed", n, labels,
                      allowed, TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("http-methods", "Method advertised in Allow 1/0",
                      TE_MI_MEAS_UNITLESS_VALUE, "advertised", n, labels,
                      advertised, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "http", min_severity);

    TEST_SUCCESS;

cleanup:

    if (probed)
        tapi_http_methods_free(&methods);
    if (ctrl_probed)
        tapi_http_methods_free(&ctrl);
    if (server != NULL)
        CLEANUP_CHECK_RC(tapi_http_server_stop(server));
    if (web_up)
        tsapi_mde_web_stop(&web);
    te_string_free(&url);
    te_string_free(&ctrl_url);
    te_string_free(&subject);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
