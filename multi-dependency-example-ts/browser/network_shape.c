/** @file
 * @brief Browser Group
 *
 * The shape of the web tier's answers, as the browser received them:
 * walk the cycle several times with different values and hop budgets,
 * then read the captured network log and check every answer - HTTP 200,
 * a text/plain body, a Content-Length that matches the body, a body that
 * is a node trace ending with a value= line - and that the log holds
 * exactly the requests the test made. A request for an unknown path is
 * the known-bad control: its 404 must be reported.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "browser/network_shape"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "browser_common.h"

/* The path of the known-bad control: the gateway answers it with 404. */
#define CONTROL_PATH    "/mde-no-such-path"

/* Upper bound of the requests charted. */
#define MAX_REQ         64

/* What one captured answer looked like. */
typedef struct shape_req {
    long   status;          /**< HTTP status, -1 if none */
    double body;            /**< Body bytes */
    double content_length;  /**< Content-Length, -1 if none */
} shape_req;

/* Check one captured HTTP entry, add findings, fill @p req. */
static void
shape_check(const char *entry, tsapi_mde_report *report, shape_req *req,
            bool *is_ring)
{
    te_string   url = TE_STRING_INIT;
    te_string   host = TE_STRING_INIT;
    te_string   path = TE_STRING_INIT;
    te_string   ctype = TE_STRING_INIT;
    te_string   clen = TE_STRING_INIT;
    te_string   body = TE_STRING_INIT;
    te_string   failure = TE_STRING_INIT;
    const char *resp;
    const char *subject;
    long        status = -1;

    browser_json_str(entry, "url", &url);
    browser_url_split(url.ptr != NULL ? url.ptr : "", &host, &path);
    subject = path.ptr != NULL ? path.ptr : "/";
    *is_ring = strcmp(subject, "/ring") == 0;

    browser_json_int(entry, "status", &status);
    req->status = status;
    req->body = 0;
    req->content_length = -1;

    if (browser_json_str(entry, "failure", &failure))
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_HIGH,
                                 "web.request-failed", subject,
                                 "%s failed: %s", url.ptr, failure.ptr);
        goto out;
    }

    if (status != 200)
    {
        /*
         * A browser may ask for a favicon on its own; the gateway does not
         * serve one, and that is not an answer of the walk.
         */
        tapi_cybersec_report_add(&report->cyber,
                                 strcmp(subject, "/favicon.ico") == 0 ?
                                     TAPI_CYBERSEC_SEV_INFO :
                                     TAPI_CYBERSEC_SEV_HIGH,
                                 "web.http-status", subject,
                                 "%s answered HTTP %ld", url.ptr, status);
    }

    resp = strstr(entry, "\"response_headers\":");
    if (resp == NULL)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "web.no-response", subject,
                                 "%s has no response in the log", url.ptr);
        goto out;
    }

    if (!browser_json_str(resp, "content-type", &ctype) ||
        ctype.ptr == NULL || strncmp(ctype.ptr, "text/plain", 10) != 0)
    {
        tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "web.content-type", subject,
                                 "%s is served as '%s', not text/plain",
                                 url.ptr, ctype.ptr != NULL ?
                                          ctype.ptr : "(none)");
    }

    if (browser_json_str(resp, "response_body", &body))
        req->body = body.len;

    if (browser_json_str(resp, "content-length", &clen) && clen.ptr != NULL)
    {
        req->content_length = strtod(clen.ptr, NULL);
        if ((size_t)req->content_length != body.len)
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "web.content-length", subject,
                                     "%s declares %s bytes, the body has "
                                     "%zu", url.ptr, clen.ptr, body.len);
        }
    }

    if (*is_ring && status == 200)
    {
        te_string value = TE_STRING_INIT;

        if (browser_count_nodes(body.ptr != NULL ? body.ptr : "", NULL) == 0 ||
            !browser_value_line(body.ptr != NULL ? body.ptr : "", &value))
        {
            tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "web.body-shape", subject,
                                     "%s answered a body that is not a node "
                                     "trace with a value= line", url.ptr);
        }
        te_string_free(&value);
    }

    RING("Captured %s: HTTP %ld, %s, %.0f body bytes, Content-Length %.0f",
         url.ptr, status, ctype.ptr != NULL ? ctype.ptr : "(no type)",
         req->body, req->content_length);

out:
    te_string_free(&url);
    te_string_free(&host);
    te_string_free(&path);
    te_string_free(&ctype);
    te_string_free(&clen);
    te_string_free(&body);
    te_string_free(&failure);
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity min_severity;
    int                 requests;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_web       web;
    bool                web_started = false;
    tapi_playwright    *pw = NULL;
    tsapi_mde_report    report;
    te_string           url = TE_STRING_INIT;
    te_string           netlog = TE_STRING_INIT;
    te_string           entry = TE_STRING_INIT;
    shape_req           req[MAX_REQ];
    double              goto_s[MAX_REQ];
    double              statuses[MAX_REQ];
    double              bodies[MAX_REQ];
    unsigned int        n_req = 0;
    unsigned int        n_ring = 0;
    unsigned int        n_other = 0;
    unsigned int        n_2xx = 0;
    unsigned int        n_4xx = 0;
    unsigned int        n_5xx = 0;
    unsigned int        n_none = 0;
    const char         *cursor;
    int                 i;

    TEST_START;
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(requests);
    TEST_GET_MDE_SEVERITY(min_severity);
    if (requests < 1 || requests > MAX_REQ - 1)
        TEST_FAIL("requests must be within 1..%d", MAX_REQ - 1);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "browser_shape", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_VERDICT("The web tier is not built - build the example first");
    browser_skip_unless_ready(&session);

    TEST_STEP("Start the web tier and a browser that captures its traffic");
    web_started = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    browser_open(&session, true, false, false, &pw);

    TEST_STEP("Walk the cycle %d time(s) with different values and budgets",
              requests);
    for (i = 0; i < requests; i++)
    {
        double t0;

        te_string_reset(&url);
        tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1 + i * 0.5, i % 6,
                          &url);
        t0 = tsapi_mde_now();
        CHECK_RC(tapi_playwright_goto(pw, url.ptr));
        goto_s[i] = tsapi_mde_now() - t0;
    }

    TEST_STEP("Known-bad control: request a path the gateway does not serve");
    te_string_reset(&url);
    te_string_append(&url, "http://127.0.0.1:%u" CONTROL_PATH,
                     TSAPI_MDE_WEB_GATEWAY_PORT);
    CHECK_RC(tapi_playwright_goto(pw, url.ptr));
    CHECK_RC(tapi_playwright_wait_load(pw, TAPI_PLAYWRIGHT_NETWORKIDLE));

    TEST_STEP("Check every answer in the captured network log");
    CHECK_RC(tapi_playwright_network_dump(pw, &netlog));
    cursor = netlog.ptr;
    while (browser_net_next(&cursor, &entry))
    {
        te_string type = TE_STRING_INIT;
        bool      is_ring = false;

        browser_json_str(entry.ptr, "type", &type);
        if (type.ptr != NULL && strcmp(type.ptr, "http") == 0 &&
            n_req < MAX_REQ)
        {
            shape_check(entry.ptr, &report, &req[n_req], &is_ring);
            if (is_ring)
                n_ring++;
            else
                n_other++;

            if (req[n_req].status < 0)
                n_none++;
            else if (req[n_req].status < 300)
                n_2xx++;
            else if (req[n_req].status < 500)
                n_4xx++;
            else
                n_5xx++;

            statuses[n_req] = req[n_req].status;
            bodies[n_req] = req[n_req].body;
            n_req++;
        }
        te_string_free(&type);
    }
    TEST_ARTIFACT("Network log: %u HTTP entr(ies): %u /ring, %u other; "
                  "%u 2xx, %u 4xx, %u 5xx, %u without a response",
                  n_req, n_ring, n_other, n_2xx, n_4xx, n_5xx, n_none);

    if (n_ring != (unsigned int)requests)
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "browser.request-count", "/ring",
                                 "the log holds %u /ring request(s), the "
                                 "test made %d", n_ring, requests);
    }

    tsapi_mde_report_expect(&report, "web.http-status", CONTROL_PATH);
    tsapi_mde_report_drop_subject(&report, CONTROL_PATH);

    TEST_STEP("Chart status codes, sizes and times");
    tsapi_mde_mi_series("browser", "HTTP status per captured request",
                        TE_MI_MEAS_UNITLESS_VALUE, "status", n_req, statuses,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_series("browser", "Response body size per captured request",
                        TE_MI_MEAS_MEMORY, "body", n_req, bodies,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_series("browser", "goto time per walk", TE_MI_MEAS_TIME,
                        "goto", (size_t)requests, goto_s,
                        TE_MI_MEAS_MULTIPLIER_PLAIN);
    {
        const char *labels[] = { "2xx", "4xx", "5xx", "none" };
        double      vals[4];

        vals[0] = n_2xx;
        vals[1] = n_4xx;
        vals[2] = n_5xx;
        vals[3] = n_none;
        tsapi_mde_mi_bars("browser", "Captured answers per status class",
                          TE_MI_MEAS_UNITLESS_VALUE, "answers",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "browser", min_severity);

    TEST_SUCCESS;

cleanup:

    tapi_playwright_destroy(pw);
    if (web_started)
        tsapi_mde_web_stop(&web);
    tsapi_mde_report_free(&report);
    te_string_free(&url);
    te_string_free(&netlog);
    te_string_free(&entry);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
