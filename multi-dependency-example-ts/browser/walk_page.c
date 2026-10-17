/** @file
 * @brief Browser Group
 *
 * Walk the web tier's cycle from a real browser: Chromium opens
 * the gateway's /ring page, the page text is read and its node lines are
 * counted, and every piece of evidence the browser can leave is kept on
 * the agent at a stable path - a screenshot, the page text, a HAR and a
 * Playwright trace - with its size and SHA-256. The same URL is fetched
 * with curl as a second, independent reading of the same walk.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "browser/walk_page"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_web.h"
#include "browser_common.h"

/* Navigation timing of the page, read in the page itself. */
#define WALK_NAV_SCRIPT \
    "(() => { const n = performance.getEntriesByType('navigation')[0]; " \
    "return n ? [n.responseStatus || 0, n.duration, "                   \
    "n.responseEnd - n.requestStart, n.transferSize, n.decodedBodySize] " \
    ": null; })()"

/* Default viewport of a Playwright page. */
#define WALK_VIEWPORT_W 1280

/* Log a file kept on the agent as an artifact: path, size, SHA-256. */
static unsigned long
walk_evidence(tsapi_mde_session *session, const char *what, const char *path)
{
    te_string     sha = TE_STRING_INIT;
    unsigned long size = 0;

    if (browser_file_evidence(session, path, &size, &sha))
    {
        TEST_ARTIFACT("%s: %s (%lu bytes, sha256 %s)", what, path, size,
                      sha.ptr);
    }
    else
    {
        WARN("Cannot read the size and hash of %s", path);
        size = 0;
    }
    te_string_free(&sha);

    return size;
}

int
main(int argc, char **argv)
{
    int                 hops;
    unsigned int        expected;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut;
    tsapi_mde_web       web;
    bool                web_started = false;
    tapi_playwright    *pw = NULL;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;
    te_string           url = TE_STRING_INIT;
    te_string           text = TE_STRING_INIT;
    te_string           value_line = TE_STRING_INIT;
    te_string           curl_value = TE_STRING_INIT;
    te_string           nav = TE_STRING_INIT;
    te_string           shot_remote = TE_STRING_INIT;
    te_string           netlog = TE_STRING_INIT;
    te_string           entry = TE_STRING_INIT;
    te_string           trace_local = TE_STRING_INIT;
    te_string           har_local = TE_STRING_INIT;
    char                png_path[64];
    char                txt_path[64];
    char                har_path[64];
    char                trace_path[64];
    char                shot_name[32];
    unsigned int        per_node[BROWSER_N_NODES];
    unsigned int        steps;
    unsigned int        curl_steps = 0;
    bool                have_curl_body = false;
    unsigned int        width = 0;
    unsigned int        height = 0;
    unsigned int        n_http = 0;
    unsigned int        n_ring_200 = 0;
    long                har_entries = -1;
    double              t0;
    double              t_start;
    double              t_goto;
    double              nav_status = 0;
    double              nav_duration = 0;
    double              nav_ttfb = 0;
    double              nav_transfer = 0;
    double              nav_body = 0;
    bool                have_nav = false;
    unsigned long       shot_size = 0;
    unsigned long       har_size = 0;
    unsigned long       trace_size = 0;
    time_t              wall_start = time(NULL) - 1;
    te_mi_logger       *logger = NULL;
    const char         *cursor;
    unsigned int        i;

    TEST_START;
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    t_start = tsapi_mde_now();

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(hops);
    expected = (unsigned int)hops + 1;
    TE_SPRINTF(png_path, "/tmp/mde-browser-walk-h%d.png", hops);
    TE_SPRINTF(txt_path, "/tmp/mde-browser-walk-h%d.txt", hops);
    TE_SPRINTF(har_path, "/tmp/mde-browser-walk-h%d.har", hops);
    TE_SPRINTF(trace_path, "/tmp/mde-browser-walk-h%d.trace.zip", hops);
    TE_SPRINTF(shot_name, "walk-h%d", hops);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "browser_walk", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built - build the example first");
    browser_skip_unless_ready(&session);

    TEST_STEP("Start the web tier");
    web_started = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));

    TEST_STEP("Start Chromium with network capture, a HAR and a trace");
    browser_open(&session, true, true, true, &pw);

    TEST_STEP("Open the gateway's ring page for hops=%d", hops);
    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, hops, &url);
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_playwright_goto(pw, url.ptr));
    t_goto = tsapi_mde_now() - t0;
    rc = tapi_playwright_expect_text(pw, "body", "[gateway-rs] hops=");
    if (rc != 0)
        TEST_VERDICT("The gateway page shows no gateway-rs node line");

    TEST_STEP("Read the page text and parse its node lines");
    CHECK_RC(tapi_playwright_get_text(pw, "body", &text));
    RING("Page text of %s:\n%s", url.ptr, text.ptr);
    steps = browser_count_nodes(text.ptr, per_node);
    if (!browser_value_line(text.ptr, &value_line))
        TEST_VERDICT("The gateway page has no value= line");
    TEST_ARTIFACT("Browser walk hops=%d: %u node step(s) "
                  "(gateway-rs %u, service-go %u, service-cs %u), %s",
                  hops, steps, per_node[0], per_node[1], per_node[2],
                  value_line.ptr);
    CHECK_RC(tapi_file_create_ta(session.ta, txt_path, "%s", text.ptr));
    walk_evidence(&session, "Page text", txt_path);

    TEST_STEP("Read the navigation timing of the page");
    if (tapi_playwright_eval(pw, WALK_NAV_SCRIPT, &nav) == 0 &&
        nav.ptr != NULL &&
        sscanf(nav.ptr, "[%lf,%lf,%lf,%lf,%lf]", &nav_status, &nav_duration,
               &nav_ttfb, &nav_transfer, &nav_body) == 5)
    {
        have_nav = true;
        TEST_ARTIFACT("Navigation: HTTP %.0f, %.1f ms total, %.1f ms "
                      "request-to-end, %.0f bytes transferred, %.0f bytes "
                      "of body", nav_status, nav_duration, nav_ttfb,
                      nav_transfer, nav_body);
        if (nav_status != 0 && nav_status != 200)
        {
            TEST_VERDICT("The gateway answered the browser with HTTP %.0f",
                         nav_status);
        }
    }
    else
    {
        WARN("No navigation timing: %s", nav.ptr != NULL ? nav.ptr : "");
    }

    TEST_STEP("Fetch the same URL with curl: a second reading of the walk");
    if (tsapi_mde_have(&session, "curl"))
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "curl -s '%s'", url.ptr));
        if (tsapi_mde_sh_ok(&sh) && sh.out.ptr != NULL)
        {
            have_curl_body = true;
            curl_steps = browser_count_nodes(sh.out.ptr, NULL);
            browser_value_line(sh.out.ptr, &curl_value);
            TEST_ARTIFACT("curl: %u node step(s), %zu bytes, %s", curl_steps,
                          sh.out.len, curl_value.ptr != NULL ?
                                      curl_value.ptr : "(no value line)");
            if (curl_steps != steps)
            {
                TEST_VERDICT("Browser and curl saw different walks: %u vs %u "
                             "node step(s)", steps, curl_steps);
            }
            if (curl_value.ptr == NULL ||
                strcmp(curl_value.ptr, value_line.ptr) != 0)
            {
                TEST_VERDICT("Browser and curl got different results of the "
                             "walk");
            }
            if (have_nav && nav_body > 0 &&
                (size_t)nav_body != sh.out.len)
            {
                TEST_VERDICT("Browser and curl received bodies of different "
                             "sizes");
            }
        }
        else
        {
            WARN("curl could not fetch %s", url.ptr);
        }
    }
    else
    {
        RING("curl is not installed on the agent: no second reading");
    }

    TEST_STEP("Take a screenshot and keep it at %s", png_path);
    CHECK_RC(browser_screenshot_ta(pw, session.ta, shot_name, &shot_remote));
    CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "mv -f '%s' '%s'",
                          shot_remote.ptr, png_path));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot move the screenshot to %s", png_path);
    shot_size = walk_evidence(&session, "Screenshot", png_path);
    if (!browser_png_dims(&session, png_path, &width, &height))
        TEST_VERDICT("The browser screenshot is not a PNG image");
    TEST_ARTIFACT("Screenshot is a %ux%u PNG", width, height);
    if (width != WALK_VIEWPORT_W || height == 0)
        TEST_VERDICT("The screenshot does not have the viewport's width");

    TEST_STEP("Read the network log the browser captured");
    CHECK_RC(tapi_playwright_network_dump(pw, &netlog));
    cursor = netlog.ptr;
    while (browser_net_next(&cursor, &entry))
    {
        te_string type = TE_STRING_INIT;
        te_string req_url = TE_STRING_INIT;
        te_string host = TE_STRING_INIT;
        te_string path = TE_STRING_INIT;
        long      status = -1;

        browser_json_str(entry.ptr, "type", &type);
        browser_json_str(entry.ptr, "url", &req_url);
        browser_json_int(entry.ptr, "status", &status);
        if (type.ptr != NULL && strcmp(type.ptr, "http") == 0 &&
            req_url.ptr != NULL)
        {
            n_http++;
            browser_url_split(req_url.ptr, &host, &path);
            if (path.ptr != NULL && strcmp(path.ptr, "/ring") == 0 &&
                status == 200)
                n_ring_200++;
            RING("Captured: %s %s -> %ld", type.ptr, req_url.ptr, status);
        }
        te_string_free(&type);
        te_string_free(&req_url);
        te_string_free(&host);
        te_string_free(&path);
    }
    TEST_ARTIFACT("Network log: %u HTTP request(s), %u /ring answered 200",
                  n_http, n_ring_200);
    if (n_ring_200 != 1)
    {
        TEST_VERDICT("The browser captured %u successful /ring request(s), "
                     "expected 1", n_ring_200);
    }

    TEST_STEP("Save the Playwright trace and keep it at %s", trace_path);
    CHECK_RC(tapi_playwright_trace_save(pw, shot_name, &trace_local));
    CHECK_RC(rcf_ta_put_file(session.ta, 0, trace_local.ptr, trace_path));
    trace_size = walk_evidence(&session, "Playwright trace", trace_path);
    {
        uint8_t magic[4];

        if (browser_head_bytes(&session, trace_path, sizeof(magic),
                               magic) != sizeof(magic) ||
            memcmp(magic, "PK\003\004", 4) != 0)
        {
            TEST_VERDICT("The Playwright trace is not a zip archive");
        }
    }
    if (tsapi_mde_have(&session, "python3"))
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              "python3 -m zipfile -l '%s'", trace_path));
        RING("Trace archive members:\n%s", sh.out.ptr != NULL ?
                                           sh.out.ptr : "");
        if (sh.out.ptr == NULL || strstr(sh.out.ptr, ".trace") == NULL)
            WARN("The trace archive lists no .trace member");
    }

    TEST_STEP("Close the browser: the HAR is flushed and copied off");
    CHECK_RC(tapi_playwright_stop(pw));
    if (!browser_find_engine_file("_session.har", wall_start, &har_local))
        TEST_VERDICT("The browser left no HAR of the session");
    CHECK_RC(rcf_ta_put_file(session.ta, 0, har_local.ptr, har_path));
    har_size = walk_evidence(&session, "HAR", har_path);
    if (tsapi_mde_have(&session, "python3"))
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh,
                              "python3 -c 'import json,sys; "
                              "print(len(json.load(open(sys.argv[1]))"
                              "[\"log\"][\"entries\"]))' '%s'", har_path));
        if (tsapi_mde_sh_ok(&sh) && sh.out.ptr != NULL)
            har_entries = strtol(sh.out.ptr, NULL, 10);
        TEST_ARTIFACT("HAR holds %ld entr(ies); the network log %u request(s)",
                      har_entries, n_http);
        if (har_entries < 1)
            TEST_VERDICT("The HAR of the session holds no request");
        if ((unsigned long)har_entries != n_http)
        {
            WARN("The HAR and the network log disagree on the number of "
                 "requests: %ld vs %u", har_entries, n_http);
        }
    }

    TEST_STEP("Chart what was measured");
    tsapi_mde_mi_point("browser", "Page load (goto) time", TE_MI_MEAS_TIME,
                       "goto", t_goto, TE_MI_MEAS_MULTIPLIER_PLAIN);
    if (have_nav)
    {
        tsapi_mde_mi_point("browser", "Navigation duration in the page",
                           TE_MI_MEAS_TIME, "navigation", nav_duration,
                           TE_MI_MEAS_MULTIPLIER_MILLI);
        tsapi_mde_mi_point("browser", "Response body size", TE_MI_MEAS_MEMORY,
                           "body", nav_body, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        const char *labels[] = { "page text", "screenshot", "trace", "har" };
        double      sizes[4];

        sizes[0] = (double)text.len;
        sizes[1] = (double)shot_size;
        sizes[2] = (double)trace_size;
        sizes[3] = (double)har_size;
        tsapi_mde_mi_bars("browser", "Evidence kept on the agent",
                          TE_MI_MEAS_MEMORY, "bytes", TE_ARRAY_LEN(labels),
                          labels, sizes, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        const char *labels[BROWSER_N_NODES];
        double      counts[BROWSER_N_NODES];

        for (i = 0; i < BROWSER_N_NODES; i++)
        {
            labels[i] = browser_node_name(i);
            counts[i] = per_node[i];
        }
        tsapi_mde_mi_bars("browser", "Node steps per service",
                          TE_MI_MEAS_UNITLESS_VALUE, "steps", BROWSER_N_NODES,
                          labels, counts, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    if (tsapi_mde_mi_create("browser", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "hops", "%d", hops);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "hops", TE_MI_MEAS_AGGR_SINGLE, hops,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "observed", TE_MI_MEAS_AGGR_SINGLE, steps,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "expected", TE_MI_MEAS_AGGR_SINGLE, expected,
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
        if (have_curl_body)
        {
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "curl", TE_MI_MEAS_AGGR_SINGLE, curl_steps,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
        }
        tsapi_mde_mi_line(logger, "steps", "Node steps vs expected",
                          "hops", "observed", "expected", NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }
    tsapi_mde_mi_point("browser", "Whole walk test time", TE_MI_MEAS_TIME,
                       "elapsed", tsapi_mde_now() - t_start,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Check that the walk reached every node step");
    if (steps != expected)
    {
        TEST_VERDICT("Browser walk traced %u node step(s), expected %u",
                     steps, expected);
    }

    TEST_SUCCESS;

cleanup:

    tapi_playwright_destroy(pw);
    if (web_started)
        tsapi_mde_web_stop(&web);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&url);
    te_string_free(&text);
    te_string_free(&value_line);
    te_string_free(&curl_value);
    te_string_free(&nav);
    te_string_free(&shot_remote);
    te_string_free(&netlog);
    te_string_free(&entry);
    te_string_free(&trace_local);
    te_string_free(&har_local);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
