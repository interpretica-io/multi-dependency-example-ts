/** @file
 * @brief AI Group
 *
 * A vision model reads the browser's screenshot of a web tier walk and
 * counts its node lines; the count must equal the suite's own parse of
 * the page text behind the same screenshot. The screenshot and the text
 * the browser group kept (/tmp/mde-browser-walk-h5.{png,txt}) are reused
 * when they are there; otherwise this test makes them itself.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "ai/grade_screenshot"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tapi_ai.h"
#include "tapi_ai_file.h"
#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"
#include "tsapi_mde_report.h"
#include "tsapi_mde_web.h"
#include "ai_common.h"
#include "../browser/browser_common.h"

/* Hop budget of the walk shown. */
#define SHOT_HOPS   5

/* What the browser group keeps. */
#define SHOT_PNG    "/tmp/mde-browser-walk-h5.png"
#define SHOT_TXT    "/tmp/mde-browser-walk-h5.txt"

/* What this test makes when those are missing. */
#define OWN_PNG     "/tmp/mde-ai-walk-h5.png"
#define OWN_TXT     "/tmp/mde-ai-walk-h5.txt"

static const char shot_system[] =
    "You read screenshots exactly as they are and answer with one JSON "
    "object and nothing else.";

static const char shot_prompt[] =
    "The image is a browser screenshot of a plain-text web page. Count the "
    "lines that start with \"[gateway-rs]\", \"[service-go]\" or "
    "\"[service-cs]\" immediately followed by \"hops=\" - lines such as "
    "\"[gateway-rs] upstream ... unreachable\" do not count. Answer with "
    "this JSON object only: {\"node_lines\": <count>, \"value_line\": "
    "\"<the full line that starts with value=, as shown>\"}";

/* Make the screenshot and the text with Chromium. */
static void
shot_make(tsapi_mde_session *session, const tsapi_mde_dut *dut,
          tsapi_mde_web *web, bool *web_started, tapi_playwright **pw,
          te_string *text)
{
    te_string           url = TE_STRING_INIT;
    te_string           remote = TE_STRING_INIT;
    tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

    if (!tsapi_mde_web_built(session, dut))
        TEST_SKIP("No kept screenshot and the web tier is not built");
    browser_skip_unless_ready(session);

    *web_started = true;
    CHECK_RC(tsapi_mde_web_start(session, dut, web));
    browser_open(session, false, false, false, pw);

    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, SHOT_HOPS, &url);
    CHECK_RC(tapi_playwright_goto(*pw, url.ptr));
    CHECK_RC(tapi_playwright_get_text(*pw, "body", text));
    CHECK_RC(browser_screenshot_ta(*pw, session->ta, "ai-walk", &remote));
    CHECK_RC(tsapi_mde_sh(session, 30000, &sh, "mv -f '%s' '" OWN_PNG "'",
                          remote.ptr));
    if (!tsapi_mde_sh_ok(&sh))
        TEST_FAIL("Cannot move the screenshot to " OWN_PNG);
    CHECK_RC(tapi_file_create_ta(session->ta, OWN_TXT, "%s", text->ptr));

    tsapi_mde_sh_result_free(&sh);
    te_string_free(&url);
    te_string_free(&remote);
}

int
main(int argc, char **argv)
{
    tapi_ai_provider       provider = TAPI_AI_ANTHROPIC;
    tapi_cybersec_severity min_severity;
    tsapi_mde_session      session;
    bool                   session_up = false;
    tsapi_mde_dut          dut;
    tsapi_mde_web          web;
    bool                   web_started = false;
    tapi_playwright       *pw = NULL;
    tapi_ai_conn           conn;
    bool                   conn_up = false;
    tapi_ai_opts           opts = TAPI_AI_OPTS_INIT;
    tapi_ai_reply          reply;
    te_string              model = TE_STRING_INIT;
    te_string              text = TE_STRING_INIT;
    te_string              value_line = TE_STRING_INIT;
    te_string              obj = TE_STRING_INIT;
    te_string              model_value = TE_STRING_INIT;
    te_string              sha = TE_STRING_INIT;
    tsapi_mde_sh_result    sh = TSAPI_MDE_SH_RESULT_INIT;
    tsapi_mde_report       report;
    const char            *png = SHOT_PNG;
    bool                   reused = false;
    unsigned int           n_lines;
    unsigned int           width = 0;
    unsigned int           height = 0;
    unsigned long          size = 0;
    long                   model_lines = -1;
    double                 t0;
    double                 secs;

    TEST_START;
    memset(&dut, 0, sizeof(dut));
    memset(&web, 0, sizeof(web));
    memset(&conn, 0, sizeof(conn));
    memset(&reply, 0, sizeof(reply));
    tsapi_mde_report_init(&report);

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(provider, AI_PROVIDER_MAPPING_LIST);
    TEST_GET_MDE_SEVERITY(min_severity);

    TEST_STEP("Open a session, locate the example, connect to the model");
    TSAPI_MDE_OPEN_OR_SKIP(session, "ai_shot", dut, session_up);
    if (!tapi_ai_supports(provider, TAPI_AI_FEAT_IMAGE))
        TEST_SKIP("The provider takes no images");
    ai_open(&session, provider, &conn, &conn_up, &model);
    opts.model = model.len > 0 ? model.ptr : NULL;
    opts.json_mode = true;
    opts.temperature_pct = 0;
    opts.max_tokens = 300;

    TEST_STEP("Take the browser's screenshot and the text behind it");
    if (tsapi_mde_exists(&session, SHOT_PNG) &&
        tsapi_mde_exists(&session, SHOT_TXT))
    {
        CHECK_RC(tsapi_mde_sh(&session, 30000, &sh, "cat '" SHOT_TXT "'"));
        if (tsapi_mde_sh_ok(&sh) && sh.out.ptr != NULL)
        {
            te_string_append(&text, "%s", sh.out.ptr);
            reused = true;
        }
    }
    if (!reused)
    {
        png = OWN_PNG;
        shot_make(&session, &dut, &web, &web_started, &pw, &text);
    }
    if (!browser_png_dims(&session, png, &width, &height))
        TEST_VERDICT("The screenshot to grade is not a PNG image");
    if (browser_file_evidence(&session, png, &size, &sha))
    {
        TEST_ARTIFACT("Screenshot %s (%s): %ux%u, %lu bytes, sha256 %s", png,
                      reused ? "kept by the browser group" : "made here",
                      width, height, size, sha.ptr);
    }

    TEST_STEP("The suite's own reading of the page text");
    n_lines = browser_count_nodes(text.ptr != NULL ? text.ptr : "", NULL);
    browser_value_line(text.ptr != NULL ? text.ptr : "", &value_line);
    TEST_ARTIFACT("Suite's parse: %u node line(s), '%s'", n_lines,
                  value_line.ptr != NULL ? value_line.ptr : "");

    TEST_STEP("Ask the vision model to read the screenshot");
    t0 = tsapi_mde_now();
    ai_check_rc(tapi_ai_ask_with_file(&conn, shot_system, shot_prompt, png,
                                      "image/png", &opts, AI_TIMEOUT_MS,
                                      &reply), "Asking about the screenshot");
    secs = tsapi_mde_now() - t0;
    tapi_ai_reply_log(&reply);
    ai_chart_cost("screenshot", secs, &reply.usage);

    if (!ai_json_object(reply.text, &obj) ||
        !ai_json_int(obj.ptr, "node_lines", &model_lines))
    {
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "ai.bad-json", "screenshot",
                                 "the model did not answer with the JSON "
                                 "object asked for");
    }
    else
    {
        ai_json_str(obj.ptr, "value_line", &model_value);
        TEST_ARTIFACT("Model's reading: %ld node line(s), '%s'", model_lines,
                      model_value.ptr != NULL ? model_value.ptr : "");
        if (model_lines != (long)n_lines)
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_LOW,
                                     "ai.disagrees", "screenshot/node_lines",
                                     "the model sees %ld node line(s), the "
                                     "page text has %u", model_lines,
                                     n_lines);
        }
        if (value_line.ptr != NULL &&
            (model_value.ptr == NULL ||
             strcmp(model_value.ptr, value_line.ptr) != 0))
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "ai.disagrees", "screenshot/value_line",
                                     "the model reads '%s', the page text "
                                     "says '%s'",
                                     model_value.ptr != NULL ?
                                         model_value.ptr : "",
                                     value_line.ptr);
        }
    }

    TEST_STEP("Chart the two readings");
    {
        const char *labels[] = { "page text", "vision model" };
        double      vals[2];

        vals[0] = n_lines;
        vals[1] = model_lines;
        tsapi_mde_mi_bars("ai", "Node lines: page text vs screenshot",
                          TE_MI_MEAS_UNITLESS_VALUE, "lines",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "ai", min_severity);

    TEST_SUCCESS;

cleanup:

    tapi_ai_reply_free(&reply);
    if (conn_up)
        tapi_ai_conn_fini(&conn);
    tapi_playwright_destroy(pw);
    if (web_started)
        tsapi_mde_web_stop(&web);
    tsapi_mde_sh_result_free(&sh);
    te_string_free(&model);
    te_string_free(&text);
    te_string_free(&value_line);
    te_string_free(&obj);
    te_string_free(&model_value);
    te_string_free(&sha);
    tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
