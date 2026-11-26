/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_serve_http, `guess serve` answers GET /ring
 *        (settles H3)
 *
 * Starts `./scripts/run.sh guess serve` as a job with RING_HOST and
 * RING_PORT set, sends a valid GET /ring (200) and hops=65 (400 with a body
 * starting with "error:"), and stops the job.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_serve_http"

#include "tsg.h"

/** NULL when @p code and @p body are the documented answer. */
static const char *
judge(int code, const char *body, int want, const char *prefix)
{
    if (code != want)
        return "wrong status";
    if (prefix != NULL && strncmp(body, prefix, strlen(prefix)) != 0)
        return "wrong body start";
    return NULL;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                up = false;
    tsj_svc             svc = { .job = NULL };
    web_reply           reply = WEB_REPLY_INIT;
    char                cmd[500];
    char                url[200];
    const char         *root;
    const char         *why;
    unsigned int        port;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_serve_http"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H3 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the judge rejects planted wrong replies");
    if (judge(200, "error: x\n", 400, "error:") == NULL ||
        judge(400, "oops\n", 400, "error:") == NULL ||
        judge(400, "error: x\n", 400, "error:") != NULL ||
        judge(200, "[x]\n", 200, NULL) != NULL)
        TEST_VERDICT("H3 NOT SETTLED: the reply judge is wrong");

    TSG_NEED_NODE(session);

    TEST_STEP("Start `guess serve` as a job");
    port = tsj_free_port(&session);
    if (port == 0)
        TEST_VERDICT("H3 NOT SETTLED: no free port on the agent");
    snprintf(cmd, sizeof(cmd), "cd '%s' && RING_HOST=127.0.0.1 RING_PORT=%u "
             "exec ./scripts/run.sh guess serve", root, port);
    CHECK_RC(tsj_start(&session, "guess-serve", cmd, port, &svc));
    if (!tsj_wait_port(&session, &svc, 600))
        TEST_VERDICT("H3 FAILED: `guess serve` did not open its port");

    TEST_STEP("Known-good: a valid GET /ring answers 200");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=42&hops=3",
             port);
    CHECK_RC(web_get(&session, "", url, 5, &reply));
    tsj_art_reply("H3", "valid query", reply.code, web_str(&reply.body));
    why = judge(reply.code, web_str(&reply.body), 200, NULL);
    if (why != NULL)
        TEST_VERDICT("H3 FAILED: a valid GET /ring: %s (want 200)", why);

    TEST_STEP("Known-bad: hops=65 answers 400 with an error: body");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=1&hops=65",
             port);
    CHECK_RC(web_get(&session, "", url, 5, &reply));
    tsj_art_reply("H3", "hops=65", reply.code, web_str(&reply.body));
    why = judge(reply.code, web_str(&reply.body), 400, "error:");
    if (why != NULL)
        TEST_VERDICT("H3 FAILED: hops=65: %s (want 400 and a body "
                     "starting with 'error:')", why);

    TEST_ARTIFACT("H3 guess serve answers 200 to a valid query and 400 "
                  "with an error: body to hops=65");
    TEST_SUCCESS;

cleanup:
    tsj_stop(&svc);
    te_string_free(&reply.body);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
