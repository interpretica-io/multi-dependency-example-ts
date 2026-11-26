/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_service_contract, web/service-ts answers on its port
 *        (settles H2)
 *
 * Starts web/service-ts as a job, waits for the port, sends one request and
 * checks status and body against the contract, records the reply, then
 * sends malformed requests (a bad value, a bad request target): an error
 * reply and a live process are expected. The listener must be on loopback
 * only. The job is stopped at the end.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_service_contract"

#include "tsj.h"

/** NULL when the reply follows the contract of GET /ring?value=42&hops=0. */
static const char *
good_reply(int code, const char *body)
{
    if (code != 200)
        return "status is not 200";
    if (strncmp(body, "[service-ts] hops=0 ", 20) != 0)
        return "no stage line";
    if (strstr(body, "\nvalue=34.5\n") == NULL)
        return "value is not 34.5";
    return NULL;
}

/** NULL when the reply is the documented error answer. */
static const char *
error_reply(int code, const char *body)
{
    if (code != 400)
        return "status is not 400";
    if (strncmp(body, "error:", 6) != 0)
        return "no error line";
    return NULL;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                up = false;
    tsj_svc             svc = { .job = NULL };
    web_reply           reply = WEB_REPLY_INIT;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    char                cmd[700];
    char                url[200];
    const char         *root;
    const char         *why;
    unsigned int        port;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_service_contract"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H2 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the checks reject planted wrong replies");
    if (good_reply(200, "value=34.5\n") == NULL ||
        good_reply(500, "[service-ts] hops=0 x\nvalue=34.5\n") == NULL ||
        good_reply(200, "[service-ts] hops=0 x\nvalue=35\n") == NULL ||
        good_reply(200, "[service-ts] hops=0 x\nvalue=34.5\n") != NULL ||
        error_reply(200, "error: x\n") == NULL ||
        error_reply(400, "oops\n") == NULL ||
        error_reply(400, "error: x\n") != NULL)
        TEST_VERDICT("H2 NOT SETTLED: the reply checks accepted a planted "
                     "wrong reply or rejected a planted good one");

    TEST_STEP("Skip when node or the compiled service is missing");
    if (!tsapi_mde_have(&session, "node"))
        TEST_SKIP("node is not on the agent and the setup script could not "
                  "install it");
    snprintf(cmd, sizeof(cmd), "test -f '%s/web/service-ts/out/main.js'", root);
    if (!tsj_ok(&session, 10000, cmd))
        TEST_VERDICT("H2 FAILED: web/service-ts/out/main.js is not built "
                     "by ./build.sh");

    TEST_STEP("Start web/service-ts as a job");
    port = tsj_free_port(&session);
    if (port == 0)
        TEST_VERDICT("H2 NOT SETTLED: no free port on the agent");
    tsj_ts_cmd(root, port, cmd, sizeof(cmd));
    CHECK_RC(tsj_start(&session, "service-ts", cmd, port, &svc));
    if (!tsj_wait_port(&session, &svc, 20))
        TEST_VERDICT("H2 FAILED: service-ts did not open its port");

    TEST_STEP("Send one valid request and check status and body");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=42&hops=0",
             port);
    CHECK_RC(web_get(&session, "", url, 5, &reply));
    TEST_ARTIFACT("H2 reply to value=42 hops=0: HTTP %d [%.300s]", reply.code,
                  web_str(&reply.body));
    why = good_reply(reply.code, web_str(&reply.body));
    if (why != NULL)
        TEST_VERDICT("H2 FAILED: the reply to a valid request breaks the "
                     "contract: %s", why);

    TEST_STEP("Known-bad control: a bad value gets an error reply");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=abc&hops=0",
             port);
    CHECK_RC(web_get(&session, "", url, 5, &reply));
    TEST_ARTIFACT("H2 reply to value=abc: HTTP %d [%.200s]", reply.code,
                  web_str(&reply.body));
    why = error_reply(reply.code, web_str(&reply.body));
    if (why != NULL)
        TEST_VERDICT("H2 FAILED: a bad value is not answered with an "
                     "error: %s", why);

    TEST_STEP("Known-bad control: a malformed request target");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u//x", port);
    CHECK_RC(web_get(&session, "--path-as-is", url, 5, &reply));
    TEST_ARTIFACT("H2 reply to //x: HTTP %d [%.200s]", reply.code,
                  web_str(&reply.body));
    why = error_reply(reply.code, web_str(&reply.body));
    if (why != NULL)
        TEST_VERDICT("H2 FAILED: a malformed target is not answered with "
                     "an error: %s", why);

    TEST_STEP("The service survived the malformed requests");
    if (!tsj_running(&svc))
        TEST_VERDICT("H2 FAILED: service-ts crashed on a malformed request");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=42&hops=0",
             port);
    CHECK_RC(web_get(&session, "", url, 5, &reply));
    if (good_reply(reply.code, web_str(&reply.body)) != NULL)
        TEST_VERDICT("H2 FAILED: service-ts does not answer correctly after "
                     "malformed requests");

    TEST_STEP("The listener is bound to loopback only");
    CHECK_RC(tsapi_mde_sh(&session, 15000, &res, "ss -ltnH"));
    snprintf(url, sizeof(url), ":%u ", port);
    tsj_log_text("listeners", web_str(&res.out));
    {
        const char *l = strstr(web_str(&res.out), url);

        if (l == NULL)
            TEST_VERDICT("H2 NOT SETTLED: ss does not show the listener");
        while (l > web_str(&res.out) && l[-1] != ' ')
            l--;
        if (strncmp(l, "127.0.0.1:", 10) != 0)
            TEST_VERDICT("H2 FAILED: service-ts listens on more than "
                         "loopback");
    }
    TEST_ARTIFACT("H2 service-ts answered on its port, rejected bad input "
                  "and listens on loopback only");

    TEST_SUCCESS;

cleanup:
    tsj_stop(&svc);
    te_string_free(&reply.body);
    tsapi_mde_sh_result_free(&res);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
