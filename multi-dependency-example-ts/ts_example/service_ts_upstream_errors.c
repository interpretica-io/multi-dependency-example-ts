/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: service_ts_upstream_errors, 502 for a dead upstream and
 *        504 for a silent one (settles H4)
 *
 * Starts `./scripts/run.sh guess service-ts` as a job with
 * SERVICE_TS_UPSTREAM on a closed port (expect 502 and a JSON error field),
 * then on a listener that accepts and never replies (expect 504 after about
 * 5 s). The 504 case is skipped when python3, the listener tool, is absent.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/service_ts_upstream_errors"

#include "tsg.h"

/** NULL when the reply is @p want with a JSON "error" field. */
static const char *
judge(int code, const char *body, int want)
{
    if (code != want)
        return "wrong status";
    if (strstr(body, "{\"error\":") == NULL)
        return "no JSON error field";
    return NULL;
}

/** Start service-ts on a fresh port with the upstream @p up_port. */
static te_errno
start_service(tsapi_mde_session *s, const char *root, unsigned int up_port,
              tsj_svc *svc, unsigned int *port, bool *opened)
{
    char     cmd[600];
    te_errno rc;

    *port = tsj_free_port(s);
    if (*port == 0)
        return TE_RC(TE_TAPI, TE_ENOENT);
    snprintf(cmd, sizeof(cmd), "cd '%s' && RING_HOST=127.0.0.1 RING_PORT=%u "
             "SERVICE_TS_UPSTREAM=127.0.0.1:%u exec ./scripts/run.sh guess "
             "service-ts", root, *port, up_port);
    rc = tsj_start(s, "service-ts", cmd, *port, svc);

    if (rc != 0)
        return rc;
    *opened = tsj_wait_port(s, svc, 600);
    return 0;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                up = false;
    tsj_svc             svc = { .job = NULL };
    tsj_svc             silent = { .job = NULL };
    web_reply           reply = WEB_REPLY_INIT;
    char                cmd[500];
    char                url[200];
    const char         *root;
    const char         *why;
    unsigned int        port;
    unsigned int        dead;
    unsigned int        quiet;
    bool                opened = false;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "service_ts_upstream_errors"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H4 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the judge rejects planted wrong replies");
    if (judge(200, "{\"error\":\"x\"}", 502) == NULL ||
        judge(502, "error: x\n", 502) == NULL ||
        judge(502, "{\"error\":\"x\"}\n", 502) != NULL)
        TEST_VERDICT("H4 NOT SETTLED: the reply judge is wrong");

    TSG_NEED_NODE(session);

    TEST_STEP("Case 1: the upstream is a closed port");
    dead = tsj_free_port(&session);
    if (dead == 0)
        TEST_VERDICT("H4 NOT SETTLED: no free port on the agent");
    CHECK_RC(start_service(&session, root, dead, &svc, &port, &opened));
    if (!opened)
        TEST_VERDICT("H4 FAILED: `guess service-ts` did not open its port");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=1&hops=2",
             port);
    CHECK_RC(web_get(&session, "", url, 8, &reply));
    tsj_art_reply("H4", "closed upstream", reply.code, web_str(&reply.body));
    why = judge(reply.code, web_str(&reply.body), 502);
    if (why != NULL)
        TEST_VERDICT("H4 FAILED: closed upstream: %s (want 502 and a JSON "
                     "body with an error field)", why);
    tsj_stop(&svc);

    TEST_STEP("Case 2: the upstream accepts and never replies");
    if (!tsapi_mde_have(&session, "python3"))
    {
        TEST_ARTIFACT("H4 the 504 case is skipped: python3, the only "
                      "listener tool here, is not on the agent");
        TEST_SUCCESS;
    }
    quiet = tsj_free_port(&session);
    if (quiet == 0)
        TEST_VERDICT("H4 NOT SETTLED: no free port on the agent");
    snprintf(cmd, sizeof(cmd), "exec python3 -c \"import socket,time;"
             "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,"
             "socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',%u));s.listen(8);"
             "c=[];\nwhile True:\n c.append(s.accept()[0])\"", quiet);
    CHECK_RC(tsj_start(&session, "silent-peer", cmd, quiet, &silent));
    usleep(1000000);
    if (!tsj_running(&silent))
        TEST_VERDICT("H4 NOT SETTLED: the silent listener did not start");
    opened = false;
    CHECK_RC(start_service(&session, root, quiet, &svc, &port, &opened));
    if (!opened)
        TEST_VERDICT("H4 FAILED: `guess service-ts` did not open its port");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring?value=1&hops=2",
             port);
    CHECK_RC(web_get(&session, "", url, 15, &reply));
    tsj_art_reply("H4", "silent upstream", reply.code, web_str(&reply.body));
    TEST_ARTIFACT("H4 silent upstream answered after %d s",
                  (int)(reply.time_s + 0.5));
    why = judge(reply.code, web_str(&reply.body), 504);
    if (why != NULL)
        TEST_VERDICT("H4 FAILED: silent upstream: %s (want 504 and a JSON "
                     "body with an error field)", why);
    if (reply.time_s < 4.0 || reply.time_s > 9.0)
        TEST_VERDICT("H4 FAILED: the 504 did not come after about 5 s");

    TEST_ARTIFACT("H4 service-ts answers 502 for a closed upstream and 504 "
                  "after about 5 s for a silent one");
    TEST_SUCCESS;

cleanup:
    tsj_stop(&svc);
    tsj_stop(&silent);
    te_string_free(&reply.body);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
