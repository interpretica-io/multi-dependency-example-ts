/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_vs_go_parity, the TypeScript and Go services keep
 *        the same contract (settles H3)
 *
 * Starts service-go on its contract port and service-ts, waits for each port
 * with a retry loop (up to 10 s, 100 ms apart), sends the same requests to
 * both and records both status codes and both bodies as artifacts. Only the
 * status code class (2xx or 4xx) and the shape of a good reply (a stage tag
 * in brackets, "hops=N", a "value=" line) are compared; the formula, the
 * stage tag name and the number differ by design. A known-bad control sends a
 * request to a closed port: the same helper must report a connection
 * failure. Skipped when service-go is not built.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_vs_go_parity"

#include "tsj.h"

static const struct {
    const char *name;
    const char *target;
} reqs[] = {
    { "value-42-hops-0",  "/ring?value=42&hops=0" },
    { "value-1-hops-0",   "/ring?value=1&hops=0" },
    { "value-neg-hops-0", "/ring?value=-3.5&hops=0" },
    { "bad-value",        "/ring?value=abc&hops=0" },
    { "bad-hops",         "/ring?value=1&hops=abc" },
    { "no-query",         "/ring" },
};

#define CONN_FAILED     (-1)

/** Send GET @p target to 127.0.0.1:@p port; the HTTP code or CONN_FAILED. */
static int
probe(tsapi_mde_session *s, unsigned int port, const char *target,
      web_reply *reply)
{
    char url[200];

    snprintf(url, sizeof(url), "http://127.0.0.1:%u%s", port, target);
    if (web_get(s, "", url, 5, reply) != 0 || reply->code == 0)
        return CONN_FAILED;
    return reply->code;
}

/** Poll the port up to 10 s, 100 ms apart; true when it answers. */
static bool
poll_port(tsapi_mde_session *s, tsj_svc *svc, unsigned int port)
{
    web_reply reply = WEB_REPLY_INIT;
    int       i;
    bool      up = false;

    for (i = 0; i < 100 && !up; i++)
    {
        if (!tsj_running(svc))
            break;
        if (probe(s, port, "/ring?value=1&hops=0", &reply) != CONN_FAILED)
            up = true;
        else
            usleep(100000);
    }
    te_string_free(&reply.body);
    return up;
}

/** NULL when @p body has the shape of a good reply. */
static const char *
good_shape(const char *body)
{
    const char *o = strchr(body, '[');
    const char *c = o != NULL ? strchr(o, ']') : NULL;
    const char *h = strstr(body, "hops=");

    if (o == NULL || c == NULL || c - o < 2)
        return "no stage tag in brackets";
    if (h == NULL || h[5] < '0' || h[5] > '9')
        return "no hops=N";
    if (strncmp(body, "value=", 6) != 0 && strstr(body, "\nvalue=") == NULL)
        return "no value= line";
    return NULL;
}

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                up = false;
    tsj_svc             go = { .job = NULL };
    tsj_svc             ts = { .job = NULL };
    web_reply           rg = WEB_REPLY_INIT;
    web_reply           rt = WEB_REPLY_INIT;
    char                cmd[800];
    char                diff[900] = "";
    const char         *root;
    unsigned int        tsport;
    size_t              i;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_vs_go_parity"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H3 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the shape check rejects planted wrong replies");
    if (good_shape("[service-x] hops=0 1.0000 -> 2.0000 f\nvalue=2\n") != NULL ||
        good_shape("service hops=0\nvalue=2\n") == NULL ||
        good_shape("[a] 1.0\nvalue=2\n") == NULL ||
        good_shape("[a] hops=0 1.0\n") == NULL ||
        good_shape("error: bad\n") == NULL)
        TEST_VERDICT("H3 NOT SETTLED: the reply shape check accepted a "
                     "planted wrong reply or rejected a planted good one");

    TEST_STEP("Skip when node or the Go service is missing");
    if (!tsapi_mde_have(&session, "node"))
        TEST_SKIP("node is not on the agent and the setup script could not "
                  "install it");
    snprintf(cmd, sizeof(cmd), "test -x '%s/dist/bin/service-go'", root);
    if (!tsj_ok(&session, 10000, cmd))
        TEST_SKIP("The Go service is not built (dist/bin/service-go)");
    snprintf(cmd, sizeof(cmd), "test -f '%s/web/service-ts/out/main.js'", root);
    if (!tsj_ok(&session, 10000, cmd))
        TEST_VERDICT("H3 FAILED: web/service-ts/out/main.js is not built "
                     "by ./build.sh");

    TEST_STEP("Known-bad control: a closed port is a connection failure");
    {
        unsigned int closed = tsj_free_port(&session);

        if (closed == 0)
            TEST_VERDICT("H3 NOT SETTLED: no free port on the agent");
        if (probe(&session, closed, "/ring?value=1&hops=0", &rg) !=
            CONN_FAILED)
            TEST_VERDICT("H3 NOT SETTLED: a request to a closed port was "
                         "not reported as a connection failure");
        TEST_ARTIFACT("H3 control: a request to a closed port is reported "
                      "as a connection failure");
    }

    TEST_STEP("Start the Go service on its contract port %d", TSJ_GO_PORT);
    snprintf(cmd, sizeof(cmd), "cd '%s' && LD_LIBRARY_PATH='%s/dist/lib' "
             "exec dist/bin/service-go", root, root);
    CHECK_RC(tsj_start(&session, "service-go", cmd, TSJ_GO_PORT, &go));

    TEST_STEP("Start the TypeScript service");
    tsport = tsj_free_port(&session);
    if (tsport == 0)
        TEST_VERDICT("H3 NOT SETTLED: no free port on the agent");
    tsj_ts_cmd(root, tsport, cmd, sizeof(cmd));
    CHECK_RC(tsj_start(&session, "service-ts", cmd, tsport, &ts));

    TEST_STEP("Wait for both ports before the first request");
    if (!poll_port(&session, &ts, tsport))
        TEST_VERDICT("H3 FAILED: service-ts did not open its port within "
                     "10 s");
    if (!poll_port(&session, &go, TSJ_GO_PORT))
        TEST_VERDICT("H3 NOT SETTLED: service-go did not open port %d "
                     "within 10 s", TSJ_GO_PORT);

    for (i = 0; i < TE_ARRAY_LEN(reqs); i++)
    {
        int         cg;
        int         ct;
        const char *why = NULL;
        char        one[200];

        TEST_STEP("Send %s to both services", reqs[i].name);
        cg = probe(&session, TSJ_GO_PORT, reqs[i].target, &rg);
        ct = probe(&session, tsport, reqs[i].target, &rt);
        snprintf(one, sizeof(one), "%s go", reqs[i].name);
        tsj_art_reply("H3", one, rg.code, web_str(&rg.body));
        snprintf(one, sizeof(one), "%s ts", reqs[i].name);
        tsj_art_reply("H3", one, rt.code, web_str(&rt.body));
        if (cg == CONN_FAILED || ct == CONN_FAILED)
            why = "connection failure";
        else if (cg / 100 != ct / 100)
            why = "status class";
        else if (cg / 100 == 2 &&
                 (good_shape(web_str(&rg.body)) != NULL ||
                  good_shape(web_str(&rt.body)) != NULL))
            why = "reply shape";
        if (why != NULL)
        {
            char item[120];

            snprintf(item, sizeof(item), "H3 contract differs for %s: "
                     "go=%d ts=%d", reqs[i].name, rg.code, rt.code);
            RING("%s (%s)", item, why);
            if (diff[0] != '\0')
                te_strlcat(diff, "; ", sizeof(diff));
            te_strlcat(diff, item, sizeof(diff));
        }
    }

    TEST_STEP("A difference fails the test and names the request");
    if (diff[0] != '\0')
        TEST_VERDICT("%s", diff);

    TEST_ARTIFACT("H3 the Go and TypeScript services keep the same status "
                  "class and reply shape for every request");
    TEST_SUCCESS;

cleanup:
    tsj_stop(&ts);
    tsj_stop(&go);
    te_string_free(&rg.body);
    te_string_free(&rt.body);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
