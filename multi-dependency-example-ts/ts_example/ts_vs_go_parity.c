/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_vs_go_parity, the TypeScript and Go services give
 *        the same answers (settles H3)
 *
 * Starts service-go on its contract port and service-ts, sends the same
 * requests to both and compares status and body byte for byte. Both replies
 * are recorded as artifacts; a difference fails the test and names the
 * request. Skipped when service-go is not built.
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
    { "no-query-hops-0",  "/ring?hops=0" },
};

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
    char                url[200];
    char                diff[400] = "";
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

    TEST_STEP("Start the Go service on its contract port %d", TSJ_GO_PORT);
    snprintf(cmd, sizeof(cmd), "cd '%s' && LD_LIBRARY_PATH='%s/dist/lib' "
             "exec dist/bin/service-go", root, root);
    CHECK_RC(tsj_start(&session, "service-go", cmd, TSJ_GO_PORT, &go));
    if (!tsj_wait_port(&session, &go, 20))
        TEST_VERDICT("H3 NOT SETTLED: service-go did not open port %d",
                     TSJ_GO_PORT);

    TEST_STEP("Start the TypeScript service");
    tsport = tsj_free_port(&session);
    if (tsport == 0)
        TEST_VERDICT("H3 NOT SETTLED: no free port on the agent");
    tsj_ts_cmd(root, tsport, cmd, sizeof(cmd));
    CHECK_RC(tsj_start(&session, "service-ts", cmd, tsport, &ts));
    if (!tsj_wait_port(&session, &ts, 20))
        TEST_VERDICT("H3 FAILED: service-ts did not open its port");

    for (i = 0; i < TE_ARRAY_LEN(reqs); i++)
    {
        bool same;

        TEST_STEP("Send %s to both services", reqs[i].name);
        snprintf(url, sizeof(url), "http://127.0.0.1:%d%s", TSJ_GO_PORT,
                 reqs[i].target);
        CHECK_RC(web_get(&session, "", url, 5, &rg));
        snprintf(url, sizeof(url), "http://127.0.0.1:%u%s", tsport,
                 reqs[i].target);
        CHECK_RC(web_get(&session, "", url, 5, &rt));
        TEST_ARTIFACT("H3 %s go: HTTP %d [%.300s]", reqs[i].name, rg.code,
                      web_str(&rg.body));
        TEST_ARTIFACT("H3 %s ts: HTTP %d [%.300s]", reqs[i].name, rt.code,
                      web_str(&rt.body));
        same = rg.code == rt.code &&
               strlen(web_str(&rg.body)) == strlen(web_str(&rt.body)) &&
               memcmp(web_str(&rg.body), web_str(&rt.body),
                      strlen(web_str(&rg.body))) == 0;
        if (!same)
        {
            if (diff[0] != '\0')
                te_strlcat(diff, ", ", sizeof(diff));
            te_strlcat(diff, reqs[i].name, sizeof(diff));
        }
    }

    TEST_STEP("A difference fails the test and names the request");
    if (diff[0] != '\0')
        TEST_VERDICT("H3 FAILED: the Go and TypeScript services answer "
                     "differently for: %s", diff);

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
