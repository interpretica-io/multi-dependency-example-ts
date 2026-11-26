/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_vs_go_parity, each service against its own contract
 *        (settles H6 and H7)
 *
 * Starts service-go and service-ts, polls each port (20 tries, 0.5 s apart),
 * and checks service-ts only against its contract: 200 with value 3.7500 for
 * value=1 hops=0, 400 for value=abc, 400 for hops=65 and hops=abc. The Go
 * status and value of each case, and the TS status of the no-query case, are
 * recorded as artifacts only: Go answering 200 on bad input (H7) is a known
 * difference outside the TypeScript goal. A closed port is the known-bad
 * control (curl exit 7). Skipped when service-go is not built.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_vs_go_parity"

#include "tsj.h"

static const struct {
    const char *name;
    const char *target;
    int         want;       /* TS status, 0 when only recorded */
} reqs[] = {
    { "good",        "/ring?value=1&hops=0",   200 },
    { "bad-value",   "/ring?value=abc&hops=0", 400 },
    { "hops-65",     "/ring?value=1&hops=65",  400 },
    { "bad-hops",    "/ring?value=1&hops=abc", 400 },
    { "no-query",    "/ring",                  0 },
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

/** Poll the port up to 20 tries, 0.5 s apart; true when it answers. */
static bool
poll_port(tsapi_mde_session *s, tsj_svc *svc, unsigned int port)
{
    web_reply reply = WEB_REPLY_INIT;
    int       i;
    bool      up = false;

    for (i = 0; i < 20 && !up; i++)
    {
        if (!tsj_running(svc))
            break;
        if (probe(s, port, "/ring?value=1&hops=0", &reply) != CONN_FAILED)
            up = true;
        else
            usleep(500000);
    }
    te_string_free(&reply.body);
    return up;
}

/** The value line of a reply, copied into @p out; empty when none. */
static const char *
value_of(const char *body, char *out, size_t size)
{
    const char *p = strstr(body, "value=");
    size_t      n = 0;

    out[0] = '\0';
    if (p == NULL)
        return out;
    for (p += 6; n + 1 < size && *p != '\0' && *p != '\n'; p++)
        out[n++] = *p;
    out[n] = '\0';
    return out;
}

/** Whether a good TS body carries the value 3.7500. */
static bool
is_good_value(const char *body)
{
    char v[64];

    return strcmp(value_of(body, v, sizeof(v)), "3.7500") == 0 ||
           strstr(body, "\"value\":3.7500") != NULL ||
           strstr(body, "\"value\": 3.7500") != NULL;
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
    char                val[64];
    tsapi_mde_sh_result cres = TSAPI_MDE_SH_RESULT_INIT;
    const char         *root;
    unsigned int        tsport;
    size_t              i;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_vs_go_parity"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H6 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the value check rejects planted wrong replies");
    if (!is_good_value("[service-ts] hops=0 x\nvalue=3.7500\n") ||
        is_good_value("[service-ts] hops=0 x\nvalue=6.2400\n") ||
        is_good_value("error: bad\n"))
        TEST_VERDICT("H6 NOT SETTLED: the value check accepted a planted "
                     "wrong reply or rejected a planted good one");

    TEST_STEP("Skip when node or the Go service is missing");
    if (!tsapi_mde_have(&session, "node"))
        TEST_SKIP("node is not on the agent and the setup script could not "
                  "install it");
    snprintf(cmd, sizeof(cmd), "test -x '%s/dist/bin/service-go'", root);
    if (!tsj_ok(&session, 10000, cmd))
        TEST_SKIP("The Go service is not built (dist/bin/service-go)");
    snprintf(cmd, sizeof(cmd), "test -f '%s/web/service-ts/out/main.js'", root);
    if (!tsj_ok(&session, 10000, cmd))
        TEST_VERDICT("H6 FAILED: web/service-ts/out/main.js is not built "
                     "by ./build.sh");

    TEST_STEP("Known-bad control: a closed port is a connection failure");
    {
        unsigned int closed = tsj_free_port(&session);

        if (closed == 0)
            TEST_VERDICT("H6 NOT SETTLED: no free port on the agent");
        if (probe(&session, closed, "/ring?value=1&hops=0", &rg) !=
            CONN_FAILED)
            TEST_VERDICT("H6 NOT SETTLED: a request to a closed port was "
                         "not reported as a connection failure");
        CHECK_RC(tsapi_mde_sh(&session, 20000, &cres,
                              "curl -sS --max-time 3 'http://127.0.0.1:%u/'",
                              closed));
        if (cres.status.type != TAPI_JOB_STATUS_EXITED ||
            cres.status.value != 7)
            TEST_VERDICT("H6 NOT SETTLED: curl to a closed port did not "
                         "exit with code 7");
        TEST_ARTIFACT("H6 control: a request to a closed port is reported "
                      "as a connection failure (curl exit 7)");
    }

    TEST_STEP("Start the Go service on its contract port %d", TSJ_GO_PORT);
    snprintf(cmd, sizeof(cmd), "cd '%s' && LD_LIBRARY_PATH='%s/dist/lib' "
             "exec dist/bin/service-go", root, root);
    CHECK_RC(tsj_start(&session, "service-go", cmd, TSJ_GO_PORT, &go));

    TEST_STEP("Start the TypeScript service");
    tsport = tsj_free_port(&session);
    if (tsport == 0)
        TEST_VERDICT("H6 NOT SETTLED: no free port on the agent");
    tsj_ts_cmd(root, tsport, cmd, sizeof(cmd));
    CHECK_RC(tsj_start(&session, "service-ts", cmd, tsport, &ts));

    TEST_STEP("Wait for both ports before the first request");
    if (!poll_port(&session, &ts, tsport))
        TEST_VERDICT("H6 FAILED: service-ts did not open its port within "
                     "10 s (20 tries)");
    if (!poll_port(&session, &go, TSJ_GO_PORT))
        TEST_VERDICT("H6 NOT SETTLED: service-go did not open port %d "
                     "within 10 s", TSJ_GO_PORT);

    for (i = 0; i < TE_ARRAY_LEN(reqs); i++)
    {
        int         ct;
        const char *why = NULL;
        char        one[200];

        TEST_STEP("Send %s to both services", reqs[i].name);
        (void)probe(&session, TSJ_GO_PORT, reqs[i].target, &rg);
        ct = probe(&session, tsport, reqs[i].target, &rt);
        TEST_ARTIFACT("H7 go %s: status %d value [%s] (recorded only)",
                      reqs[i].name, rg.code,
                      value_of(web_str(&rg.body), val, sizeof(val)));
        snprintf(one, sizeof(one), "%s ts", reqs[i].name);
        tsj_art_reply("H6", one, rt.code, web_str(&rt.body));
        if (reqs[i].want == 0)
        {
            TEST_ARTIFACT("H6 ts %s: status %d (recorded only)",
                          reqs[i].name, ct);
            continue;
        }
        if (ct == CONN_FAILED)
            why = "connection failure";
        else if (ct != reqs[i].want)
            why = "wrong status";
        else if (ct == 200 && !is_good_value(web_str(&rt.body)))
            why = "value is not 3.7500";
        if (why != NULL)
        {
            char item[160];

            snprintf(item, sizeof(item), "H6 ts contract broken for %s: "
                     "%s, want %d", reqs[i].name, why, reqs[i].want);
            if (diff[0] != '\0')
                te_strlcat(diff, "; ", sizeof(diff));
            te_strlcat(diff, item, sizeof(diff));
        }
    }

    TEST_STEP("A broken contract fails the test and names the request");
    if (diff[0] != '\0')
        TEST_VERDICT("%s", diff);

    TEST_ARTIFACT("H6 service-ts keeps its contract: 200 with 3.7500 for "
                  "value=1 hops=0, 400 for bad value and bad hops");
    TEST_SUCCESS;

cleanup:
    tsj_stop(&ts);
    tsj_stop(&go);
    tsapi_mde_sh_result_free(&cres);
    te_string_free(&rg.body);
    te_string_free(&rt.body);
    if (up)
        tsapi_mde_session_fini(&session);
    TEST_END;
}
