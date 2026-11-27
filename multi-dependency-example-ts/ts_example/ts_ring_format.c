/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: ts_ring_format, the ts server answers GET /ring in the
 *        format of service-go (settles H3)
 *
 * Starts `guess serve` (the ts server) and service-go, sends GET /ring with
 * no query to each with tapi_http (web_get), and compares the field names
 * (the "hops=" stage lines and the "value=" line) and the defaults (the
 * first stage line carries hops=6 and the input 1.0). Skipped when node or
 * service-go is missing. Control: the extractor rejects planted wrong text.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "ts_example/ts_ring_format"

#include <math.h>
#include "tsg.h"

/** Fields of one /ring reply. */
typedef struct fields {
    bool    has_value;      /**< a "value=" line */
    bool    has_stage;      /**< a "hops=" stage line */
    int     hops;           /**< the hops of the first stage line, -1 if none */
    double  input;          /**< the input of the first stage line */
} fields;

/** Parse the first stage line and the value line of @p body. */
static void
parse(const char *body, fields *f)
{
    const char *p = strstr(body, "hops=");
    char       *end = NULL;

    f->has_value = strstr(body, "\nvalue=") != NULL ||
                   strncmp(body, "value=", 6) == 0;
    f->has_stage = p != NULL;
    f->hops = -1;
    f->input = NAN;
    if (p == NULL)
        return;
    f->hops = (int)strtol(p + 5, &end, 10);
    f->input = strtod(end, NULL);
}

/** NULL when @p f has the default format; else what is wrong. */
static const char *
check_default(const fields *f)
{
    if (!f->has_stage)
        return "no hops= stage line";
    if (!f->has_value)
        return "no value= line";
    if (f->hops != 6)
        return "default hops is not 6";
    if (isnan(f->input) || fabs(f->input - 1.0) > 0.0001)
        return "default value is not 1.0";
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
    fields              fg;
    fields              ft;
    char                cmd[800];
    char                url[200];
    const char         *root;
    const char         *why;
    unsigned int        tsport;

    TEST_START;

    TEST_STEP("Open a session and locate the project");
    CHECK_RC(tsapi_mde_session_init(&session, "ts_ring_format"));
    up = true;
    root = tsj_root();
    if (root == NULL)
        TEST_VERDICT("H3 NOT SETTLED: TE_TS_MDE_SRC is not set");

    TEST_STEP("Control: the format check rejects planted wrong replies");
    parse("[s] hops=6      1.0000 -> 3.7500\nvalue=3.75\n", &ft);
    if (check_default(&ft) != NULL)
        TEST_VERDICT("H3 NOT SETTLED: the check rejects a planted good "
                     "reply");
    parse("[s] hops=5      1.0000 -> 3.7500\nvalue=3.75\n", &ft);
    if (check_default(&ft) == NULL)
        TEST_VERDICT("H3 NOT SETTLED: the check accepts hops=5");
    parse("[s] hops=6      2.0000 -> 3.7500\nvalue=3.75\n", &ft);
    if (check_default(&ft) == NULL)
        TEST_VERDICT("H3 NOT SETTLED: the check accepts a default of 2.0");
    parse("[s] hops=6      1.0000 -> 3.7500\nresult=3.75\n", &ft);
    if (check_default(&ft) == NULL)
        TEST_VERDICT("H3 NOT SETTLED: the check accepts a renamed field");

    TSG_NEED_NODE(session);
    snprintf(cmd, sizeof(cmd), "test -x '%s/dist/bin/service-go'", root);
    if (!tsj_ok(&session, 10000, cmd))
        TEST_SKIP("The Go service is not built (dist/bin/service-go)");

    TEST_STEP("Start the Go service on its contract port %d", TSJ_GO_PORT);
    snprintf(cmd, sizeof(cmd), "cd '%s' && LD_LIBRARY_PATH='%s/dist/lib' "
             "exec dist/bin/service-go", root, root);
    CHECK_RC(tsj_start(&session, "service-go", cmd, TSJ_GO_PORT, &go));

    TEST_STEP("Start the ts server (guess serve)");
    tsport = tsj_free_port(&session);
    if (tsport == 0)
        TEST_VERDICT("H3 NOT SETTLED: no free port on the agent");
    snprintf(cmd, sizeof(cmd), "cd '%s' && RING_HOST=127.0.0.1 RING_PORT=%u "
             "exec ./scripts/run.sh guess serve", root, tsport);
    CHECK_RC(tsj_start(&session, "guess-serve", cmd, tsport, &ts));
    if (!tsj_wait_port(&session, &ts, 600))
        TEST_VERDICT("H3 FAILED: the ts server did not open its port");
    if (!tsj_wait_port(&session, &go, 60))
        TEST_VERDICT("H3 NOT SETTLED: service-go did not open port %d",
                     TSJ_GO_PORT);

    TEST_STEP("GET /ring on both servers with tapi_http");
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring", TSJ_GO_PORT);
    CHECK_RC(web_get(&session, "", url, 5, &rg));
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/ring", tsport);
    CHECK_RC(web_get(&session, "", url, 5, &rt));
    tsj_art_reply("H3", "go /ring", rg.code, web_str(&rg.body));
    tsj_art_reply("H3", "ts /ring", rt.code, web_str(&rt.body));
    if (rg.code != 200)
        TEST_VERDICT("H3 NOT SETTLED: service-go did not answer 200 to "
                     "GET /ring");
    if (rt.code != 200)
        TEST_VERDICT("H3 FAILED: the ts server did not answer 200 to "
                     "GET /ring");

    TEST_STEP("Compare the field names and the default values");
    parse(web_str(&rg.body), &fg);
    parse(web_str(&rt.body), &ft);
    why = check_default(&fg);
    if (why != NULL)
        TEST_VERDICT("H3 NOT SETTLED: the Go reference does not show the "
                     "default format: %s", why);
    why = check_default(&ft);
    if (why != NULL)
        TEST_VERDICT("H3 FAILED: the ts reply differs from service-go: %s",
                     why);

    TEST_ARTIFACT("H3 the ts server answers GET /ring with the same field "
                  "names (hops=, value=) and defaults (1.0, 6) as "
                  "service-go");
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
