/** @file
 * @brief Web Group
 *
 * Start the three HTTP services of the web tier and send one request into the
 * cycle. Correct code walks gateway-rs -> service-go -> service-cs and back,
 * tracing hops+1 node steps in the response body; the injected always-true
 * defect in each node's forward() stops the walk after the first node.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "web/cycle"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"
#include "tsapi_evo.h"
#include "tsapi_mde.h"

/* Any node's body trace line: "[service-go] hops=4 ... ". */
#define WEB_STEP_RE     "\\[(gateway-rs|service-go|service-cs)\\]\\s+hops="
/* The last body line of every node: "value=13.7925...". */
#define WEB_VALUE_RE    "value=(-?[0-9][0-9.eE+-]*)"

/* The web tier, from web/contract/services.tab. gateway-rs is the entry. */
#define WEB_GATEWAY_PORT    8081

typedef struct web_service {
    const char         *name;       /**< Binary name under dist/bin. */
    tapi_job_t         *job;        /**< Its running process. */
    tapi_job_channel_t *out[2];     /**< stdout, stderr. */
    tapi_job_channel_t *ready;      /**< Readable filter for the ready line. */
} web_service;

/* gateway-rs is the entry point; the other two complete the HTTP cycle. */
#define WEB_N_SERVICES  3

static web_service services[WEB_N_SERVICES] = {
    { .name = "gateway-rs" },
    { .name = "service-go" },
    { .name = "service-cs" },
};

/* Start one service and wait until it announces its listening URL. The Go
 * node logs that line to stderr, so the ready filter watches both channels. */
static te_errno
web_service_start(tsapi_mde_session *session, const char *dist_bin,
                  web_service *svc)
{
    te_string   program = TE_STRING_INIT;
    te_string   ready_re = TE_STRING_INIT;
    const char *argv[2];
    tapi_job_buffer_t buf = TAPI_JOB_BUFFER_INIT;
    te_errno    rc;

    te_string_append(&program, "%s/%s", dist_bin, svc->name);
    argv[0] = program.ptr;
    argv[1] = NULL;

    rc = tapi_job_create(session->factory, NULL, program.ptr, argv, NULL,
                         &svc->job);
    if (rc != 0)
        goto out;

    rc = tapi_job_alloc_output_channels(svc->job, 2, svc->out);
    if (rc != 0)
        goto out;

    /* Log everything the service prints, on both channels. */
    rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(svc->out[0], svc->out[1]),
                                "log", false, TE_LL_RING, NULL);
    if (rc != 0)
        goto out;

    /* Readable filter for the "[name] http://..." startup line. */
    rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(svc->out[0], svc->out[1]),
                                "ready", true, 0, &svc->ready);
    if (rc != 0)
        goto out;
    te_string_append(&ready_re, "\\[%s\\] http://", svc->name);
    rc = tapi_job_filter_add_regexp(svc->ready, ready_re.ptr, 0);
    if (rc != 0)
        goto out;

    rc = tapi_job_start(svc->job);
    if (rc != 0)
        goto out;

    /* Wait for the listening line; a service that never binds times out. */
    rc = tapi_job_receive(TAPI_JOB_CHANNEL_SET(svc->ready), 10000, &buf);
    if (rc != 0)
    {
        ERROR("Service '%s' did not become ready: %r", svc->name, rc);
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    }

out:
    te_string_free(&program);
    te_string_free(&ready_re);
    te_string_free(&buf.data);
    return rc;
}

static void
web_service_stop(web_service *svc)
{
    if (svc->job != NULL)
    {
        tapi_job_destroy(svc->job, -1);
        svc->job = NULL;
    }
}

int
main(int argc, char **argv)
{
    int                  hops;
    const char          *src;
    te_string            dist_bin = TE_STRING_INIT;
    te_string            url = TE_STRING_INIT;
    const char          *curl_ver[] = { "curl", "--version", NULL };
    const char          *cmd[5];
    tsapi_mde_session    session;
    bool                 session_up = false;
    tsapi_mde_run_result res;
    tsapi_evo_schart     chart;
    char                 metric[32];
    char                 xaxis[32];
    unsigned int         expected;
    size_t               i;
    bool                 started[WEB_N_SERVICES] = { false };

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_INT_PARAM(hops);

    TEST_STEP("Locate the example under test");
    src = tsapi_mde_src();
    if (src == NULL)
        TEST_SKIP("TE_TS_MDE_SRC is not set");
    te_string_append(&dist_bin, "%s/dist/bin", src);

    TEST_STEP("Open a session on the agent");
    CHECK_RC(tsapi_mde_session_init(&session, "web"));
    session_up = true;

    TEST_STEP("Skip unless the services and curl can be run");
    for (i = 0; i < WEB_N_SERVICES; i++)
    {
        te_string path = TE_STRING_INIT;
        bool      ok;

        te_string_append(&path, "%s/%s", dist_bin.ptr, services[i].name);
        ok = tsapi_mde_exists(&session, path.ptr);
        te_string_free(&path);
        if (!ok)
            TEST_SKIP("%s/%s is missing - build the example first",
                      dist_bin.ptr, services[i].name);
    }
    CHECK_RC(tsapi_mde_run(&session, "curl", curl_ver, 10000, NULL, NULL,
                           &res));
    if (!res.started || res.status.type != TAPI_JOB_STATUS_EXITED ||
        res.status.value != 0)
    {
        TEST_SKIP("curl is not available on the agent");
    }

    TEST_STEP("Start the three HTTP services");
    for (i = 0; i < WEB_N_SERVICES; i++)
    {
        CHECK_RC(web_service_start(&session, dist_bin.ptr, &services[i]));
        started[i] = true;
    }

    TEST_STEP("Send one request into the cycle and count the node steps");
    te_string_append(&url, "http://127.0.0.1:%d/ring?value=1&hops=%d",
                     WEB_GATEWAY_PORT, hops);
    cmd[0] = "curl";
    cmd[1] = "-s";
    cmd[2] = url.ptr;
    cmd[3] = NULL;
    CHECK_RC(tsapi_mde_run(&session, cmd[0], cmd, 30000,
                           WEB_STEP_RE, WEB_VALUE_RE, &res));
    if (!res.started)
        TEST_FAIL("curl could not be started");
    if (res.match_count == 0)
        TEST_VERDICT("The gateway returned no node trace - is it serving?");

    RING("Web request traced %u node step(s); value=%s %g",
         res.match_count, res.have_value ? "" : "(none)",
         res.have_value ? res.value : 0.0);

    TEST_STEP("Record the propagation depth");
    tsapi_evo_analysis_hint(
        "Node steps should equal hops+1 as the request walks the HTTP cycle. "
        "A value of 1 means each node answered only for itself - the injected "
        "always-true defect in forward().");
    tsapi_evo_schart_init(&chart, "Web propagation",
                          "Node steps / hops", "0", "steps");
    TE_SPRINTF(xaxis, "hops=%d", hops);
    TE_SPRINTF(metric, "%u", res.match_count);
    tsapi_evo_schart_add_metric(&chart, xaxis, metric, NULL);
    tsapi_evo_schart_print(&chart);
    tsapi_evo_schart_fini(&chart);

    TEST_STEP("Check that the request reached every node step");
    expected = (unsigned int)hops + 1;
    if (res.match_count != expected)
    {
        TEST_VERDICT("Web ring propagated through %u node step(s), "
                     "expected %u", res.match_count, expected);
    }

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < WEB_N_SERVICES; i++)
    {
        if (started[i])
            web_service_stop(&services[i]);
    }
    te_string_free(&dist_bin);
    te_string_free(&url);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
