/** @file
 * @brief Exposure Group
 *
 * Where the gateway actually connects while a walk runs, seen from inside
 * the process with Frida: every connect() of gateway-rs is traced and
 * judged by tapi_frida_check_egress() against the only place it may
 * connect to, the next node of the tier on loopback. Unlike the socket
 * table this does not miss a connection that opens and closes between
 * two snapshots.
 *
 * Deep check: the gateway connects to service-go once per forward, and
 * the walk's response says how many forwards the gateway made - the node
 * steps at positions 0, 3, 6, ... that are not the last one.
 *
 * Known-bad control: curl spawned under Frida towards a TEST-NET address
 * must be reported as @c runtime.unexpected-egress.
 *
 * Frida is test equipment and is usually not installed: the test skips
 * cleanly then.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/frida"

#include "te_config.h"

#include <unistd.h>

#include "tapi_test.h"
#include "tapi_file.h"
#include "te_string.h"

#include "tapi_egress.h"
#include "tapi_frida.h"

#include "exposure_common.h"

/** Control destination: TEST-NET-2, documentation only, never answers. */
#define TESTNET_ADDR    "198.51.100.1"

/** Run one traced program or attach to one process and collect events. */
static te_errno
frida_trace(tsapi_mde_session *session, const tapi_frida_opt *opt,
            bool spawned, tapi_frida_app **app)
{
    te_errno rc;

    rc = tapi_frida_create(session->factory, opt, app);
    if (rc != 0)
        return rc;

    rc = tapi_frida_start(*app);
    if (rc != 0)
        return rc;

    if (spawned)
    {
        rc = tapi_frida_wait(*app, 30000);
        if (TE_RC_GET_ERROR(rc) == TE_EINPROGRESS)
            rc = tapi_frida_stop(*app);
    }

    return rc;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    int                     hops;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_web           web;
    bool                    web_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    static const tapi_egress_rule rules[] = {
        { IPPROTO_TCP, "127.0.0.1/32", EXPOSURE_WEB_FIRST,
          EXPOSURE_WEB_LAST },
    };
    tapi_egress_policy      policy = {
        .n_rules = TE_ARRAY_LEN(rules), .rules = rules,
        .allow_loopback = false, .allow_private = false,
    };
    te_string               script = TE_STRING_INIT;
    te_string               script_path = TE_STRING_INIT;
    te_string               curl_path = TE_STRING_INIT;
    tsapi_mde_sh_result     res = TSAPI_MDE_SH_RESULT_INIT;
    tapi_frida_opt          opt;
    tapi_frida_app         *control = NULL;
    tapi_frida_app         *app = NULL;
    bool                    app_running = false;
    te_vec                  events;
    bool                    events_up = false;
    const tapi_frida_event *ev;
    const char             *control_args[] = { "-s", "-m", "3",
                                               "http://" TESTNET_ADDR "/" };
    unsigned int            steps = 0;
    unsigned int            expected_connects = 0;
    unsigned int            n_connect = 0;
    unsigned int            n_other = 0;
    unsigned int            k;
    double                  t_walk = 0;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);
    TEST_GET_INT_PARAM(hops);

    TEST_STEP("Open a session and check for Frida");
    TSAPI_MDE_OPEN_OR_SKIP(session, "exposure_frida", dut, session_up);
    if (!tsapi_mde_have(&session, "frida"))
        TEST_SKIP("Frida is not installed on the agent");
    if (tapi_frida_check_available(session.factory, 30000) != 0)
        TEST_SKIP("Frida is not usable on the agent");
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built in this configuration");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("There is no curl on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Put the connect() tracing script on the agent");
    tapi_frida_script_trace_connect(&script);
    CHECK_RC(tapi_frida_script_put(session.ta, script.ptr, &script_path));

    TEST_STEP("Known-bad control: curl towards TEST-NET, traced");
    CHECK_RC(tsapi_mde_sh(&session, 10000, &res, "command -v curl"));
    te_string_append(&curl_path, "%s", te_string_value(&res.out));
    te_string_chop(&curl_path, "\n");
    opt = tapi_frida_default_opt;
    opt.spawn = curl_path.ptr;
    opt.spawn_args = control_args;
    opt.n_spawn_args = TE_ARRAY_LEN(control_args);
    opt.script_path = script_path.ptr;
    if (frida_trace(&session, &opt, true, &control) != 0)
        TEST_SKIP("Frida cannot spawn a program on the agent");
    CHECK_RC(tapi_frida_check_egress(control, &policy, &report.cyber));
    tsapi_mde_report_expect(&report, "runtime.unexpected-egress",
                            TESTNET_ADDR ":80");
    tsapi_mde_report_drop_subject(&report, TESTNET_ADDR ":80");

    TEST_STEP("Start the web tier and attach to gateway-rs");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    if (!exposure_web_wait(&session))
        TEST_VERDICT("The web tier does not accept connections on its "
                     "contract ports");
    exposure_chart_web_start(&web);

    opt = tapi_frida_default_opt;
    opt.target_name = "gateway-rs";
    opt.script_path = script_path.ptr;
    app_running = true;
    if (frida_trace(&session, &opt, false, &app) != 0)
        TEST_SKIP("Frida cannot attach to gateway-rs (ptrace is refused?)");
    /* Give the script time to be injected before the walk. */
    sleep(3);

    TEST_STEP("Send one walk while gateway-rs is traced");
    if (!exposure_walk(&session, TSAPI_MDE_WEB_GATEWAY_PORT, hops, &steps,
                       &t_walk, NULL))
        TEST_VERDICT("The gateway does not answer a walk");
    sleep(1);
    app_running = false;
    CHECK_RC(tapi_frida_stop(app));

    TEST_STEP("Judge the connections the gateway made");
    CHECK_RC(tapi_frida_check_egress(app, &policy, &report.cyber));
    CHECK_RC(tapi_frida_events(app, &events));
    events_up = true;
    TE_VEC_FOREACH(&events, ev)
    {
        RING("frida event: %s %s %s", ev->kind, ev->name, ev->detail);
        if (strcmp(ev->kind, "connect") == 0)
            n_connect++;
        else
            n_other++;
    }

    /* Step k is served by node k mod 3; it forwards unless it is last. */
    for (k = 0; k + 1 < steps; k++)
    {
        if (k % TSAPI_MDE_WEB_N == 0)
            expected_connects++;
    }
    TEST_ARTIFACT("gateway-rs: %u connect() call(s) traced; the response "
                  "(%u node steps) implies %u", n_connect, steps,
                  expected_connects);
    if (n_connect != expected_connects)
        TEST_VERDICT("gateway-rs made %u connection(s), the walk's response "
                     "implies %u", n_connect, expected_connects);

    TEST_STEP("Chart the events");
    {
        const char *labels[] = { "connect", "other", "expected_connect" };
        double      vals[] = { n_connect, n_other, expected_connects };

        tsapi_mde_mi_bars("frida", "Events traced in gateway-rs",
                          TE_MI_MEAS_UNITLESS_VALUE, "events",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_point("frida", "Walk time under tracing", TE_MI_MEAS_TIME,
                       "walk", t_walk, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "exposure", min_sev);

    TEST_SUCCESS;

cleanup:

    if (events_up)
        tapi_frida_events_free(&events);
    if (app != NULL)
    {
        if (app_running)
            (void)tapi_frida_stop(app);
        CLEANUP_CHECK_RC(tapi_frida_destroy(app));
    }
    if (control != NULL)
        CLEANUP_CHECK_RC(tapi_frida_destroy(control));
    if (script_path.len != 0)
        (void)tapi_file_ta_unlink_fmt(session.ta, "%s", script_path.ptr);
    if (web_up)
        tsapi_mde_web_stop(&web);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&res);
    te_string_free(&script);
    te_string_free(&script_path);
    te_string_free(&curl_path);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
