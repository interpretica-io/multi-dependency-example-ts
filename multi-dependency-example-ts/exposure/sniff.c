/** @file
 * @brief Exposure Group
 *
 * The loopback traffic of one walk through the web tier, judged by the
 * rules of tapi_sniffrules (cleartext protocols, credentials in the
 * clear, weak TLS, plaintext DNS, name leaks, unexpected egress) and
 * kept as a pcap captured by tcpdump next to it.
 *
 * Deep checks on the capture: every node step the response reports is
 * one HTTP request on the wire, and the requests go round the cycle
 * gateway-rs :8081 -> service-go :8082 -> service-cs :8083 -> ... in
 * order, so the number of requests per port follows from the number of
 * steps.
 *
 * Known-bad control: during the window a request with HTTP basic
 * authentication is sent to a throw-away listener; it must be reported
 * as @c traffic.cleartext-credentials.
 *
 * Capturing needs raw sockets: for the CSAPs of the agent and for
 * tcpdump through passwordless sudo. Without them the test skips.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/sniff"

#include "te_config.h"

#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"

#include "tapi_egress.h"
#include "tapi_sniffrules.h"

#include "exposure_common.h"

/** The capture kept as evidence. */
#define SNIFF_PCAP      "/tmp/mde-exposure-sniff.pcap"
/** What tcpdump printed. */
#define SNIFF_LOG       "/tmp/mde-exposure-sniff.log"
/** Control listener the credentials are sent to. */
#define CONTROL_PORT    18096

/** Ports charted: the tier and the control. */
static const unsigned int chart_ports[] = { 8081, 8082, 8083, CONTROL_PORT };
#define N_CHART_PORTS TE_ARRAY_LEN(chart_ports)

/** Index of a port in #chart_ports, or -1. */
static int
chart_port_index(unsigned int port)
{
    size_t i;

    for (i = 0; i < N_CHART_PORTS; i++)
    {
        if (chart_ports[i] == port)
            return (int)i;
    }

    return -1;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity   min_sev;
    int                      hops;
    tsapi_mde_session        session = { .ta = NULL };
    tsapi_mde_dut            dut = { .root = NULL };
    bool                     session_up = false;
    tsapi_mde_web            web;
    bool                     web_up = false;
    tsapi_mde_report         report;
    bool                     report_up = false;
    tapi_sniffrules_session *ss = NULL;
    tapi_sniffrules_opt      sopt = tapi_sniffrules_default_opt;
    static const tapi_egress_rule rules[] = {
        { IPPROTO_TCP, "127.0.0.1/32", EXPOSURE_WEB_FIRST,
          EXPOSURE_WEB_LAST },
    };
    tapi_egress_policy       policy = {
        .n_rules = TE_ARRAY_LEN(rules), .rules = rules,
        .allow_loopback = true, .allow_private = false,
    };
    tsapi_mde_sh_result      res = TSAPI_MDE_SH_RESULT_INIT;
    unsigned int             pid_tcpdump = 0;
    unsigned int             pid_control = 0;
    unsigned int             steps = 0;
    unsigned int             requests = 0;
    double                   t_walk = 0;
    double                   t_window;
    double                   t0;
    te_string                body = TE_STRING_INIT;
    double                   req_obs[N_CHART_PORTS] = { 0 };
    double                   req_model[N_CHART_PORTS] = { 0 };
    double                   pkts[N_CHART_PORTS] = { 0 };
    double                   bytes[N_CHART_PORTS] = { 0 };
    const char              *labels[N_CHART_PORTS];
    char                     label_buf[N_CHART_PORTS][8];
    unsigned long            pcap_size = 0;
    char                     pcap_sha[65] = "unknown";
    const char              *line;
    unsigned int             k;
    te_errno                 err;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);
    TEST_GET_INT_PARAM(hops);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "exposure_sniff", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built in this configuration");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("There is no curl on the agent");
    if (!tsapi_mde_have(&session, "tcpdump"))
        TEST_SKIP("There is no tcpdump on the agent");
    if (!exposure_sh_quiet(&session, "sudo -n true"))
        TEST_SKIP("The agent cannot run tcpdump through sudo");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("There is no python3 on the agent for the control");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Start the web tier and the control listener");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    if (!exposure_web_wait(&session))
        TEST_VERDICT("The web tier does not accept connections on its "
                     "contract ports");
    exposure_chart_web_start(&web);
    if (!exposure_listener_start(&session, CONTROL_PORT, "127.0.0.1",
                                 &pid_control))
        TEST_VERDICT("Cannot start the control listener");

    TEST_STEP("Start capturing on the loopback interface");
    sopt.rules = TAPI_SNIFFRULE_ALL;
    sopt.egress = &policy;
    err = tapi_sniffrules_start(session.ta, "lo", &sopt, &ss);
    if (err != 0)
    {
        ss = NULL;
        TEST_SKIP("The agent cannot capture on its loopback interface");
    }

    CHECK_RC(tsapi_mde_sh(&session, 20000, &res,
                          "rm -f " SNIFF_PCAP " " SNIFF_LOG "; "
                          "sudo -n sh -c 'tcpdump -i lo -U -nn -s 0 "
                          "-w " SNIFF_PCAP " \"tcp and (portrange "
                          "8081-8083 or port 18096)\" "
                          ">" SNIFF_LOG " 2>&1 </dev/null & echo $!'"));
    pid_tcpdump = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);
    if (pid_tcpdump == 0 ||
        !exposure_sh_quiet(&session,
                           "i=0; until grep -q 'listening on' " SNIFF_LOG
                           " 2>/dev/null; do i=$((i+1)); "
                           "[ $i -ge 50 ] && exit 1; sleep 0.1; done"))
    {
        TEST_SKIP("tcpdump cannot capture on the loopback interface");
    }
    t0 = tsapi_mde_now();

    TEST_STEP("Send one walk through the tier");
    if (!exposure_walk(&session, TSAPI_MDE_WEB_GATEWAY_PORT, hops, &steps,
                       &t_walk, &body))
        TEST_VERDICT("The gateway does not answer a walk");
    RING("Walk response:\n%s", body.ptr);
    TEST_ARTIFACT("Walk hops=%d: %u node step(s) in %.3f s", hops, steps,
                  t_walk);

    TEST_STEP("Known-bad control: basic authentication in the clear");
    if (!exposure_sh_quiet(&session, "curl -s -o /dev/null -m 5 "
                                     "-u mde:planted-secret "
                                     "http://127.0.0.1:18096/"))
        TEST_VERDICT("The control request was not answered");

    TEST_STEP("Close the capture window");
    usleep(500000);
    CHECK_RC(tsapi_mde_sh(&session, 20000, &res,
                          "sudo -n kill -INT %u; i=0; "
                          "while sudo -n kill -0 %u 2>/dev/null && "
                          "[ $i -lt 50 ]; do i=$((i+1)); sleep 0.1; done",
                          pid_tcpdump, pid_tcpdump));
    pid_tcpdump = 0;
    t_window = tsapi_mde_now() - t0;

    err = tapi_sniffrules_stop(ss, &report.cyber);
    ss = NULL;
    CHECK_RC(err);

    TEST_STEP("Check the control was found, then drop it");
    tsapi_mde_report_expect(&report, "traffic.cleartext-credentials",
                            "tcp/18096");
    tsapi_mde_report_drop_subject(&report, "tcp/18096");

    TEST_STEP("Read the capture back");
    CHECK_RC(tsapi_mde_sh(&session, 60000, &res,
                          "f=" SNIFF_PCAP "; "
                          "echo size $(sudo -n stat -c %%s $f); "
                          "echo sha256 $(sudo -n sha256sum $f | cut -c1-64); "
                          "echo requests $(sudo -n tcpdump -nn -r $f -A "
                          "'tcp dst portrange 8081-8083' 2>/dev/null | "
                          "grep -c 'GET /ring'); "
                          "sudo -n tcpdump -nn -r $f -A 2>/dev/null | "
                          "awk '/ IP / {n = split($5, d, \".\"); "
                          "p = d[n]; sub(\":\", \"\", p)} "
                          "/GET \\/ring/ {r[p]++} "
                          "END {for (k in r) print \"req\", k, r[k]}'; "
                          "sudo -n tcpdump -nn -q -r $f 2>/dev/null | "
                          "awk '{ns = split($3, s, \".\"); "
                          "nd = split($5, d, \".\"); sp = s[ns] + 0; "
                          "dp = d[nd]; sub(\":\", \"\", dp); dp = dp + 0; "
                          "p = ((dp >= 8081 && dp <= 8083) || "
                          "dp == 18096) ? dp : sp; "
                          "n[p]++; b[p] += $NF} "
                          "END {for (k in n) print \"port\", k, n[k], b[k]}'"));
    RING("Capture summary:\n%s", te_string_value(&res.out));

    line = te_string_value(&res.out);
    while (line != NULL && *line != '\0')
    {
        unsigned int  port;
        unsigned long a;
        unsigned long b;
        char          hex[65];
        int           idx;

        if (sscanf(line, "size %lu", &a) == 1)
            pcap_size = a;
        else if (sscanf(line, "sha256 %64s", hex) == 1)
            TE_SPRINTF(pcap_sha, "%s", hex);
        else if (sscanf(line, "requests %lu", &a) == 1)
            requests = (unsigned int)a;
        else if (sscanf(line, "req %u %lu", &port, &a) == 2)
        {
            idx = chart_port_index(port);
            if (idx >= 0)
                req_obs[idx] = a;
        }
        else if (sscanf(line, "port %u %lu %lu", &port, &a, &b) == 3)
        {
            idx = chart_port_index(port);
            if (idx >= 0)
            {
                pkts[idx] = a;
                bytes[idx] = b;
            }
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

    TEST_ARTIFACT("pcap %s: %lu bytes, sha256 %s", SNIFF_PCAP, pcap_size,
                  pcap_sha);
    TEST_ARTIFACT("HTTP requests to the tier on the wire: %u; node steps "
                  "in the response: %u", requests, steps);

    TEST_STEP("Every node step is one request on the wire");
    if (requests != steps)
        TEST_VERDICT("HTTP requests on the wire (%u) differ from the node "
                     "steps the response reports (%u)", requests, steps);

    TEST_STEP("The requests go round the cycle in contract order");
    for (k = 0; k < steps; k++)
        req_model[k % TSAPI_MDE_WEB_N] += 1;
    for (k = 0; k < TSAPI_MDE_WEB_N; k++)
    {
        if (req_model[k] != req_obs[k])
            TEST_VERDICT("Requests per port on the wire do not follow the "
                         "cycle of the contract");
    }

    TEST_STEP("Chart the capture");
    for (k = 0; k < N_CHART_PORTS; k++)
    {
        TE_SPRINTF(label_buf[k], "%u", chart_ports[k]);
        labels[k] = label_buf[k];
    }
    {
        const char *lines[] = { "packets", "bytes" };
        double      vals[2 * N_CHART_PORTS];

        for (k = 0; k < N_CHART_PORTS; k++)
        {
            vals[k] = pkts[k];
            vals[N_CHART_PORTS + k] = bytes[k];
        }
        exposure_mi_matrix("sniff", "traffic", "Packets and bytes per port",
                           N_CHART_PORTS, labels, TE_ARRAY_LEN(lines), lines,
                           vals);
    }
    {
        const char *lines[] = { "model", "observed" };
        double      vals[2 * N_CHART_PORTS];

        for (k = 0; k < N_CHART_PORTS; k++)
        {
            vals[k] = req_model[k];
            vals[N_CHART_PORTS + k] = req_obs[k];
        }
        exposure_mi_matrix("sniff", "requests",
                           "HTTP requests per port: cycle model vs wire",
                           N_CHART_PORTS, labels, TE_ARRAY_LEN(lines), lines,
                           vals);
    }
    {
        const char *tl[] = { "walk", "window" };
        double      tv[] = { t_walk, t_window };

        tsapi_mde_mi_bars("sniff", "Walk and capture window time",
                          TE_MI_MEAS_TIME, "time", TE_ARRAY_LEN(tl), tl, tv,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_point("sniff", "Capture size", TE_MI_MEAS_MEMORY, "pcap",
                       (double)pcap_size, TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "exposure", min_sev);

    TEST_SUCCESS;

cleanup:

    if (ss != NULL)
        (void)tapi_sniffrules_stop(ss, NULL);
    if (pid_tcpdump != 0)
    {
        (void)tsapi_mde_sh(&session, 10000, &res, "sudo -n kill -INT %u",
                           pid_tcpdump);
    }
    exposure_kill(&session, pid_control);
    if (session_up)
        (void)exposure_sh_quiet(&session, "sudo -n rm -f " SNIFF_LOG);
    if (web_up)
        tsapi_mde_web_stop(&web);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&res);
    te_string_free(&body);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
