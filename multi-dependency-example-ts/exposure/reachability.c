/** @file
 * @brief Exposure Group
 *
 * What of the running web tier answers a connection, over loopback and
 * over the agent's own non-loopback address - the outside view of
 * tapi_netexpose, connect probes from an RPC server - and whether that
 * agrees with the inside view, the address each service is bound to in
 * the socket table: a port bound to loopback must answer on loopback and
 * nowhere else, a wildcard one everywhere (@c net.view-mismatch
 * otherwise).
 *
 * A connect scan of the port range around the tier then reports every
 * port that answers and is neither the tier's nor already open before
 * the tier started (@c net.unexpected-reachable-port). Known-bad control:
 * a listener planted in that range must be reported.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/reachability"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "exposure_common.h"

/** The port range scanned around the tier. */
#define SCAN_FIRST  8079
#define SCAN_LAST   8090
#define SCAN_N      (SCAN_LAST - SCAN_FIRST + 1)

/** Name of a probe result. */
static const char *
state_str(tapi_netexpose_port_state st)
{
    switch (st)
    {
        case TAPI_NETEXPOSE_PORT_OPEN:   return "open";
        case TAPI_NETEXPOSE_PORT_CLOSED: return "closed";
        default:                         return "filtered";
    }
}

/** Whether a port is in a vector of uint16_t. */
static bool
vec_has_port(const te_vec *v, unsigned int port)
{
    const uint16_t *p;

    TE_VEC_FOREACH(v, p)
    {
        if (*p == port)
            return true;
    }

    return false;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    int                     probe_timeout_ms;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_web           web;
    bool                    web_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    struct sockaddr_in      lo;
    struct sockaddr_in      host;
    te_string               host_text = TE_STRING_INIT;
    bool                    have_host;
    te_vec                  base_lo;
    te_vec                  base_host;
    bool                    base_lo_up = false;
    bool                    base_host_up = false;
    te_vec                  sockets;
    bool                    sockets_up = false;
    tapi_netexpose_opt      opt = exposure_tcp_opt();
    unsigned int            control_port = 0;
    unsigned int            pid_control = 0;
    const char             *port_labels[TSAPI_MDE_WEB_N + 1];
    char                    port_names[TSAPI_MDE_WEB_N + 1][16];
    double                  states[2 * (TSAPI_MDE_WEB_N + 1)];
    double                  latency[2 * (TSAPI_MDE_WEB_N + 1)];
    unsigned int            n_ports = 0;
    uint16_t                allowed_lo[SCAN_N + TSAPI_MDE_WEB_N];
    uint16_t                allowed_host[SCAN_N];
    size_t                  n_allowed_lo = 0;
    size_t                  n_allowed_host = 0;
    double                  t_scan_lo = 0;
    double                  t_scan_host = 0;
    double                  t0;
    unsigned int            i;
    unsigned int            a;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);
    TEST_GET_INT_PARAM(probe_timeout_ms);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "exposure_reach", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built in this configuration");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("There is no curl on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;

    memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET;
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(&host, 0, sizeof(host));
    have_host = exposure_host_addr(&session, &host, &host_text);
    TEST_ARTIFACT("Agent non-loopback address: %s",
                  have_host ? host_text.ptr : "none");

    TEST_STEP("Baseline: what answers in %u..%u before the tier starts",
              SCAN_FIRST, SCAN_LAST);
    CHECK_RC(tapi_netexpose_scan(session.pco, SA(&lo), SCAN_FIRST, SCAN_LAST,
                                 probe_timeout_ms, &base_lo));
    base_lo_up = true;
    for (i = EXPOSURE_WEB_FIRST; i <= EXPOSURE_WEB_LAST; i++)
    {
        if (vec_has_port(&base_lo, i))
            TEST_FAIL("A web tier port answers before the tier starts");
    }
    if (have_host)
    {
        CHECK_RC(tapi_netexpose_scan(session.pco, SA(&host), SCAN_FIRST,
                                     SCAN_LAST, probe_timeout_ms,
                                     &base_host));
        base_host_up = true;
    }
    TEST_ARTIFACT("Baseline: %zu port(s) open on loopback, %zu on the host "
                  "address", te_vec_size(&base_lo),
                  base_host_up ? te_vec_size(&base_host) : (size_t)0);

    TEST_STEP("Start the web tier");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    if (!exposure_web_wait(&session))
        TEST_VERDICT("The web tier does not accept connections on its "
                     "contract ports");
    exposure_chart_web_start(&web);

    TEST_STEP("Known-bad control: a listener planted in the scanned range");
    if (tsapi_mde_have(&session, "python3"))
    {
        for (i = EXPOSURE_WEB_LAST + 1; i <= SCAN_LAST; i++)
        {
            if (!vec_has_port(&base_lo, i))
            {
                control_port = i;
                break;
            }
        }
        if (control_port != 0 &&
            !exposure_listener_start(&session, control_port, "127.0.0.1",
                                     &pid_control))
            TEST_VERDICT("Cannot start the control listener");
    }
    if (pid_control == 0)
        WARN("No control listener: python3 is missing or the range is busy");

    TEST_STEP("Read where each service is bound (inside view)");
    CHECK_RC(tapi_netexpose_sockets(session.factory, &opt, &sockets));
    sockets_up = true;

    TEST_STEP("Probe each port over loopback and the host address");
    for (i = 0; i < TSAPI_MDE_WEB_N + 1; i++)
    {
        unsigned int port = (i < TSAPI_MDE_WEB_N) ? web.svc[i].port :
                                                    control_port;
        bool         bound_lo = false;
        bool         bound_any = false;
        bool         bound_host = false;
        bool         bound = false;
        const tapi_netexpose_socket *sock;
        tapi_netexpose_port_state    st[2] = { TAPI_NETEXPOSE_PORT_FILTERED,
                                               TAPI_NETEXPOSE_PORT_FILTERED };

        if (port == 0)
            continue;

        TE_VEC_FOREACH(&sockets, sock)
        {
            if (!tapi_netexpose_socket_is_listening(sock) ||
                exposure_port(&sock->local) != port)
                continue;
            bound = true;
            if (exposure_is_loopback(&sock->local))
                bound_lo = true;
            else if (exposure_is_wildcard(&sock->local))
                bound_any = true;
            else if (have_host && sock->family == AF_INET &&
                     ((const struct sockaddr_in *)&sock->local)->
                        sin_addr.s_addr == host.sin_addr.s_addr)
                bound_host = true;
        }

        for (a = 0; a < 2; a++)
        {
            bool expect_open;
            bool is_open;

            if (a == 1 && !have_host)
                break;

            t0 = tsapi_mde_now();
            CHECK_RC(tapi_netexpose_probe_port(session.pco,
                                               a == 0 ? SA(&lo) : SA(&host),
                                               (uint16_t)port,
                                               probe_timeout_ms, &st[a]));
            latency[a * (TSAPI_MDE_WEB_N + 1) + n_ports] =
                tsapi_mde_now() - t0;

            expect_open = bound_any || (a == 0 ? bound_lo : bound_host);
            is_open = st[a] == TAPI_NETEXPOSE_PORT_OPEN;
            if (bound && expect_open != is_open)
            {
                te_string subject = TE_STRING_INIT;

                te_string_append(&subject, "tcp/%u@%s", port,
                                 a == 0 ? "loopback" : "host");
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_MEDIUM,
                                         "net.view-mismatch", subject.ptr,
                                         "the socket table says it should "
                                         "%sanswer there, a connect probe "
                                         "found it %s",
                                         expect_open ? "" : "not ",
                                         state_str(st[a]));
                te_string_free(&subject);
            }
        }
        if (!have_host)
            latency[1 * (TSAPI_MDE_WEB_N + 1) + n_ports] = 0;

        if (i < TSAPI_MDE_WEB_N && st[0] != TAPI_NETEXPOSE_PORT_OPEN)
            TEST_VERDICT("%s does not answer on loopback", web.svc[i].name);

        TEST_ARTIFACT("tcp/%u %s: loopback=%s host=%s bound=%s", port,
                      i < TSAPI_MDE_WEB_N ? web.svc[i].name : "control",
                      state_str(st[0]),
                      have_host ? state_str(st[1]) : "n/a",
                      !bound ? "not-listening" :
                      bound_any ? "wildcard" :
                      bound_lo ? "loopback" :
                      bound_host ? "host" : "other");

        TE_SPRINTF(port_names[n_ports], "%u", port);
        port_labels[n_ports] = port_names[n_ports];
        states[n_ports] = (double)st[0];
        states[(TSAPI_MDE_WEB_N + 1) + n_ports] =
            have_host ? (double)st[1] : -1.0;
        n_ports++;
    }

    TEST_STEP("Scan the range on loopback against the expected ports");
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
        allowed_lo[n_allowed_lo++] = (uint16_t)web.svc[i].port;
    {
        const uint16_t *p;

        TE_VEC_FOREACH(&base_lo, p)
            allowed_lo[n_allowed_lo++] = *p;
    }
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_netexpose_scan_check(session.pco, SA(&lo), SCAN_FIRST,
                                       SCAN_LAST, probe_timeout_ms,
                                       allowed_lo, n_allowed_lo,
                                       &report.cyber));
    t_scan_lo = tsapi_mde_now() - t0;

    if (pid_control != 0)
    {
        te_string subject = TE_STRING_INIT;

        te_string_append(&subject, "tcp/%u", control_port);
        tsapi_mde_report_expect(&report, "net.unexpected-reachable-port",
                                subject.ptr);
        tsapi_mde_report_drop_subject(&report, subject.ptr);
        te_string_free(&subject);
    }

    if (have_host)
    {
        const uint16_t *p;

        TEST_STEP("Scan the range on the host address: the tier is "
                  "loopback-only, nothing of it may answer there");
        TE_VEC_FOREACH(&base_host, p)
            allowed_host[n_allowed_host++] = *p;
        t0 = tsapi_mde_now();
        CHECK_RC(tapi_netexpose_scan_check(session.pco, SA(&host),
                                           SCAN_FIRST, SCAN_LAST,
                                           probe_timeout_ms, allowed_host,
                                           n_allowed_host, &report.cyber));
        t_scan_host = tsapi_mde_now() - t0;
    }

    TEST_STEP("Chart reachability");
    {
        const char *lines[] = { "loopback", "host" };
        double      packed[2 * (TSAPI_MDE_WEB_N + 1)];
        double      lat[2 * (TSAPI_MDE_WEB_N + 1)];

        for (i = 0; i < n_ports; i++)
        {
            packed[i] = states[i];
            packed[n_ports + i] = states[(TSAPI_MDE_WEB_N + 1) + i];
            lat[i] = latency[i];
            lat[n_ports + i] = latency[(TSAPI_MDE_WEB_N + 1) + i];
        }
        exposure_mi_matrix("netexpose", "reach",
                           "Probe result per port (0 filtered, 1 closed, "
                           "2 open; -1 no host address)", n_ports,
                           port_labels, TE_ARRAY_LEN(lines), lines, packed);
        exposure_mi_matrix("netexpose", "latency",
                           "Connect probe time per port, seconds", n_ports,
                           port_labels, TE_ARRAY_LEN(lines), lines, lat);
    }
    {
        const char *labels[] = { "loopback", "host" };
        double      vals[] = { t_scan_lo, t_scan_host };

        tsapi_mde_mi_bars("netexpose", "Time to scan the range per address",
                          TE_MI_MEAS_TIME, "scan", TE_ARRAY_LEN(labels),
                          labels, vals, TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "exposure", min_sev);

    TEST_SUCCESS;

cleanup:

    exposure_kill(&session, pid_control);
    if (web_up)
        tsapi_mde_web_stop(&web);
    if (sockets_up)
        tapi_netexpose_sockets_free(&sockets);
    if (base_lo_up)
        te_vec_free(&base_lo);
    if (base_host_up)
        te_vec_free(&base_host);
    if (report_up)
        tsapi_mde_report_free(&report);
    te_string_free(&host_text);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
