/** @file
 * @brief Exposure Group
 *
 * What the running web tier listens on, read from the socket tables of
 * the agent by tapi_netexpose and checked against what it is allowed to
 * listen on: the three contract ports, each on loopback only.
 *
 * The agent shares the host network, so the table holds every listener
 * of the host too. A snapshot taken before the tier starts is the
 * baseline: those listeners are the environment's, not the example's,
 * and are allowed as they are. What the gate judges is what the tier
 * added.
 *
 * Two known-bad controls run next to the tier: a listener nobody allowed
 * (@c net.unexpected-listener) and a listener that is allowed on
 * loopback only but binds every address (@c net.listens-beyond-loopback).
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/listeners"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "exposure_common.h"

/** Control listener nobody allowed. */
#define CONTROL_UNEXPECTED_PORT 18099
/** Control listener allowed on loopback only, bound to every address. */
#define CONTROL_WIDE_PORT       18098

/** Most listeners remembered from the baseline. */
#define MAX_BASELINE    256

/** Add a port to a set unless it is there. */
static void
port_set_add(uint16_t *set, size_t *n, size_t max, uint16_t port)
{
    size_t i;

    for (i = 0; i < *n; i++)
    {
        if (set[i] == port)
            return;
    }
    if (*n < max)
        set[(*n)++] = port;
}

/** Whether a port is in a set. */
static bool
port_set_has(const uint16_t *set, size_t n, uint16_t port)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        if (set[i] == port)
            return true;
    }

    return false;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_web           web;
    bool                    web_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    tapi_netexpose_opt      opt = exposure_tcp_opt();
    te_vec                  before;
    te_vec                  after;
    bool                    before_up = false;
    bool                    after_up = false;
    const tapi_netexpose_socket *sock;
    uint16_t                baseline[MAX_BASELINE];
    size_t                  n_baseline = 0;
    tapi_netexpose_allowed  allowed[MAX_BASELINE + 8];
    size_t                  n_allowed = 0;
    unsigned int            pid_unexpected = 0;
    unsigned int            pid_wide = 0;
    bool                    have_python;
    bool                    control_ok = false;
    bool                    web_found[TSAPI_MDE_WEB_N] = { false };
    unsigned int            n_loop4 = 0;
    unsigned int            n_loop6 = 0;
    unsigned int            n_any4 = 0;
    unsigned int            n_any6 = 0;
    unsigned int            n_other = 0;
    unsigned int            n_listen_after = 0;
    unsigned int            n_new = 0;
    unsigned int            n_rows = 0;
    double                  t0;
    double                  t_check;
    size_t                  i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "exposure_listeners", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_VERDICT("The web tier is not built in this configuration");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_VERDICT("There is no curl on the agent");
    have_python = tsapi_mde_have(&session, "python3");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Take the baseline: what listens before the tier starts");
    CHECK_RC(tapi_netexpose_sockets(session.factory, &opt, &before));
    before_up = true;
    TE_VEC_FOREACH(&before, sock)
    {
        uint16_t port;

        if (!tapi_netexpose_socket_is_listening(sock))
            continue;
        port = (uint16_t)exposure_port(&sock->local);
        if (exposure_is_web_port(port))
            TEST_FAIL("A web tier port is taken before the tier starts");
        port_set_add(baseline, &n_baseline, MAX_BASELINE, port);
    }
    TEST_ARTIFACT("Baseline: %zu listening TCP port(s) before the tier "
                  "starts", n_baseline);

    TEST_STEP("Start the web tier");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    if (!exposure_web_wait(&session))
        TEST_VERDICT("The web tier does not accept connections on its "
                     "contract ports");
    exposure_chart_web_start(&web);

    TEST_STEP("Start the known-bad control listeners");
    if (!have_python)
    {
        WARN("There is no python3 on the agent: no control listener");
    }
    else if (port_set_has(baseline, n_baseline, CONTROL_UNEXPECTED_PORT) ||
             port_set_has(baseline, n_baseline, CONTROL_WIDE_PORT))
    {
        WARN("A control port is busy before the test: no control listener");
    }
    else
    {
        if (!exposure_listener_start(&session, CONTROL_UNEXPECTED_PORT,
                                     "0.0.0.0", &pid_unexpected) ||
            !exposure_listener_start(&session, CONTROL_WIDE_PORT, "0.0.0.0",
                                     &pid_wide))
            TEST_VERDICT("Cannot start the control listeners");
        control_ok = true;
    }

    TEST_STEP("Build the allowed set");
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        allowed[n_allowed].proto = IPPROTO_TCP;
        allowed[n_allowed].port = (uint16_t)web.svc[i].port;
        allowed[n_allowed].loopback_only = true;
        n_allowed++;
    }
    allowed[n_allowed].proto = IPPROTO_TCP;
    allowed[n_allowed].port = CONTROL_WIDE_PORT;
    allowed[n_allowed].loopback_only = true;
    n_allowed++;
    for (i = 0; i < n_baseline; i++)
    {
        allowed[n_allowed].proto = IPPROTO_TCP;
        allowed[n_allowed].port = baseline[i];
        allowed[n_allowed].loopback_only = false;
        n_allowed++;
    }

    TEST_STEP("Check what listens against the allowed set");
    t0 = tsapi_mde_now();
    CHECK_RC(tapi_netexpose_check(session.factory, &opt, allowed, n_allowed,
                                  &report.cyber));
    t_check = tsapi_mde_now() - t0;

    TEST_STEP("Read the table again for the evidence and the deep checks");
    CHECK_RC(tapi_netexpose_sockets(session.factory, &opt, &after));
    after_up = true;
    tapi_netexpose_sockets_log(&after, true);

    TE_VEC_FOREACH(&after, sock)
    {
        te_string    where = TE_STRING_INIT;
        const char  *tag;
        unsigned int port;

        if (!tapi_netexpose_socket_is_listening(sock))
            continue;
        n_listen_after++;
        port = exposure_port(&sock->local);

        if (exposure_is_loopback(&sock->local))
        {
            if (sock->family == AF_INET)
                n_loop4++;
            else
                n_loop6++;
        }
        else if (exposure_is_wildcard(&sock->local))
        {
            if (sock->family == AF_INET)
                n_any4++;
            else
                n_any6++;
        }
        else
        {
            n_other++;
        }

        if (exposure_is_web_port(port))
        {
            tag = "web";
            for (i = 0; i < TSAPI_MDE_WEB_N; i++)
            {
                if (web.svc[i].port == port)
                    web_found[i] = true;
            }

            /* The service announced 127.0.0.1; the table must agree. */
            if (!exposure_is_loopback(&sock->local))
            {
                te_string subject = TE_STRING_INIT;
                te_string addr = TE_STRING_INIT;

                exposure_addr_str(&sock->local, &addr);
                te_string_append(&subject, "tcp/%u", port);
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_MEDIUM,
                                         "net.view-mismatch", subject.ptr,
                                         "the service announced "
                                         "http://127.0.0.1:%u but the socket "
                                         "table has it bound at %s", port,
                                         addr.ptr);
                te_string_free(&subject);
                te_string_free(&addr);
            }
        }
        else if (port == CONTROL_UNEXPECTED_PORT ||
                 port == CONTROL_WIDE_PORT)
        {
            tag = control_ok ? "control" : "foreign";
        }
        else if (port_set_has(baseline, n_baseline, (uint16_t)port))
        {
            tag = "baseline";
        }
        else
        {
            tag = "new";
            n_new++;
        }

        exposure_addr_str(&sock->local, &where);
        if (n_rows < 64)
        {
            TEST_ARTIFACT("listener tcp%s %s:%u uid=%u inode=%lu [%s]",
                          sock->family == AF_INET6 ? "6" : "", where.ptr,
                          port, sock->uid, sock->inode, tag);
        }
        n_rows++;
        te_string_free(&where);
    }
    if (n_rows > 64)
        TEST_ARTIFACT("listener table: %u more row(s) in the log",
                      n_rows - 64);

    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        if (!web_found[i])
            TEST_VERDICT("%s does not listen on its contract port",
                         web.svc[i].name);
    }

    TEST_STEP("Check the controls were found, then drop them");
    if (control_ok)
    {
        tsapi_mde_report_expect(&report, "net.unexpected-listener",
                                "tcp/18099");
        tsapi_mde_report_expect(&report, "net.listens-beyond-loopback",
                                "tcp/18098");
        tsapi_mde_report_drop_subject(&report, "tcp/18099");
        tsapi_mde_report_drop_subject(&report, "tcp/18098");
    }

    TEST_STEP("Chart the listeners");
    {
        const char *labels[] = { "loopback4", "loopback6", "any4", "any6",
                                 "other" };
        double      vals[] = { n_loop4, n_loop6, n_any4, n_any6, n_other };

        tsapi_mde_mi_bars("netexpose", "Listeners per bound address class",
                          TE_MI_MEAS_UNITLESS_VALUE, "listeners",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        const char *labels[] = { "baseline", "after", "new" };
        double      vals[] = { (double)n_baseline, n_listen_after, n_new };

        tsapi_mde_mi_bars("netexpose", "Listening ports before and after "
                          "the tier started", TE_MI_MEAS_UNITLESS_VALUE,
                          "listeners", TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        const char *labels[] = { "allowed", "findings" };
        double      vals[] = { (double)n_allowed,
                               (double)te_vec_size(&report.cyber.findings) };

        tsapi_mde_mi_bars("netexpose", "Allowed set and findings",
                          TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    tsapi_mde_mi_point("netexpose", "Time to read and check the socket "
                       "tables", TE_MI_MEAS_TIME, "check", t_check,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("%u listener(s) after the start, %u new beyond the tier "
                  "and the controls", n_listen_after, n_new);

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "exposure", min_sev);

    TEST_SUCCESS;

cleanup:

    exposure_kill(&session, pid_unexpected);
    exposure_kill(&session, pid_wide);
    if (web_up)
        tsapi_mde_web_stop(&web);
    if (before_up)
        tapi_netexpose_sockets_free(&before);
    if (after_up)
        tapi_netexpose_sockets_free(&after);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
