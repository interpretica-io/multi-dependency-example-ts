/** @file
 * @brief Exposure Group
 *
 * Hypothesis H3: the hardcoded loopback endpoints are the only ones the
 * web tier uses, and none of its listeners is exposed beyond loopback.
 *
 * With the three services running and a few walks going through them:
 * - tapi_netexpose lists the listening sockets; the web tier ports must
 *   be there on loopback, and no listener that appeared after the tier
 *   started, under the agent's user, may be bound to 0.0.0.0, :: or any
 *   non-loopback address;
 * - tapi_egress takes snapshots of the outgoing connections of the
 *   agent's user; the allowed set is 127.0.0.1:8081-8083. A destination
 *   outside loopback is egress outside the set. The agent's own control
 *   connections are loopback too and share the user, so a loopback peer
 *   outside the set is recorded in the report at info level and does not
 *   change the verdict;
 * - tapi_binscan reads NX, PIE, RELRO and the stack canary of the three
 *   binaries; these go into the report as info findings and are not part
 *   of the verdict.
 *
 * Verdict: a listener on a wildcard or non-loopback address, or an egress
 * outside the allowed set, proves H3; otherwise H3 is DISPROVEN.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/h3_endpoints"

#include "te_config.h"

#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"

#include "tapi_binscan.h"
#include "tapi_egress.h"

#include "exposure_common.h"

/** Snapshots of the outgoing connections. */
#define H3_SNAPSHOTS    5
/** Walks sent while the tier is watched. */
#define H3_WALKS        10
/** Most baseline ports remembered. */
#define H3_MAX_BASELINE 256
/** Where the walks write their answers. */
#define H3_LOAD_OUT     "/tmp/mde-exposure-h3.out"

/** Whether a port is in a set. */
static bool
h3_has(const uint16_t *set, size_t n, uint16_t port)
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
    static const tapi_egress_rule rules[] = {
        { IPPROTO_TCP, "127.0.0.1/32", EXPOSURE_WEB_FIRST,
          EXPOSURE_WEB_LAST },
    };
    tapi_egress_policy      policy = {
        .n_rules = TE_ARRAY_LEN(rules), .rules = rules,
        .allow_loopback = true, .allow_private = false,
    };
    tapi_egress_policy      strict = {
        .n_rules = TE_ARRAY_LEN(rules), .rules = rules,
        .allow_loopback = false, .allow_private = false,
    };
    tsapi_mde_sh_result     res = TSAPI_MDE_SH_RESULT_INIT;
    te_string               cmd = TE_STRING_INIT;
    te_string               url = TE_STRING_INIT;
    te_string               path = TE_STRING_INIT;
    te_vec                  before;
    te_vec                  after;
    bool                    before_up = false;
    bool                    after_up = false;
    const tapi_netexpose_socket *sock;
    uint16_t                baseline[H3_MAX_BASELINE];
    size_t                  n_baseline = 0;
    tapi_netexpose_allowed  allowed[H3_MAX_BASELINE + 4];
    size_t                  n_allowed = 0;
    bool                    web_found[TSAPI_MDE_WEB_N] = { false };
    unsigned int            uid = 0;
    unsigned int            pid_load = 0;
    unsigned int            n_exposed = 0;
    unsigned int            n_egress = 0;
    unsigned int            n_loop_peer = 0;
    unsigned int            n_dest = 0;
    unsigned int            n_listen = 0;
    size_t                  i;
    unsigned int            s;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "exposure_h3", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_VERDICT("The web tier is not built in this configuration");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_VERDICT("There is no curl on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;

    CHECK_RC(tsapi_mde_sh(&session, 10000, &res, "id -u"));
    if (!tsapi_mde_sh_ok(&res))
        TEST_FAIL("Cannot read the user id of the agent");
    uid = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);

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
        if (!h3_has(baseline, n_baseline, port) &&
            n_baseline < H3_MAX_BASELINE)
            baseline[n_baseline++] = port;
    }

    TEST_STEP("Start the web tier and a few walks");
    web_up = true;
    tsapi_mde_web_init(&web);
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    if (!exposure_web_wait(&session))
        TEST_VERDICT("The web tier does not accept connections on its "
                     "contract ports");
    exposure_chart_web_start(&web);

    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, 3, &url);
    te_string_append(&cmd, "sh -c 'rm -f " H3_LOAD_OUT "; i=0; "
                     "while [ $i -lt %d ]; do curl -s -m 10 \"%s\" "
                     ">> " H3_LOAD_OUT "; echo >> " H3_LOAD_OUT "; "
                     "sleep 0.2; i=$((i+1)); done'", H3_WALKS, url.ptr);
    if (!exposure_spawn(&session, cmd.ptr, &pid_load))
        TEST_FAIL("Cannot start the walks");

    TEST_STEP("tapi_netexpose: check the listeners against the loopback "
              "endpoints");
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        allowed[n_allowed].proto = IPPROTO_TCP;
        allowed[n_allowed].port = (uint16_t)web.svc[i].port;
        allowed[n_allowed].loopback_only = true;
        n_allowed++;
    }
    for (i = 0; i < n_baseline; i++)
    {
        allowed[n_allowed].proto = IPPROTO_TCP;
        allowed[n_allowed].port = baseline[i];
        allowed[n_allowed].loopback_only = false;
        n_allowed++;
    }
    CHECK_RC(tapi_netexpose_check(session.factory, &opt, allowed, n_allowed,
                                  &report.cyber));

    CHECK_RC(tapi_netexpose_sockets(session.factory, &opt, &after));
    after_up = true;
    tapi_netexpose_sockets_log(&after, true);
    TE_VEC_FOREACH(&after, sock)
    {
        te_string    addr = TE_STRING_INIT;
        unsigned int port;
        bool         is_web;
        bool         is_new;

        if (!tapi_netexpose_socket_is_listening(sock))
            continue;
        n_listen++;
        port = exposure_port(&sock->local);
        is_web = exposure_is_web_port(port);
        is_new = !h3_has(baseline, n_baseline, (uint16_t)port);

        if (is_web)
        {
            for (i = 0; i < TSAPI_MDE_WEB_N; i++)
            {
                if (web.svc[i].port == port)
                    web_found[i] = true;
            }
        }

        /* The tier's own listeners, and whatever the agent's user started
         * after the baseline. */
        if ((is_web || (is_new && sock->uid == uid)) &&
            !exposure_is_loopback(&sock->local))
        {
            exposure_addr_str(&sock->local, &addr);
            n_exposed++;
            TEST_ARTIFACT("SEC listener beyond loopback: tcp %s:%u uid=%u%s",
                          addr.ptr, port, sock->uid,
                          is_web ? " (web tier port)" : "");
        }
        te_string_free(&addr);
    }
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        if (!web_found[i])
            TEST_VERDICT("%s does not listen on its contract port",
                         web.svc[i].name);
    }

    TEST_STEP("tapi_egress: snapshots of the outgoing connections");
    for (s = 0; s < H3_SNAPSHOTS; s++)
    {
        te_vec                       conns;
        te_vec                       sockets;
        const tapi_netexpose_socket *c;

        CHECK_RC(tapi_egress_snapshot(session.factory, &opt, &conns));
        if (tapi_netexpose_sockets(session.factory, &opt, &sockets) != 0)
        {
            te_vec_free(&conns);
            TEST_FAIL("Cannot read the socket tables of the agent");
        }

        TE_VEC_FOREACH(&conns, c)
        {
            te_string    addr = TE_STRING_INIT;
            te_string    subject = TE_STRING_INIT;
            bool         inbound = false;
            const tapi_netexpose_socket *l;

            TE_VEC_FOREACH(&sockets, l)
            {
                if (tapi_netexpose_socket_is_listening(l) &&
                    exposure_port(&l->local) == exposure_port(&c->local))
                    inbound = true;
            }
            if (inbound || c->inode == 0 || c->uid != uid)
                goto next;

            exposure_addr_str(&c->remote, &addr);
            te_string_append(&subject, "tcp/%s:%u", addr.ptr,
                             exposure_port(&c->remote));
            n_dest++;

            if (!tapi_egress_policy_allows(&policy, IPPROTO_TCP,
                                           CONST_SA(&c->remote)))
            {
                if (tsapi_mde_report_has(&report, "net.unexpected-egress",
                                         subject.ptr) == 0)
                {
                    n_egress++;
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_HIGH,
                                             "net.unexpected-egress",
                                             subject.ptr, "outside the "
                                             "hardcoded loopback "
                                             "endpoints");
                }
            }
            else if (!tapi_egress_policy_allows(&strict, IPPROTO_TCP,
                                                CONST_SA(&c->remote)) &&
                     tsapi_mde_report_has(&report, "net.loopback-peer",
                                          subject.ptr) == 0)
            {
                n_loop_peer++;
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_INFO,
                                         "net.loopback-peer", subject.ptr,
                                         "loopback peer outside "
                                         "8081-8083 (agent's own "
                                         "connection, most likely)");
            }
next:
            te_string_free(&addr);
            te_string_free(&subject);
        }

        te_vec_free(&conns);
        tapi_netexpose_sockets_free(&sockets);
        usleep(250000);
    }

    TEST_STEP("tapi_binscan: NX, PIE, RELRO and canary of the binaries");
    for (i = 0; i < TSAPI_MDE_WEB_N; i++)
    {
        tapi_binscan_info info;

        te_string_reset(&path);
        te_string_append(&path, "%s/%s", dut.bin, web.svc[i].name);
        CHECK_RC(tapi_binscan_inspect(session.ta, path.ptr, &info));
        TEST_ARTIFACT("SEC binscan %s: NX=%s PIE=%s RELRO=%s canary=%s",
                      web.svc[i].name,
                      info.nx_unknown ? "unknown" : (info.nx ? "yes" : "no"),
                      info.kind == TAPI_BINSCAN_KIND_PIE ? "yes" : "no",
                      tapi_binscan_relro2str(info.relro),
                      info.canary ? "yes" : "no");
        tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                 "binscan.properties", web.svc[i].name,
                                 "NX=%s PIE=%s RELRO=%s canary=%s",
                                 info.nx_unknown ? "unknown" :
                                 (info.nx ? "yes" : "no"),
                                 info.kind == TAPI_BINSCAN_KIND_PIE ? "yes" :
                                 "no", tapi_binscan_relro2str(info.relro),
                                 info.canary ? "yes" : "no");
        tapi_binscan_info_free(&info);
    }

    TEST_STEP("Chart and report");
    {
        const char *labels[] = { "listeners", "beyond-loopback",
                                 "egress-dest", "outside-set",
                                 "loopback-peers" };
        double      vals[] = { n_listen, n_exposed, n_dest, n_egress,
                               n_loop_peer };

        tsapi_mde_mi_bars("h3", "Listeners and egress of the web tier",
                          TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        /* The report carries the findings and the artifacts; the verdict
         * below is H3's own. */
        te_string text = TE_STRING_INIT;

        (void)tsapi_mde_report_finish(&report, "exposure", min_sev, &text);
        te_string_free(&text);
    }

    TEST_STEP("Decide on the exposure verdict");
    if (n_exposed > 0 || n_egress > 0)
    {
        ERROR_VERDICT("SEC PROVEN: %u listener(s) beyond loopback, %u egress "
                      "destination(s) outside 127.0.0.1:8081-8083",
                      n_exposed, n_egress);
        TEST_STOP;
    }

    RING_VERDICT("SEC DISPROVEN: all listeners of the web tier are on "
                 "loopback and its egress stays within 127.0.0.1:8081-8083");

    TEST_SUCCESS;

cleanup:

    exposure_kill(&session, pid_load);
    if (session_up)
        (void)exposure_sh_quiet(&session, "rm -f " H3_LOAD_OUT);
    if (web_up)
        tsapi_mde_web_stop(&web);
    if (before_up)
        tapi_netexpose_sockets_free(&before);
    if (after_up)
        tapi_netexpose_sockets_free(&after);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&res);
    te_string_free(&cmd);
    te_string_free(&url);
    te_string_free(&path);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
