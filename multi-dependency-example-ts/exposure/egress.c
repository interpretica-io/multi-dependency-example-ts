/** @file
 * @brief Exposure Group
 *
 * What the agent talks to while walks run through the web tier, against
 * where it is allowed to talk: the tier itself, 127.0.0.1:8081-8083.
 *
 * Outgoing connections are taken from the socket tables with
 * tapi_egress_snapshot() several times during the window, so that short
 * connections are caught too, and judged with tapi_egress_policy_allows().
 * The agent shares the host network, so the tables hold the host's
 * connections as well; the gate judges the connections owned by the
 * agent's user (the tier, the walks, the controls), connections accepted
 * by a local listener are inbound and not egress, and loopback is not
 * egress at all (a loopback peer outside the tier is recorded as an
 * info finding). The host-wide view of tapi_egress_check() is logged next
 * to it for reference.
 *
 * Known-bad control: during the window a connection is attempted to a
 * TEST-NET address (198.51.100.1:80, RFC 5737: it never answers), or, if
 * there is no route there, held open to the agent's own non-loopback
 * address. It must be reported as @c net.unexpected-egress.
 *
 * Deep check: every walk sent during the window is answered, with the
 * node steps a single walk reports.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "exposure/egress"

#include "te_config.h"

#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"

#include "tapi_egress.h"

#include "exposure_common.h"

/** Snapshots taken during the window. */
#define N_SNAPSHOTS     6
/** Distinct destinations remembered. */
#define MAX_DEST        64
/** Where the walks of the window write their answers. */
#define LOAD_OUT        "/tmp/mde-exposure-egress.out"
/** Control destination: TEST-NET-2, documentation only, never answers. */
#define TESTNET_ADDR    "198.51.100.1"
/** Port the fallback control holds a connection to. */
#define HOLD_PORT       18097

/** One destination and how often it was seen. */
typedef struct dest_count {
    char         key[96];   /**< "tcp/addr:port". */
    unsigned int seen;      /**< Snapshots it was in. */
    bool         flagged;   /**< Already reported. */
} dest_count;

/** Find or add a destination. */
static dest_count *
dest_get(dest_count *d, unsigned int *n, const char *key)
{
    unsigned int i;

    for (i = 0; i < *n; i++)
    {
        if (strcmp(d[i].key, key) == 0)
            return &d[i];
    }
    if (*n >= MAX_DEST)
        return NULL;
    memset(&d[*n], 0, sizeof(d[*n]));
    TE_SPRINTF(d[*n].key, "%s", key);
    return &d[(*n)++];
}

/** Whether a local port is one somebody listens on (an accepted socket). */
static bool
port_is_listened(const te_vec *sockets, unsigned int port)
{
    const tapi_netexpose_socket *s;

    TE_VEC_FOREACH(sockets, s)
    {
        if (tapi_netexpose_socket_is_listening(s) &&
            exposure_port(&s->local) == port)
            return true;
    }

    return false;
}

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    int                     walks;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_web           web;
    bool                    web_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    tapi_cybersec_report    hostwide;
    bool                    hostwide_up = false;
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
    unsigned int            uid = 0;
    unsigned int            steps_one = 0;
    unsigned int            answered = 0;
    double                  t_walk = 0;
    double                  t_window;
    double                  t0;
    unsigned int            pid_load = 0;
    unsigned int            pid_control = 0;
    unsigned int            pid_hold_listener = 0;
    te_string               control_subject = TE_STRING_INIT;
    te_string               host_text = TE_STRING_INIT;
    struct sockaddr_in      host;
    te_string               cmd = TE_STRING_INIT;
    te_string               url = TE_STRING_INIT;
    dest_count              dests[MAX_DEST];
    unsigned int            n_dests = 0;
    double                  per_snap[5 * N_SNAPSHOTS];
    const char             *snap_lines[] = { "owned_out", "inbound",
                                             "foreign", "orphan",
                                             "flagged" };
    const char             *snap_labels[N_SNAPSHOTS];
    char                    snap_names[N_SNAPSHOTS][8];
    unsigned int            n_flagged = 0;
    unsigned int            n_loop_peer = 0;
    unsigned int            s;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);
    TEST_GET_INT_PARAM(walks);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "exposure_egress", dut, session_up);
    if (!tsapi_mde_web_built(&session, &dut))
        TEST_SKIP("The web tier is not built in this configuration");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("There is no curl on the agent");

    tsapi_mde_report_init(&report);
    report_up = true;
    tapi_cybersec_report_init(&hostwide);
    hostwide_up = true;

    CHECK_RC(tsapi_mde_sh(&session, 10000, &res, "id -u"));
    if (!tsapi_mde_sh_ok(&res))
        TEST_FAIL("Cannot read the user id of the agent");
    uid = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);
    RING("Agent user id: %u", uid);

    TEST_STEP("Start the web tier and send one walk");
    web_up = true;
    CHECK_RC(tsapi_mde_web_start(&session, &dut, &web));
    if (!exposure_web_wait(&session))
        TEST_VERDICT("The web tier does not accept connections on its "
                     "contract ports");
    exposure_chart_web_start(&web);
    if (!exposure_walk(&session, TSAPI_MDE_WEB_GATEWAY_PORT, 3, &steps_one,
                       &t_walk, NULL))
        TEST_VERDICT("The gateway does not answer a walk");
    TEST_ARTIFACT("One walk (hops=3): %u node step(s) in %.3f s", steps_one,
                  t_walk);

    TEST_STEP("Start the walks of the window and the control");
    tsapi_mde_web_url(TSAPI_MDE_WEB_GATEWAY_PORT, 1, 3, &url);
    te_string_append(&cmd, "sh -c 'rm -f " LOAD_OUT "; i=0; "
                     "while [ $i -lt %d ]; do curl -s -m 10 \"%s\" "
                     ">> " LOAD_OUT "; echo >> " LOAD_OUT "; "
                     "sleep 0.2; i=$((i+1)); done'", walks, url.ptr);
    if (!exposure_spawn(&session, cmd.ptr, &pid_load))
        TEST_FAIL("Cannot start the walks of the window");

    if (exposure_sh_quiet(&session, "ip route get " TESTNET_ADDR
                                    " >/dev/null 2>&1"))
    {
        if (!exposure_spawn(&session, "curl -s -m 8 http://" TESTNET_ADDR "/",
                            &pid_control))
            TEST_VERDICT("Cannot start the egress control");
        te_string_append(&control_subject, "tcp/%s:80", TESTNET_ADDR);
    }
    else if (tsapi_mde_have(&session, "python3") &&
             exposure_host_addr(&session, &host, &host_text))
    {
        te_string hold = TE_STRING_INIT;

        if (!exposure_listener_start(&session, HOLD_PORT, "0.0.0.0",
                                     &pid_hold_listener))
            TEST_VERDICT("Cannot start the egress control listener");
        te_string_append(&hold, "python3 -c 'import socket, time; "
                         "s = socket.create_connection((\"%s\", %u)); "
                         "time.sleep(8)'", host_text.ptr, HOLD_PORT);
        if (!exposure_spawn(&session, hold.ptr, &pid_control))
        {
            te_string_free(&hold);
            TEST_VERDICT("Cannot start the egress control");
        }
        te_string_free(&hold);
        te_string_append(&control_subject, "tcp/%s:%u", host_text.ptr,
                         HOLD_PORT);
    }
    else
    {
        WARN("No route to TEST-NET and no host address: no egress control");
    }
    /* Let the connections get going before the first snapshot. */
    usleep(300000);

    TEST_STEP("Watch the outgoing connections during the window");
    t0 = tsapi_mde_now();
    for (s = 0; s < N_SNAPSHOTS; s++)
    {
        te_vec                       conns;
        te_vec                       sockets;
        const tapi_netexpose_socket *c;
        unsigned int owned = 0, inbound = 0, foreign = 0, orphan = 0;
        unsigned int flagged = 0;

        CHECK_RC(tapi_egress_snapshot(session.factory, &opt, &conns));
        if (tapi_netexpose_sockets(session.factory, &opt, &sockets) != 0)
        {
            te_vec_free(&conns);
            TEST_FAIL("Cannot read the socket tables of the agent");
        }

        TE_VEC_FOREACH(&conns, c)
        {
            te_string   key = TE_STRING_INIT;
            te_string   addr = TE_STRING_INIT;
            dest_count *d;

            if (port_is_listened(&sockets, exposure_port(&c->local)))
            {
                inbound++;
                continue;
            }
            if (c->inode == 0)
            {
                /* TIME_WAIT and the like: no owner any more. */
                orphan++;
                continue;
            }
            if (c->uid != uid)
            {
                foreign++;
                continue;
            }
            owned++;

            exposure_addr_str(&c->remote, &addr);
            te_string_append(&key, "tcp/%s:%u", addr.ptr,
                             exposure_port(&c->remote));
            d = dest_get(dests, &n_dests, key.ptr);
            if (d != NULL)
                d->seen++;

            if (!tapi_egress_policy_allows(&policy, IPPROTO_TCP,
                                           CONST_SA(&c->remote)))
            {
                flagged++;
                if (d != NULL && !d->flagged)
                {
                    d->flagged = true;
                    n_flagged++;
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_HIGH,
                                             "net.unexpected-egress",
                                             key.ptr,
                                             "a process of the agent's user "
                                             "connects there during the "
                                             "walks and no rule allows it");
                }
            }
            else if (!tapi_egress_policy_allows(&strict, IPPROTO_TCP,
                                                CONST_SA(&c->remote)) &&
                     d != NULL && !d->flagged)
            {
                d->flagged = true;
                n_loop_peer++;
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_INFO,
                                         "net.loopback-peer", key.ptr,
                                         "a loopback connection outside "
                                         "the web tier (the test "
                                         "environment's own, most likely)");
            }

            te_string_free(&key);
            te_string_free(&addr);
        }

        per_snap[0 * N_SNAPSHOTS + s] = owned;
        per_snap[1 * N_SNAPSHOTS + s] = inbound;
        per_snap[2 * N_SNAPSHOTS + s] = foreign;
        per_snap[3 * N_SNAPSHOTS + s] = orphan;
        per_snap[4 * N_SNAPSHOTS + s] = flagged;
        TE_SPRINTF(snap_names[s], "s%u", s);
        snap_labels[s] = snap_names[s];
        RING("Snapshot %u: %u owned outgoing, %u inbound, %u foreign, "
             "%u orphan, %u not allowed", s, owned, inbound, foreign,
             orphan, flagged);

        te_vec_free(&conns);
        tapi_netexpose_sockets_free(&sockets);
        usleep(250000);
    }

    TEST_STEP("The host-wide view of tapi_egress, for reference");
    CHECK_RC(tapi_egress_check(session.factory, &opt, &policy, &hostwide));
    tapi_cybersec_report_log(&hostwide);
    t_window = tsapi_mde_now() - t0;
    TEST_ARTIFACT("Host-wide tapi_egress_check: %u finding(s) at high or "
                  "worse (not gated: the host's own connections)",
                  tapi_cybersec_report_count(&hostwide,
                                             TAPI_CYBERSEC_SEV_HIGH));

    TEST_STEP("Check the control was seen, then drop it");
    if (control_subject.len != 0)
    {
        tsapi_mde_report_expect(&report, "net.unexpected-egress",
                                control_subject.ptr);
        tsapi_mde_report_drop_subject(&report, control_subject.ptr);
        if (n_flagged > 0)
            n_flagged--;
    }

    TEST_STEP("Check every walk of the window was answered");
    CHECK_RC(tsapi_mde_sh(&session, 60000, &res,
                          "i=0; while kill -0 %u 2>/dev/null && "
                          "[ $i -lt 200 ]; do i=$((i+1)); sleep 0.2; done",
                          pid_load));
    CHECK_RC(tsapi_mde_sh(&session, 10000, &res,
                          "grep -cE '^\\[(gateway-rs|service-go|service-cs)"
                          "\\] hops=' " LOAD_OUT));
    answered = (unsigned int)strtoul(te_string_value(&res.out), NULL, 10);
    TEST_ARTIFACT("Walks of the window: %d sent, %u node step(s) answered, "
                  "%u per walk expected", walks, answered, steps_one);
    if (answered != (unsigned int)walks * steps_one)
        TEST_VERDICT("The walks of the egress window reported %u node "
                     "step(s), expected %u", answered,
                     (unsigned int)walks * steps_one);

    TEST_STEP("Chart connections per destination and per snapshot");
    {
        const char  *labels[MAX_DEST];
        double       vals[MAX_DEST];
        unsigned int k;

        for (k = 0; k < n_dests; k++)
        {
            labels[k] = dests[k].key;
            vals[k] = dests[k].seen;
            TEST_ARTIFACT("destination %s: seen in %u snapshot(s)%s",
                          dests[k].key, dests[k].seen,
                          dests[k].flagged ? ", reported" : "");
        }
        tsapi_mde_mi_bars("egress", "Owned outgoing connections per "
                          "destination (snapshots seen in)",
                          TE_MI_MEAS_UNITLESS_VALUE, "connections",
                          n_dests, labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    exposure_mi_matrix("egress", "snapshots",
                       "Connections per snapshot during the window",
                       N_SNAPSHOTS, snap_labels, TE_ARRAY_LEN(snap_lines),
                       snap_lines, per_snap);
    tsapi_mde_mi_point("egress", "Length of the egress window",
                       TE_MI_MEAS_TIME, "window", t_window,
                       TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("%u destination(s), %u not allowed (controls excluded), "
                  "%u loopback peer(s) outside the tier", n_dests, n_flagged,
                  n_loop_peer);

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "exposure", min_sev);

    TEST_SUCCESS;

cleanup:

    exposure_kill(&session, pid_load);
    exposure_kill(&session, pid_control);
    exposure_kill(&session, pid_hold_listener);
    if (session_up)
        (void)exposure_sh_quiet(&session, "rm -f " LOAD_OUT);
    if (web_up)
        tsapi_mde_web_stop(&web);
    if (hostwide_up)
        tapi_cybersec_report_free(&hostwide);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_sh_result_free(&res);
    te_string_free(&control_subject);
    te_string_free(&host_text);
    te_string_free(&cmd);
    te_string_free(&url);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
