/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H3: the services may reach unexpected destinations.
 *
 * With the three services running, one request is sent through each of
 * them (a loop repeats it so that short connections are caught), and
 * tapi_egress_snapshot() samples the outgoing connections several times.
 * Only sockets held by the three processes count (matched by the inodes
 * of /proc/PID/fd). The allowed set is loopback only.
 *
 * - FAIL (H3 confirmed): any non-loopback destination.
 * - PASS: every destination of the services is loopback.
 *
 * Every destination is recorded in the tapi_cybersec_report.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_egress"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "tapi_egress.h"

#include "webdeps_common.h"

#define T   "webdeps_egress"
#define H   "H3"

/** Snapshots and the pause between them, us. */
#define SNAPSHOTS   20
#define PAUSE_US    150000
/** Requests the load sends to each service. */
#define WALKS       12
#define MAX_INODES  128

int
main(int argc, char **argv)
{
    wd_ctx                ctx = WD_CTX_INIT;
    tsapi_mde_report      report;
    bool                  report_up = false;
    tapi_netexpose_opt    opt = exposure_tcp_opt();
    tapi_egress_policy    policy = {
        .n_rules = 0, .rules = NULL, .allow_loopback = true,
        .allow_private = false,
    };
    te_string             why = TE_STRING_INIT;
    te_string             cmd = TE_STRING_INIT;
    te_string             seen = TE_STRING_INIT;
    te_string             foreign = TE_STRING_INIT;
    te_string             out = TE_STRING_INIT;
    unsigned int          pid_load = 0;
    unsigned int          n_dest = 0;
    unsigned int          n_foreign = 0;
    unsigned int          s;
    size_t                i;

    TEST_START;

    TEST_STEP("Open a session and start the three services");
    WD_OPEN(ctx, T, H);
    tsapi_mde_report_init(&report);
    report_up = true;
    if (!wd_start_all(&ctx, &why))
        WD_FAIL(T, H, "a binary failed to start: %s", why.ptr);

    TEST_STEP("Send requests through each service in the background");
    te_string_append(&cmd, "sh -c 'i=0; while [ $i -lt %d ]; do", WALKS);
    for (i = 0; i < WD_N; i++)
        te_string_append(&cmd, " curl -s -m 10 -o /dev/null "
                         "\"http://127.0.0.1:%u/ring?value=1&hops=3\";",
                         ctx.port[i]);
    te_string_append(&cmd, " sleep 0.1; i=$((i+1)); done'");
    if (!exposure_spawn(&ctx.session, cmd.ptr, &pid_load))
        WD_FAIL(T, H, "cannot start the requests");

    TEST_STEP("tapi_egress: sample the outgoing connections of the "
              "services; allowed set: loopback only");
    for (s = 0; s < SNAPSHOTS; s++)
    {
        te_vec                       conns;
        te_vec                       sockets;
        const tapi_netexpose_socket *c;
        unsigned long                inodes[MAX_INODES];
        size_t                       n_inodes = 0;
        const char                  *p;

        te_string_reset(&out);
        if (!wd_sh(&ctx, 20000, &out, "sh " WD_DIR "/wd.sh sockets %u %u %u",
                   ctx.pid[WD_GW], ctx.pid[WD_GO], ctx.pid[WD_CS]))
            WD_FAIL(T, H, "cannot list the sockets of the services");
        for (p = te_string_value(&out); *p != '\0' && n_inodes < MAX_INODES;)
        {
            char *end;

            inodes[n_inodes] = strtoul(p, &end, 10);
            if (end == p)
                break;
            n_inodes++;
            p = end;
            while (*p == '\n' || *p == ' ')
                p++;
        }

        if (tapi_egress_snapshot(ctx.session.factory, &opt, &conns) != 0)
            WD_FAIL(T, H, "tapi_egress cannot read the connections");
        if (tapi_netexpose_sockets(ctx.session.factory, &opt, &sockets) != 0)
        {
            te_vec_free(&conns);
            WD_FAIL(T, H, "tapi_netexpose cannot read the socket tables");
        }

        TE_VEC_FOREACH(&conns, c)
        {
            te_string                    addr = TE_STRING_INIT;
            te_string                    subject = TE_STRING_INIT;
            const tapi_netexpose_socket *l;
            bool                         mine = false;
            bool                         inbound = false;

            for (i = 0; i < n_inodes; i++)
            {
                if (inodes[i] == c->inode)
                    mine = true;
            }
            TE_VEC_FOREACH(&sockets, l)
            {
                if (tapi_netexpose_socket_is_listening(l) &&
                    exposure_port(&l->local) == exposure_port(&c->local))
                    inbound = true;
            }
            if (!mine || inbound || c->inode == 0)
                goto next;

            exposure_addr_str(&c->remote, &addr);
            te_string_append(&subject, "tcp/%s:%u", addr.ptr,
                             exposure_port(&c->remote));
            if (strstr(te_string_value(&seen), subject.ptr) == NULL)
            {
                bool allowed = tapi_egress_policy_allows(
                                   &policy, IPPROTO_TCP, CONST_SA(&c->remote));

                n_dest++;
                te_string_append(&seen, "%s ", subject.ptr);
                TEST_ARTIFACT("H3 outbound destination: %s (%s)",
                              subject.ptr, allowed ? "loopback, allowed" :
                              "NOT loopback");
                if (allowed)
                {
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_INFO,
                                             "net.egress-destination",
                                             subject.ptr, "H3: loopback");
                }
                else
                {
                    n_foreign++;
                    te_string_append(&foreign, "%s%s", foreign.len > 0 ?
                                     ", " : "", subject.ptr);
                    tapi_cybersec_report_add(&report.cyber,
                                             TAPI_CYBERSEC_SEV_HIGH,
                                             "net.unexpected-egress",
                                             subject.ptr, "H3: outside the "
                                             "loopback-only allowed set");
                }
            }
next:
            te_string_free(&addr);
            te_string_free(&subject);
        }

        te_vec_free(&conns);
        tapi_netexpose_sockets_free(&sockets);
        usleep(PAUSE_US);
    }

    {
        const char *labels[] = { "destinations", "non-loopback" };
        double      vals[] = { n_dest, n_foreign };

        tsapi_mde_mi_bars("webdeps", "H3: outbound destinations of the "
                          "services", TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        te_string text = TE_STRING_INIT;

        (void)tsapi_mde_report_finish(&report, "webdeps",
                                      TAPI_CYBERSEC_SEV_CRITICAL, &text);
        te_string_free(&text);
    }

    TEST_STEP("Decide on H3");
    if (n_foreign > 0)
        WD_FAIL(T, H, "H3 confirmed: the services connected to %u "
                "non-loopback destination(s): %s", n_foreign, foreign.ptr);

    WD_PASS(T, H, "H3 disproved: the services' outbound destinations are "
            "loopback only (%u distinct seen: %s)", n_dest,
            n_dest > 0 ? te_string_value(&seen) : "none caught in the "
            "snapshots");

    TEST_SUCCESS;

cleanup:

    if (ctx.session_up)
        exposure_kill(&ctx.session, pid_load);
    if (report_up)
        tsapi_mde_report_free(&report);
    wd_close(&ctx);
    te_string_free(&why);
    te_string_free(&cmd);
    te_string_free(&seen);
    te_string_free(&foreign);
    te_string_free(&out);

    TEST_END;
}
