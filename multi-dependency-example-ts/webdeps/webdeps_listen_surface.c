/** @file
 * @brief Webdeps Group
 *
 * Hypothesis H3: the services may be exposed beyond loopback.
 *
 * With the three services running, tapi_netexpose lists every listening
 * socket of the agent. The sockets held by the three processes (matched
 * by the socket inodes of /proc/PID/fd, the same inodes as in
 * /proc/net/tcp) are recorded with the address each is bound to, and every
 * listening socket is appended to the tapi_cybersec_report.
 *
 * - FAIL (H3 confirmed): a socket of a service is bound to 0.0.0.0, :: or
 *   any non-loopback address and is not the gateway's public port, or the
 *   gateway is not the only externally reachable service.
 * - PASS: the backends are loopback only.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "webdeps/webdeps_listen_surface"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "webdeps_common.h"

#define T   "webdeps_listen_surface"
#define H   "H3"

/** Most socket inodes remembered. */
#define MAX_INODES  64

int
main(int argc, char **argv)
{
    wd_ctx                       ctx = WD_CTX_INIT;
    tsapi_mde_report             report;
    bool                         report_up = false;
    tapi_netexpose_opt           opt = exposure_tcp_opt();
    te_vec                       socks;
    bool                         socks_up = false;
    const tapi_netexpose_socket *s;
    te_string                    out = TE_STRING_INIT;
    te_string                    why = TE_STRING_INIT;
    te_string                    exposed = TE_STRING_INIT;
    te_string                    reachable = TE_STRING_INIT;
    unsigned long                inodes[MAX_INODES];
    size_t                       n_inodes = 0;
    unsigned int                 n_listen = 0;
    unsigned int                 n_tier = 0;
    unsigned int                 n_exposed = 0;
    bool                         gw_loopback = true;
    const char                  *p;
    size_t                       i;

    TEST_START;

    TEST_STEP("Open a session and start the three services");
    WD_OPEN(ctx, T, H);
    tsapi_mde_report_init(&report);
    report_up = true;
    if (!wd_start_all(&ctx, &why))
        WD_FAIL(T, H, "a binary failed to start: %s", why.ptr);

    TEST_STEP("Collect the socket inodes held by the three processes");
    if (!wd_sh(&ctx, 20000, &out, "sh " WD_DIR "/wd.sh sockets %u %u %u",
               ctx.pid[WD_GW], ctx.pid[WD_GO], ctx.pid[WD_CS]))
        WD_FAIL(T, H, "cannot list the sockets of the services");
    for (p = te_string_value(&out); *p != '\0' && n_inodes < MAX_INODES; )
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

    TEST_STEP("tapi_netexpose: list the listening sockets");
    if (tapi_netexpose_sockets(ctx.session.factory, &opt, &socks) != 0)
        WD_FAIL(T, H, "tapi_netexpose cannot read the socket tables");
    socks_up = true;
    tapi_netexpose_sockets_log(&socks, true);

    TE_VEC_FOREACH(&socks, s)
    {
        te_string    addr = TE_STRING_INIT;
        te_string    subject = TE_STRING_INIT;
        unsigned int port;
        bool         mine = false;
        bool         loopback;
        unsigned int svc = WD_N;

        if (!tapi_netexpose_socket_is_listening(s))
            continue;
        n_listen++;
        port = exposure_port(&s->local);
        for (i = 0; i < n_inodes; i++)
        {
            if (inodes[i] == s->inode)
                mine = true;
        }
        for (i = 0; i < WD_N; i++)
        {
            if (ctx.port[i] == port && mine)
                svc = i;
        }
        loopback = exposure_is_loopback(&s->local);
        exposure_addr_str(&s->local, &addr);
        te_string_append(&subject, "tcp/%s:%u", addr.ptr, port);

        TEST_ARTIFACT("H3 listening socket: %s uid=%u owner=%s%s%s",
                      subject.ptr, s->uid, svc < WD_N ? wd_names[svc] :
                      mine ? "a service (other socket)" : "not a service",
                      exposure_is_wildcard(&s->local) ? " WILDCARD" : "",
                      !loopback && !exposure_is_wildcard(&s->local) ?
                      " NON-LOOPBACK" : "");

        if (!mine)
        {
            /* Whatever else the host listens on is not the services'. */
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "net.listen-surface", subject.ptr,
                                     "H3 information: not held by the web "
                                     "tier");
            goto next;
        }

        n_tier++;
        if (svc == WD_GW && !loopback)
        {
            gw_loopback = false;
            te_string_append(&reachable, "%s%s", reachable.len > 0 ? ", " :
                             "", subject.ptr);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "net.listen-surface", subject.ptr,
                                     "H3: gateway-rs public port, not "
                                     "loopback only");
        }
        else if (!loopback)
        {
            n_exposed++;
            te_string_append(&exposed, "%s%s %s", exposed.len > 0 ? ", " :
                             "", svc < WD_N ? wd_names[svc] : "a service",
                             subject.ptr);
            te_string_append(&reachable, "%s%s", reachable.len > 0 ? ", " :
                             "", subject.ptr);
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "net.backend-exposed", subject.ptr,
                                     "H3: %s bound beyond loopback",
                                     svc < WD_N ? wd_names[svc] : "a service");
        }
        else
        {
            tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                                     "net.listen-surface", subject.ptr,
                                     "H3: %s on loopback only",
                                     svc < WD_N ? wd_names[svc] : "a service");
        }
next:
        te_string_free(&addr);
        te_string_free(&subject);
    }

    tapi_cybersec_report_add(&report.cyber, TAPI_CYBERSEC_SEV_INFO,
                             "net.listen-surface", "web tier",
                             "H3 result: %u listening socket(s) on the "
                             "agent, %u held by the services, %u backend "
                             "socket(s) beyond loopback, gateway %s",
                             n_listen, n_tier, n_exposed,
                             gw_loopback ? "on loopback" : "public");

    {
        const char *labels[] = { "listening", "web tier", "beyond-loopback" };
        double      vals[] = { n_listen, n_tier, n_exposed };

        tsapi_mde_mi_bars("webdeps", "H3: listening sockets",
                          TE_MI_MEAS_UNITLESS_VALUE, "count",
                          TE_ARRAY_LEN(labels), labels, vals,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }
    {
        /* The report carries the findings; the verdict below is H3's. */
        te_string text = TE_STRING_INIT;

        (void)tsapi_mde_report_finish(&report, "webdeps",
                                      TAPI_CYBERSEC_SEV_CRITICAL, &text);
        te_string_free(&text);
    }

    TEST_STEP("Decide on H3");
    if (n_tier == 0)
        WD_FAIL(T, H, "H3 not decided: none of the %u listening socket(s) "
                "belongs to the three services - the listener table cannot "
                "be matched to their processes", n_listen);
    if (n_exposed > 0)
        WD_FAIL(T, H, "H3 confirmed: %u socket(s) of the services are "
                "bound beyond loopback and are not the gateway's public "
                "port: %s; externally reachable: %s", n_exposed,
                exposed.ptr, reachable.ptr);

    WD_PASS(T, H, "H3 disproved: all %u listening socket(s) of the services "
            "are loopback only (gateway-rs on %u too; externally reachable: "
            "%s)", n_tier, ctx.port[WD_GW], reachable.len > 0 ?
            reachable.ptr : "none");

    TEST_SUCCESS;

cleanup:

    if (socks_up)
        tapi_netexpose_sockets_free(&socks);
    if (report_up)
        tsapi_mde_report_free(&report);
    wd_close(&ctx);
    te_string_free(&out);
    te_string_free(&why);
    te_string_free(&exposed);
    te_string_free(&reachable);

    TEST_END;
}
