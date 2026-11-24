/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: port_and_egress_policy, listeners and outbound
 *        connections of the web tier against an allowed list (settles H3)
 *
 * Hypothesis H3: a service listens on a non-loopback address or connects to
 * a host outside the allowed list (the addresses fixed in main.rs:33-36,
 * Program.cs:24,34,78 and main.go:46,51,87).
 *
 * Allowed list: loopback only, and the ports ./scripts/run.sh starts (the
 * contract ports). Starts gateway-rs, service-cs and service-go, sends each
 * a valid request, lists the listeners with tapi_netexpose and the outbound
 * connections with tapi_egress, and adds every result to the
 * tapi_cybersec_report.
 *
 * Verdicts (every one starts with H3):
 *  - "H3 listener PROC ADDR:PORT": one line per listener, informational.
 *  - "H3 DISPROVED all-loopback" (pass): no listener off loopback and no
 *    outbound connection outside the list.
 *  - "H3 CONFIRMED non-loopback-PROC-ADDR:PORT" or "H3 CONFIRMED
 *    egress-non-loopback-PROC-ADDR:PORT" (fail), with the addresses found.
 *  - "H3 setup-<step>-failed: ..." (fail): nothing is settled.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/port_and_egress_policy"

#include "te_config.h"

#include <ifaddrs.h>
#include <net/if.h>


#include "webdeps_lib.h"

#define EVID_LEN    700

/** The only bind addresses the test accepts. */
static bool
bind_allowed(const char *addr)
{
    return strcmp(addr, "127.0.0.1") == 0 || strcmp(addr, "::1") == 0;
}

/** Source lines holding the hardcoded endpoints, per service. */
static const unsigned gw_lines[] = { 33, 34, 35, 36 };
static const unsigned go_lines[] = { 46, 87 };
static const unsigned cs_lines[] = { 24, 34, 78 };

/** Allowed list of the egress checks: loopback only, any port. */
static const tapi_egress_policy loopback_only = {
    .n_rules = 0, .rules = NULL, .allow_loopback = true,
    .allow_private = false,
};

/** True when a connect to @p port on a non-loopback address of the agent works. */
static bool
reachable_outside(unsigned port, char *via, size_t size)
{
    struct ifaddrs *ifa;
    struct ifaddrs *i;
    bool            ok = false;

    via[0] = '\0';
    if (getifaddrs(&ifa) != 0)
        return false;
    for (i = ifa; i != NULL && !ok; i = i->ifa_next)
    {
        struct sockaddr_in sa;
        struct timeval     tv = { .tv_sec = 1 };
        int                s;

        if (i->ifa_addr == NULL || i->ifa_addr->sa_family != AF_INET ||
            (i->ifa_flags & IFF_LOOPBACK) != 0)
            continue;
        memcpy(&sa, i->ifa_addr, sizeof(sa));
        sa.sin_port = htons(port);
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0)
            continue;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0)
        {
            ok = true;
            inet_ntop(AF_INET, &sa.sin_addr, via, size);
        }
        close(s);
    }
    freeifaddrs(ifa);
    return ok;
}

/** H3: start the three services, record every listener, check each is loopback. */
int
main(int argc, char **argv)
{
    res_t                res = { .kind = R_PASS };
    proc_t              *svc[NAMES] = { NULL };
    tsapi_mde_session    session = { .ta = NULL };
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    te_vec               socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    const int            which[] = { GO, CS, GW };
    char                 first_bad[200] = "";
    char                 first_egress[200] = "";
    char                 evid[EVID_LEN] = "";
    char                 listen_[EVID_LEN] = "";
    char                 egress[EVID_LEN] = "";
    unsigned             n_listen = 0;
    unsigned             n_bad_listen = 0;
    unsigned             n_bad_egress = 0;
    unsigned             n_conns = 0;
    unsigned             n_lit = 0;
    int                  round;
    int                  i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;
    if (tsapi_mde_session_init(&session, "port_and_egress_policy") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "H3 setup-open-session-failed: no session "
                "on the agent for the scanners");
        goto verdict;
    }

    TEST_STEP("Start the three services");
    for (i = 0; i < 3; i++)
    {
        svc[which[i]] = svc_start_exposed(&res, &session, which[i]);
        if (svc[which[i]] == NULL)
        {
            char orig[sizeof(res.msg)];

            snprintf(orig, sizeof(orig), "%s", res.msg);
            res_set(&res, R_SETUP, "H3 setup-start-%s-failed: %.1400s",
                    names[which[i]], orig);
            goto verdict;
        }
    }

    opt.udp = false;
    opt.tcp = true;

    TEST_STEP("Literal endpoints in the sources");
    n_lit += endpoint_scan("web/gateway-rs/src/main.rs", gw_lines,
                           TE_ARRAY_LEN(gw_lines));
    n_lit += endpoint_scan("web/service-go/main.go", go_lines,
                           TE_ARRAY_LEN(go_lines));
    n_lit += endpoint_scan("web/service-cs/Program.cs", cs_lines,
                           TE_ARRAY_LEN(cs_lines));

    TEST_STEP("Every listening socket of the three processes");
    for (i = 0; i < NAMES; i++)
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    if (tapi_netexpose_sockets(session.factory, &opt, &socks) != 0)
    {
        setup_svc = "tapi_netexpose";
        res_set(&res, R_SETUP, "H3 setup-netexpose-failed: tapi_netexpose "
                "cannot read the socket tables");
        goto verdict;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        char     addr[64];
        char     via[64];
        int      o;
        bool     wild;
        bool     outside;

        if (!tapi_netexpose_socket_is_listening(s))
            continue;
        o = owner_of(svc, ino, n_ino, s->inode);
        if (o < 0)
            continue;
        sock_addr(&s->local, addr, sizeof(addr));
        wild = !bind_allowed(addr);
        outside = wild && reachable_outside(sock_port(&s->local), via,
                                            sizeof(via));
        n_listen++;
        RING_VERDICT("H3 listener %s %s:%u", names[o], addr,
                     sock_port(&s->local));
        append(listen_, sizeof(listen_), "%s %s:%u%s; ", names[o], addr,
               sock_port(&s->local), wild ? " (NON-LOOPBACK)" : "");
        RING("webdeps H3: %s listens on %s:%u, non-loopback bind %s, "
             "reachable from outside loopback %s%s%s", names[o], addr,
             sock_port(&s->local), wild ? "yes" : "no",
             outside ? "yes via " : "no", outside ? via : "", "");
        T_FINDING(wild ? TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
                  "net.listener", names[o],
                  "listens on %s:%u; reachable from outside loopback: %s",
                  addr, sock_port(&s->local), outside ? "yes" : "no");
        if (!port_in_contract(sock_port(&s->local)))
            T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "net.port-not-started",
                      names[o], "listens on port %u, which ./scripts/run.sh "
                      "does not start (contract ports only)",
                      sock_port(&s->local));
        if (wild)
        {
            n_bad_listen++;
            append(evid, sizeof(evid), "%s listens on %s:%u; ", names[o],
                   addr, sock_port(&s->local));
            if (first_bad[0] == '\0')
                snprintf(first_bad, sizeof(first_bad),
                         "H3 CONFIRMED non-loopback-%s-%s:%u", names[o], addr,
                         sock_port(&s->local));
        }
    }
    te_vec_free(&socks);
    if (n_listen == 0)
    {
        setup_svc = "tapi_netexpose";
        res_set(&res, R_SETUP, "H3 setup-netexpose-failed: tapi_netexpose "
                "shows no listening socket of the three services");
        goto verdict;
    }

    TEST_STEP("Normal traffic and every outbound destination (tapi_egress)");
    for (round = 0; round < 6; round++)
    {
        te_vec conns = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *c;
        hg_res h;

        for (i = 0; i < NAMES; i++)
            http_get(svc[i]->port, REQUEST, 5, &h);
        for (i = 0; i < NAMES; i++)
            n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
        if (tapi_egress_snapshot(session.factory, &opt, &conns) != 0)
        {
            setup_svc = "tapi_egress";
            res_set(&res, R_SETUP, "H3 setup-egress-failed: tapi_egress "
                    "cannot read the connections of the agent");
            te_vec_free(&conns);
            goto verdict;
        }
        TE_VEC_FOREACH(&conns, c)
        {
            char addr[64];
            char rec[120];
            int  o = owner_of(svc, ino, n_ino, c->inode);

            if (o < 0 || c->inode == 0 || sock_port(&c->remote) == 0 ||
                port_in_contract(sock_port(&c->local)))
                continue;
            sock_addr(&c->remote, addr, sizeof(addr));
            snprintf(rec, sizeof(rec), "%s->%s:%u", names[o], addr,
                     sock_port(&c->remote));
            n_conns++;
            if (strstr(egress, rec) == NULL)
                append(egress, sizeof(egress), "%s; ", rec);
            if (tapi_egress_policy_allows(&loopback_only, IPPROTO_TCP,
                                          CONST_SA(&c->remote)))
            {
                T_FINDING(TAPI_CYBERSEC_SEV_INFO, "net.egress", names[o],
                          "outbound to %s:%u, loopback (in the allowed list)",
                          addr, sock_port(&c->remote));
            }
            else
            {
                n_bad_egress++;
                T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "net.unexpected-egress",
                          names[o], "outbound to %s:%u, not loopback (outside the allowed list)",
                          addr, sock_port(&c->remote));
                append(evid, sizeof(evid), "%s connects to %s:%u; ", names[o],
                       addr, sock_port(&c->remote));
                if (first_egress[0] == '\0')
                    snprintf(first_egress, sizeof(first_egress),
                             "H3 CONFIRMED egress-non-loopback-%s-%s:%u", names[o],
                             addr, sock_port(&c->remote));
            }
        }
        te_vec_free(&conns);
        usleep(100000);
    }
    if (n_lit > 0)
        append(evid, sizeof(evid), "%u source line(s) with an address outside "
               "the list; ", n_lit);
    RING("webdeps H3: listeners: %s", listen_);
    RING("webdeps H3: outbound: %s", egress[0] != '\0' ? egress : "(none)");

    if (n_bad_listen > 0 || n_bad_egress > 0)
        res_set(&res, R_FAIL, "%s: %s listeners: %s outbound: %s",
                first_bad[0] != '\0' ? first_bad : first_egress[0] != '\0' ?
                first_egress : "H3 CONFIRMED non-loopback-traffic", evid, listen_,
                egress[0] != '\0' ? egress : "(none)");
    else
        res_set(&res, R_PASS, "H3 DISPROVED all-loopback: every listener is on "
                "127.0.0.1 or ::1 (%s) and every outbound destination (%u connection "
                "sample(s): %s) is loopback%s", listen_,
                n_conns, egress[0] != '\0' ? egress : "none seen",
                n_lit > 0 ? "; note: some literal lines name hosts outside "
                "the allowed list, see the report" : "");

verdict:
    if (session.ta != NULL)
        tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}
