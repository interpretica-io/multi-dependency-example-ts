/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t14_exposure, listeners and outbound destinations of the
 *        web tier (settles H3)
 *
 * Start gateway-rs, service-go and service-cs and, while they run, read
 * every listening socket they own with tapi_netexpose: the address, the
 * port and whether it is reachable from outside the loopback interface (a
 * wildcard or non-loopback bind, confirmed by a connect to each non-loopback
 * address of the agent). Send normal traffic and read every outbound
 * connection of the three processes with tapi_egress. The literal
 * addresses of main.rs:33-36, main.go:46-51 and Program.cs:24-78 are read
 * from the sources; a listener or destination outside them is a finding.
 * Every result is appended to the tapi_cybersec_report.
 *
 * H3 CONFIRMED if a service listens on a non-loopback address or connects
 * to a host that is not in those literals; H3 DISPROVED otherwise.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t14_exposure"

#include "te_config.h"

#include <ifaddrs.h>
#include <net/if.h>

#include "webdeps_lib.h"

#define EVID_LEN    700

/** Source lines holding the hardcoded endpoints, per service. */
static const unsigned gw_lines[] = { 33, 34, 35, 36 };
static const unsigned go_lines[] = { 46, 47, 48, 49, 50, 51 };
static const unsigned cs_lines[] = { 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
                                     34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                                     44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
                                     54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
                                     64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
                                     74, 75, 76, 77, 78 };

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

int
main(int argc, char **argv)
{
    res_t                res = { .kind = R_PASS };
    proc_t              *svc[NAMES] = { NULL };
    tsapi_mde_session    session = { .ta = NULL };
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    tapi_egress_rule     rules[2 * NAMES];
    tapi_egress_policy   policy = { .n_rules = 2 * NAMES, .rules = rules,
                                    .allow_loopback = false,
                                    .allow_private = false };
    te_vec               socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    const int            which[] = { GO, CS, GW };
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
    if (tsapi_mde_session_init(&session, "t14_exposure") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for the scanners");
        goto verdict;
    }

    TEST_STEP("Start the three services");
    for (i = 0; i < 3; i++)
    {
        svc[which[i]] = svc_start_exposed(&res, &session, which[i]);
        if (svc[which[i]] == NULL)
            goto verdict;
    }

    for (i = 0; i < NAMES; i++)
    {
        rules[2 * i] = (tapi_egress_rule){ IPPROTO_TCP, "127.0.0.1/32",
                                           tab_port[i], tab_port[i] };
        rules[2 * i + 1] = (tapi_egress_rule){ IPPROTO_TCP, "::1/128",
                                               tab_port[i], tab_port[i] };
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
        res_set(&res, R_INCONCLUSIVE, "tapi_netexpose cannot read the "
                "socket tables");
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
        wild = !is_loopback(addr);
        outside = wild && reachable_outside(sock_port(&s->local), via,
                                            sizeof(via));
        n_listen++;
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
        if (wild)
        {
            n_bad_listen++;
            append(evid, sizeof(evid), "%s listens on %s:%u; ", names[o],
                   addr, sock_port(&s->local));
        }
    }
    te_vec_free(&socks);
    if (n_listen == 0)
    {
        setup_svc = "tapi_netexpose";
        res_set(&res, R_INCONCLUSIVE, "tapi_netexpose shows no listening "
                "socket of the three services");
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
            res_set(&res, R_INCONCLUSIVE, "tapi_egress cannot read the "
                    "connections of the agent");
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
            if (tapi_egress_policy_allows(&policy, IPPROTO_TCP,
                                          CONST_SA(&c->remote)))
            {
                T_FINDING(TAPI_CYBERSEC_SEV_INFO, "net.egress", names[o],
                          "outbound to %s:%u, a literal of the sources",
                          addr, sock_port(&c->remote));
            }
            else
            {
                n_bad_egress++;
                T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "net.unexpected-egress",
                          names[o], "outbound to %s:%u, not in the literals",
                          addr, sock_port(&c->remote));
                append(evid, sizeof(evid), "%s connects to %s:%u; ", names[o],
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
        res_set(&res, R_FAIL, "H3 CONFIRMED: %s listeners: %s outbound: %s",
                evid, listen_, egress[0] != '\0' ? egress : "(none)");
    else
        res_set(&res, R_PASS, "H3 DISPROVED: every listener is on loopback "
                "(%s) and every outbound destination (%u connection "
                "sample(s): %s) is a literal of the sources%s", listen_,
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
