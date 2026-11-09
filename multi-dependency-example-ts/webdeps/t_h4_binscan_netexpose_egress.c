/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H4, listeners and egress of the web tier
 *
 * Run the three services (each port read with tapi_netexpose), send one
 * normal request to each, and with tapi_egress compare all their outgoing
 * connections with an allowed list of loopback only; every unexpected
 * destination goes into the tapi_cybersec_report and fails the test. The
 * test also fails if tapi_netexpose shows a service listening on a
 * non-loopback address. tapi_binscan on gateway-rs, service-go and the C#
 * host adds its result to the same report as context only: it never
 * fails the test. A scanner that comes back with no data at all is
 * INCONCLUSIVE, not a finding.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t_h4_binscan_netexpose_egress"

#include "te_config.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "te_sockaddr.h"
#include "tsapi_mde.h"

#include "tapi_cybersec.h"
#include "tapi_netexpose.h"
#include "tapi_egress.h"
#include "tapi_binscan.h"

#include "webdeps_lib.h"

#define FIRST_LEN   400

/** Remember the first finding only; the report keeps all of them. */
static void
first_finding(char *first, const char *fmt, ...)
{
    va_list ap;

    if (first[0] != '\0')
        return;
    va_start(ap, fmt);
    vsnprintf(first, FIRST_LEN, fmt, ap);
    va_end(ap);
}

/** NX, PIE, RELRO and canary of one binary, added to the report as INFO. */
static bool
scan_one_binary(res_t *r, tsapi_mde_session *session, const char *path,
                const char *subject, tapi_cybersec_report *report)
{
    tapi_binscan_info info;
    bool              pie;
    bool              nx;
    te_errno          rc;

    rc = tapi_binscan_inspect(session->ta, path, &info);
    if (rc != 0 || !info.elf)
    {
        setup_svc = subject;
        res_set(r, R_SETUP, "tapi_binscan cannot read %s as ELF (rc %d)",
                path, (int)rc);
        return false;
    }
    tapi_binscan_info_log(&info, path);
    pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
          info.kind == TAPI_BINSCAN_KIND_SHARED;
    nx = info.nx && !info.nx_unknown;
    tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                             "binary.hardening", subject, "%s: NX %s, PIE "
                             "%s, RELRO %s, stack canary %s", path,
                             nx ? "yes" : "no", pie ? "yes" : "no",
                             info.relro == TAPI_BINSCAN_RELRO_NONE ?
                             "no" : "yes", info.canary ? "yes" : "no");
    tapi_binscan_info_free(&info);
    return true;
}

/** tapi_binscan on the three service binaries; context only. */
static bool
scan_binaries(res_t *r, tsapi_mde_session *session,
              tapi_cybersec_report *report)
{
    int i;
    char path[600];

    for (i = 0; i < NAMES; i++)
    {
        snprintf(path, sizeof(path), "%s/dist/bin/%s", src_root, names[i]);
        if (!scan_one_binary(r, session, path, names[i], report))
            return false;
    }
    return true;
}

/** Every listener of the three processes is on the expected list. */
static bool
scan_listeners(res_t *r, tsapi_mde_session *session, proc_t **svc,
               tapi_cybersec_report *report, char *first)
{
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    te_vec               socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    unsigned             listeners = 0;
    int                  i;

    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    if (tapi_netexpose_sockets(session->factory, &opt, &socks) != 0)
    {
        res_set(r, R_SETUP, "tapi_netexpose cannot read the socket tables");
        te_vec_free(&socks);
        return false;
    }
    if (te_vec_size(&socks) == 0)
    {
        res_set(r, R_INCONCLUSIVE, "tapi_netexpose returned no sockets at "
                "all");
        te_vec_free(&socks);
        return false;
    }
    TE_VEC_FOREACH(&socks, s)
    {
        char     addr[64];
        int      o;
        unsigned port;

        if (!tapi_netexpose_socket_is_listening(s))
            continue;
        o = owner_of(svc, ino, n_ino, s->inode);
        if (o < 0)
            continue;
        listeners++;
        sock_addr(&s->local, addr, sizeof(addr));
        port = sock_port(&s->local);
        if (!is_loopback(addr))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "net.non-loopback-listener", names[o],
                                     "listens on %s:%u, not a loopback "
                                     "address", addr, port);
            first_finding(first, "%s: listens on non-loopback %s:%u",
                          names[o], addr, port);
        }
        else if (port != tab_port[o])
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "net.unexpected-port", names[o],
                                     "listens on %s:%u, contract port %u",
                                     addr, port, tab_port[o]);
        }
        else
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                     "net.listener", names[o],
                                     "listens on %s:%u", addr, port);
        }
    }
    te_vec_free(&socks);
    if (listeners < NAMES)
    {
        res_set(r, R_SETUP, "tapi_netexpose found %u listener(s) of the "
                "three processes", listeners);
        return false;
    }
    return true;
}

/** Outbound connections of the three processes against loopback only. */
static bool
scan_egress(res_t *r, tsapi_mde_session *session, proc_t **svc,
            tapi_cybersec_report *report, char *first)
{
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    /* The allowed list: loopback only, any port. */
    tapi_egress_rule     rules[] = {
        { IPPROTO_TCP, "127.0.0.0/8", 0, 0 },
        { IPPROTO_TCP, "::1/128", 0, 0 },
    };
    tapi_egress_policy   policy = { .n_rules = TE_ARRAY_LEN(rules),
                                    .rules = rules,
                                    .allow_loopback = false,
                                    .allow_private = false };
    int                  round;
    int                  i;
    unsigned             total_conns = 0;

    opt.udp = false;
    opt.tcp = true;
    for (round = 0; round < 6; round++)
    {
        te_vec conns = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *c;
        hg_res h;

        for (i = 0; i < NAMES; i++)
            http_get(svc[i]->port, REQUEST, 5, &h);
        for (i = 0; i < NAMES; i++)
            n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
        if (tapi_egress_snapshot(session->factory, &opt, &conns) != 0)
        {
            res_set(r, R_SETUP, "tapi_egress cannot read the connections");
            te_vec_free(&conns);
            return false;
        }
        total_conns += te_vec_size(&conns);
        TE_VEC_FOREACH(&conns, c)
        {
            char addr[64];
            int  o = owner_of(svc, ino, n_ino, c->inode);

            if (o < 0 || c->inode == 0 || sock_port(&c->remote) == 0)
                continue;
            /* Accepted connections of a service are inbound, not egress. */
            if (port_in_contract(sock_port(&c->local)))
                continue;
            sock_addr(&c->remote, addr, sizeof(addr));
            if (!tapi_egress_policy_allows(&policy, IPPROTO_TCP,
                                           CONST_SA(&c->remote)))
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                         "net.unexpected-egress", names[o],
                                         "outbound to %s:%u", addr,
                                         sock_port(&c->remote));
                first_finding(first, "%s: outbound to %s:%u not in the "
                              "allow list", names[o], addr,
                              sock_port(&c->remote));
            }
        }
        te_vec_free(&conns);
        usleep(100000);
    }
    if (total_conns == 0)
    {
        res_set(r, R_INCONCLUSIVE, "tapi_egress returned no connections at "
                "all across %d round(s)", round);
        return false;
    }
    return true;
}

int
main(int argc, char **argv)
{
    res_t                res = { .kind = R_SETUP };
    proc_t              *svc[NAMES] = { NULL };
    tsapi_mde_session    session = { .ta = NULL };
    tapi_cybersec_report report;
    bool                 report_ready = false;
    char                 first[FIRST_LEN] = "";
    const int            which[] = { GO, CS, GW };
    int                  i;

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start the three services and wait for their ports");
    if (tsapi_mde_session_init(&session, "t_h4") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for the scanners");
        goto verdict;
    }
    for (i = 0; i < 3; i++)
    {
        svc[which[i]] = svc_start_exposed(&res, &session, which[i]);
        if (svc[which[i]] == NULL)
            goto verdict;
    }
    tapi_cybersec_report_init(&report);
    report_ready = true;

    TEST_STEP("tapi_binscan on gateway-rs, service-go, service-cs (context)");
    if (!scan_binaries(&res, &session, &report))
        goto verdict;
    TEST_STEP("tapi_netexpose while all three services run");
    if (!scan_listeners(&res, &session, svc, &report, first))
        goto verdict;
    TEST_STEP("tapi_egress against the allow list");
    if (!scan_egress(&res, &session, svc, &report, first))
        goto verdict;

    tapi_cybersec_report_log(&report);
    if (first[0] != '\0')
        res_set(&res, R_FAIL, "t_h4_binscan_netexpose_egress H4:proven: "
                "first finding: %s; report has %u finding(s) at or above "
                "INFO, %u at or above HIGH", first,
                tapi_cybersec_report_count(&report, TAPI_CYBERSEC_SEV_INFO),
                tapi_cybersec_report_count(&report, TAPI_CYBERSEC_SEV_HIGH));
    else
        res_set(&res, R_PASS, "t_h4_binscan_netexpose_egress H4:disproved: "
                "every listener is on a loopback address and no outbound "
                "destination is outside loopback; binscan result is "
                "context only");

verdict:
    if (report_ready)
        tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}
