/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: H4, hardening, listeners and egress of the web tier
 *
 * tapi_binscan on the three service binaries, tapi_netexpose and
 * tapi_egress while all three run. Every result is appended to one
 * tapi_cybersec_report, which is logged; the test fails on the first
 * finding, naming the file and the flag.
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

/** NX, PIE, RELRO and canary of the three binaries. */
static bool
scan_binaries(res_t *r, tsapi_mde_session *session,
              tapi_cybersec_report *report, char *first)
{
    int i;

    for (i = 0; i < NAMES; i++)
    {
        char              path[600];
        tapi_binscan_info info;
        bool              pie;
        bool              nx;
        bool              managed = i == CS;
        te_errno          rc;

        snprintf(path, sizeof(path), "%s/dist/bin/%s", src_root, names[i]);
        rc = tapi_binscan_inspect(session->ta, path, &info);
        if (rc != 0 || !info.elf)
        {
            setup_svc = names[i];
            res_set(r, R_SETUP, "tapi_binscan cannot read %s as ELF (rc %d)",
                    path, (int)rc);
            return false;
        }
        tapi_binscan_info_log(&info, path);
        pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
              info.kind == TAPI_BINSCAN_KIND_SHARED;
        nx = info.nx && !info.nx_unknown;
        if (!nx)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "binary.no-nx", names[i], "%s: NX "
                                     "missing", path);
            first_finding(first, "%s: NX missing", path);
        }
        if (!pie)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "binary.no-pie", names[i], "%s: PIE "
                                     "missing (%s)", path,
                                     tapi_binscan_kind2str(info.kind));
            first_finding(first, "%s: PIE missing", path);
        }
        if (info.relro == TAPI_BINSCAN_RELRO_NONE)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "binary.no-relro", names[i], "%s: "
                                     "RELRO missing", path);
            first_finding(first, "%s: RELRO missing", path);
        }
        if (!info.canary)
        {
            /*
             * A managed (NativeAOT) binary has no C stack protector to
             * find; the flag is noted, not failed, for it.
             */
            tapi_cybersec_report_add(report, managed ?
                                     TAPI_CYBERSEC_SEV_INFO :
                                     TAPI_CYBERSEC_SEV_HIGH,
                                     "binary.no-canary", names[i], "%s: "
                                     "stack canary missing%s", path,
                                     managed ? " (C#: may not apply to a "
                                     "managed binary)" : "");
            if (!managed)
                first_finding(first, "%s: stack canary missing", path);
        }
        tapi_binscan_info_free(&info);
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
        /* The expected list is the port of the service itself. */
        if (port != tab_port[o])
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "net.unexpected-listener", names[o],
                                     "listens on %s:%u, expected port %u",
                                     addr, port, tab_port[o]);
            first_finding(first, "%s: unexpected listener %s:%u", names[o],
                          addr, port);
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

/**
 * Outbound connections of the three processes against an allow list of the
 * addresses their sources name: 127.0.0.1 on the three contract ports.
 */
static bool
scan_egress(res_t *r, tsapi_mde_session *session, proc_t **svc,
            tapi_cybersec_report *report, char *first)
{
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    tapi_egress_rule     rules[NAMES];
    tapi_egress_policy   policy = { .n_rules = NAMES, .rules = rules,
                                    .allow_loopback = false,
                                    .allow_private = false };
    int                  round;
    int                  i;

    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
    {
        rules[i] = (tapi_egress_rule){ IPPROTO_TCP, "127.0.0.1/32",
                                       tab_port[i], tab_port[i] };
    }
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

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    TEST_STEP("Start the three services and wait for their ports");
    if (!start_all(&res, svc, which, 3))
        goto verdict;
    if (tsapi_mde_session_init(&session, "t_h4") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for the scanners");
        goto verdict;
    }
    tapi_cybersec_report_init(&report);
    report_ready = true;

    TEST_STEP("tapi_binscan on gateway-rs, service-go, service-cs");
    if (!scan_binaries(&res, &session, &report, first))
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
                "NX, PIE, RELRO and canary present (canary not required for "
                "C#), listeners are exactly the three expected ports, no "
                "outbound destination outside the allow list");

verdict:
    if (report_ready)
        tapi_cybersec_report_free(&report);
    tsapi_mde_session_fini(&session);
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}
