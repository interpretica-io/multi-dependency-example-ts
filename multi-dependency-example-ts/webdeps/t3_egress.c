/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T3, egress of the web tier (settles H3)
 *
 * Start gateway-rs, service-go and service-cs (each port read with
 * tapi_netexpose), send normal traffic to each in several rounds, and
 * with tapi_egress compare every outgoing connection of the three
 * processes with an allowed list of loopback only. Every destination
 * outside it goes into the tapi_cybersec_report and fails the test; the
 * verdict names each one. A service that does not start is NOT RUN; a
 * scanner that sees no connection at all is INCONCLUSIVE.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t3_egress"

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

#define FIRST_LEN   600

/** Collect the findings for the verdict; the report keeps all of them. */
static void
first_finding(char *first, const char *fmt, ...)
{
    va_list ap;
    char    one[160];
    size_t  l = strlen(first);

    va_start(ap, fmt);
    vsnprintf(one, sizeof(one), fmt, ap);
    va_end(ap);
    if (strstr(first, one) != NULL || l + strlen(one) + 3 >= FIRST_LEN)
        return;
    snprintf(first + l, FIRST_LEN - l, "%s; ", one);
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
                first_finding(first, "%s -> %s:%u", names[o], addr,
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
    res_t                res = { .kind = R_PASS };
    proc_t              *svc[NAMES] = { NULL };
    tsapi_mde_session    session = { .ta = NULL };
    char                 first[FIRST_LEN] = "";
    const int            which[] = { GO, CS, GW };
    int                  i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    TEST_STEP("Start the three services and wait for their ports");
    if (tsapi_mde_session_init(&session, "t3_egress") != 0)
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

    TEST_STEP("Normal traffic and tapi_egress against the allow list");
    if (!scan_egress(&res, &session, svc, &t_report, first))
        goto verdict;

    if (first[0] != '\0')
        res_set(&res, R_FAIL, "H3 FAIL: connections outside loopback: %s; "
                "the report has %u finding(s) at or above HIGH", first,
                tapi_cybersec_report_count(&t_report, TAPI_CYBERSEC_SEV_HIGH));
    else
        res_set(&res, R_PASS, "H3 PASS: gateway-rs, service-go and "
                "service-cs made no connection outside loopback while "
                "serving normal traffic");

verdict:
    tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}
