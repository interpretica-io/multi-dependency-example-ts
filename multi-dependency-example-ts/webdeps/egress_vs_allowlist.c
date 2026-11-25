/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: egress_vs_allowlist, outgoing connections and listening
 *        ports of the web tier against an allowed list (settles H3)
 *
 * Hypothesis H3: the gateway and the services use fixed addresses outside
 * an allowed list. The test needs nothing from the other tests of the group.
 *
 * gateway-rs, service-go and service-cs are started, normal requests go to
 * each in several rounds, and
 *  - tapi_egress lists the outgoing connections of the three processes;
 *    the allowed list holds the loopback addresses 127.0.0.1 and ::1 only;
 *  - tapi_netexpose lists the listening ports of the three processes; the
 *    allowed ports are those that appear in main.rs, main.go or Program.cs.
 * Every outgoing connection and every listening port goes into the log and
 * the tapi_cybersec_report.
 *
 * Verdicts (each starts with H3):
 *  - "H3 CONFIRMED": an outgoing connection to a non-loopback address
 *    (each is printed) or a listening port that is in none of the three
 *    sources (each is printed);
 *  - "H3 DISPROVED": none, for this run;
 *  - "H3 NOT RUN": gateway-rs or service-go did not start, or a scanner
 *    gave no data; the reason is printed;
 *  - service-cs that does not start is "not run" in the text; it does not
 *    change the verdict of the other two.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/egress_vs_allowlist"

#include "te_config.h"

#include "webdeps_lib.h"

#define ROUNDS  6
#define LIST_LEN 700

static const char * const src_files[NAMES] = {
    "web/gateway-rs/src/main.rs", "web/service-go/main.go",
    "web/service-cs/Program.cs",
};

static bool src_port[65536];

/** Mark every number 1..65535 written in a source file; false if unreadable. */
static bool
read_source_ports(const char *rel)
{
    char  path[700];
    FILE *f;
    int   c;
    long  v = -1;

    snprintf(path, sizeof(path), "%s/%s", src_root, rel);
    f = fopen(path, "r");
    if (f == NULL)
        return false;
    while ((c = fgetc(f)) != EOF)
    {
        if (c >= '0' && c <= '9')
        {
            v = (v < 0 ? 0 : v) * 10 + (c - '0');
            if (v > 65535)
                v = 70000;
        }
        else
        {
            if (v > 0 && v <= 65535)
                src_port[v] = true;
            v = -1;
        }
    }
    if (v > 0 && v <= 65535)
        src_port[v] = true;
    fclose(f);
    return true;
}

/** Add @p what to a list once, bounded. */
static void
add_once(char *list, const char *what)
{
    size_t l = strlen(list);

    if (strstr(list, what) != NULL || l + strlen(what) + 3 >= LIST_LEN)
        return;
    snprintf(list + l, LIST_LEN - l, "%s; ", what);
}

int
main(int argc, char **argv)
{
    res_t                res = { .kind = R_PASS };
    proc_t              *svc[NAMES] = { NULL };
    tsapi_mde_session    session = { .ta = NULL };
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES] = { 0 };
    char                 bad_out[LIST_LEN] = "";
    char                 bad_listen[LIST_LEN] = "";
    char                 seen[LIST_LEN] = "";
    char                 listens[LIST_LEN] = "";
    char                 notrun[200] = "";
    char                 why[600] = "";
    unsigned             total = 0;
    unsigned             n_listen = 0;
    bool                 not_run = false;
    bool                 src_ok = true;
    const int            order[] = { GO, CS, GW };
    int                  i;
    int                  round;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        not_run = true;
        goto verdict;
    }
    if (tsapi_mde_session_init(&session, "egress_vs_allowlist") != 0)
    {
        snprintf(why, sizeof(why), "no session on the agent for the "
                 "scanners");
        not_run = true;
        goto verdict;
    }

    TEST_STEP("Read the ports written in the three sources");
    for (i = 0; i < NAMES; i++)
    {
        if (!read_source_ports(src_files[i]))
        {
            src_ok = false;
            append(why, sizeof(why), "%s cannot be read; ", src_files[i]);
        }
    }
    if (!src_ok)
    {
        not_run = true;
        goto verdict;
    }

    TEST_STEP("Start service-go, service-cs and gateway-rs");
    for (i = 0; i < 3; i++)
    {
        res_t r2 = { .kind = R_PASS };

        svc[order[i]] = svc_start_exposed(&r2, &session, order[i]);
        if (svc[order[i]] != NULL)
            continue;
        if (order[i] == CS)
        {
            snprintf(notrun, sizeof(notrun), "service-cs not run: %.150s",
                     r2.msg);
            RING("webdeps H3: %s", notrun);
            continue;
        }
        snprintf(why, sizeof(why), "%s did not start: %.400s",
                 names[order[i]], r2.msg);
        not_run = true;
        goto verdict;
    }
    for (i = 0; i < NAMES; i++)
    {
        if (svc[i] != NULL)
            n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    }

    TEST_STEP("Listening ports of the started processes");
    {
        te_vec socks = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *s;

        opt.udp = false;
        opt.tcp = true;
        if (tapi_netexpose_sockets(session.factory, &opt, &socks) != 0)
        {
            snprintf(why, sizeof(why), "tapi_netexpose cannot read the "
                     "socket tables");
            not_run = true;
            te_vec_free(&socks);
            goto verdict;
        }
        TE_VEC_FOREACH(&socks, s)
        {
            char     addr[64];
            char     one[160];
            unsigned port = sock_port(&s->local);
            int      o;

            if (!tapi_netexpose_socket_is_listening(s))
                continue;
            o = owner_of(svc, ino, n_ino, s->inode);
            if (o < 0)
                continue;
            sock_addr(&s->local, addr, sizeof(addr));
            n_listen++;
            snprintf(one, sizeof(one), "%s %s:%u", names[o], addr, port);
            add_once(listens, one);
            RING("webdeps H3: listening port %s", one);
            if (port > 0 && src_port[port])
            {
                T_FINDING(TAPI_CYBERSEC_SEV_INFO, "net.listener", names[o],
                          "listens on %s:%u, port written in the source",
                          addr, port);
                continue;
            }
            snprintf(one, sizeof(one), "%s listens on %s:%u (port in none "
                     "of main.rs, main.go, Program.cs)", names[o], addr,
                     port);
            add_once(bad_listen, one);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "net.unexpected-listener",
                      names[o], "%s", one);
        }
        te_vec_free(&socks);
    }

    TEST_STEP("Normal requests and tapi_egress against the allowed list");
    opt.udp = true;
    for (round = 0; round < ROUNDS; round++)
    {
        te_vec conns = TE_VEC_INIT(tapi_netexpose_socket);
        const tapi_netexpose_socket *c;
        hg_res h;

        for (i = 0; i < NAMES; i++)
        {
            if (svc[i] != NULL)
                http_get(svc[i]->port, REQUEST, 5, &h);
        }
        if (tapi_egress_snapshot(session.factory, &opt, &conns) != 0)
        {
            snprintf(why, sizeof(why), "tapi_egress cannot read the "
                     "connections of the agent");
            not_run = true;
            te_vec_free(&conns);
            goto verdict;
        }
        total += te_vec_size(&conns);
        TE_VEC_FOREACH(&conns, c)
        {
            char addr[64];
            char one[200];
            int  o = owner_of(svc, ino, n_ino, c->inode);

            if (o < 0 || c->inode == 0 || sock_port(&c->remote) == 0)
                continue;
            /* Accepted connections of a service are not outgoing. */
            if (port_in_contract(sock_port(&c->local)) ||
                (svc[o] != NULL && sock_port(&c->local) == svc[o]->port))
                continue;
            sock_addr(&c->remote, addr, sizeof(addr));
            snprintf(one, sizeof(one), "%s -> %s:%u", names[o], addr,
                     sock_port(&c->remote));
            add_once(seen, one);
            if (is_loopback(addr))
            {
                T_FINDING(TAPI_CYBERSEC_SEV_INFO, "net.egress", names[o],
                          "outgoing connection to %s:%u, loopback, allowed",
                          addr, sock_port(&c->remote));
                continue;
            }
            add_once(bad_out, one);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "net.unexpected-egress",
                      names[o], "outgoing connection to %s:%u, not loopback",
                      addr, sock_port(&c->remote));
        }
        te_vec_free(&conns);
        usleep(100000);
    }
    if (total == 0)
    {
        snprintf(why, sizeof(why), "tapi_egress returned no connections at "
                 "all in %d rounds", ROUNDS);
        not_run = true;
    }

verdict:
    tsapi_mde_session_fini(&session);
    if (not_run)
        res_set(&res, R_FAIL, "H3 NOT RUN: %.700s%s%s", why,
                notrun[0] != '\0' ? "; " : "", notrun);
    else if (bad_out[0] != '\0' || bad_listen[0] != '\0')
        res_set(&res, R_FAIL, "H3 CONFIRMED: outgoing connections to "
                "non-loopback addresses: [%s]; listening ports not in the "
                "sources: [%s]; all outgoing seen: [%s]; %s", bad_out,
                bad_listen, seen, notrun[0] != '\0' ? notrun : "all three "
                "services ran");
    else
        res_set(&res, R_PASS, "H3 DISPROVED for this run: every outgoing "
                "connection stayed on loopback and every listening port is "
                "written in the sources; outgoing seen: [%s]; listening: "
                "[%s]; %s", seen[0] != '\0' ? seen : "none", listens,
                notrun[0] != '\0' ? notrun : "all three services ran");
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}
