/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: egress_vs_allowlist, outgoing connections of the web
 *        tier against an allowed list (settles H3)
 *
 * Hypothesis H3: gateway-rs, service-cs and service-go open connections
 * to fixed addresses outside the allowed list.
 *
 * gateway-rs and service-go are started; service-cs only when it starts
 * here, otherwise "service-cs SETUP_FAILED: <reason>" is printed and the
 * test goes on. tapi_netexpose lists the listening ports of each. Each
 * service gets GET / and one request per route written in its source
 * (quoted strings that start with "/"). tapi_egress snapshots the
 * outgoing connections after every request; each is recorded by process
 * name, destination address and port.
 *
 * The allowed list is 127.0.0.1, ::1 and the addresses the three services
 * listen on. The literal addresses at main.rs:33-36, Program.cs:24,34,78
 * and main.go:46,51,87 are read from the sources and compared with the
 * connections seen; each one never contacted is printed as "not reached"
 * (a literal never reached is not proven harmless).
 *
 * Verdicts (each starts with H3):
 *  - "H3 FAIL (H3 confirmed)": a process connected outside the list;
 *  - "H3 PASS (H3 disproved)": every connection stayed inside the list;
 *  - "H3 SETUP_FAILED": gateway-rs or service-go did not start, or a
 *    scanner gave no data; the reason is printed.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/egress_vs_allowlist"

#include "te_config.h"

#include "webdeps_lib.h"

#define ROUNDS  6
#define LIST_LEN 700

#define MAX_ROUTES 16
#define MAX_LIT    16

static const char * const src_files[NAMES] = {
    "web/gateway-rs/src/main.rs", "web/service-go/main.go",
    "web/service-cs/Program.cs",
};

/** Source lines holding the literal addresses, 0-terminated. */
static const unsigned lit_lines[NAMES][4] = {
    { 33, 34, 35, 36 }, { 46, 51, 87, 0 }, { 24, 34, 78, 0 },
};

typedef struct lit_t {
    char addr[48];
    char where[48];
    bool reached;
} lit_t;

static lit_t    lits[MAX_LIT];
static unsigned n_lits;
static char     routes[NAMES][MAX_ROUTES][80];
static unsigned n_routes[NAMES];
static char     allowed[NAMES][64];

/** Add a dotted-quad found in @p line to the literal list. */
static void
scan_literals(const char *line, const char *where)
{
    const char *p;

    for (p = line; *p != '\0'; p++)
    {
        unsigned a, b, c, d;
        int      n = 0;

        if (*p < '0' || *p > '9' || (p > line && (p[-1] == '.' ||
            (p[-1] >= '0' && p[-1] <= '9'))))
            continue;
        if (sscanf(p, "%3u.%3u.%3u.%3u%n", &a, &b, &c, &d, &n) == 4 &&
            a < 256 && b < 256 && c < 256 && d < 256 && n > 0 &&
            n_lits < MAX_LIT)
        {
            snprintf(lits[n_lits].addr, sizeof(lits[0].addr), "%.*s", n, p);
            snprintf(lits[n_lits].where, sizeof(lits[0].where), "%s", where);
            n_lits++;
            p += n - 1;
        }
    }
}

/** Read routes and the literal addresses of one source; false if unreadable. */
static bool
read_source(int idx)
{
    char     path[700];
    char     line[1024];
    FILE    *f;
    unsigned ln = 0;

    snprintf(path, sizeof(path), "%s/%s", src_root, src_files[idx]);
    f = fopen(path, "r");
    if (f == NULL)
        return false;
    while (fgets(line, sizeof(line), f) != NULL)
    {
        const char *q;
        unsigned    k;

        ln++;
        for (k = 0; k < 4 && lit_lines[idx][k] != 0; k++)
        {
            if (lit_lines[idx][k] == ln)
            {
                char where[48];

                snprintf(where, sizeof(where), "%s:%u",
                         strrchr(src_files[idx], '/') + 1, ln);
                scan_literals(line, where);
            }
        }
        for (q = line; (q = strchr(q, '"')) != NULL; q++)
        {
            size_t l = 0;
            char   r[80];

            if (q[1] != '/')
                continue;
            while (q[1 + l] != '\0' && q[1 + l] != '"' && l < sizeof(r) - 1 &&
                   q[1 + l] > ' ')
                l++;
            if (q[1 + l] != '"' || l == 0)
                continue;
            snprintf(r, sizeof(r), "%.*s", (int)l, q + 1);
            for (k = 0; k < n_routes[idx]; k++)
            {
                if (strcmp(routes[idx][k], r) == 0)
                    break;
            }
            if (k == n_routes[idx] && k < MAX_ROUTES)
                snprintf(routes[idx][n_routes[idx]++], 80, "%s", r);
            q += l + 1;
        }
    }
    fclose(f);
    return true;
}

/** True when @p addr is in the allowed list. */
static bool
is_allowed(const char *addr)
{
    int i;

    if (strcmp(addr, "127.0.0.1") == 0 || strcmp(addr, "::1") == 0)
        return true;
    for (i = 0; i < NAMES; i++)
    {
        if (allowed[i][0] != '\0' && strcmp(allowed[i], addr) == 0)
            return true;
    }
    return false;
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
    char                 seen[LIST_LEN] = "";
    char                 listens[LIST_LEN] = "";
    char                 notrun[200] = "";
    char                 why[2200] = "";
    unsigned             total = 0;
    unsigned             n_listen = 0;
    bool                 not_run = false;
    bool                 src_ok = true;
    char                 notreached[LIST_LEN] = "";
    char                 reached_s[LIST_LEN] = "";
    unsigned             k;
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

    TEST_STEP("Read routes and literal addresses from the three sources");
    for (i = 0; i < NAMES; i++)
    {
        if (!read_source(i))
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
            snprintf(notrun, sizeof(notrun), "service-cs SETUP_FAILED: %.150s",
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
            if (strcmp(addr, "0.0.0.0") != 0 && strcmp(addr, "::") != 0 &&
                allowed[o][0] == '\0')
                snprintf(allowed[o], sizeof(allowed[o]), "%s", addr);
            T_FINDING(TAPI_CYBERSEC_SEV_INFO, "net.listener", names[o],
                      "listens on %s:%u", addr, port);
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
            if (svc[i] == NULL)
                continue;
            http_get(svc[i]->port, "/", 5, &h);
            http_get(svc[i]->port, REQUEST, 5, &h);
            for (k = 0; k < n_routes[i]; k++)
                http_get(svc[i]->port, routes[i][k], 5, &h);
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
            for (k = 0; k < n_lits; k++)
            {
                if (strcmp(lits[k].addr, addr) == 0)
                    lits[k].reached = true;
            }
            if (is_allowed(addr))
            {
                T_FINDING(TAPI_CYBERSEC_SEV_INFO, "net.egress", names[o],
                          "outgoing connection to %s:%u, in the allowed list",
                          addr, sock_port(&c->remote));
                continue;
            }
            add_once(bad_out, one);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "net.unexpected-egress",
                      names[o], "outgoing connection to %s:%u, outside the allowed list",
                      addr, sock_port(&c->remote));
        }
        te_vec_free(&conns);
        usleep(100000);
    }
    if (total == 0 && !not_run)
    {
        snprintf(why, sizeof(why), "tapi_egress returned no connections at "
                 "all in %d rounds", ROUNDS);
        not_run = true;
    }

verdict:
    tsapi_mde_session_fini(&session);
    for (k = 0; k < n_lits; k++)
    {
        char one[120];

        snprintf(one, sizeof(one), "%s (%s)", lits[k].addr, lits[k].where);
        add_once(lits[k].reached ? reached_s : notreached, one);
    }
    if (not_run)
        res_set(&res, R_SETUP, "H3 SETUP_FAILED: %.700s%s%s (no verdict on "
                "H3)", why, notrun[0] != '\0' ? "; " : "", notrun);
    else if (bad_out[0] != '\0')
        res_set(&res, R_FAIL, "H3 FAIL (H3 confirmed): connections outside "
                "the allowed list: [%s]; literals reached: [%s]; literals "
                "not reached: [%s]; all outgoing seen: [%s]; listening: "
                "[%s]; %s", bad_out, reached_s, notreached, seen, listens,
                notrun[0] != '\0' ? notrun : "all three services ran");
    else
        res_set(&res, R_PASS, "H3 PASS (H3 disproved for this run): every "
                "connection stayed in the allowed list; literals reached: "
                "[%s]; literals not reached: [%s] (not proof they are "
                "harmless); outgoing seen: [%s]; listening: [%s]; %s",
                reached_s, notreached, seen[0] != '\0' ? seen : "none",
                listens, notrun[0] != '\0' ? notrun : "all three services "
                "ran");
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}
