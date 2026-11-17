/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t14_exposure, listeners and outbound destinations of the
 *        web tier (settles H3)
 *
 * Hypothesis H3: a service listens on a non-loopback address (the
 * addresses fixed in main.rs:33-34, Program.cs:24 and main.go:51).
 *
 * Sends and reads: starts gateway-rs, the C# service (service-cs) and the
 * Go service (service-go). Normal requests go through the three services.
 * tapi_netexpose reads every listening socket; each listener owned by one
 * of the three processes is written as one verdict line "H3 listener
 * PROC ADDR:PORT". tapi_egress reads the outbound connections against an
 * allowed list of loopback only; the literal endpoints of the source
 * lines are logged. The tapi_sniffrules captures and the frida hooks are
 * not run in this round (T14_CAPTURE_HOOKS is 0): they gave no verdict
 * twice and come back only after t0_smoke and this test report.
 *
 * Verdicts (every one starts with H3):
 *  - "H3 listener PROC ADDR:PORT": one line per listener, informational.
 *  - "H3 all-loopback" (pass): every bind address is 127.0.0.1 or ::1 and
 *    every outbound destination is loopback; H3 is false.
 *  - "H3 non-loopback-PROC-ADDR:PORT" (fail): PROC binds ADDR:PORT, which
 *    is not 127.0.0.1 or ::1; H3 is true. A destination outside loopback
 *    reads "H3 egress-non-loopback-PROC-ADDR:PORT" (fail).
 *  - "H3 setup-<step>-failed: ..." (fail): the step named did not work
 *    (a service did not start, a scanner returned no data); nothing is
 *    settled.
 * Each outcome is appended to the tapi_cybersec_report with its reason.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t14_exposure"

#include "te_config.h"

#include <ifaddrs.h>
#include <net/if.h>

#include "tapi_frida.h"
#include "tapi_sniffrules.h"

#include "webdeps_lib.h"

#define EVID_LEN    700

/** 1 runs the tapi_sniffrules captures and the frida hooks; off this round. */
#define T14_CAPTURE_HOOKS   0

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

/** Number of hooked processes the test tries. */
#define N_HOOKS NAMES

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

/**
 * Name of the first up, non-loopback interface with an IPv4 address; false
 * when the agent has none.
 */
static bool
first_external_iface(char *name, size_t size)
{
    struct ifaddrs *ifa;
    struct ifaddrs *i;
    bool            found = false;

    if (getifaddrs(&ifa) != 0)
        return false;
    for (i = ifa; i != NULL && !found; i = i->ifa_next)
    {
        if (i->ifa_addr == NULL || i->ifa_addr->sa_family != AF_INET ||
            (i->ifa_flags & (IFF_LOOPBACK | IFF_UP)) != IFF_UP)
            continue;
        snprintf(name, size, "%s", i->ifa_name);
        found = true;
    }
    freeifaddrs(ifa);
    return found;
}

/**
 * Start a tapi_sniffrules capture on @p ifname with the loopback-only
 * allowed list. A capture that cannot start is logged and dropped: @p ss
 * stays NULL and the reason goes to the report.
 */
static void
sniff_start(tsapi_mde_session *session, const char *ifname,
            tapi_sniffrules_session **ss)
{
    tapi_sniffrules_opt sopt = tapi_sniffrules_default_opt;
    te_errno            rc;

    sopt.rules = TAPI_SNIFFRULE_ALL;
    sopt.egress = &loopback_only;
    *ss = NULL;
    rc = tapi_sniffrules_start(session->ta, ifname, &sopt, ss);
    if (rc != 0)
    {
        *ss = NULL;
        WARN("webdeps H3: capture on %s dropped: cannot start (%r)", ifname,
             rc);
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "capture.dropped", ifname,
                  "tapi_sniffrules cannot start on this interface (rc %d)",
                  (int)rc);
    }
}

/**
 * Stop a capture and add its findings to the report of the test. Returns
 * how many of them are destinations outside the allowed list.
 */
static unsigned
sniff_stop(tapi_sniffrules_session *ss, const char *ifname, char *evid,
           size_t size)
{
    tapi_cybersec_report    rep;
    const tapi_cybersec_finding *f;
    unsigned                outside = 0;
    te_errno                rc;

    if (ss == NULL)
        return 0;
    tapi_cybersec_report_init(&rep);
    rc = tapi_sniffrules_stop(ss, &rep);
    if (rc != 0)
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "capture.dropped", ifname,
                  "tapi_sniffrules_stop failed (rc %d)", (int)rc);
    TE_VEC_FOREACH(&rep.findings, f)
    {
        RING("webdeps H3: capture on %s: %s %s: %s", ifname, f->check,
             f->subject, f->detail != NULL ? f->detail : "");
        T_FINDING(f->severity, f->check, f->subject, "capture on %s: %s",
                  ifname, f->detail != NULL ? f->detail : "");
        if (strcmp(f->check, "traffic.unexpected-egress") == 0)
        {
            outside++;
            append(evid, size, "capture on %s saw traffic to %s; ", ifname,
                   f->subject);
        }
    }
    tapi_cybersec_report_free(&rep);
    return outside;
}

/**
 * Attach a frida connect() hook to the process of one service. A hook that
 * cannot attach is dropped (the app is destroyed, *app is NULL) and the
 * reason is logged.
 */
static void
hook_attach(tsapi_mde_session *session, const char *script_path,
            const char *name, tapi_frida_app **app)
{
    tapi_frida_opt opt = tapi_frida_default_opt;
    te_errno       rc;

    *app = NULL;
    opt.target_name = name;
    opt.script_path = script_path;
    rc = tapi_frida_create(session->factory, &opt, app);
    if (rc == 0)
        rc = tapi_frida_start(*app);
    if (rc != 0)
    {
        WARN("webdeps H3: frida hook on %s dropped: it does not attach "
             "(%r)", name, rc);
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "frida.dropped", name,
                  "the hook does not attach (rc %d)", (int)rc);
        if (*app != NULL)
            (void)tapi_frida_destroy(*app);
        *app = NULL;
    }
}

/**
 * Stop a hook, judge the connect() calls it saw against the loopback-only
 * list and add them to the report. Returns how many are outside the list.
 */
static unsigned
hook_judge(tapi_frida_app *app, const char *name, char *evid, size_t size)
{
    tapi_cybersec_report    rep;
    const tapi_cybersec_finding *f;
    unsigned                outside = 0;

    if (app == NULL)
        return 0;
    tapi_cybersec_report_init(&rep);
    (void)tapi_frida_stop(app);
    if (tapi_frida_check_egress(app, &loopback_only, &rep) != 0)
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "frida.dropped", name,
                  "the trace cannot be judged");
    TE_VEC_FOREACH(&rep.findings, f)
    {
        RING("webdeps H3: frida on %s: %s %s", name, f->check, f->subject);
        T_FINDING(f->severity, f->check, f->subject, "frida on %s", name);
        outside++;
        append(evid, size, "%s connects to %s (frida); ", name, f->subject);
    }
    tapi_cybersec_report_free(&rep);
    (void)tapi_frida_destroy(app);
    return outside;
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
    tapi_sniffrules_session *ss_lo = NULL;
    tapi_sniffrules_session *ss_ext = NULL;
    tapi_frida_app      *hooks[N_HOOKS] = { NULL };
    te_string            script = TE_STRING_INIT;
    te_string            script_path = TE_STRING_INIT;
    char                 ext_if[64] = "";
    unsigned             n_bad_cap = 0;
    unsigned             n_bad_hook = 0;
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
    if (tsapi_mde_session_init(&session, "t14_exposure") != 0)
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

    if (T14_CAPTURE_HOOKS)
    {
    TEST_STEP("Capture on loopback and on an external interface");
    sniff_start(&session, "lo", &ss_lo);
    if (first_external_iface(ext_if, sizeof(ext_if)))
        sniff_start(&session, ext_if, &ss_ext);
    else
        RING("webdeps H3: the agent has no external interface; only the "
             "loopback capture runs");

    TEST_STEP("Hook the three processes with frida (dropped when it "
              "does not attach)");
    tapi_frida_script_trace_connect(&script);
    if (tapi_frida_check_available(session.factory, 30000) != 0)
    {
        WARN("webdeps H3: frida is not usable on the agent: the hooks are "
             "dropped");
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "frida.dropped", "frida",
                  "frida is not usable on the agent");
    }
    else if (tapi_frida_script_put(session.ta, script.ptr, &script_path) != 0)
    {
        WARN("webdeps H3: the frida script cannot be put on the agent: the "
             "hooks are dropped");
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "frida.dropped", "frida",
                  "the tracing script cannot be put on the agent");
    }
    else
    {
        for (i = 0; i < NAMES; i++)
            hook_attach(&session, script_path.ptr, names[i], &hooks[i]);
        sleep(2);
    }
    }

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
        if (wild)
        {
            n_bad_listen++;
            append(evid, sizeof(evid), "%s listens on %s:%u; ", names[o],
                   addr, sock_port(&s->local));
            if (first_bad[0] == '\0')
                snprintf(first_bad, sizeof(first_bad),
                         "H3 non-loopback-%s-%s:%u", names[o], addr,
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
                             "H3 egress-non-loopback-%s-%s:%u", names[o],
                             addr, sock_port(&c->remote));
            }
        }
        te_vec_free(&conns);
        usleep(100000);
    }
    TEST_STEP("Stop the captures and the hooks and judge them");
    n_bad_cap += sniff_stop(ss_lo, "lo", evid, sizeof(evid));
    ss_lo = NULL;
    n_bad_cap += sniff_stop(ss_ext, ext_if, evid, sizeof(evid));
    ss_ext = NULL;
    for (i = 0; i < NAMES; i++)
    {
        n_bad_hook += hook_judge(hooks[i], names[i], evid, sizeof(evid));
        hooks[i] = NULL;
    }
    if (n_lit > 0)
        append(evid, sizeof(evid), "%u source line(s) with an address outside "
               "the list; ", n_lit);
    RING("webdeps H3: listeners: %s", listen_);
    RING("webdeps H3: outbound: %s", egress[0] != '\0' ? egress : "(none)");

    if (n_bad_listen > 0 || n_bad_egress > 0 || n_bad_cap > 0 ||
        n_bad_hook > 0)
        res_set(&res, R_FAIL, "%s: %s listeners: %s outbound: %s",
                first_bad[0] != '\0' ? first_bad : first_egress[0] != '\0' ?
                first_egress : "H3 non-loopback-traffic", evid, listen_,
                egress[0] != '\0' ? egress : "(none)");
    else
        res_set(&res, R_PASS, "H3 all-loopback: every listener is on "
                "127.0.0.1 or ::1 (%s) and every outbound destination (%u connection "
                "sample(s): %s) is loopback%s", listen_,
                n_conns, egress[0] != '\0' ? egress : "none seen",
                n_lit > 0 ? "; note: some literal lines name hosts outside "
                "the allowed list, see the report" : "");

verdict:
    for (i = 0; i < NAMES; i++)
    {
        if (hooks[i] != NULL)
            (void)tapi_frida_destroy(hooks[i]);
    }
    {
        char scratch[64];

        /* Captures still running after an early exit are stopped here. */
        (void)sniff_stop(ss_lo, "lo", scratch, sizeof(scratch));
        (void)sniff_stop(ss_ext, ext_if, scratch, sizeof(scratch));
    }
    te_string_free(&script);
    te_string_free(&script_path);
    if (session.ta != NULL)
        tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H3");

cleanup:
    cleanup_all();
    TEST_END;
}
