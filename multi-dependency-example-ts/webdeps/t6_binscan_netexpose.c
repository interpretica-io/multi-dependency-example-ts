/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T6, hardening and listeners (settles H6)
 *
 * Run tapi_binscan on gateway-rs, service-go, the C# host service-cs and
 * the C/C++ demo binaries (cpp-demo, rust-demo, libpycore, libcppcore)
 * and report NX, PIE, RELRO, stack canary and fortify per binary. Start
 * the three services and run tapi_netexpose on the agent; report every
 * listening TCP port with its bind address. A missing hardening flag is
 * a finding and never fails the test. H6 FAIL if a port owned by the
 * project (one of its services, or a contract port) is bound to a
 * wildcard address (0.0.0.0 or ::) and the contract that documents the
 * ports (web/contract/services.tab) does not list it. Wildcard listeners
 * of other processes on the agent are findings too, and do not fail the
 * test. A binary that is not built or a service that does not start is
 * NOT RUN; a scanner with no data is INCONCLUSIVE.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t6_binscan_netexpose"

#include "te_config.h"

#include "webdeps_lib.h"

#define FIRST_LEN   600

static const char * const scan_paths[] = {
    "dist/bin/gateway-rs", "dist/bin/service-go", "dist/bin/service-cs",
    "dist/bin/cpp-demo", "dist/bin/rust-demo", "dist/lib/libpycore.so",
    "dist/lib/libcppcore.so",
};

static bool
is_wildcard(const char *addr)
{
    return strcmp(addr, "0.0.0.0") == 0 || strcmp(addr, "::") == 0;
}

/** NX, PIE, RELRO, canary and fortify of one binary into the report. */
static bool
scan_one(res_t *r, tsapi_mde_session *session, const char *rel,
         unsigned *missing)
{
    tapi_binscan_info info;
    char              path[700];
    bool              pie;
    bool              nx;
    bool              relro;
    te_errno          rc;

    snprintf(path, sizeof(path), "%s/%s", src_root, rel);
    if (access(path, R_OK) != 0)
    {
        setup_svc = rel;
        res_set(r, R_SETUP, "binary %s is not built", path);
        return false;
    }
    rc = tapi_binscan_inspect(session->ta, path, &info);
    if (rc != 0)
    {
        setup_svc = rel;
        res_set(r, R_SETUP, "tapi_binscan cannot read %s (rc %d)", path,
                (int)rc);
        return false;
    }
    if (!info.elf)
    {
        tapi_binscan_info_free(&info);
        setup_svc = rel;
        res_set(r, R_INCONCLUSIVE, "tapi_binscan: %s is not an ELF file",
                rel);
        return false;
    }
    tapi_binscan_info_log(&info, path);
    pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
          info.kind == TAPI_BINSCAN_KIND_SHARED;
    nx = info.nx && !info.nx_unknown;
    relro = info.relro != TAPI_BINSCAN_RELRO_NONE;
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "binary.hardening", rel,
              "NX %s, PIE %s, RELRO %s (%s), canary %s, fortify %s%s",
              nx ? "yes" : "no", pie ? "yes" : "no", relro ? "yes" : "no",
              tapi_binscan_relro2str(info.relro), info.canary ? "yes" : "no",
              info.fortify ? "yes" : "no", info.stripped ?
              " (stripped: canary and fortify are guesses)" : "");
    RING("webdeps: %s: NX %d PIE %d RELRO %d canary %d fortify %d", rel, nx,
         pie, relro, info.canary, info.fortify);
    if (!nx)
        T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "binary.no-nx", rel,
                  "stack is executable or unknown");
    if (!pie)
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "binary.no-pie", rel,
                  "not position independent");
    if (!relro)
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "binary.no-relro", rel,
                  "no RELRO");
    if (!info.canary)
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "binary.no-canary", rel,
                  "no stack canary");
    if (!info.fortify)
        T_FINDING(TAPI_CYBERSEC_SEV_LOW, "binary.no-fortify", rel,
                  "no _FORTIFY_SOURCE");
    *missing += !nx + !pie + !relro + !info.canary + !info.fortify;
    tapi_binscan_info_free(&info);
    return true;
}

/** Every listening TCP port with its bind address. */
static bool
scan_ports(res_t *r, tsapi_mde_session *session, proc_t **svc, char *bad,
           unsigned *n_listen, unsigned *n_wild)
{
    unsigned long        ino[NAMES][MAX_INO];
    size_t               n_ino[NAMES];
    tapi_netexpose_opt   opt = tapi_netexpose_default_opt;
    te_vec               socks = TE_VEC_INIT(tapi_netexpose_socket);
    const tapi_netexpose_socket *s;
    int                  i;

    opt.udp = false;
    opt.tcp = true;
    for (i = 0; i < NAMES; i++)
        n_ino[i] = pid_inodes(svc[i]->pid, ino[i], MAX_INO);
    if (tapi_netexpose_sockets(session->factory, &opt, &socks) != 0)
    {
        setup_svc = "agent";
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
        char     subject[64];
        int      o;
        unsigned port;
        bool     wild;
        bool     ours;

        if (!tapi_netexpose_socket_is_listening(s))
            continue;
        o = owner_of(svc, ino, n_ino, s->inode);
        sock_addr(&s->local, addr, sizeof(addr));
        port = sock_port(&s->local);
        wild = is_wildcard(addr);
        ours = o >= 0 || port_in_contract(port);
        snprintf(subject, sizeof(subject), "%s:%u", addr, port);
        (*n_listen)++;
        RING("webdeps: listening %s (%s)", subject,
             o >= 0 ? names[o] : (ours ? "contract port" : "other"));
        if (!wild)
        {
            T_FINDING(TAPI_CYBERSEC_SEV_INFO, "net.listener", subject,
                      "bound to %s, owner %s", addr,
                      o >= 0 ? names[o] : "other");
            continue;
        }
        (*n_wild)++;
        if (ours && !port_in_contract(port))
        {
            size_t l = strlen(bad);

            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "net.undocumented-wildcard",
                      subject, "%s binds a wildcard address on a port the "
                      "contract does not list", o >= 0 ? names[o] : "?");
            if (l + 80 < FIRST_LEN)
                snprintf(bad + l, FIRST_LEN - l, "%s (%s); ", subject,
                         o >= 0 ? names[o] : "?");
        }
        else if (ours)
            T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "net.wildcard-listener",
                      subject, "%s binds a wildcard address; port %u is in "
                      "the contract", o >= 0 ? names[o] : "contract port",
                      port);
        else
            T_FINDING(TAPI_CYBERSEC_SEV_MEDIUM, "net.wildcard-listener",
                      subject, "other process on the agent, not part of the "
                      "project");
    }
    te_vec_free(&socks);
    return true;
}

int
main(int argc, char **argv)
{
    res_t                res = { .kind = R_PASS };
    proc_t              *svc[NAMES] = { NULL };
    tsapi_mde_session    session = { .ta = NULL };
    char                 bad[FIRST_LEN] = "";
    const int            which[] = { GO, CS, GW };
    unsigned             missing = 0;
    unsigned             n_listen = 0;
    unsigned             n_wild = 0;
    size_t               i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    if (tsapi_mde_session_init(&session, "t6_binscan") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for the scanners");
        goto verdict;
    }

    TEST_STEP("tapi_binscan on the services and the C/C++ binaries");
    for (i = 0; i < TE_ARRAY_LEN(scan_paths); i++)
    {
        if (!scan_one(&res, &session, scan_paths[i], &missing))
            goto verdict;
    }

    TEST_STEP("Start the three services");
    for (i = 0; i < 3; i++)
    {
        svc[which[i]] = svc_start_exposed(&res, &session, which[i]);
        if (svc[which[i]] == NULL)
            goto verdict;
    }

    TEST_STEP("tapi_netexpose on the agent");
    if (!scan_ports(&res, &session, svc, bad, &n_listen, &n_wild))
        goto verdict;

    if (bad[0] != '\0')
        res_set(&res, R_FAIL, "H6 FAIL: undocumented wildcard listener(s): "
                "%s; %u hardening flag(s) missing over %zu binaries "
                "(findings)", bad, missing, TE_ARRAY_LEN(scan_paths));
    else
        res_set(&res, R_PASS, "H6 PASS: no undocumented port on 0.0.0.0; "
                "%u listener(s) seen, %u on a wildcard address; %u hardening "
                "flag(s) missing over %zu binaries (reported as findings, "
                "not failures)", n_listen, n_wild, missing,
                TE_ARRAY_LEN(scan_paths));

verdict:
    tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H6");

cleanup:
    cleanup_all();
    TEST_END;
}
