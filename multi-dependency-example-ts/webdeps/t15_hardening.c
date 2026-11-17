/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t15_hardening, hardening flags of every built binary
 *        (settles H4)
 *
 * Run tapi_binscan on each built binary: gateway-rs (Rust), service-go
 * (Go), service-cs (the .NET apphost) and the C++, C and Python extension
 * libraries (libcppcore, libpycore) in dist/. Each binary is listed with
 * its flags (NX, PIE, RELRO, canary, fortify). A flag counts only where the
 * language supports it: Rust and Go binaries are held to NX, PIE and full
 * RELRO (neither emits stack canaries or fortified libc calls); the native
 * apphost of service-cs and the C and C++ libraries to all five.
 *
 * H4 CONFIRMED if any binary lacks a flag its language supports, naming
 * the binary and the flag; H4 DISPROVED otherwise. A binary that is absent
 * or cannot be scanned is INCONCLUSIVE naming it.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t15_hardening"

#include "te_config.h"

#include "webdeps_lib.h"

enum { F_NX = 1, F_PIE = 2, F_RELRO = 4, F_CANARY = 8, F_FORTIFY = 16,
       F_BASIC = F_NX | F_PIE | F_RELRO, F_ALL = F_BASIC | F_CANARY | F_FORTIFY };

static const struct {
    const char *rel;        /**< Under the example root. */
    const char *lang;
    unsigned    need;       /**< Flags the language supports. */
} bins[] = {
    { "dist/bin/gateway-rs", "Rust", F_BASIC },
    { "dist/bin/service-go", "Go", F_BASIC },
    { "dist/bin/service-cs", "C# (native apphost)", F_ALL },
    { "dist/lib/libcppcore.so", "C++", F_ALL },
    { "dist/lib/libpycore.so", "C (Python extension)", F_ALL },
};

int
main(int argc, char **argv)
{
    res_t               res = { .kind = R_PASS };
    tsapi_mde_session   session = { .ta = NULL };
    char                lacking[1200] = "";
    char                listing[1200] = "";
    char                absent[600] = "";
    unsigned            n_lacking = 0;
    unsigned            n_absent = 0;
    size_t              i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;
    if (tsapi_mde_session_init(&session, "t15_hardening") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_binscan");
        goto verdict;
    }

    for (i = 0; i < TE_ARRAY_LEN(bins); i++)
    {
        tapi_binscan_info   info;
        char                path[700];
        char                miss[120] = "";
        te_errno            rc;
        bool                pie;

        snprintf(path, sizeof(path), "%s/%s", src_root, bins[i].rel);
        TEST_STEP("tapi_binscan on %s (%s)", path, bins[i].lang);
        if (access(path, R_OK) != 0)
        {
            n_absent++;
            append(absent, sizeof(absent), "%s is not built; ", path);
            continue;
        }
        rc = tapi_binscan_inspect(session.ta, path, &info);
        if (rc != 0 || !info.elf)
        {
            if (rc == 0)
                tapi_binscan_info_free(&info);
            n_absent++;
            append(absent, sizeof(absent), "%s cannot be scanned (rc %d, "
                   "ELF %s); ", path, (int)rc, rc == 0 ? "no" : "?");
            continue;
        }
        tapi_binscan_info_log(&info, path);
        pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
              info.kind == TAPI_BINSCAN_KIND_SHARED;
        if ((bins[i].need & F_NX) && (!info.nx || info.nx_unknown))
            append(miss, sizeof(miss), "NX ");
        if ((bins[i].need & F_PIE) && !pie)
            append(miss, sizeof(miss), "PIE ");
        if ((bins[i].need & F_RELRO) && info.relro != TAPI_BINSCAN_RELRO_FULL)
            append(miss, sizeof(miss), "RELRO(%s) ",
                   tapi_binscan_relro2str(info.relro));
        if ((bins[i].need & F_CANARY) && !info.canary)
            append(miss, sizeof(miss), "canary ");
        if ((bins[i].need & F_FORTIFY) && !info.fortify)
            append(miss, sizeof(miss), "fortify ");
        RING("webdeps H4: %s (%s): kind %s, NX %d, PIE %d, RELRO %s, canary "
             "%d, fortify %d; lacking %s", bins[i].rel, bins[i].lang,
             tapi_binscan_kind2str(info.kind), info.nx, pie,
             tapi_binscan_relro2str(info.relro), info.canary, info.fortify,
             miss[0] != '\0' ? miss : "nothing");
        append(listing, sizeof(listing), "%s [NX %s, PIE %s, RELRO %s, "
               "canary %s, fortify %s]; ", bins[i].rel,
               info.nx ? "yes" : "no", pie ? "yes" : "no",
               tapi_binscan_relro2str(info.relro),
               info.canary ? "yes" : "no", info.fortify ? "yes" : "no");
        T_FINDING(miss[0] != '\0' ? TAPI_CYBERSEC_SEV_MEDIUM :
                  TAPI_CYBERSEC_SEV_INFO, "binary.hardening", bins[i].rel,
                  "%s: NX %d, PIE %d, RELRO %s, canary %d, fortify %d; "
                  "lacking where supported: %s", bins[i].lang, info.nx, pie,
                  tapi_binscan_relro2str(info.relro), info.canary,
                  info.fortify, miss[0] != '\0' ? miss : "nothing");
        if (miss[0] != '\0')
        {
            n_lacking++;
            append(lacking, sizeof(lacking), "%s lacks %s; ", bins[i].rel,
                   miss);
        }
        tapi_binscan_info_free(&info);
    }

    if (n_absent > 0)
    {
        setup_svc = "tapi_binscan";
        res_set(&res, R_INCONCLUSIVE, "%u of %zu binaries were not "
                "scanned: %s", n_absent, TE_ARRAY_LEN(bins), absent);
    }
    else if (n_lacking > 0)
        res_set(&res, R_FAIL, "H4 CONFIRMED: %u of %zu binaries lack a flag "
                "their language supports: %sall binaries: %s", n_lacking,
                TE_ARRAY_LEN(bins), lacking, listing);
    else
        res_set(&res, R_PASS, "H4 DISPROVED: every binary has the flags its "
                "language supports: %s", listing);

verdict:
    if (session.ta != NULL)
        tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}
