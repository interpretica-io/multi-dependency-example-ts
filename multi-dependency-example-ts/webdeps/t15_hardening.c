/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t15_hardening, hardening flags of the built web binaries
 *        (settles H4)
 *
 * Hypothesis H4: the built web binaries lack NX, PIE, RELRO or a stack
 * canary.
 *
 * Sends: nothing to the network. tapi_binscan reads, on the agent, the
 * gateway (dist/bin/gateway-rs), the Go service (dist/bin/service-go), the
 * C# host (dist/bin/service-cs, the native apphost) and the Rust demo
 * binary (dist/bin/rust-demo). Each is listed with NX, PIE, RELRO, canary
 * and fortify.
 *
 * H4 CONFIRMED (fail) if any binary has no NX, no PIE or no full RELRO,
 * naming the binary and the flag. Canary and fortify are informational: they
 * are logged and added to the tapi_cybersec_report but never fail the test.
 * H4 DISPROVED (pass) if all four have NX, PIE and full RELRO.
 * INCONCLUSIVE, with the path and the error, if a binary is absent or
 * tapi_binscan cannot read it. The outcome is appended to the report with
 * its reason.
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
    unsigned    need;       /**< Flags that fail H4 when missing. */
} bins[] = {
    { "dist/bin/gateway-rs", "Rust", F_BASIC },
    { "dist/bin/service-go", "Go", F_BASIC },
    { "dist/bin/service-cs", "C# (native apphost)", F_BASIC },
    { "dist/bin/rust-demo", "Rust demo", F_BASIC },
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
            append(absent, sizeof(absent), "%s is not readable: %s; ", path,
                   strerror(errno));
            ERROR("webdeps H4: %s is not readable: %s", path, strerror(errno));
            continue;
        }
        rc = tapi_binscan_inspect(session.ta, path, &info);
        if (rc != 0 || !info.elf)
        {
            if (rc == 0)
                tapi_binscan_info_free(&info);
            n_absent++;
            append(absent, sizeof(absent), "%s cannot be scanned: %s%s; ", path,
                   rc != 0 ? te_rc_err2str(rc) : "not an ELF file", "");
            ERROR("webdeps H4: tapi_binscan cannot read %s: %s", path,
                  rc != 0 ? te_rc_err2str(rc) : "not an ELF file");
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
                  "%s: NX %d, PIE %d, RELRO %s, canary %d (informational), "
                  "fortify %d (informational); lacking: %s", bins[i].lang,
                  info.nx, pie,
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

    if (n_lacking > 0)
        res_set(&res, R_FAIL, "H4 CONFIRMED: %u of %zu binaries lack NX, "
                "PIE or full RELRO: %sall scanned: %s%s%s", n_lacking,
                TE_ARRAY_LEN(bins), lacking, listing,
                n_absent > 0 ? "; not scanned: " : "", absent);
    else if (n_absent > 0)
    {
        setup_svc = "tapi_binscan";
        res_set(&res, R_INCONCLUSIVE, "%u of %zu binaries were not "
                "scanned: %s", n_absent, TE_ARRAY_LEN(bins), absent);
    }
    else
        res_set(&res, R_PASS, "H4 DISPROVED: all %zu binaries have NX, PIE "
                "and full RELRO (canary and fortify are informational): %s",
                TE_ARRAY_LEN(bins), listing);

verdict:
    if (session.ta != NULL)
        tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}
