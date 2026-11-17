/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t15_hardening, hardening flags of the gateway and the Go
 *        service (settles H4)
 *
 * Hypothesis H4: the gateway and the Go service binaries lack NX, PIE,
 * RELRO or a stack canary.
 *
 * Sends and reads: nothing goes to the network. tapi_binscan reads, on the
 * agent, exactly two binaries: dist/bin/gateway-rs and dist/bin/service-go.
 *
 * Verdicts (every one starts with H4):
 *  - One line per binary, "H4 BIN nx=Y/N pie=Y/N relro=full/partial/none
 *    canary=Y/N", for example "H4 gateway-rs nx=Y pie=N relro=partial
 *    canary=Y". It is logged for each binary and is informational.
 *  - "H4 hardening-read" (pass): both binaries were scanned, whatever their
 *    flags: a missing flag does not fail the test in this round. Each
 *    missing NX, PIE, full RELRO or canary is a finding in the
 *    tapi_cybersec_report (medium); a flag set on every binary is H4
 *    false, a missing one is H4 true.
 *  - "H4 setup-<step>-failed: ..." (fail): the step named did not work (no
 *    session, a binary absent or tapi_binscan cannot read it); nothing is
 *    settled.
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
    const char *name;       /**< In the verdict line. */
    const char *lang;
    unsigned    need;       /**< Flags reported as findings when missing. */
} bins[] = {
    { "dist/bin/gateway-rs", "gateway-rs", "Rust", F_BASIC | F_CANARY },
    { "dist/bin/service-go", "service-go", "Go", F_BASIC | F_CANARY },
};

/** H4: one scan per binary, one verdict line each, a finding per missing flag. */
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
        res_set(&res, R_SETUP, "H4 setup-open-session-failed: no session "
                "on the agent for tapi_binscan");
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
        if ((bins[i].need & F_CANARY) && !info.canary)
            append(miss, sizeof(miss), "canary ");
        RING_VERDICT("H4 %s nx=%s pie=%s relro=%s canary=%s", bins[i].name,
                     info.nx ? "Y" : "N", pie ? "Y" : "N",
                     tapi_binscan_relro2str(info.relro),
                     info.canary ? "Y" : "N");
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

    if (n_absent > 0)
    {
        setup_svc = "tapi_binscan";
        res_set(&res, R_SETUP, "H4 setup-binscan-failed: %u of %zu binaries "
                "were not scanned: %s", n_absent, TE_ARRAY_LEN(bins), absent);
    }
    else
        res_set(&res, R_PASS, "H4 hardening-read: both binaries scanned; "
                "%u lack a flag (each is a finding in the report, no "
                "failure in this round): %s%s", n_lacking, lacking,
                listing);

verdict:
    if (session.ta != NULL)
        tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H4");

cleanup:
    cleanup_all();
    TEST_END;
}
