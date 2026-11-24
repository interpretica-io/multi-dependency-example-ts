/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: binary_hardening, hardening flags of the gateway binary
 *        (informational, context for H1)
 *
 * Runs tapi_binscan on dist/bin/gateway-rs and logs NX, PIE, RELRO, canary
 * and fortify. The test never fails on a flag: a missing flag is a finding
 * in the tapi_cybersec_report and the result is context for H1 (a panic is
 * easier to turn into more when the binary lacks mitigations). Only a binary
 * that cannot be scanned is reported, as an INCONCLUSIVE verdict.
 *
 * Verdict: "H1 context binary_hardening: nx=Y/N pie=Y/N relro=... canary=Y/N
 * fortify=Y/N" (pass).
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/binary_hardening"

#include "te_config.h"

#include "webdeps_lib.h"

int
main(int argc, char **argv)
{
    res_t               res = { .kind = R_PASS };
    tsapi_mde_session   session = { .ta = NULL };
    tapi_binscan_info   info;
    char                path[700];
    char                miss[160] = "";
    te_errno            rc;
    bool                pie;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;
    if (tsapi_mde_session_init(&session, "binary_hardening") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "H1 setup-open-session-failed: no session "
                "on the agent for tapi_binscan");
        goto verdict;
    }

    snprintf(path, sizeof(path), "%s/dist/bin/gateway-rs", src_root);
    TEST_STEP("tapi_binscan on %s", path);
    rc = tapi_binscan_inspect(session.ta, path, &info);
    if (rc != 0 || !info.elf)
    {
        if (rc == 0)
            tapi_binscan_info_free(&info);
        setup_svc = "tapi_binscan";
        res_set(&res, R_INCONCLUSIVE, "%s cannot be scanned: %s", path,
                rc != 0 ? te_rc_err2str(rc) : "not an ELF file");
        goto verdict;
    }
    tapi_binscan_info_log(&info, path);
    pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
          info.kind == TAPI_BINSCAN_KIND_SHARED;
    if (!info.nx || info.nx_unknown)
        append(miss, sizeof(miss), "NX ");
    if (!pie)
        append(miss, sizeof(miss), "PIE ");
    if (info.relro != TAPI_BINSCAN_RELRO_FULL)
        append(miss, sizeof(miss), "RELRO(%s) ",
               tapi_binscan_relro2str(info.relro));
    if (!info.canary)
        append(miss, sizeof(miss), "canary ");
    if (!info.fortify)
        append(miss, sizeof(miss), "fortify ");
    RING("webdeps H1 context: gateway-rs NX %d, PIE %d, RELRO %s, canary %d, "
         "fortify %d; lacking %s", info.nx, pie,
         tapi_binscan_relro2str(info.relro), info.canary, info.fortify,
         miss[0] != '\0' ? miss : "nothing");
    T_FINDING(miss[0] != '\0' ? TAPI_CYBERSEC_SEV_LOW : TAPI_CYBERSEC_SEV_INFO,
              "binary.hardening", "gateway-rs",
              "NX %d, PIE %d, RELRO %s, canary %d, fortify %d; lacking: %s "
              "(informational, context for H1)", info.nx, pie,
              tapi_binscan_relro2str(info.relro), info.canary, info.fortify,
              miss[0] != '\0' ? miss : "nothing");
    res_set(&res, R_PASS, "H1 context binary_hardening: nx=%s pie=%s "
            "relro=%s canary=%s fortify=%s (informational, not a failure)",
            info.nx ? "Y" : "N", pie ? "Y" : "N",
            tapi_binscan_relro2str(info.relro), info.canary ? "Y" : "N",
            info.fortify ? "Y" : "N");
    tapi_binscan_info_free(&info);

verdict:
    if (session.ta != NULL)
        tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
