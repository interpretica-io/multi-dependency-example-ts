/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: T5, hardening flags of the built binaries (settles H5)
 *
 * Run tapi_binscan on every binary the language builds of T4 produce
 * (rust-demo, cpp-demo, libgocore, libcscore, librustcore, libcppcore,
 * libpycore) and on gateway-rs, service-go and service-cs. Every result
 * goes into the tapi_cybersec_report. A binary that lacks NX, PIE, full
 * RELRO, a stack canary or fortify fails; the verdict prints the missing
 * flags per binary. A binary that is not built, or that binscan cannot
 * read, is INCONCLUSIVE (never a pass) when nothing else failed.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t5_binscan"

#include "te_config.h"

#include "webdeps_lib.h"

static const char * const scan_paths[] = {
    "dist/bin/rust-demo", "dist/bin/cpp-demo", "dist/lib/libgocore.so",
    "dist/lib/libcscore.so", "dist/lib/librustcore.so",
    "dist/lib/libcppcore.so", "dist/lib/libpycore.so",
    "dist/bin/gateway-rs", "dist/bin/service-go", "dist/bin/service-cs",
};

/**
 * Scan one binary; @p missing receives the flags it lacks ("" if none).
 * Returns false when it could not be scanned (@p why says why).
 */
static bool
scan_one(tsapi_mde_session *session, const char *rel, char *missing,
         size_t size, char *why, size_t why_size)
{
    tapi_binscan_info info;
    char              path[700];
    te_errno          rc;
    bool              pie;

    missing[0] = '\0';
    snprintf(path, sizeof(path), "%s/%s", src_root, rel);
    if (access(path, R_OK) != 0)
    {
        snprintf(why, why_size, "%s is not built", rel);
        return false;
    }
    rc = tapi_binscan_inspect(session->ta, path, &info);
    if (rc != 0)
    {
        snprintf(why, why_size, "tapi_binscan cannot read %s (rc %d)", rel,
                 (int)rc);
        return false;
    }
    if (!info.elf)
    {
        tapi_binscan_info_free(&info);
        snprintf(why, why_size, "tapi_binscan: %s is not an ELF file", rel);
        return false;
    }
    tapi_binscan_info_log(&info, path);
    pie = info.kind == TAPI_BINSCAN_KIND_PIE ||
          info.kind == TAPI_BINSCAN_KIND_SHARED;
    if (!info.nx || info.nx_unknown)
        append(missing, size, "NX ");
    if (!pie)
        append(missing, size, "PIE ");
    if (info.relro != TAPI_BINSCAN_RELRO_FULL)
        append(missing, size, "full-RELRO(%s) ",
               tapi_binscan_relro2str(info.relro));
    if (!info.canary)
        append(missing, size, "canary ");
    if (!info.fortify)
        append(missing, size, "fortify ");
    T_FINDING(missing[0] == '\0' ? TAPI_CYBERSEC_SEV_INFO :
              TAPI_CYBERSEC_SEV_MEDIUM, "binary.hardening", rel,
              "kind %s, missing: %s%s", tapi_binscan_kind2str(info.kind),
              missing[0] != '\0' ? missing : "nothing",
              info.stripped ? " (stripped: canary and fortify are guesses)" :
              "");
    tapi_binscan_info_free(&info);
    return true;
}

int
main(int argc, char **argv)
{
    res_t               res = { .kind = R_PASS };
    tsapi_mde_session   session = { .ta = NULL };
    char                missing[200];
    char                why[300];
    char                bad[1000] = "";
    char                absent[600] = "";
    unsigned            n_bad = 0;
    unsigned            n_absent = 0;
    size_t              i;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
        goto verdict;

    if (tsapi_mde_session_init(&session, "t5_binscan") != 0)
    {
        setup_svc = "agent";
        res_set(&res, R_SETUP, "no session on the agent for tapi_binscan");
        goto verdict;
    }

    for (i = 0; i < TE_ARRAY_LEN(scan_paths); i++)
    {
        TEST_STEP("tapi_binscan on %s", scan_paths[i]);
        if (!scan_one(&session, scan_paths[i], missing, sizeof(missing), why,
                      sizeof(why)))
        {
            n_absent++;
            append(absent, sizeof(absent), "%s; ", why);
            T_FINDING(TAPI_CYBERSEC_SEV_LOW, "binary.not-scanned",
                      scan_paths[i], "%s", why);
            RING("webdeps: %s: not scanned: %s", scan_paths[i], why);
            continue;
        }
        RING("webdeps: %s: missing flags: %s", scan_paths[i],
             missing[0] != '\0' ? missing : "none");
        if (missing[0] != '\0')
        {
            n_bad++;
            append(bad, sizeof(bad), "%s lacks %s| ", scan_paths[i], missing);
        }
    }

    if (n_bad > 0)
        res_set(&res, R_FAIL, "H5 FAIL: %u of %zu binaries lack hardening "
                "flags: %s%s%s", n_bad, TE_ARRAY_LEN(scan_paths), bad,
                n_absent > 0 ? "not scanned: " : "", absent);
    else if (n_absent > 0)
        res_set(&res, R_INCONCLUSIVE, "no scanned binary lacks a flag but "
                "%u of %zu could not be scanned: %s", n_absent,
                TE_ARRAY_LEN(scan_paths), absent);
    else
        res_set(&res, R_PASS, "H5 PASS: all %zu binaries have NX, PIE, full "
                "RELRO, a stack canary and fortify", TE_ARRAY_LEN(scan_paths));

verdict:
    tsapi_mde_session_fini(&session);
    T_VERDICT(&res, "H5");

cleanup:
    cleanup_all();
    TEST_END;
}
